//! seccomp(2) filter emulation.
//!
//! The dispatcher already sees every guest syscall, so a classic-BPF (cBPF)
//! filter check fits naturally at the dispatch seam: before a handler runs,
//! installed filters are evaluated against a `seccomp_data` view of the call
//! and the resulting action (allow / errno / kill / …) is applied.
//!
//! This is a faithful interpreter for the cBPF subset libseccomp emits (LD
//! ABS/IMM, JMP JA/JEQ/JGT/JGE/JSET, ALU AND, RET A/K, MISC TAX/TXA). Anything
//! malformed or out of the modelled subset evaluates to `SECCOMP_RET_KILL_PROCESS`
//! (fail-closed), and evaluation is step-bounded so a bad filter can't loop.

use parking_lot::Mutex;

// Linux AUDIT_ARCH for the guest. Filters compare seccomp_data.arch against
// this; aarch64 guests see AUDIT_ARCH_AARCH64.
pub(crate) const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

// seccomp filter actions (high 16 bits of the cBPF return value); the low bits
// carry RET_DATA (e.g. the errno for RET_ERRNO). The kernel picks the *most
// restrictive* action (numerically smallest) across all filters.
pub(crate) const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub(crate) const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
pub(crate) const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
pub(crate) const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub(crate) const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
pub(crate) const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
pub(crate) const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

pub(crate) const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;
pub(crate) const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

// seccomp(2) operations / flags we recognize.
pub(crate) const SECCOMP_SET_MODE_STRICT: u32 = 0;
pub(crate) const SECCOMP_SET_MODE_FILTER: u32 = 1;

/// A cBPF instruction (`struct sock_filter`), 8 bytes on the wire.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SockFilter {
    pub(crate) code: u16,
    pub(crate) jt: u8,
    pub(crate) jf: u8,
    pub(crate) k: u32,
}

impl SockFilter {
    /// Parse a packed filter program (`struct sock_filter[]`, 8 bytes each).
    pub(crate) fn parse_program(bytes: &[u8]) -> Option<Vec<SockFilter>> {
        if bytes.is_empty() || !bytes.len().is_multiple_of(8) {
            return None;
        }
        let mut prog = Vec::with_capacity(bytes.len() / 8);
        for chunk in bytes.chunks_exact(8) {
            prog.push(SockFilter {
                code: u16::from_ne_bytes([chunk[0], chunk[1]]),
                jt: chunk[2],
                jf: chunk[3],
                k: u32::from_ne_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
            });
        }
        Some(prog)
    }
}

/// The kernel's `struct seccomp_data` — the read-only input a filter sees.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SeccompData {
    pub(crate) nr: i32,
    pub(crate) arch: u32,
    pub(crate) instruction_pointer: u64,
    pub(crate) args: [u64; 6],
}

impl SeccompData {
    /// Load the 32-bit word at byte `offset` into the `seccomp_data` layout
    /// (nr@0, arch@4, ip@8, args@16..64). Out-of-range offsets read as 0,
    /// matching the kernel's bounded BPF_LD|BPF_ABS over the 64-byte struct.
    fn load_word(&self, offset: u32) -> u32 {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&self.nr.to_ne_bytes());
        buf[4..8].copy_from_slice(&self.arch.to_ne_bytes());
        buf[8..16].copy_from_slice(&self.instruction_pointer.to_ne_bytes());
        for (i, arg) in self.args.iter().enumerate() {
            let base = 16 + i * 8;
            buf[base..base + 8].copy_from_slice(&arg.to_ne_bytes());
        }
        let off = offset as usize;
        match buf.get(off..off + 4) {
            Some(b) => u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
            None => 0,
        }
    }
}

// cBPF opcode bit fields.
const BPF_CLASS: u16 = 0x07;
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

const BPF_RVAL: u16 = 0x18; // RET source: K=0x00, A=0x10
const BPF_A: u16 = 0x10;

const BPF_OP: u16 = 0xf0; // ALU/JMP operation
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;
const BPF_ALU_AND: u16 = 0x50;

const BPF_SRC_X: u16 = 0x08; // operand source: K=0x00, X=0x08

const BPF_MISC_TAX: u16 = 0x00;
const BPF_MISC_TXA: u16 = 0x80;

const MAX_STEPS: usize = 4096;

/// Evaluate one cBPF filter against `data`, returning its raw cBPF return value.
/// Fail-closed: a malformed program or one that runs off the end / past the
/// step bound returns `SECCOMP_RET_KILL_PROCESS`.
pub(crate) fn eval_filter(prog: &[SockFilter], data: &SeccompData) -> u32 {
    let mut acc: u32 = 0;
    let mut x: u32 = 0;
    let mut pc: usize = 0;
    for _ in 0..MAX_STEPS {
        let Some(ins) = prog.get(pc) else {
            return SECCOMP_RET_KILL_PROCESS;
        };
        pc += 1;
        match ins.code & BPF_CLASS {
            BPF_LD => acc = load_operand(ins, data),
            BPF_LDX => x = load_operand(ins, data),
            BPF_ALU if ins.code & BPF_OP == BPF_ALU_AND => {
                let rhs = if ins.code & BPF_SRC_X != 0 { x } else { ins.k };
                acc &= rhs;
            }
            BPF_ALU => return SECCOMP_RET_KILL_PROCESS, // unmodelled ALU op
            BPF_JMP => {
                let op = ins.code & BPF_OP;
                if op == BPF_JA {
                    pc = pc.wrapping_add(ins.k as usize);
                    continue;
                }
                let rhs = if ins.code & BPF_SRC_X != 0 { x } else { ins.k };
                let taken = match op {
                    BPF_JEQ => acc == rhs,
                    BPF_JGT => acc > rhs,
                    BPF_JGE => acc >= rhs,
                    BPF_JSET => acc & rhs != 0,
                    _ => return SECCOMP_RET_KILL_PROCESS,
                };
                pc += if taken {
                    ins.jt as usize
                } else {
                    ins.jf as usize
                };
            }
            BPF_RET => {
                return if ins.code & BPF_RVAL == BPF_A {
                    acc
                } else {
                    ins.k
                };
            }
            BPF_MISC => match ins.code & BPF_MISC_TXA {
                BPF_MISC_TAX => x = acc,
                _ => acc = x,
            },
            _ => return SECCOMP_RET_KILL_PROCESS,
        }
    }
    SECCOMP_RET_KILL_PROCESS
}

fn load_operand(ins: &SockFilter, data: &SeccompData) -> u32 {
    // BPF_ABS (0x20) loads from seccomp_data at offset k; BPF_IMM (0x00) loads
    // the immediate k. Other modes (MEM/IND/LEN) aren't used by seccomp filters.
    const BPF_MODE: u16 = 0xe0;
    const BPF_ABS: u16 = 0x20;
    const BPF_IMM: u16 = 0x00;
    match ins.code & BPF_MODE {
        BPF_ABS => data.load_word(ins.k),
        BPF_IMM => ins.k,
        _ => 0,
    }
}

/// Per-process installed seccomp filters. Filters stack (each `seccomp` /
/// `prctl(PR_SET_SECCOMP)` call adds one); a syscall is checked against all of
/// them and the most restrictive action wins.
#[derive(Debug, Default)]
pub(crate) struct SeccompState {
    filters: Mutex<Vec<Vec<SockFilter>>>,
}

impl SeccompState {
    /// Install a parsed filter program (appended to the stack).
    pub(crate) fn install(&self, prog: Vec<SockFilter>) {
        self.filters.lock().push(prog);
    }

    pub(crate) fn is_active(&self) -> bool {
        !self.filters.lock().is_empty()
    }

    /// Evaluate all installed filters against `data` and return the winning
    /// (most restrictive) cBPF value, or `SECCOMP_RET_ALLOW` if none installed.
    /// The kernel takes the numerically-smallest action across filters.
    pub(crate) fn check(&self, data: &SeccompData) -> u32 {
        let filters = self.filters.lock();
        let mut result = SECCOMP_RET_ALLOW;
        for prog in filters.iter() {
            let ret = eval_filter(prog, data);
            if (ret & SECCOMP_RET_ACTION_FULL) < (result & SECCOMP_RET_ACTION_FULL) {
                result = ret;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the canonical "deny one syscall number with EPERM, allow the rest"
    /// filter libseccomp would emit:
    ///   LD  [0]            ; A = seccomp_data.nr
    ///   JEQ deny_nr, 0, 1  ; if nr == deny_nr fall through, else skip 1
    ///   RET ERRNO|EPERM
    ///   RET ALLOW
    fn deny_nr_filter(deny_nr: u32, errno: u32) -> Vec<SockFilter> {
        vec![
            SockFilter {
                code: BPF_LD | 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            }, // LD|W|ABS [0] (nr)
            SockFilter {
                code: BPF_JMP | BPF_JEQ,
                jt: 0,
                jf: 1,
                k: deny_nr,
            },
            SockFilter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | errno,
            },
            SockFilter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
        ]
    }

    fn data_for(nr: i32) -> SeccompData {
        SeccompData {
            nr,
            arch: AUDIT_ARCH_AARCH64,
            instruction_pointer: 0,
            args: [0; 6],
        }
    }

    #[test]
    fn deny_filter_blocks_target_and_allows_others() {
        let prog = deny_nr_filter(101, 1 /*EPERM*/);
        let denied = eval_filter(&prog, &data_for(101));
        assert_eq!(denied & SECCOMP_RET_ACTION_FULL, SECCOMP_RET_ERRNO);
        assert_eq!(denied & SECCOMP_RET_DATA, 1);
        let allowed = eval_filter(&prog, &data_for(63));
        assert_eq!(allowed, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn arch_and_arg_loads_and_jset_work() {
        // LD [4] (arch); JEQ AARCH64 ? continue : kill; LD [16] (arg0);
        // JSET 0x1 ? RET ERRNO : RET ALLOW  — deny odd arg0.
        let prog = vec![
            SockFilter {
                code: BPF_LD | 0x20,
                jt: 0,
                jf: 0,
                k: 4,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ,
                jt: 1,
                jf: 0,
                k: AUDIT_ARCH_AARCH64,
            },
            SockFilter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
            SockFilter {
                code: BPF_LD | 0x20,
                jt: 0,
                jf: 0,
                k: 16,
            },
            SockFilter {
                code: BPF_JMP | BPF_JSET,
                jt: 0,
                jf: 1,
                k: 0x1,
            },
            SockFilter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | 13,
            },
            SockFilter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
        ];
        let mut odd = data_for(63);
        odd.args[0] = 0x3;
        assert_eq!(
            eval_filter(&prog, &odd) & SECCOMP_RET_ACTION_FULL,
            SECCOMP_RET_ERRNO
        );
        let mut even = data_for(63);
        even.args[0] = 0x2;
        assert_eq!(eval_filter(&prog, &even), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn malformed_or_runaway_filter_fails_closed() {
        // No RET reached (runs off the end) -> KILL.
        let prog = vec![SockFilter {
            code: BPF_LD | 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        }];
        assert_eq!(eval_filter(&prog, &data_for(1)), SECCOMP_RET_KILL_PROCESS);
        assert!(SockFilter::parse_program(&[0u8; 7]).is_none());
        assert!(SockFilter::parse_program(&[0u8; 8]).is_some());
    }

    #[test]
    fn state_stacks_filters_and_takes_most_restrictive() {
        let state = SeccompState::default();
        assert!(!state.is_active());
        assert_eq!(state.check(&data_for(101)), SECCOMP_RET_ALLOW);
        state.install(deny_nr_filter(101, 1));
        state.install(deny_nr_filter(202, 1));
        assert!(state.is_active());
        // 101 denied by the first filter, allowed by the second -> ERRNO wins.
        assert_eq!(
            state.check(&data_for(101)) & SECCOMP_RET_ACTION_FULL,
            SECCOMP_RET_ERRNO
        );
        assert_eq!(
            state.check(&data_for(202)) & SECCOMP_RET_ACTION_FULL,
            SECCOMP_RET_ERRNO
        );
        assert_eq!(state.check(&data_for(63)), SECCOMP_RET_ALLOW);
    }
}
