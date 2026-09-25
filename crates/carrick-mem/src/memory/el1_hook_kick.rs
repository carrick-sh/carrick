//! Contract `kernel.vcpu.kick-el0-boundary`, VM-free binding for the EL1
//! syscall hook (Fact 9 of EL1 plan 1a).
//!
//! A host kick that stops the vCPU inside the hook is owed to the EL0
//! boundary: the engine publishes it to the slot's `pending_host_work` flag
//! and clears `I` in the live `SPSR_EL1` (`carrick_aarch64::owed_kick`). The
//! hook saves `SPSR_EL1` into the TrapFrame on entry and reloads it before
//! `eret`, so the served path must leave through the host (the forward path)
//! or `eret` with the owed unmask intact. Otherwise EL0 resumes with the kick
//! pending but masked, and a thread that makes no further host syscall never
//! stops for the page-table drain that kicked it.
//!
//! This interprets the REAL emitted hook bytes, not a model of them, and
//! injects the kick at every instruction boundary of the hook.

use super::*;
use std::collections::BTreeMap;

const PSTATE_I: u64 = 1 << 7;
/// Carrick's EL0 return state: EL0t with DAIF masked.
const EL0_DAIF_MASKED: u64 = 0x3c0;
const GUEST_ELR: u64 = 0x4000_1000;
const SLOT: u64 = 3;
/// The mailbox capture's offset in the test page; reaching it is a host exit.
const CAPTURE: usize = 0x800;
/// `CurrentTask` is 64 bytes (`lsl #6` in the hook); `pending_host_work` at 40.
const PENDING_HOST_WORK: u64 = 40;

#[derive(Debug, PartialEq, Eq)]
enum Exit {
    /// Reached the mailbox capture: the syscall surfaces to the host.
    Host,
    /// `eret` to EL0 with this `SPSR_EL1` and `ELR_EL1`.
    Eret { spsr: u64, elr: u64 },
}

/// Small independent interpreter of the hook's instruction subset. Unknown
/// instructions fail closed.
struct Machine {
    regs: [u64; 31],
    sp: u64,
    mem: BTreeMap<u64, u64>,
    elr: u64,
    spsr: u64,
    esr: u64,
    pc: usize,
    equal: bool,
    bytes: Vec<u8>,
    /// Instructions retired; the kick lands before instruction `kick_at`.
    retired: usize,
    /// Where the injected kick stopped the vCPU.
    kicked_pc: Option<usize>,
}

impl Machine {
    fn new() -> Self {
        let mut bytes = vec![0u8; LINUX_EL1_VECTORS_SIZE as usize];
        write_el1_vector_hook(&mut bytes, EL1_VECTOR_HOOK_OFFSET, CAPTURE);
        Self {
            regs: std::array::from_fn(|i| 0xAB00 + i as u64),
            sp: LINUX_SYSCALL_MAILBOX_BASE + SLOT * 256,
            mem: BTreeMap::new(),
            elr: GUEST_ELR,
            spsr: EL0_DAIF_MASKED,
            esr: 0x15 << 26,
            pc: EL1_VECTOR_HOOK_OFFSET,
            equal: false,
            bytes,
            retired: 0,
            kicked_pc: None,
        }
    }

    fn pending_host_work_addr() -> u64 {
        carrick_el1_abi::EL1_CURRENT_TASKS_BASE + SLOT * 64 + PENDING_HOST_WORK
    }

    fn read(&self, addr: u64) -> u64 {
        *self.mem.get(&addr).unwrap_or(&0)
    }

    /// Register `n` as a base/source where 31 is SP.
    fn xn_sp(&self, n: usize) -> u64 {
        if n == 31 { self.sp } else { self.regs[n] }
    }

    fn set_xd_sp(&mut self, d: usize, v: u64) {
        if d == 31 {
            self.sp = v;
        } else {
            self.regs[d] = v;
        }
    }

    /// Register `n` as an operand where 31 is XZR.
    fn xn_zr(&self, n: usize) -> u64 {
        if n == 31 { 0 } else { self.regs[n] }
    }

    fn set_xd_zr(&mut self, d: usize, v: u64) {
        if d != 31 {
            self.regs[d] = v;
        }
    }

    /// What the engine does when it absorbs a kick inside Carrick's EL1 code:
    /// the kick is published to the slot and the live EL0 return state
    /// (`SPSR_EL1`) is unmasked.
    fn absorb_kick(&mut self) {
        self.mem.insert(Self::pending_host_work_addr(), 1);
        self.spsr &= !PSTATE_I;
    }

    /// The EL1 image (`carrick_el1_syscall`): forward at entry when host work
    /// is pending, else serve (`Action::Served == 0`) and write the result.
    fn el1_image(&mut self) {
        let frame = self.regs[0];
        let pending = self.read(Self::pending_host_work_addr()) != 0;
        if pending {
            self.regs[0] = 1;
        } else {
            self.mem.insert(frame, 0x5E4E);
            self.regs[0] = 0;
        }
    }

    fn run(&mut self, kick_at: Option<usize>) -> Exit {
        for _ in 0..1000 {
            if Some(self.retired) == kick_at {
                self.kicked_pc = Some(self.pc);
                self.absorb_kick();
            }
            if self.pc == CAPTURE {
                return Exit::Host;
            }
            let op = u32::from_le_bytes(self.bytes[self.pc..self.pc + 4].try_into().expect("word"));
            let pc = self.pc;
            self.pc += 4;
            self.retired += 1;
            let rd = (op & 31) as usize;
            let rn = ((op >> 5) & 31) as usize;
            let rm = ((op >> 16) & 31) as usize;
            if op == 0xD69F_03E0 {
                return Exit::Eret {
                    spsr: self.spsr,
                    elr: self.elr,
                };
            }
            if op == 0xD63F_0200 {
                // blr x16: the EL1 image, then return here.
                self.regs[30] = pc as u64 + 4;
                self.el1_image();
                continue;
            }
            // mrs/msr of ELR_EL1, SPSR_EL1, ESR_EL1 with any Xt.
            match op & !31 {
                0xD538_4020 => self.set_xd_zr(rd, self.elr),
                0xD538_4000 => self.set_xd_zr(rd, self.spsr),
                0xD538_5200 => self.set_xd_zr(rd, self.esr),
                0xD518_4020 => self.elr = self.xn_zr(rd),
                0xD518_4000 => self.spsr = self.xn_zr(rd),
                0xD518_5200 => self.esr = self.xn_zr(rd),
                _ => {}
            }
            if matches!(
                op & !31,
                0xD538_4020 | 0xD538_4000 | 0xD538_5200 | 0xD518_4020 | 0xD518_4000 | 0xD518_5200
            ) {
                continue;
            }
            if op & 0xFC00_0000 == 0x1400_0000 {
                let d = ((op << 6) as i32 >> 6) as i64 * 4;
                self.pc = (pc as i64 + d) as usize;
            } else if op & 0xFF00_0010 == 0x5400_0000 {
                // b.eq (cond 0) / b.ne (cond 1)
                let d = (((op >> 5) & 0x7FFFF) << 13) as i32 >> 13;
                if self.equal == (op & 15 == 0) {
                    self.pc = (pc as i64 + i64::from(d) * 4) as usize;
                }
            } else if op & 0xFF00_0000 == 0x3400_0000 {
                // cbz wN
                let d = (((op >> 5) & 0x7FFFF) << 13) as i32 >> 13;
                if self.xn_zr(rd) & 0xFFFF_FFFF == 0 {
                    self.pc = (pc as i64 + i64::from(d) * 4) as usize;
                }
            } else if op & 0xFFC0_0000 == 0xF900_0000 {
                let addr = self.xn_sp(rn) + u64::from((op >> 10) & 0xFFF) * 8;
                self.mem.insert(addr, self.xn_zr(rd));
            } else if op & 0xFFC0_0000 == 0xF940_0000 {
                let addr = self.xn_sp(rn) + u64::from((op >> 10) & 0xFFF) * 8;
                let v = self.read(addr);
                self.set_xd_zr(rd, v);
            } else if op & 0xFFFF_FC00 == 0x88DF_FC00 {
                let v = self.read(self.xn_sp(rn)) & 0xFFFF_FFFF;
                self.set_xd_zr(rd, v);
            } else if op & 0xFFFF_FC00 == 0x889F_FC00 {
                self.mem
                    .insert(self.xn_sp(rn), self.xn_zr(rd) & 0xFFFF_FFFF);
            } else if op & 0xFF80_0000 == 0xD280_0000 {
                let shift = ((op >> 21) & 3) * 16;
                self.set_xd_zr(rd, u64::from((op >> 5) & 0xFFFF) << shift);
            } else if op & 0xFF80_0000 == 0xF280_0000 {
                let shift = ((op >> 21) & 3) * 16;
                let v = (self.xn_zr(rd) & !(0xFFFF << shift))
                    | (u64::from((op >> 5) & 0xFFFF) << shift);
                self.set_xd_zr(rd, v);
            } else if op & 0xFFC0_0000 == 0x9100_0000 {
                let v = self.xn_sp(rn) + u64::from((op >> 10) & 0xFFF);
                self.set_xd_sp(rd, v);
            } else if op & 0xFFC0_0000 == 0xD100_0000 {
                let v = self.xn_sp(rn) - u64::from((op >> 10) & 0xFFF);
                self.set_xd_sp(rd, v);
            } else if op & 0xFFC0_0000 == 0xF100_0000 && rd == 31 {
                self.equal = self.xn_sp(rn) == u64::from((op >> 10) & 0xFFF);
            } else if op & 0xFFE0_0000 == 0x8B00_0000 {
                let amount = (op >> 10) & 0x3F;
                self.set_xd_zr(rd, self.xn_zr(rn) + (self.xn_zr(rm) << amount));
            } else if op & 0xFFE0_0000 == 0xCB00_0000 {
                let amount = (op >> 10) & 0x3F;
                self.set_xd_zr(rd, self.xn_zr(rn) - (self.xn_zr(rm) << amount));
            } else if op & 0xFFC0_FC00 == 0xD340_FC00 {
                // lsr xd, xn, #immr
                let amount = (op >> 16) & 0x3F;
                self.set_xd_zr(rd, self.xn_zr(rn) >> amount);
            } else {
                panic!("unsupported hook opcode {op:08x} at {pc:#x}");
            }
        }
        panic!("unbounded hook control flow");
    }
}

/// Instructions the hook retires on the served path with no kick.
fn served_path_len() -> usize {
    let mut m = Machine::new();
    assert!(matches!(m.run(None), Exit::Eret { .. }));
    m.retired
}

/// No kick: the syscall is served in EL1 and EL0 resumes with its exact
/// PSTATE and return address (the owed-kick machinery is guest-invisible).
#[test]
fn served_path_restores_el0_state_exactly() {
    let mut m = Machine::new();
    let original = m.regs;
    assert_eq!(
        m.run(None),
        Exit::Eret {
            spsr: EL0_DAIF_MASKED,
            elr: GUEST_ELR,
        }
    );
    assert_eq!(m.sp, LINUX_SYSCALL_MAILBOX_BASE + SLOT * 256);
    assert_eq!(m.regs[0], 0x5E4E, "x0 is the served result");
    assert_eq!(m.regs[1..], original[1..], "x1..x30 restored");
}

/// A kick absorbed at ANY instruction boundary of the served hook either
/// leaves through the host or returns to EL0 with IRQs unmasked, so the
/// pending kick IRQ is taken at the first EL0 instruction.
#[test]
fn kick_absorbed_anywhere_in_served_hook_surfaces() {
    let len = served_path_len();
    let mut lost = Vec::new();
    for kick_at in 0..len {
        let mut m = Machine::new();
        match m.run(Some(kick_at)) {
            Exit::Host => {}
            Exit::Eret { spsr, elr } => {
                assert_eq!(elr, GUEST_ELR);
                if spsr & PSTATE_I != 0 {
                    let pc = m.kicked_pc.expect("kick injected");
                    lost.push(format!("hook+{:#x}", pc - EL1_VECTOR_HOOK_OFFSET));
                }
            }
        }
    }
    assert!(
        lost.is_empty(),
        "an owed kick returned to EL0 masked (lost until the next host exit) when \
         absorbed at {lost:?} ({len} served-path instructions)"
    );
}
