//! AArch64 `ESR_EL1` debug-class decoding.

/// Map an EL0 synchronous *debug* exception `ESR_EL1` to the Linux
/// `(SIGTRAP, si_code)` the kernel would deliver, or `None` if it isn't a debug
/// class (leaving it to `el0_fault_signal`).
pub fn el0_debug_signal(esr: u64) -> Option<(i32, i32)> {
    const SIGTRAP: i32 = 5;
    const TRAP_BRKPT: i32 = 1; // software breakpoint (BRK)
    const TRAP_TRACE: i32 = 2; // process trace trap (single-step)
    const TRAP_HWBKPT: i32 = 4; // hardware breakpoint/watchpoint
    let ec = (esr >> 26) & 0x3f;
    match ec {
        0x3c => Some((SIGTRAP, TRAP_BRKPT)),         // BRK (AArch64)
        0x32 | 0x33 => Some((SIGTRAP, TRAP_TRACE)),  // software step
        0x30 | 0x31 => Some((SIGTRAP, TRAP_HWBKPT)), // HW breakpoint
        0x34 | 0x35 => Some((SIGTRAP, TRAP_HWBKPT)), // watchpoint
        _ => None,
    }
}

pub const AARCH64_SYS64_EXCEPTION_CLASS: u64 = 0x18;
const AARCH64_ESR_ISS_MASK: u64 = (1 << 25) - 1;
const AARCH64_SYS64_ISS_DIR_READ: u64 = 0x1;
pub const AARCH64_SYS64_ISS_RT_SHIFT: u64 = 5;
const AARCH64_SYS64_ISS_RT_MASK: u64 = 0x1f << AARCH64_SYS64_ISS_RT_SHIFT;
const AARCH64_SYS64_ISS_CRM_SHIFT: u64 = 1;
const AARCH64_SYS64_ISS_CRM_MASK: u64 = 0xf << AARCH64_SYS64_ISS_CRM_SHIFT;
const AARCH64_SYS64_ISS_CRN_SHIFT: u64 = 10;
const AARCH64_SYS64_ISS_CRN_MASK: u64 = 0xf << AARCH64_SYS64_ISS_CRN_SHIFT;
const AARCH64_SYS64_ISS_OP1_SHIFT: u64 = 14;
const AARCH64_SYS64_ISS_OP1_MASK: u64 = 0x7 << AARCH64_SYS64_ISS_OP1_SHIFT;
const AARCH64_SYS64_ISS_OP2_SHIFT: u64 = 17;
const AARCH64_SYS64_ISS_OP2_MASK: u64 = 0x7 << AARCH64_SYS64_ISS_OP2_SHIFT;
const AARCH64_SYS64_ISS_OP0_SHIFT: u64 = 20;
const AARCH64_SYS64_ISS_OP0_MASK: u64 = 0x3 << AARCH64_SYS64_ISS_OP0_SHIFT;
const AARCH64_SYS64_ISS_SYS_OP_MASK: u64 = AARCH64_SYS64_ISS_OP0_MASK
    | AARCH64_SYS64_ISS_OP1_MASK
    | AARCH64_SYS64_ISS_OP2_MASK
    | AARCH64_SYS64_ISS_CRN_MASK
    | AARCH64_SYS64_ISS_CRM_MASK
    | AARCH64_SYS64_ISS_DIR_READ;

const fn aarch64_sys64_iss_sys_val(op0: u64, op1: u64, op2: u64, crn: u64, crm: u64) -> u64 {
    (op0 << AARCH64_SYS64_ISS_OP0_SHIFT)
        | (op1 << AARCH64_SYS64_ISS_OP1_SHIFT)
        | (op2 << AARCH64_SYS64_ISS_OP2_SHIFT)
        | (crn << AARCH64_SYS64_ISS_CRN_SHIFT)
        | (crm << AARCH64_SYS64_ISS_CRM_SHIFT)
}

pub const AARCH64_SYS64_ISS_SYS_CNTFRQ: u64 =
    aarch64_sys64_iss_sys_val(3, 3, 0, 14, 0) | AARCH64_SYS64_ISS_DIR_READ;
pub const AARCH64_SYS64_ISS_SYS_CNTVCT: u64 =
    aarch64_sys64_iss_sys_val(3, 3, 2, 14, 0) | AARCH64_SYS64_ISS_DIR_READ;
// CTR_EL0 (Cache Type Register) = op0=3 op1=3 CRn=0 CRm=0 op2=1; DCZID_EL0
// (Data Cache Zero ID) = op0=3 op1=3 CRn=0 CRm=0 op2=7. glibc 2.41 (Debian
// trixie / python:3.12-slim) reads CTR_EL0 at startup for the i/d cache line
// sizes; without SCTLR_EL1.UCT that MRS traps to EL1 (EC=0x18) and, unemulated,
// became a fatal SIGSEGV. We enable native EL0 access via SCTLR_EL1.UCT/DZE
// (see trap.rs) AND keep these as the emulate fallback, mirroring CNTVCT.
pub const AARCH64_SYS64_ISS_SYS_CTR: u64 =
    aarch64_sys64_iss_sys_val(3, 3, 1, 0, 0) | AARCH64_SYS64_ISS_DIR_READ;
pub const AARCH64_SYS64_ISS_SYS_DCZID: u64 =
    aarch64_sys64_iss_sys_val(3, 3, 7, 0, 0) | AARCH64_SYS64_ISS_DIR_READ;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum El0SysRegRead {
    CntfrqEl0,
    CntvctEl0,
    CtrEl0,
    DczidEl0,
}

pub fn decode_el0_sys64_read(esr: u64) -> Option<(u8, El0SysRegRead)> {
    if carrick_hal::aarch64::aarch64_exception_class(esr) != AARCH64_SYS64_EXCEPTION_CLASS {
        return None;
    }
    let iss = esr & AARCH64_ESR_ISS_MASK;
    let rt = ((iss & AARCH64_SYS64_ISS_RT_MASK) >> AARCH64_SYS64_ISS_RT_SHIFT) as u8;
    let reg = match iss & AARCH64_SYS64_ISS_SYS_OP_MASK {
        AARCH64_SYS64_ISS_SYS_CNTFRQ => El0SysRegRead::CntfrqEl0,
        AARCH64_SYS64_ISS_SYS_CNTVCT => El0SysRegRead::CntvctEl0,
        AARCH64_SYS64_ISS_SYS_CTR => El0SysRegRead::CtrEl0,
        AARCH64_SYS64_ISS_SYS_DCZID => El0SysRegRead::DczidEl0,
        _ => return None,
    };
    Some((rt, reg))
}

// ESR exception-class decode (svc/hvc/maintenance/syscall classifiers, the
// SVC/HVC class consts, and ExecLevel) live in the shared carrick_hal::aarch64
// module — imported above. This SHIFT is kept local only for the counter-trap
// TESTS that synthesize an ESR syndrome (cntfrq/cntvct/dczid), so it is test-only.
#[cfg(test)]
const AARCH64_EXCEPTION_CLASS_SHIFT: u64 = 26;

#[cfg(test)]
#[path = "esr/tests/sys64.rs"]
mod sys64_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const SIGTRAP: i32 = 5;
    const TRAP_BRKPT: i32 = 1;
    const TRAP_TRACE: i32 = 2;
    const TRAP_HWBKPT: i32 = 4;

    fn esr(ec: u64) -> u64 {
        ec << 26
    }

    #[test]
    fn brk_aarch64_maps_to_sigtrap_brkpt() {
        // EC=0x3c is `BRK #imm` from AArch64 — the in-guest software breakpoint
        // Go's debug-call protocol hits. Linux delivers SIGTRAP/TRAP_BRKPT.
        assert_eq!(el0_debug_signal(esr(0x3c)), Some((SIGTRAP, TRAP_BRKPT)));
    }

    #[test]
    fn software_step_maps_to_sigtrap_trace() {
        // EC=0x32/0x33 software-step exception → SIGTRAP/TRAP_TRACE (PTRACE_SINGLESTEP).
        assert_eq!(el0_debug_signal(esr(0x32)), Some((SIGTRAP, TRAP_TRACE)));
        assert_eq!(el0_debug_signal(esr(0x33)), Some((SIGTRAP, TRAP_TRACE)));
    }

    #[test]
    fn hw_breakpoint_and_watchpoint_map_to_sigtrap_hwbkpt() {
        // EC=0x30/0x31 HW breakpoint, 0x34/0x35 watchpoint → SIGTRAP/TRAP_HWBKPT.
        assert_eq!(el0_debug_signal(esr(0x30)), Some((SIGTRAP, TRAP_HWBKPT)));
        assert_eq!(el0_debug_signal(esr(0x31)), Some((SIGTRAP, TRAP_HWBKPT)));
        assert_eq!(el0_debug_signal(esr(0x34)), Some((SIGTRAP, TRAP_HWBKPT)));
        assert_eq!(el0_debug_signal(esr(0x35)), Some((SIGTRAP, TRAP_HWBKPT)));
    }

    #[test]
    fn non_debug_faults_are_not_debug_signals() {
        // Aborts and unknown classes are NOT debug exceptions — they stay on the
        // SIGSEGV/SIGBUS path (`el0_fault_signal`), so the classifier returns None.
        assert_eq!(el0_debug_signal(esr(0x20)), None); // instruction abort
        assert_eq!(el0_debug_signal(esr(0x24)), None); // data abort
        assert_eq!(el0_debug_signal(esr(0x00)), None); // unknown
    }
}
