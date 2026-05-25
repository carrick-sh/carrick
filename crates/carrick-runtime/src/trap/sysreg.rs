//! AArch64 EL0 system-register trap decoding.

pub(super) const AARCH64_SYS64_EXCEPTION_CLASS: u64 = 0x18;
const AARCH64_ESR_ISS_MASK: u64 = (1 << 25) - 1;
const AARCH64_SYS64_ISS_DIR_READ: u64 = 0x1;
pub(super) const AARCH64_SYS64_ISS_RT_SHIFT: u64 = 5;
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
pub(super) const AARCH64_GUEST_COUNTER_HZ: u64 = 1_000_000_000;

const fn aarch64_sys64_iss_sys_val(op0: u64, op1: u64, op2: u64, crn: u64, crm: u64) -> u64 {
    (op0 << AARCH64_SYS64_ISS_OP0_SHIFT)
        | (op1 << AARCH64_SYS64_ISS_OP1_SHIFT)
        | (op2 << AARCH64_SYS64_ISS_OP2_SHIFT)
        | (crn << AARCH64_SYS64_ISS_CRN_SHIFT)
        | (crm << AARCH64_SYS64_ISS_CRM_SHIFT)
}

pub(super) const AARCH64_SYS64_ISS_SYS_CNTFRQ: u64 =
    aarch64_sys64_iss_sys_val(3, 3, 0, 14, 0) | AARCH64_SYS64_ISS_DIR_READ;
pub(super) const AARCH64_SYS64_ISS_SYS_CNTVCT: u64 =
    aarch64_sys64_iss_sys_val(3, 3, 2, 14, 0) | AARCH64_SYS64_ISS_DIR_READ;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum El0SysRegRead {
    CntfrqEl0,
    CntvctEl0,
}

pub(super) fn decode_el0_sys64_read(esr: u64) -> Option<(u8, El0SysRegRead)> {
    if super::aarch64_exception_class(esr) != AARCH64_SYS64_EXCEPTION_CLASS {
        return None;
    }
    let iss = esr & AARCH64_ESR_ISS_MASK;
    let rt = ((iss & AARCH64_SYS64_ISS_RT_MASK) >> AARCH64_SYS64_ISS_RT_SHIFT) as u8;
    let reg = match iss & AARCH64_SYS64_ISS_SYS_OP_MASK {
        AARCH64_SYS64_ISS_SYS_CNTFRQ => El0SysRegRead::CntfrqEl0,
        AARCH64_SYS64_ISS_SYS_CNTVCT => El0SysRegRead::CntvctEl0,
        _ => return None,
    };
    Some((rt, reg))
}

/// Read the host's ARM generic-timer virtual count and frequency at EL0. With
/// `CNTKCTL_EL1.EL0VCTEN` set, the guest reads the SAME counter via CNTVCT_EL0,
/// so these calibrate the vDSO's clock conversion. (macOS allows EL0 reads of
/// both registers.)
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn host_counter() -> (u64, u64) {
    let (cntvct, cntfrq): (u64, u64);
    // SAFETY: cntvct_el0/cntfrq_el0 are unprivileged reads on aarch64 macOS.
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) cntvct, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) cntfrq, options(nomem, nostack));
    }
    (cntvct, cntfrq)
}

pub(super) fn guest_counter_ticks() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}
