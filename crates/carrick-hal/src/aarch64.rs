//! AArch64 exception-syndrome (ESR_EL2/ESR_EL1) decode + execution-level
//! classification — pure architectural bitfield math shared by every backend.
//!
//! The TRAP VEHICLE differs per platform (HVF takes an `hvc #2` EL1-vector
//! re-trap, KVM uses an MMIO sentinel store, bhyve surfaces HVC/SMCCC/paging
//! exits), but the SYNDROME DECODE — exception class, svc-vs-hvc, EL0-vs-EL1 —
//! is identical AArch64 semantics. Hoisting it here keeps a third backend from
//! re-deriving the EC shift/mask (a class of subtle off-by-one bugs).

/// ESR exception class for an EL0 `svc` (system call) — `EC = 0x15`.
pub const AARCH64_SVC_EXCEPTION_CLASS: u64 = 0x15;
/// ESR exception class for an `hvc` (hypervisor call) — `EC = 0x16`.
pub const AARCH64_HVC_EXCEPTION_CLASS: u64 = 0x16;

const AARCH64_EXCEPTION_CLASS_SHIFT: u64 = 26;
const AARCH64_EXCEPTION_CLASS_MASK: u64 = 0x3f;

/// The exception class (EC) field — `ESR[31:26]`.
pub fn aarch64_exception_class(syndrome: u64) -> u64 {
    (syndrome >> AARCH64_EXCEPTION_CLASS_SHIFT) & AARCH64_EXCEPTION_CLASS_MASK
}

/// True for an EL0 `svc` (`EC = 0x15`).
pub fn is_aarch64_svc_exception(syndrome: u64) -> bool {
    aarch64_exception_class(syndrome) == AARCH64_SVC_EXCEPTION_CLASS
}

/// True for an `hvc` (`EC = 0x16`).
pub fn is_aarch64_hvc_exception(syndrome: u64) -> bool {
    aarch64_exception_class(syndrome) == AARCH64_HVC_EXCEPTION_CLASS
}

/// True for the EL1 stage-1 maintenance trampoline's `hvc #1` completion
/// marker. The HVC immediate is the low 16 bits of the syndrome ISS. Distinct
/// from the `hvc #2` syscall forward so the maintenance run loop and the
/// syscall trap path never confuse the two.
pub fn is_aarch64_hvc_maintenance(syndrome: u64) -> bool {
    is_aarch64_hvc_exception(syndrome) && (syndrome & 0xffff) == 1
}

/// HVC immediate reserved for the EL1 vector's "unexpected current-EL
/// synchronous exception" trap (`hvc #3`). carrick's guest only ever runs at
/// EL0; a *synchronous* exception taken while the CPU is at EL1 (inside the EL1
/// vector / syscall-shim trampoline) is therefore always a carrick state
/// corruption — e.g. a signal handler entered with SPSR_EL1=EL1h, whose PXN
/// instruction fetch aborts. The current-EL synchronous vector slots issue this
/// `hvc #3` so the host SEES the fault and fails LOUD, instead of the old bare
/// `eret` that silently re-entered the faulting instruction at 100% CPU forever.
pub const AARCH64_HVC_FAULT_IMM: u64 = 3;

/// True for the EL1 vector's `hvc #3` unexpected-current-EL-exception trap.
/// Distinct immediate from `hvc #1` (maintenance) and `hvc #2` (syscall) so the
/// host never confuses a fail-loud EL1 fault with a real syscall forward.
pub fn is_aarch64_hvc_fault(syndrome: u64) -> bool {
    is_aarch64_hvc_exception(syndrome) && (syndrome & 0xffff) == AARCH64_HVC_FAULT_IMM
}

/// True for syscall-shaped traps a host can dispatch identically: EL0 `svc #0`
/// (`EC = 0x15`) and an EL1 vector's `hvc #2` re-trap (`EC = 0x16`). Both
/// deliver the syscall ABI registers unchanged.
pub fn is_aarch64_syscall_exception(syndrome: u64) -> bool {
    is_aarch64_svc_exception(syndrome) || is_aarch64_hvc_exception(syndrome)
}

/// Whether a captured vCPU PC is genuine guest userspace (EL0) or inside
/// carrick's own trap trampoline (EL1+). A captured PC must NOT be treated as a
/// guest resume target unless it is `Guest` — injecting a signal frame at an EL1
/// PC overwrites an in-flight syscall. Classify with [`ExecLevel::from_pstate`]
/// at every point that captures a live vCPU PC for guest use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecLevel {
    /// EL0 — genuine guest userspace. Its PC is a valid guest resume target.
    Guest,
    /// EL1+ — inside carrick's trap trampoline. Its PC is a carrick address.
    Kernel,
}

impl ExecLevel {
    /// Classify from PSTATE/SPSR. `M[3:2]` is the exception level (00 = EL0).
    pub fn from_pstate(pstate: u64) -> Self {
        if (pstate >> 2) & 0b11 == 0 {
            ExecLevel::Guest
        } else {
            ExecLevel::Kernel
        }
    }

    pub fn is_guest(self) -> bool {
        matches!(self, ExecLevel::Guest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esr(ec: u64, iss: u64) -> u64 {
        (ec << 26) | (iss & 0x01ff_ffff)
    }

    #[test]
    fn decodes_svc_hvc_and_maintenance() {
        assert!(is_aarch64_svc_exception(esr(0x15, 0)));
        assert!(!is_aarch64_hvc_exception(esr(0x15, 0)));
        assert!(is_aarch64_hvc_exception(esr(0x16, 2)));
        assert!(is_aarch64_syscall_exception(esr(0x15, 0)));
        assert!(is_aarch64_syscall_exception(esr(0x16, 2)));
        // hvc #1 is the maintenance marker; hvc #2 is the syscall forward.
        assert!(is_aarch64_hvc_maintenance(esr(0x16, 1)));
        assert!(!is_aarch64_hvc_maintenance(esr(0x16, 2)));
        assert!(!is_aarch64_hvc_maintenance(esr(0x15, 1)));
        // hvc #3 is the unexpected-current-EL-exception (fail-loud) marker,
        // distinct from the maintenance (#1) and syscall (#2) immediates.
        assert!(is_aarch64_hvc_fault(esr(0x16, 3)));
        assert!(!is_aarch64_hvc_fault(esr(0x16, 1)));
        assert!(!is_aarch64_hvc_fault(esr(0x16, 2)));
        assert!(!is_aarch64_hvc_fault(esr(0x15, 3)));
        // A #3 HVC must NOT be mistaken for the maintenance marker, and vice
        // versa — the run loop dispatches on these to wholly different paths.
        assert!(!is_aarch64_hvc_maintenance(esr(0x16, 3)));
        // A data abort (EC=0x24) is neither.
        assert!(!is_aarch64_syscall_exception(esr(0x24, 0)));
    }

    #[test]
    fn exec_level_from_pstate() {
        assert_eq!(ExecLevel::from_pstate(0x3c0), ExecLevel::Guest); // EL0t
        assert!(ExecLevel::from_pstate(0x3c0).is_guest());
        assert_eq!(ExecLevel::from_pstate(0x3c5), ExecLevel::Kernel); // EL1h
        assert!(!ExecLevel::from_pstate(0x3c5).is_guest());
    }
}
