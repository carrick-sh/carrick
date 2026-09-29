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

/// HVC immediate reserved for the EL1 vector's lower-EL IRQ kick boundary trap (`hvc #4`).
pub const AARCH64_HVC_KICK_IMM: u64 = 4;

/// True for the EL1 vector's `hvc #4` kick boundary trap.
pub fn is_aarch64_hvc_kick(syndrome: u64) -> bool {
    is_aarch64_hvc_exception(syndrome) && (syndrome & 0xffff) == AARCH64_HVC_KICK_IMM
}

/// The DAIF bits of every EL0 PSTATE Carrick shows the guest: all four
/// masked (`0x3c0`), as Carrick has always run guest EL0. Under the in-kernel
/// GIC (EL1 plan 1c) EL0 runs with `I` clear so the virtual timer and SGIs
/// reach Carrick's EL1 kernel; the guest never sees that bit, because every
/// PSTATE it can read (a signal frame's `pstate`, a core file's `pstate`)
/// passes through [`el0_visible_pstate`].
pub const AARCH64_EL0_VISIBLE_DAIF: u64 = 0x3c0;

/// The guest-visible form of an interrupted EL0 PSTATE: its NZCV and other
/// fields as they are, DAIF as [`AARCH64_EL0_VISIBLE_DAIF`].
pub const fn el0_visible_pstate(pstate: u64) -> u64 {
    pstate | AARCH64_EL0_VISIBLE_DAIF
}

/// HVC immediate of the EL1 vector's idle exit (`hvc #5`, EL1 plan 1c): the
/// vCPU's thread parked in the in-guest scheduler, nothing else was runnable,
/// and host work arrived while the vCPU idled. No thread is on the vCPU; the
/// parked thread's context is in its zone record.
pub const AARCH64_HVC_IDLE_IMM: u64 = 5;

/// True for the EL1 vector's `hvc #5` idle exit.
pub fn is_aarch64_hvc_idle(syndrome: u64) -> bool {
    is_aarch64_hvc_exception(syndrome) && (syndrome & 0xffff) == AARCH64_HVC_IDLE_IMM
}

/// HVC immediate of the EL1 metadata extent grant / return hypercall (`hvc #6`).
pub const AARCH64_HVC_METADATA_GRANT_IMM: u64 = 6;

/// True for the EL1 metadata extent grant / return hypercall (`hvc #6`).
pub fn is_aarch64_hvc_metadata_grant(syndrome: u64) -> bool {
    is_aarch64_hvc_exception(syndrome) && (syndrome & 0xffff) == AARCH64_HVC_METADATA_GRANT_IMM
}

/// True for syscall-shaped traps a host can dispatch identically: EL0 `svc #0`
/// (`EC = 0x15`) and an EL1 vector's `hvc #2` re-trap (`EC = 0x16`). Both
/// deliver the syscall ABI registers unchanged.
pub fn is_aarch64_syscall_exception(syndrome: u64) -> bool {
    is_aarch64_svc_exception(syndrome)
        || (is_aarch64_hvc_exception(syndrome)
            && !is_aarch64_hvc_maintenance(syndrome)
            && !is_aarch64_hvc_fault(syndrome)
            && !is_aarch64_hvc_kick(syndrome)
            && !is_aarch64_hvc_idle(syndrome)
            && !is_aarch64_hvc_metadata_grant(syndrome))
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

/// The `svc #0` opcode HvPatch's syscall islands reissue.
const AARCH64_SVC_ZERO: u32 = 0xd400_0001;
const AARCH64_B_OPCODE: u32 = 0x1400_0000;
const AARCH64_B_OPCODE_MASK: u32 = 0xfc00_0000;

/// Recover an HvPatch syscall island's original `svc #0` instruction address
/// (NOT `+4` — see below) from its return-branch address.
///
/// HvPatch's direct-execution pivot replaces a guest `svc #0` with a branch
/// to a per-site island: the island itself re-issues `svc #0` (so the trap
/// the host takes is architecturally identical) followed by an
/// unconditional `B` back to `original_svc_addr + 4`. A thread the host or
/// the in-guest scheduler parks mid-syscall therefore has its saved PC
/// addressing the ISLAND's return-branch instruction, not guest `.text` — an
/// address that exists in no ELF program header and that no Linux-visible
/// consumer (a core file's `NT_PRSTATUS.pc`, `ptrace`, a signal frame) may
/// ever see published as-is.
///
/// `resume_pc` is the return-branch instruction's own address; `svc` and
/// `return_branch` are the 32-bit words the caller already read from
/// `resume_pc - 4` and `resume_pc` (the two instructions every island begins
/// with). Returns `None` when the bytes do not match that exact shape — a
/// live EL0 PC that is not, in fact, inside an island — so every caller
/// falls back to the untranslated `resume_pc` rather than publishing a wrong
/// guess.
///
/// This returns the SVC INSTRUCTION'S OWN address, not `+4`: a caller that
/// wants a symbol to look up (a wait diagnostic) uses it directly, one that
/// wants the Linux-visible resume PC of a thread blocked in that syscall
/// (a core file, `ptrace`) adds 4 itself — two different, legitimate
/// meanings from the one address this decodes.
pub fn decode_hvpatch_island_origin(resume_pc: u64, svc: u32, return_branch: u32) -> Option<u64> {
    if svc != AARCH64_SVC_ZERO || return_branch & AARCH64_B_OPCODE_MASK != AARCH64_B_OPCODE {
        return None;
    }
    let imm26 = i64::from(return_branch & 0x03ff_ffff);
    let signed_imm26 = (imm26 << 38) >> 38;
    let target = i128::from(resume_pc).checked_add(i128::from(signed_imm26) * 4)?;
    let origin = target.checked_sub(4)?;
    u64::try_from(origin).ok()
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
        assert!(!is_aarch64_syscall_exception(esr(0x16, 1)));
        // hvc #3 is the unexpected-current-EL-exception (fail-loud) marker,
        // distinct from the maintenance (#1) and syscall (#2) immediates.
        assert!(is_aarch64_hvc_fault(esr(0x16, 3)));
        assert!(!is_aarch64_hvc_fault(esr(0x16, 1)));
        assert!(!is_aarch64_hvc_fault(esr(0x16, 2)));
        assert!(!is_aarch64_hvc_fault(esr(0x15, 3)));
        assert!(!is_aarch64_syscall_exception(esr(0x16, 3)));
        // hvc #4 is the kick marker.
        assert!(is_aarch64_hvc_kick(esr(0x16, 4)));
        assert!(!is_aarch64_syscall_exception(esr(0x16, 4)));
        // hvc #5 is the idle marker.
        assert!(is_aarch64_hvc_idle(esr(0x16, 5)));
        assert!(!is_aarch64_syscall_exception(esr(0x16, 5)));
        // hvc #6 is the metadata grant marker.
        assert!(is_aarch64_hvc_metadata_grant(esr(0x16, 6)));
        assert!(!is_aarch64_syscall_exception(esr(0x16, 6)));
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

    /// `B <target>` at address `from`, exactly as HvPatch's island writer
    /// encodes the return branch.
    fn encode_b(from: u64, target: u64) -> u32 {
        let delta = (target as i64) - (from as i64);
        assert_eq!(delta % 4, 0, "branch target must be word-aligned");
        let imm26 = ((delta / 4) as u32) & 0x03ff_ffff;
        AARCH64_B_OPCODE | imm26
    }

    #[test]
    fn decodes_an_islands_return_branch_back_to_the_original_svc() {
        // A real island shape: guest svc at 0x210270 (so Linux-visible resume
        // pc is 0x210274), island placed well outside the guest's own image
        // at 0x234000, whose return branch (at 0x234004) targets 0x210274 --
        // exactly the fixture layout that produced the reported bug.
        const ORIGINAL_SVC: u64 = 0x210270;
        const ISLAND_RETURN_BRANCH: u64 = 0x234004;
        let return_branch = encode_b(ISLAND_RETURN_BRANCH, ORIGINAL_SVC + 4);

        let origin =
            decode_hvpatch_island_origin(ISLAND_RETURN_BRANCH, AARCH64_SVC_ZERO, return_branch)
                .expect("island shape must decode");
        assert_eq!(
            origin, ORIGINAL_SVC,
            "decode returns the svc's own address, not +4"
        );
        assert_eq!(
            origin + 4,
            ORIGINAL_SVC + 4,
            "a caller wanting the Linux-visible resume pc adds 4 itself"
        );
    }

    #[test]
    fn refuses_bytes_that_are_not_an_island() {
        // The word before a live, untranslated EL0 pc is ordinary guest code,
        // essentially never `svc #0` followed by a `B`; a caller must fall
        // back to the untranslated pc rather than publish a wrong guess.
        assert_eq!(
            decode_hvpatch_island_origin(
                0x210274,
                0x9100_0fe0, /* add x0, sp, #0 */
                0x1400_0002
            ),
            None,
            "the preceding word must be exactly svc #0"
        );
        assert_eq!(
            decode_hvpatch_island_origin(0x210274, AARCH64_SVC_ZERO, 0xd503_201f /* nop */),
            None,
            "the following word must decode as a B instruction"
        );
    }

    #[test]
    fn round_trips_across_a_negative_branch_offset() {
        // The island can sit either side of the guest image; a return branch
        // to a LOWER address must decode identically to a higher one.
        const ORIGINAL_SVC: u64 = 0x400000;
        const ISLAND_RETURN_BRANCH: u64 = 0x100004;
        let return_branch = encode_b(ISLAND_RETURN_BRANCH, ORIGINAL_SVC + 4);
        assert_eq!(
            decode_hvpatch_island_origin(ISLAND_RETURN_BRANCH, AARCH64_SVC_ZERO, return_branch),
            Some(ORIGINAL_SVC)
        );
    }
}
