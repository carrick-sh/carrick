//! `fork(2)` support for the KVM backend: the [`VcpuSnapshot`] register-file
//! capture used to clone the parent vCPU's architectural state onto the child's
//! freshly-rebuilt vCPU.
//!
//! Approach A (lean on Linux COW): KVM's VM/vCPU fds are per-process and NOT
//! usefully inherited across `libc::fork`, so after the fork the CHILD builds a
//! brand-new [`crate::kvm::KvmVm`] over the COW-inherited host mmaps and restores
//! this snapshot, while the PARENT keeps its live VM untouched. Because the guest
//! RAM windows are `MAP_PRIVATE|MAP_ANONYMOUS` (except the `MAP_SHARED` aperture),
//! Linux COW gives correct POSIX fork divergence for free — no `mincore` snapshot
//! and no per-region clone (unlike the HVF backend, whose RAM is `MAP_SHARED`).

/// Snapshot of a vCPU's architectural register file, taken on the parent before
/// `fork(2)` and restored onto the child's rebuilt vCPU so it resumes exactly
/// where the parent left off (inside the trapped `clone`/`fork` syscall).
///
/// FP/SIMD state (`vregs`/`fpsr`/`fpcr`) is STUBBED to zero in Phase 2 — full
/// FP/SIMD capture is Phase 4. The fields are kept here so Task 5 (threads) can
/// reuse this struct without an ABI change; `.fpsr` holds FPSR and `.fpcr` holds
/// FPCR (do not swap).
#[derive(Debug, Clone)]
pub struct VcpuSnapshot {
    /// X0..X30 (the general-purpose register file).
    pub gprs: [u64; 31],
    pub pc: u64,
    pub pstate: u64,
    /// `user_pt_regs.sp` == SP_EL0 (the EL0/user stack pointer).
    pub sp_el0: u64,
    pub sp_el1: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub ttbr0: u64,
    pub ttbr1: u64,
    pub tcr: u64,
    pub sctlr: u64,
    pub mair: u64,
    pub vbar: u64,
    pub cpacr: u64,
    /// TPIDR_EL0 — the EL0 thread pointer (libc TLS base).
    pub tpidr_el0: u64,
    /// V0..V31. Phase 4 captures these; zero-stubbed in Phase 2.
    pub vregs: [u128; 32],
    /// FPSR. Phase 4; zero-stubbed in Phase 2.
    pub fpsr: u32,
    /// FPCR. Phase 4; zero-stubbed in Phase 2.
    pub fpcr: u32,
}

/// Seed a fresh sibling vCPU's register file for a `clone(CLONE_THREAD)` thread
/// (Task 5). Starts from the parent's [`VcpuSnapshot`] — so the new thread
/// inherits the same stage-1 MMU sysregs (TTBR0/1, TCR, SCTLR, MAIR, VBAR,
/// CPACR) and runs in the SAME guest address space — then applies the four
/// thread-entry deltas Linux `clone` establishes for the new thread:
///
/// - `gprs[0] = 0` — the child's `clone`/`syscall` return value (it returns 0,
///   like the child side of `fork`).
/// - `sp_el0 = stack` — the new thread's user stack (`child_stack` arg to
///   `clone`). Uses [`carrick_hal::Reg::Sp`] semantics (SP_EL0), NOT a sysreg.
/// - `tpidr_el0 = tls` — the new thread's TLS base (the `tls` arg to `clone`,
///   set when `CLONE_SETTLS` is requested; glibc always passes it for threads).
/// - `pc = parent.elr_el1` — the guest PC just past the trapped `clone` `svc`.
///   At the trap the parent vCPU is suspended on the EL1 vector's sentinel
///   store with `ELR_EL1` already latched to (svc + 4); the sibling's PC is
///   seeded to that post-svc address.
/// - `pstate = parent.spsr_el1` — the EL0t resume PSTATE (Phase 2 Task 7 carry,
///   spec §D). The parent snapshot's `pstate` is the EL1h **trap-time** PSTATE
///   (the exception level at which the vCPU is suspended on the sentinel store),
///   so a sibling restored with it would re-enter at EL1, not EL0. The
///   architecturally-correct EL0t PSTATE was latched into `SPSR_EL1` by the
///   hardware on the `svc` exception; copying it into the sibling's `pstate`
///   makes the new vCPU resume directly at EL0 (mode `0b0000` = EL0t) with the
///   right DAIF/condition flags — exactly where the parent's guest thread is
///   about to resume after its `eret`. (We start the sibling at EL0 directly
///   rather than routing through an EL1-vector `eret`; both are valid, this is
///   simpler since the sibling has no pending-MMIO sentinel store to replay.)
///
/// FP/SIMD (`vregs`/`fpsr`/`fpcr`) is carried verbatim (`.fpsr` stays FPSR,
/// `.fpcr` stays FPCR — do NOT swap); it is zero-stubbed until Phase 4.
pub fn seed_sibling_snapshot(
    parent: &VcpuSnapshot,
    entry: carrick_hal::GuestEntryRegs,
) -> VcpuSnapshot {
    let mut snap = parent.clone();
    snap.gprs[0] = entry.return_value;
    if let Some(stack) = entry.stack {
        snap.sp_el0 = stack;
    }
    if let Some(tls) = entry.tls {
        snap.tpidr_el0 = tls;
    }
    snap.pc = parent.elr_el1;
    // EL0-resume PSTATE: the SPSR latched on the parent's `svc` trap IS the EL0t
    // PSTATE the new thread must run with. Without this the sibling restores the
    // EL1h trap-time PSTATE and re-enters at the wrong exception level (spec §D).
    snap.pstate = parent.spsr_el1;
    snap
}

#[cfg(test)]
mod seed_tests {
    use super::*;

    fn sample() -> VcpuSnapshot {
        VcpuSnapshot {
            gprs: [0xAA; 31],
            pc: 0x1000,
            pstate: 0x3c0,
            sp_el0: 0xDEAD,
            sp_el1: 0xBEEF,
            elr_el1: 0x4000_0000,
            spsr_el1: 0x5,
            ttbr0: 0x100,
            ttbr1: 0x100,
            tcr: 0x200,
            sctlr: 0x300,
            mair: 0xFF,
            vbar: 0x400,
            cpacr: 0x3 << 20,
            tpidr_el0: 0x1234,
            vregs: [0; 32],
            fpsr: 0x11,
            fpcr: 0x22,
        }
    }

    /// The four thread-entry deltas are applied and nothing else drifts: the
    /// stage-1 MMU sysregs are inherited verbatim (same address space) and the
    /// FPSR/FPCR fields are carried WITHOUT being swapped.
    #[test]
    fn seed_applies_thread_entry_deltas() {
        let parent = sample();
        let child = seed_sibling_snapshot(&parent, 0x7FFF_0000, 0xCAFE_0000);

        // The four deltas.
        assert_eq!(child.gprs[0], 0, "x0 (clone return value) must be 0");
        assert_eq!(child.sp_el0, 0x7FFF_0000, "sp_el0 must be the child stack");
        assert_eq!(
            child.tpidr_el0, 0xCAFE_0000,
            "tpidr_el0 must be the tls arg"
        );
        assert_eq!(
            child.pc, parent.elr_el1,
            "pc must be the post-svc address (parent.elr_el1)"
        );

        // Inherited verbatim (same guest address space).
        assert_eq!(child.ttbr0, parent.ttbr0);
        assert_eq!(child.ttbr1, parent.ttbr1);
        assert_eq!(child.tcr, parent.tcr);
        assert_eq!(child.sctlr, parent.sctlr);
        assert_eq!(child.mair, parent.mair);
        assert_eq!(child.vbar, parent.vbar);
        assert_eq!(child.cpacr, parent.cpacr);
        assert_eq!(child.spsr_el1, parent.spsr_el1);
        // EL0-resume PSTATE (Task 7 fix): the sibling's pstate is seeded from the
        // parent's SPSR_EL1 (the EL0t PSTATE), NOT the parent's EL1h trap-time
        // pstate — so the new vCPU resumes at EL0.
        assert_eq!(
            child.pstate, parent.spsr_el1,
            "sibling pstate must be the EL0t SPSR_EL1, not the EL1h trap pstate"
        );

        // The other GPRs are inherited (x1..x30 unchanged).
        for n in 1..31 {
            assert_eq!(child.gprs[n], parent.gprs[n], "x{n} must be inherited");
        }

        // FPSR/FPCR carried, NOT swapped.
        assert_eq!(
            child.fpsr, parent.fpsr,
            "fpsr must NOT be swapped with fpcr"
        );
        assert_eq!(
            child.fpcr, parent.fpcr,
            "fpcr must NOT be swapped with fpsr"
        );
    }
}
