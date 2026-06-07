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
