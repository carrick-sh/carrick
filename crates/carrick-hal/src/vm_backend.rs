//! The ISA-NEUTRAL slice of the per-VMM backend trait surface.
//!
//! Both ISA axes (`carrick-aarch64`'s `Aarch64Vmm` and `carrick-x86`'s `X86Vmm`)
//! carry a small set of methods whose signatures are character-identical and use
//! NO ISA-specific associated type (`Vcpu`/`SiblingBuilder`/snapshot shapes). That
//! shared slice lives here, as [`GuestVmBackend`], so the two ISA traits inherit
//! it (`Aarch64Vmm: GuestVmBackend`, `X86Vmm: GuestVmBackend`) instead of
//! re-declaring the same methods twice. The genuinely ISA-divergent surface — the
//! memory seam (aarch64 stage-1/2 translated model vs x86 page-table model), the
//! fork/clone choreography, the typed snapshot/restore, exits, and per-vCPU traits
//! — stays in each ISA trait.
//!
//! [`ForkRamStrategy`] lives here too: it was byte-for-byte duplicated in both ISA
//! vmm modules, and is pure POLICY (COW-inherit vs eager full-RAM copy at
//! `fork(2)`) shared by both fork paths.

use crate::TrapError;

/// COW-inherit vs eager full-RAM copy at `fork(2)`. POLICY only: the shared fork
/// path (aarch64 or x86) reads this to decide *whether* to freeze; the per-backend
/// copy MECHANISM stays in the backend (aarch64's `rebuild_child_after_fork`, x86's
/// `freeze_ram`/`rebuild_child_vm`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkRamStrategy {
    /// KVM `MAP_PRIVATE` / NVMM host-fork COW: the child inherits RAM for free,
    /// nothing is copied.
    Cow,
    /// A backend whose guest RAM is `MAP_SHARED` / kernel-owned non-COW (HVF's
    /// windows; bhyve's sysmem): the parent freezes the segment pre-fork and the
    /// child rebuilds a fresh VM from it.
    EagerCopy,
}

/// The ISA-NEUTRAL slice of the per-VMM backend trait. The supertrait of both
/// `Aarch64Vmm` and `X86Vmm`: every method here is signature-identical across the
/// two ISA axes and depends on NO associated type, so it is declared ONCE.
pub trait GuestVmBackend {
    /// The host pointer backing `[gpa, gpa + len)`, or `None` if unmapped. The
    /// engine's `GuestMemory` impl copies through this.
    fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8>;

    /// Mutable variant of [`Self::host_ptr`]. Backends with sparse/lazy backing
    /// may materialize the requested range before returning the host pointer.
    fn host_ptr_mut(&mut self, gpa: u64, len: usize) -> Option<*mut u8> {
        self.host_ptr(gpa, len)
    }

    /// Copy `bytes` into guest physical memory at `gpa`.
    fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), TrapError>;

    /// COW-inherit vs eager copy. KVM/NVMM are `MAP_PRIVATE`/host-fork COW; HVF's
    /// windows and bhyve's sysmem are not, so their children must copy.
    fn fork_ram_strategy(&self) -> ForkRamStrategy;

    /// Forked-child / process `_exit` cleanup (a HOOK, not `Drop` — the forked
    /// child `_exit`s skipping Rust Drops). Default no-op; backends with a
    /// per-process VM node (bhyve) override it.
    fn process_exit_cleanup(&mut self) {}

    /// Backend admission gate before a new vCPU thread runs (HVF's concurrent-vCPU
    /// cap; a no-op on KVM/bhyve/NVMM).
    fn wait_for_vcpu_slot() {}

    /// Live concurrent-vCPU budget N for the M:N admission scheduler. `usize::MAX`
    /// = no carrick-side cap (KVM); a capped backend returns its concurrent cap.
    fn vcpu_budget() -> usize {
        usize::MAX
    }

    /// Whether this backend RECLAIMS a thread's vCPU slot on block (M:N reclaim).
    /// `false` (default) = Phase-1 lifetime-binding (KVM); HVF/bhyve return `true`.
    fn reclaims(&self) -> bool {
        false
    }
}
