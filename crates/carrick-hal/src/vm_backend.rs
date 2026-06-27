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
use std::sync::OnceLock;

/// Process-global hook to tear down a reaped forked child's leaked host VM node.
///
/// A bhyve VM is a NAMED `/dev/vmm/<name>` node that persists until `vm_destroy`
/// (unlike KVM/HVF, whose VMs are fd/process-lifetime bound and released by the OS
/// on `_exit`). A forked guest child `_exit`s past every Drop, and its in-process
/// `process_exit_cleanup` cannot tear the node down — the engine keeps a
/// `BhyveSharedVm` clone, so a live-holder destroy HANGS. Instead the PARENT, when
/// it reaps the child (`wait4`/`waitid`), calls [`reap_child_vm`] with the dead
/// child's HOST pid: the owning process is gone, so opening + destroying the
/// orphaned node is the sole, unambiguous, non-hanging teardown. No-op until a
/// backend installs a hook.
static REAP_CHILD_VM_HOOK: OnceLock<fn(u32)> = OnceLock::new();

/// Install the reap-child-VM hook (set-once; the fn is the same code address in
/// every forked process, so one registration is inherited across `fork`). `f`
/// receives the dead child's host pid.
pub fn set_reap_child_vm_hook(f: fn(u32)) {
    let _ = REAP_CHILD_VM_HOOK.set(f);
}

/// Tear down a reaped child's leaked host VM node, if a backend installed a hook.
/// Called from the dispatcher's `wait4`/`waitid` reap with the dead child's host
/// pid. No-op on KVM/HVF.
pub fn reap_child_vm(host_pid: u32) {
    if let Some(f) = REAP_CHILD_VM_HOOK.get() {
        f(host_pid);
    }
}

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
