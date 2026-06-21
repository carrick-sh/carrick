//! `Aarch64EngineCore<V>` — the generic aarch64 trap engine scaffold.
//!
//! Mirrors `carrick-x86`'s `X86EngineCore<V>`: the eventual goal is to implement
//! the `carrick-hal` engine traits ONCE over the thin
//! [`Aarch64Vmm`](crate::vmm::Aarch64Vmm)/[`Aarch64Vcpu`](crate::vmm::Aarch64Vcpu)
//! trait pair, replacing the two per-VMM copies of the aarch64 trap loop (HVF's
//! `HvfTrapEngine` and KVM's aarch64 `trap_engine`).
//!
//! ## Status — Stage 1 (compile-only scaffold)
//!
//! This struct only DEFINES the engine's owned state today; nothing implements
//! the `carrick-hal` engine traits over it yet, and no backend is wired. The
//! field set is taken from the union of the two existing engines (see the
//! per-field docs for the HVF vs KVM origin).
//!
//! ## The pending-syscall state lives HERE (§2.1)
//!
//! Collapsing each backend's pending-doorbell bookkeeping into the single
//! [`Aarch64Exit::Syscall { resume_pc }`](crate::vmm::Aarch64Exit::Syscall) moves
//! the "which doorbell is pending" state into the engine. On aarch64 there is no
//! SYSRET trampoline — `ELR_EL1` is always live and the EL1 vector's `eret`
//! consumes it — so the engine carries no `sysret_resume` analogue, which makes
//! this core SMALLER than `X86EngineCore`.

use std::sync::{Arc, Mutex};

use carrick_guest_mem::protections::MemoryProtections;
use carrick_mem::page_table::PageTableManager;

use crate::vmm::{Aarch64VcpuSnapshot, Aarch64Vmm};

/// The generic aarch64 trap engine. Owns the VM, the (one) vCPU, the
/// pending-syscall resume PC, and the SA_RESTART syscall-number stash.
/// Per-backend behaviour is reached only through the
/// [`Aarch64Vmm`](crate::vmm::Aarch64Vmm)/[`Aarch64Vcpu`](crate::vmm::Aarch64Vcpu)
/// trait pair.
pub struct Aarch64EngineCore<V: Aarch64Vmm> {
    // ── backend bindings (the only per-VMM members) ──
    /// Owns stage-2 mapping, fork/execve rebuild, sibling spawn.
    vm: V,
    /// The (one) vCPU for this process thread.
    vcpu: V::Vcpu,

    // ── syscall-doorbell state (OWNED BY ENGINE, §2.1; backend run() stateless) ──
    /// Resume PC (= `ELR_EL1`, post-`svc`) for the pending syscall; `Some` between
    /// `next_syscall` and `complete_syscall`. On aarch64 the EL1 vector's `eret`
    /// consumes `ELR_EL1`, so `complete_syscall` sets X0 only and never
    /// re-advances — but we still carry `resume_pc` to detect the trampoline-vs-
    /// direct case and to expose `current_pc` on a non-syscall kick. (x86 calls
    /// this `pending_resume_pc`.)
    pending_resume_pc: Option<u64>,

    /// Linux syscall number (x8) of the most recent trapped `svc`. Feeds the
    /// loop's SA_RESTART decision (`last_syscall_nr()`). `None` before the first
    /// syscall. (Both backends already have this.)
    last_syscall_nr: Option<u64>,

    /// Original x0 of the most recent trapped `svc` (the pre-syscall x0 the
    /// SA_RESTART rewind needs; supplies `InjectParams::orig_x0`). x86 calls this
    /// `last_orig_rax`.
    last_syscall_orig_x0: u64,

    /// `ESR_EL1` of the most recent EL0 synchronous fault (supplies
    /// `InjectParams::fault_esr`; the arm64 sigframe's `esr_context`, required by
    /// Rosetta's handler). Reset to 0 across fork/clone/execve and right after
    /// delivery.
    last_fault_esr: u64,

    // ── trap-surface discriminator (the one aarch64-specific scalar) ──
    /// EC of the most recent exit: did we leave EL0 via `svc` (EC=0x15) or the
    /// EL1 vector's `hvc` (EC=0x16)? `complete_syscall` consults it to know
    /// whether to advance PC past the HVC. HVF-meaningful; on KVM the vector's own
    /// `eret` handles PC, so KVM leaves it at a fixed value. Kept as a plain field
    /// because it is engine policy, not backend state.
    last_exit_class: u64,

    // ── fork marker ──
    /// `true` on the child side of a guest `fork(2)`. Drives the
    /// `_exit`-without-report shutdown path + the `forked=` diagnostic.
    is_forked_child: bool,

    // ── shared memory state (the X86EngineCore parallels) ──
    /// Live stage-1 page-table editor over the guest's own translation tables at
    /// `LINUX_PAGE_TABLES_BASE`. Built lazily on first protect/unmap edit; reset
    /// to a fresh `None` on fork, shared (`Arc` clone) across `CLONE_THREAD`
    /// siblings. The codec is the SHARED `carrick_mem` [`PageTableManager`].
    page_tables: Arc<Mutex<Option<PageTableManager>>>,

    /// Process-wide PROT_NONE ranges; the EFAULT gate on every syscall-buffer
    /// access. SHARED by `CLONE_THREAD` siblings (`Arc` clone), COW'd on fork.
    protections: Arc<MemoryProtections>,

    /// Per-thread reclaim snapshot stash (M:N reclaim-on-block, HVF only today):
    /// `save_guest_state` snapshots this vCPU at a block point, `rebind_to_slot`
    /// restores on wake. The same host thread saves/restores, so a plain `Option`
    /// field.
    reclaim_snapshot: Option<Aarch64VcpuSnapshot>,
}

impl<V: Aarch64Vmm> Aarch64EngineCore<V> {
    /// Build an engine around an already-constructed VM + vCPU (the backend's
    /// bring-up produces these). Mirrors `X86EngineCore::from_parts`: the
    /// tracking fields start cleared, and a freshly brought-up engine gets a
    /// fresh page-table editor and an empty PROT_NONE set. Siblings instead SHARE
    /// the spawning thread's `page_tables`/`protections` via the (later) sibling
    /// constructor.
    pub fn from_parts(vm: V, vcpu: V::Vcpu) -> Self {
        Self {
            vm,
            vcpu,
            pending_resume_pc: None,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            last_fault_esr: 0,
            last_exit_class: 0,
            is_forked_child: false,
            page_tables: Arc::new(Mutex::new(None)),
            protections: Arc::new(MemoryProtections::default()),
            reclaim_snapshot: None,
        }
    }

    /// The backend VM half (stage-2 mapping, fork/execve rebuild, sibling spawn).
    pub fn vm(&self) -> &V {
        &self.vm
    }

    /// Mutable access to the backend VM half.
    pub fn vm_mut(&mut self) -> &mut V {
        &mut self.vm
    }

    /// The (one) vCPU for this process thread.
    pub fn vcpu(&self) -> &V::Vcpu {
        &self.vcpu
    }

    /// Mutable access to the vCPU (the trap-surfacing primitive runs through it).
    pub fn vcpu_mut(&mut self) -> &mut V::Vcpu {
        &mut self.vcpu
    }

    /// The pending syscall resume PC (`Some` between `next_syscall` and
    /// `complete_syscall`).
    pub fn pending_resume_pc(&self) -> Option<u64> {
        self.pending_resume_pc
    }

    /// The Linux syscall number (x8) of the most recent trapped `svc` (the
    /// SA_RESTART input).
    pub fn last_syscall_nr(&self) -> Option<u64> {
        self.last_syscall_nr
    }

    /// The pre-syscall x0 of the most recent trapped `svc` (the SA_RESTART rewind
    /// input).
    pub fn last_syscall_orig_x0(&self) -> u64 {
        self.last_syscall_orig_x0
    }

    /// The `ESR_EL1` of the most recent EL0 synchronous fault.
    pub fn last_fault_esr(&self) -> u64 {
        self.last_fault_esr
    }

    /// The EC of the most recent exit (the `svc`-vs-`hvc` trap-surface
    /// discriminator).
    pub fn last_exit_class(&self) -> u64 {
        self.last_exit_class
    }

    /// Whether this engine is the child side of a guest `fork(2)`.
    pub fn is_forked_child(&self) -> bool {
        self.is_forked_child
    }

    /// The shared stage-1 page-table editor handle (cloned across `CLONE_THREAD`
    /// siblings, reset on fork).
    pub fn page_tables(&self) -> &Arc<Mutex<Option<PageTableManager>>> {
        &self.page_tables
    }

    /// The shared PROT_NONE EFAULT gate (cloned across `CLONE_THREAD` siblings,
    /// COW'd on fork).
    pub fn protections(&self) -> &Arc<MemoryProtections> {
        &self.protections
    }

    /// The per-thread reclaim snapshot stash (M:N reclaim-on-block).
    pub fn reclaim_snapshot(&self) -> Option<&Aarch64VcpuSnapshot> {
        self.reclaim_snapshot.as_ref()
    }
}
