//! `Aarch64EngineCore<V>` — the generic aarch64 trap engine scaffold.
//!
//! Mirrors `carrick-x86`'s `X86EngineCore<V>`: implements the `carrick-hal` engine
//! traits ONCE over the thin [`Aarch64Vmm`] / [`Aarch64Vcpu`] trait pair,
//! replacing the two per-VMM copies of the aarch64 trap loop (HVF's
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

use carrick_abi::LinuxSiginfo;
use carrick_guest_mem::protections::MemoryProtections;
use carrick_guest_mem::{Gpa, GuestMemory, GuestVa, HostVa, MemoryError};
use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::{
    ForkOutcome, GuestEntryRegs, OsError, RawSyscall, Reg, SlotId, SysReg, SyscallTrap,
    ThreadedEngine, TrapError,
};
use carrick_mem::memory::AddressSpace;
use carrick_mem::page_table::{PageTableError, PageTableManager};

use crate::vmm::{Aarch64Exit, Aarch64Vcpu, Aarch64VcpuSnapshot, Aarch64Vmm, ForkRamStrategy};

/// The generic aarch64 trap engine. Owns the VM, the (one) vCPU, the
/// pending-syscall resume PC, and the SA_RESTART syscall-number stash.
/// Per-backend behaviour is reached only through the [`Aarch64Vmm`] /
/// [`Aarch64Vcpu`] trait pair.
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

    /// Like [`from_parts`](Self::from_parts) but ADOPTS the spawning thread's
    /// page-table editor + PROT_NONE bookkeeping — used to make a
    /// `clone(CLONE_THREAD)` sibling SHARE its parent's stage-1 manager (same VM,
    /// same backing) and PROT_NONE set. On KVM the PROT_NONE set itself lives in
    /// the backend `GuestRam` (shared via `from_shared_windows`), so this `Arc`
    /// is the engine-side mirror; the page-table `Arc` is the load-bearing share.
    pub fn from_parts_with_shared(
        vm: V,
        vcpu: V::Vcpu,
        page_tables: Arc<Mutex<Option<PageTableManager>>>,
        protections: Arc<MemoryProtections>,
    ) -> Self {
        Self {
            vm,
            vcpu,
            pending_resume_pc: None,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            last_fault_esr: 0,
            last_exit_class: 0,
            is_forked_child: false,
            page_tables,
            protections,
            reclaim_snapshot: None,
        }
    }

    /// Read `len` bytes of live guest memory at guest-physical `gpa` (e.g. a
    /// `write(2)` buffer the guest passed). Backed by the same host RAM the vCPU
    /// sees, so guest writes are visible. (The standalone run-elf loop uses this.)
    pub fn read_guest(&self, gpa: Gpa, len: usize) -> Result<Vec<u8>, TrapError> {
        self.vm.read_gpa(gpa.raw(), len)
    }

    // ── test / bring-up setters (used by the backend crates' unit tests) ──
    // These poke the same engine-owned tracking fields the trap loop maintains, so
    // a per-VMM `#[cfg(test)]` (which lives in another crate and cannot reach the
    // private fields) can assert the fork/execve/inject behaviour. They are plain
    // `pub` (not `#[cfg(test)]`) because the consumers are cross-crate tests, so
    // they are not dead code.

    /// Set the forked-child marker (mirrors what the shared `fork()` does on the
    /// child side). For cross-crate tests of `execve` is_forked_child preservation.
    #[doc(hidden)]
    pub fn set_is_forked_child_for_test(&mut self, v: bool) {
        self.is_forked_child = v;
    }

    /// Set the most-recent-fault ESR stash (the `inject_signal` sigframe input).
    #[doc(hidden)]
    pub fn set_last_fault_esr_for_test(&mut self, v: u64) {
        self.last_fault_esr = v;
    }

    /// Set the SA_RESTART syscall-number / orig-x0 stash.
    #[doc(hidden)]
    pub fn set_last_syscall_for_test(&mut self, nr: Option<u64>, orig_x0: u64) {
        self.last_syscall_nr = nr;
        self.last_syscall_orig_x0 = orig_x0;
    }

    // ── stage-1 page-table edit core (the locked EDIT primitive) ──

    /// Edit the live stage-1 page tables (the guest's own translation tables at
    /// `LINUX_PAGE_TABLES_BASE`) under the shared manager lock and replay the
    /// changed descriptors into the guest page-table backing — the locked EDIT
    /// CORE, WITHOUT a TLB flush. Builds the `PageTableManager` lazily from the
    /// live backing on first use (the boot image already wrote
    /// `stage1_identity_page_tables` there). Returns whether the edit CHANGED any
    /// descriptor (so the caller can skip a pointless flush on a no-op edit).
    ///
    /// This is the no-flush primitive: callers that map a BRAND-NEW VA (no stale
    /// TLB entry, so the guest's first access walks the just-written tables) — e.g.
    /// [`Self::map_host_alias`]'s fresh alias — use [`Self::pt_edit`] directly.
    /// Callers that may RE-protect an already-walked VA route through
    /// [`Self::pt_edit_and_flush`], which runs [`Self::run_el1_maintenance`]
    /// afterwards so the stale stage-1 TLB entry is invalidated.
    fn pt_edit_locked(
        &mut self,
        edit: impl FnOnce(&mut PageTableManager) -> Result<bool, PageTableError>,
    ) -> Result<bool, MemoryError> {
        const PT_BASE: u64 = carrick_mem::memory::LINUX_PAGE_TABLES_BASE;
        let size = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
        let host = self
            .vm
            .host_ptr(PT_BASE, size)
            .ok_or_else(|| MemoryError::HostMap("page-table region not mapped".to_string()))?;
        // `Arc::strong_count > 1` ⟺ a `clone(CLONE_THREAD)` sibling shares THIS
        // page-table manager (the spec clones the Arc into each sibling engine);
        // `== 1` ⟺ this is the SOLE vCPU over the backing. Coalescing reclaims
        // spare sub-tables into the pool — a break-before-make table↔block flip
        // plus a page free, unsafe only if another vCPU holds a stale walk-cache
        // reference to the freed page. So coalesce is safe iff the edit is
        // EXCLUSIVE. The single-vCPU case is provably exclusive here, so re-enable
        // coalescing then (the OutOfTables→ENOMEM-under-churn fix for a
        // single-threaded guest). The multi-vCPU case stays conservative
        // (unsafe_to_coalesce = true): the generic loop's Pause-Modify-Resume pauses
        // siblings + `tlbi vmalle1is`-broadcasts around every threaded stage-1 editor
        // (vcpu_loop.rs pt_pause), but the engine cannot read that barrier from this
        // crate, so it keeps the conservative flag rather than assume the PMR is held.
        //
        // Measure the count BEFORE the local `pt` clone below — the clone adds a
        // reference, so `strong_count(&pt)` is 2 for a SOLE vCPU and `> 1` is
        // ALWAYS true, leaving the sole-vCPU reclaim DEAD and leaking the 440-page
        // table pool under single-threaded mmap churn (CPython multiprocessing's
        // 400+ SemLock map/unmap cycles exhausted it: "stage-1 page-table pool
        // exhausted"). `strong_count(&self.page_tables)` == the live engine count.
        let unsafe_to_coalesce = Arc::strong_count(&self.page_tables) > 1;
        let pt = Arc::clone(&self.page_tables);
        let mut guard = pt.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            // Build from the live guest backing (the boot tables) on first edit —
            // nothing else writes the tables before this, so it matches the image.
            let bytes = self
                .vm
                .read_gpa(PT_BASE, size)
                .map_err(|_| MemoryError::HostMap("read live page tables".to_string()))?;
            // Build through this engine's `GuestArch` MMU codec.
            use carrick_hal::PageTableCodec as _;
            *guard = Some(
                <<Self as ThreadedEngine>::Arch as carrick_hal::GuestArch>::Mmu::new_manager(
                    bytes, PT_BASE,
                ),
            );
        }
        // INVARIANT: populated just above if it was `None` (so the else is dead);
        // a returned Err keeps us clear of the workspace's expect/panic deny lints.
        let Some(mgr) = guard.as_mut() else {
            return Err(MemoryError::HostMap(
                "page-table manager unexpectedly absent".to_string(),
            ));
        };
        mgr.set_multi_vcpu(unsafe_to_coalesce);
        let changed = edit(mgr).map_err(|e| match e {
            PageTableError::OutOfTables => {
                MemoryError::HostMap("stage-1 page-table pool exhausted".to_string())
            }
            PageTableError::BadAddress => MemoryError::OutOfBounds {
                address: 0,
                length: 0,
            },
        })?;
        if changed {
            // SAFETY: `host` backs the live page-table region for the whole process
            // lifetime; the manager writes only 8-byte-aligned descriptor slots
            // within `[host, host + size)`.
            unsafe { mgr.sync_to_host(host) };
        }
        Ok(changed)
    }

    /// Edit the stage-1 tables WITHOUT a TLB flush. For BRAND-NEW VAs only (no
    /// stale TLB entry): the guest's first access walks the just-written tables.
    /// Used by [`Self::map_host_alias`]'s fresh alias mapping — re-protecting an
    /// already-walked VA must instead go through [`Self::pt_edit_and_flush`].
    fn pt_edit(
        &mut self,
        edit: impl FnOnce(&mut PageTableManager) -> Result<bool, PageTableError>,
    ) -> Result<(), MemoryError> {
        self.pt_edit_locked(edit).map(|_changed| ())
    }

    /// Edit the stage-1 tables AND, if any descriptor changed, flush the stale
    /// stage-1 TLB by running the EL1-maintenance trampoline on this vCPU
    /// ([`Self::run_el1_maintenance`]). This makes a RE-protect / `munmap` of an
    /// ALREADY-WALKED page take effect (e.g. `mprotect(PROT_READ)` of a touched RW
    /// page → a subsequent store faults; `munmap` of a touched page → access
    /// faults), where a bare descriptor edit would leave a stale writable TLB entry
    /// live. A no-op edit (range already at the target protection) writes nothing
    /// and skips the flush. Mirrors HVF's `pt_edit_and_flush`.
    ///
    /// Cross-vCPU: the generic threaded loop's Pause-Modify-Resume
    /// (`vcpu_loop.rs` `pt_pause`) has already PAUSED every sibling vCPU out of
    /// guest before this edit runs, and the maintenance trampoline's
    /// `tlbi vmalle1is` is INNER-SHAREABLE, so it broadcasts the invalidation to
    /// the paused siblings' stage-1 TLBs too — multi-threaded correctness comes
    /// from PMR (pause) + the inner-shareable flush, both reused here, not
    /// re-invented.
    fn pt_edit_and_flush(
        &mut self,
        edit: impl FnOnce(&mut PageTableManager) -> Result<bool, PageTableError>,
    ) -> Result<(), MemoryError> {
        let changed = self.pt_edit_locked(edit)?;
        if !changed {
            // Nothing changed (range already at the target protection): no host
            // write happened, so there is no stale TLB entry to flush.
            return Ok(());
        }
        self.run_el1_maintenance()
            .map_err(|e| MemoryError::HostMap(format!("stage-1 TLBI failed: {e}")))
    }

    /// Flush the stale stage-1 TLB after a host page-descriptor edit by running the
    /// EL1 stage-1 maintenance trampoline on THIS vCPU. The trampoline
    /// (`dsb sy; tlbi vmalle1is; dsb sy; isb`) lives at
    /// [`carrick_mem::memory::LINUX_EL1_MAINT_BASE`] and ends in a backend
    /// completion vehicle — KVM's MMIO store to `MAINT_SENTINEL_GPA` (surfaced as
    /// `Aarch64Exit::MaintenanceDone`), in place of HVF's `hvc #1`.
    ///
    /// The vCPU is parked at a syscall (or fault) trap when this runs, so it saves
    /// and restores the interrupted EL1-vector state — PC, PSTATE (CPSR), ELR_EL1,
    /// SPSR_EL1 — AND the two GPRs the trampoline clobbers (x8 the store value, x9
    /// the sentinel-address scratch). With those restored, the in-flight syscall
    /// resumes exactly as before. Mirrors HVF's `run_el1_maintenance`.
    fn run_el1_maintenance(&mut self) -> Result<(), TrapError> {
        // M[3:0]=0b0101 EL1h (SP_EL1) + DAIF masked, PAN(bit22)=0 — the SAME PSTATE
        // boot uses to run the EL0-entry trampoline at EL1 (program_sysregs sets
        // `PSTATE_M_EL1H | DAIF_MASKED`). The maintenance trampoline issues no
        // EL0-accessible store under PAN, so PAN=0 is not strictly required, but
        // matching boot keeps the EL1 entry conditions identical.
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;

        let g = |this: &Self, r: Reg| this.vcpu.get_reg(r);
        // Save the interrupted EL1-vector state + the two scratch GPRs the
        // trampoline clobbers.
        let saved_pc = g(self, Reg::Pc)?;
        let saved_pstate = g(self, Reg::Pstate)?;
        let saved_elr = g(self, Reg::ElrEl1)?;
        let saved_spsr = g(self, Reg::SpsrEl1)?;
        let saved_x8 = g(self, Reg::X(8))?;
        let saved_x9 = g(self, Reg::X(9))?;

        let s = |this: &mut Self, r: Reg, v: u64| this.vcpu.set_reg(r, v);
        s(self, Reg::Pc, carrick_mem::memory::LINUX_EL1_MAINT_BASE)?;
        s(self, Reg::Pstate, AARCH64_PSTATE_EL1H_DAIF_MASKED)?;

        // Run the trampoline to its completion vehicle. A cross-thread kick
        // (`Aarch64Exit::Kicked`) can land mid-flush; the trampoline is tiny and
        // idempotent, so just re-enter it. Any OTHER exit is ambiguous (we cannot
        // trust guest memory visibility) — surface it. (No guest_cpu accounting:
        // this is a host-driven flush, not guest execution time.)
        let result = loop {
            match self.vcpu.run() {
                Ok(Aarch64Exit::MaintenanceDone) => {
                    if std::env::var_os("CARRICK_MAINT_DEBUG").is_some() {
                        eprintln!("[MAINTDBG tid={}] stage-1 TLBI completed", debug_tid());
                    }
                    break Ok(());
                }
                Ok(Aarch64Exit::Kicked) => continue,
                Ok(other) => {
                    break Err(TrapError::UnexpectedExit {
                        reason: format!(
                            "{} during EL1 stage-1 maintenance",
                            exit_variant_name(&other)
                        ),
                    });
                }
                Err(e) => break Err(e),
            }
        };

        // Restore the interrupted EL1-vector state + scratch GPRs on EVERY path so
        // the parked syscall resumes unperturbed even if the flush errored.
        s(self, Reg::Pc, saved_pc)?;
        s(self, Reg::Pstate, saved_pstate)?;
        s(self, Reg::ElrEl1, saved_elr)?;
        s(self, Reg::SpsrEl1, saved_spsr)?;
        s(self, Reg::X(8), saved_x8)?;
        s(self, Reg::X(9), saved_x9)?;
        result
    }

    /// The IPA a syscall buffer at guest VA `va` resolves to. Identity (`va`) for
    /// the common heap/stack/private-mmap pointer — NO page-table walk on the hot
    /// path. Only a `repoint_private` overlay over a shared-aperture VA
    /// ([`carrick_mem::memory::needs_stage1_translation`]) walks the live stage-1
    /// tables to find the overlay IPA whose backing the guest's OWN EL0 accesses
    /// hit (the VA-keyed window still resolves to the STALE shared aperture).
    /// High-VA aliases are EXCLUDED: their backend `WindowDesc::base == va`, so
    /// identity is correct and re-basing on the IPA would miss the window. A walk
    /// miss falls back to `va` (identity), preserving prior behaviour for an
    /// unmapped VA.
    fn syscall_buffer_ipa(&self, va: GuestVa, len: usize) -> Gpa {
        let raw = va.raw();
        if !carrick_mem::memory::needs_stage1_translation(raw, len as u64) {
            return Gpa(raw);
        }
        let guard = self.page_tables.lock().unwrap_or_else(|e| e.into_inner());
        Gpa(guard.as_ref().and_then(|m| m.translate(raw)).unwrap_or(raw))
    }
}

/// Name a non-MaintenanceDone exit for the EL1-maintenance error path (the
/// `Aarch64Exit::Syscall` payload is not `Display`).
fn exit_variant_name(exit: &Aarch64Exit) -> &'static str {
    match exit {
        Aarch64Exit::Syscall { .. } => "Syscall",
        Aarch64Exit::EL0Fault { .. } => "EL0Fault",
        Aarch64Exit::Sys64Read { .. } => "Sys64Read",
        Aarch64Exit::MaintenanceDone => "MaintenanceDone",
        Aarch64Exit::Halt => "Halt",
        Aarch64Exit::Kicked => "Kicked",
        Aarch64Exit::Memory { .. } => "Memory",
    }
}

/// Map an engine-side `TrapError` from a `Vcpu` register read back to an
/// `OsError`, for the `read_aarch64_syscall_frame` closure (which wants `OsError`).
fn trap_to_os(e: TrapError) -> OsError {
    OsError::new(e.to_string())
}

/// The OS thread id for a diagnostic line, portably: `gettid(2)` on Linux (where
/// the KVM lane runs), `0` elsewhere (this crate also compiles on macOS for the
/// later HVF migration, where `SYS_gettid` is absent).
fn debug_tid() -> i64 {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::syscall(libc::SYS_gettid) }
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

// ─── GuestMemory ─────────────────────────────────────────────────────────────
//
// The guest is identity-mapped (stage-1 maps VA == IPA, and the single backend
// memory slot maps IPA == GPA), so a syscall's guest *virtual* pointer is
// numerically the same as its guest-physical address and indexes straight into
// the host backing. `read_bytes`/`write_bytes` move syscall buffers; the PROT_NONE
// gate is the backend's set (shared across siblings); `protect_range`/
// `unmap_range`/`repoint_private` edit the live stage-1 tables so the GUEST's own
// EL0 access honours mmap/mprotect/munmap permissions.

impl<V: Aarch64Vmm> GuestMemory for Aarch64EngineCore<V> {
    /// The PROT_NONE set the shared default `read_bytes`/`write_bytes` gate on
    /// (keyed on the guest VA). The backend owns it (KVM in `GuestRam`, shared
    /// across siblings); `*_raw` does the IPA-translated backing lookup only.
    fn protections(&self) -> Option<&MemoryProtections> {
        self.vm.protections()
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        // PROT_NONE was gated on the guest VA in the default `read_bytes`; here we
        // do the IPA-translated single-region lookup so a `repoint_private` overlay
        // / high-VA alias resolves to the page the guest's OWN EL0 accesses hit —
        // NOT the stale shared-aperture backing the VA still covers. Identity VAs:
        // ipa==address (skips the walk). The copy stays glue (in the backend).
        let ipa = self.syscall_buffer_ipa(GuestVa(address), length).raw();
        self.vm.translated_read(address, ipa, length)
    }

    fn read_into_raw(&self, address: u64, dst: &mut [u8]) -> Result<(), MemoryError> {
        // No-alloc fixed-size read (`read_u32`/`read_u64`/struct headers). The
        // backend may `volatile`-copy straight into `dst` (HVF); the default copies
        // through a `Vec`. PROT_NONE was already gated in `read_into`.
        let ipa = self.syscall_buffer_ipa(GuestVa(address), dst.len()).raw();
        self.vm.translated_read_into(address, ipa, dst)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        // PROT_NONE gated on the guest VA in the default `write_bytes`; backing
        // lookup on the translated IPA (see `read_bytes_raw`). For a
        // `repoint_private` overlay the syscall write lands in the PRIVATE overlay
        // backing the guest reads, not the shared aperture. The backend's
        // `translated_write` ALSO enforces the guest-visible WRITE permission (HVF
        // returns EFAULT on a read-only mapping — audit M1); KVM models none.
        let ipa = self.syscall_buffer_ipa(GuestVa(address), bytes.len()).raw();
        self.vm.translated_write(address, ipa, bytes)
    }

    fn write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        // carrick-INTERNAL frame the guest must receive even into a guest-read-only
        // mapping (vdso vvar, sigframe, bootstrap): bypass the per-mapping WRITE
        // permission (the host page is writable). PROT_NONE is NOT re-gated (the
        // default `write_bytes_unchecked` doesn't gate either). The translated IPA
        // resolves a `repoint_private` overlay to the private backing.
        let ipa = self.syscall_buffer_ipa(GuestVa(address), bytes.len()).raw();
        self.vm.translated_write_unchecked(address, ipa, bytes)
    }

    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        self.vm.guest_range_is_writable(address, length)
    }

    fn host_ptr_for_read(&self, address: u64, len: usize) -> Option<*const u8> {
        self.vm.host_ptr_for_read(address, len)
    }

    fn host_ptr_for_write(&mut self, address: u64, len: usize) -> Option<*mut u8> {
        self.vm.host_ptr_for_write(address, len)
    }

    /// Record/clear a PROT_NONE range so syscall buffers there fault (EFAULT). This
    /// is the HOST-SIDE check only; the COMPLEMENTARY guest-side enforcement (so
    /// the guest's own EL0 access faults) is done by `protect_range`/`unmap_range`/
    /// `unmap_alias_range`, which edit the live stage-1 tables AND flush the stale
    /// TLB via `pt_edit_and_flush` + the EL0-fault→SIGSEGV path.
    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.vm.set_no_access(address, len, no_access);
    }

    /// Scrub the physical backing of `[address, address+len)`, BYPASSING the
    /// PROT_NONE check — used to clear a reused/`munmap`'d region whose stale bytes
    /// must never resurface after a later `mprotect` makes it readable.
    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.vm.zero_backing(address, len)
    }

    /// Host VA of a guest futex word IFF it lives in the `MAP_SHARED` aperture —
    /// routes a guest cross-process (`MAP_SHARED`) futex through the shared
    /// host-`SYS_futex` path on the same physical page. `None` for a private/COW
    /// word (those stay in-process via the parking-lot `FutexTable`).
    fn shared_futex_host_addr(&self, guest_addr: u64) -> Option<usize> {
        // The `GuestMemory` trait method itself stays raw (stage-9 scope); the
        // backend seam below is typed GuestVa → HostVa.
        self.vm
            .shared_futex_host_addr(GuestVa(guest_addr))
            .map(HostVa::raw)
    }

    /// Make a guest `mprotect`/`mmap`'s protection GUEST-visible by editing the
    /// live stage-1 tables. PROT_EXEC clears UXN (executable); its absence sets UXN
    /// (NX / W^X), matching Linux — so the dynamic loader's freshly-mapped library
    /// text (PROT_READ|PROT_EXEC) actually executes instead of permission-faulting
    /// on the NX-by-default arena. (Boot regions — image text, trampolines, vDSO —
    /// are mapped executable at boot and never edited here.)
    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        use carrick_abi::{LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_WRITE};
        let exec = prot & LINUX_PROT_EXEC != 0;
        // pt_edit_AND_FLUSH: a guest can `mprotect` an ALREADY-TOUCHED page (e.g.
        // RELRO RW→RO), so the stale stage-1 TLB entry must be invalidated for the
        // new protection to take effect.
        self.pt_edit_and_flush(|mgr| {
            if prot & LINUX_PROT_WRITE != 0 {
                mgr.set_rw(address, len, exec)
            } else if prot & LINUX_PROT_READ != 0 {
                mgr.set_readonly(address, len, exec)
            } else {
                mgr.set_prot_none(address, len)
            }
        })
    }

    /// `munmap`: invalidate the stage-1 descriptors for `[address, address+len)` so
    /// the guest's own access faults (vs the host-side `no_access` check). The
    /// unmapped range is typically ALREADY-TOUCHED, so flush the stale TLB entry.
    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        // Drop any process-shared alias index entry for this VA range BEFORE the
        // stage-1 invalidate (no-op for the common low-VA arena; HVF's
        // `alias_registry` for a high-VA alias routed here). KVM no-op.
        self.vm.on_unmap(address, len);
        self.pt_edit_and_flush(|mgr| mgr.invalidate(address, len))
    }

    /// `munmap` of a high-VA alias: invalidate AND reclaim the now-empty alias
    /// sub-table(s) (vs `unmap_range`, which keeps the table for the low-VA arena's
    /// in-place reuse). Flush the stale TLB entry. Mirrors HVF.
    fn unmap_alias_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        // The alias backing is freed here; drop the process-shared index entry first
        // so a cross-thread fallback never resolves a now-munmap'd `host_addr` (HVF).
        self.vm.on_unmap(address, len);
        self.pt_edit_and_flush(|mgr| mgr.unmap_aliased(address, len))
    }

    /// Repoint guest VA `[va, va+len)` to a slot in the boot-mapped PRIVATE overlay
    /// aperture (`overlay_ipa`, identity IPA==VA), seeding the slot with `content`
    /// first. Backs a guest `mmap(MAP_FIXED|MAP_PRIVATE|MAP_ANON)` over a
    /// SHARED-aperture VA: carrick's shared aperture is host-`MAP_SHARED`, so it is
    /// inherited across `fork(2)` AND visible to sibling carrick processes —
    /// leaving the VA pointed there would make a guest's "private" stores leak.
    ///
    /// (1) seed the overlay backing FIRST, while `va` still translates to the OLD
    /// (shared) IPA, so no concurrent reader sees a torn page through `va` during
    /// the flip; (2) `pt_edit_and_flush(map_aliased)` repoints the stage-1 leaf
    /// (splitting any covering boot block down to a page leaf) and — because the
    /// dispatcher may have ALREADY touched the overlay VA — runs the EL1-maintenance
    /// TLBI so any stale stage-1 entry is invalidated.
    fn repoint_private(
        &mut self,
        va: u64,
        overlay_ipa: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), MemoryError> {
        // 1. Resolve the overlay slot's host backing pointer (the same resolver the
        //    live page-table editor's `sync_to_host` uses). `len.max(1)` so a
        //    zero-length repoint still resolves the start page.
        let dst = self
            .vm
            .host_ptr(overlay_ipa, len.max(1))
            .ok_or(MemoryError::OutOfBounds {
                address: overlay_ipa,
                length: len,
            })?;
        // 2. Seed `content` into the overlay backing FIRST, while `va` still
        //    translates to the OLD (shared) IPA — no torn read through `va` during
        //    the flip. Copy at most `len` bytes.
        if !content.is_empty() {
            let n = content.len().min(len);
            // SAFETY: `host_ptr` proved `[overlay_ipa, overlay_ipa+len)` lies wholly
            // within the overlay slot's backing, so `dst[..n]` (n <= len) is valid
            // and writable; `content[..n]` is a distinct, valid source slice.
            unsafe {
                std::ptr::copy_nonoverlapping(content.as_ptr(), dst, n);
            }
        }
        // 3. Stage-1 repoint + TLB flush. `map_aliased` splits the covering boot
        //    block to a page leaf so a single page within the shared aperture is
        //    repointed without disturbing its neighbours; the flush invalidates any
        //    stale stage-1 entry for an already-touched overlay VA.
        self.pt_edit_and_flush(|mgr| mgr.map_aliased(va, overlay_ipa, len as u64, true))
    }
}

// ─── RegAccess ───────────────────────────────────────────────────────────────

impl<V: Aarch64Vmm> carrick_hal::RegAccess for Aarch64EngineCore<V> {
    fn get_reg(&self, r: Reg) -> Result<u64, OsError> {
        self.vcpu.get_reg(r).map_err(trap_to_os)
    }
    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), OsError> {
        self.vcpu.set_reg(r, v).map_err(trap_to_os)
    }
    fn get_sys_reg(&self, r: SysReg) -> Result<u64, OsError> {
        self.vcpu.get_sys_reg(r).map_err(trap_to_os)
    }
    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), OsError> {
        self.vcpu.set_sys_reg(r, v).map_err(trap_to_os)
    }
    fn get_vreg(&self, n: u32) -> Result<u128, OsError> {
        self.vcpu.get_vreg(n).map_err(trap_to_os)
    }
    fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), OsError> {
        self.vcpu.set_vreg(n, v).map_err(trap_to_os)
    }
    fn get_fpcr(&self) -> Result<u64, OsError> {
        self.vcpu.get_fpcr().map_err(trap_to_os)
    }
    fn set_fpcr(&mut self, v: u64) -> Result<(), OsError> {
        self.vcpu.set_fpcr(v).map_err(trap_to_os)
    }
    fn get_fpsr(&self) -> Result<u64, OsError> {
        self.vcpu.get_fpsr().map_err(trap_to_os)
    }
    fn set_fpsr(&mut self, v: u64) -> Result<(), OsError> {
        self.vcpu.set_fpsr(v).map_err(trap_to_os)
    }
}

// ─── SyscallTrap ─────────────────────────────────────────────────────────────

impl<V: Aarch64Vmm> SyscallTrap for Aarch64EngineCore<V> {
    fn next_syscall(&mut self) -> Result<Option<RawSyscall>, TrapError> {
        // One guest run per call. The loop exists ONLY to re-enter the guest when a
        // kick lands mid-syscall-trap (the `Kicked` arm); every other exit returns.
        loop {
            // Account the guest's CPU time (wall time inside the backend's guest
            // run) into this thread's guest_cpu slot so getrusage(RUSAGE_SELF) /
            // times / `/proc` see it. Done ONCE here, so every aarch64 backend on
            // this shared engine gets it for free (mirrors carrick-x86).
            let run_result = carrick_host::guest_cpu::timed_run(|| self.vcpu.run());
            match run_result? {
                Aarch64Exit::Syscall { frame, resume_pc } => {
                    // The EL0 `svc` re-entered EL1 and hit the sentinel store. The
                    // hardware already set ELR_EL1 = (svc addr + 4); the EL1
                    // vector's own `eret` (after the sentinel store) consumes it —
                    // so we do NOT touch the PC here; we just read the frame. The
                    // ENGINE owns the pending state (§2.1).
                    self.pending_resume_pc = Some(resume_pc);
                    self.last_syscall_nr = Some(frame.x8);
                    self.last_syscall_orig_x0 = frame.x0;
                    // Decode through this engine's `GuestArch` so the runtime loop is
                    // ISA-neutral: x8 → number, x0..x5 → args. `last_syscall_nr`/
                    // `orig_x0` stay set from the raw frame above (their x8/x0
                    // meaning is aarch64-fixed).
                    let (number, args) = <Self as ThreadedEngine>::Arch::decode_syscall(&frame);
                    let guest_abi = <Self as ThreadedEngine>::Arch::linux_guest_abi();
                    return Ok(Some(RawSyscall {
                        number: carrick_abi::CanonicalNr(number),
                        args,
                        guest_abi,
                        // aarch64 guests already issue canonical numbers, so the
                        // ISA-native number equals the dispatch number.
                        native_number: carrick_abi::NativeNr(number),
                    }));
                }
                Aarch64Exit::EL0Fault {
                    syndrome,
                    elr,
                    far,
                    x16,
                    x17,
                    x29,
                    x30,
                    sp,
                    from_el0_direct,
                } => {
                    // The fault ESR is only valid between fault and delivery; latch
                    // it so `inject_signal` can put it in the arm64 sigframe's
                    // `esr_context` (required by Rosetta's handler).
                    self.last_fault_esr = syndrome;
                    return Err(TrapError::el0_fault(
                        syndrome,
                        elr,
                        far,
                        x16,
                        x17,
                        x29,
                        x30,
                        sp,
                        from_el0_direct,
                    ));
                }
                Aarch64Exit::Sys64Read { esr: _ } => {
                    // An EL0 `MRS` of an emulated ID/timer/cache register (Rosetta
                    // x86-on-arm + HVF). KVM's config never traps `MRS`, so this
                    // never surfaces on the KVM path; a future HVF migration
                    // services it via the shared `emulate_el0_sys64_read` and
                    // re-enters. Re-run the guest for now (no-op on KVM).
                    continue;
                }
                Aarch64Exit::MaintenanceDone => {
                    // The maintenance trampoline's completion vehicle is consumed by
                    // `run_el1_maintenance`'s own loop; reaching it here is a
                    // spurious re-entry — re-run the guest.
                    continue;
                }
                // A WFI/halt with no pending syscall: report `None` so the run loop
                // can run signal delivery and resume.
                Aarch64Exit::Halt => return Ok(None),
                Aarch64Exit::Kicked => {
                    // A cross-thread kick (host signal → KVM_RUN EINTR, e.g. a timer
                    // or `tgkill`) can land while the guest is MID-SYSCALL-TRAP: the
                    // EL0 `svc` has already re-entered EL1 and the vCPU PC is inside
                    // carrick's EL1 vector, with the sentinel-store MMIO not yet
                    // surfaced. Reporting that as a deliverable kick (→ the loop
                    // injects a signal at the EL1-vector PC) corrupts the in-flight
                    // syscall and wedges the guest in an EL0 spin. If the PC is in
                    // the EL1 vector, swallow the kick and re-enter the guest so the
                    // syscall completes; the pending signal is delivered cleanly on
                    // the syscall return. Only a kick taken in genuine guest EL0 code
                    // is reported (`Ok(None)`).
                    let pc = self.vcpu.get_reg(Reg::Pc)?;
                    if carrick_mem::memory::is_carrick_el1_vector_va(pc) {
                        continue;
                    }
                    return Ok(None);
                }
                Aarch64Exit::Memory { gpa, va } => {
                    // A sparse/alias backend (HVF lazy high-VA alias re-map) can
                    // resolve + retry; KVM keeps the default `Ok(false)`. Unhandled
                    // → surface.
                    if self.vm.handle_memory_exit(gpa, va)? {
                        continue;
                    }
                    return Err(TrapError::Hypervisor(format!(
                        "aarch64 backend did not handle memory exit for gpa=0x{gpa:x} va=0x{va:x}"
                    )));
                }
            }
        }
    }

    fn last_syscall_nr(&self) -> Option<u64> {
        self.last_syscall_nr
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        self.vcpu.get_reg(Reg::Pc)
    }

    fn process_exit_cleanup(&mut self) {
        self.vm.process_exit_cleanup();
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        // The pending state is engine-owned; clear it. On aarch64 the EL1 vector's
        // `eret` already consumed ELR_EL1 (= svc+4), so we do NOT re-advance the
        // PC — we just write x0 (and restore x9, below).
        self.pending_resume_pc = None;
        // Write the syscall result into x0. The guest resume PC is already correct:
        // ELR_EL1 (= svc+4) was latched by the exception and is restored by the EL1
        // vector's `eret`. We must NOT advance it again, or the instruction after
        // the `svc` would be skipped.
        self.vcpu.set_reg(Reg::X(0), return_value as u64)?;
        // Restore the guest's x9 IFF this backend's trap vehicle clobbered it. The
        // Linux aarch64 syscall ABI preserves x1..x30 across an `svc`, and musl
        // relies on it (`__expand_heap` holds its malloc-context pointer in x9 across
        // `brk(2)` and then `str x10, [x9, #920]`). KVM's EL1 sentinel vector clobbers
        // x9 as the sentinel-store scratch, so it stashes the guest's x9 in a scratch
        // sysreg (TPIDR_EL1, free at EL0) and returns it as `Some` here. HVF's `hvc #2`
        // vehicle clobbers NO GPR (x9 stays live in the register file), so it returns
        // `None` and we must NOT write x9 — a blanket `set_reg(X9, 0)` would DESTROY
        // the guest's live malloc-context pointer and fault it at `[0 + 920]`
        // (=0x398), the alpine/musl dynamic-binary crash. (glibc never held a live x9
        // across an svc, which masked even the KVM case until alpine/musl.)
        if let Some(saved_x9) = self.vcpu.get_saved_x9()? {
            self.vcpu.set_reg(Reg::X(9), saved_x9)?;
        }
        Ok(())
    }

    fn is_forked_child(&self) -> bool {
        self.is_forked_child
    }

    fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        // 1. Snapshot the parent vCPU register file BEFORE forking, so both sides
        //    resume inside the same trapped syscall site. (Taken while the vCPU is
        //    suspended at the syscall trap — atomic, race-free.)
        let snap = self.vcpu.snapshot()?;
        // The guest's real x9 to carry onto the child (the child resumes straight at
        // the eret and never runs `complete_syscall`). KVM's snapshot captured the
        // CLOBBERED x9 (the sentinel store), so it returns `Some(real_x9)` to repair.
        // HVF's vehicle clobbers no GPR, so its snapshot already holds the live x9 and
        // it returns `None` (and ignores this param in `rebuild_*_after_fork`); 0 is a
        // harmless placeholder there.
        let saved_x9 = self.vcpu.get_saved_x9().ok().flatten().unwrap_or(0);

        // For EagerCopy backends (HVF), freeze RAM pre-fork so the child can rebuild
        // from a coherent image; Cow backends (KVM) lean on Linux COW.
        match self.vm.fork_ram_strategy() {
            ForkRamStrategy::EagerCopy => self.vm.freeze_ram_for_fork()?,
            ForkRamStrategy::Cow => {}
        }

        // Clone the parent's page-table manager VALUE now (under the lock), to seed
        // the child's OWN fresh Arc below. Cloning (vs resetting to None) mirrors
        // HVF: a reset would force a lazy rebuild on the child's first pt_edit, but
        // `syscall_buffer_ipa` is `&self` and CANNOT rebuild — so a forked child
        // that passes a `repoint_private` overlay VA to a syscall BEFORE its first
        // mmap/mprotect/munmap would translate against a None manager, fall back to
        // identity, and read the STALE SHARED aperture instead of its own COW
        // overlay. Cloning lets the child translate immediately. At fork the child's
        // COW table backing == the parent's synced manager bytes, so the clone is
        // exactly what a lazy rebuild from the child's backing would produce.
        let cloned_pt = self
            .page_tables
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        // 2. Real host fork.
        //
        // SAFETY: the run loop quiesces other threads around a guest fork; the
        // calling thread is the only active one here, so no other thread holds the
        // malloc lock (or any other process-global lock) at fork time, and the child
        // inherits a consistent allocator state.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(TrapError::ForkFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        if pid > 0 {
            // PARENT: KVM's live VM is untouched (`rebuild_parent_after_fork` is a
            // no-op). HVF tore its VM down pre-fork (in `freeze_ram_for_fork`), so
            // it MUST rebuild here too — a fresh VM, re-`hv_vm_map` of its own (and
            // the quiesced siblings') buffers, and a register restore from the
            // pre-fork snapshot. Return the child pid so the runtime writes it into
            // the guest's x0.
            self.vm
                .rebuild_parent_after_fork(&mut self.vcpu, &snap, saved_x9)?;
            return Ok(ForkOutcome::Parent {
                child_pid: pid as i32,
            });
        }

        // 3. CHILD: rebuild the VM (per backend) + re-seat the register file (the
        //    backend owns the x0=0 / x9 / sentinel-PC-advance / vDSO re-calibration,
        //    since the PC-advance distance and post-MMIO replay are per-trap-vehicle).
        self.vm
            .rebuild_child_after_fork(&mut self.vcpu, &snap, saved_x9)?;
        self.is_forked_child = true;
        // The child resumes mid-clone; clear stale parent syscall/fault state so a
        // signal arriving before the child's first svc cannot read parent values.
        self.pending_resume_pc = None;
        self.last_syscall_nr = None;
        self.last_syscall_orig_x0 = 0;
        self.last_fault_esr = 0;
        // Give the child its OWN page-table manager — a FRESH Arc, NOT the Arc the
        // parent's CLONE_THREAD siblings still share (so a later child pt_edit can
        // never reach back into the parent's manager). Seeded with the clone taken
        // above (the child's COW table backing == the parent's synced bytes).
        self.page_tables = Arc::new(Mutex::new(cloned_pt));
        Ok(ForkOutcome::Child)
    }

    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError> {
        // Delegate the image replacement to the backend (remap slots / rebuild VM +
        // reprogram the live vCPU's sysregs). PRESERVE is_forked_child across execve:
        // a descendant of a forked child keeps the `_exit`-without-report shutdown
        // path even after it execve's into a different image. The flag is a plain
        // field on `self`, untouched by the remap.
        self.vm.execve_rebuild(&mut self.vcpu, new_image)?;
        // A fresh image has no in-flight syscall or fault.
        self.pending_resume_pc = None;
        self.last_syscall_nr = None;
        self.last_syscall_orig_x0 = 0;
        self.last_fault_esr = 0;
        // `execve_rebuild` wrote fresh `stage1_identity_page_tables` into the new
        // RAM, so the old page-table editor is stale — drop it so the next edit
        // rebuilds from the new image's tables. (execve replaces the whole address
        // space; Linux has already torn down sibling threads, so the shared Arc is
        // moot here.)
        self.page_tables = Arc::new(Mutex::new(None));
        Ok(())
    }

    fn map_host_alias(
        &mut self,
        va: GuestVa,
        ipa: Gpa,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(), TrapError> {
        // Back a dynamic alias mapping: the backend mmaps the host file/anon backing
        // and registers a fresh stage-2 alias slot, returning the (gpa, writable);
        // the engine then builds the VA→gpa stage-1 path via the SHARED
        // `map_aliased`. The dispatcher ALREADY allocated `ipa` from the global alias
        // IPA arena (`crate::memory::alloc_alias_ipa`) and tracks it for the matching
        // `munmap`; HVF MUST map at that exact IPA (re-allocating would double-consume
        // the arena and desync the dispatcher's VA→IPA bookkeeping). KVM IGNORES `ipa`
        // and derives the gpa from the VA inside its <1 TiB arena. No TLBI: the alias
        // VA is brand-new (no stale TLB entry), so the guest's first access walks the
        // just-written tables — the same fresh-page argument as `protect_range`.
        let (gpa, writable) = self.vm.add_alias(va.raw(), ipa.raw(), len, payload, file)?;
        self.pt_edit(|mgr| mgr.map_aliased(va.raw(), gpa, len, writable))
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
        fault_siginfo: Option<(i32, u64)>,
        queued_siginfo: Option<LinuxSiginfo>,
        restart_syscall: bool,
    ) -> Result<(), TrapError> {
        use carrick_hal::RegAccess as _;
        // Choose the resume mechanism by the LIVE exception level, NOT by whether the
        // caller supplied an interrupted_pc. When the vCPU is at EL1 (inside the EL1
        // trampoline — a syscall boundary OR a just-serviced rt_sigreturn), the
        // interrupted USER context is latched in ELR_EL1/SPSR_EL1 and the handler
        // must enter via the pending `eret` (which drops to EL0t). A caller-supplied
        // interrupted_pc is the x86 rt_sigreturn resume-RIP workaround (vcpu_loop
        // sets signal_interrupted_pc after SigReturn); on aarch64 it is an EL1
        // trampoline PC, and taking the "kick" path for it (overwrite the live PC,
        // keep the EL1 PSTATE) would run the handler AT EL1 → its first PXN
        // instruction fetch aborts. Normalising interrupted_pc to None when at EL1
        // routes saved_pc/PSTATE/handler-entry through the eret path so the handler
        // runs at EL0t. Genuine EL0 kicks (the run loop's CANCELED handler guarantees
        // is_guest) keep the live-CPSR kick path. (KVM never sets interrupted_pc on
        // aarch64, so this is inert there.)
        let live_pstate = self.get_reg(Reg::Pstate)?;
        let interrupted_pc = if carrick_hal::aarch64::ExecLevel::from_pstate(live_pstate).is_guest()
        {
            interrupted_pc
        } else {
            None
        };
        // The interrupted PSTATE to save into the sigframe: KICK path (interrupted_pc
        // set, EL0) → the live CPSR we just read; SYSCALL/eret path → SPSR_EL1 where
        // the `svc`/sigreturn-svc latched the EL0 PSTATE. Single-sourced (F7); reuse
        // the already-read `live_pstate` for the kick path.
        let pstate_source =
            carrick_hal::aarch64_signal_pstate_source(interrupted_pc, Some(live_pstate), |r| {
                self.get_reg(r)
            })
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let params = carrick_hal::sigframe::InjectParams {
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc,
            altstack,
            saved_sigmask,
            fault_siginfo,
            queued_siginfo,
            restart_syscall,
            pstate_source,
            orig_x0: self.last_syscall_orig_x0,
            fault_esr: self.last_fault_esr,
            // HVF gates FP/SIMD save on `CARRICK_NO_FPSIMD` (differential measurement);
            // KVM keeps the default `true`.
            fpsimd_enabled: self.vm.fpsimd_enabled(),
            sigreturn_trampoline_base: carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_BASE,
        };
        <Self as ThreadedEngine>::Arch::build_sigframe(self, params)?;
        // The fault ESR is only valid between fault and delivery; clear it so a
        // later async signal doesn't reuse a stale synchronous-fault syndrome.
        self.last_fault_esr = 0;
        Ok(())
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        // fpsimd_enabled MUST match inject_signal. Returns the SAVED SIGMASK — not
        // saved_pc — mirroring the per-backend impls.
        let fpsimd = self.vm.fpsimd_enabled();
        let r = <Self as ThreadedEngine>::Arch::restore_sigframe(self, fpsimd)?;
        Ok(r.sigmask)
    }
}

// ─── ThreadedEngine ──────────────────────────────────────────────────────────

/// The `Send` payload `build_sibling_spec` hands to a freshly spawned host thread,
/// which `materialize_sibling` turns into a sibling engine. Backend-parameterized:
/// the backend supplies how to build a sibling VM/vCPU from `builder`; the SEEDED
/// register snapshot + the SHARED page-table editor / PROT_NONE set ride along so
/// the new vCPU runs in the SAME guest address space on the SAME VM.
pub struct Aarch64SiblingSpec<V: Aarch64Vmm> {
    builder: V::SiblingBuilder,
    snapshot: Aarch64VcpuSnapshot,
    /// The parent's live stage-1 page-table editor, SHARED (Arc clone): a
    /// `clone(CLONE_THREAD)` sibling runs on the SAME VM with the SAME page-table
    /// backing, so its `mmap`/`mprotect` edits must go through the SAME manager.
    page_tables: Arc<Mutex<Option<PageTableManager>>>,
    /// The parent's PROT_NONE bookkeeping, SHARED (Arc clone). On KVM the
    /// load-bearing share is inside the backend `GuestRam` (via
    /// `from_shared_windows`); this is the engine-side mirror.
    protections: Arc<MemoryProtections>,
}

// SAFETY: the snapshot is POD; the page-table / protections `Arc`s are Send+Sync;
// the builder is the backend's own bounded-`Send` payload.
unsafe impl<V: Aarch64Vmm> Send for Aarch64SiblingSpec<V> where V::SiblingBuilder: Send {}

/// Seed a fresh sibling vCPU's register file for a `clone(CLONE_THREAD)` thread.
/// Starts from the parent snapshot (inheriting the SAME stage-1 MMU sysregs +
/// guest address space) then applies the aarch64 thread-entry deltas: x0 = the
/// clone return value, SP_EL0 = the child stack, TPIDR_EL0 = the TLS base,
/// PC = parent.elr_el1 (the post-svc address), and PSTATE = parent.spsr_el1 (the
/// EL0t resume PSTATE the `svc` latched — NOT the EL1h trap-time PSTATE, or the
/// sibling would re-enter at the wrong exception level). FP/SIMD is carried
/// verbatim. This is aarch64-shared logic (lifted from KVM's `seed_sibling_snapshot`).
fn seed_sibling_snapshot(
    parent: &Aarch64VcpuSnapshot,
    entry: GuestEntryRegs,
) -> Aarch64VcpuSnapshot {
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
    // EL1h trap-time PSTATE and re-enters at the wrong exception level.
    snap.pstate = parent.spsr_el1;
    snap
}

impl<V: Aarch64Vmm> ThreadedEngine for Aarch64EngineCore<V> {
    type Arch = carrick_hal::Aarch64GuestArch;
    type KickHandle = V::KickHandle;
    type SiblingSpec = Aarch64SiblingSpec<V>;

    fn kick_handle(&self) -> Self::KickHandle {
        self.vm.kick_handle()
    }

    fn wait_for_vcpu_slot() {
        V::wait_for_vcpu_slot();
    }

    fn vcpu_budget() -> usize {
        V::vcpu_budget()
    }

    fn reclaims(&self) -> bool {
        self.vm.reclaims()
    }

    fn reclaim_refreshes_kicker(&self) -> bool {
        self.vm.reclaim_refreshes_kicker()
    }

    fn save_guest_state(&mut self) -> Vec<u8> {
        // M:N reclaim-on-block. KVM aarch64 does not reclaim (`reclaims()` is false),
        // so this is never called on that path; HVF DESTROYS its vCPU in place here
        // (passing `&mut self.vcpu`) and stashes the snapshot internally, so the
        // returned bytes are unused (empty). On any failure return empty —
        // `rebind_to_slot` then errors (a reclaim failure is fatal to the thread,
        // never silent corruption).
        match self.vm.save_guest_state(&mut self.vcpu) {
            Ok(snap) => serialize_snapshot(&snap),
            Err(_) => Vec::new(),
        }
    }

    fn rebind_to_slot(&mut self, slot: SlotId, state: &[u8]) -> Result<(), TrapError> {
        // HVF stashes the snapshot internally (it destroyed the vCPU in place), so
        // the serialized `state` is empty for it; reconstruct a snapshot only if
        // present (a future serialize-based backend), else hand a zeroed placeholder
        // the HVF rebind ignores (it `take`s its own stashed snapshot). The backend
        // recreates the vCPU and writes it back through `&mut self.vcpu`.
        let snap = deserialize_snapshot(state).unwrap_or_else(zeroed_snapshot);
        self.vm.rebind_to_slot(slot, &snap, &mut self.vcpu)
    }

    fn build_sibling_spec(&self, entry: GuestEntryRegs) -> Result<Self::SiblingSpec, TrapError> {
        // Snapshot the parent vCPU (taken while it is suspended at the trapped
        // `clone` syscall — atomic, race-free), then seed it for the new thread
        // (x0=0, sp_el0=stack, tpidr_el0=tls, pc=parent.elr_el1 = post-svc).
        let parent = self.vcpu.snapshot()?;
        let snapshot = seed_sibling_snapshot(&parent, entry);
        // HVF needs the parent vCPU to clone its VM handle + capture its mapping
        // descriptors into the builder; KVM ignores it. The seeded SNAPSHOT (above)
        // is what the new vCPU is restored from — both backends share that.
        let builder = self.vm.build_sibling_builder(&self.vcpu, entry)?;
        Ok(Aarch64SiblingSpec {
            builder,
            snapshot,
            // Share the SAME page-table editor (Arc clone): the sibling edits the
            // SAME backing through the SAME manager.
            page_tables: Arc::clone(&self.page_tables),
            // Share the SAME PROT_NONE bookkeeping (engine-side mirror; the backing
            // share lives in the backend `GuestRam`).
            protections: Arc::clone(&self.protections),
        })
    }

    fn materialize_sibling(spec: Self::SiblingSpec) -> Result<Self, TrapError> {
        let (vm, mut vcpu) = V::materialize_sibling(spec.builder)?;
        // Restore the seeded register file onto the FRESHLY-CREATED sibling vCPU via
        // `restore_thread_start`: KVM does a plain restore (the PC is already the
        // post-svc address — no sentinel-store replay to skip); HVF routes through
        // its EL0-trampoline thread-start so a brand-new vCPU eret's into EL0 at the
        // post-clone instruction.
        vcpu.restore_thread_start(&spec.snapshot)?;
        // SHARE the spawning thread's page-table editor + PROT_NONE set.
        Ok(Self::from_parts_with_shared(
            vm,
            vcpu,
            spec.page_tables,
            spec.protections,
        ))
    }

    fn program_counter(&self) -> Result<u64, TrapError> {
        self.vcpu.get_reg(Reg::Pc)
    }

    fn set_guest_sp_el0(&self, sp: u64) -> Result<(), TrapError> {
        self.vm.set_guest_sp(&self.vcpu, sp)
    }

    fn set_guest_thread_id(&self, tid: u64) -> Result<(), TrapError> {
        // Stamp the per-thread scratch sysreg the EL1-vector `gettid` fast path
        // reads, so `gettid(2)` is serviced at EL1 without a host trap. Genuinely
        // per-VMM (see `Aarch64Vcpu::stamp_guest_thread_id`): HVF stamps TPIDR_EL1;
        // KVM no-ops (TPIDR_EL1 is its live-x9 stash) and traps `gettid` to the host.
        self.vcpu.stamp_guest_thread_id(tid)
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn carrick_hal::VcpuRegistry> {
        self.vm.fresh_fork_kicker()
    }

    fn fork_vfork(&mut self) -> Result<ForkOutcome, TrapError> {
        // vfork (`CLONE_VM`): the child SHARES the parent's guest RAM. Flag it on the
        // backend (HVF maps the SAME buffers instead of snapshotting private regions;
        // KVM ignores the flag — its fork is plain COW), run the normal fork, then
        // clear the flag so a later plain fork snapshots again.
        self.vm.set_vfork_share(true);
        let r = self.fork();
        self.vm.set_vfork_share(false);
        r
    }

    fn release_vcpu_for_fork(&mut self) -> Result<(), TrapError> {
        // Multithreaded-fork sibling: snapshot + destroy THIS vCPU and publish its
        // regions so the forker re-maps them into the rebuilt VM (HVF). KVM no-op.
        self.vm.release_vcpu_for_fork(&mut self.vcpu)
    }

    fn rebuild_vcpu_after_fork(&mut self) -> Result<(), TrapError> {
        // Multithreaded-fork sibling, step 2: recreate this vCPU in the forker's
        // republished VM and restore the pre-fork register state (HVF). KVM no-op.
        self.vm.rebuild_vcpu_after_fork(&mut self.vcpu)
    }

    fn publish_vm_for_siblings(&mut self) -> Result<(), TrapError> {
        // Forker, after rebuilding its VM: publish a clone for the quiesced siblings
        // to recreate their vCPUs in (HVF). KVM no-op.
        self.vm.publish_vm_for_siblings()
    }

    fn destroy_vcpu_on_thread_exit(&mut self) {
        // A guest thread exiting frees an HVF concurrent-vCPU slot (HVF). KVM no-op.
        self.vm.destroy_vcpu_on_thread_exit(&mut self.vcpu);
    }
}

/// An all-zero [`Aarch64VcpuSnapshot`]. Used as the placeholder the engine hands to
/// a destroy-in-place reclaim backend (HVF), which ignores it and `take`s its own
/// internally-stashed snapshot. A serialize-based backend never hits this path
/// (its `state` deserializes).
fn zeroed_snapshot() -> Aarch64VcpuSnapshot {
    Aarch64VcpuSnapshot {
        gprs: [0; 31],
        pc: 0,
        pstate: 0,
        sp_el0: 0,
        sp_el1: 0,
        elr_el1: 0,
        spsr_el1: 0,
        ttbr0: 0,
        ttbr1: 0,
        tcr: 0,
        sctlr: 0,
        mair: 0,
        vbar: 0,
        cpacr: 0,
        tpidr_el0: 0,
        tpidrro_el0: 0,
        tpidr_el1: 0,
        actlr_el1: 0,
        vregs: [0; 32],
        fpsr: 0,
        fpcr: 0,
    }
}

/// Serialize an [`Aarch64VcpuSnapshot`] for the reclaim save→rebind round-trip
/// (same host thread, so endianness/layout are trivially consistent). KVM aarch64
/// never reclaims, so this is exercised only by a later HVF migration; kept here
/// so the engine is self-contained.
fn serialize_snapshot(s: &Aarch64VcpuSnapshot) -> Vec<u8> {
    let mut buf = Vec::with_capacity(31 * 8 + 17 * 8 + 32 * 16 + 8);
    for g in &s.gprs {
        buf.extend_from_slice(&g.to_le_bytes());
    }
    for v in [
        s.pc,
        s.pstate,
        s.sp_el0,
        s.sp_el1,
        s.elr_el1,
        s.spsr_el1,
        s.ttbr0,
        s.ttbr1,
        s.tcr,
        s.sctlr,
        s.mair,
        s.vbar,
        s.cpacr,
        s.tpidr_el0,
        s.tpidrro_el0,
        s.tpidr_el1,
        s.actlr_el1,
    ] {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    for v in &s.vregs {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    buf.extend_from_slice(&s.fpsr.to_le_bytes());
    buf.extend_from_slice(&s.fpcr.to_le_bytes());
    buf
}

fn deserialize_snapshot(state: &[u8]) -> Option<Aarch64VcpuSnapshot> {
    const GPR_BYTES: usize = 31 * 8;
    const SPECIAL_BYTES: usize = 17 * 8;
    const VREG_BYTES: usize = 32 * 16;
    const TOTAL: usize = GPR_BYTES + SPECIAL_BYTES + VREG_BYTES + 8;
    if state.len() < TOTAL {
        return None;
    }
    let rd64 = |off: usize| -> u64 {
        u64::from_le_bytes(state[off..off + 8].try_into().unwrap_or([0u8; 8]))
    };
    let mut gprs = [0u64; 31];
    for (i, g) in gprs.iter_mut().enumerate() {
        *g = rd64(i * 8);
    }
    let mut o = GPR_BYTES;
    let mut next = || {
        let v = rd64(o);
        o += 8;
        v
    };
    let pc = next();
    let pstate = next();
    let sp_el0 = next();
    let sp_el1 = next();
    let elr_el1 = next();
    let spsr_el1 = next();
    let ttbr0 = next();
    let ttbr1 = next();
    let tcr = next();
    let sctlr = next();
    let mair = next();
    let vbar = next();
    let cpacr = next();
    let tpidr_el0 = next();
    let tpidrro_el0 = next();
    let tpidr_el1 = next();
    let actlr_el1 = next();
    let mut vregs = [0u128; 32];
    for (i, v) in vregs.iter_mut().enumerate() {
        let base = GPR_BYTES + SPECIAL_BYTES + i * 16;
        *v = u128::from_le_bytes(state[base..base + 16].try_into().unwrap_or([0u8; 16]));
    }
    let fp_base = GPR_BYTES + SPECIAL_BYTES + VREG_BYTES;
    let fpsr = u32::from_le_bytes(state[fp_base..fp_base + 4].try_into().unwrap_or([0u8; 4]));
    let fpcr = u32::from_le_bytes(
        state[fp_base + 4..fp_base + 8]
            .try_into()
            .unwrap_or([0u8; 4]),
    );
    Some(Aarch64VcpuSnapshot {
        gprs,
        pc,
        pstate,
        sp_el0,
        sp_el1,
        elr_el1,
        spsr_el1,
        ttbr0,
        ttbr1,
        tcr,
        sctlr,
        mair,
        vbar,
        cpacr,
        tpidr_el0,
        tpidrro_el0,
        tpidr_el1,
        actlr_el1,
        vregs,
        fpsr,
        fpcr,
    })
}

/// `Aarch64EngineCore` is `Send` when the backend pair is: the VM/vCPU hold the
/// host VMM fds (Send) and raw window pointers valid in every thread.
//
// SAFETY: `V`/`V::Vcpu` carry only host VMM fds + raw window pointers that are
// valid in every thread of the process (threads share the address space). The
// engine is moved to its owning sibling/vCPU thread before use.
unsafe impl<V: Aarch64Vmm> Send for Aarch64EngineCore<V> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Aarch64VcpuSnapshot {
        Aarch64VcpuSnapshot {
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
            tpidrro_el0: 0x5678,
            tpidr_el1: 0x9abc,
            actlr_el1: 0x2,
            vregs: [0x9; 32],
            fpsr: 0x11,
            fpcr: 0x22,
        }
    }

    /// The thread-entry deltas are applied and nothing else drifts: the stage-1
    /// MMU sysregs are inherited verbatim (same address space) and the FPSR/FPCR
    /// fields are carried WITHOUT being swapped. (Lifted from the old KVM
    /// `fork::seed_tests`, with the corrected `GuestEntryRegs` signature.)
    #[test]
    fn seed_applies_thread_entry_deltas() {
        let parent = sample();
        let entry = GuestEntryRegs {
            return_value: 0,
            stack: Some(0x7FFF_0000),
            tls: Some(0xCAFE_0000),
        };
        let child = seed_sibling_snapshot(&parent, entry);

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
        // EL0-resume PSTATE: seeded from the parent's SPSR_EL1 (the EL0t PSTATE),
        // NOT the parent's EL1h trap-time pstate.
        assert_eq!(
            child.pstate, parent.spsr_el1,
            "sibling pstate must be the EL0t SPSR_EL1, not the EL1h trap pstate"
        );
        // Inherited verbatim (same guest address space).
        assert_eq!(child.ttbr0, parent.ttbr0);
        assert_eq!(child.sctlr, parent.sctlr);
        assert_eq!(child.vbar, parent.vbar);
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

    /// The reclaim snapshot (de)serialization round-trips every field bit-exact
    /// (same-thread save→rebind; exercised by a later HVF migration).
    #[test]
    fn snapshot_serialization_roundtrips() {
        let s = sample();
        let bytes = serialize_snapshot(&s);
        let back = deserialize_snapshot(&bytes).expect("round-trip");
        assert_eq!(back.gprs, s.gprs);
        assert_eq!(back.pc, s.pc);
        assert_eq!(back.spsr_el1, s.spsr_el1);
        assert_eq!(back.ttbr0, s.ttbr0);
        assert_eq!(back.cpacr, s.cpacr);
        assert_eq!(back.tpidr_el0, s.tpidr_el0);
        assert_eq!(back.vregs, s.vregs);
        assert_eq!(back.fpsr, s.fpsr);
        assert_eq!(back.fpcr, s.fpcr);
        // A short buffer is rejected, not silently zero-filled.
        assert!(deserialize_snapshot(&bytes[..bytes.len() - 1]).is_none());
    }
}
