//! KvmTrapEngine: drives a `KvmVcpu` to implement the `carrick-hal`
//! `SyscallTrap` contract. `next_syscall` runs KVM_RUN until the EL1 vector's
//! sentinel store surfaces as `VcpuExit::MmioWrite { gpa: SENTINEL_GPA, .. }`,
//! reads x0..x5,x8 into an `Aarch64SyscallFrame`, and returns it.
use std::sync::{Arc, Mutex};

use carrick_abi::LinuxSiginfo;
use carrick_guest_mem::{Aarch64SyscallFrame, GuestMemory, MemoryError};
use carrick_hal::{
    ForkOutcome, HvVcpu, HvVm, MemPerms, OsError, Reg, SysReg, SyscallTrap, TrapError, VcpuExit,
};
use carrick_mem::memory::AddressSpace;
use carrick_mem::protections::MemoryProtections;

use crate::fork::{VcpuSnapshot, seed_sibling_snapshot};
use crate::guest_setup::{
    BroughtUp, FAULT_SENTINEL_GPA, GuestRam, SENTINEL_GPA, WindowDesc, bring_up,
    populate_vdso_vvar, program_sysregs,
};
use crate::kvm::{KvmVcpu, KvmVm, SharedVmHandle};
use crate::kvm_kicker::{KvmKickHandle, KvmKicker};

pub struct KvmTrapEngine {
    /// The live VM. Held (not `_`-prefixed) because `fork` swaps in a freshly
    /// rebuilt VM on the child side; the field's host-mmap-backed slots must
    /// stay alive for the new vCPU to run.
    vm: KvmVm,
    vcpu: KvmVcpu,
    ram: GuestRam,
    /// Set `true` on the child side of a guest `fork(2)`. Preserved across a
    /// later `execve` (Task 4) so exit-reporting can distinguish a forked child;
    /// mirrors the HVF backend's `is_forked_child`. Default `false`.
    is_forked_child: bool,
    /// Linux syscall number (x8) of the most recent trapped `svc`. Feeds the
    /// shared loop's SA_RESTART decision (`vcpu_loop.rs` calls `last_syscall_nr()`,
    /// whose trait default is `None` — so SA_RESTART is inert until this is set).
    /// `None` before the first syscall. Mirrors HVF's inner field.
    last_syscall_nr: Option<u64>,
    /// Original x0 of the most recent trapped `svc` (the SA_RESTART path needs the
    /// pre-syscall x0). Supplies `InjectParams::orig_x0` (Task 5).
    last_syscall_orig_x0: u64,
    /// ESR of the most recent synchronous exception. Supplies `InjectParams::fault_esr` (Task 5).
    last_fault_esr: u64,
    /// Live stage-1 page-table editor over the guest's own translation tables at
    /// `LINUX_PAGE_TABLES_BASE`. Built lazily on the first `protect_range`/
    /// `unmap_range` edit from the live guest backing (which `build_for_image`
    /// seeded with `stage1_identity_page_tables`). This is what makes a guest
    /// `mmap`/`mprotect` GUEST-visible — clearing UXN so the dynamic loader's
    /// freshly-mapped library text is executable (vs the host-side
    /// `range_no_access` EFAULT check, which only guards syscall buffers).
    ///
    /// Shared across `clone(CLONE_THREAD)` siblings (they run on the SAME VM with
    /// the SAME page-table backing) so concurrent edits stay coherent; a `fork(2)`
    /// child resets it to a fresh `None` (its tables are a COW copy it rebuilds
    /// lazily). `None` until the first edit. Mirrors HVF's
    /// `page_tables: Arc<Mutex<Option<PageTableManager>>>`.
    page_tables: Arc<Mutex<Option<carrick_mem::page_table::PageTableManager>>>,
}

impl KvmTrapEngine {
    /// Bring up the guest from a freestanding ELF image and return an engine
    /// parked at the EL1 trampoline (first `next_syscall` runs into EL0).
    pub fn new(image: &AddressSpace) -> Result<Self, TrapError> {
        let BroughtUp {
            vm,
            vcpu,
            ram,
            entry: _,
        } = bring_up(image).map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        Ok(Self {
            vm,
            vcpu,
            ram,
            is_forked_child: false,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            last_fault_esr: 0,
            page_tables: Arc::new(Mutex::new(None)),
        })
    }

    /// Edit the live stage-1 page tables (the guest's own translation tables at
    /// `LINUX_PAGE_TABLES_BASE`) under the shared manager lock and replay the
    /// changed descriptors into the guest page-table backing — the locked EDIT
    /// CORE, WITHOUT a TLB flush. Builds the `PageTableManager` lazily from the
    /// live backing on first use (the boot image already wrote
    /// `stage1_identity_page_tables` there). Returns whether the edit CHANGED any
    /// descriptor (so the caller can skip a pointless flush on a no-op edit).
    ///
    /// This is the no-flush primitive: callers that map a BRAND-NEW VA (no stale
    /// TLB entry, so the guest's first access walks the just-written tables) —
    /// e.g. [`Self::map_host_alias`]'s fresh alias — use [`Self::pt_edit`]
    /// directly. Callers that may RE-protect an already-walked VA route through
    /// [`Self::pt_edit_and_flush`], which runs [`Self::run_el1_maintenance`]
    /// afterwards so the stale stage-1 TLB entry is invalidated.
    fn pt_edit_locked(
        &mut self,
        edit: impl FnOnce(
            &mut carrick_mem::page_table::PageTableManager,
        ) -> Result<bool, carrick_mem::page_table::PageTableError>,
    ) -> Result<bool, MemoryError> {
        use carrick_mem::page_table::{PageTableError, PageTableManager};
        const PT_BASE: u64 = carrick_mem::memory::LINUX_PAGE_TABLES_BASE;
        let size = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
        let host = self
            .ram
            .host_ptr(PT_BASE, size)
            .ok_or_else(|| MemoryError::HostMap("page-table region not mapped".to_string()))?;
        let pt = Arc::clone(&self.page_tables);
        // `Arc::strong_count > 1` ⟺ a `clone(CLONE_THREAD)` sibling shares THIS
        // page-table manager (the spec clones the Arc into each sibling engine);
        // `== 1` ⟺ this is the SOLE vCPU over the backing. Coalescing reclaims
        // spare sub-tables into the pool — a break-before-make table↔block flip
        // plus a page free, unsafe only if another vCPU holds a stale walk-cache
        // reference to the freed page. So coalesce is safe iff the edit is
        // EXCLUSIVE. The single-vCPU case (count==1) is provably exclusive here,
        // so re-enable coalescing then (the OutOfTables→ENOMEM-under-churn fix
        // for a single-threaded guest). The multi-vCPU case stays conservative
        // (unsafe_to_coalesce = true): the generic loop's Pause-Modify-Resume DOES
        // pause siblings + `tlbi vmalle1is`-broadcast around every threaded stage-1
        // editor (vcpu_loop.rs pt_pause), making coalesce safe there too, but the
        // engine cannot read that barrier from this crate (it lives in
        // carrick-runtime), so it keeps today's conservative flag rather than
        // assume the PMR is held. (HVF, which CAN read the barrier, uses
        // `live_multi && !is_quiescing()`.)
        let unsafe_to_coalesce = Arc::strong_count(&pt) > 1;
        let mut guard = pt.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            // Build from the live guest backing (the boot tables) on first edit —
            // nothing else writes the tables before this, so it matches the image.
            let bytes = self
                .ram
                .read(PT_BASE, size)
                .map_err(|_| MemoryError::HostMap("read live page tables".to_string()))?;
            *guard = Some(PageTableManager::new(bytes, PT_BASE));
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
            // SAFETY: `host` backs the live page-table region for the whole
            // process lifetime; the manager writes only 8-byte-aligned descriptor
            // slots within `[host, host + size)`.
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
        edit: impl FnOnce(
            &mut carrick_mem::page_table::PageTableManager,
        ) -> Result<bool, carrick_mem::page_table::PageTableError>,
    ) -> Result<(), MemoryError> {
        self.pt_edit_locked(edit).map(|_changed| ())
    }

    /// Edit the stage-1 tables AND, if any descriptor changed, flush the stale
    /// stage-1 TLB by running the EL1-maintenance trampoline on this vCPU
    /// ([`Self::run_el1_maintenance`]). This makes a RE-protect / `munmap` of an
    /// ALREADY-WALKED page take effect (e.g. `mprotect(PROT_READ)` of a touched
    /// RW page → a subsequent store faults; `munmap` of a touched page → access
    /// faults), where a bare descriptor edit would leave a stale writable TLB
    /// entry live. A no-op edit (range already at the target protection) writes
    /// nothing and skips the flush. Mirrors HVF's `pt_edit_and_flush`.
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
        edit: impl FnOnce(
            &mut carrick_mem::page_table::PageTableManager,
        ) -> Result<bool, carrick_mem::page_table::PageTableError>,
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

    /// Flush the stale stage-1 TLB after a host page-descriptor edit by running
    /// the EL1 stage-1 maintenance trampoline on THIS vCPU. The trampoline
    /// (`dsb sy; tlbi vmalle1is; dsb sy; isb`) lives at
    /// [`carrick_mem::memory::LINUX_EL1_MAINT_BASE`] and ends in an MMIO store to
    /// [`crate::guest_setup::MAINT_SENTINEL_GPA`] — the KVM completion vehicle, in
    /// place of HVF's `hvc #1` (which KVM's PSCI handler would swallow).
    ///
    /// The vCPU is parked at a syscall (or fault) trap when this runs, so it
    /// saves and restores the interrupted EL1-vector state — PC, PSTATE (CPSR),
    /// ELR_EL1, SPSR_EL1 — AND the two GPRs the trampoline clobbers (x8 the store
    /// value, x9 the sentinel-address scratch). With those restored, the in-flight
    /// syscall resumes exactly as before. Mirrors HVF's `run_el1_maintenance`.
    fn run_el1_maintenance(&mut self) -> Result<(), TrapError> {
        use crate::guest_setup::MAINT_SENTINEL_GPA;
        // M[3:0]=0b0101 EL1h (SP_EL1) + DAIF masked, PAN(bit22)=0 — the SAME
        // PSTATE boot uses to run the EL0-entry trampoline at EL1 (program_sysregs
        // sets `PSTATE_M_EL1H | DAIF_MASKED`). The maintenance trampoline issues
        // no EL0-accessible store under PAN, so PAN=0 is not strictly required,
        // but matching boot keeps the EL1 entry conditions identical.
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;

        let g = |this: &Self, r: Reg| {
            this.vcpu
                .reg(r)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))
        };
        // Save the interrupted EL1-vector state + the two scratch GPRs the
        // trampoline clobbers.
        let saved_pc = g(self, Reg::Pc)?;
        let saved_pstate = g(self, Reg::Pstate)?;
        let saved_elr = g(self, Reg::ElrEl1)?;
        let saved_spsr = g(self, Reg::SpsrEl1)?;
        let saved_x8 = g(self, Reg::X(8))?;
        let saved_x9 = g(self, Reg::X(9))?;

        let s = |this: &mut Self, r: Reg, v: u64| {
            this.vcpu
                .set_reg(r, v)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))
        };
        s(self, Reg::Pc, carrick_mem::memory::LINUX_EL1_MAINT_BASE)?;
        s(self, Reg::Pstate, AARCH64_PSTATE_EL1H_DAIF_MASKED)?;

        // Run the trampoline to its completion MMIO store. A cross-thread kick
        // (KVM_RUN EINTR → VcpuExit::Kicked) can land mid-flush; the trampoline is
        // tiny and idempotent, so just re-enter it. Any OTHER exit is ambiguous
        // (we cannot trust guest memory visibility) — surface it. (No guest_cpu
        // accounting: this is a host-driven flush, not guest execution time.)
        let result = loop {
            match self.vcpu.run() {
                Ok(VcpuExit::MmioWrite { gpa, .. }) if gpa == MAINT_SENTINEL_GPA => {
                    if std::env::var_os("CARRICK_MAINT_DEBUG").is_some() {
                        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
                        eprintln!("[MAINTDBG tid={tid}] stage-1 TLBI completed");
                    }
                    break Ok(());
                }
                Ok(VcpuExit::Kicked) => continue,
                Ok(other) => {
                    // `VcpuExit` is not Debug; describe the variant inline.
                    let what = match other {
                        VcpuExit::MmioWrite { gpa, .. } => {
                            format!("MmioWrite at non-maint gpa=0x{gpa:x}")
                        }
                        VcpuExit::Halt => "Halt".to_string(),
                        VcpuExit::Exception { syndrome, .. } => {
                            format!("Exception esr=0x{syndrome:x}")
                        }
                        VcpuExit::Kicked => "Kicked".to_string(),
                    };
                    break Err(TrapError::UnexpectedExit {
                        reason: format!("{what} during EL1 stage-1 maintenance"),
                    });
                }
                Err(e) => break Err(TrapError::Hypervisor(e.to_string())),
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

    /// Read `len` bytes of live guest memory at guest-physical `gpa` (e.g. a
    /// `write(2)` buffer the guest passed). Backed by the same host RAM the
    /// vCPU sees, so guest writes are visible.
    pub fn read_guest(&self, gpa: u64, len: usize) -> Result<Vec<u8>, TrapError> {
        self.ram
            .read(gpa, len)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    /// The IPA a syscall buffer at guest VA `va` resolves to. Identity (`va`) for
    /// the common heap/stack/private-mmap pointer — NO page-table walk on the hot
    /// path. Only a `repoint_private` overlay over a shared-aperture VA
    /// ([`carrick_mem::memory::needs_stage1_translation`]) walks the live stage-1
    /// tables to find the overlay IPA whose backing the guest's OWN EL0 accesses
    /// hit (the VA-keyed window still resolves to the STALE shared aperture).
    /// High-VA aliases are EXCLUDED: their KVM `Window::base == va`, so identity
    /// is correct and re-basing on the IPA would miss the window. A walk miss
    /// falls back to `va` (identity), preserving prior behaviour for an unmapped
    /// VA.
    fn syscall_buffer_ipa(&self, va: u64, len: usize) -> u64 {
        if !carrick_mem::memory::needs_stage1_translation(va, len as u64) {
            return va;
        }
        let guard = self.page_tables.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().and_then(|m| m.translate(va)).unwrap_or(va)
    }
}

// NOTE: KvmTrapEngine implements the `carrick-hal` SyscallTrap contract; the
// MVP drives it from `crate::run_elf`, reading the trapped write(2) buffer out
// of the live guest RAM via `read_guest`. Pairing it with the full
// carrick-runtime dispatcher (SplitView @ runtime.rs:3701) is the full-Linux-
// backend spec's job — that path needs ~200 macOS-isms ported off the dispatch
// layer first (see run_elf.rs).

/// `GuestMemory` over the KVM guest RAM. The guest is **identity-mapped** (the
/// stage-1 tables map VA == IPA, and the single KVM memory slot maps IPA == GPA
/// at host-mmap offset), so a syscall's guest *virtual* pointer is numerically
/// the same as its guest-physical address and indexes straight into the host
/// backing. The real dispatcher reads/writes its syscall buffers through this.
///
/// `read_bytes`/`write_bytes` move syscall buffers; `set_no_access`/
/// `zero_backing` implement the HOST-SIDE PROT_NONE check (a bad syscall
/// buffer faults with EFAULT). `protect_range`/`unmap_range`/`unmap_alias_range`
/// edit the live stage-1 tables (via [`KvmTrapEngine::pt_edit_and_flush`]) so the
/// GUEST's own EL0 access honours `mmap`/`mprotect`/`munmap` permissions —
/// clearing UXN makes a freshly-mapped library text executable; combined with the
/// Phase-4 EL0-fault→SIGSEGV path, a PROT_NONE/munmap'd page faults the guest. A
/// RE-protect / `munmap` of an ALREADY-WALKED page also takes effect: the edit
/// runs the EL1-maintenance TLBI ([`KvmTrapEngine::run_el1_maintenance`]) to drop
/// the stale stage-1 TLB entry (a fresh, never-walked alias needs no flush, so
/// [`KvmTrapEngine::map_host_alias`] uses the no-flush [`KvmTrapEngine::pt_edit`]).
/// `repoint_private` (the MAP_FIXED|MAP_PRIVATE overlay) is a LIVE override too:
/// it seeds the boot-mapped private-overlay slot then repoints the VA's stage-1
/// leaf to it (+ flush), so a guest's "private" stores no longer leak through the
/// fork-/sibling-shared backing.
/// Gated (CARRICK_MEM_DEBUG) diagnostic for a failed syscall-path guest access:
/// prints the address, length, and the calling thread's window view so a
/// cross-thread translation miss (a stale per-sibling `GuestRam` snapshot) is
/// visible. No-op unless the env var is set, so it never costs the hot path.
fn mem_debug(op: &str, ram: &GuestRam, address: u64, length: usize) {
    if std::env::var_os("CARRICK_MEM_DEBUG").is_some() {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        eprintln!(
            "[MEMDBG tid={tid} {op} FAIL] {}",
            ram.debug_access(address, length)
        );
    }
}

impl GuestMemory for KvmTrapEngine {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        // The PROT_NONE gate (a syscall buffer overlapping a PROT_NONE range
        // faults EFAULT even though the host backing is accessible — C2 host-side
        // check) AND the single-region whole-range lookup are the SHARED neutral
        // gate (`safe_access_translated`). The PROT_NONE check stays keyed on the
        // guest VA (`address`), while the backing lookup uses the stage-1
        // translation (`ipa`) so a `repoint_private` overlay / high-VA alias
        // resolves to the page the guest's OWN EL0 accesses hit — NOT the stale
        // shared-aperture backing the VA still covers. Identity VAs: ipa==address,
        // so this is byte-identical (and skips the walk). Both failure modes map
        // to OutOfBounds (→ EFAULT), unchanged; the copy stays glue.
        let ipa = self.syscall_buffer_ipa(address, length);
        let host = self
            .ram
            .safe_access_translated(address, ipa, length)
            .map_err(|e| {
                mem_debug("read", &self.ram, ipa, length);
                e.map_to_memory_error(address, length)
            })?;
        let mut out = vec![0u8; length];
        // SAFETY: `safe_access` proved [address, address+length) ⊆ one window, so
        // `host` points at `length` readable bytes of that window's backing.
        unsafe {
            std::ptr::copy_nonoverlapping(host, out.as_mut_ptr(), length);
        }
        Ok(out)
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        // PROT_NONE on the guest VA; backing lookup on the translated IPA (see
        // `read_bytes`). For a `repoint_private` overlay the syscall write lands
        // in the PRIVATE overlay backing the guest reads, not the shared aperture.
        let ipa = self.syscall_buffer_ipa(address, length);
        let host = self
            .ram
            .safe_access_translated(address, ipa, length)
            .map_err(|e| {
                mem_debug("write", &self.ram, ipa, length);
                e.map_to_memory_error(address, length)
            })?;
        // SAFETY: `safe_access` proved [address, address+length) ⊆ one window, so
        // `host` points at `length` writable bytes of that window's backing.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, length);
        }
        Ok(())
    }

    /// Record/clear a PROT_NONE range so syscall buffers there fault (EFAULT).
    /// This is the HOST-SIDE check only; the COMPLEMENTARY guest-side enforcement
    /// (so the guest's own EL0 access faults) is done by `protect_range`/
    /// `unmap_range`/`unmap_alias_range`, which edit the live stage-1 tables AND
    /// flush the stale TLB via `pt_edit_and_flush` + the Phase-4 EL0-fault→SIGSEGV
    /// path — those are LIVE overrides, not no-ops.
    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.ram.set_no_access(address, len, no_access);
    }

    /// Scrub the physical backing of `[address, address+len)`, BYPASSING the
    /// PROT_NONE check — used to clear a reused/`munmap`'d region whose stale
    /// bytes must never resurface after a later `mprotect` makes it readable.
    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        let zeros = vec![0u8; len];
        self.ram
            .write_gpa(address, &zeros)
            .map_err(|_| MemoryError::OutOfBounds {
                address,
                length: len,
            })
    }

    /// Host VA of a guest futex word IFF it lives in the `MAP_SHARED` aperture —
    /// the hook (Task 7 fix #3) that lets the dispatcher route a guest
    /// cross-process (`MAP_SHARED`) futex through `KvmFutex::shared_{wait,wake}`
    /// (bare host `SYS_futex` on the same physical page, inherited across
    /// `fork(2)`). For a 4-byte futex word: the guest is identity-mapped, so the
    /// guest VA == GPA indexes straight into the shared window's host backing.
    /// Returns `None` for a word in a private/COW window — those stay in-process
    /// via the parking-lot `FutexTable` (the default trait impl returned `None`
    /// unconditionally, which is why shared guest futexes never reached the
    /// shared path before this override).
    fn shared_futex_host_addr(&self, guest_addr: u64) -> Option<usize> {
        self.ram.shared_futex_host_addr(guest_addr, 4)
    }

    /// Make a guest `mprotect`/`mmap`'s protection GUEST-visible by editing the
    /// live stage-1 tables. PROT_EXEC clears UXN (executable); its absence sets
    /// UXN (NX / W^X), matching Linux — so the dynamic loader's freshly-mapped
    /// library text (PROT_READ|PROT_EXEC) actually executes instead of
    /// permission-faulting on the NX-by-default arena. (Boot regions — image
    /// text, trampolines, vDSO — are mapped executable at boot and never edited
    /// here; only guest mmap/mprotect ranges pass through.) Mirrors HVF's
    /// `protect_range`.
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

    /// `munmap`: invalidate the stage-1 descriptors for `[address, address+len)`
    /// so the guest's own access faults (vs the host-side `no_access` check). The
    /// unmapped range is typically ALREADY-TOUCHED, so flush the stale TLB entry.
    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.pt_edit_and_flush(|mgr| mgr.invalidate(address, len))
    }

    /// `munmap` of a high-VA alias: invalidate AND reclaim the now-empty alias
    /// sub-table(s) (vs `unmap_range`, which keeps the table for the low-VA
    /// arena's in-place reuse). Flush the stale TLB entry. Mirrors HVF.
    fn unmap_alias_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.pt_edit_and_flush(|mgr| mgr.unmap_aliased(address, len))
    }

    /// Repoint guest VA `[va, va+len)` to a slot in the boot-mapped PRIVATE
    /// overlay aperture (`overlay_ipa`, identity IPA==VA), seeding the slot with
    /// `content` first. Backs a guest `mmap(MAP_FIXED|MAP_PRIVATE|MAP_ANON)` over
    /// a SHARED-aperture VA: carrick's shared aperture is host-`MAP_SHARED`, so it
    /// is inherited across `fork(2)` AND visible to sibling carrick processes —
    /// leaving the VA pointed there would make a guest's "private" stores leak. The
    /// overlay window is `WindowKind::Private` (boot-mapped + its own KVM slot, so
    /// `fork` COW-isolates it per process), so after this repoint the guest's
    /// stores to `va` hit the per-process overlay page, not the shared backing.
    ///
    /// Mirrors HVF's `repoint_private`: (1) seed the overlay backing FIRST, while
    /// `va` still translates to the OLD (shared) IPA, so no concurrent reader sees
    /// a torn page through `va` during the flip; (2) `pt_edit_and_flush(map_aliased)`
    /// repoints the stage-1 leaf (splitting any covering boot block down to a page
    /// leaf) and — because the dispatcher may have ALREADY touched the overlay VA
    /// (e.g. the guest wrote it before the MAP_FIXED) — runs the EL1-maintenance
    /// TLBI so any stale stage-1 entry is invalidated. The overlay window was
    /// registered as a KVM slot at boot (`build_for_image` maps every high region,
    /// including `LINUX_PRIVATE_OVERLAY_BASE`), so this is a stage-1 edit only — no
    /// post-vCPU stage-2 mutation.
    fn repoint_private(
        &mut self,
        va: u64,
        overlay_ipa: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), MemoryError> {
        // 1. Resolve the overlay slot's host backing pointer (the same resolver
        //    the live page-table editor's `sync_to_host` uses). `len.max(1)` so a
        //    zero-length repoint still resolves the start page.
        let dst = self
            .ram
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
        //    repointed without disturbing its neighbours; the flush (Task 8)
        //    invalidates any stale stage-1 entry for an already-touched overlay VA.
        self.pt_edit_and_flush(|mgr| mgr.map_aliased(va, overlay_ipa, len as u64, true))
    }
}

impl SyscallTrap for KvmTrapEngine {
    fn next_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError> {
        // One KVM_RUN per call. The loop exists ONLY to re-enter the guest when a
        // kick lands mid-syscall-trap (the `Kicked` arm); every other exit returns.
        loop {
            let run_start = std::time::Instant::now();
            carrick_host::guest_cpu::begin_active();
            let run_result = self
                .vcpu
                .run()
                .map_err(|e| TrapError::Hypervisor(e.to_string()));
            let run_ns = run_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            carrick_host::guest_cpu::finish_active(run_ns);
            match run_result? {
                VcpuExit::MmioWrite { gpa, .. } if gpa == SENTINEL_GPA => {
                    // The EL0 `svc` re-entered EL1 and hit the sentinel store.
                    // The hardware already set ELR_EL1 = (svc addr + 4) on the
                    // exception, and the EL1 vector's own `eret` (after the
                    // sentinel store) consumes it — so we do NOT touch the PC
                    // here; we just read the syscall frame.
                    let frame = self.read_frame()?;
                    self.last_syscall_nr = Some(frame.x8);
                    self.last_syscall_orig_x0 = frame.x0;
                    return Ok(Some(frame));
                }
                VcpuExit::MmioWrite { gpa, .. } if gpa == FAULT_SENTINEL_GPA => {
                    // An EL0 SYNCHRONOUS FAULT (data/instruction abort, alignment)
                    // vectored into the EL1 sentinel slot, which read ESR.EC, saw
                    // it was not an `svc`, and stored to FAULT_SENTINEL_GPA. (A
                    // bare EL0 abort is NOT a KVM_RUN exit — KVM steers it to the
                    // guest's own VBAR_EL1 — so this is the ONLY way it reaches the
                    // host.) Capture the still-pristine EL0 fault state (the vector
                    // clobbered only x9) and return EL0Fault; the shared loop's
                    // deliver_fault_signal maps ESR.EC -> SIGSEGV/SIGBUS and injects
                    // the handler (or terminates). `from_el0_direct = false`: the
                    // EL1 vector latched ELR_EL1, and inject_signal redirects
                    // ELR_EL1 (the syscall-path mechanism) which the vector's
                    // `eret` then consumes — exactly like a syscall return.
                    let syndrome = self
                        .vcpu
                        .get_esr_el1()
                        .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
                    let far = self
                        .vcpu
                        .get_far_el1()
                        .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
                    let g = |r: Reg| {
                        self.vcpu
                            .reg(r)
                            .map_err(|e| TrapError::Hypervisor(e.to_string()))
                    };
                    self.last_fault_esr = syndrome;
                    return Err(TrapError::EL0Fault {
                        syndrome,
                        elr: g(Reg::ElrEl1)?,
                        far,
                        x16: g(Reg::X(16))?,
                        x17: g(Reg::X(17))?,
                        x29: g(Reg::X(29))?,
                        x30: g(Reg::X(30))?,
                        sp: g(Reg::Sp)?,
                        from_el0_direct: false,
                    });
                }
                VcpuExit::MmioWrite { gpa, data, len } => {
                    let pc = self.vcpu.reg(Reg::Pc).unwrap_or(0);
                    let elr = self.vcpu.reg(Reg::ElrEl1).unwrap_or(0);
                    let g = |n: u32| self.vcpu.reg(Reg::X(n)).unwrap_or(0);
                    return Err(TrapError::UnexpectedExit {
                        reason: format!(
                            "MMIO at non-sentinel gpa=0x{gpa:x} data=0x{data:x} len={len} \
                             pc=0x{pc:x} elr=0x{elr:x} x0=0x{:x} x1=0x{:x} x8=0x{:x} sp=0x{:x}",
                            g(0),
                            g(1),
                            g(8),
                            self.vcpu.reg(Reg::Sp).unwrap_or(0),
                        ),
                    });
                }
                // A WFI/halt with no pending syscall: report `None` so the run
                // loop can run signal delivery and resume.
                VcpuExit::Halt => return Ok(None),
                VcpuExit::Kicked => {
                    // A cross-thread kick (host signal → KVM_RUN EINTR, e.g. a
                    // timer or `tgkill`) can land while the guest is MID-SYSCALL-
                    // TRAP: the EL0 `svc` has already re-entered EL1 and the vCPU
                    // PC is inside carrick's EL1 vector, with the sentinel-store
                    // MMIO not yet surfaced. Reporting that as a deliverable kick
                    // (→ the loop injects a signal at the EL1-vector PC) corrupts
                    // the in-flight syscall and wedges the guest in an EL0 spin.
                    // Mirror HVF (trap.rs:1305): if the PC is in the EL1 vector,
                    // swallow the kick and re-enter the guest so the syscall
                    // completes; the pending signal is delivered cleanly on the
                    // syscall return. Only a kick taken in genuine guest EL0 code
                    // is reported (`Ok(None)`).
                    let pc = self
                        .vcpu
                        .reg(Reg::Pc)
                        .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
                    if carrick_mem::memory::is_carrick_el1_vector_va(pc) {
                        continue;
                    }
                    return Ok(None);
                }
                VcpuExit::Exception { syndrome, far } => {
                    self.last_fault_esr = syndrome;
                    return Err(TrapError::UnexpectedException {
                        syndrome,
                        virtual_address: far,
                        physical_address: far,
                    });
                }
            }
        }
    }

    fn last_syscall_nr(&self) -> Option<u64> {
        self.last_syscall_nr
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        self.vcpu
            .reg(Reg::Pc)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        // Write the syscall result into x0. The guest resume PC is already
        // correct: ELR_EL1 (= svc+4) was latched by the exception and is
        // restored by the EL1 vector's `eret`. We must NOT advance it again,
        // or the instruction after the `svc` would be skipped.
        self.vcpu
            .set_reg(Reg::X(0), return_value as u64)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // Restore the guest's x9. The Linux aarch64 syscall ABI preserves x1..x30
        // across an `svc`, and musl relies on it (`__expand_heap` holds its
        // malloc-context pointer in x9 across `brk(2)` and then `str x10, [x9,
        // #920]`). The EL1 sentinel vector clobbers x9 as the sentinel-store
        // scratch, so it first stashes the guest's x9 in TPIDR_EL1 (free on KVM);
        // restore it here, on every syscall return. Without this the guest resumes
        // with x9 = SENTINEL_GPA and faults on that store. (glibc never held a
        // live x9 across an svc, which masked this until alpine/musl.)
        let saved_x9 = self
            .vcpu
            .get_tpidr_el1()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        self.vcpu
            .set_reg(Reg::X(9), saved_x9)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        // Approach A — lean on Linux COW. KVM's VM/vCPU fds are per-process and
        // are NOT usefully inherited across `libc::fork` (the inherited fds point
        // at the parent's kernel VM), so the CHILD rebuilds a brand-new KvmVm
        // over the COW-inherited host mmaps while the PARENT keeps its live VM.
        //
        // Because the guest RAM windows are MAP_PRIVATE|MAP_ANONYMOUS (except the
        // MAP_SHARED aperture), Linux COW gives correct POSIX fork divergence for
        // free — no `mincore` snapshot and no per-region clone (unlike HVF, whose
        // RAM is MAP_SHARED). The HVF-only lifecycle hooks
        // (publish_vm_for_siblings / rebuild_vcpu_after_fork /
        // release_vcpu_for_fork) stay default no-ops on KVM.

        // 1. Snapshot the parent vCPU register file BEFORE forking, so both sides
        //    resume inside the same trapped syscall site. (Taken while the vCPU is
        //    suspended at the syscall trap — atomic, race-free.)
        let snap = self
            .vcpu
            .snapshot()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // The EL1 vector stashed the guest's live x9 in TPIDR_EL1 (the sentinel
        // store clobbers x9). The snapshot captured the CLOBBERED x9 and does NOT
        // carry TPIDR_EL1, so capture the real x9 here to restore on the child.
        // The child resumes straight at the eret and never runs `complete_syscall`
        // (which is what restores x9 in the parent on syscall return), so without
        // this it would resume holding x9 = SENTINEL_GPA. A guest that keeps a
        // live x9 across to its next svc without reloading it (e.g. musl's
        // `brk`-via-`__expand_heap`, `str x10,[x9,#920]`) would then fault on the
        // sentinel GPA — the same class of bug the EL1-vector save/restore fixes
        // for the straight-line path. (fork preserves x1..x30.)
        let saved_x9 = self.vcpu.get_tpidr_el1().unwrap_or(0);

        // 2. Real host fork.
        //
        // SAFETY: the carrick-linux thin-shim run loop spawns no threads, so the
        // process is SINGLE-THREADED at this point.  That is the load-bearing
        // invariant: because no other thread exists, no other thread can be
        // holding the malloc lock (or any other process-global lock) at fork
        // time, so the child inherits a consistent allocator state and may
        // safely allocate during `rebuild_vm_for_child`.
        //
        // NOTE (Task 7): the threaded-capstone run loop breaks this invariant —
        // when `KvmForkCoordinator::fork_from_threaded_context` is implemented,
        // this path will need re-examination (quiesce-all-threads protocol or
        // async-signal-safe-only child path).
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(TrapError::ForkFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        if pid > 0 {
            // 3. PARENT: the live VM is untouched (its KVM fds are still valid;
            //    its private RAM is unchanged by the child's COW writes). Return
            //    the child pid so the runtime writes it into the guest's x0.
            return Ok(ForkOutcome::Parent { child_pid: pid });
        }

        // 4. CHILD: build a brand-new KvmVm over the COW-inherited host mmaps:
        //    open /dev/kvm -> KVM_CREATE_VM -> re-register every window in the
        //    SAME order/GPA/slot id (the SENTINEL_GPA hole stays unmapped) ->
        //    KVM_CREATE_VCPU. PRIVATE windows are the Linux-COW copies; the
        //    MAP_SHARED aperture re-registers the SAME inherited host pages.
        let (new_vm, mut new_vcpu) = self
            .ram
            .rebuild_vm_for_child()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // Restore the parent's register file onto the child's fresh vCPU, then
        // set x0 = 0 (the child's fork(2) return value). The child resumes inside
        // the same trapped clone/fork syscall, just like the parent.
        new_vcpu
            .restore(&snap)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        new_vcpu
            .set_reg(Reg::X(0), 0)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // Restore the child's real x9 (the snapshot carried the vector-clobbered
        // SENTINEL_GPA — see `saved_x9` above). The Linux syscall ABI preserves
        // x1..x30 across the clone/fork svc, so the child must resume with the
        // parent's pre-svc x9.
        new_vcpu
            .set_reg(Reg::X(9), saved_x9)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // CRITICAL: advance the child PC past the EL1 vector's sentinel store.
        //
        // At the trap, the vCPU is suspended ON the `str x8,[x9]` sentinel store
        // (snap.pc points AT it). On the PARENT's ORIGINAL vCPU, KVM remembers the
        // MMIO is being completed and auto-advances PC by 4 on the next KVM_RUN,
        // so it resumes at the vector's `eret`. The CHILD's vCPU is BRAND-NEW with
        // no pending-MMIO state, so a plain restore would RE-EXECUTE the sentinel
        // store → another MMIO exit → re-trap the SAME (clone) frame → fork bomb.
        // We replicate KVM's post-MMIO advance ourselves: PC = snap.pc + 4 lands
        // on the vector's `eret`, which loads PC←ELR_EL1 (= the guest svc+4) and
        // PSTATE←SPSR_EL1 (= EL0t), dropping the child back into EL0 just past its
        // clone — exactly where the parent resumes.
        const SENTINEL_STR_WIDTH: u64 = 4; // one A64 instruction (the sentinel `str x8,[x9]`)
        new_vcpu
            .set_reg(Reg::Pc, snap.pc.wrapping_add(SENTINEL_STR_WIDTH))
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // Swap the rebuilt VM/vCPU into `self`. The old (inherited, now-useless)
        // KvmVm/KvmVcpu drop here, closing their stale fds. `ram` is unchanged —
        // the host mmaps it tracks are exactly the COW-inherited pages the new
        // slots point at.
        self.vm = new_vm;
        self.vcpu = new_vcpu;
        // The child inherited the PARENT's VCPU_LIVE value (plain static,
        // copied by libc::fork) — including siblings' vCPUs that do NOT exist
        // in this process (fork replicates only the calling thread, and the
        // KVM fork quiesce parks siblings WITHOUT releasing their vCPUs). The
        // child owns exactly ONE vCPU: the rebuild above created it (+1) and
        // the swap dropped the inherited engine vCPU (-1), but the inherited
        // BASE value is still the parent's. Re-stamp the truth, or a child
        // that later goes multithreaded and execve's would wait on phantom
        // siblings in `terminate_siblings_for_exec` and ride out the bounded
        // timeout on every exec.
        crate::kvm::VCPU_LIVE.store(1, std::sync::atomic::Ordering::SeqCst);
        self.is_forked_child = true;
        // The child resumes mid-clone; clear stale parent syscall/fault state so
        // a signal arriving before the child's first svc cannot read parent values.
        self.last_syscall_nr = None;
        self.last_syscall_orig_x0 = 0;
        self.last_fault_esr = 0;
        // Give the child its OWN page-table manager — a FRESH Arc, NOT the Arc the
        // parent's CLONE_THREAD siblings still share (so a later child pt_edit can
        // never reach back into the parent's manager). The child's tables are a
        // fresh Linux-COW copy of the parent's (in the rebuilt-VM's private
        // windows), and `pt_edit_locked`/`pt_host_ptr` already resolve their host
        // backing through `self.ram` (the child's COW windows), so the child still
        // edits/syncs to its OWN backing after this swap.
        //
        // But CLONE the parent's manager VALUE rather than RESET to None (which
        // mirrors HVF, trap.rs ~:3542). A reset would force a lazy rebuild on the
        // child's first pt_edit, but `syscall_buffer_ipa` is `&self` and CANNOT
        // rebuild — so a forked child that passes a `repoint_private` overlay VA to
        // a syscall (write/read/sendmsg/…) BEFORE its first mmap/mprotect/munmap
        // would translate against a None manager, fall back to identity, and read
        // the STALE SHARED aperture instead of its own COW overlay. Cloning lets
        // the child translate immediately. Correctness: at fork the child's COW
        // table backing == the parent's synced manager bytes, so the clone is
        // exactly what a lazy rebuild from the child's backing would produce — and
        // the bump cursor/pool state matches that backing too. If the parent never
        // built a manager (None — never edited the tables), the clone is None,
        // which is correct (nothing was repointed → identity VA → no translation).
        let cloned = self
            .page_tables
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        self.page_tables = Arc::new(Mutex::new(cloned));
        // Re-calibrate the vDSO clock against the CHILD's counter: the child runs
        // on a brand-new KvmVm, so its guest counter basis differs from the
        // parent's, and the COW-inherited vvar's realtime_off no longer matches.
        // (CNTKCTL is set on the child's vCPU via the shared add_vcpu create path.)
        let _ = populate_vdso_vvar(&self.vcpu, &mut self.ram);
        Ok(ForkOutcome::Child)
    }

    fn is_forked_child(&self) -> bool {
        self.is_forked_child
    }

    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError> {
        // In-place image replacement on the LIVE VM (no teardown, unlike HVF
        // which rebuilds the VM). Mirrors the HVF structure
        // (carrick-hvf/src/trap.rs:3764-3913): build the new layout up front,
        // remap the slots, reprogram the registers, preserve is_forked_child.
        //
        // 1. Build the new image's guest RAM (fresh host mmaps + image segments +
        //    the EL0 trampoline / stage-1 identity tables / EL1 sentinel vector)
        //    FIRST, so any image/window error surfaces BEFORE we tear down the
        //    live slots (Linux execve semantics: on failure the caller keeps
        //    running its old image). `build_for_image` refuses any window that
        //    would back the unmapped SENTINEL_GPA (the guard in `add_window` is
        //    not weakened), so the sentinel hole stays a stage-2 MMIO fault.
        let new_ram = GuestRam::build_for_image(new_image)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // 2. Unregister EVERY currently-registered KVM memory slot on the LIVE VM
        //    (`KVM_SET_USER_MEMORY_REGION` with memory_size = 0). Slot ids are
        //    dense from 0 (the shared allocator never recycles and failures are
        //    fatal), so `0..slot_count()` is the complete live set — including
        //    any alias slot a SIBLING thread registered post-spawn, which this
        //    engine's `ram.window_count()` would UNDERCOUNT (the sibling's
        //    window lives only in its own GuestRam view). Linux execve destroys
        //    all threads' mappings; a stale alias slot would collide with a
        //    re-issued id after the counter resets below.
        let old_slot_count = self.vm.slot_count();
        for slot in 0..old_slot_count {
            self.vm
                .unmap_memory_slot(slot)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        }
        // Reset the slot allocator so the new windows re-register from slot 0
        // (same ids/order a fresh VM would use), then publish them on the LIVE
        // VM. The SENTINEL_GPA hole stays unmapped.
        self.vm.reset_slot_counter();
        for (base, host, len) in new_ram.windows_for_kvm() {
            self.vm
                .map_memory(base, host, len, MemPerms::ReadWriteExec)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        }

        // 3. Swap in the new RAM. The OLD GuestRam drops here, `munmap`ing its
        //    host windows — safe because their KVM slots were just deleted, so no
        //    live vCPU references them. `no_access` is dropped with it: execve
        //    replaces the address space, so any prior PROT_NONE ranges are gone
        //    (the new image starts with none until it mmaps them).
        self.ram = new_ram;

        // 4. Reprogram the system + core registers for the new image (MAIR=0xFF,
        //    TCR bootstrap, TTBR0/1 = LINUX_PAGE_TABLES_BASE, SCTLR, CPACR,
        //    VBAR = LINUX_EL1_VECTORS_BASE, TPIDR_EL0 = 0, PSTATE/SPSR/ELR/PC +
        //    SP from the new image's entry/initial stack). Reuses the SAME
        //    builder bring-up uses, so the sysreg values cannot drift between
        //    the two paths.
        program_sysregs(&mut self.vcpu, new_image)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // Re-calibrate the vDSO clock for the new image's vvar (same vCPU, so
        // CNTKCTL is still set; best-effort like bring_up).
        let _ = populate_vdso_vvar(&self.vcpu, &mut self.ram);

        // 5. Zero x0..x30. Linux's execve contract starts the new program with
        //    all GPRs clear (except SP/PC, set by `program_sysregs`). Without
        //    this the new image's _start inherits the old image's x8, which can
        //    decode as a bogus syscall number on its first `svc`. (`program_sysregs`
        //    deliberately leaves the GPRs to us — it sets only SP/PC/PSTATE.)
        for n in 0..=30u32 {
            self.vcpu
                .set_reg(Reg::X(n), 0)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        }

        // 6. PRESERVE is_forked_child across execve (Task 2 flag): a descendant
        //    of a forked child keeps the `_exit`-without-report shutdown path
        //    even after it execve's into a different image (mirrors HVF
        //    trap.rs:3795). The flag is a plain field on `self`, untouched by
        //    the remap above — so this is a no-op assertion of intent, kept
        //    explicit for the contract.
        // (self.is_forked_child is intentionally left unchanged.)

        // A fresh image has no in-flight syscall or fault.
        self.last_syscall_nr = None;
        self.last_syscall_orig_x0 = 0;
        self.last_fault_esr = 0;
        // `build_for_image` wrote fresh `stage1_identity_page_tables` into the new
        // RAM, so the old page-table editor is stale — drop it so the next edit
        // rebuilds from the new image's tables. (execve replaces the whole address
        // space; Linux has already torn down sibling threads, so the shared Arc is
        // moot here.)
        self.page_tables = Arc::new(Mutex::new(None));

        Ok(())
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
        use carrick_hal::RegAccess;
        // The interrupted PSTATE to save into the sigframe. Which register holds
        // it depends on HOW we left EL0 — NOT on the EL (KVM is always EL0; the
        // HVF EL1-trampoline discrimination is what does NOT apply here):
        //   * SYSCALL path (`interrupted_pc.is_none()`): the `svc` exception
        //     latched the EL0 PSTATE into SPSR_EL1, so read `Reg::SpsrEl1`.
        //   * KICK path (`interrupted_pc.is_some()`): a host signal EINTR'd
        //     `KVM_RUN` mid-EL0 with NO exception taken, so SPSR_EL1 is stale
        //     (frozen at the last eret-into-EL0). The LIVE EL0 PSTATE is in
        //     `user_pt_regs.pstate` (`Reg::Pstate`) — the same place the loop
        //     read the live PC for `interrupted_pc`. Mirrors HVF (trap.rs:1319).
        let pstate_source = if interrupted_pc.is_some() {
            self.get_reg(Reg::Pstate)
        } else {
            self.get_reg(Reg::SpsrEl1)
        }
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
            fpsimd_enabled: true,
            sigreturn_trampoline_base: carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_BASE,
        };
        carrick_hal::sigframe::build_sigframe(self, params)?;
        // The fault ESR is only valid between fault and delivery; clear it so a
        // later async signal doesn't reuse a stale synchronous-fault syndrome.
        self.last_fault_esr = 0;
        Ok(())
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        // fpsimd_enabled MUST match inject_signal (true on KVM). Returns the
        // SAVED SIGMASK — not saved_pc — mirroring HVF.
        let r = carrick_hal::sigframe::restore_sigframe(self, true)?;
        Ok(r.sigmask)
    }

    /// Back a dynamic alias mapping (`DispatchOutcome::MapHostAlias`) — a guest
    /// `mmap(MAP_SHARED, fd)` or other high-VA mapping the dispatcher placed at a
    /// VA >= 1 TiB. KVM mirrors HVF (mmap the host file/anon, then map VA -> a low
    /// alias GPA in stage-1) but backs stage-2 with a NEW KVM memory slot instead
    /// of `hv_vm_map`. The stage-1 path is the SHARED `map_aliased`.
    fn map_host_alias(
        &mut self,
        va: u64,
        _ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(), TrapError> {
        use crate::guest_setup::{AliasBacking, KVM_ALIAS_GPA_BASE, KVM_ALIAS_GPA_SIZE};
        use carrick_mem::memory::LINUX_HIGH_VA_THRESHOLD;
        // KVM IGNORES the dispatcher's `ipa` (HVF-shaped: a low IPA at 96 GiB that
        // sits INSIDE KVM's single low-window slot, so it can't be a fresh slot).
        // Derive the alias GPA deterministically from the guest VA, inside the free
        // <1 TiB arena (the 40-bit nested-KVM IPA limit). The dispatcher's alias
        // VAs span [1 TiB, 1 TiB + 64 GiB), so the offset always lands in-arena; a
        // guest-FIXED VA outside that span (e.g. Rosetta amd64 mapping at 128 TiB)
        // is not yet supported on KVM — fail clearly rather than corrupt memory.
        let off = va
            .checked_sub(LINUX_HIGH_VA_THRESHOLD)
            .filter(|&o| o < KVM_ALIAS_GPA_SIZE)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "KVM map_host_alias: VA 0x{va:x} outside the alias arena \
                     [1 TiB, 1 TiB+64 GiB) — guest-fixed high-VA / Rosetta unsupported on KVM"
                ))
            })?;
        let gpa = KVM_ALIAS_GPA_BASE + off;
        let writable = match file {
            Some((_, _, prot)) => prot & libc::PROT_WRITE != 0,
            None => true,
        };
        let backing = match file {
            Some((fd, offset, prot)) => AliasBacking::File { fd, offset, prot },
            None => AliasBacking::Anon { payload },
        };
        // mmap the host backing + register a live KVM slot at `gpa`, tracked in
        // GuestRam keyed by `va` (so the syscall read/write path resolves it).
        self.ram
            .add_alias(&mut self.vm, va, gpa, len, backing)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // Build the VA -> GPA stage-1 path via the SHARED PageTableManager. No
        // TLBI: the alias VA is brand-new (no stale TLB entry), so the guest's
        // first access walks the just-written tables — the same fresh-page
        // argument as `protect_range`.
        self.pt_edit(|mgr| mgr.map_aliased(va, gpa, len, writable))
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        Ok(())
    }
}

impl KvmTrapEngine {
    fn read_frame(&self) -> Result<Aarch64SyscallFrame, TrapError> {
        let g = |n: u32| {
            self.vcpu
                .reg(Reg::X(n))
                .map_err(|e| TrapError::Hypervisor(e.to_string()))
        };
        Ok(Aarch64SyscallFrame {
            x0: g(0)?,
            x1: g(1)?,
            x2: g(2)?,
            x3: g(3)?,
            x4: g(4)?,
            x5: g(5)?,
            x8: g(8)?,
        })
    }
}

// SAFETY: `KvmTrapEngine` holds a `KvmVm` (`Arc<VmFd>` + `Option<Kvm>` — `File`s,
// all `Send + Sync`), a `KvmVcpu` (`VcpuFd` — `Send + Sync` in kvm-ioctls), and a
// `GuestRam` whose only non-`Send` members are the window mmaps' raw `*mut u8`.
// Those host pointers are valid in EVERY thread of the process (threads share
// the address space; no fork is involved on the sibling path), and the KVM fds
// are usable from any thread, so moving the engine to its owning sibling thread
// is sound. Mirrors `unsafe impl Send for HvfTrapEngine`.
unsafe impl Send for KvmTrapEngine {}

/// The `Send` payload [`carrick_hal::ThreadedEngine::build_sibling_spec`] hands
/// to a freshly spawned host thread, which turns it into a sibling engine via
/// [`carrick_hal::ThreadedEngine::materialize_sibling`]. It carries a SHARED
/// handle to the parent's VM (`Arc<VmFd>` — `VmFd` is `Send + Sync`) plus the
/// seeded register snapshot and the parent's window descriptors so the new vCPU
/// runs in the SAME guest address space on the SAME VM. Unlike the `fork` child,
/// NO new VM is built and NO memory is re-registered — the sibling shares every
/// slot by construction.
pub struct KvmSiblingSpec {
    /// Shared handle to the SAME VM the parent runs on — the `VmFd` AND the
    /// shared vcpu-id allocator, so the sibling's `KVM_CREATE_VCPU` draws a
    /// UNIQUE id (1, 2, 3, …) instead of colliding with the main vCPU's id 0
    /// (the EEXIST that deadlocked the threaded loop). (Task 5 unknown #1.)
    vm: SharedVmHandle,
    /// `Send`-safe descriptors of the parent's host windows (raw `*mut u8`
    /// carried as `usize`; same VA in the sibling thread — no fork). The sibling
    /// builds a NON-OWNING `GuestRam` view over these (Task 5 unknown #2).
    windows: Vec<WindowDesc>,
    /// The parent's register file, already seeded for the new thread
    /// (x0=0, sp_el0=child stack, tpidr_el0=tls, pc=post-svc).
    snapshot: VcpuSnapshot,
    /// The parent's live stage-1 page-table editor, SHARED (Arc clone): a
    /// `clone(CLONE_THREAD)` sibling runs on the SAME VM with the SAME page-table
    /// backing, so its `mmap`/`mprotect` edits must go through the SAME manager —
    /// otherwise two managers over one backing would diverge (each holds its own
    /// in-memory descriptor copy). Mirrors HVF sharing the `page_tables` Arc.
    page_tables: Arc<Mutex<Option<carrick_mem::page_table::PageTableManager>>>,
    /// The parent's PROT_NONE bookkeeping, SHARED (Arc clone) so the sibling's
    /// syscall-path access checks observe the parent's (and every sibling's)
    /// `mprotect(PROT_NONE)`. Mirrors HVF sharing its `protections` Arc. Carried
    /// into the sibling's `GuestRam` via `from_shared_windows`.
    protections: Arc<MemoryProtections>,
    /// The sibling's reserved `VCPU_LIVE` slot, acquired HERE (synchronously
    /// with the trapped clone) so the execve drain can see the sibling before
    /// its host thread constructs a vCPU. Consumed at materialization (the +1
    /// transfers to the vcpu); dropped-unmaterialized releases it.
    ticket: crate::kvm::VcpuLiveTicket,
}

impl carrick_hal::RegAccess for KvmTrapEngine {
    fn get_reg(&self, r: Reg) -> Result<u64, OsError> {
        self.vcpu.reg(r)
    }
    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), OsError> {
        self.vcpu.set_reg(r, v)
    }
    fn get_sys_reg(&self, r: SysReg) -> Result<u64, OsError> {
        self.vcpu.get_sys_reg(r)
    }
    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), OsError> {
        self.vcpu.set_sys_reg(r, v)
    }
    fn get_vreg(&self, n: u32) -> Result<u128, OsError> {
        self.vcpu.get_vreg(n)
    }
    fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), OsError> {
        self.vcpu.set_vreg(n, v)
    }
    fn get_fpcr(&self) -> Result<u64, OsError> {
        Ok(u64::from(self.vcpu.get_fpcr()?))
    }
    fn set_fpcr(&mut self, v: u64) -> Result<(), OsError> {
        self.vcpu.set_fpcr(v as u32)
    }
    fn get_fpsr(&self) -> Result<u64, OsError> {
        Ok(u64::from(self.vcpu.get_fpsr()?))
    }
    fn set_fpsr(&mut self, v: u64) -> Result<(), OsError> {
        self.vcpu.set_fpsr(v as u32)
    }
}

impl carrick_hal::ThreadedEngine for KvmTrapEngine {
    type Arch = carrick_hal::Aarch64GuestArch;
    type KickHandle = KvmKickHandle;
    type SiblingSpec = KvmSiblingSpec;

    fn kick_handle(&self) -> Self::KickHandle {
        // Built on (and returning) the CURRENT vCPU thread's pthread id, so a
        // cross-thread `pthread_kill(tid, SIGRTMIN)` forces this vCPU out of
        // KVM_RUN. (The shared loop calls this on the owning vCPU thread.)
        KvmKickHandle::for_current_thread()
    }

    fn wait_for_vcpu_slot() {
        // NO-OP for KVM: there is no Apple-HVF-style concurrent-vCPU cap (HVF
        // limits ~64 concurrent vCPUs; KVM has no such admission gate), so a
        // sibling never has to wait for a slot before KVM_CREATE_VCPU.
    }

    fn build_sibling_spec(&self, stack: u64, tls: u64) -> Result<Self::SiblingSpec, TrapError> {
        // Snapshot the parent vCPU (taken while it is suspended at the trapped
        // `clone` syscall — atomic, race-free), then seed it for the new thread
        // (x0=0, sp_el0=stack, tpidr_el0=tls, pc=parent.elr_el1 = post-svc).
        let parent = self
            .vcpu
            .snapshot()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let snapshot = seed_sibling_snapshot(&parent, stack, tls);
        // Share the SAME VM (Arc<VmFd>) + the parent's window descriptors so the
        // sibling vCPU runs in the SAME address space on the SAME VM.
        Ok(KvmSiblingSpec {
            vm: self.vm.vm_handle(),
            windows: self.ram.window_descriptors(),
            snapshot,
            // Share the SAME page-table editor (Arc clone): the sibling edits the
            // SAME backing through the SAME manager.
            page_tables: Arc::clone(&self.page_tables),
            // Share the SAME PROT_NONE bookkeeping so the sibling observes the
            // parent's mprotect(PROT_NONE) (and vice versa) on the syscall path.
            protections: self.ram.shared_protections(),
            // Reserve the sibling's VCPU_LIVE slot NOW — this runs while the
            // parent is suspended at the trapped clone, BEFORE the guest can
            // race ahead into execve, closing the materialization blind window
            // (9/60 multithreaded-execv iterations EFAULT'd without it).
            ticket: crate::kvm::VcpuLiveTicket::acquire(),
        })
    }

    fn materialize_sibling(spec: Self::SiblingSpec) -> Result<Self, TrapError>
    where
        Self: Sized,
    {
        // Create a NEW vCPU on the SAME VM (siblings share all slots — no
        // re-registration, unlike the fork child which rebuilds a fresh VM).
        let vm = KvmVm::from_shared_vm(spec.vm);
        let mut vcpu = vm
            .add_sibling_vcpu()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // The vcpu now exists: transfer the spec's reserved VCPU_LIVE slot to
        // it (KvmVcpu::drop owns the decrement from here on). Consume BEFORE
        // the fallible restore below — if restore fails, the dropped vcpu does
        // the single decrement; consuming later would double-count the error
        // path (ticket Drop + vcpu Drop).
        spec.ticket.consume();
        // Restore the seeded register file onto the new vCPU. Unlike the fork
        // child, the PC is already the post-svc address (seed_sibling_snapshot
        // set pc = parent.elr_el1), so there is NO sentinel-store replay to skip.
        vcpu.restore(&spec.snapshot)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // A NON-OWNING view over the parent's host windows: the sibling reads/
        // writes syscall buffers through the SAME backing but NEVER munmaps it
        // (the owning parent frees it at process exit). It SHARES the parent's
        // PROT_NONE bookkeeping so cross-thread mprotect is coherent.
        let ram = GuestRam::from_shared_windows(&spec.windows, Arc::clone(&spec.protections));
        Ok(Self {
            vm,
            vcpu,
            ram,
            // A clone(CLONE_THREAD) sibling is NOT a forked child — it shares the
            // parent's process and exits via the normal thread-exit path.
            is_forked_child: false,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            last_fault_esr: 0,
            // Share the parent's page-table editor (same VM, same backing). The
            // PROT_NONE bookkeeping is shared via `ram`'s protections (above).
            page_tables: spec.page_tables,
        })
    }

    fn program_counter(&self) -> Result<u64, TrapError> {
        self.vcpu
            .reg(Reg::Pc)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn set_guest_sp_el0(&self, sp: u64) -> Result<(), TrapError> {
        // SP_EL0 is `Reg::Sp` (the EL0/user stack), NOT a sysreg. `&self` write
        // via the shared (`&self`) KVM_SET_ONE_REG path.
        self.vcpu
            .set_reg_shared(Reg::Sp, sp)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn set_guest_thread_id(&self, _tid: u64) -> Result<(), TrapError> {
        // No-op: KVM has no in-guest gettid fast path (that needs the syscall
        // shim, which the KVM backend does not run). The guest reads its tid via
        // the trapped `gettid` syscall, serviced by the dispatcher. Mirrors the
        // HVF no-shim path.
        Ok(())
    }

    fn destroy_vcpu_on_thread_exit(&mut self) {
        // No explicit KVM teardown is required on a sibling thread exit:
        // dropping `self.vcpu` PARKS its `VcpuFd` into the shared per-VM
        // recycle pool for reuse (vcpu ids are finite and never freed — see
        // `KvmVcpu::fd`), and the sibling's non-owning `GuestRam` view drops
        // without munmapping the shared windows. The shared VM stays alive via
        // the parent's (and other siblings') Arc.
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn carrick_hal::VcpuRegistry> {
        // CHILD side of a guest fork: libc::fork replicated only the calling
        // thread, so the child drops the parent's kicker and starts over with an
        // empty one (no phantom siblings). The child rebuilds its private-futex
        // backend via the PlatformFutexFactory in the run loop (Task 7).
        Arc::new(KvmKicker::new())
    }

    // The fork-lifecycle hooks (fork_vfork / release_vcpu_for_fork /
    // rebuild_vcpu_after_fork / publish_vm_for_siblings) keep their trait-default
    // no-ops: KVM's fork() rebuilds a fresh VM in the child directly (Task 2),
    // and siblings share the live VM without any HVF-style publish step.
}

#[cfg(test)]
mod execve_tests {
    //! `execve_into` unit tests. These build a REAL `KvmTrapEngine` (needing
    //! `/dev/kvm`) and assert the post-execve vCPU state directly — no full guest
    //! run. They therefore execute only where `/dev/kvm` is present (the lima L2
    //! lane / a native aarch64 Linux host); on a host without KVM they SKIP (the
    //! crate itself is `cfg(target_os = "linux")`, so macOS never compiles them).
    use super::*;
    use carrick_hal::SysReg;
    use carrick_mem::memory::{AddressSpace, LINUX_EL1_VECTORS_BASE, LINUX_PAGE_TABLES_BASE};

    // Two freestanding static aarch64 ELFs committed under fixtures/: the
    // fork-wait4 driver (initial image) and the exit0 execve target (new image).
    // Both are valid ELFs `AddressSpace::load_elf_bytes` can parse.
    const INITIAL_ELF: &[u8] = include_bytes!("../fixtures/fork-wait4/fork-wait4");
    const TARGET_ELF: &[u8] = include_bytes!("../fixtures/exec-target-exit0/exec-target-exit0");

    /// True when `/dev/kvm` is usable; tests SKIP (return early) otherwise so the
    /// suite is green on KVM-less hosts.
    fn kvm_available() -> bool {
        std::path::Path::new("/dev/kvm").exists()
    }

    fn engine_for(bytes: &[u8]) -> KvmTrapEngine {
        let image = AddressSpace::load_elf_bytes(bytes).expect("load test ELF");
        KvmTrapEngine::new(&image).expect("bring up test engine")
    }

    /// Like `engine_for`, but gives the guest a real Linux initial stack (8 MiB at
    /// `LINUX_STACK_TOP`) so signal-frame pushes have writable headroom. The committed
    /// freestanding fixtures (e.g. fork-wait4) deliberately set up no stack of their own.
    fn engine_for_with_stack(bytes: &[u8]) -> KvmTrapEngine {
        let no_env: [&str; 0] = [];
        let image = AddressSpace::load_elf_bytes(bytes)
            .expect("load test ELF")
            .with_linux_initial_stack(["prog"], no_env)
            .expect("attach initial stack");
        KvmTrapEngine::new(&image).expect("bring up test engine")
    }

    /// After `execve_into`, the stage-1 MMU sysregs point at the canonical
    /// carrick page-table / vector bases and MAIR is the Normal-WB value — i.e.
    /// the new image is correctly re-bootstrapped on the LIVE vCPU.
    #[test]
    fn execve_into_reprograms_sysregs() {
        if !kvm_available() {
            eprintln!("SKIP execve_into_reprograms_sysregs: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");
        engine.execve_into(&new_image).expect("execve_into");

        let v = &engine.vcpu;
        assert_eq!(
            v.get_sys_reg(SysReg::Ttbr0).unwrap(),
            LINUX_PAGE_TABLES_BASE,
            "TTBR0 must point at the stage-1 identity tables"
        );
        assert_eq!(
            v.get_sys_reg(SysReg::Ttbr1).unwrap(),
            LINUX_PAGE_TABLES_BASE,
            "TTBR1 shares the stage-1 root"
        );
        assert_eq!(
            v.get_sys_reg(SysReg::Vbar).unwrap(),
            LINUX_EL1_VECTORS_BASE,
            "VBAR must point at the sentinel EL1 vectors"
        );
        assert_eq!(
            v.get_sys_reg(SysReg::Mair).unwrap(),
            0xFF,
            "MAIR slot 0 = Normal Inner/Outer WB"
        );
        // Stage-1 on (SCTLR_EL1.M = bit 0).
        assert_eq!(
            v.get_sys_reg(SysReg::Sctlr).unwrap() & 1,
            1,
            "SCTLR_EL1.M must be set (stage-1 MMU on)"
        );
        // execve resets the EL0 thread pointer.
        assert_eq!(
            v.get_sys_reg(SysReg::TpidrEl0).unwrap(),
            0,
            "TPIDR_EL0 must be reset to 0 across execve"
        );
    }

    /// Linux execve starts the new program with x0..x30 clear. Dirty every GPR
    /// before execve and assert they are all zero afterwards.
    #[test]
    fn execve_into_clears_gprs() {
        if !kvm_available() {
            eprintln!("SKIP execve_into_clears_gprs: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        // Dirty all GPRs to a non-zero pattern.
        for n in 0..=30u32 {
            engine
                .vcpu
                .set_reg(Reg::X(n), 0xDEAD_0000 | u64::from(n))
                .unwrap();
        }
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");
        engine.execve_into(&new_image).expect("execve_into");
        for n in 0..=30u32 {
            assert_eq!(
                engine.vcpu.reg(Reg::X(n)).unwrap(),
                0,
                "x{n} must be cleared by execve"
            );
        }
    }

    /// `is_forked_child` must survive execve (a forked-then-execve'd descendant
    /// keeps the `_exit`-without-report shutdown path).
    #[test]
    fn execve_into_preserves_is_forked_child() {
        if !kvm_available() {
            eprintln!("SKIP execve_into_preserves_is_forked_child: no /dev/kvm");
            return;
        }
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");

        // Case A: a NON-forked engine stays non-forked across execve.
        let mut e0 = engine_for(INITIAL_ELF);
        assert!(!e0.is_forked_child());
        e0.execve_into(&new_image)
            .expect("execve_into (non-forked)");
        assert!(
            !e0.is_forked_child(),
            "execve must not spuriously set is_forked_child"
        );

        // Case B: a forked engine stays forked across execve.
        let mut e1 = engine_for(INITIAL_ELF);
        e1.is_forked_child = true;
        e1.execve_into(&new_image).expect("execve_into (forked)");
        assert!(
            e1.is_forked_child(),
            "execve must preserve is_forked_child = true"
        );
    }

    /// PC after execve is the EL0 trampoline base (the vCPU restarts in EL1h and
    /// `eret`s into the new image's entry), and ELR_EL1 holds the new entry.
    #[test]
    fn execve_into_repositions_pc_to_new_entry() {
        if !kvm_available() {
            eprintln!("SKIP execve_into_repositions_pc_to_new_entry: no /dev/kvm");
            return;
        }
        use carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE;
        let mut engine = engine_for(INITIAL_ELF);
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");
        let new_entry = new_image.entry();
        engine.execve_into(&new_image).expect("execve_into");
        assert_eq!(
            engine.vcpu.reg(Reg::Pc).unwrap(),
            LINUX_EL0_TRAMPOLINE_BASE,
            "PC must be the EL0 trampoline so the eret drops to EL0 at the new entry"
        );
        assert_eq!(
            engine.vcpu.reg(Reg::ElrEl1).unwrap(),
            new_entry,
            "ELR_EL1 must hold the new image's entry"
        );
    }

    #[test]
    fn kvm_fpsimd_roundtrip() {
        use carrick_hal::RegAccess;
        if !kvm_available() {
            eprintln!("SKIP kvm_fpsimd_roundtrip: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        // Distinct u128 patterns into V0..V3, known u32s into FPSR/FPCR, read back.
        for n in 0..4u32 {
            let v = (0x1111_1111_0000_0000u128 << (n as u128)) | (u128::from(n) + 1);
            engine.set_vreg(n, v).unwrap();
            assert_eq!(engine.get_vreg(n).unwrap(), v, "V{n} must round-trip");
        }
        engine.set_fpsr(0x0000_0010).unwrap();
        engine.set_fpcr(0x0040_0000).unwrap();
        assert_eq!(engine.get_fpsr().unwrap(), 0x0000_0010, "FPSR round-trips");
        assert_eq!(engine.get_fpcr().unwrap(), 0x0040_0000, "FPCR round-trips");
    }

    #[test]
    fn kvm_fpsimd_snapshot_restore() {
        use carrick_hal::RegAccess;
        if !kvm_available() {
            eprintln!("SKIP kvm_fpsimd_snapshot_restore: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        engine.set_vreg(0, 0xABCD_0000_0000_1234u128).unwrap();
        engine.set_fpsr(0x0000_0008).unwrap();
        let snap = engine.vcpu.snapshot().unwrap();
        assert_eq!(
            snap.vregs[0], 0xABCD_0000_0000_1234u128,
            "snapshot captures V0"
        );
        assert_eq!(snap.fpsr, 0x0000_0008, "snapshot captures FPSR");
        // Trash live state, then restore from the snapshot.
        engine.set_vreg(0, 0).unwrap();
        engine.set_fpsr(0).unwrap();
        engine.vcpu.restore(&snap).unwrap();
        assert_eq!(
            engine.get_vreg(0).unwrap(),
            0xABCD_0000_0000_1234u128,
            "restore recovers V0"
        );
        assert_eq!(
            engine.get_fpsr().unwrap(),
            0x0000_0008,
            "restore recovers FPSR"
        );
    }

    #[test]
    fn kvm_orig_x0_and_nr_captured_on_syscall() {
        if !kvm_available() {
            eprintln!("SKIP kvm_orig_x0_and_nr_captured_on_syscall: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        let frame = engine
            .next_syscall()
            .expect("run to first svc")
            .expect("a syscall frame");
        assert_eq!(
            engine.last_syscall_orig_x0, frame.x0,
            "orig_x0 latched from frame.x0"
        );
        assert_eq!(
            engine.last_syscall_nr(),
            Some(frame.x8),
            "last_syscall_nr latched from frame.x8"
        );
    }

    #[test]
    fn kvm_tracking_fields_reset_across_execve() {
        if !kvm_available() {
            eprintln!("SKIP kvm_tracking_fields_reset_across_execve: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        engine.last_fault_esr = 0xDEAD;
        engine.last_syscall_orig_x0 = 0xBEEF;
        engine.last_syscall_nr = Some(99);
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");
        engine.execve_into(&new_image).expect("execve_into");
        assert_eq!(engine.last_fault_esr, 0, "fault_esr reset across execve");
        assert_eq!(
            engine.last_syscall_orig_x0, 0,
            "orig_x0 reset across execve"
        );
        assert_eq!(
            engine.last_syscall_nr, None,
            "last_syscall_nr reset across execve"
        );
    }

    #[test]
    fn kvm_inject_signal_redirects_to_handler() {
        use carrick_hal::RegAccess;
        if !kvm_available() {
            eprintln!("SKIP kvm_inject_signal_redirects_to_handler: no /dev/kvm");
            return;
        }
        let mut engine = engine_for_with_stack(INITIAL_ELF);
        // Run to the guest's first svc so the engine is in a post-syscall state
        // (ELR_EL1 = svc+4, SPSR_EL1 = EL0t, tracking fields populated).
        engine
            .next_syscall()
            .expect("first svc")
            .expect("a syscall frame");

        let handler = 0x4_0000u64;
        let sp_before = engine.get_reg(Reg::Sp).unwrap();
        engine
            .inject_signal(
                libc::SIGUSR1,
                handler,
                0,
                None,
                None,
                None,
                0,
                None,
                None,
                false,
            )
            .expect("inject_signal");

        // Syscall path (interrupted_pc = None) redirects ELR_EL1, not live PC.
        assert_eq!(
            engine.get_reg(Reg::ElrEl1).unwrap(),
            handler,
            "handler entry on ELR_EL1"
        );
        assert_eq!(
            engine.get_reg(Reg::X(0)).unwrap(),
            libc::SIGUSR1 as u64,
            "x0 = signum"
        );
        assert!(
            engine.get_reg(Reg::Sp).unwrap() < sp_before,
            "frame pushed: SP_EL0 moved down"
        );
    }

    #[test]
    fn kvm_inject_then_restore_roundtrips() {
        use carrick_hal::RegAccess;
        if !kvm_available() {
            eprintln!("SKIP kvm_inject_then_restore_roundtrips: no /dev/kvm");
            return;
        }
        let mut engine = engine_for_with_stack(INITIAL_ELF);
        engine
            .next_syscall()
            .expect("first svc")
            .expect("a syscall frame");

        let saved_elr = engine.get_reg(Reg::ElrEl1).unwrap(); // pre-signal resume PC
        let saved_sp = engine.get_reg(Reg::Sp).unwrap();
        engine.set_vreg(0, 0x0BAD_F00D_0000_1234u128).unwrap();
        let v0_before = engine.get_vreg(0).unwrap();
        let sigmask = 0x0000_0000_0000_FF00u64;

        engine
            .inject_signal(
                libc::SIGUSR1,
                0x4_0000,
                0,
                None,
                None,
                None,
                sigmask,
                None,
                None,
                false,
            )
            .expect("inject_signal");
        // Simulate the handler clobbering V0 before rt_sigreturn.
        engine.set_vreg(0, 0).unwrap();

        let got_mask = engine
            .restore_from_sigframe()
            .expect("restore_from_sigframe");
        assert_eq!(
            got_mask, sigmask,
            "restore returns the SAVED SIGMASK (not saved_pc)"
        );
        assert_eq!(
            engine.get_reg(Reg::ElrEl1).unwrap(),
            saved_elr,
            "resume PC restored"
        );
        assert_eq!(
            engine.get_reg(Reg::Sp).unwrap(),
            saved_sp,
            "SP_EL0 restored"
        );
        assert_eq!(
            engine.get_vreg(0).unwrap(),
            v0_before,
            "V0 restored from the frame"
        );
    }

    /// `map_host_alias` with `file=None` (a high-VA anonymous alias) seeds the
    /// payload into a fresh KVM-backed window and the syscall read-path resolves
    /// the high alias VA back to it (proving the VA-keyed window + the live slot).
    #[test]
    fn kvm_map_host_alias_anon_roundtrips() {
        use carrick_guest_mem::GuestMemory;
        use carrick_mem::memory::LINUX_HIGH_VA_THRESHOLD;
        if !kvm_available() {
            eprintln!("SKIP kvm_map_host_alias_anon_roundtrips: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        let before = engine.ram.window_count();
        // 2 MiB into the alias VA span (2 MiB-aligned -> map_aliased block path).
        let va = LINUX_HIGH_VA_THRESHOLD + 0x20_0000;
        let payload = b"carrick alias payload".to_vec();
        engine
            .map_host_alias(va, 0, 0x1000, &payload, None)
            .expect("map_host_alias anon");
        assert_eq!(
            engine.ram.window_count(),
            before + 1,
            "alias added exactly one KVM-backed window"
        );
        let got = engine.read_bytes(va, payload.len()).expect("read alias VA");
        assert_eq!(
            got, payload,
            "read_bytes at the alias VA returns the payload"
        );
    }

    /// `map_host_alias` with `file=Some(..)` maps a host fd MAP_SHARED; the alias
    /// VA reads back the file's bytes (the MAP_SHARED-file coherence path).
    #[test]
    fn kvm_map_host_alias_file_roundtrips() {
        use carrick_guest_mem::GuestMemory;
        use carrick_mem::memory::LINUX_HIGH_VA_THRESHOLD;
        if !kvm_available() {
            eprintln!("SKIP kvm_map_host_alias_file_roundtrips: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        let content = b"file-backed alias via MAP_SHARED";
        // An anonymous host file (memfd) with known content.
        let fd = unsafe { libc::memfd_create(c"carrick-alias".as_ptr(), 0) };
        assert!(fd >= 0, "memfd_create");
        assert_eq!(unsafe { libc::ftruncate(fd, 0x1000) }, 0, "ftruncate");
        let n = unsafe { libc::pwrite(fd, content.as_ptr().cast(), content.len(), 0) };
        assert_eq!(n, content.len() as isize, "pwrite");
        // map_host_alias closes the fd it receives, so hand it a dup.
        let dup = unsafe { libc::dup(fd) };
        assert!(dup >= 0, "dup");
        let va = LINUX_HIGH_VA_THRESHOLD + 0x40_0000;
        engine
            .map_host_alias(
                va,
                0,
                0x1000,
                &[],
                Some((dup, 0, libc::PROT_READ | libc::PROT_WRITE)),
            )
            .expect("map_host_alias file");
        let got = engine
            .read_bytes(va, content.len())
            .expect("read file alias VA");
        assert_eq!(
            got, content,
            "read_bytes at the file-alias VA returns the file content"
        );
        unsafe { libc::close(fd) };
    }

    /// A guest-FIXED VA outside the 64 GiB alias arena (e.g. the Rosetta 128 TiB
    /// range) is rejected with an error, NOT silently mapped to a colliding GPA.
    #[test]
    fn kvm_map_host_alias_rejects_out_of_arena_va() {
        use carrick_mem::memory::LINUX_HIGH_VA_THRESHOLD;
        if !kvm_available() {
            eprintln!("SKIP kvm_map_host_alias_rejects_out_of_arena_va: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        // 1 TiB + ~6.4 TiB: well past the 64 GiB arena.
        let va = LINUX_HIGH_VA_THRESHOLD + 0x10_0000_0000u64 * 100;
        let r = engine.map_host_alias(va, 0, 0x1000, &[1, 2, 3], None);
        assert!(
            r.is_err(),
            "a VA outside the alias arena must be rejected, not corrupt memory"
        );
    }
}
