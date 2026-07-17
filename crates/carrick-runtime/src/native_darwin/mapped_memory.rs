//! Guest-memory model for the Darwin-native execution backend.
//!
//! Owns `NativeMappedMemory` (the `GuestMemory` impl backing the native
//! backend), its image-mapping/protection/exclusive-monitor machinery, and
//! the small immutable-config wrapper (`NativeMemoryHandle`/
//! `NativeMemoryConfig`) that lets hot-path readers avoid its `RwLock`.

use super::*;

pub(super) const VM_INHERIT_SHARE: libc::c_int = 0;
pub(super) const VM_INHERIT_COPY: libc::c_int = 1;

/// Immutable-after-image-load memory configuration: `address_mode`,
/// `host_page_size`, `linux_page_size`, and `owned_host_ranges` are set once
/// when an image is mapped and only ever rewritten (all together) by
/// `NativeMemoryHandle::replace_image` on execve -- a whole-process quiesce,
/// so a plain snapshot swap is safe. Bundled behind its own dedicated lock,
/// separate from `NativeMappedMemory`'s big `RwLock` (which also gates
/// region/protection-table mutation and DSR translation), so hot-path
/// readers of just these fields never contend with that lock. A single lock
/// over all of them (rather than independent atomics per field) also
/// guarantees callers observe a consistent snapshot instead of a torn read
/// mid-execve.
///
/// `owned_host_ranges` is `Arc`-wrapped rather than duplicated by value: it
/// is a `Vec` (unlike the other, `Copy` fields), and `NativeMappedMemory`'s
/// own cold-path methods (`prepare_exec_mapping`/`replace_image`/
/// `fixed_mapping_target`) still read it directly off `self` under the big
/// lock they already hold, exactly as before. The `Arc` here is a cheap
/// refcount clone of that same allocation, not a second source of truth --
/// `from_memory` (below) is the only place it's produced, always from the
/// `NativeMappedMemory` that is about to become (or just became) canonical.
#[derive(Clone, Debug)]
pub(super) struct NativeMemoryConfig {
    address_mode: NativeAddressMode,
    host_page_size: u64,
    linux_page_size: u64,
    owned_host_ranges: Arc<Vec<std::ops::Range<carrick_guest_mem::HostVa>>>,
}

impl NativeMemoryConfig {
    pub(super) fn from_memory(memory: &NativeMappedMemory) -> Self {
        Self {
            address_mode: memory.address_mode,
            host_page_size: memory.host_page_size,
            linux_page_size: memory.linux_page_size,
            owned_host_ranges: Arc::clone(&memory.owned_host_ranges),
        }
    }
}

/// Owner of a `NativeMappedMemory`'s `RwLock`, paired with the lock-free
/// `NativeMemoryConfig` snapshot (Task 8). `Deref`s to
/// `RwLock<NativeMappedMemory>` so every existing `.read()`/`.write()`/
/// `.upgradable_read()` call site through `SharedNativeMemory` keeps working
/// unchanged; the config accessors below are additional, not a replacement
/// for the locked struct fields (which every other internal
/// `NativeMappedMemory` method continues to read directly).
pub(super) struct NativeMemoryHandle {
    memory: parking_lot::RwLock<NativeMappedMemory>,
    config: parking_lot::RwLock<NativeMemoryConfig>,
}

impl NativeMemoryHandle {
    pub(super) fn new(memory: NativeMappedMemory) -> Self {
        let config = NativeMemoryConfig::from_memory(&memory);
        Self {
            memory: parking_lot::RwLock::new(memory),
            config: parking_lot::RwLock::new(config),
        }
    }

    /// `address_mode` without acquiring `self.memory`'s `RwLock` -- see
    /// `NativeMemoryConfig`'s doc comment.
    pub(super) fn address_mode(&self) -> NativeAddressMode {
        self.config.read().address_mode
    }

    /// `host_page_size` without acquiring `self.memory`'s `RwLock` -- see
    /// `NativeMemoryConfig`'s doc comment.
    pub(super) fn host_page_size(&self) -> u64 {
        self.config.read().host_page_size
    }

    /// `linux_page_size` without acquiring `self.memory`'s `RwLock` -- see
    /// `NativeMemoryConfig`'s doc comment.
    pub(super) fn linux_page_size(&self) -> u64 {
        self.config.read().linux_page_size
    }

    /// `owned_host_ranges` without acquiring `self.memory`'s `RwLock` -- see
    /// `NativeMemoryConfig`'s doc comment. Returns a cheap `Arc` clone (a
    /// refcount bump, not a copy of the ranges); the caller can then read
    /// the ranges without holding ANY lock at all. Only exercised directly
    /// by tests today (`biased_guest_fault_address`, below, is the
    /// production caller); kept `pub(super)` as the general-purpose
    /// lock-free accessor future hot-path callers should reach for.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn owned_host_ranges(&self) -> Arc<Vec<std::ops::Range<carrick_guest_mem::HostVa>>> {
        Arc::clone(&self.config.read().owned_host_ranges)
    }

    /// Reverse-translates a Biased-mode host fault address to its guest VA
    /// using only the lock-free `address_mode`/`owned_host_ranges` config --
    /// mirrors `NativeMappedMemory::guest_fault_address`'s Biased-mode
    /// branch exactly, without acquiring `self.memory`'s `RwLock`. Callers
    /// must already know they're in Biased mode (checked via the
    /// also-lock-free `address_mode()`); Direct mode still needs
    /// `region_contains`, which remains behind the big lock pending the
    /// later ArcSwap phases (`docs/superpowers/specs/2026-07-15-mmap-writer-
    /// lockfree-reads-design.md`).
    pub(super) fn biased_guest_fault_address(
        &self,
        address: carrick_guest_mem::HostVa,
    ) -> Option<carrick_guest_mem::GuestVa> {
        let config = self.config.read();
        if !config
            .owned_host_ranges
            .iter()
            .any(|range| address >= range.start && address < range.end)
        {
            return None;
        }
        config.address_mode.to_guest(address).ok()
    }

    /// Mirrors `NativeMappedMemory::uses_linux4k_subpages`, backed by the
    /// same immutable-after-init config, without acquiring `self.memory`'s
    /// `RwLock`.
    pub(super) fn uses_linux4k_subpages(&self) -> bool {
        self.host_page_size() == 16 * 1024 && self.linux_page_size() == 4 * 1024
    }

    /// Forwards to `NativeMappedMemory::replace_image` under the write
    /// guard, then refreshes the lock-free config snapshot so subsequent
    /// `address_mode`/`host_page_size`/`linux_page_size`/`owned_host_ranges`
    /// reads observe the new image immediately. This is the ONLY path that
    /// may rewrite those fields after image load (execve), so routing every
    /// `SharedNativeMemory`-level `replace_image` call through here (instead
    /// of `.write().replace_image(...)`) makes forgetting the config
    /// refresh impossible for production callers. Tests that operate on a
    /// bare `NativeMappedMemory` (not wrapped in a handle) still call
    /// `NativeMappedMemory::replace_image` directly and are unaffected.
    pub(super) fn replace_image(
        &self,
        image: &AddressSpace,
        relative_relocations: &[NativeRelativeRelocation],
        plan: &ExecutionPlan,
        dsr_tid: Option<crate::thread::ThreadId>,
        prepared: PreparedNativeExecMapping,
    ) -> Result<(), RuntimeError> {
        let mut guard = self.memory.write();
        guard.replace_image(image, relative_relocations, plan, dsr_tid, prepared)?;
        *self.config.write() = NativeMemoryConfig::from_memory(&guard);
        Ok(())
    }
}

impl std::ops::Deref for NativeMemoryHandle {
    type Target = parking_lot::RwLock<NativeMappedMemory>;

    fn deref(&self) -> &Self::Target {
        &self.memory
    }
}

pub(super) type SharedNativeMemory = Arc<NativeMemoryHandle>;

/// A reference-counted temporary lift of a single PROTECTED host guest page.
///
/// `prepare_temporary_host_access` flips a bookkept-PROTECTED page to
/// accessible via a process-global `mprotect` so a supervisor copy can touch
/// the backing, then `restore_temporary_host_access` flips it back. Because the
/// non-mutating syscall path now runs under a shared memory-`RwLock` read guard
/// (Task 6), two accessors can lift/restore the SAME page concurrently; without
/// coordination one accessor's restore would strand another mid-copy with a
/// PROT_NONE page (host SIGSEGV). This record keeps a page lifted while ANY
/// accessor holds it and restores it to `original_prot` only when the LAST one
/// leaves.
#[derive(Debug)]
pub(super) struct HostLift {
    /// Number of in-flight accessors currently relying on this page's lift.
    refcount: u32,
    /// The protection to restore once the final accessor releases -- the page's
    /// bookkept native protection at the time of the first lift.
    original_prot: libc::c_int,
    /// The protection the page is currently mprotect-ed to; monotonically
    /// upgraded (never downgraded before refcount 0) so a reader-then-writer
    /// overlap ends up at RW and stays there until both release.
    lifted_prot: libc::c_int,
}

/// RAII backstop that runs `restore_temporary_host_access` on drop while
/// `armed`, so a temporary host-page lift's refcount is never stranded if the
/// window between prepare and restore unwinds or exits early. Callers disarm it
/// and restore explicitly on the success path to preserve restore-error
/// propagation.
pub(super) struct HostLiftRestoreGuard<'a> {
    memory: &'a NativeMappedMemory,
    changed: &'a [(u64, libc::c_int)],
    address: u64,
    length: usize,
    armed: bool,
}

impl Drop for HostLiftRestoreGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Best-effort: a Drop cannot propagate the restore error, but the
            // refcount decrement happens regardless so no lift is leaked.
            let _ =
                self.memory
                    .restore_temporary_host_access(self.changed, self.address, self.length);
        }
    }
}

pub(super) struct NativeMappedMemory {
    pub(super) address_mode: NativeAddressMode,
    // Host-coordinate authority for image retirement, biased fixed remaps,
    // and validated reverse faults. Biased intervals are collision-reserved;
    // direct intervals are normalized planned ownership recorded after the
    // established unreserved MAP_FIXED mapping path succeeds. `Arc`-wrapped
    // so `NativeMemoryConfig` (above) can hold a cheap refcount-clone of the
    // SAME allocation and serve hot-path reads without acquiring this
    // struct's own big `RwLock` -- see `NativeMemoryConfig`'s doc comment.
    // Never incrementally mutated (no push/insert/remove anywhere): only
    // set at construction and wholesale-replaced by `replace_image`
    // (execve), exactly like `address_mode`/`host_page_size`/
    // `linux_page_size`.
    pub(super) owned_host_ranges: Arc<Vec<std::ops::Range<carrick_guest_mem::HostVa>>>,
    pub(super) regions: Vec<NativeMappedRegion>,
    pub(super) protections: MemoryProtections,
    pub(super) native_page_protections: BTreeMap<u64, u64>,
    pub(super) native_write_exec_writable_pages: BTreeSet<u64>,
    pub(super) linux4k_page_protections: BTreeMap<u64, [u64; 4]>,
    // The exclusive-monitor reservation itself now lives per guest thread
    // (`NativeThreadRuntime.exclusive_reservation`), not here. The DSR-hot
    // path already threaded it through `exclusive_load_for`/`exclusive_store_for`;
    // the single-threaded-gated linux4k guarded path (`emulate_linux4k_guarded_*`)
    // now does the same via `exclusive_load`/`exclusive_store`. Only the shared
    // sequence bookkeeping below remains on the struct, behind its own interior
    // lock so it stays reachable through a shared `&self`.
    pub(super) exclusive_sequences:
        parking_lot::Mutex<BTreeMap<NativeExclusiveLocation, NativeExclusiveSequence>>,
    pub(super) host_page_size: u64,
    pub(super) linux_page_size: u64,
    pub(super) dsr_generations: dsr::cache::PageGenerationTable,
    pub(super) dsr_translator: Option<Arc<dsr::ProcessTranslator>>,
    // Reference-counted temporary host-page lifts (see [`HostLift`]). Keyed by
    // the guest page address recorded in each accessor's `changed` list.
    // Interior-mutable so `prepare_temporary_host_access`/
    // `restore_temporary_host_access` stay `&self` (REQUIRED: they run under the
    // shared memory-`RwLock` read guard). This is a LEAF lock -- while it is
    // held we only touch the map, call `host_address` (pure arithmetic), and
    // `set_host_prot` (a bare `mprotect`, or the test spy); never another lock
    // or the memory `RwLock`. The no-lift fast path never acquires it.
    pub(super) host_access_lifts: parking_lot::Mutex<std::collections::HashMap<u64, HostLift>>,
}

pub(super) struct PreparedNativeExecMapping {
    pub(super) native_layout: NativeLayout,
    pub(super) process_translator: Arc<dsr::ProcessTranslator>,
    pub(super) reset_inherited_translator: bool,
    pub(super) direct_target_reservations: Vec<crate::host_proc::DirectVmReservation>,
    pub(super) rollback_plan: NativeMappingRollbackPlan,
}

#[derive(Clone, Copy)]
pub(super) enum NativeImageBacking<'a> {
    AnonymousBytes,
    Prepared(&'a ValidatedPreparedImage),
}

impl NativeImageBacking<'_> {
    #[cfg(test)]
    pub(super) fn is_prepared(self) -> bool {
        matches!(self, Self::Prepared(_))
    }
}

pub(super) struct NativeMappingRollbackPlan {
    pub(super) supplemental_ranges: Vec<std::ops::Range<carrick_guest_mem::HostVa>>,
}

impl NativeMappingRollbackPlan {
    pub(super) fn for_fresh_layout(layout: &NativeLayout) -> Self {
        let supplemental_ranges = match layout.address_mode() {
            NativeAddressMode::Direct => layout.owned_ranges().to_vec(),
            NativeAddressMode::Biased { .. } => Vec::new(),
        };
        Self {
            supplemental_ranges,
        }
    }

    pub(super) fn direct_exec(
        owned_ranges: &[std::ops::Range<carrick_guest_mem::HostVa>],
        mut reservation_ranges: Vec<std::ops::Range<carrick_guest_mem::HostVa>>,
    ) -> Self {
        normalize_host_ranges(&mut reservation_ranges);
        Self {
            supplemental_ranges: subtract_host_ranges(owned_ranges, &reservation_ranges),
        }
    }
}

pub(super) struct NativeMappingRollback {
    supplemental_ranges: Vec<std::ops::Range<carrick_guest_mem::HostVa>>,
    mapped_supplemental_ranges: Vec<std::ops::Range<carrick_guest_mem::HostVa>>,
    host_page_size: usize,
    armed: bool,
}

impl NativeMappingRollback {
    pub(super) fn new(
        plan: NativeMappingRollbackPlan,
        host_page_size: u64,
        capacity: usize,
    ) -> Result<Self, RuntimeError> {
        let host_page_size = usize::try_from(host_page_size).map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native rollback host page size is not representable: 0x{host_page_size:x}"
            ))
        })?;
        if !host_page_size.is_power_of_two() {
            return Err(RuntimeError::Unsupported(format!(
                "native rollback host page size is invalid: 0x{host_page_size:x}"
            )));
        }
        Ok(Self {
            supplemental_ranges: plan.supplemental_ranges,
            mapped_supplemental_ranges: Vec::with_capacity(capacity),
            host_page_size,
            armed: true,
        })
    }

    pub(super) fn track_mapping(&mut self, start: carrick_guest_mem::HostVa, length: usize) {
        if length == 0 || self.supplemental_ranges.is_empty() {
            return;
        }
        let page_mask = self.host_page_size.saturating_sub(1);
        let mapped_start = start.raw() & !page_mask;
        let mapped_end = start.raw().saturating_add(length).saturating_add(page_mask) & !page_mask;
        for owned in &self.supplemental_ranges {
            let overlap_start = mapped_start.max(owned.start.raw());
            let overlap_end = mapped_end.min(owned.end.raw());
            if overlap_start < overlap_end {
                self.mapped_supplemental_ranges.push(
                    carrick_guest_mem::HostVa(overlap_start)
                        ..carrick_guest_mem::HostVa(overlap_end),
                );
            }
        }
        normalize_host_ranges(&mut self.mapped_supplemental_ranges);
    }

    pub(super) fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for NativeMappingRollback {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for range in &self.mapped_supplemental_ranges {
            let length = range.end.raw().saturating_sub(range.start.raw());
            if length == 0 {
                continue;
            }
            #[cfg(test)]
            NATIVE_TEST_SUPPLEMENTAL_ROLLBACKS.with(|slot| slot.borrow_mut().push(range.clone()));
            unsafe {
                libc::munmap(range.start.raw() as *mut libc::c_void, length);
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct NativeMappingPageSizes {
    host: u64,
    linux: u64,
}

pub(super) struct NativeMappingOptions<'a> {
    reusable_translator: Option<Arc<dsr::ProcessTranslator>>,
    exec_map_dsr_tid: Option<crate::thread::ThreadId>,
    relative_relocations: &'a [NativeRelativeRelocation],
    backing: NativeImageBacking<'a>,
    rollback_plan: NativeMappingRollbackPlan,
}

pub(super) struct NativeByteRegionOptions {
    final_prot: libc::c_int,
    executable: bool,
    exec_map_dsr_tid: Option<crate::thread::ThreadId>,
}

#[derive(Clone, Copy)]
pub(super) struct PreparedRegionMapping {
    mapped: *mut libc::c_void,
    mapped_length: usize,
    logical_length: u64,
}

#[derive(Clone, Copy)]
pub(super) struct NativeExclusiveReservation {
    pub(super) location: NativeExclusiveLocation,
    pub(super) observed: u64,
    pub(super) sequence: NativeExclusiveSequence,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct NativeExclusiveLocation {
    pub(super) address: u64,
    pub(super) width: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct NativeExclusiveSequence(u64);

impl NativeExclusiveSequence {
    pub(super) const INITIAL: Self = Self(0);

    pub(super) fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

pub(super) struct NativeMappedRegion {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) host_protects: bool,
    pub(super) shared_futex: bool,
    pub(super) guest_writable: bool,
    pub(super) default_prot: u64,
    /// File-identity futex-key base (`trap::shared_file_key_base`) for a
    /// direct host `MAP_SHARED` FILE mapping, else 0. Two processes mapping
    /// the same file at DIFFERENT guest addresses (native exec rebuilds the
    /// address space, so an exec'd child re-attaches an LTP checkpoint page
    /// wherever mmap lands) must resolve one futex word to ONE waiter-count
    /// key; a guest-VA key made the exec'd child's FUTEX_WAKE miss the
    /// parent's registered waiter (ltpcheckpointexec). 0 keeps VA-keying:
    /// anon MAP_SHARED is fork-inherited at the SAME VA everywhere.
    pub(super) shared_key_base: u64,
    /// File offset of `start` for `shared_key_base != 0` regions.
    pub(super) shared_key_offset: u64,
}

pub(super) fn native_region_linux_prot(read: bool, write: bool, exec: bool) -> u64 {
    let mut prot = 0;
    if read {
        prot |= crate::linux_abi::LINUX_PROT_READ;
    }
    if write {
        prot |= crate::linux_abi::LINUX_PROT_WRITE;
    }
    if exec {
        prot |= crate::linux_abi::LINUX_PROT_EXEC;
    }
    prot
}

pub(super) fn normalize_host_ranges(ranges: &mut Vec<std::ops::Range<carrick_guest_mem::HostVa>>) {
    ranges.sort_unstable_by_key(|range| range.start.raw());
    let mut write = 0;
    for read in 0..ranges.len() {
        if write != 0 && ranges[read].start.raw() <= ranges[write - 1].end.raw() {
            if ranges[read].end.raw() > ranges[write - 1].end.raw() {
                ranges[write - 1].end = ranges[read].end;
            }
        } else {
            ranges.swap(write, read);
            write += 1;
        }
    }
    ranges.truncate(write);
}

pub(super) fn subtract_host_ranges(
    owned: &[std::ops::Range<carrick_guest_mem::HostVa>],
    retained: &[std::ops::Range<carrick_guest_mem::HostVa>],
) -> Vec<std::ops::Range<carrick_guest_mem::HostVa>> {
    let mut result = Vec::new();
    for range in owned {
        let mut cursor = range.start.raw();
        for keep in retained {
            if keep.end.raw() <= cursor || keep.start.raw() >= range.end.raw() {
                continue;
            }
            if keep.start.raw() > cursor {
                result.push(
                    carrick_guest_mem::HostVa(cursor)..carrick_guest_mem::HostVa(keep.start.raw()),
                );
            }
            cursor = cursor.max(keep.end.raw()).min(range.end.raw());
            if cursor == range.end.raw() {
                break;
            }
        }
        if cursor < range.end.raw() {
            result.push(
                carrick_guest_mem::HostVa(cursor)..carrick_guest_mem::HostVa(range.end.raw()),
            );
        }
    }
    result
}

impl NativeMappedMemory {
    pub(super) fn address_mode(&self) -> NativeAddressMode {
        self.address_mode
    }

    pub(super) fn host_address(
        &self,
        address: carrick_guest_mem::GuestVa,
    ) -> Result<carrick_guest_mem::HostVa, MemoryError> {
        self.address_mode
            .to_host(address)
            .map_err(|error| MemoryError::HostMap(error.to_string()))
    }

    pub(super) fn guest_fault_address(
        &self,
        address: carrick_guest_mem::HostVa,
    ) -> Option<carrick_guest_mem::GuestVa> {
        if matches!(self.address_mode, NativeAddressMode::Biased { .. }) {
            if !self
                .owned_host_ranges
                .iter()
                .any(|range| address >= range.start && address < range.end)
            {
                return None;
            }
            return self.address_mode.to_guest(address).ok();
        }
        let guest = self.address_mode.to_guest(address).ok()?;
        self.region_contains(guest.raw(), 1).then_some(guest)
    }

    pub(super) fn dsr_process_translator(
        &self,
    ) -> Result<Arc<dsr::ProcessTranslator>, RuntimeError> {
        self.dsr_translator.as_ref().map(Arc::clone).ok_or_else(|| {
            RuntimeError::Unsupported(
                "native DSR process translator is unavailable outside DSR mode".to_string(),
            )
        })
    }

    pub(super) fn note_dsr_code_mutation(
        &self,
        address: u64,
        len: usize,
    ) -> Result<Option<dsr::types::CodeGeneration>, MemoryError> {
        if len == 0 {
            return Ok(None);
        }
        let end = address
            .checked_add(len as u64)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        self.dsr_generations
            .note_guest_code_write(
                carrick_guest_mem::GuestVa(address)..carrick_guest_mem::GuestVa(end),
            )
            .map(Some)
            .map_err(|error| MemoryError::HostMap(error.to_string()))
    }

    pub(super) fn dsr_generation_observation(
        &self,
        pc: carrick_guest_mem::GuestVa,
    ) -> Result<dsr::cache::PageGenerationObservation, dsr::types::DsrError> {
        self.dsr_generations.observe(pc)
    }

    pub(super) fn range_may_execute(&self, address: u64, len: usize) -> bool {
        if len == 0 {
            return false;
        }
        let end = address.saturating_add(len as u64);
        let mut page = address & !(self.host_page_size - 1);
        while page < end {
            let prot = self
                .native_page_protections
                .get(&page)
                .copied()
                .unwrap_or_else(|| self.default_linux_prot_at(page));
            if prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
                return true;
            }
            page = page.saturating_add(self.host_page_size);
        }
        false
    }

    #[cfg(test)]
    pub(super) fn map(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
        linux_page_size: u64,
    ) -> Result<Self, RuntimeError> {
        Self::map_with_translator(image, layout, host_page_size, linux_page_size, None, None)
    }

    pub(super) fn map_for_plan(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
        linux_page_size: u64,
        _plan: &ExecutionPlan,
        relative_relocations: &[NativeRelativeRelocation],
    ) -> Result<Self, RuntimeError> {
        let native_layout = NativeLayout::for_image(image, layout, host_page_size)
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        let rollback_plan = NativeMappingRollbackPlan::for_fresh_layout(&native_layout);
        Self::map_with_layout(
            image,
            layout,
            NativeMappingPageSizes {
                host: host_page_size,
                linux: linux_page_size,
            },
            native_layout,
            NativeMappingOptions {
                reusable_translator: None,
                exec_map_dsr_tid: None,
                relative_relocations,
                backing: NativeImageBacking::AnonymousBytes,
                rollback_plan,
            },
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn map_prepared_for_plan(
        prepared: &ValidatedPreparedImage,
        layout: MemoryLayout,
        plan: &ExecutionPlan,
    ) -> Result<Self, RuntimeError> {
        let native_layout =
            NativeLayout::for_image(&prepared.image, layout, plan.page_geometry.host_page_size)
                .map_err(|error| RuntimeError::Unsupported(format!("prepared-map: {error}")))?;
        let rollback_plan = NativeMappingRollbackPlan::for_fresh_layout(&native_layout);
        Self::map_with_layout(
            &prepared.image,
            layout,
            NativeMappingPageSizes {
                host: plan.page_geometry.host_page_size,
                linux: plan.page_geometry.linux_page_size,
            },
            native_layout,
            NativeMappingOptions {
                reusable_translator: None,
                exec_map_dsr_tid: None,
                relative_relocations: &prepared.relocations,
                backing: NativeImageBacking::Prepared(prepared),
                rollback_plan,
            },
        )
    }

    #[cfg(test)]
    pub(super) fn map_with_translator(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
        linux_page_size: u64,
        reusable_translator: Option<Arc<dsr::ProcessTranslator>>,
        exec_map_dsr_tid: Option<crate::thread::ThreadId>,
    ) -> Result<Self, RuntimeError> {
        let native_layout = NativeLayout::for_image(image, layout, host_page_size)
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        let rollback_plan = NativeMappingRollbackPlan::for_fresh_layout(&native_layout);
        Self::map_with_layout(
            image,
            layout,
            NativeMappingPageSizes {
                host: host_page_size,
                linux: linux_page_size,
            },
            native_layout,
            NativeMappingOptions {
                reusable_translator,
                exec_map_dsr_tid,
                relative_relocations: &[],
                backing: NativeImageBacking::AnonymousBytes,
                rollback_plan,
            },
        )
    }

    pub(super) fn map_with_layout(
        image: &AddressSpace,
        layout: MemoryLayout,
        page_sizes: NativeMappingPageSizes,
        native_layout: NativeLayout,
        options: NativeMappingOptions<'_>,
    ) -> Result<Self, RuntimeError> {
        let NativeMappingOptions {
            reusable_translator,
            exec_map_dsr_tid,
            relative_relocations,
            backing,
            rollback_plan,
        } = options;
        native_exec_map_profile_start(exec_map_dsr_tid);
        let mut regions = Vec::new();
        let mut rollback =
            NativeMappingRollback::new(rollback_plan, page_sizes.host, image.regions().len() + 5)?;
        let prepared_region_mappings = match backing {
            NativeImageBacking::AnonymousBytes => None,
            NativeImageBacking::Prepared(prepared) => {
                native_reexec_lifecycle(
                    crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapBegin,
                );
                let mappings = image
                    .regions()
                    .iter()
                    .enumerate()
                    .map(|(region_index, region)| {
                        let file_backing = prepared
                            .backings
                            .get(region_index)
                            .copied()
                            .ok_or_else(|| {
                                RuntimeError::Unsupported(format!(
                                    "prepared-map: missing file backing for region {region_index}"
                                ))
                            })?;
                        map_prepared_region_extent(
                            region_index,
                            region,
                            file_backing,
                            prepared,
                            exec_map_dsr_tid,
                            &native_layout,
                            &mut rollback,
                        )
                    })
                    .collect::<Result<Vec<_>, RuntimeError>>()?;
                native_reexec_lifecycle(
                    crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapEnd,
                );
                Some(mappings)
            }
        };
        for (region_index, region) in image.regions().iter().enumerate() {
            match backing {
                NativeImageBacking::AnonymousBytes => map_region(
                    region,
                    exec_map_dsr_tid,
                    image.initial_stack_pointer(),
                    &native_layout,
                    &mut rollback,
                )?,
                NativeImageBacking::Prepared(_) => {
                    let mapped = prepared_region_mappings
                        .as_ref()
                        .and_then(|mappings| mappings.get(region_index))
                        .ok_or_else(|| {
                            RuntimeError::Unsupported(format!(
                                "prepared-map: missing mapped region {region_index}"
                            ))
                        })?;
                    finalize_image_region_mapping(
                        region,
                        mapped.mapped,
                        mapped.mapped_length,
                        mapped.logical_length,
                        exec_map_dsr_tid,
                        true,
                    )?;
                }
            };
            if region.start == NATIVE_DARWIN_VDSO_BASE && region.perms.execute {
                native_exec_map_detail(
                    exec_map_dsr_tid,
                    crate::probes::DsrCacheLifecyclePhase::ExecMapVvarBegin,
                    region.len(),
                );
                relocate_vdso_vvar_loads(region, &native_layout)?;
                native_exec_map_detail(
                    exec_map_dsr_tid,
                    crate::probes::DsrCacheLifecyclePhase::ExecMapVvarEnd,
                    0,
                );
            }
            regions.push(NativeMappedRegion {
                start: region.start,
                end: region.end,
                host_protects: true,
                shared_futex: false,
                guest_writable: region.perms.write,
                default_prot: native_region_linux_prot(
                    region.perms.read,
                    region.perms.write,
                    region.perms.execute,
                ),
                shared_key_base: 0,
                shared_key_offset: 0,
            });
        }
        map_bytes_region(
            NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
            carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE,
            &carrick_mem::memory::sigreturn_trampoline_bytes(),
            NativeByteRegionOptions {
                final_prot: libc::PROT_READ | libc::PROT_EXEC,
                executable: true,
                exec_map_dsr_tid,
            },
            &native_layout,
            &mut rollback,
        )?;
        regions.push(NativeMappedRegion {
            start: NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
            end: NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE
                + carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE,
            host_protects: true,
            shared_futex: false,
            guest_writable: false,
            default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
            shared_key_base: 0,
            shared_key_offset: 0,
        });
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
            layout.heap_size,
        );
        map_anonymous_region(
            layout.heap_base,
            layout.heap_size,
            false,
            &native_layout,
            &mut rollback,
        )?;
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
            0,
        );
        regions.push(NativeMappedRegion {
            start: layout.heap_base,
            end: checked_add_u64(layout.heap_base, layout.heap_size, "native heap end")?,
            host_protects: false,
            shared_futex: false,
            guest_writable: true,
            default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            shared_key_base: 0,
            shared_key_offset: 0,
        });
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
            layout.mmap_size,
        );
        map_anonymous_region(
            layout.mmap_base,
            layout.mmap_size,
            false,
            &native_layout,
            &mut rollback,
        )?;
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
            0,
        );
        regions.push(NativeMappedRegion {
            start: layout.mmap_base,
            end: checked_add_u64(layout.mmap_base, layout.mmap_size, "native mmap arena end")?,
            host_protects: true,
            shared_futex: false,
            guest_writable: true,
            default_prot: if page_sizes.linux == page_sizes.host {
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE
            } else {
                0
            },
            shared_key_base: 0,
            shared_key_offset: 0,
        });
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
            crate::memory::LINUX_SHARED_FILE_SIZE,
        );
        map_anonymous_region(
            crate::memory::LINUX_SHARED_FILE_BASE,
            crate::memory::LINUX_SHARED_FILE_SIZE,
            true,
            &native_layout,
            &mut rollback,
        )?;
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
            0,
        );
        regions.push(NativeMappedRegion {
            start: crate::memory::LINUX_SHARED_FILE_BASE,
            end: checked_add_u64(
                crate::memory::LINUX_SHARED_FILE_BASE,
                crate::memory::LINUX_SHARED_FILE_SIZE,
                "native shared aperture end",
            )?,
            host_protects: true,
            shared_futex: true,
            guest_writable: true,
            default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            shared_key_base: 0,
            shared_key_offset: 0,
        });
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
            crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
        );
        map_anonymous_region(
            crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
            crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
            false,
            &native_layout,
            &mut rollback,
        )?;
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
            0,
        );
        regions.push(NativeMappedRegion {
            start: crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
            end: checked_add_u64(
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
                "native private overlay aperture end",
            )?,
            host_protects: false,
            shared_futex: false,
            guest_writable: true,
            default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            shared_key_base: 0,
            shared_key_offset: 0,
        });
        let protections = MemoryProtections::default();
        for span in image.ro_spans() {
            let _span_end = checked_add_u64(span.start, span.len, "read-only ELF span end")?;
            let len = usize::try_from(span.len).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin read-only ELF span too large: 0x{:x}+0x{:x}",
                    span.start, span.len
                ))
            })?;
            protections.set_no_write(span.start, len, true);
        }
        let address_mode = native_layout.address_mode();
        let owned_host_ranges = Arc::new(native_layout.owned_ranges().to_vec());
        let setup: Result<Self, RuntimeError> = (|| {
            let mut memory = Self {
                address_mode,
                owned_host_ranges,
                regions,
                protections,
                native_page_protections: BTreeMap::new(),
                native_write_exec_writable_pages: BTreeSet::new(),
                linux4k_page_protections: BTreeMap::new(),
                exclusive_sequences: parking_lot::Mutex::new(BTreeMap::new()),
                host_access_lifts: parking_lot::Mutex::new(std::collections::HashMap::new()),
                host_page_size: page_sizes.host,
                linux_page_size: page_sizes.linux,
                dsr_generations: dsr::cache::PageGenerationTable::new(page_sizes.host)
                    .map_err(|error| RuntimeError::Unsupported(error.to_string()))?,
                dsr_translator: if let Some(translator) = reusable_translator {
                    Some(translator)
                } else {
                    Some(Arc::new(
                        dsr::ProcessTranslator::new(64 * 1024 * 1024)
                            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?,
                    ))
                },
            };
            // Publishing the vvar contents is part of establishing the address
            // space: the initial boot maps here, and an execve replacement re-maps
            // here (`replace_image`), so both get a freshly stamped vvar.
            native_exec_map_detail(
                exec_map_dsr_tid,
                crate::probes::DsrCacheLifecyclePhase::ExecMapVvarBegin,
                crate::vdso::LINUX_VVAR_SIZE,
            );
            #[cfg(test)]
            if backing.is_prepared()
                && take_native_prepared_mapping_failpoint(NativePreparedMappingFailpoint::VvarStamp)
            {
                return Err(RuntimeError::Unsupported(
                    "prepared-map: injected vvar stamping failure".to_string(),
                ));
            }
            memory.stamp_vdso_vvar()?;
            native_exec_map_detail(
                exec_map_dsr_tid,
                crate::probes::DsrCacheLifecyclePhase::ExecMapVvarEnd,
                0,
            );
            #[cfg(test)]
            if backing.is_prepared()
                && take_native_prepared_mapping_failpoint(
                    NativePreparedMappingFailpoint::Relocation,
                )
            {
                return Err(RuntimeError::Unsupported(
                    "prepared-map: injected relocation failure".to_string(),
                ));
            }
            apply_native_relative_relocations(&mut memory, relative_relocations)?;
            #[cfg(test)]
            if exec_map_dsr_tid.is_some()
                && NATIVE_TEST_FAIL_EXEC_AFTER_SETUP.with(|failpoint| failpoint.replace(false))
            {
                return Err(RuntimeError::Unsupported(
                    "injected native exec failure after target mapping, vvar setup, and relocations"
                        .to_string(),
                ));
            }
            Ok(memory)
        })();
        let memory = native_layout.commit_if_ok(setup)?;
        rollback.commit();
        native_exec_map_profile_finish();
        Ok(memory)
    }

    /// Publish the vvar data page (RNG generation + clock calibration) for a
    /// freshly mapped image — the native counterpart of the HVF vvar stamper
    /// (`populate_vdso_data_page` in carrick-vmm-hvf/src/trap.rs). It uses the
    /// same calibration sources and publishes the SAME realtime offset via
    /// [`crate::vdso::set_realtime_off_ns`], so the userspace vDSO fast paths
    /// and the trapping syscall clock paths cannot drift apart
    /// (clock_gettime04 coherence). No-op when the image carries no vDSO
    /// (CARRICK_DISABLE_VDSO).
    ///
    /// Natively DSR translates the guest's `mrs cntvct_el0` into an adjusted
    /// suspend-excluding counter read. Known host counter modes remain inline:
    /// they apply Darwin's live uptime offset and convert into the preserved
    /// `CNTFRQ_EL0` domain, matching this `CLOCK_UPTIME_RAW` calibration.
    /// Unknown modes use the correctness-first scaled fallback. The resulting
    /// guest-visible timeline is gated empirically by
    /// `native_virtual_counter_reads_track_clock_uptime_raw`.
    pub(super) fn stamp_vdso_vvar(&self) -> Result<(), RuntimeError> {
        if !self.vvar_region_is_mapped() {
            return Ok(());
        }
        #[cfg(test)]
        if let Some(words) = NATIVE_TEST_VVAR_WORDS.with(|slot| slot.borrow().clone()) {
            return self.write_vvar_words(&words);
        }
        // RNG generation first and unconditionally (getrandom needs no
        // calibrated counter): this process's host PID, unique per process and
        // re-stamped in a forked child, so the userspace getrandom blob
        // reseeds instead of reusing a COW-inherited keystream.
        let pid = unsafe { libc::getpid() } as u64;
        let mut words = vec![(crate::vdso::VVAR_OFF_RNG_GENERATION, pid)];
        let (freq, mono_ns) = native_vvar_clock_sources();
        if freq != 0 {
            let unix_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let realtime_off = unix_ns.wrapping_sub(mono_ns);
            crate::vdso::set_realtime_off_ns(realtime_off);
            words.push((crate::vdso::VVAR_OFF_FREQ, freq));
            words.push((crate::vdso::VVAR_OFF_REALTIME_OFF_NS, realtime_off));
        }
        self.write_vvar_words(&words)
    }

    /// Re-stamp the vvar RNG generation with THIS process's PID — the native
    /// fork-child counterpart of the HVF child-side re-stamp in `fork_rebuild`.
    /// The child's distinct generation forces the userspace getrandom blob to
    /// reseed instead of replaying the parent's keystream (gated by the
    /// getrandomvdsofork probe). No-op when the vDSO is disabled.
    pub(super) fn restamp_vdso_rng_generation_after_fork(&self) -> Result<(), RuntimeError> {
        if !self.vvar_region_is_mapped() {
            return Ok(());
        }
        let pid = unsafe { libc::getpid() } as u64;
        self.write_vvar_words(&[(crate::vdso::VVAR_OFF_RNG_GENERATION, pid)])
    }

    pub(super) fn vvar_region_is_mapped(&self) -> bool {
        self.region_contains(
            NATIVE_DARWIN_VVAR_BASE,
            crate::vdso::LINUX_VVAR_SIZE as usize,
        )
    }

    /// Write little-endian u64s into the vvar data page. The vvar is mapped
    /// read-only for the guest, so the containing host page flips writable for
    /// the duration of the write. Every caller runs before guest code can
    /// observe the page (boot mapping, execve replacement, a fresh
    /// single-threaded fork child), so the transient writability is invisible.
    pub(super) fn write_vvar_words(&self, words: &[(usize, u64)]) -> Result<(), RuntimeError> {
        let vvar_end = NATIVE_DARWIN_VVAR_BASE + crate::vdso::LINUX_VVAR_SIZE;
        let (page_start, page_len) = self
            .host_page_range(NATIVE_DARWIN_VVAR_BASE, vvar_end)
            .map_err(|_| {
                RuntimeError::Unsupported("native Darwin vvar page range overflow".to_string())
            })?;
        let page_ptr = self
            .host_address(carrick_guest_mem::GuestVa(page_start))
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?
            .raw() as *mut libc::c_void;
        if unsafe { libc::mprotect(page_ptr, page_len, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
            return Err(last_io_error("mprotect native Darwin vvar page writable"));
        }
        for &(offset, value) in words {
            debug_assert!(
                offset + std::mem::size_of::<u64>() <= crate::vdso::LINUX_VVAR_SIZE as usize
            );
            let address = NATIVE_DARWIN_VVAR_BASE + offset as u64;
            let bytes = value.to_le_bytes();
            // SAFETY: the vvar region is mapped at its fixed VA (checked by the
            // callers via vvar_region_is_mapped) and was just made writable.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    self.host_address(carrick_guest_mem::GuestVa(address))
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?
                        .raw() as *mut u8,
                    bytes.len(),
                );
            }
        }
        if unsafe { libc::mprotect(page_ptr, page_len, libc::PROT_READ) } != 0 {
            return Err(last_io_error("restore native Darwin vvar page read-only"));
        }
        Ok(())
    }

    pub(super) fn set_fork_inheritance(&self, share: bool) {
        let trace = std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some();
        for region in &self.regions {
            if region.shared_futex || !region.guest_writable {
                continue;
            }
            let Ok(start) = self.host_address(carrick_guest_mem::GuestVa(region.start)) else {
                continue;
            };
            let Ok(len) = usize::try_from(region.end.saturating_sub(region.start)) else {
                continue;
            };
            let changed =
                set_native_region_fork_inheritance(start.raw() as *mut libc::c_void, len, share);
            if trace {
                child_write_stderr(
                    format!(
                        "native trace pid={} fork-inherit share={} start=0x{:x} end=0x{:x} changed={}\n",
                        unsafe { libc::getpid() },
                        share,
                        region.start,
                        region.end,
                        changed
                    )
                    .as_bytes(),
                );
            }
        }
    }

    pub(super) fn prepare_exec_mapping(
        &self,
        image: &AddressSpace,
        plan: &ExecutionPlan,
    ) -> Result<PreparedNativeExecMapping, RuntimeError> {
        let native_layout = NativeLayout::for_exec(
            image,
            native_memory_layout(),
            plan.page_geometry.host_page_size,
            &self.owned_host_ranges,
        )
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        let target_only = if matches!(native_layout.address_mode(), NativeAddressMode::Direct) {
            // Every Carrick-owned overlap can transfer continuously into a
            // Direct replacement, regardless of the source address mode.
            // External mappings remain in target_only and fail the screen.
            subtract_host_ranges(native_layout.owned_ranges(), &self.owned_host_ranges)
        } else {
            Vec::new()
        };
        let mut direct_target_reservations = Vec::with_capacity(target_only.len());
        let mut direct_reservation_ranges = Vec::with_capacity(target_only.len());
        let reset_inherited_translator =
            NATIVE_FORKED_GUEST_CHILD.load(std::sync::atomic::Ordering::Acquire);
        let process_translator = if reset_inherited_translator {
            self.dsr_process_translator()?
        } else {
            Arc::new(
                dsr::ProcessTranslator::new(64 * 1024 * 1024)
                    .map_err(|error| RuntimeError::Unsupported(error.to_string()))?,
            )
        };
        // This is the final pre-PONR screen. The layout, target-only range
        // vector, reservation-vector capacity, and replacement MAP_JIT cache
        // are all allocated first. Each allocatable interval becomes an exact
        // PROT_NONE guard; only the measured dyld delegated shared-pmap empty
        // covering tuple may proceed without one. No allocator or mmap may run
        // after this loop before old-image retirement.
        for range in &target_only {
            let length = range
                .end
                .raw()
                .checked_sub(range.start.raw())
                .ok_or_else(|| {
                    RuntimeError::Unsupported(format!(
                        "native direct exec target range is inverted: 0x{:x}..0x{:x}",
                        range.start.raw(),
                        range.end.raw()
                    ))
                })? as u64;
            match crate::host_proc::reserve_self_direct_vm_range(range.start.raw() as u64, length)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?
            {
                crate::host_proc::DirectVmReservationOutcome::Reserved(reservation) => {
                    for (start, length) in reservation.owned_spans() {
                        let end = start.checked_add(length).ok_or_else(|| {
                            RuntimeError::Unsupported(format!(
                                "native direct exec reservation range overflows: 0x{start:x}+0x{length:x}"
                            ))
                        })?;
                        direct_reservation_ranges.push(
                            carrick_guest_mem::HostVa(usize::try_from(start).map_err(|_| {
                                RuntimeError::Unsupported(format!(
                                    "native direct exec reservation start is not representable: 0x{start:x}"
                                ))
                            })?)
                                ..carrick_guest_mem::HostVa(usize::try_from(end).map_err(|_| {
                                    RuntimeError::Unsupported(format!(
                                        "native direct exec reservation end is not representable: 0x{end:x}"
                                    ))
                                })?),
                        );
                    }
                    direct_target_reservations.push(reservation);
                }
                crate::host_proc::DirectVmReservationOutcome::DelegatedDyldPmapEmpty => {}
            }
        }
        let rollback_plan = match native_layout.address_mode() {
            NativeAddressMode::Direct => NativeMappingRollbackPlan::direct_exec(
                native_layout.owned_ranges(),
                direct_reservation_ranges,
            ),
            NativeAddressMode::Biased { .. } => NativeMappingRollbackPlan {
                supplemental_ranges: Vec::new(),
            },
        };
        Ok(PreparedNativeExecMapping {
            native_layout,
            process_translator,
            reset_inherited_translator,
            direct_target_reservations,
            rollback_plan,
        })
    }

    pub(super) fn replace_image(
        &mut self,
        image: &AddressSpace,
        relative_relocations: &[NativeRelativeRelocation],
        plan: &ExecutionPlan,
        dsr_tid: Option<crate::thread::ThreadId>,
        mut prepared: PreparedNativeExecMapping,
    ) -> Result<(), RuntimeError> {
        let lifecycle = |phase| {
            if let Some(tid) = dsr_tid {
                crate::probes::dsr_cache_lifecycle(tid.raw(), phase, 0, 0, 0);
            }
        };
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecImageUnmapBegin);
        if self.owned_host_ranges.is_empty() {
            return Err(RuntimeError::Unsupported(
                "native Darwin execve cannot retire an address space without owned host ranges"
                    .to_string(),
            ));
        }
        let retained_target_ranges = prepared.native_layout.owned_ranges();
        let retired_ranges = subtract_host_ranges(&self.owned_host_ranges, retained_target_ranges);
        // Everything above remains pre-PONR: it may validate and allocate,
        // and dropping `prepared` must leave the authoritative old image
        // untouched. From here onward replacement may retire or overwrite old
        // mappings, so arm the already-allocated reusable guards in place.
        // Any subsequent failure is fatal and the new layout becomes the sole
        // rollback owner for those transferred intervals.
        prepared.native_layout.arm_prepared_adoptions();
        for range in &retired_ranges {
            let start = range.start.raw();
            let end = range.end.raw();
            let len = end.checked_sub(start).ok_or_else(|| {
                RuntimeError::Unsupported(format!(
                    "native Darwin execve owned range is inverted: 0x{start:x}..0x{end:x}"
                ))
            })?;
            if len != 0 && unsafe { libc::munmap(start as *mut libc::c_void, len) } != 0 {
                return Err(last_io_error(&format!(
                    "munmap native Darwin execve owned range 0x{start:x}..0x{end:x}"
                )));
            }
        }
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecImageUnmapEnd);
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecImageMapBegin);
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecRelocationBegin);
        let PreparedNativeExecMapping {
            native_layout,
            process_translator,
            reset_inherited_translator,
            direct_target_reservations,
            rollback_plan,
        } = prepared;
        native_layout
            .reset_biased_aperture_to_guards()
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        let inherited_translator =
            reset_inherited_translator.then(|| Arc::clone(&process_translator));
        let replacement = Self::map_with_layout(
            image,
            native_memory_layout(),
            NativeMappingPageSizes {
                host: plan.page_geometry.host_page_size,
                linux: plan.page_geometry.linux_page_size,
            },
            native_layout,
            NativeMappingOptions {
                reusable_translator: Some(process_translator),
                exec_map_dsr_tid: dsr_tid,
                relative_relocations,
                backing: NativeImageBacking::AnonymousBytes,
                rollback_plan,
            },
        )?;
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecRelocationEnd);
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecImageMapEnd);
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecCacheResetBegin);
        if let Some(translator) = inherited_translator {
            // A fork child cannot allocate a fresh JIT cache safely, so exec
            // reuses its inherited mapping. Keep the old cache intact until
            // the complete replacement image is mapped and relocated; only
            // then clear its inherited publications before the thread-level
            // handoff can execute the new image.
            translator.reset_after_fork_for_exec();
        }
        for reservation in direct_target_reservations {
            reservation.commit();
        }
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecCacheResetEnd);
        *self = replacement;
        Ok(())
    }

    pub(super) fn region_contains(&self, address: u64, length: usize) -> bool {
        let Ok(length) = u64::try_from(length) else {
            return false;
        };
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        self.regions
            .iter()
            .any(|region| address >= region.start && end <= region.end)
    }

    pub(super) fn host_protected_overlaps(
        &self,
        address: u64,
        length: usize,
    ) -> impl Iterator<Item = (u64, u64)> + '_ {
        let end = address.saturating_add(length as u64);
        let linux4k = self.uses_linux4k_subpages();
        self.regions
            .iter()
            .filter(move |region| {
                (linux4k || region.host_protects) && address < region.end && region.start < end
            })
            .map(move |region| (address.max(region.start), end.min(region.end)))
    }

    pub(super) fn host_page_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<(u64, usize), MemoryError> {
        let page_size = self.host_page_size;
        let page_start = start & !(page_size - 1);
        let page_end = end
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or(MemoryError::OutOfBounds {
                address: start,
                length: usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX),
            })?;
        let len = usize::try_from(page_end.saturating_sub(page_start)).map_err(|_| {
            MemoryError::OutOfBounds {
                address: start,
                length: usize::MAX,
            }
        })?;
        Ok((page_start, len))
    }

    pub(super) fn uses_linux4k_subpages(&self) -> bool {
        self.host_page_size == 16 * 1024 && self.linux_page_size == 4 * 1024
    }

    pub(super) fn native16k_write_exec_page(&self, address: u64) -> Option<u64> {
        if self.uses_linux4k_subpages()
            || !self.regions.iter().any(|region| {
                region.host_protects && address >= region.start && address < region.end
            })
        {
            return None;
        }
        let page_start = address & !(self.host_page_size - 1);
        let prot = self
            .native_page_protections
            .get(&page_start)
            .copied()
            .unwrap_or_else(|| self.default_linux_prot_at(address));
        let write_exec = crate::linux_abi::LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC;
        (prot & write_exec == write_exec).then_some(page_start)
    }

    pub(super) fn has_native16k_write_exec_pages(&self) -> bool {
        if self.host_page_size != 16 * 1024 || self.linux_page_size != self.host_page_size {
            return false;
        }
        let write_exec = crate::linux_abi::LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC;
        self.native_page_protections
            .values()
            .copied()
            .chain(self.regions.iter().map(|region| region.default_prot))
            .any(|prot| prot & write_exec == write_exec)
    }

    pub(super) fn write_exec_blocks_multithreaded_lifecycle(&self) -> bool {
        false
    }

    pub(super) fn native16k_clone_thread_rejection(&self) -> Option<&'static str> {
        None
    }

    pub(super) fn native16k_vfork_rejection(&self) -> Option<&'static str> {
        self.has_native16k_write_exec_pages().then_some(
            "native16k cannot vfork while write-exec pages are present because vfork shares writable mappings",
        )
    }

    pub(super) fn make_native16k_write_exec_page_writable(
        &mut self,
        page_start: u64,
        operation_address: u64,
        operation_len: usize,
    ) -> Result<(), MemoryError> {
        if self.native_write_exec_writable_pages.contains(&page_start) {
            return Ok(());
        }
        self.note_dsr_code_mutation(page_start, self.host_page_size as usize)?;
        self.mprotect_host_page(
            page_start,
            libc::PROT_READ | libc::PROT_WRITE,
            operation_address,
            operation_len,
        )?;
        self.native_write_exec_writable_pages.insert(page_start);
        Ok(())
    }

    pub(super) fn make_native16k_write_exec_page_executable(
        &mut self,
        page_start: u64,
        operation_address: u64,
        operation_len: usize,
    ) -> Result<(), MemoryError> {
        if !self.native_write_exec_writable_pages.contains(&page_start) {
            return Ok(());
        }
        let page_len =
            usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                address: operation_address,
                length: operation_len,
            })?;
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(page_start))?
            .raw() as *mut u8;
        unsafe { carrick_native_clear_icache(ptr.cast(), page_len) };
        let prot = self
            .native_page_protections
            .get(&page_start)
            .copied()
            .unwrap_or_else(|| self.default_linux_prot_at(page_start));
        self.mprotect_host_page(
            page_start,
            native16k_host_prot(prot),
            operation_address,
            operation_len,
        )?;
        self.native_write_exec_writable_pages.remove(&page_start);
        Ok(())
    }

    pub(super) fn prepare_native16k_write_exec_host_write(
        &mut self,
        address: u64,
        len: usize,
    ) -> Result<(), MemoryError> {
        if len == 0 || self.uses_linux4k_subpages() {
            return Ok(());
        }
        let end = address
            .checked_add(len as u64)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        let mut page = address & !(self.host_page_size - 1);
        while page < end {
            if self.native16k_write_exec_page(page).is_some() {
                self.make_native16k_write_exec_page_writable(page, address, len)?;
            }
            page = page.saturating_add(self.host_page_size);
        }
        Ok(())
    }

    pub(super) fn resolve_native16k_write_exec_fault(
        &mut self,
        fault_address: u64,
        pc: u64,
        esr: u64,
    ) -> Result<bool, RuntimeError> {
        let Some(page_start) = self.native16k_write_exec_page(fault_address) else {
            return Ok(false);
        };
        let ec = (esr >> 26) & 0x3f;
        let fault_status = esr & 0x3f;
        if !matches!(fault_status, 0x0c..=0x0f) {
            return Ok(false);
        }
        if matches!(ec, 0x20 | 0x21) {
            if !self.native_write_exec_writable_pages.contains(&page_start) {
                return Ok(false);
            }
            self.make_native16k_write_exec_page_executable(
                page_start,
                fault_address,
                self.host_page_size as usize,
            )
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native16k could not make guest write-exec page 0x{page_start:x} executable: {error}"
                ))
            })?;
            return Ok(true);
        }
        let write_data_abort = matches!(ec, 0x24 | 0x25) && esr & (1 << 6) != 0;
        if !write_data_abort || self.native_write_exec_writable_pages.contains(&page_start) {
            return Ok(false);
        }
        let pc_page = pc & !(self.host_page_size - 1);
        if pc_page == page_start {
            return Err(RuntimeError::Unsupported(format!(
                "native16k cannot write a guest RWX page while executing from the same 16K host page at pc=0x{pc:x} addr=0x{fault_address:x}"
            )));
        }
        self.make_native16k_write_exec_page_writable(
            page_start,
            fault_address,
            self.host_page_size as usize,
        )
        .map_err(|error| {
            RuntimeError::Unsupported(format!(
                "native16k could not make guest write-exec page 0x{page_start:x} writable: {error}"
            ))
        })?;
        Ok(true)
    }

    pub(super) fn default_linux_prot_at(&self, address: u64) -> u64 {
        self.regions
            .iter()
            .rev()
            .find(|region| address >= region.start && address < region.end)
            .map_or(0, |region| region.default_prot)
    }

    pub(super) fn guest_address_is_executable(&self, address: u64) -> bool {
        let prot = if self.uses_linux4k_subpages() {
            let host_page = address & !(self.host_page_size - 1);
            let subpage = ((address - host_page) / self.linux_page_size) as usize;
            self.linux4k_host_page_protections(host_page)
                .get(subpage)
                .copied()
                .unwrap_or(0)
        } else {
            let page = address & !(self.host_page_size - 1);
            self.native_page_protections
                .get(&page)
                .copied()
                .unwrap_or_else(|| self.default_linux_prot_at(address))
        };
        prot & crate::linux_abi::LINUX_PROT_EXEC != 0
    }

    pub(super) fn native_range_allows(&self, address: u64, len: usize, write: bool) -> bool {
        if len == 0 {
            return false;
        }
        if self.uses_linux4k_subpages() {
            return self.linux4k_range_allows(address, len, write);
        }
        let Some(end) = address.checked_add(len as u64) else {
            return false;
        };
        let required = if write {
            crate::linux_abi::LINUX_PROT_WRITE
        } else {
            crate::linux_abi::LINUX_PROT_READ
        };
        let mut cursor = address;
        while cursor < end {
            let page = cursor & !(self.host_page_size - 1);
            let prot = self
                .native_page_protections
                .get(&page)
                .copied()
                .unwrap_or_else(|| self.default_linux_prot_at(cursor));
            if prot & required == 0 {
                return false;
            }
            cursor = page.saturating_add(self.host_page_size).min(end);
        }
        true
    }

    pub(super) fn linux4k_host_page_protections(&self, page_start: u64) -> [u64; 4] {
        self.linux4k_page_protections
            .get(&page_start)
            .copied()
            .unwrap_or_else(|| {
                std::array::from_fn(|index| {
                    self.default_linux_prot_at(
                        page_start.saturating_add(index as u64 * self.linux_page_size),
                    )
                })
            })
    }

    pub(super) fn classify_linux4k_host_page(&self, protections: [u64; 4]) -> HostPageState {
        let subpages = protections.map(|prot| {
            SubpageState::new(
                PageBacking::Anonymous,
                PagePerms {
                    read: prot & crate::linux_abi::LINUX_PROT_READ != 0,
                    write: prot & crate::linux_abi::LINUX_PROT_WRITE != 0,
                    exec: prot & crate::linux_abi::LINUX_PROT_EXEC != 0,
                },
            )
        });
        classify_host_page_state(
            crate::page_profile::PageGeometry {
                host_page_size: self.host_page_size,
                linux_page_size: self.linux_page_size,
                native_profile: Some(carrick_spec::NativePageProfile::Linux4kOn16k),
            },
            subpages,
        )
    }

    pub(super) fn linux4k_range_allows(&self, address: u64, len: usize, write: bool) -> bool {
        if !self.uses_linux4k_subpages() || len == 0 {
            return false;
        }
        let Some(end) = address.checked_add(len as u64) else {
            return false;
        };
        let required = if write {
            crate::linux_abi::LINUX_PROT_WRITE
        } else {
            crate::linux_abi::LINUX_PROT_READ
        };
        let mut cursor = address;
        while cursor < end {
            let host_page = cursor & !(self.host_page_size - 1);
            let subpage = ((cursor - host_page) / self.linux_page_size) as usize;
            let protections = self.linux4k_host_page_protections(host_page);
            if protections
                .get(subpage)
                .is_none_or(|prot| prot & required == 0)
            {
                return false;
            }
            let next = (cursor & !(self.linux_page_size - 1)).saturating_add(self.linux_page_size);
            cursor = next.min(end);
        }
        true
    }

    /// Bumps the sequence for every tracked exclusive location that overlaps
    /// `[address, address+len)`, or every tracked location if `address+len`
    /// overflows. This is `invalidate_exclusive_range`'s entire job: every
    /// exclusive reservation now lives in caller-owned state (per guest
    /// thread), so bumping the shared sequence a reservation was captured
    /// against is sufficient to invalidate it on the next CAS -- there is no
    /// struct-embedded reservation left to null out here.
    pub(super) fn bump_exclusive_sequences_in_range(&self, address: u64, len: usize) {
        let mut sequences = self.exclusive_sequences.lock();
        let end = address.checked_add(len as u64);
        if let Some(end) = end {
            // DSR exclusive locations are scalar 1/2/4/8-byte accesses. An
            // overlapping key can therefore start no earlier than address-7
            // and strictly before the write end. Range the ordered map by that
            // window rather than walking every exclusive location ever seen:
            // Go's compiler issues DC ZVA continuously, and the old O(total
            // locations) scan turned each 64-byte zero into a workload-wide
            // traversal after a few thousand mutex addresses had accumulated.
            let lower = NativeExclusiveLocation {
                address: address.saturating_sub(7),
                width: 0,
            };
            let upper = NativeExclusiveLocation {
                address: end,
                width: 0,
            };
            for (location, sequence) in sequences.range_mut(lower..upper) {
                let location_end = location.address.saturating_add(location.width as u64);
                if address < location_end {
                    *sequence = sequence.next();
                }
            }
        } else {
            // An overflowing host-mediated write is rejected by its caller,
            // but conservatively invalidate every tracked reservation before
            // that error returns.
            for sequence in sequences.values_mut() {
                *sequence = sequence.next();
            }
        }
    }

    pub(super) fn invalidate_exclusive_range(&self, address: u64, len: usize) {
        self.bump_exclusive_sequences_in_range(address, len);
    }

    /// Copy `bytes` into the host backing for `[address, address+bytes.len())`,
    /// no exclusive-monitor/DSR/exec-page bookkeeping -- the shared tail of
    /// every `write_bytes_raw` path (the common `&self` case AND the `&mut
    /// self` exec-page escalation both finish here).
    pub(super) fn copy_bytes_to_host(&self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *mut u8;
        let changed = self.prepare_temporary_host_access(address, length, true)?;
        // Balance the lift refcount even if the copy unwinds or a future
        // fallible step is inserted before the explicit restore below. The
        // success path DISARMS the guard and restores explicitly so a restore
        // error still propagates; the guard only fires on early exit.
        let mut restore_on_unwind = HostLiftRestoreGuard {
            memory: self,
            changed: &changed,
            address,
            length,
            armed: true,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, length);
        }
        restore_on_unwind.armed = false;
        self.restore_temporary_host_access(&changed, address, length)
    }

    /// The exclusive-monitor bump plus the conditional DSR code-mutation note
    /// that every `write_bytes_raw` path performs before touching guest RAM,
    /// regardless of whether the write also hits a native16k write-exec page.
    /// Returns whether the range may execute (i.e. whether the caller must
    /// also escalate to [`Self::write_exec_page_bytes`] for the exec-page
    /// metadata update).
    pub(super) fn invalidate_and_note_dsr_write(
        &self,
        address: u64,
        length: usize,
    ) -> Result<bool, MemoryError> {
        self.invalidate_exclusive_range(address, length);
        let may_execute = self.range_may_execute(address, length);
        if may_execute {
            self.note_dsr_code_mutation(address, length)?;
        }
        Ok(may_execute)
    }

    /// The COMMON (non-exec-page) guest-RAM write path: bump the exclusive
    /// monitor, note a DSR code mutation when the range may execute, and copy
    /// the bytes into the host backing. Takes `&self` -- the shared state it
    /// touches is all interior-mutable: the `exclusive_sequences` map (Task 1),
    /// `dsr_generations` (already interior-mutable), and -- when the copy must
    /// temporarily lift a bookkept-PROTECTED host page -- the reference-counted
    /// `host_access_lifts` table (Task 6), which keeps that page accessible for
    /// the whole copy window and serializes the lift/restore `mprotect`s so two
    /// concurrent read-guard accessors cannot strand each other with a
    /// PROT_NONE page. It never mutates
    /// `native_write_exec_writable_pages`/`native_page_protections`, so it
    /// never needs to run under a write lock. Callers that may hit a native16k
    /// write-exec page must use [`Self::write_exec_page_bytes`] instead.
    ///
    /// DELIBERATELY named `write_bytes_raw_shared`, not `write_bytes_raw`:
    /// this crate has many EXISTING `owned_memory.write_bytes_raw(..)` call
    /// sites (e.g. `dsr::mod::tests`, the native16k rollback test) where
    /// `owned_memory: NativeMappedMemory` is an owned/by-value binding, not a
    /// `&mut self` parameter already in scope. An inherent `&self` method
    /// SHADOWING the `GuestMemory::write_bytes_raw(&mut self, ..)` trait
    /// method under the same name would silently steal exactly those call
    /// sites (Rust's method resolution tries `&Self` before `&mut Self` when
    /// expanding an owned receiver's candidate list), permanently dropping
    /// the exec-page escalation for them with no compiler warning -- verified
    /// empirically with a standalone repro before choosing this name.
    pub(super) fn write_bytes_raw_shared(
        &self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryError> {
        let length = bytes.len();
        if !self.region_contains(address, length) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        self.invalidate_and_note_dsr_write(address, length)?;
        self.copy_bytes_to_host(address, bytes)
    }

    /// Host pointer for a contiguous guest range as a zero-copy write
    /// DESTINATION (recv straight into guest memory, `writev` staged into a
    /// borrowed `iovec`), or `None` when zero-copy doesn't apply. Takes
    /// `&self` -- mirrors `write_bytes_raw_shared`'s `&self`-ness so
    /// `NativeDispatchMemory`'s read-classified adapter (held under only the
    /// memory READ guard) can still hand out a write pointer: every gate here
    /// is itself `&self`, the returned pointer is guest RAM the kernel writes
    /// directly (the same backing `write_bytes_raw_shared` copies into under
    /// a read guard), and a mapping can't be pulled out from under the
    /// pointer mid-dispatch (`munmap`/`mprotect`/exec need the WRITE guard,
    /// which excludes concurrent readers).
    ///
    /// Gates, in order: `region_contains` (one contiguous mapped region --
    /// multi-region and unmapped ranges copy instead); `native_range_allows`
    /// with `write = true` (host-writable, i.e. not a PROT_NONE-guarded
    /// range -- the checked copy path can temporarily lift a guarded page,
    /// a raw pointer cannot); `guest_range_is_writable` (a guest read-only
    /// mapping must EFAULT through the checked copy path, never be written
    /// through a raw host pointer); and `range_may_execute` (an exec/W^X
    /// page write needs `write_exec_page_bytes`'s W^X-metadata update, which
    /// a raw kernel write can't perform, so exec targets MUST fall back to
    /// the copy path). See `GuestMemory::host_ptr_for_write`.
    pub(super) fn host_ptr_for_write_shared(&self, address: u64, len: usize) -> Option<*mut u8> {
        if len == 0 {
            return None;
        }
        if !self.region_contains(address, len) {
            return None;
        }
        if !self.native_range_allows(address, len, true) {
            return None;
        }
        if !self.guest_range_is_writable(address, len) {
            return None;
        }
        if self.range_may_execute(address, len) {
            return None;
        }
        Some(
            self.host_address(carrick_guest_mem::GuestVa(address))
                .ok()?
                .raw() as *mut u8,
        )
    }

    /// The exec-page (SMC/JIT) guest-RAM write path: same exclusive-monitor
    /// and DSR bookkeeping as [`Self::write_bytes_raw_shared`], plus the
    /// `native_write_exec_writable_pages`/`native_page_protections` metadata
    /// update that a write hitting a native16k write-exec page requires.
    /// Needs `&mut self` -- this is the ONLY reason the guest-RAM write path
    /// as a whole still needs a mutable borrow. The trait's `write_bytes_raw`
    /// chooses this over the shared common path based on `range_may_execute`,
    /// exactly as the original unsplit `write_bytes_raw` always called
    /// `prepare_native16k_write_exec_host_write` unconditionally (a no-op
    /// off a write-exec page) -- `range_may_execute` is a safe superset of
    /// the pages `prepare_native16k_write_exec_host_write` actually mutates
    /// (write-exec requires the EXEC bit, so every page it would mutate is
    /// also a page `range_may_execute` reports), so gating on it changes
    /// nothing observable.
    pub(super) fn write_exec_page_bytes(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryError> {
        let length = bytes.len();
        if !self.region_contains(address, length) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        self.invalidate_and_note_dsr_write(address, length)?;
        self.prepare_native16k_write_exec_host_write(address, length)?;
        self.copy_bytes_to_host(address, bytes)
    }

    pub(super) fn atomic_load(&self, address: u64, width: usize) -> Result<u64, MemoryError> {
        if !matches!(width, 1 | 2 | 4 | 8)
            || !address.is_multiple_of(width as u64)
            || !self.region_contains(address, width)
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: width,
            });
        }
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *mut u8;
        let changed = self.prepare_temporary_host_access(address, width, false)?;
        let observed = unsafe {
            match width {
                1 => u64::from(
                    (&*ptr.cast::<std::sync::atomic::AtomicU8>())
                        .load(std::sync::atomic::Ordering::Acquire),
                ),
                2 => u64::from(
                    (&*ptr.cast::<std::sync::atomic::AtomicU16>())
                        .load(std::sync::atomic::Ordering::Acquire),
                ),
                4 => u64::from(
                    (&*ptr.cast::<std::sync::atomic::AtomicU32>())
                        .load(std::sync::atomic::Ordering::Acquire),
                ),
                _ => (&*ptr.cast::<std::sync::atomic::AtomicU64>())
                    .load(std::sync::atomic::Ordering::Acquire),
            }
        };
        self.restore_temporary_host_access(&changed, address, width)?;
        Ok(observed)
    }

    pub(super) fn atomic_store(
        &mut self,
        address: u64,
        width: usize,
        value: u64,
    ) -> Result<(), MemoryError> {
        if !matches!(width, 1 | 2 | 4 | 8)
            || !address.is_multiple_of(width as u64)
            || !self.region_contains(address, width)
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: width,
            });
        }
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *mut u8;
        self.invalidate_exclusive_range(address, width);
        let changed = self.prepare_temporary_host_access(address, width, true)?;
        unsafe {
            match width {
                1 => (&*ptr.cast::<std::sync::atomic::AtomicU8>())
                    .store(value as u8, std::sync::atomic::Ordering::Release),
                2 => (&*ptr.cast::<std::sync::atomic::AtomicU16>())
                    .store(value as u16, std::sync::atomic::Ordering::Release),
                4 => (&*ptr.cast::<std::sync::atomic::AtomicU32>())
                    .store(value as u32, std::sync::atomic::Ordering::Release),
                _ => (&*ptr.cast::<std::sync::atomic::AtomicU64>())
                    .store(value, std::sync::atomic::Ordering::Release),
            }
        }
        self.restore_temporary_host_access(&changed, address, width)
    }

    pub(super) fn atomic_fetch_add(
        &mut self,
        address: u64,
        width: usize,
        value: u64,
        ordering: std::sync::atomic::Ordering,
    ) -> Result<u64, MemoryError> {
        if !matches!(width, 1 | 2 | 4 | 8)
            || !address.is_multiple_of(width as u64)
            || !self.region_contains(address, width)
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: width,
            });
        }
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *mut u8;
        self.invalidate_exclusive_range(address, width);
        let changed = self.prepare_temporary_host_access(address, width, true)?;
        let observed = unsafe {
            match width {
                1 => u64::from(
                    (&*ptr.cast::<std::sync::atomic::AtomicU8>()).fetch_add(value as u8, ordering),
                ),
                2 => u64::from(
                    (&*ptr.cast::<std::sync::atomic::AtomicU16>())
                        .fetch_add(value as u16, ordering),
                ),
                4 => u64::from(
                    (&*ptr.cast::<std::sync::atomic::AtomicU32>())
                        .fetch_add(value as u32, ordering),
                ),
                _ => (&*ptr.cast::<std::sync::atomic::AtomicU64>()).fetch_add(value, ordering),
            }
        };
        self.restore_temporary_host_access(&changed, address, width)?;
        Ok(observed)
    }

    /// Returns the current sequence for `location`, initializing it to
    /// `NativeExclusiveSequence::INITIAL` on first observation. Preserves the
    /// `entry().or_insert()` semantics `exclusive_load_for` always used; only
    /// the locking moved, from the caller's `&mut self` borrow to this
    /// accessor's own `&self` lock on `exclusive_sequences`.
    pub(super) fn exclusive_sequence_or_insert(
        &self,
        location: NativeExclusiveLocation,
    ) -> NativeExclusiveSequence {
        *self
            .exclusive_sequences
            .lock()
            .entry(location)
            .or_insert(NativeExclusiveSequence::INITIAL)
    }

    /// Entry point for the single-threaded-gated linux4k guarded exclusive
    /// path (`emulate_linux4k_guarded_exclusive_access`). Unlike the
    /// DSR-hot path, which calls `exclusive_load_for` directly, this keeps
    /// its own name to mirror `exclusive_store` below; both simply thread
    /// the caller-owned `reservation` (the current guest thread's
    /// `NativeThreadRuntime.exclusive_reservation`) through to the `_for`
    /// implementation. `NativeMappedMemory` itself no longer owns any
    /// reservation state.
    pub(super) fn exclusive_load(
        &self,
        address: u64,
        width: usize,
        acquire: bool,
        reservation: &mut Option<NativeExclusiveReservation>,
    ) -> Result<u64, MemoryError> {
        self.exclusive_load_for(address, width, acquire, reservation)
    }

    /// `&self`: every call this makes -- `region_contains`, `host_address`,
    /// `prepare_temporary_host_access`/`restore_temporary_host_access` (host
    /// mprotect scratch-window toggling, not table mutation), and
    /// `exclusive_sequence_or_insert` (interior-mutable `exclusive_sequences`
    /// lock) -- is already `&self`-safe. The atomic load itself goes through
    /// a raw host pointer, not a `self` mutation. Kept `&mut self` until
    /// Task 5 only because nothing had narrowed the receiver yet.
    pub(super) fn exclusive_load_for(
        &self,
        address: u64,
        width: usize,
        acquire: bool,
        reservation: &mut Option<NativeExclusiveReservation>,
    ) -> Result<u64, MemoryError> {
        if !address.is_multiple_of(width as u64) || !self.region_contains(address, width) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: width,
            });
        }
        let changed = self.prepare_temporary_host_access(address, width, false)?;
        // Balance the lift refcount even if `host_address` or the width
        // match below returns early -- see `copy_bytes_to_host`. The success
        // path DISARMS the guard and restores explicitly so a restore error
        // still propagates; the guard only fires on early exit.
        let mut restore_on_unwind = HostLiftRestoreGuard {
            memory: self,
            changed: &changed,
            address,
            length: width,
            armed: true,
        };
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *mut u8;
        let ordering = if acquire {
            std::sync::atomic::Ordering::Acquire
        } else {
            std::sync::atomic::Ordering::Relaxed
        };
        let observed = unsafe {
            match width {
                1 => u64::from((&*ptr.cast::<std::sync::atomic::AtomicU8>()).load(ordering)),
                2 => u64::from((&*ptr.cast::<std::sync::atomic::AtomicU16>()).load(ordering)),
                4 => u64::from((&*ptr.cast::<std::sync::atomic::AtomicU32>()).load(ordering)),
                8 => (&*ptr.cast::<std::sync::atomic::AtomicU64>()).load(ordering),
                _ => return Err(MemoryError::Unsupported),
            }
        };
        restore_on_unwind.armed = false;
        self.restore_temporary_host_access(&changed, address, width)?;
        let location = NativeExclusiveLocation { address, width };
        let sequence = self.exclusive_sequence_or_insert(location);
        *reservation = Some(NativeExclusiveReservation {
            location,
            observed,
            sequence,
        });
        Ok(observed)
    }

    /// See `exclusive_load`: the linux4k guarded counterpart of
    /// `exclusive_store_for`, threading the caller-owned reservation through
    /// instead of consulting struct-embedded state.
    pub(super) fn exclusive_store(
        &self,
        address: u64,
        width: usize,
        value: u64,
        release: bool,
        reservation: &mut Option<NativeExclusiveReservation>,
    ) -> Result<bool, MemoryError> {
        self.exclusive_store_for(address, width, value, release, reservation)
    }

    /// Returns the current sequence for `location`, or
    /// `NativeExclusiveSequence::INITIAL` if it has never been observed
    /// (without inserting). Preserves the `get().copied().unwrap_or()`
    /// semantics `exclusive_store_for` always used; only the locking moved,
    /// from the caller's `&mut self` borrow to this accessor's own `&self`
    /// lock on `exclusive_sequences`.
    pub(super) fn exclusive_sequence_or_default(
        &self,
        location: NativeExclusiveLocation,
    ) -> NativeExclusiveSequence {
        self.exclusive_sequences
            .lock()
            .get(&location)
            .copied()
            .unwrap_or(NativeExclusiveSequence::INITIAL)
    }

    /// Advances the tracked sequence for `location` past `observed_sequence`
    /// (the value most recently compared against). Called after a
    /// successful exclusive-store CAS.
    pub(super) fn bump_exclusive_sequence(
        &self,
        location: NativeExclusiveLocation,
        observed_sequence: NativeExclusiveSequence,
    ) {
        self.exclusive_sequences
            .lock()
            .insert(location, observed_sequence.next());
    }

    /// `&self`: same reasoning as `exclusive_load_for` -- the CAS goes
    /// through a raw host pointer and `bump_exclusive_sequence` is already
    /// `&self` (interior-mutable `exclusive_sequences` lock).
    pub(super) fn exclusive_store_for(
        &self,
        address: u64,
        width: usize,
        value: u64,
        release: bool,
        reservation: &mut Option<NativeExclusiveReservation>,
    ) -> Result<bool, MemoryError> {
        let Some(reservation) = reservation.take() else {
            return Ok(false);
        };
        let location = NativeExclusiveLocation { address, width };
        let sequence = self.exclusive_sequence_or_default(location);
        if reservation.location != location || reservation.sequence != sequence {
            return Ok(false);
        }
        let changed = self.prepare_temporary_host_access(address, width, true)?;
        // Balance the lift refcount even if `host_address` or the width
        // match below returns early -- see `copy_bytes_to_host`. The success
        // path DISARMS the guard and restores explicitly so a restore error
        // still propagates; the guard only fires on early exit.
        let mut restore_on_unwind = HostLiftRestoreGuard {
            memory: self,
            changed: &changed,
            address,
            length: width,
            armed: true,
        };
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *mut u8;
        let success = if release {
            std::sync::atomic::Ordering::Release
        } else {
            std::sync::atomic::Ordering::Relaxed
        };
        let stored = unsafe {
            match width {
                1 => (&*ptr.cast::<std::sync::atomic::AtomicU8>())
                    .compare_exchange(
                        reservation.observed as u8,
                        value as u8,
                        success,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok(),
                2 => (&*ptr.cast::<std::sync::atomic::AtomicU16>())
                    .compare_exchange(
                        reservation.observed as u16,
                        value as u16,
                        success,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok(),
                4 => (&*ptr.cast::<std::sync::atomic::AtomicU32>())
                    .compare_exchange(
                        reservation.observed as u32,
                        value as u32,
                        success,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok(),
                8 => (&*ptr.cast::<std::sync::atomic::AtomicU64>())
                    .compare_exchange(
                        reservation.observed,
                        value,
                        success,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok(),
                _ => return Err(MemoryError::Unsupported),
            }
        };
        if stored {
            self.bump_exclusive_sequence(location, sequence);
        }
        restore_on_unwind.armed = false;
        self.restore_temporary_host_access(&changed, address, width)?;
        Ok(stored)
    }

    pub(super) fn linux4k_address_is_guarded(&self, address: u64) -> bool {
        if !self.uses_linux4k_subpages() {
            return false;
        }
        let host_page = address & !(self.host_page_size - 1);
        matches!(
            self.classify_linux4k_host_page(self.linux4k_host_page_protections(host_page)),
            HostPageState::MixedGuarded(_)
                | HostPageState::Composed16k
                | HostPageState::Unsupported(MixedPageReason::ExecutableMixedPage)
        )
    }

    pub(super) fn native_host_prot_for_page(&self, page_start: u64) -> libc::c_int {
        if !self.uses_linux4k_subpages() {
            let prot = self
                .native_page_protections
                .get(&page_start)
                .copied()
                .unwrap_or_else(|| self.default_linux_prot_at(page_start));
            if self.native_write_exec_writable_pages.contains(&page_start) {
                return libc::PROT_READ | libc::PROT_WRITE;
            }
            return native16k_host_prot(prot);
        }
        let protections = self.linux4k_host_page_protections(page_start);
        match self.classify_linux4k_host_page(protections) {
            HostPageState::Uniform16k => linux_prot_to_native(protections[0]),
            HostPageState::MixedGuarded(_) | HostPageState::Composed16k => libc::PROT_NONE,
            HostPageState::Unsupported(_) => libc::PROT_NONE,
        }
    }

    pub(super) fn mprotect_host_page(
        &self,
        page_start: u64,
        host_prot: libc::c_int,
        operation_address: u64,
        operation_len: usize,
    ) -> Result<(), MemoryError> {
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(page_start))?
            .raw() as *mut libc::c_void;
        let host_page_len =
            usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                address: operation_address,
                length: operation_len,
            })?;
        if unsafe { libc::mprotect(ptr, host_page_len, host_prot) } != 0 {
            return Err(MemoryError::HostMap(format!(
                "mprotect native Darwin host page 0x{page_start:x}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    pub(super) fn prepare_temporary_host_access(
        &self,
        address: u64,
        len: usize,
        write: bool,
    ) -> Result<Vec<(u64, libc::c_int)>, MemoryError> {
        self.prepare_temporary_host_access_with(address, len, write, native_host_mprotect)
    }

    pub(super) fn prepare_temporary_host_access_with<F>(
        &self,
        address: u64,
        len: usize,
        write: bool,
        mut set_host_prot: F,
    ) -> Result<Vec<(u64, libc::c_int)>, MemoryError>
    where
        F: FnMut(carrick_guest_mem::HostVa, usize, libc::c_int) -> Result<(), MemoryError>,
    {
        if len == 0 {
            return Ok(Vec::new());
        }
        let host_page_len =
            usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        let mut changed = Vec::new();
        let required = if write {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        // The lift-table guard is acquired LAZILY: the common native16k case
        // where every touched page already grants `required` never lifts a
        // page, so it never takes the lock and stays fully concurrent.
        let mut lifts: Option<
            parking_lot::MutexGuard<'_, std::collections::HashMap<u64, HostLift>>,
        > = None;

        // `host_protected_overlaps` can yield MORE THAN ONE overlap -- a
        // read/write spanning two adjacent protected regions -- and an
        // EARLIER overlap's phase 3 can already have committed refcounts
        // (and mprotected pages up) before a LATER overlap's phase 1/2 fails.
        // Run the per-overlap work in an immediately-invoked closure so `?`
        // unwinds to a `Result` here instead of straight out of the function,
        // which would strand the earlier overlap's commits forever (a
        // `HostLift` whose refcount never gets decremented). This makes
        // `prepare` all-or-nothing: on error we roll back exactly what THIS
        // call committed before propagating.
        let result: Result<(), MemoryError> = (|| {
            for (start, end) in self.host_protected_overlaps(address, len) {
                let (page_start, page_len) = self.host_page_range(start, end)?;
                let page_end = page_start.saturating_add(page_len as u64);

                // Phase 1: under the lift-table lock, decide the mprotect target
                // for each page that still needs lifting -- `Some(prot)` means
                // this accessor is the first to require `prot` (a fresh lift or
                // an upgrade of an existing one); `None` means a concurrent
                // accessor already holds the page at >= `required`. Table state
                // is only READ here (committed in phase 3); pages never repeat
                // within one call, so an earlier decision cannot invalidate a
                // later one. Pages that already grant `required` are the
                // lock-free fast path and are skipped entirely.
                let mut pending: Vec<(u64, libc::c_int, Option<libc::c_int>)> = Vec::new();
                let mut page = page_start;
                while page < page_end {
                    let restore = self.native_host_prot_for_page(page);
                    if restore & required != required {
                        let table = lifts.get_or_insert_with(|| self.host_access_lifts.lock());
                        let target = match table.get(&page) {
                            None => Some(required),
                            Some(lift) if lift.lifted_prot & required != required => {
                                Some(lift.lifted_prot | required)
                            }
                            Some(_) => None,
                        };
                        pending.push((page, restore, target));
                    }
                    page = page.saturating_add(self.host_page_size);
                }

                // Phase 2: execute the mprotects. Contiguous pages needing the
                // SAME target coalesce into one call (preserving the
                // pre-refcount behavior for the single-accessor case); a page
                // with no target (already lifted by a peer) breaks the run.
                // Done BEFORE any table mutation so a failing mprotect leaks no
                // refcount FOR THIS OVERLAP (an earlier overlap's commits, if
                // any, are unwound below).
                let mut run: Option<(u64, usize, libc::c_int)> = None;
                for &(page, _restore, target) in &pending {
                    match target {
                        Some(target_prot) => {
                            run = match run {
                                Some((run_start, run_pages, run_prot))
                                    if run_prot == target_prot
                                        && run_start.saturating_add(
                                            run_pages as u64 * self.host_page_size,
                                        ) == page =>
                                {
                                    Some((run_start, run_pages + 1, run_prot))
                                }
                                Some((run_start, run_pages, run_prot)) => {
                                    set_host_prot(
                                        self.host_address(carrick_guest_mem::GuestVa(run_start))?,
                                        host_page_len * run_pages,
                                        run_prot,
                                    )?;
                                    Some((page, 1, target_prot))
                                }
                                None => Some((page, 1, target_prot)),
                            };
                        }
                        None => {
                            if let Some((run_start, run_pages, run_prot)) = run.take() {
                                set_host_prot(
                                    self.host_address(carrick_guest_mem::GuestVa(run_start))?,
                                    host_page_len * run_pages,
                                    run_prot,
                                )?;
                            }
                        }
                    }
                }
                if let Some((run_start, run_pages, run_prot)) = run {
                    set_host_prot(
                        self.host_address(carrick_guest_mem::GuestVa(run_start))?,
                        host_page_len * run_pages,
                        run_prot,
                    )?;
                }

                // Phase 3: every mprotect for this overlap landed, so commit the
                // refcounts. A fresh page inserts refcount 1 with its original
                // protection; an already-lifted page increments and upgrades
                // `lifted_prot` (idempotent when no upgrade was needed). Each
                // page is recorded once per visit in `changed` so restore (or
                // this call's own rollback, on a later failure) decrements it
                // once.
                if let Some(table) = lifts.as_mut() {
                    for &(page, restore, _target) in &pending {
                        if let Some(lift) = table.get_mut(&page) {
                            lift.refcount = lift.refcount.saturating_add(1);
                            lift.lifted_prot |= required;
                        } else {
                            table.insert(
                                page,
                                HostLift {
                                    refcount: 1,
                                    original_prot: restore,
                                    lifted_prot: required,
                                },
                            );
                        }
                        changed.push((page, restore));
                    }
                }
            }
            Ok(())
        })();

        if let Err(err) = result {
            // Unwind exactly what THIS call committed, under the SAME guard
            // held since the first lift -- `rollback_prepared_lifts` must NOT
            // re-lock `host_access_lifts` (parking_lot::Mutex is not
            // reentrant).
            if let Some(table) = lifts.as_mut() {
                self.rollback_prepared_lifts(table, &changed, host_page_len, &mut set_host_prot);
            }
            return Err(err);
        }

        Ok(changed)
    }

    /// Undo exactly the refcounts (and, where a refcount consequently drops
    /// to zero, the mprotect-up) that THIS `prepare_temporary_host_access`
    /// call committed into `changed` before it failed partway through a
    /// LATER overlap. Called with the SAME `host_access_lifts` guard
    /// `prepare` has held since its first lift -- never re-locks (the mutex
    /// is not reentrant, so re-locking here would deadlock).
    ///
    /// Best-effort on the mprotect: `prepare` is already unwinding with a
    /// real error and cannot also surface a second one, so a rollback
    /// mprotect failure is swallowed. The refcount is removed from the table
    /// regardless -- `mprotect` is an absolute, idempotent set, so a later
    /// accessor's own lift attempt still lands the page in the right state
    /// even if this best-effort restore didn't land.
    pub(super) fn rollback_prepared_lifts<F>(
        &self,
        table: &mut std::collections::HashMap<u64, HostLift>,
        changed: &[(u64, libc::c_int)],
        host_page_len: usize,
        set_host_prot: &mut F,
    ) where
        F: FnMut(carrick_guest_mem::HostVa, usize, libc::c_int) -> Result<(), MemoryError>,
    {
        let mut to_restore: Vec<(u64, libc::c_int)> = Vec::with_capacity(changed.len());
        for &(page, restore) in changed {
            match table.entry(page) {
                std::collections::hash_map::Entry::Occupied(mut occupied) => {
                    let refcount = {
                        let lift = occupied.get_mut();
                        lift.refcount = lift.refcount.saturating_sub(1);
                        lift.refcount
                    };
                    if refcount == 0 {
                        let original = occupied.get().original_prot;
                        occupied.remove();
                        to_restore.push((page, original));
                    }
                }
                std::collections::hash_map::Entry::Vacant(_) => {
                    // Should not happen -- `changed` only records pages this
                    // call itself inserted or bumped -- but fall back to
                    // restoring the recorded protection so a page is never
                    // left stranded.
                    to_restore.push((page, restore));
                }
            }
        }

        // Restore in reverse order, merging adjacent pages whose target
        // protection is identical into one mprotect call (mirrors
        // `restore_temporary_host_access_with`).
        let mut entries = to_restore.iter().rev().peekable();
        while let Some(&(page_start, restore)) = entries.next() {
            let mut run_start = page_start;
            let mut run_pages = 1_usize;
            while let Some(&&(previous_page, previous_restore)) = entries.peek() {
                if previous_restore == restore
                    && previous_page.checked_add(self.host_page_size) == Some(run_start)
                {
                    run_start = previous_page;
                    run_pages += 1;
                    entries.next();
                } else {
                    break;
                }
            }
            let Ok(host_va) = self.host_address(carrick_guest_mem::GuestVa(run_start)) else {
                continue;
            };
            let _ = set_host_prot(host_va, host_page_len * run_pages, restore);
        }
    }

    pub(super) fn restore_temporary_host_access(
        &self,
        changed: &[(u64, libc::c_int)],
        address: u64,
        len: usize,
    ) -> Result<(), MemoryError> {
        self.restore_temporary_host_access_with(changed, address, len, native_host_mprotect)
    }

    pub(super) fn restore_temporary_host_access_with<F>(
        &self,
        changed: &[(u64, libc::c_int)],
        address: u64,
        len: usize,
        mut set_host_prot: F,
    ) -> Result<(), MemoryError>
    where
        F: FnMut(carrick_guest_mem::HostVa, usize, libc::c_int) -> Result<(), MemoryError>,
    {
        // The no-lift fast path records nothing, so it never takes the lock.
        if changed.is_empty() {
            return Ok(());
        }
        let host_page_len =
            usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                address,
                length: len,
            })?;

        // Under the lift-table lock, decrement each recorded page's refcount and
        // collect the pages THIS accessor is the last to release (refcount hit
        // 0). Pages still held by a concurrent accessor stay lifted and are not
        // restored here. A missing entry -- e.g. a direct `restore_with` unit
        // test, or a page whose lift was never tracked -- falls back to the
        // recorded protection so a page is never left stranded. The mprotect
        // stays inside the critical section: removing the entry and restoring
        // the protection must be atomic against a concurrent `prepare` that
        // could otherwise re-lift the page in between.
        let mut lifts = self.host_access_lifts.lock();
        let mut to_restore: Vec<(u64, libc::c_int)> = Vec::with_capacity(changed.len());
        for &(page, restore) in changed {
            match lifts.entry(page) {
                std::collections::hash_map::Entry::Occupied(mut occupied) => {
                    let refcount = {
                        let lift = occupied.get_mut();
                        lift.refcount = lift.refcount.saturating_sub(1);
                        lift.refcount
                    };
                    if refcount == 0 {
                        let original = occupied.get().original_prot;
                        occupied.remove();
                        to_restore.push((page, original));
                    }
                }
                std::collections::hash_map::Entry::Vacant(_) => {
                    to_restore.push((page, restore));
                }
            }
        }

        // Restore in the same reverse order as before, merging adjacent pages
        // whose target protection is identical into one mprotect call. Pages
        // with differing prots keep their own exact call.
        let mut entries = to_restore.iter().rev().peekable();
        while let Some(&(page_start, restore)) = entries.next() {
            let mut run_start = page_start;
            let mut run_pages = 1_usize;
            while let Some(&&(previous_page, previous_restore)) = entries.peek() {
                if previous_restore == restore
                    && previous_page.checked_add(self.host_page_size) == Some(run_start)
                {
                    run_start = previous_page;
                    run_pages += 1;
                    entries.next();
                } else {
                    break;
                }
            }
            set_host_prot(
                self.host_address(carrick_guest_mem::GuestVa(run_start))?,
                host_page_len * run_pages,
                restore,
            )?;
        }
        Ok(())
    }

    pub(super) fn protect_linux4k_range(
        &mut self,
        address: u64,
        len: usize,
        prot: u64,
    ) -> Result<(), MemoryError> {
        self.protect_linux4k_range_with(address, len, prot, native_host_mprotect)
    }

    pub(super) fn protect_linux4k_range_with<F>(
        &mut self,
        address: u64,
        len: usize,
        prot: u64,
        mut set_host_prot: F,
    ) -> Result<(), MemoryError>
    where
        F: FnMut(carrick_guest_mem::HostVa, usize, libc::c_int) -> Result<(), MemoryError>,
    {
        if !address.is_multiple_of(self.linux_page_size)
            || !(len as u64).is_multiple_of(self.linux_page_size)
        {
            return Err(MemoryError::Unsupported);
        }
        let end = address
            .checked_add(len as u64)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        let first_host_page = address & !(self.host_page_size - 1);
        let last_host_page = end
            .checked_add(self.host_page_size - 1)
            .map(|value| value & !(self.host_page_size - 1))
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        let mut plan = Vec::new();
        let mut page_start = first_host_page;
        while page_start < last_host_page {
            let mut protections = self.linux4k_host_page_protections(page_start);
            for (index, subpage_prot) in protections.iter_mut().enumerate() {
                let subpage_start = page_start.saturating_add(index as u64 * self.linux_page_size);
                let subpage_end = subpage_start.saturating_add(self.linux_page_size);
                if address < subpage_end && subpage_start < end {
                    *subpage_prot = prot;
                }
            }
            let state = self.classify_linux4k_host_page(protections);
            let state = match state {
                HostPageState::Unsupported(MixedPageReason::ExecutableMixedPage) => {
                    HostPageState::MixedGuarded(MixedPageReason::ExecutableMixedPage)
                }
                HostPageState::Unsupported(_) => return Err(MemoryError::Unsupported),
                state => state,
            };
            plan.push((page_start, protections, state));
            page_start = page_start.saturating_add(self.host_page_size);
        }

        let host_page_len =
            usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        struct PlannedHostPage {
            page_start: u64,
            protections: [u64; 4],
            host_prot: libc::c_int,
            needs_icache: bool,
            host_page: carrick_guest_mem::HostVa,
        }
        let mut resolved = Vec::with_capacity(plan.len());
        for (page_start, protections, state) in plan {
            let mut host_prot = match state {
                HostPageState::Uniform16k => linux_prot_to_native(protections[0]),
                HostPageState::MixedGuarded(_) | HostPageState::Composed16k => libc::PROT_NONE,
                HostPageState::Unsupported(_) => return Err(MemoryError::Unsupported),
            };
            let needs_icache = protections
                .iter()
                .any(|value| value & crate::linux_abi::LINUX_PROT_EXEC != 0);
            if needs_icache {
                host_prot = (host_prot & !libc::PROT_EXEC) | libc::PROT_READ;
            }
            resolved.push(PlannedHostPage {
                page_start,
                protections,
                host_prot,
                needs_icache,
                host_page: self.host_address(carrick_guest_mem::GuestVa(page_start))?,
            });
        }
        // Merge maximal runs of adjacent host pages whose RESOLVED final
        // host protection is identical into one mprotect call. The icache
        // clears stay per page (only pages with an executable subpage get
        // one, exactly as before), and the per-page subpage bookkeeping is
        // unchanged.
        let mut index = 0;
        while index < resolved.len() {
            let mut end = index + 1;
            while end < resolved.len()
                && resolved[end].host_prot == resolved[index].host_prot
                && resolved[end - 1]
                    .page_start
                    .checked_add(self.host_page_size)
                    == Some(resolved[end].page_start)
            {
                end += 1;
            }
            for page in &resolved[index..end] {
                if page.needs_icache {
                    let ptr = page.host_page.raw() as *mut u8;
                    unsafe { carrick_native_clear_icache(ptr.cast(), host_page_len) };
                }
            }
            set_host_prot(
                resolved[index].host_page,
                host_page_len * (end - index),
                resolved[index].host_prot,
            )?;
            for page in &resolved[index..end] {
                self.linux4k_page_protections
                    .insert(page.page_start, page.protections);
            }
            index = end;
        }
        Ok(())
    }

    pub(super) fn read_u32(&self, address: u64) -> Result<u32, RuntimeError> {
        let bytes = self
            .read_bytes_raw(address, std::mem::size_of::<u32>())
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native Darwin instruction read failed at 0x{address:x}: {error}"
                ))
            })?;
        let word: [u8; 4] = bytes.try_into().map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin instruction read was short at 0x{address:x}"
            ))
        })?;
        Ok(u32::from_le_bytes(word))
    }

    pub(super) fn instruction_fingerprint_words(
        &self,
        start: carrick_guest_mem::GuestVa,
        max_instructions: usize,
    ) -> Result<Vec<u32>, RuntimeError> {
        let page_end = (start.raw() | self.linux_page_size.saturating_sub(1)).saturating_add(1);
        let requested = max_instructions
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or_else(|| RuntimeError::Unsupported("instruction fingerprint overflow".into()))?;
        let available = usize::try_from(page_end.saturating_sub(start.raw())).unwrap_or(usize::MAX);
        let length = requested.min(available);
        let bytes = self.read_bytes_raw(start.raw(), length).map_err(|error| {
            RuntimeError::Unsupported(format!(
                "native Darwin instruction fingerprint failed at 0x{:x}: {error}",
                start.raw()
            ))
        })?;
        Ok(bytes
            .chunks_exact(std::mem::size_of::<u32>())
            .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            .collect())
    }

    pub(super) fn write_u64(&mut self, address: u64, value: u64) -> Result<(), RuntimeError> {
        if !self.region_contains(address, std::mem::size_of::<u64>()) {
            return Err(RuntimeError::Unsupported(format!(
                "native Darwin relocation outside mapped guest memory at 0x{address:x}"
            )));
        }
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?
            .raw() as *mut u64;
        unsafe { std::ptr::write_unaligned(ptr, value) };
        Ok(())
    }

    pub(super) fn fixed_mapping_target(
        &self,
        guest_start: u64,
        length: usize,
        flags: i32,
    ) -> Result<(carrick_guest_mem::HostVa, i32), MemoryError> {
        let host_start = self.host_address(carrick_guest_mem::GuestVa(guest_start))?;
        let flags = self
            .address_mode
            .fixed_mapping_flags(&self.owned_host_ranges, host_start, length, flags)
            .map_err(|error| MemoryError::HostMap(error.to_string()))?;
        Ok((host_start, flags))
    }

    pub(super) fn remap_private(
        &mut self,
        address: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), MemoryError> {
        if content.len() != len || !self.region_contains(address, len) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: len,
            });
        }
        let end = address
            .checked_add(len as u64)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        let (page_start, page_len) = self.host_page_range(address, end)?;
        let (host_start, flags) = self.fixed_mapping_target(
            page_start,
            page_len,
            libc::MAP_ANON | libc::MAP_NORESERVE | libc::MAP_PRIVATE,
        )?;
        let mut page = self.read_bytes_raw(page_start, page_len)?;
        let offset = usize::try_from(address.saturating_sub(page_start)).map_err(|_| {
            MemoryError::OutOfBounds {
                address,
                length: len,
            }
        })?;
        page[offset..offset + len].copy_from_slice(content);

        let ptr = host_start.raw() as *mut libc::c_void;
        let mapped = unsafe {
            libc::mmap(
                ptr,
                page_len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED || mapped != ptr {
            return Err(MemoryError::OutOfBounds {
                address,
                length: len,
            });
        }
        unsafe {
            std::ptr::copy_nonoverlapping(page.as_ptr(), mapped.cast::<u8>(), page.len());
        }
        Ok(())
    }

    pub(super) fn map_host_alias(
        &mut self,
        address: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
        prot_none: bool,
    ) -> Result<(), RuntimeError> {
        let map_len = align_up_u64(len, self.host_page_size, "native alias length")?;
        let map_len_usize = usize::try_from(map_len).map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin alias too large: 0x{address:x}+0x{len:x}"
            ))
        })?;
        if map_len_usize == 0 {
            return Ok(());
        }
        let page_start = address & !(self.host_page_size - 1);
        let page_delta = address.saturating_sub(page_start);
        let host_map_len = align_up_u64(
            page_delta.checked_add(len).ok_or_else(|| {
                RuntimeError::Unsupported(format!(
                    "native Darwin alias host length overflow: 0x{address:x}+0x{len:x}"
                ))
            })?,
            self.host_page_size,
            "native alias host length",
        )?;
        let host_map_len_usize = usize::try_from(host_map_len).map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin alias too large: 0x{address:x}+0x{len:x}"
            ))
        })?;
        let guest_map_start = if page_delta == 0 { address } else { page_start };

        let (mmap_prot, final_prot, flags, fd, offset, direct_file) = match file {
            Some((fd, offset, prot)) if page_delta == 0 => {
                (prot, prot, libc::MAP_SHARED, fd, offset, true)
            }
            Some((fd, offset, prot)) => (
                libc::PROT_READ | libc::PROT_WRITE,
                prot,
                libc::MAP_ANON | libc::MAP_SHARED | libc::MAP_NORESERVE,
                fd,
                offset,
                false,
            ),
            None => (
                libc::PROT_READ | libc::PROT_WRITE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
                -1,
                0,
                false,
            ),
        };
        let host_final_prot = native16k_host_prot(final_prot as u64);
        let mmap_prot = if direct_file {
            host_final_prot
        } else {
            mmap_prot
        };
        let mmap_fd = if direct_file { fd } else { -1 };
        let mmap_offset = if direct_file { offset } else { 0 };
        let (host_start, flags) =
            match self.fixed_mapping_target(guest_map_start, host_map_len_usize, flags) {
                Ok(target) => target,
                Err(error) => {
                    if file.is_some() {
                        unsafe { libc::close(fd) };
                    }
                    return Err(RuntimeError::Unsupported(error.to_string()));
                }
            };
        let addr = host_start.raw() as *mut libc::c_void;
        // File-identity futex key material (see `NativeMappedRegion`): only a
        // DIRECT host MAP_SHARED file mapping is physically coherent with an
        // independent mapping of the same file, so only it earns a file key.
        // The pread-copy fallback (unaligned offset) is anon-backed — a file
        // key there would count waiters that no physical wake can reach.
        let (shared_key_base, shared_key_offset) = if direct_file {
            (
                crate::trap::shared_file_key_base(fd),
                u64::try_from(offset).unwrap_or_default(),
            )
        } else {
            (0, 0)
        };
        let mapped = unsafe {
            libc::mmap(
                addr,
                host_map_len_usize,
                mmap_prot,
                flags,
                mmap_fd,
                mmap_offset,
            )
        };
        if mapped != libc::MAP_FAILED && file.is_some() && !direct_file {
            let copy_len = usize::try_from(len).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin alias guest length too large: 0x{address:x}+0x{len:x}"
                ))
            })?;
            let copy_offset = usize::try_from(page_delta).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin alias page delta too large: 0x{page_delta:x}"
                ))
            })?;
            let dst = unsafe { mapped.cast::<u8>().add(copy_offset) };
            let mut copied = 0usize;
            while copied < copy_len {
                let rc = unsafe {
                    libc::pread(
                        fd,
                        dst.add(copied).cast::<libc::c_void>(),
                        copy_len - copied,
                        offset.saturating_add(copied as libc::off_t),
                    )
                };
                match rc.host_syscall_errno() {
                    Ok(0) => break,
                    Ok(n) => copied = copied.saturating_add(n as usize),
                    Err(errno) if errno == crate::linux_abi::LINUX_EINTR => {}
                    Err(errno) => {
                        unsafe { libc::close(fd) };
                        return Err(RuntimeError::Unsupported(format!(
                            "native Darwin alias pread failed with errno {}",
                            errno.get()
                        )));
                    }
                }
            }
            if host_final_prot != mmap_prot {
                let rc = unsafe { libc::mprotect(mapped, host_map_len_usize, host_final_prot) };
                if rc != 0 {
                    unsafe { libc::close(fd) };
                    return Err(last_io_error(&format!(
                        "mprotect native Darwin alias 0x{page_start:x}..0x{:x}",
                        page_start.saturating_add(host_map_len)
                    )));
                }
            }
        }
        if file.is_some() {
            unsafe { libc::close(fd) };
        }
        if mapped == libc::MAP_FAILED {
            return Err(last_io_error(&format!(
                "mmap native Darwin alias 0x{address:x}..0x{:x}",
                address.saturating_add(host_map_len)
            )));
        }
        if mapped != addr {
            return Err(RuntimeError::Unsupported(format!(
                "native Darwin mmap did not honor MAP_FIXED for alias 0x{address:x}"
            )));
        }

        // MAP_FIXED replaces the physical host pages, so none of the prior
        // mapping's protection overrides remain authoritative. Leaving a
        // stale PROT_NONE entry here lets a later temporary host access restore
        // the newly writable page to no-access (Go user arenas remap freed
        // 8 MiB chunks this way). Clear whole host pages, matching mmap's
        // replacement granularity; Linux-4K subpage state is stale for the
        // same reason.
        let replaced_end = guest_map_start.saturating_add(host_map_len);
        let mut replaced_page = guest_map_start;
        while replaced_page < replaced_end {
            self.native_page_protections.remove(&replaced_page);
            self.native_write_exec_writable_pages.remove(&replaced_page);
            self.linux4k_page_protections.remove(&replaced_page);
            replaced_page = replaced_page.saturating_add(self.host_page_size);
        }

        if file.is_none() && !payload.is_empty() {
            let n = payload.len().min(map_len_usize);
            unsafe {
                std::ptr::copy_nonoverlapping(payload.as_ptr(), mapped.cast::<u8>(), n);
            }
        }

        let len_usize = usize::try_from(len).map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin alias guest length too large: 0x{address:x}+0x{len:x}"
            ))
        })?;
        self.protections.set_mapping_protection(
            address,
            len_usize,
            prot_none,
            !prot_none && final_prot & libc::PROT_WRITE == 0,
        );
        self.regions.push(NativeMappedRegion {
            start: address,
            end: checked_add_u64(address, len, "native alias end")?,
            host_protects: true,
            shared_futex: file.is_some(),
            guest_writable: final_prot & libc::PROT_WRITE != 0,
            default_prot: if prot_none { 0 } else { final_prot as u64 },
            shared_key_base,
            shared_key_offset,
        });
        Ok(())
    }

    pub(super) fn protect_native16k_range_with<F>(
        &mut self,
        address: u64,
        len: usize,
        prot: u64,
        mut set_host_prot: F,
    ) -> Result<(), MemoryError>
    where
        F: FnMut(carrick_guest_mem::HostVa, usize, libc::c_int) -> Result<(), MemoryError>,
    {
        let host_prot = native16k_host_prot(prot);
        let mut pages = BTreeSet::new();
        for (start, end) in self.host_protected_overlaps(address, len) {
            let (page_start, page_len) = self.host_page_range(start, end)?;
            let page_end = page_start.saturating_add(page_len as u64);
            let mut page = page_start;
            while page < page_end {
                pages.insert(page);
                page = page.saturating_add(self.host_page_size);
            }
        }
        let host_page_len =
            usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                address,
                length: len,
            })?;

        let pages: Vec<(u64, carrick_guest_mem::HostVa, *mut libc::c_void)> = pages
            .into_iter()
            .map(|page_start| {
                let host_page = self.host_address(carrick_guest_mem::GuestVa(page_start))?;
                let ptr = host_page.raw() as *mut libc::c_void;
                Ok((page_start, host_page, ptr))
            })
            .collect::<Result<_, MemoryError>>()?;

        struct ProtectionSnapshot {
            host_page: carrick_guest_mem::HostVa,
            ptr: *mut libc::c_void,
            old_host_prot: libc::c_int,
            patched_words: Vec<(usize, u32)>,
        }

        let mut snapshots = Vec::with_capacity(pages.len());
        let apply_result = (|| {
            // The final host protection is uniform across this call, so a
            // maximal run of adjacent host pages collapses into ONE
            // mprotect per phase. Snapshots and metadata stay per page.
            let mut index = 0;
            while index < pages.len() {
                let mut end = index + 1;
                while end < pages.len()
                    && pages[end - 1].0.checked_add(self.host_page_size) == Some(pages[end].0)
                {
                    end += 1;
                }
                let run_pages = &pages[index..end];
                let (_, run_host, run_ptr) = run_pages[0];
                let run_len = host_page_len * run_pages.len();
                if prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
                    set_host_prot(run_host, run_len, libc::PROT_READ)?;
                    for &(page_start, host_page, ptr) in run_pages {
                        snapshots.push(ProtectionSnapshot {
                            host_page,
                            ptr,
                            old_host_prot: self.native_host_prot_for_page(page_start),
                            patched_words: Vec::new(),
                        });
                    }
                    // Every page in an exec run received the icache clear
                    // before coalescing; the run-wide clear covers exactly
                    // the same pages.
                    unsafe { carrick_native_clear_icache(run_ptr, run_len) };
                } else {
                    for &(page_start, host_page, ptr) in run_pages {
                        snapshots.push(ProtectionSnapshot {
                            host_page,
                            ptr,
                            old_host_prot: self.native_host_prot_for_page(page_start),
                            patched_words: Vec::new(),
                        });
                    }
                }
                set_host_prot(run_host, run_len, host_prot)?;
                index = end;
            }
            Ok(())
        })();

        if let Err(error) = apply_result {
            let mut rollback_error = None;
            for snapshot in snapshots.iter().rev() {
                if !snapshot.patched_words.is_empty() {
                    match set_host_prot(
                        snapshot.host_page,
                        host_page_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                    ) {
                        Ok(()) => unsafe {
                            for &(offset, original) in &snapshot.patched_words {
                                let word = snapshot.ptr.cast::<u8>().add(offset).cast::<u32>();
                                std::ptr::write_unaligned(word, original);
                            }
                            carrick_native_clear_icache(snapshot.ptr, host_page_len);
                        },
                        Err(restore_error) => rollback_error = Some(restore_error),
                    }
                }
                if let Err(restore_error) =
                    set_host_prot(snapshot.host_page, host_page_len, snapshot.old_host_prot)
                {
                    rollback_error = Some(restore_error);
                }
            }
            if let Some(rollback_error) = rollback_error {
                return Err(MemoryError::HostMap(format!(
                    "native16k protection failed: {error}; rollback failed: {rollback_error}"
                )));
            }
            return Err(error);
        }

        for (page_start, _, _) in pages {
            // Sparse representation: every reader (`native_range_allows`,
            // `native_host_prot_for_page`, `guest_address_is_executable`,
            // ...) already falls back to `default_linux_prot_at` for a
            // MISSING page, so a page whose protection matches its
            // region's default is redundant to store. `region_contains`
            // in `protect_range` guarantees the region (and its
            // `default_prot`) is already established here.
            if prot == self.default_linux_prot_at(page_start) {
                self.native_page_protections.remove(&page_start);
            } else {
                self.native_page_protections.insert(page_start, prot);
            }
            self.native_write_exec_writable_pages.remove(&page_start);
        }
        Ok(())
    }
}

impl GuestMemory for NativeMappedMemory {
    fn protections(&self) -> Option<&MemoryProtections> {
        Some(&self.protections)
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if !bytes.is_empty() && self.protections.range_write_denied(address, bytes.len()) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.write_bytes_raw(address, bytes)
    }

    fn write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if bytes.is_empty() {
            return Ok(());
        }
        if !self.region_contains(address, bytes.len()) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.write_bytes_raw(address, bytes)
    }

    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        static ZERO_CHUNK: [u8; 64 * 1024] = [0; 64 * 1024];
        let mut offset = 0usize;
        while offset < len {
            let chunk = (len - offset).min(ZERO_CHUNK.len());
            let chunk_address =
                address
                    .checked_add(offset as u64)
                    .ok_or(MemoryError::OutOfBounds {
                        address,
                        length: len,
                    })?;
            self.write_bytes_unchecked(chunk_address, &ZERO_CHUNK[..chunk])?;
            offset += chunk;
        }
        Ok(())
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        if !self.region_contains(address, length) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *const u8;
        let mut out = vec![0u8; length];
        let changed = self.prepare_temporary_host_access(address, length, false)?;
        // See `copy_bytes_to_host`: keep the lift refcount balanced on an early
        // exit, disarm and restore explicitly on the success path.
        let mut restore_on_unwind = HostLiftRestoreGuard {
            memory: self,
            changed: &changed,
            address,
            length,
            armed: true,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), length);
        }
        restore_on_unwind.armed = false;
        self.restore_temporary_host_access(&changed, address, length)?;
        Ok(out)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        // Dispatch to the &self common path (`write_bytes_raw_shared`) unless
        // the write may hit a native16k write-exec page, in which case the
        // &mut self escalation (`write_exec_page_bytes`) is required for the
        // native_write_exec_writable_pages/native_page_protections metadata
        // update. Phase 2's hot path calls `write_bytes_raw_shared` directly
        // through a shared reference, bypassing this dispatcher entirely.
        if self.range_may_execute(address, bytes.len()) {
            self.write_exec_page_bytes(address, bytes)
        } else {
            self.write_bytes_raw_shared(address, bytes)
        }
    }

    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(address, len, no_access);
    }

    fn set_no_write(&mut self, address: u64, len: usize, no_write: bool) {
        self.protections.set_no_write(address, len, no_write);
    }

    fn set_unmapped(&mut self, address: u64, len: usize, unmapped: bool) {
        self.protections.set_unmapped(address, len, unmapped);
    }

    fn set_mapping_protection(
        &mut self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
    ) {
        self.protections
            .set_mapping_protection(address, len, no_access, no_write);
    }

    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        !self.protections.range_write_denied(address, length)
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        if len == 0 {
            return Ok(());
        }
        if !self.region_contains(address, len) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: len,
            });
        }
        let old_exec = self.range_may_execute(address, len);
        let result = if self.uses_linux4k_subpages() {
            self.protect_linux4k_range(address, len, prot)
        } else {
            self.protect_native16k_range_with(address, len, prot, native_host_mprotect)
        };
        result?;
        if old_exec || prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
            self.note_dsr_code_mutation(address, len)?;
        }
        Ok(())
    }

    fn supports_concurrent_exec_protection(&self) -> bool {
        true
    }

    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.protect_range(address, len, 0)?;
        self.set_unmapped(address, len, true);
        // Retire file-identity futex keys on unmapped file aliases: region
        // entries are never pruned, and `shared_futex_location`'s newest-wins
        // lookup would otherwise keep FILE-keying a shared-arena VA that the
        // guest munmapped and later reused for an ANON MAP_SHARED word (served
        // by the boot arena entry, no new region push) — this process would
        // key the word by the dead file while every other process VA-keys the
        // same physical word, silently missing cross-process wakes. A partial
        // munmap also neutralizes the remainder's key: that degrades the
        // still-mapped tail to VA-keying (the pre-file-key behavior), which is
        // strictly safer than mis-keying the reused portion.
        let end = address.saturating_add(len as u64);
        for region in &mut self.regions {
            if region.shared_key_base != 0 && region.start < end && address < region.end {
                region.shared_key_base = 0;
                region.shared_key_offset = 0;
            }
        }
        Ok(())
    }

    fn shared_futex_location(
        &self,
        guest_addr: u64,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        if !guest_addr.is_multiple_of(std::mem::align_of::<u32>() as u64) {
            return None;
        }
        let end = guest_addr.checked_add(std::mem::size_of::<u32>() as u64)?;
        // Newest matching region wins (`.rev()`): file aliases are pushed after
        // the boot-time shared-file arena that covers the same VA range, and
        // the alias carries the file-identity key material.
        let region = self.regions.iter().rev().find(|region| {
            region.shared_futex && guest_addr >= region.start && end <= region.end
        })?;
        let word = self
            .host_address(carrick_guest_mem::GuestVa(guest_addr))
            .ok()?
            .raw();
        // The physical os_sync SHARED wait/wake uses the translated host word,
        // while waiter-count metadata remains guest-keyed. A direct MAP_SHARED
        // file mapping keys that metadata by file identity +
        // file offset (HVF's scheme): the native exec rebuilds the address
        // space, so an exec'd child re-attaches the same file at a different
        // VA and a VA key would miss the parent's registered waiter
        // (ltpcheckpointexec). Anon MAP_SHARED (fork-inherited, same VA in
        // every process) keeps the VA key.
        let waiter_key = if region.shared_key_base == 0 {
            usize::try_from(guest_addr).ok()?
        } else {
            let file_offset = region
                .shared_key_offset
                .saturating_add(guest_addr - region.start);
            crate::trap::shared_futex_waiter_key(region.shared_key_base, file_offset)
        };
        Some(carrick_guest_mem::SharedFutexLocation::Direct {
            word: carrick_guest_mem::HostVa(word),
            waiter_key,
        })
    }

    fn repoint_private(
        &mut self,
        va: u64,
        _overlay_ipa: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), MemoryError> {
        self.remap_private(va, len, content)
    }

    /// Host pointer for a contiguous, host-readable guest range (zero-copy
    /// send source / `writev` source). `None` when the range spans more than
    /// one mapped region, is unmapped, or is host-guarded (PROT_NONE-lifted
    /// -- the checked copy path can temporarily lift a guarded page, a raw
    /// pointer cannot). See `GuestMemory::host_ptr_for_read`.
    fn host_ptr_for_read(&self, address: u64, len: usize) -> Option<*const u8> {
        if len == 0 {
            return None;
        }
        if !self.region_contains(address, len) {
            return None;
        }
        // `native_range_allows` only reflects the host-mprotect-fidelity
        // table (`native_page_protections`), which `munmap()` does NOT reset
        // -- it stays at the last guest-upgraded prot. Software
        // no_access/unmapped state lives in `protections` instead
        // (`unmap_range` sets `unmapped` there without touching
        // `native_page_protections`), so it must be consulted separately or
        // a freed/guarded range can still look host-readable here. Mirrors
        // the HVF reference gate (`self.range_no_access` in
        // `carrick-vmm-hvf/src/trap.rs`).
        if self
            .protections()
            .is_some_and(|p| p.range_no_access(address, len))
        {
            return None;
        }
        if !self.native_range_allows(address, len, false) {
            return None;
        }
        Some(
            self.host_address(carrick_guest_mem::GuestVa(address))
                .ok()?
                .raw() as *const u8,
        )
    }

    /// Delegates to the `&self` shared helper -- see
    /// `host_ptr_for_write_shared`'s doc comment for the full gate list and
    /// why it's sound to expose this through a shared borrow.
    fn host_ptr_for_write(&mut self, address: u64, len: usize) -> Option<*mut u8> {
        self.host_ptr_for_write_shared(address, len)
    }
}

pub(super) fn linux_prot_to_native(prot: u64) -> libc::c_int {
    let mut host_prot = 0;
    if prot & crate::linux_abi::LINUX_PROT_READ != 0 {
        host_prot |= libc::PROT_READ;
    }
    if prot & crate::linux_abi::LINUX_PROT_WRITE != 0 {
        host_prot |= libc::PROT_WRITE;
    }
    if prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
        host_prot |= libc::PROT_EXEC;
    }
    host_prot
}

pub(super) fn native16k_host_prot(prot: u64) -> libc::c_int {
    let mut host_prot = linux_prot_to_native(prot);
    let write_exec = crate::linux_abi::LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC;
    if prot & write_exec == write_exec {
        host_prot &= !libc::PROT_WRITE;
    }
    if prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
        host_prot = (host_prot & !libc::PROT_EXEC) | libc::PROT_READ;
    }
    host_prot
}

/// Applies one host `mprotect` over a contiguous run of host pages. This is
/// the production `set_host_prot` for the injectable protect/prepare/restore
/// loops; tests substitute a recording spy to assert call coalescing.
pub(super) fn native_host_mprotect(
    host_page: carrick_guest_mem::HostVa,
    len: usize,
    host_prot: libc::c_int,
) -> Result<(), MemoryError> {
    let ptr = host_page.raw() as *mut libc::c_void;
    if unsafe { libc::mprotect(ptr, len, host_prot) } != 0 {
        return Err(MemoryError::HostMap(format!(
            "mprotect native Darwin host page 0x{:x}: {}",
            host_page.raw(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[derive(Clone, Copy, Default)]
pub(super) struct NativeExecMapDetailTotal {
    duration_ns: u64,
    bytes: u64,
    operations: u64,
}

pub(super) struct NativeExecMapProfile {
    tid: crate::thread::ThreadId,
    active: Option<(crate::probes::DsrExecMapDetailKind, std::time::Instant, u64)>,
    totals: [NativeExecMapDetailTotal; 5],
}

impl NativeExecMapProfile {
    pub(super) fn new(tid: crate::thread::ThreadId) -> Self {
        Self {
            tid,
            active: None,
            totals: [NativeExecMapDetailTotal::default(); 5],
        }
    }

    pub(super) fn begin(&mut self, kind: crate::probes::DsrExecMapDetailKind, bytes: u64) {
        self.active = Some((kind, std::time::Instant::now(), bytes));
    }

    pub(super) fn end(&mut self, kind: crate::probes::DsrExecMapDetailKind) {
        let Some((active_kind, started, bytes)) = self.active.take() else {
            return;
        };
        if active_kind != kind {
            return;
        }
        let index = kind.raw() as usize - 1;
        let total = &mut self.totals[index];
        total.duration_ns = total
            .duration_ns
            .saturating_add(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        total.bytes = total.bytes.saturating_add(bytes);
        total.operations = total.operations.saturating_add(1);
    }

    pub(super) fn emit(self) {
        for (kind, total) in crate::probes::DsrExecMapDetailKind::ALL
            .into_iter()
            .zip(self.totals)
        {
            crate::probes::dsr_exec_map_detail(
                self.tid.raw(),
                kind,
                total.duration_ns,
                total.bytes,
                total.operations,
            );
        }
    }
}

thread_local! {
    static NATIVE_EXEC_MAP_PROFILE: std::cell::RefCell<Option<NativeExecMapProfile>> =
        const { std::cell::RefCell::new(None) };
}

pub(super) fn native_exec_map_profile_start(dsr_tid: Option<crate::thread::ThreadId>) {
    let profile = if std::env::var_os("CARRICK_DSR_PROFILE").is_some() {
        dsr_tid.map(NativeExecMapProfile::new)
    } else {
        None
    };
    NATIVE_EXEC_MAP_PROFILE.with(|slot| *slot.borrow_mut() = profile);
}

pub(super) fn native_exec_map_profile_finish() {
    NATIVE_EXEC_MAP_PROFILE.with(|slot| {
        if let Some(profile) = slot.borrow_mut().take() {
            profile.emit();
        }
    });
}

pub(super) fn native_exec_map_detail(
    dsr_tid: Option<crate::thread::ThreadId>,
    phase: crate::probes::DsrCacheLifecyclePhase,
    bytes: u64,
) {
    if dsr_tid.is_none() {
        return;
    }
    use crate::probes::{DsrCacheLifecyclePhase as Phase, DsrExecMapDetailKind as Kind};
    let boundary = match phase {
        Phase::ExecMapMmapBegin => Some((Kind::Mmap, true)),
        Phase::ExecMapMmapEnd => Some((Kind::Mmap, false)),
        Phase::ExecMapCopyBegin => Some((Kind::Copy, true)),
        Phase::ExecMapCopyEnd => Some((Kind::Copy, false)),
        Phase::ExecMapIcacheBegin => Some((Kind::Icache, true)),
        Phase::ExecMapIcacheEnd => Some((Kind::Icache, false)),
        Phase::ExecMapProtectBegin => Some((Kind::Protect, true)),
        Phase::ExecMapProtectEnd => Some((Kind::Protect, false)),
        Phase::ExecMapVvarBegin => Some((Kind::Vvar, true)),
        Phase::ExecMapVvarEnd => Some((Kind::Vvar, false)),
        _ => None,
    };
    if let Some((kind, begin)) = boundary {
        NATIVE_EXEC_MAP_PROFILE.with(|slot| {
            if let Some(profile) = slot.borrow_mut().as_mut() {
                if begin {
                    profile.begin(kind, bytes);
                } else {
                    profile.end(kind);
                }
            }
        });
    }
}

pub(super) fn finalize_image_region_mapping(
    region: &MemoryRegion,
    mapped: *mut libc::c_void,
    mapped_length: usize,
    logical_length: u64,
    exec_map_dsr_tid: Option<crate::thread::ThreadId>,
    _prepared: bool,
) -> Result<(), RuntimeError> {
    if region.perms.execute {
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapIcacheBegin,
            logical_length,
        );
        unsafe {
            carrick_native_clear_icache(
                mapped,
                usize::try_from(logical_length).unwrap_or(mapped_length),
            )
        };
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapIcacheEnd,
            0,
        );
    }

    #[cfg(test)]
    if _prepared
        && take_native_prepared_mapping_failpoint(NativePreparedMappingFailpoint::FinalProtection)
    {
        return Err(RuntimeError::Unsupported(
            "prepared-map: injected final protection failure".to_string(),
        ));
    }
    let mut protection = 0;
    if region.perms.read || region.perms.execute {
        protection |= libc::PROT_READ;
    }
    if region.perms.write {
        protection |= libc::PROT_WRITE;
    }
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapProtectBegin,
        logical_length,
    );
    if unsafe { libc::mprotect(mapped, mapped_length, protection) } != 0 {
        return Err(last_io_error(&format!(
            "mprotect native Darwin image region 0x{:x}..0x{:x}",
            region.start, region.end
        )));
    }
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapProtectEnd,
        0,
    );
    Ok(())
}

pub(super) fn map_region(
    region: &MemoryRegion,
    exec_map_dsr_tid: Option<crate::thread::ThreadId>,
    initial_stack_pointer: Option<u64>,
    native_layout: &NativeLayout,
    rollback: &mut NativeMappingRollback,
) -> Result<(), RuntimeError> {
    let length_u64 = region.end.checked_sub(region.start).ok_or_else(|| {
        RuntimeError::Unsupported("native Darwin empty inverted region".to_string())
    })?;
    let length = usize::try_from(length_u64).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin region too large: 0x{:x}..0x{:x}",
            region.start, region.end
        ))
    })?;
    if length == 0 {
        return Ok(());
    }
    let host_start = native_layout
        .address_mode()
        .to_host(carrick_guest_mem::GuestVa(region.start))
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let addr = host_start.raw() as *mut libc::c_void;
    let share = if region.shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
        length_u64,
    );
    let flags = native_layout
        .fixed_mapping_flags(
            host_start,
            length,
            libc::MAP_ANON | libc::MAP_NORESERVE | share,
        )
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let mapped = unsafe {
        libc::mmap(
            addr,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(last_io_error(&format!(
            "mmap native Darwin region 0x{:x}..0x{:x}",
            region.start, region.end
        )));
    }
    if mapped != addr {
        unsafe { libc::munmap(mapped, length) };
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin mmap did not honor MAP_FIXED for 0x{:x}",
            region.start
        )));
    }
    rollback.track_mapping(host_start, length);
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
        0,
    );

    let bytes = region.bytes();
    let copy_window = native_region_copy_window(region, initial_stack_pointer);
    let copy_bytes = &bytes[copy_window.clone()];
    if !copy_bytes.is_empty() {
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapCopyBegin,
            u64::try_from(copy_bytes.len()).unwrap_or(u64::MAX),
        );
        unsafe {
            std::ptr::copy_nonoverlapping(
                copy_bytes.as_ptr(),
                mapped.cast::<u8>().add(copy_window.start),
                copy_bytes.len(),
            );
        }
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapCopyEnd,
            0,
        );
    }
    finalize_image_region_mapping(region, mapped, length, length_u64, exec_map_dsr_tid, false)?;
    Ok(())
}

pub(super) fn map_prepared_region_extent(
    region_index: usize,
    region: &MemoryRegion,
    backing: PreparedImageFileBacking,
    prepared: &ValidatedPreparedImage,
    exec_map_dsr_tid: Option<crate::thread::ThreadId>,
    native_layout: &NativeLayout,
    rollback: &mut NativeMappingRollback,
) -> Result<PreparedRegionMapping, RuntimeError> {
    #[cfg(test)]
    if region_index == 1
        && take_native_prepared_mapping_failpoint(NativePreparedMappingFailpoint::SecondRegionMap)
    {
        return Err(RuntimeError::Unsupported(
            "prepared-map: injected second-region mapping failure".to_string(),
        ));
    }

    let length_u64 = region.end.checked_sub(region.start).ok_or_else(|| {
        RuntimeError::Unsupported("prepared-map: empty or inverted region".to_string())
    })?;
    let expected_extent = align_up_u64(
        length_u64,
        prepared.host_page_size(),
        "prepared artifact region extent",
    )?;
    if backing.artifact_extent.get() != expected_extent {
        return Err(RuntimeError::Unsupported(format!(
            "prepared-map: region {region_index} extent mismatch: artifact=0x{:x}, expected=0x{expected_extent:x}",
            backing.artifact_extent.get()
        )));
    }
    let length = usize::try_from(expected_extent).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "prepared-map: region {region_index} is too large: 0x{expected_extent:x}"
        ))
    })?;
    let artifact_offset = libc::off_t::try_from(backing.artifact_offset.get()).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "prepared-map: region {region_index} artifact offset is not representable: 0x{:x}",
            backing.artifact_offset.get()
        ))
    })?;
    let host_start = native_layout
        .address_mode()
        .to_host(carrick_guest_mem::GuestVa(region.start))
        .map_err(|error| RuntimeError::Unsupported(format!("prepared-map: {error}")))?;
    let address = host_start.raw() as *mut libc::c_void;
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
        length_u64,
    );
    let flags = native_layout
        .fixed_mapping_flags(host_start, length, libc::MAP_PRIVATE)
        .map_err(|error| RuntimeError::Unsupported(format!("prepared-map: {error}")))?;
    let mapped = unsafe {
        libc::mmap(
            address,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            prepared.file_fd(),
            artifact_offset,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(last_io_error(&format!(
            "prepared-map: mmap region {region_index} 0x{:x}..0x{:x}",
            region.start, region.end
        )));
    }
    if mapped != address {
        unsafe { libc::munmap(mapped, length) };
        return Err(RuntimeError::Unsupported(format!(
            "prepared-map: mmap region {region_index} returned {:p}, expected {:p}",
            mapped, address
        )));
    }
    rollback.track_mapping(host_start, length);
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
        0,
    );

    Ok(PreparedRegionMapping {
        mapped,
        mapped_length: length,
        logical_length: length_u64,
    })
}

pub(super) fn map_bytes_region(
    start: u64,
    length_u64: u64,
    bytes: &[u8],
    options: NativeByteRegionOptions,
    native_layout: &NativeLayout,
    rollback: &mut NativeMappingRollback,
) -> Result<(), RuntimeError> {
    let NativeByteRegionOptions {
        final_prot,
        executable,
        exec_map_dsr_tid,
    } = options;
    let length = usize::try_from(length_u64).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin byte region too large: 0x{start:x}+0x{length_u64:x}"
        ))
    })?;
    if length == 0 {
        return Ok(());
    }
    if bytes.len() > length {
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin byte region payload too large: {} > {length}",
            bytes.len()
        )));
    }
    let host_start = native_layout
        .address_mode()
        .to_host(carrick_guest_mem::GuestVa(start))
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let addr = host_start.raw() as *mut libc::c_void;
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
        length_u64,
    );
    let flags = native_layout
        .fixed_mapping_flags(
            host_start,
            length,
            libc::MAP_ANON | libc::MAP_NORESERVE | libc::MAP_PRIVATE,
        )
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let mapped = unsafe {
        libc::mmap(
            addr,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(last_io_error(&format!(
            "mmap native Darwin byte region 0x{start:x}+0x{length_u64:x}"
        )));
    }
    if mapped != addr {
        unsafe { libc::munmap(mapped, length) };
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin mmap did not honor MAP_FIXED for byte region 0x{start:x}"
        )));
    }
    rollback.track_mapping(host_start, length);
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
        0,
    );
    if !bytes.is_empty() {
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapCopyBegin,
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        );
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped.cast::<u8>(), bytes.len());
        }
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapCopyEnd,
            0,
        );
    }
    if executable {
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapIcacheBegin,
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        );
        unsafe { carrick_native_clear_icache(mapped, bytes.len()) };
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapIcacheEnd,
            0,
        );
    }
    let final_prot = if executable {
        (final_prot & !libc::PROT_EXEC) | libc::PROT_READ
    } else {
        final_prot
    };
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapProtectBegin,
        length_u64,
    );
    let protect = unsafe { libc::mprotect(mapped, length, final_prot) };
    if protect != 0 {
        return Err(last_io_error(&format!(
            "mprotect native Darwin byte region 0x{start:x}+0x{length_u64:x}"
        )));
    }
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapProtectEnd,
        0,
    );
    Ok(())
}

pub(super) fn map_anonymous_region(
    start: u64,
    length: u64,
    shared: bool,
    native_layout: &NativeLayout,
    rollback: &mut NativeMappingRollback,
) -> Result<(), RuntimeError> {
    let length = usize::try_from(length).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin anonymous region too large: 0x{start:x}+0x{length:x}"
        ))
    })?;
    if length == 0 {
        return Ok(());
    }
    let host_start = native_layout
        .address_mode()
        .to_host(carrick_guest_mem::GuestVa(start))
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let addr = host_start.raw() as *mut libc::c_void;
    let share = if shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    let flags = native_layout
        .fixed_mapping_flags(
            host_start,
            length,
            libc::MAP_ANON | libc::MAP_NORESERVE | share,
        )
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let mapped = unsafe {
        libc::mmap(
            addr,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(last_io_error(&format!(
            "mmap native Darwin anonymous region 0x{start:x}..0x{:x}",
            start.saturating_add(length as u64)
        )));
    }
    if mapped != addr {
        unsafe { libc::munmap(mapped, length) };
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin mmap did not honor MAP_FIXED for anonymous region 0x{start:x}"
        )));
    }
    rollback.track_mapping(host_start, length);
    Ok(())
}

pub(super) fn set_native_region_fork_inheritance(
    address: *mut libc::c_void,
    len: usize,
    share: bool,
) -> bool {
    unsafe extern "C" {
        fn minherit(
            addr: *mut libc::c_void,
            len: libc::size_t,
            inherit: libc::c_int,
        ) -> libc::c_int;
    }
    let inherit = if share {
        VM_INHERIT_SHARE
    } else {
        VM_INHERIT_COPY
    };
    unsafe { minherit(address, len, inherit) == 0 }
}

/// `movz Xd, #imm16, lsl #32` (sf=1, opc=10, hw=10), any destination register.
pub(super) const fn movz_x_lsl32(imm16: u16) -> u32 {
    0xd2c0_0000 | ((imm16 as u32) << 5)
}

/// Rewrite the injected vDSO code page's hardcoded vvar-base loads from the
/// canonical `LINUX_VVAR_BASE` to `NATIVE_DARWIN_VVAR_BASE`. The vDSO clock
/// functions and the getrandom blob each materialise the vvar VA with a single
/// `movz Xn, #(LINUX_VVAR_BASE >> 32), lsl #32`; both bases are exact 1<<32
/// multiples (const-asserted above), so retargeting is a pure immediate swap.
/// This pass runs ONLY on carrick's own vDSO page — never on guest-owned code,
/// where an immediate rewrite would corrupt legitimate instructions.
pub(super) fn relocate_vdso_vvar_loads(
    region: &MemoryRegion,
    native_layout: &NativeLayout,
) -> Result<(), RuntimeError> {
    let length = usize::try_from(region.len()).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin vDSO region is too large: 0x{:x}",
            region.len()
        ))
    })?;
    let base = native_layout
        .address_mode()
        .to_host(carrick_guest_mem::GuestVa(region.start))
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?
        .raw() as *mut u8;
    let canonical = movz_x_lsl32((carrick_mem::vdso::LINUX_VVAR_BASE >> 32) as u16);
    let relocated = movz_x_lsl32((NATIVE_DARWIN_VVAR_BASE >> 32) as u16);
    const RD_MASK: u32 = 0x1f;
    if unsafe { libc::mprotect(base.cast(), length, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
        return Err(last_io_error("mprotect native Darwin vdso page writable"));
    }
    for index in 0..length / std::mem::size_of::<u32>() {
        let ptr = unsafe { base.add(index * std::mem::size_of::<u32>()).cast::<u32>() };
        let word = unsafe { std::ptr::read_unaligned(ptr) };
        if word & !RD_MASK == canonical {
            unsafe { std::ptr::write_unaligned(ptr, relocated | (word & RD_MASK)) };
        }
    }
    unsafe { carrick_native_clear_icache(base.cast(), length) };
    let final_prot = libc::PROT_READ;
    if unsafe { libc::mprotect(base.cast(), length, final_prot) } != 0 {
        return Err(last_io_error("restore native Darwin vdso page protections"));
    }
    Ok(())
}
