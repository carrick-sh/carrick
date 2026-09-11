//! Guest Memory Read, Write, and Volatile Copy Operations

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
pub(crate) unsafe fn volatile_copy_from_guest(src: *const u8, dst: *mut u8, len: usize) {
    const W: usize = core::mem::size_of::<usize>();
    let mut i = 0usize;
    unsafe {
        // Head: byte-volatile until the guest pointer is word-aligned.
        while i < len && !(src.add(i) as usize).is_multiple_of(W) {
            dst.add(i).write(src.add(i).read_volatile());
            i += 1;
        }
        // Bulk: aligned word-volatile reads from guest, unaligned plain writes
        // to the private host buffer.
        while i + W <= len {
            let word = (src.add(i) as *const usize).read_volatile();
            (dst.add(i) as *mut usize).write_unaligned(word);
            i += W;
        }
        // Tail.
        while i < len {
            dst.add(i).write(src.add(i).read_volatile());
            i += 1;
        }
    }
}

/// Volatile copy INTO guest-shared memory. See [`volatile_copy_from_guest`] for
/// why volatile is required and the word-acceleration rationale. Here the guest
/// (`dst`) side takes aligned word-sized `write_volatile`; the private host
/// `src` uses plain unaligned reads.
///
/// SAFETY: `src` must be valid for reads of `len` bytes and `dst` valid for
/// writes of `len` bytes; the two regions must not overlap.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
pub(crate) unsafe fn volatile_copy_to_guest(src: *const u8, dst: *mut u8, len: usize) {
    const W: usize = core::mem::size_of::<usize>();
    let mut i = 0usize;
    unsafe {
        // Head: byte-volatile until the guest pointer is word-aligned.
        while i < len && !(dst.add(i) as usize).is_multiple_of(W) {
            dst.add(i).write_volatile(src.add(i).read());
            i += 1;
        }
        // Bulk: unaligned plain reads from the private host buffer, aligned
        // word-volatile writes to guest.
        while i + W <= len {
            let word = (src.add(i) as *const usize).read_unaligned();
            (dst.add(i) as *mut usize).write_volatile(word);
            i += W;
        }
        // Tail.
        while i < len {
            dst.add(i).write_volatile(src.add(i).read());
            i += 1;
        }
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod volatile_copy_tests {
    use super::{volatile_copy_from_guest, volatile_copy_to_guest};

    // Exercise every src/dst alignment combo and a spread of lengths (crossing
    // the word boundary and the head/bulk/tail seams), comparing against the
    // obvious byte copy and asserting no overrun past `len`.
    const LENS: &[usize] = &[0, 1, 7, 8, 9, 15, 16, 17, 31, 63, 64, 65, 255, 256];

    #[test]
    fn from_guest_matches_reference() {
        let src: Vec<u8> = (0..512u32)
            .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
            .collect();
        for &len in LENS {
            for s in 0..8usize {
                for d in 0..8usize {
                    if s + len > src.len() {
                        continue;
                    }
                    let mut dst = vec![0xCDu8; d + len + 1];
                    unsafe {
                        volatile_copy_from_guest(src.as_ptr().add(s), dst.as_mut_ptr().add(d), len);
                    }
                    assert_eq!(&dst[d..d + len], &src[s..s + len], "len={len} s={s} d={d}");
                    assert_eq!(dst[d + len], 0xCD, "overrun len={len} d={d}");
                }
            }
        }
    }

    #[test]
    fn to_guest_matches_reference() {
        let src: Vec<u8> = (0..512u32)
            .map(|i| (i.wrapping_mul(17).wrapping_add(3)) as u8)
            .collect();
        for &len in LENS {
            for s in 0..8usize {
                for d in 0..8usize {
                    if s + len > src.len() {
                        continue;
                    }
                    let mut dst = vec![0xABu8; d + len + 1];
                    unsafe {
                        volatile_copy_to_guest(src.as_ptr().add(s), dst.as_mut_ptr().add(d), len);
                    }
                    assert_eq!(&dst[d..d + len], &src[s..s + len], "len={len} s={s} d={d}");
                    assert_eq!(dst[d + len], 0xAB, "overrun len={len} d={d}");
                }
            }
        }
    }
}

/// Strip a 16-bit pointer tag (bits 63:48) from a guest virtual address.
/// Apple Rosetta tags pointers in the top 16 bits (a 48-bit `TaggedPointer`
/// value space, broader than the 8-bit hardware TBI), so syscall-path region
/// lookups must mask the tag to resolve a tagged pointer to its 48-bit backing
/// mapping. Pairs with TCR_EL1.TBI0/TBI1 (hardware ignores the top byte for the
/// guest's own accesses) and the mmap-hint strip in dispatch/mem.rs. A no-op
/// for native (top-byte-zero) guests.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
pub(crate) fn strip_pointer_tag(address: u64) -> u64 {
    address & 0x0000_FFFF_FFFF_FFFF
}

/// Resolve a syscall/core copy through the descriptor key preferred by the
/// translated private-overlay path, then through the Linux semantic VA used by
/// boot mappings whose stage-1 leaf now names a global frame.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn resolve_guest_copy_mapping<T>(
    translated: u64,
    semantic: u64,
    mut resolve: impl FnMut(u64) -> Option<T>,
) -> Option<(u64, T)> {
    resolve(translated)
        .map(|mapping| (translated, mapping))
        .or_else(|| {
            (translated != semantic)
                .then(|| resolve(semantic).map(|mapping| (semantic, mapping)))?
        })
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod guest_copy_mapping_tests {
    use super::resolve_guest_copy_mapping;

    #[test]
    fn translated_descriptor_wins_and_semantic_va_is_the_exact_fallback() {
        let mut translated_calls = Vec::new();
        let translated = resolve_guest_copy_mapping(0x9000, 0x4000, |key| {
            translated_calls.push(key);
            (key == 0x9000).then_some("overlay")
        });
        assert_eq!(translated, Some((0x9000, "overlay")));
        assert_eq!(translated_calls, vec![0x9000]);

        let mut semantic_calls = Vec::new();
        let semantic = resolve_guest_copy_mapping(0x9000, 0x4000, |key| {
            semantic_calls.push(key);
            (key == 0x4000).then_some("boot-heap")
        });
        assert_eq!(semantic, Some((0x4000, "boot-heap")));
        assert_eq!(semantic_calls, vec![0x9000, 0x4000]);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfVmState {
    pub(crate) fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        if let Some(mapping) = Self::mapping_for_ipa_range(&self.mappings, gpa, len.max(1)) {
            let offset = (gpa.wrapping_sub(mapping.ipa)) as usize;
            return Some(unsafe { mapping.host_addr.add(offset) });
        }
        self.carrier_mappings
            .as_ref()?
            .host_pointer_for_ipa(gpa, len)
    }

    /// Copy `bytes` into guest physical memory at `gpa` (raw GPA, no PROT_NONE
    /// gate, no permission check — the engine's run-elf / page-table seed path).
    pub(crate) fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let Some(host) = self.host_ptr(gpa, bytes.len()) else {
            return Err(MemoryError::OutOfBounds {
                address: gpa,
                length: bytes.len(),
            });
        };
        unsafe {
            volatile_copy_to_guest(bytes.as_ptr(), host, bytes.len());
        }
        Ok(())
    }

    /// Read `len` bytes of live guest memory at guest-physical `gpa` (no VA
    /// translation, no PROT_NONE gate).
    pub(crate) fn read_gpa(&self, gpa: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        let Some(host) = self.host_ptr(gpa, len) else {
            return Err(MemoryError::OutOfBounds {
                address: gpa,
                length: len,
            });
        };
        let mut out = vec![0u8; len];
        unsafe {
            volatile_copy_from_guest(host, out.as_mut_ptr(), len);
        }
        Ok(out)
    }

    pub(crate) fn read_guest_bytes(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, MemoryError> {
        let mut bytes = vec![0u8; length];
        self.read_guest_bytes_into(address, &mut bytes)?;
        Ok(bytes)
    }

    /// No-alloc core of [`Self::read_guest_bytes`]: `volatile`-copy `dst.len()` bytes
    /// of guest memory at `address` straight into `dst`. Same checks, chunked
    /// mapping walk, and trace probes as the allocating form.
    pub(crate) fn read_guest_bytes_into(
        &self,
        address: u64,
        dst: &mut [u8],
    ) -> Result<(), MemoryError> {
        let length = dst.len();
        // PROT_NONE gated once in the default `GuestMemory::read_bytes`/`read_into`.
        let mut copied = 0usize;
        while copied < length {
            let (chunk_address, chunk_len) = Self::guest_copy_chunk(address, copied, length)?;
            // For a `repoint_private` overlay VA the region+offset are keyed on the
            // translated overlay IPA, not the VA (see `syscall_buffer_lookup_addr`).
            // Identity otherwise — no walk. PROT_NONE was already gated on the VA.
            let translated_lookup = self.syscall_buffer_lookup_addr(chunk_address, chunk_len);
            let (_lookup_address, mapping_start, mapping_end, mapping_ipa, host_addr) = {
                // Private-overlay descriptors are keyed by their translated
                // IPA, while a boot brk descriptor remains keyed by Linux VA
                // even after HVPatch repoints its stage-1 leaf to a reusable
                // global frame. Keep translated-first ordering for the former,
                // but join the latter through mapping_for_range's authoritative
                // VA -> stage-1 IPA -> live global-owner path when the direct
                // IPA lookup has no descriptor.
                let resolved =
                    resolve_guest_copy_mapping(translated_lookup, chunk_address, |lookup| {
                        self.mapping_for_range(lookup, chunk_len)
                    });
                let Some((lookup_address, mapping)) = resolved else {
                    if let Some(state) = self.deferred_anonymous_state() {
                        let chunk = &mut dst[copied..copied + chunk_len];
                        if state
                            .copy_pristine_zero(carrick_guest_mem::GuestVa(chunk_address), chunk)
                            .map_err(|error| {
                                MemoryError::HostMap(format!("anonymous zero read: {error}"))
                            })?
                            || state
                                .copy_pristine_file(
                                    carrick_guest_mem::GuestVa(chunk_address),
                                    chunk,
                                )
                                .map_err(|error| {
                                    MemoryError::HostMap(format!(
                                        "deferred private file read: {error}"
                                    ))
                                })?
                        {
                            copied += chunk_len;
                            continue;
                        }
                    }
                    // `syscall_buffer_lookup_addr` deliberately stays identity
                    // for the common heap/stack hot path. Core capture has
                    // loaded the live software observer, so use its exact leaf
                    // output—not that shortcut—to join a descriptorless exec
                    // heap to the current global-frame owner.
                    let stage1_lookup = self
                        .translate_va(chunk_address)
                        .unwrap_or(translated_lookup);
                    let Some((mapping_start, mapping_end)) = copy_from_global_frame_owner_in(
                        self.custody(),
                        stage1_lookup,
                        &mut dst[copied..copied + chunk_len],
                    ) else {
                        let stage1 = self.translate_va(chunk_address);
                        let semantic_mapping = self
                            .mappings
                            .iter()
                            .any(|mapping| mapping.contains_range(chunk_address, chunk_len));
                        let stage1_mapping = stage1.is_some_and(|ipa| {
                            self.mappings
                                .iter()
                                .any(|mapping| Self::region_owns_ipa(mapping, ipa))
                        });
                        let owner_count = self.custody().global_frame_host_owners.lock().len();
                        return Err(MemoryError::HostMap(format!(
                            "live core read has no current backing: va=0x{chunk_address:x} len={chunk_len} hot_lookup=0x{translated_lookup:x} stage1={stage1:x?} mappings={} semantic_mapping={semantic_mapping} stage1_mapping={stage1_mapping} global_owners={owner_count} persistent={}",
                            self.mappings.len(),
                            self.persistent_vm_lifecycle
                        )));
                    };
                    self.emit_guest_mem_copy_decision(
                        crate::probes::guest_mem_dir::READ_GUEST,
                        chunk_address,
                        chunk_len,
                        mapping_start,
                        mapping_end,
                        stage1_lookup,
                    );
                    copied += chunk_len;
                    continue;
                };
                (
                    lookup_address,
                    mapping.start,
                    mapping.end,
                    mapping.ipa,
                    mapping.host_addr,
                )
            };
            self.emit_guest_mem_copy_decision(
                crate::probes::guest_mem_dir::READ_GUEST,
                chunk_address,
                chunk_len,
                mapping_start,
                mapping_end,
                mapping_ipa,
            );
            // Read directly out of the host buffer. Works for both
            // applevisor-owned mappings (the parent case) and raw mappings
            // we re-created in a forked child via hv_vm_map.
            let chunk_offset = (chunk_address - mapping_start) as usize;
            unsafe {
                volatile_copy_from_guest(
                    host_addr.add(chunk_offset),
                    dst.as_mut_ptr().add(copied),
                    chunk_len,
                );
            }
            copied += chunk_len;
        }
        crate::probes::guest_mem_bytes(
            crate::probes::guest_mem_dir::READ_GUEST,
            strip_pointer_tag(address),
            dst,
        );
        Ok(())
    }

    /// Host VA of `backing_gpa` iff it lives in a host-`MAP_SHARED` guest region
    /// (the boot-mapped shared aperture; shared across carrick processes via
    /// the inherited MAP_SHARED backing). Used to back a cross-process futex
    /// with the public `os_sync_wait_on_address` API (see `crate::ulock`).
    pub(crate) fn shared_futex_location(
        &self,
        backing_gpa: u64,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        // The neutral AArch64 engine has already translated the semantic guest
        // VA through stage-1 and passes the exact backing GPA here. HVPatch
        // global frames deliberately have VA != IPA, so this lookup MUST stay
        // in the raw IPA domain; treating the GPA as a second VA made every
        // fork-shared futex fall through to the process-private table.
        if let Some(location) = Self::shared_futex_mapping_for_ipa_in(
            self.custody(),
            &self.mappings,
            backing_gpa,
            self.persistent_vm_lifecycle,
        ) {
            return Some(location);
        }

        // A shared-file alias installed by another sibling may be absent from
        // this thread's mapping Vec. Its global IPA is nevertheless unique and
        // the live alias registry owns the same translated backing identity.
        if let Some(alias) = alias_registry()
            .lock()
            .newest_containing_ipa(backing_gpa, |alias| {
                alias.sharing.has_shared_futex_identity()
                    && backing_gpa >= alias.ipa
                    && backing_gpa.saturating_add(4) <= alias.ipa.saturating_add(alias.size as u64)
                    && alias_backing_is_live(alias.host_addr)
            })
        {
            return MappingView::from_alias(&alias).shared_futex_location_for_ipa(backing_gpa);
        }
        None
    }

    fn shared_futex_mapping_for_ipa_in(
        custody: &CarrierVmCustody,
        mappings: &TaskMappingIndex,
        backing_gpa: u64,
        persistent_vm_lifecycle: bool,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        backing_gpa.checked_add(4)?;
        mappings
            .candidates_for_ipa_range(backing_gpa, 4)
            .find_map(|mapping| {
                (mapping.sharing.has_shared_futex_identity()
                    && (!persistent_vm_lifecycle
                        || !is_reusable_global_frame_extent(
                            mapping.physical_ipa,
                            mapping.physical_size as u64,
                        )
                        || global_frame_region_owner_matches_in(custody, mapping)))
                .then(|| mapping.view().shared_futex_location_for_ipa(backing_gpa))
                .flatten()
            })
    }

    #[cfg(test)]
    pub(crate) fn shared_futex_mapping_for_ipa(
        mappings: &TaskMappingIndex,
        backing_gpa: u64,
        persistent_vm_lifecycle: bool,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        Self::shared_futex_mapping_for_ipa_in(
            legacy_test_carrier_vm_custody(),
            mappings,
            backing_gpa,
            persistent_vm_lifecycle,
        )
    }

    pub(crate) fn write_guest_bytes(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryError> {
        let length = bytes.len();
        // PROT_NONE gated once in the default `GuestMemory::write_bytes`.
        self.validate_guest_write_range(address, length, false)?;
        let mut copied = 0usize;
        while copied < length {
            let (chunk_address, chunk_len) = Self::guest_copy_chunk(address, copied, length)?;
            // See `read_guest_bytes_into`: a `repoint_private` overlay VA resolves
            // its region+offset via the translated overlay IPA, so a syscall write
            // lands in the PRIVATE overlay backing the guest reads, not the shared
            // aperture. Identity otherwise; PROT_NONE already gated on the VA.
            let lookup_address = self.syscall_buffer_lookup_addr(chunk_address, chunk_len);
            let (mapping_start, mapping_end, mapping_ipa, host_addr) = {
                let Some(mapping) = self.mapping_for_range_mut(lookup_address, chunk_len) else {
                    return Err(MemoryError::OutOfBounds { address, length });
                };
                (mapping.start, mapping.end, mapping.ipa, mapping.host_addr)
            };
            self.emit_guest_mem_copy_decision(
                crate::probes::guest_mem_dir::WRITE_GUEST,
                chunk_address,
                chunk_len,
                mapping_start,
                mapping_end,
                mapping_ipa,
            );
            let chunk_offset = (chunk_address - mapping_start) as usize;
            unsafe {
                volatile_copy_to_guest(
                    bytes.as_ptr().add(copied),
                    host_addr.add(chunk_offset),
                    chunk_len,
                );
            }
            copied += chunk_len;
        }
        crate::probes::guest_mem_bytes(
            crate::probes::guest_mem_dir::WRITE_GUEST,
            strip_pointer_tag(address),
            bytes,
        );
        Ok(())
    }

    /// Resolve a zero-copy pointer only when every page-bounded fragment belongs
    /// to the same backing region and both its GPA and host pointer advance
    /// linearly. Otherwise the caller must use the already-segmented copy path.
    fn contiguous_guest_host_ptr(&self, address: u64, length: usize) -> Option<*mut u8> {
        let stripped = strip_pointer_tag(address);
        let mut checked = 0usize;
        let mut first: Option<(u64, u64, u64, usize, u64, *mut u8)> = None;
        while checked < length {
            let (chunk_va, chunk_len) = Self::guest_copy_chunk(stripped, checked, length).ok()?;
            let lookup = self.syscall_buffer_lookup_addr(chunk_va, chunk_len);
            let mapping = self.mapping_for_range(lookup, chunk_len)?;
            let mapping_offset = lookup.checked_sub(mapping.start)?;
            let physical = mapping.ipa.checked_add(mapping_offset)?;
            let host = unsafe { mapping.host_addr.add(mapping_offset as usize) };
            match first {
                None => {
                    first = Some((
                        mapping.start,
                        mapping.end,
                        mapping.ipa,
                        mapping.host_addr as usize,
                        physical,
                        host,
                    ));
                }
                Some((start, end, ipa, host_base, first_physical, first_host)) => {
                    if mapping.start != start
                        || mapping.end != end
                        || mapping.ipa != ipa
                        || mapping.host_addr as usize != host_base
                        || physical != first_physical.checked_add(checked as u64)?
                        || host as usize != (first_host as usize).checked_add(checked)?
                    {
                        return None;
                    }
                }
            }
            checked += chunk_len;
        }
        first.map(|(_, _, _, _, _, host)| host)
    }

    /// Host pointer for a contiguous guest range (zero-copy send source), or
    /// `None` if any page resolves to another physical fragment. See
    /// `GuestMemory::host_ptr_for_read`.
    pub(crate) fn host_ptr_for_read(&self, address: u64, length: usize) -> Option<*const u8> {
        if length == 0 || self.range_no_access(address, length) {
            return None;
        }
        self.contiguous_guest_host_ptr(address, length)
            .map(|ptr| ptr as *const u8)
    }

    /// Host pointer for a contiguous guest range as a zero-copy recv DESTINATION,
    /// or `None` if the range isn't one mapped region OR isn't guest-writable.
    /// The guest-writable requirement mirrors `write_guest_bytes_checked`: a
    /// guest read-only mapping must EFAULT via the checked copy path, not be
    /// written by the kernel through a raw host pointer. See
    /// `GuestMemory::host_ptr_for_write`.
    pub(crate) fn host_ptr_for_write(&mut self, address: u64, length: usize) -> Option<*mut u8> {
        if length == 0 || self.range_no_access(address, length) {
            return None;
        }
        let stripped = strip_pointer_tag(address);
        if self
            .validate_guest_write_range(stripped, length, true)
            .is_err()
        {
            return None;
        }
        self.contiguous_guest_host_ptr(stripped, length)
    }

    /// Zero the PHYSICAL backing of `[address, address+length)`, bypassing BOTH
    /// the `range_no_access` and the writability checks (see
    /// `GuestMemory::zero_backing`). Used to scrub a reused anon region whose
    /// stale content must never reach the guest: a region just reclaimed from
    /// `munmap` (stage-1-invalidated → `range_no_access`) or mapped `PROT_NONE`
    /// has no write permission, so `write_guest_bytes`/`_checked` deliberately
    /// fault and cannot scrub it. The arena backing is always mapped (munmap only
    /// stage-1-invalidates; arm64 HVF has no stage-2 flush), so the lookup
    /// succeeds for the reclaimed region.
    pub(crate) fn zero_guest_backing(
        &mut self,
        address: u64,
        length: usize,
    ) -> Result<(), MemoryError> {
        let address = strip_pointer_tag(address);
        // Scrub debug: CARRICK_FORK_DEBUG_VA=<hex> logs any zeroing whose range
        // covers that VA, with the caller — the instrument that named the agent
        // zeroing a live dict granule during the forkserver corruption hunt.
        if let Some(debug_va) = fork_debug_va()
            && address <= debug_va
            && debug_va < address.saturating_add(length as u64)
        {
            eprintln!(
                "[FORKDBG pid={:?}] zero_guest_backing va={address:#x} len={length:#x}\n{}",
                self.cow_identity.map(|identity| identity.linux_pid),
                std::backtrace::Backtrace::force_capture(),
            );
        }
        let mut cleared = 0usize;
        let mut active_run: Option<ScrubRun> = None;
        while cleared < length {
            let (chunk_va, chunk_len) = Self::guest_copy_chunk(address, cleared, length)?;
            // munmap invalidates the leaf but intentionally preserves its PA.
            // Backing maintenance runs before the replacement VMA is made
            // guest-visible, so an ordinary hardware-valid translation cannot
            // identify a retained private-COW fragment here. Resolve that PA
            // through the typed invalid-leaf seam and scrub each page-bounded
            // physical fragment independently.
            let retained_ipa = self
                .page_tables_authority()
                .with_manager(|manager| manager.translate_retained_output(chunk_va))
                .flatten();
            // A partial munmap can carve this 4 KiB Linux page out of a live
            // 16 KiB private frame while preserving the invalid leaf's output
            // IPA. Reusing that page does not pass through `add_alias`, so
            // republish its semantic lifetime edge before a later sibling
            // munmap is allowed to retire the containing stage-2 lease.
            let retained_fragment = retained_ipa.and_then(|ipa| {
                retained_private_reuse_alias_fragment_in(
                    &self.carrier_foreign_mm_transport.custody,
                    &alias_registry().lock(),
                    chunk_va,
                    ipa,
                    chunk_len,
                    self.mm_root_slot,
                    self.container_root,
                )
            });
            // WRITE TARGETS ARE STAGE-1-AUTHENTICATED, PERIOD. This used to
            // fall back to `mapping_for_range_mut` — a VA-keyed search over
            // carrier-inherited rows with no scope filter — when the caller's
            // own translation had nothing. A fork child's engine inherits
            // Borrowed rows pointing at the ANCESTOR's host memory for
            // numerically identical VAs, and a reused range is scrubbed
            // exactly while its stage-1 is invalid, so that fallback resolved
            // another process's frame and zeroed it: one 16 KiB granule of the
            // forkserver server's live interned-strings dict, read back as
            // NULL me_keys by every worker (the CPython multiprocessing
            // SIGSEGV cluster).
            //
            // The scrub's purpose is to keep STALE BYTES from being observed
            // through THIS VA. If neither the live walk nor the retained
            // invalid-leaf output names an IPA, the guest has no translation
            // here and cannot observe anything — there is nothing to scrub,
            // and skipping is the correct amount of writing. With an IPA in
            // hand, `mapping_for_live_ipa_range` demands VA/IPA consistency
            // plus a live authenticated owner, so the write can only land in
            // this mm's own backing.
            let live_ipa = self.translate_va(chunk_va);
            let ipa = live_ipa.or(retained_ipa);
            let chunk_resolved = ipa
                .and_then(|ipa| {
                    self.mapping_for_live_ipa_range(chunk_va, ipa, chunk_len)
                        .and_then(|mapping| {
                            let offset = usize::try_from(ipa.checked_sub(mapping.ipa)?).ok()?;
                            let target = unsafe { mapping.host_addr.add(offset) };
                            let cow_source = self.physical_cow_source(chunk_va, ipa).is_some();
                            let is_alias = is_reusable_global_frame_extent(mapping.ipa, 1);
                            let eligible = mapping.sharing == GuestMappingSharing::Private
                                && mapping.shared_key_base == 0
                                && !cow_source
                                && !is_alias
                                && retained_fragment.is_none()
                                && zero_anonymous_remap_enabled();
                            Some((target, eligible))
                        })
                })
                .or_else(|| {
                    // VA fallback, restricted to NON-reusable backing. Boot and
                    // identity regions (the brk heap above all) are per-mm by
                    // construction and sometimes reachable only by VA here;
                    // skipping them left stale bytes where `ltp-brk02` demands
                    // zeros. Reusable global-frame results stay excluded — a
                    // VA-only join over carrier-inherited rows is exactly the
                    // cross-process write this function must never make.
                    self.mapping_for_range_mut(chunk_va, chunk_len)
                        .and_then(|mapping| {
                            // The view carries only the semantic IPA; that is
                            // sufficient here — reusable-frame mappings' semantic
                            // IPAs live inside the global-frame arena, identity
                            // and boot mappings' do not.
                            if is_reusable_global_frame_extent(mapping.ipa, 1) {
                                return None;
                            }
                            let offset =
                                usize::try_from(chunk_va.checked_sub(mapping.start)?).ok()?;
                            let target = unsafe { mapping.host_addr.add(offset) };
                            let cow_source =
                                self.physical_cow_source(chunk_va, mapping.ipa).is_some();
                            let eligible = mapping.sharing == GuestMappingSharing::Private
                                && mapping.shared_key_base == 0
                                && !cow_source
                                && retained_fragment.is_none()
                                && zero_anonymous_remap_enabled();
                            Some((target, eligible))
                        })
                });
            if let Some(debug_va) = fork_debug_va()
                && chunk_va <= debug_va
                && debug_va < chunk_va.saturating_add(chunk_len as u64)
            {
                eprintln!(
                    "[SCRUBDBG pid={:?}] chunk va={chunk_va:#x}+{chunk_len:#x} live_ipa={live_ipa:x?} \
                     retained_ipa={retained_ipa:x?} target={:?}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                    chunk_resolved.map(|(target, _)| target),
                );
            }
            if let Some(fragment) = retained_fragment {
                register_shared_alias(fragment);
            }
            match (active_run.as_mut(), chunk_resolved) {
                (Some(run), Some((target, eligible)))
                    if run.eligible == eligible
                        && unsafe { run.host_start.add(run.len) } == target =>
                {
                    run.len += chunk_len;
                }
                (Some(_), Some((target, eligible))) => {
                    if let Some(prev) = active_run.take() {
                        prev.flush();
                    }
                    active_run = Some(ScrubRun {
                        host_start: target,
                        len: chunk_len,
                        eligible,
                    });
                }
                (Some(_), None) => {
                    if let Some(prev) = active_run.take() {
                        prev.flush();
                    }
                }
                (None, Some((target, eligible))) => {
                    active_run = Some(ScrubRun {
                        host_start: target,
                        len: chunk_len,
                        eligible,
                    });
                }
                (None, None) => {}
            }
            cleared += chunk_len;
        }
        if let Some(run) = active_run {
            run.flush();
        }
        Ok(())
    }

    /// Permission-respecting write used by the SYSCALL path
    /// (`GuestMemory::write_bytes`): a write into a non-writable mapping returns
    /// EFAULT (`MemoryError::OutOfBounds`) instead of either faulting the host
    /// (SIGBUS on a genuinely read-only `MAP_SHARED` file alias) or silently
    /// corrupting a carrick-owned region (the EL1 page tables / vector table are
    /// registered `write:false`). Carrick-internal writes (vdso vvar, sigframe,
    /// bootstrap) deliberately use the unchecked `write_guest_bytes`.
    /// (audit M1; probe `rosharedbus`)
    pub(crate) fn write_guest_bytes_checked(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryError> {
        let length = bytes.len();
        // PROT_NONE gated once in the default `GuestMemory::write_bytes`.
        self.validate_guest_write_range(address, length, true)?;
        let mut copied = 0usize;
        while copied < length {
            let (chunk_address, chunk_len) = Self::guest_copy_chunk(address, copied, length)?;
            // `repoint_private` overlay VAs resolve region+offset via the translated
            // overlay IPA (see `syscall_buffer_lookup_addr`); identity otherwise.
            let lookup_address = self.syscall_buffer_lookup_addr(chunk_address, chunk_len);
            let (mapping_start, mapping_end, mapping_ipa, host_addr) = {
                let Some(mapping) = self.mapping_for_range_mut(lookup_address, chunk_len) else {
                    return Err(MemoryError::OutOfBounds { address, length });
                };
                (mapping.start, mapping.end, mapping.ipa, mapping.host_addr)
            };
            self.emit_guest_mem_copy_decision(
                crate::probes::guest_mem_dir::WRITE_GUEST_CHECKED,
                chunk_address,
                chunk_len,
                mapping_start,
                mapping_end,
                mapping_ipa,
            );
            let chunk_offset = (lookup_address - mapping_start) as usize;
            unsafe {
                volatile_copy_to_guest(
                    bytes.as_ptr().add(copied),
                    host_addr.add(chunk_offset),
                    chunk_len,
                );
            }
            copied += chunk_len;
        }
        crate::probes::guest_mem_bytes(
            crate::probes::guest_mem_dir::WRITE_GUEST_CHECKED,
            strip_pointer_tag(address),
            bytes,
        );
        Ok(())
    }

    fn validate_guest_write_range(
        &self,
        address: u64,
        length: usize,
        require_guest_writable: bool,
    ) -> Result<(), MemoryError> {
        self.validate_guest_write_range_with_pristine(
            address,
            length,
            require_guest_writable,
            false,
        )
    }

    pub(crate) fn validate_guest_write_range_with_pristine(
        &self,
        address: u64,
        length: usize,
        require_guest_writable: bool,
        allow_pristine: bool,
    ) -> Result<(), MemoryError> {
        let mut checked = 0usize;
        while checked < length {
            let (chunk_address, chunk_len) = Self::guest_copy_chunk(address, checked, length)?;
            // The writability check follows the same region a `repoint_private`
            // overlay VA's copy will hit (the translated overlay IPA), so the
            // overlay's guest_writable flag — not the stale shared region's — gates.
            let lookup_address = self.syscall_buffer_lookup_addr(chunk_address, chunk_len);
            let Some(mapping) = self.mapping_for_range(lookup_address, chunk_len) else {
                // Prevalidation may accept explicit pristine provenance. Actual
                // writes still materialize and authenticate their physical owner.
                if allow_pristine
                    && !self
                        .protections
                        .range_write_denied(chunk_address, chunk_len)
                    && self.deferred_anonymous_state().is_some_and(|state| {
                        state.covers_pristine(carrick_guest_mem::GuestVa(chunk_address), chunk_len)
                    })
                {
                    checked += chunk_len;
                    continue;
                }
                // `MemoryError::OutOfBounds` renders as "guest memory read is out
                // of bounds", which is wrong three times over on this path: it is
                // a WRITE, the address is usually mapped, and the real reason is
                // that `mapping_for_range` REJECTED a covering region as not
                // live. Say so — this exact silence cost a full investigation to
                // get behind.
                if let Some(region) = self
                    .mappings
                    .iter()
                    .find(|m| m.start <= lookup_address && lookup_address < m.end)
                {
                    tracing::error!(
                        va = format!("0x{lookup_address:x}"),
                        len = chunk_len,
                        region = format!("[0x{:x}..0x{:x})", region.start, region.end),
                        physical_ipa = format!("0x{:x}", region.physical_ipa),
                        reusable_global_frame = is_reusable_global_frame_extent(
                            region.physical_ipa,
                            region.physical_size as u64
                        ),
                        owns_host_mapping = region.host_mapping.is_some(),
                        owns_stage2_lease = region.stage2_lease.is_some(),
                        owner_generation = region.owner_generation,
                        "guest write rejected: a region covers this VA but failed \
                         the global-frame owner-liveness check"
                    );
                }
                return Err(MemoryError::OutOfBounds { address, length });
            };
            if require_guest_writable
                && (!mapping.guest_writable
                    || self
                        .protections
                        .range_write_denied(chunk_address, chunk_len))
            {
                return Err(MemoryError::OutOfBounds { address, length });
            }
            checked += chunk_len;
        }
        Ok(())
    }

    pub(crate) fn guest_copy_chunk(
        address: u64,
        offset: usize,
        total_length: usize,
    ) -> Result<(u64, usize), MemoryError> {
        let offset_u64 = u64::try_from(offset).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: total_length,
        })?;
        let raw_chunk_address =
            address
                .checked_add(offset_u64)
                .ok_or(MemoryError::OutOfBounds {
                    address,
                    length: total_length,
                })?;
        let chunk_address = strip_pointer_tag(raw_chunk_address);
        let remaining = total_length - offset;
        let page_remaining =
            (GUEST_STAGE1_PAGE_SIZE - (chunk_address & (GUEST_STAGE1_PAGE_SIZE - 1))) as usize;
        Ok((chunk_address, remaining.min(page_remaining)))
    }

    fn emit_guest_mem_copy_decision(
        &self,
        direction: u32,
        address: u64,
        length: usize,
        mapping_start: u64,
        mapping_end: u64,
        mapping_ipa: u64,
    ) {
        let stage1_ipa = crate::memory::is_high_va(address)
            .then(|| self.translate_va(address))
            .flatten();
        crate::probes::guest_mem_copy(
            direction,
            address,
            length,
            stage1_ipa,
            mapping_start,
            mapping_end,
            mapping_ipa,
        );
        self.emit_guest_mem_points(direction, address, length, mapping_start, mapping_ipa);
    }

    fn emit_guest_mem_points(
        &self,
        direction: u32,
        address: u64,
        length: usize,
        mapping_start: u64,
        mapping_ipa: u64,
    ) {
        for point in crate::probes::guest_mem_probe_points(address, length)
            .into_iter()
            .flatten()
        {
            let stage1_ipa = crate::memory::is_high_va(point)
                .then(|| self.translate_va(point))
                .flatten();
            crate::probes::guest_mem_point(
                direction,
                point,
                stage1_ipa,
                mapping_start,
                mapping_ipa,
            );
        }
    }
}
