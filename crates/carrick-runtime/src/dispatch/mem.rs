//! mem syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

/// Owned memory-subsystem state. Split out of `SyscallDispatcher`.
#[derive(Clone)]
pub(super) struct MemState {
    /// Current program break (`brk`/`sbrk`).
    pub brk_current: u64,
    /// Bump cursor for the anonymous mmap arena.
    pub mmap_next: u64,
    /// MONOTONIC high-water of the arena: the highest address ever handed out by
    /// the bump allocator, which `munmap` NEVER lowers (unlike `mmap_next`).
    ///
    /// The bump path assumes `[mmap_next, ...)` is pristine (lazily zero-filled
    /// guest RAM), so it skips the zero-fill that reused `free_regions` get. That
    /// invariant breaks when `munmap` frees the TOP region and LOWERS `mmap_next`
    /// back over pages the guest already dirtied: a later bump allocation at the
    /// lowered cursor would return that STALE data instead of the zeroed anon
    /// memory Linux guarantees. Tracking the true dirty high-water lets the mmap
    /// handler zero exactly the re-handed-out (below-high-water) ranges and keep
    /// the genuinely-fresh tail lazily zero. (CPython test_subprocess SEGV:
    /// pymalloc got 'x'-filled stderr-buffer pages back from a post-munmap mmap.)
    pub mmap_dirty_high: u64,
    /// Sub-allocator for the boot-mapped shared aperture. Guest `MAP_SHARED`
    /// mmaps carve sub-ranges here; the aperture itself is `hv_vm_map`'d once
    /// at boot, so no stage-2 mutation happens at mmap time.
    pub shared: crate::shared_aperture::SharedAperture,
    /// Sub-allocator for the boot-mapped PRIVATE overlay aperture. A guest
    /// `MAP_FIXED|MAP_PRIVATE` that lands on a shared-aperture VA carves a slot
    /// here and repoints the VA's stage-1 leaf to it (so stores stay private),
    /// without any post-vCPU `hv_vm_map`. Per-process (fork snapshots it).
    pub overlay: crate::shared_aperture::SharedAperture,
    /// Freed in-arena anonymous/private ranges available for reuse, kept sorted
    /// by start and coalesced. Reclaiming `munmap`'d space so a churning guest
    /// doesn't exhaust the bump arena. NOT used for MAP_FIXED or shared-file
    /// maps (those have their own lifecycles).
    pub free_regions: Vec<(u64, u64)>,
    /// Snapshot of the guest's `AddressSpace` regions, captured at boot
    /// via [`SyscallDispatcher::set_address_space_regions`]. When present,
    /// `/proc/self/maps` is rendered from this list (with the heap end
    /// tracking `brk_current` and the mmap arena end tracking `mmap_next`)
    /// instead of the hard-coded four-line summary.
    pub address_space_regions: Option<Vec<ProcMapsEntry>>,
    /// Bump cursor for the low-IPA arena backing dynamic high-VA aliases
    /// (`crate::memory::LINUX_ALIAS_IPA_BASE`). See `is_high_va`.
    pub alias_ipa_next: u64,
}

impl MemState {
    pub(super) fn new() -> Self {
        Self {
            brk_current: LINUX_HEAP_BASE,
            mmap_next: LINUX_MMAP_BASE,
            mmap_dirty_high: LINUX_MMAP_BASE,
            shared: crate::shared_aperture::SharedAperture::new(),
            overlay: crate::shared_aperture::SharedAperture::with_window(
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
            ),
            free_regions: Vec::new(),
            address_space_regions: None,
            alias_ipa_next: crate::memory::LINUX_ALIAS_IPA_BASE,
        }
    }
}

/// Insert `[addr, addr+len)` into `regions` (sorted by start), coalescing any
/// adjacent or overlapping ranges. `len` must be > 0.
fn free_regions_insert(regions: &mut Vec<(u64, u64)>, addr: u64, len: u64) {
    let mut new_start = addr;
    let mut new_end = addr.saturating_add(len);
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(regions.len() + 1);
    let mut inserted = false;
    for &(s, l) in regions.iter() {
        let e = s.saturating_add(l);
        if e < new_start || s > new_end {
            // Disjoint from the (growing) merged range. Emit in sorted order.
            if !inserted && s > new_end {
                out.push((new_start, new_end - new_start));
                inserted = true;
            }
            out.push((s, l));
        } else {
            // Overlapping or adjacent — absorb into the merged range.
            new_start = new_start.min(s);
            new_end = new_end.max(e);
        }
    }
    if !inserted {
        out.push((new_start, new_end - new_start));
    }
    out.sort_by_key(|&(s, _)| s);
    *regions = out;
}
impl SyscallDispatcher {
    pub(in crate::dispatch) fn next_mmap_address(
        &self,
        requested: u64,
        length: u64,
        _prot: u64,
        flags: u64,
    ) -> Option<(u64, bool)> {
        if flags & LINUX_MAP_FIXED != 0 {
            if requested == 0 || !requested.is_multiple_of(LINUX_PAGE_SIZE) {
                return None;
            }
            return Some((requested, false));
        }

        if requested != 0 {
            let valid_hint = requested.is_multiple_of(LINUX_PAGE_SIZE)
                && range_within(
                    requested,
                    length,
                    LINUX_MMAP_BASE,
                    crate::memory::mmap_arena_size(),
                );
            if valid_hint {
                let mut mem = self.mem.lock();
                let end = requested.checked_add(length)?;
                if requested >= mem.mmap_next {
                    mem.mmap_next = end;
                    // `reused` (forces a zero-fill) iff this bump landed on memory
                    // the guest already dirtied below the monotonic dirty high-
                    // water (mmap_next was lowered by a prior munmap). Above the
                    // high-water it's pristine guest RAM — keep it lazily zero.
                    let stale = requested < mem.mmap_dirty_high;
                    mem.mmap_dirty_high = mem.mmap_dirty_high.max(end);
                    return Some((requested, stale));
                }
            }
        }

        let mut mem = self.mem.lock();
        if let Some(pos) = mem.free_regions.iter().position(|&(_, l)| l >= length) {
            let (s, l) = mem.free_regions[pos];
            if l == length {
                mem.free_regions.remove(pos);
            } else {
                mem.free_regions[pos] = (s + length, l - length);
            }
            return Some((s, true));
        }
        let address = align_up_u64(mem.mmap_next, LINUX_PAGE_SIZE)?;
        if !range_within(
            address,
            length,
            LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size(),
        ) {
            return None;
        }
        let end = address.checked_add(length)?;
        mem.mmap_next = end;
        // Same dirty-high-water discipline as the hint path: a bump allocation
        // that dips below the high-water (because munmap lowered mmap_next over
        // already-touched pages) must be zeroed, not returned with stale bytes.
        let stale = address < mem.mmap_dirty_high;
        mem.mmap_dirty_high = mem.mmap_dirty_high.max(end);
        Some((address, stale))
    }

    /// Write a freed `SharedFile` allocation's bytes back to its host fd and
    /// close the owned dup. `SharedAnon` frees need no writeback. Called from
    /// `munmap` (close_fd=true) and `msync` (close_fd=false, no free).
    fn writeback_shared<M: GuestMemory>(
        &self,
        cx: &mut SyscallCtx<'_, M>,
        alloc: &crate::shared_aperture::SharedAlloc,
        close_fd: bool,
    ) {
        if let crate::shared_aperture::BackingObject::SharedFile { host_fd, offset } = alloc.backing
        {
            let len = usize::try_from(alloc.len).unwrap_or(0);
            if len > 0 {
                if let Ok(bytes) = cx.memory.read_bytes(alloc.guest_addr, len) {
                    unsafe {
                        libc::pwrite(
                            host_fd,
                            bytes.as_ptr() as *const _,
                            bytes.len(),
                            offset as libc::off_t,
                        );
                    }
                }
            }
            if close_fd {
                unsafe { libc::close(host_fd) };
            }
        }
    }

    fn membarrier(&self, command: u64, flags: u64) -> DispatchOutcome {
        if command == LINUX_MEMBARRIER_CMD_QUERY && flags == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        DispatchOutcome::errno(LINUX_EINVAL)
    }
}

impl SyscallDispatcher {
    define_syscall! {
        fn fadvise64(this, cx, fd: Fd, _offset: u64, _len: u64, advice: u64) {
            if !this.fd_is_valid(fd.0) && !is_stdio_fd(fd.0) {
                return Ok(LINUX_EBADF.into());
            }
            // Linux's generic_fadvise rejects a pipe/FIFO with ESPIPE (checked
            // before the advice value), so posix_fadvise04 (a real pipe) → ESPIPE.
            // A /dev chardev is also a HostPipe in carrick but is NOT a FIFO, so
            // ask the host kernel (fstat S_IFIFO) rather than keying on the
            // variant alone.
            if let Some(open_file) = this.open_file(fd.0) {
                let is_fifo = match &*open_file.description.read() {
                    OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. } => true,
                    OpenDescription::HostPipe { host_fd, .. } => {
                        let mut st: libc::stat = unsafe { core::mem::zeroed() };
                        let fstat_ok = unsafe { libc::fstat(*host_fd, &mut st) } == 0;
                        fstat_ok
                            && (st.st_mode as u32 & libc::S_IFMT as u32)
                                == libc::S_IFIFO as u32
                    }
                    _ => false,
                };
                if is_fifo {
                    return Ok(LINUX_ESPIPE.into());
                }
            }
            // POSIX_FADV_{NORMAL,RANDOM,SEQUENTIAL,WILLNEED,DONTNEED,NOREUSE} =
            // 0..=5 on aarch64 (asm-generic values); anything else is EINVAL
            // (posix_fadvise03). advice is u64, so a negative arg is huge → caught.
            if advice > 5 {
                return Ok(LINUX_EINVAL.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn brk(this, cx, requested: u64) {
            let mut mem = this.mem.lock();
            if requested == 0 {
                return Ok(DispatchOutcome::Returned {
                    value: mem.brk_current as i64,
                });
            }
            if range_within(requested, 0, LINUX_HEAP_BASE, LINUX_HEAP_SIZE) {
                mem.brk_current = requested;
            }
            Ok(DispatchOutcome::Returned {
                value: mem.brk_current as i64,
            })
        }

        fn mmap(this, cx, requested: GuestPtr, length: u64, prot: u64, flags: u64, fd: Fd, offset: u64) {
            let mut flags = flags;
            let memory = &mut *cx.memory;

            // io_uring ring mapping: the SQ/CQ rings and SQE array already live
            // in the guest arena (allocated by io_uring_setup); the guest maps
            // them off the ring fd with offset = IORING_OFF_*. Hand back the
            // address carrick placed them at, so guest and runtime share the
            // same coherent ring memory.
            if flags & LINUX_MAP_ANONYMOUS == 0 && fd.0 >= 0 {
                if let Some(addr) = this.io_uring_mmap_addr(fd.0, offset) {
                    return Ok(DispatchOutcome::Returned { value: addr as i64 });
                }
            }

            if flags & LINUX_MAP_FIXED_NOREPLACE != 0 {
                flags |= LINUX_MAP_FIXED;
            }

            // Linux validates the fd FIRST for a file mapping: ksys_mmap_pgoff
            // does fget(fd) and returns EBADF before do_mmap ever checks the
            // length/prot/flags (which would yield EINVAL). So a bad fd beats a
            // bad length — LTP mmap08 maps length 0 on a closed fd and expects
            // EBADF, not EINVAL. (Anonymous mappings take no fd → skip.)
            if flags & LINUX_MAP_ANONYMOUS == 0 && this.open_file(fd.0).is_none() {
                return Ok(LINUX_EBADF.into());
            }

            // glibc's vDSO getrandom state page is mapped MAP_ANONYMOUS|
            // MAP_DROPPABLE (0x28) with NO MAP_PRIVATE/MAP_SHARED bit; the kernel
            // treats MAP_DROPPABLE as a private anon mapping, so default the type
            // to PRIVATE rather than rejecting it with EINVAL.
            let map_type = {
                let t = flags & (LINUX_MAP_SHARED | LINUX_MAP_PRIVATE);
                if t == 0 && flags & LINUX_MAP_DROPPABLE != 0 {
                    LINUX_MAP_PRIVATE
                } else {
                    t
                }
            };
            if length == 0
                || prot & !(LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) != 0
                || flags & !LinuxMmapFlags::SUPPORTED_MASK != 0
                || (map_type != LINUX_MAP_SHARED && map_type != LINUX_MAP_PRIVATE)
                || (flags & LINUX_MAP_ANONYMOUS == 0 && !offset.is_multiple_of(LINUX_PAGE_SIZE))
                || (flags & LINUX_MAP_FIXED != 0 && !requested.0.is_multiple_of(LINUX_PAGE_SIZE))
            {
                return Ok(LINUX_EINVAL.into());
            }
            let length = match align_up_u64(length, LINUX_PAGE_SIZE) {
                Some(length) => length,
                None => {
                    return Ok(LINUX_ENOMEM.into());
                }
            };
            let length_usize =
                usize::try_from(length).map_err(|_| DispatchError::LengthTooLarge(length))?;

            // MAP_FIXED|MAP_PRIVATE|ANON landing on a shared-aperture VA: the
            // guest wants a genuinely PRIVATE page at exactly this (currently
            // shared) address. Writing through to the shared backing would leak
            // the guest's "private" stores to every other mapper and across
            // fork (the mapfixed privacy bug). Instead carve a slot in the
            // per-process private overlay aperture and repoint this VA's stage-1
            // leaf to it — stage-1 ONLY, since the overlay window is boot-mapped
            // (no post-vCPU hv_vm_map, per the durable-memory rule). requested.0
            // and length are already validated page-aligned/non-zero above.
            // (MAP_FIXED|MAP_PRIVATE of a FILE over a shared-aperture VA is a
            // tracked remainder — the probe and common case are anon.)
            if flags & LINUX_MAP_FIXED != 0
                && map_type == LINUX_MAP_PRIVATE
                && flags & LINUX_MAP_ANONYMOUS != 0
                && crate::memory::va_in_shared_aperture(requested.0, length)
            {
                let overlay_va = {
                    let mut mem = this.mem.lock();
                    // Re-MAP_FIXED over the same VA: free the prior overlay slot.
                    if let Some(old) = mem.overlay.find_by_source(requested.0) {
                        mem.overlay.free(old);
                    }
                    mem.overlay.alloc_sourced(
                        length,
                        crate::shared_aperture::BackingObject::PrivateAnon,
                        Some(requested.0),
                    )
                };
                let Some(overlay_va) = overlay_va else {
                    return Ok(LINUX_ENOMEM.into());
                };
                // Anonymous => fresh zero page. Seed + stage-1 repoint atomically
                // on the engine; on failure roll the slot back so it's reusable.
                let zeros = vec![0u8; length_usize];
                if memory
                    .repoint_private(requested.0, overlay_va, length_usize, &zeros)
                    .is_err()
                {
                    this.mem.lock().overlay.free(overlay_va);
                    return Ok(LINUX_ENOMEM.into());
                }
                return Ok(DispatchOutcome::Returned {
                    value: requested.0 as i64,
                });
            }

            let hvf_page = crate::trap::HVF_PAGE_SIZE;
            // Guest MAP_SHARED of a file: back the guest region with the host
            // file's page cache LIVE, via an aliased stage-2 mapping at a fresh
            // high VA. `mmap(MAP_SHARED, fd)` on the host means guest writes hit
            // the page cache directly — coherent with any other opener (and with
            // a sibling mapping of the same file) and inherited across fork,
            // because the backing kernel object is the file, not a snapshot.
            // This replaces the old aperture-snapshot+msync-writeback model,
            // which was only coherent at msync/munmap time (the memmap b_*
            // invariant). The dispatcher reserves the alias IPA and hands the
            // runtime a MapHostAlias carrying a dup'd fd; the runtime mmaps it
            // and builds the VA->IPA stage-1 path.
            if flags & LINUX_MAP_ANONYMOUS == 0
                && map_type == LINUX_MAP_SHARED
                && flags & LINUX_MAP_FIXED == 0
                && offset.is_multiple_of(hvf_page)
            {
                let dup_fd = {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(LINUX_EBADF.into());
                    };
                    let open = open_file.description.read();
                    match &*open {
                        OpenDescription::HostFile { host_fd, .. } => {
                            let d = unsafe { libc::dup(*host_fd) };
                            if d < 0 { None } else { Some(d) }
                        }
                        _ => None,
                    }
                };
                if let Some(dup_fd) = dup_fd {
                    // hv_vm_map needs 16 KiB-granular size/IPA; reserve the IPA
                    // in 2 MiB blocks so no two file mappings share a stage-1
                    // block (the existing high-VA anon path does the same).
                    const TWO_MIB: u64 = 1 << 21;
                    let map_len = align_up_u64(length, hvf_page).unwrap_or(length);
                    let alias_len = align_up_u64(length, TWO_MIB).unwrap_or(length);
                    let ipa = {
                        let mut mem = this.mem.lock();
                        let base = mem.alias_ipa_next;
                        let limit = crate::memory::LINUX_ALIAS_IPA_BASE
                            + crate::memory::LINUX_ALIAS_IPA_SIZE;
                        match base.checked_add(alias_len).filter(|e| *e <= limit) {
                            Some(end) => {
                                mem.alias_ipa_next = end;
                                Some(base)
                            }
                            None => None,
                        }
                    };
                    let Some(ipa) = ipa else {
                        // Alias arena exhausted: drop the dup, surface ENOMEM.
                        unsafe { libc::close(dup_fd) };
                        return Ok(LINUX_ENOMEM.into());
                    };
                    let va = crate::memory::LINUX_HIGH_VA_THRESHOLD
                        + (ipa - crate::memory::LINUX_ALIAS_IPA_BASE);
                    // Host mmap prot MUST match the guest's request (and thus the
                    // fd's access mode): MAP_SHARED|PROT_WRITE of a read-only fd
                    // is EACCES. Translate the guest PROT_* bits to host PROT_*.
                    let mut host_prot = 0;
                    if prot & LINUX_PROT_READ != 0 {
                        host_prot |= libc::PROT_READ;
                    }
                    if prot & LINUX_PROT_WRITE != 0 {
                        host_prot |= libc::PROT_WRITE;
                    }
                    if prot & LINUX_PROT_EXEC != 0 {
                        host_prot |= libc::PROT_EXEC;
                    }
                    return Ok(DispatchOutcome::MapHostAlias {
                        va,
                        ipa,
                        len: map_len,
                        payload: Vec::new(),
                        file: Some((dup_fd, offset as libc::off_t, host_prot)),
                    });
                }
            }

            // Guest MAP_SHARED|MAP_ANON: a sub-range of the shared aperture.
            // The bytes already live in the boot-mapped shared region, so we
            // only allocate, zero (recycled memory), and return.
            if flags & LINUX_MAP_ANONYMOUS != 0
                && map_type == LINUX_MAP_SHARED
                && flags & LINUX_MAP_FIXED == 0
            {
                let map_len = align_up_u64(length, hvf_page).unwrap_or(length);
                let addr = {
                    let mut mem = this.mem.lock();
                    mem.shared
                        .alloc(map_len, crate::shared_aperture::BackingObject::SharedAnon)
                };
                if let Some(addr) = addr {
                    let map_len_usize = usize::try_from(map_len)
                        .map_err(|_| DispatchError::LengthTooLarge(map_len))?;
                    let zeros = vec![0u8; map_len_usize];
                    let _ = memory.write_bytes(addr, &zeros);
                    return Ok(DispatchOutcome::Returned { value: addr as i64 });
                }
                return Ok(LINUX_ENOMEM.into());
            }

            let (address, reused) = match this.next_mmap_address(requested.0, length, prot, flags) {
                Some(pair) => pair,
                None => {
                    return Ok(LINUX_ENOMEM.into());
                }
            };

            if reused && !crate::memory::is_high_va(address) {
                let zeros = vec![0u8; length_usize];
                let _ = memory.write_bytes(address, &zeros);
            }

            // Restore guest-visible stage-1 validity for arena allocations: a
            // page reclaimed from a prior munmap (which invalidated it) must be
            // valid+RW again, and a PROT_NONE mmap must actually fault. No-op
            // (no TLBI) when the page is already at the target protection.
            let in_arena = range_within(address, length, LINUX_MMAP_BASE, crate::memory::mmap_arena_size());

            let prot_none = prot & (LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) == 0;
            if prot_none && flags & LINUX_MAP_ANONYMOUS != 0 {
                memory.set_no_access(address, length_usize, false);
                memory.set_no_access(address, length_usize, true);
                if in_arena && memory.protect_range(address, length_usize, 0).is_err() {
                    return Ok(LINUX_ENOMEM.into());
                }
                return Ok(DispatchOutcome::Returned {
                    value: address as i64,
                });
            }

            let mut bytes = vec![0; length_usize];
            if flags & LINUX_MAP_ANONYMOUS == 0 {
                let Some(open_file) = this.open_file(fd.0) else {
                    return Ok(LINUX_EBADF.into());
                };
                let open = open_file.description.read();
                let offset_usize =
                    usize::try_from(offset).map_err(|_| DispatchError::LengthTooLarge(offset))?;
                match &*open {
                    OpenDescription::File { contents, .. }
                    | OpenDescription::SyntheticFile { contents, .. } => {
                        if offset_usize < contents.len() {
                            let available = &contents[offset_usize..];
                            let copy_len = available.len().min(length_usize);
                            bytes[..copy_len].copy_from_slice(&available[..copy_len]);
                        }
                    }
                    OpenDescription::HostFile { host_fd, .. } => {
                        let n = unsafe {
                            libc::pread(
                                *host_fd,
                                bytes.as_mut_ptr() as *mut _,
                                length_usize,
                                offset as libc::off_t,
                            )
                        };
                        let _ = n;
                    }
                    _ => {
                        return Ok(LINUX_EBADF.into());
                    }
                }
            }

            // A high guest VA (>= 1 TiB) can't be identity-mapped (HVF IPA is 40
            // bits). Reserve a low alias IPA and hand the runtime a MapHostAlias
            // outcome that hv_vm_maps it, builds the VA->IPA page-table path, and
            // copies `bytes` (file content, or zeros for anon) in. Apple Rosetta
            // maps both its anon translation arena (240 TiB) and the x86 binary
            // this way.
            if crate::memory::is_high_va(address) {
                // Addresses with bits >= 48 set are non-canonical for the 48-bit
                // TTBR0 and can't be translated. MAP_FIXED_NOREPLACE is a hint the
                // caller will retry without if it can't have exactly this address,
                // so return EEXIST (Rosetta then maps into the normal arena).
                const VA_48: u64 = 1 << 48;
                if address >= VA_48 {
                    if flags & LINUX_MAP_FIXED_NOREPLACE != 0 {
                        return Ok(linux_errno::EEXIST.into());
                    }
                    return Ok(LINUX_ENOMEM.into());
                }
                const TWO_MIB: u64 = 1 << 21;
                let alias_len = align_up_u64(length, TWO_MIB).unwrap_or(length);
                let ipa = {
                    let mut mem = this.mem.lock();
                    let base = mem.alias_ipa_next;
                    let limit =
                        crate::memory::LINUX_ALIAS_IPA_BASE + crate::memory::LINUX_ALIAS_IPA_SIZE;
                    match base.checked_add(alias_len).filter(|e| *e <= limit) {
                        Some(end) => {
                            mem.alias_ipa_next = end;
                            base
                        }
                        None => return Ok(LINUX_ENOMEM.into()),
                    }
                };
                return Ok(DispatchOutcome::MapHostAlias {
                    va: address,
                    ipa,
                    len: alias_len,
                    payload: bytes,
                    file: None,
                });
            }

            memory.set_no_access(address, length_usize, false);
            let _ = memory.write_bytes(address, &bytes);
            if prot_none {
                memory.set_no_access(address, length_usize, true);
            }
            // Make the requested protection guest-visible (also restores RW for
            // a reused range). prot==0 here means file-backed PROT_NONE.
            if in_arena && memory.protect_range(address, length_usize, prot).is_err() {
                return Ok(LINUX_ENOMEM.into());
            }
            Ok(DispatchOutcome::Returned {
                value: address as i64,
            })
        }

        fn munmap(this, cx, address: GuestPtr, length: u64) {
            // Linux munmap EINVAL edges (__vm_munmap): the address must be
            // page-aligned and the length non-zero. LTP munmap03 munmaps the
            // address of a BSS global (8-aligned, not page-aligned) and that
            // address + 8, expecting EINVAL — carrick lacked the alignment gate.
            if !address.0.is_multiple_of(LINUX_PAGE_SIZE) {
                return Ok(LINUX_EINVAL.into());
            }
            if length == 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let freed = {
                let mut mem = this.mem.lock();
                mem.shared.free(address.0)
            };
            if let Some(alloc) = freed {
                // SharedFile backings write dirty bytes back and close the dup;
                // SharedAnon frees are pure bookkeeping. The aperture stays
                // stage-2 mapped — no hv_vm_unmap.
                this.writeback_shared(cx, &alloc, true);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // A guest VA inside the high-VA alias window is a dynamic alias
            // mapping — a MAP_SHARED file region (backed LIVE by the host page
            // cache, so no writeback is owed). It is a valid mapping, so munmap
            // must succeed (LTP munmap01/02 unmapped a MAP_SHARED file region
            // and carrick wrongly returned EINVAL because the alias VA is in
            // neither the shared aperture nor the mmap arena). Best-effort
            // stage-1 invalidate so use-after-munmap faults; arm64 HVF has no
            // stage-2 unmap, so the alias IPA + dup fd are reclaimed at process
            // teardown. Addresses BEYOND the window (e.g. RLIM_INFINITY, which
            // LTP munmap03 passes to assert EINVAL, or the Rosetta arena) fall
            // through to the range check below and stay EINVAL.
            let alias_end =
                crate::memory::LINUX_HIGH_VA_THRESHOLD + crate::memory::LINUX_ALIAS_IPA_SIZE;
            if address.0 >= crate::memory::LINUX_HIGH_VA_THRESHOLD && address.0 < alias_end {
                if let Some(len) = align_up_u64(length, LINUX_PAGE_SIZE)
                    && let Ok(len_usize) = usize::try_from(len)
                {
                    let _ = cx.memory.unmap_range(address.0, len_usize);
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !range_within(address.0, length, LINUX_MMAP_BASE, crate::memory::mmap_arena_size()) {
                return Ok(LINUX_EINVAL.into());
            }
            if let Some(len) = align_up_u64(length, LINUX_PAGE_SIZE) {
                let mut mem = this.mem.lock();
                // Invalidate the freed range in stage-1 (use-after-munmap faults
                // in-guest) BEFORE returning it to the allocator, holding `mem`
                // across the edit. A concurrent mmap that reuses this address
                // must re-acquire `mem` to allocate it, so its validity-restore
                // is strictly ordered AFTER this invalidate — otherwise a late
                // invalidate could clobber the new owner's mapping and fault it.
                // Best-effort: a failure leaves it accessible (pre-existing
                // behavior).
                if let Ok(len_usize) = usize::try_from(len) {
                    let _ = cx.memory.unmap_range(address.0, len_usize);
                }
                if address.0.checked_add(len) == Some(mem.mmap_next) {
                    mem.mmap_next = address.0;
                    while let Some(pos) = mem
                        .free_regions
                        .iter()
                        .position(|&(s, l)| s.checked_add(l) == Some(mem.mmap_next))
                    {
                        let (s, _l) = mem.free_regions.remove(pos);
                        mem.mmap_next = s;
                    }
                } else {
                    free_regions_insert(&mut mem.free_regions, address.0, len);
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn msync(this, cx, address: GuestPtr, length: u64, flags: u64) {
            if flags & !(LINUX_MS_ASYNC | LINUX_MS_INVALIDATE | LINUX_MS_SYNC) != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if flags & LINUX_MS_ASYNC != 0 && flags & LINUX_MS_SYNC != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let alloc = {
                let mem = this.mem.lock();
                mem.shared
                    .live()
                    .iter()
                    .find(|a| a.guest_addr == address.0)
                    .copied()
            };
            if let Some(alloc) = alloc {
                // Write a SharedFile backing's dirty bytes back without freeing.
                this.writeback_shared(cx, &alloc, false);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if cx.memory.read_bytes(address.0, 1).is_err() {
                return Ok(LINUX_ENOMEM.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mlock(this, cx, address: GuestPtr, length: u64) {
            let memory = &mut *cx.memory;
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if memory.read_bytes(address.0, 1).is_err() {
                return Ok(LINUX_ENOMEM.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn munlock(this, cx, address: GuestPtr, length: u64) {
            let memory = &mut *cx.memory;
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if memory.read_bytes(address.0, 1).is_err() {
                return Ok(LINUX_ENOMEM.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mlockall(this, cx, flags: u64) {
            if flags == 0 || flags & !(LINUX_MCL_CURRENT | LINUX_MCL_FUTURE | LINUX_MCL_ONFAULT) != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn munlockall(this, cx) {
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mincore(this, cx, address: GuestPtr, length: u64, vec: GuestPtr) {
            let memory = &mut *cx.memory;
            // Linux requires a page-aligned start address, else EINVAL (this is
            // what Go's TestMincoreErrorSign checks — the errno must be -EINVAL).
            if !address.0.is_multiple_of(LINUX_PAGE_SIZE) {
                return Ok(LINUX_EINVAL.into());
            }
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if memory.read_bytes(address.0, 1).is_err() {
                return Ok(LINUX_ENOMEM.into());
            }
            let pages = length.div_ceil(LINUX_PAGE_SIZE);
            let bytes = vec![1u8; pages as usize];
            if memory.write_bytes(vec.0, &bytes).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mremap(this, cx, old_address: GuestPtr, old_size: u64, new_size_req: u64, flags: u64, _new_address: GuestPtr) {
            let memory = &mut *cx.memory;
            if new_size_req == 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if flags & !(LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_FIXED | LINUX_MREMAP_DONTUNMAP) != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if !range_within(old_address.0, old_size, LINUX_MMAP_BASE, crate::memory::mmap_arena_size()) {
                return Ok(LINUX_EINVAL.into());
            }
            let Some(new_size) = align_up_u64(new_size_req, LINUX_PAGE_SIZE) else {
                return Ok(LINUX_ENOMEM.into());
            };
            if new_size <= old_size {
                return Ok(DispatchOutcome::Returned {
                    value: old_address.0 as i64,
                });
            }

            if old_address.0.checked_add(old_size) == Some(this.mem.lock().mmap_next) {
                let Some(old_end) = old_address.0.checked_add(old_size) else {
                    return Ok(LINUX_ENOMEM.into());
                };
                let Some(new_end) = old_address.0.checked_add(new_size) else {
                    return Ok(LINUX_ENOMEM.into());
                };
                if range_within(old_address.0, new_size, LINUX_MMAP_BASE, crate::memory::mmap_arena_size()) {
                    this.mem.lock().mmap_next = new_end;
                    // Re-validate the freshly-grown tail [old_end, new_end). Those
                    // pages can be a range reclaimed from a prior munmap (which
                    // invalidated their stage-1 leaves and rolled mmap_next back),
                    // so without restoring RW validity here the guest FAULTS on
                    // first access to the grown region — exactly as the move path
                    // below and the regular mmap path do. (CPython's obmalloc/
                    // realloc grows an arena buffer in place; the tail landed on
                    // invalidated pages → a level-3 translation fault.)
                    let grow_len_u64 = new_size - old_size;
                    if let Ok(grow_len) = usize::try_from(grow_len_u64) {
                        memory.set_no_access(old_end, grow_len, false);
                        if memory
                            .protect_range(old_end, grow_len, LINUX_PROT_READ | LINUX_PROT_WRITE)
                            .is_err()
                        {
                            return Ok(LINUX_ENOMEM.into());
                        }
                    }
                    return Ok(DispatchOutcome::Returned {
                        value: old_address.0 as i64,
                    });
                }
            }

            if flags & LINUX_MREMAP_MAYMOVE == 0 {
                return Ok(LINUX_ENOMEM.into());
            }
            let Some((new_addr, reused)) =
                this.next_mmap_address(0, new_size, LINUX_PROT_READ | LINUX_PROT_WRITE, 0)
            else {
                return Ok(LINUX_ENOMEM.into());
            };
            let new_len = match usize::try_from(new_size) {
                Ok(n) => n,
                Err(_) => return Ok(LINUX_ENOMEM.into()),
            };
            // Clear stale no-access tracking on the destination — it may be a
            // range reclaimed from a prior munmap (which marked it no-access).
            memory.set_no_access(new_addr, new_len, false);
            if reused {
                let zeros = vec![0u8; new_len];
                let _ = memory.write_bytes(new_addr, &zeros);
            }
            let copy_len = match usize::try_from(old_size) {
                Ok(len) => len,
                Err(_) => {
                    return Ok(LINUX_ENOMEM.into());
                }
            };
            if copy_len > 0 {
                match memory.read_bytes(old_address.0, copy_len) {
                    Ok(bytes) => {
                        let _ = memory.write_bytes(new_addr, &bytes);
                    }
                    Err(_) => {
                        return Ok(LINUX_EFAULT.into());
                    }
                }
            }
            // Re-validate the destination's guest stage-1 entries, exactly as
            // mmap does. A range reused from a munmap'd region was invalidated;
            // without this the guest FAULTS reading the freshly-mremap'd memory
            // (carrick wrote the copy host-side, so no guest write-fault ever
            // re-established the page). new_addr is always in the arena here.
            if memory
                .protect_range(new_addr, new_len, LINUX_PROT_READ | LINUX_PROT_WRITE)
                .is_err()
            {
                return Ok(LINUX_ENOMEM.into());
            }
            Ok(DispatchOutcome::Returned {
                value: new_addr as i64,
            })
        }

        fn mprotect(this, cx, address: GuestPtr, length: u64, prot: u64) {
            if prot & !(LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !address.0.is_multiple_of(LINUX_PAGE_SIZE) {
                return Ok(LINUX_EINVAL.into());
            }
            if let Ok(len) = usize::try_from(length) {
                let prot_none = prot & (LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) == 0;
                cx.memory.set_no_access(address.0, len, prot_none);
                // Make the new protection guest-VISIBLE (a violating access
                // faults during EL0 execution) by editing the stage-1 page
                // tables. Scoped to the private mmap arena for now — the shared
                // aperture and image/heap regions keep host-side checks only.
                if range_within(address.0, length, LINUX_MMAP_BASE, crate::memory::mmap_arena_size())
                    && cx.memory.protect_range(address.0, len, prot).is_err()
                {
                    return Ok(LINUX_ENOMEM.into());
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn madvise(this, cx, address: GuestPtr, length: u64, advice: u64) {
            let memory = &mut *cx.memory;

            if !address.0.is_multiple_of(LINUX_PAGE_SIZE) || !linux_madvise_advice_is_supported(advice) {
                return Ok(LINUX_EINVAL.into());
            }
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            let Ok(length) = usize::try_from(length) else {
                return Ok(LINUX_ENOMEM.into());
            };
            let Some(last_address) = address.0.checked_add(length as u64 - 1) else {
                return Ok(LINUX_ENOMEM.into());
            };
            if memory.read_bytes(address.0, 1).is_err() || memory.read_bytes(last_address, 1).is_err() {
                return Ok(LINUX_ENOMEM.into());
            }
            if advice == LINUX_MADV_DONTNEED {
                const ZERO_CHUNK: [u8; 4096] = [0; 4096];
                let mut remaining = length;
                let mut cursor = address.0;
                while remaining > 0 {
                    let chunk = remaining.min(ZERO_CHUNK.len());
                    if memory.write_bytes(cursor, &ZERO_CHUNK[..chunk]).is_err() {
                        return Ok(LINUX_ENOMEM.into());
                    }
                    remaining -= chunk;
                    cursor += chunk as u64;
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn sys_membarrier(this, cx, command: u64, flags: u64) {
            Ok(this.membarrier(command, flags))
        }

        // io_uring (WS-H4-B1). setup allocates the rings in the guest arena and
        // returns a ring fd; the guest mmaps the rings off it (handled in the
        // mmap path); enter drains the SQ ring. register is ENOSYS for now (the
        // fixed-file/buffer optimization, not needed for correctness).
        fn io_uring_setup(this, cx, entries: u64, params_ptr: GuestPtr) {
            Ok(this.io_uring_setup_impl(cx.memory, entries as u32, params_ptr.0))
        }

        // `_min_complete` stays unused: carrick's enter is synchronous, so every
        // CQE the guest waited for is posted by the time enter returns. flags/
        // argp/argsz are now validated by the impl. (audit M4)
        fn io_uring_enter(this, cx, fd: Fd, to_submit: u64, _min_complete: u64, flags: u64, argp: GuestPtr, argsz: u64) {
            Ok(this.io_uring_enter_impl(cx.memory, fd.0, to_submit as u32, flags as u32, argp.0, argsz))
        }

        fn io_uring_register(this, cx, _fd: Fd, _opcode: u64, _arg: GuestPtr, _nr_args: u64) {
            Ok(LINUX_ENOSYS.into())
        }
    }
}

fn linux_madvise_advice_is_supported(advice: u64) -> bool {
    matches!(
        advice,
        LINUX_MADV_NORMAL
            | LINUX_MADV_RANDOM
            | LINUX_MADV_SEQUENTIAL
            | LINUX_MADV_WILLNEED
            | LINUX_MADV_DONTNEED
            | LINUX_MADV_FREE
            // THP hints: advisory, accepted as a success no-op (see the abi
            // constants). carrick can't promote to huge pages, but neither must
            // it reject the hint — real Linux with THP built in returns 0.
            | LINUX_MADV_HUGEPAGE
            | LINUX_MADV_NOHUGEPAGE
            | LINUX_MADV_COLLAPSE
    )
}

fn align_up_u64(value: u64, alignment: u64) -> Option<u64> {
    value.div_ceil(alignment).checked_mul(alignment)
}

fn range_within(address: u64, length: u64, base: u64, size: u64) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    let Some(limit) = base.checked_add(size) else {
        return false;
    };
    address >= base && end <= limit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_regions_coalesce_adjacent() {
        let mut r = vec![];
        free_regions_insert(&mut r, 0x1000, 0x1000); // [0x1000,0x2000)
        free_regions_insert(&mut r, 0x3000, 0x1000); // [0x3000,0x4000)
        free_regions_insert(&mut r, 0x2000, 0x1000); // bridges → one [0x1000,0x4000)
        assert_eq!(r, vec![(0x1000, 0x3000)]);
    }

    #[test]
    fn free_regions_coalesce_overlap_and_keep_disjoint() {
        let mut r = vec![];
        free_regions_insert(&mut r, 0x1000, 0x2000); // [0x1000,0x3000)
        free_regions_insert(&mut r, 0x2000, 0x2000); // overlaps → [0x1000,0x4000)
        free_regions_insert(&mut r, 0x9000, 0x1000); // disjoint
        assert_eq!(r, vec![(0x1000, 0x3000), (0x9000, 0x1000)]);
    }

    #[test]
    fn next_mmap_address_reuses_freed_arena_region() {
        let dispatcher = SyscallDispatcher::new();
        let freed = LINUX_MMAP_BASE + (4 * LINUX_PAGE_SIZE);
        {
            let mut mem = dispatcher.mem.lock();
            free_regions_insert(&mut mem.free_regions, freed, 2 * LINUX_PAGE_SIZE);
        }

        let first = dispatcher.next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0);
        assert_eq!(first, Some((freed, true)));

        let second = dispatcher.next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0);
        assert_eq!(second, Some((freed + LINUX_PAGE_SIZE, true)));

        assert!(dispatcher.mem.lock().free_regions.is_empty());
    }
}
