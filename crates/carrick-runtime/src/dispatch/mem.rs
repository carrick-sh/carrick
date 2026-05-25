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
    /// Bump allocator for the MAP_SHARED file-mapping IPA window.
    pub shared_file_next: u64,
    /// List of live MAP_SHARED file mappings (guest_addr, len) so
    /// munmap/msync can route to them. See [`SyscallDispatcher::mmap`].
    pub shared_file_maps: Vec<(u64, usize)>,
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
}

impl MemState {
    pub(super) fn new() -> Self {
        Self {
            brk_current: LINUX_HEAP_BASE,
            mmap_next: LINUX_MMAP_BASE,
            shared_file_next: crate::memory::LINUX_SHARED_FILE_BASE,
            shared_file_maps: Vec::new(),
            free_regions: Vec::new(),
            address_space_regions: None,
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
    fn next_mmap_address(
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
                && range_within(requested, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE);
            if valid_hint {
                let mut mem = self.mem.lock();
                let end = requested.checked_add(length)?;
                if requested >= mem.mmap_next {
                    mem.mmap_next = end;
                    return Some((requested, false));
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
        if !range_within(address, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return None;
        }
        mem.mmap_next = address.checked_add(length)?;
        Some((address, false))
    }

    fn next_shared_file_address(&self, length: u64) -> Option<u64> {
        use crate::memory::{LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE};
        let mut mem = self.mem.lock();
        let address = align_up_u64(mem.shared_file_next, crate::trap::HVF_PAGE_SIZE)?;
        if !range_within(
            address,
            length,
            LINUX_SHARED_FILE_BASE,
            LINUX_SHARED_FILE_SIZE,
        ) {
            return None;
        }
        mem.shared_file_next = address.checked_add(length)?;
        Some(address)
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
        fn fadvise64(this, cx, fd: Fd, _offset: u64, _len: u64, _advice: u64) {
            if !this.fd_is_valid(fd.0) && !is_stdio_fd(fd.0) {
                return Ok(LINUX_EBADF.into());
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

            if flags & LINUX_MAP_FIXED_NOREPLACE != 0 {
                flags |= LINUX_MAP_FIXED;
            }

            let map_type = flags & (LINUX_MAP_SHARED | LINUX_MAP_PRIVATE);
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

            let hvf_page = crate::trap::HVF_PAGE_SIZE;
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
                    let map_len = align_up_u64(length, hvf_page)
                        .and_then(|l| usize::try_from(l).ok())
                        .unwrap_or(length_usize);
                    match this.next_shared_file_address(map_len as u64) {
                        Some(addr) => {
                            match memory.map_shared_file(addr, map_len, dup_fd, offset) {
                                Ok(()) => {
                                    this.mem.lock().shared_file_maps.push((addr, map_len));
                                    return Ok(DispatchOutcome::Returned { value: addr as i64 });
                                }
                                Err(_) => { /* fall through */ }
                            }
                        }
                        None => unsafe {
                            libc::close(dup_fd);
                        },
                    }
                }
            }

            if flags & LINUX_MAP_ANONYMOUS != 0
                && map_type == LINUX_MAP_SHARED
                && flags & LINUX_MAP_FIXED == 0
            {
                let map_len = align_up_u64(length, hvf_page)
                    .and_then(|l| usize::try_from(l).ok())
                    .unwrap_or(length_usize);
                if let Some(addr) = this.next_shared_file_address(map_len as u64) {
                    if memory.map_shared_anon(addr, map_len).is_ok() {
                        this.mem.lock().shared_file_maps.push((addr, map_len));
                        return Ok(DispatchOutcome::Returned { value: addr as i64 });
                    }
                }
            }

            let (address, reused) = match this.next_mmap_address(requested.0, length, prot, flags) {
                Some(pair) => pair,
                None => {
                    return Ok(LINUX_ENOMEM.into());
                }
            };
            if reused {
                let zeros = vec![0u8; length_usize];
                let _ = memory.write_bytes(address, &zeros);
            }

            let prot_none = prot & (LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) == 0;
            if prot_none && flags & LINUX_MAP_ANONYMOUS != 0 {
                memory.set_no_access(address, length_usize, false);
                memory.set_no_access(address, length_usize, true);
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

            memory.set_no_access(address, length_usize, false);
            let _ = memory.write_bytes(address, &bytes);
            if prot_none {
                memory.set_no_access(address, length_usize, true);
            }
            Ok(DispatchOutcome::Returned {
                value: address as i64,
            })
        }

        fn munmap(this, cx, address: GuestPtr, length: u64) {
            if length == 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let shared_mapping = {
                let mut mem = this.mem.lock();
                mem.shared_file_maps
                    .iter()
                    .position(|(a, _)| *a == address.0)
                    .map(|pos| mem.shared_file_maps.remove(pos))
            };
            if let Some((addr, len)) = shared_mapping {
                let _ = cx.memory.unmap_shared_file(addr, len);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !range_within(address.0, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
                return Ok(LINUX_EINVAL.into());
            }
            if let Some(len) = align_up_u64(length, LINUX_PAGE_SIZE) {
                let mut mem = this.mem.lock();
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
            let shared_mapping = this
                .mem
                .lock()
                .shared_file_maps
                .iter()
                .find(|(a, _)| *a == address.0)
                .copied();
            if let Some((addr, len)) = shared_mapping {
                let _ = cx.memory.msync_shared_file(addr, len);
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
            if !range_within(old_address.0, old_size, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
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
                let Some(new_end) = old_address.0.checked_add(new_size) else {
                    return Ok(LINUX_ENOMEM.into());
                };
                if range_within(old_address.0, new_size, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
                    this.mem.lock().mmap_next = new_end;
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
            if reused && let Ok(n) = usize::try_from(new_size) {
                let zeros = vec![0u8; n];
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
