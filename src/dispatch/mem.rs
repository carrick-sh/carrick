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
    fn dispatch_brk(&self, request: SyscallRequest) -> DispatchOutcome {
        let requested = request.arg(0);
        let mut mem = self.mem.lock();
        if requested == 0 {
            return DispatchOutcome::Returned {
                value: mem.brk_current as i64,
            };
        }
        if range_within(requested, 0, LINUX_HEAP_BASE, LINUX_HEAP_SIZE) {
            mem.brk_current = requested;
        }
        DispatchOutcome::Returned {
            value: mem.brk_current as i64,
        }
    }

    /// posix_fadvise(2): purely an advisory hint to the page cache. We have
    /// no readahead model, so honour it as a no-op — but validate the fd so a
    /// genuinely bad descriptor still reports EBADF. dpkg/apt/coreutils call
    /// this routinely; without it the unimplemented-syscall panic killed them.
    pub(super) fn fadvise64<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd: Fd = ctx.typed_arg(0);
        if !self.fd_is_valid(fd.0) && !is_stdio_fd(fd.0) {
            return Ok(LINUX_EBADF.into());
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn brk<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.dispatch_brk(ctx.request))
    }

    pub(super) fn mmap<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let requested = ctx.arg(0);
        let length = ctx.arg(1);
        let prot = ctx.arg(2);
        let mut flags = ctx.arg(3);
        let fd: Fd = ctx.typed_arg(4);
        let offset = ctx.arg(5);
        let memory = &mut *ctx.memory;

        // MAP_FIXED_NOREPLACE places at the exact requested address like
        // MAP_FIXED; carrick's FIXED path never clobbers an existing stage-2
        // mapping, so normalise it to MAP_FIXED for placement (the EEXIST
        // collision report is the only behaviour we forgo).
        if flags & LINUX_MAP_FIXED_NOREPLACE != 0 {
            flags |= LINUX_MAP_FIXED;
        }

        // Linux requires exactly one of MAP_SHARED / MAP_PRIVATE. MAP_PRIVATE
        // is a private snapshot copy of the file contents. MAP_SHARED of a
        // real host file is backed by a true shared mapping (see below) so
        // writes are coherent across mappings and persist to the file.
        let map_type = flags & (LINUX_MAP_SHARED | LINUX_MAP_PRIVATE);
        if length == 0
            || prot & !(LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) != 0
            || flags & !LinuxMmapFlags::SUPPORTED_MASK != 0
            || (map_type != LINUX_MAP_SHARED && map_type != LINUX_MAP_PRIVATE)
            || (flags & LINUX_MAP_ANONYMOUS == 0 && !offset.is_multiple_of(LINUX_PAGE_SIZE))
            || (flags & LINUX_MAP_FIXED != 0 && !requested.is_multiple_of(LINUX_PAGE_SIZE))
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

        // Coherent MAP_SHARED of a real host file: back the guest pages with
        // a libc MAP_SHARED mmap of the host file, stage-2 mapped into a
        // dedicated guest window. The guest CPU and the dispatcher accessor
        // then share the file's page cache, so writes are visible across
        // mappings and persist to disk — what apt's mmap-backed cache needs.
        // Falls through to the private-snapshot path if the fd isn't a real
        // host file or the backend can't do shared mappings (--fs memory,
        // unit tests). MAP_FIXED shared mappings keep the snapshot path.
        // hv_vm_map requires HVF-page (16 KiB) aligned addr/len/offset. The
        // guest runs with the stage-1 MMU off (VA==IPA), so we map at the IPA
        // directly; we only need to round the mapping up to the HVF page and
        // require an HVF-aligned file offset (else fall back to snapshot).
        let hvf_page = crate::trap::HVF_PAGE_SIZE;
        if flags & LINUX_MAP_ANONYMOUS == 0
            && map_type == LINUX_MAP_SHARED
            && flags & LINUX_MAP_FIXED == 0
            && offset.is_multiple_of(hvf_page)
        {
            let dup_fd = {
                let Some(open_file) = self.open_file(fd.0) else {
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
                match self.next_shared_file_address(map_len as u64) {
                    Some(addr) => {
                        // map_shared_file takes ownership of dup_fd (closes it).
                        match memory.map_shared_file(addr, map_len, dup_fd, offset) {
                            Ok(()) => {
                                self.mem.lock().shared_file_maps.push((addr, map_len));
                                return Ok(DispatchOutcome::Returned { value: addr as i64 });
                            }
                            Err(_) => { /* fall through to snapshot path */ }
                        }
                    }
                    None => unsafe {
                        libc::close(dup_fd);
                    },
                }
            }
        }

        // Coherent MAP_SHARED anonymous mapping: back it with a host
        // MAP_SHARED|MAP_ANON region (shared across fork), so the guest's
        // shared-anon memory is genuinely shared between forked processes
        // (POSIX) and usable as a cross-process futex word (LTP futex_wake03
        // forks children that FUTEX_WAIT on it). MAP_FIXED keeps the snapshot
        // path; the memory backend (--fs memory / tests) falls through too.
        if flags & LINUX_MAP_ANONYMOUS != 0
            && map_type == LINUX_MAP_SHARED
            && flags & LINUX_MAP_FIXED == 0
        {
            let map_len = align_up_u64(length, hvf_page)
                .and_then(|l| usize::try_from(l).ok())
                .unwrap_or(length_usize);
            if let Some(addr) = self.next_shared_file_address(map_len as u64) {
                if memory.map_shared_anon(addr, map_len).is_ok() {
                    self.mem.lock().shared_file_maps.push((addr, map_len));
                    return Ok(DispatchOutcome::Returned { value: addr as i64 });
                }
                // else fall through to the private-anon snapshot path.
            }
        }

        let (address, reused) = match self.next_mmap_address(requested, length, prot, flags) {
            Some(pair) => pair,
            None => {
                return Ok(LINUX_ENOMEM.into());
            }
        };
        // A reused arena range carries the previous mapping's bytes; anonymous
        // mmap must hand back zeroed memory. Fresh bump ranges are demand-zero
        // (HVF), so zero ONLY on reuse — zeroing a fresh range would force it
        // resident and defeat the lazy 32 GiB arena.
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
            let Some(open_file) = self.open_file(fd.0) else {
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
                // Real host file: pread the requested region directly.
                // MAP_PRIVATE snapshot semantics — we copy the bytes
                // into the guest mapping (we don't model live
                // MAP_SHARED file mappings).
                OpenDescription::HostFile { host_fd, .. } => {
                    let n = unsafe {
                        libc::pread(
                            *host_fd,
                            bytes.as_mut_ptr() as *mut _,
                            length_usize,
                            offset as libc::off_t,
                        )
                    };
                    // Short/zero reads just leave the tail zero-filled,
                    // matching mmap-past-EOF semantics. Negative = error
                    // but we still return the (zeroed) mapping rather
                    // than fail, mirroring the File path's leniency.
                    let _ = n;
                }
                OpenDescription::Directory { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::Netlink { .. } => {
                    return Ok(LINUX_EBADF.into());
                }
            }
        }

        // Best-effort zero-fill — if the destination isn't in our tracked
        // address space (e.g. MAP_FIXED at the heap base where we only model
        // a small window today), skip the fill and return the address. The
        // underlying stage-2 page is still backed by the host mapping for
        // that region, so the write would land in real memory.
        // Clear any prior PROT_NONE over this range BEFORE loading content, so
        // the zero-fill/file-load write below isn't rejected by our own
        // no-access check (ld.so reserves a region PROT_NONE, then MAP_FIXED-maps
        // the library's segments over it — those loads must land).
        memory.set_no_access(address, length_usize, false);
        let _ = memory.write_bytes(address, &bytes);
        // A PROT_NONE mapping must fault on the syscall path afterwards (a guest
        // passing it as a buffer gets EFAULT — LTP's tst_get_bad_addr).
        if prot_none {
            memory.set_no_access(address, length_usize, true);
        }
        Ok(DispatchOutcome::Returned {
            value: address as i64,
        })
    }

    /// Returns `(address, reused)`. `reused == true` means the range came from
    /// the free-list and the caller MUST zero it (anonymous-mmap contract);
    /// a fresh bump/FIXED/hint placement is demand-zero and must NOT be zeroed
    /// (that would force it resident and defeat the lazy arena).
    fn next_mmap_address(
        &self,
        requested: u64,
        length: u64,
        _prot: u64,
        flags: u64,
    ) -> Option<(u64, bool)> {
        if flags & LINUX_MAP_FIXED != 0 {
            // Bootstrap policy: accept MAP_FIXED at any page-aligned guest
            // address that fits in the configured IPA window. We do not
            // create new stage-2 mappings for these requests — the caller
            // expects the address back, and writes/reads will either hit a
            // pre-existing mapping or fault. musl's malloc relies on this to
            // place PROT_NONE guard pages at the heap edge.
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
            // An out-of-window hint is ADVISORY without MAP_FIXED (POSIX), so we
            // relocate the mapping into the arena rather than failing. This is
            // what lets Go's heap-arena reservations work: Go probes PROT_NONE
            // anonymous hints across the 64-bit space (256 GiB → 1.5+ TiB, far
            // beyond our IPA/page-table coverage); honoring the *first* by
            // relocating it into the arena makes Go accept the returned address
            // and stop probing, instead of ENOMEM-ing every hint and stalling.
            // Oversized reservations still ENOMEM via the arena bounds check
            // below, so a pathological multi-hundred-GiB reservation can't
            // exhaust the arena silently.
        }

        let mut mem = self.mem.lock();
        // Reuse a freed in-arena region first (first-fit) so a churning guest
        // doesn't grow the bump cursor forever. Reused ranges carry the previous
        // mapping's bytes, so the caller zeroes them.
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

    /// Bump-allocate a page-aligned guest address in the dedicated
    /// MAP_SHARED file-mapping window. Returns None if the window is full.
    fn next_shared_file_address(&self, length: u64) -> Option<u64> {
        use crate::memory::{LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE};
        // HVF-page (16 KiB) aligned so each hv_vm_map gets a valid base.
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

    pub(super) fn munmap<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = ctx.arg(1);
        if length == 0 {
            return Ok(LINUX_EINVAL.into());
        }
        // A real MAP_SHARED file mapping → tear down the host mmap + stage-2.
        let shared_mapping = {
            let mut mem = self.mem.lock();
            mem.shared_file_maps
                .iter()
                .position(|(a, _)| *a == address)
                .map(|pos| mem.shared_file_maps.remove(pos))
        };
        if let Some((addr, len)) = shared_mapping {
            let _ = ctx.memory.unmap_shared_file(addr, len);
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if !range_within(address, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return Ok(LINUX_EINVAL.into());
        }
        // Reclaim the range so a churning guest reuses it instead of growing the
        // bump cursor forever. The arena is flat stage-2-mapped, so there is no
        // host/HVF unmap to do — only mark the VA reusable.
        if let Some(len) = align_up_u64(length, LINUX_PAGE_SIZE) {
            let mut mem = self.mem.lock();
            // Fast path: freeing the top of the bump just lowers the cursor, then
            // absorb any free region now sitting at the new top.
            if address.checked_add(len) == Some(mem.mmap_next) {
                mem.mmap_next = address;
                while let Some(pos) = mem
                    .free_regions
                    .iter()
                    .position(|&(s, l)| s.checked_add(l) == Some(mem.mmap_next))
                {
                    let (s, _l) = mem.free_regions.remove(pos);
                    mem.mmap_next = s;
                }
            } else {
                free_regions_insert(&mut mem.free_regions, address, len);
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn msync<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = ctx.arg(1);
        let flags = ctx.arg(2);
        if flags & !(LINUX_MS_ASYNC | LINUX_MS_INVALIDATE | LINUX_MS_SYNC) != 0 {
            return Ok(LINUX_EINVAL.into());
        }
        if flags & LINUX_MS_ASYNC != 0 && flags & LINUX_MS_SYNC != 0 {
            return Ok(LINUX_EINVAL.into());
        }
        if length == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        // Flush a real MAP_SHARED file mapping to disk (host msync). With a
        // file-backed mapping the guest's stores already hit the file's page
        // cache, but msync makes the durability explicit.
        let shared_mapping = self
            .mem
            .lock()
            .shared_file_maps
            .iter()
            .find(|(a, _)| *a == address)
            .copied();
        if let Some((addr, len)) = shared_mapping {
            let _ = ctx.memory.msync_shared_file(addr, len);
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if ctx.memory.read_bytes(address, 1).is_err() {
            return Ok(LINUX_ENOMEM.into());
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn mlock<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = ctx.arg(1);
        let memory = &mut *ctx.memory;
        if length == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if memory.read_bytes(address, 1).is_err() {
            return Ok(LINUX_ENOMEM.into());
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn munlock<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.mlock(ctx)
    }

    pub(super) fn mlockall<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let flags = ctx.arg(0);
        if flags == 0 || flags & !(LINUX_MCL_CURRENT | LINUX_MCL_FUTURE | LINUX_MCL_ONFAULT) != 0 {
            return Ok(LINUX_EINVAL.into());
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn munlockall<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn mincore<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = ctx.arg(1);
        let vec = ctx.arg(2);
        let memory = &mut *ctx.memory;
        if length == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if memory.read_bytes(address, 1).is_err() {
            return Ok(LINUX_ENOMEM.into());
        }
        let pages = length.div_ceil(LINUX_PAGE_SIZE);
        let bytes = vec![1u8; pages as usize];
        if memory.write_bytes(vec, &bytes).is_err() {
            return Ok(LINUX_EFAULT.into());
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn mremap<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let old_address = ctx.request.arg(0);
        let old_size = ctx.request.arg(1);
        let new_size_req = ctx.request.arg(2);
        let flags = ctx.request.arg(3);
        if new_size_req == 0 {
            return Ok(LINUX_EINVAL.into());
        }
        if flags & !(LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_FIXED | LINUX_MREMAP_DONTUNMAP) != 0 {
            return Ok(LINUX_EINVAL.into());
        }
        if !range_within(old_address, old_size, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return Ok(LINUX_EINVAL.into());
        }
        let Some(new_size) = align_up_u64(new_size_req, LINUX_PAGE_SIZE) else {
            return Ok(LINUX_ENOMEM.into());
        };
        if new_size <= old_size {
            return Ok(DispatchOutcome::Returned {
                value: old_address as i64,
            });
        }

        // Grow in place when this mapping sits at the top of the bump
        // allocator: the tail bytes are fresh guest memory already backed by
        // the stage-2 mapping, so no copy is needed.
        if old_address.checked_add(old_size) == Some(self.mem.lock().mmap_next) {
            let Some(new_end) = old_address.checked_add(new_size) else {
                return Ok(LINUX_ENOMEM.into());
            };
            if range_within(old_address, new_size, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
                self.mem.lock().mmap_next = new_end;
                return Ok(DispatchOutcome::Returned {
                    value: old_address as i64,
                });
            }
        }

        // Otherwise the mapping can only grow by moving. Linux requires
        // MREMAP_MAYMOVE for that; without it the call fails.
        if flags & LINUX_MREMAP_MAYMOVE == 0 {
            return Ok(LINUX_ENOMEM.into());
        }
        let Some((new_address, reused)) =
            self.next_mmap_address(0, new_size, LINUX_PROT_READ | LINUX_PROT_WRITE, 0)
        else {
            return Ok(LINUX_ENOMEM.into());
        };
        // A reused arena range carries the previous mapping's bytes; zero the
        // whole new extent so the grown tail reads zero (the head is overwritten
        // by the copy below). A fresh bump range is demand-zero — skip it.
        if reused && let Ok(n) = usize::try_from(new_size) {
            let zeros = vec![0u8; n];
            let _ = memory.write_bytes(new_address, &zeros);
        }
        let copy_len = match usize::try_from(old_size) {
            Ok(len) => len,
            Err(_) => {
                return Ok(LINUX_ENOMEM.into());
            }
        };
        if copy_len > 0 {
            match memory.read_bytes(old_address, copy_len) {
                Ok(bytes) => {
                    let _ = memory.write_bytes(new_address, &bytes);
                }
                Err(_) => {
                    return Ok(LINUX_EFAULT.into());
                }
            }
        }
        Ok(DispatchOutcome::Returned {
            value: new_address as i64,
        })
    }

    pub(super) fn mprotect<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = ctx.arg(1);
        let prot = ctx.arg(2);
        if prot & !(LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) != 0 {
            return Ok(LINUX_EINVAL.into());
        }
        if length == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        // Page-alignment check on the address — Linux requires that. Our
        // stage-2 mappings are already r-w-x for the bootstrap, so changing
        // protections is a no-op for the guest. Don't validate the range
        // against the dispatcher's address space: musl's RELRO loop hands us
        // addresses inside the dynamically-allocated mmap arenas that we
        // don't currently model, and gating those calls produces an
        // ENOMEM-retry loop that prevents dynamic startup from finishing.
        if !address.is_multiple_of(LINUX_PAGE_SIZE) {
            return Ok(LINUX_EINVAL.into());
        }
        // Track PROT_NONE so the syscall path faults on the range (EFAULT for a
        // buffer arg); re-enabling access clears it. This is the only part of
        // mprotect carrick models — stage-2 stays r-w-x for the guest CPU.
        if let Ok(len) = usize::try_from(length) {
            let prot_none = prot & (LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) == 0;
            ctx.memory.set_no_access(address, len, prot_none);
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn madvise<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = ctx.arg(1);
        let advice = ctx.arg(2);
        let memory = &mut *ctx.memory;

        if !address.is_multiple_of(LINUX_PAGE_SIZE) || !linux_madvise_advice_is_supported(advice) {
            return Ok(LINUX_EINVAL.into());
        }
        if length == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        let Ok(length) = usize::try_from(length) else {
            return Ok(LINUX_ENOMEM.into());
        };
        let Some(last_address) = address.checked_add(length as u64 - 1) else {
            return Ok(LINUX_ENOMEM.into());
        };
        if memory.read_bytes(address, 1).is_err() || memory.read_bytes(last_address, 1).is_err() {
            return Ok(LINUX_ENOMEM.into());
        }
        if advice == LINUX_MADV_DONTNEED {
            const ZERO_CHUNK: [u8; 4096] = [0; 4096];
            let mut remaining = length;
            let mut cursor = address;
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

    fn membarrier(&self, request: SyscallRequest) -> DispatchOutcome {
        let command = request.arg(0);
        let flags = request.arg(1);

        if command == LINUX_MEMBARRIER_CMD_QUERY && flags == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        DispatchOutcome::errno(LINUX_EINVAL)
    }

    pub(super) fn sys_membarrier<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.membarrier(ctx.request))
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
    use super::free_regions_insert;

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
}
