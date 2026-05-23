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
            address_space_regions: None,
        }
    }
}

impl SyscallDispatcher {
    pub(super) fn dispatch_threaded_memory<M: GuestMemory>(
        &self,
        request: SyscallRequest,
        memory: &mut M,
        reporter: &CompatReporter,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        if !syscall_handler_is(request.number, SyscallHandler::Memory) {
            return None;
        }

        let syscall = lookup_aarch64(request.number);
        let name = syscall.map_or("unknown", |syscall| syscall.name);
        reporter.record(CompatEvent::SyscallEntry {
            number: request.number,
            name: name.to_owned(),
            args: request.args,
        });

        let mut ctx = SyscallCtx {
            request,
            memory,
            reporter,
            thread: None,
        };
        let outcome = match match request.number {
            214 => self.brk(&mut ctx),
            215 => self.munmap(&mut ctx),
            216 => self.mremap(&mut ctx),
            222 => self.mmap(&mut ctx),
            223 => self.fadvise64(&mut ctx),
            226 => self.mprotect(&mut ctx),
            227 => self.msync(&mut ctx),
            228 => self.mlock(&mut ctx),
            229 => self.munlock(&mut ctx),
            230 => self.mlockall(&mut ctx),
            231 => self.munlockall(&mut ctx),
            232 => self.mincore(&mut ctx),
            233 => self.madvise(&mut ctx),
            283 => self.sys_membarrier(&mut ctx),
            _ => unreachable!("unsupported threaded memory syscall"),
        } {
            Ok(outcome) => outcome,
            Err(error) => return Some(Err(error)),
        };

        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number,
            name: name.to_owned(),
            retval,
            errno,
        });

        Some(Ok(outcome))
    }

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
        let fd = ctx.arg(0) as i32;
        if !self.fd_is_valid(fd) && !is_stdio_fd(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
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
        let flags = ctx.arg(3);
        let fd = ctx.arg(4) as i32;
        let offset = ctx.arg(5);
        let memory = &mut *ctx.memory;

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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let length = match align_up_u64(length, LINUX_PAGE_SIZE) {
            Some(length) => length,
            None => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOMEM,
                });
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
                let Some(open_file) = self.open_file(fd) else {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
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

        let address = match self.next_mmap_address(requested, length, prot, flags) {
            Some(address) => address,
            None => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOMEM,
                });
            }
        };

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
            let Some(open_file) = self.open_file(fd) else {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
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
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
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

    fn next_mmap_address(&self, requested: u64, length: u64, prot: u64, flags: u64) -> Option<u64> {
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
            return Some(requested);
        }

        let prot_none = prot & (LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) == 0;
        let anonymous_private = flags & LINUX_MAP_ANONYMOUS != 0 && flags & LINUX_MAP_PRIVATE != 0;
        if requested != 0 {
            let valid_hint = requested.is_multiple_of(LINUX_PAGE_SIZE)
                && range_within(requested, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE);
            if valid_hint {
                let mut mem = self.mem.lock();
                let end = requested.checked_add(length)?;
                if requested >= mem.mmap_next {
                    mem.mmap_next = end;
                    return Some(requested);
                }
            } else if prot_none && anonymous_private {
                return None;
            }
        }

        let mut mem = self.mem.lock();
        let address = align_up_u64(mem.mmap_next, LINUX_PAGE_SIZE)?;
        if !range_within(address, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return None;
        }
        mem.mmap_next = address.checked_add(length)?;
        Some(address)
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if flags & LINUX_MS_ASYNC != 0 && flags & LINUX_MS_SYNC != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        }
        let pages = length.div_ceil(LINUX_PAGE_SIZE);
        let bytes = vec![1u8; pages as usize];
        if memory.write_bytes(vec, &bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if flags & !(LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_FIXED | LINUX_MREMAP_DONTUNMAP) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if !range_within(old_address, old_size, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let Some(new_size) = align_up_u64(new_size_req, LINUX_PAGE_SIZE) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
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
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOMEM,
                });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        }
        let Some(new_address) =
            self.next_mmap_address(0, new_size, LINUX_PROT_READ | LINUX_PROT_WRITE, 0)
        else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        };
        let copy_len = match usize::try_from(old_size) {
            Ok(len) => len,
            Err(_) => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOMEM,
                });
            }
        };
        if copy_len > 0 {
            match memory.read_bytes(old_address, copy_len) {
                Ok(bytes) => {
                    let _ = memory.write_bytes(new_address, &bytes);
                }
                Err(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if length == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        let Ok(length) = usize::try_from(length) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        };
        let Some(last_address) = address.checked_add(length as u64 - 1) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        };
        if memory.read_bytes(address, 1).is_err() || memory.read_bytes(last_address, 1).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        }
        if advice == LINUX_MADV_DONTNEED {
            const ZERO_CHUNK: [u8; 4096] = [0; 4096];
            let mut remaining = length;
            let mut cursor = address;
            while remaining > 0 {
                let chunk = remaining.min(ZERO_CHUNK.len());
                if memory.write_bytes(cursor, &ZERO_CHUNK[..chunk]).is_err() {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_ENOMEM,
                    });
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
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        }
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
