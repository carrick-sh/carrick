//! Memory advice and locking syscalls (`madvise`, `fadvise64`, `readahead`,
//! `mlock`/`munlock`, `mlockall`/`munlockall`, `mlock2`, `mincore`, `msync`,
//! `membarrier`, `userfaultfd`, `io_uring_*`).

use super::*;
use carrick_abi::{
    LINUX_MADV_COLLAPSE, LINUX_MADV_DODUMP, LINUX_MADV_DOFORK, LINUX_MADV_DONTDUMP,
    LINUX_MADV_DONTFORK, LINUX_MADV_DONTNEED, LINUX_MADV_FREE, LINUX_MADV_HUGEPAGE,
    LINUX_MADV_KEEPONFORK, LINUX_MADV_NOHUGEPAGE, LINUX_MADV_NORMAL, LINUX_MADV_RANDOM,
    LINUX_MADV_SEQUENTIAL, LINUX_MADV_WILLNEED, LINUX_MADV_WIPEONFORK, LINUX_MEMBARRIER_CMD_QUERY,
    LINUX_MS_ASYNC, LINUX_MS_INVALIDATE, LINUX_MS_SYNC, LinuxMlock2Flags, LinuxMlockallFlags,
};

/// Describes the VMA coverage and attributes of a requested address range for `madvise`.
pub(crate) struct MadviseRangeMeta {
    pub(crate) fully_mapped: bool,
    pub(crate) covered: Vec<MadviseCoveredSegment>,
    pub(crate) writable: bool,
    pub(crate) shared: bool,
    pub(crate) all_private_anon: bool,
    pub(crate) any_special: bool,
    pub(crate) any_droppable: bool,
    pub(crate) locked: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct MadviseCoveredSegment {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) prot: LinuxProtFlags,
    pub(crate) provenance: VmaBackingProvenance,
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
            | LINUX_MADV_DONTFORK
            | LINUX_MADV_DOFORK
            | LINUX_MADV_WIPEONFORK
            | LINUX_MADV_KEEPONFORK
            | LINUX_MADV_DONTDUMP
            | LINUX_MADV_DODUMP
            // THP hints: advisory, accepted as a success no-op (see the abi
            // constants). carrick can't promote to huge pages, but neither must
            // it reject the hint — real Linux with THP built in returns 0.
            | LINUX_MADV_HUGEPAGE
            | LINUX_MADV_NOHUGEPAGE
            | LINUX_MADV_COLLAPSE
    )
}

fn validate_mlock_range(
    memory: &mut impl CurrentMmMemory,
    range: crate::vfs::GuestMemoryRange,
    populate: bool,
    page_size: u64,
    committed_vma_covers_range: bool,
) -> Result<(), LinuxErrno> {
    let len = range_len_usize(range)?;
    if memory
        .protections()
        .is_some_and(|protections| protections.range_unmapped(range.start().raw(), len))
    {
        return Err(LINUX_ENOMEM);
    }
    if committed_vma_covers_range || memory.has_complete_mapping_metadata() {
        return Ok(());
    }
    if !populate && memory.host_ptr_for_read(range.start().raw(), len).is_some() {
        return Ok(());
    }
    let mut page = range.start().raw();
    while page < range.end().raw() {
        if memory.read_bytes(page, 1).is_err() {
            return Err(LINUX_ENOMEM);
        }
        page = page.checked_add(page_size).ok_or(LINUX_ENOMEM)?;
    }
    Ok(())
}

impl<'a> MemView<'a> {
    /// Derive `madvise` range validity + properties from carrick's mapping
    /// metadata (`semantic_vmas`), never by probing a page.
    pub(crate) fn madvise_range_meta(&self, start: u64, end: u64) -> MadviseRangeMeta {
        let mem_authority_2 = self.mem();
        let mem = mem_authority_2.lock();
        let mut covered_to = start;
        let mut covered: Vec<MadviseCoveredSegment> = Vec::new();
        let mut fully_mapped = true;
        let mut writable = true;
        let mut shared = false;
        let mut all_private_anon = true;
        let mut any_special = false;
        let mut any_droppable = false;

        for vma in mem.semantic_vmas.overlapping(start, end) {
            if vma.start > covered_to {
                // Gap before this interval → unmapped hole. Keep walking:
                // the VMAs past the hole still decide the per-VMA verdict.
                fully_mapped = false;
                covered_to = vma.start;
            }
            if vma.end > covered_to {
                let segment_end = vma.end.min(end);
                let prot = LinuxProtFlags::from_bits_retain(
                    (u64::from(vma.read) * carrick_abi::LINUX_PROT_READ)
                        | (u64::from(vma.write) * carrick_abi::LINUX_PROT_WRITE)
                        | (u64::from(vma.execute) * carrick_abi::LINUX_PROT_EXEC),
                );
                match covered.last_mut() {
                    Some(last)
                        if last.end == covered_to
                            && last.prot == prot
                            && last.provenance == vma.provenance =>
                    {
                        last.end = segment_end;
                    }
                    _ => covered.push(MadviseCoveredSegment {
                        start: covered_to,
                        end: segment_end,
                        prot,
                        provenance: vma.provenance,
                    }),
                }
                if !vma.write {
                    writable = false;
                }
                if matches!(
                    vma.provenance,
                    VmaBackingProvenance::SharedAnonymous | VmaBackingProvenance::SharedFile
                ) {
                    shared = true;
                }
                if !vma.provenance.allows_wipe_on_fork() {
                    all_private_anon = false;
                }
                if matches!(vma.provenance, VmaBackingProvenance::SpecialKernelSynthetic) {
                    any_special = true;
                }
                if vma.droppable {
                    any_droppable = true;
                }
                covered_to = vma.end;
            }
            if covered_to >= end {
                break;
            }
        }
        if covered_to < end {
            fully_mapped = false;
        }
        let locked = mem.locked_ranges.iter().any(|r| {
            let (rs, re) = (r.start().raw(), r.end().raw());
            rs < end && re > start
        });
        MadviseRangeMeta {
            fully_mapped,
            covered,
            writable,
            shared,
            all_private_anon,
            any_special,
            any_droppable,
            locked,
        }
    }

    fn membarrier(&self, command: u64, flags: u64) -> DispatchOutcome {
        // membarrier(2) command bits (also the CMD_QUERY reply mask). carrick
        // has a globally-coherent guest address space, so every barrier is a
        // no-op that succeeds once its precondition (registration, for the
        // expedited-private variants) is met.
        const CMD_GLOBAL: u64 = 1 << 0;
        const CMD_GLOBAL_EXPEDITED: u64 = 1 << 1;
        const CMD_REGISTER_GLOBAL_EXPEDITED: u64 = 1 << 2;
        const CMD_PRIVATE_EXPEDITED: u64 = 1 << 3;
        const CMD_REGISTER_PRIVATE_EXPEDITED: u64 = 1 << 4;
        const CMD_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 1 << 5;
        const CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 1 << 6;
        const SUPPORTED: u64 = CMD_GLOBAL
            | CMD_GLOBAL_EXPEDITED
            | CMD_REGISTER_GLOBAL_EXPEDITED
            | CMD_PRIVATE_EXPEDITED
            | CMD_REGISTER_PRIVATE_EXPEDITED
            | CMD_PRIVATE_EXPEDITED_SYNC_CORE
            | CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE;

        // No advertised command takes a flag (only the un-advertised RSEQ CPU
        // variant does), so any non-zero flags arg is EINVAL — checked before
        // the command, matching the kernel (and QUERY|flags=1 → EINVAL).
        if flags != 0 {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        if command == LINUX_MEMBARRIER_CMD_QUERY {
            return DispatchOutcome::returned_u64_or_errno(SUPPORTED);
        }
        match command {
            // A global (or global-expedited) barrier needs no registration.
            CMD_GLOBAL | CMD_GLOBAL_EXPEDITED | CMD_REGISTER_GLOBAL_EXPEDITED => {
                DispatchOutcome::Returned { value: 0 }
            }
            // Registering an expedited-private intent records the readiness bit
            // so a subsequent expedited-private barrier succeeds.
            CMD_REGISTER_PRIVATE_EXPEDITED => {
                self.proc.lock().membarrier_ready |= CMD_PRIVATE_EXPEDITED;
                DispatchOutcome::Returned { value: 0 }
            }
            CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
                self.proc.lock().membarrier_ready |= CMD_PRIVATE_EXPEDITED_SYNC_CORE;
                DispatchOutcome::Returned { value: 0 }
            }
            // An expedited-private barrier requires prior registration; an
            // unregistered call is EPERM (Linux >= 4.16).
            CMD_PRIVATE_EXPEDITED | CMD_PRIVATE_EXPEDITED_SYNC_CORE => {
                if self.proc.lock().membarrier_ready & command != 0 {
                    DispatchOutcome::Returned { value: 0 }
                } else {
                    DispatchOutcome::errno(LINUX_EPERM)
                }
            }
            _ => DispatchOutcome::errno(LINUX_EINVAL),
        }
    }

    fn add_locked_range(&self, range: crate::vfs::GuestMemoryRange) -> Result<(), LinuxErrno> {
        self.check_locked_range_limit(range)?;
        locked_ranges_insert(&mut self.mem().lock().locked_ranges, range);
        Ok(())
    }

    fn remove_locked_range(&self, range: crate::vfs::GuestMemoryRange) {
        locked_ranges_remove(&mut self.mem().lock().locked_ranges, range);
    }

    pub(super) fn lock_current_mappings(
        &self,
        memory: &mut impl CurrentMmMemory,
        onfault: bool,
    ) -> Result<(), LinuxErrno> {
        let mem_authority_40 = self.mem();
        let mem = mem_authority_40.lock();
        let mut ranges = mem.locked_ranges.clone();
        if let Some(regions) = &mem.address_space_regions {
            for region in regions {
                if let Some(range) =
                    crate::vfs::GuestMemoryRange::new(GuestVa(region.start), GuestVa(region.end))
                {
                    locked_ranges_insert(&mut ranges, range);
                }
            }
        }
        for region in &mem.dynamic_maps {
            if let Some(range) =
                crate::vfs::GuestMemoryRange::new(GuestVa(region.start), GuestVa(region.end))
            {
                locked_ranges_insert(&mut ranges, range);
            }
        }
        drop(mem);

        let creds = self.cred_snapshot();
        if !creds.euid.is_root() {
            let limit = self.effective_resource_limit(LINUX_RLIMIT_MEMLOCK).rlim_cur;
            if limit == 0 {
                return Err(LINUX_EPERM);
            }
            if locked_ranges_total(&ranges) > limit {
                return Err(LINUX_ENOMEM);
            }
        }
        if !onfault {
            for range in &ranges {
                self.populate_resident_range(memory, *range)?;
            }
        }
        self.mem().lock().locked_ranges = ranges;
        Ok(())
    }

    pub(super) fn check_locked_range_limit(
        &self,
        range: crate::vfs::GuestMemoryRange,
    ) -> Result<(), LinuxErrno> {
        let creds = self.cred_snapshot();
        let memlock_limit = if creds.euid.is_root() {
            None
        } else {
            Some(self.effective_resource_limit(LINUX_RLIMIT_MEMLOCK).rlim_cur)
        };
        let mem_authority_36 = self.mem();
        let mem = mem_authority_36.lock();
        let mut next = mem.locked_ranges.clone();
        locked_ranges_insert(&mut next, range);
        if let Some(limit) = memlock_limit {
            if limit == 0 {
                return Err(LINUX_EPERM);
            }
            if locked_ranges_total(&next) > limit {
                return Err(LINUX_ENOMEM);
            }
        }
        Ok(())
    }

    define_syscall! {
        fn readahead(this, cx, fd: Fd, _offset: u64, _count: u64) {
            // Linux readahead(2): fd must be a valid open descriptor; EBADF is
            // checked FIRST (EBADF), THEN the mapping type (EINVAL).
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let status_flags = open_file.description.common().status_flags();
            // An O_PATH descriptor (or an O_WRONLY fd) is not open for reading.
            if LinuxOpenFlags::from_bits_truncate(status_flags).contains(LinuxOpenFlags::PATH)
                || (status_flags & carrick_abi::LINUX_O_ACCMODE) == carrick_abi::LINUX_O_WRONLY
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let Some(desc) = open_file.description.read() else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            // readahead only applies to objects with a readahead-capable
            // address space — regular files (and block devices). Pipes, FIFOs,
            // sockets, char devices, directories, and the anonymous fd types
            // (eventfd/timerfd/epoll/…) all lack one and are EINVAL.
            let applicable = matches!(
                &*desc,
                OpenDescription::File { .. } | OpenDescription::HostFile { .. }
            );
            if !applicable {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn fadvise64(this, cx, fd: Fd, _offset: u64, _len: u64, advice: u64) {
            if !this.fd_is_valid(fd.0) && !is_stdio_fd(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // Linux's generic_fadvise rejects a pipe/FIFO with ESPIPE (checked
            // before the advice value), so posix_fadvise04 (a real pipe) → ESPIPE.
            // A /dev chardev is also a HostPipe in carrick but is NOT a FIFO, so
            // ask the host kernel (fstat S_IFIFO) rather than keying on the
            // variant alone.
            if let Some(open_file) = this.open_file(fd.0) {
                let is_fifo = match open_file.description.read().as_deref() {
                    Some(OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. }) => true,
                    Some(OpenDescription::HostPipe { host_fd, .. }) => {
                        let mut st: libc::stat = unsafe { core::mem::zeroed() };
                        let fstat_ok = unsafe { libc::fstat(host_fd.raw(), &mut st) } == 0;
                        fstat_ok
                            && (st.st_mode as u32 & libc::S_IFMT as u32)
                                == libc::S_IFIFO as u32
                    }
                    _ => false,
                };
                if is_fifo {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
            }
            // POSIX_FADV_{NORMAL,RANDOM,SEQUENTIAL,WILLNEED,DONTNEED,NOREUSE} =
            // 0..=5 on aarch64 (asm-generic values); anything else is EINVAL
            // (posix_fadvise03). advice is u64, so a negative arg is huge → caught.
            if advice > 5 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn sys_membarrier(this, cx, command: u64, flags: u64) {
            Ok(this.membarrier(command, flags))
        }

        fn userfaultfd(this, cx, _flags: u64) {
            // Container POLICY, not kernel emulation. The differential oracle
            // (native arm64 Docker) denies userfaultfd(2) in its default
            // seccomp profile unless the caller holds CAP_SYS_PTRACE, and the
            // deny fires on the syscall NUMBER alone — before flag validation,
            // so UFFD_USER_MODE_ONLY and even invalid flag bits all yield
            // EPERM (uffdpolicy probe; LTP userfaultfd01/02/06 TCONF with
            // "userfaultfd() requires CAP_SYS_PTRACE ... EPERM"). Carrick's
            // guest runs with the same Docker-default capability set, which
            // lacks CAP_SYS_PTRACE → EPERM.
            //
            // WITH the capability the call would reach the kernel, and
            // carrick's kernel does not implement userfaultfd — exactly what
            // the synthetic /proc/config.gz declares ("# CONFIG_USERFAULTFD
            // is not set", the same answer the oracle's LinuxKit kernel
            // gives) — so that path is an honest ENOSYS, not a fake fd.
            let _ = &this;
            // Per-TASK capability check (`has_effective_capability`), never a
            // process-global one: the carrier hosts many Linux tasks, and a
            // post-setuid task holds nothing at all.
            if !crate::dispatch::creds::has_effective_capability(
                cx.kernel,
                crate::namespace::process::CAP_SYS_PTRACE,
            ) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            Ok(DispatchOutcome::errno(LINUX_ENOSYS))
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
            Ok(DispatchOutcome::errno(LINUX_ENOSYS))
        }

        mm_mutation fn msync(this, cx, address: GuestPtr, length: u64, flags: u64) {
            let permit = cx.mm_mutation.host_alias_permit();
            let _host_alias_dispatch = this.begin_host_alias_dispatch(&permit);
            if flags & !(LINUX_MS_ASYNC | LINUX_MS_INVALIDATE | LINUX_MS_SYNC) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if flags & LINUX_MS_ASYNC != 0 && flags & LINUX_MS_SYNC != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // msync requires a page-aligned start address (Linux checks this
            // before anything else). CPython's mmap.flush(offset, size) calls
            // msync(data + offset, size, ...), so flush(1, n) must EINVAL —
            // test_mmap.test_flush_return_value asserts it on Linux.
            if !address.0.is_multiple_of(this.linux_page_size()) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let alloc = {
                let mem_authority_20 = this.mem();
                let mem = mem_authority_20.lock();
                mem.shared
                    .live()
                    .iter()
                    .find(|a| a.guest_addr == address.0)
                    .cloned()
            };
            if let Some(alloc) = alloc {
                // Write a SharedFile backing's dirty bytes back without freeing.
                this.writeback_shared(&mut *cx.memory, &alloc);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if cx.memory.read_bytes(address.0, 1).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        mm_mutation fn mlock(this, cx, address: GuestPtr, length: u64) {
            let permit = cx.mm_mutation.host_alias_permit();
            let _host_alias_dispatch = this.begin_host_alias_dispatch(&permit);
            let page_size = this.linux_page_size();
            let Some(range) = page_rounded_range(address, length, page_size)? else {
                return Ok(DispatchOutcome::Returned { value: 0 });
            };
            let committed_vma_covers_range = guest_vma_covers_locked(
                &this.mem().lock(),
                range.start().raw(),
                range.len() as u64,
            );
            validate_mlock_range(
                &mut *cx.memory,
                range,
                true,
                page_size,
                committed_vma_covers_range,
            )?;
            this.populate_resident_range(&mut *cx.memory, range)?;
            this.add_locked_range(range)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        mm_mutation fn munlock(this, cx, address: GuestPtr, length: u64) {
            let permit = cx.mm_mutation.host_alias_permit();
            let _host_alias_dispatch = this.begin_host_alias_dispatch(&permit);
            let page_size = this.linux_page_size();
            let Some(range) = page_rounded_range(address, length, page_size)? else {
                return Ok(DispatchOutcome::Returned { value: 0 });
            };
            let committed_vma_covers_range = guest_vma_covers_locked(
                &this.mem().lock(),
                range.start().raw(),
                range.len() as u64,
            );
            validate_mlock_range(
                &mut *cx.memory,
                range,
                false,
                page_size,
                committed_vma_covers_range,
            )?;
            this.remove_locked_range(range);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        mm_mutation fn mlockall(this, cx, flags: u64) {
            let permit = cx.mm_mutation.host_alias_permit();
            let _host_alias_dispatch = this.begin_host_alias_dispatch(&permit);
            let Some(flags) = LinuxMlockallFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if flags.is_empty()
                || flags.contains(LinuxMlockallFlags::ONFAULT)
                    && !flags.intersects(
                        LinuxMlockallFlags::CURRENT | LinuxMlockallFlags::FUTURE,
                    )
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if flags.contains(LinuxMlockallFlags::CURRENT) {
                this.lock_current_mappings(
                    &mut *cx.memory,
                    flags.contains(LinuxMlockallFlags::ONFAULT),
                )?;
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        mm_mutation fn munlockall(this, cx) {
            let permit = cx.mm_mutation.host_alias_permit();
            let _host_alias_dispatch = this.begin_host_alias_dispatch(&permit);
            this.mem().lock().locked_ranges.clear();
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        mm_mutation fn mlock2(this, cx, address: GuestPtr, length: u64, flags: u64) {
            let permit = cx.mm_mutation.host_alias_permit();
            let _host_alias_dispatch = this.begin_host_alias_dispatch(&permit);
            let Some(flags) = LinuxMlock2Flags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let page_size = this.linux_page_size();
            let Some(range) = page_rounded_range(address, length, page_size)? else {
                return Ok(DispatchOutcome::Returned { value: 0 });
            };
            let committed_vma_covers_range = guest_vma_covers_locked(
                &this.mem().lock(),
                range.start().raw(),
                range.len() as u64,
            );
            validate_mlock_range(
                &mut *cx.memory,
                range,
                !flags.contains(LinuxMlock2Flags::ONFAULT),
                page_size,
                committed_vma_covers_range,
            )?;
            if !flags.contains(LinuxMlock2Flags::ONFAULT) {
                this.populate_resident_range(&mut *cx.memory, range)?;
            }
            this.add_locked_range(range)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        mm_mutation fn mincore(this, cx, address: GuestPtr, length: u64, vec: GuestPtr) {
            let permit = cx.mm_mutation.host_alias_permit();
            let _host_alias_dispatch = this.begin_host_alias_dispatch(&permit);
            let memory = &mut *cx.memory;
            let page_size = this.linux_page_size();
            // Linux requires a page-aligned start address, else EINVAL (this is
            // what Go's TestMincoreErrorSign checks — the errno must be -EINVAL).
            if !address.0.is_multiple_of(page_size) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // Linux returns ENOMEM unless the WHOLE [address, address+length)
            // range is mapped. Ask the VMA table, which is carrick's authority
            // for what is mapped, rather than probing whether a read happens to
            // succeed: a read can succeed through backing whose VMA is gone --
            // which is exactly what `MADV_DONTFORK` leaves behind in a child,
            // where Linux answers ENOMEM -- and probing guest memory to answer
            // a query is itself a side effect. It also bounds the work by the
            // VMA count instead of the page count, so a guest-controlled
            // `length` no longer walks page by page.
            //
            // Reject the overflowing range before anything else, and note
            // that coverage is also what BOUNDS the residency vector below: no
            // VMA spans a guest-controlled `length` near `u64::MAX`, so such a
            // call answers ENOMEM here instead of reaching a petabyte
            // `vec![1u8; pages]` and an uncatchable allocation abort.
            if address.0.checked_add(length - 1).is_none() {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            {
                let mem_authority = this.mem();
                let mem = mem_authority.lock();
                if !guest_vma_covers_locked(&mem, address.0, length) {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            }
            let pages = length.div_ceil(page_size);
            let bytes = this
                .mincore_residency_vector(memory, address.0, pages, page_size)
                .unwrap_or_else(|| vec![1u8; pages as usize]);
            memory.write_bytes(vec.0, &bytes)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        mm_mutation fn madvise(this, cx, address: GuestPtr, length: u64, advice: u64) {
            let permit = cx.mm_mutation.host_alias_permit();
            let mut host_alias_dispatch = this.begin_conditional_vma_dispatch(&permit);
            let page_size = this.linux_page_size();
            if !address.0.is_multiple_of(page_size) || !linux_madvise_advice_is_supported(advice) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            let Ok(length) = usize::try_from(length) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            // Validity is derived from carrick's VMA metadata, NEVER by touching
            // a page: a physical probe SIGBUSes the runtime on a read-only /
            // past-EOF file page (madvise02 MADV_DONTNEED on a locked read-only
            // MAP_SHARED file) and false-ENOMEMs a mapped-but-PROT_NONE range
            // (madvise05 MADV_WILLNEED on an mprotect(PROT_NONE) anon region).
            // An unmapped hole anywhere in [address, address+length) → ENOMEM,
            // but only once every visited VMA has accepted the advice: a
            // per-VMA rejection (EINVAL) is reported first, and an advice that
            // acts on pages acts on the mapped segments before the hole is
            // reported (madvise02 expects EINVAL, not ENOMEM, for
            // MADV_WIPEONFORK over one shared page plus 15 unmapped ones).
            let Some(raw_end) = address.0.checked_add(length as u64) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let Some(end) = align_up_u64(raw_end, page_size) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let meta = this.madvise_range_meta(address.0, end);
            if meta.covered.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            let hole_verdict = if meta.fully_mapped {
                DispatchOutcome::Returned { value: 0 }
            } else {
                DispatchOutcome::errno(LINUX_ENOMEM)
            };
            match advice {
                LINUX_MADV_DONTFORK | LINUX_MADV_DOFORK | LINUX_MADV_WIPEONFORK | LINUX_MADV_KEEPONFORK => {
                    if advice == LINUX_MADV_DOFORK && meta.any_special {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    if advice == LINUX_MADV_WIPEONFORK && !meta.all_private_anon {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    if advice == LINUX_MADV_KEEPONFORK && meta.any_droppable {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    let (copy_update, child_update) = match advice {
                        LINUX_MADV_DONTFORK => (Some(carrick_abi::VmaForkCopyPolicy::Omit), None),
                        LINUX_MADV_DOFORK => (Some(carrick_abi::VmaForkCopyPolicy::Inherit), None),
                        LINUX_MADV_WIPEONFORK => (None, Some(carrick_abi::VmaForkChildPolicy::ZeroInChild)),
                        LINUX_MADV_KEEPONFORK => (None, Some(carrick_abi::VmaForkChildPolicy::Preserve)),
                        _ => unreachable!(),
                    };
                    this.update_madvise_vma_policy(address.0, end - address.0, copy_update, child_update, None);
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(hole_verdict);
                }
                LINUX_MADV_DONTDUMP | LINUX_MADV_DODUMP => {
                    // Not an advisory no-op: Linux keeps a DONTDUMP VMA in the
                    // core's program headers but writes no contents for it, so
                    // the policy has to reach the dump. carrick rejected both
                    // with EINVAL, which is what `memflagmatrix`'s
                    // `madvise_hints_matrix_ok` caught -- the oracle returns 0.
                    let dump_update = if advice == LINUX_MADV_DONTDUMP {
                        carrick_abi::VmaDumpPolicy::Omit
                    } else {
                        carrick_abi::VmaDumpPolicy::Include
                    };
                    this.update_madvise_vma_policy(
                        address.0,
                        end - address.0,
                        None,
                        None,
                        Some(dump_update),
                    );
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(hole_verdict);
                }
                LINUX_MADV_DONTNEED => {
                    // Linux can_madv_lru_vma rejects VM_LOCKED (also VM_HUGETLB /
                    // VM_PFNMAP, which carrick does not model) with EINVAL before
                    // dropping any page — derived from the locked-range table.
                    if meta.locked {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    // Drop the pages by zeroing the writable PRIVATE/anonymous
                    // backing — only such mappings get zero-fill-on-next-access.
                    // A read-only mapping must NOT be written (would SIGBUS the
                    // runtime); a MAP_SHARED mapping must NOT be written either —
                    // for a shared FILE mapping zero_backing writes straight
                    // through to the file and CORRUPTS it, and Linux
                    // MADV_DONTNEED on a shared mapping does not zero (the next
                    // access re-faults the original content from the file). In
                    // all those cases treat DONTNEED as a success no-op, matching
                    // Linux dropping clean cache pages. zero_backing writes the
                    // host backing directly (same call the MAP_FIXED/munmap-reuse
                    // scrub uses), bypassing the guest write-protection gate.
                    // The pages are dropped per mapped segment: the segments
                    // ahead of and past a hole are still discarded, and the
                    // hole itself is reported afterwards.
                    for segment in &meta.covered {
                        let Ok(segment_len) = usize::try_from(segment.end - segment.start) else {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        };
                        if segment.provenance == VmaBackingProvenance::PrivateFile {
                            this.mark_vma_dispatch(&mut host_alias_dispatch);
                            if let Err(errno) = this.discard_private_file_segment(cx.memory, segment) {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                            continue;
                        }
                        if meta.writable && !meta.shared {
                            if cx.memory.zero_backing(segment.start, segment_len).is_err() {
                                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                            }
                        }
                        if meta.all_private_anon {
                            this.mark_range_nonresident(segment.start, segment_len as u64);
                            // Discarding the pages puts them back where a fresh
                            // anonymous mapping starts: not resident, and resident
                            // again on the NEXT touch. Re-arm the first-touch fault
                            // so that next touch is observed -- without this the
                            // range stays non-resident forever and `mincore` reports
                            // a written page as absent, which is the opposite of the
                            // error it used to make.
                            if std::env::var("CARRICK_MINCORE_EXACT").as_deref() != Ok("0")
                                && cx
                                    .memory
                                    .resident_pages(GuestVa(segment.start), 1, this.linux_page_size())
                                    .is_none()
                                && cx.memory.protect_range(segment.start, segment_len, 0).is_ok()
                            {
                                // This mapping stays readable; its next
                                // first-touch publication must restore the
                                // exact semantic VMA R/W/X permission.
                                // Reconstructing only READ|WRITE drops EXEC from
                                // V8's discarded code-cage pages and publishes
                                // the generated-code leaf UXN.
                                this.track_resident_fault_range(
                                    segment.start,
                                    segment_len as u64,
                                    segment.prot,
                                );
                                cx.memory.set_mapping_protection(
                                    segment.start,
                                    segment_len,
                                    false,
                                    !segment.prot.contains(LinuxProtFlags::WRITE),
                                );
                            }
                        }
                    }
                    return Ok(hole_verdict);
                }
                // MADV_FREE only applies to private anonymous mappings; a shared
                // mapping (file- or anon-backed) → EINVAL.
                LINUX_MADV_FREE if meta.shared => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                _ => {}
            }
            Ok(hole_verdict)
        }
    }
}

#[cfg(test)]
mod tests;
