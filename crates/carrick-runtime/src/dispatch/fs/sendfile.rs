//! `sendfile`/`copy_file_range` data-movement helpers: the offset resolver,
//! the in-memory/HostFile byte reader, and the Darwin `copyfile`/`fclonefileat`
//! fast path. Split out of `dispatch/fs.rs` (WS-F3) as `impl SyscallDispatcher`
//! methods; the move is type-transparent to `self.…` callers.
use super::*;
use crate::linux_abi::LinuxErrno;

/// `CARRICK_DARWIN_COPYFILE_FAST_PATH=0` disables the whole-file
/// `copyfile`/`fclonefileat` fast path in `copy_file_range`, falling back to
/// the ordinary read-then-write body. Default ON; the hatch exists so the
/// fast path can be ablated when attributing a data-corruption bug.
#[cfg(target_os = "macos")]
fn darwin_copyfile_fast_path_disabled() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISABLED.get_or_init(|| {
        std::env::var_os("CARRICK_DARWIN_COPYFILE_FAST_PATH").is_some_and(|value| value == "0")
    })
}

impl<'a> FsView<'a> {
    /// copy_file_range(2): like sendfile but file-to-file with independent
    /// in/out offset pointers. coreutils `cat`/`cp` and apt/dpkg use it for
    /// efficient copies; it was unimplemented and the panic-on-unknown guard
    /// turned that into a hard abort. We read from in_fd at its (pointer or
    /// current) offset and write to out_fd, reusing the sendfile machinery.
    #[cfg(target_os = "macos")]
    pub(super) fn try_darwin_copyfile_range_fast_path(
        &self,
        in_fd: i32,
        in_offset: usize,
        off_in_addr: u64,
        out_fd: i32,
        off_out_addr: u64,
        count: usize,
    ) -> Result<Option<DispatchOutcome>, DispatchError> {
        if off_in_addr != 0 || off_out_addr != 0 || in_offset != 0 {
            return Ok(None);
        }
        // Exact ablation hatch. This fast path validates its preconditions by
        // reading both HOST fd offsets, which forked guest processes share, so
        // it is the leading suspect for the 1-in-10 corrupt Go build-cache
        // archive. Shipping ON, with `=0` to bisect it, is the rule; a fast
        // path with no way to turn it off cannot be attributed.
        if darwin_copyfile_fast_path_disabled() {
            return Ok(None);
        }

        let Some(input) = self.host_file_copy_info(in_fd) else {
            return Ok(None);
        };
        let Some(output) = self.host_file_copy_info(out_fd) else {
            return Ok(None);
        };
        if !output.writable {
            return Ok(Some(DispatchOutcome::errno(LINUX_EBADF)));
        }
        if input.size == 0
            || output.size != 0
            || count
                < usize::try_from(input.size)
                    .map_err(|_| DispatchError::LengthTooLarge(input.size))?
        {
            return Ok(None);
        }
        let (Some(input_offset), Some(output_offset)) = (
            host_fd_offset(HostFd(input.host_fd)),
            host_fd_offset(HostFd(output.host_fd)),
        ) else {
            return Ok(None);
        };
        if input_offset != 0 || output_offset != 0 {
            return Ok(None);
        }

        match crate::darwin_fs::copyfile_clone_or_data(input.host_fd, output.host_fd, input.size) {
            Ok(Some(result)) => {
                let copied = result.bytes();
                if !set_host_fd_offset(HostFd(input.host_fd), copied)
                    || !set_host_fd_offset(HostFd(output.host_fd), copied)
                {
                    return Ok(None);
                }
                Ok(Some(DispatchOutcome::Returned {
                    value: i64::try_from(copied)
                        .map_err(|_| DispatchError::LengthTooLarge(copied))?,
                }))
            }
            Ok(None) => Ok(None),
            Err(errno) => Ok(Some(DispatchOutcome::errno(errno))),
        }
    }

    /// True iff `a` and `b` refer to the SAME underlying file — the same fd, or
    /// two host fds on the same `(st_dev, st_ino)`. Used by `copy_file_range` to
    /// reject an overlapping copy onto the same file (Linux returns EINVAL). A
    /// non-host description, or a host `fstat` failure, is treated as "cannot
    /// prove same file" (false) so a legitimate distinct-file copy is never
    /// rejected.
    pub(super) fn copy_same_file(&self, a: i32, b: i32) -> bool {
        if a == b {
            return true;
        }
        match (self.host_fd_dev_ino(a), self.host_fd_dev_ino(b)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        }
    }

    fn host_fd_dev_ino(&self, fd: i32) -> Option<(i64, u64)> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read()?;
        let OpenDescription::HostFile { host_fd, .. } = &*open else {
            return None;
        };
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(host_fd.raw(), st.as_mut_ptr()) } != 0 {
            return None;
        }
        let st = unsafe { st.assume_init() };
        Some((st.st_dev as i64, st.st_ino))
    }

    // Only the Darwin copyfile/fclonefileat fast path (above, macOS-gated) uses
    // this; HostFileCopyInfo is itself macOS-only. On Linux copy_file_range
    // falls through to the portable buffer-copy path.
    #[cfg(target_os = "macos")]
    fn host_file_copy_info(&self, fd: i32) -> Option<HostFileCopyInfo> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read()?;
        let OpenDescription::HostFile {
            host_fd, writable, ..
        } = &*open
        else {
            return None;
        };
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(host_fd.raw(), st.as_mut_ptr()) } != 0 {
            return None;
        }
        let st = unsafe { st.assume_init() };
        if st.st_size < 0 {
            return None;
        }
        Some(HostFileCopyInfo {
            host_fd: host_fd.raw(),
            size: st.st_size as u64,
            writable: *writable,
        })
    }

    pub(super) fn sendfile_offset(
        &self,
        in_fd: i32,
        offset_address: u64,
        memory: &impl CurrentMmMemory,
    ) -> Result<Result<usize, LinuxErrno>, DispatchError> {
        if offset_address != 0 {
            return match read_u64(memory, offset_address) {
                Ok(offset) => {
                    Ok(Ok(usize::try_from(offset)
                        .map_err(|_| DispatchError::LengthTooLarge(offset))?))
                }
                Err(errno) => Ok(Err(errno)),
            };
        }
        let Some(in_file) = self.open_file(in_fd) else {
            return Ok(Err(LINUX_EBADF));
        };
        let Some(open) = in_file.description.read() else {
            return Ok(Err(LINUX_EINVAL));
        };
        match &*open {
            OpenDescription::Closed { .. } => Ok(Err(LINUX_EBADF)),
            OpenDescription::File { offset, .. }
            | OpenDescription::InMemoryFile { offset, .. }
            | OpenDescription::SyntheticFile { offset, .. } => Ok(Ok(*offset)),
            // HostFile: current offset is the kernel's; query via lseek.
            OpenDescription::HostFile { host_fd, .. } => {
                match (unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR) })
                    .host_syscall_errno()
                {
                    Ok(cur) => Ok(Ok(cur as usize)),
                    Err(errno) => Ok(Err(errno)),
                }
            }
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::Pidfd { .. }
            | OpenDescription::Inotify { .. }
            | OpenDescription::Fanotify { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::SignalFd { .. }
            | OpenDescription::PerfEvent { .. }
            | OpenDescription::FsContext { .. }
            | OpenDescription::Mqueue { .. }
            | OpenDescription::BpfMap { .. }
            | OpenDescription::BpfProg { .. }
            | OpenDescription::SyntheticDevice { .. }
            | OpenDescription::Netlink { .. }
            | OpenDescription::InMemorySocket { .. } => Ok(Err(LINUX_EINVAL)),
        }
    }

    pub(super) fn sendfile_bytes(
        &self,
        in_fd: i32,
        offset: usize,
        count: usize,
    ) -> Result<Vec<u8>, LinuxErrno> {
        let Some(in_file) = self.open_file(in_fd) else {
            return Err(LINUX_EBADF);
        };
        let Some(open) = in_file.description.read() else {
            return Err(LINUX_EINVAL);
        };
        // HostFile / File: pread/read the requested window. Cap the buffer:
        // callers (Go's poll.SendFile) pass count = INT_MAX, and a naive
        // `vec![0u8; count]` would zero-fill 2 GiB per call. Linux sendfile is
        // free to transfer fewer than `count` bytes (the caller loops), so read
        // at most one chunk; pread/read_at then truncates to what the file holds.
        const SENDFILE_CHUNK: usize = 1 << 24; // 16 MiB
        let want = count.min(SENDFILE_CHUNK);
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            let mut buf = vec![0u8; want];
            let n = unsafe {
                libc::pread(
                    host_fd.raw(),
                    buf.as_mut_ptr() as *mut _,
                    want,
                    offset as libc::off_t,
                )
            };
            let n = n.host_syscall_errno()?;
            buf.truncate(n as usize);
            return Ok(buf);
        }
        let bytes = match &*open {
            OpenDescription::File { contents, .. } => {
                let file_len = contents.len()?;
                let available =
                    usize::try_from(file_len.saturating_sub(offset as u64)).unwrap_or(usize::MAX);
                let read_len = want.min(available);
                if read_len == 0 {
                    Vec::new()
                } else {
                    let mut buf = vec![0u8; read_len];
                    let n = contents.read_at(offset as u64, &mut buf)?;
                    buf.truncate(n);
                    buf
                }
            }
            OpenDescription::SyntheticFile { contents, .. } => {
                let available = contents.get(offset..).unwrap_or_default();
                let write_len = available.len().min(want);
                available[..write_len].to_vec()
            }
            OpenDescription::InMemoryFile { contents, .. } => {
                let data = contents.read();
                data.read_range(offset, want)
            }
            OpenDescription::HostFile { .. } => return Err(LINUX_EINVAL),
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::Pidfd { .. }
            | OpenDescription::Inotify { .. }
            | OpenDescription::Fanotify { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::SignalFd { .. }
            | OpenDescription::PerfEvent { .. }
            | OpenDescription::FsContext { .. }
            | OpenDescription::Mqueue { .. }
            | OpenDescription::BpfMap { .. }
            | OpenDescription::BpfProg { .. }
            | OpenDescription::SyntheticDevice { .. }
            | OpenDescription::Netlink { .. }
            | OpenDescription::InMemorySocket { .. } => return Err(LINUX_EINVAL),
            OpenDescription::Closed { .. } => return Err(LINUX_EBADF),
        };
        Ok(bytes)
    }

    define_syscall! {
        fn sendfile(this, cx, out_fd: Fd, in_fd: Fd, offset: GuestPtr, count: u64) {
            let tid = cx.tid();

            let out_fd: Fd = out_fd;
            let in_fd: Fd = in_fd;
            let offset_address = offset.0;
            let count =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let memory = &mut *cx.memory;
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            // in_fd must be READABLE — sendfile reads the source from it. An
            // O_WRONLY in_fd → EBADF (LTP sendfile03 case 4). A bad in_fd is
            // caught as EBADF by sendfile_offset below; out_fd writability is
            // enforced on the write path (sendfile03 case 2 already passes).
            if let Some(in_file) = this.open_file(in_fd.0)
                && in_file.description.common().status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }

            // memfd_secret cannot be a sendfile endpoint (no file read/write
            // methods) → EINVAL (memfd_secret(2)).
            if this.fd_is_secretmem(in_fd.0) || this.fd_is_secretmem(out_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let mut offset = this.sendfile_offset(in_fd.0, offset_address, memory)??;

            // Darwin-native fast path: a regular file -> socket uses macOS
            // sendfile(2) (BSD-style, in-kernel, zero-copy). It honors socket
            // backpressure by returning a partial `len` + EAGAIN, which Go's
            // netpoller drives via EPOLLOUT — so a large transfer does NOT hang
            // the way a userspace read-into-buffer-then-write does. Non-socket
            // destinations and in-memory file sources fall through to the buffer
            // path below.
            if let (Some(file_fd), Some(sock_fd)) =
                (this.regular_host_file_fd(in_fd.0), this.host_socket_fd(out_fd.0))
            {
                // SAFETY: both are live host fds owned by these guest fds. The
                // portable wrapper hides the Darwin (6-arg, in/out len) vs Linux
                // (4-arg, swapped fds) signature: returns bytes sent, or -1
                // (errno set), so `host_syscall_errno()` below still works.
                let rc = unsafe {
                    carrick_portable::sendfile_to_socket(
                        file_fd.get(),
                        sock_fd.get(),
                        offset as i64,
                        count,
                    )
                };
                let sent = rc.max(0) as usize;
                let advance_and_return = |offset: usize,
                                          sent: usize,
                                          memory: &mut dyn CurrentMmMemory|
                 -> Result<DispatchOutcome, DispatchError> {
                    let new_off = offset.saturating_add(sent);
                    if offset_address == 0 {
                        // macOS sendfile takes an explicit `offset` and does NOT
                        // advance the file's kernel offset; do it so a follow-up
                        // read/sendfile (no explicit offset) continues correctly.
                        unsafe { libc::lseek(file_fd.get(), new_off as libc::off_t, libc::SEEK_SET) };
                    } else if memory
                        .write_bytes(offset_address, &(new_off as u64).to_ne_bytes())
                        .is_err()
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    Ok(DispatchOutcome::returned_len_or_errno(sent))
                };
                match (rc as i64).host_syscall_errno() {
                    Ok(_) => return advance_and_return(offset, sent, memory),
                    Err(e) if e == LINUX_EAGAIN => {
                        if sent > 0 {
                            // Partial transfer before the socket filled: report it
                            // (Go advances and loops).
                            return advance_and_return(offset, sent, memory);
                        }
                        return Ok(if this.io_is_nonblocking(out_fd.0, 0) {
                            DispatchOutcome::errno(LINUX_EAGAIN)
                        } else {
                            DispatchOutcome::WaitOnFds {
                                fds: match WaitFds::raw_one(sock_fd.get(), libc::POLLOUT)
                                    .with_guest_slots(
                                        &this.captured_file_table(),
                                        [in_fd.0, out_fd.0],
                                    )
                                {
                                    Ok(fds) => fds,
                                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                                },
                                timeout: None,
                                sig_mask: carrick_abi::WaitSigMask::NONE,
                                completion: FdWaitCompletion::Fd {
                                    on_timeout: LINUX_EAGAIN.guest_retval(),
                                },
                            }
                        });
                    }
                    // FreeBSD sendfile(2) only supports STREAM sockets; an AF_UNIX
                    // (especially DGRAM) out_fd is rejected with EINVAL. Linux
                    // sendfile handles any socket destination, so fall through to the
                    // buffer path below (read in_fd, then write_output_fd, which
                    // honours the socket's EAGAIN/ENOBUFS backpressure) when the host
                    // sendfile rejects the destination outright with nothing sent
                    // (LTP sendfile07 sendfiles to a full non-blocking AF_UNIX fd).
                    Err(e) if e == LINUX_EINVAL && sent == 0 => {}
                    Err(e) => return Ok(DispatchOutcome::errno(e)),
                }
            }

            let bytes = this.sendfile_bytes(in_fd.0, offset, count)?;
            let outcome = this.complete_wait_fd_authority(
                this.write_output_fd(out_fd.0, &bytes, tid),
                &this.captured_file_table(),
                [in_fd.0, out_fd.0],
            );
            let DispatchOutcome::Returned { value } = outcome else {
                return Ok(outcome);
            };
            let written = usize::try_from(value).unwrap_or(0);
            offset = offset.saturating_add(written);
            if offset_address == 0 {
                if let Some(open_file) = this.open_file(in_fd.0)
                    && let Some(mut open) = open_file.description.write()
                {
                    match &mut *open {
                        OpenDescription::File {
                            offset: current, ..
                        }
                        | OpenDescription::SyntheticFile {
                            offset: current, ..
                        } => *current = offset,
                        // HostFile reads via `pread` (sendfile_bytes), which does
                        // NOT advance the kernel offset; advance it explicitly so a
                        // follow-up sendfile/read with no explicit offset continues
                        // past what we just sent. Without this, busybox `cat` —
                        // which copies a file with `sendfile(out, file, NULL, n)` in
                        // a `while (n > 0)` loop — re-sends offset 0 forever.
                        OpenDescription::HostFile { host_fd, .. } => {
                            // SAFETY: host_fd is a live regular-file fd owned by
                            // this guest fd; lseek to an absolute position is benign.
                            unsafe {
                                libc::lseek(host_fd.raw(), offset as libc::off_t, libc::SEEK_SET);
                            }
                        }
                        _ => {}
                    }
                }
            } else if memory
                .write_bytes(offset_address, &(offset as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::Returned { value })

        }

        fn copy_file_range(this, cx, fd_in: Fd, off_in: GuestPtr, fd_out: Fd, off_out: GuestPtr, len: u64, flags: u64) {

            // Linux currently defines no copy_file_range flags. Reject unknown
            // bits before inspecting length or endpoints.
            if flags != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let tid = cx.tid();
            let in_fd: Fd = fd_in;
            let off_in_addr = off_in.0;
            let out_fd: Fd = fd_out;
            let off_out_addr = off_out.0;
            // Callers (coreutils `cat`) pass len = SSIZE_MAX and loop until EOF,
            // so cap each call to a bounded chunk rather than trying to allocate
            // a multi-exabyte buffer. A short return is legal for copy_file_range.
            let requested = usize::try_from(len).unwrap_or(usize::MAX);
            let memory = &mut *cx.memory;
            let count = requested.min(8 * 1024 * 1024);
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            // memfd_secret cannot be a copy_file_range endpoint (no file
            // read/write methods) → EINVAL (memfd_secret(2)).
            if this.fd_is_secretmem(in_fd.0) || this.fd_is_secretmem(out_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let in_offset = this.sendfile_offset(in_fd.0, off_in_addr, memory)??;
            // copy_file_range onto the SAME file with OVERLAPPING ranges must fail
            // EINVAL (Linux). Go's io.Copy(f, f) self-copy hits exactly this: fd_in
            // == fd_out, NULL/NULL offsets → identical (thus overlapping) ranges.
            // Without this carrick copied the bytes and returned a success count, so
            // Go's zero-copy hook recorded handled=true and skipped its generic
            // doubling fallback (TestCopyFile/CopyFileItself). Reject ONLY when the
            // fds are the same file AND the per-round ranges overlap — distinct
            // files and non-overlapping self-copies are untouched. Resolve the out
            // offset only in this branch to avoid touching the out fd on the common
            // cross-file path. Sits above the Darwin clone fast path so it can't
            // mis-handle an overlapping self-copy either.
            if this.copy_same_file(in_fd.0, out_fd.0) {
                let out_offset = this.sendfile_offset(out_fd.0, off_out_addr, memory)??;
                let in_end = in_offset.saturating_add(count);
                let out_end = out_offset.saturating_add(count);
                if in_offset < out_end && out_offset < in_end {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            }
            #[cfg(target_os = "macos")]
            if let Some(outcome) = this.try_darwin_copyfile_range_fast_path(
                in_fd.0,
                in_offset,
                off_in_addr,
                out_fd.0,
                off_out_addr,
                count,
            )? {
                return Ok(outcome);
            }
            let bytes = this.sendfile_bytes(in_fd.0, in_offset, count)?;
            if bytes.is_empty() {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            // Write side. off_out == NULL → write at out_fd's current position
            // (the common case: cat to a pipe/stdout). Non-NULL → pwrite at the
            // given offset on a real host fd and advance *off_out.
            let written = if off_out_addr == 0 {
                let outcome = this.complete_wait_fd_authority(
                    this.write_output_fd(out_fd.0, &bytes, tid),
                    &this.captured_file_table(),
                    [in_fd.0, out_fd.0],
                );
                let DispatchOutcome::Returned { value } = outcome else {
                    return Ok(outcome);
                };
                usize::try_from(value).unwrap_or(0)
            } else {
                let out_off = read_u64(memory, off_out_addr)?;
                let host_fd = match this.open_file(out_fd.0).as_ref() {
                    Some(of) => match of.description.read().as_deref() {
                        Some(OpenDescription::HostFile {
                            host_fd,
                            writable: true,
                            ..
                        }) => host_fd.raw(),
                        Some(OpenDescription::HostFile { .. }) => {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        _ => {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                    },
                    None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                };
                let n = unsafe {
                    libc::pwrite(
                        host_fd,
                        bytes.as_ptr() as *const _,
                        bytes.len(),
                        out_off as libc::off_t,
                    )
                };
                let n = match n.host_syscall_errno() {
                    Ok(value) => value as usize,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                if memory
                    .write_bytes(off_out_addr, &(out_off + n as u64).to_ne_bytes())
                    .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                n
            };

            // Advance the input offset (pointer or the fd's own position).
            let new_in = in_offset.saturating_add(written);
            if off_in_addr == 0 {
                if let Some(of) = this.open_file(in_fd.0).as_ref()
                    && let Some(mut open) = of.description.write()
                {
                    match &mut *open {
                        OpenDescription::File { offset, .. }
                        | OpenDescription::SyntheticFile { offset, .. } => *offset = new_in,
                        OpenDescription::HostFile { host_fd, .. } => {
                            unsafe {
                                libc::lseek(host_fd.raw(), new_in as libc::off_t, libc::SEEK_SET)
                            };
                        }
                        _ => {}
                    }
                }
            } else if memory
                .write_bytes(off_in_addr, &(new_in as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::returned_len_or_errno(written))

        }
    }
}
