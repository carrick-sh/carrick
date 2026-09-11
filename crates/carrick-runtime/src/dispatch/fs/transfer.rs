//! Data movement subsystem: zero-copy and buffer-forwarding data transfer between
//! host handles and pipes, including staging queues and host pipe routing.
//! Split out of `dispatch/fs.rs` (WS-F3) as `impl SyscallDispatcher` methods.

use std::sync::Arc;

use carrick_abi::*;
use carrick_guest_mem::CurrentMmMemory;

use super::LinuxSpliceFlags;
use super::pipe::{PipeDrain, take_pipe_bytes, wait_for_pipe_readable};
use super::*;
use crate::dispatch::fd_table::{HostFdRef, HostWriteKind, is_anon_overlay_path};
use crate::dispatch::{HostPipeWriteTarget, WaitFdAuthority, write_host_pipe_owned};
use crate::linux_abi::{
    LINUX_EAGAIN, LINUX_EBADF, LINUX_EFAULT, LINUX_EINTR, LINUX_EINVAL, LINUX_EPIPE,
    LINUX_O_ACCMODE, LINUX_O_RDONLY, LINUX_O_WRONLY, LinuxOpenFlags,
};
use crate::vfs::PtyRole;

/// Host passthrough for tee(2). On Linux the guest pipes are real host kernel
/// pipes, so the host tee(2) gives exact zero-consume semantics; on hosts
/// without tee(2) (macOS/BSD) `SyscallDispatcher::userspace_tee` emulates it.
#[cfg(target_os = "linux")]
fn tee_host_passthrough(
    in_fd: HostFd,
    out_fd: HostFd,
    count: usize,
    flags: LinuxSpliceFlags,
) -> Result<DispatchOutcome, DispatchError> {
    // Raw escape at the libc boundary: Linux SPLICE_F_* values are identical
    // to the guest's, so the bits pass straight through.
    let n = unsafe {
        libc::tee(
            in_fd.get(),
            out_fd.get(),
            count,
            flags.bits() as libc::c_uint,
        )
    };
    Ok(DispatchOutcome::returned_len_or_errno(
        n.host_syscall_errno()?,
    ))
}

struct InMemoryTeeEndpoint<'a> {
    fd: i32,
    pipe: &'a PipeRef,
    status_flags: u64,
}

impl SyscallDispatcher {
    /// True iff `fd` refers to a genuine pipe end — an anonymous pipe, a FIFO,
    /// or a pty — as opposed to a char device (e.g. `/dev/zero`, which carrick
    /// also models as a `HostPipe`), a socket, or a regular file. splice(2)
    /// requires at least one of its two fds to be a genuine pipe; a char-device
    /// `HostPipe` must NOT satisfy that requirement (splice07).
    fn is_genuine_pipe(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        let Some(open) = open_file.description.read() else {
            return false;
        };
        match &*open {
            OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. } => true,
            OpenDescription::HostPipe {
                write_kind, pty, ..
            } => pty.is_some() || *write_kind == HostWriteKind::PipeLike,
            _ => false,
        }
    }

    /// True iff `fd` is a splice/tee SOURCE that is not open for reading, so
    /// splice(2) must reject it with EBADF: an `O_PATH` descriptor, a
    /// write-only regular file, or the write end of a one-way pipe (splice03's
    /// write-only case, splice07's `O_PATH`/pipe-write-end sources).
    pub(super) fn splice_source_not_readable(&self, fd: i32) -> bool {
        if self.fd_is_o_path(fd) {
            return true;
        }
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        let Some(open) = open_file.description.read() else {
            return false;
        };
        match &*open {
            OpenDescription::File { .. }
            | OpenDescription::SyntheticFile { .. }
            | OpenDescription::HostFile { .. }
            | OpenDescription::SyntheticDevice { .. } => {
                open_file.description.common().status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            }
            OpenDescription::PipeWriter { .. } => true,
            OpenDescription::HostPipe {
                is_read_end,
                pty,
                bidirectional,
                ..
            } => pty.is_none() && !*bidirectional && !*is_read_end,
            _ => false,
        }
    }

    /// tee(2) for in-memory anonymous pipes: duplicate up to `count` bytes from
    /// the source pipe's buffer to the destination pipe WITHOUT consuming or
    /// reordering the source.
    fn in_memory_tee(
        &self,
        src: InMemoryTeeEndpoint<'_>,
        dst: InMemoryTeeEndpoint<'_>,
        count: usize,
        splice_flags: LinuxSpliceFlags,
    ) -> Result<DispatchOutcome, DispatchError> {
        let in_nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
            || LinuxOpenFlags::from_bits_truncate(src.status_flags)
                .contains(LinuxOpenFlags::NONBLOCK);
        let out_nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
            || LinuxOpenFlags::from_bits_truncate(dst.status_flags)
                .contains(LinuxOpenFlags::NONBLOCK);

        match pipe::tee_in_memory_pipes(src.pipe, dst.pipe, count) {
            pipe::InMemoryTeeOutcome::SamePipe => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            pipe::InMemoryTeeOutcome::BrokenPipe => Ok(DispatchOutcome::errno(LINUX_EPIPE)),
            pipe::InMemoryTeeOutcome::Eof => Ok(DispatchOutcome::Returned { value: 0 }),
            pipe::InMemoryTeeOutcome::SourceWouldBlock => {
                let Some(host_fd) = src.pipe.read_poll_fd() else {
                    return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
                };
                Ok(self.splice_host_output_wait(
                    src.fd,
                    host_fd.raw(),
                    libc::POLLIN,
                    Some(host_fd),
                    in_nonblocking,
                ))
            }
            pipe::InMemoryTeeOutcome::DestWouldBlock => {
                let Some(host_fd) = dst.pipe.write_poll_fd() else {
                    return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
                };
                Ok(self.splice_host_output_wait(
                    dst.fd,
                    host_fd.raw(),
                    libc::POLLIN,
                    Some(host_fd),
                    out_nonblocking,
                ))
            }
            pipe::InMemoryTeeOutcome::Transferred(written) => {
                Ok(DispatchOutcome::returned_len_or_errno(written))
            }
        }
    }

    /// tee(2): duplicate up to `count` bytes from the source pipe's read end to
    /// the destination pipe's write end WITHOUT consuming the source. On a Linux
    /// host the real `tee(2)` is exact; elsewhere (macOS/BSD lack `tee(2)`) fall
    /// back to a userspace peek-and-copy.
    fn host_tee(
        &self,
        in_read: HostFd,
        in_pipe_id: u64,
        out_write: HostFd,
        count: usize,
        flags: LinuxSpliceFlags,
    ) -> Result<DispatchOutcome, DispatchError> {
        #[cfg(target_os = "linux")]
        {
            let _ = in_pipe_id;
            tee_host_passthrough(in_read, out_write, count, flags)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.userspace_tee(in_read, in_pipe_id, out_write, count, flags)
        }
    }

    /// Userspace `tee(2)` for hosts without the syscall: drain the source pipe's
    /// currently-buffered bytes, write them back through the source's write end
    /// to restore it (FIFO order is preserved because the pipe is momentarily
    /// emptied first), then copy up to `count` of them into the destination
    /// pipe. The restore runs before the copy so a short/failed destination
    /// write still leaves the non-consumed source intact.
    #[cfg(not(target_os = "linux"))]
    fn userspace_tee(
        &self,
        in_read: HostFd,
        in_pipe_id: u64,
        out_write: HostFd,
        count: usize,
        flags: LinuxSpliceFlags,
    ) -> Result<DispatchOutcome, DispatchError> {
        let nonblock = flags.contains(LinuxSpliceFlags::NONBLOCK);
        let avail = host_pipe_readable_bytes(in_read.get()).unwrap_or(0);
        if avail == 0 {
            // Nothing buffered: a non-blocking tee is EAGAIN; a blocking tee
            // would wait for the writer, which this path does not park for under
            // the dispatcher lock, so report 0 (empty/writer-closed) instead.
            return Ok(if nonblock {
                DispatchOutcome::errno(LINUX_EAGAIN)
            } else {
                DispatchOutcome::Returned { value: 0 }
            });
        }
        // Drain the whole buffer so the writeback restores it in FIFO order.
        let mut buf = vec![0u8; avail];
        let n = unsafe {
            // BLOCKING-IO-OK: HostPipe fds are adopted O_NONBLOCK and `avail`
            // was measured immediately before the read.
            libc::read(
                in_read.get(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                avail,
            )
        };
        let n = n.host_syscall_errno()?;
        if n <= 0 {
            return Ok(if nonblock {
                DispatchOutcome::errno(LINUX_EAGAIN)
            } else {
                DispatchOutcome::Returned { value: 0 }
            });
        }
        buf.truncate(n as usize);
        // Restore the source: write the drained bytes back via its write end. The
        // pipe was just emptied, so a non-blocking write of `n <= capacity`
        // completes in full and preserves order. If no write end is open (the
        // source's writer was closed) the source is consumed — a best-effort
        // fallback; tee01 keeps the source write end open.
        if let Some(write_fd) = self.host_pipe_write_end_for_pipe_id(in_pipe_id) {
            let mut off = 0usize;
            while off < buf.len() {
                let w = unsafe {
                    // BLOCKING-IO-OK: the source pipe was just drained, so this
                    // bounded restore writes back into known room.
                    libc::write(
                        write_fd.get(),
                        buf[off..].as_ptr().cast::<libc::c_void>(),
                        buf.len() - off,
                    )
                };
                match w.host_syscall_errno() {
                    Ok(c) if c > 0 => off += c as usize,
                    _ => break,
                }
            }
        }
        // Copy up to `count` bytes into the destination pipe.
        let copy_len = count.min(buf.len());
        let mut written = 0usize;
        while written < copy_len {
            let w = unsafe {
                // BLOCKING-IO-OK: HostPipe fds are adopted O_NONBLOCK; a full
                // destination returns EAGAIN and is handled below.
                libc::write(
                    out_write.get(),
                    buf[written..copy_len].as_ptr().cast::<libc::c_void>(),
                    copy_len - written,
                )
            };
            match w.host_syscall_errno() {
                Ok(c) if c > 0 => written += c as usize,
                // A full destination with nothing copied yet is EAGAIN under
                // SPLICE_F_NONBLOCK; otherwise report whatever landed.
                Err(e) if e == LINUX_EAGAIN && written == 0 && nonblock => {
                    return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                }
                _ => break,
            }
        }
        Ok(DispatchOutcome::returned_len_or_errno(written))
    }

    fn host_pipe_splice_staging_target(&self, fd: i32) -> Option<(i32, usize)> {
        let (pipe_id, capacity) = {
            let open_file = self.open_file(fd)?;
            let open = open_file.description.read()?;
            match &*open {
                OpenDescription::HostPipe {
                    base,
                    is_read_end: false,
                    pipe_id,
                    pty: None,
                    bidirectional: false,
                    ..
                } if *pipe_id != 0 => (*pipe_id, base.pipe_capacity()),
                _ => return None,
            }
        };
        let (read_fd, _) = self.host_pipe_read_end_for_pipe_id(pipe_id)?;
        let capacity = usize::try_from(capacity).ok()?;
        let queued = self.host_pipe_read_end_buffered_bytes(pipe_id);
        Some((read_fd, capacity.saturating_sub(queued)))
    }

    /// Room in a pipe destination, in bytes — `None` when `fd` is not a
    /// pipe. Uses the same accounting the write path applies
    /// ([`super::host_pipe_write_room`]), so a `splice(2)`/`vmsplice(2)` that bounds
    /// its transfer window by this value never hands the writer more than the pipe can take.
    /// Unlike [`Self::host_pipe_splice_staging_target`] this accepts any pipe
    /// write end, including in-memory pipes, pty, and bidirectional ends.
    pub(in crate::dispatch) fn splice_pipe_write_room(&self, fd: i32) -> Option<usize> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read()?;
        match &*open {
            OpenDescription::PipeWriter { pipe, .. } => {
                let state = pipe.state.lock();
                Some(state.capacity.saturating_sub(state.buffer.len()))
            }
            OpenDescription::HostPipe {
                base,
                pipe_id,
                is_read_end,
                bidirectional,
                host_fd,
                ..
            } => {
                let (capacity, queued) = self.host_pipe_capacity_state(
                    base,
                    *pipe_id,
                    *is_read_end,
                    *bidirectional,
                    host_fd.raw(),
                )?;
                super::host_pipe_write_room(capacity, queued)
            }
            _ => None,
        }
    }

    pub(in crate::dispatch) fn staged_splice_pipe_bytes(&self, guest_fd: i32) -> usize {
        self.open_file(guest_fd).map_or(0, |file| {
            file.description.common().splice_pushback().lock().len()
        })
    }

    pub(in crate::dispatch) fn staged_splice_description_bytes(
        &self,
        description: crate::kernel::FileDescriptionId,
    ) -> usize {
        let files = resources::files().unwrap_or_else(|| self.captured_file_table());
        for slot in files.read_open_files().values() {
            if slot.description.id() == description {
                return slot.description.common().splice_pushback().lock().len();
            }
        }
        0
    }

    pub(in crate::dispatch) fn discard_splice_pushback_if_final(&self, guest_fd: i32) {
        let Some(file) = self.open_file(guest_fd) else {
            return;
        };
        if file.description.fd_ref_count() == 1
            && !file
                .description
                .common()
                .splice_pushback()
                .lock()
                .is_empty()
        {
            file.description.clear_splice_pushback();
        }
    }

    /// Write `bytes` to a splice/sendfile destination, honoring `off_out`: NULL
    /// (addr 0) writes at the fd's current position; non-NULL pwrites at the
    /// given offset on a regular HostFile and advances `*off_out` (Linux allows
    /// off_out when fd_out is a regular file even though fd_in is a pipe —
    /// test_os.test_splice_offset_out). off_out on a non-regular target → EINVAL.
    ///
    /// The destination is written with `splice(2)`'s PARTIAL contract
    /// ([`Self::write_output_fd_partial`]): a pipe or socket that fills
    /// mid-transfer yields a short count, never a park until every byte lands.
    /// Every caller either re-stages the undelivered tail
    /// ([`Self::restore_splice_pipe_bytes`], [`Self::restore_pipe_bytes`]) or
    /// never consumed it (`vmsplice` gathers from guest memory), so a short
    /// count loses nothing.
    fn splice_write_out<M: CurrentMmMemory>(
        &self,
        out_fd: i32,
        off_out_addr: u64,
        bytes: &[u8],
        memory: &mut M,
        tid: crate::thread::ThreadId,
        nonblocking: bool,
    ) -> DispatchOutcome {
        if off_out_addr == 0 {
            if let Some(open_file) = self.open_file(out_fd) {
                if let Some(open) = open_file.description.read()
                    && let OpenDescription::SyntheticDevice {
                        kind:
                            crate::vfs::SyntheticDeviceKind::Null
                            | crate::vfs::SyntheticDeviceKind::Zero,
                        ..
                    } = &*open
                {
                    let flags = open_file.description.common().status_flags();
                    return if flags & LINUX_O_ACCMODE == LINUX_O_RDONLY {
                        DispatchOutcome::errno(LINUX_EBADF)
                    } else if LinuxOpenFlags::from_bits_truncate(flags)
                        .contains(LinuxOpenFlags::APPEND)
                    {
                        DispatchOutcome::errno(LINUX_EINVAL)
                    } else {
                        DispatchOutcome::returned_len_or_errno(bytes.len())
                    };
                }
            }
            return match self.write_output_fd_partial(out_fd, bytes, tid) {
                // The destination could not take a single byte. A blocking
                // `splice(2)` waits for room; the partial write path reports
                // that as `EAGAIN` because it asked non-blocking, so restore
                // the guest's own blocking mode here.
                DispatchOutcome::Errno { errno } if errno == LINUX_EAGAIN && !nonblocking => {
                    self.splice_output_would_block(out_fd, false)
                }
                other => other,
            };
        }
        let out_off = match read_u64(memory, off_out_addr) {
            Ok(v) => v,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        let host_fd = match self.open_file(out_fd).as_ref() {
            Some(of) => match of.description.read().as_deref() {
                Some(OpenDescription::HostFile {
                    host_fd,
                    writable: true,
                    ..
                }) => host_fd.raw(),
                Some(OpenDescription::HostFile { .. }) => {
                    return DispatchOutcome::errno(LINUX_EBADF);
                }
                _ => return DispatchOutcome::errno(LINUX_EINVAL),
            },
            None => return DispatchOutcome::errno(LINUX_EBADF),
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
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        if memory
            .write_bytes(off_out_addr, &(out_off + n as u64).to_ne_bytes())
            .is_err()
        {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        DispatchOutcome::returned_len_or_errno(n)
    }

    /// Pull up to `count` bytes off a `splice(2)` SOURCE pipe.
    ///
    /// `Ok(Ok(bytes))` is the transfer (empty = EOF, the writers are gone).
    /// `Ok(Err(outcome))` is "nothing available": `EAGAIN` for a non-blocking
    /// splice, a `WaitOnFds` readiness park for a blocking one — the same
    /// classification `blocking_io`/`read_host_pipe` apply to every other host
    /// read. carrick's host pipe fds are FORCED `O_NONBLOCK` at creation, so a
    /// bare `read` here surfaced a host `EAGAIN` verbatim and a blocking guest
    /// `splice` on an empty pipe failed instead of waiting.
    pub(in crate::dispatch) fn take_splice_pipe_bytes(
        &self,
        guest_fd: i32,
        host_fd: HostFd,
        host_fd_owner: Option<HostFdRef>,
        count: usize,
        nonblocking: bool,
    ) -> Result<Result<Vec<u8>, DispatchOutcome>, DispatchError> {
        let buf = self.take_staged_splice_pipe_bytes(guest_fd, count)?;
        // A pipe read returns the bytes already available without waiting to
        // fill the caller's whole buffer. The staged queue is the front of this
        // host pipe's logical byte stream, so do not probe the empty host fd
        // after consuming a short staged prefix (that would turn readable data
        // into EAGAIN and lose the prefix).
        if !buf.is_empty() {
            return Ok(Ok(buf));
        }

        let mut buf = vec![0; count];
        // BLOCKING-IO-OK: the host fd is O_NONBLOCK by construction; EAGAIN is
        // classified below rather than reaching the guest raw.
        let n = unsafe {
            libc::read(
                host_fd.get(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                count,
            )
        };
        let n = match n.host_syscall_errno() {
            Ok(n) => n,
            // EINTR is carrick's own machinery (the SIGURG vCPU kick), never
            // the guest's: route it through readiness like `read_host_pipe`.
            Err(errno) if errno == LINUX_EAGAIN || errno == LINUX_EINTR => {
                return Ok(Err(super::would_block_outcome(
                    host_fd.get(),
                    libc::POLLIN,
                    nonblocking,
                    host_fd_owner,
                    WaitFdAuthority::logical(
                        self.captured_slot_authority(guest_fd).ok_or(LINUX_EBADF)?,
                    ),
                )));
            }
            Err(errno) => return Err(DispatchError::Errno(errno)),
        };
        buf.truncate(n as usize);
        Ok(Ok(buf))
    }

    pub(in crate::dispatch::fs) fn take_staged_splice_pipe_bytes(
        &self,
        guest_fd: i32,
        count: usize,
    ) -> Result<Vec<u8>, DispatchError> {
        let file = self
            .open_file(guest_fd)
            .ok_or(DispatchError::Errno(LINUX_EBADF))?;
        let mut queue = file.description.common().splice_pushback().lock();
        let bytes = queue.take_vec(count);
        Ok(bytes)
    }

    /// Stage `bytes` on an open description directly, for callers that must not
    /// touch the file table (see `dispatch::pty_registry`).
    pub(in crate::dispatch) fn stage_splice_bytes_for_description(
        &self,
        description: &crate::kernel::FileDescription,
        bytes: Vec<u8>,
    ) {
        if bytes.is_empty() {
            return;
        }
        description
            .common()
            .splice_pushback()
            .lock()
            .push_back_owned(bytes);
        self.notify_inmem_epoll();
    }

    pub(in crate::dispatch) fn stage_splice_pipe_bytes_owned(&self, guest_fd: i32, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let Some(file) = self.open_file(guest_fd) else {
            return;
        };
        file.description
            .common()
            .splice_pushback()
            .lock()
            .push_back_owned(bytes);
        // The payload is userspace-resident rather than in the host pipe, so a
        // host kqueue/poll edge cannot announce it. Wake epoll instances to
        // force their level-readiness recompute.
        self.notify_inmem_epoll();
    }

    /// Push an undelivered `splice(2)` tail back onto the FRONT of an
    /// in-memory pipe, the [`Self::restore_splice_pipe_bytes`] twin for the
    /// legacy `PipeReader` source. A short destination write must leave the
    /// source byte stream exactly as it found it minus what was delivered.
    fn restore_pipe_bytes(pipe: &PipeRef, bytes: &[u8]) {
        pipe::restore_pipe_bytes(pipe, bytes);
    }

    /// The destination's readiness park for a blocking `splice`/`vmsplice`
    /// whose output could not take a single byte. Nothing has been consumed
    /// when this is reached, so the runtime re-dispatches the whole call after
    /// the wait; a non-blocking caller gets `EAGAIN` instead.
    fn splice_output_would_block(&self, fd: i32, nonblocking: bool) -> DispatchOutcome {
        let target = self.open_file(fd).and_then(|file| {
            let open = file.description.read()?;
            match &*open {
                OpenDescription::HostPipe { host_fd, .. }
                | OpenDescription::HostSocket { host_fd, .. } => {
                    Some((host_fd.raw(), libc::POLLOUT, Some(host_fd.clone())))
                }
                OpenDescription::PipeWriter { pipe, .. } => {
                    let host_fd = pipe.write_poll_fd()?;
                    Some((host_fd.raw(), libc::POLLIN, Some(host_fd)))
                }
                _ => None,
            }
        });
        match target {
            Some((host_fd, events, owner)) => {
                self.splice_host_output_wait(fd, host_fd, events, owner, nonblocking)
            }
            // No readiness source to park on: report the condition rather than
            // parking on nothing.
            None => DispatchOutcome::errno(LINUX_EAGAIN),
        }
    }

    pub(in crate::dispatch) fn splice_host_output_wait(
        &self,
        fd: i32,
        host_fd: i32,
        events: i16,
        owner: Option<HostFdRef>,
        nonblocking: bool,
    ) -> DispatchOutcome {
        let Some(authority) = self.captured_slot_authority(fd) else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        super::would_block_outcome(
            host_fd,
            events,
            nonblocking,
            owner,
            WaitFdAuthority::logical(authority),
        )
    }

    pub(super) fn restore_splice_pipe_bytes(&self, guest_fd: i32, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let Some(file) = self.open_file(guest_fd) else {
            return;
        };
        file.description
            .common()
            .splice_pushback()
            .lock()
            .push_front(bytes);
    }

    pub(in crate::dispatch::fs) fn write_output_fd(
        &self,
        fd: i32,
        bytes: &[u8],
        tid: crate::thread::ThreadId,
    ) -> DispatchOutcome {
        self.write_output_fd_inner(fd, bytes, tid, false)
    }

    /// `splice(2)` flavour of [`Self::write_output_fd`]: the destination is
    /// written with non-blocking semantics, so a pipe that fills mid-transfer
    /// yields a SHORT count (or `EAGAIN` when nothing moved) instead of parking
    /// until every byte is delivered.
    ///
    /// `write(2)` must deliver the whole buffer and may block to do it;
    /// `splice(2)` explicitly may transfer fewer bytes than requested and
    /// leaves the loop to the caller. Using the `write(2)` contract for splice
    /// deadlocks whenever the only reader is the same single-threaded guest —
    /// it cannot drain the pipe until the splice it is blocked in returns.
    fn write_output_fd_partial(
        &self,
        fd: i32,
        bytes: &[u8],
        tid: crate::thread::ThreadId,
    ) -> DispatchOutcome {
        self.write_output_fd_inner(fd, bytes, tid, true)
    }

    fn write_output_fd_inner(
        &self,
        fd: i32,
        bytes: &[u8],
        tid: crate::thread::ThreadId,
        partial_ok: bool,
    ) -> DispatchOutcome {
        let nonblocking = partial_ok || self.io_is_nonblocking(fd, 0);
        // Mirror `write`/`writev`: any fd present in `open_files` (e.g.
        // after a dup3 over stdio) takes precedence over the built-in
        // stdout/stderr buffers. Without this, `busybox cat`'s
        // `sendfile(1, infile, ...)` writes the file contents to the
        // dispatcher's internal stdout instead of the pipe write end.
        if let Some(open_file) = self.open_file(fd) {
            // Regular-file destinations need the overlay writeback to happen
            // AFTER the description borrow is dropped, so use the same
            // collect-then-write pattern as `write`. Non-file arms return
            // directly. This is what makes splice/copy_file_range/sendfile to a
            // regular file (off_out at the fd's current position) work, matching
            // real Linux (splice pipe->file).
            let outcome: DispatchOutcome;
            let writeback: Option<(String, usize, usize)>;
            {
                let Some(mut open) = open_file.description.write() else {
                    return DispatchOutcome::errno(LINUX_EBADF);
                };
                match &mut *open {
                    OpenDescription::PipeWriter { pipe, .. } => {
                        let flags = if nonblocking {
                            open_file.description.common().status_flags() | LINUX_O_NONBLOCK
                        } else {
                            open_file.description.common().status_flags()
                        };
                        let Some(wait_authority) = self
                            .captured_slot_authority(fd)
                            .map(WaitFdAuthority::logical)
                        else {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        };
                        return write_pipe(bytes, pipe, flags, fd, wait_authority, || false);
                    }
                    OpenDescription::HostPipe {
                        base,
                        host_fd,
                        is_read_end,
                        pipe_id,
                        pty,
                        bidirectional,
                        write_kind,
                        stdio_stream,
                        ..
                    } => {
                        if let Some(stream) = *stdio_stream {
                            if stream == 0 {
                                return DispatchOutcome::errno(LINUX_EBADF);
                            }
                            if !self.io.inherits_host_stdio() {
                                drop(open);
                                return self.write_stdio_sink(stream, bytes);
                            }
                        }
                        // pty ends and O_RDWR FIFOs are bidirectional; only real
                        // one-way pipe ends are gated by is_read_end.
                        #[cfg(feature = "trace-tty")]
                        if bytes.contains(&0x0a) {
                            let hf = host_fd.raw();
                            let tt = unsafe { libc::isatty(hf) };
                            eprintln!(
                                "[PTYWR2DBG-streamed] guest_fd={fd} desc_host_fd={hf} isatty={tt} pty={:?} is_read_end={is_read_end}",
                                pty.as_ref().map(|r| r.is_master)
                            );
                        }
                        return if *is_read_end && pty.is_none() && !*bidirectional {
                            DispatchOutcome::errno(LINUX_EBADF)
                        } else {
                            let (bytes_to_write, consumed_count) = if let Some(PtyRole {
                                index,
                                is_master: true,
                            }) = pty
                            {
                                let orig_len = bytes.len();
                                let forwarded = crate::kernel::tty::process_master_write(
                                    crate::kernel::tty::TtyKey::Pty(*index),
                                    host_fd.raw(),
                                    bytes,
                                );
                                let consumed = orig_len - forwarded.len();
                                (forwarded, consumed)
                            } else {
                                (bytes.to_vec(), 0)
                            };
                            if bytes_to_write.is_empty() && consumed_count > 0 {
                                return DispatchOutcome::returned_len_or_errno(consumed_count);
                            }
                            let Some(wait_authority) = self
                                .captured_slot_authority(fd)
                                .map(WaitFdAuthority::logical)
                            else {
                                return DispatchOutcome::errno(LINUX_EBADF);
                            };
                            let res = write_host_pipe_owned(
                                bytes_to_write,
                                HostPipeWriteTarget {
                                    host_fd: host_fd.raw(),
                                    host_fd_owner: Some(host_fd.clone()),
                                    nonblocking,
                                    write_kind: *write_kind,
                                    pipe_state: self.host_pipe_capacity_state(
                                        base,
                                        *pipe_id,
                                        *is_read_end,
                                        *bidirectional,
                                        host_fd.raw(),
                                    ),
                                    tid,
                                    sigpipe_on_epipe: true,
                                    authority: wait_authority,
                                },
                            );
                            match res {
                                DispatchOutcome::Returned { value } => {
                                    let total = usize::try_from(value)
                                        .ok()
                                        .and_then(|v| v.checked_add(consumed_count));
                                    match total {
                                        Some(t) => DispatchOutcome::returned_len_or_errno(t),
                                        None => DispatchOutcome::errno(LINUX_EOVERFLOW),
                                    }
                                }
                                other => {
                                    if consumed_count > 0 {
                                        DispatchOutcome::returned_len_or_errno(consumed_count)
                                    } else {
                                        other
                                    }
                                }
                            }
                        };
                    }
                    OpenDescription::HostSocket { host_fd, .. } => {
                        let Some(wait_authority) = self
                            .captured_slot_authority(fd)
                            .map(WaitFdAuthority::logical)
                        else {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        };
                        return write_host_pipe_owned(
                            bytes.to_vec(),
                            HostPipeWriteTarget {
                                host_fd: host_fd.raw(),
                                host_fd_owner: Some(host_fd.clone()),
                                nonblocking,
                                write_kind: HostWriteKind::SocketLike,
                                pipe_state: None,
                                tid,
                                sigpipe_on_epipe: false,
                                authority: wait_authority,
                            },
                        );
                    }
                    OpenDescription::InMemorySocket { socket, .. } => {
                        let socket = Arc::clone(socket);
                        return match socket.send_stream(bytes, Vec::new()) {
                            Ok(written) => {
                                self.notify_inmem_epoll();
                                DispatchOutcome::returned_len_or_errno(written)
                            }
                            Err(errno) => DispatchOutcome::errno(errno),
                        };
                    }
                    OpenDescription::HostFile {
                        host_fd, writable, ..
                    } => {
                        if !*writable {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        }
                        if LinuxOpenFlags::from_bits_truncate(
                            open_file.description.common().status_flags(),
                        )
                        .contains(LinuxOpenFlags::APPEND)
                        {
                            // Let the HOST kernel perform the append. Linux's
                            // O_APPEND seeks to end and writes as ONE atomic
                            // operation; emulating it as `lseek(SEEK_END)` then
                            // a separate `write` is a race, because anything
                            // touching the shared open description in between
                            // moves the write. A concurrent reader that seeks
                            // to the start sends the append to offset 0, which
                            // is how Go build-cache archives lost their
                            // `!<arch>\n` magic under a parallel `go build`.
                            // Darwin honours O_APPEND natively, so ensure the
                            // description carries it rather than approximating
                            // the offset ourselves.
                            let current = unsafe { libc::fcntl(host_fd.raw(), libc::F_GETFL, 0) };
                            if current >= 0 && current & libc::O_APPEND == 0 {
                                unsafe {
                                    libc::fcntl(
                                        host_fd.raw(),
                                        libc::F_SETFL,
                                        current | libc::O_APPEND,
                                    )
                                };
                            }
                        }
                        let Some(wait_authority) = self
                            .captured_slot_authority(fd)
                            .map(WaitFdAuthority::logical)
                        else {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        };
                        return write_host_pipe(
                            bytes,
                            HostPipeWriteTarget {
                                host_fd: host_fd.raw(),
                                host_fd_owner: Some(host_fd.clone()),
                                nonblocking,
                                write_kind: HostWriteKind::RegularFile,
                                pipe_state: None,
                                tid,
                                sigpipe_on_epipe: false,
                                authority: wait_authority,
                            },
                        );
                    }
                    OpenDescription::File {
                        path,
                        contents,
                        offset,
                        writable,
                        metadata,
                        ..
                    } => {
                        if !*writable {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        }
                        let write_offset = *offset;
                        let written = match write_into_file_contents(contents, offset, bytes) {
                            Ok(n) => n,
                            Err(errno) => return DispatchOutcome::errno(errno),
                        };
                        let cur_len = match contents.len() {
                            Ok(l) => l,
                            Err(errno) if written == 0 => return DispatchOutcome::errno(errno),
                            Err(_) => *offset as u64,
                        };
                        metadata.size = usize::try_from(cur_len).unwrap_or(metadata.size);
                        outcome = DispatchOutcome::returned_len_or_errno(written);
                        writeback = (!is_anon_overlay_path(path)).then(|| {
                            (
                                path.clone(),
                                write_offset,
                                usize::try_from(cur_len).unwrap_or(0),
                            )
                        });
                    }
                    _ => return DispatchOutcome::errno(LINUX_EBADF),
                }
            }
            if let Some((path, offset, final_size)) = writeback {
                let _ = self
                    .fs
                    .rootfs_vfs
                    .overlay
                    .write_file_range(&path, offset, bytes, final_size);
            }
            return outcome;
        }
        self.write_stdio_sink(fd, bytes)
    }

    define_syscall! {
        fn tee(this, cx, fd_in: Fd, fd_out: Fd, len: u64, flags: u64) {
            // tee(2) duplicates up to `len` bytes of pipe data from fd_in to
            // fd_out WITHOUT consuming the source.
            let _ = cx;
            // `from_bits` rejects exactly the historical `& !SUPPORTED` set:
            // the type's full set IS the supported set.
            let Some(splice_flags) = LinuxSpliceFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };

            // Check if both ends are HostPipe
            if let Some((in_fd, in_pipe)) = this.host_pipe_end(fd_in.0, true) {
                let Some((out_fd, out_pipe)) = this.host_pipe_end(fd_out.0, false) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if in_pipe != 0 && in_pipe == out_pipe {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let count = usize::try_from(len).map_err(|_| DispatchError::LengthTooLarge(len))?;
                if count == 0 {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                return this.host_tee(in_fd, in_pipe, out_fd, count, splice_flags);
            }

            // Check if both ends are in-memory pipes
            if let Some((in_pipe, in_status_flags)) = this.pipe_reader(fd_in.0) {
                let Some((out_pipe, out_status_flags)) = this.pipe_writer(fd_out.0) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if Arc::ptr_eq(&in_pipe, &out_pipe) || in_pipe.pipe_id() == out_pipe.pipe_id() {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let count = usize::try_from(len).map_err(|_| DispatchError::LengthTooLarge(len))?;
                if count == 0 {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                let outcome = this.in_memory_tee(
                    InMemoryTeeEndpoint {
                        fd: fd_in.0,
                        pipe: &in_pipe,
                        status_flags: in_status_flags,
                    },
                    InMemoryTeeEndpoint {
                        fd: fd_out.0,
                        pipe: &out_pipe,
                        status_flags: out_status_flags,
                    },
                    count,
                    splice_flags,
                )?;
                return Ok(this.raise_sigpipe_on_epipe(cx, outcome));
            }

            // Non-pipe fds, wrong pipe ends, or mixed pairs are rejected with EINVAL.
            Ok(DispatchOutcome::errno(LINUX_EINVAL))
        }

        fn splice(this, cx, fd_in: Fd, off_in: GuestPtr, fd_out: Fd, off_out: GuestPtr, len: u64, flags: u64) {
            let tid = cx.tid();
            let in_fd: Fd = fd_in;
            let off_in_address = off_in.0;
            let out_fd: Fd = fd_out;
            let off_out_address = off_out.0;
            let count =
                usize::try_from(len).map_err(|_| DispatchError::LengthTooLarge(len))?;
            let memory = &mut *cx.memory;
            // `from_bits` rejects exactly the historical `& !SUPPORTED` set:
            // the type's full set IS the supported set.
            let Some(splice_flags) = LinuxSpliceFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            // A closed/negative fd_in is EBADF before any routing — the
            // file→pipe fallthrough otherwise read an empty byte stream from
            // the dead fd and "spliced" 0 bytes (LTP splice03 badfd case).
            if in_fd.0 < 0 || (in_fd.0 > 2 && this.open_file(in_fd.0).is_none()) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // splice(2) reads from fd_in, so a source not open for reading — an
            // O_PATH descriptor, a write-only file, or the write end of a pipe —
            // is EBADF, decided ahead of the pipe-vs-pipe routing (splice03's
            // write-only fd_in, splice07's O_PATH / pipe-write-end sources).
            if this.splice_source_not_readable(in_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // fd_out must be open for WRITING, and Linux decides that before
            // the one-end-must-be-a-pipe rule: the oracle's splice07 matrix
            // answers EBADF for every non-writable destination (O_PATH file,
            // directory, /dev/zero, /proc/self/maps, a pipe READ end, an
            // inotify fd) and EINVAL only for writable-but-unspliceable ones
            // (eventfd/signalfd/timerfd/epoll/pidfd/memfd/sockets/regular
            // file). carrick reached the pipe rule first and answered EINVAL
            // for the whole tail.
            if let Some(errno) = this.splice_output_errno(out_fd.0)
                && errno == LINUX_EBADF
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // splice(2) requires at least ONE end to be a genuine pipe; a
            // char-device HostPipe (e.g. /dev/zero) does NOT count. When neither
            // fd is a genuine pipe the call is EINVAL, resolved BEFORE any read so
            // a char-device or socket source is never drained (splice07
            // /dev/zero->file & socket->file/socket, splice03 file->file).
            if !this.is_genuine_pipe(in_fd.0) && !this.is_genuine_pipe(out_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // An `io_uring` ring is an anonymous inode with no splice file
            // operations, so Linux answers EINVAL for either end. carrick backs
            // the ring fd with a plain `SyntheticFile`, which
            // `splice_source_not_readable` accepts: the call fell through to the
            // file->pipe path, `sendfile_bytes` read the description's empty
            // `contents`, and splice reported a successful 0-byte transfer
            // (splice07 "splice() on io uring -> pipe write end succeeded").
            if this.io_uring_description(in_fd.0).is_some()
                || this.io_uring_description(out_fd.0).is_some()
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // memfd_secret cannot be a splice endpoint (secretmem has no
            // splice_read/splice_write): EINVAL even when the other end IS a
            // genuine pipe. Ordered after the EBADF/no-pipe checks so the
            // splice07 "memfd secret" rows keep Linux's error precedence.
            if this.fd_is_secretmem(in_fd.0) || this.fd_is_secretmem(out_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // A guest that did not ask for SPLICE_F_NONBLOCK still gets
            // non-blocking behaviour when the DESTINATION fd is O_NONBLOCK,
            // exactly like write(2) on the same fd.
            let out_nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                || this.fd_is_nonblocking(out_fd.0);
            let complete_wait = |outcome| {
                this.complete_wait_fd_authority(
                    outcome,
                    &this.captured_file_table(),
                    [in_fd.0, out_fd.0],
                )
            };
            // Never hand the destination more than it can take in one go. The
            // write path returns a SHORT count rather than parking (splice(2)'s
            // own contract), and bounding the SOURCE read by the same figure
            // keeps the undelivered tail out of carrick's hands entirely.
            let count = match this.splice_pipe_write_room(out_fd.0) {
                Some(0) => {
                    return Ok(complete_wait(
                        this.splice_output_would_block(out_fd.0, out_nonblocking),
                    ));
                }
                Some(room) => count.min(room),
                None => count,
            };

            if let Some((pipe, status_flags)) = this.pipe_reader(in_fd.0) {
                // A pipe source has no seekable offset → a non-NULL off_in is
                // ESPIPE (splice(2)). off_out IS allowed (honored below) when
                // fd_out is a regular file (test_os.test_splice_offset_out).
                if off_in_address != 0 {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
                if let Some(errno) = this.splice_output_errno(out_fd.0) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                let bytes = match take_pipe_bytes(&pipe, count) {
                    PipeDrain::Bytes(bytes) => bytes,
                    PipeDrain::Eof => return Ok(DispatchOutcome::Returned { value: 0 }),
                    PipeDrain::WouldBlock => {
                        let in_nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                            || LinuxOpenFlags::from_bits_truncate(status_flags)
                                .contains(LinuxOpenFlags::NONBLOCK);
                        if in_nonblocking {
                            return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                        }
                        return Ok(complete_wait(wait_for_pipe_readable(
                            &pipe,
                            WaitFdAuthority::logical(
                                this.captured_slot_authority(in_fd.0).ok_or(LINUX_EBADF)?,
                            ),
                        )));
                    }
                };
                let outcome = this.splice_write_out(out_fd.0, off_out_address, &bytes, cx.memory, tid, out_nonblocking);
                let DispatchOutcome::Returned { value } = outcome else {
                    Self::restore_pipe_bytes(&pipe, &bytes);
                    return Ok(complete_wait(outcome));
                };
                let written = usize::try_from(value).unwrap_or(0).min(bytes.len());
                if written < bytes.len() {
                    Self::restore_pipe_bytes(&pipe, &bytes[written..]);
                }
                return Ok(DispatchOutcome::returned_len_or_errno(written));
            }

            // Splice OUT of a real host pipe's read end (the fork-safe pipe model;
            // `pipe2`/`fcntl` now hand back HostPipe descriptions, so splice must
            // recognise them just like the legacy in-memory PipeReader above).
            if let Some(host_fd) = this.host_pipe_read_fd(in_fd.0) {
                // A pipe source has no seekable offset → a non-NULL off_in is
                // ESPIPE (splice(2)). off_out IS allowed (honored below) when
                // fd_out is a regular file (test_os.test_splice_offset_out).
                if off_in_address != 0 {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
                if let Some(errno) = this.splice_output_errno(out_fd.0) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                // A source read that finds nothing waits (or reports EAGAIN)
                // like every other blocking-mode host read; the guest's own
                // O_NONBLOCK on fd_in counts alongside SPLICE_F_NONBLOCK.
                let in_nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                    || this.fd_is_nonblocking(in_fd.0);
                let host_fd_owner = this.open_file(in_fd.0).and_then(|file| {
                    let open = file.description.read()?;
                    match &*open {
                        OpenDescription::HostPipe { host_fd, .. } => Some(host_fd.clone()),
                        _ => None,
                    }
                });
                let buf = match this.take_splice_pipe_bytes(
                    in_fd.0,
                    host_fd,
                    host_fd_owner,
                    count,
                    in_nonblocking,
                )? {
                    Ok(buf) => buf,
                    Err(outcome) => return Ok(complete_wait(outcome)),
                };
                if buf.is_empty() {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                let outcome = this.splice_write_out(out_fd.0, off_out_address, &buf, cx.memory, tid, out_nonblocking);
                let DispatchOutcome::Returned { value } = outcome else {
                    this.restore_splice_pipe_bytes(in_fd.0, &buf);
                    return Ok(complete_wait(outcome));
                };
                let written = if value <= 0 {
                    0
                } else {
                    usize::try_from(value).unwrap_or(buf.len()).min(buf.len())
                };
                if written < buf.len() {
                    this.restore_splice_pipe_bytes(in_fd.0, &buf[written..]);
                }
                return Ok(DispatchOutcome::returned_len_or_errno(written));
            }

            // Splice OUT of a host socket (socket -> pipe, and socket -> socket).
            // This is the path Go's `io.Copy(pipe, conn)` takes; without it a
            // socket source fell through to the sendfile path below, which treats
            // `in_fd` as a regular file and fails. The host socket fd is
            // non-blocking, so an empty socket yields EAGAIN — which is exactly
            // what a non-blocking guest (the Go netpoller) expects; a true
            // blocking-wait for an empty socket is the same tracked follow-up as
            // the host-pipe branch above.
            if let Some(host_fd) = this.host_socket_fd(in_fd.0) {
                // A pipe/socket source has no seekable offset → off_in must be
                // NULL. off_out IS allowed (honored below) when fd_out is a
                // regular file (test_os.test_splice_offset_out).
                if off_in_address != 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if let Some(errno) = this.splice_output_errno(out_fd.0) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                if off_out_address == 0
                    && splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                    && let Some((pipe_read_fd, room)) =
                        this.host_pipe_splice_staging_target(out_fd.0)
                {
                    if room == 0 {
                        return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                    }
                    let want = count.min(room).min(1 << 20);
                    let mut buf = vec![0u8; want];
                    let n = unsafe {
                        // BLOCKING-IO-OK: MSG_DONTWAIT is passed on this recv.
                        libc::recv(
                            host_fd.get(),
                            buf.as_mut_ptr() as *mut _,
                            want,
                            libc::MSG_DONTWAIT,
                        )
                    };
                    let n = match n.host_syscall_errno() {
                        Ok(v) => v,
                        // A socket that STRUCTURALLY cannot serve as a splice
                        // source — unconnected (ENOTCONN) or a family without a
                        // splice_read op (EOPNOTSUPP) — is EINVAL, matching
                        // Linux's structural check (splice07). Every OTHER recv
                        // error is a genuine transport/nonblocking condition —
                        // EAGAIN (netpoller), ECONNRESET, EPIPE, … — which Linux
                        // propagates verbatim, so surface the real errno.
                        Err(e) if e == LINUX_ENOTCONN || e == LINUX_EOPNOTSUPP => {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        Err(e) => return Ok(DispatchOutcome::errno(e)),
                    };
                    if n == 0 {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    buf.truncate(n as usize);
                    let consumed = buf.len();
                    this.stage_splice_pipe_bytes_owned(pipe_read_fd, buf);
                    return Ok(DispatchOutcome::returned_len_or_errno(consumed));
                }
                // PEEK first, then consume EXACTLY what the destination accepts.
                // The destination is typically Go's O_NONBLOCK splice pipe (64 KiB
                // on macOS — F_SETPIPE_SZ is bookkeeping-only here). A plain
                // consuming recv() pulls up to `count` (~RCVBUF) off the socket,
                // but splice_write_out does a single non-blocking write to the
                // pipe; when recv > the pipe's free space the un-written tail —
                // ALREADY removed from the socket — is silently DROPPED and
                // unrecoverable (TestLargeCopyViaNetwork: server saw ~1.9MB of a
                // 10MB sendfile). MSG_PEEK leaves the bytes in the socket; we
                // remove only the prefix that actually reached the destination, so
                // the guest's Go splice loop just makes another pass for the rest.
                let want = count.min(1 << 20);
                let mut buf = vec![0u8; want];
                // Non-blocking peek (MSG_PEEK | MSG_DONTWAIT below): never blocks
                // under the dispatcher lock; EAGAIN is surfaced, not awaited here.
                let n = unsafe {
                    libc::recv(
                        host_fd.get(),
                        buf.as_mut_ptr() as *mut _,
                        want,
                        libc::MSG_PEEK | libc::MSG_DONTWAIT,
                    )
                };
                let n = match n.host_syscall_errno() {
                    Ok(v) => v,
                    // A socket that STRUCTURALLY cannot serve as a splice source —
                    // unconnected (ENOTCONN) or a family without a splice_read op
                    // (EOPNOTSUPP) — is EINVAL, matching Linux's structural check
                    // (splice07 socket-source cases). Every OTHER recv error is a
                    // genuine transport/nonblocking condition — EAGAIN (Go
                    // netpoller), ECONNRESET, EPIPE, … — which Linux propagates
                    // verbatim, so surface the real errno.
                    Err(e) if e == LINUX_ENOTCONN || e == LINUX_EOPNOTSUPP => {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    Err(e) => return Ok(DispatchOutcome::errno(e)),
                };
                if n == 0 {
                    // EOF: the writer closed; splice reports 0 (Go stops the loop).
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                buf.truncate(n as usize);
                let outcome = this.splice_write_out(out_fd.0, off_out_address, &buf, cx.memory, tid, out_nonblocking);
                let DispatchOutcome::Returned { value } = outcome else {
                    // EAGAIN / WaitOnFds / Errno on the destination — propagate
                    // WITHOUT consuming any socket bytes (the peek left them).
                    return Ok(complete_wait(outcome));
                };
                let written = usize::try_from(value).unwrap_or(0);
                // Now drain EXACTLY `written` bytes from the socket — they are safely
                // in the destination. recv on a stream socket may return short, so
                // loop until `written` are consumed (a single recv could leave a
                // remainder that the next PEEK re-delivers → duplicated bytes).
                let mut consumed = 0usize;
                while consumed < written {
                    // Non-blocking drain (MSG_DONTWAIT below): the bytes are known
                    // to be present (we just peeked them), so this never blocks
                    // under the dispatcher lock.
                    let cn = unsafe {
                        libc::recv(
                            host_fd.get(),
                            buf.as_mut_ptr().add(consumed) as *mut _,
                            written - consumed,
                            libc::MSG_DONTWAIT,
                        )
                    };
                    match cn.host_syscall_errno() {
                        Ok(c) if c > 0 => consumed += c as usize,
                        // 0 (peer gone) or EAGAIN: the peeked bytes should be
                        // present, but never spin — stop draining to avoid a hang.
                        _ => break,
                    }
                }
                // `consumed == written` in every normal case (the peeked bytes are
                // present). Report the bytes moved into the destination; the drain
                // above keeps the socket position in lockstep so nothing is lost.
                return Ok(DispatchOutcome::returned_len_or_errno(written));
            }

            match this.fd_is_pipe_writer(out_fd.0) {
                Ok(true) => {}
                // Neither side is a pipe → EINVAL (splice(2)); the pipe-source
                // shapes were all handled above.
                Ok(false) => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
            // fd_out IS a pipe here, so a non-NULL off_out is ESPIPE.
            if off_out_address != 0 {
                return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
            }

            if let Some(open_file) = this.open_file(in_fd.0)
                && let Some(open) = open_file.description.read()
            {
                if let OpenDescription::SyntheticDevice { kind, .. } = &*open {
                    let kind = *kind;
                    drop(open);

                    if off_in_address != 0 {
                        // Character devices have no seek position, so off_in is not
                        // used or updated, but guest pointer validity is checked.
                        if read_u64(memory, off_in_address).is_err() {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                    }

                    // Bound production by a fixed chunk ceiling (global pipe-room
                    // bounds and full-pipe wait policy already applied above).
                    const SYNTHETIC_SPLICE_CHUNK: usize = 1 << 16; // 64 KiB
                    let count = count.min(SYNTHETIC_SPLICE_CHUNK);

                    let bytes = match kind {
                        crate::vfs::SyntheticDeviceKind::Null => Vec::new(),
                        crate::vfs::SyntheticDeviceKind::Zero
                        | crate::vfs::SyntheticDeviceKind::Full => vec![0u8; count],
                        crate::vfs::SyntheticDeviceKind::Random
                        | crate::vfs::SyntheticDeviceKind::Urandom => {
                            let mut buf = vec![0u8; count];
                            unsafe {
                                libc::arc4random_buf(buf.as_mut_ptr().cast(), count);
                            }
                            buf
                        }
                    };

                    if bytes.is_empty() {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }

                    let outcome = this.write_output_fd_partial(out_fd.0, &bytes, tid);
                    let DispatchOutcome::Returned { value } = outcome else {
                        return Ok(complete_wait(outcome));
                    };
                    let written = usize::try_from(value).unwrap_or(0).min(bytes.len());
                    return Ok(DispatchOutcome::returned_len_or_errno(written));
                }
            }

            // splice(2) into a pipe moves at most what the pipe can hold and
            // returns a SHORT count; the caller loops. `write_output_fd` below
            // implements write(2) semantics instead — deliver every byte, parking
            // on POLLOUT when the pipe fills — so handing it more than the
            // destination's room deadlocks whenever the only reader is the same
            // single-threaded guest. coreutils `cat` drains its bounce pipe only
            // AFTER this splice returns, so `cat` of any file larger than one
            // pipe-full parked forever. Bound the read window by the room the
            // write path itself accounts for (`host_pipe_write_room`).
            let count = match this.splice_pipe_write_room(out_fd.0) {
                Some(room) if room > 0 => count.min(room),
                // Full pipe (or not a plain one-way host pipe): leave `count`
                // alone. A genuinely full pipe is exactly the case blocking
                // splice(2) is specified to wait out, and the write path's own
                // staging handles it.
                _ => count,
            };
            let mut offset = this.sendfile_offset(in_fd.0, off_in_address, memory)??;
            let bytes = this.sendfile_bytes(in_fd.0, offset, count)?;
            let outcome = match this.write_output_fd_partial(out_fd.0, &bytes, tid) {
                // Nothing moved: the destination pipe is full. SPLICE_F_NONBLOCK
                // reports EAGAIN; a blocking splice(2) must wait for room. Waiting
                // is safe in exactly this case — a full pipe can only be drained by
                // a DIFFERENT thread, so the write(2)-semantics path cannot
                // self-deadlock the way it does on a partially-filled pipe.
                DispatchOutcome::Errno { errno } if errno == LINUX_EAGAIN => {
                    if splice_flags.contains(LinuxSpliceFlags::NONBLOCK) {
                        return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                    }
                    this.write_output_fd(out_fd.0, &bytes, tid)
                }
                other => other,
            };
            let DispatchOutcome::Returned { value } = outcome else {
                return Ok(complete_wait(outcome));
            };
            let written = usize::try_from(value).unwrap_or(0);
            offset = offset.saturating_add(written);
            if off_in_address == 0 {
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
                        // Same contract as `sendfile`: HostFile reads via `pread`
                        // (sendfile_bytes), which does NOT advance the kernel
                        // offset, and `sendfile_offset` reads that offset back
                        // with `lseek(SEEK_CUR)`. Advance it explicitly or the
                        // next iteration re-reads the same window. Without this,
                        // coreutils `cat` — which drains a file through a pipe
                        // with `splice(file, NULL, pipe, NULL, n)` in a loop —
                        // re-sends offset 0 forever and never reaches EOF.
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
                .write_bytes(off_in_address, &(offset as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::Returned { value })
        }

        fn vmsplice(this, cx, fd: Fd, iov: GuestPtr, nr_segs: u64, flags: u64) {
            // vmsplice(2): fd must be a pipe; the pipe END selects the direction —
            // the WRITE end gathers user pages into the pipe, the READ end extracts
            // pipe bytes into user pages. SPLICE_F_GIFT/MOVE/MORE are advisory hints
            // for our copy-based path (no zero-copy page stealing); SPLICE_F_NONBLOCK
            // forces EAGAIN rather than blocking. A valid non-pipe fd is EINVAL; a
            // bad fd is EBADF.
            // `from_bits` rejects exactly the historical `& !SUPPORTED` set:
            // the type's full set IS the supported set.
            let Some(splice_flags) = LinuxSpliceFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let tid = cx.tid();
            let nr =
                usize::try_from(nr_segs).map_err(|_| DispatchError::LengthTooLarge(nr_segs))?;
            let memory = &mut *cx.memory;
            let iovecs = read_iovecs(memory, iov.0, nr)?;
            // SPLICE_F_NONBLOCK *or* an O_NONBLOCK pipe: vmsplice(2) blocks
            // only when both say it may.
            let nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                || this.fd_is_nonblocking(fd.0);

            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };

            enum VmDir {
                Write,
                /// Borrowed [`HostFd`] view + the owned handle keeping it live
                /// across the wait (mirrors the blocking-read plumbing).
                ReadHost(HostFd, Option<HostFdRef>),
                ReadMem,
            }
            let dir = {
                let Some(open) = open_file.description.read() else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                match &*open {
                    OpenDescription::HostPipe {
                        host_fd,
                        is_read_end,
                        ..
                    } => {
                        if *is_read_end {
                            VmDir::ReadHost(host_fd.view(), Some(host_fd.clone()))
                        } else {
                            VmDir::Write
                        }
                    }
                    OpenDescription::PipeWriter { .. } => VmDir::Write,
                    OpenDescription::PipeReader { .. } => VmDir::ReadMem,
                    // vmsplice(2): a valid fd that does not refer to a pipe is
                    // EBADF ("fd either not valid, or doesn't refer to a
                    // pipe"), NOT EINVAL — LTP vmsplice02's file-fd case.
                    _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                }
            };

            match dir {
                VmDir::Write => {
                    // vmsplice(2) into a pipe moves AT MOST what the pipe can
                    // hold and reports a SHORT count; the caller loops. Bound
                    // the gather by the destination's room so the transfer is
                    // a single non-blocking write. Without the bound, LTP
                    // `vmsplice01` handed 128 KiB to a 64 KiB pipe, the
                    // full-delivery write path parked on POLLOUT for the
                    // remainder, and the only reader could not run until this
                    // call returned — a hang until the 30 s test timeout.
                    let room = this.splice_pipe_write_room(fd.0);
                    if room == Some(0) {
                        return Ok(this.splice_output_would_block(fd.0, nonblocking));
                    }
                    let (bytes, faulted) = match gather_bounded_iovec_bytes(memory, &iovecs) {
                        Ok(Some(gathered)) => (gathered.bytes, gathered.faulted),
                        Ok(None) => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    if bytes.is_empty() {
                        // Same partial-transfer rule as `writev`: EFAULT only
                        // when the emptiness is a fault, not a zero-length list.
                        return if faulted {
                            Ok(DispatchOutcome::errno(LINUX_EFAULT))
                        } else {
                            Ok(DispatchOutcome::Returned { value: 0 })
                        };
                    }
                    let bytes = &bytes[..room.map_or(bytes.len(), |room| bytes.len().min(room))];
                    Ok(this.splice_write_out(fd.0, 0, bytes, memory, tid, nonblocking))
                }
                VmDir::ReadHost(hfd, owner) => Ok(Self::read_host_pipe_iovecs(
                    memory,
                    &iovecs,
                    hfd.get(),
                    owner,
                    nonblocking,
                    WaitFdAuthority::logical(
                        this.captured_slot_authority(fd.0).ok_or(LINUX_EBADF)?,
                    ),
                )),
                VmDir::ReadMem => {
                    let Some((pipe, status_flags)) = this.pipe_reader(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    let want: usize = iovecs
                        .iter()
                        .map(|v| usize::try_from(v.iov_len).unwrap_or(0))
                        .sum();
                    if want == 0 {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let bytes = match take_pipe_bytes(&pipe, want) {
                        PipeDrain::Bytes(bytes) => bytes,
                        PipeDrain::Eof => return Ok(DispatchOutcome::Returned { value: 0 }),
                        PipeDrain::WouldBlock => {
                            if nonblocking
                                || LinuxOpenFlags::from_bits_truncate(status_flags)
                                    .contains(LinuxOpenFlags::NONBLOCK)
                            {
                                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                            }
                            let wait = wait_for_pipe_readable(
                                &pipe,
                                WaitFdAuthority::logical(
                                    this.captured_slot_authority(fd.0).ok_or(LINUX_EBADF)?,
                                ),
                            );
                            return Ok(this.complete_wait_fd_authority(
                                wait,
                                &this.captured_file_table(),
                                [fd.0],
                            ));
                        }
                    };
                    let mut off = 0usize;
                    for v in &iovecs {
                        if off >= bytes.len() {
                            break;
                        }
                        let len =
                            usize::try_from(v.iov_len).unwrap_or(0).min(bytes.len() - off);
                        if len == 0 {
                            continue;
                        }
                        if memory
                            .write_bytes(v.iov_base, &bytes[off..off + len])
                            .is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        off += len;
                    }
                    Ok(DispatchOutcome::returned_len_or_errno(off))
                }
            }
        }
    }
}
