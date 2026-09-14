use carrick_abi::*;
use carrick_guest_mem::CurrentMmMemory;
use parking_lot::{Condvar, Mutex};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use super::*;
use crate::dispatch::fd_table::{HostFdRef, make_readiness_pipe};
use crate::dispatch::{FdWaitCompletion, WaitFds};

pub(crate) const DEFAULT_PIPE_CAPACITY: usize = 65536; // 64 KiB = 16 Linux pages
pub(crate) const MAX_PIPE_CAPACITY: usize = 1048576; // 1 MiB (/proc/sys/fs/pipe-max-size)
pub(crate) const PIPE_BUF: usize = 4096;

static NEXT_PIPE_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_pipe_id() -> u64 {
    NEXT_PIPE_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PipeState {
    pub(crate) buffer: VecDeque<u8>,
    pub(crate) capacity: usize,
    pub(crate) readers: usize,
    pub(crate) writers: usize,
    pub(crate) pipe_id: u64,
}

/// One in-memory guest pipe.
///
/// The two host readiness pipes (`read_pipe_ready`, `write_pipe_ready`) are the
/// level-triggered signals a host `poll`/`kqueue` waits on when a guest blocks
/// in `read`/`write` or registers the pipe with a readiness poller. They are
/// created LAZILY on the first such wait: a plain `pipe()` + copy + `close`
/// never needs them, and creating them eagerly cost every guest `pipe()` two
/// host `pipe(2)`s, four `F_DUPFD_CLOEXEC` relocations and eight `fcntl`s —
/// `ltp-pipe06` (524k pipes to `EMFILE`) ran ~29x Docker on that alone.
/// Creation is serialised under `state`, so a thread that holds the state
/// lock must use the `*_locked` accessors; the unlocked ones take the lock.
#[derive(Debug)]
pub(crate) struct PipeInner {
    pub(crate) state: Mutex<PipeState>,
    pub(crate) changed: Condvar,
    pub(crate) capacity_cell: Arc<AtomicI64>,
    read_pipe_ready: OnceLock<Option<(HostFdRef, HostFdRef)>>,
    write_pipe_ready: OnceLock<Option<(HostFdRef, HostFdRef)>>,
    read_notified: std::sync::atomic::AtomicBool,
    write_notified: std::sync::atomic::AtomicBool,
    pub(crate) wait_queue: Arc<crate::kernel::WaitQueue>,
}

pub(crate) type PipeRef = Arc<PipeInner>;

/// Exact publication authority captured before a write parks. It avoids
/// resolving a numeric guest fd after close or reuse.
pub(crate) struct PipeWriteNotification {
    kind: PipeWriteNotificationKind,
}

impl PipeWriteNotification {
    pub(crate) fn new(
        epoll_wake: crate::dispatch::EpollWakeHandle,
        kernel: Arc<crate::kernel::Kernel>,
        source_fd: i32,
    ) -> Self {
        Self {
            kind: PipeWriteNotificationKind::Live {
                epoll_wake,
                kernel,
                source_fd,
            },
        }
    }

    fn publish(&self, pipe: &PipeInner, bytes: usize) {
        match &self.kind {
            PipeWriteNotificationKind::Live {
                epoll_wake,
                kernel,
                source_fd,
            } => {
                epoll_wake.notify();
                crate::dispatch::fs::locks::fasync_notify_pipe_write(
                    kernel,
                    pipe.pipe_id(),
                    *source_fd,
                    bytes,
                );
            }
            #[cfg(test)]
            PipeWriteNotificationKind::Test => {}
        }
    }

    #[cfg(test)]
    fn for_tests() -> Self {
        Self {
            kind: PipeWriteNotificationKind::Test,
        }
    }
}

enum PipeWriteNotificationKind {
    Live {
        epoll_wake: crate::dispatch::EpollWakeHandle,
        kernel: Arc<crate::kernel::Kernel>,
        source_fd: i32,
    },
    #[cfg(test)]
    Test,
}

/// Functional writer-end ownership retained while a blocked large write is
/// driven by the continuation reactor. Holding only [`PipeRef`] is not enough:
/// a concurrent final `close(2)` would otherwise drop the writer description's
/// fd reference and publish EOF before this syscall finished its bytes.
pub(crate) struct PipeWriteEndpointLease {
    _description_lease: crate::kernel::objects::FileDescriptionFdLease,
    pipe: PipeRef,
    readiness_fd: HostFdRef,
    notification: PipeWriteNotification,
}

impl PipeWriteEndpointLease {
    pub(crate) fn retain(
        description_lease: crate::kernel::objects::FileDescriptionFdLease,
        pipe: PipeRef,
        readiness_fd: HostFdRef,
        notification: PipeWriteNotification,
    ) -> Arc<Self> {
        Arc::new(Self {
            _description_lease: description_lease,
            pipe,
            readiness_fd,
            notification,
        })
    }

    pub(crate) fn pipe(&self) -> &PipeRef {
        &self.pipe
    }

    pub(crate) fn readiness_fd(&self) -> &HostFdRef {
        &self.readiness_fd
    }

    pub(crate) fn publish_progress(&self, bytes: usize) {
        self.notification.publish(&self.pipe, bytes);
    }
}

pub(crate) fn pipe_writer_is_writable(state: &PipeState) -> bool {
    state.capacity.saturating_sub(state.buffer.len()) >= PIPE_BUF
}

impl PipeInner {
    pub(crate) fn new(pipe_id: u64, capacity: usize) -> Self {
        let capacity = capacity.clamp(PIPE_BUF, MAX_PIPE_CAPACITY);
        // The buffer grows on first write; a never-written pipe owns no heap.
        Self {
            state: Mutex::new(PipeState {
                buffer: VecDeque::new(),
                capacity,
                readers: 0,
                writers: 0,
                pipe_id,
            }),
            changed: Condvar::new(),
            capacity_cell: Arc::new(AtomicI64::new(capacity as i64)),
            read_pipe_ready: OnceLock::new(),
            write_pipe_ready: OnceLock::new(),
            read_notified: std::sync::atomic::AtomicBool::new(false),
            write_notified: std::sync::atomic::AtomicBool::new(false),
            wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_connected(pipe_id: u64, capacity: usize) -> Self {
        let pipe = Self::new(pipe_id, capacity);
        {
            let mut state = pipe.state.lock();
            state.readers = 1;
            state.writers = 1;
            pipe.update_readiness_locked(&state);
        }
        pipe
    }

    pub(crate) fn update_readiness_locked(&self, state: &PipeState) {
        let read_ready = !state.buffer.is_empty() || state.writers == 0;
        if let Some((r, w)) = self.read_pipe_ready.get().and_then(Option::as_ref) {
            if read_ready {
                if !self.read_notified.swap(true, Ordering::SeqCst) {
                    let _ = unsafe { libc::write(w.raw(), [1u8].as_ptr() as *const _, 1) };
                }
            } else if self.read_notified.swap(false, Ordering::SeqCst) {
                let mut buf = [0u8; 32];
                let _ = unsafe { libc::read(r.raw(), buf.as_mut_ptr() as *mut _, buf.len()) };
            }
        }

        let write_ready = state.readers == 0 || pipe_writer_is_writable(state);
        if let Some((r, w)) = self.write_pipe_ready.get().and_then(Option::as_ref) {
            if write_ready {
                if !self.write_notified.swap(true, Ordering::SeqCst) {
                    let _ = unsafe { libc::write(w.raw(), [1u8].as_ptr() as *const _, 1) };
                }
            } else if self.write_notified.swap(false, Ordering::SeqCst) {
                let mut buf = [0u8; 32];
                let _ = unsafe { libc::read(r.raw(), buf.as_mut_ptr() as *mut _, buf.len()) };
            }
        }

        self.wait_queue.wake_all();
    }

    /// The host fd a waiter polls (`POLLIN`) for "this pipe is readable",
    /// creating the readiness pipe on first use. `None` only when the host
    /// could not allocate the fds (the caller reports `EMFILE`).
    pub(crate) fn read_poll_fd(&self) -> Option<HostFdRef> {
        if let Some(ready) = self.read_pipe_ready.get() {
            return ready.as_ref().map(|(r, _)| r.clone());
        }
        let state = self.state.lock();
        self.read_poll_fd_locked(&state)
    }

    /// [`Self::read_poll_fd`] for a caller that already holds `state`.
    pub(crate) fn read_poll_fd_locked(&self, state: &PipeState) -> Option<HostFdRef> {
        if self.read_pipe_ready.get().is_none() {
            // Initialisation always runs under `state`, so a `get()` miss under
            // the lock means this thread is the one that creates it; the level
            // is primed from the current state before anyone can poll it.
            self.read_pipe_ready.get_or_init(make_readiness_pipe);
            self.update_readiness_locked(state);
        }
        self.read_pipe_ready
            .get()
            .and_then(Option::as_ref)
            .map(|(r, _)| r.clone())
    }

    /// The host fd a waiter polls (`POLLIN`) for "this pipe is writable" —
    /// the level protocol keeps one byte queued while the pipe has room —
    /// creating the readiness pipe on first use.
    pub(crate) fn write_poll_fd(&self) -> Option<HostFdRef> {
        if let Some(ready) = self.write_pipe_ready.get() {
            return ready.as_ref().map(|(r, _)| r.clone());
        }
        let state = self.state.lock();
        self.write_poll_fd_locked(&state)
    }

    /// [`Self::write_poll_fd`] for a caller that already holds `state`.
    pub(crate) fn write_poll_fd_locked(&self, state: &PipeState) -> Option<HostFdRef> {
        if self.write_pipe_ready.get().is_none() {
            self.write_pipe_ready.get_or_init(make_readiness_pipe);
            self.update_readiness_locked(state);
        }
        self.write_pipe_ready
            .get()
            .and_then(Option::as_ref)
            .map(|(r, _)| r.clone())
    }

    pub(crate) fn pipe_id(&self) -> u64 {
        self.state.lock().pipe_id
    }

    pub(crate) fn buffered_bytes(&self) -> usize {
        self.state.lock().buffer.len()
    }

    pub(crate) fn set_capacity(&self, new_capacity: usize) -> Result<usize, LinuxErrno> {
        let mut state = self.state.lock();
        if state.buffer.len() > new_capacity {
            return Err(LINUX_EBUSY);
        }
        state.capacity = new_capacity;
        self.capacity_cell
            .store(new_capacity as i64, Ordering::Release);
        self.update_readiness_locked(&state);
        drop(state);
        self.changed.notify_all();
        Ok(new_capacity)
    }

    #[allow(dead_code)]
    pub(crate) fn get_capacity(&self) -> usize {
        self.state.lock().capacity
    }
}

pub(crate) fn read_pipe<M: CurrentMmMemory>(
    memory: &mut M,
    address: u64,
    length: usize,
    pipe: &PipeRef,
    status_flags: u64,
    _fd: i32,
    authority: super::WaitFdAuthority,
) -> DispatchOutcome {
    if length == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }
    let nonblocking = status_flags & LINUX_O_NONBLOCK != 0;
    let mut state = pipe.state.lock();
    if !state.buffer.is_empty() {
        let read_len = state.buffer.len().min(length);
        let bytes: Vec<u8> = state.buffer.drain(..read_len).collect();
        pipe.update_readiness_locked(&state);
        drop(state);
        pipe.changed.notify_all();
        if memory.write_bytes(address, &bytes).is_err() {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        return DispatchOutcome::returned_len_or_errno(read_len);
    }
    if state.writers == 0 {
        // EOF: all writers closed and buffer empty
        return DispatchOutcome::Returned { value: 0 };
    }
    if nonblocking {
        DispatchOutcome::errno(LINUX_EAGAIN)
    } else {
        wait_for_pipe_readable_locked(pipe, &state, authority)
    }
}

/// Park until `pipe` has bytes (or loses its last writer): the one blocking
/// read wait every in-memory pipe consumer shares — `read(2)`, `splice(2)`
/// and `vmsplice(2)` out of a pipe.
fn wait_for_pipe_readable_locked(
    pipe: &PipeRef,
    state: &PipeState,
    authority: super::WaitFdAuthority,
) -> DispatchOutcome {
    if let Some(host_fd) = pipe.read_poll_fd_locked(state) {
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::authorized_raw_one(host_fd.raw(), libc::POLLIN, authority),
            timeout: None,
            sig_mask: carrick_abi::WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd {
                on_timeout: LINUX_EAGAIN.guest_retval(),
            },
        }
    } else {
        DispatchOutcome::errno(LINUX_EMFILE)
    }
}

/// Park a blocking splice/vmsplice reader on an empty pipe that still has
/// writers (see [`take_pipe_bytes`]).
pub(crate) fn wait_for_pipe_readable(
    pipe: &PipeRef,
    authority: super::WaitFdAuthority,
) -> DispatchOutcome {
    let state = pipe.state.lock();
    wait_for_pipe_readable_locked(pipe, &state, authority)
}

#[allow(dead_code)]
pub(crate) fn read_pipe_bytes(
    buf: &mut [u8],
    pipe: &PipeRef,
    _status_flags: u64,
    _tid: crate::thread::ThreadId,
) -> Result<usize, LinuxErrno> {
    if buf.is_empty() {
        return Ok(0);
    }
    let length = buf.len();
    let mut state = pipe.state.lock();
    if !state.buffer.is_empty() {
        let read_len = state.buffer.len().min(length);
        for (dest, src) in buf[..read_len]
            .iter_mut()
            .zip(state.buffer.drain(..read_len))
        {
            *dest = src;
        }
        pipe.update_readiness_locked(&state);
        drop(state);
        pipe.changed.notify_all();
        return Ok(read_len);
    }
    if state.writers == 0 {
        // EOF
        return Ok(0);
    }
    Err(LINUX_EAGAIN)
}

/// What draining an in-memory pipe for `splice`/`vmsplice` found. An empty
/// pipe is NOT a zero-byte transfer: with writers alive it is a wait (or
/// EAGAIN), and only with no writer left is it EOF. Collapsing the two into
/// an empty `Vec` made `splice(pipe -> file)` return 0 whenever the reader
/// outran the writer, so LTP splice02 ended its copy loop early under load.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PipeDrain {
    Bytes(Vec<u8>),
    Eof,
    WouldBlock,
}

pub(crate) fn take_pipe_bytes(pipe: &PipeRef, length: usize) -> PipeDrain {
    let mut state = pipe.state.lock();
    if state.buffer.is_empty() {
        if state.writers == 0 {
            return PipeDrain::Eof;
        }
        return PipeDrain::WouldBlock;
    }

    let read_len = state.buffer.len().min(length);
    let bytes = state.buffer.drain(..read_len).collect();
    pipe.update_readiness_locked(&state);
    drop(state);
    pipe.changed.notify_all();
    PipeDrain::Bytes(bytes)
}

pub(crate) fn restore_pipe_bytes(pipe: &PipeRef, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let mut state = pipe.state.lock();
    for byte in bytes.iter().rev() {
        state.buffer.push_front(*byte);
    }
    pipe.update_readiness_locked(&state);
    drop(state);
    pipe.changed.notify_all();
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InMemoryTeeOutcome {
    SamePipe,
    BrokenPipe,
    Eof,
    SourceWouldBlock,
    DestWouldBlock,
    Transferred(usize),
}

fn pipe_double_lock<'a>(
    p1: &'a PipeInner,
    p2: &'a PipeInner,
) -> (
    parking_lot::MutexGuard<'a, PipeState>,
    parking_lot::MutexGuard<'a, PipeState>,
) {
    let ptr1 = p1 as *const PipeInner as usize;
    let ptr2 = p2 as *const PipeInner as usize;
    if ptr1 < ptr2 {
        let g1 = p1.state.lock();
        let g2 = p2.state.lock();
        (g1, g2)
    } else {
        let g2 = p2.state.lock();
        let g1 = p1.state.lock();
        (g1, g2)
    }
}

pub(crate) fn tee_in_memory_pipes(
    in_pipe: &PipeRef,
    out_pipe: &PipeRef,
    count: usize,
) -> InMemoryTeeOutcome {
    if Arc::ptr_eq(in_pipe, out_pipe) || in_pipe.pipe_id() == out_pipe.pipe_id() {
        return InMemoryTeeOutcome::SamePipe;
    }
    if count == 0 {
        return InMemoryTeeOutcome::Transferred(0);
    }
    let (in_state, mut out_state) = pipe_double_lock(in_pipe, out_pipe);

    // Linux link_pipe checks destination readers first; broken destination pipe
    // takes precedence over empty source or full destination.
    if out_state.readers == 0 {
        return InMemoryTeeOutcome::BrokenPipe;
    }

    if in_state.buffer.is_empty() {
        if in_state.writers == 0 {
            return InMemoryTeeOutcome::Eof;
        }
        return InMemoryTeeOutcome::SourceWouldBlock;
    }

    let dest_room = out_state.capacity.saturating_sub(out_state.buffer.len());
    if dest_room == 0 {
        return InMemoryTeeOutcome::DestWouldBlock;
    }

    let copy_len = count.min(in_state.buffer.len()).min(dest_room);
    let (s1, s2) = in_state.buffer.as_slices();
    if copy_len <= s1.len() {
        out_state.buffer.extend(&s1[..copy_len]);
    } else {
        out_state.buffer.extend(s1);
        out_state.buffer.extend(&s2[..copy_len - s1.len()]);
    }
    out_pipe.update_readiness_locked(&out_state);

    drop(in_state);
    drop(out_state);
    out_pipe.changed.notify_all();

    InMemoryTeeOutcome::Transferred(copy_len)
}

/// Exact operation authority admitted before the pipe state lock. A parked
/// large write transfers this authority to its continuation; a non-parked
/// write drops it when the syscall returns.
pub(crate) struct PipeWriteOperation<I> {
    pub(crate) writer_lease: crate::kernel::objects::FileDescriptionFdLease,
    pub(crate) tid: crate::thread::ThreadId,
    pub(crate) authority: super::WaitFdAuthority,
    pub(crate) is_interrupted: I,
    /// Present only for syscall paths that can publish a parked continuation.
    /// Transfer helpers deliberately pass `None` and return their partial count.
    pub(crate) notification: Option<PipeWriteNotification>,
}

/// Perform the one synchronous in-memory pipe write step. A write can either
/// complete, return a partial count, wait before copying, or transfer its exact
/// operation authority to a continuation; it never retries synchronously.
pub(crate) fn write_pipe<I: Fn() -> bool>(
    bytes: &[u8],
    pipe: &PipeRef,
    status_flags: u64,
    operation: PipeWriteOperation<I>,
) -> DispatchOutcome {
    let nonblocking = status_flags & LINUX_O_NONBLOCK != 0;
    if bytes.is_empty() {
        return DispatchOutcome::Returned { value: 0 };
    }

    let mut state = pipe.state.lock();
    if state.readers == 0 {
        return DispatchOutcome::errno(LINUX_EPIPE);
    }

    let available = state.capacity.saturating_sub(state.buffer.len());
    // Writes <= PIPE_BUF are atomic. Larger writes with no room also wait
    // before their first byte rather than occupying an executor in a retry loop.
    if available == 0 || (bytes.len() <= PIPE_BUF && available < bytes.len()) {
        if nonblocking {
            return DispatchOutcome::errno(LINUX_EAGAIN);
        }
        if (operation.is_interrupted)() {
            return DispatchOutcome::errno(LINUX_EINTR);
        }
        let Some(host_fd) = pipe.write_poll_fd_locked(&state) else {
            return DispatchOutcome::errno(LINUX_EMFILE);
        };
        return DispatchOutcome::WaitOnFds {
            fds: WaitFds::authorized_raw_one(host_fd.raw(), libc::POLLIN, operation.authority),
            timeout: None,
            sig_mask: carrick_abi::WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd {
                on_timeout: LINUX_EAGAIN.guest_retval(),
            },
        };
    }

    let written = bytes.len().min(available);
    state.buffer.extend(&bytes[..written]);
    pipe.update_readiness_locked(&state);
    drop(state);
    pipe.changed.notify_all();

    if written == bytes.len() || nonblocking || (operation.is_interrupted)() {
        return DispatchOutcome::returned_len_or_errno(written);
    }
    let Some(readiness_fd) = pipe.write_poll_fd() else {
        return DispatchOutcome::returned_len_or_errno(written);
    };
    let Some(notification) = operation.notification else {
        return DispatchOutcome::returned_len_or_errno(written);
    };
    let endpoint = PipeWriteEndpointLease::retain(
        operation.writer_lease,
        Arc::clone(pipe),
        readiness_fd,
        notification,
    );
    endpoint.publish_progress(written);
    DispatchOutcome::BlockingWrite(crate::dispatch::BlockingWrite::in_memory_pipe(
        endpoint,
        bytes.to_vec(),
        written,
        operation.tid,
        true,
    ))
}

impl<'a> FsView<'a> {
    define_syscall! {
        fn pipe2(this, cx, pipefd: GuestPtr, flags: u64) {
            let address = pipefd.0;
            let memory = &mut *cx.memory;
            if super::LinuxPipe2Flags::from_bits(flags).is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let nonblock = flags & LINUX_O_NONBLOCK;
            let fd_flags = linux_fd_flags_from_open_flags(flags);

            let pipe_id = next_pipe_id();
            let pipe = Arc::new(PipeInner::new(pipe_id, DEFAULT_PIPE_CAPACITY));

            let mut read_base = OpenDescriptionBase::new(LINUX_O_RDONLY | nonblock)
                .with_fs_identity(crate::vfs::FsIdentity::Pipe);
            read_base.set_pipe_capacity_cell(Arc::clone(&pipe.capacity_cell));
            let mut write_base = OpenDescriptionBase::new(LINUX_O_WRONLY | nonblock)
                .with_fs_identity(crate::vfs::FsIdentity::Pipe);
            write_base.set_pipe_capacity_cell(Arc::clone(&pipe.capacity_cell));

            let read_open = OpenFile::from_open_description_with_status_flags(
                Arc::new(parking_lot::RwLock::new(OpenDescription::PipeReader {
                    base: read_base,
                    pipe: Arc::clone(&pipe),
                })),
                LINUX_O_RDONLY | nonblock,
                fd_flags,
            );
            let write_open = OpenFile::from_open_description_with_status_flags(
                Arc::new(parking_lot::RwLock::new(OpenDescription::PipeWriter {
                    base: write_base,
                    pipe,
                })),
                LINUX_O_WRONLY | nonblock,
                fd_flags,
            );
            let Ok((read_fd, write_fd)) = this.install_fd_pair_at_or_above(3, read_open, write_open)
            else {
                return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
            };
            let pair = LinuxFdPair { read_fd, write_fd };
            if write_kernel_struct_raw(memory, address, &pair).is_err() {
                let removed = {
                    let files = this.captured_file_table();
                    let mut table = files.write_open_files();
                    [table.remove(&read_fd), table.remove(&write_fd)]
                };
                for open_file in removed.into_iter().flatten() {
                    this.close_open_file_and_free_pty(&open_file);
                }
                this.note_fd_closed(read_fd);
                this.note_fd_closed(write_fd);
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::Returned { value: 0 })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::{InternalWaitKind, WaitFdAuthority};

    fn write_pipe_for_test(
        bytes: &[u8],
        pipe: &PipeRef,
        status_flags: u64,
        fd: i32,
        authority: WaitFdAuthority,
        is_interrupted: impl Fn() -> bool,
    ) -> DispatchOutcome {
        let description = Arc::new(
            crate::kernel::FileDescription::concrete_with_status_flags(
                Arc::new(parking_lot::RwLock::new(OpenDescription::PipeWriter {
                    base: OpenDescriptionBase::new(LINUX_O_WRONLY | status_flags),
                    pipe: Arc::clone(pipe),
                })),
                LINUX_O_WRONLY | status_flags,
            )
            .expect("test pipe writer description"),
        );
        description.retain_fd_ref();
        let lease = description
            .retain_fd_lease()
            .expect("test writer has an fd reference");
        let outcome = write_pipe(
            bytes,
            pipe,
            status_flags,
            PipeWriteOperation {
                writer_lease: lease,
                tid: crate::thread::ThreadId::synthetic_for_tests(fd),
                authority,
                is_interrupted,
                notification: None,
            },
        );
        description.release_fd_ref();
        outcome
    }

    fn write_readiness_is_signaled(pipe: &PipeInner) -> bool {
        let fd = pipe.write_poll_fd().expect("write readiness fd");
        let mut pollfd = libc::pollfd {
            fd: fd.raw(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut pollfd, 1, 0) > 0 && pollfd.revents & libc::POLLIN != 0 }
    }

    #[test]
    fn in_memory_pipe_basic_read_write() {
        let pipe = Arc::new(PipeInner::new_connected(1, 65536));
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        let data = b"hello, in-memory pipe!";
        let out = write_pipe_for_test(
            data,
            &pipe,
            0,
            4,
            WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
            || false,
        );
        assert_eq!(out, DispatchOutcome::returned_len_or_errno(data.len()));

        let mut buf = vec![0u8; data.len()];
        let read_n = read_pipe_bytes(&mut buf, &pipe, 0, tid).expect("read");
        assert_eq!(read_n, data.len());
        assert_eq!(&buf[..], data);
    }

    #[test]
    fn in_memory_pipe_write_readiness_requires_pipe_buf_room() {
        let pipe = Arc::new(PipeInner::new_connected(5, PIPE_BUF));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        let tid = crate::thread::ThreadId::synthetic_for_tests(5);
        let payload = vec![0x55; PIPE_BUF];

        assert!(write_readiness_is_signaled(&pipe));
        assert_eq!(
            write_pipe_for_test(&payload, &pipe, LINUX_O_NONBLOCK, 4, authority, || false),
            DispatchOutcome::returned_len_or_errno(PIPE_BUF)
        );
        assert!(!write_readiness_is_signaled(&pipe));

        let mut half = vec![0; PIPE_BUF / 2];
        assert_eq!(
            read_pipe_bytes(&mut half, &pipe, LINUX_O_NONBLOCK, tid),
            Ok(PIPE_BUF / 2)
        );
        assert!(
            !write_readiness_is_signaled(&pipe),
            "free space below PIPE_BUF must not be writable"
        );

        assert_eq!(
            read_pipe_bytes(&mut half, &pipe, LINUX_O_NONBLOCK, tid),
            Ok(PIPE_BUF / 2)
        );
        assert!(
            write_readiness_is_signaled(&pipe),
            "PIPE_BUF free bytes must be writable"
        );
    }

    #[test]
    fn in_memory_pipe_capacity_and_resize() {
        let pipe = Arc::new(PipeInner::new_connected(2, 4096));

        assert_eq!(pipe.get_capacity(), 4096);
        assert_eq!(pipe.set_capacity(8192), Ok(8192));
        assert_eq!(pipe.get_capacity(), 8192);

        // Fill 5000 bytes
        let data = vec![0x42u8; 5000];
        let out = write_pipe_for_test(
            &data,
            &pipe,
            0,
            4,
            WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
            || false,
        );
        assert_eq!(out, DispatchOutcome::Returned { value: 5000 });

        // Shrinking below buffered bytes must return EBUSY
        assert_eq!(pipe.set_capacity(4096), Err(LINUX_EBUSY));

        // Growing capacity succeeds
        assert_eq!(pipe.set_capacity(16384), Ok(16384));
    }

    #[test]
    fn in_memory_pipe_broken_pipe_and_eof() {
        let pipe = Arc::new(PipeInner::new_connected(3, 4096));
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        // Close all readers
        pipe.state.lock().readers = 0;
        let out = write_pipe_for_test(
            b"test",
            &pipe,
            0,
            4,
            WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
            || false,
        );
        assert_eq!(out, DispatchOutcome::errno(LINUX_EPIPE));

        // Restore reader, close all writers
        pipe.state.lock().readers = 1;
        pipe.state.lock().writers = 0;
        let mut buf = [0u8; 10];
        let n = read_pipe_bytes(&mut buf, &pipe, 0, tid).expect("read");
        assert_eq!(n, 0); // EOF
    }

    #[test]
    fn in_memory_pipe_nonblocking_eagain() {
        let pipe = Arc::new(PipeInner::new_connected(4, 4096));
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        // Read from empty nonblocking pipe -> EAGAIN
        let mut buf = [0u8; 10];
        assert_eq!(
            read_pipe_bytes(&mut buf, &pipe, LINUX_O_NONBLOCK, tid),
            Err(LINUX_EAGAIN)
        );

        // Fill pipe to capacity
        let data = vec![0xaa; 4096];
        assert_eq!(
            write_pipe_for_test(
                &data,
                &pipe,
                LINUX_O_NONBLOCK,
                4,
                WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
                || false,
            ),
            DispatchOutcome::Returned { value: 4096 }
        );

        // Write to full nonblocking pipe -> EAGAIN
        assert_eq!(
            write_pipe_for_test(
                b"more",
                &pipe,
                LINUX_O_NONBLOCK,
                4,
                WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
                || false,
            ),
            DispatchOutcome::errno(LINUX_EAGAIN)
        );
    }

    #[test]
    fn in_memory_pipe_blocking_write_to_full_parks_on_readiness() {
        let pipe = Arc::new(PipeInner::new_connected(10, 65536));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        let fill = vec![0x33; 65536];
        assert_eq!(
            write_pipe_for_test(&fill, &pipe, 0, 4, authority.clone(), || false),
            DispatchOutcome::Returned { value: 65536 }
        );

        // Pipe is now completely full (65536 bytes). A blocking write of 65536 bytes
        // must park via WaitOnFds rather than spinning or returning 0.
        let out = write_pipe_for_test(&fill, &pipe, 0, 4, authority.clone(), || false);
        let host_fd = pipe.write_poll_fd().expect("write poll fd");
        assert_eq!(
            out,
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::authorized_raw_one(host_fd.raw(), libc::POLLIN, authority),
                timeout: None,
                sig_mask: carrick_abi::WaitSigMask::NONE,
                completion: FdWaitCompletion::Fd {
                    on_timeout: LINUX_EAGAIN.guest_retval(),
                },
            }
        );
    }

    #[test]
    fn in_memory_pipe_interrupted_write_returns_eintr_when_unwritten() {
        let pipe = Arc::new(PipeInner::new_connected(11, 4096));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        let fill = vec![0x44; 4096];
        assert_eq!(
            write_pipe_for_test(&fill, &pipe, 0, 4, authority.clone(), || false),
            DispatchOutcome::Returned { value: 4096 }
        );

        // Pipe is full; write interrupted immediately must return EINTR, not 0.
        let out = write_pipe_for_test(b"blocked", &pipe, 0, 4, authority, || true);
        assert_eq!(out, DispatchOutcome::errno(LINUX_EINTR));
    }

    #[test]
    fn parked_large_write_keeps_writer_functional_after_numeric_close() {
        let pipe = Arc::new(PipeInner::new(14, PIPE_BUF));
        // The reader end is live independently of the writer description
        // constructed below.
        pipe.state.lock().readers = 1;
        let description = Arc::new(
            crate::kernel::FileDescription::concrete_with_status_flags(
                Arc::new(parking_lot::RwLock::new(OpenDescription::PipeWriter {
                    base: OpenDescriptionBase::new(LINUX_O_WRONLY),
                    pipe: Arc::clone(&pipe),
                })),
                LINUX_O_WRONLY,
            )
            .expect("writer description"),
        );
        description.retain_fd_ref();
        let lease = description
            .retain_fd_lease()
            .expect("admit live writer before pipe lock");

        let payload = vec![0x7c; PIPE_BUF * 2];
        let mut blocked = match write_pipe(
            &payload,
            &pipe,
            0,
            PipeWriteOperation {
                writer_lease: lease,
                tid: crate::thread::ThreadId::synthetic_for_tests(14),
                authority: WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
                is_interrupted: || false,
                notification: Some(PipeWriteNotification::for_tests()),
            },
        ) {
            DispatchOutcome::BlockingWrite(write) => write,
            other => panic!("expected parked partial write, got {other:?}"),
        };

        // The numeric fd closes while the continuation is parked. Its exact
        // functional lease keeps the writer endpoint live, so the reader must
        // not observe EOF before the staged suffix lands.
        description.release_fd_ref();
        assert_eq!(description.fd_ref_count(), 1);
        assert_eq!(pipe.state.lock().writers, 1);

        let mut first = vec![0; PIPE_BUF];
        assert_eq!(
            read_pipe_bytes(
                &mut first,
                &pipe,
                LINUX_O_NONBLOCK,
                crate::thread::ThreadId::synthetic_for_tests(14),
            ),
            Ok(PIPE_BUF)
        );
        assert_eq!(first, vec![0x7c; PIPE_BUF]);
        match crate::dispatch::drive_blocking_write(&mut blocked) {
            crate::dispatch::BlockingWriteStep::Done(DispatchOutcome::Returned { value }) => {
                assert_eq!(value, payload.len() as i64);
            }
            _ => panic!("expected completed blocked write"),
        }
        drop(blocked);
        assert_eq!(description.fd_ref_count(), 0);
        assert_eq!(pipe.state.lock().writers, 0);
    }

    #[test]
    fn aggregate_fault_truncates_staged_current_suffix_at_copy_boundary() {
        let pipe = Arc::new(PipeInner::new(16, PIPE_BUF));
        pipe.state.lock().readers = 1;
        let description = Arc::new(
            crate::kernel::FileDescription::concrete_with_status_flags(
                Arc::new(parking_lot::RwLock::new(OpenDescription::PipeWriter {
                    base: OpenDescriptionBase::new(LINUX_O_WRONLY),
                    pipe: Arc::clone(&pipe),
                })),
                LINUX_O_WRONLY,
            )
            .expect("writer description"),
        );
        description.retain_fd_ref();
        let lease = description.retain_fd_lease().expect("live writer");
        let current = vec![0x6b; PIPE_BUF + 1];
        let mut blocked = match write_pipe(
            &current,
            &pipe,
            0,
            PipeWriteOperation {
                writer_lease: lease,
                tid: crate::thread::ThreadId::synthetic_for_tests(16),
                authority: WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
                is_interrupted: || false,
                notification: Some(PipeWriteNotification::for_tests()),
            },
        ) {
            DispatchOutcome::BlockingWrite(write) => {
                // A 32-byte valid next iovec followed by EFAULT has a 4KiB
                // aggregate boundary: the uncommitted byte of `current` and
                // all staged tail bytes are excluded.
                write.with_in_memory_pipe_writev_boundary(vec![0x6c; 32], 0, PIPE_BUF)
            }
            other => panic!("expected parked write, got {other:?}"),
        };
        description.release_fd_ref();
        // If the aggregate boundary falls below bytes already copied into the
        // pipe, the continuation cannot retract them.
        let irreversible =
            blocked
                .clone()
                .with_in_memory_pipe_writev_boundary(Vec::new(), 1, PIPE_BUF);
        assert_eq!(irreversible.offset, PIPE_BUF);
        assert_eq!(irreversible.bytes.len(), PIPE_BUF);
        let mut first = vec![0; PIPE_BUF];
        assert_eq!(
            read_pipe_bytes(
                &mut first,
                &pipe,
                LINUX_O_NONBLOCK,
                crate::thread::ThreadId::synthetic_for_tests(16),
            ),
            Ok(PIPE_BUF)
        );
        assert_eq!(first, vec![0x6b; PIPE_BUF]);
        match crate::dispatch::drive_blocking_write(&mut blocked) {
            crate::dispatch::BlockingWriteStep::Done(DispatchOutcome::Returned { value }) => {
                assert_eq!(value, PIPE_BUF as i64);
            }
            _ => panic!("expected copy-boundary completion"),
        }
    }

    #[test]
    fn aggregate_blocking_write_excludes_unadmitted_later_vectors() {
        let pipe = Arc::new(PipeInner::new(15, PIPE_BUF));
        pipe.state.lock().readers = 1;
        let description = Arc::new(
            crate::kernel::FileDescription::concrete_with_status_flags(
                Arc::new(parking_lot::RwLock::new(OpenDescription::PipeWriter {
                    base: OpenDescriptionBase::new(LINUX_O_WRONLY),
                    pipe: Arc::clone(&pipe),
                })),
                LINUX_O_WRONLY,
            )
            .expect("writer description"),
        );
        description.retain_fd_ref();
        let lease = description.retain_fd_lease().expect("live writer");
        let current = vec![0x41; PIPE_BUF * 2];
        let mut blocked = match write_pipe(
            &current,
            &pipe,
            0,
            PipeWriteOperation {
                writer_lease: lease,
                tid: crate::thread::ThreadId::synthetic_for_tests(15),
                authority: WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
                is_interrupted: || false,
                notification: Some(PipeWriteNotification::for_tests()),
            },
        ) {
            DispatchOutcome::BlockingWrite(write) => {
                // Three bytes preceded this current iovec. A later fault
                // retains only complete aggregate copy blocks.
                write.with_in_memory_pipe_writev_boundary(Vec::new(), 3, PIPE_BUF * 2)
            }
            other => panic!("expected parked write, got {other:?}"),
        };
        description.release_fd_ref();

        let mut first = vec![0; PIPE_BUF];
        assert_eq!(
            read_pipe_bytes(
                &mut first,
                &pipe,
                LINUX_O_NONBLOCK,
                crate::thread::ThreadId::synthetic_for_tests(15),
            ),
            Ok(PIPE_BUF)
        );
        let crate::dispatch::BlockingWriteStep::Done(outcome) =
            crate::dispatch::drive_blocking_write(&mut blocked)
        else {
            panic!("second pipe progress must complete the admitted aggregate");
        };
        assert_eq!(
            outcome,
            // The current vector's final three bytes belong to the incomplete
            // aggregate copy block after the later fault and are not visible.
            DispatchOutcome::returned_len_or_errno(PIPE_BUF * 2)
        );
        let mut second = vec![0; PIPE_BUF - 3];
        assert_eq!(
            read_pipe_bytes(
                &mut second,
                &pipe,
                LINUX_O_NONBLOCK,
                crate::thread::ThreadId::synthetic_for_tests(15),
            ),
            Ok(PIPE_BUF - 3)
        );
        assert_eq!(second, vec![0x41; PIPE_BUF - 3]);
        // The physical pipe has only the retained current-vector bytes;
        // the logical prefix of three came from an earlier writev vector.
        assert_eq!(3 + first.len() + second.len(), PIPE_BUF * 2);
        let mut tail = [0; 1];
        assert_eq!(
            read_pipe_bytes(
                &mut tail,
                &pipe,
                LINUX_O_NONBLOCK,
                crate::thread::ThreadId::synthetic_for_tests(15),
            ),
            Err(LINUX_EAGAIN)
        );
    }

    #[test]
    fn in_memory_pipe_write_with_room_ignores_pending_interrupt() {
        let pipe = Arc::new(PipeInner::new_connected(13, 4096));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        // Room for the whole write: a pending signal must not turn it into
        // EINTR (a signal handler writing one wake-up byte while a second
        // signal is pending is exactly this case).
        assert_eq!(
            write_pipe_for_test(b"x", &pipe, 0, 4, authority.clone(), || true),
            DispatchOutcome::Returned { value: 1 }
        );
        assert_eq!(pipe.buffered_bytes(), 1);
    }

    #[test]
    fn in_memory_pipe_zero_length_write_returns_zero() {
        let pipe = Arc::new(PipeInner::new_connected(12, 4096));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        assert_eq!(
            write_pipe_for_test(&[], &pipe, 0, 4, authority, || false),
            DispatchOutcome::Returned { value: 0 }
        );
    }
}
