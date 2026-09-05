use carrick_abi::*;
use carrick_guest_mem::CurrentMmMemory;
use parking_lot::{Condvar, Mutex};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use super::DispatchOutcome;
use crate::dispatch::WaitFds;
use crate::dispatch::fd_table::{HostFdRef, make_readiness_pipe};

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
}

pub(crate) type PipeRef = Arc<PipeInner>;

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
        return DispatchOutcome::Returned {
            value: read_len as i64,
        };
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
            on_timeout: LINUX_EAGAIN.guest_retval(),
            sig_mask: carrick_abi::WaitSigMask::NONE,
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

pub(crate) fn write_pipe(
    bytes: &[u8],
    pipe: &PipeRef,
    status_flags: u64,
    _fd: i32,
    authority: super::WaitFdAuthority,
    is_interrupted: impl Fn() -> bool,
) -> DispatchOutcome {
    let nonblocking = status_flags & LINUX_O_NONBLOCK != 0;
    let length = bytes.len();
    if length == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }

    let mut written = 0;
    let mut state = pipe.state.lock();

    while written < length {
        if state.readers == 0 {
            if written > 0 {
                break;
            }
            return DispatchOutcome::errno(LINUX_EPIPE);
        }

        // A pending signal is consulted only where this write would WAIT.
        // Checking it before the copy made a write with room return EINTR
        // with nothing written: `sigunblockpending` unblocks two signals,
        // the first handler's pipe write ran with the second still pending
        // and lost its byte. Linux never interrupts a write that can
        // complete immediately.
        let capacity = state.capacity;
        let available = capacity.saturating_sub(state.buffer.len());

        // Writes <= PIPE_BUF (4096) must be atomic: all or wait.
        // Writes > PIPE_BUF with no room at all (available == 0) must also wait
        // for readiness before writing anything, rather than spinning in the vCPU.
        if written == 0 && (available == 0 || (length <= PIPE_BUF && available < length)) {
            if nonblocking {
                return DispatchOutcome::errno(LINUX_EAGAIN);
            }
            // Entering the sleep with a signal already pending is the one
            // place a write with nothing written answers EINTR (the BSD
            // `PCATCH`-on-entry rule).
            if is_interrupted() {
                return DispatchOutcome::errno(LINUX_EINTR);
            }
            let Some(host_fd) = pipe.write_poll_fd_locked(&state) else {
                return DispatchOutcome::errno(LINUX_EMFILE);
            };
            // The readiness protocol is a LEVEL signal: while the pipe is
            // guest-writable, one byte sits in the write-readiness
            // notification pipe, so the host wait is POLLIN on its READ end.
            // POLLOUT here polled a pipe read end for writability, which the
            // host never reports — the park completed only via signals or
            // timeouts, never via the reader draining the buffer.
            return DispatchOutcome::WaitOnFds {
                fds: WaitFds::authorized_raw_one(host_fd.raw(), libc::POLLIN, authority),
                timeout: None,
                on_timeout: LINUX_EAGAIN.guest_retval(),
                sig_mask: carrick_abi::WaitSigMask::NONE,
            };
        }

        if available > 0 {
            let chunk = (length - written).min(available);
            state.buffer.extend(&bytes[written..written + chunk]);
            written += chunk;
            pipe.update_readiness_locked(&state);
            pipe.changed.notify_all();
            if written == length || nonblocking {
                break;
            }
        } else if nonblocking {
            if written > 0 {
                break;
            }
            return DispatchOutcome::errno(LINUX_EAGAIN);
        }

        // Blocking write with no space left: wait for reader to consume or signal to interrupt.
        if is_interrupted() {
            break;
        }
        pipe.changed
            .wait_for(&mut state, std::time::Duration::from_millis(20));
        if is_interrupted() {
            break;
        }
    }

    pipe.update_readiness_locked(&state);
    drop(state);
    pipe.changed.notify_all();
    if written == 0 {
        DispatchOutcome::errno(LINUX_EINTR)
    } else {
        DispatchOutcome::Returned {
            value: written as i64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::{InternalWaitKind, WaitFdAuthority};

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
        let out = write_pipe(
            data,
            &pipe,
            0,
            4,
            WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
            || false,
        );
        assert_eq!(
            out,
            DispatchOutcome::Returned {
                value: data.len() as i64
            }
        );

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
            write_pipe(&payload, &pipe, LINUX_O_NONBLOCK, 4, authority, || false),
            DispatchOutcome::Returned {
                value: PIPE_BUF as i64
            }
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
        let out = write_pipe(
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
        let out = write_pipe(
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
            write_pipe(
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
            write_pipe(
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
            write_pipe(&fill, &pipe, 0, 4, authority.clone(), || false),
            DispatchOutcome::Returned { value: 65536 }
        );

        // Pipe is now completely full (65536 bytes). A blocking write of 65536 bytes
        // must park via WaitOnFds rather than spinning or returning 0.
        let out = write_pipe(&fill, &pipe, 0, 4, authority.clone(), || false);
        let host_fd = pipe.write_poll_fd().expect("write poll fd");
        assert_eq!(
            out,
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::authorized_raw_one(host_fd.raw(), libc::POLLIN, authority),
                timeout: None,
                on_timeout: LINUX_EAGAIN.guest_retval(),
                sig_mask: carrick_abi::WaitSigMask::NONE,
            }
        );
    }

    #[test]
    fn in_memory_pipe_interrupted_write_returns_eintr_when_unwritten() {
        let pipe = Arc::new(PipeInner::new_connected(11, 4096));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        let fill = vec![0x44; 4096];
        assert_eq!(
            write_pipe(&fill, &pipe, 0, 4, authority.clone(), || false),
            DispatchOutcome::Returned { value: 4096 }
        );

        // Pipe is full; write interrupted immediately must return EINTR, not 0.
        let out = write_pipe(b"blocked", &pipe, 0, 4, authority, || true);
        assert_eq!(out, DispatchOutcome::errno(LINUX_EINTR));
    }

    #[test]
    fn in_memory_pipe_write_with_room_ignores_pending_interrupt() {
        let pipe = Arc::new(PipeInner::new_connected(13, 4096));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        // Room for the whole write: a pending signal must not turn it into
        // EINTR (a signal handler writing one wake-up byte while a second
        // signal is pending is exactly this case).
        assert_eq!(
            write_pipe(b"x", &pipe, 0, 4, authority.clone(), || true),
            DispatchOutcome::Returned { value: 1 }
        );
        assert_eq!(pipe.buffered_bytes(), 1);
    }

    #[test]
    fn in_memory_pipe_zero_length_write_returns_zero() {
        let pipe = Arc::new(PipeInner::new_connected(12, 4096));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        assert_eq!(
            write_pipe(&[], &pipe, 0, 4, authority, || false),
            DispatchOutcome::Returned { value: 0 }
        );
    }
}
