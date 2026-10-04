//! Connection tracking and per-connection worker management for CarrierControlServer.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Instant;

use parking_lot::Mutex;

use super::{ControlEndpoint, ControlNonce};

pub(super) const CONTROL_MAX_CONNECTIONS: usize = 16;

pub(super) struct ConnectionTracker {
    next_id: u64,
    slots: Arc<ConnectionSlots>,
    cancellation: Arc<ControlCancellation>,
    handlers: Vec<JoinHandle<()>>,
}

#[derive(Default)]
struct ConnectionState {
    live: usize,
}

#[derive(Default)]
pub(super) struct ConnectionSlots {
    state: Mutex<ConnectionState>,
    #[cfg(test)]
    changed: parking_lot::Condvar,
}

struct ConnectionPermit {
    slots: Arc<ConnectionSlots>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut state = self.slots.state.lock();
        state.live -= 1;
        #[cfg(test)]
        self.slots.changed.notify_all();
    }
}

#[cfg(test)]
impl ConnectionSlots {
    pub(super) fn wait_for_count(&self, expected: usize, bound: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + bound;
        let mut state = self.state.lock();
        while state.live != expected {
            if self.changed.wait_until(&mut state, deadline).timed_out() {
                return state.live == expected;
            }
        }
        true
    }
}

impl std::fmt::Debug for ConnectionTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.slots.state.lock();
        f.debug_struct("ConnectionTracker")
            .field("next_id", &self.next_id)
            .field("live_handlers", &state.live)
            .field("handlers", &self.handlers.len())
            .finish()
    }
}

impl ConnectionTracker {
    pub(super) fn new(cancellation: Arc<ControlCancellation>) -> Self {
        Self {
            next_id: 0,
            slots: Arc::default(),
            cancellation,
            handlers: Vec::new(),
        }
    }

    fn reap_finished(&mut self) {
        let mut finished = Vec::new();
        let mut active = Vec::new();
        for handle in self.handlers.drain(..) {
            if handle.is_finished() {
                finished.push(handle);
            } else {
                active.push(handle);
            }
        }
        self.handlers = active;
        for handle in finished {
            let _ = handle.join();
        }
    }

    pub(super) fn spawn_handler(
        &mut self,
        stream: UnixStream,
        kernel: Arc<super::super::Kernel>,
        init: super::super::TaskKey,
        nonce: ControlNonce,
        exec: Arc<dyn super::CarrierExecAdmission>,
        archive: Arc<dyn super::CarrierArchiveControl>,
    ) {
        self.reap_finished();
        let mut state = self.slots.state.lock();
        if state.live >= CONTROL_MAX_CONNECTIONS {
            let _ = stream.shutdown(Shutdown::Both);
            drop(stream);
            return;
        }

        let Ok(connection) = ControlConnection::new(stream, Arc::clone(&self.cancellation)) else {
            return;
        };
        let id = self.next_id;
        self.next_id += 1;
        state.live += 1;
        #[cfg(test)]
        self.slots.changed.notify_all();
        let permit = ConnectionPermit {
            slots: Arc::clone(&self.slots),
        };
        drop(state);

        let builder = std::thread::Builder::new();
        if let Ok(handle) = builder
            .name(format!("carrick-control-conn-{id}"))
            .spawn(move || {
                // Declare the permit first so it drops last, after the
                // socket and request context, on return or unwinding. A
                // failed spawn also drops the captured permit and rolls
                // back admission without needing a handler to start.
                let _permit = permit;
                let mut connection = connection;
                let context = ControlServerContext {
                    kernel,
                    init,
                    nonce,
                    exec,
                    archive,
                };
                if let Err(_error) = super::handle(
                    &mut connection,
                    &context.kernel,
                    context.init,
                    context.nonce,
                    context.exec.as_ref(),
                    context.archive.as_ref(),
                ) {
                    #[cfg(test)]
                    eprintln!("carrier control test connection failed: {_error}");
                }
            })
        {
            self.handlers.push(handle);
        }
    }

    pub(super) fn cancel_and_join(&mut self) {
        // The pipe stays readable after cancellation, waking every current
        // and future wait. Joins hold no slot-state lock needed by release.
        self.cancellation.cancel();
        for h in self.handlers.drain(..) {
            let _ = h.join();
        }
    }

    #[cfg(test)]
    pub(super) fn live_handlers_count(&self) -> usize {
        self.slots.state.lock().live
    }

    #[cfg(test)]
    pub(super) fn retained_handlers_count(&self) -> usize {
        self.handlers.len()
    }

    #[cfg(test)]
    pub(super) fn slot_observer(&self) -> Arc<ConnectionSlots> {
        Arc::clone(&self.slots)
    }
}

pub(super) struct ControlServerContext {
    pub(super) kernel: Arc<super::super::Kernel>,
    pub(super) init: super::super::TaskKey,
    pub(super) nonce: ControlNonce,
    pub(super) exec: Arc<dyn super::CarrierExecAdmission>,
    pub(super) archive: Arc<dyn super::CarrierArchiveControl>,
}

pub(super) fn run_accept_loop(
    listener: UnixListener,
    thread_shutdown: Arc<AtomicBool>,
    context: ControlServerContext,
    thread_endpoint: ControlEndpoint,
    tracker: Arc<Mutex<ConnectionTracker>>,
    cancellation: Arc<ControlCancellation>,
) {
    while !thread_shutdown.load(Ordering::Acquire) {
        let (stream, _) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if cancellation
                    .wait(listener.as_fd(), libc::POLLIN, None)
                    .is_err()
                {
                    break;
                }
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if thread_shutdown.load(Ordering::Acquire) {
            break;
        }
        tracker.lock().spawn_handler(
            stream,
            Arc::clone(&context.kernel),
            context.init,
            context.nonce,
            Arc::clone(&context.exec),
            Arc::clone(&context.archive),
        );
    }
    tracker.lock().cancel_and_join();
    // Ownership of the record is the server's, not the accept
    // loop's: `shutdown` releases it, and a teardown quiesce keeps
    // it (marked `TearingDown`) until the terminal receipt is
    // durable.
    drop(thread_endpoint);
}

#[derive(Debug)]
pub(super) struct ControlCancellation {
    read: OwnedFd,
    write: Mutex<Option<File>>,
    cancelled: AtomicBool,
    #[cfg(test)]
    waiting_handlers: Mutex<usize>,
    #[cfg(test)]
    changed: parking_lot::Condvar,
}

impl ControlCancellation {
    pub(super) fn new() -> io::Result<Self> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // Adopt both ends immediately so every later failure closes them.
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        for fd in [&read, &write] {
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            if flags < 0
                || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) }
                    < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            read,
            write: Mutex::new(Some(File::from(write))),
            cancelled: AtomicBool::new(false),
            #[cfg(test)]
            waiting_handlers: Mutex::new(0),
            #[cfg(test)]
            changed: parking_lot::Condvar::new(),
        })
    }

    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(mut writer) = self.write.lock().take() {
            // A single byte fits an empty pipe; nobody drains it. Closing
            // the writer also publishes HUP if the write itself fails.
            let _ = writer.write_all(&[1]);
        }
    }

    fn check(&self) -> io::Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "control server cancelled",
            ))
        } else {
            Ok(())
        }
    }

    fn wait(&self, fd: BorrowedFd<'_>, events: i16, deadline: Option<Instant>) -> io::Result<()> {
        loop {
            self.check()?;
            let timeout = match deadline {
                None => -1,
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "control write deadline exceeded",
                        ));
                    }
                    i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX)
                }
            };
            let mut fds = [
                libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.read.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
            self.check()?;
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            if fds[1].revents != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "control cancellation pipe closed",
                ));
            }
            if fds[0].revents != 0 {
                return Ok(());
            }
        }
    }

    #[cfg(test)]
    fn observe_handler_wait(&self) -> HandlerWait<'_> {
        *self.waiting_handlers.lock() += 1;
        self.changed.notify_all();
        HandlerWait(self)
    }

    #[cfg(test)]
    pub(super) fn wait_for_handlers(&self, expected: usize, bound: std::time::Duration) -> bool {
        let deadline = Instant::now() + bound;
        let mut count = self.waiting_handlers.lock();
        while *count != expected {
            if self.changed.wait_until(&mut count, deadline).timed_out() {
                return *count == expected;
            }
        }
        true
    }
}

#[cfg(test)]
struct HandlerWait<'a>(&'a ControlCancellation);

#[cfg(test)]
impl Drop for HandlerWait<'_> {
    fn drop(&mut self) {
        *self.0.waiting_handlers.lock() -= 1;
        self.0.changed.notify_all();
    }
}

pub(super) struct ControlConnection {
    stream: UnixStream,
    cancellation: Arc<ControlCancellation>,
}

impl ControlConnection {
    pub(super) fn new(
        stream: UnixStream,
        cancellation: Arc<ControlCancellation>,
    ) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            cancellation,
        })
    }
}

impl AsRawFd for ControlConnection {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.stream.as_raw_fd()
    }
}

impl Read for ControlConnection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            self.cancellation.check()?;
            match self.stream.read(bytes) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    #[cfg(test)]
                    let _waiting = self.cancellation.observe_handler_wait();
                    self.cancellation
                        .wait(self.stream.as_fd(), libc::POLLIN, None)?;
                }
                result => return result,
            }
        }
    }
}

impl Write for ControlConnection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let deadline = Instant::now() + super::DEADLINE;
        loop {
            self.cancellation.check()?;
            match self.stream.write(bytes) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    #[cfg(test)]
                    let _waiting = self.cancellation.observe_handler_wait();
                    self.cancellation
                        .wait(self.stream.as_fd(), libc::POLLOUT, Some(deadline))?;
                }
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl super::FrameStream for ControlConnection {
    fn finish_frame(&self) -> io::Result<()> {
        self.stream.shutdown(Shutdown::Write)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_wakes_all_blocked_readers_and_precedes_late_reads() {
        const CANCEL_FAILURE_BOUND: std::time::Duration = std::time::Duration::from_secs(30);
        let cancellation = Arc::new(ControlCancellation::new().expect("cancellation"));
        let mut peers = Vec::new();
        let mut workers = Vec::new();
        let (tx, rx) = std::sync::mpsc::channel();
        for _ in 0..2 {
            let (peer, stream) = UnixStream::pair().expect("socket pair");
            peers.push(peer);
            let mut connection = ControlConnection::new(stream, Arc::clone(&cancellation))
                .expect("nonblocking connection");
            let tx = tx.clone();
            workers.push(std::thread::spawn(move || {
                let result = connection.read(&mut [0]);
                let _ = tx.send(result);
            }));
        }
        assert!(cancellation.wait_for_handlers(2, CANCEL_FAILURE_BOUND));
        cancellation.cancel();
        for _ in 0..2 {
            let error = rx
                .recv_timeout(CANCEL_FAILURE_BOUND)
                .expect("cancellation did not wake reader")
                .expect_err("cancelled read");
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        }
        for worker in workers {
            worker.join().expect("reader");
        }
        let (peer, stream) = UnixStream::pair().expect("late socket pair");
        peers.push(peer);
        let mut late = ControlConnection::new(stream, cancellation).expect("late connection");
        assert_eq!(
            late.read(&mut [0]).expect_err("late read cancelled").kind(),
            io::ErrorKind::ConnectionAborted
        );
    }
}
