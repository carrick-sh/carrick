//! One bounded length-prefixed frame per host RPC connection.
//!
//! Length is authoritative; EOF is teardown, never frame completion. Server
//! streams are nonblocking and wait on the socket plus a sticky cancellation
//! pipe. No server transport deadline decides whether a request is correct.

use parking_lot::Mutex;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::time::Instant;

/// Both host RPC servers admit at most this many live handlers.
pub(crate) const MAX_CONNECTIONS: usize = 16;

/// Admission and release share one authority, independent of join/reap.
#[derive(Default)]
pub(crate) struct ConnectionSlots {
    live: Mutex<usize>,
    #[cfg(test)]
    changed: parking_lot::Condvar,
}

impl ConnectionSlots {
    pub(crate) fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut live = self.live.lock();
        if *live >= MAX_CONNECTIONS {
            return None;
        }
        *live += 1;
        #[cfg(test)]
        self.changed.notify_all();
        Some(ConnectionPermit(Arc::clone(self)))
    }

    pub(crate) fn live_count(&self) -> usize {
        *self.live.lock()
    }

    #[cfg(test)]
    pub(crate) fn wait_for_count(&self, expected: usize, bound: std::time::Duration) -> bool {
        let deadline = Instant::now() + bound;
        let mut live = self.live.lock();
        while *live != expected {
            if self.changed.wait_until(&mut live, deadline).timed_out() {
                return *live == expected;
            }
        }
        true
    }
}

/// Declare before socket/context locals so handler return releases it last.
pub(crate) struct ConnectionPermit(Arc<ConnectionSlots>);
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        *self.0.live.lock() -= 1;
        #[cfg(test)]
        self.0.changed.notify_all();
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum FrameError {
    #[error("frame declares {declared} bytes, over the {cap}-byte cap")]
    TooLarge { declared: usize, cap: usize },
    #[error("frame ended after {read} of {declared} bytes")]
    Truncated { declared: usize, read: usize },
    #[error("{0}")]
    Io(#[from] io::Error),
}

pub(crate) trait FrameStream: Write {
    fn finish_frame(&mut self) -> io::Result<()>;
}

impl FrameStream for UnixStream {
    fn finish_frame(&mut self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

pub(crate) fn write_frame(
    stream: &mut impl FrameStream,
    payload: &[u8],
    cap: usize,
) -> Result<(), FrameError> {
    let length = u32::try_from(payload.len())
        .ok()
        .filter(|_| payload.len() <= cap)
        .ok_or(FrameError::TooLarge {
            declared: payload.len(),
            cap,
        })?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    if let Err(error) = stream.finish_frame() {
        // Complete bytes have already been delivered. Darwin may report
        // ENOTCONN if the reader consumed the frame and closed first.
        if error.kind() != io::ErrorKind::NotConnected {
            return Err(error.into());
        }
    }
    Ok(())
}

pub(crate) fn read_frame(stream: &mut impl Read, cap: usize) -> Result<Vec<u8>, FrameError> {
    let mut prefix = [0; size_of::<u32>()];
    read_exact(stream, &mut prefix)?;
    let declared = u32::from_be_bytes(prefix) as usize;
    if declared > cap {
        return Err(FrameError::TooLarge { declared, cap });
    }
    let mut payload = vec![0; declared];
    read_exact(stream, &mut payload)?;
    Ok(payload)
}

fn read_exact(stream: &mut impl Read, bytes: &mut [u8]) -> Result<(), FrameError> {
    let mut filled = 0;
    while filled < bytes.len() {
        match stream.read(&mut bytes[filled..]) {
            Ok(0) => {
                return Err(FrameError::Truncated {
                    declared: bytes.len(),
                    read: filled,
                });
            }
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct Cancellation {
    read: OwnedFd,
    write: Mutex<Option<File>>,
    cancelled: AtomicBool,
    #[cfg(test)]
    waiting_handlers: Mutex<usize>,
    #[cfg(test)]
    changed: parking_lot::Condvar,
}

impl Cancellation {
    pub(crate) fn new() -> io::Result<Self> {
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

    pub(crate) fn cancel(&self) {
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
                "RPC server cancelled",
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) fn wait(&self, fd: BorrowedFd<'_>, events: i16) -> io::Result<()> {
        loop {
            self.check()?;
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
            let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
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
                    "RPC cancellation pipe closed",
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
    pub(crate) fn wait_for_handlers(&self, expected: usize, bound: std::time::Duration) -> bool {
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
struct HandlerWait<'a>(&'a Cancellation);

#[cfg(test)]
impl Drop for HandlerWait<'_> {
    fn drop(&mut self) {
        *self.0.waiting_handlers.lock() -= 1;
        self.0.changed.notify_all();
    }
}

pub(crate) struct Connection {
    stream: UnixStream,
    cancellation: Arc<Cancellation>,
}

impl Connection {
    pub(crate) fn new(stream: UnixStream, cancellation: Arc<Cancellation>) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            cancellation,
        })
    }
}

impl AsRawFd for Connection {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.stream.as_raw_fd()
    }
}

impl Read for Connection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            self.cancellation.check()?;
            match self.stream.read(bytes) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    #[cfg(test)]
                    let _waiting = self.cancellation.observe_handler_wait();
                    self.cancellation.wait(self.stream.as_fd(), libc::POLLIN)?;
                }
                result => return result,
            }
        }
    }
}

impl Write for Connection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            self.cancellation.check()?;
            match self.stream.write(bytes) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    #[cfg(test)]
                    let _waiting = self.cancellation.observe_handler_wait();
                    self.cancellation.wait(self.stream.as_fd(), libc::POLLOUT)?;
                }
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl FrameStream for Connection {
    fn finish_frame(&mut self) -> io::Result<()> {
        self.stream.shutdown(Shutdown::Write)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_wakes_a_writer_blocked_by_an_unread_response() {
        const CANCEL_FAILURE_BOUND: std::time::Duration = std::time::Duration::from_secs(30);
        let cancellation = Arc::new(Cancellation::new().expect("cancellation"));
        let (peer, stream) = UnixStream::pair().expect("pair");
        let mut connection =
            Connection::new(stream, Arc::clone(&cancellation)).expect("connection");
        let (tx, rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let _ = tx.send(connection.write_all(&vec![0; 16 * 1024 * 1024]));
        });
        assert!(
            cancellation.wait_for_handlers(1, CANCEL_FAILURE_BOUND),
            "writer never reached socket backpressure"
        );
        cancellation.cancel();
        let error = rx
            .recv_timeout(CANCEL_FAILURE_BOUND)
            .expect("writer did not wake")
            .expect_err("cancelled write");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        writer.join().expect("writer");
        drop(peer);
    }

    #[test]
    fn cancellation_wakes_all_blocked_readers_and_precedes_late_reads() {
        const CANCEL_FAILURE_BOUND: std::time::Duration = std::time::Duration::from_secs(30);
        let cancellation = Arc::new(Cancellation::new().expect("cancellation"));
        let mut peers = Vec::new();
        let mut workers = Vec::new();
        let (tx, rx) = std::sync::mpsc::channel();
        for _ in 0..2 {
            let (peer, stream) = UnixStream::pair().expect("socket pair");
            peers.push(peer);
            let mut connection =
                Connection::new(stream, Arc::clone(&cancellation)).expect("nonblocking connection");
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
        let mut late = Connection::new(stream, cancellation).expect("late connection");
        assert_eq!(
            late.read(&mut [0]).expect_err("late read cancelled").kind(),
            io::ErrorKind::ConnectionAborted
        );
    }
}
