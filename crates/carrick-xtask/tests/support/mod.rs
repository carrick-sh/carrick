use std::fmt;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::{Duration, Instant};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PipeReadinessError {
    TimedOut,
    ChildExited,
    InvalidDescriptor,
    Io(i32),
}

impl fmt::Display for PipeReadinessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut => f.write_str("readiness signal timed out"),
            Self::ChildExited => f.write_str("child exited before readiness"),
            Self::InvalidDescriptor => f.write_str("poll reported invalid descriptor"),
            Self::Io(errno) => write!(f, "{}", std::io::Error::from_raw_os_error(*errno)),
        }
    }
}

impl std::error::Error for PipeReadinessError {}

pub fn wait_for_pipe_readiness(
    read_fd: BorrowedFd<'_>,
    timeout: Duration,
) -> Result<(), PipeReadinessError> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(PipeReadinessError::TimedOut);
        }
        let timeout_ms =
            libc::c_int::try_from(remaining.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
        let mut pollfd = libc::pollfd {
            fd: read_fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pollfd` is a valid single-element local struct, and `read_fd`
        // borrows a live pipe descriptor for the duration of `poll`.
        let ret = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno == libc::EINTR {
                continue;
            }
            return Err(PipeReadinessError::Io(errno));
        }
        if ret == 0 {
            return Err(PipeReadinessError::TimedOut);
        }
        if (pollfd.revents & libc::POLLNVAL) != 0 {
            return Err(PipeReadinessError::InvalidDescriptor);
        }
        break;
    }
    let mut buf = [0u8; 1];
    loop {
        // SAFETY: `buf` is a valid 1-byte mutable buffer, and `read_fd` borrows
        // a live pipe descriptor for the duration of `read`.
        let n = unsafe {
            libc::read(
                read_fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if n < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno == libc::EINTR {
                continue;
            }
            return Err(PipeReadinessError::Io(errno));
        }
        if n == 0 {
            return Err(PipeReadinessError::ChildExited);
        }
        return Ok(());
    }
}
