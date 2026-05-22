//! Interactive pty bridge for `carrick run -t`. carrick allocates a host
//! pty, hands the slave to the guest as fds 0/1/2, and relays bytes between
//! the user's real terminal and the master while the guest runs.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::thread::JoinHandle;

/// A freshly-allocated host pty (master + already-opened slave).
pub struct PtyPair {
    pub master_fd: i32,
    pub slave_fd: i32,
}

impl PtyPair {
    /// Allocate via posix_openpt + open the slave. Reuses Phase A's
    /// `open_master` (posix_openpt/grantpt/unlockpt/ptsname).
    pub fn allocate() -> io::Result<Self> {
        let (master_fd, slave_name) = crate::vfs::devpts::open_master(false)
            .map_err(io::Error::from_raw_os_error)?;
        let cname = CString::new(slave_name)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: cname is a valid NUL-terminated slave device path.
        let slave_fd = unsafe { libc::open(cname.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        if slave_fd < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(master_fd) };
            return Err(e);
        }
        Ok(Self { master_fd, slave_fd })
    }
}

/// Bidirectional byte relay between (real_in, real_out) and a pty master.
///
/// The relay runs on a dedicated thread and uses `poll(2)` to multiplex three
/// fds: `real_in` → master, master → `real_out`, and a shutdown pipe that lets
/// `stop()` cleanly terminate the thread without any signal or timeout.
pub struct PtyRelay {
    pair: PtyPair,
    shutdown_w: RawFd,
    thread: Option<JoinHandle<()>>,
    raw_active: bool,
    real_in_for_restore: RawFd,
}

impl PtyRelay {
    /// Return the slave fd so the caller can hand it to the guest as fds 0/1/2.
    pub fn slave_fd(&self) -> i32 {
        self.pair.slave_fd
    }

    /// Production entry: allocate a pty, put `real_in` in raw mode, start the
    /// relay between (real_in, real_out) and the master.
    pub fn start(real_in: RawFd, real_out: RawFd) -> io::Result<Self> {
        crate::host_tty::make_raw(real_in)?;
        let mut relay = Self::start_inner(PtyPair::allocate()?, real_in, real_out)?;
        relay.raw_active = true;
        Ok(relay)
    }

    /// Test entry: same as `start` but skips `make_raw` (the fds are pipes /
    /// socketpairs in tests, not real ttys).
    #[cfg(test)]
    pub fn start_for_test(real_in: RawFd, real_out: RawFd) -> io::Result<Self> {
        let mut relay = Self::start_inner(PtyPair::allocate()?, real_in, real_out)?;
        relay.raw_active = false;
        Ok(relay)
    }

    fn start_inner(pair: PtyPair, real_in: RawFd, real_out: RawFd) -> io::Result<Self> {
        let mut sp = [0i32; 2];
        // SAFETY: sp is a 2-int array for pipe(2).
        if unsafe { libc::pipe(sp.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (shutdown_r, shutdown_w) = (sp[0], sp[1]);
        let master = pair.master_fd;
        let thread = match std::thread::Builder::new()
            .name("pty-relay".into())
            .spawn(move || relay_loop(real_in, real_out, master, shutdown_r))
        {
            Ok(t) => t,
            Err(e) => {
                // SAFETY: these fds are owned here and not yet handed off.
                unsafe {
                    libc::close(shutdown_r);
                    libc::close(shutdown_w);
                    libc::close(pair.master_fd);
                    libc::close(pair.slave_fd);
                }
                return Err(e);
            }
        };
        Ok(Self {
            pair,
            shutdown_w,
            thread: Some(thread),
            raw_active: false,
            real_in_for_restore: real_in,
        })
    }

    /// Stop the relay, restore the terminal, close the pty.
    pub fn stop(mut self) {
        // SAFETY: shutdown_w is a live pipe write end.
        let _ = unsafe { libc::write(self.shutdown_w, b"x".as_ptr().cast(), 1) };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if self.raw_active {
            crate::host_tty::restore_stdin_termios();
            let _ = self.real_in_for_restore;
        }
        // SAFETY: these fds are owned by this relay and no longer in use after
        // the thread has joined.
        unsafe {
            libc::close(self.shutdown_w);
            libc::close(self.pair.master_fd);
            libc::close(self.pair.slave_fd);
        }
    }
}

/// Core poll loop: bridges real_in ↔ master and terminates on shutdown signal.
///
/// Directions:
///   real_in  →  master   (user keystrokes → guest tty)
///   master   →  real_out (guest output    → user terminal)
///
/// The loop does NOT copy real_in → real_out directly; all traffic
/// passes through the pty master.
fn relay_loop(real_in: RawFd, real_out: RawFd, master: RawFd, shutdown_r: RawFd) {
    let mut fds = [
        libc::pollfd { fd: real_in,    events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: master,     events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: shutdown_r, events: libc::POLLIN, revents: 0 },
    ];
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: fds is a valid 3-element pollfd array.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 3, -1) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        // Shutdown pipe readable → stop.
        if fds[2].revents & libc::POLLIN != 0 {
            break;
        }
        // real_in readable → copy to master.
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            match read_fd(real_in, &mut buf) {
                Some(0) | None => break,
                Some(k) => {
                    if write_all_fd(master, &buf[..k]).is_none() {
                        break;
                    }
                }
            }
        }
        // master readable → copy to real_out.
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            match read_fd(master, &mut buf) {
                Some(0) | None => break,
                Some(k) => {
                    if write_all_fd(real_out, &buf[..k]).is_none() {
                        break;
                    }
                }
            }
        }
    }
    // SAFETY: shutdown_r is the relay-local read end of the shutdown pipe;
    // it is not visible to the caller and safe to close here.
    unsafe { libc::close(shutdown_r) };
}

/// Read up to `buf.len()` bytes from `fd`. Returns `None` on error,
/// `Some(0)` on EOF. Retries on EINTR (e.g. SIGWINCH arriving mid-read).
fn read_fd(fd: RawFd, buf: &mut [u8]) -> Option<usize> {
    loop {
        // SAFETY: buf is a valid mutable slice.
        let r = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if r < 0 {
            // Retry if interrupted by a signal (e.g. SIGWINCH); otherwise fail.
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
        return Some(r as usize);
    }
}

/// Write all of `data` to `fd`, retrying on short writes. Returns `None` on
/// any error. Retries on EINTR without advancing the buffer.
fn write_all_fd(fd: RawFd, mut data: &[u8]) -> Option<()> {
    while !data.is_empty() {
        // SAFETY: data is a valid slice.
        let w = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if w < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
        if w == 0 {
            return None;
        }
        data = &data[w as usize..];
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_opens_master_and_tty_slave() {
        let pty = PtyPair::allocate().expect("allocate pty");
        assert!(pty.master_fd >= 0);
        assert!(pty.slave_fd >= 0);
        assert_eq!(unsafe { libc::isatty(pty.slave_fd) }, 1);
        assert_ne!(pty.master_fd, pty.slave_fd);
        unsafe { libc::close(pty.master_fd); libc::close(pty.slave_fd); }
    }

    /// Verify that the relay copies bytes in both directions and that stop()
    /// terminates the thread cleanly.
    ///
    /// Topology:
    ///   real_app ←─(socketpair)─→ real_term
    ///
    /// The relay is started with real_in = real_out = real_term.
    ///
    /// app → real_term : relay reads real_in → writes master → pty kernel →
    ///                   slave_f reads slave.
    ///
    /// slave_f → slave : pty kernel → relay reads master → writes real_out →
    ///                   kernel delivers to real_app side → app reads.
    ///
    /// Because writing to one end of a socketpair makes data readable at the
    /// OTHER end, the relay writing to real_out (== real_term) never loops
    /// back into real_in; it appears at real_app instead.
    ///
    /// Fd ownership:
    ///   - real_app  : owned by `app_file`; we mem::forget it after use to
    ///                 avoid closing it while the relay might still reference
    ///                 real_term (same underlying socket object).  We close it
    ///                 manually at the end via a dup'd fd.
    ///   - real_term : the relay holds it for the duration; we do NOT wrap it
    ///                 in a File (no drop needed).
    ///   - slave     : owned by `slave_file`; we mem::forget it before stop()
    ///                 because stop() closes pair.slave_fd.
    ///   - master    : owned by the relay (stop() closes it).
    #[test]
    fn relay_copies_both_directions_and_stops_on_eof() {
        use std::io::{Read, Write};
        use std::os::unix::io::FromRawFd;

        let (real_app, real_term) = socketpair();

        // Duplicate real_app so we can close it after mem::forget(app_file).
        // SAFETY: real_app is a valid open fd.
        let real_app_dup = unsafe { libc::dup(real_app) };
        assert!(real_app_dup >= 0, "dup(real_app) failed");

        let relay = PtyRelay::start_for_test(real_term, real_term)
            .expect("start_for_test");
        let slave = relay.slave_fd();

        // Disable echo on the slave's line discipline so the pty does not echo
        // bytes written to master back out through master again.  Without this
        // the relay would read the echo and deliver it to real_app before the
        // test's "OK" response arrives, corrupting the read order.
        // SAFETY: slave is a valid tty fd; cfmakeraw + tcsetattr are defined.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(slave, &mut t), 0, "tcgetattr slave");
            libc::cfmakeraw(&mut t);
            assert_eq!(libc::tcsetattr(slave, libc::TCSANOW, &t), 0, "tcsetattr slave raw");
        }

        // Wrap real_app in a File for convenient I/O; we'll forget it later.
        // SAFETY: real_app is open and not yet wrapped.
        let mut app_file = unsafe { std::fs::File::from_raw_fd(real_app) };

        // Wrap slave in a File; we'll forget it before stop() so stop() can
        // legitimately close pair.slave_fd.
        // SAFETY: slave is open and not yet wrapped.
        let mut slave_file = unsafe { std::fs::File::from_raw_fd(slave) };

        // ── direction 1: app → slave ──────────────────────────────────────
        app_file.write_all(b"hi\n").expect("write to app");
        let mut buf = [0u8; 3];
        slave_file.read_exact(&mut buf).expect("slave read");
        assert_eq!(&buf, b"hi\n");

        // ── direction 2: slave → app ──────────────────────────────────────
        slave_file.write_all(b"OK").expect("write to slave");
        let mut buf2 = [0u8; 2];
        app_file.read_exact(&mut buf2).expect("app read");
        assert_eq!(&buf2, b"OK");

        // Release ownership of slave_file BEFORE stop() closes pair.slave_fd,
        // and of app_file before we close real_app_dup.
        std::mem::forget(slave_file);
        std::mem::forget(app_file);

        // stop() signals the relay thread, joins it, then closes master + slave.
        relay.stop();

        // Clean up the remaining fds that we held outside the relay.
        // SAFETY: real_term and real_app_dup are still open at this point.
        unsafe {
            libc::close(real_term);
            libc::close(real_app_dup);
        }
    }

    /// Create a connected Unix-domain socket pair (AF_UNIX, SOCK_STREAM).
    fn socketpair() -> (RawFd, RawFd) {
        let mut sv = [0i32; 2];
        // SAFETY: sv is a 2-int array for socketpair(2).
        let rc = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr())
        };
        assert_eq!(rc, 0, "socketpair(2) failed");
        (sv[0], sv[1])
    }
}
