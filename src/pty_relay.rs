//! Interactive pty bridge for `carrick run -t`. carrick allocates a host
//! pty, hands the slave to the guest as fds 0/1/2, and relays bytes between
//! the user's real terminal and the master while the guest runs.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread::JoinHandle;

// ---------------------------------------------------------------------------
// SIGWINCH self-pipe
// ---------------------------------------------------------------------------
//
// Only ONE PtyRelay is active at a time (`carrick run -t` allocates one pty),
// so a single process-global static for the write end is safe. The handler is
// an extern "C" fn and cannot reach per-instance state.
//
// The write end is set to -1 when no relay is active (handler is a no-op then).

/// Write end of the SIGWINCH self-pipe. `-1` when no relay is active.
/// Written by the async handler; must be a non-blocking fd (O_NONBLOCK) so the
/// handler's write can never block.
static WINCH_PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

/// Async-signal-safe SIGWINCH handler. Only calls `write(2)` and reads one
/// atomic — both are async-signal-safe per POSIX. No ioctl, no allocation,
/// no mutex. NOTE: in carrick's HVF context SIGWINCH delivery to this handler
/// is unreliable (HVF/applevisor masks signals on the vCPU threads), so the
/// relay ALSO polls for size changes on a timeout — see `relay_loop`. This
/// handler is the low-latency path when delivery does happen.
extern "C" fn handle_sigwinch(_signum: libc::c_int) {
    let w = WINCH_PIPE_WRITE.load(Ordering::SeqCst);
    if w >= 0 {
        // SAFETY: w is a live non-blocking pipe fd; write(1 byte) is
        // async-signal-safe. EAGAIN (full pipe) is fine — a resize is already
        // pending.
        let byte = [0u8; 1];
        unsafe { libc::write(w, byte.as_ptr() as *const libc::c_void, 1) };
    }
}

// ---------------------------------------------------------------------------
// Window-size propagation
// ---------------------------------------------------------------------------

/// Read the window size from `tty_fd` and apply it to `master_fd` so the
/// guest's slave sees the resize.
pub(crate) fn propagate_winsize(tty_fd: RawFd, master_fd: RawFd) {
    if let Some(ws) = read_winsize(tty_fd) {
        // SAFETY: master_fd is a live pty master; &ws is a valid winsize.
        unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws) };
    }
}

/// Read the current window size of `fd`, or `None` if it isn't a tty.
fn read_winsize(fd: RawFd) -> Option<libc::winsize> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a live fd; ws is a valid winsize out-param.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 {
        Some(ws)
    } else {
        None
    }
}

/// Whether two winsizes differ in the dimensions we propagate.
fn winsize_changed(a: &libc::winsize, b: &libc::winsize) -> bool {
    a.ws_row != b.ws_row
        || a.ws_col != b.ws_col
        || a.ws_xpixel != b.ws_xpixel
        || a.ws_ypixel != b.ws_ypixel
}

/// A freshly-allocated host pty (master + already-opened slave).
pub struct PtyPair {
    pub master_fd: i32,
    pub slave_fd: i32,
    /// The macOS slave device path (e.g. `/dev/ttys003`), from `ptsname`.
    pub slave_name: String,
}

impl PtyPair {
    /// Allocate via posix_openpt + open the slave. Reuses Phase A's
    /// `open_master` (posix_openpt/grantpt/unlockpt/ptsname).
    pub fn allocate() -> io::Result<Self> {
        let (master_fd, slave_name) =
            crate::vfs::devpts::open_master(false).map_err(io::Error::from_raw_os_error)?;
        let cname = CString::new(slave_name.clone())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: cname is a valid NUL-terminated slave device path.
        let slave_fd = unsafe { libc::open(cname.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        if slave_fd < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(master_fd) };
            return Err(e);
        }
        Ok(Self {
            master_fd,
            slave_fd,
            slave_name,
        })
    }
}

/// Bidirectional byte relay between (real_in, real_out) and a pty master.
///
/// The relay runs on a dedicated thread and uses `poll(2)` to multiplex three
/// fds: `real_in` → master, master → `real_out`, and a shutdown pipe that lets
/// `stop()` cleanly terminate the thread without any signal or timeout.
///
/// In the production path (`start`), a SIGWINCH self-pipe is also added: the
/// handler writes a byte, the relay thread reads it and calls
/// `propagate_winsize` so the guest slave tracks terminal resizes.
pub struct PtyRelay {
    pair: PtyPair,
    shutdown_w: RawFd,
    thread: Option<JoinHandle<()>>,
    raw_active: bool,
    real_in_for_restore: RawFd,
    /// Read end of the SIGWINCH self-pipe, or `-1` if SIGWINCH is not wired
    /// (test path). Closed by `stop()`.
    winch_r: RawFd,
    /// Write end of the SIGWINCH self-pipe, or `-1`. Cleared from the global
    /// static and closed by `stop()`.
    winch_w: RawFd,
    /// Previous SIGWINCH disposition, saved so `stop()` can restore it.
    /// `None` when SIGWINCH was not installed (test path).
    old_sigwinch: Option<libc::sigaction>,
}

impl PtyRelay {
    /// Return the slave fd so the caller can hand it to the guest as fds 0/1/2.
    pub fn slave_fd(&self) -> i32 {
        self.pair.slave_fd
    }

    /// The macOS slave device path (e.g. `/dev/ttys003`). The caller registers
    /// this with the dispatcher as the guest's controlling tty so `/dev/tty`
    /// and `/proc/self/fd/{0,1,2}` resolve to it.
    pub fn slave_name(&self) -> &str {
        &self.pair.slave_name
    }

    /// Production entry: allocate a pty, put `real_in` in raw mode, install
    /// SIGWINCH propagation, and start the relay between (real_in, real_out)
    /// and the master.
    pub fn start(real_in: RawFd, real_out: RawFd) -> io::Result<Self> {
        crate::host_tty::make_raw(real_in)?;
        let pair = PtyPair::allocate()?;

        // ── SIGWINCH self-pipe ───────────────────────────────────────────────
        // Create a non-blocking pipe: handler writes, relay loop reads.
        let mut wp = [0i32; 2];
        // SAFETY: wp is a 2-int array for pipe(2).
        if unsafe { libc::pipe(wp.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (winch_r, winch_w) = (wp[0], wp[1]);
        // Make the write end non-blocking so the handler's write never blocks
        // if the pipe fills (coalescing: a pending resize is already signalled).
        unsafe {
            let fl = libc::fcntl(winch_w, libc::F_GETFL);
            if fl >= 0 {
                libc::fcntl(winch_w, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
        }
        // Make the read end non-blocking so the drain loop in relay_loop exits
        // with EAGAIN (read returns -1 → r <= 0 → break) once all pending bytes
        // are consumed, instead of blocking forever on an empty pipe.
        unsafe {
            let fl = libc::fcntl(winch_r, libc::F_GETFL);
            if fl >= 0 {
                libc::fcntl(winch_r, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
        }
        // Publish write end to global so the handler can reach it.
        WINCH_PIPE_WRITE.store(winch_w, Ordering::SeqCst);

        // Install handler; save old disposition for restore in stop().
        // SAFETY: zeroed sigaction is the documented "no flags, empty mask" form.
        let old_sigwinch = unsafe {
            let mut action: libc::sigaction = core::mem::zeroed();
            action.sa_sigaction = handle_sigwinch as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = libc::SA_RESTART;
            let mut old: libc::sigaction = core::mem::zeroed();
            libc::sigaction(libc::SIGWINCH, &action, &mut old);
            old
        };

        // Propagate initial size before the guest sees any data.
        propagate_winsize(real_in, pair.master_fd);

        let mut relay = Self::start_inner(pair, real_in, real_out, winch_r)?;
        relay.raw_active = true;
        relay.winch_r = winch_r;
        relay.winch_w = winch_w;
        relay.old_sigwinch = Some(old_sigwinch);
        Ok(relay)
    }

    /// Test entry: same as `start` but skips `make_raw` and does NOT install
    /// the process-global SIGWINCH handler (tests must not disturb signal state).
    #[cfg(test)]
    pub fn start_for_test(real_in: RawFd, real_out: RawFd) -> io::Result<Self> {
        let mut relay = Self::start_inner(PtyPair::allocate()?, real_in, real_out, -1)?;
        relay.raw_active = false;
        Ok(relay)
    }

    /// Common inner setup: shutdown pipe + relay thread. `winch_r` is passed to
    /// the thread; pass `-1` for the test path (poll ignores fds with events=0,
    /// and we special-case -1 in relay_loop to skip adding it to the poll set).
    fn start_inner(
        pair: PtyPair,
        real_in: RawFd,
        real_out: RawFd,
        winch_r: RawFd,
    ) -> io::Result<Self> {
        let mut sp = [0i32; 2];
        // SAFETY: sp is a 2-int array for pipe(2).
        if unsafe { libc::pipe(sp.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (shutdown_r, shutdown_w) = (sp[0], sp[1]);
        let master = pair.master_fd;
        let thread = match std::thread::Builder::new()
            .name("pty-relay".into())
            .spawn(move || relay_loop(real_in, real_out, master, shutdown_r, winch_r))
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
            winch_r,
            winch_w: -1,
            old_sigwinch: None,
        })
    }

    /// Stop the relay, restore SIGWINCH disposition, restore the terminal,
    /// and close the pty and winch pipe.
    pub fn stop(mut self) {
        // Signal the relay thread to shut down.
        // SAFETY: shutdown_w is a live pipe write end.
        let _ = unsafe { libc::write(self.shutdown_w, b"x".as_ptr().cast(), 1) };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }

        // Restore SIGWINCH disposition AFTER the thread has exited so the
        // handler can't fire concurrently with the restore.
        if let Some(ref old) = self.old_sigwinch {
            // Disarm the global write-end pointer first so any late signal
            // that arrives before sigaction restores becomes a no-op.
            WINCH_PIPE_WRITE.store(-1, Ordering::SeqCst);
            // SAFETY: old is a valid sigaction captured at install time.
            unsafe { libc::sigaction(libc::SIGWINCH, old, std::ptr::null_mut()) };
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
            // winch_r is closed by relay_loop (same pattern as shutdown_r).
            // Close winch_w if it was opened (production path).
            if self.winch_w >= 0 {
                libc::close(self.winch_w);
            }
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
///
/// `winch_r` is the read end of the SIGWINCH self-pipe, or `-1` (test path).
/// When `-1` the winch pollfd is given `events = 0` so `poll(2)` never fires
/// it. When readable, the loop drains it and calls `propagate_winsize`.
fn relay_loop(real_in: RawFd, real_out: RawFd, master: RawFd, shutdown_r: RawFd, winch_r: RawFd) {
    // Ensure SIGWINCH is deliverable on THIS thread so the handler can wake the
    // relay. carrick's process signal mask (set up by HVF/runtime init) may
    // block it on threads spawned later; unblock it explicitly here.
    if winch_r >= 0 {
        unsafe {
            let mut set: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGWINCH);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        }
    }
    // Index constants for the pollfd array.
    const IDX_REAL_IN: usize = 0;
    const IDX_MASTER: usize = 1;
    const IDX_SHUTDOWN: usize = 2;
    const IDX_WINCH: usize = 3;

    // If winch_r == -1, set events = 0 so poll never wakes for it.
    let winch_events = if winch_r >= 0 { libc::POLLIN } else { 0 };
    let mut fds = [
        libc::pollfd {
            fd: real_in,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: shutdown_r,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: winch_r,
            events: winch_events,
            revents: 0,
        },
    ];
    let mut buf = [0u8; 4096];
    // Track the last window size we propagated. SIGWINCH delivery is unreliable
    // in carrick's HVF context (the handler often never fires — HVF masks
    // signals on the vCPU threads), so we ALSO poll on a timeout and detect
    // size changes directly. `read_winsize` is cheap and this is the robust,
    // signal-independent path; the SIGWINCH self-pipe (when it fires) just
    // makes a resize take effect a little sooner.
    let mut last_ws = if winch_r >= 0 {
        read_winsize(real_in)
    } else {
        None
    };
    // Poll timeout: when relaying a real terminal (winch_r >= 0) wake every
    // 250ms to check for resizes; the test path (-1) blocks indefinitely.
    let poll_timeout = if winch_r >= 0 { 250 } else { -1 };
    loop {
        // SAFETY: fds is a valid 4-element pollfd array.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 4, poll_timeout) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        // Shutdown pipe readable → stop.
        if n > 0 && fds[IDX_SHUTDOWN].revents & libc::POLLIN != 0 {
            break;
        }
        // SIGWINCH self-pipe readable → drain it (the size-change check below
        // does the actual propagation). Draining stops the level-triggered
        // poll from spinning.
        if n > 0 && fds[IDX_WINCH].revents & libc::POLLIN != 0 {
            let mut drain_buf = [0u8; 64];
            loop {
                let r =
                    unsafe { libc::read(winch_r, drain_buf.as_mut_ptr().cast(), drain_buf.len()) };
                if r <= 0 {
                    break;
                }
            }
        }
        // Robust resize handling: on every wakeup (data, timeout, or SIGWINCH)
        // re-read the terminal size and propagate if it changed.
        if winch_r >= 0
            && let Some(cur) = read_winsize(real_in)
        {
            let changed = last_ws
                .as_ref()
                .is_none_or(|prev| winsize_changed(prev, &cur));
            if changed {
                // SAFETY: master is a live pty master; &cur is a valid winsize.
                unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &cur) };
                last_ws = Some(cur);
            }
        }
        // real_in readable → copy to master.
        if fds[IDX_REAL_IN].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
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
        if fds[IDX_MASTER].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
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
    // Close winch_r if one was provided (production path).
    if winch_r >= 0 {
        unsafe { libc::close(winch_r) };
    }
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
        unsafe {
            libc::close(pty.master_fd);
            libc::close(pty.slave_fd);
        }
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

        let relay = PtyRelay::start_for_test(real_term, real_term).expect("start_for_test");
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
            assert_eq!(
                libc::tcsetattr(slave, libc::TCSANOW, &t),
                0,
                "tcsetattr slave raw"
            );
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
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair(2) failed");
        (sv[0], sv[1])
    }

    /// Open a fresh pty pair (master, slave) for use in tests.
    fn open_test_pty_pr() -> (i32, i32) {
        let m = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        assert!(m >= 0, "posix_openpt failed");
        unsafe {
            libc::grantpt(m);
            libc::unlockpt(m);
        }
        let name = unsafe { std::ffi::CStr::from_ptr(libc::ptsname(m)) }.to_owned();
        let s = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        assert!(s >= 0, "open slave failed");
        (m, s)
    }

    /// `propagate_winsize` reads the size set on one tty and applies it to
    /// another pty master.
    #[test]
    fn propagate_winsize_copies_rows_cols_to_master() {
        // Use two ptys: set winsize on the slave of `from`, propagate from
        // from.slave → to.master, read it back from to.master.
        let from = open_test_pty_pr(); // (master, slave)
        let to = open_test_pty_pr();
        let ws = libc::winsize {
            ws_row: 40,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: from.1 is a live tty fd; ws is a valid winsize buffer.
        unsafe { libc::ioctl(from.1, libc::TIOCSWINSZ, &ws) };
        // Propagate: read from the slave (from.1), write to the master (to.0).
        propagate_winsize(from.1, to.0);
        let mut got: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: to.0 is a live pty master fd.
        unsafe { libc::ioctl(to.0, libc::TIOCGWINSZ, &mut got) };
        assert_eq!((got.ws_row, got.ws_col), (40, 100));
        // SAFETY: all four fds are still open.
        unsafe {
            libc::close(from.0);
            libc::close(from.1);
            libc::close(to.0);
            libc::close(to.1);
        }
    }
}
