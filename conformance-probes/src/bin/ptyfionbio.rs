//! FIONBIO on a pty MASTER must SUCCEED (rc==0) and toggle O_NONBLOCK on the
//! open file description — NOT fail with ENOTTY.
//!
//! `os.set_blocking(master_fd, False)` issues ioctl(master, FIONBIO, &1); CPython
//! relies on it for non-blocking pty I/O. carrick's ioctl dispatch
//! (crates/carrick-runtime/src/dispatch/fs.rs) handles a pty fd in a dedicated
//! early-`return` match (`if let Some((role, host_fd)) = this.pty_info(fd.0) {
//! return Ok(match ...) }`). FIONBIO was NOT among that block's arms, so a pty
//! fd fell into its catch-all `_ => ENOTTY`. The general FIONBIO handler (which
//! toggles O_NONBLOCK on the backing host fd and updates the open description's
//! status flags) lives AFTER this early return, so it was unreachable for pty
//! fds. A macOS pty master supports FIONBIO, so once the pty block forwards it
//! to the host master fd carrick matches Linux (which returns 0 and flips
//! O_NONBLOCK).
//!
//! Probe path: posix_openpt -> grantpt -> unlockpt — the exact setup
//! ptypair/ptyfionread already exercise (pass under carrick --fs host + Docker
//! linux/arm64 as aarch64-musl static ELFs); carrick routes the master through
//! a real macOS pty (HostPipe tagged `pty: Some(role)`, so `pty_info` returns
//! Some).
//!
//! DETERMINISM: only booleans are emitted; never raw flag bits, fds, or times.
//!   - enable_rc_zero   : ioctl(master, FIONBIO, &1) succeeded (BUG flips false)
//!   - nonblock_set      : F_GETFL after enable has O_NONBLOCK set
//!   - disable_rc_zero   : ioctl(master, FIONBIO, &0) succeeded (BUG flips false)
//!   - nonblock_cleared   : F_GETFL after disable has O_NONBLOCK cleared
//! Bounded: no poll loop, no fork/waitpid, no blocking read — cannot hang. Any
//! setup failure prints a single `setup_ok=false` and returns.
//!
//! Buggy carrick: setup_ok=true, enable_rc_zero=false, nonblock_set=false,
//!                disable_rc_zero=false, nonblock_cleared=false (ENOTTY).
//! Linux + fixed: setup_ok=true, enable_rc_zero=true, nonblock_set=true,
//!                disable_rc_zero=true, nonblock_cleared=true.

use conformance_probes::report;

fn main() {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 || libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
            report!(setup_ok = false);
            return;
        }

        // Enable non-blocking: ioctl(master, FIONBIO, &1). The bug makes this
        // fail with ENOTTY on a pty master under carrick.
        let on: libc::c_int = 1;
        let enable_rc = libc::ioctl(master, libc::FIONBIO, &on as *const libc::c_int);
        let enable_rc_zero = enable_rc == 0;

        // F_GETFL must now reflect O_NONBLOCK. Forwarding FIONBIO to the host
        // master toggles its O_NONBLOCK, which a subsequent F_GETFL observes.
        let flags_after_enable = libc::fcntl(master, libc::F_GETFL, 0);
        let nonblock_set = flags_after_enable >= 0 && (flags_after_enable & libc::O_NONBLOCK) != 0;

        // Disable non-blocking: ioctl(master, FIONBIO, &0).
        let off: libc::c_int = 0;
        let disable_rc = libc::ioctl(master, libc::FIONBIO, &off as *const libc::c_int);
        let disable_rc_zero = disable_rc == 0;

        let flags_after_disable = libc::fcntl(master, libc::F_GETFL, 0);
        let nonblock_cleared =
            flags_after_disable >= 0 && (flags_after_disable & libc::O_NONBLOCK) == 0;

        report!(
            setup_ok = true,
            master_isatty = libc::isatty(master) == 1,
            // Linux + fixed carrick: all true. Buggy carrick: all false (ENOTTY).
            enable_rc_zero = enable_rc_zero,
            nonblock_set = nonblock_set,
            disable_rc_zero = disable_rc_zero,
            nonblock_cleared = nonblock_cleared,
        );

        libc::close(master);
    }
}
