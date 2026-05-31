//! tty-ness of an fd drives `isatty(3)`, `os.device_encoding()`, and the
//! `input()`-on-a-tty path in CPython. On Linux `isatty(fd)` is implemented as
//! `ioctl(fd, TCGETS, &t)` — it succeeds (returns the termios) for a real
//! terminal and fails with ENOTTY for a pipe/regular file. CPython's
//! `test_input_tty*` (test_builtin) and `test_device_encoding` (test_utf8_mode)
//! gate on `sys.stdin/stdout.isatty()`, SKIPPING when stdio is piped — so a
//! runtime that mis-reports a pipe as a tty diverges (it RUNS tests Docker
//! SKIPS).
//!
//! carrick used to treat any default stdio fd (0/1/2, nothing dup3'd over it)
//! as a synthetic tty unconditionally — `ioctl(pipe, TCGETS)` returned 0 with
//! cooked defaults instead of ENOTTY. The fix makes tty-ness follow the real
//! backing host fd.
//!
//! This probe encodes the invariant directly, with deterministic resources it
//! creates itself (so it does not depend on the ambient fd 0/1/2 state, which
//! the harness pipes on both sides anyway):
//!   * a real `pipe()` end is NOT a tty; `ioctl(TCGETS)` on it → ENOTTY;
//!   * a real pty slave IS a tty; `ioctl(TCGETS)` on it → success;
//!   * `isatty(fd)` agrees with "TCGETS succeeded" for every fd (the exact
//!     relationship glibc's `isatty()` relies on);
//!   * stdin (fd 0) — base64'd data on a pipe under the harness — is NOT a tty.
//!
//! Bounded + deterministic: only opens fds + non-blocking ioctls, no read/write
//! on the pty, no fork, no waitpid; prints booleans only (no device index, pid,
//! address, or termios contents). On setup failure prints a single
//! `setup_ok=false`.

use std::ffi::CStr;

use conformance_probes::report;

// asm-generic/ioctls.h — the request the guest ABI uses for tcgetattr.
// `libc::ioctl`'s request arg is `c_int` on the aarch64-musl target.
const L_TCGETS: libc::c_int = 0x5401;
const L_ENOTTY: i32 = 25;

/// `ioctl(fd, TCGETS, &t)` — returns Some(true) on success, Some(false) when it
/// failed specifically with ENOTTY, None on any other (unexpected) error.
unsafe fn tcgets_ok(fd: i32) -> Option<bool> {
    let mut t: libc::termios = core::mem::zeroed();
    let rc = libc::ioctl(fd, L_TCGETS, &mut t as *mut libc::termios);
    if rc == 0 {
        Some(true)
    } else {
        let e = conformance_probes::errno();
        if e == L_ENOTTY {
            Some(false)
        } else {
            None
        }
    }
}

unsafe fn is_tty(fd: i32) -> bool {
    libc::isatty(fd) == 1
}

fn main() {
    unsafe {
        // --- A real pipe end: not a tty, TCGETS → ENOTTY. ---
        let mut fds = [0i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            report!(setup_ok = false);
            return;
        }
        let pipe_rd = fds[0];
        let pipe_isatty = is_tty(pipe_rd);
        let pipe_tcgets = tcgets_ok(pipe_rd);

        // --- A real pty slave: a tty, TCGETS → success. ---
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 || libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
            report!(setup_ok = false);
            return;
        }
        let name_ptr = libc::ptsname(master);
        if name_ptr.is_null() {
            report!(setup_ok = false);
            return;
        }
        let name = CStr::from_ptr(name_ptr).to_owned();
        let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY, 0u32);
        if slave < 0 {
            report!(setup_ok = false);
            return;
        }
        let pty_isatty = is_tty(slave);
        let pty_tcgets = tcgets_ok(slave);

        // --- stdin (fd 0): piped base64 input under the harness → not a tty. ---
        let stdin_isatty = is_tty(0);
        let stdin_tcgets = tcgets_ok(0);

        report!(
            setup_ok = true,
            // A pipe is never a tty, and TCGETS on it is ENOTTY.
            pipe_isatty = pipe_isatty,
            pipe_tcgets_enotty = (pipe_tcgets == Some(false)),
            pipe_isatty_matches_tcgets = (pipe_isatty == (pipe_tcgets == Some(true))),
            // A pty slave is a tty, and TCGETS on it succeeds.
            pty_isatty = pty_isatty,
            pty_tcgets_ok = (pty_tcgets == Some(true)),
            pty_isatty_matches_tcgets = (pty_isatty == (pty_tcgets == Some(true))),
            // The harness feeds stdin a pipe on both sides: not a tty.
            stdin_isatty = stdin_isatty,
            stdin_isatty_matches_tcgets = (stdin_isatty == (stdin_tcgets == Some(true))),
        );

        libc::close(pipe_rd);
        libc::close(fds[1]);
        libc::close(slave);
        libc::close(master);
    }
}
