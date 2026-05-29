//! F_SETFL must NOT change the access mode (O_RDONLY/O_WRONLY/O_RDWR) and must
//! NOT store creation-only bits (O_CREAT/O_TRUNC); it only mutates the file
//! STATUS flags (O_APPEND/O_NONBLOCK/O_DIRECT/O_NOATIME/O_ASYNC). A later
//! F_GETFL must report the original access mode with only the mutable status
//! bits changed.
//!
//! carrick stores `arg & !O_CLOEXEC` wholesale via set_status_flags
//! (dispatch/fs.rs:1899), so it clobbers the access mode to whatever the guest
//! passed and persists creation-only bits. This probe round-trips a bogus
//! F_SETFL and reads it back: the booleans diverge from Linux exactly on the bug.
//!
//! Stands in for the F_SETFL/F_GETFL access-mode-preservation invariant that
//! LTP fcntl04 (fresh-fd F_GETFL only) does not exercise.

use conformance_probes::{errno, report};

fn main() {
    unsafe {
        // run-elf's rootfs is empty; /tmp may not exist. Ignore EEXIST.
        libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);
        let path = b"/tmp/fsetfl_probe\0".as_ptr() as *const libc::c_char;
        let fd = libc::open(path, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644);
        if fd < 0 {
            report!(setup_open_ok = false, open_errno = errno());
            return;
        }

        let before = libc::fcntl(fd, libc::F_GETFL);
        // Attempt to flip the access mode (WRONLY->RDWR), set creation-only
        // bits (O_CREAT/O_TRUNC), and a legitimate status bit (O_NONBLOCK).
        let arg =
            libc::O_RDWR | libc::O_APPEND | libc::O_NONBLOCK | libc::O_CREAT | libc::O_TRUNC;
        let setfl_rc = libc::fcntl(fd, libc::F_SETFL, arg);
        let after = libc::fcntl(fd, libc::F_GETFL);

        report!(
            setup_open_ok = true,
            setfl_rc_zero = setfl_rc == 0,
            accmode_before_wronly = (before & libc::O_ACCMODE) == libc::O_WRONLY,
            // Linux: still WRONLY (F_SETFL cannot change access mode).
            accmode_after_still_wronly = (after & libc::O_ACCMODE) == libc::O_WRONLY,
            // Linux: false (creation-only bits are not stored as status).
            creat_bit_stored = (after & libc::O_CREAT) != 0,
            trunc_bit_stored = (after & libc::O_TRUNC) != 0,
            // Linux + carrick: true (legitimate mutable status bit).
            nonblock_set = (after & libc::O_NONBLOCK) != 0,
        );
        libc::close(fd);
    }
}
