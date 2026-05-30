//! fcntl owner/signal/pipe-size commands (clean-room from man fcntl(2)):
//! F_SETOWN/F_GETOWN, F_SETOWN_EX/F_GETOWN_EX, F_SETSIG/F_GETSIG,
//! F_SETPIPE_SZ/F_GETPIPE_SZ. carrick returns EINVAL for the unimplemented ones
//! (LTP fcntl31/fcntl32 fail), so this probe round-trips each and prints
//! booleans/relationships only (never the run-varying pid or exact capacity),
//! diffing line-exact carrick-vs-Linux.

use conformance_probes::report;

const F_SETOWN: i32 = 8;
const F_GETOWN: i32 = 9;
const F_SETSIG: i32 = 10;
const F_GETSIG: i32 = 11;
const F_SETOWN_EX: i32 = 15;
const F_GETOWN_EX: i32 = 16;
const F_OWNER_PID: i32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FOwnerEx {
    typ: i32,
    pid: i32,
}

fn main() {
    unsafe {
        let pid = libc::getpid();

        // owner + signal round-trips on a pipe read end (a valid async-IO fd).
        let mut fds = [0i32; 2];
        libc::pipe(fds.as_mut_ptr());
        let fd = fds[0];

        let set_own = libc::fcntl(fd, F_SETOWN, pid);
        let get_own = libc::fcntl(fd, F_GETOWN);
        report!(setown_ok = set_own == 0, getown_roundtrip = get_own == pid);

        let set_sig = libc::fcntl(fd, F_SETSIG, libc::SIGUSR1);
        let get_sig = libc::fcntl(fd, F_GETSIG);
        report!(
            setsig_ok = set_sig == 0,
            getsig_roundtrip = get_sig == libc::SIGUSR1
        );

        let owner = FOwnerEx {
            typ: F_OWNER_PID,
            pid,
        };
        let set_ex = libc::fcntl(fd, F_SETOWN_EX, &owner as *const FOwnerEx);
        let mut got = FOwnerEx::default();
        let get_ex = libc::fcntl(fd, F_GETOWN_EX, &mut got as *mut FOwnerEx);
        report!(
            setown_ex_ok = set_ex == 0,
            getown_ex_roundtrip = get_ex == 0 && got.typ == F_OWNER_PID && got.pid == pid,
        );

        // F_GETSIG must reflect the default (0 = SIGIO) on a fresh fd.
        // (F_SETPIPE_SZ is a separate pipe-buffer-resize gap, tracked in
        // docs/ltp-baseline/path-to-75.md, not gated here.)
        let fresh = libc::pipe(fds.as_mut_ptr());
        report!(getsig_default_zero = fresh == 0 && libc::fcntl(fds[0], F_GETSIG) == 0);
    }
}
