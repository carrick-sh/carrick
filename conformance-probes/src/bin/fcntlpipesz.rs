//! `fcntl(F_GETPIPE_SZ/F_SETPIPE_SZ)` pipe-capacity round-trip + `F_NOTIFY`
//! (dnotify) accept. Stands in for CPython `test_fcntl.test_fcntl_f_pipesize`
//! and `test_fcntl_64_bit`.
//!
//! Linux behaviour (aarch64; what the Docker oracle does):
//!   - F_GETPIPE_SZ on a fresh pipe returns the default capacity (>= one page,
//!     65536 today). Carrick previously returned a fixed LINUX_PIPE_BUF_SIZE
//!     and had no F_SETPIPE_SZ, so a set then get diverged.
//!   - F_SETPIPE_SZ(x) rounds x up to a page multiple (min one page, clamped to
//!     the pipe-max ceiling) and RETURNS the rounded value; a subsequent
//!     F_GETPIPE_SZ returns exactly that. default//2 is page-aligned, so it
//!     round-trips exactly — the property CPython asserts.
//!   - F_NOTIFY(dirfd, DN_MULTISHOT) SUCCEEDS on aarch64 Linux (the EINVAL the
//!     CPython test guards against is 32-bit-arm only). macOS has no dnotify;
//!     carrick accepts it as a no-op returning 0, matching the observable
//!     contract (the call must not raise).
//!
//! Deterministic booleans only — never the raw default size (it could differ
//! across kernels); the booleans encode the RELATIONSHIPS the oracle holds.

use conformance_probes::report;

// Linux fcntl commands (aarch64 asm-generic). Not all are exposed by the musl
// libc crate, so spell them out — clean-room, from the fcntl(2) man page.
const F_SETPIPE_SZ: i32 = 1031;
const F_GETPIPE_SZ: i32 = 1032;
const F_NOTIFY: i32 = 1026;
// DN_MULTISHOT: keep notifying until explicitly removed. The flag the CPython
// test picks specifically because it is > 2**31 (exercises the long-vs-int arg
// path). 1<<31 == 0x80000000.
const DN_MULTISHOT: i32 = 1 << 31;

fn main() {
    unsafe {
        let mut fds = [0i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            report!(
                getpipe_default_ge_4096 = false,
                setpipe_ok = false,
                getpipe_eq_set = false,
                fnotify_ok = false,
            );
            return;
        }
        let (rd, wr) = (fds[0], fds[1]);

        // Default capacity on the write end.
        let default_sz = libc::fcntl(wr, F_GETPIPE_SZ);
        let getpipe_default_ge_4096 = default_sz >= 4096;

        // CPython picks default//2 (still page-aligned, so it round-trips
        // exactly). Guard against a bogus default so the math stays sane.
        let want = if default_sz >= 8192 {
            default_sz / 2
        } else {
            4096
        };
        let set_rc = libc::fcntl(wr, F_SETPIPE_SZ, want);
        // Linux returns the rounded size from F_SETPIPE_SZ; want is page-aligned
        // so the return equals want.
        let setpipe_ok = set_rc == want;

        let after = libc::fcntl(wr, F_GETPIPE_SZ);
        let getpipe_eq_set = after == want;

        // F_NOTIFY on a directory fd. "." is the container CWD (always a dir).
        let dirfd = libc::open(b".\0".as_ptr() as *const libc::c_char, libc::O_RDONLY);
        let fnotify_ok = if dirfd >= 0 {
            let rc = libc::fcntl(dirfd, F_NOTIFY, DN_MULTISHOT);
            libc::close(dirfd);
            rc == 0
        } else {
            false
        };

        report!(
            getpipe_default_ge_4096 = getpipe_default_ge_4096,
            setpipe_ok = setpipe_ok,
            getpipe_eq_set = getpipe_eq_set,
            fnotify_ok = fnotify_ok,
        );

        libc::close(rd);
        libc::close(wr);
    }
}
