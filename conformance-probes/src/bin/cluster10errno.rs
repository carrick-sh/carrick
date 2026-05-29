//! Cluster #10 errno edges (roadmap remainder after getrandom + capget landed):
//!   - pidfd_open(self, 0) returns an fd with FD_CLOEXEC set (kernel creates the
//!     pidfd O_CLOEXEC unconditionally).                       — pidfd_open01
//!   - posix_fadvise with an out-of-range advice → EINVAL.     — posix_fadvise03
//!   - posix_fadvise on a pipe/FIFO → ESPIPE.                  — posix_fadvise04
//!   - ftruncate on a read-only fd → EINVAL (NOT EBADF; the fd is valid, it is
//!     just not open for writing).                             — ftruncate03
//!
//! Deterministic booleans only; the harness diffs carrick vs real Linux
//! line-exact. (All four are oracle-agreed: Docker linux/arm64 cleanly passes
//! the corresponding LTP tests.)

use conformance_probes::errno;
use std::ffi::CString;

fn open(path: &str, flags: i32, mode: u32) -> i32 {
    let c = CString::new(path).unwrap();
    unsafe { libc::open(c.as_ptr(), flags, mode as libc::c_uint) }
}

fn main() {
    unsafe {
        // (1) pidfd_open(self, 0): success + FD_CLOEXEC on the returned fd.
        let pidfd = libc::syscall(434, libc::getpid() as libc::c_long, 0i64) as i32;
        let pidfd_ok = pidfd >= 0;
        let pidfd_cloexec = pidfd_ok && {
            let f = libc::fcntl(pidfd, libc::F_GETFD);
            f >= 0 && (f & libc::FD_CLOEXEC) != 0
        };
        println!("pidfd_open_ok={}", pidfd_ok);
        println!("pidfd_cloexec={}", pidfd_cloexec);
        if pidfd >= 0 {
            libc::close(pidfd);
        }

        // (2) posix_fadvise with an out-of-range advice (999) → EINVAL.
        let fd = open(
            "/tmp/cl10_fadv",
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        let rc = libc::syscall(223, fd as libc::c_long, 0i64, 0i64, 999i64);
        println!(
            "fadvise_bad_advice_einval={}",
            rc == -1 && errno() == libc::EINVAL
        );
        if fd >= 0 {
            libc::close(fd);
        }

        // (3) posix_fadvise on a pipe read-end → ESPIPE.
        let mut fds = [0i32; 2];
        let fadvise_pipe_espipe = if libc::pipe(fds.as_mut_ptr()) == 0 {
            let rc = libc::syscall(223, fds[0] as libc::c_long, 0i64, 0i64, 0i64);
            let ok = rc == -1 && errno() == libc::ESPIPE;
            libc::close(fds[0]);
            libc::close(fds[1]);
            ok
        } else {
            false
        };
        println!("fadvise_pipe_espipe={}", fadvise_pipe_espipe);

        // (4) ftruncate on a read-only fd → EINVAL (not EBADF). Create writable,
        //     then reopen O_RDONLY.
        let wfd = open(
            "/tmp/cl10_tr",
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if wfd >= 0 {
            libc::write(wfd, b"abc".as_ptr() as *const _, 3);
            libc::close(wfd);
        }
        let rofd = open("/tmp/cl10_tr", libc::O_RDONLY, 0);
        let rc = libc::ftruncate(rofd, 0);
        let e = errno();
        println!("ftruncate_ro_einval={}", rc == -1 && e == libc::EINVAL);
        println!("ftruncate_ro_not_ebadf={}", !(rc == -1 && e == libc::EBADF));
        if rofd >= 0 {
            libc::close(rofd);
        }
    }
}
