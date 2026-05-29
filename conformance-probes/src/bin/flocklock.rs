//! flock(2) real advisory locking. carrick forwards flock to the macOS kernel
//! on host-backed fds, so two independent open descriptions of the same file
//! genuinely conflict: an exclusive lock held on one fd makes a LOCK_NB
//! exclusive request on the other fail with EAGAIN (EWOULDBLOCK), and the lock
//! is reacquirable after LOCK_UN. Plus the errno edges: bad fd → EBADF, bad
//! operation → EINVAL. Stands in for LTP flock04 / flock06.
//!
//! Deterministic booleans (no fd numbers / timing), diffed line-exact
//! carrick-vs-Linux.

use conformance_probes::errno;
use std::ffi::CString;

fn open(path: &str, flags: i32, mode: u32) -> i32 {
    let c = CString::new(path).unwrap();
    unsafe { libc::open(c.as_ptr(), flags, mode as libc::c_uint) }
}

fn main() {
    unsafe {
        let p = "/tmp/flocklk";
        let fd1 = open(p, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        let fd2 = open(p, libc::O_RDWR, 0);

        println!("flock_ex_ok={}", libc::flock(fd1, libc::LOCK_EX) == 0);

        // A second, independent fd on the same file can't take an exclusive lock
        // while fd1 holds one (LOCK_NB → EAGAIN, not a block).
        let conflict = libc::flock(fd2, libc::LOCK_EX | libc::LOCK_NB);
        println!(
            "flock_conflict_eagain={}",
            conflict == -1 && errno() == libc::EAGAIN
        );

        println!("flock_un_ok={}", libc::flock(fd1, libc::LOCK_UN) == 0);

        // After the unlock the contending fd acquires it.
        println!(
            "flock_reacquire_ok={}",
            libc::flock(fd2, libc::LOCK_EX | libc::LOCK_NB) == 0
        );

        if fd1 >= 0 {
            libc::close(fd1);
        }
        if fd2 >= 0 {
            libc::close(fd2);
        }

        // Errno edge: a bad fd is EBADF. (A bad OPERATION → EINVAL on mainline
        // Linux and carrick, but the Docker LinuxKit arm64 kernel disagrees, so
        // that case is covered by carrick's behavior + the LTP test, not asserted
        // here — the documented Docker-kernel-artifact exclusion.)
        println!(
            "flock_badfd_ebadf={}",
            libc::flock(-1, libc::LOCK_EX) == -1 && errno() == libc::EBADF
        );
    }
}
