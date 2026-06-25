//! F_OFD_* (open file description lock) probe. OFD locks are owned by the open
//! file description, not the process — so two opens of the same file IN THE SAME
//! process conflict (classic POSIX locks would not), and F_OFD_GETLK reports a
//! conflicting lock's l_pid as -1. The conformance harness runs this identical
//! static binary under carrick and real Linux and diffs line by line.
//!
//! Deterministic only: rc, errno, l_type, and the OFD sentinel l_pid (-1) — never
//! a real pid, fd, address, or timestamp. Run under --fs host so the lock targets
//! a real host file (the OFD primitive only engages on a host-backed fd).

use std::ffi::CString;

// Linux fcntl command numbers (the guest ABI carrick must honor).
const F_OFD_GETLK: i32 = 36;
const F_OFD_SETLK: i32 = 37;

fn flock(l_type: i16, start: i64, len: i64) -> libc::flock {
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = l_type;
    fl.l_whence = libc::SEEK_SET as i16;
    fl.l_start = start;
    fl.l_len = len;
    fl
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn main() {
    let tmp = CString::new("/tmp").unwrap();
    unsafe { libc::mkdir(tmp.as_ptr(), 0o777) };
    let path = CString::new("/tmp/ofdlock").unwrap();
    let fd1 = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
    };
    if fd1 < 0 {
        println!("ofd_open=ERR:{}", errno());
        return;
    }
    unsafe { libc::ftruncate(fd1, 200) };

    // 1. OFD write lock [0,10) via fd1 — succeeds.
    let mut fl = flock(libc::F_WRLCK as i16, 0, 10);
    let r1 = unsafe { libc::fcntl(fd1, F_OFD_SETLK, &mut fl) };
    println!("ofd_lock1_rc={}", r1);

    // 2. Second fd, OFD write lock [0,10) — conflicts (the OFD-vs-classic
    //    discriminator: classic same-process locks would NOT conflict).
    let fd2 = unsafe { libc::open(path.as_ptr(), libc::O_RDWR, 0) };
    let mut fl2 = flock(libc::F_WRLCK as i16, 0, 10);
    let r2 = unsafe { libc::fcntl(fd2, F_OFD_SETLK, &mut fl2) };
    println!("ofd_conflict_rc={}", r2);
    println!("ofd_conflict_errno={}", if r2 < 0 { errno() } else { 0 });

    // 3. OFD GETLK via fd2 on [0,10): expect F_WRLCK + l_pid == -1 (OFD sentinel).
    let mut fl3 = flock(libc::F_WRLCK as i16, 0, 10);
    let r3 = unsafe { libc::fcntl(fd2, F_OFD_GETLK, &mut fl3) };
    println!("ofd_getlk_rc={}", r3);
    println!("ofd_getlk_type={}", fl3.l_type);
    println!("ofd_getlk_pid={}", fl3.l_pid);

    // 4. OFD GETLK on a free range — expect F_UNLCK.
    let mut fl4 = flock(libc::F_WRLCK as i16, 100, 10);
    let _ = unsafe { libc::fcntl(fd2, F_OFD_GETLK, &mut fl4) };
    println!("ofd_getlk_free_type={}", fl4.l_type);

    // 5. Unlock via fd1, then fd2 can take the lock.
    let mut flu = flock(libc::F_UNLCK as i16, 0, 10);
    let _ = unsafe { libc::fcntl(fd1, F_OFD_SETLK, &mut flu) };
    let mut fl5 = flock(libc::F_WRLCK as i16, 0, 10);
    let r5 = unsafe { libc::fcntl(fd2, F_OFD_SETLK, &mut fl5) };
    println!("ofd_relock_rc={}", r5);

    unsafe {
        libc::close(fd1);
        libc::close(fd2);
    }
}
