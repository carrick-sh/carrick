//! /dev/shm hard-link (linkat) conformance probe — the multiprocessing SemLock path.
//!
//! glibc `sem_open` (which CPython's `_multiprocessing.SemLock` uses for every
//! multiprocessing/concurrent_futures lock) does:
//!   openat("/dev/shm/sem.TMP", O_CREAT|O_EXCL|O_RDWR) -> linkat(TMP, FINAL) -> unlink(TMP)
//! carrick mounts /dev/shm as a BindVfs (host-backed, hard-links supported), but
//! the linkat dispatcher used to bypass the mount table and hit the rootfs
//! overlay, which returned EROFS — so SemLock failed with OSError(30) and the
//! whole multiprocessing/concurrent_futures cluster SKIPPED ("broken
//! multiprocessing SemLock"). The fix routes linkat through the mount.
//!
//! This probe reproduces the exact sequence and asserts booleans. On Linux (and
//! now carrick) every step succeeds; with the bug, `link_ok=false`.

use std::ffi::CString;

fn main() {
    let tmp = CString::new("/dev/shm/clpa_probe.tmp").unwrap();
    let fin = CString::new("/dev/shm/clpa_probe.final").unwrap();
    // Idempotent: clear any leftovers from a prior run.
    unsafe {
        libc::unlink(tmp.as_ptr());
        libc::unlink(fin.as_ptr());
    }

    // 1. open the temp semaphore file (O_CREAT|O_EXCL|O_RDWR), as sem_open does.
    let fd = unsafe {
        libc::open(
            tmp.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    println!("open_ok={}", fd >= 0);

    // 2. linkat(TMP -> FINAL) — the step that EROFS'd before the mount fix.
    let link_rc = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            tmp.as_ptr(),
            libc::AT_FDCWD,
            fin.as_ptr(),
            0,
        )
    };
    let link_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    println!("link_ok={}", link_rc == 0);
    // Deterministic: report only WHETHER it errored, not the (always-0-on-success)
    // value — a non-zero errno is the bug signature, identical across machines.
    println!(
        "link_no_erofs={}",
        !(link_rc != 0 && link_errno == libc::EROFS)
    );

    // 3. the linked-to FINAL now exists (stat succeeds).
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let stat_ok = unsafe { libc::stat(fin.as_ptr(), &mut st) } == 0;
    println!("final_exists={}", stat_ok);

    // NOTE: this probe asserts only the sem_open PREREQUISITE — that linkat on
    // /dev/shm succeeds and materializes the final name (the EROFS bug). It does
    // NOT assert the two names share one inode: carrick's BindVfs currently
    // synthesizes path-hashed inodes (the Vfs Metadata has no real host ino),
    // so a /dev/shm hard link reports DIFFERENT inodes than Linux. That's a
    // separate fidelity gap (tracked) and sem_open doesn't depend on it.

    // 4. cleanup (sem_open unlinks both).
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
    let u1 = unsafe { libc::unlink(tmp.as_ptr()) } == 0;
    let u2 = unsafe { libc::unlink(fin.as_ptr()) } == 0;
    println!("cleanup_ok={}", u1 && u2);
}
