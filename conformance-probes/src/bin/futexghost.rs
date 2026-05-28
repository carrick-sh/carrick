//! Diagnostic: does FUTEX_WAKE on a freshly-mapped MAP_SHARED file return
//! 0 (clean — no waiters), or does it return phantom waiter counts?
//!
//! If the wake returns N > 0 even when no FUTEX_WAIT has ever been called
//! on this brand-new page, the kernel is leaking __ulock entries across
//! unrelated mappings — which would explain LTP pause01's `waked == 1`
//! check looping forever.

use conformance_probes::report;

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);
        let path = b"/tmp/carrick_futexghost\0";
        let fd = libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        if fd < 0 {
            report!(setup = false);
            return;
        }
        libc::ftruncate(fd, 4096);
        let map = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        if map == libc::MAP_FAILED {
            report!(setup = false);
            return;
        }
        let word = map as *mut u32;
        *word = 0;

        // No fork. No WAIT. Just call WAKE on a fresh page. Linux returns 0.
        let woke_pre = libc::syscall(
            libc::SYS_futex,
            word,
            1i32, // FUTEX_WAKE (shared)
            i32::MAX as i64,
            std::ptr::null::<libc::timespec>(),
        ) as i64;
        report!(wake_pre_fork = woke_pre);

        // Fork. Both parent and child immediately WAKE without anyone
        // having ever WAITed. Linux returns 0 in both. Carrick: ?
        let pid = libc::fork();
        if pid == 0 {
            let woke = libc::syscall(
                libc::SYS_futex,
                word,
                1i32,
                i32::MAX as i64,
                std::ptr::null::<libc::timespec>(),
            ) as i64;
            // Report from child only via exit code: 0 = clean, !0 = woke phantoms.
            libc::_exit(if woke == 0 { 0 } else { 1 });
        }
        let mut status = 0i32;
        let _ = libc::wait4(pid, &mut status, 0, std::ptr::null_mut());
        let child_clean = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        report!(wake_in_child_no_waiter_clean = child_clean);

        let woke_post = libc::syscall(
            libc::SYS_futex,
            word,
            1i32,
            i32::MAX as i64,
            std::ptr::null::<libc::timespec>(),
        ) as i64;
        report!(wake_post_fork = woke_post);

        libc::close(fd);
        libc::unlink(path.as_ptr() as *const libc::c_char);
    }
}
