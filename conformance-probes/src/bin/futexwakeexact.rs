//! Cross-process FUTEX_WAKE exact-count probe. FUTEX_WAKE(uaddr, N) on a SHARED
//! futex with FEWER than N waiters parked must return the ACTUAL number woken
//! (Linux), never inflate it. carrick's macOS os_sync_wake_by_address path can
//! count a zombie-success for a just-woken waiter, inflating the return — which
//! makes LTP tst_checkpoint_wake's accumulate-until-N loop overshoot and spin to
//! ETIMEDOUT. Over many trials, park exactly ONE waiter and request N=8; the max
//! FUTEX_WAKE return must be exactly 1.
//!
//! Deterministic: prints the max FUTEX_WAKE return over the trials (1 = correct,
//! >1 = the overcount bug). Run under --fs host / via run-elf.

const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;
const TRIALS: i32 = 100;

fn futex_wait(uaddr: *mut u32, val: u32) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            uaddr,
            FUTEX_WAIT,
            val,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null_mut::<u32>(),
            0u32,
        )
    }
}

fn futex_wake(uaddr: *mut u32, n: u32) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            uaddr,
            FUTEX_WAKE,
            n,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null_mut::<u32>(),
            0u32,
        )
    }
}

fn main() {
    let len = 4096;
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        println!("max_wake_return=ERR");
        return;
    }
    let w = p as *mut u32;
    let mut max_ret: i64 = 0;

    for _ in 0..TRIALS {
        unsafe { std::ptr::write_volatile(w, 0) };
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child: park on the SHARED futex until the word changes.
            while unsafe { std::ptr::read_volatile(w) } == 0 {
                futex_wait(w, 0);
            }
            unsafe { libc::_exit(0) };
        }
        // Let the single child reach FUTEX_WAIT and park.
        unsafe { libc::usleep(1500) };
        // Change the word so the woken child's re-check exits, then wake ONE-of-8:
        // only one waiter is parked, so a correct kernel returns exactly 1.
        unsafe { std::ptr::write_volatile(w, 1) };
        let r = futex_wake(w, 8);
        if r > max_ret {
            max_ret = r;
        }
        // Make sure the child is gone before reaping (does not affect the count).
        let _ = futex_wake(w, 8);
        let mut st = 0i32;
        unsafe { libc::waitpid(pid, &mut st, 0) };
    }
    unsafe { libc::munmap(p, len) };
    println!("max_wake_return={}", max_ret);
}
