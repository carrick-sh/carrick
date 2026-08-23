//! Cross-process futex on a `MAP_SHARED|MAP_ANONYMOUS` word must share one
//! wait queue: a child forked after the mapping parks in shared `FUTEX_WAIT`
//! on the word, and the parent's shared `FUTEX_WAKE` on the same word must
//! find and wake it (return count 1 per parked waiter, no child timeout).
//!
//! This is the anonymous-memory sibling of `futexpingpong` (which uses a
//! `MAP_SHARED` *file* word). The two differ in futex identity derivation:
//! a shared file word has a stable (file, offset) identity, while a shared
//! anonymous word's identity must come from the shared backing itself. The
//! carrick-native hazard this pins: keying the anon-shared wait queue by the
//! mapping VIEW (e.g. a per-address-space host alias address) splits parent
//! and child onto disjoint queues — writes stay coherent through the shared
//! frame, but every wake/requeue finds zero waiters and every waiter times
//! out. `futexforkrequeue` hits the same defect at 1000-waiter scale; this
//! probe is the deterministic two-waiter reducer.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use conformance_probes::errno;

const SYS_FUTEX: libc::c_long = libc::SYS_futex;
const FUTEX_WAIT: libc::c_int = 0; // SHARED (no FUTEX_PRIVATE_FLAG)
const FUTEX_WAKE: libc::c_int = 1;
const WAITERS: usize = 2;

#[repr(C)]
struct SharedPage {
    word: u32,
    parked_intent: u32,
    normal_wakes: u32,
    timed_out: u32,
    other_returns: u32,
    returned: u32,
}

unsafe fn futex_wait(addr: *mut u32, value: u32, timeout: &libc::timespec) -> libc::c_long {
    libc::syscall(
        SYS_FUTEX,
        addr,
        FUTEX_WAIT,
        value,
        timeout as *const libc::timespec,
    )
}

unsafe fn futex_wake(addr: *mut u32, count: u32) -> libc::c_long {
    libc::syscall(
        SYS_FUTEX,
        addr,
        FUTEX_WAKE,
        count,
        std::ptr::null::<libc::timespec>(),
    )
}

unsafe fn shared_counter(ptr: *mut u32) -> &'static AtomicU32 {
    &*(ptr as *const AtomicU32)
}

fn main() {
    unsafe {
        let page = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if page == libc::MAP_FAILED {
            println!("shared_map_ok=false");
            return;
        }
        println!("shared_map_ok=true");
        let shared = page as *mut SharedPage;
        let word = &mut (*shared).word as *mut u32;
        let parked_intent = &mut (*shared).parked_intent as *mut u32;
        let normal_wakes = &mut (*shared).normal_wakes as *mut u32;
        let timed_out = &mut (*shared).timed_out as *mut u32;
        let other_returns = &mut (*shared).other_returns as *mut u32;
        let returned = &mut (*shared).returned as *mut u32;

        let mut pids = Vec::with_capacity(WAITERS);
        for _ in 0..WAITERS {
            let pid = libc::fork();
            if pid == 0 {
                shared_counter(parked_intent).fetch_add(1, Ordering::SeqCst);
                let timeout = libc::timespec {
                    tv_sec: 8,
                    tv_nsec: 0,
                };
                let rc = futex_wait(word, 0, &timeout);
                if rc == 0 {
                    shared_counter(normal_wakes).fetch_add(1, Ordering::SeqCst);
                } else if rc == -1 && errno() == libc::ETIMEDOUT {
                    shared_counter(timed_out).fetch_add(1, Ordering::SeqCst);
                } else {
                    shared_counter(other_returns).fetch_add(1, Ordering::SeqCst);
                }
                shared_counter(returned).fetch_add(1, Ordering::SeqCst);
                libc::_exit(0);
            }
            pids.push(pid);
        }
        println!("forked_all={}", pids.iter().all(|&p| p > 0));

        // Wait until both children have DECLARED intent, then leave a bounded
        // enrollment window for the final user-space -> FUTEX_WAIT step (the
        // same shape futexforkrequeue uses; intent proves the child is at the
        // wait boundary, not yet enrolled in the kernel queue).
        let deadline = Instant::now() + Duration::from_secs(10);
        while shared_counter(parked_intent).load(Ordering::SeqCst) < WAITERS as u32
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(500));

        // Wake while *word is still 0 and both children are parked: every
        // waiter must be found on the shared queue.
        let woken_while_parked = futex_wake(word, i32::MAX as u32);

        // Publish the release value and wake again (belt for a waiter that
        // raced its enrollment past the first wake; Linux counts it in either
        // wake, never in neither).
        *word = 1;
        let woken_after_store = futex_wake(word, i32::MAX as u32);

        let deadline = Instant::now() + Duration::from_secs(12);
        while shared_counter(returned).load(Ordering::SeqCst) < WAITERS as u32
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut exited = 0usize;
        for &pid in &pids {
            let mut status = 0;
            if libc::waitpid(pid, &mut status, 0) == pid
                && libc::WIFEXITED(status)
                && libc::WEXITSTATUS(status) == 0
            {
                exited += 1;
            }
        }

        let total_woken = woken_while_parked.max(0) + woken_after_store.max(0);
        println!(
            "wake_calls_succeeded={}",
            woken_while_parked >= 0 && woken_after_store >= 0
        );
        println!(
            "all_waiters_woken={}",
            total_woken == WAITERS as libc::c_long
        );
        println!(
            "normal_wake_count_expected={}",
            shared_counter(normal_wakes).load(Ordering::SeqCst) == WAITERS as u32
        );
        println!(
            "timeout_count_zero={}",
            shared_counter(timed_out).load(Ordering::SeqCst) == 0
        );
        println!(
            "other_return_count_zero={}",
            shared_counter(other_returns).load(Ordering::SeqCst) == 0
        );
        println!(
            "returned_all={}",
            shared_counter(returned).load(Ordering::SeqCst) == WAITERS as u32
        );
        println!("children_exited_all={}", exited == WAITERS);

        libc::munmap(page, 4096);
    }
}
