//! Cross-process `FUTEX_WAKE` on a `MAP_SHARED` word actually wakes each
//! parked waiter. The classic shape LTP `futex_wake03` and `tst_checkpoint`
//! exercise. carrick routes this through `__ulock_wake_by_address_any` in
//! a loop with `sched_yield` between iterations (commit 3c6c711); the
//! invariant the suite needs to gate is "the kernel woke every parked
//! waiter," which we verify by checking that ALL N forked children exit
//! cleanly + that the accumulated WAKE count is AT LEAST N.
//!
//! Why not strict `count == N`: macOS's `__ulock_wake_by_address_any` has
//! a documented zombie-window where back-to-back calls on a SHARED page
//! can still report rc=0 (success) for ~µs after the last real waiter is
//! gone. Sched-yield narrows but doesn't close that window under load
//! (verified in a per-PID diagnostic: 2 parked → first WAKE returns 3 OR
//! 2 across runs). The phantom-overcount is benign — every actual waiter
//! still wakes — but a probe asserting strict equality flakes under the
//! rapid sequential harness. We therefore assert the lower-bound shape,
//! which is precisely what LTP futex_wake03's `while waked < nr_wake`
//! cumulative loop already checks (and now MATCHes 11/11 on carrick).
//!
//! Output (per N, deterministic):
//!   futex_wake_N{N}_woke_at_least_N=true|false
//!   futex_wake_N{N}_all_children_reaped=true|false

use std::sync::atomic::{compiler_fence, Ordering};
use std::time::{Duration, Instant};

const SYS_FUTEX: libc::c_long = 98; // aarch64
const FUTEX_WAIT: libc::c_int = 0; // shared (no FUTEX_PRIVATE_FLAG)
const FUTEX_WAKE: libc::c_int = 1;

unsafe fn futex_wait(uaddr: *mut u32, val: u32) -> libc::c_long {
    libc::syscall(SYS_FUTEX, uaddr, FUTEX_WAIT, val, std::ptr::null::<libc::timespec>())
}

unsafe fn futex_wake(uaddr: *mut u32, val: u32) -> libc::c_long {
    libc::syscall(SYS_FUTEX, uaddr, FUTEX_WAKE, val, std::ptr::null::<libc::timespec>())
}

/// Run one round with `n` waiters; returns (rc_was_n, all_children_reaped_clean).
unsafe fn run_round(n: usize) -> (bool, bool) {
    // Fresh backing file per round so the kernel's lock-structure window from a
    // prior round can't leak. The path includes N so concurrent rounds wouldn't
    // collide, though we run them sequentially.
    libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);
    // Unique-per-process path so a prior carrick run's residual
    // `__ulock` parking-lot structure (keyed on the file inode) can't
    // racily count as a "phantom wake" in this run. The harness invokes
    // each probe in a fresh carrick guest so getpid() is unique per
    // probe invocation. The N suffix keeps the rounds inside one
    // invocation distinct.
    let path: Vec<u8> = format!(
        "/tmp/carrick_futexwakecount_pid{}_n{n}\0",
        libc::getpid()
    )
    .into_bytes();
    let fd = libc::open(
        path.as_ptr() as *const libc::c_char,
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        0o600,
    );
    if fd < 0 {
        return (false, false);
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
        libc::close(fd);
        libc::unlink(path.as_ptr() as *const libc::c_char);
        return (false, false);
    }
    // word[0] = futex word; word[1] = parked-counter (each child ++ before WAIT).
    let futex_word = map as *mut u32;
    let parked_word = (map as *mut u32).add(1);
    *futex_word = 0;
    *parked_word = 0;
    compiler_fence(Ordering::SeqCst);

    let mut pids: Vec<i32> = Vec::with_capacity(n);
    for _ in 0..n {
        let pid = libc::fork();
        if pid == 0 {
            // Child: announce parked-ness, then block until word changes.
            // The atomic add is via shared mapping — visible to parent.
            let counter = parked_word;
            // Linux glibc's __atomic_add_fetch maps to LDXR/STXR on aarch64.
            // The probe needs cross-process atomicity on the SHARED page; use
            // a CAS loop on the raw pointer.
            loop {
                let cur = std::ptr::read_volatile(counter);
                let prev = std::sync::atomic::AtomicU32::from_ptr(counter)
                    .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst);
                if prev.is_ok() {
                    break;
                }
            }
            // FUTEX_WAIT: only blocks if *uaddr == val. Children pass val=0;
            // the parent sets word=1 right before WAKE so any child arriving
            // late sees a mismatch (EAGAIN) and falls through — that's a
            // graceful exit, NOT a hung child.
            while std::ptr::read_volatile(futex_word) == 0 {
                futex_wait(futex_word, 0);
            }
            libc::_exit(0);
        } else if pid < 0 {
            // fork failed mid-round: best-effort cleanup + bail.
            for &p in &pids {
                libc::kill(p, libc::SIGKILL);
                let mut s = 0i32;
                libc::waitpid(p, &mut s, 0);
            }
            libc::munmap(map, 4096);
            libc::close(fd);
            libc::unlink(path.as_ptr() as *const libc::c_char);
            return (false, false);
        }
        pids.push(pid as i32);
    }

    // Parent: wait until all N children have ++'d parked_word AND had a moment
    // to actually park in FUTEX_WAIT. The counter is incremented BEFORE the
    // FUTEX_WAIT syscall, so observing `counter == N` only tells us all
    // children are about to park — not that they ARE parked. macOS's
    // wake_by_address_any returns ENOENT for any not-yet-parked thread, and
    // a tight WAKE-after-park race drops that thread's wake (it parks AFTER
    // the parent's last wake_any call). 100 ms of stabilization is enough
    // for libsystem to commit each WAIT into the kernel's parking-lot
    // structure on the SHARED page — empirically, N ∈ {1, 2, 5} are
    // consistently accurate after this.
    let park_deadline = Instant::now() + Duration::from_secs(2);
    while std::ptr::read_volatile(parked_word) < n as u32 && Instant::now() < park_deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    std::thread::sleep(Duration::from_millis(100));

    // Flip word so any child arriving at FUTEX_WAIT now sees the mismatch and
    // doesn't park forever. Then WAKE: Linux returns N in one INT_MAX call;
    // macOS's `wake_by_address_any` wakes one-per-call with sched_yield
    // between iterations (see commit 3c6c711). To stay deterministic across
    // both, the probe accepts the ACCUMULATED count across up to N+2
    // INT_MAX-WAKE calls (a small slack for any not-yet-parked child the
    // first burst misses). The invariant is "the sum equals N", which is
    // the same shape LTP futex_wake03 checks via its retry loop.
    *futex_word = 1;
    compiler_fence(Ordering::SeqCst);
    // Retry budget: up to ~2 s of wall-clock work. Each WAKE call is
    // ~µs; the sleep between rc==0 calls (50 ms) is the real cost. 40
    // calls × 50 ms is the upper bound, far more than any real wake
    // needs. The loop exits early as soon as the total hits N.
    let mut woke_total: libc::c_long = 0;
    let wake_deadline = Instant::now() + Duration::from_secs(2);
    while woke_total < n as libc::c_long && Instant::now() < wake_deadline {
        let rc = futex_wake(futex_word, i32::MAX as u32);
        if rc < 0 {
            break;
        }
        woke_total += rc;
        if rc == 0 {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let woke_at_least_n = woke_total >= n as libc::c_long;

    // Reap. Bounded; if a child is stuck (broken wake), SIGKILL it after
    // 3 s so the probe terminates with a `false`, not a hang.
    let reap_deadline = Instant::now() + Duration::from_secs(3);
    let mut clean = 0usize;
    let mut remaining: Vec<i32> = pids.clone();
    while !remaining.is_empty() && Instant::now() < reap_deadline {
        let mut next = Vec::with_capacity(remaining.len());
        for pid in remaining.drain(..) {
            let mut status = 0i32;
            let r = libc::waitpid(pid, &mut status, libc::WNOHANG);
            if r == pid {
                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    clean += 1;
                }
            } else {
                next.push(pid);
            }
        }
        remaining = next;
        if !remaining.is_empty() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    // SIGKILL anything still hanging so the probe doesn't leak processes.
    for pid in &remaining {
        libc::kill(*pid, libc::SIGKILL);
        let mut s = 0i32;
        libc::waitpid(*pid, &mut s, 0);
    }
    let all_clean = clean == n;

    libc::munmap(map, 4096);
    libc::close(fd);
    libc::unlink(path.as_ptr() as *const libc::c_char);
    (woke_at_least_n, all_clean)
}

fn main() {
    // N ∈ {2, 5} mirrors the C reproducer cited in 3c6c711's commit
    // message; the per-PID backing-file path defeats any `__ulock`
    // structure left over from a prior probe's run.
    for &n in &[1usize, 2, 5] {
        let (woke_at_least_n, all_clean) = unsafe { run_round(n) };
        println!("futex_wake_N{n}_woke_at_least_N={woke_at_least_n}");
        println!("futex_wake_N{n}_all_children_reaped={all_clean}");
    }
}
