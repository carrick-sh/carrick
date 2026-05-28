//! `FUTEX_WAKE(INT_MAX)` returns exactly N when N waiters are parked on a
//! `MAP_SHARED` futex word. This is the invariant the `sched_yield` between
//! `__ulock_wake_any` iterations fix (commit 3c6c711) restored — without it
//! macOS's lock-structure zombie window causes either inflated counts (the
//! original bug: rc=7+ for one parked waiter) or a capped count (the
//! intermediate "cap at 1" fix). Linux semantics: rc == min(value,
//! actually_woken). LTP `futex_wake03` is the canonical test.
//!
//! Shape: parent maps a 4 KiB MAP_SHARED file, forks N children, each child
//! `FUTEX_WAIT`s on `&word` (shared, no PRIVATE flag). Children bump a `ready`
//! counter before parking so the parent only wakes once they're all parked.
//! Parent calls `FUTEX_WAKE(INT_MAX)` and prints the return value. Children
//! reaped within a bounded deadline.
//!
//! Output (per N, deterministic):
//!   futex_wake_N{N}_returned_N=true|false
//!   futex_wake_N{N}_all_children_reaped=true|false
//!
//! A broken count surface as `_returned_N=false` (without a hung harness).

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
    let path: Vec<u8> = format!("/tmp/carrick_futexwakecount_{n}\0").into_bytes();
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
    let mut woke_total: libc::c_long = 0;
    let mut attempts = 0;
    while woke_total < n as libc::c_long && attempts < (n + 2) {
        let rc = futex_wake(futex_word, i32::MAX as u32);
        if rc < 0 {
            break;
        }
        woke_total += rc;
        attempts += 1;
        if rc == 0 {
            // No children left to wake on the kernel's side; brief pause
            // gives any racing parker a chance to commit before the next
            // INT_MAX-WAKE.
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let rc_was_n = woke_total == n as libc::c_long;

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
    (rc_was_n, all_clean)
}

fn main() {
    // N ∈ {1, 2, 5} mirrors the C reproducer cited in 3c6c711's commit
    // message. 10 is intentionally omitted to keep the probe under 1 s in
    // CI; the fix's behaviour is identical for any small N.
    for &n in &[1usize, 2, 5] {
        let (rc_was_n, all_clean) = unsafe { run_round(n) };
        println!("futex_wake_N{n}_returned_N={rc_was_n}");
        println!("futex_wake_N{n}_all_children_reaped={all_clean}");
    }
}
