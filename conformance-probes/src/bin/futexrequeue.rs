//! `FUTEX_CMP_REQUEUE` / `FUTEX_REQUEUE` — the primitive Darwin's `__ulock`
//! lacks, implemented over `parking_lot_core::unpark_requeue` for private
//! (parking-lot) futexes. This is the operation glibc/musl `pthread_cond`
//! broadcast/signal use to avoid the thundering herd: wake one waiter on the
//! condvar word, requeue the rest onto the mutex word. Stands in for LTP
//! `futex_cmp_requeue01`.
//!
//! The invariants are the syscall RETURN VALUES, which are computed atomically
//! under the futex bucket lock and are therefore deterministic regardless of
//! scheduling (the same values LTP futex_cmp_requeue01 asserts):
//!
//!   1. **CMP_REQUEUE value mismatch → -1/EAGAIN** (the race-free condvar
//!      guard; if `*uaddr1 != val3` nothing moves).
//!   2. **CMP_REQUEUE(nr_wake=1, nr_requeue=INT_MAX) on N parked waiters
//!      returns N** (1 woken + N-1 requeued — Linux returns the sum).
//!   3. **A FUTEX_WAKE(uaddr1) immediately after returns 0** — proof the N-1
//!      really LEFT uaddr1's queue (they were requeued, not just left behind).
//!   4. **FUTEX_WAKE(uaddr2, INT_MAX) returns N-1** — proof they ARE on
//!      uaddr2's queue and a wake there reaches them.
//!   5. **all N threads then run to completion** (no waiter is stranded).
//!
//! Thread bodies are a SINGLE `FUTEX_WAIT(uaddr1, 0)` — a requeued thread
//! stays blocked in that one syscall (carrick moves it to uaddr2's queue
//! without it re-issuing a syscall), so it returns when uaddr2 is woken. No
//! re-wait loop (an earlier version's re-wait deadlocked the woken thread on
//! BOTH Linux and carrick). Every wait is released before join, so a broken
//! requeue surfaces as a `false` count, never a hang.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const SYS_FUTEX: libc::c_long = 98; // aarch64
const FUTEX_WAIT: libc::c_int = 0;
const FUTEX_WAKE: libc::c_int = 1;
const FUTEX_REQUEUE: libc::c_int = 3;
const FUTEX_CMP_REQUEUE: libc::c_int = 4;
const FUTEX_PRIVATE: libc::c_int = 128;
const N: u32 = 4;

static WORD1: AtomicU32 = AtomicU32::new(0);
static WORD2: AtomicU32 = AtomicU32::new(0);
static PARKED: AtomicU32 = AtomicU32::new(0);
static RETURNED: AtomicU32 = AtomicU32::new(0);

unsafe fn futex_op(addr: *const AtomicU32, op: libc::c_int, val: u32) -> libc::c_long {
    libc::syscall(
        SYS_FUTEX,
        addr,
        op | FUTEX_PRIVATE,
        val,
        std::ptr::null::<libc::timespec>(),
    )
}

/// FUTEX_(CMP_)REQUEUE: arg3=nr_requeue, arg4=uaddr2, arg5=val3 (CMP only).
unsafe fn requeue(
    op: libc::c_int,
    uaddr1: *const AtomicU32,
    nr_wake: u32,
    nr_requeue: u32,
    uaddr2: *const AtomicU32,
    val3: u32,
) -> libc::c_long {
    libc::syscall(
        SYS_FUTEX,
        uaddr1,
        op | FUTEX_PRIVATE,
        nr_wake,
        nr_requeue as u64,
        uaddr2,
        val3 as u64,
    )
}

/// Each thread parks once on WORD1. A requeued thread returns from this same
/// syscall when WORD2 is later woken (carrick relinks it to WORD2's queue
/// without a new syscall). Either way it returns exactly once and exits.
fn spawn_waiters() -> Vec<std::thread::JoinHandle<()>> {
    (0..N)
        .map(|_| {
            std::thread::spawn(|| unsafe {
                PARKED.fetch_add(1, Ordering::SeqCst);
                futex_op(&WORD1 as *const AtomicU32, FUTEX_WAIT, 0);
                RETURNED.fetch_add(1, Ordering::SeqCst);
            })
        })
        .collect()
}

fn wait_until(f: impl Fn() -> bool, ms: u64) -> bool {
    let deadline = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    f()
}

/// Park N waiters on WORD1, give them time to enter the syscall, then run
/// `op` (CMP_REQUEUE or REQUEUE) with nr_wake=1. Returns the op's return value
/// plus the two follow-up WAKE counts. Releases + joins all threads.
unsafe fn run_round(op: libc::c_int, val3: u32) -> (libc::c_long, libc::c_long, libc::c_long) {
    WORD1.store(0, Ordering::SeqCst);
    WORD2.store(0, Ordering::SeqCst);
    PARKED.store(0, Ordering::SeqCst);
    RETURNED.store(0, Ordering::SeqCst);
    let handles = spawn_waiters();
    wait_until(|| PARKED.load(Ordering::SeqCst) == N, 2000);
    std::thread::sleep(Duration::from_millis(100));

    let moved = requeue(
        op,
        &WORD1 as *const AtomicU32,
        1,
        i32::MAX as u32,
        &WORD2 as *const AtomicU32,
        val3,
    );
    // WAKE(WORD1): the requeued N-1 must have left → 0.
    let wake1 = futex_op(&WORD1 as *const AtomicU32, FUTEX_WAKE, i32::MAX as u32);
    // WAKE(WORD2): the requeued N-1 are here.
    WORD2.store(1, Ordering::SeqCst);
    let wake2 = futex_op(&WORD2 as *const AtomicU32, FUTEX_WAKE, i32::MAX as u32);
    // Release any straggler still on WORD1 (the woken-by-requeue thread already
    // left; this is belt-and-suspenders so join can't hang).
    WORD1.store(1, Ordering::SeqCst);
    let _ = futex_op(&WORD1 as *const AtomicU32, FUTEX_WAKE, i32::MAX as u32);
    wait_until(|| RETURNED.load(Ordering::SeqCst) == N, 3000);
    for h in handles {
        let _ = h.join();
    }
    (moved, wake1, wake2)
}

fn main() {
    unsafe {
        // (1) CMP_REQUEUE mismatch → -1/EAGAIN, no side effects.
        WORD1.store(5, Ordering::SeqCst);
        let rc = requeue(
            FUTEX_CMP_REQUEUE,
            &WORD1 as *const AtomicU32,
            1,
            i32::MAX as u32,
            &WORD2 as *const AtomicU32,
            999,
        );
        let er = *libc::__errno_location();
        println!("cmp_requeue_mismatch_rc_neg_one={}", rc == -1);
        println!("cmp_requeue_mismatch_errno_eagain={}", er == libc::EAGAIN);

        // (2) Negative nr_requeue → -1/EINVAL (the kernel reads it as a signed
        // int — which is exactly why "requeue all" must be INT_MAX, not ~0u32).
        // No threads needed.
        WORD1.store(0, Ordering::SeqCst);
        let rc = requeue(
            FUTEX_CMP_REQUEUE,
            &WORD1 as *const AtomicU32,
            1,
            0xFFFF_FFFF, /* -1 as int */
            &WORD2 as *const AtomicU32,
            0,
        );
        let er = *libc::__errno_location();
        println!("cmp_requeue_neg_count_rc_neg_one={}", rc == -1);
        println!("cmp_requeue_neg_count_errno_einval={}", er == libc::EINVAL);

        // (3) Plain FUTEX_REQUEUE on an empty queue → 0 (no waiters, no compare).
        WORD1.store(0, Ordering::SeqCst);
        let rc = requeue(
            FUTEX_REQUEUE,
            &WORD1 as *const AtomicU32,
            0,
            i32::MAX as u32,
            &WORD2 as *const AtomicU32,
            0,
        );
        println!("requeue_empty_returns_zero={}", rc == 0);

        // (4) The canonical CMP_REQUEUE(nr_wake=1, INT_MAX) over N parked
        // waiters — the pthread_cond_broadcast shape (LTP futex_cmp_requeue01).
        // Run LAST and ONCE: spawning a SECOND batch of guest threads after a
        // batch has exited currently trips a separate carrick thread-respawn
        // bug ("current thread handle already set"), unrelated to requeue and
        // tracked in handoff.md — so this probe deliberately uses a single
        // threaded round.
        let (moved, wake1, wake2) = run_round(FUTEX_CMP_REQUEUE, 0);
        println!("cmp_requeue_returned_n={}", moved == N as libc::c_long);
        println!("cmp_requeue_word1_drained={}", wake1 == 0);
        println!("cmp_requeue_word2_has_rest={}", wake2 == (N - 1) as libc::c_long);
        println!(
            "cmp_requeue_all_completed={}",
            RETURNED.load(Ordering::SeqCst) == N
        );
    }
}
