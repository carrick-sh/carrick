//! Private cross-thread FUTEX_WAKE exact-count probe.
//!
//! LTP's futex_wake02 waits until a helper thread is sleeping, then expects a
//! wake count that reflects the parked waiter. This reducer isolates that
//! thread-local shape without depending on LTP internals: one sibling enters
//! FUTEX_WAIT_PRIVATE, the parent gives it time to park, then
//! FUTEX_WAKE_PRIVATE(1) must report exactly one woken waiter.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const FUTEX_WAIT: libc::c_int = 0;
const FUTEX_WAKE: libc::c_int = 1;
const FUTEX_PRIVATE_FLAG: libc::c_int = 128;

static WORD: AtomicU32 = AtomicU32::new(0);
static ENTERED_WAIT: AtomicU32 = AtomicU32::new(0);

unsafe fn futex_wait_private(uaddr: *mut u32, val: u32) -> libc::c_long {
    libc::syscall(
        libc::SYS_futex,
        uaddr,
        FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
        val,
        std::ptr::null::<libc::timespec>(),
    )
}

unsafe fn futex_wake_private(uaddr: *mut u32, n: u32) -> libc::c_long {
    libc::syscall(
        libc::SYS_futex,
        uaddr,
        FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
        n,
        std::ptr::null::<libc::timespec>(),
    )
}

fn main() {
    WORD.store(0, Ordering::SeqCst);
    ENTERED_WAIT.store(0, Ordering::SeqCst);

    let waiter = std::thread::spawn(|| unsafe {
        ENTERED_WAIT.store(1, Ordering::SeqCst);
        futex_wait_private(WORD.as_ptr(), 0)
    });

    let ready_deadline = Instant::now() + Duration::from_secs(2);
    while ENTERED_WAIT.load(Ordering::SeqCst) == 0 && Instant::now() < ready_deadline {
        std::thread::sleep(Duration::from_millis(1));
    }

    // ENTERED_WAIT is set immediately before the syscall; give the host futex
    // enough time to enqueue the waiter. This keeps the probe about wake
    // accounting, not scheduler timing.
    std::thread::sleep(Duration::from_millis(100));

    let wake_rc = unsafe { futex_wake_private(WORD.as_ptr(), 1) };

    let join_deadline = Instant::now() + Duration::from_secs(2);
    let joined = loop {
        if waiter.is_finished() {
            break true;
        }
        if Instant::now() >= join_deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(1));
    };

    let wait_rc = if joined {
        waiter.join().unwrap_or(-999)
    } else {
        unsafe {
            WORD.store(1, Ordering::SeqCst);
            let _ = futex_wake_private(WORD.as_ptr(), 1);
        }
        -999
    };

    println!("entered_wait={}", ENTERED_WAIT.load(Ordering::SeqCst) == 1);
    println!("wake_returned_one={}", wake_rc == 1);
    println!("waiter_joined={joined}");
    println!("wait_returned_zero={}", wait_rc == 0);
}
