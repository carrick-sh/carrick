//! `/proc/<tid>/stat` state for a sleeping thread.
//!
//! LTP's futex helpers wait for a worker thread to enter a sleeping state by
//! polling `/proc/<tid>/stat`. A thread blocked in `FUTEX_WAIT_PRIVATE` should
//! report state `S`, not stay `R`.

use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::{Duration, Instant};

const FUTEX_WAIT: libc::c_int = 0;
const FUTEX_WAKE: libc::c_int = 1;
const FUTEX_PRIVATE_FLAG: libc::c_int = 128;

static WORD: AtomicU32 = AtomicU32::new(0);
static WAITER_TID: AtomicI32 = AtomicI32::new(0);

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

fn stat_state(tid: i32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{tid}/stat")).ok()?;
    let rparen = stat.rfind(')')?;
    stat[rparen + 1..].split_whitespace().next()?.chars().next()
}

fn main() {
    WORD.store(0, Ordering::SeqCst);
    WAITER_TID.store(0, Ordering::SeqCst);

    let waiter = std::thread::spawn(|| unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as i32;
        WAITER_TID.store(tid, Ordering::SeqCst);
        futex_wait_private(WORD.as_ptr(), 0)
    });

    let ready_deadline = Instant::now() + Duration::from_secs(2);
    let tid = loop {
        let tid = WAITER_TID.load(Ordering::SeqCst);
        if tid > 0 {
            break tid;
        }
        if Instant::now() >= ready_deadline {
            println!("waiter_tid_known=false");
            println!("waiter_state_is_sleeping=false");
            println!("waiter_joined=false");
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    };

    let state_deadline = Instant::now() + Duration::from_secs(2);
    let mut state = None;
    while Instant::now() < state_deadline {
        state = stat_state(tid);
        if state == Some('S') {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    WORD.store(1, Ordering::SeqCst);
    let _ = unsafe { futex_wake_private(WORD.as_ptr(), 1) };
    let joined = waiter.join().is_ok();

    println!("waiter_tid_known=true");
    println!("waiter_state={}", state.unwrap_or('?'));
    println!("waiter_state_is_sleeping={}", state == Some('S'));
    println!("waiter_joined={joined}");
}
