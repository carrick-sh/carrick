//! `/proc/self/stat` state for a sleeping process leader.
//!
//! A helper thread that polls `/proc/self/stat` should observe `S` while the
//! process leader is blocked in `FUTEX_WAIT_PRIVATE`. LTP's futex_wait03 uses
//! this shape before the helper issues `FUTEX_WAKE_PRIVATE`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const FUTEX_WAIT: libc::c_int = 0;
const FUTEX_WAKE: libc::c_int = 1;
const FUTEX_PRIVATE_FLAG: libc::c_int = 128;

static WORD: AtomicU32 = AtomicU32::new(0);
static OBSERVED_SLEEPING: AtomicU32 = AtomicU32::new(0);
static HELPER_DONE: AtomicU32 = AtomicU32::new(0);

unsafe fn futex_wait_private(uaddr: *mut u32, val: u32) -> libc::c_long {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            uaddr,
            FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
            val,
            std::ptr::null::<libc::timespec>(),
        )
    }
}

unsafe fn futex_wake_private(uaddr: *mut u32, n: u32) -> libc::c_long {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            uaddr,
            FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
            n,
            std::ptr::null::<libc::timespec>(),
        )
    }
}

fn stat_state() -> Option<char> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let rparen = stat.rfind(')')?;
    stat[rparen + 1..].split_whitespace().next()?.chars().next()
}

fn main() {
    WORD.store(0, Ordering::SeqCst);
    OBSERVED_SLEEPING.store(0, Ordering::SeqCst);
    HELPER_DONE.store(0, Ordering::SeqCst);

    let helper = std::thread::spawn(|| {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if stat_state() == Some('S') {
                OBSERVED_SLEEPING.store(1, Ordering::SeqCst);
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        WORD.store(1, Ordering::SeqCst);
        let wake_rc = unsafe { futex_wake_private(WORD.as_ptr(), 1) };
        HELPER_DONE.store((wake_rc == 1) as u32, Ordering::SeqCst);
    });

    let wait_rc = unsafe { futex_wait_private(WORD.as_ptr(), 0) };
    let joined = helper.join().is_ok();

    println!(
        "self_stat_observed_sleeping={}",
        OBSERVED_SLEEPING.load(Ordering::SeqCst) == 1
    );
    println!("helper_woke_one={}", HELPER_DONE.load(Ordering::SeqCst) == 1);
    println!("leader_wait_returned_zero={}", wait_rc == 0);
    println!("helper_joined={joined}");
}
