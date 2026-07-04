//! `/proc/<tgid>/task/<tid>/stat` state for many private futex waiters.
//!
//! LTP futex_wake02 polls every worker via the task-stat path before issuing
//! FUTEX_WAKE. A single waiter can pass while a scaled waiter set exposes vCPU
//! scheduling or guest-visible thread-state publication gaps.

use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const FUTEX_WAIT: libc::c_int = 0;
const FUTEX_WAKE: libc::c_int = 1;
const FUTEX_PRIVATE_FLAG: libc::c_int = 128;
static WORD: AtomicU32 = AtomicU32::new(0);

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

fn task_state(tgid: u32, tid: i32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{tgid}/task/{tid}/stat")).ok()?;
    let rparen = stat.rfind(')')?;
    stat[rparen + 1..].split_whitespace().next()?.chars().next()
}

fn main() {
    let waiters = std::env::var("WAITERS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(128);
    let tids = Arc::new(
        (0..waiters)
            .map(|_| AtomicI32::new(0))
            .collect::<Vec<_>>(),
    );
    WORD.store(0, Ordering::SeqCst);
    for tid in tids.iter() {
        tid.store(0, Ordering::SeqCst);
    }

    let mut handles = Vec::with_capacity(waiters);
    for idx in 0..waiters {
        let tids = Arc::clone(&tids);
        handles.push(std::thread::spawn(move || unsafe {
            let tid = libc::syscall(libc::SYS_gettid) as i32;
            tids[idx].store(tid, Ordering::SeqCst);
            futex_wait_private(WORD.as_ptr(), 0)
        }));
    }

    let ready_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < ready_deadline {
        if tids.iter().all(|tid| tid.load(Ordering::SeqCst) > 0) {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    let known = tids
        .iter()
        .filter(|tid| tid.load(Ordering::SeqCst) > 0)
        .count();
    let tgid = std::process::id();
    let sleep_deadline = Instant::now() + Duration::from_secs(5);
    let mut sleeping = 0usize;
    let mut first_not_sleeping = None;
    while Instant::now() < sleep_deadline {
        sleeping = 0;
        first_not_sleeping = None;
        for tid in tids.iter() {
            let tid = tid.load(Ordering::SeqCst);
            if tid <= 0 {
                first_not_sleeping = Some((tid, '?'));
                continue;
            }
            let state = task_state(tgid, tid).unwrap_or('?');
            if state == 'S' {
                sleeping += 1;
            } else if first_not_sleeping.is_none() {
                first_not_sleeping = Some((tid, state));
            }
        }
        if sleeping == waiters {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    WORD.store(1, Ordering::SeqCst);
    let woken = unsafe { futex_wake_private(WORD.as_ptr(), waiters as u32) };
    let joined = handles.into_iter().all(|handle| handle.join().is_ok());

    println!("waiters={waiters}");
    println!("known_tids={known}");
    println!("sleeping={sleeping}");
    match first_not_sleeping {
        Some((tid, state)) => println!("first_not_sleeping={tid}:{state}"),
        None => println!("first_not_sleeping=none"),
    }
    println!("woken={woken}");
    println!("joined={joined}");
}
