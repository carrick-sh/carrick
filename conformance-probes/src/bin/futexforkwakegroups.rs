//! Forked child futex wake groups, matching LTP futex_wake02's shape.
//!
//! The child creates sum(1..10) waiter threads, waits until each reports
//! sleeping through both `/proc/<tid>/stat` and
//! `/proc/<tgid>/task/<tid>/stat`, then issues FUTEX_WAKE with counts
//! 1, 2, ..., 10.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::{Duration, Instant};

const FUTEX_WAIT: libc::c_int = 0;
const FUTEX_WAKE: libc::c_int = 1;
const FUTEX_PRIVATE_FLAG: libc::c_int = 128;
const MAX_GROUP: usize = 10;
const WAITERS: usize = MAX_GROUP * (MAX_GROUP + 1) / 2;

static WORD: AtomicU32 = AtomicU32::new(0);
static EXITED: AtomicU32 = AtomicU32::new(0);
static LAST_PTHREAD_ERRNO: AtomicI32 = AtomicI32::new(0);

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

fn stat_state(path: String) -> Option<char> {
    let stat = std::fs::read_to_string(path).ok()?;
    let rparen = stat.rfind(')')?;
    stat[rparen + 1..].split_whitespace().next()?.chars().next()
}

fn direct_state(tid: i32) -> Option<char> {
    stat_state(format!("/proc/{tid}/stat"))
}

fn task_state(tgid: u32, tid: i32) -> Option<char> {
    stat_state(format!("/proc/{tgid}/task/{tid}/stat"))
}

extern "C" fn child_thread(_arg: *mut libc::c_void) -> *mut libc::c_void {
    unsafe {
        let _ = futex_wait_private(WORD.as_ptr(), 0);
    }
    EXITED.fetch_add(1, Ordering::SeqCst);
    std::ptr::null_mut()
}

fn task_tids(tgid: u32) -> BTreeSet<i32> {
    std::fs::read_dir(format!("/proc/{tgid}/task"))
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
        .collect()
}

fn spawn_pthread(tgid: u32, known_tids: &mut BTreeSet<i32>) -> Option<(libc::pthread_t, i32)> {
    let mut thread = std::mem::MaybeUninit::<libc::pthread_t>::uninit();
    let ret = unsafe {
        libc::pthread_create(
            thread.as_mut_ptr(),
            std::ptr::null(),
            child_thread,
            std::ptr::null_mut(),
        )
    };
    if ret != 0 {
        LAST_PTHREAD_ERRNO.store(ret, Ordering::SeqCst);
        return None;
    }
    let thread = unsafe { thread.assume_init() };
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        let now = task_tids(tgid);
        if let Some(tid) = now.iter().find(|tid| !known_tids.contains(tid)).copied() {
            *known_tids = now;
            return Some((thread, tid));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Some((thread, 0))
}

fn child_main() -> i32 {
    WORD.store(0, Ordering::SeqCst);
    EXITED.store(0, Ordering::SeqCst);
    LAST_PTHREAD_ERRNO.store(0, Ordering::SeqCst);
    let tgid = std::process::id();
    let mut known_task_tids = task_tids(tgid);
    let mut tids = Vec::with_capacity(WAITERS);
    let mut threads = Vec::with_capacity(WAITERS);
    for _ in 0..WAITERS {
        let Some((thread, tid)) = spawn_pthread(tgid, &mut known_task_tids) else {
            break;
        };
        threads.push(thread);
        tids.push(AtomicI32::new(tid));
    }

    let ready_deadline = Instant::now() + Duration::from_secs(10);
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

    let task_dir_has_tgid = std::fs::read_dir(format!("/proc/{tgid}/task"))
        .map(|entries| {
            entries.filter_map(Result::ok).any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name == tgid.to_string())
            })
        })
        .unwrap_or(false);
    let sleep_deadline = Instant::now() + Duration::from_secs(10);
    let mut direct_sleeping = 0usize;
    let mut task_sleeping = 0usize;
    let mut first_not_sleeping = None;
    while Instant::now() < sleep_deadline {
        direct_sleeping = 0;
        task_sleeping = 0;
        first_not_sleeping = None;
        for tid in tids.iter() {
            let tid = tid.load(Ordering::SeqCst);
            let direct = if tid <= 0 {
                '?'
            } else {
                direct_state(tid).unwrap_or('?')
            };
            let task = if tid <= 0 {
                '?'
            } else {
                task_state(tgid, tid).unwrap_or('?')
            };
            if direct == 'S' {
                direct_sleeping += 1;
            }
            if task == 'S' {
                task_sleeping += 1;
            }
            if direct != 'S' || task != 'S' {
                first_not_sleeping.get_or_insert((tid, direct, task));
            }
        }
        if direct_sleeping == WAITERS && task_sleeping == WAITERS {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    let mut missing_direct_after_wake = 0usize;
    let mut missing_task_after_wake = 0usize;
    if first_not_sleeping.is_some() {
        for tid in tids.iter() {
            let tid = tid.load(Ordering::SeqCst);
            if tid > 0 && direct_state(tid).is_none() {
                missing_direct_after_wake += 1;
            }
            if tid > 0 && task_state(tgid, tid).is_none() {
                missing_task_after_wake += 1;
            }
        }
    }

    let mut wake_ok = true;
    let mut wake_returns = Vec::new();
    for count in 1..=MAX_GROUP {
        let woken = unsafe { futex_wake_private(WORD.as_ptr(), count as u32) };
        wake_returns.push(woken);
        wake_ok &= woken == count as libc::c_long;
    }
    let exit_deadline = Instant::now() + Duration::from_secs(10);
    while EXITED.load(Ordering::SeqCst) < WAITERS as u32 && Instant::now() < exit_deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let joined = EXITED.load(Ordering::SeqCst) == WAITERS as u32;
    if joined {
        for thread in threads {
            unsafe {
                libc::pthread_join(thread, std::ptr::null_mut());
            }
        }
    } else {
        let _ = unsafe { futex_wake_private(WORD.as_ptr(), WAITERS as u32) };
    }
    let spawned = tids.len();

    println!("child_known_tids={known}");
    println!("spawned_threads={spawned}");
    println!(
        "last_pthread_errno={}",
        LAST_PTHREAD_ERRNO.load(Ordering::SeqCst)
    );
    println!("task_dir_has_tgid={task_dir_has_tgid}");
    println!("child_direct_sleeping={direct_sleeping}");
    println!("child_task_sleeping={task_sleeping}");
    match first_not_sleeping {
        Some((tid, direct, task)) => {
            println!("child_first_not_sleeping={tid}:direct={direct}:task={task}");
        }
        None => println!("child_first_not_sleeping=none"),
    }
    println!("missing_direct_after_wake={missing_direct_after_wake}");
    println!("missing_task_after_wake={missing_task_after_wake}");
    println!("wake_returns={wake_returns:?}");
    println!("wake_counts_ok={wake_ok}");
    println!("child_exited={}", EXITED.load(Ordering::SeqCst));
    println!("child_joined={joined}");
    if known == WAITERS
        && task_dir_has_tgid
        && direct_sleeping == WAITERS
        && task_sleeping == WAITERS
        && wake_ok
        && joined
    {
        0
    } else {
        1
    }
}

fn main() {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let grandchild = unsafe { libc::fork() };
        if grandchild == 0 {
            std::process::exit(child_main());
        }
        if grandchild < 0 {
            println!("grandchild_fork_ok=false");
            std::process::exit(1);
        }
        println!("grandchild_fork_ok=true");
        let mut status = 0;
        let waited = unsafe { libc::waitpid(grandchild, &mut status, 0) };
        let exit_ok =
            waited == grandchild && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        std::process::exit(if exit_ok { 0 } else { 1 });
    }
    if pid < 0 {
        println!("fork_ok=false");
        println!("child_exit_ok=false");
        return;
    }

    println!("fork_ok=true");
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    let exit_ok = waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    println!("child_exit_ok={exit_ok}");
}
