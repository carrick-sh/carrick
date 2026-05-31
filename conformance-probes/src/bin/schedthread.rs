//! sched_* queries must accept live Linux task IDs, including sibling thread
//! tids, not just pid 0 / getpid(). Node/V8's worker startup path reaches this
//! through pthread_getschedparam on worker threads.

use conformance_probes::{errno, report};
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

const SYS_GETTID: libc::c_long = 178;
const SYS_SCHED_GETSCHEDULER: libc::c_long = 120;
const SYS_SCHED_GETPARAM: libc::c_long = 121;

fn main() {
    let child_tid = Arc::new(AtomicI32::new(0));
    let done = Arc::new(AtomicBool::new(false));

    let child_tid_for_thread = Arc::clone(&child_tid);
    let done_for_thread = Arc::clone(&done);
    let worker = thread::spawn(move || {
        let tid = unsafe { libc::syscall(SYS_GETTID) as i32 };
        child_tid_for_thread.store(tid, Ordering::Release);
        while !done_for_thread.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(1));
        }
    });

    for _ in 0..1000 {
        if child_tid.load(Ordering::Acquire) != 0 {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    let tid = child_tid.load(Ordering::Acquire);
    unsafe {
        let sched = libc::syscall(SYS_SCHED_GETSCHEDULER, tid as libc::c_long) as i32;
        let sched_errno = if sched == -1 { errno() } else { 0 };

        let mut param: libc::sched_param = MaybeUninit::zeroed().assume_init();
        let getparam = libc::syscall(
            SYS_SCHED_GETPARAM,
            tid as libc::c_long,
            &mut param as *mut libc::sched_param as libc::c_long,
        ) as i32;
        let getparam_errno = if getparam == -1 { errno() } else { 0 };

        report!(
            child_tid_positive = tid > 0,
            sched_getscheduler_live_thread_is_other = sched == libc::SCHED_OTHER,
            sched_getscheduler_live_thread_errno_zero = sched_errno == 0,
            sched_getparam_live_thread_rc_zero = getparam == 0,
            sched_getparam_live_thread_errno_zero = getparam_errno == 0,
            sched_getparam_live_thread_priority_zero = param.sched_priority == 0,
        );
    }

    done.store(true, Ordering::Release);
    worker.join().expect("worker thread should exit");
}
