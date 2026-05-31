//! A process-wide exit_group(2) issued by the main thread must terminate live
//! sibling threads too. This catches runtimes that return from the main vCPU
//! loop while leaving host threads alive.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const SYS_EXIT_GROUP: libc::c_long = 94;

fn main() {
    let started = Arc::new(AtomicBool::new(false));
    let started_for_thread = Arc::clone(&started);
    let _sleeper = thread::spawn(move || {
        started_for_thread.store(true, Ordering::Release);
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    });

    for _ in 0..1000 {
        if started.load(Ordering::Acquire) {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    unsafe {
        libc::syscall(SYS_EXIT_GROUP, 0i32);
        libc::_exit(99);
    }
}
