//! `/proc/self/status` must report the live thread count in its `Threads:`
//! line. CPython's os.fork() reads this to decide whether to emit the
//! "fork() in a multi-threaded process may lead to deadlocks" DeprecationWarning;
//! test_threading.test_dummy_thread_after_fork /
//! test_main_thread_after_fork_from_nonmain_thread assert that warning fires.
//!
//! Carrick hardcoded `Threads:\t1` in /proc/self/status, so CPython thought the
//! process was single-threaded and never warned (the tests' `ws[0]` IndexErrored).
//!
//!  * threads_is_2: with one worker thread alive, /proc/self/status Threads == 2.

use conformance_probes::report;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static STOP: AtomicBool = AtomicBool::new(false);

fn main() {
    let worker = std::thread::spawn(|| {
        while !STOP.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    // Let the worker register.
    std::thread::sleep(Duration::from_millis(150));

    let mut s = String::new();
    let threads = std::fs::File::open("/proc/self/status")
        .and_then(|mut f| f.read_to_string(&mut s).map(|_| ()))
        .ok()
        .and_then(|()| {
            s.lines()
                .find_map(|l| l.strip_prefix("Threads:"))
                .and_then(|v| v.trim().parse::<i64>().ok())
        })
        .unwrap_or(-1);

    report!(threads_is_2 = (threads == 2));

    STOP.store(true, Ordering::Release);
    let _ = worker.join();
}
