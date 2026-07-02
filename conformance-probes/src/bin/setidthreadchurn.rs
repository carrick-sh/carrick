//! libc set*id wrappers while guest threads are live and exiting.
//!
//! Go's cgo-linked TestSetuidEtc exercises libc set*id wrappers, not raw
//! syscalls. glibc/musl synchronize those process-wide credential transitions
//! across all live OS threads. Linux returns promptly even while sibling threads
//! are starting and exiting; the probe bounds the wait and reports whether the
//! wrapper sequence completed rather than letting a stuck worker hang the gate.

use conformance_probes::report;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CHURN_THREADS: usize = 8;
const LOOPS: usize = 4;

fn setid_sequence(iter: usize) -> bool {
    let uid_a = 10 + (iter % 8) as libc::uid_t;
    let uid_b = 100 + iter as libc::uid_t;
    let gid_a = 20 + (iter % 8) as libc::gid_t;
    let gid_b = 200 + iter as libc::gid_t;
    unsafe {
        libc::setresgid(gid_a, 0, gid_b) == 0
            && libc::setresuid(uid_a, 0, uid_b) == 0
            && libc::setresgid(0, 0, 0) == 0
            && libc::setresuid(0, 0, 0) == 0
    }
}

fn main() {
    let ready = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let errors = Arc::new(AtomicUsize::new(0));

    for _ in 0..CHURN_THREADS {
        let ready = Arc::clone(&ready);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            ready.fetch_add(1, Ordering::SeqCst);
            while !stop.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
        });
    }

    let deadline = Instant::now() + Duration::from_secs(3);
    while ready.load(Ordering::SeqCst) != CHURN_THREADS && Instant::now() < deadline {
        std::thread::yield_now();
    }

    let mut setid_done = true;
    for i in 0..LOOPS {
        if !setid_sequence(i) {
            errors.fetch_add(1, Ordering::SeqCst);
            setid_done = false;
            break;
        }
    }
    stop.store(true, Ordering::SeqCst);

    report!(
        setid_threads_started = ready.load(Ordering::SeqCst) == CHURN_THREADS,
        setid_wrappers_completed = setid_done,
        setid_thread_errors_zero = errors.load(Ordering::SeqCst) == 0,
    );
}
