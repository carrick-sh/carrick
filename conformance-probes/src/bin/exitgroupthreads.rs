//! exit_group(2) must terminate every thread in the process, including a live
//! sibling thread. Node's process.exit() relies on this after worker_threads
//! have existed; returning from only the main vCPU leaves the host process
//! alive as a WorkerThread.

use conformance_probes::report;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const SYS_EXIT_GROUP: libc::c_long = 94;

fn child() -> ! {
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
        libc::syscall(SYS_EXIT_GROUP, 37i32);
        libc::_exit(99);
    }
}

fn main() {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            child();
        }

        let mut status = 0i32;
        let waited = libc::waitpid(pid, &mut status, 0);
        let exited = (status & 0x7f) == 0;
        let exit_status = (status >> 8) & 0xff;

        report!(
            waitpid_reaped_child = waited == pid,
            child_exited_normally = exited,
            child_exit_status_37 = exit_status == 37,
        );
    }
}
