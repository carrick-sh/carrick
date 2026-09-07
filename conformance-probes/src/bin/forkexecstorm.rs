//! Concurrency test for parallel fork/vfork + execve(/bin/true) + waitpid
//! from a multithreaded process.
//!
//! When multiple threads concurrently invoke vfork + execve, each child must
//! receive its own independent stage-1 authority without clobbering the
//! parent's live page tables or stealing its arena source.

use conformance_probes::report;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

const THREAD_COUNT: usize = 4;
const ITERATIONS_PER_THREAD: usize = 50;

#[allow(deprecated)]
fn thread_worker(all_ok: Arc<AtomicBool>) {
    let path = b"/bin/true\0".as_ptr() as *const libc::c_char;
    let argv = [path, std::ptr::null()];
    let envp = [std::ptr::null()];

    for _ in 0..ITERATIONS_PER_THREAD {
        let child = unsafe { libc::vfork() };
        if child == 0 {
            unsafe {
                libc::execve(path, argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        if child < 0 {
            all_ok.store(false, Ordering::SeqCst);
            break;
        }
        let mut status = 0;
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited != child || !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            all_ok.store(false, Ordering::SeqCst);
            break;
        }
    }
}

fn main() {
    let all_ok = Arc::new(AtomicBool::new(true));
    let mut handles = Vec::new();

    for _ in 0..THREAD_COUNT {
        let ok = Arc::clone(&all_ok);
        handles.push(thread::spawn(move || thread_worker(ok)));
    }

    for h in handles {
        let _ = h.join();
    }

    let success = all_ok.load(Ordering::SeqCst);
    report!(fork_exec_storm_success = success);
    if !success {
        std::process::exit(1);
    }
}
