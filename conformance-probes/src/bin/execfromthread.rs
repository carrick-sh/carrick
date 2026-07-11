//! execve(2) from a NON-LEADER thread must replace the whole thread group,
//! even while the group leader (main) is alive and running guest code.
//!
//! The sibling probe `execthreads` execs FROM main with worker siblings; this
//! probe inverts the shape: a spawned worker thread execs while MAIN is the
//! sibling that must be terminated. Linux kills the leader during exec and the
//! new image runs single-threaded (the execing task becomes the group's only
//! task). The carrick-native hazard this pins: the retired leader's host
//! thread must not tear the process down "because the thread group ended" while
//! the execing thread is running the new image — a lost exec.
//!
//! stage2 re-checks the thread count, exactly like `execthreads`.

use conformance_probes::{errno, report};
use std::ffi::CString;
use std::time::{Duration, Instant};

fn status_thread_count() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let value = line.strip_prefix("Threads:")?.trim();
        value.parse().ok()
    })
}

fn stage1(exe: &str) {
    let exe = exe.to_string();
    let worker = std::thread::spawn(move || {
        // Give main a beat to reach its keep-alive loop so the exec teardown
        // fires against a RUNNING leader (the shape under test), not one
        // still inside thread-spawn bookkeeping.
        std::thread::sleep(Duration::from_millis(50));
        let path = CString::new(exe).expect("argv[0]");
        let stage2 = CString::new("stage2").expect("stage2");
        let argv = [path.as_ptr(), stage2.as_ptr(), std::ptr::null()];
        let env = CString::new("CARRICK_EXECFROMTHREAD_STAGE2=1").expect("env");
        let envp = [env.as_ptr(), std::ptr::null()];
        unsafe {
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
        report!(stage1_thread_execve_errno = errno());
        std::process::exit(1);
    });

    // Keep-alive: on success the image is replaced out from under this loop
    // within milliseconds. The bound only reports the failure shape.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        unsafe {
            libc::sched_yield();
        }
    }
    report!(exec_from_thread_replaced_image = false);
    let _ = worker.join();
}

fn stage2() {
    let threads = status_thread_count();
    report!(
        exec_from_thread_stage2_reached = true,
        exec_from_thread_count_is_one = threads == Some(1),
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("stage2") => stage2(),
        _ => {
            let exe = args
                .first()
                .map(String::as_str)
                .unwrap_or("/tmp/execfromthread");
            stage1(exe);
        }
    }
}
