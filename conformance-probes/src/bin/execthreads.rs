//! execve(2) from a multithreaded process must replace the whole thread group.
//!
//! Go's syscall.TestExec starts many goroutines, then one thread calls
//! syscall.Exec on the same test binary. Linux kills every sibling thread during
//! exec and starts the new image as a single-threaded process. Carrick must
//! drain sibling vCPUs before rebuilding the HVF VM; otherwise the old runtime's
//! threads can keep running against the address space being destroyed.

use conformance_probes::{errno, report};
use std::ffi::CString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const WORKERS: usize = 32;
static READY: AtomicUsize = AtomicUsize::new(0);

extern "C" fn worker(_: *mut libc::c_void) -> *mut libc::c_void {
    READY.fetch_add(1, Ordering::SeqCst);
    loop {
        unsafe {
            libc::sched_yield();
        }
    }
}

fn status_thread_count() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let value = line.strip_prefix("Threads:")?.trim();
        value.parse().ok()
    })
}

fn stage1(exe: &str) {
    let mut threads = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let mut thread: libc::pthread_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::pthread_create(&mut thread, std::ptr::null(), worker, std::ptr::null_mut())
        };
        if rc != 0 {
            report!(stage1_pthread_create_errno = rc);
            return;
        }
        threads.push(thread);
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while READY.load(Ordering::SeqCst) < WORKERS && Instant::now() < deadline {
        unsafe {
            libc::sched_yield();
        }
    }
    if READY.load(Ordering::SeqCst) != WORKERS {
        report!(stage1_threads_ready = false);
        return;
    }

    let path = CString::new(exe).expect("argv[0]");
    let stage2 = CString::new("stage2").expect("stage2");
    let argv = [path.as_ptr(), stage2.as_ptr(), std::ptr::null()];
    let env = CString::new("CARRICK_EXECTHREADS_STAGE2=1").expect("env");
    let envp = [env.as_ptr(), std::ptr::null()];
    unsafe {
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }
    report!(stage1_execve_errno = errno());
}

fn stage2() {
    let threads = status_thread_count();
    report!(
        exec_stage2_reached = true,
        exec_thread_count_is_one = threads == Some(1),
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("stage2") => stage2(),
        _ => {
            let exe = args.first().map(String::as_str).unwrap_or("/tmp/execthreads");
            stage1(exe);
        }
    }
}
