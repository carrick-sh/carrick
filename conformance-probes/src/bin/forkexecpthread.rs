//! A child which replaces its image with execve(2) must be able to create a
//! pthread in the replacement image.
//!
//! This is the minimal lifecycle behind Node worker startup, Go after
//! fork-to-exec, and CPython subprocess thread tests. The fork child performs
//! only execve/_exit before image replacement; all pthread work happens in
//! stage2.

use conformance_probes::report;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};

static WORKER_RAN: AtomicBool = AtomicBool::new(false);

extern "C" fn worker(_: *mut libc::c_void) -> *mut libc::c_void {
    WORKER_RAN.store(true, Ordering::SeqCst);
    std::ptr::null_mut()
}

fn stage1(exe: &str) {
    let path = CString::new(exe).expect("argv[0]");
    let stage2 = CString::new("stage2").expect("stage2");
    let argv = [path.as_ptr(), stage2.as_ptr(), std::ptr::null()];
    let env = CString::new("CARRICK_FORKEXECPTHREAD_STAGE2=1").expect("env");
    let envp = [env.as_ptr(), std::ptr::null()];

    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }
    if child < 0 {
        report!(parent_observed_child_success = false);
        return;
    }

    let mut status = 0;
    let reaped = unsafe { libc::waitpid(child, &mut status, 0) };
    report!(
        parent_observed_child_success = reaped == child
            && libc::WIFEXITED(status)
            && libc::WEXITSTATUS(status) == 0,
    );
}

fn stage2() {
    WORKER_RAN.store(false, Ordering::SeqCst);
    let mut thread: libc::pthread_t = unsafe { std::mem::zeroed() };
    let create_rc = unsafe {
        libc::pthread_create(
            &mut thread,
            std::ptr::null(),
            worker,
            std::ptr::null_mut(),
        )
    };
    let join_rc = if create_rc == 0 {
        unsafe { libc::pthread_join(thread, std::ptr::null_mut()) }
    } else {
        -1
    };
    report!(
        fork_exec_stage2_reached = true,
        post_exec_pthread_create_ok = create_rc == 0,
        post_exec_pthread_create_errno = create_rc,
        post_exec_worker_ran = WORKER_RAN.load(Ordering::SeqCst),
        post_exec_pthread_join_ok = join_rc == 0,
    );
    if create_rc != 0 || join_rc != 0 || !WORKER_RAN.load(Ordering::SeqCst) {
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("stage2") => stage2(),
        _ => {
            let exe = args
                .first()
                .map(String::as_str)
                .unwrap_or("/tmp/forkexecpthread");
            stage1(exe);
        }
    }
}
