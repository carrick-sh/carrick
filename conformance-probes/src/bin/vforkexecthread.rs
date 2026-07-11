//! execve(2) from a sibling thread while the group LEADER is vfork-SUSPENDED
//! must complete promptly: Linux kills the vfork-waiting leader (its vfork
//! wait is killable) and replaces the image; the vfork child keeps running to
//! its own `_exit` and remains a reapable child of the (exec'd) process.
//!
//! The carrick-native hazard this pins: the vfork parent held the process
//! fork token across its suspend, so a sibling's execve HOT-SPUN on the token
//! (100% CPU, unbounded, paced by the guest-controlled vfork child) instead
//! of retiring the suspended leader. Byte-identity alone does not catch the
//! pre-fix shape (the exec eventually proceeds once the vfork child exits);
//! the discriminators are wall/CPU time, measured by the harness around this
//! probe.
//!
//! Choreography: main spawns the exec thread, then vforks a child that raw-
//! nanosleeps ~1s before `_exit(0)` (own stack via the libc `clone()` wrapper,
//! per the `vforkpid` idiom — a NULL-stack raw clone is UB). The exec thread
//! execs stage2 at ~300 ms, mid-suspend. stage2 blocks in `waitpid(-1)` and
//! reaps the surviving vfork child.

use conformance_probes::report;
use std::ffi::CString;
use std::time::Duration;

/// vfork child, on its own clone stack: raw-sleep ~1 s, then `_exit(0)`.
/// nanosleep + `_exit` only — the async-signal-safe set a vfork child may use.
extern "C" fn vfork_child(_arg: *mut libc::c_void) -> libc::c_int {
    let ts = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    unsafe {
        libc::nanosleep(&ts, std::ptr::null_mut());
        libc::_exit(0)
    }
}

fn stage1(exe: &str) {
    let exe = exe.to_string();
    std::thread::spawn(move || {
        // Exec mid-suspend: main vforks within microseconds of spawning us;
        // the child exits at ~1 s, so 300 ms lands inside the suspend window.
        std::thread::sleep(Duration::from_millis(300));
        let path = CString::new(exe).expect("argv[0]");
        let stage2 = CString::new("stage2").expect("stage2");
        let argv = [path.as_ptr(), stage2.as_ptr(), std::ptr::null()];
        let env = CString::new("CARRICK_VFORKEXECTHREAD_STAGE2=1").expect("env");
        let envp = [env.as_ptr(), std::ptr::null()];
        unsafe {
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
        report!(stage1_thread_execve_failed = true);
        std::process::exit(1);
    });

    // 64 KiB child stack, 16-byte aligned top (vforkpid idiom).
    let mut stack = vec![0u8; 1usize << 16];
    unsafe {
        let top = (stack.as_mut_ptr().add(stack.len()) as usize & !0xf) as *mut libc::c_void;
        let flags = libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD;
        let child = libc::clone(vfork_child, top, flags, std::ptr::null_mut());
        if child < 0 {
            report!(stage1_vfork_failed = true);
            std::process::exit(1);
        }
        // On Linux this thread is DEAD before vfork returns (the exec killed
        // it mid-suspend). Reaching here means the exec never fired.
        report!(stage1_survived_vfork_suspend = true);
        std::process::exit(1);
    }
}

fn stage2() {
    // The vfork child (raw-sleeping ~700 ms more) survived the exec and is
    // still OUR child; reap it.
    let mut status = 0;
    let reaped = unsafe { libc::waitpid(-1, &mut status, 0) };
    report!(
        vfork_exec_stage2_reached = true,
        vfork_child_survived_exec =
            reaped > 0 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
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
                .unwrap_or("/tmp/vforkexecthread");
            stage1(exe);
        }
    }
}
