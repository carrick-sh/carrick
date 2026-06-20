//! Timer-generated SIGALRM must be consumable by synchronous signal waits.
//!
//! CPython's `test_signal.PendingSignalsTests.test_sigwait` runs in a freshly
//! exec'd child process, blocks SIGALRM, arms `alarm(1)`, then calls
//! `sigwait([SIGALRM])`. Linux queues the timer signal while it is blocked and
//! `sigwait` consumes it synchronously; the async handler must not run when the
//! signal is later unblocked.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static HANDLER_COUNT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_alrm(_: i32) {
    HANDLER_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

unsafe fn child_sigwait_alarm() -> i32 {
    let mut action: libc::sigaction = std::mem::zeroed();
    action.sa_sigaction = on_alrm as *const () as usize;
    action.sa_flags = 0;
    libc::sigemptyset(&mut action.sa_mask);
    if libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut()) != 0 {
        return 10;
    }

    let mut set: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut set);
    libc::sigaddset(&mut set, libc::SIGALRM);
    if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
        return 11;
    }

    HANDLER_COUNT.store(0, Ordering::SeqCst);
    if libc::alarm(1) != 0 {
        return 12;
    }

    let mut received = 0;
    let sigwait_rc = libc::sigwait(&set, &mut received);
    let handler_count_before_unblock = HANDLER_COUNT.load(Ordering::SeqCst);
    let unblock_rc = libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
    let handler_count_after_unblock = HANDLER_COUNT.load(Ordering::SeqCst);
    libc::alarm(0);

    if sigwait_rc != 0 {
        return 20 + sigwait_rc.min(99);
    }
    if received != libc::SIGALRM {
        return 30;
    }
    if handler_count_before_unblock != 0 {
        return 31;
    }
    if unblock_rc != 0 {
        return 32;
    }
    if handler_count_after_unblock != 0 {
        return 33;
    }
    0
}

unsafe fn wait_child_with_timeout(pid: libc::pid_t) -> (bool, i32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut status = 0i32;
    loop {
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid {
            if libc::WIFEXITED(status) {
                return (true, libc::WEXITSTATUS(status));
            }
            return (true, 128);
        }
        if rc < 0 && errno() != libc::EINTR {
            return (true, 129);
        }
        if Instant::now() >= deadline {
            libc::kill(pid, libc::SIGKILL);
            let _ = libc::waitpid(pid, &mut status, 0);
            return (false, 124);
        }
        libc::usleep(20_000);
    }
}

fn main() {
    unsafe {
        if std::env::args().nth(1).as_deref() == Some("child") {
            libc::_exit(child_sigwait_alarm());
        }

        let pid = libc::fork();
        if pid == 0 {
            let path = b"/tmp/p\0";
            let arg0 = b"/tmp/p\0";
            let arg1 = b"child\0";
            let argv = [
                arg0.as_ptr() as *const libc::c_char,
                arg1.as_ptr() as *const libc::c_char,
                std::ptr::null(),
            ];
            libc::execv(path.as_ptr() as *const libc::c_char, argv.as_ptr());
            libc::_exit(127);
        }
        let (child_exited, status) = wait_child_with_timeout(pid);
        println!("sigwait_alarm_child_exited={child_exited}");
        println!("sigwait_alarm_child_status_zero={}", status == 0);
    }
}
