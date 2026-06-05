//! LTP pause02 reducer: parent waits until a forked child is sleeping in
//! pause(), sends SIGINT to that child, and expects the child to resume from
//! pause() with -1/EINTR. The parent must not receive that child-directed
//! SIGINT.

use conformance_probes::{errno, install_handler, report};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static PARENT_SIGINT_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn parent_sigint(_: i32) {
    PARENT_SIGINT_HITS.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn child_sigint(_: i32) {}

fn read_proc_state(pid: i32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(") ")?.1;
    after_comm.chars().next()
}

fn wait_until_sleeping(pid: i32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if matches!(read_proc_state(pid), Some('S' | 'D')) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

unsafe fn wait_child_bounded(pid: i32, timeout: Duration) -> (bool, i32) {
    let deadline = Instant::now() + timeout;
    let mut status = 0i32;
    while Instant::now() < deadline {
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid {
            return (true, status);
        }
        if rc == -1 && errno() != libc::EINTR {
            return (false, status);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    libc::kill(pid, libc::SIGKILL);
    let _ = libc::waitpid(pid, &mut status, 0);
    (false, status)
}

fn main() {
    unsafe {
        PARENT_SIGINT_HITS.store(0, Ordering::SeqCst);
        let parent_handler_ok = install_handler(libc::SIGINT, parent_sigint, 0);

        let pid = libc::fork();
        if pid == 0 {
            libc::signal(libc::SIGALRM, libc::SIG_DFL);
            if !install_handler(libc::SIGINT, child_sigint, 0) {
                libc::_exit(10);
            }
            libc::alarm(3);
            let rc = libc::pause();
            let err = errno();
            libc::alarm(0);
            if rc == -1 && err == libc::EINTR {
                libc::_exit(0);
            }
            if rc == -1 {
                libc::_exit(11);
            }
            libc::_exit(12);
        }

        let fork_ok = pid > 0;
        let child_sleeping = fork_ok && wait_until_sleeping(pid);
        let send_sigint_ok = child_sleeping && libc::kill(pid, libc::SIGINT) == 0;
        let (child_reaped, status) = if fork_ok {
            wait_child_bounded(pid, Duration::from_secs(5))
        } else {
            (false, 0)
        };

        report!(
            parent_handler_ok = parent_handler_ok,
            fork_ok = fork_ok,
            child_sleeping = child_sleeping,
            send_sigint_ok = send_sigint_ok,
            parent_did_not_get_child_sigint = PARENT_SIGINT_HITS.load(Ordering::SeqCst) == 0,
            child_reaped = child_reaped,
            child_exited = child_reaped && libc::WIFEXITED(status),
            child_exit_zero = child_reaped && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            child_not_signaled = child_reaped && !libc::WIFSIGNALED(status),
        );
    }
}
