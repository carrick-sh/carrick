//! `waitid(P_PID, WEXITED)` child-identity probe.
//!
//! HVPatch owns Linux process identity, credentials, and child-exit state. A
//! terminal `waitid` result must therefore describe the logical child, not the
//! VM carrier or the host user executing Carrick. The child reports its guest
//! real UID through a pipe before exiting; the parent compares that
//! independently observed value with `siginfo_t.si_uid`.
//!
//! Every wait is bounded. Output contains relationships only: no PID, UID,
//! time, address, or process-specific value is printed.

use conformance_probes::{errno, report};
use std::time::{Duration, Instant};

const CHILD_EXIT: i32 = 37;
const WAIT_DEADLINE: Duration = Duration::from_secs(4);
const CLEANUP_DEADLINE: Duration = Duration::from_secs(1);
const WEXITED: libc::c_int = 4;
const WNOHANG: libc::c_int = 1;

fn poll_readable(fd: i32, deadline: Instant) -> bool {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining_ms.max(1)) };
        if rc > 0 {
            return pfd.revents & (libc::POLLIN | libc::POLLHUP) != 0;
        }
        if rc == -1 && errno() == libc::EINTR {
            continue;
        }
        return false;
    }
}

fn read_exact_bounded(fd: i32, bytes: &mut [u8], deadline: Instant) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        if !poll_readable(fd, deadline) {
            return false;
        }
        let rc = unsafe {
            libc::read(
                fd,
                bytes[offset..].as_mut_ptr().cast::<libc::c_void>(),
                bytes.len() - offset,
            )
        };
        if rc > 0 {
            offset += rc as usize;
        } else if rc == 0 || (rc == -1 && errno() != libc::EINTR) {
            return false;
        }
    }
    true
}

unsafe fn write_exact(fd: i32, bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        let rc = libc::write(
            fd,
            bytes[offset..].as_ptr().cast::<libc::c_void>(),
            bytes.len() - offset,
        );
        if rc > 0 {
            offset += rc as usize;
        } else if rc != -1 || errno() != libc::EINTR {
            return false;
        }
    }
    true
}

unsafe fn cleanup_child_bounded(pid: libc::pid_t) {
    // `waitid` may have consumed the child while returning malformed siginfo.
    // Check ECHILD before signaling so a rapidly reused PID is never killed.
    let mut status = 0;
    loop {
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid || (rc == -1 && errno() == libc::ECHILD) {
            return;
        }
        if rc == 0 {
            break;
        }
        if rc == -1 && errno() == libc::EINTR {
            continue;
        }
        return;
    }

    let _ = libc::kill(pid, libc::SIGKILL);
    let deadline = Instant::now() + CLEANUP_DEADLINE;
    loop {
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid || (rc == -1 && errno() != libc::EINTR) || Instant::now() >= deadline {
            return;
        }
        libc::usleep(1_000);
    }
}

fn print_failure() {
    report!(
        child_reported_ruid = false,
        waitid_reaped_child = false,
        waitid_si_pid_matches_child = false,
        waitid_si_uid_matches_child_ruid = false,
        waitid_si_code_is_cld_exited = false,
        waitid_si_status_matches_exit = false,
    );
}

fn main() {
    unsafe {
        let mut pipefd = [-1; 2];
        if libc::pipe2(pipefd.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            print_failure();
            return;
        }

        let child = libc::fork();
        if child == 0 {
            libc::close(pipefd[0]);
            // Linux specifies SIGCHLD si_uid as the child's REAL uid. When
            // privileged, make real/effective differ so the probe catches an
            // implementation that accidentally reports the effective uid.
            let ruid = libc::getuid();
            let identity_ready = if ruid == 0 {
                (libc::geteuid() != ruid || libc::seteuid(65_534) == 0) && libc::geteuid() != ruid
            } else {
                true
            };
            if identity_ready {
                let _ = write_exact(pipefd[1], &ruid.to_ne_bytes());
            }
            libc::close(pipefd[1]);
            libc::_exit(CHILD_EXIT);
        }

        libc::close(pipefd[1]);
        if child < 0 {
            libc::close(pipefd[0]);
            print_failure();
            return;
        }

        let deadline = Instant::now() + WAIT_DEADLINE;
        let mut uid_bytes = [0u8; core::mem::size_of::<libc::uid_t>()];
        let child_reported_ruid = read_exact_bounded(pipefd[0], &mut uid_bytes, deadline);
        libc::close(pipefd[0]);
        let child_ruid = libc::uid_t::from_ne_bytes(uid_bytes);

        let mut terminal_info: libc::siginfo_t = core::mem::zeroed();
        let mut reaped = false;
        loop {
            let mut info: libc::siginfo_t = core::mem::zeroed();
            let rc = libc::waitid(
                libc::P_PID,
                child as libc::id_t,
                &mut info,
                WEXITED | WNOHANG,
            );
            if rc == 0 && info.si_pid() == child {
                terminal_info = info;
                reaped = true;
                break;
            }
            if rc == -1 && errno() != libc::EINTR {
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            libc::usleep(1_000);
        }

        if !reaped {
            cleanup_child_bounded(child);
        }

        report!(
            child_reported_ruid = child_reported_ruid,
            waitid_reaped_child = reaped,
            waitid_si_pid_matches_child = reaped && terminal_info.si_pid() == child,
            waitid_si_uid_matches_child_ruid =
                reaped && child_reported_ruid && terminal_info.si_uid() == child_ruid,
            waitid_si_code_is_cld_exited = reaped && terminal_info.si_code == libc::CLD_EXITED,
            waitid_si_status_matches_exit = reaped && terminal_info.si_status() == CHILD_EXIT,
        );
    }
}
