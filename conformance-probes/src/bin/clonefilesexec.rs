//! `execve(2)` by one cross-process `CLONE_FILES` sharer.
//!
//! Linux unshares a shared descriptor table when one sharer successfully execs.
//! `FD_CLOEXEC` closure therefore applies only to the successor's new table; it
//! must not remove that slot from the non-execing sharer. Conversely, a
//! non-CLOEXEC slot survives into the successor, and closing it there must not
//! close the original sharer's now-independent slot.
//!
//! The exec successor returns a bitset through a non-CLOEXEC result pipe. The
//! parent prints every observation after a bounded read/reap, so output remains
//! fixed and deterministic even when clone or exec fails. Contracts come from
//! the `clone(2)`, `execve(2)`, and `fcntl(2)` man pages.

use conformance_probes::{errno, report};
use std::ffi::CString;
use std::time::{Duration, Instant};

const IO_TIMEOUT_MS: i32 = 3_000;
const REAP_TIMEOUT: Duration = Duration::from_secs(4);
const KILL_REAP_TIMEOUT: Duration = Duration::from_millis(500);
const SUCCESSOR_MARKER: u8 = 0x80;

fn wait_fd(fd: i32, events: i16) -> bool {
    let mut pollfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        let rc = unsafe { libc::poll(&mut pollfd, 1, IO_TIMEOUT_MS) };
        if rc > 0 {
            return true;
        }
        if rc == -1 && errno() == libc::EINTR {
            continue;
        }
        return false;
    }
}

fn write_exact(fd: i32, bytes: &[u8]) -> bool {
    let mut done = 0;
    while done < bytes.len() {
        if !wait_fd(fd, libc::POLLOUT) {
            return false;
        }
        let n = unsafe {
            libc::write(
                fd,
                bytes[done..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - done,
            )
        };
        if n > 0 {
            done += n as usize;
        } else if n != -1 || errno() != libc::EINTR {
            return false;
        }
    }
    true
}

fn read_exact(fd: i32, bytes: &mut [u8]) -> bool {
    let mut done = 0;
    while done < bytes.len() {
        if !wait_fd(fd, libc::POLLIN) {
            return false;
        }
        let n = unsafe {
            libc::read(
                fd,
                bytes[done..].as_mut_ptr().cast::<libc::c_void>(),
                bytes.len() - done,
            )
        };
        if n > 0 {
            done += n as usize;
        } else if n != -1 || errno() != libc::EINTR {
            return false;
        }
    }
    true
}

fn reap_bounded(pid: i32) -> Option<i32> {
    let deadline = Instant::now() + REAP_TIMEOUT;
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            return Some(status);
        }
        if rc == -1 && errno() != libc::EINTR {
            return None;
        }
        if Instant::now() >= deadline {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let kill_deadline = Instant::now() + KILL_REAP_TIMEOUT;
            loop {
                let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if rc == pid || (rc == -1 && errno() != libc::EINTR) {
                    return None;
                }
                if Instant::now() >= kill_deadline {
                    return None;
                }
                unsafe { libc::usleep(10_000) };
            }
        }
        unsafe { libc::usleep(10_000) };
    }
}

unsafe fn raw_clone_files() -> i64 {
    let flags = libc::CLONE_FILES | libc::SIGCHLD;
    libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) as i64
}

fn successor_mode(args: &[String]) -> bool {
    if args.first().map(String::as_str) != Some("--successor") {
        return false;
    }
    let parse_fd = |index: usize| args.get(index).and_then(|arg| arg.parse::<i32>().ok());
    let Some(keep_fd) = parse_fd(1) else {
        return true;
    };
    let Some(cloexec_fd) = parse_fd(2) else {
        return true;
    };
    let Some(result_fd) = parse_fd(3) else {
        return true;
    };

    let cloexec_closed =
        unsafe { libc::fcntl(cloexec_fd, libc::F_GETFD) } == -1 && errno() == libc::EBADF;
    let kept_open = unsafe { libc::fcntl(keep_fd, libc::F_GETFD) } >= 0;
    let successor_close_ok = unsafe { libc::close(keep_fd) } == 0;
    let observations =
        u8::from(cloexec_closed) | (u8::from(kept_open) << 1) | (u8::from(successor_close_ok) << 2);
    let sent = write_exact(result_fd, &[SUCCESSOR_MARKER | observations]);
    std::process::exit(if sent && observations == 0b111 { 0 } else { 22 });
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if successor_mode(&args) {
        return;
    }

    unsafe { libc::mkdir(c"/tmp".as_ptr(), 0o777) };
    let keep_path = CString::new("/tmp/clonefilesexec-keep").unwrap();
    let cloexec_path = CString::new("/tmp/clonefilesexec-cloexec").unwrap();
    let keep_fd = unsafe {
        libc::open(
            keep_path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    let cloexec_fd = unsafe {
        libc::open(
            cloexec_path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    let cloexec_set =
        cloexec_fd >= 0 && unsafe { libc::fcntl(cloexec_fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0;
    let mut result_pipe = [0i32; 2];
    let setup_ok =
        keep_fd >= 0 && cloexec_set && unsafe { libc::pipe2(result_pipe.as_mut_ptr(), 0) } == 0;
    if !setup_ok {
        report!(
            clone_files_exec_clone_ok = false,
            successor_exec_succeeded = false,
            successor_closed_cloexec = false,
            successor_inherited_noncloexec = false,
            successor_closed_own_noncloexec = false,
            parent_retained_cloexec_slot = false,
            parent_retained_successor_closed_slot = false,
            successor_exited_zero = false,
        );
        return;
    }

    let exe = CString::new(std::env::args().next().unwrap_or_default()).unwrap();
    let mode = CString::new("--successor").unwrap();
    let keep_arg = CString::new(keep_fd.to_string()).unwrap();
    let cloexec_arg = CString::new(cloexec_fd.to_string()).unwrap();
    let result_arg = CString::new(result_pipe[1].to_string()).unwrap();
    let argv = [
        exe.as_ptr(),
        mode.as_ptr(),
        keep_arg.as_ptr(),
        cloexec_arg.as_ptr(),
        result_arg.as_ptr(),
        core::ptr::null(),
    ];
    let envp = [core::ptr::null()];

    let child = unsafe { raw_clone_files() };
    if child == 0 {
        unsafe {
            libc::execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
        let _ = write_exact(result_pipe[1], &[0]);
        unsafe { libc::_exit(127) };
    }

    let clone_ok = child > 0;
    let mut successor_bits = [0u8; 1];
    let got_successor = clone_ok && read_exact(result_pipe[0], &mut successor_bits);
    let child_status = clone_ok.then(|| reap_bounded(child as i32)).flatten();
    let successor_exited_zero = child_status
        .is_some_and(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    let bits = if got_successor { successor_bits[0] } else { 0 };
    let successor_exec_succeeded = got_successor && bits & SUCCESSOR_MARKER != 0;
    let parent_cloexec_flags = unsafe { libc::fcntl(cloexec_fd, libc::F_GETFD) };
    let parent_retained_cloexec = successor_exec_succeeded
        && parent_cloexec_flags >= 0
        && (parent_cloexec_flags & libc::FD_CLOEXEC) != 0;
    let parent_retained_keep = successor_exec_succeeded
        && unsafe { libc::fcntl(keep_fd, libc::F_GETFD) } >= 0;

    report!(
        clone_files_exec_clone_ok = clone_ok,
        successor_exec_succeeded = successor_exec_succeeded,
        successor_closed_cloexec = successor_exec_succeeded && bits & 0b001 != 0,
        successor_inherited_noncloexec = successor_exec_succeeded && bits & 0b010 != 0,
        successor_closed_own_noncloexec = successor_exec_succeeded && bits & 0b100 != 0,
        parent_retained_cloexec_slot = parent_retained_cloexec,
        parent_retained_successor_closed_slot = parent_retained_keep,
        successor_exited_zero = successor_exited_zero,
    );

    unsafe {
        libc::close(keep_fd);
        libc::close(cloexec_fd);
        libc::close(result_pipe[0]);
        libc::close(result_pipe[1]);
        libc::unlink(keep_path.as_ptr());
        libc::unlink(cloexec_path.as_ptr());
    }
}
