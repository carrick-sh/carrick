//! Pre-fork staged `splice(2)` bytes keep one global pipe order.
//!
//! Bytes are moved from an AF_UNIX stream into a nonblocking pipe before
//! `fork(2)`. Carrick's copy-based socket-to-pipe lowering may stage those bytes
//! outside the host pipe, which is precisely the state that must become
//! per-description FileAuthority state. After fork, the parent consumes
//! `AAAA`, the child consumes `BBBB`, and the parent consumes `CCCC`, with
//! control pipes forcing that order.
//!
//! Real Linux keeps the bytes in the pipe object shared by both inherited open
//! file descriptions. The result follows only `pipe(7)`, `splice(2)`, and
//! `fork(2)` behavior. All reads and reaping have deterministic deadlines; no
//! pid, fd, address, or timing value is reported.

use conformance_probes::{errno, report};
use std::time::{Duration, Instant};

const IO_TIMEOUT_MS: i32 = 3_000;
const REAP_TIMEOUT: Duration = Duration::from_secs(4);
const KILL_REAP_TIMEOUT: Duration = Duration::from_millis(500);
const SPLICE_TIMEOUT: Duration = Duration::from_secs(3);
const PAYLOAD: &[u8; 12] = b"AAAABBBBCCCC";

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

fn wait_fd_until(fd: i32, events: i16, deadline: Instant) -> bool {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        if timeout == 0 {
            return false;
        }
        let mut pollfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pollfd, 1, timeout) };
        if rc > 0 {
            return pollfd.revents & events != 0;
        }
        if rc == -1 && errno() == libc::EINTR {
            continue;
        }
        return false;
    }
}

fn splice_exact(source: i32, destination: i32, length: usize) -> bool {
    let deadline = Instant::now() + SPLICE_TIMEOUT;
    let mut transferred = 0usize;
    while transferred < length {
        let count = unsafe {
            libc::splice(
                source,
                core::ptr::null_mut(),
                destination,
                core::ptr::null_mut(),
                length - transferred,
                libc::SPLICE_F_NONBLOCK,
            )
        };
        if count > 0 {
            transferred += count as usize;
            continue;
        }
        if count == -1 && errno() == libc::EINTR {
            continue;
        }
        if count == -1 && errno() == libc::EAGAIN {
            if !wait_fd_until(source, libc::POLLIN, deadline)
                || !wait_fd_until(destination, libc::POLLOUT, deadline)
            {
                return false;
            }
            continue;
        }
        return false;
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

fn main() {
    let mut sockets = [0i32; 2];
    let mut data_pipe = [0i32; 2];
    let mut child_to_parent = [0i32; 2];
    let mut parent_to_child = [0i32; 2];
    let setup_ok = unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr()) == 0
            && libc::pipe2(data_pipe.as_mut_ptr(), libc::O_NONBLOCK) == 0
            && libc::pipe2(child_to_parent.as_mut_ptr(), 0) == 0
            && libc::pipe2(parent_to_child.as_mut_ptr(), 0) == 0
    };
    if !setup_ok {
        report!(
            splice_staged_all = false,
            fork_after_splice_succeeded = false,
            parent_consumed_prefix = false,
            child_consumed_middle = false,
            parent_consumed_suffix = false,
            global_pipe_order_exact = false,
            child_exited_zero = false,
        );
        return;
    }

    let source_written = write_exact(sockets[0], PAYLOAD);
    let splice_staged_all =
        source_written && splice_exact(sockets[1], data_pipe[1], PAYLOAD.len());

    let child = if splice_staged_all {
        unsafe { libc::fork() }
    } else {
        -1
    };
    if child == 0 {
        unsafe {
            libc::close(child_to_parent[0]);
            libc::close(parent_to_child[1]);
        }
        let mut start = [0u8; 1];
        let released = read_exact(parent_to_child[0], &mut start);
        let mut middle = [0u8; 4];
        let read_middle = released && read_exact(data_pipe[0], &mut middle);
        let sent_middle = write_exact(child_to_parent[1], &middle);
        unsafe { libc::_exit(if read_middle && sent_middle { 0 } else { 23 }) };
    }

    let fork_ok = child > 0;
    unsafe {
        libc::close(child_to_parent[1]);
        libc::close(parent_to_child[0]);
    }
    let mut prefix = [0u8; 4];
    let parent_read_prefix = fork_ok && read_exact(data_pipe[0], &mut prefix);
    let released_child = write_exact(parent_to_child[1], &[u8::from(parent_read_prefix)]);
    let mut middle = [0u8; 4];
    let got_middle = fork_ok && released_child && read_exact(child_to_parent[0], &mut middle);
    let mut suffix = [0u8; 4];
    let parent_read_suffix = got_middle && read_exact(data_pipe[0], &mut suffix);
    let child_status = fork_ok.then(|| reap_bounded(child)).flatten();
    let child_exited_zero = child_status
        .is_some_and(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    let prefix_ok = parent_read_prefix && prefix == *b"AAAA";
    let middle_ok = got_middle && middle == *b"BBBB";
    let suffix_ok = parent_read_suffix && suffix == *b"CCCC";

    report!(
        splice_staged_all = splice_staged_all,
        fork_after_splice_succeeded = fork_ok,
        parent_consumed_prefix = prefix_ok,
        child_consumed_middle = middle_ok,
        parent_consumed_suffix = suffix_ok,
        global_pipe_order_exact = prefix_ok && middle_ok && suffix_ok,
        child_exited_zero = child_exited_zero,
    );

    unsafe {
        for fd in sockets
            .into_iter()
            .chain(data_pipe)
            .chain(child_to_parent)
            .chain(parent_to_child)
        {
            libc::close(fd);
        }
    }
}
