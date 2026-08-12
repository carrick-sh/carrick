//! Ordinary `fork(2)` file-table membership versus open-description sharing.
//!
//! `fork(2)` gives the child a copy of the parent's descriptor table. Later
//! opens and descriptor flags are table-local, but inherited slots refer to the
//! same open file description, so file offset and status flags are shared. Two
//! control pipes order the observations and every blocking read/reap is bounded.
//!
//! The fixed descriptor numbers are closed before fork, then installed on only
//! one side with `dup3(2)`. That makes membership checks independent of the
//! allocator's lowest-free choice. Behavior comes from `fork(2)` and `fcntl(2)`
//! man-page contracts; output contains deterministic booleans only.

use conformance_probes::{errno, report};
use std::ffi::CString;
use std::time::{Duration, Instant};

const CHILD_ONLY_FD: i32 = 200;
const PARENT_ONLY_FD: i32 = 201;
const IO_TIMEOUT_MS: i32 = 3_000;
const REAP_TIMEOUT: Duration = Duration::from_secs(4);
const KILL_REAP_TIMEOUT: Duration = Duration::from_millis(500);

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

fn main() {
    unsafe {
        libc::mkdir(c"/tmp".as_ptr(), 0o777);
        libc::close(CHILD_ONLY_FD);
        libc::close(PARENT_ONLY_FD);
    }
    let shared_path = CString::new("/tmp/forkfiletable-shared").unwrap();
    let child_path = CString::new("/tmp/forkfiletable-child").unwrap();
    let parent_path = CString::new("/tmp/forkfiletable-parent").unwrap();
    let shared_fd = unsafe {
        libc::open(
            shared_path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    let payload = b"abcdefgh";
    let seeded = shared_fd >= 0
        && unsafe {
            libc::write(
                shared_fd,
                payload.as_ptr().cast::<libc::c_void>(),
                payload.len(),
            )
        } == payload.len() as isize
        && unsafe { libc::lseek(shared_fd, 0, libc::SEEK_SET) } == 0;

    let mut child_to_parent = [0i32; 2];
    let mut parent_to_child = [0i32; 2];
    let setup_ok = seeded
        && unsafe { libc::pipe2(child_to_parent.as_mut_ptr(), 0) } == 0
        && unsafe { libc::pipe2(parent_to_child.as_mut_ptr(), 0) } == 0;
    if !setup_ok {
        report!(
            fork_succeeded = false,
            child_open_isolated_from_parent = false,
            parent_slot_installed = false,
            parent_open_isolated_from_child = false,
            shared_offset_child_read_prefix = false,
            shared_offset_parent_read_next = false,
            shared_status_visible_in_parent = false,
            descriptor_flags_isolated_from_parent = false,
            child_exited_zero = false,
        );
        return;
    }

    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::close(child_to_parent[0]);
            libc::close(parent_to_child[1]);
        }
        let opened = unsafe {
            libc::open(
                child_path.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o600,
            )
        };
        let child_slot_ok =
            opened >= 0 && unsafe { libc::dup3(opened, CHILD_ONLY_FD, 0) } == CHILD_ONLY_FD;
        if opened >= 0 {
            unsafe { libc::close(opened) };
        }
        let sent_child_slot = write_exact(child_to_parent[1], &[u8::from(child_slot_ok)]);

        let mut parent_ready = [0u8; 1];
        let got_parent_ready = read_exact(parent_to_child[0], &mut parent_ready);
        let parent_slot_isolated = got_parent_ready
            && parent_ready[0] == 1
            && unsafe { libc::fcntl(PARENT_ONLY_FD, libc::F_GETFD) } == -1
            && errno() == libc::EBADF;

        let mut first = [0u8; 2];
        let child_read_prefix = unsafe {
            libc::read(
                shared_fd,
                first.as_mut_ptr().cast::<libc::c_void>(),
                first.len(),
            )
        } == first.len() as isize
            && first == *b"ab";
        let sent_prefix = write_exact(child_to_parent[1], &[u8::from(child_read_prefix)]);

        let mut parent_read_done = [0u8; 1];
        let got_parent_read_done = read_exact(parent_to_child[0], &mut parent_read_done);
        let old_status = unsafe { libc::fcntl(shared_fd, libc::F_GETFL) };
        let setfl_ok = old_status >= 0
            && unsafe { libc::fcntl(shared_fd, libc::F_SETFL, old_status | libc::O_APPEND) } == 0;
        let setfd_ok = unsafe { libc::fcntl(shared_fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0;
        let sent_mutations = write_exact(
            child_to_parent[1],
            &[
                u8::from(parent_slot_isolated),
                u8::from(setfl_ok),
                u8::from(setfd_ok),
            ],
        );
        let ok = sent_child_slot
            && got_parent_ready
            && parent_ready[0] == 1
            && sent_prefix
            && got_parent_read_done
            && sent_mutations;
        unsafe { libc::_exit(if ok { 0 } else { 21 }) };
    }

    let fork_ok = child > 0;
    unsafe {
        libc::close(child_to_parent[1]);
        libc::close(parent_to_child[0]);
    }
    let mut child_slot = [0u8; 1];
    let got_child_slot = fork_ok && read_exact(child_to_parent[0], &mut child_slot);
    let child_open_isolated = got_child_slot
        && child_slot[0] == 1
        && unsafe { libc::fcntl(CHILD_ONLY_FD, libc::F_GETFD) } == -1
        && errno() == libc::EBADF;

    let parent_opened = unsafe {
        libc::open(
            parent_path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    let parent_slot_ok = parent_opened >= 0
        && unsafe { libc::dup3(parent_opened, PARENT_ONLY_FD, 0) } == PARENT_ONLY_FD;
    if parent_opened >= 0 {
        unsafe { libc::close(parent_opened) };
    }
    let _ = write_exact(parent_to_child[1], &[u8::from(parent_slot_ok)]);

    let mut child_prefix = [0u8; 1];
    let got_child_prefix = fork_ok && read_exact(child_to_parent[0], &mut child_prefix);
    let mut next = [0u8; 2];
    let parent_read_next = got_child_prefix
        && child_prefix[0] == 1
        && unsafe {
            libc::read(
                shared_fd,
                next.as_mut_ptr().cast::<libc::c_void>(),
                next.len(),
            )
        } == next.len() as isize
        && next == *b"cd";
    let _ = write_exact(parent_to_child[1], &[u8::from(parent_read_next)]);

    let mut child_observations = [0u8; 3];
    let got_observations = fork_ok && read_exact(child_to_parent[0], &mut child_observations);
    let shared_status_visible = got_observations
        && child_observations[1] == 1
        && unsafe { libc::fcntl(shared_fd, libc::F_GETFL) } & libc::O_APPEND != 0;
    let descriptor_flags_isolated = got_observations
        && child_observations[2] == 1
        && unsafe { libc::fcntl(shared_fd, libc::F_GETFD) } & libc::FD_CLOEXEC == 0;
    let child_status = fork_ok.then(|| reap_bounded(child)).flatten();
    let child_exited_zero = child_status
        .is_some_and(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);

    report!(
        fork_succeeded = fork_ok,
        child_open_isolated_from_parent = child_open_isolated,
        parent_slot_installed = parent_slot_ok,
        parent_open_isolated_from_child = parent_slot_ok
            && got_observations
            && child_observations[0] == 1,
        shared_offset_child_read_prefix = got_child_prefix && child_prefix[0] == 1,
        shared_offset_parent_read_next = parent_read_next,
        shared_status_visible_in_parent = shared_status_visible,
        descriptor_flags_isolated_from_parent = descriptor_flags_isolated,
        child_exited_zero = child_exited_zero,
    );

    unsafe {
        libc::close(CHILD_ONLY_FD);
        libc::close(PARENT_ONLY_FD);
        libc::close(shared_fd);
        libc::close(child_to_parent[0]);
        libc::close(parent_to_child[1]);
        libc::unlink(shared_path.as_ptr());
        libc::unlink(child_path.as_ptr());
        libc::unlink(parent_path.as_ptr());
    }
}
