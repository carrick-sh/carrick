//! Cross-process `CLONE_FILES` file-table sharing.
//!
//! The Linux `clone(2)` contract says `CLONE_FILES` makes the child and parent
//! refer to the same file-descriptor table even without `CLONE_VM`. Changes by
//! either process are therefore immediately visible to the other. This probe
//! orders four opposite-process mutations with two control pipes:
//!
//! 1. the child opens a descriptor and the parent observes it;
//! 2. the parent closes that descriptor and the child observes `EBADF`;
//! 3. the parent creates a `F_DUPFD_CLOEXEC` slot and the child observes it;
//! 4. the child clears `FD_CLOEXEC` and sets `O_APPEND`, which the parent sees.
//!
//! `FD_CLOEXEC` is descriptor-table state (`fcntl(2)`), while `O_APPEND` is
//! open-file-description state. All synchronization reads and child reaping are
//! bounded. Output is deterministic booleans only.

use conformance_probes::{errno, report};
use std::ffi::CString;
use std::time::{Duration, Instant};

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

fn send_i32(fd: i32, value: i32) -> bool {
    write_exact(fd, &value.to_ne_bytes())
}

fn recv_i32(fd: i32) -> Option<i32> {
    let mut bytes = [0u8; 4];
    read_exact(fd, &mut bytes).then(|| i32::from_ne_bytes(bytes))
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

fn main() {
    unsafe {
        libc::mkdir(c"/tmp".as_ptr(), 0o777);
    }
    let seed_path = CString::new("/tmp/clonefileshare-seed").unwrap();
    let child_path = CString::new("/tmp/clonefileshare-child").unwrap();
    let seed_fd = unsafe {
        libc::open(
            seed_path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    let mut child_to_parent = [0i32; 2];
    let mut parent_to_child = [0i32; 2];
    let setup_ok = seed_fd >= 0
        && unsafe { libc::pipe2(child_to_parent.as_mut_ptr(), 0) } == 0
        && unsafe { libc::pipe2(parent_to_child.as_mut_ptr(), 0) } == 0;
    if !setup_ok {
        report!(
            clone_files_clone_ok = false,
            child_open_visible_in_parent = false,
            parent_close_visible_in_child = false,
            parent_dup_visible_in_child = false,
            child_setfd_visible_in_parent = false,
            child_setfl_visible_in_parent = false,
            child_exited_zero = false,
        );
        return;
    }

    let child = unsafe { raw_clone_files() };
    if child == 0 {
        let opened = unsafe {
            libc::open(
                child_path.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o600,
            )
        };
        let sent_open = send_i32(child_to_parent[1], opened);
        let mut ack = [0u8; 1];
        let got_close_ack = read_exact(parent_to_child[0], &mut ack);
        let parent_close_visible = opened >= 0
            && unsafe { libc::fcntl(opened, libc::F_GETFD) } == -1
            && errno() == libc::EBADF;

        let duplicated = recv_i32(parent_to_child[0]).unwrap_or(-1);
        let duplicated_flags = unsafe { libc::fcntl(duplicated, libc::F_GETFD) };
        let parent_dup_visible =
            duplicated_flags >= 0 && (duplicated_flags & libc::FD_CLOEXEC) != 0;
        let setfd_ok = unsafe { libc::fcntl(duplicated, libc::F_SETFD, 0) } == 0;
        let old_status = unsafe { libc::fcntl(seed_fd, libc::F_GETFL) };
        let setfl_ok = old_status >= 0
            && unsafe { libc::fcntl(seed_fd, libc::F_SETFL, old_status | libc::O_APPEND) } == 0;
        let observations = [
            u8::from(parent_close_visible),
            u8::from(parent_dup_visible),
            u8::from(setfd_ok),
            u8::from(setfl_ok),
        ];
        let sent_observations = write_exact(child_to_parent[1], &observations);
        let ok = sent_open && got_close_ack && sent_observations;
        unsafe { libc::_exit(if ok { 0 } else { 20 }) };
    }

    let clone_ok = child > 0;
    let opened = if clone_ok {
        recv_i32(child_to_parent[0]).unwrap_or(-1)
    } else {
        -1
    };
    let child_open_visible = opened >= 0 && unsafe { libc::fcntl(opened, libc::F_GETFD) } >= 0;
    if opened >= 0 {
        unsafe { libc::close(opened) };
    }
    let _ = write_exact(parent_to_child[1], &[1]);

    let duplicated = unsafe { libc::fcntl(seed_fd, libc::F_DUPFD_CLOEXEC, 100) };
    let _ = send_i32(parent_to_child[1], duplicated);
    let mut observations = [0u8; 4];
    let got_observations = clone_ok && read_exact(child_to_parent[0], &mut observations);

    let child_setfd_visible = got_observations
        && observations[2] == 1
        && duplicated >= 0
        && unsafe { libc::fcntl(duplicated, libc::F_GETFD) } & libc::FD_CLOEXEC == 0;
    let child_setfl_visible = got_observations
        && observations[3] == 1
        && unsafe { libc::fcntl(seed_fd, libc::F_GETFL) } & libc::O_APPEND != 0;
    let child_status = clone_ok.then(|| reap_bounded(child as i32)).flatten();
    let child_exited_zero = child_status
        .is_some_and(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);

    report!(
        clone_files_clone_ok = clone_ok,
        child_open_visible_in_parent = child_open_visible,
        parent_close_visible_in_child = got_observations && observations[0] == 1,
        parent_dup_visible_in_child = got_observations && observations[1] == 1,
        child_setfd_visible_in_parent = child_setfd_visible,
        child_setfl_visible_in_parent = child_setfl_visible,
        child_exited_zero = child_exited_zero,
    );

    unsafe {
        if duplicated >= 0 {
            libc::close(duplicated);
        }
        libc::close(seed_fd);
        for fd in child_to_parent.into_iter().chain(parent_to_child) {
            libc::close(fd);
        }
        libc::unlink(seed_path.as_ptr());
        libc::unlink(child_path.as_ptr());
    }
}
