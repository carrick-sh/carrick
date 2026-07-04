//! `PR_SET_CHILD_SUBREAPER` fork and orphan-reparenting semantics.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use conformance_probes::report;

const PR_SET_CHILD_SUBREAPER: libc::c_int = 36;
const PR_GET_CHILD_SUBREAPER: libc::c_int = 37;

static SIGCHLD_COUNT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_sigchld(_: libc::c_int) {
    SIGCHLD_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn install_sigchld_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigchld as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut());
    }
}

fn read_exact_fd(fd: libc::c_int, buf: &mut [u8]) -> bool {
    let mut off = 0;
    while off < buf.len() {
        let rc = unsafe { libc::read(fd, buf[off..].as_mut_ptr() as *mut _, buf.len() - off) };
        if rc <= 0 {
            return false;
        }
        off += rc as usize;
    }
    true
}

fn write_all_fd(fd: libc::c_int, buf: &[u8]) -> bool {
    let mut off = 0;
    while off < buf.len() {
        let rc = unsafe { libc::write(fd, buf[off..].as_ptr() as *const _, buf.len() - off) };
        if rc <= 0 {
            return false;
        }
        off += rc as usize;
    }
    true
}

fn wait_pid(pid: libc::pid_t) -> Option<i32> {
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return Some(status);
        }
        if rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return None;
    }
}

fn main() {
    install_sigchld_handler();
    let root_pid = unsafe { libc::getpid() };
    let set_ok = unsafe { libc::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == 0;

    let mut ready_pipe = [0; 2];
    let mut release_pipe = [0; 2];
    let mut ppid_pipe = [0; 2];
    let pipes_ok = unsafe {
        libc::pipe(ready_pipe.as_mut_ptr()) == 0
            && libc::pipe(release_pipe.as_mut_ptr()) == 0
            && libc::pipe(ppid_pipe.as_mut_ptr()) == 0
    };

    let child = if pipes_ok { unsafe { libc::fork() } } else { -1 };
    if child == 0 {
        unsafe {
            libc::close(ready_pipe[0]);
            libc::close(release_pipe[1]);
            libc::close(ppid_pipe[0]);
        }
        let mut inherited = -1i32;
        let get_ok = unsafe {
            libc::prctl(
                PR_GET_CHILD_SUBREAPER,
                &mut inherited as *mut i32 as libc::c_ulong,
                0,
                0,
                0,
            )
        } == 0;
        let grandchild = unsafe { libc::fork() };
        if grandchild == 0 {
            unsafe {
                libc::close(ready_pipe[1]);
            }
            let mut byte = [0u8; 1];
            let _ = read_exact_fd(release_pipe[0], &mut byte);
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut observed = unsafe { libc::getppid() };
            while observed != root_pid && Instant::now() < deadline {
                unsafe {
                    libc::sched_yield();
                }
                observed = unsafe { libc::getppid() };
            }
            let _ = write_all_fd(ppid_pipe[1], &observed.to_ne_bytes());
            unsafe { libc::_exit(7) };
        }
        let child_ok = get_ok && inherited == 0 && grandchild > 0;
        let _ = write_all_fd(ready_pipe[1], &grandchild.to_ne_bytes());
        unsafe { libc::_exit(if child_ok { 0 } else { 3 }) };
    }

    unsafe {
        libc::close(ready_pipe[1]);
        libc::close(release_pipe[0]);
        libc::close(ppid_pipe[1]);
    }
    let mut grandchild_bytes = [0u8; 4];
    let got_grandchild = read_exact_fd(ready_pipe[0], &mut grandchild_bytes);
    let grandchild = i32::from_ne_bytes(grandchild_bytes);
    let child_status = wait_pid(child);
    let child_subreaper_not_inherited =
        child_status.is_some_and(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);

    SIGCHLD_COUNT.store(0, Ordering::SeqCst);
    let _ = write_all_fd(release_pipe[1], &[1]);
    let mut observed_ppid_bytes = [0u8; 4];
    let got_observed_ppid = read_exact_fd(ppid_pipe[0], &mut observed_ppid_bytes);
    let observed_ppid = i32::from_ne_bytes(observed_ppid_bytes);
    let orphan_status = wait_pid(grandchild);
    let sigchld_from_orphan = SIGCHLD_COUNT.load(Ordering::SeqCst) > 0;

    report!(set_subreaper_ok = set_ok);
    report!(child_subreaper_not_inherited = child_subreaper_not_inherited);
    report!(grandchild_pid_reported = got_grandchild && grandchild > 0);
    report!(orphan_ppid_is_subreaper = got_observed_ppid && observed_ppid == root_pid);
    report!(wait_reaped_orphan = orphan_status.is_some());
    report!(orphan_exit_status = orphan_status
        .is_some_and(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 7));
    report!(sigchld_from_orphan = sigchld_from_orphan);
}
