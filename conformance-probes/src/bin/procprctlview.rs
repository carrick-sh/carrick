//! Procfs views backed by prctl state.
//!
//! Linux exposes the calling thread's `PR_SET_NAME` value through
//! `/proc/self/comm`, and the current timer slack through
//! `/proc/self/timerslack_ns`. The prctl get paths can round-trip while these
//! procfs files still report stale defaults, so keep this as a line-exact probe.

use conformance_probes::report;
use std::fs;

const PR_SET_NAME: libc::c_int = 15;
const PR_GET_TIMERSLACK: libc::c_int = 30;
const PR_SET_TIMERSLACK: libc::c_int = 29;

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim_end_matches('\n').to_string())
}

fn set_name(name: &[u8]) -> bool {
    unsafe { libc::prctl(PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0) == 0 }
}

fn set_timerslack(ns: libc::c_ulong) -> bool {
    unsafe { libc::prctl(PR_SET_TIMERSLACK, ns, 0, 0, 0) == 0 }
}

fn get_timerslack() -> i64 {
    unsafe { i64::from(libc::prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0)) }
}

fn fork_child_default_matches_parent_current() -> bool {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return false;
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return false;
    }

    if pid == 0 {
        unsafe {
            libc::close(fds[0]);
        }
        let ok = set_timerslack(0)
            && get_timerslack() == 70000
            && read_trimmed("/proc/self/timerslack_ns").as_deref() == Some("70000");
        let byte = if ok { b'1' } else { b'0' };
        unsafe {
            libc::write(fds[1], &byte as *const u8 as *const libc::c_void, 1);
            libc::close(fds[1]);
            libc::_exit(0);
        }
    }

    unsafe {
        libc::close(fds[1]);
    }
    let mut byte = 0u8;
    let read_ok = unsafe { libc::read(fds[0], &mut byte as *mut u8 as *mut libc::c_void, 1) } == 1;
    unsafe {
        libc::close(fds[0]);
    }
    let mut status = 0;
    let wait_ok = unsafe { libc::waitpid(pid, &mut status, 0) } == pid;
    read_ok && wait_ok && byte == b'1'
}

fn main() {
    let name = b"procprctl-name\0";
    let long_name = b"procprctl-name-longer\0";

    report!(proc_self_comm_set_name = set_name(name)
        && read_trimmed("/proc/self/comm").as_deref() == Some("procprctl-name"));
    report!(proc_self_comm_truncated = set_name(long_name)
        && read_trimmed("/proc/self/comm").as_deref() == Some("procprctl-name-"));

    report!(proc_self_timerslack_min = set_timerslack(1)
        && read_trimmed("/proc/self/timerslack_ns").as_deref() == Some("1"));
    report!(proc_self_timerslack_middle = set_timerslack(70000)
        && read_trimmed("/proc/self/timerslack_ns").as_deref() == Some("70000"));
    report!(forked_timerslack_default = fork_child_default_matches_parent_current());
    report!(proc_self_timerslack_reset = set_timerslack(0)
        && read_trimmed("/proc/self/timerslack_ns").as_deref() == Some("50000"));
}
