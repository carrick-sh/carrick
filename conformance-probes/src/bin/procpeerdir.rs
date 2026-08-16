//! A FOREIGN process's `/proc/<pid>` must be a real directory, not just a
//! prefix that per-pid file reads happen to resolve.
//!
//! Under carrick's HVPatch backend every Linux process is a THREAD of one
//! Darwin process, so a peer has no host pid of its own. The `/proc/<pid>`
//! machinery resolved a guest pid through the HOST process table, which cannot
//! tell a live peer from a pid that never existed — so `cat /proc/<peer>/stat`
//! worked (the file renderers were already routed through Carrick's kernel task
//! graph) while `ls -d /proc/<peer>`, `test -d /proc/<peer>`,
//! `stat /proc/<peer>`, `ls /proc/<peer>/task` and `ls /proc | grep <peer>` all
//! reported ENOENT. LTP `pidfd_send_signal02`/`03` open `/proc/<foreign-pid>`
//! with `O_DIRECTORY`; `futex_wake02`/`04` and `tgkill03` `opendir` their own
//! pid spelled NUMERICALLY, which lands in the same foreign code path.
//!
//!  * peer_access:      access("/proc/<peer>", F_OK) succeeds.
//!  * peer_is_dir:      stat("/proc/<peer>") reports S_IFDIR.
//!  * peer_opendir:     open("/proc/<peer>", O_DIRECTORY) succeeds.
//!  * peer_task_dir:    open("/proc/<peer>/task", O_DIRECTORY) succeeds.
//!  * peer_task_lists_leader: readdir("/proc/<peer>/task") contains the pid.
//!  * peer_stat_file:   open("/proc/<peer>/stat") succeeds (already-working
//!                      control — it is what makes the divergence above a
//!                      HALF-fixed path rather than an absent one).
//!  * peer_in_proc:     readdir("/proc") lists the peer.
//!  * self_numeric_dir: open("/proc/<getpid()>", O_DIRECTORY) succeeds — the
//!                      same parser, reached with the reader's own pid.
//!  * dead_pid_enoent:  /proc/<never-allocated> stays ENOENT, so the fix does
//!                      not fabricate a directory for every number.

use conformance_probes::report;
use std::ffi::CString;

fn cstr(path: &str) -> CString {
    CString::new(path).expect("probe paths carry no NUL")
}

fn opendir_ok(path: &str) -> bool {
    let c = cstr(path);
    unsafe {
        let fd = libc::open(c.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY);
        if fd >= 0 {
            libc::close(fd);
            true
        } else {
            false
        }
    }
}

fn open_file_ok(path: &str) -> bool {
    let c = cstr(path);
    unsafe {
        let fd = libc::open(c.as_ptr(), libc::O_RDONLY);
        if fd >= 0 {
            libc::close(fd);
            true
        } else {
            false
        }
    }
}

fn dir_contains(path: &str, name: &str) -> bool {
    let c = cstr(path);
    unsafe {
        let dir = libc::opendir(c.as_ptr());
        if dir.is_null() {
            return false;
        }
        let mut found = false;
        loop {
            let entry = libc::readdir(dir);
            if entry.is_null() {
                break;
            }
            let d_name = (*entry).d_name.as_ptr();
            let mut len = 0usize;
            while *d_name.add(len) != 0 {
                len += 1;
            }
            let bytes = std::slice::from_raw_parts(d_name as *const u8, len);
            if bytes == name.as_bytes() {
                found = true;
                break;
            }
        }
        libc::closedir(dir);
        found
    }
}

fn is_dir(path: &str) -> bool {
    let c = cstr(path);
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        libc::stat(c.as_ptr(), &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR
    }
}

fn main() {
    unsafe {
        let child = libc::fork();
        if child == 0 {
            // Long enough that the parent's whole observation window sees a
            // LIVE peer; the parent kills it before exiting either way.
            libc::sleep(30);
            libc::_exit(0);
        }
        assert!(child > 0, "probe requires a forked peer");
        // Let the child reach its sleep so the peer is unambiguously live.
        libc::usleep(200_000);

        let peer = format!("/proc/{child}");
        let peer_access = libc::access(cstr(&peer).as_ptr(), libc::F_OK) == 0;
        let peer_is_dir = is_dir(&peer);
        let peer_opendir = opendir_ok(&peer);
        let peer_task_dir = opendir_ok(&format!("{peer}/task"));
        let peer_task_lists_leader = dir_contains(&format!("{peer}/task"), &child.to_string());
        let peer_stat_file = open_file_ok(&format!("{peer}/stat"));
        let peer_in_proc = dir_contains("/proc", &child.to_string());

        let own = libc::getpid();
        let self_numeric_dir = opendir_ok(&format!("/proc/{own}"));

        // A pid no allocator has reached in this container. Kept well below
        // pid_max so this is "not allocated", not "out of range".
        let dead_pid_enoent = !is_dir("/proc/424242") && !opendir_ok("/proc/424242");

        libc::kill(child, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);

        report!(
            peer_access = peer_access,
            peer_is_dir = peer_is_dir,
            peer_opendir = peer_opendir,
            peer_task_dir = peer_task_dir,
            peer_task_lists_leader = peer_task_lists_leader,
            peer_stat_file = peer_stat_file,
            peer_in_proc = peer_in_proc,
            self_numeric_dir = self_numeric_dir,
            dead_pid_enoent = dead_pid_enoent
        );
    }
}
