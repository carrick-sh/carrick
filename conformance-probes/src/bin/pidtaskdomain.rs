//! One pid domain: every guest-visible rendering of a process's identity
//! names the same number.
//!
//! Carrick's kernel graph allocates task ids, and a separate per-namespace
//! counter used to hand out the pid `getpid(2)` reported. The two drifted
//! whenever a fork retried after a dropped reservation (a task id is burnt,
//! the counter is not), so a child could be task 4 to `/proc` while
//! `getpid()` said 3: `access("/proc/3/oom_score_adj")` was ENOENT, `ls /proc`
//! listed a pid no process answered to, and LTP's `tst_test` setup TBROKed in
//! `tst_enable_oom_protection` for any case run as a non-exec'd child. The
//! drift needed an exited sibling still retiring when the next fork ran, so
//! this probe forks and reaps in a tight loop and checks EVERY child.
//!
//! Invariants encoded (each becomes one report! line, aggregated over all
//! rounds so no pid is ever printed):
//!   * the fork return value in the parent equals the child's `getpid()`
//!   * `gettid()` equals `getpid()` in a single-threaded child
//!   * `getppid()` in the child equals the parent's `getpid()`
//!   * `readlink("/proc/self")` names `getpid()`
//!   * `/proc/<getpid()>` is a directory and `/proc/<getpid()>/oom_score_adj`
//!     passes `access(2)` (the exact LTP setup call)
//!   * `/proc/<getpid()>/status` reports `Pid:`/`Tgid:`/`PPid:` matching
//!   * `readdir("/proc")` lists `getpid()` and `getppid()`
//!
//! Deterministic output only — booleans, never times/PIDs/addresses.
//! Harness diffs stdout byte-for-byte against the Linux oracle.

use conformance_probes::{errno, pipe2, reap, report};

const ROUNDS: usize = 40;

/// Bits the child reports back through the pipe; a set bit is a FAILURE.
const F_TID: u8 = 1 << 0;
const F_PPID: u8 = 1 << 1;
const F_SELF_LINK: u8 = 1 << 2;
const F_DIR: u8 = 1 << 3;
const F_OOM_ACCESS: u8 = 1 << 4;
const F_STATUS: u8 = 1 << 5;
const F_LISTED: u8 = 1 << 6;

fn status_field(status: &str, key: &str) -> i64 {
    status
        .lines()
        .find_map(|l| {
            l.strip_prefix(key)
                .map(|v| v.trim().parse::<i64>().unwrap_or(-1))
        })
        .unwrap_or(-2)
}

fn proc_lists(pid: i64) -> bool {
    std::fs::read_dir("/proc")
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy() == pid.to_string())
        })
        .unwrap_or(false)
}

fn access_ok(path: &str) -> bool {
    let c = std::ffi::CString::new(path).expect("probe path has no interior NUL");
    unsafe { libc::access(c.as_ptr(), libc::F_OK) == 0 }
}

unsafe fn child_failures(parent_pid: i64) -> u8 {
    let pid = i64::from(libc::getpid());
    let tid = libc::syscall(libc::SYS_gettid);
    let ppid = i64::from(libc::getppid());
    let mut failures = 0u8;
    if tid != pid {
        failures |= F_TID;
    }
    if ppid != parent_pid {
        failures |= F_PPID;
    }
    let self_link = std::fs::read_link("/proc/self")
        .ok()
        .and_then(|p| p.to_str().and_then(|s| s.parse::<i64>().ok()));
    if self_link != Some(pid) {
        failures |= F_SELF_LINK;
    }
    let dir = format!("/proc/{pid}");
    if !std::fs::metadata(&dir).map(|m| m.is_dir()).unwrap_or(false) {
        failures |= F_DIR;
    }
    if !access_ok(&format!("{dir}/oom_score_adj")) {
        failures |= F_OOM_ACCESS;
    }
    let status = std::fs::read_to_string(format!("{dir}/status")).unwrap_or_default();
    if status_field(&status, "Pid:") != pid
        || status_field(&status, "Tgid:") != pid
        || status_field(&status, "PPid:") != parent_pid
    {
        failures |= F_STATUS;
    }
    if !proc_lists(pid) || !proc_lists(parent_pid) {
        failures |= F_LISTED;
    }
    failures
}

fn main() {
    unsafe {
        let parent_pid = i64::from(libc::getpid());
        let parent_self_link = std::fs::read_link("/proc/self")
            .ok()
            .and_then(|p| p.to_str().and_then(|s| s.parse::<i64>().ok()))
            == Some(parent_pid);

        let mut rounds_run = 0usize;
        let mut fork_rc_eq_child_getpid = true;
        let mut child_reported = true;
        let mut child_exit_clean = true;
        let mut failures = 0u8;
        for _ in 0..ROUNDS {
            let (rd, wr) = pipe2();
            let pid = libc::fork();
            if pid < 0 {
                panic!("fork() failed: errno={}", errno());
            }
            if pid == 0 {
                libc::close(rd);
                let mine = libc::getpid();
                let report = [
                    mine.to_ne_bytes()[0],
                    mine.to_ne_bytes()[1],
                    mine.to_ne_bytes()[2],
                    mine.to_ne_bytes()[3],
                    child_failures(parent_pid),
                ];
                let mut written = 0usize;
                while written < report.len() {
                    let n = libc::write(
                        wr,
                        report[written..].as_ptr().cast(),
                        report.len() - written,
                    );
                    if n > 0 {
                        written += n as usize;
                    } else if errno() != libc::EINTR {
                        break;
                    }
                }
                libc::_exit(0);
            }
            libc::close(wr);
            let mut buf = [0u8; 5];
            let mut got = 0usize;
            while got < buf.len() {
                let n = libc::read(rd, buf[got..].as_mut_ptr().cast(), buf.len() - got);
                if n > 0 {
                    got += n as usize;
                } else if n == 0 || errno() != libc::EINTR {
                    break;
                }
            }
            libc::close(rd);
            let (rc, status) = reap(pid);
            rounds_run += 1;
            if got != buf.len() {
                child_reported = false;
                continue;
            }
            let child_pid = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
            if child_pid != pid {
                fork_rc_eq_child_getpid = false;
            }
            failures |= buf[4];
            if rc != pid || !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                child_exit_clean = false;
            }
        }

        report!(
            rounds_complete = rounds_run == ROUNDS,
            parent_proc_self_names_getpid = parent_self_link,
            every_child_reported = child_reported,
            every_child_exited_clean = child_exit_clean,
            fork_rc_eq_child_getpid = fork_rc_eq_child_getpid,
            child_gettid_eq_getpid = failures & F_TID == 0,
            child_getppid_eq_parent_getpid = failures & F_PPID == 0,
            child_proc_self_names_getpid = failures & F_SELF_LINK == 0,
            child_proc_pid_dir_exists = failures & F_DIR == 0,
            child_proc_pid_oom_score_adj_accessible = failures & F_OOM_ACCESS == 0,
            child_proc_pid_status_ids_match = failures & F_STATUS == 0,
            proc_lists_child_and_parent = failures & F_LISTED == 0,
        );
    }
}
