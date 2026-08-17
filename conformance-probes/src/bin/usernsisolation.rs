//! Cross-process isolation of the user-namespace view.
//!
//! `user_namespaces(7)`: `unshare(CLONE_NEWUSER)` moves ONLY the calling
//! process into a fresh user namespace, and `/proc/self/uid_map` names the
//! reader's own namespace. A child that unshares and writes its maps therefore
//! changes nothing about the parent, which goes on reading the identity map of
//! the namespace it never left.
//!
//!   parent reports its own uid_map/gid_map/setgroups
//!   child unshares CLONE_NEWUSER, writes a uid_map, reports its own
//!   parent re-reports its own          (must be byte-identical to before)
//!
//! Under a runtime that keeps the user namespace in one process-global cell
//! shared by every guest process, the child's unshare re-points the parent too
//! and the child's map write appears in the parent's `/proc/self/uid_map`.
//!
//! The unshare `rc` is reported rather than asserted: an environment that
//! forbids unprivileged userns creation returns EPERM on BOTH sides of the
//! diff, so the probe stays line-exact and simply records that outcome.

use conformance_probes::errno;

/// Read a `/proc/self` file with whitespace collapsed to single spaces, so the
/// diff is about CONTENT and not about a kernel's column padding.
fn proc_field(name: &str) -> String {
    match std::fs::read_to_string(format!("/proc/self/{name}")) {
        Ok(text) => {
            let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
            if joined.is_empty() {
                "empty".to_string()
            } else {
                joined
            }
        }
        Err(e) => format!("err={}", e.raw_os_error().unwrap_or(-1)),
    }
}

fn report(who: &str) {
    for name in ["uid_map", "gid_map", "setgroups"] {
        println!("{who}_{name}={}", proc_field(name));
    }
}

fn wait_exit(pid: libc::pid_t) -> i32 {
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            };
        }
        if rc < 0 && errno() == libc::EINTR {
            continue;
        }
        return -1;
    }
}

fn main() {
    report("parent_before");

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        let rc = if rc < 0 { -errno() } else { rc };
        println!("child_unshare_newuser_rc={rc}");
        if rc == 0 {
            // In a fresh namespace the maps start EMPTY and are write-once.
            report("child_after_unshare");
            // A single-line identity map for uid 0 is what a container init
            // writes; the write must be visible to this process only.
            let wrote = std::fs::write("/proc/self/uid_map", "0 0 1\n");
            println!(
                "child_uid_map_write_rc={}",
                wrote.map_or_else(|e| -e.raw_os_error().unwrap_or(-1), |()| 0)
            );
            report("child_after_write");
        }
        std::process::exit(0);
    }
    println!("child_exit={}", wait_exit(pid));

    // THE ASSERTION: the parent never left its namespace, so every field must
    // be byte-identical to the `parent_before` block above.
    report("parent_after");
}
