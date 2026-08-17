//! Cross-process isolation of the capability bounding set.
//!
//! `capabilities(7)`: the bounding set is a **per-process** attribute. A
//! `PR_CAPBSET_DROP` performed by one process is irreversible *for that
//! process and its future descendants*, and is invisible to every other
//! process — including a sibling forked before the drop and the parent that
//! forked the dropper. A `fork` child starts from a copy of the parent's set;
//! a later divergence in the child does not propagate back up.
//!
//! This probe encodes exactly that. It is a CROSS-PROCESS claim, so it needs
//! three live Linux processes: a parent, a dropper (A) and a bystander (B)
//! that was forked BEFORE A dropped and is still alive after.
//!
//!   parent forks B (B parks on a pipe read)
//!   parent forks A -> A drops CAP_NET_RAW + CAP_SYS_CHROOT, reports, exits
//!   parent reaps A, then re-reads its OWN bounding set  (must be unchanged)
//!   parent releases B; B reads its OWN bounding set     (must be unchanged)
//!   parent forks C after the drop; C inherits the parent's set (unchanged)
//!
//! Under a runtime that keeps the bounding set in one process-global cell
//! shared by every guest process, A's drop is observed by the parent, by B and
//! by C, and all three of those lines flip to 0.
//!
//! Only capabilities present in the default container set are dropped, so the
//! drop itself succeeds under `docker run` as well as under carrick.
//! `CAP_SYS_ADMIN` is included purely as a not-held control.

use conformance_probes::{errno, pipe2};

const PR_CAPBSET_READ: libc::c_int = 23;
const PR_CAPBSET_DROP: libc::c_int = 24;

/// Capabilities in the Docker default set (`CapBnd 00000000a80425fb`), so a
/// drop is permitted on both sides of the diff.
const CAP_CHOWN: u32 = 0;
const CAP_KILL: u32 = 5;
const CAP_SETPCAP: u32 = 8;
const CAP_NET_RAW: u32 = 13;
const CAP_SYS_CHROOT: u32 = 18;
/// NOT in the default container set — the control that must read 0 everywhere.
const CAP_SYS_ADMIN: u32 = 21;

/// The caps process A drops. Both are in the default set, so "held before,
/// not held after" is a real transition rather than a no-op.
const DROPPED: [u32; 2] = [CAP_NET_RAW, CAP_SYS_CHROOT];
/// The caps every process reports, in a fixed order.
const WATCHED: [(&str, u32); 6] = [
    ("chown", CAP_CHOWN),
    ("kill", CAP_KILL),
    ("setpcap", CAP_SETPCAP),
    ("net_raw", CAP_NET_RAW),
    ("sys_chroot", CAP_SYS_CHROOT),
    ("sys_admin", CAP_SYS_ADMIN),
];

fn capbset_read(cap: u32) -> i32 {
    let rc = unsafe { libc::prctl(PR_CAPBSET_READ, cap as libc::c_ulong, 0, 0, 0) };
    if rc < 0 { -errno() } else { rc }
}

fn capbset_drop(cap: u32) -> i32 {
    let rc = unsafe { libc::prctl(PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
    if rc < 0 { -errno() } else { rc }
}

/// Print one `<who>_capbset_<name>=<0|1|-errno>` line per watched capability.
fn report_capbset(who: &str) {
    for (name, cap) in WATCHED {
        println!("{who}_capbset_{name}={}", capbset_read(cap));
    }
}

/// The `CapBnd:` line of `/proc/self/status`, without the tab/label, or
/// `"unreadable"`. This is the second, independent window onto the same
/// per-process attribute — a runtime can get `prctl` right and still synthesise
/// `/proc` from a global, so both are diffed.
fn proc_capbnd() -> String {
    let Ok(text) = std::fs::read_to_string("/proc/self/status") else {
        return "unreadable".to_string();
    };
    text.lines()
        .find_map(|line| line.strip_prefix("CapBnd:"))
        .map_or_else(|| "absent".to_string(), |v| v.trim().to_string())
}

fn read_byte(fd: i32) -> bool {
    let mut b = 0u8;
    loop {
        let rc = unsafe { libc::read(fd, std::ptr::from_mut(&mut b).cast(), 1) };
        if rc == 1 {
            return true;
        }
        if rc < 0 && errno() == libc::EINTR {
            continue;
        }
        return false;
    }
}

fn write_byte(fd: i32) {
    loop {
        let b = 1u8;
        let rc = unsafe { libc::write(fd, std::ptr::from_ref(&b).cast(), 1) };
        if rc < 0 && errno() == libc::EINTR {
            continue;
        }
        return;
    }
}

/// Reap `pid`, returning its exit status or `-1`.
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
    // Baseline: the parent's own set before anything happens. Identical under
    // carrick and docker only if carrick models the default container set.
    report_capbset("parent_before");
    println!("parent_before_status_capbnd={}", proc_capbnd());

    // --- B: forked BEFORE the drop, alive across it. ------------------------
    let (b_go_r, b_go_w) = pipe2();
    let (b_done_r, b_done_w) = pipe2();
    let b_pid = unsafe { libc::fork() };
    if b_pid == 0 {
        unsafe {
            libc::close(b_go_w);
            libc::close(b_done_r);
        }
        // Park until the parent has reaped A, so B's observation is strictly
        // after A's drop and the output order is deterministic.
        if !read_byte(b_go_r) {
            std::process::exit(9);
        }
        report_capbset("bystander_after_sibling_drop");
        println!(
            "bystander_after_sibling_drop_status_capbnd={}",
            proc_capbnd()
        );
        write_byte(b_done_w);
        std::process::exit(0);
    }
    unsafe {
        libc::close(b_go_r);
        libc::close(b_done_w);
    }

    // --- A: the dropper. ----------------------------------------------------
    let a_pid = unsafe { libc::fork() };
    if a_pid == 0 {
        // A inherits the parent's set at fork.
        report_capbset("dropper_before");
        for cap in DROPPED {
            println!("dropper_drop_rc_{cap}={}", capbset_drop(cap));
        }
        report_capbset("dropper_after");
        println!("dropper_after_status_capbnd={}", proc_capbnd());
        std::process::exit(0);
    }
    println!("dropper_exit={}", wait_exit(a_pid));

    // --- The three assertions. ----------------------------------------------
    // 1. The parent that forked the dropper is untouched.
    report_capbset("parent_after");
    println!("parent_after_status_capbnd={}", proc_capbnd());

    // 2. A live sibling forked before the drop is untouched.
    write_byte(b_go_w);
    let _ = read_byte(b_done_r);
    println!("bystander_exit={}", wait_exit(b_pid));

    // 3. A child forked AFTER the drop inherits the parent's set, which never
    //    lost anything — a drop in a dead unrelated process is not inherited.
    let c_pid = unsafe { libc::fork() };
    if c_pid == 0 {
        report_capbset("later_child");
        println!("later_child_status_capbnd={}", proc_capbnd());
        std::process::exit(0);
    }
    println!("later_child_exit={}", wait_exit(c_pid));
}
