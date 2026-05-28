//! `kill(2)` permission check: a non-root caller cannot signal a target
//! process owned by a different euid; the kernel returns EPERM. carrick
//! has to enforce this across host processes (each guest is a separate
//! host process) — without it, LTP `kill05` TFAILs with "kill succeeded
//! unexpectedly". The fix routes the check through a small per-process
//! cred-IPC file (`/tmp/carrick-cred-<host_pid>`).
//!
//! Invariants encoded:
//!   1. Same-euid kill is allowed (rc=0).
//!   2. Cross-euid non-root kill is rejected (-1/EPERM).
//!   3. Root (euid=0) can signal anyone (rc=0).
//!
//! The probe forks helper children that setreuid into specific uids then
//! pause; the parent then issues the corresponding `kill()` calls. Each
//! helper exits when signalled (or on its own bounded deadline so a
//! broken probe doesn't leak processes).

use conformance_probes::{errno, report};
use std::time::{Duration, Instant};

/// Linux UIDs commonly present in the LTP / ubuntu:24.04 image.
const ROOT_UID: u32 = 0;
const BIN_UID: u32 = 2;
const NOBODY_UID: u32 = 65534;

unsafe fn spawn_as(uid: u32) -> i32 {
    let pid = libc::fork();
    if pid == 0 {
        let _ = libc::setreuid(uid, uid);
        // Briefly hold so the parent can issue its kill before we exit.
        // Bounded so a buggy probe doesn't leak children.
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if Instant::now() >= deadline {
                libc::_exit(0);
            }
            libc::usleep(20_000);
        }
    }
    pid
}

fn main() {
    unsafe {
        // (3) Root → anyone allowed. We start as root (carrick guest
        //     defaults to uid 0).
        let target = spawn_as(BIN_UID);
        // Give the child a moment to setreuid and publish its cred.
        libc::usleep(60_000);
        let rc_root = libc::kill(target, 0); // null signal, just permission probe
        report!(root_to_other_uid_allowed = rc_root == 0);
        libc::kill(target, libc::SIGTERM);
        let mut s = 0i32;
        libc::waitpid(target, &mut s, 0);

        // (2) Become non-root, then try to kill a target with a DIFFERENT euid.
        let target = spawn_as(BIN_UID);
        libc::usleep(60_000);
        let _ = libc::setreuid(NOBODY_UID, NOBODY_UID);
        // Republish our own cred so the target's reverse check (not used
        // here) would see it too; the publish happens inside the setreuid
        // dispatcher anyway.
        let rc_cross = libc::kill(target, 0);
        let cross_errno = if rc_cross < 0 { errno() } else { 0 };
        report!(
            cross_uid_nonroot_kill_rc_neg_one = rc_cross == -1,
            cross_uid_nonroot_kill_errno_eperm = cross_errno == libc::EPERM,
        );
        // Become root again to reap (parents need to be able to wait for
        // their children regardless of euid in Linux).
        let _ = libc::setreuid(ROOT_UID, ROOT_UID);
        libc::kill(target, libc::SIGTERM);
        let mut s = 0i32;
        libc::waitpid(target, &mut s, 0);

        // (1) Same-euid kill is allowed: drop to a uid, fork a child with
        //     the same uid, and verify the kill goes through.
        let _ = libc::setreuid(NOBODY_UID, NOBODY_UID);
        let target = spawn_as(NOBODY_UID);
        libc::usleep(60_000);
        let rc_same = libc::kill(target, 0);
        report!(same_uid_nonroot_kill_allowed = rc_same == 0);
        libc::kill(target, libc::SIGTERM);
        let mut s = 0i32;
        libc::waitpid(target, &mut s, 0);
    }
}
