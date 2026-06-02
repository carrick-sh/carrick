//! The NsSupervisor — a per-container macOS process that orchestrates PID
//! namespace lifecycle in place of the Linux kernel (design §3).
//!
//! It is the **parent half of the runtime fork**: created fresh by each
//! `carrick run` that requests namespace placement, it runs no guest code (no
//! HVF VM, no vCPU) and never calls a Linux syscall. The **child** continues
//! into the HVF loop as the guest-init (ns-pid 1). This is NOT a shared daemon
//! — there is one supervisor per running container, exactly like the parent in
//! `interactive_supervisor.rs`. See [[carrick-no-daemon]].
//!
//! Responsibilities (all in userspace, because macOS has no namespaces):
//! - **Orphan reparenting** (§3.6): macOS reparents an orphan to launchd, not
//!   to the ns-init. The supervisor watches every member via
//!   `EVFILT_PROC`/`NOTE_EXIT`; when a parent dies it flags the surviving
//!   children `MEMBER_ORPHANED` so their `getppid()` reports ns-pid 1.
//! - **Exit-status harvest** (§3.4): on a member's `NOTE_EXIT` it stores the
//!   status (from the kqueue `data` field) so the ns-init can reap orphaned
//!   grandchildren even after launchd took the host zombie.
//! - **Teardown** (§5.4): when the guest-init (its direct child) exits, it
//!   `killpg`s the namespace process group and sweeps the member table to
//!   SIGKILL any escapee, then exits with the init's status — which propagates
//!   up to `carrick` (or, for `run -d`, is recorded in the state registry).

use std::sync::atomic::Ordering;

use crate::darwin_kqueue::{Kevent, Kqueue};

use super::pid::{self, MEMBER_DEAD};

/// Outcome of running the supervisor loop: the guest-init's `waitpid` status
/// (to be converted to an exit code and propagated up).
pub struct SupervisorExit {
    pub init_status: i32,
}

/// Run the NsSupervisor event loop until the guest-init (`init_host_pid`,
/// the supervisor's direct child) exits, then tear the namespace down and
/// return the init's status. `reg_pipe_read` is the read end of the
/// member-registration pipe (the write end is inherited by every guest member).
///
/// This function never returns to run guest code; the caller (the fork parent)
/// should `exit()` with the derived code afterwards.
pub fn run(init_host_pid: i32, reg_pipe_read: i32) -> SupervisorExit {
    let kq = match Kqueue::new_internal() {
        Some(kq) => kq,
        None => {
            // Without a kqueue we can't watch members; fall back to a plain
            // waitpid on the init so teardown + status propagation still work
            // (orphan reaping degrades, but the container still runs/exits).
            return SupervisorExit {
                init_status: wait_init_blocking(init_host_pid),
            };
        }
    };

    // Watch the registration pipe for new members, and arm an exit watch on the
    // init itself (so its death wakes the loop just like any other member).
    let _ = kq.apply(&[
        Kevent::read(reg_pipe_read, libc::EV_ADD),
        Kevent::proc_exit(init_host_pid),
    ]);

    // Track which members we've already armed a watch for (by slot index), so a
    // pipe wake / periodic rescan only arms new entries.
    let mut watched = vec![false; pid::MEMBER_SLOTS];
    arm_member_watches(&kq, &mut watched);

    let mut events = [Kevent::empty(); 8];
    // 1s periodic rescan as a fallback when a registration-pipe write was lost
    // (pipe full) or a watch arm raced a death (§3.5).
    let timeout = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };

    loop {
        // Reap the init non-blockingly first: if it already exited (its
        // NOTE_EXIT may have fired below, or it raced ahead), tear down.
        if let Some(status) = try_reap_init(init_host_pid) {
            teardown(&kq, init_host_pid);
            return SupervisorExit {
                init_status: status,
            };
        }

        let n = match kq.wait(&[], &mut events, Some(&timeout)) {
            Ok(n) => n,
            Err(_) => {
                // Transient kevent error — re-check the init and retry.
                continue;
            }
        };

        let mut drained_pipe = false;
        for ev in events.iter().take(n) {
            let ev = *ev;
            if let Some(dead) = ev.proc_exit_ident() {
                let status = ev.proc_exit_status();
                if dead == init_host_pid {
                    // The ns-init exited. Do NOT trust the kqueue `data` field as
                    // the exit status: the watch is armed with `NOTE_EXIT` (not
                    // `NOTE_EXITSTATUS`), so on macOS `data` reads back 0, not the
                    // wait-status. The init is our direct child, so harvest the
                    // authoritative status with `waitpid` (which also reaps it).
                    // Using the kqueue `data` here silently reported exit code 0
                    // for every container caught on this path (~half of runs).
                    let init_status = try_reap_init(init_host_pid)
                        .unwrap_or_else(|| wait_init_blocking(init_host_pid));
                    teardown(&kq, init_host_pid);
                    return SupervisorExit { init_status };
                }
                handle_member_death(dead as u32, status);
            } else {
                // EVFILT_READ on the registration pipe: a new member registered.
                drained_pipe = true;
            }
        }
        if drained_pipe {
            drain_pipe(reg_pipe_read);
        }
        // On any wake (pipe, member death, or timeout) re-arm watches for any
        // members that appeared since the last scan.
        arm_member_watches(&kq, &mut watched);
    }
}

/// Arm `EVFILT_PROC`/`NOTE_EXIT` for every registered member we haven't watched
/// yet. If a member already exited, `kevent` either fires immediately or errors
/// with ESRCH — both are handled by the loop (the immediate event marks it
/// dead; a missed one is caught by the periodic rescan).
fn arm_member_watches(kq: &Kqueue, watched: &mut [bool]) {
    let Some(region) = pid::region() else { return };
    for (i, slot) in region.members().iter().enumerate() {
        if watched[i] {
            continue;
        }
        let host = slot.host_pid.load(Ordering::Acquire);
        if host == 0 {
            continue;
        }
        // Arm the watch; ignore ESRCH (already gone — the rescan / immediate
        // fire covers it).
        let _ = kq.apply(&[Kevent::proc_exit(host as i32)]);
        watched[i] = true;
    }
}

/// A member died: record its exit status and flag its surviving children as
/// orphaned so their next `getppid()` returns ns-pid 1 (§3.6).
fn handle_member_death(dead_host_pid: u32, status: i32) {
    let Some(region) = pid::region() else { return };
    region.mark_children_orphaned(dead_host_pid);
    region.mark_dead(dead_host_pid, status);
}

/// Tear the namespace down after the init exits (§5.4): kill the whole process
/// group (fast path) then sweep the member table to SIGKILL any escapee that
/// left the group via setpgid/setsid. Idempotent and best-effort — a member
/// that already exited just yields ESRCH.
fn teardown(_kq: &Kqueue, init_host_pid: i32) {
    // Fast path: the container's processes overwhelmingly share the init's
    // process group, so one killpg reaches them. The init led its own group
    // (setsid in the detached/interactive paths) so its pgid == its pid.
    // SAFETY: killpg with SIGKILL; ESRCH if the group is already empty.
    unsafe {
        libc::killpg(init_host_pid, libc::SIGKILL);
    }
    // Sweep: SIGKILL every still-live member individually (escapees).
    if let Some(region) = pid::region() {
        for slot in region.members() {
            let host = slot.host_pid.load(Ordering::Acquire);
            if host == 0 || host as i32 == init_host_pid {
                continue;
            }
            if slot.flags.load(Ordering::Acquire) != MEMBER_DEAD {
                // SAFETY: kill with SIGKILL; ESRCH if already gone.
                unsafe {
                    libc::kill(host as i32, libc::SIGKILL);
                }
            }
        }
    }
}

/// Non-blocking reap of the init (the supervisor's direct child). Returns its
/// `waitpid` status if it has exited, else `None`.
fn try_reap_init(init_host_pid: i32) -> Option<i32> {
    let mut status: libc::c_int = 0;
    // SAFETY: standard waitpid on our direct child.
    let r = unsafe { libc::waitpid(init_host_pid, &mut status, libc::WNOHANG) };
    if r == init_host_pid {
        Some(status)
    } else {
        None
    }
}

/// Blocking reap of the init — the degraded path when no kqueue is available.
fn wait_init_blocking(init_host_pid: i32) -> i32 {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: standard blocking waitpid on our direct child.
        let r = unsafe { libc::waitpid(init_host_pid, &mut status, 0) };
        if r == init_host_pid {
            return status;
        }
        if r < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EINTR {
                continue;
            }
            return 0;
        }
    }
}

/// Drain any pending bytes from the registration pipe (one byte per new member;
/// the content is irrelevant — the wake is the signal, the member table is the
/// truth).
fn drain_pipe(fd: i32) {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: reading into a stack buffer from a non-blocking pipe fd.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
    }
}

/// Convert a `waitpid` status word to a process exit code (mirrors
/// `interactive_supervisor::wait_status_to_exit_code`): WEXITSTATUS for a clean
/// exit, 128+signal for a signal death, else 1.
pub fn status_to_exit_code(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::status_to_exit_code;
    use crate::darwin_kqueue::{Kevent, Kqueue};

    /// A namespace member (a process the supervisor CANNOT waitpid — it's
    /// reparented to launchd) exits 42. The supervisor recovers the status from
    /// the kqueue event's `data` field. This guards that `proc_exit` is armed
    /// with `NOTE_EXITSTATUS`: under plain `NOTE_EXIT` `data` is 0, which would
    /// make every reaped orphan report exit code 0.
    #[test]
    fn member_exit_status_harvested_from_kqueue_data() {
        // SAFETY: fork in a test; the child only calls nanosleep + `_exit`, both
        // async-signal-safe. The short sleep lets the parent arm the EVFILT_PROC
        // watch while the child is still alive (arming on an already-dead zombie
        // races to ESRCH and never fires).
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 200_000_000,
            };
            unsafe {
                libc::nanosleep(&ts, std::ptr::null_mut());
                libc::_exit(42);
            }
        }
        let kq = Kqueue::new_internal().expect("kqueue");
        let _ = kq.apply(&[Kevent::proc_exit(child)]);
        let mut events = [Kevent::empty(); 4];
        let timeout = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let n = kq.wait(&[], &mut events, Some(&timeout)).expect("kqueue wait");
        let mut harvested = None;
        for ev in events.iter().take(n) {
            if ev.proc_exit_ident() == Some(child) {
                harvested = Some(ev.proc_exit_status());
            }
        }
        // Reap our zombie (in the real supervisor flow launchd does this).
        let mut st = 0;
        unsafe { libc::waitpid(child, &mut st, 0) };
        let data = harvested.expect("no NOTE_EXIT event for the child");
        assert_eq!(status_to_exit_code(data), 42, "kqueue data was {data:#x}");
    }
}
