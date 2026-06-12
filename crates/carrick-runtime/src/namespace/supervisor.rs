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
//!   to the ns-init. The supervisor watches every member for exit through the
//!   platform [`EventMultiplexer`](carrick_hal::event::EventMultiplexer)
//!   (kqueue `EVFILT_PROC`/`NOTE_EXIT` on macOS, a real pidfd on Linux); when a
//!   parent dies it flags the surviving children `MEMBER_ORPHANED` so their
//!   `getppid()` reports ns-pid 1.
//! - **Exit-status harvest** (§3.4): on a member's exit it stores the harvested
//!   exit code (the multiplexer's [`PollEvent::exit_status`], a bare
//!   WEXITSTATUS / 128+signal code) so the ns-init can reap orphaned
//!   grandchildren even after launchd took the host zombie.
//! - **Teardown** (§5.4): when the guest-init (its direct child) exits, it
//!   `killpg`s the namespace process group and sweeps the member table to
//!   SIGKILL any escapee, then exits with the init's status — which propagates
//!   up to `carrick` (or, for `run -d`, is recorded in the state registry).

use std::sync::atomic::Ordering;
use std::time::Duration;

use carrick_hal::event::{EventMultiplexer, Interest, PollEvent, TriggerMode};

use super::pid::{self, HOST_PID_REGISTERING, MEMBER_DEAD};

/// Reserved [`PollEvent::token`] for the member-registration pipe's read
/// readiness. Host pids (used as member/init tokens) are positive and far below
/// this sentinel, so there is no collision.
const REG_PIPE_TOKEN: u64 = u64::MAX;
/// Reserved [`PollEvent::token`] for the guest-init's exit watch. Distinct from
/// the per-member tokens (host pids) so the loop can route the init's death to
/// the `waitpid` harvest (which also reaps it) rather than the member path.
const INIT_TOKEN: u64 = u64::MAX - 1;

/// Token for a member's exit watch: its host pid. A member-exit `PollEvent`
/// carries the dead member's host pid in `token`, which the harvest needs to
/// locate the slot and flag its surviving children.
fn member_token(host_pid: i32) -> u64 {
    host_pid as u32 as u64
}

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
    let mut mux = match crate::event_mux::make_event_multiplexer() {
        Ok(mux) => mux,
        Err(_) => {
            // Without a multiplexer we can't watch members; fall back to a plain
            // waitpid on the init so teardown + status propagation still work
            // (orphan reaping degrades, but the container still runs/exits).
            return SupervisorExit {
                init_status: wait_init_blocking(init_host_pid),
            };
        }
    };

    // Watch the registration pipe for new members, and arm an exit watch on the
    // init itself (so its death wakes the loop just like any other member).
    let _ = mux.register_io(
        reg_pipe_read,
        REG_PIPE_TOKEN,
        Interest::READ,
        TriggerMode::Level,
    );
    let _ = mux.watch_process_exit(init_host_pid, INIT_TOKEN);

    // Track which host pid each slot is armed for. Slots are reused after a
    // terminal wait reaps a child, so a plain per-slot boolean would skip the
    // replacement member and miss its exit.
    let mut watched = vec![0u32; pid::MEMBER_SLOTS];
    arm_member_watches(mux.as_mut(), &mut watched);

    let mut events: Vec<PollEvent> = Vec::new();
    // 1s periodic rescan as a fallback when a registration-pipe write was lost
    // (pipe full) or a watch arm raced a death (§3.5).
    let timeout = Duration::from_secs(1);

    loop {
        // Reap the init non-blockingly first: if it already exited (its exit
        // event may have fired below, or it raced ahead), tear down.
        if let Some(status) = try_reap_init(init_host_pid) {
            teardown(init_host_pid);
            return SupervisorExit {
                init_status: status,
            };
        }

        if mux.wait(&mut events, Some(timeout)).is_err() {
            // Transient multiplexer error — re-check the init and retry.
            continue;
        }

        let mut drained_pipe = false;
        for ev in &events {
            match ev.token {
                INIT_TOKEN => {
                    // The ns-init exited. Do NOT trust the event's exit_status as
                    // the propagated status: the init is our direct child, so
                    // harvest the authoritative status with `waitpid` (which also
                    // reaps it). This deliberately keeps the historical
                    // init-via-waitpid semantics rather than the kqueue/pidfd
                    // exit code (§3.4).
                    let init_status = try_reap_init(init_host_pid)
                        .unwrap_or_else(|| wait_init_blocking(init_host_pid));
                    teardown(init_host_pid);
                    return SupervisorExit { init_status };
                }
                REG_PIPE_TOKEN => {
                    // Read readiness on the registration pipe: a new member
                    // registered.
                    drained_pipe = true;
                }
                token => {
                    // A watched member exited. The token is its host pid; the
                    // harvested exit code rides in `PollEvent.exit_status` (a bare
                    // WEXITSTATUS / 128+signal code). `exit_status` can be absent
                    // if the watch resolved via an error/already-gone path — fall
                    // back to 0 (the member is dead either way; the wake is what
                    // drives orphan-reparenting).
                    let dead = token as u32;
                    let status = ev.exit_status.unwrap_or(0);
                    handle_member_death(dead, status);
                }
            }
        }
        if drained_pipe {
            drain_pipe(reg_pipe_read);
        }
        // On any wake (pipe, member death, or timeout) re-arm watches for any
        // members that appeared since the last scan.
        arm_member_watches(mux.as_mut(), &mut watched);
    }
}

/// Arm an exit watch for every registered member we haven't watched yet. If a
/// member already exited, the multiplexer either fires immediately or errors
/// (the pid is gone) — both are handled by the loop (the immediate event marks
/// it dead; a missed one is caught by the periodic rescan).
fn arm_member_watches(mux: &mut dyn EventMultiplexer, watched: &mut [u32]) {
    let Some(region) = pid::region() else { return };
    for (i, slot) in region.members().iter().enumerate() {
        let host = slot.host_pid.load(Ordering::Acquire);
        if host == 0 || host == HOST_PID_REGISTERING {
            watched[i] = 0;
            continue;
        }
        if watched[i] == host {
            continue;
        }
        // Arm the watch; ignore an error (already gone — the rescan / immediate
        // fire covers it).
        let _ = mux.watch_process_exit(host as i32, member_token(host as i32));
        watched[i] = host;
    }
}

/// A member died: record its harvested exit code and flag its surviving children
/// as orphaned so their next `getppid()` returns ns-pid 1 (§3.6).
fn handle_member_death(dead_host_pid: u32, exit_code: i32) {
    let Some(region) = pid::region() else { return };
    region.mark_children_orphaned(dead_host_pid);
    region.mark_dead(dead_host_pid, exit_code);
}

/// Tear the namespace down after the init exits (§5.4): kill the whole process
/// group (fast path) then sweep the member table to SIGKILL any escapee that
/// left the group via setpgid/setsid. Idempotent and best-effort — a member
/// that already exited just yields ESRCH.
fn teardown(init_host_pid: i32) {
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
            if host == 0 || host == HOST_PID_REGISTERING || host as i32 == init_host_pid {
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

/// Blocking reap of the init — the degraded path when no multiplexer is
/// available.
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
    use super::{handle_member_death, member_token, status_to_exit_code};
    use carrick_hal::event::PollEvent;
    use std::time::Duration;

    /// A namespace member (a process the supervisor CANNOT waitpid — it's
    /// reparented to launchd) exits 42. The supervisor recovers the status from
    /// the multiplexer's `PollEvent.exit_status` (the bare exit code the macOS
    /// kqueue backend decodes from `NOTE_EXITSTATUS`, the Linux backend peeks
    /// from the pidfd). This guards that the member-exit harvest path reads the
    /// exit code from the `PollEvent`, not a stale 0.
    #[test]
    fn member_exit_status_harvested_from_poll_event() {
        // SAFETY: fork in a test; the child only calls nanosleep + `_exit`, both
        // async-signal-safe. The short sleep lets the parent arm the exit watch
        // while the child is still alive (arming on an already-dead zombie races
        // to ESRCH and never fires the status-carrying event).
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
        let mut mux = crate::event_mux::make_event_multiplexer().expect("multiplexer");
        mux.watch_process_exit(child, member_token(child))
            .expect("watch_process_exit");
        let mut events: Vec<PollEvent> = Vec::new();
        let mut harvested = None;
        // The exit fires after ~200ms; poll a few 1s windows so a spurious early
        // wake (none expected here) doesn't end the loop before the exit lands.
        for _ in 0..5 {
            let _ = mux.wait(&mut events, Some(Duration::from_secs(1)));
            for ev in &events {
                if ev.token == member_token(child) {
                    harvested = Some(ev.exit_status);
                }
            }
            if harvested.is_some() {
                break;
            }
        }
        // Reap our zombie (in the real supervisor flow launchd does this).
        let mut st = 0;
        unsafe { libc::waitpid(child, &mut st, 0) };
        let exit_status = harvested.expect("no exit event for the child");
        // `PollEvent.exit_status` is the BARE exit code on both backends.
        assert_eq!(
            exit_status,
            Some(42),
            "harvested exit_status was {exit_status:?}"
        );
    }

    /// `status_to_exit_code` still maps a `waitpid` status word for the
    /// init-propagation path (which deliberately keeps using `waitpid`).
    #[test]
    fn status_to_exit_code_maps_clean_exit() {
        // 0x2a00 is the `waitpid` status word for a clean exit(42).
        assert_eq!(status_to_exit_code(42 << 8), 42);
    }

    /// `handle_member_death` records the harvested bare exit code in the member
    /// slot (smoke: it must not panic when no shared region is mapped, the test
    /// process's normal state).
    #[test]
    fn handle_member_death_is_safe_without_region() {
        handle_member_death(999_999, 42);
    }
}
