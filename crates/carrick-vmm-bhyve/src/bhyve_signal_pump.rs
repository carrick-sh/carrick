//! bhyve async host-signal pump — the FreeBSD mirror of
//! [`carrick_vmm_kvm::kvm_signal_pump`] (SP4.2). Catches host-delivered
//! PROCESS-directed signals (`SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT` — the ones a
//! supervisor or a tty sends, and which carrick NEVER injects into a guest
//! itself) and turns them into a guest-deliverable pending signal; ALSO runs the
//! SIGCHLD-driven child-exit reaper that publishes a forked child's exit signal
//! to its recorded parent tid.
//!
//! ## Why a pump at all
//!
//! Unlike a guest-issued `tgkill`/`raise` (serviced inline by the dispatcher), a
//! host signal arrives ASYNCHRONOUSLY on whatever host thread the kernel picks,
//! OUTSIDE the dispatcher, where the handler can do almost nothing safely. So:
//!   - the **handler** (async-signal-safe ONLY): atomically OR the signal's bit
//!     into `carrick_signal_core::PROC_PENDING` and `write()` one byte to a
//!     self-pipe. NOTHING else.
//!   - the **pump thread** (a normal daemon thread): blocks in `poll`/`read` on
//!     the self-pipe; on each wake drains the byte(s), reaps any exited child,
//!     then `registry.kick_all()` + `futex.notify_signal_pending()` so EVERY
//!     in-guest vCPU returns from `vm_run` and re-checks pending at its safe point.
//!
//! ## Translation
//!
//! On FreeBSD the host and guest (Linux) signal numbers DIFFER for several signals
//! (see [`crate::bhyve_signum`]). The pumped set (HUP/INT/QUIT/TERM = 1/2/3/15) is
//! numbered identically on both, but the handler still translates host->Linux when
//! computing the PROC_PENDING bit so the contract is explicit and a future addition
//! to the pumped set (e.g. a BSD-divergent number) stays correct.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use carrick_hal::{PlatformFutex, VcpuRegistry};

use crate::bhyve_signum::host_to_linux_signum;

/// Host signals carrick catches and forwards to the guest. These are
/// process-directed signals a supervisor/tty delivers; carrick itself never
/// injects them, so catching them here cannot collide with guest-routed delivery.
/// HUP/INT/QUIT/TERM are numbered identically on Linux and FreeBSD.
const PUMP_SIGNALS: [i32; 4] = [
    libc::SIGHUP,  // 1
    libc::SIGINT,  // 2
    libc::SIGQUIT, // 3
    libc::SIGTERM, // 15
];

/// The self-pipe WRITE fd the async handler pokes. `-1` until the pump installs
/// the pipe. Read with a plain `load` in the handler (async-signal-safe).
static SELF_PIPE_W: AtomicI32 = AtomicI32::new(-1);

/// The self-pipe READ fd the pump thread polls. Published so [`stop_pump_for_fork`]
/// can close it after joining the pump.
static SELF_PIPE_R: AtomicI32 = AtomicI32::new(-1);

/// Raised by [`stop_pump_for_fork`]; the pump thread checks it on every wake and
/// exits. Cleared again once the stop completes.
static PUMP_STOP: AtomicBool = AtomicBool::new(false);

/// The live pump thread's join handle, so [`stop_pump_for_fork`] can join it to a
/// full stop before `libc::fork`. A plain std Mutex: never touched from a signal
/// handler.
static PUMP_THREAD: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);

/// Async-signal-safe SIGCHLD handler. Unlike [`pump_handler`], it does NOT touch
/// `PROC_PENDING`: SIGCHLD here is NOT a guest-published process signal but the
/// host's native notification that a guest CHILD (a real host process — a guest
/// `fork` ran `libc::fork`) exited. Resolving WHICH watched child exited and
/// publishing the RECORDED exit signal to the RECORDED parent tid is the pump
/// thread's reaper job (`reap_exited_watches`), which needs `waitid` + locks and
/// must NOT run in an async handler. So the handler does ONLY `poke()`.
extern "C" fn sigchld_handler(_signum: libc::c_int) {
    poke();
}

/// Guards the one-time install of the separate SIGCHLD sigaction.
static SIGCHLD_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install the SIGCHLD disposition (idempotent), with `SA_RESTART | SA_NOCLDSTOP`
/// so a child STOP/CONTINUE does NOT fire SIGCHLD (only a terminal exit does) and
/// a blocking host `wait4`/`waitid` restarts across this handler's EINTR.
fn install_sigchld_handler() {
    if SIGCHLD_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = sigchld_handler as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART | libc::SA_NOCLDSTOP;
        libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut());
    }
}

/// Peek every currently-tracked guest child for a terminal exit and, on one,
/// publish its RECORDED exit signal to its RECORDED parent tid. Runs on the pump
/// THREAD (not the async handler), so `waitid` + the child-watch locks +
/// `publish_pending_for` are all safe here. Mirrors the KVM reaper: `WNOWAIT`
/// PEEKS the zombie WITHOUT reaping it, so the guest's own later `wait4` still
/// returns the child's status.
fn reap_exited_watches() {
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    for pid in carrick_signal_core::child_watch::tracked_pids() {
        if pid <= 0 {
            continue;
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        if rc != 0 {
            // ESRCH/ECHILD: not ours / already reaped — drop the stale watch so the
            // table does not grow unbounded. Any other errno: leave it to retry.
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::ECHILD) || errno == Some(libc::ESRCH) {
                let _ = carrick_signal_core::child_watch::take(pid);
            }
            continue;
        }
        // WNOHANG with no ready child returns 0 with si_pid == 0 (still running).
        // SAFETY: reads the POSIX-defined `si_pid` union member; libc marks the
        // accessor unsafe only because it reads a union.
        let si_pid = unsafe { info.si_pid() };
        if si_pid != pid || !matches!(info.si_code, CLD_EXITED | CLD_KILLED | CLD_DUMPED) {
            continue;
        }
        // Terminal exit observed. Atomically remove the watch (publish-once) and
        // publish the recorded exit signal to the recorded parent tid. If the guest
        // already reaped this child synchronously, the dispatcher's terminal-reap
        // cancel removed it first, so `take` returns None and we publish nothing.
        if let Some((parent_tid, exit_signal)) = carrick_signal_core::child_watch::take(pid)
            && exit_signal != 0
        {
            carrick_signal_core::child_watch::record_siginfo(
                parent_tid,
                exit_signal,
                carrick_signal_core::child_watch::ChildExitSiginfo {
                    si_code: info.si_code,
                    host_pid: si_pid,
                    // SAFETY: POSIX siginfo child-exit payload fields.
                    host_uid: unsafe { info.si_uid() },
                    // SAFETY: POSIX siginfo child-exit payload fields.
                    host_status: unsafe { info.si_status() },
                },
            );
            carrick_signal_core::publish_pending_for(parent_tid, exit_signal);
        }
    }
}

/// Async-signal-safe handler for the pumped host signals. Does ONLY:
///   1. `proc_pending_fetch_or(bit)` — a lock-free atomic OR into PROC_PENDING,
///      keyed on the GUEST (Linux) signum (host->Linux translated).
///   2. `write(SELF_PIPE_W, &[0u8], 1)` — wake the pump thread.
///
/// NO allocation, locks, or non-reentrant libc.
extern "C" fn pump_handler(host_signum: libc::c_int) {
    let linux_signum = host_to_linux_signum(host_signum);
    if let Some(bit) = carrick_signal_core::pending_bit(linux_signum) {
        carrick_signal_core::proc_pending_fetch_or(bit);
    }
    let w = SELF_PIPE_W.load(Ordering::Relaxed);
    if w >= 0 {
        let byte = [0u8; 1];
        // write(2) is async-signal-safe. Ignore the result: a full nonblocking
        // pipe already has a pending wake, and EINTR is harmless here.
        unsafe {
            libc::write(w, byte.as_ptr() as *const libc::c_void, 1);
        }
    }
}

/// Wake the pump thread from another async-signal-safe context (the xsignal nudge
/// handler — see [`crate::bhyve_xsig`]). Reads the published self-pipe write fd
/// with a relaxed atomic load and, if live, `write(2)`s one byte. Async-signal-safe.
pub fn poke() {
    let w = SELF_PIPE_W.load(Ordering::Relaxed);
    if w >= 0 {
        let byte = [0u8; 1];
        // SAFETY: write(2) is async-signal-safe; `w` is a live pipe write fd.
        unsafe {
            libc::write(w, byte.as_ptr() as *const libc::c_void, 1);
        }
    }
}

/// Install the `sigaction` disposition for every pumped signal (with `SA_RESTART`)
/// plus the separate SIGCHLD reaper disposition. Idempotent.
fn install_handlers() {
    for &sig in &PUMP_SIGNALS {
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = pump_handler as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = libc::SA_RESTART;
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
    // SIGCHLD gets its OWN (separate) disposition: it must NOT fan out into
    // PROC_PENDING like the PUMP_SIGNALS — it triggers the child-exit reaper.
    install_sigchld_handler();
}

/// Create the nonblocking, close-on-exec self-pipe and publish its write end.
/// Returns the READ fd for the pump thread to poll, or `-1` on failure.
fn make_self_pipe() -> i32 {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if rc != 0 {
        return -1;
    }
    SELF_PIPE_W.store(fds[1], Ordering::SeqCst);
    SELF_PIPE_R.store(fds[0], Ordering::SeqCst);
    fds[0]
}

/// Spawn the pump daemon thread: block in `poll` on `read_fd`, drain on wake, reap
/// any exited child, then kick every vCPU + nudge the futex.
fn spawn_pump_thread(read_fd: i32, registry: Arc<dyn VcpuRegistry>, futex: Arc<dyn PlatformFutex>) {
    let handle = std::thread::Builder::new()
        .name("carrick-vmm-bhyve-sig-pump".to_string())
        .spawn(move || {
            let mut pfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let mut drain = [0u8; 64];
            loop {
                if PUMP_STOP.load(Ordering::SeqCst) {
                    return;
                }
                let n = unsafe { libc::poll(&mut pfd, 1, -1) };
                if PUMP_STOP.load(Ordering::SeqCst) {
                    return;
                }
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    // Unexpected poll error: the pipe is unusable. Stop the pump;
                    // PROC_PENDING is still set by the handler, so a later kick
                    // still delivers — only host-only-signal latency degrades.
                    return;
                }
                // Drain everything the handler wrote (coalesced wakes are fine).
                loop {
                    let r = unsafe {
                        libc::read(
                            read_fd,
                            drain.as_mut_ptr() as *mut libc::c_void,
                            drain.len(),
                        )
                    };
                    if r <= 0 {
                        break;
                    }
                    if (r as usize) < drain.len() {
                        break;
                    }
                }
                // Resolve any watched guest child that EXITED before kicking, so the
                // published thread-pending signal is visible when the woken parent
                // vCPU reaches its delivery point.
                reap_exited_watches();
                // Wake every in-guest vCPU so it returns from vm_run and the generic
                // loop drains PROC_PENDING (and any just-published child-exit signal)
                // at its safe point.
                registry.kick_all();
                futex.notify_signal_pending();
            }
        });
    if let Ok(h) = handle {
        *PUMP_THREAD.lock().unwrap_or_else(|e| e.into_inner()) = Some(h);
    }
}

/// Stop + JOIN the pump thread before `libc::fork`. The pump takes process-global
/// locks on every wake; a `libc::fork` landing while one is held hands the CHILD a
/// mutex locked by a thread that does not exist in it — a permanent child deadlock.
/// Returns whether a pump thread was actually running (the caller's restart token).
pub fn stop_pump_for_fork() -> bool {
    let handle = PUMP_THREAD.lock().unwrap_or_else(|e| e.into_inner()).take();
    let Some(handle) = handle else {
        return false;
    };
    PUMP_STOP.store(true, Ordering::SeqCst);
    // Wake the pump out of its poll. If the nonblocking pipe is full, POLLIN is
    // already pending — the pump wakes either way and sees the stop flag.
    poke();
    let _ = handle.join();
    // Tear the pipe down (the restart makes a fresh one) and clear the guards so a
    // post-fork `start_pump` re-arms instead of no-opping.
    let w = SELF_PIPE_W.swap(-1, Ordering::SeqCst);
    if w >= 0 {
        unsafe {
            libc::close(w);
        }
    }
    let r = SELF_PIPE_R.swap(-1, Ordering::SeqCst);
    if r >= 0 {
        unsafe {
            libc::close(r);
        }
    }
    PUMP_STOP.store(false, Ordering::SeqCst);
    PUMP_STARTED.store(false, Ordering::SeqCst);
    true
}

/// Guards the one-time install of the sigactions + self-pipe + pump thread.
static PUMP_STARTED: AtomicBool = AtomicBool::new(false);

/// Start the async host-signal pump (idempotent). Installs the sigactions, makes
/// the self-pipe, and spawns ONE daemon thread. A second call is a no-op.
pub fn start_pump(registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
    // Always (re-)assert the dispositions: cheap, idempotent.
    install_handlers();
    if PUMP_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return; // already running
    }
    let read_fd = make_self_pipe();
    if read_fd < 0 {
        return; // pipe failed; handlers still set PROC_PENDING (kick-delivered)
    }
    spawn_pump_thread(read_fd, Arc::clone(registry), Arc::clone(futex));
    // Kick-start one pump pass: a SIGCHLD that landed while the pump was stopped
    // across a fork only set a zombie to reap — there is no byte in the NEW pipe to
    // wake the fresh thread. One unconditional poke makes the first pass run
    // reap_exited_watches + kick_all immediately; harmless when idle.
    poke();
}

/// Re-arm the pump in a freshly forked CHILD. The child inherited the parent's
/// `PUMP_STARTED == true` and pipe fds but NOT the parent's pump thread (only the
/// forking thread survives `libc::fork`). Reset the guard + published write fd,
/// then `start_pump` again so the child gets its own self-pipe + pump thread.
pub fn reinit_after_fork(registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
    let stale_w = SELF_PIPE_W.swap(-1, Ordering::SeqCst);
    if stale_w >= 0 {
        unsafe {
            libc::close(stale_w);
        }
    }
    let stale_r = SELF_PIPE_R.swap(-1, Ordering::SeqCst);
    if stale_r >= 0 {
        unsafe {
            libc::close(stale_r);
        }
    }
    // Drop any inherited join handle: it names a PARENT thread that does not exist
    // in this child; joining it would block forever.
    *PUMP_THREAD.lock().unwrap_or_else(|e| e.into_inner()) = None;
    PUMP_STOP.store(false, Ordering::SeqCst);
    // The inherited child-exit watches belong to the PARENT's children (this
    // child's siblings); the freshly-forked child must not reap or deliver their
    // exit signals. Its own children are registered fresh on its own pump.
    carrick_signal_core::child_watch::clear();
    PUMP_STARTED.store(false, Ordering::SeqCst);
    SIGCHLD_INSTALLED.store(false, Ordering::SeqCst);
    start_pump(registry, futex);
}

/// Reset the pump's process-global guard state in a forked child WITHOUT
/// re-spawning. The spawn-free analogue of [`reinit_after_fork`]; the caller does
/// the spawn (via its own later `start_signal_pump`).
pub fn reset_state_for_supervisor_fork() {
    let stale_w = SELF_PIPE_W.swap(-1, Ordering::SeqCst);
    if stale_w >= 0 {
        unsafe {
            libc::close(stale_w);
        }
    }
    let stale_r = SELF_PIPE_R.swap(-1, Ordering::SeqCst);
    if stale_r >= 0 {
        unsafe {
            libc::close(stale_r);
        }
    }
    *PUMP_THREAD.lock().unwrap_or_else(|e| e.into_inner()) = None;
    PUMP_STOP.store(false, Ordering::SeqCst);
    carrick_signal_core::child_watch::clear();
    PUMP_STARTED.store(false, Ordering::SeqCst);
    SIGCHLD_INSTALLED.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `pending_bit` (used by the handler) maps the pumped signals to their
    /// 1<<(signum-1) bits, matching `PROC_PENDING`'s convention. HUP/INT/QUIT/TERM
    /// are identical on Linux and FreeBSD, so the host->Linux translation is identity.
    #[test]
    fn pump_signal_bits_match_proc_pending_convention() {
        for &sig in &PUMP_SIGNALS {
            let linux = host_to_linux_signum(sig);
            assert_eq!(
                linux, sig,
                "HUP/INT/QUIT/TERM are identical on both kernels"
            );
            let bit = carrick_signal_core::pending_bit(linux).expect("pumped signum in 1..=64");
            assert_eq!(bit, 1u64 << (sig - 1));
        }
    }

    /// The pumped set is exactly the host-delivered, carrick-never-injected signals
    /// (SIGHUP/INT/QUIT/TERM) and excludes the kick + guest-routed signals.
    #[test]
    fn pump_set_excludes_kick_and_guest_signals() {
        assert!(PUMP_SIGNALS.contains(&libc::SIGTERM));
        assert!(PUMP_SIGNALS.contains(&libc::SIGINT));
        assert!(PUMP_SIGNALS.contains(&libc::SIGHUP));
        assert!(PUMP_SIGNALS.contains(&libc::SIGQUIT));
        // FreeBSD SIGUSR1/2 are 30/31; the kick is SIGRTMIN = 65.
        assert!(!PUMP_SIGNALS.contains(&30));
        assert!(!PUMP_SIGNALS.contains(&31));
        assert!(!PUMP_SIGNALS.contains(&crate::bhyve_kicker::kick_signal()));
    }
}
