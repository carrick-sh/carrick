//! KVM async host-signal pump: catch host-delivered PROCESS-directed signals
//! (`SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT` — the ones a supervisor or a tty sends,
//! and which carrick NEVER injects into a guest itself) and turn them into a
//! guest-deliverable pending signal.
//!
//! ## Why a pump at all
//!
//! Unlike a guest-issued `tgkill`/`raise` (which the dispatcher services inline,
//! publishing into the per-thread or process pending table), a host signal
//! arrives ASYNCHRONOUSLY on whatever host thread the kernel picks, OUTSIDE the
//! dispatcher. The async handler can do almost nothing safely. So the split is:
//!
//!   - the **handler** (async-signal-safe ONLY): atomically OR the signal's bit
//!     into `carrick_signal_core::PROC_PENDING` (`proc_pending_fetch_or`, a
//!     lock-free `fetch_or`) and `write()` one byte to a self-pipe. NOTHING else
//!     — no `Mutex`, `HashMap`, alloc, or `println!`.
//!   - the **pump thread** (a normal daemon thread): blocks in `poll`/`read` on
//!     the self-pipe's read end; on each wake it drains the byte(s) then
//!     `registry.kick_all()` + `futex.notify_signal_pending()` so EVERY in-guest
//!     vCPU returns from `KVM_RUN` and re-checks `has_process_pending()` at its
//!     safe point, where `deliver_pending_signal` drains `PROC_PENDING` and runs
//!     the guest's handler (or the default terminate action).
//!
//! Without this, a host `SIGTERM` hit the host default disposition and killed the
//! whole carrick process (exit 143) before any guest `SIGTERM` handler ran.
//!
//! ## Idempotency
//!
//! `start_pump` is `Once`-guarded: the sigactions + self-pipe + daemon thread are
//! created exactly once per process. `libc::fork` preserves signal dispositions
//! but resets the `Once` only in the sense that the CHILD inherits a copy of the
//! parent's `Once` state — already "completed" — so a forked child does NOT
//! double-spawn. The child re-arms via [`reinit_after_fork`], which forces a
//! fresh self-pipe + pump thread under a NEW `Once` token (the parent's pipe fds
//! are still open in the child but its pump thread did not survive the fork, so
//! the child needs its own).

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use carrick_hal::{PlatformFutex, VcpuRegistry};

/// Host signals carrick catches and forwards to the guest. These are
/// process-directed signals a supervisor/tty delivers; carrick itself never
/// injects them, so catching them here cannot collide with guest-routed
/// delivery. On Linux the host and guest signal numbers are identical, so the
/// raw numbers double as both the host disposition and the guest pending bit.
const PUMP_SIGNALS: [i32; 4] = [
    libc::SIGHUP,  // 1
    libc::SIGINT,  // 2
    libc::SIGQUIT, // 3
    libc::SIGTERM, // 15
];

/// The self-pipe WRITE fd the async handler pokes. `-1` until the pump installs
/// the pipe. Read with a plain `load` in the handler (async-signal-safe).
static SELF_PIPE_W: AtomicI32 = AtomicI32::new(-1);

/// The self-pipe READ fd the pump thread polls. Published so
/// [`stop_pump_for_fork`] can close it after joining the pump (and the fork
/// reinit paths can close the stale inherited copy).
static SELF_PIPE_R: AtomicI32 = AtomicI32::new(-1);

/// Raised by [`stop_pump_for_fork`]; the pump thread checks it on every wake
/// and exits. Cleared again once the stop completes.
static PUMP_STOP: AtomicBool = AtomicBool::new(false);

/// The live pump thread's join handle, so [`stop_pump_for_fork`] can join it
/// to a full stop before `libc::fork`. A plain std Mutex: never touched from a
/// signal handler.
static PUMP_THREAD: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);

/// Async-signal-safe SIGCHLD handler. Unlike [`pump_handler`], it does NOT touch
/// `PROC_PENDING`: SIGCHLD here is NOT a guest-published process signal but the
/// host's native notification that a guest CHILD (a real host process — a guest
/// `fork` ran `libc::fork`) exited. Resolving WHICH watched child exited and
/// publishing the RECORDED exit signal to the RECORDED parent tid is the pump
/// thread's reaper job (`reap_exited_watches`), which needs `waitid` + locks and
/// must NOT run in an async handler. So the handler does ONLY `poke()` — one
/// `write(2)` to the self-pipe — to wake the pump thread.
extern "C" fn sigchld_handler(_signum: libc::c_int) {
    poke();
}

/// Guards the one-time install of the separate SIGCHLD sigaction.
static SIGCHLD_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install the SIGCHLD disposition (idempotent). Installed with
/// `SA_RESTART | SA_NOCLDSTOP`:
///   * `SA_NOCLDSTOP` so a child STOP/CONTINUE does NOT fire SIGCHLD — only a
///     terminal exit does, which is all the reaper cares about.
///   * `SA_RESTART` so a blocking host `wait4`/`waitid` on the SYNCHRONOUS reap
///     path (`io_wait::wait_proc_exit`) restarts across this handler's EINTR
///     rather than failing (that path already tolerates EINTR by re-polling, but
///     SA_RESTART keeps the contract explicit and minimises spurious wakeups).
/// Must be live by the time the first child-exit watch is registered, so it is
/// installed from the same `start_pump` path the kick + pump use.
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
/// `publish_pending_for` are all safe here.
///
/// For each `child_watch::tracked_pids()` entry we `waitid(P_PID, pid, WEXITED |
/// WNOWAIT | WNOHANG)`. `WNOWAIT` is REQUIRED: it PEEKS the zombie WITHOUT reaping
/// it, so the guest's own later `wait4` still returns the child's status (reaping
/// here would make that `wait4` see `ECHILD`). On a terminal exit (si_pid == pid,
/// code CLD_EXITED/KILLED/DUMPED) we `child_watch::take(pid)` (the atomic remove —
/// publish-once) and, if it returned `Some((parent_tid, exit_signal))` with a
/// non-zero exit signal, `publish_pending_for(parent_tid, exit_signal)`. The
/// caller's subsequent `kick_all()` + `notify_signal_pending()` then wakes the
/// parent vCPU to deliver it. An untracked child that exited is never `waitid`ed
/// here (we only probe the tracked set), so it just leaves the pump wake harmless.
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
            // ESRCH/ECHILD: not ours / already reaped — drop the stale watch so
            // the table does not grow unbounded. Any other errno: leave it for a
            // later pump wake to retry.
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::ECHILD) || errno == Some(libc::ESRCH) {
                let _ = carrick_signal_core::child_watch::take(pid);
            }
            continue;
        }
        // WNOHANG with no ready child returns 0 with si_pid == 0 (still running).
        // carrick-linux is a Linux-only crate, so `siginfo_t::si_pid()` (the libc
        // accessor over the anonymous union) is available directly.
        // SAFETY: reads the POSIX-defined `si_pid` union member; libc marks the
        // accessor `unsafe` only because it reads a union.
        let si_pid = unsafe { info.si_pid() };
        if si_pid != pid || !matches!(info.si_code, CLD_EXITED | CLD_KILLED | CLD_DUMPED) {
            continue;
        }
        // Terminal exit observed. Atomically remove the watch (publish-once) and
        // publish the recorded exit signal to the recorded parent tid. If the
        // guest already reaped this child synchronously, the dispatcher's
        // terminal-reap cancel (`take_child_exit_parent`) removed it first, so
        // `take` returns None here and we publish nothing (double-delivery guard).
        if let Some((parent_tid, exit_signal)) = carrick_signal_core::child_watch::take(pid)
            && exit_signal != 0
        {
            carrick_signal_core::publish_pending_for(parent_tid, exit_signal);
        }
    }
}

/// Async-signal-safe handler for the pumped host signals. Does ONLY:
///   1. `proc_pending_fetch_or(bit)` — a lock-free atomic OR into PROC_PENDING.
///   2. `write(SELF_PIPE_W, &[0u8], 1)` — wake the pump thread.
/// `carrick_signal_core::pending_bit` is pure arithmetic (`1 << (signum-1)`), so
/// it is safe to call here. NO allocation, locks, or non-reentrant libc.
extern "C" fn pump_handler(signum: libc::c_int) {
    if let Some(bit) = carrick_signal_core::pending_bit(signum) {
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

/// Wake the pump thread from another async-signal-safe context (the xsignal
/// nudge handler — see [`crate::kvm_xsig`]). Reads the published self-pipe write
/// fd with a relaxed atomic load and, if live, `write(2)`s one byte (ignoring the
/// result — a full nonblocking pipe already has a pending wake, EINTR is
/// harmless). Async-signal-safe: only an atomic load + `write(2)`. Lets the nudge
/// handler reuse the pump's `kick_all` fan-out without duplicating pipe state.
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

/// Install the `sigaction` disposition for every pumped signal. The handler runs
/// with `SA_RESTART` so an interrupted host syscall (the pump's own `poll`/`read`
/// is the only blocking host call on the threads that might catch it) restarts
/// rather than failing. Idempotent: re-installing the same disposition is cheap
/// and harmless.
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
    // PROC_PENDING like the PUMP_SIGNALS — it triggers the child-exit reaper
    // instead. Installed here (always, from the same `start_pump` path the kick +
    // pump use) so it is live by the time the first child-exit watch registers.
    install_sigchld_handler();
}

/// Create the nonblocking, close-on-exec self-pipe and publish its write end.
/// Returns the READ fd for the pump thread to poll. Returns `-1` on failure (the
/// handler then just sets PROC_PENDING without a wake — a kicked vCPU still picks
/// it up at its next safe point, only the latency is worse).
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

/// Spawn the pump daemon thread: block in `poll` on `read_fd`, drain on wake,
/// then kick every vCPU + nudge the futex so all in-guest threads re-check
/// `has_process_pending()`.
fn spawn_pump_thread(
    read_fd: i32,
    registry: Arc<dyn VcpuRegistry>,
    futex: Arc<dyn PlatformFutex>,
) {
    let handle = std::thread::Builder::new()
        .name("carrick-sig-pump".to_string())
        .spawn(move || {
            let mut pfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let mut drain = [0u8; 64];
            loop {
                // A pre-fork stop (`stop_pump_for_fork`) raised the flag and
                // poked the pipe; exit WITHOUT touching any shared lock so the
                // joiner can proceed straight to `libc::fork`.
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
                    // (e.g. a guest send) still delivers — only host-only-signal
                    // latency degrades.
                    return;
                }
                // Drain everything the handler wrote (coalesced wakes are fine —
                // the pending bits already record WHICH signals arrived).
                loop {
                    let r = unsafe {
                        libc::read(read_fd, drain.as_mut_ptr() as *mut libc::c_void, drain.len())
                    };
                    if r <= 0 {
                        break;
                    }
                    if (r as usize) < drain.len() {
                        break;
                    }
                }
                // Resolve any watched guest child that EXITED before kicking: the
                // SIGCHLD handler only `poke()`d us (async-signal-safe), so the
                // actual `waitid`-peek + publish of the recorded exit signal to the
                // recorded parent tid runs HERE on the pump thread. This must
                // precede the kick so the published thread-pending signal is
                // visible when the woken parent vCPU reaches its delivery point.
                reap_exited_watches();
                // Wake every in-guest vCPU so it returns from KVM_RUN and the
                // generic loop drains PROC_PENDING (and any just-published
                // thread-pending child-exit signal) at its safe point. The futex
                // nudge covers threads blocked in a futex wait.
                registry.kick_all();
                futex.notify_signal_pending();
            }
        });
    if let Ok(h) = handle {
        *PUMP_THREAD.lock().unwrap_or_else(|e| e.into_inner()) = Some(h);
    }
}

/// Stop + JOIN the pump thread before `libc::fork`, mirroring the HVF
/// `ForkCoordinator::prepare_host_fork` contract. The pump takes process-global
/// locks on every wake (`carrick_signal_core` THREAD_PENDING via
/// `publish_pending_for`, the child-watch table in `reap_exited_watches`, the
/// kicker registry in `kick_all`, the futex table in `notify_signal_pending`).
/// A `libc::fork` landing while one is held hands the CHILD a mutex locked by a
/// thread that does not exist in it — the child then deadlocks in
/// `host_signal::reinit_after_fork` (`clear_thread_pending` /
/// `child_watch::clear`) and the vfork parent rides its 60s suspend timeout
/// (the go-os_exec TestConcurrentExec SIGCHLD-storm wedge). Returns whether a
/// pump thread was actually running (the caller's restart token).
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
    // Tear the pipe down (the restart makes a fresh one) and clear the guards
    // so a post-fork `start_pump` re-arms instead of no-opping. The handler
    // keeps running across the stop window: it sees SELF_PIPE_W == -1 and only
    // sets PROC_PENDING bits, which the restarted pump's kick-off poke drains.
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
/// the self-pipe, and spawns ONE daemon thread. A second call is a no-op (the
/// process-global `PUMP_STARTED` guard), so the loop's repeated
/// `start_signal_pump` (startup + after every dispatch via the pump-request) and
/// the post-fork parent re-assert never double-spawn.
pub fn start_pump(registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
    // Always (re-)assert the dispositions: cheap, idempotent, and makes the
    // contract explicit even if a prior path cleared them.
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
    // Kick-start one pump pass: a signal (e.g. a SIGCHLD burst) that landed
    // while the pump was stopped across a fork (`stop_pump_for_fork`) only set
    // pending bits / left a zombie to reap — there is no byte in the NEW pipe
    // to wake the fresh thread. One unconditional poke makes the first pass
    // run reap_exited_watches + kick_all immediately; harmless when idle.
    poke();
}

/// Re-arm the pump in a freshly forked CHILD. The child inherited the parent's
/// `PUMP_STARTED == true` and the parent's pipe fds, but NOT the parent's pump
/// thread (only the forking thread survives `libc::fork`). Reset the guard and
/// the published write fd, then `start_pump` again so the child gets its own
/// self-pipe + pump thread. The parent's inherited pipe fds are O_CLOEXEC and
/// will be replaced; closing the stale write fd avoids leaking it.
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
    // Drop any inherited join handle: it names a PARENT thread that does not
    // exist in this child; joining it would block forever. (After a fork via
    // the coordinator this is already None — `stop_pump_for_fork` took it —
    // but a path that forks without prepare must not strand it.)
    *PUMP_THREAD.lock().unwrap_or_else(|e| e.into_inner()) = None;
    PUMP_STOP.store(false, Ordering::SeqCst);
    // The inherited child-exit watches belong to the PARENT's children (this
    // child's siblings); the freshly-forked child must not reap or deliver their
    // exit signals. Its own children are registered fresh on its own pump.
    carrick_signal_core::child_watch::clear();
    PUMP_STARTED.store(false, Ordering::SeqCst);
    // Re-install the SIGCHLD disposition in the child too: `libc::fork` preserves
    // dispositions, but resetting the guard keeps `install_handlers` (called by
    // `start_pump`) re-asserting it explicitly — and a future eager-teardown
    // can't strand a child without it.
    SIGCHLD_INSTALLED.store(false, Ordering::SeqCst);
    start_pump(registry, futex);
}

/// Reset the pump's process-global guard state in a forked child WITHOUT
/// re-spawning. Used by the interactive-`--tty` supervisor-fork reset
/// (`host_signal::reset_after_supervisor_fork`), where the runtime child has NO
/// `(registry, futex)` in hand yet — it proceeds to the normal runtime setup,
/// which calls `start_signal_pump` (and therefore [`start_pump`]) itself. This
/// helper only undoes the inherited "already started" bookkeeping so that later
/// `start_pump` actually re-arms the child instead of no-opping:
///   * close + clear the stale inherited [`SELF_PIPE_W`] (the parent's pipe write
///     end, whose read end / pump thread did NOT survive the fork) so the next
///     `make_self_pipe` publishes a fresh fd;
///   * reset [`PUMP_STARTED`] so the next `start_pump` CAS spawns the daemon
///     thread + makes a new self-pipe;
///   * reset [`SIGCHLD_INSTALLED`] so `install_handlers` re-asserts the SIGCHLD
///     reaper disposition;
///   * `child_watch::clear()` so the child does not reap or deliver the
///     supervisor's child-exit watches.
/// This is the spawn-free analogue of [`reinit_after_fork`]; the caller does the
/// spawn (via its own later `start_signal_pump`).
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
    // See reinit_after_fork: the inherited handle names a parent thread.
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
    /// 1<<(signum-1) bits, matching `PROC_PENDING`'s convention.
    #[test]
    fn pump_signal_bits_match_proc_pending_convention() {
        for &sig in &PUMP_SIGNALS {
            let bit = carrick_signal_core::pending_bit(sig).expect("pumped signum in 1..=64");
            assert_eq!(bit, 1u64 << (sig - 1));
        }
    }

    /// The pumped set is exactly the host-delivered, carrick-never-injected
    /// signals (SIGHUP/INT/QUIT/TERM) and excludes the kick signal (SIGRTMIN) and
    /// guest-routed signals (SIGUSR1/2).
    #[test]
    fn pump_set_excludes_kick_and_guest_signals() {
        assert!(PUMP_SIGNALS.contains(&libc::SIGTERM));
        assert!(PUMP_SIGNALS.contains(&libc::SIGINT));
        assert!(PUMP_SIGNALS.contains(&libc::SIGHUP));
        assert!(PUMP_SIGNALS.contains(&libc::SIGQUIT));
        assert!(!PUMP_SIGNALS.contains(&libc::SIGUSR1));
        assert!(!PUMP_SIGNALS.contains(&libc::SIGUSR2));
        assert!(!PUMP_SIGNALS.contains(&libc::SIGRTMIN()));
    }
}
