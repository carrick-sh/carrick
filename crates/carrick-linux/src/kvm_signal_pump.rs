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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

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
    let _ = std::thread::Builder::new()
        .name("carrick-sig-pump".to_string())
        .spawn(move || {
            let mut pfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let mut drain = [0u8; 64];
            loop {
                let n = unsafe { libc::poll(&mut pfd, 1, -1) };
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
                // Wake every in-guest vCPU so it returns from KVM_RUN and the
                // generic loop drains PROC_PENDING at its safe point. The futex
                // nudge covers threads blocked in a futex wait.
                registry.kick_all();
                futex.notify_signal_pending();
            }
        });
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
    PUMP_STARTED.store(false, Ordering::SeqCst);
    start_pump(registry, futex);
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
