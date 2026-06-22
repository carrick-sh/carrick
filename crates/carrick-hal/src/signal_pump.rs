//! The async host-signal PUMP, shared by every kick+futex backend (KVM, bhyve,
//! NVMM). Catch host-delivered PROCESS-directed signals (`SIGHUP`/`SIGINT`/
//! `SIGQUIT`/`SIGTERM` — the ones a supervisor or tty sends, which carrick never
//! injects itself) and turn them into a guest-deliverable pending signal, plus
//! run the child-exit reaper. This is the byte-identical `kvm/bhyve/nvmm_signal_pump`
//! collapsed into ONE module, generic over the backend's [`HostSignalGlue`](carrick_signal_core::HostSignalGlue) for the
//! single delta: `pump_handler` translates the host signum to the guest's Linux
//! signum (KVM identity; the BSD backends use their table). HVF has a different
//! (kqueue) pump and does NOT use this.
//!
//! ## The split (why a pump)
//!
//! A host signal arrives ASYNCHRONOUSLY on whatever host thread the kernel picks,
//! OUTSIDE the dispatcher, where the handler can do almost nothing safely. So:
//!   - the **handler** (async-signal-safe ONLY): `proc_pending_fetch_or` the
//!     signal's bit into `PROC_PENDING` and `write()` one byte to a self-pipe.
//!   - the **pump thread** (a normal daemon): blocks in `poll`/`read` on the
//!     self-pipe; on each wake it drains, runs the child-exit reaper, then
//!     `registry.kick_all()` + `futex.notify_signal_pending()` so every in-guest
//!     vCPU returns from its run-loop ioctl and re-checks `has_process_pending()`.
//!
//! ## Statics are process-global
//!
//! The pump is a per-PROCESS singleton (one self-pipe, one daemon thread). The
//! statics below are module-level (one set), and the generic fns only parameterize
//! WHICH `pump_handler::<G>` is installed — there is exactly one active backend `G`
//! per build, so monomorphization installs one handler over the one pump.

#![cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use carrick_signal_core::HostSignalGlue;

use crate::{PlatformFutex, VcpuRegistry};

/// Host signals carrick catches and forwards to the guest. Process-directed
/// signals a supervisor/tty delivers; carrick never injects them, so catching
/// them cannot collide with guest-routed delivery. SIGHUP/INT/QUIT/TERM are
/// 1/2/3/15 on Linux AND the BSDs, so the raw host numbers are correct on every
/// pump host; `pump_handler` translates to the guest Linux number before
/// recording pending (an identity on Linux).
const PUMP_SIGNALS: [i32; 4] = [
    libc::SIGHUP,  // 1
    libc::SIGINT,  // 2
    libc::SIGQUIT, // 3
    libc::SIGTERM, // 15
];

/// The self-pipe WRITE fd the async handler pokes. `-1` until the pump installs it.
static SELF_PIPE_W: AtomicI32 = AtomicI32::new(-1);

/// The self-pipe READ fd the pump thread polls.
static SELF_PIPE_R: AtomicI32 = AtomicI32::new(-1);

/// Raised by [`stop_pump_for_fork`]; the pump thread checks it on every wake.
static PUMP_STOP: AtomicBool = AtomicBool::new(false);

/// The live pump thread's join handle. A plain std Mutex: never touched from a
/// signal handler.
static PUMP_THREAD: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);

/// Original signal mask for the thread currently crossing `libc::fork`.
static FORK_OLD_SIGNAL_MASK: Mutex<Option<libc::sigset_t>> = Mutex::new(None);

/// Guards the one-time install of the SIGCHLD sigaction.
static SIGCHLD_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Guards the one-time install of the sigactions + self-pipe + pump thread.
static PUMP_STARTED: AtomicBool = AtomicBool::new(false);

/// Async-signal-safe SIGCHLD handler. Does NOT touch `PROC_PENDING`: SIGCHLD is the
/// host's native notification that a guest CHILD (a real host process) exited;
/// resolving WHICH child + publishing its exit signal is the pump thread's reaper
/// job ([`reap_exited_watches`], needs `waitid` + locks). So the handler does ONLY
/// `poke()` — one `write(2)` — to wake the pump thread.
extern "C" fn sigchld_handler(_signum: libc::c_int) {
    poke();
}

/// Install the SIGCHLD disposition (idempotent), `SA_RESTART | SA_NOCLDSTOP`
/// (only terminal exits fire; blocking host `waitid` restarts across EINTR).
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

fn pump_signal_set() -> libc::sigset_t {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        for &sig in &PUMP_SIGNALS {
            libc::sigaddset(&mut set, sig);
        }
    }
    set
}

/// Block host-pumped signals on the thread about to call `fork(2)`, so a parent's
/// immediate `kill(child, SIGTERM)` is held pending by the kernel until the child
/// has cleared inherited state + restarted its own pump + restored this mask
/// (otherwise the inherited handler records a real post-fork signal that the
/// child's reinit clear wrongly drops).
pub fn block_pump_signals_for_fork() {
    let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
    let set = pump_signal_set();
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old) };
    if rc == 0 {
        *FORK_OLD_SIGNAL_MASK
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(old);
    }
}

/// Restore the signal mask saved by [`block_pump_signals_for_fork`].
pub fn restore_pump_signals_after_fork() {
    let old = FORK_OLD_SIGNAL_MASK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if let Some(old) = old {
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        }
    }
}

/// Peek every tracked guest child for a terminal exit and, on one, publish its
/// RECORDED exit signal to its RECORDED parent tid. Runs on the pump THREAD, so
/// `waitid` + the child-watch locks are safe. `WNOWAIT` PEEKS the zombie WITHOUT
/// reaping it, so the guest's own later `wait4` still returns the status.
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
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::ECHILD) || errno == Some(libc::ESRCH) {
                let _ = carrick_signal_core::child_watch::take(pid);
            }
            continue;
        }
        // SAFETY: reads the POSIX `si_pid` union member; libc marks the accessor
        // unsafe only because it reads a union.
        let si_pid = unsafe { info.si_pid() };
        if si_pid != pid || !matches!(info.si_code, CLD_EXITED | CLD_KILLED | CLD_DUMPED) {
            continue;
        }
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

/// Async-signal-safe handler for the pumped host signals: `proc_pending_fetch_or`
/// the guest Linux bit (translating the host signum via `G::host_to_linux` — an
/// identity on Linux, the table on BSD) then `write(2)` to the self-pipe. NO
/// allocation, locks, or non-reentrant libc.
extern "C" fn pump_handler<G: HostSignalGlue>(signum: libc::c_int) {
    let linux_signum = G::host_to_linux(signum);
    if let Some(bit) = carrick_signal_core::pending_bit(linux_signum) {
        carrick_signal_core::proc_pending_fetch_or(bit);
    }
    let w = SELF_PIPE_W.load(Ordering::Relaxed);
    if w >= 0 {
        let byte = [0u8; 1];
        // SAFETY: write(2) is async-signal-safe. EINTR / full-pipe are harmless.
        unsafe {
            libc::write(w, byte.as_ptr() as *const libc::c_void, 1);
        }
    }
}

/// Wake the pump thread from another async-signal-safe context (the xsignal nudge
/// handler). Only an atomic load + `write(2)` — async-signal-safe. This is the
/// fn every backend's `HostSignalGlue::poke` calls.
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

/// Install the `sigaction` disposition (`pump_handler::<G>`, `SA_RESTART`) for every
/// pumped signal, plus the separate SIGCHLD reaper disposition. Idempotent.
fn install_handlers<G: HostSignalGlue>() {
    for &sig in &PUMP_SIGNALS {
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = pump_handler::<G> as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = libc::SA_RESTART;
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
    install_sigchld_handler();
}

/// Create the nonblocking, close-on-exec self-pipe and publish its write end.
/// Returns the READ fd, or `-1` on failure (the handler then only sets pending).
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

/// Spawn the pump daemon thread: block in `poll`, drain on wake, reap exited
/// watches, then kick every vCPU + nudge the futex.
fn spawn_pump_thread(read_fd: i32, registry: Arc<dyn VcpuRegistry>, futex: Arc<dyn PlatformFutex>) {
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
                    return;
                }
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
                reap_exited_watches();
                registry.kick_all();
                futex.notify_signal_pending();
            }
        });
    if let Ok(h) = handle {
        *PUMP_THREAD.lock().unwrap_or_else(|e| e.into_inner()) = Some(h);
    }
}

/// Stop + JOIN the pump thread before `libc::fork` (the pump takes process-global
/// locks on every wake; a fork landing while one is held hands the child a mutex
/// locked by a thread that does not exist in it). Returns whether a pump was
/// running (the caller's restart token).
pub fn stop_pump_for_fork() -> bool {
    let handle = PUMP_THREAD.lock().unwrap_or_else(|e| e.into_inner()).take();
    let Some(handle) = handle else {
        return false;
    };
    PUMP_STOP.store(true, Ordering::SeqCst);
    poke();
    let _ = handle.join();
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

/// Start the async host-signal pump (idempotent): install the sigactions
/// (`pump_handler::<G>`), make the self-pipe, spawn ONE daemon thread. A second
/// call is a no-op (the `PUMP_STARTED` guard).
pub fn start_pump<G: HostSignalGlue>(
    registry: &Arc<dyn VcpuRegistry>,
    futex: &Arc<dyn PlatformFutex>,
) {
    install_handlers::<G>();
    if PUMP_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    let read_fd = make_self_pipe();
    if read_fd < 0 {
        return;
    }
    spawn_pump_thread(read_fd, Arc::clone(registry), Arc::clone(futex));
    // Kick-start one pass: a signal that landed while the pump was stopped across
    // a fork only set pending bits / left a zombie; one poke runs the first
    // reap_exited_watches + kick_all immediately. Harmless when idle.
    poke();
}

/// Re-arm the pump in a freshly forked CHILD: the child inherited `PUMP_STARTED`
/// and the parent's pipe fds but NOT the parent's pump thread. Reset the guards,
/// the stale fds, and the inherited child-watches, then `start_pump` again.
pub fn reinit_after_fork<G: HostSignalGlue>(
    registry: &Arc<dyn VcpuRegistry>,
    futex: &Arc<dyn PlatformFutex>,
) {
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
    start_pump::<G>(registry, futex);
}

/// Reset the pump's process-global guard state in a forked child WITHOUT
/// re-spawning (the interactive-`--tty` supervisor-fork reset, where the child has
/// no `(registry, futex)` yet — its later `start_signal_pump` does the spawn). Undoes
/// the inherited "already started" bookkeeping so the later `start_pump` re-arms.
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
    /// `1<<(signum-1)` bits, matching `PROC_PENDING`'s convention.
    #[test]
    fn pump_signal_bits_match_proc_pending_convention() {
        for &sig in &PUMP_SIGNALS {
            let bit = carrick_signal_core::pending_bit(sig).expect("pumped signum in 1..=64");
            assert_eq!(bit, 1u64 << (sig - 1));
        }
    }

    /// The pumped set is exactly the host-delivered, carrick-never-injected signals
    /// and excludes guest-routed signals (SIGUSR1/2).
    #[test]
    fn pump_set_excludes_guest_signals() {
        assert!(PUMP_SIGNALS.contains(&libc::SIGTERM));
        assert!(PUMP_SIGNALS.contains(&libc::SIGINT));
        assert!(PUMP_SIGNALS.contains(&libc::SIGHUP));
        assert!(PUMP_SIGNALS.contains(&libc::SIGQUIT));
        assert!(!PUMP_SIGNALS.contains(&libc::SIGUSR1));
        assert!(!PUMP_SIGNALS.contains(&libc::SIGUSR2));
    }
}
