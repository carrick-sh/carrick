//! Host-side signal capture for guest delivery.
//!
//! The Carrick host process catches a small set of UNIX signals
//! (currently just `SIGINT`) and translates them into pending guest
//! signal numbers that the runtime drains between vCPU iterations.
//! When the guest has a handler registered for the translated signum,
//! the runtime synthesises a guest signal frame; otherwise the default
//! action (terminate with `128 + signum`) is taken.
//!
//! The shared state is intentionally minimal:
//!
//! * A single `AtomicI32` (`PENDING`) carries the *most recent* host
//!   signal we observed. `0` means "no signal pending"; any positive
//!   value is the Linux signum the guest should see.
//! * `install_default_handlers()` registers our handler once via
//!   `libc::sigaction`. Re-installation is a no-op so test runners that
//!   spin up multiple runtime instances inside the same process don't
//!   stomp on each other.
//!
//! We deliberately do NOT serialise signals through the host kernel's
//! pending mask; the goal of v0 is "Ctrl-C breaks a long-running
//! command", not "perfectly faithful POSIX signal queueing". One slot
//! is enough for that.

use std::sync::atomic::{AtomicI32, AtomicU8, AtomicU64, Ordering};

use crate::linux_abi::LINUX_SIGINT;

/// `(linux_signum, host_signum)` pairs that DIFFER between Linux and macOS.
/// Signals not listed (HUP/INT/QUIT/ILL/TRAP/ABRT/FPE/KILL/SEGV/PIPE/ALRM/
/// TERM/TTIN/TTOU/XCPU/XFSZ/VTALRM/PROF/WINCH) share the same number on both
/// and translate as identity. Cross-process signals must be translated on the
/// send side (`libc::kill`), the receive side (host handler -> guest), and in
/// the `wait4` status, or e.g. a guest SIGUSR1 (10) would be sent to macOS as
/// signal 10 (SIGBUS).
const SIGNUM_XLATE: &[(i32, i32)] = &[
    (7, 10),  // SIGBUS
    (10, 30), // SIGUSR1
    (12, 31), // SIGUSR2
    (17, 20), // SIGCHLD
    (18, 19), // SIGCONT
    (19, 17), // SIGSTOP
    (20, 18), // SIGTSTP
    (23, 16), // SIGURG
    (29, 23), // SIGIO / SIGPOLL
    (31, 12), // SIGSYS
];

/// Translate a Linux signal number to the macOS host number. Identity for
/// signals that share a number.
pub fn linux_to_host_signum(linux: i32) -> i32 {
    SIGNUM_XLATE
        .iter()
        .find(|(l, _)| *l == linux)
        .map(|(_, h)| *h)
        .unwrap_or(linux)
}

/// Translate a macOS host signal number to the Linux number. Identity for
/// signals that share a number.
pub fn host_to_linux_signum(host: i32) -> i32 {
    SIGNUM_XLATE
        .iter()
        .find(|(_, h)| *h == host)
        .map(|(l, _)| *l)
        .unwrap_or(host)
}

/// Bitmask of Linux signums for which we've installed a host handler, so
/// `ensure_host_handler` is idempotent per signal. Bit `n` = signum `n`.
static INSTALLED_MASK: AtomicU64 = AtomicU64::new(0);

/// "No signal pending" sentinel. Chosen as `0` because Linux's
/// `kill(pid, 0)` is documented as the null-signal probe; no real
/// delivery ever uses signum 0.
pub const NO_PENDING_SIGNAL: i32 = 0;

static PENDING: AtomicI32 = AtomicI32::new(NO_PENDING_SIGNAL);

/// Process-wide self-pipe used to wake threads parked in a blocking-I/O
/// `kevent()` (see `io_wait`) the instant a signal becomes pending. The signal
/// handler writes one byte (async-signal-safe); every thread's kqueue watches
/// `PENDING_PIPE_READ` via `EVFILT_READ`, so all parked waits return promptly —
/// no 50ms poll, and no reliance on `SA_RESTART`/EINTR. `-1` until initialised.
static PENDING_PIPE_READ: AtomicI32 = AtomicI32::new(-1);
static PENDING_PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

/// Read end of the self-pipe for `io_wait::ThreadWaiter` to watch, or `-1` if
/// not yet initialised (callers then fall back to a polled wait).
pub fn pending_pipe_read_fd() -> i32 {
    PENDING_PIPE_READ.load(Ordering::SeqCst)
}

/// Create (or recreate) the self-pipe. If already open the old ends are closed
/// first (used by `reinit_after_fork`). Both ends are non-blocking + CLOEXEC.
fn open_pending_pipe() {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return;
    }
    for fd in fds {
        unsafe {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            if fl >= 0 {
                libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
            let fdfl = libc::fcntl(fd, libc::F_GETFD);
            if fdfl >= 0 {
                libc::fcntl(fd, libc::F_SETFD, fdfl | libc::FD_CLOEXEC);
            }
        }
    }
    let old_r = PENDING_PIPE_READ.swap(fds[0], Ordering::SeqCst);
    let old_w = PENDING_PIPE_WRITE.swap(fds[1], Ordering::SeqCst);
    if old_r >= 0 {
        unsafe { libc::close(old_r) };
    }
    if old_w >= 0 {
        unsafe { libc::close(old_w) };
    }
}

/// fork(2) does not inherit a kqueue, and the inherited self-pipe is shared
/// with the parent (cross-process spurious wakes). Give the child a fresh
/// self-pipe so its parked-thread wakes are its own.
pub fn reinit_after_fork() {
    open_pending_pipe();
}

/// Wake any thread parked in a blocking-I/O `kevent()` by making the self-pipe
/// readable. Async-signal-safe (a single non-blocking `write`); a full pipe
/// already means a wake is pending, so EAGAIN is ignored.
fn notify_pending() {
    let w = PENDING_PIPE_WRITE.load(Ordering::SeqCst);
    if w >= 0 {
        let byte = [1u8];
        unsafe {
            libc::write(w, byte.as_ptr() as *const libc::c_void, 1);
        }
    }
}

/// Drain the self-pipe (non-blocking). Called by a waiter after it observes the
/// pipe readable so the level-triggered `EVFILT_READ` doesn't spin. Racing
/// drains across threads are harmless — `has_pending` is the source of truth.
pub fn drain_pending_pipe() {
    let r = PENDING_PIPE_READ.load(Ordering::SeqCst);
    if r < 0 {
        return;
    }
    let mut buf = [0u8; 64];
    loop {
        let n = unsafe { libc::read(r, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
    }
}

/// Publish a pending guest signum AND wake parked waiters. The single store +
/// the pipe write are both async-signal-safe, so this is callable from a host
/// signal handler.
fn publish_pending(signum: i32) {
    PENDING.store(signum, Ordering::SeqCst);
    notify_pending();
}

/// 0 = handlers not installed yet, 1 = installed. Used to make
/// `install_default_handlers` idempotent across test setups.
static INSTALLED: AtomicU8 = AtomicU8::new(0);

/// Async-signal-safe handler. The only thing we do here is publish the
/// observed signum into `PENDING`. The runtime drains it between vCPU
/// iterations.
extern "C" fn handle_sigint(_signum: libc::c_int) {
    // Store the LINUX signum, not the host one; on Darwin and Linux
    // SIGINT happens to share the value 2, but we route everything
    // through the Linux numbering on the guest side so the dispatcher's
    // signal_handlers table lookup matches.
    publish_pending(LINUX_SIGINT);
}

/// Generic host handler for a cross-process signal the guest registered a
/// handler for. Receives the HOST signum, translates it to the Linux
/// numbering, and publishes it for the runtime to deliver to the guest's
/// handler. Async-signal-safe (only an atomic store + a const-table lookup).
extern "C" fn handle_routed(host_signum: libc::c_int) {
    publish_pending(host_to_linux_signum(host_signum));
}

/// Install a host handler for `linux_signum` so a cross-process `kill` from
/// another guest process is routed to this guest's registered handler rather
/// than taking the host's default action (which would terminate the carrick
/// process). Idempotent per signal. Skips signals carrick must not hook:
/// SIGKILL (9) / SIGSTOP (19) can't be caught, and SIGCHLD (17) must keep its
/// default disposition or `wait4`'s host-`waitpid` passthrough breaks.
pub fn ensure_host_handler(linux_signum: i32) {
    if !(1..=63).contains(&linux_signum) || matches!(linux_signum, 9 | 17 | 19) {
        return;
    }
    let bit = 1u64 << linux_signum;
    if INSTALLED_MASK.fetch_or(bit, Ordering::SeqCst) & bit != 0 {
        return;
    }
    let host = linux_to_host_signum(linux_signum);
    // SAFETY: zero-initialised sigaction is the documented "no flags, empty
    // mask" form; we fill sa_sigaction before calling libc. SA_RESTART keeps
    // applevisor's vcpu.run from breaking on delivery (the EINTR-while-blocked-
    // in-a-host-syscall case is a tracked follow-up).
    unsafe {
        let mut action: libc::sigaction = core::mem::zeroed();
        action.sa_sigaction = handle_routed as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART;
        libc::sigaction(host, &action, std::ptr::null_mut());
    }
}

/// Install the host SIGINT handler. Subsequent calls are no-ops. Safe
/// to call from anywhere; the runtime calls it once per `run_*`
/// invocation.
pub fn install_default_handlers() {
    if INSTALLED
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    // The self-pipe must exist before any handler can fire (the handler writes
    // it to wake parked waiters).
    open_pending_pipe();
    // SAFETY: zero-initialised `sigaction` is the documented Linux/Darwin
    // "no flags, empty mask" form. We immediately fill `sa_sigaction`
    // with our handler before calling into libc.
    unsafe {
        let mut action: libc::sigaction = core::mem::zeroed();
        action.sa_sigaction = handle_sigint as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        // Restart syscalls where possible so the host-side `vcpu.run`
        // syscall isn't permanently broken by a SIGINT. Without
        // SA_RESTART, applevisor's wrapper would observe EINTR and
        // surface a hypervisor error; with it set, the kernel returns
        // to the same vcpu_run call and we then notice PENDING when
        // the run completes via the normal HVC trap path.
        action.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    }
}

/// Drain whatever signal is currently pending. Returns `0` if none.
/// Atomic so the runtime can call this from any thread that's about to
/// re-enter `vcpu.run`.
pub fn take_pending() -> i32 {
    PENDING.swap(NO_PENDING_SIGNAL, Ordering::SeqCst)
}

/// Non-draining peek: is a signal currently pending? Used by a thread parked
/// in `futex` to decide whether to interrupt its wait so the trap loop can
/// deliver the signal. Does NOT consume it — `take_pending` (under the kernel
/// lock) is still the single point of delivery.
pub fn has_pending() -> bool {
    PENDING.load(Ordering::SeqCst) != NO_PENDING_SIGNAL
}

/// Set a pending guest signum from inside the guest itself (e.g. from
/// `kill(self, SIGINT)`). Lets the runtime's signal-injection path
/// service synthetic raises the same way it services host SIGINT.
pub fn raise_for_self(signum: i32) {
    publish_pending(signum);
}
