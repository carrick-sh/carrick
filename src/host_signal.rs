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

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicU8, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use crate::linux_abi::LINUX_SIGINT;

/// Host fds at or above this value are reserved for Carrick internals. Guest
/// Linux fds are capped at 1024 by the dispatcher, so putting the signal
/// self-pipe here prevents fork reinitialization from closing a low host fd
/// that the guest pipe/socket layer has reused.
const HOST_INTERNAL_FD_MIN: i32 = 16 * 1024;
const HOST_INTERNAL_FD_TARGET: libc::rlim_t = (HOST_INTERNAL_FD_MIN as libc::rlim_t) + 16;
static NOFILE_RAISE_ATTEMPTED: AtomicU8 = AtomicU8::new(0);

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

/// Thread-directed pending signals, keyed by guest tid. A process-directed
/// signal (host `SIGINT`, `kill(pid)`) goes into the global `PENDING` slot and
/// may be serviced by any thread; a *thread*-directed signal (guest
/// `tgkill(tid, sig)` / `tkill`) targets exactly one guest thread and is parked
/// here so only that thread delivers it. Set ONLY from guest-dispatch context
/// (never a host async handler — a host signal can't name a guest tid), so a
/// plain `Mutex` is safe; it is never locked from a signal handler. One slot
/// per tid mirrors the single-slot global model (last delivered wins).
static THREAD_PENDING: LazyLock<Mutex<HashMap<i32, i32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Publish a signal targeted at a specific guest `tid` and wake parked waiters.
/// The waking thread (and only it, via `take_pending_for`) will deliver it.
/// Unlike `publish_pending`, this is NOT async-signal-safe (takes a `Mutex`) —
/// call it only from normal dispatch context, which is the only place a guest
/// tid is known.
pub fn publish_pending_for(tid: i32, signum: i32) {
    #[allow(clippy::expect_used)]
    THREAD_PENDING
        .lock()
        .expect("THREAD_PENDING poisoned")
        .insert(tid, signum);
    notify_pending();
}

/// Drain the signal deliverable to `tid`: a thread-directed one for this tid
/// takes priority, otherwise the process-directed global slot. Returns `0`
/// (`NO_PENDING_SIGNAL`) if neither is set. This is the single point of
/// consumption (called under the dispatcher lock in `deliver_pending_signal`).
pub fn take_pending_for(tid: i32) -> i32 {
    #[allow(clippy::expect_used)]
    if let Some(s) = THREAD_PENDING
        .lock()
        .expect("THREAD_PENDING poisoned")
        .remove(&tid)
    {
        return s;
    }
    PENDING.swap(NO_PENDING_SIGNAL, Ordering::SeqCst)
}

/// Is a signal deliverable to `tid` pending? True for a thread-directed signal
/// for this tid OR any process-directed signal. Used by a thread parked in
/// `kevent`/`futex` to decide whether to break its wait so the trap loop can
/// run delivery — without waking siblings for a signal that isn't theirs.
pub fn has_pending_for(tid: i32) -> bool {
    if PENDING.load(Ordering::SeqCst) != NO_PENDING_SIGNAL {
        return true;
    }
    #[allow(clippy::expect_used)]
    THREAD_PENDING
        .lock()
        .expect("THREAD_PENDING poisoned")
        .contains_key(&tid)
}

pub fn has_process_pending() -> bool {
    PENDING.load(Ordering::SeqCst) != NO_PENDING_SIGNAL
}

pub fn pending_thread_tids() -> Vec<i32> {
    #[allow(clippy::expect_used)]
    THREAD_PENDING
        .lock()
        .expect("THREAD_PENDING poisoned")
        .keys()
        .copied()
        .collect()
}

/// Drop any thread-directed pending entry for `tid` (called when a guest thread
/// exits so a recycled tid never inherits a stale signal). A forked child also
/// clears the whole table via `reinit_after_fork`.
pub fn forget_thread(tid: i32) {
    #[allow(clippy::expect_used)]
    THREAD_PENDING
        .lock()
        .expect("THREAD_PENDING poisoned")
        .remove(&tid);
}

/// Process-wide self-pipe used to wake threads parked in a blocking-I/O
/// `kevent()` (see `io_wait`) the instant a signal becomes pending. The signal
/// handler writes one byte (async-signal-safe); every thread's kqueue watches
/// `PENDING_PIPE_READ` via `EVFILT_READ`, so all parked waits return promptly —
/// no 50ms poll, and no reliance on `SA_RESTART`/EINTR. `-1` until initialised.
static PENDING_PIPE_READ: AtomicI32 = AtomicI32::new(-1);
static PENDING_PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);
/// Dedicated async-signal-safe wake pipe for the signal pump. This must be
/// separate from the waiter self-pipe so a blocking I/O waiter cannot drain the
/// only byte that should kick vCPUs out of guest userspace.
static PUMP_PIPE_READ: AtomicI32 = AtomicI32::new(-1);
static PUMP_PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);
/// kqueue fd of this process's signal pump, holding an `EVFILT_USER` (ident 0)
/// the pump blocks on. `notify_pump` triggers it (`NOTE_TRIGGER`) to wake the
/// pump from a NORMAL thread (e.g. an interval-timer thread) without the
/// self-pipe's edge-coalescing quirk and without a poll. -1 until the pump
/// registers it; reset on fork (the child re-spawns its pump).
static PUMP_KQUEUE: AtomicI32 = AtomicI32::new(-1);

/// Record the signal pump's kqueue fd (called by the pump after it registers
/// its `EVFILT_USER`). See `notify_pump`.
pub fn set_pump_kqueue(kq: i32) {
    PUMP_KQUEUE.store(kq, Ordering::SeqCst);
}

/// Wake the signal pump via its `EVFILT_USER` (`NOTE_TRIGGER`). NOT
/// async-signal-safe (`kevent` isn't) — call only from normal thread context;
/// host signal handlers use the self-pipe (`notify_pending`) instead.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn notify_pump() {
    let kq = PUMP_KQUEUE.load(Ordering::SeqCst);
    if kq < 0 {
        return;
    }
    let trigger = libc::kevent {
        ident: 0,
        filter: libc::EVFILT_USER,
        flags: 0,
        fflags: libc::NOTE_TRIGGER,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: kevent with a single change and no event buffer; kq is a live
    // kqueue fd owned by the pump for the process's lifetime.
    unsafe {
        libc::kevent(kq, &trigger, 1, std::ptr::null_mut(), 0, std::ptr::null());
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn notify_pump() {}

/// Read end of the self-pipe for `io_wait::ThreadWaiter` to watch, or `-1` if
/// not yet initialised (callers then fall back to a polled wait).
pub fn pending_pipe_read_fd() -> i32 {
    PENDING_PIPE_READ.load(Ordering::SeqCst)
}

/// Read end of the signal pump's dedicated wake pipe.
pub fn pump_pipe_read_fd() -> i32 {
    PUMP_PIPE_READ.load(Ordering::SeqCst)
}

/// Create (or recreate) the self-pipe. If already open the old ends are closed
/// first (used by `reinit_after_fork`). Both ends are non-blocking + CLOEXEC.
fn open_pending_pipe() {
    let Some((read_fd, write_fd)) = open_internal_pipe() else {
        return;
    };
    replace_pipe(&PENDING_PIPE_READ, &PENDING_PIPE_WRITE, read_fd, write_fd);

    if let Some((pump_read, pump_write)) = open_internal_pipe() {
        replace_pipe(&PUMP_PIPE_READ, &PUMP_PIPE_WRITE, pump_read, pump_write);
    }
}

fn open_internal_pipe() -> Option<(i32, i32)> {
    let mut raw_fds = [0i32; 2];
    let rc = unsafe { libc::pipe(raw_fds.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let Some(read_fd) = duplicate_internal_fd(raw_fds[0]) else {
        close_raw_fds(&raw_fds);
        return None;
    };
    let Some(write_fd) = duplicate_internal_fd(raw_fds[1]) else {
        unsafe { libc::close(read_fd) };
        close_raw_fds(&raw_fds);
        return None;
    };
    close_raw_fds(&raw_fds);

    for fd in [read_fd, write_fd] {
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
    Some((read_fd, write_fd))
}

fn replace_pipe(read_slot: &AtomicI32, write_slot: &AtomicI32, read_fd: i32, write_fd: i32) {
    let old_r = read_slot.swap(read_fd, Ordering::SeqCst);
    let old_w = write_slot.swap(write_fd, Ordering::SeqCst);
    if old_r >= 0 && old_r != read_fd && old_r != write_fd {
        unsafe { libc::close(old_r) };
    }
    if old_w >= 0 && old_w != read_fd && old_w != write_fd {
        unsafe { libc::close(old_w) };
    }
}

fn close_raw_fds(fds: &[i32; 2]) {
    for fd in fds {
        unsafe { libc::close(*fd) };
    }
}

fn duplicate_internal_fd(fd: i32) -> Option<i32> {
    ensure_internal_fd_range();
    let duped = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, HOST_INTERNAL_FD_MIN) };
    if duped >= 0 { Some(duped) } else { None }
}

pub(crate) fn relocate_internal_fd(fd: i32) -> i32 {
    let Some(duped) = duplicate_internal_fd(fd) else {
        return fd;
    };
    unsafe { libc::close(fd) };
    duped
}

fn ensure_internal_fd_range() {
    if NOFILE_RAISE_ATTEMPTED
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return;
    }
    let mut limit = unsafe { limit.assume_init() };
    if limit.rlim_cur >= HOST_INTERNAL_FD_TARGET {
        return;
    }
    let desired = if limit.rlim_max == libc::RLIM_INFINITY {
        HOST_INTERNAL_FD_TARGET
    } else {
        HOST_INTERNAL_FD_TARGET.min(limit.rlim_max)
    };
    if desired > limit.rlim_cur {
        limit.rlim_cur = desired;
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}

/// fork(2) does not inherit a kqueue, and the inherited self-pipe is shared
/// with the parent (cross-process spurious wakes). Give the child a fresh
/// self-pipe so its parked-thread wakes are its own.
pub fn reinit_after_fork() {
    open_pending_pipe();
    // The parent's pump kqueue fd is meaningless in the child; the child
    // re-spawns its own pump (which calls set_pump_kqueue). Until then, no
    // EVFILT_USER target — publish_process_signal still wakes via the pipe.
    PUMP_KQUEUE.store(-1, Ordering::SeqCst);
    // The child is single-threaded (fork copies only the calling thread); any
    // sibling-directed pending entries inherited from the parent are stale.
    if let Ok(mut map) = THREAD_PENDING.lock() {
        map.clear();
    }
    PENDING.store(NO_PENDING_SIGNAL, Ordering::SeqCst);
}

/// Reset inherited host-signal state in the runtime child after the
/// interactive session supervisor forks. This runs before the HVF runtime
/// installs default handlers, so the child does not inherit stale pending
/// signals, routed-handler bookkeeping, or the supervisor's self-pipe fds.
pub fn reset_after_supervisor_fork() {
    INSTALLED.store(0, Ordering::SeqCst);
    INSTALLED_MASK.store(0, Ordering::SeqCst);
    if let Ok(mut map) = THREAD_PENDING.lock() {
        map.clear();
    }
    PENDING.store(NO_PENDING_SIGNAL, Ordering::SeqCst);
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
    let pump = PUMP_PIPE_WRITE.load(Ordering::SeqCst);
    if pump >= 0 {
        let byte = [1u8];
        unsafe {
            libc::write(pump, byte.as_ptr() as *const libc::c_void, 1);
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

/// Drain the signal pump's dedicated wake pipe.
pub fn drain_pump_pipe() {
    let r = PUMP_PIPE_READ.load(Ordering::SeqCst);
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

/// Publish a process-directed guest signal from a non-vCPU host thread (e.g.
/// the interval-timer thread delivering SIGALRM/SIGVTALRM/SIGPROF on expiry).
/// Sets the process-directed pending slot and wakes parked waiters; the kick
/// daemon forces any in-guest vCPU out so the runtime delivers it promptly.
pub fn publish_process_signal(signum: i32) {
    publish_pending(signum);
    // Wake the pump via EVFILT_USER too: a busy-waiting guest (no parked
    // waiter draining the self-pipe) wouldn't be re-kicked off the pipe edge
    // alone. Safe here — this is called from a normal thread, not a handler.
    notify_pump();
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
/// SIGPIPE (13) is excluded too: carrick deliberately sets it to SIG_IGN
/// process-wide (see main.rs) so its own host writes to a closed pipe yield
/// EPIPE rather than a signal, and the guest's own pipe-write SIGPIPE is
/// synthesised on the syscall path. Installing a host SIGPIPE handler here —
/// triggered merely because a guest registered one (e.g. LTP's tst_sig.c
/// installs handlers for every signal) — would re-route carrick's internal
/// EPIPE writes into the guest as a spurious SIGPIPE. (LTP sigaltstack01,
/// kill02, pause02/03, sigrelse01 all break this way.)
pub fn ensure_host_handler(linux_signum: i32) {
    if !(1..=63).contains(&linux_signum) || matches!(linux_signum, 9 | 13 | 17 | 19) {
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

#[cfg(test)]
mod tests {
    use super::*;

    // These tests touch process-global state (the single `PENDING` slot), so a
    // shared lock serialises them; each drains `PENDING` on entry. The
    // THREAD_PENDING map is keyed by disjoint high tids per test.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn waiter_and_pump_signal_pipes_are_distinct() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_after_supervisor_fork();
        let waiter_read = pending_pipe_read_fd();
        let pump_read = pump_pipe_read_fd();

        assert!(waiter_read >= 0);
        assert!(pump_read >= 0);
        assert_ne!(waiter_read, pump_read);
    }

    #[test]
    fn waiter_pipe_drain_does_not_consume_pump_wake() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_after_supervisor_fork();
        PENDING.store(NO_PENDING_SIGNAL, Ordering::SeqCst);

        publish_pending(LINUX_SIGINT);
        assert!(pipe_is_readable(pending_pipe_read_fd()));
        assert!(pipe_is_readable(pump_pipe_read_fd()));

        drain_pending_pipe();
        assert!(!pipe_is_readable(pending_pipe_read_fd()));
        assert!(pipe_is_readable(pump_pipe_read_fd()));

        drain_pump_pipe();
        assert!(!pipe_is_readable(pump_pipe_read_fd()));
        PENDING.store(NO_PENDING_SIGNAL, Ordering::SeqCst);
    }

    fn pipe_is_readable(fd: i32) -> bool {
        assert!(fd >= 0);
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pollfd, 1, 0) };
        assert!(rc >= 0);
        rc > 0 && (pollfd.revents & libc::POLLIN) != 0
    }

    #[test]
    fn thread_directed_takes_priority_for_its_tid() {
        let _g = TEST_LOCK.lock().unwrap();
        PENDING.store(NO_PENDING_SIGNAL, Ordering::SeqCst);
        let tid = 900_001;
        publish_pending_for(tid, LINUX_SIGINT);
        assert!(has_pending_for(tid));
        // A different tid does NOT see another thread's directed signal
        // (no process-directed signal is pending here).
        assert!(!has_pending_for(900_002));
        assert_eq!(take_pending_for(tid), LINUX_SIGINT);
        // Consumed exactly once.
        assert_eq!(take_pending_for(tid), NO_PENDING_SIGNAL);
    }

    #[test]
    fn forget_thread_drops_pending() {
        let _g = TEST_LOCK.lock().unwrap();
        PENDING.store(NO_PENDING_SIGNAL, Ordering::SeqCst);
        let tid = 900_003;
        publish_pending_for(tid, 15);
        forget_thread(tid);
        assert_eq!(take_pending_for(tid), NO_PENDING_SIGNAL);
    }

    #[test]
    fn take_pending_for_falls_back_to_process_directed() {
        let _g = TEST_LOCK.lock().unwrap();
        let tid = 900_004;
        // No thread-directed entry; a process-directed signal is deliverable by
        // any tid.
        PENDING.store(7, Ordering::SeqCst);
        assert!(has_pending_for(tid));
        assert_eq!(take_pending_for(tid), 7);
        assert_eq!(PENDING.load(Ordering::SeqCst), NO_PENDING_SIGNAL);
    }
}
