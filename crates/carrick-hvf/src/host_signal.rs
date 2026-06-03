//! Host-side signal capture and routing for guest delivery.
//!
//! THEORY OF OPERATION
//!
//! There is no guest Linux kernel to maintain per-thread pending-signal masks,
//! so this module is the bookkeeping that stands in for it. A guest signal can
//! originate three ways, and all three converge on the same "publish a pending
//! Linux signum, then wake whoever needs to deliver it" model that the runtime's
//! delivery cycle drains between vCPU iterations:
//!
//!   1. A real host UNIX signal the Carrick process catches (e.g. host `SIGINT`,
//!      or a cross-process `kill` from macOS). The async-signal-safe handler
//!      records the translated Linux signum and pokes a self-pipe.
//!   2. A guest-issued process-directed signal (`kill(getpid(), sig)`), which
//!      any thread of the process may deliver.
//!   3. A guest-issued thread-directed signal (`tgkill`/`tkill`), which targets
//!      exactly one guest tid.
//!
//! PENDING STATE. Process-directed signals land in a single `AtomicI32`
//! (`PENDING`) — set from an async signal handler, so it must stay lock-free.
//! Thread-directed signals land in `THREAD_PENDING`, a `tid -> u64 BITMASK` map:
//! a per-tid bitmask, not a single slot, because distinct signals routed to one
//! thread (libuv's `signal_multiple_loops` sends SIGUSR1 then SIGUSR2) must ALL
//! survive — a single i32 coalesced them and hung the second's waiters. Standard
//! signals still coalesce same-signal repeats; RT-signal queue depth lives in
//! the dispatcher, not here. `THREAD_PENDING` is touched only from normal
//! dispatch context (a host handler can't name a guest tid), so a plain `Mutex`
//! is safe there.
//!
//! NUMBER TRANSLATION. Linux and macOS disagree on several signal numbers
//! (SIGUSR1, SIGCHLD, SIGSTOP, SIGURG, …). `SIGNUM_XLATE` is the single source of
//! truth, applied on the SEND side (`libc::kill` to a host pid), the RECEIVE
//! side (host handler -> guest pending), and in `wait4` status decoding —
//! omitting any one of those would, e.g., turn a guest SIGUSR1 (10) into a host
//! signal 10 (SIGBUS). Signals that share a number translate as identity.
//!
//! PROMPT WAKEUP. Publishing a pending signal is useless if the target thread is
//! asleep. Three wake channels cover the three places a guest thread can be:
//!
//!   * The process-wide SELF-PIPE (`PENDING_PIPE`): every blocking-I/O waiter
//!     (`io_wait`) registers its read end on its kqueue, so a handler-written
//!     byte wakes parked waiters promptly — no 50 ms poll, no reliance on
//!     `SA_RESTART`/EINTR (it is a queue event, not a Unix signal).
//!   * A PER-THREAD wake pipe (`THREAD_WAITERS`) for thread-directed signals, so
//!     a sibling thread cannot drain the target's wake before the target's
//!     kqueue observes it.
//!   * The signal PUMP's own pipe + `EVFILT_USER` (`PUMP_PIPE`/`PUMP_KQUEUE`),
//!     which wakes the [`crate::vcpu_kick`] pump so it can kick in-guest vCPUs
//!     that are spinning in userspace (not parked in any host syscall, so the
//!     self-pipe alone can't reach them). The pump is also where SIGCHLD comes
//!     from: guest children are watched via `EVFILT_PROC`/`NOTE_EXIT`
//!     (`CHILD_WATCHES`) so no host SIGCHLD handler is installed — installing one
//!     would break `wait4`'s host-`waitpid` passthrough, since carrick reaps
//!     guest children with real host `waitpid`. `NOTE_EXIT` is readiness-only; it
//!     does NOT consume the child's status, leaving the reap to the guest.
//!
//! FORK COHERENCE. `fork(2)` does not inherit a kqueue, and the inherited
//! self-pipe is shared with the parent. [`reinit_after_fork`] tears down the
//! inherited channels and rebuilds private ones so a child's wakes are its own,
//! and clears the inherited `CHILD_WATCHES`/`THREAD_*` tables. Carrick-internal
//! fds (self-pipes, kqueues) are relocated to a high fd range
//! (`HOST_INTERNAL_FD_MIN`) above the guest's 1024-fd cap so fork
//! reinitialization can't close a low host fd the guest fd layer has reused (see
//! [`relocate_internal_fd`]).
//!
//! Installation is idempotent (`INSTALLED`/`INSTALLED_MASK`) so multiple runtime
//! instances in one host process — e.g. test runners — don't stomp each other's
//! `sigaction`. This is no longer the "one slot, Ctrl-C only" v0: it is faithful
//! enough to carry CPython, Go, Node, and libuv signal conformance, while still
//! deliberately NOT round-tripping the host kernel's own pending mask (the
//! pending model above is the authority).

use std::collections::HashMap;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use crate::linux_abi::LINUX_SIGINT;

/// Host fds at or above this value are reserved for Carrick internals. Guest
/// Linux fds are capped at 1024 by the dispatcher, so putting the signal
/// self-pipe here prevents fork reinitialization from closing a low host fd
/// that the guest pipe/socket layer has reused.
const HOST_INTERNAL_FD_MIN: i32 = 16 * 1024;
/// Fallback floor used ONLY when the host's `RLIMIT_NOFILE` cannot reach
/// [`HOST_INTERNAL_FD_MIN`] — e.g. a CI runner, or any host whose per-process fd
/// cap is below 16K. 2048 still clears the guest fd range (the dispatcher caps
/// guest fds at 1024) with margin, so internal fds keep out of the way of the
/// host fds backing guest fds; we just can't reserve as wide a band on a
/// constrained host. Normal hosts never reach this — they place internals at
/// [`HOST_INTERNAL_FD_MIN`].
const HOST_INTERNAL_FD_MIN_FALLBACK: i32 = 2048;
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
/// plain `Mutex` is safe; it is never locked from a signal handler. The value
/// is a per-tid BITMASK of pending signums (bit `signum-1`): distinct signals
/// targeting one thread must ALL be delivered, so a second must not overwrite a
/// first. A single i32 slot coalesced them — when libuv's signal_multiple_loops
/// routed SIGUSR1 then SIGUSR2 to the same thread, SIGUSR1 was overwritten and
/// its waiters hung. Same-signal repeats still coalesce (standard-signal
/// semantics); RT-signal queue depth lives in the dispatcher's
/// `rt_pending_counts`, not here.
static THREAD_PENDING: LazyLock<Mutex<HashMap<i32, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static THREAD_WAITERS: LazyLock<Mutex<HashMap<i32, ThreadWakeRegistration>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Children the guest forked, mapped from their (host == guest, mirrored) pid to
/// the guest tid of the forking parent. The signal pump watches each child via
/// `EVFILT_PROC`/`NOTE_EXIT` (macOS-native process-lifecycle tracking); on the
/// child's exit it resolves the pid through this map and publishes SIGCHLD to
/// the parent tid. This is how SIGCHLD reaches a guest handler WITHOUT installing
/// a host SIGCHLD handler — installing one would break `wait4`'s host-`waitpid`
/// passthrough (carrick reaps guest children with real host `waitpid`/`wait4`).
/// `NOTE_EXIT` is purely a readiness notification: it does NOT consume the
/// child's exit status, so the actual reap stays with the guest's `wait4`.
/// Value is `(parent_tid, exit_signal)`: the guest tid to wake on the child's
/// exit, and the signal the guest asked for (clone exit_signal / clone3
/// `exit_signal`). `0` means "no exit signal" (e.g. `clone(0)`) — the pump
/// publishes nothing in that case.
static CHILD_WATCHES: LazyLock<Mutex<HashMap<i32, (i32, i32)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct ThreadWakeRegistration {
    fds: Arc<ThreadWakeFds>,
}

struct ThreadWakeFds {
    read_fd: RawFd,
    write_fd: RawFd,
    closed: AtomicBool,
}

impl ThreadWakeFds {
    fn new(read_fd: RawFd, write_fd: RawFd) -> Self {
        Self {
            read_fd,
            write_fd,
            closed: AtomicBool::new(false),
        }
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        unsafe {
            libc::close(self.read_fd);
            if self.write_fd != self.read_fd {
                libc::close(self.write_fd);
            }
        }
    }
}

pub struct ThreadWakePipe {
    tid: i32,
    fds: Arc<ThreadWakeFds>,
}

impl ThreadWakePipe {
    pub fn read_fd(&self) -> RawFd {
        self.fds.read_fd
    }

    pub fn drain(&self) {
        drain_fd(self.fds.read_fd);
    }
}

impl Drop for ThreadWakePipe {
    fn drop(&mut self) {
        unregister_thread_waiter(self.tid, &self.fds);
    }
}

/// `THREAD_PENDING` bit for `signum` (bit `signum-1`), or 0 if out of range.
fn thread_pending_bit(signum: i32) -> u64 {
    if (1..=64).contains(&signum) {
        1u64 << (signum - 1)
    } else {
        0
    }
}

/// Lowest pending signum in a `THREAD_PENDING` bitmask (caller ensures `mask != 0`).
fn lowest_pending_signum(mask: u64) -> i32 {
    (mask.trailing_zeros() as i32) + 1
}

/// Publish a signal targeted at a specific guest `tid` and wake parked waiters.
/// The waking thread (and only it, via `take_pending_for`) will deliver it.
/// Unlike `publish_pending`, this is NOT async-signal-safe (takes a `Mutex`) —
/// call it only from normal dispatch context, which is the only place a guest
/// tid is known.
pub fn publish_pending_for(tid: i32, signum: i32) {
    crate::probes::signal_publish(tid, signum, 1);
    let bit = thread_pending_bit(signum);
    #[allow(clippy::expect_used)]
    if bit != 0 {
        *THREAD_PENDING
            .lock()
            .expect("THREAD_PENDING poisoned")
            .entry(tid)
            .or_insert(0) |= bit;
    }
    if !wake_thread_waiter(tid) {
        notify_waiters_fallback();
    }
    wake_signal_pump_pipe();
}

/// Record that guest tid `parent_tid` forked child `child_pid`, and arm an
/// `EVFILT_PROC`/`NOTE_EXIT` watch for the child on the signal pump's kqueue so
/// the pump publishes SIGCHLD to `parent_tid` when the child exits. Called from
/// the runtime's fork parent branch (normal dispatch context). No host SIGCHLD
/// handler is installed — see `CHILD_WATCHES`. If the pump kqueue is not yet
/// registered, the mapping is still recorded and the pump arms the watch when it
/// next learns the pid (we re-arm on every register); a missing watch only
/// delays SIGCHLD, never breaks `wait4`. The `EV_ONESHOT` watch (see
/// `Kevent::proc_exit`) auto-removes once it fires.
pub fn register_child_exit_watch(child_pid: i32, parent_tid: i32, exit_signal: i32) {
    if child_pid <= 0 {
        return;
    }
    // Sanitize the requested exit signal: 0 is the "no exit signal" sentinel
    // (preserved as-is); any value outside the valid signal range falls back
    // to SIGCHLD so a malformed signum still produces SIGCHLD-class behavior.
    let exit_signal = if exit_signal == 0 {
        0
    } else if (1..=64).contains(&exit_signal) {
        exit_signal
    } else {
        crate::linux_abi::LINUX_SIGCHLD
    };
    #[allow(clippy::expect_used)]
    CHILD_WATCHES
        .lock()
        .expect("CHILD_WATCHES poisoned")
        .insert(child_pid, (parent_tid, exit_signal));
    let kq = PUMP_KQUEUE.load(Ordering::SeqCst);
    if kq >= 0 {
        // ENOENT (the child already exited and was reaped before we armed) is
        // fine: the reap path delivers no SIGCHLD in that race, matching the
        // kernel's collapse of a missed wait into the eventual wait4 return.
        let _ = crate::darwin_kqueue::apply_changes(
            kq,
            &[crate::darwin_kqueue::Kevent::proc_exit(child_pid)],
        );
    }
}

/// Arm an `EVFILT_PROC`/`NOTE_EXIT` watch on `kq` for every currently-tracked
/// guest child. Called by the signal pump right after it publishes its kqueue,
/// so any child registered before the pump existed (or before it learned its
/// kqueue) is still observed. Idempotent: re-adding an existing watch is a
/// no-op; ENOENT for an already-exited child is harmless.
pub fn rearm_child_watches(kq: i32) {
    if kq < 0 {
        return;
    }
    let pids: Vec<i32> = {
        #[allow(clippy::expect_used)]
        CHILD_WATCHES
            .lock()
            .expect("CHILD_WATCHES poisoned")
            .keys()
            .copied()
            .collect()
    };
    for pid in pids {
        let _ = crate::darwin_kqueue::apply_changes(
            kq,
            &[crate::darwin_kqueue::Kevent::proc_exit(pid)],
        );
    }
}

/// Resolve a child pid whose `NOTE_EXIT` fired to the `(parent_tid,
/// exit_signal)` pair: the guest tid that should receive the exit signal and
/// the signal the guest requested at clone time, removing the entry (the watch
/// is one-shot). `None` if the pid was not a tracked guest child. Called only
/// from the signal pump.
pub fn take_child_exit_parent(child_pid: i32) -> Option<(i32, i32)> {
    #[allow(clippy::expect_used)]
    CHILD_WATCHES
        .lock()
        .expect("CHILD_WATCHES poisoned")
        .remove(&child_pid)
}

/// True iff `child_pid` is a tracked guest child (a fired `EVFILT_PROC` event's
/// `ident`). Lets the pump distinguish a child-exit event from its other wake
/// sources without consuming the mapping.
pub fn is_tracked_child(child_pid: i32) -> bool {
    #[allow(clippy::expect_used)]
    CHILD_WATCHES
        .lock()
        .expect("CHILD_WATCHES poisoned")
        .contains_key(&child_pid)
}

/// Drain the signal deliverable to `tid`: a thread-directed one for this tid
/// takes priority, otherwise the process-directed global slot. Returns `0`
/// (`NO_PENDING_SIGNAL`) if neither is set. This is the single point of
/// consumption (called under the dispatcher lock in `deliver_pending_signal`).
pub fn take_pending_for(tid: i32) -> i32 {
    #[allow(clippy::expect_used)]
    {
        let mut guard = THREAD_PENDING.lock().expect("THREAD_PENDING poisoned");
        if let Some(mask) = guard.get_mut(&tid)
            && *mask != 0
        {
            let signum = lowest_pending_signum(*mask);
            *mask &= *mask - 1; // clear the lowest set bit
            if *mask == 0 {
                guard.remove(&tid);
            }
            return signum;
        }
    }
    PENDING.swap(NO_PENDING_SIGNAL, Ordering::SeqCst)
}

/// Drain a signal pending for `tid` only if it intersects `wait_set` (bit
/// `signum-1`). Used by `rt_sigtimedwait`: signals outside the waited set must
/// remain pending for normal delivery instead of being consumed and requeued.
pub fn take_pending_in_for(tid: i32, wait_set: u64) -> i32 {
    let in_set = |signum: i32| -> bool {
        (1..=64).contains(&signum) && wait_set & (1u64 << (signum - 1)) != 0
    };
    #[allow(clippy::expect_used)]
    {
        // `wait_set` uses the same bit `signum-1` convention as the mask, so a
        // bitwise AND yields the pending signums that are in the waited set;
        // drain only the lowest, leaving the rest pending for normal delivery.
        let mut guard = THREAD_PENDING.lock().expect("THREAD_PENDING poisoned");
        if let Some(mask) = guard.get_mut(&tid) {
            let in_set_bits = *mask & wait_set;
            if in_set_bits != 0 {
                let signum = lowest_pending_signum(in_set_bits);
                *mask &= !thread_pending_bit(signum);
                if *mask == 0 {
                    guard.remove(&tid);
                }
                return signum;
            }
        }
    }
    let pending = PENDING.load(Ordering::SeqCst);
    if pending != NO_PENDING_SIGNAL
        && in_set(pending)
        && PENDING
            .compare_exchange(
                pending,
                NO_PENDING_SIGNAL,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    {
        return pending;
    }
    NO_PENDING_SIGNAL
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
        .get(&tid)
        .is_some_and(|&mask| mask != 0)
}

/// Like [`has_pending_for`], but a signal blocked by `block_mask` (bit
/// `signum-1`) does NOT count as deliverable-for-waking. Used by a blocking
/// `epoll_pwait`/`ppoll`/`pselect6` whose temporary sigmask blocks a signal:
/// the signal stays pending (delivered after the syscall, per the persistent
/// mask) but must not break the wait. `block_mask == 0` is identical to
/// [`has_pending_for`]. SIGKILL/SIGSTOP can't be blocked, matching the kernel.
pub fn has_unblocked_pending_for(tid: i32, block_mask: u64) -> bool {
    let blocked = |signum: i32| -> bool {
        signum != crate::linux_abi::LINUX_SIGKILL
            && signum != crate::linux_abi::LINUX_SIGSTOP
            && (1..=64).contains(&signum)
            && block_mask & (1u64 << (signum - 1)) != 0
    };
    let p = PENDING.load(Ordering::SeqCst);
    if p != NO_PENDING_SIGNAL && !blocked(p) {
        return true;
    }
    #[allow(clippy::expect_used)]
    let guard = THREAD_PENDING.lock().expect("THREAD_PENDING poisoned");
    // Any pending bit that isn't blocked is deliverable. SIGKILL/SIGSTOP can
    // never be blocked, so they always count even if their bit is in block_mask.
    let always_deliverable = thread_pending_bit(crate::linux_abi::LINUX_SIGKILL)
        | thread_pending_bit(crate::linux_abi::LINUX_SIGSTOP);
    guard
        .get(&tid)
        .is_some_and(|&mask| mask & (!block_mask | always_deliverable) != 0)
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

/// The signal pump's kqueue fd, or `-1` if the pump has not registered yet.
/// `setitimer` uses this to arm `EVFILT_TIMER` events on the pump's kqueue.
pub fn pump_kqueue() -> i32 {
    PUMP_KQUEUE.load(Ordering::SeqCst)
}

/// Clear the pump kqueue slot if it still names `kq`. Used when a stoppable
/// signal pump exits so a later pump is not accidentally hidden.
pub fn clear_pump_kqueue(kq: i32) {
    let _ = PUMP_KQUEUE.compare_exchange(kq, -1, Ordering::SeqCst, Ordering::SeqCst);
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
    let _ = crate::darwin_kqueue::trigger_user(kq, 0);
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn notify_pump() {}

/// Read end of the self-pipe for `io_wait::ThreadWaiter` to watch, or `-1` if
/// not yet initialised (callers then fall back to a polled wait).
pub fn pending_pipe_read_fd() -> i32 {
    PENDING_PIPE_READ.load(Ordering::SeqCst)
}

/// Register a per-thread wake pipe for thread-directed signals. Unlike the
/// process-wide self-pipe, this pipe is watched and drained only by `tid`, so a
/// sibling blocked in `kevent()` cannot consume the target's wake byte.
pub fn register_thread_waiter(tid: i32) -> Option<ThreadWakePipe> {
    let (read_fd, write_fd) = open_internal_pipe()?;
    let fds = Arc::new(ThreadWakeFds::new(read_fd, write_fd));
    let registration = ThreadWakeRegistration {
        fds: Arc::clone(&fds),
    };
    {
        #[allow(clippy::expect_used)]
        THREAD_WAITERS
            .lock()
            .expect("THREAD_WAITERS poisoned")
            .insert(tid, registration);
    }
    Some(ThreadWakePipe { tid, fds })
}

/// Read end of the signal pump's dedicated wake pipe.
pub fn pump_pipe_read_fd() -> i32 {
    PUMP_PIPE_READ.load(Ordering::SeqCst)
}

/// Wake the signal pump's dedicated pipe from normal thread context.
pub fn wake_signal_pump_pipe() {
    let pump = PUMP_PIPE_WRITE.load(Ordering::SeqCst);
    if pump >= 0 {
        let byte = [1u8];
        unsafe {
            libc::write(pump, byte.as_ptr() as *const libc::c_void, 1);
        }
    }
}

/// Wake the signal pump via BOTH channels — the dedicated pipe (EVFILT_READ)
/// and the EVFILT_USER NOTE_TRIGGER. The two race-fail independently (a fork
/// child still setting up its pipe vs. its kqueue), so `SignalPump::stop` pokes
/// both to maximise the chance the pump observes its stop flag instead of
/// parking in `kevent` and hanging the fork.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn wake_signal_pump_all() {
    wake_signal_pump_pipe();
    notify_pump();
}

/// Test/diagnostic hook: sever BOTH pump wake channels (used to prove
/// `SignalPump::stop` still returns — by detaching — when the pump can no
/// longer be woken). Not for production use.
#[doc(hidden)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn debug_break_pump_wake() {
    PUMP_PIPE_WRITE.store(-1, Ordering::SeqCst);
    PUMP_KQUEUE.store(-1, Ordering::SeqCst);
}

/// Create (or recreate) the self-pipe. If already open the old ends are closed
/// first (used by `reinit_after_fork`). Both ends are non-blocking + CLOEXEC.
fn open_pending_pipe() {
    let Some((read_fd, write_fd)) = open_internal_pipe() else {
        return;
    };
    replace_pipe(&PENDING_PIPE_READ, &PENDING_PIPE_WRITE, read_fd, write_fd);
    // The PUMP pipe is NOT created here: it is created+owned by the signal-pump
    // thread itself (see `pump_install_pipe`), AFTER it allocates its kqueue.
    // Creating it here (before the kqueue) left a window in which the pump pipe's
    // read fd could be closed and the kqueue allocated the same fd number — the
    // pump then armed EVFILT_READ on its own kqueue fd, so wake bytes never woke
    // it and `pump.stop()`'s join hung the whole process (apt fork storm).
}

/// Create a fresh signal-pump wake pipe and publish both ends, closing any prior
/// (stale or fork-inherited) pump pipe via `replace_pipe`. Called by the pump
/// thread AFTER it has allocated its kqueue, so the new read fd can never collide
/// with the kqueue fd. Returns the read end for the pump to arm on its kqueue.
pub fn pump_install_pipe() -> Option<i32> {
    let (read_fd, write_fd) = open_internal_pipe()?;
    replace_pipe(&PUMP_PIPE_READ, &PUMP_PIPE_WRITE, read_fd, write_fd);
    Some(read_fd)
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

fn unregister_thread_waiter(tid: i32, fds: &Arc<ThreadWakeFds>) {
    let removed = {
        #[allow(clippy::expect_used)]
        let mut guard = THREAD_WAITERS.lock().expect("THREAD_WAITERS poisoned");
        match guard.get(&tid) {
            Some(reg) if Arc::ptr_eq(&reg.fds, fds) => guard.remove(&tid),
            _ => None,
        }
    };
    drop(removed);
    fds.close();
}

fn clear_thread_waiters() {
    let waiters = {
        #[allow(clippy::expect_used)]
        THREAD_WAITERS
            .lock()
            .expect("THREAD_WAITERS poisoned")
            .drain()
            .map(|(_, registration)| registration.fds)
            .collect::<Vec<_>>()
    };
    for fds in waiters {
        fds.close();
    }
}

fn close_raw_fds(fds: &[i32; 2]) {
    for fd in fds {
        unsafe { libc::close(*fd) };
    }
}

fn duplicate_internal_fd(fd: i32) -> Option<i32> {
    ensure_internal_fd_range();
    // Prefer the high internal range. On a host whose RLIMIT_NOFILE cannot reach
    // it, `F_DUPFD_CLOEXEC` returns EMFILE for every fd >= HOST_INTERNAL_FD_MIN;
    // fall back to a lower floor that still clears the guest fd range, so carrick
    // keeps working (and CI runners with a low fd cap stay green) instead of
    // failing every internal-pipe allocation.
    for floor in [HOST_INTERNAL_FD_MIN, HOST_INTERNAL_FD_MIN_FALLBACK] {
        let duped = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, floor) };
        if duped >= 0 {
            return Some(duped);
        }
    }
    None
}

pub fn relocate_internal_fd(fd: i32) -> i32 {
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
    // POSIX timers registered by the parent have their fallback threads dead
    // in the child (fork copies only the calling thread). Clear the registry
    // so the child doesn't accidentally reuse the parent's timer IDs without
    // a backing thread.
    crate::posix_timer::clear();
    // The child is single-threaded (fork copies only the calling thread); any
    // sibling-directed pending entries inherited from the parent are stale.
    if let Ok(mut map) = THREAD_PENDING.lock() {
        map.clear();
    }
    // The inherited child-exit watches belong to the PARENT's children (this
    // child's siblings); the freshly-forked child must not deliver SIGCHLD for
    // them. Its own children are registered on its own re-spawned pump.
    if let Ok(mut map) = CHILD_WATCHES.lock() {
        map.clear();
    }
    clear_thread_waiters();
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
    clear_thread_waiters();
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
    wake_signal_pump_pipe();
}

fn notify_waiters_fallback() {
    let w = PENDING_PIPE_WRITE.load(Ordering::SeqCst);
    if w >= 0 {
        let byte = [1u8];
        unsafe {
            libc::write(w, byte.as_ptr() as *const libc::c_void, 1);
        }
    }
}

/// Wake every blocking-I/O waiter via the process-wide self-pipe (the channel
/// all `io_wait` kqueues watch). Used by the fork quiesce to nudge threads
/// blocked in `io_wait` back to their run-loop top so they reach the barrier.
pub fn wake_all_waiters() {
    notify_waiters_fallback();
}

fn wake_thread_waiter(tid: i32) -> bool {
    let write_fd = {
        #[allow(clippy::expect_used)]
        THREAD_WAITERS
            .lock()
            .expect("THREAD_WAITERS poisoned")
            .get(&tid)
            .map(|registration| Arc::clone(&registration.fds))
    };
    let Some(fds) = write_fd else {
        return false;
    };
    let byte = [1u8];
    let rc = unsafe { libc::write(fds.write_fd, byte.as_ptr() as *const libc::c_void, 1) };
    rc >= 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN)
}

/// Drain the self-pipe (non-blocking). Called by a waiter after it observes the
/// pipe readable so the level-triggered `EVFILT_READ` doesn't spin. Racing
/// drains across threads are harmless — `has_pending` is the source of truth.
pub fn drain_pending_pipe() {
    let r = PENDING_PIPE_READ.load(Ordering::SeqCst);
    if r < 0 {
        return;
    }
    drain_fd(r);
}

/// Drain the signal pump's dedicated wake pipe.
pub fn drain_pump_pipe() {
    let r = PUMP_PIPE_READ.load(Ordering::SeqCst);
    if r < 0 {
        return;
    }
    drain_fd(r);
}

fn drain_fd(fd: RawFd) {
    let mut buf = [0u8; 64];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
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
/// handler. Installed with `SA_SIGINFO` so it can tell a *synchronous CPU
/// fault* (a bug in carrick's own host code) from an externally-delivered
/// signal (a cross-process `kill`).
///
/// This guard is essential: the guest runs under HVF, so a *guest* fault
/// arrives as a vmexit, never as a host signal — therefore a host
/// SIGSEGV/SIGBUS/SIGILL/SIGFPE with a kernel-generated `si_code` is always a
/// carrick host bug. Without the guard, handle_routed would publish it to the
/// guest and return, the faulting host instruction would re-execute, fault
/// again, and the process would spin forever in the signal trampoline
/// (an unkillable hang that masks the real crash). On such a fault we restore
/// the default disposition and return, so the instruction re-raises and
/// carrick dies visibly with the true signal (and a core/crash report).
///
/// Async-signal-safe: only a const-table lookup, an atomic store, and (on the
/// fault path) a `sigaction` to SIG_DFL — all signal-safe.
extern "C" fn handle_routed(
    host_signum: libc::c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    let synchronous_fault = matches!(
        host_signum,
        libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGFPE | libc::SIGTRAP
    );
    if synchronous_fault && !info.is_null() {
        // si_code > 0 ⇒ generated by the hardware/kernel (a real fault at the
        // faulting PC). si_code <= 0 ⇒ SI_USER/SI_QUEUE/SI_TKILL, i.e. sent by
        // another process — those we still route to the guest.
        let code = unsafe { (*info).si_code };
        if code > 0 {
            // SAFETY: zeroed sigaction with SIG_DFL is the documented
            // "default disposition" form; signal-safe.
            unsafe {
                let mut dfl: libc::sigaction = core::mem::zeroed();
                dfl.sa_sigaction = libc::SIG_DFL;
                libc::sigemptyset(&mut dfl.sa_mask);
                libc::sigaction(host_signum, &dfl, std::ptr::null_mut());
            }
            return;
        }
    }
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
        // SA_SIGINFO so handle_routed sees si_code and can distinguish a
        // synchronous host fault (carrick bug → crash visibly) from an
        // externally-sent signal (route to the guest). SA_RESTART keeps
        // applevisor's vcpu.run from breaking on delivery.
        action.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
        libc::sigaction(host, &action, std::ptr::null_mut());
    }
}

/// Mirror a guest `SIG_IGN` disposition to the HOST disposition, so a
/// CROSS-PROCESS `kill` from a sibling guest process is DROPPED at the host
/// level (matching the guest's ignore) instead of taking macOS's default
/// action — which for most signals is to TERMINATE this carrick process. The
/// guest set `linux_signum` to `SIG_IGN`; without this, another guest process's
/// `kill(us, sig)` killed us (CPython test_interprocess_signal: the parent set
/// SIGUSR2=SIG_IGN, a child `kill`ed it, and the parent died with -12).
///
/// Excludes signals carrick must keep its own host disposition for:
///   * SIGKILL(9)/SIGSTOP(19): can't be caught or ignored.
///   * SIGPIPE(13)/SIGCHLD(17): carrick-managed (internal EPIPE / wait4).
///   * SIGINT(2): carrick keeps its own Ctrl-C handler; a guest-ignored SIGINT
///     is dropped at the dispatch layer (the routed handler marks it pending,
///     the delivery cycle sees SIG_IGN and discards it) — so the process still
///     survives a cross-process SIGINT without host-ignoring it.
///   * Synchronous faults SIGILL(4)/SIGTRAP(5)/SIGABRT(6)/SIGBUS(7)/SIGFPE(8)/
///     SIGSEGV(11): the host disposition is shared between a real synchronous
///     fault and an async kill; host-SIG_IGN'ing one would make a genuine fault
///     re-execute forever. carrick keeps catching these (handle_routed); a
///     cross-process instance is dropped at the dispatch layer instead.
pub fn set_host_ignore(linux_signum: i32) {
    if !(1..=63).contains(&linux_signum)
        || matches!(linux_signum, 2 | 4 | 5 | 6 | 7 | 8 | 9 | 11 | 13 | 17 | 19)
    {
        return;
    }
    let host = linux_to_host_signum(linux_signum);
    // SAFETY: zero-initialised sigaction with SIG_IGN is the documented
    // "ignore, no flags, empty mask" form.
    unsafe {
        let mut action: libc::sigaction = core::mem::zeroed();
        action.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        libc::sigaction(host, &action, std::ptr::null_mut());
    }
    // The host no longer routes this signal (it's ignored), so drop the
    // routed-handler bookkeeping: a later ensure_host_handler (guest installs a
    // real handler) must re-install handle_routed rather than skip as a no-op.
    INSTALLED_MASK.fetch_and(!(1u64 << linux_signum), Ordering::SeqCst);
}

/// Reset host signal dispositions that were installed only to route guest
/// caught-signal handlers. Guest `execve(2)` resets caught dispositions to
/// default while preserving `SIG_IGN`; because Carrick does not host-exec, the
/// host process would otherwise keep catching those signals after the emulated
/// disposition was gone.
pub fn reset_routed_handlers_after_execve(ignored_mask: u64) {
    for linux_signum in 1..=63 {
        if matches!(linux_signum, LINUX_SIGINT | 9 | 13 | 17 | 19) {
            continue;
        }
        let bit = 1u64 << linux_signum;
        if INSTALLED_MASK.fetch_and(!bit, Ordering::SeqCst) & bit == 0 {
            continue;
        }
        let host = linux_to_host_signum(linux_signum);
        unsafe {
            let mut action: libc::sigaction = core::mem::zeroed();
            action.sa_sigaction = if ignored_mask & bit != 0 {
                libc::SIG_IGN
            } else {
                libc::SIG_DFL
            };
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(host, &action, std::ptr::null_mut());
        }
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
    // Dispatch context (not a signal handler), so the probe is safe here —
    // unlike `publish_pending` itself, which a host handler also calls.
    crate::probes::signal_publish(0, signum, 0);
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
    fn child_exit_watch_resolves_parent_tid_once() {
        let _g = TEST_LOCK.lock().unwrap();
        // No pump kqueue published here, so register only records the mapping;
        // resolution is what the pump does on NOTE_EXIT.
        PUMP_KQUEUE.store(-1, Ordering::SeqCst);
        let child_pid = 0x7FFF_0001;
        let parent_tid = 0x7FFF_0002;
        register_child_exit_watch(child_pid, parent_tid, crate::linux_abi::LINUX_SIGCHLD);
        assert!(is_tracked_child(child_pid));
        assert_eq!(
            take_child_exit_parent(child_pid),
            Some((parent_tid, crate::linux_abi::LINUX_SIGCHLD))
        );
        // One-shot: a second resolve (a duplicate event) yields nothing.
        assert!(!is_tracked_child(child_pid));
        assert_eq!(take_child_exit_parent(child_pid), None);
    }

    #[test]
    fn child_exit_watch_ignores_invalid_pid() {
        let _g = TEST_LOCK.lock().unwrap();
        register_child_exit_watch(0, 1234, crate::linux_abi::LINUX_SIGCHLD);
        register_child_exit_watch(-1, 1234, crate::linux_abi::LINUX_SIGCHLD);
        assert!(!is_tracked_child(0));
        assert!(!is_tracked_child(-1));
    }

    #[test]
    fn reinit_after_fork_clears_child_watches() {
        let _g = TEST_LOCK.lock().unwrap();
        let child_pid = 0x7FFE_0001;
        register_child_exit_watch(child_pid, 0x7FFE_0002, crate::linux_abi::LINUX_SIGCHLD);
        assert!(is_tracked_child(child_pid));
        reinit_after_fork();
        assert!(
            !is_tracked_child(child_pid),
            "a forked child must not inherit the parent's child-exit watches"
        );
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

    #[test]
    fn thread_directed_wake_uses_target_private_pipe() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_after_supervisor_fork();
        PENDING.store(NO_PENDING_SIGNAL, Ordering::SeqCst);

        let target_tid = 900_010;
        let other_tid = 900_011;
        let target = register_thread_waiter(target_tid).expect("target waiter pipe");
        let other = register_thread_waiter(other_tid).expect("other waiter pipe");

        publish_pending_for(target_tid, LINUX_SIGINT);
        assert!(pipe_is_readable(target.read_fd()));
        assert!(!pipe_is_readable(other.read_fd()));
        assert!(!pipe_is_readable(pending_pipe_read_fd()));
        assert!(pipe_is_readable(pump_pipe_read_fd()));

        target.drain();
        drain_pump_pipe();
        assert!(!pipe_is_readable(target.read_fd()));
        assert_eq!(take_pending_for(target_tid), LINUX_SIGINT);
        drop(other);
        drop(target);
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
        drain_pending_pipe();
        drain_pump_pipe();
    }

    #[test]
    fn distinct_thread_directed_signals_do_not_coalesce() {
        let _g = TEST_LOCK.lock().unwrap();
        PENDING.store(NO_PENDING_SIGNAL, Ordering::SeqCst);
        let tid = 900_021;
        // Two DISTINCT signals routed to one tid must BOTH survive — a single
        // last-write-wins slot dropped the first (the signal_multiple_loops
        // hang). Drained lowest-first, one per take, both present.
        publish_pending_for(tid, 10); // SIGUSR1
        publish_pending_for(tid, 12); // SIGUSR2
        assert!(has_pending_for(tid));
        assert_eq!(take_pending_for(tid), 10);
        assert_eq!(take_pending_for(tid), 12);
        assert_eq!(take_pending_for(tid), NO_PENDING_SIGNAL);
        assert!(!has_pending_for(tid));
        drain_pending_pipe();
        drain_pump_pipe();
    }

    #[test]
    fn take_pending_in_for_leaves_non_matching_signals_queued() {
        let _g = TEST_LOCK.lock().unwrap();
        PENDING.store(NO_PENDING_SIGNAL, Ordering::SeqCst);
        let tid = 900_012;
        publish_pending_for(tid, 12);

        assert_eq!(
            take_pending_in_for(tid, 1u64 << (LINUX_SIGINT - 1)),
            NO_PENDING_SIGNAL
        );
        assert_eq!(take_pending_in_for(tid, 1u64 << (12 - 1)), 12);
        assert_eq!(
            take_pending_in_for(tid, 1u64 << (12 - 1)),
            NO_PENDING_SIGNAL
        );
        drain_pending_pipe();
        drain_pump_pipe();
    }

    #[test]
    fn forget_thread_drops_pending() {
        let _g = TEST_LOCK.lock().unwrap();
        PENDING.store(NO_PENDING_SIGNAL, Ordering::SeqCst);
        let tid = 900_003;
        publish_pending_for(tid, 15);
        forget_thread(tid);
        assert_eq!(take_pending_for(tid), NO_PENDING_SIGNAL);
        drain_pending_pipe();
        drain_pump_pipe();
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
