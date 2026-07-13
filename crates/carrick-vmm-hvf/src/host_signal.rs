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
//! PENDING STATE. Process-directed signals land in `PROC_PENDING`, an
//! `AtomicU64` BITMASK of pending signums (bit `signum-1`) — set from an async
//! signal handler via a lock-free `fetch_or`, so it must stay lock-free. It is a
//! bitmask, not a single slot, for the same reason `THREAD_PENDING` is: distinct
//! signals targeting one process (LTP kill10's manager sends SIGUSR1/SIGUSR2/
//! SIGQUIT to the master) must ALL survive — a single i32 slot coalesced them, so
//! the second `kill` clobbered the first and a process counting acks hung forever.
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
//!     from: guest children are watched via `EVFILT_PROC`/`NOTE_EXIT` (the
//!     neutral `carrick_signal_core::child_watch` registry records the parent
//!     tid + exit signal) so no host SIGCHLD handler is installed — installing one
//!     would break `wait4`'s host-`waitpid` passthrough, since carrick reaps
//!     guest children with real host `waitpid`. `NOTE_EXIT` is readiness-only; it
//!     does NOT consume the child's status, leaving the reap to the guest.
//!
//! FORK COHERENCE. `fork(2)` does not inherit a kqueue, and the inherited
//! self-pipe is shared with the parent. [`reinit_after_fork`] tears down the
//! inherited channels and rebuilds private ones so a child's wakes are its own,
//! and clears the inherited child-watch (`carrick_signal_core::child_watch`) /
//! `THREAD_*` tables. Carrick-internal
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

use parking_lot::Mutex;
use std::collections::HashMap;
use std::mem::ManuallyDrop;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU8, Ordering};
use std::sync::{Arc, LazyLock};

use crate::linux_abi::LINUX_SIGINT;
// The platform-NEUTRAL host-disposition mirroring policy (the shared INSTALLED_MASK
// idempotency bitmask + the `is_host_routable` base excluded-signum set) lives in
// `carrick_signal_core::host_disposition`, shared verbatim with the KVM backend so
// the two cannot drift. HVF's install/handler code below layers its own per-signum
// SKIP set + the Linux<->macOS number translation on top.
use carrick_signal_core::host_disposition;

// Platform-NEUTRAL pending bookkeeping (the THREAD_PENDING/PROC_PENDING store,
// SENDER_PID, and their pure operations) lives in `carrick-signal-core`, shared
// verbatim with the KVM backend. Re-export the neutral surface; the HVF GLUE
// below (the kqueue pump, self-pipe + per-thread wakes, and the cross-process
// xsignal ring) layers on top. `publish_pending_for`, `has_pending_for`, and
// `has_unblocked_pending_for` are NOT re-exported: HVF defines its own
// glue-wrapped versions (wakes + xsignal peek) that call the core primitives.
pub use carrick_signal_core::{
    NO_PENDING_SIGNAL, clear_proc_pending, clear_thread_pending, forget_thread,
    has_process_pending, last_sender_for, lowest_pending_signum, pending_bit, pending_thread_tids,
    proc_pending_fetch_or, record_sender, signal_unblocked_by_mask, take_pending_for,
    take_pending_in_for, take_process_pending, thread_pending_bit,
};

// The platform-NEUTRAL cross-process xsignal ring core now lives in
// `carrick-signal-core::xsig`; only the nudge SIGNAL number + nudge handler wake
// below is HVF glue. Re-export the ring surface so HVF's call sites are unchanged.
pub use carrick_signal_core::xsig::{
    mark_xsig_dirty, xsig_drain_for_self, xsig_enqueue, xsig_has_pending,
    xsig_has_unblocked_for_self, xsig_init,
};
// The fork-coherent FASYNC (signal-driven I/O) registry shares the xsignal
// ring's pre-fork MAP_SHARED lifetime; init it alongside the ring so every
// guest process inherits the one table.
pub use carrick_signal_core::fasync::fasync_init;

// The `(linux, host)` signal-number translation table that DIFFERS between Linux
// and the BSDs (SIGUSR1/SIGCHLD/SIGSTOP/SIGURG/…) is the ONE BSD-family table in
// `carrick_host_bsd::signum` — macOS shares BSD signal numbering with FreeBSD, so the
// table that was duplicated here (and again in `carrick_vmm_bhyve::bhyve_signum`)
// now lives once. Cross-process signals must be translated on the send side
// (`libc::kill`), the receive side (host handler -> guest), and in the `wait4`
// status, or e.g. a guest SIGUSR1 (10) would be sent to macOS as signal 10
// (SIGBUS). Re-exported so HVF's many call sites are unchanged.
pub use carrick_host_bsd::signum::{host_to_linux_signum, linux_to_host_signum};

fn hvf_private_thread_signal_set(set: &mut libc::sigset_t) {
    unsafe {
        libc::sigemptyset(set);
        for linux in 1..=63 {
            // Do not mask uncatchable signals, SIGCHLD/SIGPIPE special cases,
            // or host-synchronous fault/assertion signals in Apple's helper
            // threads. We only want to keep guest-routed asynchronous signals
            // off HVF-private pthreads.
            if matches!(linux, 4 | 5 | 6 | 7 | 8 | 9 | 11 | 13 | 17 | 19 | 31) {
                continue;
            }
            let host = linux_to_host_signum(linux);
            if (1..=libc::SIGUSR2).contains(&host) {
                let _ = libc::sigaddset(set, host);
            }
        }
        // Carrick's explicit cross-process signal nudge uses host SIGINFO. It
        // has no guest-signum mapping, but it is still Carrick-owned routing and
        // should not land on HVF's private helper threads.
        let _ = libc::sigaddset(set, XSIG_NUDGE_HOST_SIGNUM);
    }
}

pub struct HvfPrivateSignalMaskGuard {
    old: libc::sigset_t,
    active: bool,
}

impl Drop for HvfPrivateSignalMaskGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut());
            }
        }
    }
}

/// Temporarily block guest-routed host signals in the current thread so any
/// private pthreads HVF spawns during VM creation inherit that blocked mask.
/// Dropping the guard restores Carrick's own thread mask immediately.
pub fn block_hvf_private_thread_signals() -> HvfPrivateSignalMaskGuard {
    unsafe {
        let mut set: libc::sigset_t = core::mem::zeroed();
        let mut old: libc::sigset_t = core::mem::zeroed();
        hvf_private_thread_signal_set(&mut set);
        let active = libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old) == 0;
        HvfPrivateSignalMaskGuard { old, active }
    }
}

// The per-signum idempotency bitmask that records which signals have a mirrored
// host disposition (so `ensure_host_handler`/`set_host_ignore` are idempotent) is
// now the platform-NEUTRAL `carrick_signal_core::host_disposition::INSTALLED_MASK`
// (shared verbatim with the KVM backend, so the two cannot drift on the install
// bookkeeping). HVF reads/writes it through the neutral
// `mark_installed`/`clear_installed`/`is_installed`/`installed_mask`/`clear_all`
// helpers; the per-signum SKIP set (the HVF-specific exclusions layered on top of
// the neutral `is_host_routable` base) stays HVF glue in the install code below.

// The `child_pid -> (parent_tid, exit_signal)` registry that records, for each
// watched guest child, the guest tid to wake on the child's exit and the signal
// the guest asked for (clone exit_signal / clone3 `exit_signal`), is now the
// platform-NEUTRAL `carrick_signal_core::child_watch` core (shared verbatim with
// the KVM backend). HVF's GLUE below layers the `EVFILT_PROC`/`NOTE_EXIT` kqueue
// watch on top: the signal pump watches each registered child (macOS-native
// process-lifecycle tracking); on the child's exit it resolves the pid through
// the neutral registry and publishes the recorded exit signal to the recorded
// parent tid. This is how SIGCHLD reaches a guest handler WITHOUT installing a
// host SIGCHLD handler — installing one would break `wait4`'s host-`waitpid`
// passthrough (carrick reaps guest children with real host `waitpid`/`wait4`).
// `NOTE_EXIT` is purely a readiness notification: it does NOT consume the child's
// exit status, so the actual reap stays with the guest's `wait4`. `0` as an exit
// signal means "no exit signal" (e.g. `clone(0)`) — the pump publishes nothing.

struct ThreadWakeRegistration {
    fds: Arc<ThreadWakeFds>,
}

type ThreadWaiterMap = HashMap<i32, ThreadWakeRegistration>;

/// A waiter registry whose mutex backing can be abandoned after `fork(2)`.
///
/// A parking-lot mutex with queued parent threads is not safe to unlock or
/// relock in the single-threaded child: its copied queue references threads
/// which do not exist there. Published backings therefore live for the process
/// lifetime. The fork prepare guard preallocates a clean replacement which the
/// child can publish without allocating, unlocking, or destroying the copied
/// contended backing.
struct ForkResetWaiterRegistry {
    current: AtomicPtr<Mutex<ThreadWaiterMap>>,
}

impl ForkResetWaiterRegistry {
    fn new() -> Self {
        let backing = Box::into_raw(Box::new(Mutex::new(HashMap::new())));
        Self {
            current: AtomicPtr::new(backing),
        }
    }

    fn lock(&self) -> parking_lot::MutexGuard<'_, ThreadWaiterMap> {
        let backing = self.current.load(Ordering::SeqCst);
        // SAFETY: `new` publishes a non-null boxed mutex before the registry is
        // visible. Child resets publish another boxed mutex, and published
        // backings are intentionally never freed, so the loaded pointer remains
        // valid for the returned guard's lifetime.
        unsafe { &*backing }.lock()
    }

    fn hold_for_fork(&'static self) -> ThreadWaitersForkGuard {
        // Allocate before taking the current lock: the child branch must not
        // enter the allocator after fork while parent allocator locks may be
        // inherited from vanished threads.
        let fresh = Box::new(Mutex::new(HashMap::new()));
        let guard = self.lock();
        ThreadWaitersForkGuard {
            registry: self,
            owner_pid: unsafe { libc::getpid() },
            guard: ManuallyDrop::new(guard),
            fresh: ManuallyDrop::new(fresh),
        }
    }
}

struct ThreadWaitersForkGuard {
    registry: &'static ForkResetWaiterRegistry,
    owner_pid: libc::pid_t,
    guard: ManuallyDrop<parking_lot::MutexGuard<'static, ThreadWaiterMap>>,
    fresh: ManuallyDrop<Box<Mutex<ThreadWaiterMap>>>,
}

impl Drop for ThreadWaitersForkGuard {
    fn drop(&mut self) {
        if unsafe { libc::getpid() } == self.owner_pid {
            // SAFETY: the parent owns both values and drops this guard exactly
            // once. Unlock before freeing the unused replacement.
            unsafe {
                ManuallyDrop::drop(&mut self.guard);
                ManuallyDrop::drop(&mut self.fresh);
            }
            return;
        }

        // SAFETY: this child is the sole surviving thread and this Drop runs
        // exactly once. Move out the pre-fork allocation and publish it. The
        // inherited guard remains deliberately undropped because unlocking its
        // copied parking queue can wait forever on vanished parent threads.
        let fresh = unsafe { ManuallyDrop::take(&mut self.fresh) };
        self.registry
            .current
            .store(Box::into_raw(fresh), Ordering::SeqCst);
    }
}

static THREAD_WAITERS: LazyLock<ForkResetWaiterRegistry> =
    LazyLock::new(ForkResetWaiterRegistry::new);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainResult {
    Drained,
    Dead,
}

impl ThreadWakePipe {
    pub fn read_fd(&self) -> RawFd {
        self.fds.read_fd
    }

    pub fn drain(&self) -> DrainResult {
        drain_fd(self.fds.read_fd)
    }
}

impl Drop for ThreadWakePipe {
    fn drop(&mut self) {
        unregister_thread_waiter(self.tid, &self.fds);
    }
}

/// Publish a signal targeted at a specific guest `tid` and wake parked waiters.
/// The waking thread (and only it, via `take_pending_for`) will deliver it.
/// Unlike `publish_pending`, this is NOT async-signal-safe (takes a `Mutex`) —
/// call it only from normal dispatch context, which is the only place a guest
/// tid is known. The pending store is the neutral core's; the probe + the three
/// wake channels are HVF glue.
pub fn publish_pending_for(tid: i32, signum: i32) {
    crate::probes::signal_publish(tid, signum, 1);
    carrick_signal_core::publish_pending_for(tid, signum);
    if !wake_thread_waiter(tid) {
        notify_waiters_fallback();
    }
    wake_signal_pump_pipe();
}

/// ATFORK-PREPARE bundle for a guest `fork`: every fork-shared signal-static
/// mutex that a NON-forking auxiliary thread can hold — the child-exit
/// watcher publishing an exit (`child_watch` tables → `publish_pending_for`'s
/// `THREAD_PENDING` → `wake_thread_waiter`'s `THREAD_WAITERS`). The FORKING
/// thread acquires the bundle immediately before `libc::fork()` and drops it
/// immediately after in BOTH processes. Ordinary guards unlock normally;
/// `THREAD_WAITERS` instead publishes a preallocated empty backing in the child
/// and abandons its copied contended parking queue. A fork child therefore
/// never tries to reuse a lock whose owner or queued waiters vanished (the
/// child's `reinit_after_fork` wedge behind the execpermitchurn load TIMEOUTs).
/// The three stores are only ever locked transiently and non-nested, so the
/// bundle acquisition cannot deadlock against their users.
pub struct SignalForkLocks {
    // Declared first so its child-side reset runs before the other guards drop.
    _waiters: ThreadWaitersForkGuard,
    _child_watch: carrick_signal_core::child_watch::ChildWatchForkGuard,
    _thread_pending: carrick_signal_core::ThreadPendingForkGuard,
}

/// Acquire the atfork-prepare bundle (see [`SignalForkLocks`]). Call
/// immediately before `libc::fork()`; drop immediately after in both processes
/// to unlock parent state or publish child replacements, strictly before any
/// child-side signal reinit.
pub fn hold_signal_locks_for_fork() -> SignalForkLocks {
    let child_watch = carrick_signal_core::child_watch::hold_for_fork();
    let thread_pending = carrick_signal_core::hold_thread_pending_for_fork();
    let waiters = THREAD_WAITERS.hold_for_fork();
    SignalForkLocks {
        _waiters: waiters,
        _child_watch: child_watch,
        _thread_pending: thread_pending,
    }
}

/// Record that guest tid `parent_tid` forked child `child_pid`, and arm an
/// `EVFILT_PROC`/`NOTE_EXIT` watch for the child on the signal pump's kqueue so
/// the pump publishes SIGCHLD to `parent_tid` when the child exits. Called from
/// the runtime's fork parent branch (normal dispatch context). No host SIGCHLD
/// handler is installed — see the neutral `carrick_signal_core::child_watch`
/// registry. If the pump kqueue is not yet
/// registered, the mapping is still recorded and the pump arms the watch when it
/// next learns the pid (we re-arm on every register). The `EV_ONESHOT` watch
/// (see `Kevent::proc_exit`) auto-removes once it fires.
pub fn register_child_exit_watch(child_pid: i32, parent_tid: i32, exit_signal: i32) {
    if child_pid <= 0 {
        return;
    }
    // Record the mapping (with the 0-sentinel / SIGCHLD-fallback sanitization) in
    // the neutral child-watch core; the EVFILT_PROC arming below is HVF glue.
    carrick_signal_core::child_watch::register(child_pid, parent_tid, exit_signal);
    let kq = PUMP_KQUEUE.load(Ordering::SeqCst);
    if kq >= 0 {
        let result = crate::darwin_kqueue::apply_changes(
            kq,
            &[crate::darwin_kqueue::Kevent::proc_exit(child_pid)],
        );
        if let Err(errno) = result {
            handle_child_exit_watch_arm_error(child_pid, errno);
        } else {
            publish_child_exit_if_waitable(child_pid);
        }
    }
}

/// Arm an `EVFILT_PROC`/`NOTE_EXIT` watch on `kq` for every currently-tracked
/// guest child. Called by the signal pump right after it publishes its kqueue,
/// so any child registered before the pump existed (or before it learned its
/// kqueue) is still observed. Idempotent: re-adding an existing watch is a
/// no-op. If the child is already gone, synthesize the exit signal that the
/// missed one-shot watch can no longer publish.
pub fn rearm_child_watches(kq: i32) {
    if kq < 0 {
        return;
    }
    let pids: Vec<i32> = carrick_signal_core::child_watch::tracked_pids();
    for pid in pids {
        let result = crate::darwin_kqueue::apply_changes(
            kq,
            &[crate::darwin_kqueue::Kevent::proc_exit(pid)],
        );
        if let Err(errno) = result {
            handle_child_exit_watch_arm_error(pid, errno);
        } else {
            publish_child_exit_if_waitable(pid);
        }
    }
}

fn handle_child_exit_watch_arm_error(child_pid: i32, errno: i32) {
    if errno == libc::ESRCH || errno == libc::ENOENT {
        publish_child_exit_signal(child_pid);
    }
}

fn publish_child_exit_signal(child_pid: i32) -> bool {
    if let Some((parent_tid, exit_signal)) = take_child_exit_parent(child_pid) {
        if exit_signal != 0 {
            publish_pending_for(parent_tid, exit_signal);
        }
        true
    } else {
        false
    }
}

fn publish_child_exit_if_waitable(child_pid: i32) -> bool {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            child_pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    if rc != 0 {
        return false;
    }
    if info.si_pid == child_pid
        && matches!(
            info.si_code,
            libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
        )
    {
        return publish_child_exit_signal(child_pid);
    }
    false
}

/// Resolve a child pid whose `NOTE_EXIT` fired to the `(parent_tid,
/// exit_signal)` pair: the guest tid that should receive the exit signal and
/// the signal the guest requested at clone time, removing the entry (the watch
/// is one-shot). `None` if the pid was not a tracked guest child. Called only
/// from the signal pump.
pub fn take_child_exit_parent(child_pid: i32) -> Option<(i32, i32)> {
    carrick_signal_core::child_watch::take(child_pid)
}

/// Pop a backend-recorded child-exit `waitid` payload for the next delivery of
/// `exit_signal` to `parent_tid`. HVF's kqueue path currently does not record a
/// payload here, but the runtime host-signal surface is shared with KVM/bhyve.
pub fn take_child_exit_siginfo(
    parent_tid: i32,
    exit_signal: i32,
) -> Option<carrick_signal_core::child_watch::ChildExitSiginfo> {
    carrick_signal_core::child_watch::take_siginfo(parent_tid, exit_signal)
}

/// True iff `child_pid` is a tracked guest child (a fired `EVFILT_PROC` event's
/// `ident`). Lets the pump distinguish a child-exit event from its other wake
/// sources without consuming the mapping.
pub fn is_tracked_child(child_pid: i32) -> bool {
    carrick_signal_core::child_watch::is_tracked(child_pid)
}

/// Is a signal deliverable to `tid` pending? True for a thread-directed signal
/// for this tid OR any process-directed signal. Used by a thread parked in
/// `kevent`/`futex` to decide whether to break its wait so the trap loop can
/// run delivery — without waking siblings for a signal that isn't theirs. Wraps
/// the neutral core check with the HVF xsignal-ring peek.
pub fn has_pending_for(tid: i32) -> bool {
    if xsig_has_unblocked_for_self(carrick_abi::SigBlockMask::NONE) {
        return true;
    }
    carrick_signal_core::has_pending_for(tid)
}

/// Like [`has_pending_for`], but a signal blocked by `block_mask` does NOT
/// count as deliverable-for-waking. Used by a blocking
/// `epoll_pwait`/`ppoll`/`pselect6` whose temporary sigmask blocks a signal:
/// the signal stays pending (delivered after the syscall, per the persistent
/// mask) but must not break the wait. `SigBlockMask::NONE` is identical to
/// [`has_pending_for`]. SIGKILL/SIGSTOP can't be blocked, matching the kernel.
/// Wraps the neutral core check with the HVF xsignal-ring peek.
pub fn has_unblocked_pending_for(tid: i32, block_mask: carrick_abi::SigBlockMask) -> bool {
    // A queued cross-process signal may be sitting in the xsignal ring. Peek at
    // the ring without consuming it so a temporary ppoll/epoll_pwait mask can
    // keep genuinely blocked signals pending until the syscall returns.
    if xsig_has_unblocked_for_self(block_mask) {
        return true;
    }
    carrick_signal_core::has_unblocked_pending_for(tid, block_mask)
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
        THREAD_WAITERS.lock().insert(tid, registration);
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
        let mut guard = THREAD_WAITERS.lock();
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

pub use carrick_host_bsd::{duplicate_internal_fd, relocate_internal_fd};

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
    // Interval timers (setitimer/alarm) are NOT inherited across fork on Linux
    // (POSIX: a fork child starts with all timers cleared). The neutral
    // itimer-core slot state is copied by libc::fork; without this clear the
    // child's re-spawned signal pump reconcile loop (vcpu_kick.rs) re-registers
    // the inherited armed EVFILT_TIMER and the child wrongly receives the
    // parent's SIGALRM (LTP alarm07). Mirrors the KVM reinit_after_fork.
    crate::itimer::clear();
    // The child is single-threaded (fork copies only the calling thread); any
    // sibling-directed pending entries inherited from the parent are stale.
    clear_thread_pending();
    // The inherited child-exit watches belong to the PARENT's children (this
    // child's siblings); the freshly-forked child must not deliver SIGCHLD for
    // them. Its own children are registered on its own re-spawned pump.
    carrick_signal_core::child_watch::clear();
    clear_thread_waiters();
    clear_proc_pending();
}

/// Reset inherited host-signal state in the runtime child after the
/// interactive session supervisor forks. This runs before the HVF runtime
/// installs default handlers, so the child does not inherit stale pending
/// signals, routed-handler bookkeeping, or the supervisor's self-pipe fds.
pub fn reset_after_supervisor_fork() {
    INSTALLED.store(0, Ordering::SeqCst);
    host_disposition::clear_all();
    clear_thread_pending();
    clear_thread_waiters();
    clear_proc_pending();
    // The supervisor's child-exit watches belong to ITS children; the runtime
    // child must not reap or deliver their exit signals. Harmless today (the
    // supervisor forks before any guest fork, so the watch map is empty), but
    // matches the KVM runtime `reset_after_supervisor_fork` (lib.rs) and the
    // HVF guest-fork `reset_after_fork` above, both of which clear it.
    carrick_signal_core::child_watch::clear();
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

fn wake_thread_waiter_fds(fds: &ThreadWakeFds) -> bool {
    let byte = [1u8];
    let rc = unsafe { libc::write(fds.write_fd, byte.as_ptr() as *const libc::c_void, 1) };
    rc >= 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN)
}

/// Wake every blocking-I/O waiter. The process-wide self-pipe is useful as a
/// fallback, but it is not a reliable broadcast: all waiters share one read fd,
/// and one waiter can drain the byte before siblings observe it. Fork quiesce
/// needs every parked vCPU thread to return to the run-loop barrier, so also
/// nudge each registered per-thread wake pipe.
pub fn wake_all_waiters() {
    notify_waiters_fallback();
    let waiters: Vec<Arc<ThreadWakeFds>> = {
        #[allow(clippy::expect_used)]
        THREAD_WAITERS
            .lock()
            .values()
            .map(|registration| Arc::clone(&registration.fds))
            .collect()
    };
    for fds in waiters {
        let _ = wake_thread_waiter_fds(&fds);
    }
}

fn wake_thread_waiter(tid: i32) -> bool {
    let write_fd = {
        #[allow(clippy::expect_used)]
        THREAD_WAITERS
            .lock()
            .get(&tid)
            .map(|registration| Arc::clone(&registration.fds))
    };
    let Some(fds) = write_fd else {
        return false;
    };
    wake_thread_waiter_fds(&fds)
}

/// Drain the self-pipe (non-blocking). Called by a waiter after it observes the
/// pipe readable so queued wake bytes do not keep the source readable. Racing
/// drains across threads are harmless — `has_pending` is the source of truth.
pub fn drain_pending_pipe() -> DrainResult {
    let r = PENDING_PIPE_READ.load(Ordering::SeqCst);
    if r < 0 {
        return DrainResult::Dead;
    }
    drain_fd(r)
}

/// Drain the signal pump's dedicated wake pipe.
pub fn drain_pump_pipe() -> DrainResult {
    let r = PUMP_PIPE_READ.load(Ordering::SeqCst);
    if r < 0 {
        return DrainResult::Dead;
    }
    drain_fd(r)
}

pub(crate) fn drain_fd(fd: RawFd) -> DrainResult {
    // Wake pipes are created non-blocking, but fork/fd churn must not turn a
    // drain into an unbounded host read if that invariant is violated.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl < 0 {
        return DrainResult::Dead;
    }
    if fl & libc::O_NONBLOCK == 0
        && unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) } != 0
    {
        return DrainResult::Dead;
    }
    let mut buf = [0u8; 64];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            continue;
        }
        if n == 0 {
            return DrainResult::Dead;
        }
        let errno = std::io::Error::last_os_error().raw_os_error();
        if errno == Some(libc::EINTR) {
            continue;
        }
        if errno == Some(libc::EAGAIN) || errno == Some(libc::EWOULDBLOCK) {
            return DrainResult::Drained;
        }
        break;
    }
    DrainResult::Dead
}

// SENDER_PID, `record_sender`, and `last_sender_for` are neutral and live in
// `carrick-signal-core` (re-exported above). `handle_routed` overwrites the
// sender on each cross-process arrival and `raise_for_self` records self, so a
// stale cross-process value never leaks into a self-raise.

// ---- Cross-process explicit-signal delivery (the "xsignal" ring) ----
//
// Some signals can't be carried to another carrick process by a plain host
// `kill` (the runtime decides which — see signal::cross_process_needs_xsig):
//   * a guest-SENT SIGCHLD — a host SIGCHLD is consumed by the wait4/kqueue
//     child-exit pump, so the target's guest SIGCHLD handler never runs
//     (LTP kill12's parent waits forever for the child's SIGCHLD readiness);
//   * a synchronous-fault signal (SIGILL/SIGTRAP/SIGABRT/SIGBUS/SIGFPE/SIGSEGV)
//     whose guest SIG_IGN can't be mirrored onto the host fault disposition
//     (shared with a genuine guest fault) — a host `kill` of one would take the
//     host default action and core-dump the receiver (LTP kill12's SIG_IGN loop);
//   * a real-time signal (32..=64) — macOS has no such signal number, so the
//     host `kill` would EINVAL.
// For these the sender writes an entry into a MAP_SHARED ring (inherited across
// fork, so every carrick process shares ONE ring) and nudges the target with a
// host signal NO guest signal maps to — SIGINFO (29); Linux 29 is SIGIO, which
// maps to host 23, so host 29 is free. The target's nudge handler sets a dirty
// flag + wakes parked waiters; the runtime drains the ring in DISPATCH context
// (where it can take locks) and publishes each signal to the guest with the
// sender's ns-pid + sigval.

// The platform-NEUTRAL ring core (the slot/ring layout, the `MAP_SHARED|MAP_ANON`
// allocation, enqueue, drain, dirty flag, and the deliverable-for-self peek) now
// lives in `carrick_signal_core::xsig` (re-exported above). Only the nudge SIGNAL
// number + the nudge handler wake below is HVF glue.

/// Host SIGINFO — the "drain your xsignal ring" nudge (free; see above).
const XSIG_NUDGE_HOST_SIGNUM: i32 = 29;

/// Whether the host signal `host_signum` is the xsignal nudge.
pub fn is_xsig_nudge(host_signum: i32) -> bool {
    host_signum == XSIG_NUDGE_HOST_SIGNUM
}

/// Nudge `target_host_pid` to drain its xsignal entries (host SIGINFO).
pub fn xsig_nudge(target_host_pid: i32) {
    unsafe {
        libc::kill(target_host_pid, XSIG_NUDGE_HOST_SIGNUM);
    }
}

/// The xsignal nudge handler: a guest process queued a SIGCHLD/RT for us. Just
/// flag + wake (async-signal-safe); the real drain runs in dispatch context. The
/// dirty flag is the neutral core's (set via `mark_xsig_dirty`); `notify_pending`
/// is the HVF self-pipe wake.
extern "C" fn handle_xsig_nudge(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    carrick_signal_core::xsig::mark_xsig_dirty();
    notify_pending();
}

/// Publish a pending guest signum AND wake parked waiters. The `fetch_or` (a
/// lock-free atomic OR into the process-directed bitmask) + the pipe write are
/// both async-signal-safe, so this is callable from a host signal handler.
/// Distinct concurrent signums accumulate rather than clobber one another; a
/// same-signum repeat coalesces (standard-signal semantics). The lock-free store
/// is the neutral core's; `notify_pending` is the HVF self-pipe wake.
fn publish_pending(signum: i32) {
    let bit = thread_pending_bit(signum); // bit `signum-1`, 0 if out of range
    if bit != 0 {
        proc_pending_fetch_or(bit);
    }
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

/// The HVF [`carrick_signal_core::HostSignalGlue`]: HVF's signal characteristics
/// expressed for the SHARED `carrick_signal_core::host_glue` disposition driver,
/// so HVF's `ensure_host_handler` / `set_host_ignore` / `set_host_default` /
/// `reset_routed_handlers_after_execve` (and the routed handler,
/// `host_glue::shared_routed_handler::<HvfGlue>`) are the SAME generic code
/// KVM/bhyve/NVMM use. The old hand-rolled `handle_routed` + four disposition fns
/// are gone; only this ~30-line glue remains, and it shares the cross-process
/// pending table (HVF already uses `carrick_signal_core::proc_pending_fetch_or`).
///
/// HVF differs from the signal-based backends in two load-bearing ways, both
/// expressed here: (1) it ROUTES the synchronous-fault set (a sibling
/// `kill -SEGV` must reach the guest) and tells a REAL CPU fault apart via
/// [`is_synchronous_self_fault`](carrick_signal_core::HostSignalGlue::is_synchronous_self_fault)
/// — under HVF a guest fault is a vmexit, so a host SIGSEGV with a
/// kernel-generated `si_code` is always carrick's own bug and must crash visibly,
/// not re-execute forever; (2) it kicks vCPUs with `hv_vcpus_exit`, NOT a signal,
/// so the kick methods are unused stubs (the disposition path never consults
/// them — every `skip_*` is overridden).
pub struct HvfGlue;

impl carrick_signal_core::HostSignalGlue for HvfGlue {
    // ── stubs: HVF kicks via `hv_vcpus_exit`, not a signal; never consulted by
    //    the disposition path (every `skip_*` below is overridden). ──
    fn kick_signal() -> i32 {
        // Unused: HVF has no signal-based kick. A sentinel past the routable range.
        33
    }
    fn install_kick_handler() {}
    fn is_claimed(linux_signum: i32) -> bool {
        // Unused for HVF's disposition (every `skip_*` is overridden); reported as
        // the uncatchable / carrick-managed set for completeness.
        !carrick_host_bsd::signum::linux_signum_has_host_carrier(linux_signum)
            || matches!(linux_signum, 9 | 13 | 17 | 19)
    }

    // ── real HVF signal characteristics ──
    fn host_to_linux(host_signum: i32) -> i32 {
        host_to_linux_signum(host_signum)
    }
    fn linux_to_host(linux_signum: i32) -> i32 {
        linux_to_host_signum(linux_signum)
    }
    fn poke() {
        notify_pending();
    }

    /// HVF ROUTES the fault set, so it skips a SMALLER install set than the
    /// neutral default: only the uncatchable (SIGKILL 9 / SIGSTOP 19) and the
    /// carrick-managed SIGPIPE(13)/SIGCHLD(17). (Was `ensure_host_handler`'s skip.)
    fn skip_install_routing(linux_signum: i32) -> bool {
        !(1..=63).contains(&linux_signum)
            || !carrick_host_bsd::signum::linux_signum_has_host_carrier(linux_signum)
            || matches!(linux_signum, 9 | 13 | 17 | 19)
    }

    /// Mirroring a guest SIG_IGN/SIG_DFL ALSO skips the fault set + SIGINT:
    /// host-`SIG_IGN`ing a synchronous fault would let a real fault re-execute
    /// forever, and carrick keeps its own SIGINT handler. (Was the
    /// `set_host_ignore`/`set_host_default` skip.)
    fn skip_ignore_mirror(linux_signum: i32) -> bool {
        !(1..=63).contains(&linux_signum)
            || !carrick_host_bsd::signum::linux_signum_has_host_carrier(linux_signum)
            || matches!(linux_signum, 2 | 4 | 5 | 6 | 7 | 8 | 9 | 11 | 13 | 17 | 19)
    }

    /// The execve reset skips SIGINT + the uncatchable/managed set (the shared
    /// loop's own install-mask check handles the rest). (Was
    /// `reset_routed_handlers_after_execve`'s skip.)
    fn skip_execve_reset(linux_signum: i32) -> bool {
        !carrick_host_bsd::signum::linux_signum_has_host_carrier(linux_signum)
            || matches!(linux_signum, LINUX_SIGINT | 9 | 13 | 17 | 19)
    }

    /// A real synchronous CPU fault (carrick's OWN bug, must crash visibly): the
    /// Linux fault set SIGILL(4)/SIGTRAP(5)/SIGBUS(7)/SIGFPE(8)/SIGSEGV(11) with a
    /// kernel-generated code. Darwin reports AArch64 `brk` as SIGTRAP with
    /// `(si_code=0, si_pid=0)`, so include that no-sender shape too. (NOT
    /// SIGABRT(6) — it was not in the historical `handle_routed` host set.) An
    /// async cross-process `kill` carries sender identity and is routed to the
    /// guest.
    fn is_synchronous_self_fault(linux_signum: i32, si_code: i32, si_pid: i32) -> bool {
        matches!(linux_signum, 4 | 5 | 7 | 8 | 11)
            && (si_code > 0 || (linux_signum == 5 && si_code == 0 && si_pid == 0))
    }
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
    carrick_signal_core::host_glue::ensure_host_handler::<HvfGlue>(linux_signum);
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
    carrick_signal_core::host_glue::set_host_ignore::<HvfGlue>(linux_signum);
}

/// Reset a guest-mirrorable signal's HOST disposition back to `SIG_DFL` — the
/// companion of [`set_host_ignore`]/[`ensure_host_handler`]. When the guest sets
/// `SIG_DFL`, any host `SIG_IGN` or routed handler that was mirrored earlier (and
/// INHERITED across fork) must be cleared, or the host swallows the signal.
///
/// This is what makes job control work: a job-control shell sets SIGTSTP/SIGTTIN/
/// SIGTTOU to `SIG_IGN` for itself, which carrick mirrors to the host; each forked
/// child then resets those to `SIG_DFL` BEFORE `execve` so the controlling pty's
/// ^Z/^C act on the job. Without this reset the child inherits the host `SIG_IGN`
/// and the pty's SIGTSTP is *discarded* — Ctrl-Z does nothing. Same exclusions as
/// [`set_host_ignore`]: carrick-managed / synchronous-fault signals keep their
/// host routing (resetting them to default would let a host-delivered instance
/// take the lethal default action or break carrick's fault handling).
pub fn set_host_default(linux_signum: i32) {
    carrick_signal_core::host_glue::set_host_default::<HvfGlue>(linux_signum);
}

/// Reset host signal dispositions that were installed only to route guest
/// caught-signal handlers. Guest `execve(2)` resets caught dispositions to
/// default while preserving `SIG_IGN`; because Carrick does not host-exec, the
/// host process would otherwise keep catching those signals after the emulated
/// disposition was gone.
pub fn reset_routed_handlers_after_execve(ignored: carrick_abi::SigSet) {
    carrick_signal_core::host_glue::reset_routed_handlers_after_execve::<HvfGlue>(ignored);
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
    // Cross-process explicit-signal (xsignal) ring + its SIGINFO nudge handler.
    // The ring is MAP_SHARED so every carrick process shares it; both it and the
    // SIGINFO disposition are inherited across fork (this runs once per process
    // via the INSTALLED guard; the forked child keeps the inherited copies).
    xsig_init();
    // The FASYNC registry is MAP_SHARED with the same pre-fork lifetime as the
    // xsignal ring; map it here so a writer process can look up a reader's
    // signal-driven-I/O arming.
    fasync_init();
    // SAFETY: zero-initialised sigaction; we fill sa_sigaction before libc.
    unsafe {
        let mut action: libc::sigaction = core::mem::zeroed();
        action.sa_sigaction = handle_xsig_nudge as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
        libc::sigaction(XSIG_NUDGE_HOST_SIGNUM, &action, std::ptr::null_mut());
    }
}

/// Drain the lowest process-directed pending signum. Returns `0` if none.
/// Atomic so the runtime can call this from any thread that's about to
/// re-enter `vcpu.run`; other pending signums stay in the mask.
pub fn take_pending() -> i32 {
    take_process_pending()
}

/// Non-draining peek: is a signal currently pending? Used by a thread parked
/// in `futex` to decide whether to interrupt its wait so the trap loop can
/// deliver the signal. Does NOT consume it — `take_pending` (under the kernel
/// lock) is still the single point of delivery.
pub fn has_pending() -> bool {
    has_process_pending()
}

/// Set a pending guest signum from inside the guest itself (e.g. from
/// `kill(self, SIGINT)`). Lets the runtime's signal-injection path
/// service synthetic raises the same way it services host SIGINT.
pub fn raise_for_self(signum: i32) {
    // Dispatch context (not a signal handler), so the probe is safe here —
    // unlike `publish_pending` itself, which a host handler also calls.
    crate::probes::signal_publish(0, signum, 0);
    // The sender is THIS process; record it so the delivery path's si_pid is
    // self (and never a stale cross-process sender left from a prior signal).
    record_sender(signum, unsafe { libc::getpid() });
    publish_pending(signum);
}

/// Crate-test-shared lock serialising every test that touches process-global
/// pump-pipe / kqueue / `PENDING` state. It lives at module scope (not inside
/// `mod tests`) so sibling test modules — `vcpu_kick::tests`,
/// `fork_coord::tests` — that spawn or sever the signal pump can acquire the
/// SAME lock and never race the pump-assertion tests here. Acquire it via
/// `pump_state_test_guard()`.
#[cfg(test)]
pub(crate) static PUMP_STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the crate-test-shared pump-state lock. `parking_lot::Mutex` does not
/// poison, so this simply blocks until the guard is available.
#[cfg(test)]
pub(crate) fn pump_state_test_guard() -> parking_lot::MutexGuard<'static, ()> {
    PUMP_STATE_TEST_LOCK.lock()
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests touch process-global state (the single `PENDING` slot) plus
    // the global pump pipe/kqueue, so a shared lock serialises them; each drains
    // `PENDING` on entry. The THREAD_PENDING map is keyed by disjoint high tids
    // per test. This is the SAME lock the vcpu_kick/fork_coord pump tests take.
    use super::PUMP_STATE_TEST_LOCK as TEST_LOCK;

    /// Open a fresh pump wake pipe for a unit test. The pump pipe is normally
    /// created by the signal-pump thread (`pump_install_pipe`), which does not
    /// run in unit tests, so tests that assert on pump-pipe readability must
    /// open it themselves rather than depend on another test having done so
    /// (libtest collection order is not stable).
    fn ensure_pump_pipe_for_test() {
        let _ = pump_install_pipe();
    }

    fn wait_for_child_exit_bounded(pid: libc::pid_t, timeout: std::time::Duration) -> i32 {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if waited == pid {
                return status;
            }
            assert_eq!(
                waited,
                0,
                "waitpid({pid}) failed: {}",
                std::io::Error::last_os_error()
            );
            if std::time::Instant::now() >= deadline {
                let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
                let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
                panic!("child {pid} did not exit within {timeout:?}; status=0x{status:x}");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn fork_child_resets_contended_thread_waiters() {
        let _fork_serial = crate::fork_test_lock();
        let _g = TEST_LOCK.lock();
        reset_after_supervisor_fork();

        let signal_locks = hold_signal_locks_for_fork();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            started_tx
                .send(())
                .expect("report waiter-lock contention start");
            let _waiters = THREAD_WAITERS.lock();
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("contender reaches waiter lock");
        std::thread::sleep(std::time::Duration::from_millis(50));

        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            drop(signal_locks);
            reinit_after_fork();
            unsafe { libc::_exit(0) };
        }

        drop(signal_locks);
        contender.join().expect("waiter contender exits");
        let status = wait_for_child_exit_bounded(child, std::time::Duration::from_secs(2));
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn waiter_and_pump_signal_pipes_are_distinct() {
        let _g = TEST_LOCK.lock();
        reset_after_supervisor_fork();
        ensure_pump_pipe_for_test();
        let waiter_read = pending_pipe_read_fd();
        let pump_read = pump_pipe_read_fd();

        assert!(waiter_read >= 0);
        assert!(pump_read >= 0);
        assert_ne!(waiter_read, pump_read);
    }

    #[test]
    fn child_exit_watch_resolves_parent_tid_once() {
        let _g = TEST_LOCK.lock();
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
        let _g = TEST_LOCK.lock();
        register_child_exit_watch(0, 1234, crate::linux_abi::LINUX_SIGCHLD);
        register_child_exit_watch(-1, 1234, crate::linux_abi::LINUX_SIGCHLD);
        assert!(!is_tracked_child(0));
        assert!(!is_tracked_child(-1));
    }

    #[test]
    fn missed_child_exit_watch_publishes_exit_signal_once() {
        let _g = TEST_LOCK.lock();
        reset_after_supervisor_fork();
        PUMP_KQUEUE.store(-1, Ordering::SeqCst);
        let child_pid = 0x7FFD_0001;
        let parent_tid = 0x7FFD_0002;

        register_child_exit_watch(child_pid, parent_tid, crate::linux_abi::LINUX_SIGCHLD);
        assert!(publish_child_exit_signal(child_pid));

        assert!(!is_tracked_child(child_pid));
        assert_eq!(
            take_pending_for(parent_tid),
            crate::linux_abi::LINUX_SIGCHLD
        );
        assert_eq!(take_pending_for(parent_tid), NO_PENDING_SIGNAL);
        assert!(!publish_child_exit_signal(child_pid));
        drain_pump_pipe();
    }

    #[test]
    fn waitable_child_exit_check_publishes_without_reaping() {
        let _fork_serial = crate::fork_test_lock();
        let _g = TEST_LOCK.lock();
        reset_after_supervisor_fork();
        PUMP_KQUEUE.store(-1, Ordering::SeqCst);
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            unsafe {
                libc::_exit(0);
            }
        }
        let parent_tid = 0x7FFD_0102;
        register_child_exit_watch(child, parent_tid, crate::linux_abi::LINUX_SIGCHLD);

        let mut published = false;
        for _ in 0..100 {
            if publish_child_exit_if_waitable(child) {
                published = true;
                break;
            }
            unsafe {
                libc::usleep(10_000);
            }
        }
        assert!(published, "waitable child exit was not published");
        assert_eq!(
            take_pending_for(parent_tid),
            crate::linux_abi::LINUX_SIGCHLD
        );

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        drain_pump_pipe();
    }

    #[test]
    fn missed_child_exit_watch_honors_zero_exit_signal() {
        let _g = TEST_LOCK.lock();
        reset_after_supervisor_fork();
        PUMP_KQUEUE.store(-1, Ordering::SeqCst);
        let child_pid = 0x7FFD_0011;
        let parent_tid = 0x7FFD_0012;

        register_child_exit_watch(child_pid, parent_tid, 0);
        assert!(publish_child_exit_signal(child_pid));

        assert!(!is_tracked_child(child_pid));
        assert_eq!(take_pending_for(parent_tid), NO_PENDING_SIGNAL);
        drain_pump_pipe();
    }

    #[test]
    fn reinit_after_fork_clears_child_watches() {
        let _g = TEST_LOCK.lock();
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
        let _g = TEST_LOCK.lock();
        reset_after_supervisor_fork();
        clear_proc_pending();
        ensure_pump_pipe_for_test();

        publish_pending(LINUX_SIGINT);
        assert!(pipe_is_readable(pending_pipe_read_fd()));
        assert!(pipe_is_readable(pump_pipe_read_fd()));

        drain_pending_pipe();
        assert!(!pipe_is_readable(pending_pipe_read_fd()));
        assert!(pipe_is_readable(pump_pipe_read_fd()));

        drain_pump_pipe();
        assert!(!pipe_is_readable(pump_pipe_read_fd()));
        clear_proc_pending();
    }

    #[test]
    fn drain_fd_forces_empty_pipe_nonblocking() {
        let _g = TEST_LOCK.lock();
        let (read_fd, write_fd) = open_internal_pipe().expect("internal pipe");
        unsafe {
            let fl = libc::fcntl(read_fd, libc::F_GETFL);
            assert!(fl >= 0);
            assert!(fl & libc::O_NONBLOCK != 0);
            assert_eq!(
                libc::fcntl(read_fd, libc::F_SETFL, fl & !libc::O_NONBLOCK),
                0
            );
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let start = std::time::Instant::now();
        let handle = std::thread::spawn(move || {
            drain_fd(read_fd);
            let _ = tx.send(start.elapsed());
            unsafe { libc::close(read_fd) };
        });

        let elapsed = match rx.recv_timeout(std::time::Duration::from_millis(50)) {
            Ok(elapsed) => elapsed,
            Err(err) => {
                unsafe { libc::close(write_fd) };
                let _ = rx.recv_timeout(std::time::Duration::from_secs(1));
                handle
                    .join()
                    .expect("drain thread exits after writer close");
                panic!("drain_fd blocked on an empty internal pipe: {err}");
            }
        };

        unsafe { libc::close(write_fd) };
        handle.join().expect("drain thread exits");
        assert!(elapsed < std::time::Duration::from_millis(50));
    }

    #[test]
    fn drain_fd_reports_dead_on_eof() {
        let _g = TEST_LOCK.lock();
        let (read_fd, write_fd) = open_internal_pipe().expect("internal pipe");
        assert_eq!(unsafe { libc::close(write_fd) }, 0);
        assert_eq!(drain_fd(read_fd), DrainResult::Dead);
        assert_eq!(unsafe { libc::close(read_fd) }, 0);
    }

    #[test]
    fn thread_directed_wake_uses_target_private_pipe() {
        let _g = TEST_LOCK.lock();
        reset_after_supervisor_fork();
        clear_proc_pending();
        ensure_pump_pipe_for_test();

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

    #[test]
    fn wake_all_waiters_broadcasts_to_private_pipes() {
        let _g = TEST_LOCK.lock();
        reset_after_supervisor_fork();
        clear_proc_pending();

        let first = register_thread_waiter(900_040).expect("first waiter pipe");
        let second = register_thread_waiter(900_041).expect("second waiter pipe");

        wake_all_waiters();
        assert!(pipe_is_readable(pending_pipe_read_fd()));
        assert!(pipe_is_readable(first.read_fd()));
        assert!(pipe_is_readable(second.read_fd()));

        drain_pending_pipe();
        first.drain();
        second.drain();
        assert!(!pipe_is_readable(pending_pipe_read_fd()));
        assert!(!pipe_is_readable(first.read_fd()));
        assert!(!pipe_is_readable(second.read_fd()));
        drop(second);
        drop(first);
    }

    #[test]
    fn hvf_private_signal_mask_guard_restores_current_thread_mask() {
        let _g = TEST_LOCK.lock();
        let before = signal_is_blocked(libc::SIGUSR1);
        {
            let _guard = block_hvf_private_thread_signals();
            assert!(signal_is_blocked(libc::SIGUSR1));
            assert!(signal_is_blocked(libc::SIGALRM));
            assert!(!signal_is_blocked(libc::SIGTRAP));
        }
        assert_eq!(signal_is_blocked(libc::SIGUSR1), before);
    }

    #[test]
    fn darwin_brk_trap_is_classified_as_host_fault() {
        use carrick_signal_core::HostSignalGlue;

        assert!(
            HvfGlue::is_synchronous_self_fault(5, 0, 0),
            "Darwin AArch64 brk reports SIGTRAP as si_code=0, si_pid=0"
        );
        assert!(
            !HvfGlue::is_synchronous_self_fault(5, 0, 44_001),
            "a sender pid still routes as an async guest signal"
        );
        assert!(HvfGlue::is_synchronous_self_fault(11, 1, 0));
        assert!(!HvfGlue::is_synchronous_self_fault(6, 0, 0));
    }

    #[test]
    fn zero_sender_does_not_clobber_last_real_sender() {
        let _g = TEST_LOCK.lock();
        record_sender(12, 44_001);
        record_sender(12, 0);
        assert_eq!(last_sender_for(12), 44_001);
    }

    #[test]
    fn xsignal_peek_honors_temporary_block_mask() {
        let _g = TEST_LOCK.lock();
        reset_after_supervisor_fork();
        clear_proc_pending();
        xsig_init();
        let _ = xsig_drain_for_self();

        let signum = crate::linux_abi::LINUX_SIGUSR1;
        let blocked =
            carrick_abi::SigBlockMask::blocking_all_of(carrick_abi::SigSet::EMPTY.with(signum));
        assert!(xsig_enqueue(
            std::process::id() as i32,
            signum,
            0,
            42,
            0,
            0,
            0
        ));
        mark_xsig_dirty();

        assert!(has_pending_for(900_050));
        assert!(has_unblocked_pending_for(
            900_050,
            carrick_abi::SigBlockMask::NONE
        ));
        assert!(!has_unblocked_pending_for(900_050, blocked));
        assert!(has_unblocked_pending_for(
            900_050,
            carrick_abi::SigBlockMask::blocking_all_of(
                carrick_abi::SigSet::EMPTY.with(crate::linux_abi::LINUX_SIGUSR2)
            )
        ));

        // `xsig_drain_for_self` clears the dirty flag, leaving the ring clean.
        let _ = xsig_drain_for_self();
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

    fn signal_is_blocked(signum: libc::c_int) -> bool {
        unsafe {
            let mut current: libc::sigset_t = core::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current),
                0
            );
            libc::sigismember(&current, signum) == 1
        }
    }

    #[test]
    fn thread_directed_takes_priority_for_its_tid() {
        let _g = TEST_LOCK.lock();
        clear_proc_pending();
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
        let _g = TEST_LOCK.lock();
        clear_proc_pending();
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
    fn distinct_process_directed_signals_do_not_coalesce() {
        let _g = TEST_LOCK.lock();
        reset_after_supervisor_fork();
        let tid = 900_031;
        // Two DISTINCT process-directed signals pending at once must BOTH
        // survive — the single-i32 slot dropped the first (LTP kill10's master
        // missing one manager's ack and hanging). Drained lowest-first.
        publish_pending(10); // SIGUSR1
        publish_pending(12); // SIGUSR2
        assert!(has_pending_for(tid));
        assert_eq!(take_pending_for(tid), 10);
        assert_eq!(take_pending_for(tid), 12);
        assert_eq!(take_pending_for(tid), NO_PENDING_SIGNAL);
        assert!(!has_pending_for(tid));
        // A same-signum repeat still coalesces (standard-signal semantics).
        publish_pending(10);
        publish_pending(10);
        assert_eq!(take_pending_for(tid), 10);
        assert_eq!(take_pending_for(tid), NO_PENDING_SIGNAL);
        drain_pending_pipe();
        drain_pump_pipe();
    }

    #[test]
    fn process_directed_signal_is_consumed_once_under_concurrent_takers() {
        let _g = TEST_LOCK.lock();
        reset_after_supervisor_fork();
        clear_proc_pending();

        publish_pending(10); // SIGUSR1
        let ready = std::sync::Arc::new(std::sync::Barrier::new(5));
        let handles = (0..4)
            .map(|i| {
                let ready = std::sync::Arc::clone(&ready);
                std::thread::spawn(move || {
                    ready.wait();
                    take_pending_for(901_000 + i)
                })
            })
            .collect::<Vec<_>>();

        ready.wait();
        let delivered = handles
            .into_iter()
            .map(|handle| handle.join().expect("taker thread should finish"))
            .filter(|&signum| signum == 10)
            .count();
        assert_eq!(delivered, 1);
        assert_eq!(take_pending_for(901_100), NO_PENDING_SIGNAL);
        drain_pending_pipe();
        drain_pump_pipe();
    }

    #[test]
    fn take_pending_in_for_leaves_non_matching_signals_queued() {
        let _g = TEST_LOCK.lock();
        clear_proc_pending();
        let tid = 900_012;
        publish_pending_for(tid, 12);

        assert_eq!(
            take_pending_in_for(tid, carrick_abi::SigSet::EMPTY.with(LINUX_SIGINT)),
            NO_PENDING_SIGNAL
        );
        assert_eq!(
            take_pending_in_for(tid, carrick_abi::SigSet::EMPTY.with(12)),
            12
        );
        assert_eq!(
            take_pending_in_for(tid, carrick_abi::SigSet::EMPTY.with(12)),
            NO_PENDING_SIGNAL
        );
        drain_pending_pipe();
        drain_pump_pipe();
    }

    #[test]
    fn forget_thread_drops_pending() {
        let _g = TEST_LOCK.lock();
        clear_proc_pending();
        let tid = 900_003;
        publish_pending_for(tid, 15);
        forget_thread(tid);
        assert_eq!(take_pending_for(tid), NO_PENDING_SIGNAL);
        drain_pending_pipe();
        drain_pump_pipe();
    }

    #[test]
    fn take_pending_for_falls_back_to_process_directed() {
        let _g = TEST_LOCK.lock();
        clear_proc_pending();
        let tid = 900_004;
        // No thread-directed entry; a process-directed signal is deliverable by
        // any tid. Publish SIGBUS(7) into the process-directed mask.
        publish_process_signal(7);
        assert!(has_pending_for(tid));
        assert_eq!(take_pending_for(tid), 7);
        assert!(!has_process_pending());
    }
}
