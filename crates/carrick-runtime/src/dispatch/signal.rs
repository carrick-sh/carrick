//! Signal subsystem: the dispatcher-side state machine for POSIX/Linux signals.
//!
//! # Theory of operation
//!
//! Signal handling in carrick is split across three places, and this file owns
//! the MIDDLE one — the bookkeeping. It is worth being precise about the seam:
//!
//!   - **carrick-vmm-hvf** (`host_signal`) owns the host↔guest signum translation
//!     (`SIGNUM_XLATE` / `host_to_linux_signum`): a macOS host signal that the
//!     runtime catches must be mapped to its Linux number before this layer
//!     reasons about it, because the numbers differ above the POSIX core (e.g.
//!     SIGCHLD, SIGUSR1/2, SIGURG sit at different values on the two kernels).
//!   - **runtime.rs** owns the PHYSICAL frame build: when a signal is actually
//!     delivered to a vCPU, `inject_signal` writes the Linux `rt_sigframe`
//!     (saved GPRs/PC/PSTATE + `ucontext` + `siginfo`) onto the guest stack,
//!     points the vCPU at the handler with the EL0 trampoline / `sa_restorer`
//!     as the return address, and `restore_from_sigframe` reverses it on
//!     `rt_sigreturn`. (The trampoline exists because glibc-aarch64 passes
//!     `sa_restorer = 0` and expects the kernel's VDSO `__kernel_rt_sigreturn`.)
//!   - **this file** owns everything BETWEEN: which signal is deliverable to
//!     which thread right now, what the handler-entry mask is, and what
//!     `rt_sigreturn` must restore. No vCPU registers are touched here; the
//!     handlers return [`DispatchOutcome`] values (e.g. `SignalThread`,
//!     `SigReturn`) that the runtime turns into frame builds and vCPU kicks.
//!
//! ## The state machine ([`SignalState`])
//!
//! The hard part of Linux signals is that masks, pending sets, and alternate
//! stacks are **per-thread**, while handlers and one shared pending set are
//! **per-process (thread-group)**. Getting this wrong is not a crash — it is a
//! lost or misrouted signal, the worst kind of bug to chase. Several fields
//! here exist specifically because a process-global shortcut once stranded a
//! signal:
//!
//!   - `masks`, `pendings`, `altstack`, `handler_frames` are keyed by
//!     [`crate::thread::ThreadId`]. A process-global mask let one thread's
//!     `rt_sigprocmask` block a signal for a sibling; a process-global alt
//!     stack made concurrent SIGURG frames overlap and corrupt goroutine
//!     stacks. Both were real (the field docstrings cite the cases).
//!   - `process_pending` / `process_rt_pending_counts` are the SHARED
//!     thread-group pending set for a process-directed signal that no thread
//!     can take immediately (every thread blocks it). `take_pending_in`
//!     considers it alongside the per-thread set so ANY thread that next
//!     unblocks — or that calls `rt_sigtimedwait`/`sigwait` — can consume it.
//!   - `rt_pending_counts` gives real-time signals (SIGRTMIN..=SIGRTMAX) POSIX
//!     queuing: N sends while blocked yield N deliveries on unblock, whereas a
//!     standard signal coalesces to one. The pending BIT only clears when the
//!     last queued instance drains.
//!   - `restore_masks` implements Linux's `set_restore_sigmask`: a syscall that
//!     temporarily swaps the mask for the duration of a wait (`sigsuspend`,
//!     `pselect`/`ppoll` with a sigmask) arms the mask that the NEXT handler's
//!     `rt_sigreturn` must restore — so the handler runs under the temporary
//!     mask and the original returns afterward.
//!
//! ## Delivery cycle and EINTR
//!
//! The runtime drives delivery: after a syscall, it asks
//! `take_deliverable_pending` for the lowest-numbered pending, unblocked signal
//! and injects ONE per cycle, so each handler runs and returns via
//! `rt_sigreturn` before the next is injected — matching the kernel's
//! "deliver all pending before returning to userspace" rule. `enter_signal_handler`
//! computes the handler-entry mask (current ∪ the delivered signal unless
//! SA_NODEFER ∪ `sa_mask`), applies SA_RESETHAND/one-shot disposition resets,
//! and records the alt-stack frame; the returned mask is what the frame saves
//! for `rt_sigreturn`. `non_interrupting_signal_mask` encodes which pending
//! signals must NOT cause a blocking host wait to return EINTR (a signal whose
//! disposition is ignore or default-ignore should never interrupt a `waitpid`).
//!
//! Methods are `impl` blocks on [`SyscallDispatcher`]; see [`super`] for the
//! dispatcher struct and the normalized dispatch table.
use super::*;

syscall_table! {
    /// Per-module syscall routing for the `signal` subsystem (Task A1).
    ///
    /// Owns the `number → handler` arms for every syscall this module
    /// implements. `resolve_handler` in `dispatch/mod.rs` chains this with
    /// the other modules' tables. Add a `signal` syscall by adding an arm
    /// HERE — no shared routing table to edit.
    pub(crate) fn dispatch_signal;
    74 => signalfd4,
    129 => kill,
    130 => tkill,
    131 => tgkill,
    132 => sigaltstack,
    133 => rt_sigsuspend,
    134 => rt_sigaction,
    135 => rt_sigprocmask,
    136 => rt_sigpending,
    137 => rt_sigtimedwait,
    138 => rt_sigqueueinfo,
    139 => rt_sigreturn,
    240 => rt_tgsigqueueinfo,
}
use crate::linux_abi::LinuxSiginfo;
use carrick_abi::{SigBlockMask, SigSet};
use std::collections::VecDeque;

/// Owned signal-subsystem state. Split out of `SyscallDispatcher` so the
/// signal handlers borrow only what they touch instead of the whole
/// dispatcher. Field semantics are unchanged from the former loose
/// fields (`signal_handlers`/`signal_mask`/`pending_signals`/`sig_altstack`).
pub(super) struct SignalState {
    /// Installed signal handlers per signum (1..=64). When the guest
    /// calls `rt_sigaction(signum, new, old, 8)` we record `new` here
    /// and return whatever was previously stored via `old`.
    pub handlers: HashMap<i32, LinuxSigaction>,
    /// Guest's blocked-signal mask (bit `signum-1`), PER GUEST THREAD. The
    /// signal mask is per-thread in Linux; a process-global mask let one
    /// thread's `rt_sigprocmask` (e.g. musl's pthread_create block/restore
    /// dance) block a signal for ANOTHER thread → a cross-thread signal was
    /// "blocked" at the target and never delivered (found via `carrick trace`
    /// signal-publish/deliver probes). Default (absent key) = empty mask.
    pub masks: HashMap<crate::thread::ThreadId, SigSet>,
    /// Signals raised while blocked, awaiting unblock or a synchronous wait
    /// (`rt_sigtimedwait`), PER GUEST THREAD (bit `signum-1`). For a standard
    /// signal the bit is presence only (multiple sends coalesce, matching
    /// Linux). For a real-time signal (SIGRTMIN..=SIGRTMAX) the COUNT of queued
    /// instances lives in `rt_pending_counts`; the bit here just mirrors
    /// "count > 0".
    pub pendings: HashMap<crate::thread::ThreadId, SigSet>,
    /// Queue depth for pending REAL-TIME signals, keyed by `(tid, signum)`.
    /// RT signals must deliver once per send (POSIX queuing), unlike standard
    /// signals which coalesce — so N `rt_sigqueueinfo`/`kill` of an RT signal
    /// while blocked must yield N deliveries on unblock. `take_pending_in`
    /// decrements this and only clears the pending bit when it hits 0.
    pub rt_pending_counts: HashMap<(crate::thread::ThreadId, i32), u32>,
    /// SHARED (process-level) pending set (bit `signum-1`) for PROCESS-directed
    /// signals (`kill(getpid(), sig)`) that no thread can take immediately
    /// because EVERY thread blocks `sig`. Linux holds such a signal in the
    /// thread group's shared pending set, deliverable to whichever thread next
    /// unblocks it (`rt_sigprocmask` -> `take_deliverable_pending`) OR dequeues
    /// it synchronously (`rt_sigtimedwait`/sigwait). Pinning it to the SENDER's
    /// per-thread set instead stranded a SIBLING's `sigwait` forever (CPython
    /// test_sigwait_thread). `take_pending_in` considers this alongside the
    /// per-thread set so any thread can consume it.
    pub process_pending: SigSet,
    /// Queue depth for SHARED pending REAL-TIME signals, keyed by `signum`
    /// (the process-level analogue of `rt_pending_counts`).
    pub process_rt_pending_counts: HashMap<i32, u32>,
    /// Installed alternate signal stack (`sigaltstack`), PER GUEST THREAD.
    /// `sigaltstack` is per-thread in Linux (each thread/M registers its own
    /// signal stack), so this MUST be keyed by tid: a process-global slot made
    /// every thread's SIGURG (Go async-preempt) frame land on the last-set
    /// stack → concurrent frames overlapped → goroutine-stack corruption →
    /// the c>=20 EL0 faults (found via `carrick trace` on the `signal-inject`
    /// probe: identical `new_sp` across threads). Signal HANDLERS stay global
    /// (Linux shares them across threads); only the alt stack is per-thread.
    pub altstack: HashMap<crate::thread::ThreadId, LinuxSigaltstack>,
    /// Per-thread stack of currently-active signal-handler frames; each `bool`
    /// records whether THAT frame is executing on the alternate signal stack
    /// (SA_ONSTACK + an alt stack was configured). `enter_signal_handler` pushes
    /// on delivery, `rt_sigreturn` pops on return. A thread "is on the alt
    /// stack" iff any active frame's bool is true — used so `sigaltstack(NULL,
    /// &old)` reports SS_ONSTACK and a `sigaltstack(SET)` while on it returns
    /// EPERM (Linux semantics). (audit M13)
    pub handler_frames: HashMap<crate::thread::ThreadId, Vec<bool>>,
    /// Linux's `set_restore_sigmask()` shadow: when a syscall (sigsuspend,
    /// pselect, ppoll with a sigmask) temporarily replaced the thread's
    /// signal mask, this records the mask to restore AFTER the next signal
    /// handler runs — NOT immediately on syscall return. The handler runs
    /// under the temporary mask (so a now-deliverable pending signal can
    /// actually be delivered), and `rt_sigreturn` then pops THIS mask off
    /// the sigframe. `enter_signal_handler` consumes the entry the first
    /// time a handler runs after it's armed.
    pub restore_masks: HashMap<crate::thread::ThreadId, SigSet>,
    /// Caller-supplied `siginfo_t` queued for delivery, keyed by `(tid,
    /// signum)`. `rt_sigqueueinfo` pushes the user's siginfo here so the
    /// SA_SIGINFO handler sees the original `si_value` payload instead of
    /// a synthesised SI_USER. RT signals (32..=64) queue multiple entries
    /// (POSIX queuing); standard signals overwrite the head. Each delivery
    /// pops the front entry.
    pub pending_siginfos: HashMap<(crate::thread::ThreadId, i32), VecDeque<LinuxSiginfo>>,
    /// Handler action snapshots for unblocked thread-directed signals. The
    /// backend pending slot stores only a signum; without this, delayed delivery
    /// can observe a later `sigaction(SIG_IGN)` and drop a signal that was
    /// generated while a real handler was installed.
    pub pending_actions: HashMap<(crate::thread::ThreadId, i32), VecDeque<LinuxSigaction>>,
}

impl SignalState {
    pub(super) fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            masks: HashMap::new(),
            pendings: HashMap::new(),
            rt_pending_counts: HashMap::new(),
            process_pending: SigSet::EMPTY,
            process_rt_pending_counts: HashMap::new(),
            altstack: HashMap::new(),
            handler_frames: HashMap::new(),
            restore_masks: HashMap::new(),
            pending_siginfos: HashMap::new(),
            pending_actions: HashMap::new(),
        }
    }

    fn mask_for(&self, tid: crate::thread::ThreadId) -> SigSet {
        self.masks.get(&tid).copied().unwrap_or(SigSet::EMPTY)
    }
}

/// Real-time signals (`SIGRTMIN`..=`SIGRTMAX`, kernel numbers 32..=64) queue
/// per POSIX; standard signals (1..=31) coalesce.
fn is_rt_signal(signum: i32) -> bool {
    (32..=64).contains(&signum)
}

/// A cross-process `kill`/`sigqueue` to a *specific* guest process that a plain
/// host kill cannot carry faithfully, so it must route through the shared
/// explicit-signal ring + SIGINFO nudge (`host_signal` xsignal) instead — the
/// ring delivers it through the receiver's in-guest `deliver_pending_signal`,
/// which honours the guest disposition (SIG_IGN drop / handler / SIG_DFL term):
///   * SIGCHLD (17) — a host SIGCHLD is swallowed by the receiver's wait4/kqueue
///     child-exit pump, so its guest SIGCHLD handler never runs (LTP kill12).
///   * Synchronous faults SIGILL(4)/SIGTRAP(5)/SIGABRT(6)/SIGBUS(7)/SIGFPE(8)/
///     SIGSEGV(11) — their HOST disposition is shared with a genuine guest fault
///     (which arrives as a vmexit, not a host signal), so a guest `SIG_IGN`
///     cannot be mirrored to the host (`set_host_ignore` excludes them). A host
///     kill of one then takes the host default action and core-dumps the
///     receiver instead of being ignored (LTP kill12's `sigset(sig, SIG_IGN)`
///     loop). Routing through the ring keeps the host fault disposition intact
///     while still honouring the guest's ignore/handler.
///   * SIGPIPE (13) — carrick keeps a process-wide host `SIG_IGN` for SIGPIPE
///     (its OWN internal writes to a closed pipe must return EPIPE, not kill
///     the process), and NEITHER backend mirrors a guest SIGPIPE disposition
///     onto the host (`ensure_host_handler` excludes 13 on both: a routed host
///     SIGPIPE handler would re-route carrick's internal EPIPE writes into the
///     guest as a spurious signal). So a host kill of SIGPIPE to a sibling
///     carrick process is silently DROPPED by the receiver's host SIG_IGN —
///     LTP sigrelse01's `kill(child, SIGPIPE)` was never delivered on the
///     non-namespaced path. The ring carries it to the receiver's dispatch
///     layer, which honours the guest disposition (handler/pending/SIG_DFL).
///   * RT signals (32..=64) — macOS has no such signal number to host-kill with.
fn cross_process_needs_xsig(signum: i32) -> bool {
    signum == crate::linux_abi::LINUX_SIGCHLD
        || signum == crate::linux_abi::LINUX_SIGPIPE
        || signum == crate::linux_abi::LINUX_SIGSTKFLT
        || signum == crate::linux_abi::LINUX_SIGPWR
        || matches!(signum, 4 | 5 | 6 | 7 | 8 | 11)
        || is_rt_signal(signum)
}

fn namespace_member_standard_kill_needs_xsig(signum: i32) -> bool {
    (1..32).contains(&signum)
        && !matches!(
            signum,
            LINUX_SIGKILL | crate::linux_abi::LINUX_SIGCONT | LINUX_SIGSTOP
        )
}

fn altstack_contains_guest_sp(stack: LinuxSigaltstack, sp: u64) -> bool {
    stack
        .ss_sp
        .checked_add(stack.ss_size)
        .is_some_and(|top| sp > stack.ss_sp && sp <= top)
}

fn stop_self_by_signal(signum: i32) {
    let host_signum = crate::host_signal::linux_to_host_signum(signum);
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, host_signum);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(host_signum);
    }
}

fn should_route_specific_xsig(target_host_pid: i32, signum: i32) -> bool {
    if target_host_pid <= 0 {
        return false;
    }
    if cross_process_needs_xsig(signum) {
        return true;
    }
    if !namespace_member_standard_kill_needs_xsig(signum) || !crate::namespace::pid::enabled() {
        return false;
    }
    crate::namespace::pid::host_to_ns_or_self(target_host_pid as u32) != 0
}

fn sanitize_signal_mask(mask: SigSet) -> SigSet {
    mask.without(LINUX_SIGKILL).without(LINUX_SIGSTOP)
}

impl SyscallDispatcher {
    /// Look up the currently-installed handler for `signum`. Returns
    /// `None` when no handler has been recorded via `rt_sigaction`, or
    /// when the recorded handler is `SIG_DFL` / `SIG_IGN`. The runtime
    /// uses this to decide whether to inject a guest frame (handler is
    /// `Some`) or apply the host-side default (handler is `None`).
    pub fn registered_signal_handler(&self, signum: i32) -> Option<LinuxSigaction> {
        let action = self.signal.lock().handlers.get(&signum).copied()?;
        let handler = action.sa_handler;
        if handler == crate::linux_abi::LINUX_SIG_DFL || handler == crate::linux_abi::LINUX_SIG_IGN
        {
            None
        } else {
            Some(action)
        }
    }

    /// The currently-installed alternate signal stack as `(ss_sp, ss_size)`,
    /// or `None` when no alt stack is set. The runtime uses this to place the
    /// signal frame on the alt stack when a handler is registered `SA_ONSTACK`.
    pub fn signal_altstack(&self, tid: crate::thread::ThreadId) -> Option<(u64, u64)> {
        self.signal
            .lock()
            .altstack
            .get(&tid)
            .map(|a| (a.ss_sp, a.ss_size))
    }

    /// True iff the guest installed `SIG_IGN` for `signum`. Lets the
    /// runtime drop a pending signal without injecting it.
    pub fn signal_is_ignored(&self, signum: i32) -> bool {
        self.signal
            .lock()
            .handlers
            .get(&signum)
            .map(|a| a.sa_handler == crate::linux_abi::LINUX_SIG_IGN)
            .unwrap_or(false)
    }

    /// `(SigIgn, SigCgt, ShdPnd)` masks (bit `signum-1`) for a
    /// `/proc/<pid>/status` render: the process-global ignored set, the caught
    /// (real-handler) set, and the shared process pending set. SigBlk/SigPnd are
    /// per-thread and rendered separately (currently 0 — not yet wired to a
    /// target tid). CPython test_subprocess.test_restore_signals compares the
    /// SigIgn line across two children, so it must reflect real dispositions.
    pub fn proc_status_signal_masks(&self) -> (SigSet, SigSet, SigSet) {
        let signal = self.signal.lock();
        let mut ignored = SigSet::EMPTY;
        let mut caught = SigSet::EMPTY;
        for (&signum, action) in signal.handlers.iter() {
            if sigmask_bit(signum).is_none() {
                continue;
            }
            let h = action.sa_handler;
            if h == crate::linux_abi::LINUX_SIG_IGN {
                ignored = ignored.with(signum);
            } else if h != crate::linux_abi::LINUX_SIG_DFL {
                caught = caught.with(signum);
            }
        }
        (ignored, caught, signal.process_pending)
    }

    /// True when a fork-style child exit must be observed asynchronously by the
    /// signal pump. A default, unblocked SIGCHLD is inert for signal delivery
    /// and a later wait4/waitid can reap through its own wait path, so it does
    /// not need a per-child EVFILT_PROC watch. Caught handlers, blocked signals
    /// (sigtimedwait/sigwait), and non-ignored default dispositions do.
    pub fn child_exit_signal_needs_pump(
        &self,
        tid: crate::thread::ThreadId,
        exit_signal: u32,
    ) -> bool {
        let signum = if exit_signal == 0 {
            return false;
        } else if (1..=64).contains(&exit_signal) {
            exit_signal as i32
        } else {
            crate::linux_abi::LINUX_SIGCHLD
        };
        if sigmask_bit(signum).is_none() {
            return false;
        }
        let signal = self.signal.lock();
        match signal.handlers.get(&signum).map(|a| a.sa_handler) {
            Some(h) if h == crate::linux_abi::LINUX_SIG_IGN => false,
            Some(h) if h == crate::linux_abi::LINUX_SIG_DFL => {
                signal.mask_for(tid).contains(signum) || !is_default_ignore_signum(signum)
            }
            Some(_) => true,
            None => signal.mask_for(tid).contains(signum) || !is_default_ignore_signum(signum),
        }
    }

    /// The set of signals that must NOT interrupt a blocking,
    /// restartable syscall (wait4/waitid) for `tid`. On Linux a syscall is
    /// interrupted only by a signal that is both unblocked AND has an effect:
    /// a signal that is blocked, explicitly `SIG_IGN`, or `SIG_DFL` with a
    /// default action of "ignore" (SIGCHLD/SIGURG/SIGWINCH) is delivered-and-
    /// dropped without interrupting. carrick previously interrupted the wait
    /// for ANY pending signal, so a sibling child's default-ignored SIGCHLD
    /// spuriously EINTR'd a `waitpid(other_child)` (LTP futex_cmp_requeue01's
    /// `SAFE_WAITPID` then TBROKed). Folding the ignored set into the wait's
    /// block mask makes those pending-but-inert signals leave the wait running.
    pub fn non_interrupting_signal_mask(&self, tid: crate::thread::ThreadId) -> SigSet {
        let signal = self.signal.lock();
        // Start from the thread's blocked set.
        let mut mask = signal.mask_for(tid);
        for signum in 1..=64i32 {
            let disposition = signal.handlers.get(&signum).map(|a| a.sa_handler);
            let ignored = match disposition {
                Some(h) if h == crate::linux_abi::LINUX_SIG_IGN => true,
                // No recorded handler, or SIG_DFL: inert only when the DEFAULT
                // action is ignore (SIGCHLD/SIGURG/SIGWINCH). Every other
                // SIG_DFL signal (terminate/core/stop) still interrupts.
                None => is_default_ignore_signum(signum),
                Some(h) if h == crate::linux_abi::LINUX_SIG_DFL => is_default_ignore_signum(signum),
                // A real handler is installed → the signal interrupts (then
                // SA_RESTART decides whether the syscall restarts).
                Some(_) => false,
            };
            if ignored {
                mask = mask.with(signum);
            }
        }
        mask
    }

    /// True iff `signum` is currently blocked by the guest's signal mask.
    /// SIGKILL/SIGSTOP can never be blocked, matching the kernel.
    pub fn signal_blocked(&self, tid: crate::thread::ThreadId, signum: i32) -> bool {
        if signum == LINUX_SIGKILL || signum == LINUX_SIGSTOP {
            return false;
        }
        self.signal.lock().mask_for(tid).contains(signum)
    }

    pub fn signal_mask_for(&self, tid: crate::thread::ThreadId) -> SigSet {
        self.signal.lock().mask_for(tid)
    }

    /// Record a (blocked) signal as pending for `tid`. It stays queued until the
    /// thread unblocks it or dequeues it via `rt_sigtimedwait`. Real-time
    /// signals queue (each send adds a deliverable instance); standard signals
    /// coalesce (the bit is set-once), matching Linux.
    pub fn mark_signal_pending(&self, tid: crate::thread::ThreadId, signum: i32) {
        if sigmask_bit(signum).is_some() {
            let mut s = self.signal.lock();
            let pending = s.pendings.entry(tid).or_insert(SigSet::EMPTY);
            *pending = pending.with(signum);
            if is_rt_signal(signum) {
                *s.rt_pending_counts.entry((tid, signum)).or_insert(0) += 1;
            }
        }
    }

    /// Drop a thread's per-thread signal state (mask/pending/alt stack) when it
    /// exits, so the maps don't grow unbounded over a long run and a recycled
    /// tid starts clean. Signal handlers are process-global and untouched.
    pub fn forget_thread_signal_state(&self, tid: crate::thread::ThreadId) {
        let mut s = self.signal.lock();
        s.masks.remove(&tid);
        s.pendings.remove(&tid);
        s.rt_pending_counts.retain(|(t, _), _| *t != tid);
        s.pending_actions.retain(|(t, _), _| *t != tid);
        s.altstack.remove(&tid);
        s.handler_frames.remove(&tid);
    }

    /// Re-key a thread's per-thread signal state from `old` to `new` across
    /// fork(2): the child gets a NEW tid (its own pid) but INHERITS the
    /// parent's blocked mask and alternate signal stack (POSIX). The pending
    /// set is NOT migrated — fork clears the child's pending signals. Without
    /// this, the child's per-tid lookups miss (the state stays orphaned under
    /// the parent's tid) and an inherited SA_ONSTACK alt stack is silently lost.
    /// (audit M2; probe forkaltstack)
    pub fn migrate_thread_signal_state(
        &self,
        old: crate::thread::ThreadId,
        new: crate::thread::ThreadId,
    ) {
        if old == new {
            return;
        }
        let mut s = self.signal.lock();
        if let Some(mask) = s.masks.remove(&old) {
            s.masks.insert(new, mask);
        }
        if let Some(alt) = s.altstack.remove(&old) {
            s.altstack.insert(new, alt);
        }
        if let Some(rm) = s.restore_masks.remove(&old) {
            s.restore_masks.insert(new, rm);
        }
        // fork clears the child's pending set; drop any stale entries keyed
        // under the new tid so the child starts clean.
        s.pendings.remove(&new);
        s.rt_pending_counts.retain(|(t, _), _| *t != new);
        s.pending_actions.clear();
        // fork ALSO clears the inherited (copied) shared process pending set —
        // a process-directed signal pending in the parent is not pending in the
        // new child (POSIX). This runs only in the post-fork child (a separate
        // host process), so it never affects the parent's shared set.
        s.process_pending = SigSet::EMPTY;
        s.process_rt_pending_counts.clear();
    }

    /// Initialize a new `CLONE_THREAD` task's per-thread signal state. Linux
    /// threads inherit the creator's blocked-signal mask at clone time, while
    /// pending signals and alternate signal stacks are not inherited by the new
    /// thread.
    pub fn inherit_thread_signal_mask(
        &self,
        parent: crate::thread::ThreadId,
        child: crate::thread::ThreadId,
    ) {
        if parent == child {
            return;
        }
        let mut s = self.signal.lock();
        let mask = s.mask_for(parent);
        if mask.is_empty() {
            s.masks.remove(&child);
        } else {
            s.masks.insert(child, mask);
        }
        s.pendings.remove(&child);
        s.rt_pending_counts.retain(|(t, _), _| *t != child);
        s.pending_actions.retain(|(t, _), _| *t != child);
        s.altstack.remove(&child);
        s.handler_frames.remove(&child);
        s.restore_masks.remove(&child);
    }

    /// Reset signal dispositions across `execve(2)`, matching the kernel: every
    /// CAUGHT signal (a handler installed) is reset to `SIG_DFL`; `SIG_IGN`
    /// dispositions are PRESERVED; the blocked mask and pending signals are
    /// preserved (the new image inherits them). The alternate signal stack is
    /// cleared. Without this, a process that installed handlers and then execs
    /// (e.g. a shell `exec`ing — or `/bin/sh -c CMD` fork+exec'ing — a program)
    /// leaks the OLD image's handler ADDRESSES into the new image; a later
    /// signal then jumps to a stale address that is unrelated code in the new
    /// binary and crashes (the `/bin/sh -c <ltp-test>` mass segfaults: dash's
    /// SIGCHLD handler addr, invoked in the test's address space when its child
    /// exited). Handlers are process-global, so this resets for the process.
    pub fn reset_signal_handlers_on_execve(&self) {
        let mut s = self.signal.lock();
        let ignored = s
            .handlers
            .iter()
            .filter(|&(&_signum, action)| action.sa_handler == crate::linux_abi::LINUX_SIG_IGN)
            .fold(carrick_abi::SigSet::EMPTY, |set, (&signum, _)| {
                set.with(signum)
            });
        // Keep only SIG_IGN dispositions; a caught handler → default (absent).
        s.handlers
            .retain(|_, a| a.sa_handler == crate::linux_abi::LINUX_SIG_IGN);
        s.pending_actions.clear();
        // execve disestablishes any alternate signal stack for the process and
        // discards active user signal frames from the old image. The blocked
        // mask and pending sets survive, but handler-frame bookkeeping and
        // temporary restore masks are tied to the replaced user stack.
        s.altstack.clear();
        s.handler_frames.clear();
        s.restore_masks.clear();
        drop(s);
        crate::host_signal::reset_routed_handlers_after_execve(ignored);
    }

    /// Apply Linux handler-time masking for `signum`, returning the mask that
    /// `rt_sigreturn` should restore (saved in the sigframe).
    ///
    /// Normally that's the thread's current mask. But if a syscall armed a
    /// "restore mask" via `arm_restore_mask` (Linux's `saved_sigmask`/
    /// `set_restore_sigmask` analogue — sigsuspend / pselect / ppoll with a
    /// sigmask), THAT mask is what `rt_sigreturn` must restore — the
    /// temp-masked syscall lets the handler run with the temp mask, then
    /// the original mask comes back. We consume the entry on first use.
    pub fn enter_signal_handler(
        &self,
        tid: crate::thread::ThreadId,
        signum: i32,
        action: LinuxSigaction,
    ) -> SigSet {
        let mut signal = self.signal.lock();
        let saved = signal
            .restore_masks
            .remove(&tid)
            .unwrap_or_else(|| signal.mask_for(tid));
        // SA_NODEFER: leave the signal being delivered UNblocked during its own
        // handler (the kernel default is to block it, preventing re-entry). With
        // it unblocked, a signal re-raised from inside the handler is delivered
        // synchronously to whatever handler is installed AT THAT MOMENT — which
        // is exactly how CPython faulthandler's `chain=True` re-raise reaches the
        // restored previous handler instead of re-entering faulthandler forever.
        let delivered = if action.sa_flags & crate::linux_abi::LINUX_SA_NODEFER != 0 {
            SigSet::EMPTY
        } else {
            SigSet::EMPTY.with(signum)
        };
        let current = signal.mask_for(tid);
        // `sa_mask` holds the guest sigaction's wire sigset_t word.
        let handler_mask = sanitize_signal_mask(
            current
                .union(delivered)
                .union(SigSet::from_raw(action.sa_mask[0])),
        );
        signal.masks.insert(tid, handler_mask);
        // SA_RESETHAND (one-shot): the disposition is reset to SIG_DFL *before*
        // the handler runs, so a second occurrence of the signal takes the
        // default action. Keep the action record with the reset disposition
        // rather than deleting it outright: Linux still reports metadata such
        // as SA_SIGINFO to an in-handler sigaction(SIG, NULL, &old) query.
        if action.sa_flags & crate::linux_abi::LINUX_SA_RESETHAND != 0 {
            let mut reset = action;
            reset.sa_handler = crate::linux_abi::LINUX_SIG_DFL;
            signal.handlers.insert(signum, reset);
        }
        // Record whether this handler runs on the alt stack (SA_ONSTACK + an
        // alt stack is configured), so sigaltstack queries report SS_ONSTACK and
        // a reconfigure-while-active returns EPERM. Popped by rt_sigreturn.
        // (audit M13)
        let on_alt = action.sa_flags & crate::linux_abi::LINUX_SA_ONSTACK != 0
            && signal.altstack.contains_key(&tid);
        signal.handler_frames.entry(tid).or_default().push(on_alt);
        saved
    }

    /// True iff `tid` is currently executing a signal handler ON its alternate
    /// signal stack (any active SA_ONSTACK frame). (audit M13)
    fn is_on_altstack(&self, tid: crate::thread::ThreadId, current_guest_sp: Option<u64>) -> bool {
        let mut signal = self.signal.lock();
        let frame_says_on_alt = signal
            .handler_frames
            .get(&tid)
            .is_some_and(|frames| frames.iter().any(|&on_alt| on_alt));
        if !frame_says_on_alt {
            return false;
        }
        let Some(sp) = current_guest_sp else {
            return true;
        };
        let sp_on_alt = signal
            .altstack
            .get(&tid)
            .is_some_and(|stack| altstack_contains_guest_sp(*stack, sp));
        if !sp_on_alt {
            signal.handler_frames.remove(&tid);
        }
        sp_on_alt
    }

    /// Pop the returning handler frame's alt-stack record (rt_sigreturn).
    fn pop_handler_frame(&self, tid: crate::thread::ThreadId) {
        let mut signal = self.signal.lock();
        if let Some(frames) = signal.handler_frames.get_mut(&tid) {
            frames.pop();
            if frames.is_empty() {
                signal.handler_frames.remove(&tid);
            }
        }
    }

    /// Arm a "restore this mask after the next handler runs" override (Linux's
    /// `set_restore_sigmask`). The next `enter_signal_handler` for `tid`
    /// returns `mask` as the sigframe's saved mask and clears the arm.
    pub fn arm_restore_mask(&self, tid: crate::thread::ThreadId, mask: SigSet) {
        let mut signal = self.signal.lock();
        signal.restore_masks.insert(tid, sanitize_signal_mask(mask));
    }

    /// True if a signal deliverable under `suspend_mask` (per-thread pending or
    /// shared process-directed) has a CAUGHT handler installed for `tid`. This
    /// is the only `rt_sigsuspend`-wake case where the temporary mask is kept
    /// and the post-handler restore is armed: the handler runs under
    /// `suspend_mask` and its `rt_sigreturn` pops the saved mask. On every other
    /// wake (spurious/timeout, or a signal whose disposition is ignore /
    /// default-ignore — no handler, so no `rt_sigreturn`) the saved mask must be
    /// restored by `rt_sigsuspend` itself, or the thread is stranded under the
    /// temporary mask. (audit M1)
    fn sigsuspend_caught_handler_deliverable(
        &self,
        tid: crate::thread::ThreadId,
        suspend_mask: SigSet,
    ) -> bool {
        let deliverable = {
            let signal = self.signal.lock();
            signal
                .pendings
                .get(&tid)
                .copied()
                .unwrap_or(SigSet::EMPTY)
                .union(signal.process_pending)
                .difference(suspend_mask)
        };
        if deliverable.is_empty() {
            return false;
        }
        (1..=64i32)
            .any(|sig| deliverable.contains(sig) && self.registered_signal_handler(sig).is_some())
    }

    /// Queue a caller-supplied `siginfo_t` for the next delivery of
    /// `(tid, signum)`. Standard signals overwrite the single queued entry;
    /// RT signals (32..=64) append (POSIX queuing). `take_pending_siginfo`
    /// pops the front.
    pub fn record_pending_siginfo(
        &self,
        tid: crate::thread::ThreadId,
        signum: i32,
        info: LinuxSiginfo,
    ) {
        let mut signal = self.signal.lock();
        let entry = signal.pending_siginfos.entry((tid, signum)).or_default();
        if !is_rt_signal(signum) {
            entry.clear();
        }
        entry.push_back(info);
    }

    /// Pop the next queued `siginfo_t` for `(tid, signum)`, if any. Returned to
    /// the signal-delivery path so `inject_signal` can carry the caller's
    /// payload (e.g. `rt_sigqueueinfo`'s `si_value.sival_int`) instead of
    /// synthesising an SI_USER siginfo. Returns `None` when no siginfo was
    /// queued (the normal raise/kill case — synthesised SI_USER is correct).
    pub fn take_pending_siginfo(
        &self,
        tid: crate::thread::ThreadId,
        signum: i32,
    ) -> Option<LinuxSiginfo> {
        let mut signal = self.signal.lock();
        let queue = signal.pending_siginfos.get_mut(&(tid, signum))?;
        let front = queue.pop_front();
        if queue.is_empty() {
            signal.pending_siginfos.remove(&(tid, signum));
        }
        front
    }

    /// Snapshot the current caught handler for a thread-directed signal that is
    /// deliverable now. The kicked target vCPU may not drain the backend
    /// pending slot until after the sender changes the process-global
    /// disposition; delivery must still use the handler that made the generated
    /// signal catchable.
    pub fn record_pending_signal_action(
        &self,
        tid: crate::thread::ThreadId,
        signum: i32,
        action: LinuxSigaction,
    ) {
        let mut signal = self.signal.lock();
        let entry = signal.pending_actions.entry((tid, signum)).or_default();
        if !is_rt_signal(signum) {
            entry.clear();
        }
        entry.push_back(action);
    }

    /// Pop the handler action snapshotted for a generated thread-directed
    /// signal, if any. Normal pending signals fall back to the current
    /// disposition.
    pub fn take_pending_signal_action(
        &self,
        tid: crate::thread::ThreadId,
        signum: i32,
    ) -> Option<LinuxSigaction> {
        let mut signal = self.signal.lock();
        let queue = signal.pending_actions.get_mut(&(tid, signum))?;
        let front = queue.pop_front();
        if queue.is_empty() {
            signal.pending_actions.remove(&(tid, signum));
        }
        front
    }

    fn record_tkill_siginfo(&self, tid: crate::thread::ThreadId, signum: i32) {
        if signum == 0 {
            return;
        }
        let info = LinuxSiginfo::kill(
            signum,
            crate::linux_abi::LINUX_SI_TKILL,
            crate::namespace::pid::self_ns_pid() as i32,
            self.cred_snapshot().ruid,
        );
        self.record_pending_siginfo(tid, signum, info);
    }

    /// Drain cross-process explicit signals queued for this host process into
    /// dispatcher pending state for `tid`, preserving siginfo payloads. Normal
    /// async delivery and synchronous waits (`rt_sigtimedwait`/sigwait) both use
    /// this so an xsignal can be consumed by either path.
    pub(crate) fn drain_xsignals_for_tid(&self, tid: crate::thread::ThreadId) {
        // Ring-authoritative gate (`SigBlockMask::NONE` => "any entry targets
        // this process"),
        // NOT the losable process-local `XSIG_DIRTY` hint: a dropped host nudge
        // must not hide an already-enqueued cross-process signal from the drain,
        // or a re-dispatched `rt_sigtimedwait`/sigwait would never consume it and
        // the waiter would re-block forever.
        if !carrick_signal_core::xsig::xsig_has_unblocked_for_self(SigBlockMask::NONE) {
            return;
        }
        for (signum, code, sender_ns, sender_uid, value) in
            crate::host_signal::xsig_drain_for_self()
        {
            // The ring carries the send's REAL si_code: a plain kill(2) of an
            // RT signal is SI_USER (kill-shaped siginfo), only rt_sigqueueinfo
            // deliveries are SI_QUEUE with a sigval payload.
            let info = if code == crate::linux_abi::LINUX_SI_QUEUE {
                LinuxSiginfo::rt_queue(signum, sender_ns, sender_uid, value)
            } else {
                LinuxSiginfo::kill(signum, code, sender_ns, sender_uid)
            };
            self.record_pending_siginfo(tid, signum, info);
            self.mark_signal_pending(tid, signum);
        }
    }

    pub fn restore_signal_mask(&self, tid: crate::thread::ThreadId, mask: SigSet) {
        self.signal
            .lock()
            .masks
            .insert(tid, sanitize_signal_mask(mask));
    }

    /// Lowest-numbered pending signal that is NOT currently blocked, cleared
    /// from the pending set. The runtime drains this each delivery cycle to
    /// deliver signals raised while blocked and since unblocked (rt_sigprocmask)
    /// — one per cycle so each handler runs (and returns via rt_sigreturn)
    /// before the next is injected, matching the kernel's deliver-all-pending-
    /// before-returning-to-userspace behaviour. None when none remain.
    pub fn take_deliverable_pending(&self, tid: crate::thread::ThreadId) -> Option<i32> {
        let mask = self.signal.lock().mask_for(tid);
        self.take_pending_in(tid, mask.complement())
    }

    /// True iff dispatcher-owned signal state has a pending signal deliverable
    /// to `tid` for a blocking wait. This complements
    /// `host_signal::has_unblocked_pending_for`: host_signal sees backend/pump
    /// pending state, while this sees the dispatcher's per-thread and shared
    /// process pending sets.
    ///
    /// `sig_mask` selects the wait's effective block mask. For
    /// `ppoll`/`pselect6`/`epoll_pwait`, [`carrick_abi::WaitSigMask::Replace`] carries a
    /// POSIX sigmask that REPLACES the thread mask for the wait, so it is used
    /// ALONE — a signal the temp mask unblocks must interrupt even if
    /// persistently blocked (probe `ppollunblock`). For a plain
    /// `read`/`recv`/`connect` ([`carrick_abi::WaitSigMask::Additive`], usually with an
    /// empty set), the thread's PERSISTENT mask gates the wait — a
    /// blocked-and-pending signal must NOT interrupt it (probe `maskfork`).
    /// Unioning the two would over-block the ppoll-unblock case, so the policy
    /// travels with the outcome as the enum variant.
    pub(crate) fn has_deliverable_dispatch_pending_for_wait(
        &self,
        tid: crate::thread::ThreadId,
        sig_mask: carrick_abi::WaitSigMask,
    ) -> bool {
        use carrick_abi::WaitSigMask;
        let always_deliverable = SigSet::EMPTY.with(LINUX_SIGKILL).with(LINUX_SIGSTOP);
        let signal = self.signal.lock();
        let effective_block_mask = match sig_mask {
            WaitSigMask::Replace(s) => s,
            WaitSigMask::Additive(s) => signal.mask_for(tid).union(s),
        };
        let pending = signal
            .pendings
            .get(&tid)
            .copied()
            .unwrap_or(SigSet::EMPTY)
            .union(signal.process_pending);
        !pending
            .intersect(effective_block_mask.complement().union(always_deliverable))
            .is_empty()
    }

    /// The set of signals whose CURRENT disposition would be
    /// ignored at delivery: an installed `SIG_IGN`, or no/`SIG_DFL` handler on
    /// a default-ignore signal (SIGCHLD/SIGURG/SIGWINCH). A
    /// [`DispatchOutcome::WaitOnSignals`] park folds these into its block mask:
    /// on Linux a to-be-ignored signal neither interrupts `sigtimedwait` (no
    /// handler runs → no EINTR) nor may it busy-wake the park (nothing consumes
    /// it until the run-loop tail) — the classic case is the SIGCHLD a reaped
    /// child sends a handler-less parent mid-`sigtimedwait`.
    pub(crate) fn wait_ignored_disposition_mask(&self) -> SigSet {
        let signal = self.signal.lock();
        let mut mask = SigSet::EMPTY;
        for signum in 1..=64i32 {
            let ignored = match signal.handlers.get(&signum) {
                Some(a) if a.sa_handler == crate::linux_abi::LINUX_SIG_IGN => true,
                Some(a) if a.sa_handler == crate::linux_abi::LINUX_SIG_DFL => {
                    crate::vcpu_loop::is_default_ignore_signal(signum)
                }
                Some(_) => false,
                None => crate::vcpu_loop::is_default_ignore_signal(signum),
            };
            if ignored {
                mask = mask.with(signum);
            }
        }
        mask
    }

    /// True iff a [`DispatchOutcome::WaitOnSignals`] park woken by a signal
    /// should complete with EINTR instead of re-dispatching: an unblocked
    /// pending signal OUTSIDE the wait set (pending in the dispatcher's sets,
    /// the host slot, or the cross-process xsignal ring). The run loop then
    /// returns EINTR and its delivery tail runs the handler — re-dispatching
    /// instead would `take_pending_in(wait_set)`, find nothing, and RE-PARK,
    /// wedging `rt_sigtimedwait(set=∅)` forever (the kvm-lane LTP
    /// sigtimedwait01/sigwaitinfo01 TIMEOUT cluster). A wait-set signal (or a
    /// consumed/spurious wake) returns false: re-dispatch dequeues it and
    /// completes with the signum.
    pub(crate) fn signal_wait_should_eintr(
        &self,
        tid: crate::thread::ThreadId,
        wait_set: carrick_abi::SigSet,
        block_mask: carrick_abi::SigBlockMask,
    ) -> bool {
        // Everything that must NOT produce EINTR: the wait set itself (handled
        // by re-dispatch) plus the blocked/ignored remainder the block mask
        // already encodes. That union is already the wait's COMPLETE effective
        // mask, so hand it to the dispatch-pending predicate as `Replace` (the
        // persistent thread mask is folded in, not unioned again).
        let non_eintr = block_mask.non_eintr_union(wait_set);
        let non_eintr_block = SigBlockMask::blocking_all_of(non_eintr);
        crate::host_signal::has_unblocked_pending_for(tid.raw(), non_eintr_block)
            || carrick_signal_core::xsig::xsig_has_unblocked_for_self(non_eintr_block)
            || self.has_deliverable_dispatch_pending_for_wait(
                tid,
                carrick_abi::WaitSigMask::Replace(non_eintr),
            )
    }

    /// Lowest-numbered pending signal for `tid` that intersects `set`, cleared
    /// from that thread's pending set OR the shared process pending set. Used by
    /// `rt_sigtimedwait`/sigwait and `take_deliverable_pending`. The union lets
    /// any thread consume a process-directed signal held in the shared set
    /// (`process_pending`), matching Linux's thread-group shared pending.
    fn take_pending_in(&self, tid: crate::thread::ThreadId, set: SigSet) -> Option<i32> {
        let mut signal = self.signal.lock();
        let per_thread = signal.pendings.get(&tid).copied().unwrap_or(SigSet::EMPTY);
        let shared = signal.process_pending;
        let candidates = per_thread.union(shared).intersect(set);
        let signum = candidates.lowest_signum()?;
        // A signal pending on THIS thread is taken from its per-thread queue;
        // otherwise it's a process-directed signal from the shared set.
        let from_thread = per_thread.contains(signum);
        // RT signals queue: take one instance, and only clear the pending bit
        // once the last queued instance is drained (so N sends → N deliveries).
        if is_rt_signal(signum) {
            if from_thread {
                let key = (tid, signum);
                let remaining = signal
                    .rt_pending_counts
                    .get(&key)
                    .copied()
                    .unwrap_or(0)
                    .saturating_sub(1);
                if remaining > 0 {
                    signal.rt_pending_counts.insert(key, remaining);
                    return Some(signum); // more queued — leave the bit set
                }
                signal.rt_pending_counts.remove(&key);
                signal.pendings.insert(tid, per_thread.without(signum));
            } else {
                let remaining = signal
                    .process_rt_pending_counts
                    .get(&signum)
                    .copied()
                    .unwrap_or(0)
                    .saturating_sub(1);
                if remaining > 0 {
                    signal.process_rt_pending_counts.insert(signum, remaining);
                    return Some(signum); // more queued — leave the bit set
                }
                signal.process_rt_pending_counts.remove(&signum);
                signal.process_pending = signal.process_pending.without(signum);
            }
            return Some(signum);
        }
        if from_thread {
            signal.pendings.insert(tid, per_thread.without(signum));
        } else {
            signal.process_pending = signal.process_pending.without(signum);
        }
        Some(signum)
    }

    /// `read(2)` on a signalfd: drain pending signals matching the fd's `mask`
    /// for `tid` into `struct signalfd_siginfo` (128-byte) records, consuming
    /// them. Each record fills `ssi_signo`, and — when a queued
    /// `rt_sigqueueinfo` payload exists — `ssi_code`/`ssi_pid`/`ssi_uid`.
    /// Mirrors the inotify read path: a buffer smaller than one record → EINVAL;
    /// an empty queue → EAGAIN (signalfd is overwhelmingly used non-blocking +
    /// epoll; a true blocking wait on the backing readiness is a tracked
    /// follow-up). (audit H4)
    pub fn read_signalfd<M: GuestMemory>(
        &self,
        memory: &mut M,
        address: u64,
        length: usize,
        mask: SigSet,
        tid: crate::thread::ThreadId,
    ) -> DispatchOutcome {
        const SIGINFO_LEN: usize = 128;
        if length < SIGINFO_LEN {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        let max = length / SIGINFO_LEN;
        let mut out: Vec<u8> = Vec::new();
        for _ in 0..max {
            let Some(signum) = self.take_pending_in(tid, mask) else {
                break;
            };
            let mut rec = [0u8; SIGINFO_LEN];
            // ssi_signo @0.
            rec[0..4].copy_from_slice(&(signum as u32).to_le_bytes());
            // Carry a queued rt_sigqueueinfo payload's code/pid/uid if present.
            // LinuxSiginfo packs si_pid (low 32) and si_uid (high 32) into
            // si_addr (see LinuxSiginfo::kill).
            if let Some(info) = self.take_pending_siginfo(tid, signum) {
                rec[8..12].copy_from_slice(&info.si_code.to_le_bytes()); // ssi_code @8
                let pid = (info.si_addr & 0xffff_ffff) as u32;
                let uid = (info.si_addr >> 32) as u32;
                rec[12..16].copy_from_slice(&pid.to_le_bytes()); // ssi_pid @12
                rec[16..20].copy_from_slice(&uid.to_le_bytes()); // ssi_uid @16
            }
            out.extend_from_slice(&rec);
        }
        if out.is_empty() {
            return DispatchOutcome::errno(LINUX_EAGAIN);
        }
        if memory.write_bytes(address, &out).is_err() {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        DispatchOutcome::Returned {
            value: out.len() as i64,
        }
    }

    /// Record a PROCESS-directed signal in the SHARED pending set (no thread
    /// could take it because every thread blocks it). Deliverable to whichever
    /// thread next unblocks or `sigwait`s it. RT signals queue per POSIX.
    fn mark_process_signal_pending(&self, signum: i32) {
        if sigmask_bit(signum).is_some() {
            let mut s = self.signal.lock();
            s.process_pending = s.process_pending.with(signum);
            if is_rt_signal(signum) {
                *s.process_rt_pending_counts.entry(signum).or_insert(0) += 1;
            }
        }
    }

    /// Raise a process-directed `signum` against the guest itself
    /// (`kill(getpid(), sig)`). If the signal is blocked it is held pending;
    /// otherwise it is handed to the runtime's process-directed delivery slot.
    /// signum 0 is the null probe and a no-op success.
    fn raise_self(&self, tid: crate::thread::ThreadId, signum: u64) -> DispatchOutcome {
        if signum == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        let s = signum as i32;
        if s == LINUX_SIGSTOP {
            stop_self_by_signal(s);
            return DispatchOutcome::Returned { value: 0 };
        }
        if self.signal_blocked(tid, s) {
            self.mark_signal_pending(tid, s);
        } else {
            crate::host_signal::raise_for_self(s);
        }
        DispatchOutcome::Returned { value: 0 }
    }

    /// Raise a thread-directed signal at the calling thread (`tkill/tgkill`
    /// self). This must use the per-thread pending slot: publishing into the
    /// process-directed slot lets a sibling consume the signal, which breaks
    /// Linux's `tgkill(getpid(), gettid(), sig)` contract.
    fn raise_thread_directed_self(
        &self,
        tid: crate::thread::ThreadId,
        signum: u64,
    ) -> DispatchOutcome {
        if signum == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        let s = signum as i32;
        if s == LINUX_SIGSTOP {
            stop_self_by_signal(s);
            return DispatchOutcome::Returned { value: 0 };
        }
        if self.signal_blocked(tid, s) {
            self.mark_signal_pending(tid, s);
        } else {
            if let Some(action) = self.registered_signal_handler(s) {
                self.record_pending_signal_action(tid, s, action);
            }
            crate::host_signal::publish_pending_for(tid.raw(), s);
        }
        DispatchOutcome::Returned { value: 0 }
    }

    /// The calling guest thread's tid (or `0` if no thread context).
    pub(crate) fn ctx_tid<M: GuestMemory>(ctx: &SyscallCtx<M>) -> crate::thread::ThreadId {
        ctx.thread
            .as_ref()
            .map(|t| t.tid)
            .unwrap_or(crate::thread::ThreadId::NONE)
    }

    /// Deliver a PROCESS-directed signal (`kill(getpid(), sig)`), honoring the
    /// per-thread signal mask. Linux delivers a process-directed signal to ANY
    /// thread that does not block it. We prefer the calling thread when it has
    /// the signal unblocked (the common case + cheapest); otherwise we route to
    /// the lowest-tid sibling that leaves it unblocked. Only when EVERY thread
    /// blocks the signal is it held pending (on the caller, delivered when it
    /// next unblocks).
    ///
    /// Routing to an unblocked sibling matters for multi-threaded signal
    /// handling: e.g. libuv's signal_multiple_loops blocks all signals in the
    /// main thread and then `kill(getpid(), SIGUSR1)`, expecting a worker thread
    /// to run the (process-wide) handler. Always delivering to the blocked
    /// caller stranded the signal pending and hung the process.
    fn raise_process_directed<M: GuestMemory>(
        &self,
        ctx: &SyscallCtx<M>,
        caller_tid: crate::thread::ThreadId,
        signum: u64,
    ) -> DispatchOutcome {
        if signum == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        let s = signum as i32;
        // Fast path: the calling thread can take it.
        if !self.signal_blocked(caller_tid, s) {
            return self.raise_self(caller_tid, signum);
        }
        // Caller blocks it — find a sibling that doesn't. Lowest tid for
        // determinism.
        if let Some(t) = ctx.thread.as_ref() {
            let mut tids = t.registry.live_tids();
            tids.sort_unstable();
            for tid in tids {
                if tid == caller_tid {
                    continue;
                }
                if !self.signal_blocked(tid, s) {
                    return DispatchOutcome::SignalThread { tid, signum: s };
                }
            }
        }
        // Every thread blocks it: hold it in the SHARED process pending set so
        // whichever thread next unblocks it (rt_sigprocmask) OR dequeues it
        // synchronously (sigwait/rt_sigtimedwait) consumes it. Pinning it to
        // the (blocked) caller stranded a SIBLING thread's sigwait forever
        // (CPython test_sigwait_thread; probe sigwaitthread).
        self.mark_process_signal_pending(s);
        DispatchOutcome::Returned { value: 0 }
    }

    define_syscall! {
        /// kill(pid, sig): send `sig` to process `pid`.
        fn kill(this, cx, pid: Pid, sig: Signal) {
            let signum = sig.0 as u64;
            if !is_valid_signum(signum) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // PID namespace (§5.3, §6.6): translate the guest target.
            //  - pid > 0: an ns-pid → its host pid (kill(1) hits the ns-init);
            //    a non-member → ESRCH.
            //  - pid < -1: a process group `-ns_pgid` → `-host_pgid` (getpgrp/
            //    getpgid now report ns-pgids, so the guest negates an ns-pgid).
            //  - pid == 0 (caller's group) and pid == -1 (every process) pass
            //    through to the host unchanged.
            // Identity when namespaces are off.
            let pid = if crate::namespace::pid::enabled() {
                if pid.0 > 0 {
                    match crate::namespace::pid::ns_to_host_or_self(pid.0 as u32) {
                        Some(h) => i64::from(h as i32),
                        None => return Ok(DispatchOutcome::errno(LINUX_ESRCH)),
                    }
                } else if pid.0 < -1 {
                    let ns_pgid = (-(pid.0 as i64)) as u32;
                    match crate::namespace::pid::ns_to_host_or_self(ns_pgid) {
                        Some(h) => -(i64::from(h as i32)),
                        None => return Ok(DispatchOutcome::errno(LINUX_ESRCH)),
                    }
                } else {
                    i64::from(pid.0)
                }
            } else {
                i64::from(pid.0)
            };
            // pid-1 protection on the NON-namespaced OCI path (§5.4,
            // pid_namespaces(7)). The guest's init presents itself as bootstrap
            // pid 1; carrick does NOT fork a real NsSupervisor here (unlike the
            // macOS/HVF path), so a `kill(1, SIG)` would otherwise fall into the
            // `signal_is_self_target(1)` fast path and self-raise — terminating
            // the SENDER (a forked descendant) instead of being dropped as Linux
            // drops a default-lethal, UNHANDLED signal aimed at pid 1. Intercept
            // BEFORE the self-target fast path: a default-lethal signal to the
            // guest init (bootstrap pid 1) that the init has no handler for is
            // dropped (the call still returns success — Linux delivers nothing
            // but does not error). SIGKILL/SIGSTOP always act and are excluded by
            // `is_init_protected_default_signal`. When THIS process is the init we
            // can consult its own handler table; a forked descendant cannot see
            // the init's table on this path, so a default-lethal unhandled-by-the-
            // sender signal to pid 1 is dropped (the common, Linux-correct case).
            // On the namespaced (macOS/HVF) path the real NsSupervisor is pid 1,
            // `should_drop_signal_to_init` (below) handles it, and `pid` here is
            // the init's translated HOST pid (not bootstrap 1), so this guard is
            // a no-op there.
            if signum != 0
                && pid == LINUX_BOOTSTRAP_PID as i64
                && crate::namespace::pid::is_init_protected_default_signal(signum as i32)
                && this.registered_signal_handler(signum as i32).is_none()
                && !this.signal_is_ignored(signum as i32)
            {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if signal_is_self_target(pid) {
                let tid = Self::ctx_tid(cx);
                if this.proc.lock().ptrace_traceme && signum != 0 {
                    if signum == LINUX_SIGKILL as u64 {
                        crate::guest_cpu::record_child_exit(
                            std::process::id(),
                            crate::guest_cpu::total_ns(),
                        );
                        crate::guest_cpu::mark_self_ptrace_stop_pending();
                        stop_self_by_signal(LINUX_SIGKILL);
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    crate::guest_cpu::mark_self_ptrace_stop_pending();
                    if signum == crate::linux_abi::LINUX_SIGCONT as u64
                        || is_rt_signal(signum as i32)
                    {
                        // Darwin has no host signal numbers for Linux RT
                        // signals (32..=64), and SIGCONT's host default action
                        // is "continue" rather than a tracee delivery stop. A
                        // traced Linux child still becomes waitable as a ptrace
                        // signal-delivery stop; use a host SIGSTOP as the
                        // carrier so the parent observes WIFSTOPPED instead of
                        // the child falling through to normal exit.
                        stop_self_by_signal(LINUX_SIGSTOP);
                    } else {
                        let host_signum = crate::host_signal::linux_to_host_signum(signum as i32);
                        unsafe {
                            libc::raise(host_signum);
                        }
                    }
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                // Linux populates si_pid/si_uid with the sender's identity for a
                // kill(2)-delivered signal (si_code SI_USER). Queue that siginfo
                // so the SA_SIGINFO handler sees the real sender instead of the
                // all-zero synthesised SI_USER. (tkill/tgkill — si_code SI_TKILL
                // — and cross-process sender identity route through the shared
                // thread-signal / host-kill paths and are a tracked follow-up;
                // see conformance-probes/src/bin/siginfo.rs.)
                if signum != 0 {
                    let info = crate::linux_abi::LinuxSiginfo::kill(
                        signum as i32,
                        crate::linux_abi::LINUX_SI_USER,
                        // The sender's identity the handler sees is its ns-pid
                        // (1 for the init), not its host pid (§5.3). Identity
                        // when namespaces are off.
                        crate::namespace::pid::self_ns_pid() as i32,
                        this.cred_snapshot().ruid,
                    );
                    this.record_pending_siginfo(tid, signum as i32, info);
                }
                return Ok(this.raise_process_directed(cx, tid, signum));
            }
            // pid-1 protection (§5.4, pid_namespaces(7)): a default-lethal
            // signal sent to the ns-init by another ns member is DROPPED unless
            // the init installed a handler (SIGKILL/SIGSTOP always act). The
            // call still returns success — Linux delivers nothing but does not
            // error. `pid` is the translated host pid here.
            if pid > 0
                && crate::namespace::pid::should_drop_signal_to_init(pid as u32, signum as i32)
            {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let caller_euid = Some(this.cred_snapshot().euid);
            // `pid` is the ns→host-translated kill(2) pid encoding here (see
            // the translation block above): decompose it into the typed target.
            Ok(bootstrap_signal_send_as(
                SignalTarget::from_host_kill_pid(pid),
                signum,
                caller_euid,
            ))
        }

        /// signalfd4(fd, mask, sizemask, flags): create (fd==-1) or re-target a
        /// signalfd. macOS has no signalfd, so this is emulated. SFD_CLOEXEC ==
        /// O_CLOEXEC and SFD_NONBLOCK == O_NONBLOCK; the dispatch flag table
        /// already rejects other bits (defensive re-check here). Only the fd-flag
        /// surface (FD_CLOEXEC / O_NONBLOCK on the returned fd) is exercised today
        /// (signalfd4_01/02); a read()/poll() delivery path that drains the
        /// process's pending masked signals is a tracked follow-up.
        fn signalfd4(this, cx, fd: Fd, mask: GuestPtr, sizemask: u64, flags: u64) {
            if flags & !(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The kernel sigset_t ABI is exactly 8 bytes (_NSIG/8 on aarch64); any
            // other sizemask is rejected with EINVAL BEFORE the mask pointer is
            // touched (fs/signalfd.c: `if (sizemask != sizeof(sigset_t)) return
            // -EINVAL`). Verified vs docker linux/arm64. (glibc's signalfd() always
            // passes 8 here regardless of its 128-byte userspace sigset_t.)
            if sizemask != 8 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // sigset_t is 8 bytes; read it (EFAULT on bad ptr).
            let mask_val = match cx.memory.read_bytes(mask.0, 8) {
                Ok(b) => {
                    let arr: [u8; 8] = b.as_slice().try_into().unwrap_or([0u8; 8]);
                    SigSet::from_raw(u64::from_le_bytes(arr))
                }
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
            };
            if fd.0 == -1 {
                let description = OpenDescription::SignalFd {
                    base: OpenDescriptionBase::new(flags & LINUX_O_NONBLOCK),
                    mask: mask_val,
                };
                Ok(this.install_fd(description, linux_fd_flags_from_open_flags(flags)))
            } else {
                let Some(open_file) = this.open_file(fd.0) else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                let mut open = open_file.description.write();
                match &mut *open {
                    OpenDescription::SignalFd { mask, .. } => {
                        *mask = mask_val;
                        Ok(DispatchOutcome::Returned { value: fd.0 as i64 })
                    }
                    _ => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                }
            }
        }

        /// tkill(tid, sig): send `sig` to thread `tid`.
        fn tkill(this, cx, tid: Pid, sig: Signal) {
            let tid = i64::from(tid.0);
            let signum = sig.0 as u64;
            if tid <= 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !is_valid_signum(signum) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if let Some((routed, _target)) = this.route_thread_signal(cx, tid, signum, true) {
                return Ok(routed);
            }
            // raise()/pthread_kill name the caller as tkill(gettid()). Under a
            // PID namespace gettid() reports the caller's ns-pid (the main thread
            // reads as the process ns-pid), so a self-target arrives as that
            // ns-pid — recognize it with the ns-aware `names_self_pid`, not
            // `signal_is_self_target` (which only knows the host/bootstrap pid and
            // would send the ns-pid to a nonexistent host tid → ESRCH). Mirrors
            // tgkill below (LTP tkill01).
            if names_self_pid(tid) {
                let self_tid = cx
                    .thread
                    .as_ref()
                    .map(|t| t.tid)
                    .unwrap_or(crate::thread::ThreadId::NONE);
                return Ok(this.raise_self(self_tid, signum));
            }
            Ok(bootstrap_signal_send(
                SignalTarget::GuestTid(NsPid(tid as i32)),
                signum,
            ))
        }

        /// tgkill(tgid, tid, sig): send `sig` to thread `tid` in group `tgid`.
        fn tgkill(this, cx, tgid: Pid, tid: Pid, sig: Signal) {
            let tgid = i64::from(tgid.0);
            let tid = i64::from(tid.0);
            let signum = sig.0 as u64;
            if tgid <= 0 || tid <= 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !is_valid_signum(signum) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if let Some((routed, _target)) = this.route_thread_signal(cx, tid, signum, true) {
                return Ok(routed);
            }
            // raise()/pthread_kill name the caller as tgkill(getpid(), gettid()).
            // Under a PID namespace getpid()/gettid() report the ns-pid, so a
            // self-target here is the caller's ns-pid — not just host-pid/
            // bootstrap. (Sibling threads were already handled by
            // route_thread_signal above.)
            let valid_self = names_self_pid(tgid) && names_self_pid(tid);
            if !valid_self {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            let self_tid = cx
                .thread
                .as_ref()
                .map(|t| t.tid)
                .unwrap_or(crate::thread::ThreadId::NONE);
            Ok(this.raise_self(self_tid, signum))
        }

        /// sigaltstack(ss, old_ss): set/query alternate signal stack.
        fn sigaltstack(this, cx, ss: GuestPtr, old_ss: GuestPtr) {
            let ss = ss.0;
            let old_ss = old_ss.0;
            let tid = cx
                .thread
                .as_ref()
                .map(|t| t.tid)
                .unwrap_or(crate::thread::ThreadId::NONE);
            let memory = &mut *cx.memory;

            let on_altstack = this.is_on_altstack(tid, cx.request.current_guest_sp);
            if old_ss != 0 {
                let mut current = this
                    .signal
                    .lock()
                    .altstack
                    .get(&tid)
                    .copied()
                    .unwrap_or_else(LinuxSigaltstack::disabled);
                // Report SS_ONSTACK while a handler is executing on the alt stack
                // (Linux: the query reflects the current execution state). (M13)
                if on_altstack {
                    current.ss_flags |= LINUX_SS_ONSTACK as i32;
                }
                memory.write_bytes(old_ss, current.abi_bytes())?;
            }

            if ss != 0 {
                // Linux forbids changing the alt stack while executing ON it
                // (the running handler would have the rug pulled out). (M13)
                if on_altstack {
                    return Ok(DispatchOutcome::errno(LINUX_EPERM));
                }
                let bytes = match memory.read_bytes(ss, core::mem::size_of::<LinuxSigaltstack>()) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                };
                let new_stack = match LinuxSigaltstack::read_from_bytes(&bytes) {
                    Ok(stack) => stack,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                };
                let flags = new_stack.ss_flags as u32 as u64;
                if flags & !LINUX_SS_DISABLE != 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if flags & LINUX_SS_DISABLE != 0 {
                    this.signal.lock().altstack.remove(&tid);
                } else {
                    let size = new_stack.ss_size;
                    if size < LINUX_MINSIGSTKSZ {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    this.signal.lock().altstack.insert(tid, new_stack);
                }
            }

            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// rt_sigsuspend(mask_ptr, sigset_size): suspend thread until signal.
        fn rt_sigsuspend(this, cx, mask_ptr: GuestPtr, sigset_size: u64) {
            let mask_ptr = mask_ptr.0;
            let tid = Self::ctx_tid(cx);
            let memory = &*cx.memory;
            if sigset_size != LINUX_RT_SIGSET_SIZE {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let mask_bytes = memory.read_bytes(mask_ptr, LINUX_RT_SIGSET_SIZE as usize)?;
            let suspend_mask = sanitize_signal_mask(SigSet::from_raw(u64::from_le_bytes(
                mask_bytes.try_into().unwrap_or([0; 8]),
            )));
            // sigsuspend semantics (Linux kernel: signal.c rt_sigsuspend):
            //   1. save the current mask;
            //   2. install `suspend_mask`;
            //   3. block until a signal deliverable under `suspend_mask`;
            //   4. arm restore_sigmask so the next handler delivery restores the
            //      saved mask AFTER the handler runs (NOT immediately on
            //      syscall return);
            //   5. return -EINTR.
            // The runtime's delivery cycle then injects the handler under
            // `suspend_mask` (so a previously-pending signal is now deliverable),
            // and `rt_sigreturn` pops the saved mask back via the sigframe.
            // The 5 s wait bound is a safety belt — a missed wake edge yields
            // a spurious EINTR, which the canonical `while (!flag) sigsuspend`
            // idiom transparently re-enters.
            let original = this.signal_mask_for(tid);
            this.restore_signal_mask(tid, suspend_mask);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let signal = this.signal.lock();
                // A queued per-thread signal OR a shared process-directed signal
                // now deliverable under suspend_mask wakes sigsuspend.
                let pending = signal
                    .pendings
                    .get(&tid)
                    .copied()
                    .unwrap_or(SigSet::EMPTY)
                    .union(signal.process_pending);
                drop(signal);
                if !pending.difference(suspend_mask).is_empty() {
                    break; // a queued signal is now deliverable
                }
                // A sibling tgkill/tkill of an unblocked signal lands in the
                // per-tid host slot (THREAD_PENDING) via complete_signal_thread
                // -> publish_pending_for; the global take_pending() below never
                // sees it and the vCPU kick is a no-op while we spin here. Detect
                // it WITHOUT consuming, so the post-EINTR delivery cycle injects
                // the handler under suspend_mask. (audit M3; probe sigsuspendxthread)
                if crate::host_signal::has_unblocked_pending_for(
                    tid.raw(),
                    SigBlockMask::blocking_all_of(suspend_mask),
                ) {
                    break;
                }
                let host_pending = crate::host_signal::take_pending();
                if host_pending != 0 {
                    // Re-raise so the runtime's delivery cycle injects the
                    // handler after this syscall returns EINTR.
                    crate::host_signal::raise_for_self(host_pending);
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            // Keep the temporary mask + arm the post-handler restore ONLY when a
            // caught handler is actually going to run: it runs under
            // `suspend_mask`, and its `rt_sigreturn` pops `original` via the
            // armed mask. On a spurious/timeout wake, or a wake by a signal whose
            // disposition is ignore / default-ignore (no handler runs, so no
            // `rt_sigreturn`), restore `original` HERE — otherwise the thread is
            // stranded running under `suspend_mask`. A cross-thread host-pending
            // wake re-raised above, so a handler will run there too. (audit M1)
            if this.sigsuspend_caught_handler_deliverable(tid, suspend_mask)
                || crate::host_signal::has_unblocked_pending_for(
                    tid.raw(),
                    SigBlockMask::blocking_all_of(suspend_mask),
                )
            {
                this.arm_restore_mask(tid, original);
            } else {
                this.restore_signal_mask(tid, original);
            }
            Ok(DispatchOutcome::errno(LINUX_EINTR))
        }

        /// rt_sigaction(signum, new_action, old_action, sigset_size): configure handler.
        fn rt_sigaction(this, cx, signum: Signal, new_action: GuestPtr, old_action: GuestPtr, sigset_size: u64) {
            let signum = signum.0;
            let new_action = new_action.0;
            let old_action = old_action.0;
            let memory = &mut *cx.memory;
            if sigset_size != LINUX_RT_SIGSET_SIZE {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !(1..=64).contains(&signum) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let new_sa = if new_action != 0 {
                let bytes =
                    match memory.read_bytes(new_action, core::mem::size_of::<LinuxSigaction>()) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                    };
                if signum == LINUX_SIGKILL || signum == LINUX_SIGSTOP {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                match LinuxSigaction::ref_from_bytes(&bytes) {
                    Ok(sa) => {
                        let w = |o: usize| {
                            bytes
                                .get(o..o + 8)
                                .and_then(|s| s.try_into().ok())
                                .map(u64::from_le_bytes)
                                .unwrap_or(0)
                        };
                        crate::probes::sigaction_read(signum, w(0), w(8), w(16), w(24));
                        Some(*sa)
                    }
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
            } else {
                None
            };
            if old_action != 0 {
                let prev = this
                    .signal
                    .lock()
                    .handlers
                    .get(&signum)
                    .copied()
                    .unwrap_or_else(LinuxSigaction::empty);
                if write_kernel_struct_raw(memory, old_action, &prev).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }
            if let Some(sa) = new_sa {
                this.signal.lock().handlers.insert(signum, sa);
                let h = sa.sa_handler;
                let real_handler =
                    h != crate::linux_abi::LINUX_SIG_DFL && h != crate::linux_abi::LINUX_SIG_IGN;
                if real_handler {
                    crate::host_signal::ensure_host_handler(signum);
                    this.request_signal_pump();
                } else if h == crate::linux_abi::LINUX_SIG_IGN {
                    // Mirror SIG_IGN to the host disposition so a CROSS-PROCESS
                    // kill from a sibling guest process is dropped instead of
                    // host-default-terminating us (test_interprocess_signal:
                    // SIGUSR2=SIG_IGN + child kill → parent died -12; probe
                    // xprocsigign). Excludes faults/carrick-managed signals.
                    crate::host_signal::set_host_ignore(signum);
                } else {
                    // h == SIG_DFL: the guest reset the disposition to default.
                    // Clear any host SIG_IGN / routed handler that was mirrored
                    // earlier and possibly INHERITED across fork, so the host no
                    // longer swallows the signal. This is what makes Ctrl-Z work:
                    // a job-control shell sets SIGTSTP=SIG_IGN for itself, then
                    // each forked child resets SIGTSTP to SIG_DFL before exec; the
                    // pty's ^Z (host SIGTSTP) must then actually stop the job
                    // instead of being discarded by the inherited host SIG_IGN.
                    crate::host_signal::set_host_default(signum);
                }
                // pid-1 protection (§5.4): if WE are the ns-init, publish whether
                // we now handle this signal so the kill path knows not to drop a
                // handled signal (and to drop an unhandled default-lethal one).
                // A non-init member's handler table is irrelevant to this.
                if crate::namespace::pid::self_ns_pid() == crate::namespace::pid::NS_INIT_PID {
                    crate::namespace::pid::set_init_handler(signum, real_handler);
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// rt_sigprocmask(how, new_set, old_set, sigset_size): configure blocked mask.
        fn rt_sigprocmask(this, cx, how: u64, new_set: GuestPtr, old_set: GuestPtr, sigset_size: u64) {
            let new_set = new_set.0;
            let old_set = old_set.0;
            let tid = Self::ctx_tid(cx);
            let memory = &mut *cx.memory;
            if sigset_size != LINUX_RT_SIGSET_SIZE {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let previous_mask = this.signal.lock().mask_for(tid);
            if old_set != 0
                && memory
                    .write_bytes(old_set, &previous_mask.raw().to_le_bytes())
                    .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if new_set != 0 {
                let bytes = match memory.read_bytes(new_set, LINUX_RT_SIGSET_SIZE as usize) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                };
                let set = SigSet::from_raw(u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])));
                let mask = match how {
                    LINUX_SIG_BLOCK => previous_mask.union(set),
                    LINUX_SIG_UNBLOCK => previous_mask.difference(set),
                    LINUX_SIG_SETMASK => set,
                    _ => {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                };
                this.signal
                    .lock()
                    .masks
                    .insert(tid, sanitize_signal_mask(mask));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// rt_sigpending(set_ptr, sigset_size): query pending mask.
        fn rt_sigpending(this, cx, set_ptr: GuestPtr, sigset_size: u64) {
            let set_ptr = set_ptr.0;
            let tid = Self::ctx_tid(cx);
            let memory = &mut *cx.memory;
            if sigset_size != LINUX_RT_SIGSET_SIZE {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let signal = this.signal.lock();
            // Pending = this thread's per-thread set UNION the shared process
            // pending set (Linux sigpending reports both).
            let pending = signal
                .pendings
                .get(&tid)
                .copied()
                .unwrap_or(SigSet::EMPTY)
                .union(signal.process_pending);
            drop(signal);
            if set_ptr != 0
                && memory
                    .write_bytes(set_ptr, &pending.raw().to_le_bytes())
                    .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// rt_sigtimedwait(set_ptr, info_ptr, timeout_ptr, sigset_size): wait for signals.
        fn rt_sigtimedwait(this, cx, set_ptr: GuestPtr, info_ptr: GuestPtr, timeout_ptr: GuestPtr, sigset_size: u64) {
            let set_ptr = set_ptr.0;
            let info_ptr = info_ptr.0;
            let timeout_ptr = timeout_ptr.0;
            let tid = Self::ctx_tid(cx);
            let memory = &*cx.memory;
            if sigset_size != LINUX_RT_SIGSET_SIZE {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let set_bytes = match memory.read_bytes(set_ptr, LINUX_RT_SIGSET_SIZE as usize) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            };
            let wait_set =
                SigSet::from_raw(u64::from_le_bytes(set_bytes.try_into().unwrap_or([0; 8])));
            let mut timeout: Option<Duration> = None;
            if timeout_ptr != 0 {
                let ts = read_timespec(memory, timeout_ptr)?;
                let tv_sec = ts.tv_sec;
                let tv_nsec = ts.tv_nsec;
                if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                timeout = Some(Duration::new(tv_sec as u64, tv_nsec as u32));
            }

            this.drain_xsignals_for_tid(tid);
            let memory = &mut *cx.memory;
            if let Some(signum) = this.take_pending_in(tid, wait_set) {
                // Carry any queued rt_sigqueueinfo payload (si_code/pid/uid/value)
                // into the caller's siginfo, not just si_signo. (audit M9)
                let queued = this.take_pending_siginfo(tid, signum);
                return Ok(rt_sigtimedwait_deliver(memory, info_ptr, signum, queued));
            }
            let signum = crate::host_signal::take_pending_in_for(tid.raw(), wait_set);
            if signum != crate::host_signal::NO_PENDING_SIGNAL {
                // A host-delivered signal carries no carrick-queued payload.
                let queued = this.take_pending_siginfo(tid, signum);
                return Ok(rt_sigtimedwait_deliver(memory, info_ptr, signum, queued));
            }
            install_host_handlers_for_wait_set(wait_set);
            match timeout {
                Some(d) if d.is_zero() => Ok(DispatchOutcome::errno(LINUX_EAGAIN)),
                _ => Ok(DispatchOutcome::WaitOnSignals {
                    wait_set,
                    // The named constructor states the park policy: wait-set
                    // signals always wake, unblocked caught non-set signals
                    // wake to EINTR, thread-blocked or to-be-ignored ones
                    // (e.g. handler-less SIGCHLD) do neither.
                    block_mask: SigBlockMask::for_signal_wait(
                        wait_set,
                        this.signal_mask_for(tid),
                        this.wait_ignored_disposition_mask(),
                    ),
                    timeout,
                }),
            }
        }

        /// rt_sigqueueinfo(tgid, sig, info_ptr): queue `sig` to the thread group
        /// with a caller-supplied `siginfo_t` whose `si_value` payload the
        /// SA_SIGINFO handler must observe. Self-target only (guest pid == host
        /// pid); the signal is mark-pending'd (NOT raised via the host slot)
        /// so the queued siginfo can be paired with the delivery: the runtime
        /// pops it from `pending_siginfos[(tid, signum)]` and writes it into
        /// the sigframe instead of synthesising SI_USER.
        fn rt_sigqueueinfo(this, cx, tgid: Pid, sig: Signal, info_ptr: GuestPtr) {
            // rt_sigqueueinfo routes on the tgid itself (LTP rt_sigqueueinfo01
            // permits a non-leader tid here because find_vpid + thread_group
            // still resolve to the same process), so route_target == ns_target.
            let tgid = i64::from(tgid.0);
            Ok(this.sigqueueinfo_common(cx, tgid, tgid, sig.0 as u64, info_ptr))
        }

        /// rt_tgsigqueueinfo(tgid, tid, sig, uinfo): queue `sig` with the
        /// caller's siginfo to a SPECIFIC thread `tid` within thread-group
        /// `tgid` (Linux nr 240). Same delivery machinery as rt_sigqueueinfo,
        /// but the thread routing keys on the explicit `tid` argument rather
        /// than re-using the tgid as the thread. LTP rt_tgsigqueueinfo01 spawns
        /// threads and checks each target's SA_SIGINFO handler observes the
        /// queued si_ptr payload (signal-to-self, to a sibling, and to the
        /// parent thread).
        fn rt_tgsigqueueinfo(this, cx, tgid: Pid, tid: Pid, sig: Signal, info_ptr: GuestPtr) {
            // Same delivery machinery as rt_sigqueueinfo, but routing keys on the
            // explicit `tid` while the self/cross-process decision uses `tgid`.
            Ok(this.sigqueueinfo_common(
                cx,
                i64::from(tid.0),
                i64::from(tgid.0),
                sig.0 as u64,
                info_ptr,
            ))
        }

        /// rt_sigreturn(): pop signal frame and restore registers.
        fn rt_sigreturn(this, cx) {
            // Pop this handler frame's alt-stack record (audit M13).
            this.pop_handler_frame(Self::ctx_tid(cx));
            Ok(DispatchOutcome::SigReturn)
        }
    }

    /// Shared tgkill/tkill routing for the multi-threaded path. Returns
    /// `Some(outcome)` when `tid` names a live thread of this process:
    /// `raise_self` if it's the caller, a queued success if the sibling has the
    /// signal blocked, else a `SignalThread` outcome the runtime delivers +
    /// kicks. Returns `None` (so the caller falls back to the pid/bootstrap
    /// path) when there's no thread context (single-threaded) or `tid` isn't a
    /// live sibling.
    fn route_thread_signal<M: GuestMemory>(
        &self,
        ctx: &SyscallCtx<M>,
        tid: i64,
        signum: u64,
        record_synthetic: bool,
    ) -> Option<(DispatchOutcome, crate::thread::ThreadId)> {
        let t = ctx.thread.as_ref()?;
        let raw_target = crate::thread::ThreadId::from_guest_supplied_tid(tid as i32);
        let target = if t.registry.is_live(raw_target) {
            raw_target
        } else if names_self_pid(tid) {
            let mut tids = t.registry.live_tids();
            tids.sort_unstable();
            tids.into_iter().next()?
        } else {
            return None;
        };
        if target == t.tid {
            // tkill/tgkill carry no payload, so they synthesize an SI_TKILL
            // siginfo here. rt_sigqueueinfo/rt_tgsigqueueinfo pass `false`: they
            // record the caller's REAL payload siginfo themselves, and recording
            // BOTH would queue the zero-payload synthetic AHEAD of the real one
            // for an RT signal (record_pending_siginfo appends for RT) — take()
            // pops the front, so the queued si_value would be lost.
            if record_synthetic {
                self.record_tkill_siginfo(t.tid, signum as i32);
            }
            return Some((self.raise_thread_directed_self(t.tid, signum), target));
        }
        if t.registry.is_live(target) {
            let signum_i32 = signum as i32;
            if record_synthetic {
                self.record_tkill_siginfo(target, signum_i32);
            }
            if self.signal_blocked(target, signum_i32) {
                self.mark_signal_pending(target, signum_i32);
                return Some((DispatchOutcome::Returned { value: 0 }, target));
            }
            if let Some(action) = self.registered_signal_handler(signum_i32) {
                self.record_pending_signal_action(target, signum_i32, action);
            }
            return Some((
                DispatchOutcome::SignalThread {
                    tid: target,
                    signum: signum_i32,
                },
                target,
            ));
        }
        None
    }

    /// Shared body of `rt_sigqueueinfo`/`rt_tgsigqueueinfo`: read the caller's
    /// `siginfo_t` once, route to `route_target` if it names a live sibling
    /// (carrying the queued payload into that thread's SA_SIGINFO frame), else
    /// translate `ns_target` through the PID namespace and either forward
    /// cross-process or mark-pending against the caller. `route_target` is the
    /// tgid for `rt_sigqueueinfo` and the explicit tid for `rt_tgsigqueueinfo`;
    /// `ns_target` is the tgid in both.
    fn sigqueueinfo_common<M: GuestMemory>(
        &self,
        ctx: &SyscallCtx<M>,
        route_target: i64,
        ns_target: i64,
        signum: u64,
        info_ptr: GuestPtr,
    ) -> DispatchOutcome {
        if !is_valid_signum(signum) {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        let s = signum as i32;

        // Read the caller's siginfo once; the kernel re-stamps si_signo.
        let mut user_info: Option<LinuxSiginfo> = None;
        if info_ptr.0 != 0 {
            let memory = &*ctx.memory;
            if let Ok(bytes) = memory.read_bytes(info_ptr.0, core::mem::size_of::<LinuxSiginfo>())
                && let Ok(mut info) = LinuxSiginfo::read_from_bytes(&bytes)
            {
                info.si_signo = s;
                user_info = Some(info);
            }
        }

        // Sibling-thread route: deliver directly so the SA_SIGINFO frame carries
        // the original si_value (LTP rt_sigqueueinfo01 / rt_tgsigqueueinfo01).
        if let Some((routed, target_tid)) =
            self.route_thread_signal(ctx, route_target, signum, false)
        {
            if let Some(info) = user_info {
                self.record_pending_siginfo(target_tid, s, info);
            }
            return routed;
        }

        // PID namespace (§5.3): translate the ns-pid thread-group to its host pid
        // for the self/cross-process decision. Foreign ns-pid → ESRCH; identity
        // when ns is off.
        let ns_target = if crate::namespace::pid::enabled() && ns_target > 0 {
            match crate::namespace::pid::ns_to_host_or_self(ns_target as u32) {
                Some(h) => i64::from(h as i32),
                None => return DispatchOutcome::errno(LINUX_ESRCH),
            }
        } else {
            ns_target
        };
        let host_pid = std::process::id() as i64;
        let is_self = ns_target == host_pid || ns_target == LINUX_BOOTSTRAP_PID as i64;
        if !is_self {
            // Cross-process signal that a plain host kill can't carry faithfully
            // for this target: route it through the shared explicit-signal ring
            // carrying sender identity and optional si_value, then nudge the
            // target. `ns_target` is already the target's HOST pid here.
            if should_route_specific_xsig(ns_target as i32, s) {
                let target_host = ns_target as i32;
                let sender_ns = crate::namespace::pid::self_ns_pid() as i32;
                let sender_uid = self.cred_snapshot().euid;
                // si_value lives at offset 24 of the siginfo = `_pad[0..8]`.
                let value = user_info
                    .and_then(|i| i._pad.get(0..8).and_then(|b| b.try_into().ok()))
                    .map(i64::from_le_bytes)
                    .unwrap_or(0);
                let code = user_info
                    .map(|i| i.si_code)
                    .unwrap_or(crate::linux_abi::LINUX_SI_QUEUE);
                if crate::host_signal::xsig_enqueue(
                    target_host,
                    s,
                    code,
                    sender_ns,
                    sender_uid,
                    value,
                ) {
                    crate::host_signal::xsig_nudge(target_host);
                    return DispatchOutcome::Returned { value: 0 };
                }
            }
            // Non-ring route (or ring full outside a private pid namespace):
            // kill(2)-style host route. `ns_target` is already the host-domain
            // kill(2) pid encoding here (translated above when ns is active).
            return bootstrap_signal_send(SignalTarget::from_host_kill_pid(ns_target), signum);
        }

        // Self-target (single-threaded, or no sibling registry hit): queue
        // against the caller's tid so delivery pairs with the same frame.
        let tid = Self::ctx_tid(ctx);
        if let Some(info) = user_info {
            self.record_pending_siginfo(tid, s, info);
        }
        self.mark_signal_pending(tid, s);
        DispatchOutcome::Returned { value: 0 }
    }
}

pub(crate) fn is_valid_signum(signum: u64) -> bool {
    signum <= LINUX_MAX_SIGNUM
}

/// Signals whose Linux DEFAULT disposition is "ignore" (`Ign`): a SIG_DFL /
/// no-handler instance is dropped, not a terminating action. Mirrors the
/// runtime's `is_default_ignore_signal`; kept here so the dispatcher can
/// compute the no-interrupt mask without crossing crates.
fn is_default_ignore_signum(signum: i32) -> bool {
    matches!(
        signum,
        crate::linux_abi::LINUX_SIGCHLD
            | crate::linux_abi::LINUX_SIGURG
            | crate::linux_abi::LINUX_SIGWINCH
    )
}

/// Bit mask for `signum` (1..=64) within a Linux `sigset_t` word, or
/// `None` if out of range.
fn sigmask_bit(signum: i32) -> Option<u64> {
    if (1..=64).contains(&signum) {
        Some(1u64 << (signum - 1))
    } else {
        None
    }
}

fn install_host_handlers_for_wait_set(wait_set: SigSet) {
    for signum in 1..=64 {
        if wait_set.contains(signum) {
            crate::host_signal::ensure_host_handler(signum);
        }
    }
}

/// Complete a successful `rt_sigtimedwait`: write the FULL `siginfo_t` to
/// `info_ptr` if non-NULL and return the signal number. A `queued`
/// rt_sigqueueinfo payload supplies si_code/si_pid/si_uid/si_value; otherwise a
/// zeroed siginfo carrying just si_signo. The kernel re-stamps si_signo. (M9)
fn rt_sigtimedwait_deliver(
    memory: &mut impl GuestMemory,
    info_ptr: u64,
    signum: i32,
    queued: Option<LinuxSiginfo>,
) -> DispatchOutcome {
    if info_ptr != 0 {
        // No carrick-queued payload (the host-kill routed path): synthesize the
        // SI_USER siginfo from the recorded last sender, exactly as async
        // delivery (`deliver_pending_signal`) does — LTP tse_unmasked_matching
        // checks the dequeued si_pid names the killer child, and an empty
        // si_pid=0 siginfo fails it on the kvm/bhyve lanes where standard
        // cross-process signals arrive as real host signals.
        let queued = queued.or_else(|| {
            let sender_host = crate::host_signal::last_sender_for(signum);
            (sender_host > 0).then(|| {
                let ns_pid = crate::namespace::pid::host_to_ns_or_self(sender_host as u32) as i32;
                let uid = crate::cred_ipc::read_target(sender_host).unwrap_or(0);
                LinuxSiginfo::kill(signum, crate::linux_abi::LINUX_SI_USER, ns_pid, uid)
            })
        });
        let mut si = queued.unwrap_or_else(LinuxSiginfo::empty);
        si.si_signo = signum;
        // A bad `info` pointer must surface EFAULT (the kernel's copyout
        // fault; LTP tse_bad_address). Swallowing it and returning the signum
        // made glibc's sigwaitinfo copy its own buffer to the bad pointer in
        // USERSPACE — killing the guest with SIGSEGV where Linux returns -1.
        if memory.write_bytes(info_ptr, si.as_bytes()).is_err() {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
    }
    DispatchOutcome::Returned {
        value: signum as i64,
    }
}

/// True iff a kill/tkill/tgkill `target` refers to the guest itself.
/// getpid() exposes the host pid, so glibc uses that as the self-id;
/// accept it, LINUX_BOOTSTRAP_PID (1), and — for the pid form — 0
/// (process-group, which is just us in the single-process bootstrap).
fn signal_is_self_target(target: i64) -> bool {
    // Self-target for kill(2): the canonical NsPid::names_self (host pid,
    // bootstrap pid, or the caller's ns-pid). pid 0 is deliberately NOT self —
    // kill(0, sig) targets the caller's whole PROCESS GROUP (which after a fork
    // includes child guest processes); it must fall through to
    // bootstrap_signal_send_as's host group-kill (LTP kill02 "Process 1 did not
    // receive"). names_self also excludes 0, so that group path is preserved.
    // (tgkill/tkill route tids as SignalTarget::GuestTid and never 0.)
    NsPid(target as i32).names_self()
}

/// True iff `x` names THIS process (or thread) — host pid, bootstrap pid, or,
/// under a PID namespace, the caller's own ns-pid (what getpid()/gettid()
/// report there). Used by tgkill/tkill to recognize `raise()`/`pthread_kill`
/// (which target getpid()/gettid()) as a self-signal even when the guest is
/// PID-namespaced.
fn names_self_pid(x: i64) -> bool {
    // The canonical self-check lives on NsPid; this i64 wrapper stays for the
    // signal handlers that hold a raw pid_t (tgkill/tkill).
    NsPid(x as i32).names_self()
}

/// The target of a host-routed (cross-process) signal send — the typed
/// replacement for the old `(target: i64, tid_required: bool)` convention,
/// where a HOST pid, a kill(2) process-group/sentinel encoding, and a guest
/// tid all shared one integer disambiguated by a bool. Each variant names the
/// domain its payload actually lives in; [`Self::host_kill_encoding`] is the
/// ONE raw escape back to the kill(2) wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalTarget {
    /// One process named by its HOST pid: `kill(pid > 0)` after ns→host
    /// translation, `pidfd_send_signal`'s registered host pid, fasync
    /// `F_OWNER_PID` after ns→host translation.
    HostProcess(HostPid),
    /// A HOST process group: `kill(-pgid)` after ns→host-pgid translation,
    /// fasync `F_OWNER_PGRP`. Holds the POSITIVE pgid; the kill(2) negative
    /// encoding exists only inside [`Self::host_kill_encoding`].
    HostProcessGroup(HostPid),
    /// `kill(0)`: every process in the CALLER's own process group.
    CallerProcessGroup,
    /// `kill(-1)`: every process the caller has permission to signal.
    Broadcast,
    /// One thread named by a HOST-domain tid: fasync `F_OWNER_TID` after
    /// ns→host translation. Cross-process, a main-thread tid is the target
    /// process's host pid, which is how the host kill reaches it.
    HostThread(HostPid),
    /// tkill(2)'s cross-process fallthrough: the tid exactly as the GUEST
    /// passed it (ns domain, deliberately untranslated — the pre-enum
    /// behaviour, kept bit-identical; cross-process it names another guest
    /// process's main thread, whose tid equals its pid). Always `> 0` (tkill
    /// rejects the rest with EINVAL before routing here).
    GuestTid(NsPid),
}

impl SignalTarget {
    /// Decompose a kill(2)-style pid argument that is ALREADY in the HOST pid
    /// domain (the caller has done any ns→host translation): `> 0` one host
    /// process, `0` the caller's process group, `-1` broadcast, `< -1` a host
    /// process group as `-pgid`. NOT for raw guest/ns values — translate
    /// first.
    pub(crate) fn from_host_kill_pid(pid: i64) -> Self {
        if pid > 0 {
            Self::HostProcess(HostPid(pid as u32))
        } else if pid == 0 {
            Self::CallerProcessGroup
        } else if pid == -1 {
            Self::Broadcast
        } else {
            Self::HostProcessGroup(HostPid(pid.unsigned_abs() as u32))
        }
    }

    /// The kill(2) encoding of this target — the exact i64 the old raw
    /// `target` parameter carried. Every comparison in
    /// [`bootstrap_signal_send_as`] (self test, `0` = caller's group, the
    /// i32-range ESRCH guard, the `> 0` xsig gate) and the final `libc::kill`
    /// operate on this value, so the sign/sentinel semantics live in one
    /// place.
    fn host_kill_encoding(self) -> i64 {
        match self {
            Self::HostProcess(p) | Self::HostThread(p) => i64::from(p.0),
            Self::HostProcessGroup(pg) => -i64::from(pg.0),
            Self::CallerProcessGroup => 0,
            Self::Broadcast => -1,
            Self::GuestTid(t) => i64::from(t.0),
        }
    }
}

pub(crate) fn bootstrap_signal_send(target: SignalTarget, signum: u64) -> DispatchOutcome {
    bootstrap_signal_send_as(target, signum, /*caller_euid=*/ None)
}

/// Same as [`bootstrap_signal_send`] but the caller passes its own current
/// euid so we can enforce Linux's kill(2) permission check across guest
/// processes. `None` means "skip the check" (used by the self-target /
/// process-group cases that don't cross processes).
pub(crate) fn bootstrap_signal_send_as(
    target: SignalTarget,
    signum: u64,
    caller_euid: Option<u32>,
) -> DispatchOutcome {
    if !is_valid_signum(signum) {
        return DispatchOutcome::errno(LINUX_EINVAL);
    }
    // The raw kill(2) value this target denotes: every sign/sentinel test
    // below and the final host kill read this single escape.
    let target = target.host_kill_encoding();
    // getpid() exposes the host pid (std::process::id()) so glibc and
    // friends use that as the self-id when calling kill/tkill/tgkill.
    // Accept either that or LINUX_BOOTSTRAP_PID so existing callers
    // that hard-coded `1` keep working.
    let host_pid = std::process::id() as i64;
    let bootstrap_pid = LINUX_BOOTSTRAP_PID as i64;
    // A specific self-pid (kill(getpid())) is self. kill(0) — CallerProcessGroup
    // — is NOT self: it targets the caller's whole PROCESS GROUP, which after a
    // guest fork includes child guest processes (separate host pids in the same
    // host group). It must reach them via the host group-kill below — the same
    // path kill(-pgid) takes — not raise_for_self, which signals only the
    // caller and made LTP kill02 TFAIL ("Process 1 did not receive the
    // signal"). Self is still covered: the host group-kill delivers to the
    // caller's own host process too, routed into the guest like any other
    // cross-process signal (identical to how kill(-own_pgid) already works).
    let self_target = target == host_pid || target == bootstrap_pid;
    if self_target {
        if signum == 0 {
            // POSIX: signum 0 is the null-signal "is this pid alive" probe.
            return DispatchOutcome::Returned { value: 0 };
        }
        // Queue the signal for self-delivery. The runtime drains the pending
        // slot between vCPU iterations and either injects a handler frame or
        // applies the default action (terminate with 128 + signum).
        crate::host_signal::raise_for_self(signum as i32);
        return DispatchOutcome::Returned { value: 0 };
    }
    // kill(0) = the caller's process group. Fanning it out via a host group-kill
    // is safe ONLY when carrick leads its own process group (so the group holds
    // just carrick + its guest children) — true under the conformance harness
    // (which spawns carrick with its own process group) and after any guest
    // setpgrp/setsid. If carrick is NOT the group leader (a bare foreground
    // `carrick run` still in the launcher's group), a host kill(0) would escape
    // to the launcher's other jobs — so degrade to self-only delivery: correct
    // for the contained case, safe for the shared one.
    if target == 0 && unsafe { libc::getpgrp() } != std::process::id() as i32 {
        if signum != 0 {
            crate::host_signal::raise_for_self(signum as i32);
        }
        return DispatchOutcome::Returned { value: 0 };
    }
    // Cross-process: enforce kill(2)'s Linux permission model when both
    // the caller and the target have published a guest euid. Root (euid==0)
    // can signal anyone (matches Linux's CAP_KILL effective semantics for
    // the simple uid-only model); a non-root caller must share the
    // target's euid. LTP `kill05` walks this path: parent sets euid=Y,
    // child sets euid=X (different); parent's `kill(child, SIGKILL)` must
    // return EPERM. If we can't read either cred (peer is non-carrick or
    // hasn't published yet) we fall through to allow — matching today's
    // behaviour for processes outside the published set.
    if let (Some(caller), Some(target_euid)) =
        (caller_euid, crate::cred_ipc::read_target(target as i32))
        && caller != 0
        && caller != target_euid
    {
        return DispatchOutcome::errno(LINUX_EPERM);
    }
    // Cross-process kill: target is some other host pid. After clone(),
    // child guests run as separate host processes — apt's parent
    // process uses kill(child_pid, SIGINT) as part of the AcquireMethod
    // shutdown protocol, and ESRCH here breaks the protocol with
    // "method did not start correctly". Defer to libc::kill on the host;
    // the host kernel knows whether `target` is one of our descendants
    // and returns ESRCH itself if not. Negative pids (process-group kill)
    // pass through too.
    // target == 0 (the caller's process group) and target < -1 (a specific
    // process group) both deliver to a host process group via libc::kill below;
    // only an out-of-i32 target is a genuinely non-existent pid.
    if target < i32::MIN as i64 || target > i32::MAX as i64 {
        return DispatchOutcome::errno(LINUX_ESRCH);
    }
    // A plain host kill can't faithfully carry some cross-process signals to
    // another carrick process. For private-pid-namespace members, route every
    // catchable specific-target signal through the shared explicit-signal ring
    // too: the ring carries sender ns-pid directly, instead of relying on a
    // process-global host siginfo side channel that races under signal floods.
    let route_xsig = target > 0 && should_route_specific_xsig(target as i32, signum as i32);
    if route_xsig {
        let sender_ns = crate::namespace::pid::self_ns_pid() as i32;
        let sender_uid = caller_euid.unwrap_or_else(|| unsafe { libc::getuid() });
        if crate::host_signal::xsig_enqueue(
            target as i32,
            signum as i32,
            crate::linux_abi::LINUX_SI_USER,
            sender_ns,
            sender_uid,
            0,
        ) {
            crate::host_signal::xsig_nudge(target as i32);
            return DispatchOutcome::Returned { value: 0 };
        }
        if crate::namespace::pid::enabled()
            && namespace_member_standard_kill_needs_xsig(signum as i32)
        {
            return DispatchOutcome::Returned { value: 0 };
        }
        // Ring full / unavailable: fall through to the host kill below.
    }
    // Translate the Linux signum to the host's numbering: the target is a real
    // host process, and Linux/macOS disagree on several numbers (e.g. SIGUSR1
    // 10 vs 30). `wait4` translates the resulting status back to Linux.
    let host_signum = crate::host_signal::linux_to_host_signum(signum as i32);
    let rc = unsafe { libc::kill(target as i32, host_signum) };
    if let Err(errno) = rc.host_syscall_errno() {
        return DispatchOutcome::errno(errno);
    }
    DispatchOutcome::Returned { value: 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_process_xsig_policy_routes_unhostable_signals() {
        // SIGPIPE: both backends keep a process-wide host SIG_IGN for it (and
        // never mirror a guest disposition onto host SIGPIPE), so a plain host
        // kill is silently dropped — it MUST take the ring (LTP sigrelse01).
        assert!(cross_process_needs_xsig(crate::linux_abi::LINUX_SIGPIPE));
        // SIGCHLD, Linux-only SIGSTKFLT/SIGPWR, the synchronous-fault set, and
        // RT signals (no host number / host disposition owned by another
        // mechanism) ride the ring too.
        assert!(cross_process_needs_xsig(crate::linux_abi::LINUX_SIGCHLD));
        assert!(cross_process_needs_xsig(crate::linux_abi::LINUX_SIGSTKFLT));
        assert!(cross_process_needs_xsig(crate::linux_abi::LINUX_SIGPWR));
        for s in [4, 5, 6, 7, 8, 11, 34] {
            assert!(cross_process_needs_xsig(s), "signum {s} must take the ring");
        }
        // Ordinary host-carryable standard signals stay on the host-kill path
        // (the routed-handler mirror delivers them faithfully).
        for s in [1, 10, 12, 14, 15] {
            assert!(!cross_process_needs_xsig(s), "signum {s} is host-carryable");
        }
    }

    #[test]
    fn namespace_member_xsig_policy_routes_catchable_standard_signals() {
        assert!(namespace_member_standard_kill_needs_xsig(
            crate::linux_abi::LINUX_SIGUSR1
        ));
        assert!(namespace_member_standard_kill_needs_xsig(
            crate::linux_abi::LINUX_SIGUSR2
        ));
        assert!(namespace_member_standard_kill_needs_xsig(15));
        assert!(!namespace_member_standard_kill_needs_xsig(0));
        assert!(!namespace_member_standard_kill_needs_xsig(LINUX_SIGKILL));
        assert!(!namespace_member_standard_kill_needs_xsig(
            crate::linux_abi::LINUX_SIGCONT
        ));
        assert!(!namespace_member_standard_kill_needs_xsig(LINUX_SIGSTOP));
        assert!(!namespace_member_standard_kill_needs_xsig(34));
        assert!(!namespace_member_standard_kill_needs_xsig(65));
    }

    #[test]
    fn rt_signals_queue_while_standard_signals_coalesce() {
        let d = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        // A standard signal (10) sent 3× while pending coalesces to one delivery.
        d.mark_signal_pending(tid, 10);
        d.mark_signal_pending(tid, 10);
        d.mark_signal_pending(tid, 10);
        assert_eq!(d.take_deliverable_pending(tid), Some(10));
        assert_eq!(d.take_deliverable_pending(tid), None);

        // A real-time signal (34) sent 3× delivers 3× (POSIX queuing).
        d.mark_signal_pending(tid, 34);
        d.mark_signal_pending(tid, 34);
        d.mark_signal_pending(tid, 34);
        assert_eq!(d.take_deliverable_pending(tid), Some(34));
        assert_eq!(d.take_deliverable_pending(tid), Some(34));
        assert_eq!(d.take_deliverable_pending(tid), Some(34));
        assert_eq!(d.take_deliverable_pending(tid), None);

        // Mixed: the lowest deliverable comes first, then the RT queue drains.
        d.mark_signal_pending(tid, 34);
        d.mark_signal_pending(tid, 34);
        d.mark_signal_pending(tid, 10);
        assert_eq!(d.take_deliverable_pending(tid), Some(10));
        assert_eq!(d.take_deliverable_pending(tid), Some(34));
        assert_eq!(d.take_deliverable_pending(tid), Some(34));
        assert_eq!(d.take_deliverable_pending(tid), None);

        // Thread teardown clears the RT queue too (no leak into a recycled tid).
        d.mark_signal_pending(tid, 34);
        d.forget_thread_signal_state(tid);
        assert_eq!(d.take_deliverable_pending(tid), None);
    }

    #[test]
    fn process_directed_pending_is_consumable_by_any_thread() {
        // A process-directed signal that EVERY thread blocks lands in the shared
        // pending set (raise_process_directed's all-blocked branch). It must be
        // dequeuable by a thread OTHER than the sender — the CPython
        // test_sigwait_thread case where the killer thread sends and a SIBLING
        // (the main thread) is parked in sigwait. Pinning to the sender's tid
        // stranded that sibling forever (probe sigwaitthread).
        let d = SyscallDispatcher::new();
        let sender = crate::thread::ThreadId::synthetic_for_tests(7);
        let waiter = crate::thread::ThreadId::synthetic_for_tests(42);
        let usr1 = 10i32;
        let set = SigSet::EMPTY.with(usr1);

        d.mark_process_signal_pending(usr1);
        // A sigwait whose set does NOT include SIGUSR1 must not dequeue it.
        let other = SigSet::EMPTY.with(12); // SIGUSR2 (12), not SIGUSR1
        assert_eq!(d.take_pending_in(waiter, other), None);
        // The SIBLING (a thread other than the sender) parked in sigwait
        // selecting SIGUSR1 dequeues the shared signal — the core fix.
        assert_eq!(d.take_pending_in(waiter, set), Some(usr1));
        // Consumed exactly once — no second thread can also take it.
        assert_eq!(d.take_pending_in(sender, set), None);
        assert_eq!(d.take_pending_in(waiter, set), None);

        // The deliver-on-unblock path (take_deliverable_pending) also drains the
        // shared set, for a thread that unblocks the signal without sigwait.
        d.mark_process_signal_pending(usr1);
        assert_eq!(d.take_deliverable_pending(waiter), Some(usr1));
        assert_eq!(d.take_deliverable_pending(sender), None);

        // Shared RT signals queue per POSIX (N sends → N deliveries), independent
        // of which thread drains them.
        d.mark_process_signal_pending(34);
        d.mark_process_signal_pending(34);
        assert_eq!(d.take_deliverable_pending(waiter), Some(34));
        assert_eq!(d.take_deliverable_pending(sender), Some(34));
        assert_eq!(d.take_deliverable_pending(waiter), None);
    }

    #[test]
    fn rt_signal_survives_handler_mask_restore() {
        let d = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::main_from_host_pid();
        let signum = 34;
        let action = LinuxSigaction {
            sa_handler: 0x1000,
            ..LinuxSigaction::empty()
        };

        d.mark_signal_pending(tid, signum);
        d.mark_signal_pending(tid, signum);
        assert_eq!(d.take_deliverable_pending(tid), Some(signum));
        let saved = d.enter_signal_handler(tid, signum, action);
        assert_eq!(d.take_deliverable_pending(tid), None);
        d.restore_signal_mask(tid, saved);
        assert_eq!(d.take_deliverable_pending(tid), Some(signum));
        assert_eq!(d.take_deliverable_pending(tid), None);
    }

    #[test]
    fn wait_predicate_sees_shared_process_pending() {
        use carrick_abi::WaitSigMask;

        let d = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::synthetic_for_tests(42);
        let usr1 = 10;
        let blocked = SigSet::EMPTY.with(usr1);

        d.mark_process_signal_pending(usr1);

        // Additive (read/recv, empty extra set): an UNBLOCKED pending signal is
        // deliverable and interrupts the wait.
        assert!(d.has_deliverable_dispatch_pending_for_wait(tid, WaitSigMask::NONE));
        // Replace (ppoll/pselect/epoll_pwait): a signal the temp mask BLOCKS does
        // not interrupt.
        assert!(!d.has_deliverable_dispatch_pending_for_wait(tid, WaitSigMask::Replace(blocked)));
        d.restore_signal_mask(tid, blocked);
        // Additive: a signal blocked by the thread's PERSISTENT mask must NOT
        // interrupt a plain read — this is the `maskfork` invariant.
        assert!(!d.has_deliverable_dispatch_pending_for_wait(tid, WaitSigMask::NONE));
        // Replace: an EMPTY temp mask UNBLOCKS that persistently-blocked pending
        // signal, so it MUST be deliverable — POSIX ppoll/pselect replace
        // semantics. Unioning the persistent mask would wrongly suppress it; this
        // guards the `ppollunblock` regression.
        assert!(
            d.has_deliverable_dispatch_pending_for_wait(tid, WaitSigMask::Replace(SigSet::EMPTY))
        );
    }

    #[test]
    fn child_exit_signal_pump_predicate_tracks_observable_dispositions() {
        let d = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::synthetic_for_tests(7);

        assert!(
            !d.child_exit_signal_needs_pump(tid, crate::linux_abi::LINUX_SIGCHLD as u32),
            "default unblocked SIGCHLD is inert; wait4 owns the reap path"
        );
        assert!(
            d.child_exit_signal_needs_pump(tid, crate::linux_abi::LINUX_SIGUSR1 as u32),
            "non-ignored default exit signals can terminate the parent"
        );

        let chld_set = SigSet::EMPTY.with(crate::linux_abi::LINUX_SIGCHLD);
        d.signal.lock().masks.insert(tid, chld_set);
        assert!(
            d.child_exit_signal_needs_pump(tid, crate::linux_abi::LINUX_SIGCHLD as u32),
            "blocked SIGCHLD must become pending for sigwait/sigtimedwait"
        );

        let mut ign = LinuxSigaction::empty();
        ign.sa_handler = crate::linux_abi::LINUX_SIG_IGN;
        d.signal
            .lock()
            .handlers
            .insert(crate::linux_abi::LINUX_SIGCHLD, ign);
        assert!(
            !d.child_exit_signal_needs_pump(tid, crate::linux_abi::LINUX_SIGCHLD as u32),
            "explicit SIG_IGN suppresses the async notification even if the mask contains SIGCHLD"
        );

        let mut caught = LinuxSigaction::empty();
        caught.sa_handler = 0x4000;
        d.signal
            .lock()
            .handlers
            .insert(crate::linux_abi::LINUX_SIGCHLD, caught);
        assert!(
            d.child_exit_signal_needs_pump(tid, crate::linux_abi::LINUX_SIGCHLD as u32),
            "caught SIGCHLD needs the pump so a spinning parent observes the handler"
        );

        assert!(
            !d.child_exit_signal_needs_pump(tid, 0),
            "clone exit_signal 0 requests no signal"
        );
    }

    #[test]
    fn execve_resets_caught_handlers_preserves_sig_ign_and_clears_altstack() {
        let d = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);
        {
            let mut s = d.signal.lock();
            // A CAUGHT SIGCHLD handler (a real address) — must reset to default.
            let mut chld = LinuxSigaction::empty();
            chld.sa_handler = 0x1000133c0;
            s.handlers.insert(crate::linux_abi::LINUX_SIGCHLD, chld);
            // SIG_IGN for SIGUSR1 (10) — must be PRESERVED across execve.
            let mut ign = LinuxSigaction::empty();
            ign.sa_handler = crate::linux_abi::LINUX_SIG_IGN;
            s.handlers.insert(10, ign);
            // An installed alternate signal stack — execve disestablishes it.
            s.altstack.insert(
                tid,
                LinuxSigaltstack {
                    ss_sp: 0x4000,
                    ss_flags: 0,
                    __pad: 0,
                    ss_size: 0x2000,
                },
            );
            // Active handler-frame and restore-mask state belongs to the old
            // user image's signal frame; it must not poison the exec'd image's
            // first sigaltstack() call.
            s.handler_frames.insert(tid, vec![true]);
            s.restore_masks.insert(tid, SigSet::from_raw(0x1234));
        }
        // Pre-execve: the caught handler is live.
        assert!(
            d.registered_signal_handler(crate::linux_abi::LINUX_SIGCHLD)
                .is_some()
        );

        d.reset_signal_handlers_on_execve();

        // The caught SIGCHLD handler is reset to default (no leak of the old
        // image's handler address — the bug that crashed shell-launched tests).
        assert!(
            d.registered_signal_handler(crate::linux_abi::LINUX_SIGCHLD)
                .is_none()
        );
        // SIG_IGN survives execve (Linux semantics).
        assert!(d.signal_is_ignored(10));
        // The alternate signal stack is cleared.
        assert!(d.signal_altstack(tid).is_none());
        let signal = d.signal.lock();
        assert!(signal.handler_frames.is_empty());
        assert!(signal.restore_masks.is_empty());
    }

    #[test]
    fn sa_resethand_resets_disposition_to_default_on_handler_entry() {
        let d = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        // A one-shot (SA_RESETHAND) handler for SIGUSR1 (10).
        let mut oneshot = LinuxSigaction::empty();
        oneshot.sa_handler = 0x4000;
        oneshot.sa_flags =
            crate::linux_abi::LINUX_SA_RESETHAND | crate::linux_abi::LINUX_SA_SIGINFO;
        d.signal.lock().handlers.insert(10, oneshot);
        assert!(d.registered_signal_handler(10).is_some());

        // Entering the handler resets the disposition to SIG_DFL (Linux's
        // one-shot semantics): a second occurrence takes the default action.
        d.enter_signal_handler(tid, 10, oneshot);
        assert!(
            d.registered_signal_handler(10).is_none(),
            "SA_RESETHAND handler must reset to SIG_DFL on entry"
        );
        let reset = d.signal.lock().handlers.get(&10).copied().unwrap();
        let reset_handler = reset.sa_handler;
        let reset_flags = reset.sa_flags;
        assert_eq!(reset_handler, crate::linux_abi::LINUX_SIG_DFL);
        assert_ne!(
            reset_flags & crate::linux_abi::LINUX_SA_SIGINFO,
            0,
            "SA_RESETHAND must not clear SA_SIGINFO from sigaction old state"
        );

        // Control: a handler WITHOUT SA_RESETHAND persists across entry.
        let mut sticky = LinuxSigaction::empty();
        sticky.sa_handler = 0x5000;
        d.signal.lock().handlers.insert(11, sticky);
        d.enter_signal_handler(tid, 11, sticky);
        assert!(
            d.registered_signal_handler(11).is_some(),
            "a non-RESETHAND handler must persist across entry"
        );
    }

    #[test]
    fn thread_directed_pending_action_survives_later_ignore_disposition() {
        let d = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);
        let signum = 34;

        let mut caught = LinuxSigaction::empty();
        caught.sa_handler = 0x4000;
        caught.sa_flags = crate::linux_abi::LINUX_SA_RESTORER;
        caught.sa_restorer = 0x5000;
        d.record_pending_signal_action(tid, signum, caught);

        let mut ignored = LinuxSigaction::empty();
        ignored.sa_handler = crate::linux_abi::LINUX_SIG_IGN;
        d.signal.lock().handlers.insert(signum, ignored);
        assert!(d.registered_signal_handler(signum).is_none());
        assert!(d.signal_is_ignored(signum));

        let delivered = d.take_pending_signal_action(tid, signum).unwrap();
        let delivered_handler = delivered.sa_handler;
        let delivered_restorer = delivered.sa_restorer;
        let caught_handler = caught.sa_handler;
        let caught_restorer = caught.sa_restorer;
        assert_eq!(delivered_handler, caught_handler);
        assert_eq!(delivered_restorer, caught_restorer);
        assert!(d.take_pending_signal_action(tid, signum).is_none());
    }

    #[test]
    fn sibling_thread_signal_snapshots_current_handler_action() {
        let d = SyscallDispatcher::new();
        let caller = crate::thread::ThreadId::synthetic_for_tests(1000);
        let registry = crate::thread::ThreadRegistry::new(caller);
        let target = registry.register_child(0);
        let futex = crate::thread::FutexTable::new();
        let mut memory = crate::dispatch::LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = crate::compat::CompatReporter::default();
        let cx = crate::dispatch::SyscallCtx {
            request: crate::dispatch::SyscallRequest::new(
                130,
                crate::dispatch::SyscallArgs::from([target.raw() as u64, 34, 0, 0, 0, 0]),
            ),
            memory: &mut memory,
            reporter: &reporter,
            thread: Some(crate::dispatch::ThreadCtx {
                tid: caller,
                registry: &registry,
                futex: &futex,
            }),
        };

        let mut caught = LinuxSigaction::empty();
        caught.sa_handler = 0x4000;
        caught.sa_flags = crate::linux_abi::LINUX_SA_RESTORER;
        caught.sa_restorer = 0x5000;
        d.signal.lock().handlers.insert(34, caught);

        let routed = d.route_thread_signal(&cx, i64::from(target.raw()), 34, true);
        assert!(matches!(
            routed,
            Some((crate::dispatch::DispatchOutcome::SignalThread { tid, signum }, resolved))
                if tid == target && signum == 34 && resolved == target
        ));

        let mut ignored = LinuxSigaction::empty();
        ignored.sa_handler = crate::linux_abi::LINUX_SIG_IGN;
        d.signal.lock().handlers.insert(34, ignored);
        assert!(d.signal_is_ignored(34));

        let delivered = d.take_pending_signal_action(target, 34).unwrap();
        let delivered_handler = delivered.sa_handler;
        let delivered_restorer = delivered.sa_restorer;
        let caught_handler = caught.sa_handler;
        let caught_restorer = caught.sa_restorer;
        assert_eq!(delivered_handler, caught_handler);
        assert_eq!(delivered_restorer, caught_restorer);
    }

    #[test]
    fn thread_signal_to_guest_main_tid_routes_to_registry_main_thread() {
        let d = SyscallDispatcher::new();
        let main = crate::thread::ThreadId::synthetic_for_tests(1000);
        let registry = crate::thread::ThreadRegistry::new(main);
        let caller = registry.register_child(0);
        let futex = crate::thread::FutexTable::new();
        let mut memory = crate::dispatch::LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = crate::compat::CompatReporter::default();
        let guest_main_tid = i64::from(std::process::id());
        let cx = crate::dispatch::SyscallCtx {
            request: crate::dispatch::SyscallRequest::new(
                130,
                crate::dispatch::SyscallArgs::from([guest_main_tid as u64, 34, 0, 0, 0, 0]),
            ),
            memory: &mut memory,
            reporter: &reporter,
            thread: Some(crate::dispatch::ThreadCtx {
                tid: caller,
                registry: &registry,
                futex: &futex,
            }),
        };

        let mut caught = LinuxSigaction::empty();
        caught.sa_handler = 0x4000;
        caught.sa_flags = crate::linux_abi::LINUX_SA_RESTORER;
        caught.sa_restorer = 0x5000;
        d.signal.lock().handlers.insert(34, caught);

        let routed = d.route_thread_signal(&cx, guest_main_tid, 34, true);
        assert!(matches!(
            routed,
            Some((crate::dispatch::DispatchOutcome::SignalThread { tid, signum }, resolved))
                if tid == main && signum == 34 && resolved == main
        ));
        assert!(d.take_pending_signal_action(main, 34).is_some());
    }

    #[test]
    fn sigqueueinfo_payload_uses_resolved_guest_main_thread_key() {
        use zerocopy::IntoBytes;

        let d = SyscallDispatcher::new();
        let main = crate::thread::ThreadId::synthetic_for_tests(1000);
        let registry = crate::thread::ThreadRegistry::new(main);
        let caller = registry.register_child(0);
        let futex = crate::thread::FutexTable::new();
        let mut memory = crate::dispatch::LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = crate::compat::CompatReporter::default();
        let guest_main_tid = i64::from(std::process::id());
        let siginfo = LinuxSiginfo::rt_queue(34, 1234, 0, 0x00ca_fe42);
        memory.write_bytes(0x400, siginfo.as_bytes()).unwrap();
        let cx = crate::dispatch::SyscallCtx {
            request: crate::dispatch::SyscallRequest::new(
                129,
                crate::dispatch::SyscallArgs::from([guest_main_tid as u64, 34, 0x400, 0, 0, 0]),
            ),
            memory: &mut memory,
            reporter: &reporter,
            thread: Some(crate::dispatch::ThreadCtx {
                tid: caller,
                registry: &registry,
                futex: &futex,
            }),
        };

        let routed =
            d.sigqueueinfo_common(&cx, guest_main_tid, guest_main_tid, 34, GuestPtr(0x400));
        assert!(matches!(
            routed,
            crate::dispatch::DispatchOutcome::SignalThread { tid, signum }
                if tid == main && signum == 34
        ));
        assert!(
            d.take_pending_siginfo(
                crate::thread::ThreadId::from_guest_supplied_tid(guest_main_tid as i32),
                34
            )
            .is_none()
        );
        let queued = d.take_pending_siginfo(main, 34).unwrap();
        assert_eq!(queued._pad[0..8], siginfo._pad[0..8]);
    }

    #[test]
    fn clone_thread_inherits_signal_mask_without_pending_or_altstack() {
        let d = SyscallDispatcher::new();
        let parent = crate::thread::ThreadId::synthetic_for_tests(1);
        let child = crate::thread::ThreadId::synthetic_for_tests(2);
        let blocked = SigSet::EMPTY.with(10).with(34);

        d.restore_signal_mask(parent, blocked);
        d.mark_signal_pending(child, 34);
        d.signal.lock().altstack.insert(
            child,
            LinuxSigaltstack {
                ss_sp: 0x4000,
                ss_flags: 0,
                __pad: 0,
                ss_size: 0x2000,
            },
        );

        d.inherit_thread_signal_mask(parent, child);

        assert_eq!(d.signal_mask_for(child), blocked);
        assert_eq!(d.take_deliverable_pending(child), None);
        assert!(d.signal_altstack(child).is_none());
    }

    #[test]
    fn sigaltstack_reports_ss_onstack_and_rejects_reconfigure_while_on_stack() {
        let d = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        // Configure an alt stack for the thread.
        d.signal.lock().altstack.insert(
            tid,
            LinuxSigaltstack {
                ss_sp: 0x4000,
                ss_flags: 0,
                __pad: 0,
                ss_size: 0x4000,
            },
        );
        // Not in a handler yet → not on the alt stack.
        assert!(!d.is_on_altstack(tid, None));

        // Enter an SA_ONSTACK handler → now executing on the alt stack.
        let mut on = LinuxSigaction::empty();
        on.sa_handler = 0x9000;
        on.sa_flags = crate::linux_abi::LINUX_SA_ONSTACK;
        d.enter_signal_handler(tid, 10, on);
        assert!(
            d.is_on_altstack(tid, None),
            "SA_ONSTACK handler marks the thread on-stack"
        );

        // rt_sigreturn pops the frame → back off the alt stack.
        d.pop_handler_frame(tid);
        assert!(!d.is_on_altstack(tid, None));

        // A handler WITHOUT SA_ONSTACK does not mark the thread on-stack.
        let mut off = LinuxSigaction::empty();
        off.sa_handler = 0x9000;
        d.enter_signal_handler(tid, 11, off);
        assert!(
            !d.is_on_altstack(tid, None),
            "a non-SA_ONSTACK handler is not on the alt stack"
        );
        d.pop_handler_frame(tid);
    }

    #[test]
    fn siglongjmp_stale_altstack_frame_is_reconciled_from_guest_sp() {
        let d = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        d.signal.lock().altstack.insert(
            tid,
            LinuxSigaltstack {
                ss_sp: 0x4000,
                ss_flags: 0,
                __pad: 0,
                ss_size: 0x4000,
            },
        );
        d.signal.lock().handler_frames.insert(tid, vec![true]);

        assert!(
            d.is_on_altstack(tid, Some(0x7000)),
            "live SP inside altstack keeps SS_ONSTACK state"
        );
        assert!(
            !d.is_on_altstack(tid, Some(0x9000)),
            "SP outside altstack means siglongjmp escaped the handler frame"
        );
        assert!(
            !d.signal.lock().handler_frames.contains_key(&tid),
            "stale handler-frame bookkeeping should be cleared"
        );
    }

    #[test]
    fn rt_sigsuspend_keeps_temp_mask_only_when_a_caught_handler_will_run() {
        let d = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);
        let unblock_all = SigSet::EMPTY;

        // Spurious / timeout wake: nothing pending → DON'T keep the temp mask
        // (rt_sigsuspend must restore the saved mask, not strand the thread).
        assert!(!d.sigsuspend_caught_handler_deliverable(tid, unblock_all));

        // A deliverable signal with NO caught handler (default disposition):
        // no handler runs, so still restore.
        d.mark_signal_pending(tid, 10);
        assert!(!d.sigsuspend_caught_handler_deliverable(tid, unblock_all));

        // Install a caught handler for SIGUSR1 (10): now a handler WILL run, so
        // the temp mask is kept and the post-handler restore is armed.
        let mut h = LinuxSigaction::empty();
        h.sa_handler = 0x4000;
        d.signal.lock().handlers.insert(10, h);
        assert!(d.sigsuspend_caught_handler_deliverable(tid, unblock_all));

        // The same signal BLOCKED by suspend_mask is not deliverable → restore.
        let block_10 = SigSet::EMPTY.with(10);
        assert!(!d.sigsuspend_caught_handler_deliverable(tid, block_10));
    }
}
