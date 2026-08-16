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
//! ## Kernel-owned state machine
//!
//! Linux thread-group actions live in the exact Kernel [`crate::kernel::Sighand`],
//! process-directed pending signals in [`crate::kernel::TaskPendingSignals`],
//! and masks, thread-directed queues, alternate stacks, handler frames, restore
//! masks, siginfo, and action snapshots in each exact
//! [`crate::kernel::ThreadSignalState`]. The dispatcher retains only an exact
//! `Sighand` binding; it owns no mutable signal semantics. Standard signals
//! coalesce, real-time signals retain FIFO instances, and an atomic dequeue
//! selects thread-directed state before task-directed state on a same-signum
//! tie.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DispatchPendingSignal {
    pub(crate) signum: i32,
    pub(crate) owner: crate::kernel::SignalPendingOwner,
    pub(crate) siginfo: Option<LinuxSiginfo>,
    pub(crate) job_control_generation: Option<crate::kernel::JobControlStopInvalidationGeneration>,
}

/// Real-time signals (`SIGRTMIN`..=`SIGRTMAX`, kernel numbers 32..=64) queue
/// per POSIX; standard signals (1..=31) coalesce.
fn is_rt_signal(signum: i32) -> bool {
    crate::kernel::LinuxSignal::for_signal_number(signum).is_ok_and(|signal| signal.is_realtime())
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

pub(super) fn sanitize_signal_mask(mask: SigSet) -> SigSet {
    mask.without(LINUX_SIGKILL).without(LINUX_SIGSTOP)
}

impl SyscallDispatcher {
    #[cfg(test)]
    pub(crate) fn exact_signal_context_for_test(&self) -> crate::kernel::KernelContext {
        self.capture_one_task_context()
            .expect("capture exact test signal context")
    }

    fn signal_action_entry(
        context: &crate::kernel::KernelContext,
        signum: i32,
    ) -> Option<LinuxSigaction> {
        let signal = crate::kernel::LinuxSignal::for_signal_number(signum).ok()?;
        context.shared().sighand().action_entry(signal)
    }

    fn signal_action(context: &crate::kernel::KernelContext, signum: i32) -> LinuxSigaction {
        crate::kernel::LinuxSignal::for_signal_number(signum)
            .ok()
            .map(|signal| context.shared().sighand().action(signal))
            .unwrap_or_else(LinuxSigaction::empty)
    }

    fn install_signal_action(
        context: &crate::kernel::KernelContext,
        signum: i32,
        action: LinuxSigaction,
    ) {
        let signal =
            crate::kernel::LinuxSignal::for_signal_number(signum).unwrap_or_else(|error| {
                tracing::error!(%error, signum, "invalid signal reached Kernel Sighand install");
                std::process::abort();
            });
        context.shared().sighand().install_action(signal, action);
    }

    fn signal_actions(context: &crate::kernel::KernelContext) -> Vec<(i32, LinuxSigaction)> {
        context
            .shared()
            .sighand()
            .actions()
            .into_iter()
            .map(|(signal, action)| (signal.raw(), action))
            .collect()
    }

    fn signal_thread(
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
    ) -> Option<crate::kernel::ThreadRef> {
        context.task().thread_by_registry_id(tid)
    }

    fn required_signal_thread(
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
    ) -> crate::kernel::ThreadRef {
        Self::signal_thread(context, tid).unwrap_or_else(|| {
            tracing::error!(
                ?tid,
                task = ?context.task().key(),
                "signal operation escaped its captured KernelContext"
            );
            std::process::abort();
        })
    }

    fn signal_authority_for(
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
    ) -> crate::kernel::SignalAuthority {
        crate::kernel::SignalAuthority::new(
            context.shared().sighand(),
            context.shared().pending_signals(),
            Arc::clone(context.task()),
            Self::required_signal_thread(context, tid),
        )
    }

    fn any_signal_thread_blocks(context: &crate::kernel::KernelContext, signum: i32) -> bool {
        context
            .task()
            .threads()
            .into_iter()
            .any(|thread| thread.signal_state().blocked().contains(signum))
    }

    /// Look up the currently-installed handler from the exact captured Sighand.
    pub fn registered_signal_handler(
        &self,
        context: &crate::kernel::KernelContext,
        signum: i32,
    ) -> Option<LinuxSigaction> {
        let action = Self::signal_action_entry(context, signum)?;
        let handler = action.sa_handler;
        if handler == crate::linux_abi::LINUX_SIG_DFL || handler == crate::linux_abi::LINUX_SIG_IGN
        {
            None
        } else {
            Some(action)
        }
    }

    pub fn signal_altstack(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
    ) -> Option<(u64, u64)> {
        Self::signal_thread(context, tid)
            .and_then(|thread| thread.signal_state().altstack())
            .map(|altstack| (altstack.ss_sp, altstack.ss_size))
    }

    pub fn signal_is_ignored(&self, context: &crate::kernel::KernelContext, signum: i32) -> bool {
        Self::signal_action_entry(context, signum)
            .is_some_and(|action| action.sa_handler == crate::linux_abi::LINUX_SIG_IGN)
    }

    pub fn proc_status_signal_masks(
        &self,
        context: &crate::kernel::KernelContext,
    ) -> (SigSet, SigSet, SigSet) {
        let mut ignored = SigSet::EMPTY;
        let mut caught = SigSet::EMPTY;
        for (signum, action) in Self::signal_actions(context) {
            if sigmask_bit(signum).is_none() {
                continue;
            }
            let handler = action.sa_handler;
            if handler == crate::linux_abi::LINUX_SIG_IGN {
                ignored = ignored.with(signum);
            } else if handler != crate::linux_abi::LINUX_SIG_DFL {
                caught = caught.with(signum);
            }
        }
        (
            ignored,
            caught,
            context.shared().pending_signals().present(),
        )
    }

    pub fn child_exit_signal_needs_pump(
        &self,
        context: &crate::kernel::KernelContext,
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
        match Self::signal_action_entry(context, signum).map(|action| action.sa_handler) {
            Some(handler) if handler == crate::linux_abi::LINUX_SIG_IGN => false,
            Some(handler) if handler == crate::linux_abi::LINUX_SIG_DFL => {
                self.signal_mask_for(context, tid).contains(signum)
                    || !is_default_ignore_signum(signum)
            }
            Some(_) => true,
            None => {
                self.signal_mask_for(context, tid).contains(signum)
                    || !is_default_ignore_signum(signum)
            }
        }
    }

    pub fn child_exit_signal_needs_process_pump(
        &self,
        context: &crate::kernel::KernelContext,
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
        match Self::signal_action_entry(context, signum).map(|action| action.sa_handler) {
            Some(handler) if handler == crate::linux_abi::LINUX_SIG_IGN => false,
            Some(handler) if handler == crate::linux_abi::LINUX_SIG_DFL => {
                Self::any_signal_thread_blocks(context, signum) || !is_default_ignore_signum(signum)
            }
            Some(_) => true,
            None => {
                Self::any_signal_thread_blocks(context, signum) || !is_default_ignore_signum(signum)
            }
        }
    }

    pub fn non_interrupting_signal_mask(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
    ) -> SigSet {
        let mut mask = self.signal_mask_for(context, tid);
        for signum in 1..=64i32 {
            let disposition =
                Self::signal_action_entry(context, signum).map(|action| action.sa_handler);
            let ignored = match disposition {
                Some(handler) if handler == crate::linux_abi::LINUX_SIG_IGN => true,
                None => is_default_ignore_signum(signum),
                Some(handler) if handler == crate::linux_abi::LINUX_SIG_DFL => {
                    is_default_ignore_signum(signum)
                }
                Some(_) => false,
            };
            if ignored {
                mask = mask.with(signum);
            }
        }
        mask
    }

    pub fn signal_blocked(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signum: i32,
    ) -> bool {
        if signum == LINUX_SIGKILL || signum == LINUX_SIGSTOP {
            return false;
        }
        self.signal_mask_for(context, tid).contains(signum)
    }

    pub fn signal_mask_for(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
    ) -> SigSet {
        Self::signal_thread(context, tid)
            .map(|thread| thread.signal_state().blocked())
            .unwrap_or(SigSet::EMPTY)
    }

    pub fn mark_signal_pending(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signum: i32,
    ) {
        let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(signum) else {
            return;
        };
        let authority = Self::signal_authority_for(context, tid);
        if is_rt_signal(signum) {
            authority.enqueue_thread_realtime(signal, None);
        } else {
            authority.enqueue_thread_standard(signal, None);
        }
    }

    fn signal_dispatch_pending_possible(
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
    ) -> bool {
        Self::signal_thread(context, tid)
            .is_some_and(|thread| !thread.signal_state().pending().is_empty())
            || context.shared().pending_signals().may_be_nonempty()
    }

    pub fn reset_signal_handlers_on_execve(&self, context: &crate::kernel::KernelContext) {
        let ignored = Self::signal_actions(context)
            .into_iter()
            .filter(|(_, action)| action.sa_handler == crate::linux_abi::LINUX_SIG_IGN)
            .fold(carrick_abi::SigSet::EMPTY, |set, (signum, _)| {
                set.with(signum)
            });
        for thread in context.task().threads() {
            thread.update_signal_state(|state| {
                *state = crate::kernel::ThreadSignalState::for_exec(state);
            });
        }
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
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signum: i32,
        action: LinuxSigaction,
    ) -> SigSet {
        let thread = Self::required_signal_thread(context, tid);
        let saved = thread.update_signal_state(|state| {
            let saved = state
                .take_armed_restore_mask()
                .unwrap_or_else(|| state.blocked());
            let delivered = if action.sa_flags & crate::linux_abi::LINUX_SA_NODEFER != 0 {
                SigSet::EMPTY
            } else {
                SigSet::EMPTY.with(signum)
            };
            let handler_mask = sanitize_signal_mask(
                state
                    .blocked()
                    .union(delivered)
                    .union(SigSet::from_raw(action.sa_mask[0])),
            );
            state.set_blocked(handler_mask);
            let on_altstack = action.sa_flags & crate::linux_abi::LINUX_SA_ONSTACK != 0
                && state.altstack().is_some();
            state.push_handler_frame(crate::kernel::HandlerFrameState {
                on_altstack,
                restore_mask: None,
            });
            saved
        });
        // Change the shared disposition only after releasing the thread leaf.
        if action.sa_flags & crate::linux_abi::LINUX_SA_RESETHAND != 0 {
            let mut reset = action;
            reset.sa_handler = crate::linux_abi::LINUX_SIG_DFL;
            Self::install_signal_action(context, signum, reset);
        }
        saved
    }

    /// True iff `tid` is currently executing a signal handler ON its alternate
    /// signal stack (any active SA_ONSTACK frame). (audit M13)
    fn is_on_altstack(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        current_guest_sp: Option<u64>,
    ) -> bool {
        let thread = Self::required_signal_thread(context, tid);
        let state = thread.signal_state();
        if !state.has_altstack_handler_frame() {
            return false;
        }
        let Some(sp) = current_guest_sp else {
            return true;
        };
        let sp_on_alt = state
            .altstack()
            .is_some_and(|stack| altstack_contains_guest_sp(stack, sp));
        if !sp_on_alt {
            thread.update_signal_state(crate::kernel::ThreadSignalState::clear_handler_frames);
        }
        sp_on_alt
    }

    /// Pop the returning handler frame's alt-stack record (rt_sigreturn).
    pub fn pop_handler_frame(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
    ) {
        Self::required_signal_thread(context, tid).update_signal_state(|state| {
            state.pop_handler_frame();
        });
    }

    /// Arm a "restore this mask after the next handler runs" override (Linux's
    /// `set_restore_sigmask`). The next `enter_signal_handler` for `tid`
    /// returns `mask` as the sigframe's saved mask and clears the arm.
    pub fn arm_restore_mask(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        mask: SigSet,
    ) {
        Self::required_signal_thread(context, tid).update_signal_state(|state| {
            state.arm_restore_mask(Some(sanitize_signal_mask(mask)));
        });
    }

    fn begin_sigsuspend(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        suspend_mask: SigSet,
    ) -> SigSet {
        Self::required_signal_thread(context, tid).update_signal_state(|state| {
            let original = state
                .armed_restore_mask()
                .unwrap_or_else(|| state.blocked());
            if state.armed_restore_mask().is_none() {
                state.arm_restore_mask(Some(original));
            }
            state.set_blocked(sanitize_signal_mask(suspend_mask));
            original
        })
    }

    fn cancel_sigsuspend(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        original: SigSet,
    ) {
        Self::required_signal_thread(context, tid).update_signal_state(|state| {
            state.arm_restore_mask(None);
            state.set_blocked(sanitize_signal_mask(original));
        });
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
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        suspend_mask: SigSet,
    ) -> bool {
        let deliverable = Self::required_signal_thread(context, tid)
            .signal_state()
            .pending()
            .union(context.shared().pending_signals().present())
            .difference(suspend_mask);
        if deliverable.is_empty() {
            return false;
        }
        (1..=64i32).any(|sig| {
            deliverable.contains(sig) && self.registered_signal_handler(context, sig).is_some()
        })
    }

    /// Queue a caller-supplied `siginfo_t` for the next delivery of
    /// `(tid, signum)`. Standard signals overwrite the single queued entry;
    /// RT signals (32..=64) append (POSIX queuing). `take_pending_siginfo`
    /// pops the front.
    pub fn record_pending_siginfo(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signum: i32,
        info: LinuxSiginfo,
    ) {
        let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(signum) else {
            return;
        };
        Self::required_signal_thread(context, tid)
            .update_signal_state(|state| state.record_routed_siginfo(signal, info));
    }

    /// Pop the next queued `siginfo_t` for `(tid, signum)`, if any. Returned to
    /// the signal-delivery path so `inject_signal` can carry the caller's
    /// payload (e.g. `rt_sigqueueinfo`'s `si_value.sival_int`) instead of
    /// synthesising an SI_USER siginfo. Returns `None` when no siginfo was
    /// queued (the normal raise/kill case — synthesised SI_USER is correct).
    pub fn take_pending_siginfo(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signum: i32,
    ) -> Option<LinuxSiginfo> {
        let signal = crate::kernel::LinuxSignal::for_signal_number(signum).ok()?;
        Self::required_signal_thread(context, tid)
            .update_signal_state(|state| state.take_routed_siginfo(signal))
    }

    /// Snapshot the current caught handler for a thread-directed signal that is
    /// deliverable now. The kicked target vCPU may not drain the backend
    /// pending slot until after the sender changes the process-global
    /// disposition; delivery must still use the handler that made the generated
    /// signal catchable.
    pub fn record_pending_signal_action(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signum: i32,
        action: LinuxSigaction,
    ) {
        let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(signum) else {
            return;
        };
        Self::signal_authority_for(context, tid).record_pending_action(signal, action);
    }

    /// Pop the handler action snapshotted for a generated thread-directed
    /// signal, if any. Normal pending signals fall back to the current
    /// disposition.
    pub fn take_pending_signal_action(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signum: i32,
    ) -> Option<LinuxSigaction> {
        let signal = crate::kernel::LinuxSignal::for_signal_number(signum).ok()?;
        Self::signal_authority_for(context, tid).take_pending_action(signal)
    }

    fn record_tkill_siginfo(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signum: i32,
    ) {
        if signum == 0 {
            return;
        }
        let info = LinuxSiginfo::kill(
            signum,
            crate::linux_abi::LINUX_SI_TKILL,
            crate::namespace::pid::self_ns_pid() as i32,
            self.cred_snapshot().ruid.raw(),
        );
        self.record_pending_siginfo(context, tid, signum, info);
    }

    /// Drain cross-process explicit signals queued for this host process,
    /// publishing each to the dispatcher's PROCESS-directed pending state
    /// (`target_ns_tid == 0` — kill/rt_sigqueueinfo/pidfd, no target tid) or a
    /// named THREAD's per-tid state (`target_ns_tid != 0` — tkill/tgkill/
    /// rt_tgsigqueueinfo), preserving siginfo payloads either way. Normal
    /// async delivery and synchronous waits (`rt_sigtimedwait`/sigwait) both
    /// use this so an xsignal can be consumed by either path — any thread may
    /// run the drain.
    pub(crate) fn drain_xsignals_process_directed(&self, context: &crate::kernel::KernelContext) {
        // Ring-authoritative gate (`SigBlockMask::NONE` => "any entry targets
        // this process"),
        // NOT the losable process-local `XSIG_DIRTY` hint: a dropped host nudge
        // must not hide an already-enqueued cross-process signal from the drain,
        // or a re-dispatched `rt_sigtimedwait`/sigwait would never consume it and
        // the waiter would re-block forever.
        if !carrick_signal_core::xsig::xsig_has_unblocked_for_self(SigBlockMask::NONE) {
            return;
        }
        for (signum, code, sender_ns, sender_uid, value, target_ns_tid) in
            crate::host_signal::xsig_drain_for_self()
        {
            // The ring carries the send's REAL si_code: a plain kill(2)/tkill of
            // an RT signal is SI_USER/SI_TKILL (kill-shaped siginfo), only
            // rt_sigqueueinfo/rt_tgsigqueueinfo deliveries are SI_QUEUE with a
            // sigval payload.
            let info = if code == crate::linux_abi::LINUX_SI_QUEUE {
                LinuxSiginfo::rt_queue(signum, sender_ns, sender_uid, value)
            } else {
                LinuxSiginfo::kill(signum, code, sender_ns, sender_uid)
            };
            if target_ns_tid == 0 {
                // Process-directed (no target tid on the slot): publish it to
                // the SHARED pending set, NOT to the tid that happened to run
                // this drain. Pinning it to the drainer stranded the signal
                // forever when the drain race was won by a thread that blocks
                // `signum` (the procladder_mt pause()-sibling):
                // `take_pending_in_from(main, set)` only consults
                // exact thread queue ∪ task-directed queue, so the sigwait-ing main
                // thread never saw it — the whole-process silent stall. Same
                // bug class as the process_pending doc's CPython
                // test_sigwait_thread precedent, one layer down.
                self.mark_process_signal_pending_with_info(context, signum, Some(info));
                continue;
            }
            // Thread-directed: resolve the guest ns tid to a live local thread
            // the same way `route_thread_signal` resolves its `tgkill`/`tkill`
            // target, then mirror its in-process delivery half (per-tid
            // siginfo store + per-tid pending mark + host-slot waiter kick)
            // instead of the shared-set publish above.
            let Some(target) = resolve_xsig_thread_target(target_ns_tid) else {
                // No live thread bears this tid: Linux discards a
                // thread-directed pending signal at thread exit (it is NOT
                // redirected to a sibling or the whole thread group), so the
                // ring entry is simply dropped.
                continue;
            };
            self.record_pending_siginfo(context, target, signum, info);
            if self.signal_blocked(context, target, signum) {
                // Held pending until the target unblocks it or a sigwait
                // dequeues it — exactly `route_thread_signal`'s blocked
                // branch, no host-slot publish (nothing to wake yet).
                self.mark_signal_pending(context, target, signum);
            } else {
                if let Some(action) = self.registered_signal_handler(context, signum) {
                    self.record_pending_signal_action(context, target, signum, action);
                }
                // The host-level per-tid slot `deliver_pending_signal` checks
                // first for `target`'s own vCPU loop iteration — the same
                // publish `complete_signal_thread` performs for a live,
                // in-process `SignalThread` route. The nudge that triggered
                // this drain already broadcast a wake to every parked thread
                // of this process (see the xsig ring's nudge-handler doc), so
                // no separate kick is needed here.
                crate::host_signal::publish_pending_for(target.raw(), signum);
            }
        }
    }

    pub fn restore_signal_mask(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        mask: SigSet,
    ) {
        Self::required_signal_thread(context, tid)
            .update_signal_state(|state| state.set_blocked(sanitize_signal_mask(mask)));
    }

    /// Lowest-numbered pending signal that is NOT currently blocked, cleared
    /// from the pending set. The runtime drains this each delivery cycle to
    /// deliver signals raised while blocked and since unblocked (rt_sigprocmask)
    /// — one per cycle so each handler runs (and returns via rt_sigreturn)
    /// before the next is injected, matching the kernel's deliver-all-pending-
    /// before-returning-to-userspace behaviour. None when none remain.
    pub fn take_deliverable_pending(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
    ) -> Option<i32> {
        self.take_deliverable_pending_from(context, tid)
            .map(|pending| pending.signum)
    }

    /// [`Self::take_deliverable_pending`] with owner and payload from the same
    /// dequeue transaction.
    pub(crate) fn take_deliverable_pending_from(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
    ) -> Option<DispatchPendingSignal> {
        if !Self::signal_dispatch_pending_possible(context, tid) {
            return None;
        }
        let set = self.signal_mask_for(context, tid).complement();
        self.take_pending_in_from(context, tid, set)
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
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        sig_mask: carrick_abi::WaitSigMask,
    ) -> bool {
        use carrick_abi::WaitSigMask;
        if !Self::signal_dispatch_pending_possible(context, tid) {
            return false;
        }
        let always_deliverable = SigSet::EMPTY.with(LINUX_SIGKILL).with(LINUX_SIGSTOP);
        let effective_block_mask = match sig_mask {
            WaitSigMask::Replace(s) => s,
            WaitSigMask::Additive(s) => self.signal_mask_for(context, tid).union(s),
        };
        // Linux only interrupts a blocking syscall for a signal whose delivery
        // can run a handler or apply a non-ignore default action. SIGCHLD,
        // SIGURG, and SIGWINCH at SIG_DFL (plus explicit SIG_IGN) may remain in
        // the pending set until the next userspace boundary, but their wake is
        // an internal re-dispatch edge rather than guest-visible EINTR.
        let non_interrupting =
            effective_block_mask.union(self.wait_ignored_disposition_mask(context));
        let pending = Self::required_signal_thread(context, tid)
            .signal_state()
            .pending()
            .union(context.shared().pending_signals().present());
        !pending
            .intersect(non_interrupting.complement().union(always_deliverable))
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
    pub(crate) fn wait_ignored_disposition_mask(
        &self,
        context: &crate::kernel::KernelContext,
    ) -> SigSet {
        let mut mask = SigSet::EMPTY;
        for signum in 1..=64i32 {
            let ignored = match Self::signal_action_entry(context, signum) {
                Some(action) if action.sa_handler == crate::linux_abi::LINUX_SIG_IGN => true,
                Some(action) if action.sa_handler == crate::linux_abi::LINUX_SIG_DFL => {
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
    /// instead would `take_pending_in_from(wait_set)`, find nothing, and RE-PARK,
    /// wedging `rt_sigtimedwait(set=∅)` forever (the kvm-lane LTP
    /// sigtimedwait01/sigwaitinfo01 TIMEOUT cluster). A wait-set signal (or a
    /// consumed/spurious wake) returns false: re-dispatch dequeues it and
    /// completes with the signum.
    pub(crate) fn signal_wait_should_eintr(
        &self,
        context: &crate::kernel::KernelContext,
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
                context,
                tid,
                carrick_abi::WaitSigMask::Replace(non_eintr),
            )
    }

    /// Convenience for tests that assert only the selected signum.
    #[cfg(test)]
    fn take_pending_in(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        set: SigSet,
    ) -> Option<i32> {
        self.take_pending_in_from(context, tid, set)
            .map(|pending| pending.signum)
    }

    /// Choose and dequeue the lowest pending signal with its owner and siginfo
    /// in one transaction. Thread-directed state wins a same-signum tie.
    fn take_pending_in_from(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        set: SigSet,
    ) -> Option<DispatchPendingSignal> {
        let dequeued = Self::signal_authority_for(context, tid).take_lowest_in(set)?;
        Some(DispatchPendingSignal {
            signum: dequeued.pending.signal.raw(),
            owner: dequeued.owner,
            siginfo: dequeued.pending.siginfo,
            job_control_generation: dequeued.job_control_generation,
        })
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
        context: &crate::kernel::KernelContext,
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
            let Some(pending) = self.take_pending_in_from(context, tid, mask) else {
                break;
            };
            let mut rec = [0u8; SIGINFO_LEN];
            // ssi_signo @0.
            rec[0..4].copy_from_slice(&(pending.signum as u32).to_le_bytes());
            // Payload and pending owner were dequeued together.
            if let Some(info) = pending.siginfo {
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
    pub fn mark_process_signal_pending(&self, context: &crate::kernel::KernelContext, signum: i32) {
        self.mark_process_signal_pending_with_info(context, signum, None);
    }

    pub(in crate::dispatch) fn mark_process_signal_pending_with_info(
        &self,
        context: &crate::kernel::KernelContext,
        signum: i32,
        siginfo: Option<LinuxSiginfo>,
    ) {
        let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(signum) else {
            return;
        };
        let task_pending = context.shared().pending_signals();
        if is_rt_signal(signum) {
            task_pending.enqueue_realtime(signal, siginfo);
        } else {
            task_pending.enqueue_standard(signal, siginfo);
        }
    }

    /// Publish an asynchronous signal from another Linux process multiplexed
    /// inside the same hvpatch host process. The caller owns wakeup/kick routing;
    /// this method only records the signal in this dispatcher's process-private
    /// pending set, avoiding host-global signal slots.
    pub(crate) fn mark_in_process_signal_pending(
        &self,
        context: &crate::kernel::KernelContext,
        signum: i32,
    ) {
        crate::probes::signal_publish(0, signum, 0);
        self.mark_process_signal_pending(context, signum);
    }

    /// Raise a process-directed `signum` against the guest itself
    /// (`kill(getpid(), sig)`). If the signal is blocked it is held pending;
    /// otherwise it is handed to the runtime's process-directed delivery slot.
    /// signum 0 is the null probe and a no-op success.
    fn raise_self(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signum: u64,
    ) -> DispatchOutcome {
        if signum == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        let s = signum as i32;
        if crate::exec_helpers::stop_for_ptrace_signal(self, s) {
            return DispatchOutcome::Returned { value: 0 };
        }
        if s == LINUX_SIGSTOP {
            stop_self_by_signal(s);
            return DispatchOutcome::Returned { value: 0 };
        }
        if self.signal_blocked(context, tid, s) {
            self.mark_signal_pending(context, tid, s);
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
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signum: u64,
    ) -> DispatchOutcome {
        if signum == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        let s = signum as i32;
        if crate::exec_helpers::stop_for_ptrace_signal(self, s) {
            return DispatchOutcome::Returned { value: 0 };
        }
        if s == LINUX_SIGSTOP {
            stop_self_by_signal(s);
            return DispatchOutcome::Returned { value: 0 };
        }
        if self.signal_blocked(context, tid, s) {
            self.mark_signal_pending(context, tid, s);
        } else {
            if let Some(action) = self.registered_signal_handler(context, s) {
                self.record_pending_signal_action(context, tid, s, action);
            }
            crate::host_signal::publish_pending_for(tid.raw(), s);
        }
        DispatchOutcome::Returned { value: 0 }
    }

    /// The calling guest thread's tid (or `0` if no thread context).
    pub(crate) fn ctx_tid<M: GuestMemory>(ctx: &SyscallCtx<M>) -> crate::thread::ThreadId {
        ctx.thread
            .as_ref()
            .map(|thread| thread.tid)
            .unwrap_or_else(|| ctx.kernel.thread().registry_id())
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
    /// `kill(2)`'s group and broadcast targets on the KERNEL lane, resolved and
    /// delivered inside the kernel. `None` means "not mine" — another lane, or
    /// a positive pid, which names one process and is not handled here.
    ///
    /// The host cannot answer these. On this lane every Linux process is a
    /// thread of one host process, so they all share ONE host process group: a
    /// guest pgid means nothing to `libc::kill`, and `killpg` would either hit
    /// every guest at once or, once the id space is seeded at 1, negate to
    /// `kill(-1, …)` — the host BROADCAST sentinel, aimed at everything the
    /// user can signal. The kernel's own `process_group` table is the only
    /// authority that describes the guest.
    ///
    /// Linux returns success if at least one process was signalled and ESRCH if
    /// none matched, so an empty group is ESRCH rather than a silent success.
    /// signum 0 is the null probe: it resolves membership and reports whether
    /// anything is there WITHOUT delivering, which is what `kill(pgid, 0)`
    /// liveness checks depend on.
    fn hvpatch_group_signal<M: GuestMemory>(
        &self,
        ctx: &SyscallCtx<M>,
        pid: i32,
        signum: u64,
    ) -> Option<DispatchOutcome> {
        if !crate::dispatch::hvpatch_lane_active() || pid > 0 {
            return None;
        }
        let kernel = ctx.kernel.kernel();
        let caller = ctx.kernel.task();
        let targets = if pid == -1 {
            kernel.task_keys_for_broadcast(caller.key().id)
        } else {
            // pid == 0 is the caller's own group; pid < -1 names `-pid`.
            let group = if pid == 0 {
                caller.process_group()
            } else {
                match crate::kernel::ProcessGroupId::from_abi_positive(-pid) {
                    Ok(group) => group,
                    Err(_) => return Some(DispatchOutcome::errno(LINUX_ESRCH)),
                }
            };
            kernel.task_keys_in_process_group(group)
        };
        let signal = if signum == 0 {
            None
        } else {
            match crate::kernel::LinuxSignal::for_signal_number(signum as i32) {
                Ok(signal) => Some(signal),
                Err(_) => return Some(DispatchOutcome::errno(LINUX_EINVAL)),
            }
        };
        // Linux fills si_pid/si_uid with the SENDER's identity for a
        // kill(2)-delivered signal, so an SA_SIGINFO handler in the target can
        // tell who signalled it rather than seeing an all-zero SI_USER.
        let creds = self.cred_snapshot();
        let info = crate::linux_abi::LinuxSiginfo::kill(
            signum as i32,
            crate::linux_abi::LINUX_SI_USER,
            caller.key().id.raw(),
            creds.ruid.raw(),
        );
        let mut accepted = 0_usize;
        let mut denied = 0_usize;
        for target in targets {
            match kernel.authorize_signal_target_exact(ctx.kernel, target, None, signal) {
                crate::kernel::ExactSignalTargetAuthorization::Allowed(ticket) => {
                    if signal.is_none_or(|signal| {
                        kernel.post_signal_to_authorized_target(&ticket, signal, Some(info))
                    }) {
                        accepted += 1;
                    }
                }
                crate::kernel::ExactSignalTargetAuthorization::DropProtectedInit => accepted += 1,
                crate::kernel::ExactSignalTargetAuthorization::Denied => denied += 1,
                crate::kernel::ExactSignalTargetAuthorization::Missing => {}
            }
        }
        if accepted != 0 {
            return Some(DispatchOutcome::Returned { value: 0 });
        }
        Some(DispatchOutcome::errno(if denied != 0 {
            LINUX_EPERM
        } else {
            LINUX_ESRCH
        }))
    }

    /// Route every positive HVPatch task target through the kernel, including
    /// self. Falling through for self would reach host `raise(3)`/global
    /// pending state even though all HVPatch tasks share one carrier process.
    fn hvpatch_specific_process_signal<M: GuestMemory>(
        &self,
        ctx: &SyscallCtx<M>,
        pid: i32,
        signum: u64,
        siginfo: Option<LinuxSiginfo>,
    ) -> Option<DispatchOutcome> {
        if !hvpatch_owns_specific_process_signal(crate::dispatch::hvpatch_lane_active(), pid) {
            return None;
        }
        let kernel = ctx.kernel.kernel();
        let Some(target_key) = hvpatch_process_signal_target(kernel, pid) else {
            if hvpatch_signal_observes_zombie(kernel, pid) {
                // Addressable but no longer running: the signal is dropped and
                // the call succeeds, exactly as Linux does for a zombie.
                return Some(DispatchOutcome::Returned { value: 0 });
            }
            return Some(DispatchOutcome::errno(LINUX_ESRCH));
        };
        Some(self.hvpatch_exact_process_signal(ctx.kernel, target_key, signum, siginfo))
    }

    /// Deliver through one exact HVPatch process identity. Pidfds already hold
    /// a generation-bearing [`TaskKey`](crate::kernel::TaskKey), so they must
    /// not collapse back to a numeric pid lookup (or to the shared host pid)
    /// before applying the same authorization and pending-signal machinery as
    /// `kill(2)`.
    pub(super) fn hvpatch_exact_process_signal(
        &self,
        context: &crate::kernel::KernelContext,
        target_key: crate::kernel::TaskKey,
        signum: u64,
        siginfo: Option<LinuxSiginfo>,
    ) -> DispatchOutcome {
        let kernel = context.kernel();
        let signal = if signum == 0 {
            None
        } else {
            match crate::kernel::LinuxSignal::for_signal_number(signum as i32) {
                Ok(signal) => Some(signal),
                Err(_) => return DispatchOutcome::errno(LINUX_EINVAL),
            }
        };
        match kernel.authorize_signal_target_exact(context, target_key, None, signal) {
            crate::kernel::ExactSignalTargetAuthorization::Allowed(ticket) => {
                if signal.is_none_or(|signal| {
                    kernel.post_signal_to_authorized_target(&ticket, signal, siginfo)
                }) {
                    DispatchOutcome::Returned { value: 0 }
                } else {
                    DispatchOutcome::errno(LINUX_ESRCH)
                }
            }
            crate::kernel::ExactSignalTargetAuthorization::DropProtectedInit => {
                DispatchOutcome::Returned { value: 0 }
            }
            crate::kernel::ExactSignalTargetAuthorization::Denied => {
                DispatchOutcome::errno(LINUX_EPERM)
            }
            crate::kernel::ExactSignalTargetAuthorization::Missing => {
                DispatchOutcome::errno(LINUX_ESRCH)
            }
        }
    }

    /// Route a HVPatch thread target by Linux `(tgid, tid)` identity. With no
    /// tgid this is `tkill`'s globally unique tid lookup.
    fn hvpatch_specific_thread_signal<M: GuestMemory>(
        &self,
        ctx: &SyscallCtx<M>,
        tgid: Option<i32>,
        tid: i32,
        signum: u64,
        siginfo: Option<LinuxSiginfo>,
    ) -> Option<DispatchOutcome> {
        if !hvpatch_owns_specific_thread_signal(crate::dispatch::hvpatch_lane_active()) {
            return None;
        }
        let tid = match crate::kernel::LinuxTid::from_abi_positive(tid) {
            Ok(tid) => tid,
            Err(_) => return Some(DispatchOutcome::errno(LINUX_ESRCH)),
        };
        let required_task = match tgid {
            Some(raw) => match crate::kernel::TaskId::from_abi_positive(raw) {
                Ok(task) => Some(task),
                Err(_) => return Some(DispatchOutcome::errno(LINUX_ESRCH)),
            },
            None => None,
        };
        let kernel = ctx.kernel.kernel();
        let Some((target_task, target_thread)) = kernel.live_keys_for_thread(required_task, tid)
        else {
            return Some(DispatchOutcome::errno(LINUX_ESRCH));
        };
        let signal = if signum == 0 {
            None
        } else {
            match crate::kernel::LinuxSignal::for_signal_number(signum as i32) {
                Ok(signal) => Some(signal),
                Err(_) => return Some(DispatchOutcome::errno(LINUX_EINVAL)),
            }
        };
        // RLIMIT_SIGPENDING caps the number of QUEUED real-time signals;
        // tgkill(2)/sigqueue(3) report EAGAIN once it is reached. The check
        // already exists and its own comment cites LTP tgkill02, but its only
        // callers were `route_thread_signal` (the non-HVPatch route) and
        // `sigqueueinfo_common` — the HVPatch branch returned before reaching
        // either, so the limit was simply never enforced on this lane.
        if signum != 0 && is_rt_signal(signum as i32) && self.sigpending_limit_exceeded(ctx.kernel)
        {
            return Some(DispatchOutcome::errno(crate::linux_abi::LINUX_EAGAIN));
        }
        Some(
            match kernel.authorize_signal_target_exact(
                ctx.kernel,
                target_task,
                Some(target_thread),
                signal,
            ) {
                crate::kernel::ExactSignalTargetAuthorization::Allowed(ticket) => {
                    if signal.is_none_or(|signal| {
                        kernel.post_signal_to_authorized_target(&ticket, signal, siginfo)
                    }) {
                        DispatchOutcome::Returned { value: 0 }
                    } else {
                        DispatchOutcome::errno(LINUX_ESRCH)
                    }
                }
                crate::kernel::ExactSignalTargetAuthorization::DropProtectedInit => {
                    DispatchOutcome::Returned { value: 0 }
                }
                crate::kernel::ExactSignalTargetAuthorization::Denied => {
                    DispatchOutcome::errno(LINUX_EPERM)
                }
                crate::kernel::ExactSignalTargetAuthorization::Missing => {
                    DispatchOutcome::errno(LINUX_ESRCH)
                }
            },
        )
    }

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
        if !self.signal_blocked(ctx.kernel, caller_tid, s) {
            return self.raise_self(ctx.kernel, caller_tid, signum);
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
                if !self.signal_blocked(ctx.kernel, tid, s) {
                    return DispatchOutcome::SignalThread { tid, signum: s };
                }
            }
        }
        // Every thread blocks it: hold it in the SHARED process pending set so
        // whichever thread next unblocks it (rt_sigprocmask) OR dequeues it
        // synchronously (sigwait/rt_sigtimedwait) consumes it. Pinning it to
        // the (blocked) caller stranded a SIBLING thread's sigwait forever
        // (CPython test_sigwait_thread; probe sigwaitthread).
        self.mark_process_signal_pending(ctx.kernel, s);
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
            // The pid the GUEST asked for, before any ns→host translation. The
            // self-target test below needs it: under the kernel (`hvpatch`)
            // lane a Linux process is a THREAD of one host process, so its own
            // Linux pid is nothing like `std::process::id()` and the
            // host-identity test can never fire. `identity_pid()` is the same
            // authority `getpid(2)` answers from, so "the guest asked to signal
            // the pid it believes it has" is exactly a self-target.
            let requested_pid = i64::from(pid.0);
            // KERNEL LANE: group (`0`, `< -1`) and broadcast (`-1`) targets are
            // resolved and delivered inside the kernel. This must come BEFORE
            // the ns→host translation below: a guest pgid is a kernel
            // `ProcessGroupId`, not a host pgid, so translating it is
            // meaningless and handing the result to `libc::kill` aims at the
            // host. Positive pids fall through and are handled as before.
            if let Some(outcome) = this.hvpatch_group_signal(cx, pid.0, signum) {
                return Ok(outcome);
            }
            let kill_info = (signum != 0).then(|| {
                crate::linux_abi::LinuxSiginfo::kill(
                    signum as i32,
                    crate::linux_abi::LINUX_SI_USER,
                    cx.kernel.task().key().id.raw(),
                    this.cred_snapshot().ruid.raw(),
                )
            });
            if let Some(outcome) =
                this.hvpatch_specific_process_signal(cx, pid.0, signum, kill_info)
            {
                return Ok(outcome);
            }
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
            let signal_target_names_self = pid == std::process::id() as i64
                || requested_pid == i64::from(this.identity_pid())
                || (!crate::namespace::pid::enabled() && pid == LINUX_BOOTSTRAP_PID as i64);
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
                && this.registered_signal_handler(cx.kernel, signum as i32).is_none()
                && !this.signal_is_ignored(cx.kernel, signum as i32)
            {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if signal_target_names_self {
                let tid = Self::ctx_tid(cx);
                if signum != 0
                    && crate::exec_helpers::stop_for_ptrace_signal(this, signum as i32)
                {
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
                        this.cred_snapshot().ruid.raw(),
                    );
                    this.record_pending_siginfo(cx.kernel, tid, signum as i32, info);
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
            if LinuxSignalfdFlags::from_bits(flags).is_none() {
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
            if crate::dispatch::hvpatch_lane_active() {
                let info = (signum != 0).then(|| {
                    crate::linux_abi::LinuxSiginfo::kill(
                        signum as i32,
                        crate::linux_abi::LINUX_SI_TKILL,
                        cx.kernel.task().key().id.raw(),
                        this.cred_snapshot().ruid.raw(),
                    )
                });
                return Ok(this
                    .hvpatch_specific_thread_signal(cx, None, tid as i32, signum, info)
                    .unwrap_or_else(|| DispatchOutcome::errno(LINUX_ESRCH)));
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
                let self_tid = Self::ctx_tid(cx);
                return Ok(this.raise_self(cx.kernel, self_tid, signum));
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
            if crate::dispatch::hvpatch_lane_active() {
                let info = (signum != 0).then(|| {
                    crate::linux_abi::LinuxSiginfo::kill(
                        signum as i32,
                        crate::linux_abi::LINUX_SI_TKILL,
                        cx.kernel.task().key().id.raw(),
                        this.cred_snapshot().ruid.raw(),
                    )
                });
                if let Some(outcome) = this.hvpatch_specific_thread_signal(
                    cx,
                    Some(tgid as i32),
                    tid as i32,
                    signum,
                    info,
                ) {
                    return Ok(outcome);
                }
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            // tgid-membership: `tid` must belong to thread group `tgid`. A guest
            // process is one host process whose threads all share tgid == the
            // process pid, and that is the only thread group tgkill can reach.
            // So `tgid` must name THIS process — a (tgid, tid) pair where tid is
            // a live thread but is NOT in tgid's group is ESRCH, even though a
            // plain tkill(tid) would have succeeded (LTP tgkill03 "Defunct
            // tgid": tgkill(defunct_tid, child_tid) with child_tid live).
            if !names_current_thread_group(cx, tgid) {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            if let Some((routed, _target)) = this.route_thread_signal(cx, tid, signum, true) {
                return Ok(routed);
            }
            // raise()/pthread_kill name the caller as tgkill(getpid(), gettid()).
            // Under a PID namespace getpid()/gettid() report the ns-pid, so a
            // self-target here is the caller's ns-pid — not just host-pid/
            // bootstrap. (Sibling threads were already handled by
            // route_thread_signal above.)
            let valid_self = names_current_thread_group(cx, tgid) && names_self_pid(tid);
            if !valid_self {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            let self_tid = Self::ctx_tid(cx);
            Ok(this.raise_self(cx.kernel, self_tid, signum))
        }

        /// sigaltstack(ss, old_ss): set/query alternate signal stack.
        fn sigaltstack(this, cx, ss: GuestPtr, old_ss: GuestPtr) {
            let ss = ss.0;
            let old_ss = old_ss.0;
            let tid = Self::ctx_tid(cx);
            let memory = &mut *cx.memory;

            let on_altstack = this.is_on_altstack(cx.kernel, tid, cx.request.current_guest_sp);
            if old_ss != 0 {
                let mut current = Self::required_signal_thread(cx.kernel, tid)
                    .signal_state()
                    .altstack()
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
                let replacement = if flags & LINUX_SS_DISABLE != 0 {
                    None
                } else {
                    let size = new_stack.ss_size;
                    if size < LINUX_MINSIGSTKSZ {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    Some(new_stack)
                };
                Self::required_signal_thread(cx.kernel, tid)
                    .update_signal_state(|state| state.set_altstack(replacement));
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
            // Install the temporary mask and retain the original across the
            // run loop's wait/re-dispatch cycle. Blocking here would retain the
            // caller's guest-memory borrow and starve the sibling that must
            // dispatch tgkill/tkill to wake us.
            let original = this.begin_sigsuspend(cx.kernel, tid, suspend_mask);
            let dispatcher_pending = Self::required_signal_thread(cx.kernel, tid)
                .signal_state()
                .pending()
                .union(cx.kernel.shared().pending_signals().present())
                .difference(suspend_mask);
            let block_mask = SigBlockMask::blocking_all_of(suspend_mask);
            let host_pending = crate::host_signal::has_unblocked_pending_for(
                tid.raw(),
                block_mask,
            );
            if dispatcher_pending.is_empty() && !host_pending {
                return Ok(DispatchOutcome::WaitOnSignals {
                    wait_set: suspend_mask.complement(),
                    block_mask,
                    timeout: None,
                });
            }
            // Keep the temporary mask + arm the post-handler restore ONLY when a
            // caught handler is actually going to run: it runs under
            // `suspend_mask`, and its `rt_sigreturn` pops `original` via the
            // armed mask. On a spurious/timeout wake, or a wake by a signal whose
            // disposition is ignore / default-ignore (no handler runs, so no
            // `rt_sigreturn`), restore `original` HERE — otherwise the thread is
            // stranded running under `suspend_mask`. A cross-thread host-pending
            // wake re-raised above, so a handler will run there too. (audit M1)
            if this.sigsuspend_caught_handler_deliverable(cx.kernel, tid, suspend_mask)
                || host_pending
            {
                // `begin_sigsuspend` already armed `original`; handler entry
                // consumes it into the Linux sigframe.
            } else {
                this.cancel_sigsuspend(cx.kernel, tid, original);
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
                let prev = Self::signal_action(cx.kernel, signum);
                if write_kernel_struct_raw(memory, old_action, &prev).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }
            if let Some(sa) = new_sa {
                Self::install_signal_action(cx.kernel, signum, sa);
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
            let previous_mask = this.signal_mask_for(cx.kernel, tid);
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
                this.restore_signal_mask(cx.kernel, tid, mask);
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
            // Pending = this exact Kernel thread queue UNION the shared task
            // queue (Linux sigpending reports both).
            let pending = Self::required_signal_thread(cx.kernel, tid)
                .signal_state()
                .pending()
                .union(cx.kernel.shared().pending_signals().present());
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

            this.drain_xsignals_process_directed(cx.kernel);
            let memory = &mut *cx.memory;
            if let Some(pending) = this.take_pending_in_from(cx.kernel, tid, wait_set) {
                return Ok(rt_sigtimedwait_deliver(
                    memory,
                    info_ptr,
                    pending.signum,
                    pending.siginfo,
                ));
            }
            let signum = crate::host_signal::take_pending_in_for(tid.raw(), wait_set);
            if signum != crate::host_signal::NO_PENDING_SIGNAL {
                // A host-delivered signal carries no carrick-queued payload.
                let queued = this.take_pending_siginfo(cx.kernel, tid, signum);
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
                        this.signal_mask_for(cx.kernel, tid),
                        this.wait_ignored_disposition_mask(cx.kernel),
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
            // It targets the whole thread GROUP, never a specific thread —
            // `tid_directed = false` keeps a cross-process send process-directed.
            let tgid = i64::from(tgid.0);
            Ok(this.sigqueueinfo_common(cx, tgid, tgid, sig.0 as u64, info_ptr, false))
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
            // `tid_directed = true`: unlike rt_sigqueueinfo this names ONE
            // thread, so a cross-process send must carry that tid through the
            // xsig ring instead of landing process-directed.
            Ok(this.sigqueueinfo_common(
                cx,
                i64::from(tid.0),
                i64::from(tgid.0),
                sig.0 as u64,
                info_ptr,
                true,
            ))
        }

        /// rt_sigreturn(): pop signal frame and restore registers.
        fn rt_sigreturn(this, cx) {
            // Pop this handler frame's alt-stack record (audit M13).
            this.pop_handler_frame(cx.kernel, Self::ctx_tid(cx));
            Ok(DispatchOutcome::SigReturn)
        }
    }

    /// Count of currently-queued pending signals for this process — carrick's
    /// per-process analogue of the Linux per-user `sigpending` count that
    /// `RLIMIT_SIGPENDING` bounds. Standard signals (1..=31) coalesce, so each
    /// pending standard signum is one slot; real-time signals queue per POSIX,
    /// so each queued instance counts. Linux's limit is per-user across the
    /// user's processes; carrick approximates it per-process (one user per
    /// guest here), which is exact for the single-process case.
    fn pending_signal_count(&self, context: &crate::kernel::KernelContext) -> u64 {
        let thread_total = context
            .task()
            .threads()
            .into_iter()
            .map(|thread| u64::try_from(thread.signal_state().pending_count()).unwrap_or(u64::MAX))
            .fold(0u64, u64::saturating_add);
        thread_total.saturating_add(
            u64::try_from(context.shared().pending_signals().pending_count()).unwrap_or(u64::MAX),
        )
    }

    /// True when queuing one more signal would exceed this process's effective
    /// `RLIMIT_SIGPENDING` soft limit (an INFINITY limit — carrick's default —
    /// never does). Linux allows a queue alloc iff `count + 1 <= limit`; the
    /// send fails with `EAGAIN` otherwise (LTP tgkill02: a blocked SIGRTMIN with
    /// `RLIMIT_SIGPENDING = {0, 0}`).
    fn sigpending_limit_exceeded(&self, context: &crate::kernel::KernelContext) -> bool {
        let limit = self
            .effective_resource_limit(crate::linux_abi::LINUX_RLIMIT_SIGPENDING)
            .rlim_cur;
        if limit == LINUX_RLIM_INFINITY {
            return false;
        }
        self.pending_signal_count(context) >= limit
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
                self.record_tkill_siginfo(ctx.kernel, t.tid, signum as i32);
            }
            return Some((
                self.raise_thread_directed_self(ctx.kernel, t.tid, signum),
                target,
            ));
        }
        if t.registry.is_live(target) {
            let signum_i32 = signum as i32;
            // RLIMIT_SIGPENDING: a real-time signal allocates a queue entry when
            // generated, so a send at the pending-signal limit fails with EAGAIN
            // BEFORE anything is recorded (LTP tgkill02: a sibling with SIGRTMIN
            // blocked and RLIMIT_SIGPENDING={0,0}). Standard signals coalesce and
            // are not bounded per-entry, so they are unaffected.
            if is_rt_signal(signum_i32) && self.sigpending_limit_exceeded(ctx.kernel) {
                return Some((DispatchOutcome::errno(LINUX_EAGAIN), target));
            }
            if record_synthetic {
                self.record_tkill_siginfo(ctx.kernel, target, signum_i32);
            }
            if self.signal_blocked(ctx.kernel, target, signum_i32) {
                self.mark_signal_pending(ctx.kernel, target, signum_i32);
                return Some((DispatchOutcome::Returned { value: 0 }, target));
            }
            if let Some(action) = self.registered_signal_handler(ctx.kernel, signum_i32) {
                self.record_pending_signal_action(ctx.kernel, target, signum_i32, action);
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
    /// `ns_target` is the tgid in both. `tid_directed` distinguishes the two at
    /// the CROSS-PROCESS ring send: `rt_tgsigqueueinfo` names one specific
    /// thread (`route_target` carries that tid through the ring), while
    /// `rt_sigqueueinfo` targets the whole thread group (ring entry stays
    /// process-directed, `target_ns_tid = 0`).
    fn sigqueueinfo_common<M: GuestMemory>(
        &self,
        ctx: &SyscallCtx<M>,
        route_target: i64,
        ns_target: i64,
        signum: u64,
        info_ptr: GuestPtr,
        tid_directed: bool,
    ) -> DispatchOutcome {
        if !is_valid_signum(signum) {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        // rt_sigqueueinfo/rt_tgsigqueueinfo name one thread group. Unlike
        // kill(2), zero and negative pid encodings never mean a group/broadcast.
        if ns_target <= 0 {
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
                // rt_sigqueueinfo(2): "EPERM ... or `info->si_code` is invalid:
                // it must be negative (i.e. not one of the codes the kernel
                // generates) unless the signal is being sent to the caller's
                // own thread group." Without this a guest can forge a
                // kernel-origin si_code such as SI_USER into ANOTHER thread
                // group's siginfo, which is a real cross-process spoof and not
                // merely a missing assertion (LTP rt_sigqueueinfo02).
                if info.si_code >= 0 && ns_target != i64::from(self.identity_pid()) {
                    return DispatchOutcome::errno(LINUX_EPERM);
                }
                info.si_signo = s;
                user_info = Some(info);
            }
        }

        // Every HVPatch target, including this task and its sibling threads,
        // is kernel identity. The mature route below publishes through host-
        // process globals and `SignalThread`, which are shared by unrelated
        // HVPatch tasks and bypass task-wide signal generation ordering.
        if crate::dispatch::hvpatch_lane_active() {
            if is_rt_signal(s) && self.sigpending_limit_exceeded(ctx.kernel) {
                return DispatchOutcome::errno(LINUX_EAGAIN);
            }
            return if tid_directed {
                self.hvpatch_specific_thread_signal(
                    ctx,
                    Some(ns_target as i32),
                    route_target as i32,
                    signum,
                    user_info,
                )
                .unwrap_or_else(|| DispatchOutcome::errno(LINUX_ESRCH))
            } else {
                self.hvpatch_specific_process_signal(ctx, ns_target as i32, signum, user_info)
                    .unwrap_or_else(|| DispatchOutcome::errno(LINUX_ESRCH))
            };
        }

        // Sibling-thread route: deliver directly so the SA_SIGINFO frame carries
        // the original si_value (LTP rt_sigqueueinfo01 / rt_tgsigqueueinfo01).
        if let Some((routed, target_tid)) =
            self.route_thread_signal(ctx, route_target, signum, false)
        {
            // Only record the queued payload when the route actually queued the
            // signal. If the route failed with an errno (e.g. RLIMIT_SIGPENDING
            // EAGAIN, which returns BEFORE any pending bit is set), Linux queued
            // nothing — recording here would leave a stale RT payload that a
            // LATER legitimate rt_sigqueueinfo(same sig) would pop and deliver
            // with the wrong si_value.
            if !matches!(routed, DispatchOutcome::Errno { .. })
                && let Some(info) = user_info
            {
                self.record_pending_siginfo(ctx.kernel, target_tid, s, info);
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
            // A queued cross-process signal always needs the explicit-signal ring:
            // even a host-carryable standard signal loses SI_QUEUE and si_value if
            // it follows the plain-kill policy. `ns_target` is already the target's
            // HOST pid here. Signal 0 remains an existence check with no payload.
            if s != 0
                && let Ok(target_host) = i32::try_from(ns_target)
                && target_host > 0
            {
                // Preserve ESRCH/EPERM ordering without delivering a host signal.
                let sender_uid = self.cred_snapshot().euid;
                match bootstrap_signal_send_as(
                    SignalTarget::from_host_kill_pid(ns_target),
                    /* signum = */ 0,
                    Some(sender_uid),
                ) {
                    DispatchOutcome::Returned { value: 0 } => {}
                    outcome => return outcome,
                }
                let sender_ns = crate::namespace::pid::self_ns_pid() as i32;
                // si_value lives at offset 24 of the siginfo = `_pad[0..8]`.
                let value = user_info
                    .and_then(|i| i._pad.get(0..8).and_then(|b| b.try_into().ok()))
                    .map(i64::from_le_bytes)
                    .unwrap_or(0);
                let code = user_info
                    .map(|i| i.si_code)
                    .unwrap_or(crate::linux_abi::LINUX_SI_QUEUE);
                // rt_tgsigqueueinfo names a specific thread; carry it through
                // the ring as the guest-supplied tid (untranslated — same
                // convention `SignalTarget::GuestTid` uses). rt_sigqueueinfo
                // targets the thread group, so this stays 0.
                let target_ns_tid = if tid_directed { route_target as i32 } else { 0 };
                if crate::host_signal::xsig_enqueue(
                    target_host,
                    s,
                    code,
                    sender_ns,
                    sender_uid.raw(),
                    value,
                    target_ns_tid,
                ) {
                    crate::host_signal::xsig_nudge(target_host);
                    return DispatchOutcome::Returned { value: 0 };
                }
                // A host kill cannot preserve the queued payload. Report resource
                // exhaustion instead of silently delivering a different signal.
                return DispatchOutcome::errno(LINUX_EAGAIN);
            }
            // Signal 0 retains the kill(2)-style host route for its existence
            // check, but Linux still applies the caller's signal permissions.
            let sender_uid = self.cred_snapshot().euid;
            return bootstrap_signal_send_as(
                SignalTarget::from_host_kill_pid(ns_target),
                signum,
                Some(sender_uid),
            );
        }

        // Self-target (single-threaded, or no sibling registry hit): queue
        // against the caller's tid so delivery pairs with the same frame.
        let tid = Self::ctx_tid(ctx);
        if let Some(info) = user_info {
            self.record_pending_siginfo(ctx.kernel, tid, s, info);
        }
        self.mark_signal_pending(ctx.kernel, tid, s);
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
                let uid =
                    crate::cred_ipc::read_target(sender_host).unwrap_or(carrick_abi::NsUid::ROOT);
                LinuxSiginfo::kill(signum, crate::linux_abi::LINUX_SI_USER, ns_pid, uid.raw())
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

/// Resolve a THREAD-DIRECTED xsig ring entry's guest ns tid to a live local
/// `ThreadId`, mirroring `route_thread_signal`'s membership check
/// (`ctx.thread.registry.is_live`) for a caller with no `SyscallCtx` — the
/// ring drain runs outside any single syscall's dispatch, so it cannot borrow
/// a per-call thread registry the way `route_thread_signal` does.
///
/// The main thread's registry key deterministically equals this process's
/// host pid (`ThreadId::main_from_host_pid`), so when the CURRENT process has
/// no MT thread registry installed at all (the single-threaded run loop never
/// calls `set_current_registry` — there is no CLONE_THREAD table to consult)
/// a `target_ns_tid` naming the main thread still resolves: this is the common
/// "tid == pid" cross-process case (`bootstrap_signal_send_as`'s `GuestTid`
/// comment), and it must keep working for a single-threaded target exactly as
/// it did before this ring carried a tid at all. When a registry IS installed
/// (an MT process), its `is_live` is authoritative for every tid, including
/// the main one — deferred to entirely rather than short-circuited, so a
/// thread-group leader that has since exited is not misreported live.
fn resolve_xsig_thread_target(target_ns_tid: i32) -> Option<crate::thread::ThreadId> {
    let requested = crate::thread::ThreadId::from_guest_supplied_tid(target_ns_tid);
    match crate::thread::current_registry_liveness(requested) {
        Some(live) => live.then_some(requested),
        None => (requested == crate::thread::ThreadId::main_from_host_pid()).then_some(requested),
    }
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

fn names_current_thread_group<M: GuestMemory>(ctx: &SyscallCtx<'_, M>, x: i64) -> bool {
    names_self_pid(x)
        || ctx.thread.as_ref().is_some_and(|t| {
            t.registry.main_tid() == crate::thread::ThreadId::from_guest_supplied_tid(x as i32)
        })
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

fn host_signal_transport_allowed(hvpatch_lane: bool, _target: SignalTarget) -> bool {
    !hvpatch_lane
}

fn hvpatch_owns_specific_process_signal(hvpatch_lane: bool, pid: i32) -> bool {
    hvpatch_lane && pid > 0
}

fn hvpatch_process_signal_target(
    kernel: &crate::kernel::Kernel,
    pid: i32,
) -> Option<crate::kernel::TaskKey> {
    let target = crate::kernel::TaskId::from_abi_positive(pid).ok()?;
    kernel.live_task_key(target).or_else(|| {
        let tid = crate::kernel::LinuxTid::from_abi_positive(pid).ok()?;
        kernel
            .live_keys_for_thread(None, tid)
            .map(|(task, _thread)| task)
    })
}

fn hvpatch_signal_observes_zombie(kernel: &crate::kernel::Kernel, pid: i32) -> bool {
    // Linux keeps an exited child addressable until its parent consumes the
    // wait result. Numeric reuse cannot race this lookup: the zombie retains
    // its TaskClaim until that same consuming wait removes it.
    //
    // This holds for EVERY signal, not just the signum-0 existence probe.
    // kill(2) is explicit: "Note that an existing process might be a zombie, a
    // process that has terminated execution but has not yet been wait(2)ed
    // for." The signal is discarded, but the call SUCCEEDS. Restricting this to
    // signum 0 made carrick return ESRCH for a real signal to an unreaped
    // child, which is what LTP's `SAFE_KILL(child, SIGTERM)` teardown does to
    // the one-shot signal helper `create_sig_proc()` spawns.
    crate::kernel::TaskId::from_abi_positive(pid)
        .ok()
        .is_some_and(|target| kernel.registry().zombie(target).is_some())
}

fn hvpatch_owns_specific_thread_signal(hvpatch_lane: bool) -> bool {
    hvpatch_lane
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
    caller_euid: Option<carrick_abi::NsUid>,
) -> DispatchOutcome {
    if !is_valid_signum(signum) {
        return DispatchOutcome::errno(LINUX_EINVAL);
    }
    // A `GuestTid` target names one specific thread (tkill's cross-process
    // fallthrough); every other variant is process/group-directed. Captured
    // BEFORE `host_kill_encoding` collapses the typed target to its raw kill(2)
    // i64 (which cannot distinguish a tid from a pid), so the xsig ring send
    // below can still carry it.
    let target_ns_tid = match target {
        SignalTarget::GuestTid(t) => t.0,
        _ => 0,
    };
    let host_transport_allowed =
        host_signal_transport_allowed(crate::dispatch::hvpatch_lane_active(), target);
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
    if !host_transport_allowed {
        return DispatchOutcome::errno(LINUX_ESRCH);
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
        && !caller.is_root()
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
        let sender_uid = caller_euid
            .map(|u| u.raw())
            .unwrap_or_else(|| unsafe { libc::getuid() });
        // Routing still addresses the ring by host pid (`target`), so
        // cross-process thread-directed delivery only reaches a tid the
        // target process's registry actually has live — in practice this
        // works where it worked before (tid == pid main threads), and now
        // lands thread-directed in the target instead of process-directed.
        if crate::host_signal::xsig_enqueue(
            target as i32,
            signum as i32,
            crate::linux_abi::LINUX_SI_USER,
            sender_ns,
            sender_uid,
            0,
            target_ns_tid,
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
    // THE KERNEL LANE MUST NOT REACH THE HOST WITH A GUEST PID.
    //
    // Everything below assumes `target` is a host pid, which it is on `native`
    // and `vmm` where a Linux process IS a host process. On the kernel lane a
    // Linux process is a THREAD of this host process and its pid is a
    // carrick-kernel task id, so handing it to `libc::kill` signals whatever
    // host process happens to own that number.
    //
    // That is not a future hazard, it is a live one: guest task ids are
    // allocated from `host_pid + 1` upward
    // (`docs/perf-results/2026-08-13-hvpatch-id-mechanism-settled.md`), and
    // host pids in that range belong to real, unrelated processes started
    // around the same time. It gets categorically worse once the id space is
    // seeded at 1, where pid 1 on macOS is `launchd` — which is why this guard
    // is a PREREQUISITE for that change rather than a consequence of it.
    //
    // ESRCH is the honest answer while cross-process guest signal delivery
    // still goes through the kernel's own queues rather than the host's: it is
    // what the host call already returns for a guest pid that matches nothing,
    // minus the chance of hitting one that does.
    if crate::dispatch::hvpatch_lane_active() && target > 0 {
        return DispatchOutcome::errno(LINUX_ESRCH);
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
    fn hvpatch_blocks_every_guest_selector_before_xsig_or_host_kill() {
        let guest_one = HostPid(carrick_abi::LINUX_BOOTSTRAP_PID as u32);
        for target in [
            SignalTarget::HostProcess(guest_one),
            SignalTarget::HostProcessGroup(guest_one),
            SignalTarget::CallerProcessGroup,
            SignalTarget::Broadcast,
            SignalTarget::HostThread(guest_one),
            SignalTarget::GuestTid(NsPid(carrick_abi::LINUX_BOOTSTRAP_PID as i32)),
        ] {
            assert!(
                !host_signal_transport_allowed(true, target),
                "HVPatch guest selector {target:?} must not become an xsig key or Darwin kill target",
            );
            assert!(
                host_signal_transport_allowed(false, target),
                "reference lanes must retain their host-process transport for {target:?}",
            );
        }
        assert!(hvpatch_owns_specific_process_signal(
            true,
            carrick_abi::LINUX_BOOTSTRAP_PID as i32,
        ));
        assert!(hvpatch_owns_specific_thread_signal(true));
        assert!(!hvpatch_owns_specific_process_signal(
            false,
            carrick_abi::LINUX_BOOTSTRAP_PID as i32,
        ));
        assert!(!hvpatch_owns_specific_thread_signal(false));
    }

    #[test]
    fn hvpatch_process_signal_target_accepts_live_member_tid() {
        let dispatcher = SyscallDispatcher::new();
        let root = dispatcher.capture_one_task_context().unwrap();
        let registry_id = crate::thread::ThreadId::synthetic_for_tests(8101);
        let sibling_tid = dispatcher
            .register_one_task_thread(&root, registry_id)
            .unwrap();

        assert_eq!(
            hvpatch_process_signal_target(root.kernel(), sibling_tid.raw()),
            Some(root.task().key())
        );
    }

    #[test]
    fn hvpatch_signal_observes_zombie_until_reap() {
        let dispatcher = SyscallDispatcher::new();
        let parent = dispatcher.capture_one_task_context().expect("context");
        let child_thread =
            crate::thread::ThreadId::synthetic_for_tests(parent.thread().registry_id().raw() + 1);
        let plan =
            crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty()).unwrap();
        let child = parent
            .kernel()
            .reserve_fork(&parent, plan, "signal-zombie-fork".to_owned(), None)
            .unwrap()
            .prepare_reference(child_thread)
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0;
        let child_id = child.task().key().id;
        let child_pid = child_id.raw();

        parent
            .kernel()
            .exit_task(
                child_id,
                crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("child exit");

        assert!(hvpatch_process_signal_target(parent.kernel(), child_pid).is_none());
        // Addressable until reaped, for EVERY signal — not just the signum-0
        // existence probe. The predicate no longer takes a signum at all; it
        // used to, and the assertion here demanded that a real signal NOT
        // observe the zombie, pinning the ESRCH bug in place. kill(2): "an
        // existing process might be a zombie ... that has not yet been
        // wait(2)ed for."
        assert!(hvpatch_signal_observes_zombie(parent.kernel(), child_pid));
        assert!(!hvpatch_signal_observes_zombie(
            parent.kernel(),
            child_pid + 1000,
        ));

        parent
            .kernel()
            .wait_child(
                parent.task().key().id,
                Some(child_id),
                crate::kernel::WaitMode::Consume,
            )
            .expect("consume child wait");
        assert!(!hvpatch_signal_observes_zombie(parent.kernel(), child_pid));
    }

    #[test]
    fn exact_pidfd_signal_preserves_queued_siginfo() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.exact_signal_context_for_test();
        let tid = context.thread().registry_id();
        let signum = crate::linux_abi::LINUX_SIGUSR1;
        let info = LinuxSiginfo::rt_queue(signum, 71, 72, 0x1234_5678);

        assert_eq!(
            dispatcher.hvpatch_exact_process_signal(
                &context,
                context.task().key(),
                signum as u64,
                Some(info),
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        let pending = dispatcher
            .take_deliverable_pending_from(&context, tid)
            .expect("exact pidfd signal must enter the target task queue");
        assert_eq!(pending.signum, signum);
        assert_eq!(pending.siginfo, Some(info));
    }

    #[test]
    fn dispatcher_action_binding_is_the_captured_kernel_sighand() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("context");
        let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("signal");
        let action = LinuxSigaction {
            sa_handler: 0x1234_0000,
            sa_flags: crate::linux_abi::LINUX_SA_SIGINFO,
            sa_restorer: 0x5678_0000,
            sa_mask: [0x55],
        };

        SyscallDispatcher::install_signal_action(
            &dispatcher.exact_signal_context_for_test(),
            signal.raw(),
            action,
        );

        assert_eq!(context.shared().sighand().action(signal), action);
        assert_eq!(
            dispatcher.registered_signal_handler(
                &dispatcher.exact_signal_context_for_test(),
                signal.raw()
            ),
            Some(action)
        );
    }

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
    fn fork_child_clears_old_and_new_pending_signal_state() {
        let d = SyscallDispatcher::new();
        let parent = d.capture_one_task_context().expect("context");
        let old = parent.thread().registry_id();
        let new = crate::thread::ThreadId::synthetic_for_tests(old.raw() + 1);
        let mask = SigSet::EMPTY.with(12);
        let restore = SigSet::EMPTY.with(14);
        d.restore_signal_mask(&d.exact_signal_context_for_test(), old, mask);
        parent.thread().update_signal_state(|state| {
            state.set_altstack(Some(carrick_abi::LinuxSigaltstack::empty()));
            state.push_handler_frame(crate::kernel::HandlerFrameState {
                on_altstack: true,
                restore_mask: None,
            });
            state.arm_restore_mask(Some(restore));
        });
        d.mark_signal_pending(&d.exact_signal_context_for_test(), old, 10);
        d.mark_process_signal_pending(&d.exact_signal_context_for_test(), 10);
        let plan =
            crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty()).unwrap();
        let child = parent
            .kernel()
            .reserve_fork(&parent, plan, "signal-pending-fork".to_owned(), None)
            .unwrap()
            .prepare_reference(new)
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0;
        let state = child.thread().signal_state();
        assert_eq!(state.blocked(), mask);
        assert!(state.altstack_enabled());
        assert_eq!(state.handler_frame_depth(), 1);
        assert_eq!(state.armed_restore_mask(), Some(restore));
        assert!(state.pending().is_empty());
        assert!(!child.signal_authority().may_have_task_pending());
        assert!(parent.signal_authority().may_have_task_pending());
    }

    #[test]
    fn fork_child_retires_sibling_thread_signal_state() {
        let d = SyscallDispatcher::new();
        let parent = d.capture_one_task_context().unwrap();
        let keeper = parent.thread().registry_id();
        let sibling = crate::thread::ThreadId::synthetic_for_tests(keeper.raw() + 1);
        d.register_one_task_thread(&parent, sibling).unwrap();
        let parent = d.capture_kernel_context(parent.thread().key().tid).unwrap();
        d.mark_signal_pending(&d.exact_signal_context_for_test(), keeper, 10);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), sibling, 12);
        let child_tid = crate::thread::ThreadId::synthetic_for_tests(keeper.raw() + 2);
        let plan =
            crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty()).unwrap();
        let child = parent
            .kernel()
            .reserve_fork(&parent, plan, "signal-sibling-fork".to_owned(), None)
            .unwrap()
            .prepare_reference(child_tid)
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0;
        assert_eq!(child.task().threads().len(), 1);
        assert!(child.thread().signal_state().pending().is_empty());
        assert!(parent.task().thread_by_registry_id(sibling).is_some());
    }

    #[test]
    fn pending_hints_never_hide_deliverable_signals() {
        let d = SyscallDispatcher::new();
        let context = d.capture_one_task_context().unwrap();
        let tid = context.thread().registry_id();
        let sibling = crate::thread::ThreadId::synthetic_for_tests(tid.raw() + 1);
        let sibling_tid = d.register_one_task_thread(&context, sibling).unwrap();
        let take = |target| {
            d.take_deliverable_pending_from(&d.exact_signal_context_for_test(), target)
                .map(|pending| (pending.signum, pending.owner))
        };

        // Empty state: the fast path proves emptiness.
        assert_eq!(take(tid), None);

        // Per-tid mark → deliverable through the fast path; drained → empty.
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 10);
        assert_eq!(
            take(tid),
            Some((10, crate::kernel::SignalPendingOwner::Thread))
        );
        assert_eq!(take(tid), None);

        // RT double-queue (dnotify chain shape): two instances, two takes.
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 34);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 34);
        assert_eq!(
            take(tid),
            Some((34, crate::kernel::SignalPendingOwner::Thread))
        );
        assert_eq!(
            take(tid),
            Some((34, crate::kernel::SignalPendingOwner::Thread)),
            "second queued RT instance must chain (hint must stay set)"
        );
        assert_eq!(take(tid), None);

        // Shared process-directed mark: ANY tid may take it.
        d.mark_process_signal_pending(&d.exact_signal_context_for_test(), 15);
        assert_eq!(
            take(sibling),
            Some((15, crate::kernel::SignalPendingOwner::Task))
        );
        assert_eq!(take(sibling), None);

        // A blocked-then-unblocked signal: pending while blocked (no take),
        // deliverable after the mask restore — no new mark bumps the hint, so
        // a stale-clear hint would strand it forever.
        d.restore_signal_mask(
            &d.exact_signal_context_for_test(),
            tid,
            SigSet::EMPTY.with(12),
        );
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 12);
        assert_eq!(take(tid), None, "blocked signal must stay pending");
        d.restore_signal_mask(&d.exact_signal_context_for_test(), tid, SigSet::EMPTY);
        assert_eq!(
            take(tid),
            Some((12, crate::kernel::SignalPendingOwner::Thread))
        );

        // Sibling retirement refreshes hints without dropping the keeper's.
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 10);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), sibling, 10);
        let sibling_context = d.capture_kernel_context(sibling_tid).unwrap();
        sibling_context
            .kernel()
            .exit_thread(&sibling_context, None)
            .unwrap();
        assert_eq!(
            take(tid),
            Some((10, crate::kernel::SignalPendingOwner::Thread))
        );
        assert_eq!(take(sibling), None);
    }

    #[test]
    fn rt_sigqueueinfo_rejects_nonpositive_tgid_with_einval() {
        let d = SyscallDispatcher::new();
        let mut memory = crate::dispatch::LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = crate::compat::CompatReporter::default();
        let kernel = d.capture_one_task_context().unwrap();
        let cx = crate::dispatch::SyscallCtx {
            kernel: &kernel,
            request: crate::dispatch::SyscallRequest::new(
                138,
                crate::dispatch::SyscallArgs::from([0, 0, 0, 0, 0, 0]),
            ),
            memory: &mut memory,
            reporter: &reporter,
            thread: None,
        };

        for tgid in [0, -1, -2] {
            assert_eq!(
                d.sigqueueinfo_common(&cx, tgid, tgid, 0, GuestPtr(0), false),
                DispatchOutcome::errno(LINUX_EINVAL),
                "rt_sigqueueinfo tgid {tgid} must not use kill-style target semantics"
            );
        }
    }

    #[test]
    fn cross_process_sigqueue_usr1_ring_full_returns_eagain_without_host_kill_fallback() {
        use zerocopy::IntoBytes;

        let _g = XSIG_RING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(
            !crate::namespace::pid::enabled(),
            "the regression is the ordinary non-namespaced route"
        );

        carrick_signal_core::xsig::xsig_init();
        let me = std::process::id() as i32;
        let usr1 = crate::linux_abi::LINUX_SIGUSR1;
        let _ = carrick_signal_core::xsig::xsig_drain_for_self();
        // Fill with null signals so parallel signal-wait tests cannot observe
        // this capacity fixture as deliverable pending work.
        for slot in 0..256 {
            assert!(
                carrick_signal_core::xsig::xsig_enqueue(
                    me,
                    0,
                    crate::linux_abi::LINUX_SI_QUEUE,
                    slot,
                    0,
                    i64::from(slot),
                    0,
                ),
                "ring slot {slot} must be available"
            );
        }
        assert!(
            !carrick_signal_core::xsig::xsig_enqueue(
                me,
                0,
                crate::linux_abi::LINUX_SI_QUEUE,
                999,
                0,
                0,
                0,
            ),
            "the regression requires a full ring"
        );

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn signal target");
        let child_pid = i64::from(child.id());
        assert!(
            !should_route_specific_xsig(child_pid as i32, usr1),
            "plain kill policy deliberately keeps ordinary SIGUSR1 off the ring"
        );

        let d = SyscallDispatcher::new();
        let mut memory = crate::dispatch::LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = crate::compat::CompatReporter::default();
        let siginfo = LinuxSiginfo::rt_queue(usr1, me, 0, 0x5eed_cafe);
        memory.write_bytes(0x400, siginfo.as_bytes()).unwrap();
        let kernel = d.capture_one_task_context().unwrap();
        let cx = crate::dispatch::SyscallCtx {
            kernel: &kernel,
            request: crate::dispatch::SyscallRequest::new(
                138,
                crate::dispatch::SyscallArgs::from([child_pid as u64, usr1 as u64, 0x400, 0, 0, 0]),
            ),
            memory: &mut memory,
            reporter: &reporter,
            thread: None,
        };
        let outcome = d.sigqueueinfo_common(
            &cx,
            child_pid,
            child_pid,
            usr1 as u64,
            GuestPtr(0x400),
            false,
        );

        let _ = child.kill();
        let _ = child.wait();
        let _ = carrick_signal_core::xsig::xsig_drain_for_self();

        assert_eq!(
            outcome,
            DispatchOutcome::errno(LINUX_EAGAIN),
            "queued delivery must report ring exhaustion instead of losing si_value via host kill"
        );
    }

    #[test]
    fn cross_process_sigqueue_checks_guest_credentials_before_ring_capacity() {
        use std::os::unix::fs::PermissionsExt as _;
        use zerocopy::IntoBytes;

        let _g = XSIG_RING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(
            !crate::namespace::pid::enabled(),
            "the regression is the ordinary non-namespaced route"
        );

        carrick_signal_core::xsig::xsig_init();
        let me = std::process::id() as i32;
        let usr1 = crate::linux_abi::LINUX_SIGUSR1;
        let _ = carrick_signal_core::xsig::xsig_drain_for_self();
        // Null-signal entries consume capacity without waking parallel waiters.
        for slot in 0..256 {
            assert!(carrick_signal_core::xsig::xsig_enqueue(
                me,
                0,
                crate::linux_abi::LINUX_SI_QUEUE,
                slot,
                0,
                i64::from(slot),
                0,
            ));
        }

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn signal target");
        let child_pid = i64::from(child.id());
        let target_euid = carrick_abi::NsUid::new(2000);
        let cred_path = std::path::PathBuf::from(format!("/tmp/carrick-cred-{child_pid}"));
        let _ = std::fs::remove_file(&cred_path);
        std::fs::write(&cred_path, target_euid.raw().to_le_bytes())
            .expect("publish target guest euid");
        let mut permissions = std::fs::metadata(&cred_path)
            .expect("read target cred metadata")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&cred_path, permissions).expect("secure target cred fixture");
        let published_euid = crate::cred_ipc::read_target(child_pid as i32);

        let d = SyscallDispatcher::new();
        d.set_credentials(carrick_abi::NsUid::new(1000), carrick_abi::NsGid::new(1000));
        let mut memory = crate::dispatch::LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = crate::compat::CompatReporter::default();
        let siginfo = LinuxSiginfo::rt_queue(usr1, me, 1000, 0x5eed_cafe);
        memory.write_bytes(0x400, siginfo.as_bytes()).unwrap();
        let kernel = d.capture_one_task_context().unwrap();
        let cx = crate::dispatch::SyscallCtx {
            kernel: &kernel,
            request: crate::dispatch::SyscallRequest::new(
                138,
                crate::dispatch::SyscallArgs::from([child_pid as u64, usr1 as u64, 0x400, 0, 0, 0]),
            ),
            memory: &mut memory,
            reporter: &reporter,
            thread: None,
        };
        let outcome = d.sigqueueinfo_common(
            &cx,
            child_pid,
            child_pid,
            usr1 as u64,
            GuestPtr(0x400),
            false,
        );

        let _ = std::fs::remove_file(cred_path);
        let _ = child.kill();
        let _ = child.wait();
        let _ = carrick_signal_core::xsig::xsig_drain_for_self();

        assert_eq!(published_euid, Some(target_euid));
        assert_eq!(
            outcome,
            DispatchOutcome::errno(LINUX_EPERM),
            "guest credential denial must precede ring-full EAGAIN"
        );
    }

    #[test]
    fn cross_process_sigqueue_signal_zero_checks_guest_credentials() {
        use std::os::unix::fs::PermissionsExt as _;

        assert!(
            !crate::namespace::pid::enabled(),
            "the regression is the ordinary non-namespaced route"
        );

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn signal target");
        let child_pid = i64::from(child.id());
        let target_euid = carrick_abi::NsUid::new(2000);
        let cred_path = std::path::PathBuf::from(format!("/tmp/carrick-cred-{child_pid}"));
        let _ = std::fs::remove_file(&cred_path);
        std::fs::write(&cred_path, target_euid.raw().to_le_bytes())
            .expect("publish target guest euid");
        let mut permissions = std::fs::metadata(&cred_path)
            .expect("read target cred metadata")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&cred_path, permissions).expect("secure target cred fixture");
        let published_euid = crate::cred_ipc::read_target(child_pid as i32);

        let d = SyscallDispatcher::new();
        d.set_credentials(carrick_abi::NsUid::new(1000), carrick_abi::NsGid::new(1000));
        let mut memory = crate::dispatch::LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = crate::compat::CompatReporter::default();
        let kernel = d.capture_one_task_context().unwrap();
        let cx = crate::dispatch::SyscallCtx {
            kernel: &kernel,
            request: crate::dispatch::SyscallRequest::new(
                138,
                crate::dispatch::SyscallArgs::from([child_pid as u64, 0, 0, 0, 0, 0]),
            ),
            memory: &mut memory,
            reporter: &reporter,
            thread: None,
        };
        let outcome = d.sigqueueinfo_common(&cx, child_pid, child_pid, 0, GuestPtr(0), false);

        let _ = std::fs::remove_file(cred_path);
        let _ = child.kill();
        let _ = child.wait();

        assert_eq!(published_euid, Some(target_euid));
        assert_eq!(
            outcome,
            DispatchOutcome::errno(LINUX_EPERM),
            "signal 0 must apply the guest credential permission check"
        );
    }

    #[test]
    fn rt_signals_queue_while_standard_signals_coalesce() {
        let d = SyscallDispatcher::new();
        let tid = d.capture_one_task_context().unwrap().thread().registry_id();

        // A standard signal (10) sent 3× while pending coalesces to one delivery.
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 10);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 10);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 10);
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            Some(10)
        );
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            None
        );

        // A real-time signal (34) sent 3× delivers 3× (POSIX queuing).
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 34);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 34);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 34);
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            Some(34)
        );
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            Some(34)
        );
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            Some(34)
        );
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            None
        );

        // Mixed: the lowest deliverable comes first, then the RT queue drains.
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 34);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 34);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 10);
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            Some(10)
        );
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            Some(34)
        );
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            Some(34)
        );
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            None
        );
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
        install_kernel_signal_threads(&d, &[sender, waiter]);

        d.mark_process_signal_pending(&d.exact_signal_context_for_test(), usr1);
        // A sigwait whose set does NOT include SIGUSR1 must not dequeue it.
        let other = SigSet::EMPTY.with(12); // SIGUSR2 (12), not SIGUSR1
        assert_eq!(
            d.take_pending_in(&d.exact_signal_context_for_test(), waiter, other),
            None
        );
        // The SIBLING (a thread other than the sender) parked in sigwait
        // selecting SIGUSR1 dequeues the shared signal — the core fix.
        assert_eq!(
            d.take_pending_in(&d.exact_signal_context_for_test(), waiter, set),
            Some(usr1)
        );
        // Consumed exactly once — no second thread can also take it.
        assert_eq!(
            d.take_pending_in(&d.exact_signal_context_for_test(), sender, set),
            None
        );
        assert_eq!(
            d.take_pending_in(&d.exact_signal_context_for_test(), waiter, set),
            None
        );

        // The deliver-on-unblock path (take_deliverable_pending) also drains the
        // shared set, for a thread that unblocks the signal without sigwait.
        d.mark_process_signal_pending(&d.exact_signal_context_for_test(), usr1);
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), waiter),
            Some(usr1)
        );
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), sender),
            None
        );

        // Shared RT signals queue per POSIX (N sends → N deliveries), independent
        // of which thread drains them.
        d.mark_process_signal_pending(&d.exact_signal_context_for_test(), 34);
        d.mark_process_signal_pending(&d.exact_signal_context_for_test(), 34);
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), waiter),
            Some(34)
        );
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), sender),
            Some(34)
        );
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), waiter),
            None
        );
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

        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, signum);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, signum);
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            Some(signum)
        );
        let saved = d.enter_signal_handler(&d.exact_signal_context_for_test(), tid, signum, action);
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            None
        );
        d.restore_signal_mask(&d.exact_signal_context_for_test(), tid, saved);
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            Some(signum)
        );
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), tid),
            None
        );
    }

    #[test]
    fn wait_predicate_sees_shared_process_pending() {
        use carrick_abi::WaitSigMask;

        let d = SyscallDispatcher::new();
        let tid = d.capture_one_task_context().unwrap().thread().registry_id();
        let usr1 = 10;
        let blocked = SigSet::EMPTY.with(usr1);

        d.mark_process_signal_pending(&d.exact_signal_context_for_test(), usr1);

        // Additive (read/recv, empty extra set): an UNBLOCKED pending signal is
        // deliverable and interrupts the wait.
        assert!(d.has_deliverable_dispatch_pending_for_wait(
            &d.exact_signal_context_for_test(),
            tid,
            WaitSigMask::NONE
        ));
        // Replace (ppoll/pselect/epoll_pwait): a signal the temp mask BLOCKS does
        // not interrupt.
        assert!(!d.has_deliverable_dispatch_pending_for_wait(
            &d.exact_signal_context_for_test(),
            tid,
            WaitSigMask::Replace(blocked)
        ));
        d.restore_signal_mask(&d.exact_signal_context_for_test(), tid, blocked);
        // Additive: a signal blocked by the thread's PERSISTENT mask must NOT
        // interrupt a plain read — this is the `maskfork` invariant.
        assert!(!d.has_deliverable_dispatch_pending_for_wait(
            &d.exact_signal_context_for_test(),
            tid,
            WaitSigMask::NONE
        ));
        // Replace: an EMPTY temp mask UNBLOCKS that persistently-blocked pending
        // signal, so it MUST be deliverable — POSIX ppoll/pselect replace
        // semantics. Unioning the persistent mask would wrongly suppress it; this
        // guards the `ppollunblock` regression.
        assert!(d.has_deliverable_dispatch_pending_for_wait(
            &d.exact_signal_context_for_test(),
            tid,
            WaitSigMask::Replace(SigSet::EMPTY)
        ));
    }

    #[test]
    fn wait_predicate_does_not_interrupt_for_default_ignored_signal() {
        use carrick_abi::WaitSigMask;

        let d = SyscallDispatcher::new();
        let context = d.exact_signal_context_for_test();
        let tid = context.thread().registry_id();
        d.mark_process_signal_pending(&context, crate::linux_abi::LINUX_SIGCHLD);

        assert!(
            !d.has_deliverable_dispatch_pending_for_wait(&context, tid, WaitSigMask::NONE),
            "default-ignored SIGCHLD is pending but cannot interrupt a Linux blocking wait"
        );
    }

    /// Pins the procladder_mt silent-stall root cause: a PROCESS-directed
    /// signal drained from the cross-process xsignal ring by a thread that is
    /// NOT the eventual consumer (the pause()-sibling winning the drain race)
    /// must land in the SHARED pending set — visible to a sibling thread's
    /// sigwait — and carry the sender's identity with it. Pre-fix, the drain
    /// pinned it to the drainer (`mark_signal_pending(drainer)`), and the
    /// `take_pending_in(main, …)` below returned None forever: the whole-
    /// process wedge.
    ///
    /// This test and the three `ring_drain_*`/`per_tid_delivery_*` tests below
    /// that touch the REAL global xsig ring all target THIS process
    /// (`std::process::id()`, the test binary's own pid — there is no other
    /// "cross-process" target available in-process) with overlapping signums,
    /// so they race each other if cargo runs them on parallel test threads.
    /// Serialised on one lock, mirroring the same-shaped `TEST_LOCK` already
    /// used by `carrick-signal-core`'s and `carrick-vmm-hvf`'s own xsig ring
    /// tests for the identical reason.
    static XSIG_RING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn install_kernel_signal_threads(
        dispatcher: &SyscallDispatcher,
        registry_ids: &[crate::thread::ThreadId],
    ) {
        let parent = dispatcher.capture_one_task_context().unwrap();
        for registry_id in registry_ids {
            dispatcher
                .register_one_task_thread(&parent, *registry_id)
                .unwrap();
        }
    }

    #[test]
    fn ring_drain_publishes_process_directed_signal_visible_to_non_drainer() {
        let _g = XSIG_RING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let d = SyscallDispatcher::new();
        let main = crate::thread::ThreadId::synthetic_for_tests(6001);
        let sibling = crate::thread::ThreadId::synthetic_for_tests(6002);
        let usr1 = crate::linux_abi::LINUX_SIGUSR1;
        install_kernel_signal_threads(&d, &[main, sibling]);
        // Probe shape: BOTH threads block SIGUSR1 (main consumes via sigwait,
        // the sibling can never take delivery).
        d.restore_signal_mask(
            &d.exact_signal_context_for_test(),
            main,
            SigSet::EMPTY.with(usr1),
        );
        d.restore_signal_mask(
            &d.exact_signal_context_for_test(),
            sibling,
            SigSet::EMPTY.with(usr1),
        );

        carrick_signal_core::xsig::xsig_init();
        assert!(
            carrick_signal_core::xsig::xsig_enqueue(
                std::process::id() as i32,
                usr1,
                crate::linux_abi::LINUX_SI_USER,
                4242,
                1000,
                0,
                0,
            ),
            "ring slot available"
        );
        // The SIBLING wins the drain race (the hang's interleaving).
        d.drain_xsignals_process_directed(&d.exact_signal_context_for_test());

        // Nothing may be pinned to the drainer…
        assert!(
            d.take_pending_siginfo(&d.exact_signal_context_for_test(), sibling, usr1)
                .is_none(),
            "drain must not pin the payload to the drainer tid"
        );
        // …the MAIN thread's sigwait take must find it in the shared set…
        let set = SigSet::EMPTY.with(usr1);
        let pending = d
            .take_pending_in_from(&d.exact_signal_context_for_test(), main, set)
            .expect("process-directed signal must be visible to the non-drainer's sigwait");
        assert_eq!(pending.signum, usr1);
        assert_eq!(pending.owner, crate::kernel::SignalPendingOwner::Task);
        // …with the sender's identity travelling alongside.
        let info = pending
            .siginfo
            .expect("siginfo payload follows the shared set");
        assert_eq!(
            (info.si_addr & 0xffff_ffff) as i32,
            4242,
            "sender ns-pid survives the drain"
        );
        // Exactly-once: nothing left for a second take.
        assert_eq!(
            d.take_pending_in(&d.exact_signal_context_for_test(), main, set),
            None
        );
    }

    /// Provenance gate: a per-tid (host-slot-style) delivery of the SAME
    /// signum must not steal a queued PROCESS-directed payload while the
    /// shared pending bit is still set — and each take pairs with the siginfo
    /// from its own store.
    #[test]
    fn per_tid_delivery_does_not_steal_process_directed_payload() {
        let d = SyscallDispatcher::new();
        let main = crate::thread::ThreadId::synthetic_for_tests(6003);
        let chld = crate::linux_abi::LINUX_SIGCHLD;
        let set = SigSet::EMPTY.with(chld);
        install_kernel_signal_threads(&d, &[main]);

        // Shared-set instance with payload (the ring-drain shape).
        d.mark_process_signal_pending_with_info(
            &d.exact_signal_context_for_test(),
            chld,
            Some(LinuxSiginfo::kill(
                chld,
                crate::linux_abi::LINUX_SI_USER,
                7777,
                0,
            )),
        );

        // Host-slot-style per-tid fetch (per-tid queue EMPTY): must NOT
        // consume the shared queue (an ungated fallback returned 7777 here,
        // swapping payloads between two same-signum instances).
        assert!(
            d.take_pending_siginfo(&d.exact_signal_context_for_test(), main, chld)
                .is_none(),
            "per-tid siginfo fetch must not consume the process-directed queue"
        );

        // With a per-tid instance ALSO queued: the per-thread take pairs with
        // the per-tid payload…
        d.mark_signal_pending(&d.exact_signal_context_for_test(), main, chld);
        d.record_pending_siginfo(
            &d.exact_signal_context_for_test(),
            main,
            chld,
            LinuxSiginfo::kill(chld, crate::linux_abi::LINUX_SI_USER, 1111, 0),
        );
        let first = d
            .take_pending_in_from(&d.exact_signal_context_for_test(), main, set)
            .unwrap();
        assert_eq!(first.signum, chld);
        assert_eq!(first.owner, crate::kernel::SignalPendingOwner::Thread);
        assert_eq!((first.siginfo.unwrap().si_addr & 0xffff_ffff) as i32, 1111);
        // …and the shared instance + payload remain intact for the shared take.
        let second = d
            .take_pending_in_from(&d.exact_signal_context_for_test(), main, set)
            .unwrap();
        assert_eq!(second.signum, chld);
        assert_eq!(second.owner, crate::kernel::SignalPendingOwner::Task);
        assert_eq!((second.siginfo.unwrap().si_addr & 0xffff_ffff) as i32, 7777);
    }

    /// Set up a live registry (main + one sibling) and publish it as the
    /// process's CURRENT thread registry, so `drain_xsignals_process_directed`'s
    /// `target_ns_tid` resolution (which consults
    /// `crate::thread::current_registry_liveness`, the same per-process handle
    /// `route_thread_signal` reaches via `ctx.thread.registry`) can resolve
    /// `main`/`sibling` as live. Registered under the SAME test-shape tids the
    /// pinning tests above use (`ThreadRegistry::new` takes `main` as the
    /// registry's main tid; `register_child` then allocates monotonically from
    /// `main + 1`, landing exactly on `sibling`). Callers serialise on
    /// `XSIG_RING_TEST_LOCK`: `CURRENT_REGISTRY` is ALSO a process-global
    /// singleton, alongside the xsig ring itself.
    fn install_test_registry(main: crate::thread::ThreadId, sibling: crate::thread::ThreadId) {
        let registry = std::sync::Arc::new(crate::thread::ThreadRegistry::new(main));
        let allocated = registry.register_child(0);
        assert_eq!(
            allocated, sibling,
            "test tids must line up with the registry's next-tid allocation"
        );
        crate::thread::set_current_registry(registry);
    }

    /// Pins the target_ns_tid resolution + publish half of Task 3: a
    /// THREAD-DIRECTED cross-process xsig entry (tkill/tgkill/
    /// rt_tgsigqueueinfo across processes) must land ONLY in the named
    /// thread's per-tid state — never pinned to the drainer, and never in the
    /// SHARED process-directed set (that would let ANY sibling consume a send
    /// Linux delivers to one specific thread).
    #[test]
    fn ring_drain_routes_thread_directed_to_target_tid_only() {
        let _g = XSIG_RING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let d = SyscallDispatcher::new();
        let main = crate::thread::ThreadId::synthetic_for_tests(6101);
        let sibling = crate::thread::ThreadId::synthetic_for_tests(6102);
        let usr1 = crate::linux_abi::LINUX_SIGUSR1;
        install_kernel_signal_threads(&d, &[main, sibling]);
        // Probe shape: BOTH threads block SIGUSR1 (mirrors
        // ring_drain_publishes_process_directed_signal_visible_to_non_drainer),
        // so nothing here is deliverable by the fast "unblocked" path — the
        // resolution must come from the target_ns_tid itself, not a blocked-mask
        // side effect.
        d.restore_signal_mask(
            &d.exact_signal_context_for_test(),
            main,
            SigSet::EMPTY.with(usr1),
        );
        d.restore_signal_mask(
            &d.exact_signal_context_for_test(),
            sibling,
            SigSet::EMPTY.with(usr1),
        );
        install_test_registry(main, sibling);

        carrick_signal_core::xsig::xsig_init();
        assert!(
            carrick_signal_core::xsig::xsig_enqueue(
                std::process::id() as i32,
                usr1,
                crate::linux_abi::LINUX_SI_TKILL,
                4242,
                1000,
                0,
                main.raw(),
            ),
            "ring slot available"
        );
        // The SIBLING wins the drain race (the same interleaving the
        // process-directed pinning test guards against).
        d.drain_xsignals_process_directed(&d.exact_signal_context_for_test());

        // NOT pinned to the drainer.
        assert!(
            d.take_pending_siginfo(&d.exact_signal_context_for_test(), sibling, usr1)
                .is_none(),
            "thread-directed drain must not pin the payload to the drainer tid"
        );
        // NOT process-directed: the shared set must stay untouched.
        assert!(
            !d.exact_signal_context_for_test()
                .shared()
                .pending_signals()
                .may_be_nonempty(),
            "thread-directed drain must not land in the shared process-pending set"
        );
        // Visible to MAIN per-thread, carrying the sender identity + SI_TKILL.
        let set = SigSet::EMPTY.with(usr1);
        let pending = d
            .take_pending_in_from(&d.exact_signal_context_for_test(), main, set)
            .expect("thread-directed signal must be visible to its named target");
        assert_eq!(pending.signum, usr1);
        assert_eq!(pending.owner, crate::kernel::SignalPendingOwner::Thread);
        let info = pending
            .siginfo
            .expect("siginfo payload follows the per-thread store");
        assert_eq!(
            (info.si_addr & 0xffff_ffff) as i32,
            4242,
            "sender ns-pid survives the drain"
        );
        assert_eq!({ info.si_code }, crate::linux_abi::LINUX_SI_TKILL);
        // Exactly-once: nothing left for a second take.
        assert_eq!(
            d.take_pending_in(&d.exact_signal_context_for_test(), main, set),
            None
        );
    }

    /// `target_ns_tid == 0` must keep TODAY's process-directed contract
    /// byte-for-byte — the exact assertions
    /// `ring_drain_publishes_process_directed_signal_visible_to_non_drainer`
    /// makes, just re-run here to pin that the new tid-carrying arity didn't
    /// change the zero case.
    #[test]
    fn ring_drain_target_tid_zero_stays_process_directed() {
        let _g = XSIG_RING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let d = SyscallDispatcher::new();
        let main = crate::thread::ThreadId::synthetic_for_tests(6201);
        let sibling = crate::thread::ThreadId::synthetic_for_tests(6202);
        let usr1 = crate::linux_abi::LINUX_SIGUSR1;
        install_kernel_signal_threads(&d, &[main, sibling]);
        d.restore_signal_mask(
            &d.exact_signal_context_for_test(),
            main,
            SigSet::EMPTY.with(usr1),
        );
        d.restore_signal_mask(
            &d.exact_signal_context_for_test(),
            sibling,
            SigSet::EMPTY.with(usr1),
        );

        carrick_signal_core::xsig::xsig_init();
        assert!(
            carrick_signal_core::xsig::xsig_enqueue(
                std::process::id() as i32,
                usr1,
                crate::linux_abi::LINUX_SI_USER,
                4242,
                1000,
                0,
                0,
            ),
            "ring slot available"
        );
        d.drain_xsignals_process_directed(&d.exact_signal_context_for_test());

        assert!(
            d.take_pending_siginfo(&d.exact_signal_context_for_test(), sibling, usr1)
                .is_none(),
            "drain must not pin the payload to the drainer tid"
        );
        let set = SigSet::EMPTY.with(usr1);
        let pending = d
            .take_pending_in_from(&d.exact_signal_context_for_test(), main, set)
            .expect("process-directed signal must be visible to the non-drainer's sigwait");
        assert_eq!(pending.signum, usr1);
        assert_eq!(pending.owner, crate::kernel::SignalPendingOwner::Task);
        let info = pending
            .siginfo
            .expect("siginfo payload follows the shared set");
        assert_eq!(
            (info.si_addr & 0xffff_ffff) as i32,
            4242,
            "sender ns-pid survives the drain"
        );
        assert_eq!(
            d.take_pending_in(&d.exact_signal_context_for_test(), main, set),
            None
        );
    }

    /// A thread-directed ring entry whose `target_ns_tid` matches NO live
    /// thread (the target already exited) must be DISCARDED entirely, matching
    /// Linux's own semantics: a thread-directed pending signal for an exited
    /// thread is dropped, not redirected to a sibling or the shared set.
    #[test]
    fn ring_drain_discards_thread_directed_for_exited_tid() {
        let _g = XSIG_RING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let d = SyscallDispatcher::new();
        let main = crate::thread::ThreadId::synthetic_for_tests(6301);
        let sibling = crate::thread::ThreadId::synthetic_for_tests(6302);
        let exited = crate::thread::ThreadId::synthetic_for_tests(6399);
        let usr1 = crate::linux_abi::LINUX_SIGUSR1;
        install_kernel_signal_threads(&d, &[main, sibling]);
        install_test_registry(main, sibling);

        carrick_signal_core::xsig::xsig_init();
        assert!(carrick_signal_core::xsig::xsig_enqueue(
            std::process::id() as i32,
            usr1,
            crate::linux_abi::LINUX_SI_TKILL,
            4242,
            1000,
            0,
            exited.raw(),
        ));
        d.drain_xsignals_process_directed(&d.exact_signal_context_for_test());

        let set = SigSet::EMPTY.with(usr1);
        assert!(
            d.take_pending_in(&d.exact_signal_context_for_test(), main, set)
                .is_none()
        );
        assert!(
            d.take_pending_in(&d.exact_signal_context_for_test(), sibling, set)
                .is_none()
        );
        assert!(
            !d.exact_signal_context_for_test()
                .shared()
                .pending_signals()
                .may_be_nonempty()
        );
    }

    #[test]
    fn child_exit_signal_pump_predicate_tracks_observable_dispositions() {
        let d = SyscallDispatcher::new();
        let tid = d.capture_one_task_context().unwrap().thread().registry_id();

        assert!(
            !d.child_exit_signal_needs_pump(
                &d.exact_signal_context_for_test(),
                tid,
                crate::linux_abi::LINUX_SIGCHLD as u32
            ),
            "default unblocked SIGCHLD is inert; wait4 owns the reap path"
        );
        assert!(
            d.child_exit_signal_needs_pump(
                &d.exact_signal_context_for_test(),
                tid,
                crate::linux_abi::LINUX_SIGUSR1 as u32
            ),
            "non-ignored default exit signals can terminate the parent"
        );

        let chld_set = SigSet::EMPTY.with(crate::linux_abi::LINUX_SIGCHLD);
        d.restore_signal_mask(&d.exact_signal_context_for_test(), tid, chld_set);
        assert!(
            d.child_exit_signal_needs_pump(
                &d.exact_signal_context_for_test(),
                tid,
                crate::linux_abi::LINUX_SIGCHLD as u32
            ),
            "blocked SIGCHLD must become pending for sigwait/sigtimedwait"
        );

        let mut ign = LinuxSigaction::empty();
        ign.sa_handler = crate::linux_abi::LINUX_SIG_IGN;
        SyscallDispatcher::install_signal_action(
            &d.exact_signal_context_for_test(),
            crate::linux_abi::LINUX_SIGCHLD,
            ign,
        );
        assert!(
            !d.child_exit_signal_needs_pump(
                &d.exact_signal_context_for_test(),
                tid,
                crate::linux_abi::LINUX_SIGCHLD as u32
            ),
            "explicit SIG_IGN suppresses the async notification even if the mask contains SIGCHLD"
        );

        let mut caught = LinuxSigaction::empty();
        caught.sa_handler = 0x4000;
        SyscallDispatcher::install_signal_action(
            &d.exact_signal_context_for_test(),
            crate::linux_abi::LINUX_SIGCHLD,
            caught,
        );
        assert!(
            d.child_exit_signal_needs_pump(
                &d.exact_signal_context_for_test(),
                tid,
                crate::linux_abi::LINUX_SIGCHLD as u32
            ),
            "caught SIGCHLD needs the pump so a spinning parent observes the handler"
        );

        assert!(
            !d.child_exit_signal_needs_pump(&d.exact_signal_context_for_test(), tid, 0),
            "clone exit_signal 0 requests no signal"
        );
    }

    #[test]
    fn process_child_exit_predicate_follows_surviving_thread_masks() {
        let d = SyscallDispatcher::new();
        let survivor = d.capture_one_task_context().unwrap().thread().registry_id();
        let retired_leader = crate::thread::ThreadId::synthetic_for_tests(survivor.raw() + 100);
        let chld = crate::linux_abi::LINUX_SIGCHLD;
        d.restore_signal_mask(
            &d.exact_signal_context_for_test(),
            survivor,
            SigSet::EMPTY.with(chld),
        );

        assert!(
            d.child_exit_signal_needs_process_pump(&d.exact_signal_context_for_test(), chld as u32)
        );
        assert!(
            !d.child_exit_signal_needs_pump(
                &d.exact_signal_context_for_test(),
                retired_leader,
                chld as u32
            ),
            "a fixed retired leader would miss the surviving sigwait mask"
        );

        let mut ignored = LinuxSigaction::empty();
        ignored.sa_handler = crate::linux_abi::LINUX_SIG_IGN;
        SyscallDispatcher::install_signal_action(&d.exact_signal_context_for_test(), chld, ignored);
        assert!(
            !d.child_exit_signal_needs_process_pump(
                &d.exact_signal_context_for_test(),
                chld as u32
            )
        );
    }

    #[test]
    fn execve_resets_caught_handlers_preserves_sig_ign_and_clears_altstack() {
        let d = SyscallDispatcher::new();
        let context = d.capture_one_task_context().unwrap();
        let tid = context.thread().registry_id();
        // A CAUGHT SIGCHLD handler (a real address) — must reset to default.
        let mut chld = LinuxSigaction::empty();
        chld.sa_handler = 0x1000133c0;
        SyscallDispatcher::install_signal_action(
            &d.exact_signal_context_for_test(),
            crate::linux_abi::LINUX_SIGCHLD,
            chld,
        );
        // SIG_IGN for SIGUSR1 (10) — must be PRESERVED across execve.
        let mut ign = LinuxSigaction::empty();
        ign.sa_handler = crate::linux_abi::LINUX_SIG_IGN;
        SyscallDispatcher::install_signal_action(&d.exact_signal_context_for_test(), 10, ign);
        context.thread().update_signal_state(|state| {
            state.set_altstack(Some(LinuxSigaltstack {
                ss_sp: 0x4000,
                ss_flags: 0,
                __pad: 0,
                ss_size: 0x2000,
            }));
            state.push_handler_frame(crate::kernel::HandlerFrameState {
                on_altstack: true,
                restore_mask: None,
            });
            state.arm_restore_mask(Some(SigSet::from_raw(0x1234)));
        });
        // Pre-execve: the caught handler is live.
        assert!(
            d.registered_signal_handler(
                &d.exact_signal_context_for_test(),
                crate::linux_abi::LINUX_SIGCHLD
            )
            .is_some()
        );

        let prepared = d.prepare_one_task_kernel_exec(&context).unwrap();
        d.reset_signal_handlers_on_execve(&context);
        let exec_context = d.commit_one_task_kernel_exec(prepared).unwrap();

        // The caught SIGCHLD handler is reset to default (no leak of the old
        // image's handler address — the bug that crashed shell-launched tests).
        assert!(
            d.registered_signal_handler(&exec_context, crate::linux_abi::LINUX_SIGCHLD)
                .is_none()
        );
        // SIG_IGN survives execve (Linux semantics).
        assert!(d.signal_is_ignored(&exec_context, 10));
        // The alternate signal stack is cleared.
        assert!(d.signal_altstack(&exec_context, tid).is_none());
        let thread_state = exec_context.thread().signal_state();
        assert_eq!(thread_state.handler_frame_depth(), 0);
        assert_eq!(thread_state.armed_restore_mask(), None);
    }

    #[test]
    fn sa_resethand_resets_disposition_to_default_on_handler_entry() {
        let d = SyscallDispatcher::new();
        let tid = d.capture_one_task_context().unwrap().thread().registry_id();

        // A one-shot (SA_RESETHAND) handler for SIGUSR1 (10).
        let mut oneshot = LinuxSigaction::empty();
        oneshot.sa_handler = 0x4000;
        oneshot.sa_flags =
            crate::linux_abi::LINUX_SA_RESETHAND | crate::linux_abi::LINUX_SA_SIGINFO;
        SyscallDispatcher::install_signal_action(&d.exact_signal_context_for_test(), 10, oneshot);
        assert!(
            d.registered_signal_handler(&d.exact_signal_context_for_test(), 10)
                .is_some()
        );

        // Entering the handler resets the disposition to SIG_DFL (Linux's
        // one-shot semantics): a second occurrence takes the default action.
        d.enter_signal_handler(&d.exact_signal_context_for_test(), tid, 10, oneshot);
        assert!(
            d.registered_signal_handler(&d.exact_signal_context_for_test(), 10)
                .is_none(),
            "SA_RESETHAND handler must reset to SIG_DFL on entry"
        );
        let reset =
            SyscallDispatcher::signal_action_entry(&d.exact_signal_context_for_test(), 10).unwrap();
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
        SyscallDispatcher::install_signal_action(&d.exact_signal_context_for_test(), 11, sticky);
        d.enter_signal_handler(&d.exact_signal_context_for_test(), tid, 11, sticky);
        assert!(
            d.registered_signal_handler(&d.exact_signal_context_for_test(), 11)
                .is_some(),
            "a non-RESETHAND handler must persist across entry"
        );
    }

    #[test]
    fn thread_directed_pending_action_survives_later_ignore_disposition() {
        let d = SyscallDispatcher::new();
        let tid = d.capture_one_task_context().unwrap().thread().registry_id();
        let signum = 34;

        let mut caught = LinuxSigaction::empty();
        caught.sa_handler = 0x4000;
        caught.sa_flags = crate::linux_abi::LINUX_SA_RESTORER;
        caught.sa_restorer = 0x5000;
        d.record_pending_signal_action(&d.exact_signal_context_for_test(), tid, signum, caught);

        let mut ignored = LinuxSigaction::empty();
        ignored.sa_handler = crate::linux_abi::LINUX_SIG_IGN;
        SyscallDispatcher::install_signal_action(
            &d.exact_signal_context_for_test(),
            signum,
            ignored,
        );
        assert!(
            d.registered_signal_handler(&d.exact_signal_context_for_test(), signum)
                .is_none()
        );
        assert!(d.signal_is_ignored(&d.exact_signal_context_for_test(), signum));

        let delivered = d
            .take_pending_signal_action(&d.exact_signal_context_for_test(), tid, signum)
            .unwrap();
        let delivered_handler = delivered.sa_handler;
        let delivered_restorer = delivered.sa_restorer;
        let caught_handler = caught.sa_handler;
        let caught_restorer = caught.sa_restorer;
        assert_eq!(delivered_handler, caught_handler);
        assert_eq!(delivered_restorer, caught_restorer);
        assert!(
            d.take_pending_signal_action(&d.exact_signal_context_for_test(), tid, signum)
                .is_none()
        );
    }

    #[test]
    fn sibling_thread_signal_snapshots_current_handler_action() {
        let d = SyscallDispatcher::new();
        let kernel = d.capture_one_task_context().unwrap();
        let caller = kernel.thread().registry_id();
        let registry = crate::thread::ThreadRegistry::new(caller);
        let target = registry.register_child(0);
        d.register_one_task_thread(&kernel, target).unwrap();
        let futex = crate::thread::FutexTable::new();
        let mut memory = crate::dispatch::LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = crate::compat::CompatReporter::default();
        let cx = crate::dispatch::SyscallCtx {
            kernel: &kernel,
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
        SyscallDispatcher::install_signal_action(&d.exact_signal_context_for_test(), 34, caught);
        let routed = d.route_thread_signal(&cx, i64::from(target.raw()), 34, true);
        assert!(
            matches!(routed, Some((crate::dispatch::DispatchOutcome::SignalThread { tid, signum }, resolved)) if tid == target && signum == 34 && resolved == target)
        );
        let mut ignored = LinuxSigaction::empty();
        ignored.sa_handler = crate::linux_abi::LINUX_SIG_IGN;
        SyscallDispatcher::install_signal_action(&d.exact_signal_context_for_test(), 34, ignored);
        let delivered = d
            .take_pending_signal_action(&d.exact_signal_context_for_test(), target, 34)
            .unwrap();
        assert_eq!(delivered, caught);
    }

    #[test]
    fn thread_signal_to_guest_main_tid_routes_to_registry_main_thread() {
        let d = SyscallDispatcher::new();
        let kernel = d.capture_one_task_context().unwrap();
        let main = kernel.thread().registry_id();
        let registry = crate::thread::ThreadRegistry::new(main);
        let caller = registry.register_child(0);
        d.register_one_task_thread(&kernel, caller).unwrap();
        let futex = crate::thread::FutexTable::new();
        let mut memory = crate::dispatch::LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = crate::compat::CompatReporter::default();
        let guest_main_tid = i64::from(std::process::id());
        let cx = crate::dispatch::SyscallCtx {
            kernel: &kernel,
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
        SyscallDispatcher::install_signal_action(&d.exact_signal_context_for_test(), 34, caught);
        let routed = d.route_thread_signal(&cx, guest_main_tid, 34, true);
        assert!(
            matches!(routed, Some((crate::dispatch::DispatchOutcome::SignalThread { tid, signum }, resolved)) if tid == main && signum == 34 && resolved == main)
        );
        assert!(
            d.take_pending_signal_action(&d.exact_signal_context_for_test(), main, 34)
                .is_some()
        );
    }

    #[test]
    fn sigqueueinfo_payload_uses_resolved_guest_main_thread_key() {
        use zerocopy::IntoBytes;
        let d = SyscallDispatcher::new();
        let kernel = d.capture_one_task_context().unwrap();
        let main = kernel.thread().registry_id();
        let registry = crate::thread::ThreadRegistry::new(main);
        let caller = registry.register_child(0);
        d.register_one_task_thread(&kernel, caller).unwrap();
        let futex = crate::thread::FutexTable::new();
        let mut memory = crate::dispatch::LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = crate::compat::CompatReporter::default();
        let guest_main_tid = i64::from(std::process::id());
        let siginfo = LinuxSiginfo::rt_queue(34, 1234, 0, 0x00ca_fe42);
        memory.write_bytes(0x400, siginfo.as_bytes()).unwrap();
        let cx = crate::dispatch::SyscallCtx {
            kernel: &kernel,
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
        let routed = d.sigqueueinfo_common(
            &cx,
            guest_main_tid,
            guest_main_tid,
            34,
            GuestPtr(0x400),
            false,
        );
        assert!(
            matches!(routed, crate::dispatch::DispatchOutcome::SignalThread { tid, signum } if tid == main && signum == 34)
        );
        let queued = d
            .take_pending_siginfo(&d.exact_signal_context_for_test(), main, 34)
            .unwrap();
        assert_eq!(queued._pad[0..8], siginfo._pad[0..8]);
    }

    #[test]
    fn clone_thread_inherits_signal_mask_without_pending_or_altstack() {
        let d = SyscallDispatcher::new();
        let parent_context = d.capture_one_task_context().unwrap();
        let parent = parent_context.thread().registry_id();
        let child = crate::thread::ThreadId::synthetic_for_tests(parent.raw() + 1);
        let blocked = SigSet::EMPTY.with(10).with(34);
        d.restore_signal_mask(&d.exact_signal_context_for_test(), parent, blocked);
        let child_tid = d.register_one_task_thread(&parent_context, child).unwrap();
        let child_context = d.capture_kernel_context(child_tid).unwrap();

        assert_eq!(
            d.signal_mask_for(&d.exact_signal_context_for_test(), child),
            blocked
        );
        assert_eq!(child_context.thread().signal_state().blocked(), blocked);
        assert_eq!(
            d.take_deliverable_pending(&d.exact_signal_context_for_test(), child),
            None
        );
        assert!(
            d.signal_altstack(&d.exact_signal_context_for_test(), child)
                .is_none()
        );
    }

    #[test]
    fn exec_rekey_preserves_survivor_mask_and_pending_but_retires_siblings() {
        let d = SyscallDispatcher::new();
        let context = d.capture_one_task_context().unwrap();
        let old = context.thread().registry_id();
        let new = old;
        let blocked = SigSet::EMPTY.with(10).with(34);
        d.restore_signal_mask(&d.exact_signal_context_for_test(), old, blocked);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), old, 10);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), old, 34);
        d.mark_signal_pending(&d.exact_signal_context_for_test(), old, 34);
        SyscallDispatcher::required_signal_thread(&d.exact_signal_context_for_test(), old)
            .update_signal_state(|state| {
                state.set_altstack(Some(LinuxSigaltstack {
                    ss_sp: 0x4000,
                    ss_flags: 0,
                    __pad: 0,
                    ss_size: 0x2000,
                }));
                state.arm_restore_mask(Some(SigSet::EMPTY.with(2)));
            });

        assert_eq!(
            d.signal_mask_for(&d.exact_signal_context_for_test(), new),
            blocked
        );
        let state = context.thread().signal_state();
        assert!(state.pending().contains(10));
        assert!(state.pending().contains(34));
        assert_eq!(state.pending_count(), 3);
        let state = context.thread().signal_state();
        assert_eq!(state.blocked(), blocked);
        assert!(state.altstack_enabled());
    }

    #[test]
    fn sigaltstack_reports_ss_onstack_and_rejects_reconfigure_while_on_stack() {
        let d = SyscallDispatcher::new();
        let tid = d.capture_one_task_context().unwrap().thread().registry_id();

        // Configure an alt stack for the thread.
        SyscallDispatcher::required_signal_thread(&d.exact_signal_context_for_test(), tid)
            .update_signal_state(|state| {
                state.set_altstack(Some(LinuxSigaltstack {
                    ss_sp: 0x4000,
                    ss_flags: 0,
                    __pad: 0,
                    ss_size: 0x4000,
                }));
            });
        // Not in a handler yet → not on the alt stack.
        assert!(!d.is_on_altstack(&d.exact_signal_context_for_test(), tid, None));

        // Enter an SA_ONSTACK handler → now executing on the alt stack.
        let mut on = LinuxSigaction::empty();
        on.sa_handler = 0x9000;
        on.sa_flags = crate::linux_abi::LINUX_SA_ONSTACK;
        d.enter_signal_handler(&d.exact_signal_context_for_test(), tid, 10, on);
        assert!(
            d.is_on_altstack(&d.exact_signal_context_for_test(), tid, None),
            "SA_ONSTACK handler marks the thread on-stack"
        );

        // rt_sigreturn pops the frame → back off the alt stack.
        d.pop_handler_frame(&d.exact_signal_context_for_test(), tid);
        assert!(!d.is_on_altstack(&d.exact_signal_context_for_test(), tid, None));

        // A handler WITHOUT SA_ONSTACK does not mark the thread on-stack.
        let mut off = LinuxSigaction::empty();
        off.sa_handler = 0x9000;
        d.enter_signal_handler(&d.exact_signal_context_for_test(), tid, 11, off);
        assert!(
            !d.is_on_altstack(&d.exact_signal_context_for_test(), tid, None),
            "a non-SA_ONSTACK handler is not on the alt stack"
        );
        d.pop_handler_frame(&d.exact_signal_context_for_test(), tid);
    }

    #[test]
    fn fork_child_rekeys_active_handler_frames_for_ss_onstack() {
        let parent = SyscallDispatcher::new();
        let parent_context = parent.capture_one_task_context().unwrap();
        let old = parent_context.thread().registry_id();
        let new = crate::thread::ThreadId::synthetic_for_tests(old.raw() + 1);
        SyscallDispatcher::required_signal_thread(&parent.exact_signal_context_for_test(), old)
            .update_signal_state(|state| {
                state.set_altstack(Some(LinuxSigaltstack {
                    ss_sp: 0x4000,
                    ss_flags: 0,
                    __pad: 0,
                    ss_size: 0x4000,
                }));
            });
        let mut on = LinuxSigaction::empty();
        on.sa_handler = 0x9000;
        on.sa_flags = crate::linux_abi::LINUX_SA_ONSTACK;
        parent.enter_signal_handler(&parent.exact_signal_context_for_test(), old, 10, on);

        let plan =
            crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty()).unwrap();
        let child_context = parent_context
            .kernel()
            .reserve_fork(&parent_context, plan, "signal-fork-test".to_owned(), None)
            .unwrap()
            .prepare_reference(new)
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0;
        let child = parent.fork_clone_in_process(old, new, old.raw() as u32, new.raw() as u32);

        assert!(parent.is_on_altstack(&parent.exact_signal_context_for_test(), old, None));
        assert!(child.is_on_altstack(&child_context, new, None));
        child.pop_handler_frame(&child_context, new);
        assert!(!child.is_on_altstack(&child_context, new, None));
    }

    #[test]
    fn siglongjmp_stale_altstack_frame_is_reconciled_from_guest_sp() {
        let d = SyscallDispatcher::new();
        let tid = d.capture_one_task_context().unwrap().thread().registry_id();

        SyscallDispatcher::required_signal_thread(&d.exact_signal_context_for_test(), tid)
            .update_signal_state(|state| {
                state.set_altstack(Some(LinuxSigaltstack {
                    ss_sp: 0x4000,
                    ss_flags: 0,
                    __pad: 0,
                    ss_size: 0x4000,
                }));
                state.push_handler_frame(crate::kernel::HandlerFrameState {
                    on_altstack: true,
                    restore_mask: None,
                });
            });

        assert!(
            d.is_on_altstack(&d.exact_signal_context_for_test(), tid, Some(0x7000)),
            "live SP inside altstack keeps SS_ONSTACK state"
        );
        assert!(
            !d.is_on_altstack(&d.exact_signal_context_for_test(), tid, Some(0x9000)),
            "SP outside altstack means siglongjmp escaped the handler frame"
        );
        assert_eq!(
            SyscallDispatcher::required_signal_thread(&d.exact_signal_context_for_test(), tid)
                .signal_state()
                .handler_frame_depth(),
            0,
            "stale handler-frame bookkeeping should be cleared"
        );
    }

    #[test]
    fn rt_sigsuspend_keeps_temp_mask_only_when_a_caught_handler_will_run() {
        let d = SyscallDispatcher::new();
        let tid = d.capture_one_task_context().unwrap().thread().registry_id();
        let unblock_all = SigSet::EMPTY;

        // Spurious / timeout wake: nothing pending → DON'T keep the temp mask
        // (rt_sigsuspend must restore the saved mask, not strand the thread).
        assert!(!d.sigsuspend_caught_handler_deliverable(
            &d.exact_signal_context_for_test(),
            tid,
            unblock_all
        ));

        // A deliverable signal with NO caught handler (default disposition):
        // no handler runs, so still restore.
        d.mark_signal_pending(&d.exact_signal_context_for_test(), tid, 10);
        assert!(!d.sigsuspend_caught_handler_deliverable(
            &d.exact_signal_context_for_test(),
            tid,
            unblock_all
        ));

        // Install a caught handler for SIGUSR1 (10): now a handler WILL run, so
        // the temp mask is kept and the post-handler restore is armed.
        let mut h = LinuxSigaction::empty();
        h.sa_handler = 0x4000;
        SyscallDispatcher::install_signal_action(&d.exact_signal_context_for_test(), 10, h);
        assert!(d.sigsuspend_caught_handler_deliverable(
            &d.exact_signal_context_for_test(),
            tid,
            unblock_all
        ));

        // The same signal BLOCKED by suspend_mask is not deliverable → restore.
        let block_10 = SigSet::EMPTY.with(10);
        assert!(!d.sigsuspend_caught_handler_deliverable(
            &d.exact_signal_context_for_test(),
            tid,
            block_10
        ));
    }

    #[test]
    fn rt_sigsuspend_releases_dispatch_before_waiting() {
        const MASK_PTR: u64 = 0x1000;
        let d = SyscallDispatcher::new();
        let context = d.capture_one_task_context().unwrap();
        let tid = context.thread().registry_id();
        let registry = crate::thread::ThreadRegistry::new(tid);
        let futex = crate::thread::FutexTable::new();
        let reporter = crate::compat::CompatReporter::default();
        let mut memory = crate::dispatch::LinearMemory::new(MASK_PTR, vec![0; 64]);
        memory
            .write_bytes(MASK_PTR, &SigSet::EMPTY.raw().to_le_bytes())
            .expect("write suspend mask");
        let original = SigSet::EMPTY.with(crate::linux_abi::LINUX_SIGUSR1);
        d.restore_signal_mask(&d.exact_signal_context_for_test(), tid, original);

        let started = Instant::now();
        let outcome = d
            .dispatch_threaded(
                &context,
                SyscallRequest::new(
                    133,
                    SyscallArgs::from([MASK_PTR, LINUX_RT_SIGSET_SIZE, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
                tid,
                &registry,
                &futex,
            )
            .expect("dispatch rt_sigsuspend");

        assert!(
            started.elapsed() < Duration::from_millis(100),
            "rt_sigsuspend must park outside dispatch"
        );
        assert!(matches!(
            outcome,
            DispatchOutcome::WaitOnSignals {
                wait_set,
                block_mask,
                timeout: None,
            } if wait_set == SigSet::EMPTY.complement()
                && block_mask == SigBlockMask::blocking_all_of(SigSet::EMPTY)
        ));
        assert_eq!(
            d.signal_mask_for(&d.exact_signal_context_for_test(), tid),
            SigSet::EMPTY
        );
        assert_eq!(
            context.thread().signal_state().armed_restore_mask(),
            Some(original)
        );
    }
}
