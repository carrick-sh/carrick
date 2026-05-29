//! signal syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;
use crate::linux_abi::LinuxSiginfo;
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
    pub masks: HashMap<crate::thread::ThreadId, u64>,
    /// Signals raised while blocked, awaiting unblock or a synchronous wait
    /// (`rt_sigtimedwait`), PER GUEST THREAD (bit `signum-1`). For a standard
    /// signal the bit is presence only (multiple sends coalesce, matching
    /// Linux). For a real-time signal (SIGRTMIN..=SIGRTMAX) the COUNT of queued
    /// instances lives in `rt_pending_counts`; the bit here just mirrors
    /// "count > 0".
    pub pendings: HashMap<crate::thread::ThreadId, u64>,
    /// Queue depth for pending REAL-TIME signals, keyed by `(tid, signum)`.
    /// RT signals must deliver once per send (POSIX queuing), unlike standard
    /// signals which coalesce — so N `rt_sigqueueinfo`/`kill` of an RT signal
    /// while blocked must yield N deliveries on unblock. `take_pending_in`
    /// decrements this and only clears the pending bit when it hits 0.
    pub rt_pending_counts: HashMap<(crate::thread::ThreadId, i32), u32>,
    /// Installed alternate signal stack (`sigaltstack`), PER GUEST THREAD.
    /// `sigaltstack` is per-thread in Linux (each thread/M registers its own
    /// signal stack), so this MUST be keyed by tid: a process-global slot made
    /// every thread's SIGURG (Go async-preempt) frame land on the last-set
    /// stack → concurrent frames overlapped → goroutine-stack corruption →
    /// the c>=20 EL0 faults (found via `carrick trace` on the `signal-inject`
    /// probe: identical `new_sp` across threads). Signal HANDLERS stay global
    /// (Linux shares them across threads); only the alt stack is per-thread.
    pub altstack: HashMap<crate::thread::ThreadId, LinuxSigaltstack>,
    /// Linux's `set_restore_sigmask()` shadow: when a syscall (sigsuspend,
    /// pselect, ppoll with a sigmask) temporarily replaced the thread's
    /// signal mask, this records the mask to restore AFTER the next signal
    /// handler runs — NOT immediately on syscall return. The handler runs
    /// under the temporary mask (so a now-deliverable pending signal can
    /// actually be delivered), and `rt_sigreturn` then pops THIS mask off
    /// the sigframe. `enter_signal_handler` consumes the entry the first
    /// time a handler runs after it's armed.
    pub restore_masks: HashMap<crate::thread::ThreadId, u64>,
    /// Caller-supplied `siginfo_t` queued for delivery, keyed by `(tid,
    /// signum)`. `rt_sigqueueinfo` pushes the user's siginfo here so the
    /// SA_SIGINFO handler sees the original `si_value` payload instead of
    /// a synthesised SI_USER. RT signals (32..=64) queue multiple entries
    /// (POSIX queuing); standard signals overwrite the head. Each delivery
    /// pops the front entry.
    pub pending_siginfos: HashMap<(crate::thread::ThreadId, i32), VecDeque<LinuxSiginfo>>,
}

impl SignalState {
    pub(super) fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            masks: HashMap::new(),
            pendings: HashMap::new(),
            rt_pending_counts: HashMap::new(),
            altstack: HashMap::new(),
            restore_masks: HashMap::new(),
            pending_siginfos: HashMap::new(),
        }
    }

    fn mask_for(&self, tid: crate::thread::ThreadId) -> u64 {
        self.masks.get(&tid).copied().unwrap_or(0)
    }
}

/// Real-time signals (`SIGRTMIN`..=`SIGRTMAX`, kernel numbers 32..=64) queue
/// per POSIX; standard signals (1..=31) coalesce.
fn is_rt_signal(signum: i32) -> bool {
    (32..=64).contains(&signum)
}

fn sanitize_signal_mask(mut mask: u64) -> u64 {
    #[allow(clippy::unwrap_used)]
    let unmaskable = sigmask_bit(LINUX_SIGKILL).unwrap() | sigmask_bit(LINUX_SIGSTOP).unwrap();
    mask &= !unmaskable;
    mask
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

    /// Bitmask (bit `signum-1`) of signals that must NOT interrupt a blocking,
    /// restartable syscall (wait4/waitid) for `tid`. On Linux a syscall is
    /// interrupted only by a signal that is both unblocked AND has an effect:
    /// a signal that is blocked, explicitly `SIG_IGN`, or `SIG_DFL` with a
    /// default action of "ignore" (SIGCHLD/SIGURG/SIGWINCH) is delivered-and-
    /// dropped without interrupting. carrick previously interrupted the wait
    /// for ANY pending signal, so a sibling child's default-ignored SIGCHLD
    /// spuriously EINTR'd a `waitpid(other_child)` (LTP futex_cmp_requeue01's
    /// `SAFE_WAITPID` then TBROKed). Folding the ignored set into the wait's
    /// block mask makes those pending-but-inert signals leave the wait running.
    pub fn non_interrupting_signal_mask(&self, tid: crate::thread::ThreadId) -> u64 {
        let signal = self.signal.lock();
        // Start from the thread's blocked set.
        let mut mask = signal.mask_for(tid);
        for signum in 1..=64i32 {
            let Some(bit) = sigmask_bit(signum) else {
                continue;
            };
            let disposition = signal.handlers.get(&signum).map(|a| a.sa_handler);
            let ignored = match disposition {
                Some(h) if h == crate::linux_abi::LINUX_SIG_IGN => true,
                // No recorded handler, or SIG_DFL: inert only when the DEFAULT
                // action is ignore (SIGCHLD/SIGURG/SIGWINCH). Every other
                // SIG_DFL signal (terminate/core/stop) still interrupts.
                None => is_default_ignore_signum(signum),
                Some(h) if h == crate::linux_abi::LINUX_SIG_DFL => {
                    is_default_ignore_signum(signum)
                }
                // A real handler is installed → the signal interrupts (then
                // SA_RESTART decides whether the syscall restarts).
                Some(_) => false,
            };
            if ignored {
                mask |= bit;
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
        match sigmask_bit(signum) {
            Some(bit) => self.signal.lock().mask_for(tid) & bit != 0,
            None => false,
        }
    }

    pub fn signal_mask_for(&self, tid: crate::thread::ThreadId) -> u64 {
        self.signal.lock().mask_for(tid)
    }

    /// Record a (blocked) signal as pending for `tid`. It stays queued until the
    /// thread unblocks it or dequeues it via `rt_sigtimedwait`. Real-time
    /// signals queue (each send adds a deliverable instance); standard signals
    /// coalesce (the bit is set-once), matching Linux.
    pub fn mark_signal_pending(&self, tid: crate::thread::ThreadId, signum: i32) {
        if let Some(bit) = sigmask_bit(signum) {
            let mut s = self.signal.lock();
            *s.pendings.entry(tid).or_insert(0) |= bit;
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
        s.altstack.remove(&tid);
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
        // Keep only SIG_IGN dispositions; a caught handler → default (absent).
        s.handlers
            .retain(|_, a| a.sa_handler == crate::linux_abi::LINUX_SIG_IGN);
        // execve disestablishes any alternate signal stack for the process.
        s.altstack.clear();
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
    ) -> u64 {
        let mut signal = self.signal.lock();
        let saved = signal
            .restore_masks
            .remove(&tid)
            .unwrap_or_else(|| signal.mask_for(tid));
        let delivered = sigmask_bit(signum).unwrap_or(0);
        let current = signal.mask_for(tid);
        let handler_mask = sanitize_signal_mask(current | delivered | action.sa_mask[0]);
        signal.masks.insert(tid, handler_mask);
        saved
    }

    /// Arm a "restore this mask after the next handler runs" override (Linux's
    /// `set_restore_sigmask`). The next `enter_signal_handler` for `tid`
    /// returns `mask` as the sigframe's saved mask and clears the arm.
    pub fn arm_restore_mask(&self, tid: crate::thread::ThreadId, mask: u64) {
        let mut signal = self.signal.lock();
        signal
            .restore_masks
            .insert(tid, sanitize_signal_mask(mask));
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
        let entry = signal
            .pending_siginfos
            .entry((tid, signum))
            .or_default();
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

    pub fn restore_signal_mask(&self, tid: crate::thread::ThreadId, mask: u64) {
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
        self.take_pending_in(tid, !mask)
    }

    /// Lowest-numbered pending signal for `tid` that intersects `set`, cleared
    /// from that thread's pending set. Used by `rt_sigtimedwait`.
    fn take_pending_in(&self, tid: crate::thread::ThreadId, set: u64) -> Option<i32> {
        let mut signal = self.signal.lock();
        let cur = signal.pendings.get(&tid).copied().unwrap_or(0);
        let candidates = cur & set;
        if candidates == 0 {
            return None;
        }
        let signum = candidates.trailing_zeros() as i32 + 1;
        // RT signals queue: take one instance, and only clear the pending bit
        // once the last queued instance is drained (so N sends → N deliveries).
        if is_rt_signal(signum) {
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
        }
        signal.pendings.insert(tid, cur & !(1u64 << (signum - 1)));
        Some(signum)
    }

    /// Raise `signum` against the guest itself (kill/tkill/tgkill self
    /// target). If the signal is blocked it is held pending; otherwise it
    /// is handed to the runtime's delivery slot. signum 0 is the null
    /// probe and a no-op success.
    fn raise_self(&self, tid: crate::thread::ThreadId, signum: u64) -> DispatchOutcome {
        if signum == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        let s = signum as i32;
        if self.signal_blocked(tid, s) {
            self.mark_signal_pending(tid, s);
        } else {
            crate::host_signal::raise_for_self(s);
        }
        DispatchOutcome::Returned { value: 0 }
    }

    /// The calling guest thread's tid (or `0` if no thread context).
    pub(crate) fn ctx_tid<M: GuestMemory>(ctx: &SyscallCtx<M>) -> crate::thread::ThreadId {
        ctx.thread.as_ref().map(|t| t.tid).unwrap_or(0)
    }

    define_syscall! {
        /// kill(pid, sig): send `sig` to process `pid`.
        fn kill(this, cx, pid: Pid, sig: Signal) {
            let pid = i64::from(pid.0);
            let signum = sig.0 as u64;
            if !is_valid_signum(signum) {
                return Ok(LINUX_EINVAL.into());
            }
            if signal_is_self_target(pid, /*tid_required=*/ false) {
                return Ok(this.raise_self(Self::ctx_tid(cx), signum));
            }
            let caller_euid = Some(this.cred_snapshot().euid);
            Ok(bootstrap_signal_send_as(
                pid, /*tid_required=*/ false, signum, caller_euid,
            ))
        }

        /// signalfd4(fd, mask, sizemask, flags): create (fd==-1) or re-target a
        /// signalfd. macOS has no signalfd, so this is emulated. SFD_CLOEXEC ==
        /// O_CLOEXEC and SFD_NONBLOCK == O_NONBLOCK; the dispatch flag table
        /// already rejects other bits (defensive re-check here). Only the fd-flag
        /// surface (FD_CLOEXEC / O_NONBLOCK on the returned fd) is exercised today
        /// (signalfd4_01/02); a read()/poll() delivery path that drains the
        /// process's pending masked signals is a tracked follow-up.
        fn signalfd4(this, cx, fd: Fd, mask: GuestPtr, _sizemask: u64, flags: u64) {
            if flags & !(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC) != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            // The kernel sigset_t ABI is 8 bytes; read it (EFAULT on bad ptr).
            let mask_val = match cx.memory.read_bytes(mask.0, 8) {
                Ok(b) => {
                    let arr: [u8; 8] = b.as_slice().try_into().unwrap_or([0u8; 8]);
                    u64::from_le_bytes(arr)
                }
                Err(_) => return Ok(LINUX_EFAULT.into()),
            };
            if fd.0 == -1 {
                let description = OpenDescription::SignalFd {
                    base: OpenDescriptionBase::new(flags & LINUX_O_NONBLOCK),
                    mask: mask_val,
                };
                Ok(this.install_fd(description, linux_fd_flags_from_open_flags(flags)))
            } else {
                let Some(open_file) = this.open_file(fd.0) else {
                    return Ok(LINUX_EBADF.into());
                };
                let mut open = open_file.description.write();
                match &mut *open {
                    OpenDescription::SignalFd { mask, .. } => {
                        *mask = mask_val;
                        Ok(DispatchOutcome::Returned { value: fd.0 as i64 })
                    }
                    _ => Ok(LINUX_EINVAL.into()),
                }
            }
        }

        /// tkill(tid, sig): send `sig` to thread `tid`.
        fn tkill(this, cx, tid: Pid, sig: Signal) {
            let tid = i64::from(tid.0);
            let signum = sig.0 as u64;
            if tid <= 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if !is_valid_signum(signum) {
                return Ok(LINUX_EINVAL.into());
            }
            if let Some(routed) = this.route_thread_signal(cx, tid, signum) {
                return Ok(routed);
            }
            if signal_is_self_target(tid, /*tid_required=*/ true) {
                let self_tid = cx.thread.as_ref().map(|t| t.tid).unwrap_or(0);
                return Ok(this.raise_self(self_tid, signum));
            }
            Ok(bootstrap_signal_send(tid, /*tid_required=*/ true, signum))
        }

        /// tgkill(tgid, tid, sig): send `sig` to thread `tid` in group `tgid`.
        fn tgkill(this, cx, tgid: Pid, tid: Pid, sig: Signal) {
            let tgid = i64::from(tgid.0);
            let tid = i64::from(tid.0);
            let signum = sig.0 as u64;
            if tgid <= 0 || tid <= 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if !is_valid_signum(signum) {
                return Ok(LINUX_EINVAL.into());
            }
            if let Some(routed) = this.route_thread_signal(cx, tid, signum) {
                return Ok(routed);
            }
            let host_pid = std::process::id() as i64;
            let bootstrap_pid = LINUX_BOOTSTRAP_PID as i64;
            let valid_self = (tgid == host_pid || tgid == bootstrap_pid)
                && (tid == host_pid || tid == bootstrap_pid);
            if !valid_self {
                return Ok(LINUX_ESRCH.into());
            }
            let self_tid = cx.thread.as_ref().map(|t| t.tid).unwrap_or(0);
            Ok(this.raise_self(self_tid, signum))
        }

        /// sigaltstack(ss, old_ss): set/query alternate signal stack.
        fn sigaltstack(this, cx, ss: GuestPtr, old_ss: GuestPtr) {
            let ss = ss.0;
            let old_ss = old_ss.0;
            let tid = cx.thread.as_ref().map(|t| t.tid).unwrap_or(0);
            let memory = &mut *cx.memory;

            if old_ss != 0 {
                let current = this
                    .signal
                    .lock()
                    .altstack
                    .get(&tid)
                    .copied()
                    .unwrap_or_else(LinuxSigaltstack::disabled);
                if memory.write_bytes(old_ss, current.abi_bytes()).is_err() {
                    return Ok(LINUX_EFAULT.into());
                }
            }

            if ss != 0 {
                let bytes = match memory.read_bytes(ss, core::mem::size_of::<LinuxSigaltstack>()) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Ok(LINUX_EFAULT.into());
                    }
                };
                let new_stack = match LinuxSigaltstack::read_from_bytes(&bytes) {
                    Ok(stack) => stack,
                    Err(_) => {
                        return Ok(LINUX_EFAULT.into());
                    }
                };
                let flags = new_stack.ss_flags as u32 as u64;
                if flags & !LINUX_SS_DISABLE != 0 {
                    return Ok(LINUX_EINVAL.into());
                }
                if flags & LINUX_SS_DISABLE != 0 {
                    this.signal.lock().altstack.remove(&tid);
                } else {
                    let size = new_stack.ss_size;
                    if size < LINUX_MINSIGSTKSZ {
                        return Ok(LINUX_ENOMEM.into());
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
                return Ok(LINUX_EINVAL.into());
            }
            let mask_bytes = match memory.read_bytes(mask_ptr, LINUX_RT_SIGSET_SIZE as usize) {
                Ok(bytes) => bytes,
                Err(_) => return Ok(LINUX_EFAULT.into()),
            };
            let suspend_mask = sanitize_signal_mask(u64::from_le_bytes(
                mask_bytes.try_into().unwrap_or([0; 8]),
            ));
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
                let pending = this.signal.lock().pendings.get(&tid).copied().unwrap_or(0);
                if pending & !suspend_mask != 0 {
                    break; // a queued signal is now deliverable
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
            // Leave the mask as `suspend_mask` so the runtime can deliver the
            // newly-deliverable signal; arm_restore_mask makes that handler's
            // rt_sigreturn restore `original` instead of `suspend_mask`.
            this.arm_restore_mask(tid, original);
            Ok(LINUX_EINTR.into())
        }

        /// rt_sigaction(signum, new_action, old_action, sigset_size): configure handler.
        fn rt_sigaction(this, cx, signum: Signal, new_action: GuestPtr, old_action: GuestPtr, sigset_size: u64) {
            let signum = signum.0;
            let new_action = new_action.0;
            let old_action = old_action.0;
            let memory = &mut *cx.memory;
            if sigset_size != LINUX_RT_SIGSET_SIZE {
                return Ok(LINUX_EINVAL.into());
            }
            if !(1..=64).contains(&signum) {
                return Ok(LINUX_EINVAL.into());
            }
            let new_sa = if new_action != 0 {
                let bytes =
                    match memory.read_bytes(new_action, core::mem::size_of::<LinuxSigaction>()) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            return Ok(LINUX_EFAULT.into());
                        }
                    };
                if signum == LINUX_SIGKILL || signum == LINUX_SIGSTOP {
                    return Ok(LINUX_EINVAL.into());
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
                        return Ok(LINUX_EFAULT.into());
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
                    return Ok(LINUX_EFAULT.into());
                }
            }
            if let Some(sa) = new_sa {
                this.signal.lock().handlers.insert(signum, sa);
                let h = sa.sa_handler;
                if h != crate::linux_abi::LINUX_SIG_DFL && h != crate::linux_abi::LINUX_SIG_IGN {
                    crate::host_signal::ensure_host_handler(signum);
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
                return Ok(LINUX_EINVAL.into());
            }
            let previous_mask = this.signal.lock().mask_for(tid);
            if old_set != 0
                && memory
                    .write_bytes(old_set, &previous_mask.to_le_bytes())
                    .is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }
            if new_set != 0 {
                let bytes = match memory.read_bytes(new_set, LINUX_RT_SIGSET_SIZE as usize) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Ok(LINUX_EFAULT.into());
                    }
                };
                let set = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
                let mut mask = match how {
                    LINUX_SIG_BLOCK => previous_mask | set,
                    LINUX_SIG_UNBLOCK => previous_mask & !set,
                    LINUX_SIG_SETMASK => set,
                    _ => {
                        return Ok(LINUX_EINVAL.into());
                    }
                };
                mask = sanitize_signal_mask(mask);
                this.signal.lock().masks.insert(tid, mask);
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// rt_sigpending(set_ptr, sigset_size): query pending mask.
        fn rt_sigpending(this, cx, set_ptr: GuestPtr, sigset_size: u64) {
            let set_ptr = set_ptr.0;
            let tid = Self::ctx_tid(cx);
            let memory = &mut *cx.memory;
            if sigset_size != LINUX_RT_SIGSET_SIZE {
                return Ok(LINUX_EINVAL.into());
            }
            let pending = this.signal.lock().pendings.get(&tid).copied().unwrap_or(0);
            if set_ptr != 0 && memory.write_bytes(set_ptr, &pending.to_le_bytes()).is_err() {
                return Ok(LINUX_EFAULT.into());
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
                return Ok(LINUX_EINVAL.into());
            }
            let set_bytes = match memory.read_bytes(set_ptr, LINUX_RT_SIGSET_SIZE as usize) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(LINUX_EFAULT.into());
                }
            };
            let wait_set = u64::from_le_bytes(set_bytes.try_into().unwrap_or([0; 8]));
            let mut timeout: Option<Duration> = None;
            if timeout_ptr != 0 {
                let ts = match read_timespec(memory, timeout_ptr) {
                    Ok(ts) => ts,
                    Err(errno) => return Ok(errno.into()),
                };
                let tv_sec = ts.tv_sec;
                let tv_nsec = ts.tv_nsec;
                if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
                    return Ok(LINUX_EINVAL.into());
                }
                timeout = Some(Duration::new(tv_sec as u64, tv_nsec as u32));
            }

            let memory = &mut *cx.memory;
            if let Some(signum) = this.take_pending_in(tid, wait_set) {
                return Ok(rt_sigtimedwait_deliver(memory, info_ptr, signum));
            }
            let signum = crate::host_signal::take_pending_in_for(tid, wait_set);
            if signum != crate::host_signal::NO_PENDING_SIGNAL {
                return Ok(rt_sigtimedwait_deliver(memory, info_ptr, signum));
            }
            install_host_handlers_for_wait_set(wait_set);
            match timeout {
                Some(d) if d.is_zero() => Ok(LINUX_EAGAIN.into()),
                _ => Ok(DispatchOutcome::WaitOnSignals { wait_set, timeout }),
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
            let tgid = i64::from(tgid.0);
            let signum = sig.0 as u64;
            if !is_valid_signum(signum) {
                return Ok(LINUX_EINVAL.into());
            }
            let host_pid = std::process::id() as i64;
            let bootstrap_pid = LINUX_BOOTSTRAP_PID as i64;
            let is_self = tgid == host_pid || tgid == bootstrap_pid;
            let s = signum as i32;

            // Read the caller's siginfo once up front — same source of truth
            // regardless of whether we deliver to self, a sibling, or a peer.
            // The kernel re-stamps si_signo per the rt_sigqueueinfo(2) ABI.
            let mut user_info: Option<LinuxSiginfo> = None;
            if info_ptr.0 != 0 {
                let memory = &*cx.memory;
                if let Ok(bytes) =
                    memory.read_bytes(info_ptr.0, core::mem::size_of::<LinuxSiginfo>())
                {
                    if let Some(mut info) = LinuxSiginfo::read_from_bytes(&bytes).ok() {
                        info.si_signo = s;
                        user_info = Some(info);
                    }
                }
            }

            // If `tgid` names a sibling thread, deliver to that thread directly
            // (parallels what tkill/tgkill do). LTP `rt_sigqueueinfo01` relies
            // on this: it spawns a thread, calls
            // `rt_sigqueueinfo(sibling_tid, SIGUSR1, &info)`, and expects the
            // sibling's SA_SIGINFO handler to observe the queued payload. Linux
            // permits a non-leader tid here because `find_vpid` plus
            // `thread_group` still resolves to the same process; we mirror that
            // by routing to the sibling tid so its SA_SIGINFO frame carries
            // the original `si_value`.
            if let Some(routed) = this.route_thread_signal(cx, tgid, signum) {
                let target_tid = tgid as crate::thread::ThreadId;
                if let Some(info) = user_info {
                    this.record_pending_siginfo(target_tid, s, info);
                }
                return Ok(routed);
            }

            if !is_self {
                // Cross-process (target is some other host pid, not a sibling
                // thread of ours). Defer to bootstrap_signal_send for the
                // kill(2)-style host route. User siginfo payload doesn't
                // cross the process boundary today — receiver synthesises
                // SI_USER, same shape as a host kill — tracked separately.
                return Ok(bootstrap_signal_send(
                    tgid, /*tid_required=*/ false, signum,
                ));
            }

            // Single-threaded self-target (or multi-threaded but no thread
            // registry hit): queue against the caller's tid so the delivery
            // pairs with the same SA_SIGINFO frame.
            let tid = Self::ctx_tid(cx);
            if let Some(info) = user_info {
                this.record_pending_siginfo(tid, s, info);
            }
            this.mark_signal_pending(tid, s);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// rt_sigreturn(): pop signal frame and restore registers.
        fn rt_sigreturn(this, cx) {
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
    ) -> Option<DispatchOutcome> {
        let t = ctx.thread.as_ref()?;
        let target = tid as crate::thread::ThreadId;
        if i64::from(t.tid) == tid {
            return Some(self.raise_self(t.tid, signum));
        }
        if t.registry.is_live(target) {
            let signum_i32 = signum as i32;
            if self.signal_blocked(target, signum_i32) {
                self.mark_signal_pending(target, signum_i32);
                return Some(DispatchOutcome::Returned { value: 0 });
            }
            return Some(DispatchOutcome::SignalThread {
                tid: target,
                signum: signum_i32,
            });
        }
        None
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

fn install_host_handlers_for_wait_set(wait_set: u64) {
    for signum in 1..=64 {
        let Some(bit) = sigmask_bit(signum) else {
            continue;
        };
        if wait_set & bit != 0 {
            crate::host_signal::ensure_host_handler(signum);
        }
    }
}

/// Complete a successful `rt_sigtimedwait`: write a minimal `siginfo_t`
/// (just `si_signo`) to `info_ptr` if non-NULL and return the signal
/// number, matching the kernel's success contract.
fn rt_sigtimedwait_deliver(
    memory: &mut impl GuestMemory,
    info_ptr: u64,
    signum: i32,
) -> DispatchOutcome {
    if info_ptr != 0 {
        let _ = memory.write_bytes(info_ptr, &signum.to_le_bytes());
    }
    DispatchOutcome::Returned {
        value: signum as i64,
    }
}

/// True iff a kill/tkill/tgkill `target` refers to the guest itself.
/// getpid() exposes the host pid, so glibc uses that as the self-id;
/// accept it, LINUX_BOOTSTRAP_PID (1), and — for the pid form — 0
/// (process-group, which is just us in the single-process bootstrap).
fn signal_is_self_target(target: i64, tid_required: bool) -> bool {
    let host_pid = std::process::id() as i64;
    let bootstrap_pid = LINUX_BOOTSTRAP_PID as i64;
    if tid_required {
        target == host_pid || target == bootstrap_pid
    } else {
        target == host_pid || target == bootstrap_pid || target == 0
    }
}

pub(crate) fn bootstrap_signal_send(
    target: i64,
    tid_required: bool,
    signum: u64,
) -> DispatchOutcome {
    bootstrap_signal_send_as(target, tid_required, signum, /*caller_euid=*/ None)
}

/// Same as [`bootstrap_signal_send`] but the caller passes its own current
/// euid so we can enforce Linux's kill(2) permission check across guest
/// processes. `None` means "skip the check" (used by the self-target /
/// process-group cases that don't cross processes).
pub(crate) fn bootstrap_signal_send_as(
    target: i64,
    tid_required: bool,
    signum: u64,
    caller_euid: Option<u32>,
) -> DispatchOutcome {
    if !is_valid_signum(signum) {
        return DispatchOutcome::errno(LINUX_EINVAL);
    }
    // getpid() exposes the host pid (std::process::id()) so glibc and
    // friends use that as the self-id when calling kill/tkill/tgkill.
    // Accept either that or LINUX_BOOTSTRAP_PID so existing callers
    // that hard-coded `1` keep working.
    let host_pid = std::process::id() as i64;
    let bootstrap_pid = LINUX_BOOTSTRAP_PID as i64;
    let self_target = if tid_required {
        target == host_pid || target == bootstrap_pid
    } else {
        // kill(0, sig) targets the calling process's process group; in our
        // single-process bootstrap that's still just us.
        target == host_pid || target == bootstrap_pid || target == 0
    };
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
    // Cross-process: enforce kill(2)'s Linux permission model when both
    // the caller and the target have published a guest euid. Root (euid==0)
    // can signal anyone (matches Linux's CAP_KILL effective semantics for
    // the simple uid-only model); a non-root caller must share the
    // target's euid. LTP `kill05` walks this path: parent sets euid=Y,
    // child sets euid=X (different); parent's `kill(child, SIGKILL)` must
    // return EPERM. If we can't read either cred (peer is non-carrick or
    // hasn't published yet) we fall through to allow — matching today's
    // behaviour for processes outside the published set.
    if let (Some(caller), Some(target_euid)) = (
        caller_euid,
        crate::cred_ipc::read_target(target as i32),
    ) && caller != 0 && caller != target_euid {
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
    if target == 0 || target < i32::MIN as i64 || target > i32::MAX as i64 {
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
    fn rt_signals_queue_while_standard_signals_coalesce() {
        let d = SyscallDispatcher::new();
        let tid: crate::thread::ThreadId = 1;

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
    fn execve_resets_caught_handlers_preserves_sig_ign_and_clears_altstack() {
        let d = SyscallDispatcher::new();
        let tid: crate::thread::ThreadId = 1;
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
    }
}
