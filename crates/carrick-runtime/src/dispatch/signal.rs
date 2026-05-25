//! signal syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

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
    /// (`rt_sigtimedwait`), PER GUEST THREAD (bit `signum-1`).
    pub pendings: HashMap<crate::thread::ThreadId, u64>,
    /// Installed alternate signal stack (`sigaltstack`), PER GUEST THREAD.
    /// `sigaltstack` is per-thread in Linux (each thread/M registers its own
    /// signal stack), so this MUST be keyed by tid: a process-global slot made
    /// every thread's SIGURG (Go async-preempt) frame land on the last-set
    /// stack → concurrent frames overlapped → goroutine-stack corruption →
    /// the c>=20 EL0 faults (found via `carrick trace` on the `signal-inject`
    /// probe: identical `new_sp` across threads). Signal HANDLERS stay global
    /// (Linux shares them across threads); only the alt stack is per-thread.
    pub altstack: HashMap<crate::thread::ThreadId, LinuxSigaltstack>,
}

impl SignalState {
    pub(super) fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            masks: HashMap::new(),
            pendings: HashMap::new(),
            altstack: HashMap::new(),
        }
    }

    fn mask_for(&self, tid: crate::thread::ThreadId) -> u64 {
        self.masks.get(&tid).copied().unwrap_or(0)
    }
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
    /// thread unblocks it or dequeues it via `rt_sigtimedwait`.
    pub fn mark_signal_pending(&self, tid: crate::thread::ThreadId, signum: i32) {
        if let Some(bit) = sigmask_bit(signum) {
            *self.signal.lock().pendings.entry(tid).or_insert(0) |= bit;
        }
    }

    /// Drop a thread's per-thread signal state (mask/pending/alt stack) when it
    /// exits, so the maps don't grow unbounded over a long run and a recycled
    /// tid starts clean. Signal handlers are process-global and untouched.
    pub fn forget_thread_signal_state(&self, tid: crate::thread::ThreadId) {
        let mut s = self.signal.lock();
        s.masks.remove(&tid);
        s.pendings.remove(&tid);
        s.altstack.remove(&tid);
    }

    /// Apply Linux handler-time masking for `signum`, returning the previous
    /// per-thread mask so `rt_sigreturn` can restore it from the sigframe.
    pub fn enter_signal_handler(
        &self,
        tid: crate::thread::ThreadId,
        signum: i32,
        action: LinuxSigaction,
    ) -> u64 {
        let mut signal = self.signal.lock();
        let previous = signal.mask_for(tid);
        let delivered = sigmask_bit(signum).unwrap_or(0);
        let handler_mask = sanitize_signal_mask(previous | delivered | action.sa_mask[0]);
        signal.masks.insert(tid, handler_mask);
        previous
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
    fn ctx_tid<M: GuestMemory>(ctx: &SyscallCtx<M>) -> crate::thread::ThreadId {
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
            Ok(bootstrap_signal_send(
                pid, /*tid_required=*/ false, signum,
            ))
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
            let memory = &*cx.memory;
            if sigset_size != LINUX_RT_SIGSET_SIZE {
                return Ok(LINUX_EINVAL.into());
            }
            if memory
                .read_bytes(mask_ptr, LINUX_RT_SIGSET_SIZE as usize)
                .is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }
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
            match timeout {
                Some(d) if !d.is_zero() => {
                    let deadline = Instant::now() + d.min(Duration::from_secs(5));
                    while Instant::now() < deadline {
                        let pending = crate::host_signal::take_pending();
                        if pending != 0 {
                            let in_set = sigmask_bit(pending).is_some_and(|b| wait_set & b != 0);
                            if in_set {
                                return Ok(rt_sigtimedwait_deliver(memory, info_ptr, pending));
                            }
                            crate::host_signal::raise_for_self(pending);
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Ok(LINUX_EAGAIN.into())
                }
                _ => Ok(LINUX_EAGAIN.into()),
            }
        }

        /// rt_sigqueueinfo(tgid, sig, info_ptr): send queue info signal.
        fn rt_sigqueueinfo(this, cx, tgid: Pid, sig: Signal, info_ptr: GuestPtr) {
            let tgid = i64::from(tgid.0);
            let signum = sig.0 as u64;
            if !is_valid_signum(signum) {
                return Ok(LINUX_EINVAL.into());
            }
            let self_tgids = [LINUX_BOOTSTRAP_PID as i64, std::process::id() as i64];
            if !self_tgids.contains(&tgid) {
                return Ok(LINUX_ESRCH.into());
            }
            Ok(LINUX_ENOSYS.into())
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

/// Bit mask for `signum` (1..=64) within a Linux `sigset_t` word, or
/// `None` if out of range.
fn sigmask_bit(signum: i32) -> Option<u64> {
    if (1..=64).contains(&signum) {
        Some(1u64 << (signum - 1))
    } else {
        None
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
