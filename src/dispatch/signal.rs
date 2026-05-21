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
    /// Guest's blocked-signal mask (bit `signum-1`). Updated by
    /// `rt_sigprocmask`. A blocked signal that is raised is held in
    /// `pending` instead of being delivered.
    pub mask: u64,
    /// Signals raised while blocked, awaiting unblock or a synchronous
    /// wait (`rt_sigtimedwait`). Bit `signum-1`.
    pub pending: u64,
    /// Installed alternate signal stack (`sigaltstack`). `None` means no
    /// alt stack is installed; queried back via the `old_ss` out-param.
    pub altstack: Option<LinuxSigaltstack>,
}

impl SignalState {
    pub(super) fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            mask: 0,
            pending: 0,
            altstack: None,
        }
    }
}

impl SyscallDispatcher {
    /// Look up the currently-installed handler for `signum`. Returns
    /// `None` when no handler has been recorded via `rt_sigaction`, or
    /// when the recorded handler is `SIG_DFL` / `SIG_IGN`. The runtime
    /// uses this to decide whether to inject a guest frame (handler is
    /// `Some`) or apply the host-side default (handler is `None`).
    pub fn registered_signal_handler(&self, signum: i32) -> Option<LinuxSigaction> {
        let action = self.signal.handlers.get(&signum).copied()?;
        let handler = action.sa_handler;
        if handler == crate::linux_abi::LINUX_SIG_DFL
            || handler == crate::linux_abi::LINUX_SIG_IGN
        {
            None
        } else {
            Some(action)
        }
    }

    /// True iff the guest installed `SIG_IGN` for `signum`. Lets the
    /// runtime drop a pending signal without injecting it.
    pub fn signal_is_ignored(&self, signum: i32) -> bool {
        self.signal.handlers
            .get(&signum)
            .map(|a| a.sa_handler == crate::linux_abi::LINUX_SIG_IGN)
            .unwrap_or(false)
    }

    /// True iff `signum` is currently blocked by the guest's signal mask.
    /// SIGKILL/SIGSTOP can never be blocked, matching the kernel.
    pub fn signal_blocked(&self, signum: i32) -> bool {
        if signum == LINUX_SIGKILL || signum == LINUX_SIGSTOP {
            return false;
        }
        match sigmask_bit(signum) {
            Some(bit) => self.signal.mask & bit != 0,
            None => false,
        }
    }

    /// Record a (blocked) signal as pending. It stays queued until the
    /// guest unblocks it or dequeues it via `rt_sigtimedwait`.
    pub fn mark_signal_pending(&mut self, signum: i32) {
        if let Some(bit) = sigmask_bit(signum) {
            self.signal.pending |= bit;
        }
    }

    /// Lowest-numbered pending signal that intersects `set`, cleared from
    /// the pending set. Used by `rt_sigtimedwait`.
    fn take_pending_in(&mut self, set: u64) -> Option<i32> {
        let candidates = self.signal.pending & set;
        if candidates == 0 {
            return None;
        }
        let signum = candidates.trailing_zeros() as i32 + 1;
        self.signal.pending &= !(1u64 << (signum - 1));
        Some(signum)
    }

    /// Raise `signum` against the guest itself (kill/tkill/tgkill self
    /// target). If the signal is blocked it is held pending; otherwise it
    /// is handed to the runtime's delivery slot. signum 0 is the null
    /// probe and a no-op success.
    fn raise_self(&mut self, signum: u64) -> DispatchOutcome {
        if signum == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        let s = signum as i32;
        if self.signal_blocked(s) {
            self.mark_signal_pending(s);
        } else {
            crate::host_signal::raise_for_self(s);
        }
        DispatchOutcome::Returned { value: 0 }
    }

    pub(super) fn kill<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i64;
        let signum = ctx.arg(1);
        if !is_valid_signum(signum) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if signal_is_self_target(pid, /*tid_required=*/ false) {
            return Ok(self.raise_self(signum));
        }
        Ok(bootstrap_signal_send(pid, /*tid_required=*/ false, signum))
    }

    pub(super) fn tkill<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let tid = ctx.arg(0) as i64;
        let signum = ctx.arg(1);
        if !is_valid_signum(signum) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // tkill's target is a thread id, not a "0 means self" pid form.
        if signal_is_self_target(tid, /*tid_required=*/ true) {
            return Ok(self.raise_self(signum));
        }
        Ok(bootstrap_signal_send(tid, /*tid_required=*/ true, signum))
    }

    pub(super) fn tgkill<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let tgid = ctx.arg(0) as i64;
        let tid = ctx.arg(1) as i64;
        let signum = ctx.arg(2);
        if !is_valid_signum(signum) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let host_pid = std::process::id() as i64;
        let bootstrap_pid = LINUX_BOOTSTRAP_PID as i64;
        let valid_self =
            (tgid == host_pid || tgid == bootstrap_pid)
                && (tid == host_pid || tid == bootstrap_pid);
        if !valid_self {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        Ok(self.raise_self(signum))
    }

    pub(super) fn sigaltstack<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let ss = ctx.arg(0);
        let old_ss = ctx.arg(1);
        let memory = &mut *ctx.memory;

        // Report the currently-installed alt stack (or a disabled stack
        // when none is set) into the old_ss out-param.
        if old_ss != 0 {
            let current = self.signal.altstack.unwrap_or_else(LinuxSigaltstack::disabled);
            if memory.write_bytes(old_ss, current.abi_bytes()).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }

        if ss != 0 {
            let bytes = match memory.read_bytes(ss, core::mem::size_of::<LinuxSigaltstack>()) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            };
            let new_stack = match LinuxSigaltstack::read_from_bytes(&bytes) {
                Ok(stack) => stack,
                Err(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            };
            let flags = new_stack.ss_flags as u32 as u64;
            // SS_ONSTACK is a query-only flag; reject it along with anything
            // unrecognized. Only SS_DISABLE is accepted from userspace.
            if flags & !LINUX_SS_DISABLE != 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            if flags & LINUX_SS_DISABLE != 0 {
                // SS_DISABLE removes any installed alt stack.
                self.signal.altstack = None;
            } else {
                let size = new_stack.ss_size;
                if size < LINUX_MINSIGSTKSZ {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_ENOMEM,
                    });
                }
                // Record the alt stack so a subsequent query returns it.
                // (We don't yet switch to it during delivery, but glibc and
                // sigaltstack(2) callers rely on the get/set round-trip.)
                self.signal.altstack = Some(new_stack);
            }
        }

        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn rt_sigsuspend<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let mask_ptr = ctx.arg(0);
        let sigset_size = ctx.arg(1);
        let memory = &*ctx.memory;
        if sigset_size != LINUX_RT_SIGSET_SIZE {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // Validate readability of the mask. The bootstrap has no signal
        // delivery, so we don't need to honour the mask — but we do owe the
        // caller an EFAULT if the pointer is bad. rt_sigsuspend is documented
        // to always return -1; with no signals to deliver, EINTR is the only
        // honest answer.
        if memory
            .read_bytes(mask_ptr, LINUX_RT_SIGSET_SIZE as usize)
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Errno {
            errno: LINUX_EINTR,
        })
    }

    pub(super) fn rt_sigaction<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let signum = ctx.arg(0) as i32;
        let new_action = ctx.arg(1);
        let old_action = ctx.arg(2);
        let _sigset_size = ctx.arg(3);
        let memory = &mut *ctx.memory;
        // Linux returns EINVAL for signum <= 0 or > _NSIG (64 on
        // most arches). Reject these.
        if !(1..=64).contains(&signum) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // Write back the previously-installed handler (or zero if none).
        if old_action != 0 {
            let prev = self
                .signal
                .handlers
                .get(&signum)
                .copied()
                .unwrap_or_else(LinuxSigaction::empty);
            let _ = write_kernel_struct_raw(memory, old_action, &prev);
        }
        // Read and store the new handler. The kernel rejects attempts
        // to install handlers for SIGKILL (9) and SIGSTOP (19); leave
        // signum=0 in the lenient bucket for the interactive sh probe.
        if new_action != 0 && signum != 9 && signum != 19
            && let Ok(bytes) = memory.read_bytes(new_action, core::mem::size_of::<LinuxSigaction>())
                && let Ok(sa) = LinuxSigaction::ref_from_bytes(&bytes) {
                    self.signal.handlers.insert(signum, *sa);
                    // If the guest installed a real handler (not SIG_DFL/IGN),
                    // install a matching host handler so a cross-process kill
                    // from another guest process is routed here instead of
                    // taking the host's default action (process termination).
                    let h = sa.sa_handler;
                    if h != crate::linux_abi::LINUX_SIG_DFL
                        && h != crate::linux_abi::LINUX_SIG_IGN
                    {
                        crate::host_signal::ensure_host_handler(signum);
                    }
                }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn rt_sigprocmask<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let how = ctx.arg(0);
        let new_set = ctx.arg(1);
        let old_set = ctx.arg(2);
        let sigset_size = ctx.arg(3);
        let memory = &mut *ctx.memory;
        if sigset_size != LINUX_RT_SIGSET_SIZE {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let previous_mask = self.signal.mask;
        // Write back the *previous* mask before applying changes (the
        // caller may pass the same buffer for new_set and old_set).
        if old_set != 0
            && memory
                .write_bytes(old_set, &previous_mask.to_le_bytes())
                .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        if new_set != 0 {
            let bytes = match memory.read_bytes(new_set, LINUX_RT_SIGSET_SIZE as usize) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            };
            let set = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
            let mut mask = match how {
                LINUX_SIG_BLOCK => previous_mask | set,
                LINUX_SIG_UNBLOCK => previous_mask & !set,
                LINUX_SIG_SETMASK => set,
                _ => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EINVAL,
                    });
                }
            };
            // SIGKILL and SIGSTOP can never be masked.
            // INVARIANT: SIGKILL/SIGSTOP are valid signal numbers (< 64), so sigmask_bit is Some.
            #[allow(clippy::unwrap_used)]
            let unmaskable = sigmask_bit(LINUX_SIGKILL).unwrap() | sigmask_bit(LINUX_SIGSTOP).unwrap();
            mask &= !unmaskable;
            self.signal.mask = mask;
            // Any pending signal that just became unblocked is eligible for
            // delivery now. Hand one to the runtime's pending slot.
            let deliverable = self.signal.pending & !mask;
            if deliverable != 0 {
                let signum = deliverable.trailing_zeros() as i32 + 1;
                self.signal.pending &= !(1u64 << (signum - 1));
                crate::host_signal::raise_for_self(signum);
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn rt_sigpending<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let set_ptr = ctx.arg(0);
        let sigset_size = ctx.arg(1);
        let memory = &mut *ctx.memory;
        if sigset_size != LINUX_RT_SIGSET_SIZE {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if set_ptr != 0
            && memory
                .write_bytes(set_ptr, &self.signal.pending.to_le_bytes())
                .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn rt_sigtimedwait<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let set_ptr = ctx.arg(0);
        let info_ptr = ctx.arg(1);
        let timeout_ptr = ctx.arg(2);
        let sigset_size = ctx.arg(3);
        let memory = &*ctx.memory;
        if sigset_size != LINUX_RT_SIGSET_SIZE {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let set_bytes = match memory.read_bytes(set_ptr, LINUX_RT_SIGSET_SIZE as usize) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        };
        let wait_set = u64::from_le_bytes(set_bytes.try_into().unwrap_or([0; 8]));
        let mut timeout: Option<Duration> = None;
        if timeout_ptr != 0 {
            let ts = match read_timespec(memory, timeout_ptr) {
                Ok(ts) => ts,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            // Copy out of the packed struct before use (taking a reference
            // to a packed field is UB / a hard error).
            let tv_sec = ts.tv_sec;
            let tv_nsec = ts.tv_nsec;
            if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            timeout = Some(Duration::new(tv_sec as u64, tv_nsec as u32));
        }

        let memory = &mut *ctx.memory;
        // A signal already pending (e.g. raised while blocked) is dequeued
        // immediately and its number returned.
        if let Some(signum) = self.take_pending_in(wait_set) {
            return Ok(rt_sigtimedwait_deliver(memory, info_ptr, signum));
        }
        // Nothing pending. A zero (or absent) timeout is a non-blocking poll.
        match timeout {
            Some(d) if !d.is_zero() => {
                // Bounded wait: the only async source that can arrive is the
                // host slot (e.g. SIGINT). Sleep up to the timeout (capped so
                // the conformance harness can't wedge) re-checking it.
                let deadline = Instant::now() + d.min(Duration::from_secs(5));
                while Instant::now() < deadline {
                    let pending = crate::host_signal::take_pending();
                    if pending != 0 {
                        let in_set = sigmask_bit(pending).is_some_and(|b| wait_set & b != 0);
                        if in_set {
                            return Ok(rt_sigtimedwait_deliver(memory, info_ptr, pending));
                        }
                        // Not awaited: re-queue for normal delivery and stop.
                        crate::host_signal::raise_for_self(pending);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(DispatchOutcome::Errno {
                    errno: LINUX_EAGAIN,
                })
            }
            _ => Ok(DispatchOutcome::Errno {
                errno: LINUX_EAGAIN,
            }),
        }
    }

    pub(super) fn rt_sigqueueinfo<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let tgid = ctx.arg(0) as i64;
        let signum = ctx.arg(1);
        if !is_valid_signum(signum) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if tgid != LINUX_BOOTSTRAP_PID as i64 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        // No signal delivery; surface the gap explicitly rather than silently
        // swallowing the queued siginfo.
        Ok(DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        })
    }

    pub(super) fn rt_sigreturn<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // rt_sigreturn is invoked from a signal trampoline to restore the
        // pre-signal context. The dispatcher can't perform the restore
        // itself — only the trap engine has access to the vCPU register
        // file — so we signal `SigReturn` and let the runtime drive
        // `HvfTrapEngine::rt_sigreturn`. There is no x0 retval to write;
        // the restored x0 IS the value the guest sees.
        Ok(DispatchOutcome::SigReturn)
    }
}

fn is_valid_signum(signum: u64) -> bool {
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

fn bootstrap_signal_send(target: i64, tid_required: bool, signum: u64) -> DispatchOutcome {
    if !is_valid_signum(signum) {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
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
        return DispatchOutcome::Returned { value: 0 }
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
        return DispatchOutcome::Errno { errno: LINUX_ESRCH };
    }
    // Translate the Linux signum to the host's numbering: the target is a real
    // host process, and Linux/macOS disagree on several numbers (e.g. SIGUSR1
    // 10 vs 30). `wait4` translates the resulting status back to Linux.
    let host_signum = crate::host_signal::linux_to_host_signum(signum as i32);
    let rc = unsafe { libc::kill(target as i32, host_signum) };
    if rc < 0 {
        return DispatchOutcome::Errno { errno: host_errno() };
    }
    DispatchOutcome::Returned { value: 0 }
}
