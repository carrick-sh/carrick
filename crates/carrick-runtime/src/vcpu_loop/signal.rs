//! SIGNAL concern of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

use super::*;

pub(crate) fn signal_wait_slice(
    deadline: &mut Option<Instant>,
    timeout: Option<Duration>,
) -> Option<Duration> {
    if let Some(timeout) = timeout {
        let target = deadline.get_or_insert_with(|| Instant::now() + timeout);
        let now = Instant::now();
        if now >= *target {
            return None;
        }
        Some((*target - now).min(SIGNAL_WAIT_SLICE))
    } else {
        *deadline = None;
        Some(SIGNAL_WAIT_SLICE)
    }
}

pub(crate) fn signal_wait_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|target| Instant::now() >= target)
}

/// The GUEST's remaining overall signal-wait budget: `None` for an indefinite
/// `sigwait`/`rt_sigtimedwait(NULL)`, else the time left until the deadline
/// `signal_wait_slice` established (call this AFTER it, in the same loop
/// iteration, so a finite wait's deadline exists). This is what the vCPU park
/// decision must be judged by — the 50 ms service slice is carrick-internal
/// and would otherwise make every signal wait look "short" and never park.
pub(crate) fn signal_wait_remaining(
    deadline: Option<Instant>,
    timeout: Option<Duration>,
) -> Option<Duration> {
    timeout.map(|timeout| {
        deadline.map_or(timeout, |target| {
            target.saturating_duration_since(Instant::now())
        })
    })
}

pub(crate) fn raise_sigpipe_for_blocking_write(
    dispatcher: &SyscallDispatcher,
    write: &crate::dispatch::BlockingHostWrite,
    outcome: DispatchOutcome,
) -> DispatchOutcome {
    if write.sigpipe_on_epipe()
        && matches!(
            &outcome,
            DispatchOutcome::Errno {
                errno: crate::linux_abi::LINUX_EPIPE
            }
        )
        && !dispatcher.signal_is_ignored(crate::linux_abi::LINUX_SIGPIPE)
    {
        dispatcher.mark_signal_pending(write.tid(), crate::linux_abi::LINUX_SIGPIPE);
    }
    outcome
}

pub(crate) fn partial_write_interrupt_outcome(
    write: &crate::dispatch::BlockingHostWrite,
) -> DispatchOutcome {
    if write.offset() > 0 {
        DispatchOutcome::Returned {
            value: write.offset() as i64,
        }
    } else {
        DispatchOutcome::Errno {
            errno: crate::linux_abi::LINUX_EINTR,
        }
    }
}

// ===================================================================
// EL0 synchronous-fault translation (moved from runtime/fault.rs; the
// classifier fns are pure and the delivery fn is generic over the engine).
// ===================================================================

/// Map an EL0 synchronous-fault `ESR_EL1` to the Linux `(signum, si_code)` the
/// kernel would deliver, or `None` for a class we don't translate (kept fatal).
pub(crate) fn el0_fault_signal(esr: u64) -> Option<(i32, i32)> {
    const SIGSEGV: i32 = 11;
    const SIGBUS: i32 = 7;
    const SEGV_MAPERR: i32 = 1;
    const SEGV_ACCERR: i32 = 2;
    const BUS_ADRALN: i32 = 1;
    let ec = (esr >> 26) & 0x3f;
    let dfsc = esr & 0x3f;
    let segv_code = if (0x0c..=0x0f).contains(&dfsc) {
        SEGV_ACCERR
    } else {
        SEGV_MAPERR
    };
    match ec {
        0x20 | 0x21 => Some((SIGSEGV, segv_code)), // instruction abort
        0x24 | 0x25 => {
            if dfsc == 0x21 {
                Some((SIGBUS, BUS_ADRALN)) // alignment fault
            } else {
                Some((SIGSEGV, segv_code))
            }
        }
        _ => None,
    }
}

/// Map an EL0 synchronous *debug* exception `ESR_EL1` to the Linux
/// `(SIGTRAP, si_code)` the kernel would deliver, or `None` if it isn't a debug
/// class (leaving it to `el0_fault_signal`).
pub(crate) fn el0_debug_signal(esr: u64) -> Option<(i32, i32)> {
    const SIGTRAP: i32 = 5;
    const TRAP_BRKPT: i32 = 1; // software breakpoint (BRK)
    const TRAP_TRACE: i32 = 2; // process trace trap (single-step)
    const TRAP_HWBKPT: i32 = 4; // hardware breakpoint/watchpoint
    let ec = (esr >> 26) & 0x3f;
    match ec {
        0x3c => Some((SIGTRAP, TRAP_BRKPT)),         // BRK (AArch64)
        0x32 | 0x33 => Some((SIGTRAP, TRAP_TRACE)),  // software step
        0x30 | 0x31 => Some((SIGTRAP, TRAP_HWBKPT)), // HW breakpoint
        0x34 | 0x35 => Some((SIGTRAP, TRAP_HWBKPT)), // watchpoint
        _ => None,
    }
}

/// Upgrade `SEGV_MAPERR` to `SEGV_ACCERR` when the faulting VA lies inside a
/// range the guest mapped/`mprotect`ed `PROT_NONE`. Linux reports ACCERR there
/// — the VMA exists, the permission doesn't — but carrick expresses PROT_NONE
/// as a NON-PRESENT leaf (aarch64 invalid descriptor / x86 P=0), whose raw
/// fault class decodes as MAPERR on both ISAs. The engine's process-wide
/// [`carrick_guest_mem::protections::MemoryProtections`] no-access set (the
/// same one the syscall-path EFAULT gate consults) is the tracked PROT_NONE
/// state, so consult it at delivery time. Anything not tracked there (a
/// genuinely unmapped VA) keeps MAPERR.
pub(super) fn upgrade_prot_none_si_code<E: ThreadedEngine>(
    engine: &E,
    signum: i32,
    si_code: i32,
    fault_addr: u64,
) -> i32 {
    const SIGSEGV: i32 = 11;
    const SEGV_MAPERR: i32 = 1;
    const SEGV_ACCERR: i32 = 2;
    if signum == SIGSEGV
        && si_code == SEGV_MAPERR
        && engine
            .protections()
            .is_some_and(|p| p.range_no_access(fault_addr, 1))
    {
        SEGV_ACCERR
    } else {
        si_code
    }
}

/// Lower a raw aarch64 `EL0Fault` (raw `ESR_EL1` + `elr`/`far`) to the
/// ISA-neutral resolved signal triple `(signum, si_code, fault_addr)`, or `None`
/// for a class we don't translate (kept fatal → caller terminates by SIGSEGV).
///
/// This is the aarch64 → [`TrapError::GuestFault`] lowering. It MUST cover BOTH
/// fault arms so the GuestFault path is byte-identical to the historical
/// `EL0Fault` path: `el0_debug_signal` (BRK/single-step/HW-bp → SIGTRAP/TRAP_*)
/// is tried FIRST (so a debug exception carries the faulting PC as `si_addr`),
/// then `el0_fault_signal` (instruction/data abort → SIGSEGV/SIGBUS, carrying
/// `FAR_EL1` as `si_addr`). Mapping only `el0_fault_signal` would regress
/// BRK/single-step SIGTRAP delivery (ptrace, Go TestDebugCall).
pub(super) fn lower_el0_fault(esr: u64, elr: u64, far: u64) -> Option<(i32, i32, u64)> {
    if let Some((signum, si_code)) = el0_debug_signal(esr) {
        Some((signum, si_code, elr))
    } else {
        el0_fault_signal(esr).map(|(signum, si_code)| (signum, si_code, far))
    }
}

/// Deliver a synchronous guest fault as a Linux signal, exactly as the kernel
/// does, from the ALREADY-RESOLVED [`TrapError::GuestFault`] triple. Returns
/// `Some(outcome)` to terminate, `None` to resume into the injected handler.
///
/// `interrupted_pc` is the faulting instruction's PC iff the sigframe should
/// record it as the resume target (aarch64's direct-EL0-abort path); `None`
/// means the injected frame re-runs the faulting instruction from the engine's
/// own saved PC. ISA-neutral: aarch64 lowers `EL0Fault` to this via
/// [`lower_el0_fault`]; x86 backends emit `GuestFault` directly (CR2 →
/// `fault_addr`).
#[allow(clippy::too_many_arguments)]
pub(super) fn deliver_fault_signal<E: ThreadedEngine>(
    kernel: &Kernel,
    engine: &mut E,
    this_tid: ThreadId,
    mut signum: i32,
    mut si_code: i32,
    si_addr: u64,
    interrupted_pc: Option<u64>,
    traps: usize,
) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
    let dispatcher = &kernel.dispatcher;
    const SIGSEGV: i32 = 11;
    const SIGBUS: i32 = 7;
    const BUS_ADRERR: i32 = 2;
    if signum == SIGSEGV
        && let Some((page, prot)) = dispatcher.resident_fault_plan(si_addr)
        && engine
            .protect_range(page, crate::linux_abi::LINUX_PAGE_SIZE as usize, prot)
            .is_ok()
    {
        dispatcher.commit_resident_fault(page);
        return Ok(None);
    }
    if signum == SIGSEGV
        && let Some((grow_start, grow_len)) = dispatcher.mmap_growdown_fault_plan(si_addr)
        && engine
            .protect_range(
                grow_start,
                grow_len,
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            )
            .is_ok()
    {
        dispatcher.commit_mmap_growdown(grow_start);
        return Ok(None);
    }
    if signum == SIGSEGV && dispatcher.mmap_fault_is_sigbus(si_addr) {
        signum = SIGBUS;
        si_code = BUS_ADRERR;
    }
    // Capture the forked-child flag up front so the `terminate` closure does not
    // borrow `engine` — it is now also called in the inject-failure arm below,
    // after a &mut engine use, and a closure-held &engine would conflict. (M1b)
    let is_forked_child = engine.is_forked_child();
    let terminate = |signum: i32| -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
        if is_forked_child || kernel.dispatcher.is_forked_guest_process() {
            let out = dispatcher.stdout();
            let err = dispatcher.stderr();
            dispatcher.cleanup_sysv_ipc_on_process_exit();
            forked_child_die_by_signal(signum, &out, &err);
        }
        let result = assemble_run_result(kernel, 128 + signum, traps, false);
        Ok(Some(VcpuLoopOutcome::ProcessExit(Box::new(result))))
    };

    if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
        eprintln!(
            "[FAULTDBG tid={this_tid:?}] signum={signum} si_code={si_code} si_addr={si_addr:#x} interrupted_pc={interrupted_pc:?}"
        );
    }
    crate::probes::signal_deliver(this_tid.raw(), signum);
    crate::exec_helpers::stop_for_debug_signal(signum);

    // A synchronous fault with the signal blocked, or no handler installed,
    // forces the default action (terminate) on Linux.
    let action = dispatcher.registered_signal_handler(signum);
    if dispatcher.signal_blocked(this_tid, signum) || action.is_none() {
        return terminate(signum);
    }
    // INVARIANT: the `action.is_none()` arm above returned, so this is `Some`.
    #[allow(clippy::unwrap_used)]
    let action = action.unwrap();
    let restorer = if action.sa_flags & crate::linux_abi::LINUX_SA_RESTORER != 0 {
        action.sa_restorer
    } else {
        0
    };
    let altstack = if action.sa_flags & crate::linux_abi::LINUX_SA_ONSTACK != 0 {
        dispatcher.signal_altstack(this_tid)
    } else {
        None
    };
    // The sigframe stores the saved mask in wire form; escape the typed set at
    // the frame-build boundary.
    let saved_sigmask = dispatcher
        .enter_signal_handler(this_tid, signum, action)
        .raw();
    let injected = engine.inject_signal(
        signum,
        action.sa_handler,
        restorer,
        None,
        interrupted_pc,
        altstack,
        saved_sigmask,
        Some((si_code, si_addr)),
        None,  // a synchronous fault never carries a queued (rt_sigqueueinfo) siginfo
        false, // a synchronous fault re-runs the faulting instruction, never a syscall restart
    );
    match injected {
        Ok(()) => Ok(None),
        // Linux force_sigsegv: the handler frame couldn't be written to the
        // user stack -> the thread-group dies by SIGSEGV (exit 139).
        Err(TrapError::SignalDeliveryFault) => terminate(11), // SIGSEGV
        Err(e) => Err(e.into()),
    }
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    pub(super) fn complete_signal_thread(
        &self,
        engine: &mut E,
        target: ThreadId,
        signum: i32,
    ) -> Result<i64, RuntimeError> {
        let retval: i64 = if self.registry.is_live(target) {
            crate::host_signal::publish_pending_for(target.raw(), signum);
            self.kicker.kick(target);
            0
        } else {
            crate::linux_abi::LINUX_ESRCH.guest_retval()
        };
        self.complete_returned(engine, retval)
    }
}

thread_local! {
    // Per-vCPU-thread count of signal HANDLERS delivered to the guest. The vCPU
    // loop's trap watchdog measures traps since this last advanced (not lifetime
    // total): a guest legitimately busy-waiting for a signal makes millions of
    // syscalls but is responsive, so each delivered handler resets the budget. A
    // genuinely stuck guest delivers no handlers and still trips the watchdog.
    static SIGNAL_PROGRESS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Note that a signal handler was delivered to the guest on this vCPU thread —
/// progress that resets the trap watchdog (see the vCPU loop).
pub(crate) fn note_signal_progress() {
    SIGNAL_PROGRESS.with(|c| c.set(c.get().wrapping_add(1)));
}

/// This vCPU thread's running count of delivered signal handlers.
pub(crate) fn signal_progress_count() -> u64 {
    SIGNAL_PROGRESS.with(std::cell::Cell::get)
}

/// Drain whatever signal is sitting in the host pending slot and dispatch it to
/// the guest. Returns `Ok(None)` when nothing was pending.
pub(crate) fn deliver_pending_signal<T>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    last_syscall_retval: Option<i64>,
    tid: ThreadId,
    interrupted_pc: Option<u64>,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    // Drain the cross-process explicit-signal ring into pending state, so the
    // normal delivery below runs each with the sender's identity.
    dispatcher.drain_xsignals_process_directed();

    let pending = crate::host_signal::take_pending_for(tid.raw());
    // Provenance of the taken signal (see take_pending_in_from): a host-slot
    // delivery is thread-directed; only a shared-set take may consume the
    // PROCESS-directed siginfo queue below.
    let (pending, from_shared) = if pending == 0 {
        // Nothing newly arrived in the host slot. Deliver the next signal that was
        // raised while blocked and has since been unblocked.
        match dispatcher.take_deliverable_pending_from(tid) {
            Some((s, from_thread)) => (s, !from_thread),
            None => return Ok(None),
        }
    } else {
        (pending, false)
    };
    crate::probes::signal_deliver(tid.raw(), pending);
    // A blocked signal must not be delivered — hold it pending until the guest
    // unblocks it.
    if dispatcher.signal_blocked(tid, pending) {
        dispatcher.mark_signal_pending(tid, pending);
        return Ok(Some(PendingSignalAction::ignored()));
    }
    if dispatcher.is_ptrace_traceme() {
        crate::guest_cpu::mark_self_ptrace_stop_pending(pending);
        crate::exec_helpers::stop_by_signal(crate::linux_abi::LINUX_SIGSTOP);
        return Ok(Some(PendingSignalAction::ignored()));
    }
    crate::exec_helpers::stop_for_debug_signal(pending);
    let action = dispatcher
        .take_pending_signal_action(tid, pending)
        .or_else(|| dispatcher.registered_signal_handler(pending));
    if action.is_none() && dispatcher.signal_is_ignored(pending) {
        return Ok(Some(PendingSignalAction::ignored()));
    }
    match action {
        Some(action) => {
            // A handler is about to run in the guest: real progress, resets the
            // trap watchdog (a busy-wait-for-signal loop is not a hang).
            note_signal_progress();
            // Block the signal (+ its sa_mask) for the duration of the handler, as
            // the kernel does — restored by rt_sigreturn.
            let restorer = if action.sa_flags & crate::linux_abi::LINUX_SA_RESTORER != 0 {
                action.sa_restorer
            } else {
                0
            };
            // SA_ONSTACK: run the handler on the alternate signal stack if one is
            // installed.
            let altstack = if action.sa_flags & crate::linux_abi::LINUX_SA_ONSTACK != 0 {
                dispatcher.signal_altstack(tid)
            } else {
                None
            };
            // SA_RESTART: if this handler interrupted a blocking, restartable
            // syscall that returned EINTR, restart it instead of surfacing the
            // EINTR.
            let restart_syscall = interrupted_pc.is_none()
                && last_syscall_retval == Some(crate::linux_abi::LINUX_EINTR.guest_retval())
                && action.sa_flags & crate::linux_abi::LINUX_SA_RESTART != 0
                && trap.last_syscall_nr().is_some_and(is_restartable_syscall);
            // Wire form for the sigframe build (see the synchronous-fault arm).
            let saved_sigmask = dispatcher.enter_signal_handler(tid, pending, action).raw();
            // If rt_sigqueueinfo queued a caller-supplied siginfo for this (tid,
            // signum), pop it now and hand it to inject_signal. Failing that,
            // synthesise an SI_USER siginfo with the sender's ns-pid.
            // Provenance-gated: a shared-set take reads the PROCESS-directed
            // queue; a host-slot/per-thread take reads the per-tid queue only.
            let queued_siginfo = if from_shared {
                dispatcher.take_process_pending_siginfo(pending)
            } else {
                dispatcher.take_pending_siginfo(tid, pending)
            }
            .or_else(|| {
                crate::host_signal::take_child_exit_siginfo(tid.raw(), pending).map(|info| {
                    const CLD_EXITED: i32 = 1;
                    let ns_pid =
                        crate::namespace::pid::host_to_ns_or_self(info.host_pid as u32) as i32;
                    let linux_status = if info.si_code == CLD_EXITED {
                        info.host_status
                    } else {
                        crate::host_signal::host_to_linux_signum(info.host_status)
                    };
                    crate::linux_abi::LinuxSiginfo::child_exit(
                        pending,
                        ns_pid,
                        info.host_uid,
                        info.si_code,
                        linux_status,
                    )
                })
            })
            .or_else(|| {
                let sender_host = crate::host_signal::last_sender_for(pending);
                (sender_host > 0).then(|| {
                    let ns_pid =
                        crate::namespace::pid::host_to_ns_or_self(sender_host as u32) as i32;
                    let uid = crate::cred_ipc::read_target(sender_host).unwrap_or(0);
                    crate::linux_abi::LinuxSiginfo::kill(
                        pending,
                        crate::linux_abi::LINUX_SI_USER,
                        ns_pid,
                        uid,
                    )
                })
            });
            match trap.inject_signal(
                pending,
                action.sa_handler,
                restorer,
                last_syscall_retval,
                interrupted_pc,
                altstack,
                saved_sigmask,
                None, // SI_USER-shaped (tkill/sysmon); faults use deliver_fault_signal
                queued_siginfo,
                restart_syscall,
            ) {
                Ok(()) => Ok(Some(PendingSignalAction::ignored())),
                // Linux force_sigsegv: the signal frame couldn't be written to the
                // user stack. Terminate the whole thread-group by SIGSEGV (exit
                // 139).
                Err(TrapError::SignalDeliveryFault) => {
                    Ok(Some(PendingSignalAction::terminate(11))) // SIGSEGV
                }
                Err(e) => Err(e.into()),
            }
        }
        // No registered handler → the kernel takes the signal's DEFAULT action.
        None if is_default_ignore_signal(pending) => Ok(Some(PendingSignalAction::ignored())),
        None if is_default_stop_signal(pending) => Ok(Some(PendingSignalAction::stop(pending))),
        None => Ok(Some(PendingSignalAction::terminate(pending))),
    }
}

/// Signals whose DEFAULT disposition is "ignore" (Linux `Ign`).
pub(crate) fn is_default_ignore_signal(signum: i32) -> bool {
    matches!(
        signum,
        crate::linux_abi::LINUX_SIGCHLD
            | crate::linux_abi::LINUX_SIGURG
            | crate::linux_abi::LINUX_SIGWINCH
    )
}
