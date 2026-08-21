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
    context: &crate::kernel::KernelContext,
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
        && !dispatcher.signal_is_ignored(context, crate::linux_abi::LINUX_SIGPIPE)
    {
        dispatcher.mark_signal_pending(context, write.tid(), crate::linux_abi::LINUX_SIGPIPE);
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

// `el0_debug_signal` (a pure AArch64 ESR_EL1 architectural fact) moved to
// `carrick_dsr_aarch64::esr` with the DSR translator extraction (its exit
// dispatch is a second consumer); re-exported so the HVF lowering below and
// every `el0_debug_signal` call path resolve unchanged.
pub(crate) use carrick_dsr_aarch64::esr::el0_debug_signal;

/// Upgrade `SEGV_MAPERR` to `SEGV_ACCERR` when Carrick's protection metadata
/// says the faulting VA belongs to a live mapping that denies the access.
/// Linux reports ACCERR there because the VMA exists. Carrick can otherwise
/// see MAPERR when `PROT_NONE` is represented by a non-present guest leaf, or
/// when Darwin reports an initial read-only host mapping as a translation-style
/// fault. The process-wide no-access and no-write sets are the durable VMA
/// permission evidence; an address in neither set remains a genuine MAPERR.
pub(crate) fn upgrade_protection_si_code<M: GuestMemory>(
    memory: &M,
    signum: i32,
    si_code: i32,
    fault_addr: u64,
) -> i32 {
    const SIGSEGV: i32 = 11;
    const SEGV_MAPERR: i32 = 1;
    const SEGV_ACCERR: i32 = 2;
    if signum == SIGSEGV
        && si_code == SEGV_MAPERR
        && memory
            .protections()
            .is_some_and(|p| p.range_fault_is_access_error(fault_addr, 1))
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
pub(crate) fn lower_el0_fault(esr: u64, elr: u64, far: u64) -> Option<(i32, i32, u64)> {
    if let Some((signum, si_code)) = el0_debug_signal(esr) {
        Some((signum, si_code, elr))
    } else {
        el0_fault_signal(esr).map(|(signum, si_code)| (signum, si_code, far))
    }
}

pub(crate) enum FaultSignalDisposition {
    Injected,
    Terminate(i32),
}

/// Apply Linux's synchronous-fault signal rules to any syscall trap adapter.
/// Backend-specific code resolves paging first, then calls this helper with the
/// final signal triple and decides how to terminate its host process.
#[allow(clippy::too_many_arguments)]
pub(crate) fn inject_fault_signal<T: SyscallTrap>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    this_tid: ThreadId,
    signum: i32,
    si_code: i32,
    si_addr: u64,
    interrupted_pc: Option<u64>,
) -> Result<FaultSignalDisposition, RuntimeError> {
    crate::probes::signal_deliver(this_tid.raw(), signum);
    crate::exec_helpers::stop_for_debug_signal(signum);

    let action = dispatcher.registered_signal_handler(context, signum);
    if dispatcher.signal_blocked(context, this_tid, signum) || action.is_none() {
        return Ok(FaultSignalDisposition::Terminate(signum));
    }
    // INVARIANT: the `action.is_none()` arm above returned, so this is `Some`.
    #[allow(clippy::unwrap_used)]
    let action = action.unwrap();
    let sa_flags = carrick_abi::LinuxSaFlags::from_bits_truncate(action.sa_flags);
    let restorer = if sa_flags.contains(carrick_abi::LinuxSaFlags::RESTORER) {
        action.sa_restorer
    } else {
        0
    };
    let altstack = if sa_flags.contains(carrick_abi::LinuxSaFlags::ONSTACK) {
        dispatcher.signal_altstack(context, this_tid)
    } else {
        None
    };
    let saved_sigmask = dispatcher
        .enter_signal_handler(context, this_tid, signum, action)
        .raw();
    match trap.inject_signal(
        signum,
        action.sa_handler,
        restorer,
        None,
        interrupted_pc,
        altstack,
        saved_sigmask,
        Some((si_code, si_addr)),
        None,
        false,
    ) {
        Ok(()) => Ok(FaultSignalDisposition::Injected),
        Err(TrapError::SignalDeliveryFault) => Ok(FaultSignalDisposition::Terminate(11)),
        Err(error) => Err(error.into()),
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
    context: &crate::kernel::KernelContext,
    engine: &mut E,
    this_tid: ThreadId,
    fatal_image_generation: u64,
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
        && let Some(plan) = dispatcher.resident_fault_plan(si_addr)
        && engine
            .protect_range(
                plan.page(),
                crate::linux_abi::LINUX_PAGE_SIZE as usize,
                plan.prot(),
            )
            .is_ok()
    {
        dispatcher.commit_resident_fault(plan);
        return Ok(None);
    }
    if signum == SIGSEGV
        && let Some(plan) = dispatcher.mmap_growdown_fault_plan(si_addr)
        && engine
            .protect_range(
                plan.start(),
                plan.len(),
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            )
            .is_ok()
    {
        dispatcher.commit_mmap_growdown(plan);
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
        if super::requires_no_unwind_host_exit(kernel, is_forked_child) {
            let out = dispatcher.stdout();
            let err = dispatcher.stderr();
            dispatcher.cleanup_sysv_ipc_on_process_exit();
            forked_child_die_by_signal(signum, &out, &err);
        }
        kernel.record_fatal_signal(super::FatalSignalRecord {
            image_generation: fatal_image_generation,
            tid: context.thread().key().tid,
            signo: signum,
            code: si_code,
            addr: si_addr,
        });
        let result = assemble_run_result(kernel, 128 + signum, Some(signum), traps, false);
        Ok(Some(VcpuLoopOutcome::ProcessExit(Box::new(result))))
    };

    if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
        eprintln!(
            "[FAULTDBG tid={this_tid:?}] signum={signum} si_code={si_code} si_addr={si_addr:#x} interrupted_pc={interrupted_pc:?}"
        );
    }
    match inject_fault_signal(
        engine,
        dispatcher,
        context,
        this_tid,
        signum,
        si_code,
        si_addr,
        interrupted_pc,
    )? {
        FaultSignalDisposition::Injected => Ok(None),
        FaultSignalDisposition::Terminate(signum) => terminate(signum),
    }
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    pub(super) fn complete_signal_thread(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        target: ThreadId,
        signum: i32,
        kernel_target: Option<crate::kernel::ThreadKey>,
    ) -> Result<i64, RuntimeError> {
        let retval: i64 = if let Some(exact) = kernel_target {
            if exact.tid.raw() != target.raw() {
                return Err(RuntimeError::Configuration(
                    "Kernel-native thread signal target identity mismatch".to_owned(),
                ));
            }
            let context = self.service_kernel_context.as_ref().ok_or_else(|| {
                RuntimeError::Configuration(
                    "Kernel-native thread signal lost caller context".to_owned(),
                )
            })?;
            let directory = kernel.hvpatch_runtime.as_ref().ok_or_else(|| {
                RuntimeError::Configuration(
                    "Kernel-native thread signal has no runtime directory".to_owned(),
                )
            })?;
            let (scheduler, _service) = directory.continuation_services(context.kernel());
            let _ = scheduler.wake(exact);
            0
        } else if self.registry.is_live(target) {
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

/// Reset the executor-local watchdog baseline while returning the exact prior
/// task's progress receipt. A successor must always begin from zero.
pub(crate) fn reset_signal_progress_for_executor_boundary() -> u64 {
    SIGNAL_PROGRESS.with(|progress| progress.replace(0))
}

pub(crate) fn signal_progress_is_zero_for_executor_boundary() -> bool {
    SIGNAL_PROGRESS.with(|progress| progress.get() == 0)
}

/// Drain whatever signal is sitting in the host pending slot and dispatch it to
/// the guest. Returns `Ok(None)` when nothing was pending.
pub(crate) fn deliver_pending_signal<T>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    last_syscall_retval: Option<i64>,
    tid: ThreadId,
    interrupted_pc: Option<u64>,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    deliver_pending_signal_with_restart(
        trap,
        dispatcher,
        context,
        last_syscall_retval,
        tid,
        interrupted_pc,
        None,
    )
}

pub(crate) fn deliver_pending_signal_with_restart<T>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    last_syscall_retval: Option<i64>,
    tid: ThreadId,
    interrupted_pc: Option<u64>,
    continuation_restart: Option<bool>,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    deliver_signal_with_restart(
        trap,
        dispatcher,
        context,
        last_syscall_retval,
        tid,
        interrupted_pc,
        continuation_restart,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn deliver_reserved_signal_with_restart<T>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    last_syscall_retval: Option<i64>,
    tid: ThreadId,
    interrupted_pc: Option<u64>,
    continuation_restart: Option<bool>,
    reserved: crate::vcpu_loop::continuation::ReservedSignal,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    if !reserved.consume() {
        return Err(RuntimeError::Configuration(
            "reserved signal was already consumed".to_owned(),
        ));
    }
    let caught = {
        let action = reserved.action();
        action.sa_handler != carrick_abi::LINUX_SIG_DFL
            && action.sa_handler != carrick_abi::LINUX_SIG_IGN
    };
    let result = deliver_signal_with_restart(
        trap,
        dispatcher,
        context,
        last_syscall_retval,
        tid,
        interrupted_pc,
        continuation_restart,
        Some(&reserved),
    );
    if !caught {
        reserved.restore_persistent_after_default_action();
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn deliver_signal_with_restart<T>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    last_syscall_retval: Option<i64>,
    tid: ThreadId,
    interrupted_pc: Option<u64>,
    continuation_restart: Option<bool>,
    reserved: Option<&crate::vcpu_loop::continuation::ReservedSignal>,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    // Drain the cross-process explicit-signal ring into pending state, so the
    // normal delivery below runs each with the sender's identity.
    if reserved.is_none() {
        dispatcher.drain_xsignals_process_directed(context);
    }

    let pending = reserved.map_or_else(
        || crate::host_signal::take_pending_for(tid.raw()),
        crate::vcpu_loop::continuation::ReservedSignal::signum,
    );
    // A dispatcher dequeue returns owner and payload atomically. A host-slot
    // signal remains thread-directed and consumes its per-thread payload below.
    let (pending, dequeued_siginfo, from_dispatcher, job_control_generation) =
        if let Some(reserved) = reserved {
            (
                pending,
                reserved.siginfo(),
                true,
                reserved.job_control_generation(),
            )
        } else if pending == 0 {
            match dispatcher.take_deliverable_pending_from(context, tid) {
                Some(pending) => (
                    pending.signum,
                    pending.siginfo,
                    true,
                    pending.job_control_generation,
                ),
                None => return Ok(None),
            }
        } else {
            (pending, None, false, None)
        };
    crate::probes::signal_deliver(tid.raw(), pending);
    // A blocked signal must not be delivered — hold it pending until the guest
    // unblocks it.
    if reserved.is_none() && dispatcher.signal_blocked(context, tid, pending) {
        dispatcher.mark_signal_pending(context, tid, pending);
        return Ok(Some(PendingSignalAction::ignored()));
    }
    if crate::exec_helpers::stop_for_ptrace_signal(dispatcher, pending) {
        return Ok(Some(PendingSignalAction::ignored()));
    }
    crate::exec_helpers::stop_for_debug_signal(pending);
    let action = reserved
        .map(crate::vcpu_loop::continuation::ReservedSignal::action)
        .filter(|action| {
            action.sa_handler != carrick_abi::LINUX_SIG_DFL
                && action.sa_handler != carrick_abi::LINUX_SIG_IGN
        })
        .or_else(|| {
            if reserved.is_none() {
                dispatcher
                    .take_pending_signal_action(context, tid, pending)
                    .or_else(|| dispatcher.registered_signal_handler(context, pending))
            } else {
                None
            }
        });
    if reserved.is_none() && action.is_none() && dispatcher.signal_is_ignored(context, pending) {
        return Ok(Some(PendingSignalAction::ignored()));
    }
    match action {
        Some(action) => {
            // A handler is about to run in the guest: real progress, resets the
            // trap watchdog (a busy-wait-for-signal loop is not a hang).
            note_signal_progress();
            // Block the signal (+ its sa_mask) for the duration of the handler, as
            // the kernel does — restored by rt_sigreturn.
            let sa_flags = carrick_abi::LinuxSaFlags::from_bits_truncate(action.sa_flags);
            let restorer = if sa_flags.contains(carrick_abi::LinuxSaFlags::RESTORER) {
                action.sa_restorer
            } else {
                0
            };
            // SA_ONSTACK: run the handler on the alternate signal stack if one is
            // installed.
            let altstack = if sa_flags.contains(carrick_abi::LinuxSaFlags::ONSTACK) {
                dispatcher.signal_altstack(context, tid)
            } else {
                None
            };
            // SA_RESTART: if this handler interrupted a blocking, restartable
            // syscall that returned EINTR, restart it instead of surfacing the
            // EINTR.
            let at_syscall_boundary = interrupted_pc.is_none();
            let retval_is_eintr =
                last_syscall_retval == Some(crate::linux_abi::LINUX_EINTR.guest_retval());
            let handler_wants_restart = sa_flags.contains(carrick_abi::LinuxSaFlags::RESTART);
            let syscall_restartable = trap.last_syscall_nr().is_some_and(is_restartable_syscall);
            let restart_syscall = continuation_restart.unwrap_or({
                at_syscall_boundary
                    && retval_is_eintr
                    && handler_wants_restart
                    && syscall_restartable
            });
            // Publish WHICH predicate decided. All four live in one boolean, so
            // from outside "the guest saw EINTR under SA_RESTART" is otherwise a
            // dead end — you cannot tell a missing syscall from the restartable
            // set apart from a retval that was never EINTR in the first place.
            crate::probes::signal_restart_decision(
                tid.raw(),
                pending,
                trap.last_syscall_nr().map_or(-1, |nr| nr as i64),
                last_syscall_retval.unwrap_or(0),
                i32::from(at_syscall_boundary)
                    | (i32::from(retval_is_eintr) << 1)
                    | (i32::from(handler_wants_restart) << 2)
                    | (i32::from(syscall_restartable) << 3),
            );
            // Wire form for the sigframe build (see the synchronous-fault arm).
            let saved_sigmask = dispatcher
                .enter_signal_handler(context, tid, pending, action)
                .raw();
            // If rt_sigqueueinfo queued a caller-supplied siginfo for this (tid,
            // signum), hand it to inject_signal. Dispatcher-owned pending
            // dequeues already carried the exact payload; host-slot delivery
            // consumes only the matching per-thread queue.
            let queued_siginfo = if reserved.is_some() {
                dequeued_siginfo
            } else {
                dequeued_siginfo
                    .or_else(|| {
                        (!from_dispatcher)
                            .then(|| dispatcher.take_pending_siginfo(context, tid, pending))
                            .flatten()
                    })
                    .or_else(|| {
                        crate::host_signal::take_child_exit_siginfo(tid.raw(), pending).map(
                            |info| {
                                const CLD_EXITED: i32 = 1;
                                let ns_pid =
                                    crate::namespace::pid::host_to_ns_or_self(info.host_pid as u32)
                                        as i32;
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
                            },
                        )
                    })
                    .or_else(|| {
                        let sender_host = crate::host_signal::last_sender_for(pending);
                        (sender_host > 0).then(|| {
                            let ns_pid =
                                crate::namespace::pid::host_to_ns_or_self(sender_host as u32)
                                    as i32;
                            let uid = crate::cred_ipc::read_target(sender_host)
                                .unwrap_or(carrick_abi::NsUid::ROOT);
                            crate::linux_abi::LinuxSiginfo::kill(
                                pending,
                                crate::linux_abi::LINUX_SI_USER,
                                ns_pid,
                                uid.raw(),
                            )
                        })
                    })
            };
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
        // SIGCONT's state transition happens at generation time so a stopped
        // HVPatch task can wake before any vCPU is available to consume this
        // queue entry. Delivery itself has no terminate/stop action.
        None if pending == crate::linux_abi::LINUX_SIGCONT => {
            Ok(Some(PendingSignalAction::ignored()))
        }
        None if is_default_ignore_signal(pending) => Ok(Some(PendingSignalAction::ignored())),
        None if is_default_stop_signal(pending) => Ok(Some(PendingSignalAction::stop(
            pending,
            job_control_generation,
        ))),
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

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    static PTRACE_SIGNAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[derive(Default)]
    struct NoopTrap {
        restart: bool,
        delivered_signum: i32,
        delivered_handler: u64,
    }

    impl crate::trap::SyscallTrap for NoopTrap {
        fn next_syscall(&mut self) -> Result<Option<crate::trap::RawSyscall>, TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }

        fn current_pc(&self) -> Result<u64, TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }

        fn complete_syscall(&mut self, _return_value: i64) -> Result<(), TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }

        fn fork(&mut self) -> Result<crate::trap::ForkOutcome, TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }

        fn execve_into(
            &mut self,
            _new_image: &crate::memory::AddressSpace,
        ) -> Result<(), TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }

        fn inject_signal(
            &mut self,
            signum: i32,
            handler: u64,
            _sa_restorer: u64,
            _pending_syscall_retval: Option<i64>,
            _interrupted_pc: Option<u64>,
            _altstack: Option<(u64, u64)>,
            _saved_sigmask: u64,
            _fault_siginfo: Option<(i32, u64)>,
            _queued_siginfo: Option<crate::linux_abi::LinuxSiginfo>,
            restart_syscall: bool,
        ) -> Result<(), TrapError> {
            self.restart = restart_syscall;
            self.delivered_signum = signum;
            self.delivered_handler = handler;
            Ok(())
        }

        fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }
    }

    #[test]
    fn reserved_delivery_cannot_borrow_later_signal_action_or_restart_class() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("context");
        let authority = context.signal_authority();
        let first = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let second = crate::kernel::LinuxSignal::for_signal_number(12).expect("SIGUSR2");
        let mut restart = carrick_abi::LinuxSigaction::empty();
        restart.sa_handler = 0x1110;
        restart.sa_flags = carrick_abi::LINUX_SA_RESTART;
        let mut no_restart = carrick_abi::LinuxSigaction::empty();
        no_restart.sa_handler = 0x2220;
        authority.install_action(first, restart);
        authority.install_action(second, no_restart);
        authority.enqueue_thread_standard(first, None);
        let dequeued = authority
            .take_lowest_in(carrick_abi::SigSet::EMPTY.with(10))
            .expect("first reservation");
        let (action_generation, action) = authority.action_with_generation(first);
        let reserved = crate::vcpu_loop::continuation::ReservedSignal::kernel(
            authority.clone(),
            dequeued,
            action_generation,
            action,
            carrick_abi::SigSet::EMPTY,
        );
        authority.enqueue_thread_standard(second, None);

        let mut trap = NoopTrap::default();
        deliver_reserved_signal_with_restart(
            &mut trap,
            &dispatcher,
            &context,
            Some(crate::linux_abi::LINUX_EINTR.guest_retval()),
            ThreadId::synthetic_for_tests(context.thread().key().tid.raw()),
            None,
            Some(true),
            reserved,
        )
        .expect("reserved delivery")
        .expect("handler action");
        assert_eq!(trap.delivered_signum, 10);
        let restart_handler = restart.sa_handler;
        assert_eq!(trap.delivered_handler, restart_handler);
        assert!(trap.restart);
        assert_eq!(
            authority
                .take_lowest_in(carrick_abi::SigSet::EMPTY.with(12))
                .expect("second remains pending")
                .pending
                .signal
                .raw(),
            12
        );
    }

    #[test]
    fn reserved_ppoll_pselect_default_terminate_and_stop_ignore_restored_persistent_block() {
        for (pid, signum, expect_terminate) in [(15_466, 10, true), (15_467, 20, false)] {
            let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
                pid,
                ThreadId::synthetic_for_tests(pid),
                "reserved default action".to_owned(),
            )
            .expect("bootstrap input");
            let (_kernel, context) =
                crate::kernel::Kernel::bootstrap_root(bootstrap).expect("reserved default kernel");
            let dispatcher = SyscallDispatcher::new();
            let authority = context.signal_authority();
            let signal = crate::kernel::LinuxSignal::for_signal_number(signum).expect("signal");
            let persistent = carrick_abi::SigSet::EMPTY.with(signum);
            authority.set_blocked(carrick_abi::SigSet::EMPTY);
            authority.enqueue_thread_standard(signal, None);
            let dequeued = authority
                .take_lowest_in(carrick_abi::SigSet::EMPTY.with(signum))
                .expect("temporary mask reserves default signal");
            let (action_generation, action) = authority.action_with_generation(signal);
            let reserved = crate::vcpu_loop::continuation::ReservedSignal::kernel(
                authority.clone(),
                dequeued,
                action_generation,
                action,
                persistent,
            );
            authority.set_blocked(persistent);

            let action = deliver_reserved_signal_with_restart(
                &mut NoopTrap::default(),
                &dispatcher,
                &context,
                Some(crate::linux_abi::LINUX_EINTR.guest_retval()),
                ThreadId::synthetic_for_tests(pid),
                None,
                Some(false),
                reserved,
            )
            .expect("reserved default delivery")
            .expect("default action");
            if expect_terminate {
                assert_eq!(action.term_signal, Some(signum));
                assert_eq!(action.stop_signal, None);
            } else {
                assert_eq!(action.term_signal, None);
                assert_eq!(action.stop_signal, Some(signum));
            }
            assert_eq!(authority.blocked(), persistent);
        }
    }

    #[test]
    fn reserved_default_action_wins_over_concurrent_sigaction_change() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("context");
        let authority = context.signal_authority();
        let signum = 10;
        let signal = crate::kernel::LinuxSignal::for_signal_number(signum).expect("SIGUSR1");
        authority.enqueue_thread_standard(signal, None);
        let dequeued = authority
            .take_lowest_in(carrick_abi::SigSet::EMPTY.with(signum))
            .expect("reserve default SIGUSR1");
        let (action_generation, action) = authority.action_with_generation(signal);
        let reserved = crate::vcpu_loop::continuation::ReservedSignal::kernel(
            authority.clone(),
            dequeued,
            action_generation,
            action,
            carrick_abi::SigSet::EMPTY,
        );
        let mut ignored = carrick_abi::LinuxSigaction::empty();
        ignored.sa_handler = carrick_abi::LINUX_SIG_IGN;
        authority.install_action(signal, ignored);

        let action = deliver_reserved_signal_with_restart(
            &mut NoopTrap::default(),
            &dispatcher,
            &context,
            Some(crate::linux_abi::LINUX_EINTR.guest_retval()),
            ThreadId::synthetic_for_tests(context.thread().key().tid.raw()),
            None,
            Some(false),
            reserved,
        )
        .expect("reserved default delivery")
        .expect("captured default action");
        assert_eq!(action.term_signal, Some(signum));
    }

    fn native_geometry() -> crate::page_profile::PageGeometry {
        crate::page_profile::PageGeometry {
            host_page_size: 16 * 1024,
            linux_page_size: 16 * 1024,
            native_profile: Some(carrick_spec::NativePageProfile::Native16k),
        }
    }

    #[test]
    fn ptrace_signal_stop_queued_native_signal_reports_and_resumes() {
        let _guard = PTRACE_SIGNAL_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::guest_cpu::init_child_table();
        let tracer_pid = std::process::id();
        let prepared = crate::guest_cpu::prepare_child_record_pre_fork(tracer_pid, 0, 0, false, 0)
            .expect("prepare native queued-signal child");
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            crate::guest_cpu::complete_child_record_post_fork_child();
            let dispatcher = SyscallDispatcher::with_page_geometry(native_geometry());
            dispatcher.set_ptrace_traceme_for_test();
            if !crate::guest_cpu::register_self_virtual_ptrace(tracer_pid) {
                unsafe { libc::_exit(70) };
            }
            let tid = ThreadId::main_from_host_pid();
            dispatcher.mark_signal_pending(
                &dispatcher.exact_signal_context_for_test(),
                tid,
                crate::linux_abi::LINUX_SIGUSR2,
            );
            let mut trap = NoopTrap::default();
            if deliver_pending_signal(
                &mut trap,
                &dispatcher,
                &dispatcher.exact_signal_context_for_test(),
                None,
                tid,
                None,
            )
            .is_err()
            {
                unsafe { libc::_exit(71) };
            }
            unsafe { libc::_exit(42) };
        }

        crate::guest_cpu::publish_prepared_child_record_parent_ref(prepared, child as u32);
        let mut stop_status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child, &mut stop_status, libc::WUNTRACED) },
            child
        );
        assert!(libc::WIFSTOPPED(stop_status));
        assert_eq!(libc::WSTOPSIG(stop_status), libc::SIGSTOP);
        let stop = crate::guest_cpu::report_child_virtual_ptrace_stop(child as u32)
            .expect("queued virtual stop");
        assert_eq!(stop.linux_signum(), crate::linux_abi::LINUX_SIGUSR2);
        assert!(crate::guest_cpu::resume_child_virtual_ptrace(stop));

        let mut exit_status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut exit_status, 0) }, child);
        assert!(libc::WIFEXITED(exit_status));
        assert_eq!(libc::WEXITSTATUS(exit_status), 42);
        let _ = crate::guest_cpu::reap_child_guest_ns(child as u32);
    }

    #[test]
    fn ptrace_signal_stop_queued_host_sigkill_remains_terminal() {
        let _guard = PTRACE_SIGNAL_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::guest_cpu::init_child_table();
        let parent = std::process::id();
        let prepared = crate::guest_cpu::prepare_child_record_pre_fork(parent, 0, 0, false, 0)
            .expect("prepare host queued-sigkill child");
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            crate::guest_cpu::complete_child_record_post_fork_child();
            let dispatcher = SyscallDispatcher::new();
            dispatcher.set_ptrace_traceme_for_test();
            let tid = ThreadId::main_from_host_pid();
            dispatcher.mark_signal_pending(
                &dispatcher.exact_signal_context_for_test(),
                tid,
                crate::linux_abi::LINUX_SIGKILL,
            );
            let mut trap = NoopTrap::default();
            let _ = deliver_pending_signal(
                &mut trap,
                &dispatcher,
                &dispatcher.exact_signal_context_for_test(),
                None,
                tid,
                None,
            );
            unsafe { libc::_exit(70) };
        }

        crate::guest_cpu::publish_prepared_child_record_parent_ref(prepared, child as u32);
        let mut exit_status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut exit_status, 0) }, child);
        assert!(libc::WIFSIGNALED(exit_status));
        assert_eq!(libc::WTERMSIG(exit_status), libc::SIGKILL);
        let _ = crate::guest_cpu::reap_child_guest_ns(child as u32);
    }

    #[test]
    fn default_sigcont_resumes_without_terminating() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.exact_signal_context_for_test();
        let tid = ThreadId::main_from_host_pid();
        dispatcher.mark_signal_pending(&context, tid, crate::linux_abi::LINUX_SIGCONT);

        let action = deliver_pending_signal(
            &mut NoopTrap::default(),
            &dispatcher,
            &context,
            None,
            tid,
            None,
        )
        .expect("deliver default SIGCONT")
        .expect("SIGCONT produces an explicit nonterminal action");

        assert_eq!(action.term_signal, None);
        assert_eq!(action.stop_signal, None);
    }

    #[test]
    fn initially_blocked_write_then_reader_close_returns_epipe_and_queues_sigpipe() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.exact_signal_context_for_test();
        let tid = context.thread().registry_id();
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let flags = unsafe { libc::fcntl(fds[1], libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let fill = [0u8; 4096];
        loop {
            let written = unsafe { libc::write(fds[1], fill.as_ptr().cast(), fill.len()) };
            if written < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN)
                );
                break;
            }
        }
        let mut write =
            crate::dispatch::BlockingHostWrite::for_tests(fds[1], vec![0x5a], 0, tid, true)
                .expect("pin blocked pipe writer");
        assert!(matches!(
            crate::dispatch::drive_blocking_host_write(&mut write),
            crate::dispatch::BlockingHostWriteStep::Wait
        ));
        assert_eq!(unsafe { libc::close(fds[0]) }, 0);
        let crate::dispatch::BlockingHostWriteStep::Done(outcome) =
            crate::dispatch::drive_blocking_host_write(&mut write)
        else {
            panic!("closed reader must complete the blocked write");
        };
        let outcome = raise_sigpipe_for_blocking_write(&dispatcher, &context, &write, outcome);
        assert_eq!(
            outcome,
            DispatchOutcome::Errno {
                errno: crate::linux_abi::LINUX_EPIPE
            }
        );
        assert!(
            context
                .signal_authority()
                .thread_pending()
                .contains(crate::linux_abi::LINUX_SIGPIPE)
        );
        assert_eq!(unsafe { libc::close(fds[1]) }, 0);
    }

    #[test]
    fn continuation_restart_decision_controls_real_handler_injection() {
        for expected in [false, true] {
            let dispatcher = SyscallDispatcher::new();
            let context = dispatcher.exact_signal_context_for_test();
            let tid = ThreadId::main_from_host_pid();
            let signal =
                crate::kernel::LinuxSignal::for_signal_number(crate::linux_abi::LINUX_SIGUSR1)
                    .expect("SIGUSR1");
            let mut action = carrick_abi::LinuxSigaction::empty();
            action.sa_handler = 0x1234;
            context.signal_authority().install_action(signal, action);
            dispatcher.mark_signal_pending(&context, tid, crate::linux_abi::LINUX_SIGUSR1);
            let mut trap = NoopTrap::default();
            let delivered = deliver_pending_signal_with_restart(
                &mut trap,
                &dispatcher,
                &context,
                Some(crate::linux_abi::LINUX_EINTR.guest_retval()),
                tid,
                None,
                Some(expected),
            )
            .expect("handler injection")
            .expect("pending handler");
            assert_eq!(delivered.term_signal, None);
            assert_eq!(trap.restart, expected);
        }
    }
}
