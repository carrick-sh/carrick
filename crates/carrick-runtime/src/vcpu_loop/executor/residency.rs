//! Lazy vCPU register residency tracking and materialization authority for HVPatch executors.

use crate::trap::TrapError;
use carrick_hal::threaded::GuestCpuState;
use carrick_kernel::kernel::objects::ExecutorId;

/// Typed residency generation counter for a persistent executor vCPU.
///
/// Bumping this generation invalidates any previous resident tokens held by
/// tasks that ran on this vCPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ResidencyGeneration(u64);

impl ResidencyGeneration {
    pub const INITIAL: Self = Self(1);

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Self {
        Self(self.0.wrapping_add(1).max(1))
    }
}

/// The authoritative register residency of a parked task.
///
/// A task is either `Materialized` with an exact architectural [`GuestCpuState`],
/// or `Resident` on an executor's vCPU with an exact [`ResidencyGeneration`].
///
/// Under the "rule in a comment is a bug" standard, this enum has no method
/// returning registers directly from `Resident`; consumers that need registers
/// must go through the typed accessor (`materialize` / `materialize_with`), which
/// requests materialization from the owning executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskCpuResidency {
    Materialized(GuestCpuState),
    Resident {
        executor: ExecutorId,
        generation: ResidencyGeneration,
    },
    /// Parked in the in-guest zone: the EL0 registers are in the zone
    /// record, which the host owns by the time the task is loaded (its
    /// handback made it runnable). The loader combines them with `base`.
    Zone {
        base: GuestCpuState,
        record: carrick_el1_abi::RecordRef,
    },
}

impl TaskCpuResidency {
    pub fn is_resident_on(&self, executor: ExecutorId, generation: ResidencyGeneration) -> bool {
        match self {
            Self::Resident {
                executor: resident_executor,
                generation: resident_generation,
            } => *resident_executor == executor && *resident_generation == generation,
            Self::Materialized(_) | Self::Zone { .. } => false,
        }
    }

    pub fn resident_authority(&self) -> Option<(ExecutorId, ResidencyGeneration)> {
        match self {
            Self::Resident {
                executor,
                generation,
            } => Some((*executor, *generation)),
            Self::Materialized(_) | Self::Zone { .. } => None,
        }
    }

    pub fn as_materialized(&self) -> Option<&GuestCpuState> {
        match self {
            Self::Materialized(cpu) => Some(cpu),
            Self::Resident { .. } | Self::Zone { .. } => None,
        }
    }

    /// Obtain the materialized CPU state through the typed accessor.
    ///
    /// If currently resident, forces snapshot through `materialize`, transitions
    /// self to `Materialized`, and returns a reference to the registers.
    pub fn materialize_with(
        &mut self,
        materialize: impl FnOnce(ExecutorId, ResidencyGeneration) -> Result<GuestCpuState, TrapError>,
    ) -> Result<&GuestCpuState, TrapError> {
        if let Self::Zone { base, record } = self {
            let cpu = materialize_zone(base, *record)?;
            *self = Self::Materialized(cpu);
        }
        match self {
            Self::Zone { .. } => unreachable!("zone residency materialized above"),
            Self::Materialized(cpu) => Ok(cpu),
            Self::Resident {
                executor,
                generation,
            } => {
                let cpu = materialize(*executor, *generation)?;
                *self = Self::Materialized(cpu);
                match self {
                    Self::Materialized(cpu) => Ok(cpu),
                    Self::Resident { .. } | Self::Zone { .. } => unreachable!(),
                }
            }
        }
    }
}

/// Restore a zone-parked task after its exact record returns to the host.
/// Guest operations resume from the record's EL0 context. A host-owned
/// operation only received a notification: its original syscall snapshot
/// remains authoritative until the host completes that operation.
pub(crate) fn materialize_zone(
    base: &GuestCpuState,
    record: carrick_el1_abi::RecordRef,
) -> Result<GuestCpuState, TrapError> {
    let zone = carrick_el1_abi::zone_tables()
        .ok_or_else(|| TrapError::Hypervisor("zone residency without zone tables".to_owned()))?;
    materialize_zone_in(zone, base, record)
}

fn materialize_zone_in(
    zone: &carrick_el1_abi::ZoneTables,
    base: &GuestCpuState,
    record: carrick_el1_abi::RecordRef,
) -> Result<GuestCpuState, TrapError> {
    let GuestCpuState::Aarch64V1(base) = base else {
        return Err(TrapError::Hypervisor(
            "zone residency on a non-AArch64 task".to_owned(),
        ));
    };
    let rec = zone
        .live(record)
        .ok_or_else(|| TrapError::Hypervisor(format!("zone record {record:?} is gone")))?;
    if !matches!(rec.claim(), carrick_el1_abi::Claim::Host { .. }) {
        return Err(TrapError::Hypervisor(format!(
            "zone record {record:?} is not host-owned: {:?}",
            rec.claim()
        )));
    }
    if rec.object_host_continuation() {
        if !rec.has_object_operation() || base.syscall_continuation.is_none() {
            return Err(TrapError::Hypervisor(
                "host-owned zone wait lost its operation or syscall continuation".to_owned(),
            ));
        }
        // park_host_rechecked excludes guest execution of this operation.
        // Its record is a wake receipt, not a completed EL0 syscall frame.
        // In particular, preserve the mailbox request across repeated owner
        // waits and executor migration so only complete_returned consumes it.
        return Ok(GuestCpuState::Aarch64V1(base.clone()));
    }
    // SAFETY: the host owns the record (checked above); its context is
    // frozen until the loader frees it.
    let parked = unsafe { *rec.ctx_mut() };
    let ctx = parked
        .host_resume(rec.resume_disposition())
        .ok_or_else(|| {
            TrapError::Hypervisor("owned zone continuation lost its native entry".to_owned())
        })?;
    let mut state = (**base).clone();
    state.gprs = ctx.x;
    // Zone settlement retained this job's translation state through its
    // stage-1 lease, even if EL1 switched to another task or the idle root.
    // The record owns the EL0 registers, not a hardware TTBR: scheduler-only
    // saves can leave its address metadata empty, and native lifecycle saves
    // carry a physical root without ASID bits. Preserve the task-owned TTBR
    // and use that same authority for both halves of its address space.
    state.ttbr1 = base.ttbr0;
    state.pc = ctx.pc;
    state.pstate = ctx.pstate;
    state.trap_pc = ctx.pc;
    state.trap_pstate = ctx.pstate;
    state.elr_el1 = ctx.pc;
    state.spsr_el1 = ctx.pstate;
    state.sp_el0 = ctx.sp_el0;
    state.tpidr_el0 = ctx.tpidr_el0;
    state.tpidrro_el0 = ctx.tpidrro_el0;
    state.contextidr_el1 = ctx.contextidr_el1;
    state.vregs = ctx.v;
    state.fpsr = ctx.fpsr as u32;
    state.fpcr = ctx.fpcr as u32;
    state.pending_resume_pc = None;
    state.last_syscall_nr = None;
    state.last_syscall_orig_x0 = 0;
    state.last_fault_esr = 0;
    state.syscall_continuation = None;
    Ok(GuestCpuState::from_aarch64_v1(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::ZoneTables;
    use carrick_hal::threaded::Aarch64SyscallContinuationV1;
    use carrick_sched_core::object_wait::{ObjectWaitKey, OperationToken, OwnedObjectWakeEffects};
    use carrick_sched_core::{BoundedSpin, RecordRef, ThreadIdentity, Waker};
    use std::cell::RefCell;

    fn zone() -> Box<ZoneTables> {
        // SAFETY: the shared zone ABI has an all-zero initial state. Heap
        // allocation avoids placing the complete carrier tables on the stack.
        unsafe {
            let raw = std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables>());
            assert!(!raw.is_null());
            Box::from_raw(raw.cast())
        }
    }

    fn pending_read() -> GuestCpuState {
        let GuestCpuState::Aarch64V1(cpu) =
            crate::vcpu_loop::executor::tests::test_guest_cpu_state(0x100)
        else {
            panic!("AArch64 fixture");
        };
        let mut cpu = (*cpu).clone();
        cpu.ttbr0 = (1 << 48) | 0x10000;
        cpu.ttbr1 = cpu.ttbr0;
        cpu.trap_pc = 0x8000;
        cpu.trap_pstate = 0x3c5;
        cpu.pending_resume_pc = Some(0x4004);
        cpu.last_syscall_nr = Some(63);
        cpu.last_syscall_orig_x0 = 7;
        cpu.syscall_continuation = Some(Aarch64SyscallContinuationV1 {
            sequence: 73,
            state: 1,
            trap_kind: 1,
            response_action: 0,
            flags: 0,
            native_nr: 63,
            args: [7, 0x6000, 0x2000, 0, 0, 0],
            x8: 63,
            resume_pc: 0x4004,
            spsr: 0,
            fp: 0x7000,
            lr: 0x4100,
            sp: 0x7100,
            esr: 0x15 << 26,
            return_value: 0,
            resume_x16: 0x1616,
            resume_x17: 0x1717,
        });
        GuestCpuState::from_aarch64_v1(cpu)
    }

    #[test]
    fn host_owned_memory_wait_keeps_syscall_through_two_wakes() {
        exercise_zone_wakes(true);
    }

    #[test]
    fn guest_zone_wait_resumes_el0_without_replaying_the_completed_syscall() {
        exercise_zone_wakes(false);
    }

    #[test]
    fn native_terminal_host_wake_does_not_return_after_exit_group() {
        let mut native = carrick_el1_abi::ThreadCtx::ZERO;
        native.pc = 0x4004;
        native.x[0] = 7;
        native.x[8] = 94;
        carrick_el1_linux::aarch64_process_tests::with_native_terminal_host_handback(
            native,
            |zone, record| {
                let restored = materialize_zone_in(zone, &pending_read(), record).unwrap();
                let GuestCpuState::Aarch64V1(cpu) = restored else {
                    panic!("AArch64 owner");
                };
                assert_ne!(
                    (cpu.pc, cpu.pstate & 0xf),
                    (native.pc, 0),
                    "terminal readiness must re-enter retained owner custody, never return from exit_group to EL0"
                );
                assert_eq!(
                    (cpu.ttbr0, cpu.ttbr1),
                    ((1 << 48) | 0x10000, (1 << 48) | 0x10000),
                    "a physical parked root must not erase the task's ASID"
                );
                let mut restored = native;
                restored.pc = cpu.pc;
                restored.pstate = cpu.pstate;
                restored.x = cpu.gprs;
                restored
            },
        );
    }

    fn exercise_zone_wakes(host_owned: bool) -> (Box<ZoneTables>, RecordRef) {
        let zone = zone();
        let key = ObjectWaitKey::metadata_request(17).unwrap();
        let delivered = RefCell::new(Vec::new());
        let complete =
            |owned: OwnedObjectWakeEffects<'_, carrick_el1_abi::Aarch64ParkedContext>| {
                let (_, effects) =
                    owned.deliver_handbacks(&mut |record| delivered.borrow_mut().push(record));
                assert!(!effects.queued_own);
            };
        zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &complete)
            .unwrap();
        let original = pending_read();
        let mut saved = original.clone();
        let mut retired = None;
        for round in 0..if host_owned { 2 } else { 1 } {
            let source = zone
                .admit_object_notification(key, &BoundedSpin(0), &complete)
                .unwrap();
            let record = zone
                .alloc_record(ThreadIdentity {
                    tid: 101,
                    serial: 101,
                    mm: 1,
                    file_table: 1,
                    generation: 1,
                    affinity: 0,
                    lifecycle_page: 0,
                    control_slot: 0,
                })
                .unwrap();
            let reference = zone.record_ref(record);
            let ctx = crate::vcpu_loop::zone::zone_ctx_from_state(
                &saved,
                crate::vcpu_loop::zone::ZoneExit::Syscall { completed: true },
            )
            .expect("a repeated owner wait still owns its syscall");
            // SAFETY: this newly allocated record has not been published.
            unsafe {
                *zone.record(record).ctx_mut() =
                    carrick_el1_abi::Aarch64ParkedContext::from_register(ctx, 0, 1, 1)
            };
            {
                let guard = zone
                    .object_wait_with_completion(key, &BoundedSpin(0), &complete)
                    .unwrap();
                let operation = OperationToken::metadata_request(17).unwrap();
                if host_owned {
                    guard.park_host_rechecked(guard.snapshot(), record, operation, || true)
                } else {
                    guard.park_rechecked(guard.snapshot(), record, operation, || true)
                }
                .unwrap();
            }
            assert!(materialize_zone_in(&zone, &saved, reference).is_err());
            source.publish(Waker::Host, &complete);
            assert_eq!(delivered.borrow_mut().pop(), Some(reference));
            saved = materialize_zone_in(&zone, &saved, reference).unwrap();
            let GuestCpuState::Aarch64V1(cpu) = &saved else {
                panic!("AArch64 restore");
            };
            if host_owned {
                assert_eq!(
                    cpu.syscall_continuation
                        .as_ref()
                        .map(|request| request.sequence),
                    Some(73),
                    "owner wake {round} must retain the original request"
                );
                assert_eq!(
                    saved, original,
                    "a host notification is not a syscall return"
                );
            } else {
                assert!(cpu.syscall_continuation.is_none());
                assert!(cpu.pending_resume_pc.is_none());
                assert!(cpu.last_syscall_nr.is_none());
                assert_eq!((cpu.trap_pc, cpu.trap_pstate), (ctx.pc, ctx.pstate));
                assert_eq!(cpu.gprs, ctx.x);
                assert_eq!(
                    (cpu.ttbr0, cpu.ttbr1),
                    ((1 << 48) | 0x10000, (1 << 48) | 0x10000),
                    "a scheduler-only save has no translation authority"
                );
            }
            let rec = zone.record(record);
            assert_eq!(rec.object_host_continuation(), host_owned);
            // SAFETY: the completion handed this exact record to the host.
            assert_eq!(
                unsafe { rec.take_object_operation() }
                    .unwrap()
                    .metadata_generation(),
                Some(17)
            );
            // SAFETY: the same host owns the record; consuming is one-shot.
            assert!(unsafe { rec.take_object_operation() }.is_none());
            zone.free_record(record);
            assert!(materialize_zone_in(&zone, &saved, reference).is_err());
            retired = Some(reference);
        }
        (zone, retired.unwrap())
    }

    #[test]
    fn recycled_owner_wait_record_restores_one_root_to_both_halves() {
        let (zone, retired) = exercise_zone_wakes(true);
        let record = zone
            .alloc_record(ThreadIdentity {
                tid: 102,
                serial: 102,
                mm: 1,
                file_table: 1,
                generation: 1,
                affinity: 0,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        let reference = zone.record_ref(record);
        assert_eq!(reference.id, retired.id, "exercise actual slot reuse");
        assert_ne!(reference, retired, "the allocation has a fresh incarnation");
        let mut saved = pending_read();
        let GuestCpuState::Aarch64V1(cpu) = &mut saved else {
            panic!("AArch64 fixture");
        };
        let cpu = std::sync::Arc::make_mut(cpu);
        cpu.ttbr0 = 0x4000;
        cpu.ttbr1 = 0x8000;
        let ctx = crate::vcpu_loop::zone::zone_ctx_from_state(
            &saved,
            crate::vcpu_loop::zone::ZoneExit::Syscall { completed: true },
        )
        .unwrap();
        // SAFETY: the freshly allocated record has not been published.
        unsafe {
            *zone.record(record).ctx_mut() =
                carrick_el1_abi::Aarch64ParkedContext::from_register(ctx, 0x4000, 1, 1)
        };
        let GuestCpuState::Aarch64V1(cpu) = &mut saved else {
            panic!("AArch64 fixture");
        };
        // zone_park retires the completed futex syscall before saving its CPU.
        std::sync::Arc::make_mut(cpu).syscall_continuation = None;
        let guard = zone
            .lock(
                ZoneTables::bucket_of_with_context(1, 0x6000),
                &BoundedSpin(0),
            )
            .unwrap();
        let seq = zone.next_seq(record);
        zone.enqueue(&guard, record, seq, 1, 0x6000, u32::MAX, 0)
            .unwrap();
        zone.publish_park(record, seq);
        let mut transfers = Vec::new();
        assert_eq!(
            zone.wake_host(
                &guard,
                1,
                0x6000,
                u32::MAX,
                1,
                false,
                &mut |transfer| transfers.push(transfer),
                &mut |_| panic!("host wake must return this record"),
            ),
            1
        );
        drop(guard);
        assert_eq!(transfers.len(), 1);
        assert_eq!(
            transfers.pop().unwrap().finish(&BoundedSpin(0)),
            Some(reference)
        );
        let restored = materialize_zone_in(&zone, &saved, reference)
            .expect("a completed futex must not inherit a previous owner's continuation");
        let GuestCpuState::Aarch64V1(cpu) = restored else {
            panic!("AArch64 fixture");
        };
        assert!(cpu.syscall_continuation.is_none());
        assert_eq!((cpu.trap_pc, cpu.trap_pstate), (ctx.pc, ctx.pstate));
        assert_eq!(cpu.gprs, ctx.x);
        assert_eq!(
            cpu.ttbr0, 0x4000,
            "resume the parked caller's published root"
        );
        assert_eq!(
            cpu.ttbr1, 0x4000,
            "both halves use the parked caller's root"
        );
        assert!(!zone.record(record).has_object_operation());
        zone.free_record(record);
        assert!(zone.live(reference).is_none());
    }

    #[derive(Default)]
    struct SignalBoundaryTrap {
        completed: Vec<i64>,
        injected: Vec<(Option<i64>, Option<u64>, bool)>,
    }

    impl carrick_hal::SyscallTrap for SignalBoundaryTrap {
        fn next_syscall(&mut self) -> Result<Option<carrick_hal::RawSyscall>, TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }
        fn current_pc(&self) -> Result<u64, TrapError> {
            Ok(0x8000)
        }
        fn last_syscall_nr(&self) -> Option<u64> {
            Some(63)
        }
        fn complete_syscall(&mut self, value: i64) -> Result<(), TrapError> {
            self.completed.push(value);
            Ok(())
        }
        fn execve_into(&mut self, _: &crate::memory::AddressSpace) -> Result<(), TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }
        fn inject_signal(&mut self, signal: carrick_hal::SignalInjection) -> Result<(), TrapError> {
            assert_eq!(
                self.completed.len(),
                1,
                "complete the syscall before its handler"
            );
            self.injected.push((
                signal.pending_syscall_retval,
                signal.interrupted_pc,
                signal.restart_syscall,
            ));
            Ok(())
        }
        fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
            Err(TrapError::UnsupportedPlatform)
        }
    }

    fn owner_event_within(
        service: &carrick_kernel::kernel::continuation::CarrierWaitService,
        token: carrick_kernel::kernel::continuation::ContinuationWakeToken,
        timeout: std::time::Duration,
    ) -> Option<
        Result<
            carrick_kernel::kernel::continuation::ContinuationEvent,
            carrick_kernel::kernel::continuation::WaitServiceError,
        >,
    > {
        use std::future::Future;
        use std::task::{Context, Poll, Wake, Waker};

        struct ThreadWaker(std::thread::Thread);
        impl Wake for ThreadWaker {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.unpark();
            }
        }

        let start = std::time::Instant::now();
        let mut future = std::pin::pin!(service.event(token));
        let waker = Waker::from(std::sync::Arc::new(ThreadWaker(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                return Some(value);
            }
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return None;
            }
            std::thread::park_timeout(timeout.saturating_sub(elapsed));
        }
    }

    #[test]
    fn prepared_copyout_signals_use_production_delivery_and_linux_restart_classes() {
        use carrick_hal::SyscallTrap;
        use carrick_kernel::kernel::continuation::{
            CarrierWaitService, ContinuationCapture, RestartClass, RestartDecision, ZoneWait,
        };

        for (index, (nr, restart, sa_restart, expected)) in [
            (
                carrick_abi::syscall::nr::FSTAT.raw(),
                RestartClass::RestartNoIntr,
                false,
                RestartDecision::Restart,
            ),
            (
                carrick_abi::syscall::nr::WAIT4.raw(),
                RestartClass::RestartSyscall,
                false,
                RestartDecision::NoRestart,
            ),
            (
                carrick_abi::syscall::nr::WAIT4.raw(),
                RestartClass::RestartSyscall,
                true,
                RestartDecision::Restart,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
            let (process, context) =
                crate::hvpatch::process_context_for_tests(71_300 + index as i32);
            dispatcher.bind_hvpatch_process(std::sync::Arc::new(process.clone()));
            let kernel = std::sync::Arc::new(crate::vcpu_loop::KernelState::new(
                dispatcher,
                std::sync::Arc::new(crate::vcpu_loop::tests::EndpointTestSignalPump),
                std::sync::Arc::new(crate::vcpu_loop::tests::EndpointTestSignalArrival),
                Some(process),
                None,
            ));
            let mm = context.shared().mm().id();
            let mut saved = pending_read();
            let GuestCpuState::Aarch64V1(cpu) = &mut saved else {
                panic!("AArch64 fixture");
            };
            std::sync::Arc::make_mut(cpu).mm_generation = mm.raw();
            let generation = context
                .thread()
                .publish_initial_task_state(carrick_kernel::kernel::objects::MigratableTaskState {
                    cpu: saved,
                    mm,
                    asid_generation: 1,
                })
                .unwrap();
            let capture = ContinuationCapture::new(
                &context,
                generation,
                carrick_kernel::dispatch::SyscallRequest::new(
                    nr,
                    crate::compat::SyscallArgs([3, 0x6000, 0, 0x7000, 0, 0]),
                ),
                restart,
            )
            .unwrap();
            let continuation = crate::vcpu_loop::zone::owner_zone_continuation_for_resume(
                &crate::vcpu_loop::binding::OwnedSyscallResume::PreparedCopyout(
                    if restart == RestartClass::RestartNoIntr {
                        carrick_kernel::dispatch::PreparedCopyoutRestart::NoIntr
                    } else {
                        carrick_kernel::dispatch::PreparedCopyoutRestart::Sys
                    },
                ),
                capture,
                ZoneWait::new(carrick_el1_abi::RecordRef::PLACEHOLDER, 1),
            );
            let service = CarrierWaitService::new(std::sync::Arc::new(
                carrick_kernel::kernel::Scheduler::new(std::sync::Arc::clone(context.kernel())),
            ));
            let mut registration = service.prepare_registration(&continuation);
            service.enroll(&mut registration).unwrap();
            let token = registration.wake_token();
            let signal =
                carrick_kernel::kernel::LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGUSR1)
                    .unwrap();
            let mut action = carrick_abi::LinuxSigaction::empty();
            action.sa_handler = 0x5000;
            if sa_restart {
                action.sa_flags = carrick_abi::LINUX_SA_RESTART;
            }
            context.signal_authority().install_action(signal, action);
            assert!(
                context
                    .kernel()
                    .post_signal_to_task(context.task().key().id, signal, None,)
            );
            service.publish_signal_for_thread(context.thread().key());
            let event = owner_event_within(&service, token, std::time::Duration::from_secs(1))
                .expect("ordinary signal must wake the owner park")
                .expect("signal event");
            let mut result = continuation.resume(event, &context).unwrap();
            assert_eq!(result.restart(), expected);
            let effects = result.take_resume_effects();
            let mut trap = crate::vcpu_loop::tests::CrashCaptureTestEngine::default();
            trap.complete_syscall(carrick_abi::LINUX_EINTR.guest_retval())
                .unwrap();
            crate::vcpu_loop::service_signals_threaded(
                &kernel,
                &context,
                &mut trap,
                carrick_hal::ThreadId::synthetic_for_tests(context.thread().key().tid.raw()),
                0,
                Some(carrick_abi::LINUX_EINTR.guest_retval()),
                None,
                effects.restart,
                effects.reserved_signal,
                0,
            )
            .unwrap();
            assert_eq!(trap.injected_signals, 1);
            assert_eq!(trap.injected_signal_records.len(), 1);
            assert_eq!(
                trap.injected_signal_records[0].pending_syscall_retval,
                Some(carrick_abi::LINUX_EINTR.guest_retval())
            );
            assert_eq!(
                trap.injected_signal_records[0].restart_syscall,
                expected == RestartDecision::Restart
            );
            assert_eq!(
                trap.completed_syscalls,
                [carrick_abi::LINUX_EINTR.guest_retval()]
            );
        }
    }

    #[test]
    fn sigstop_interrupts_every_owner_park_before_release_and_sigcont_allows_retry() {
        use carrick_kernel::kernel::continuation::{
            CarrierWaitService, ContinuationCapture, RestartClass, ZoneWait,
        };

        let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
        let (process, context) = crate::hvpatch::process_context_for_tests(71_302);
        dispatcher.bind_hvpatch_process(std::sync::Arc::new(process.clone()));
        let kernel = std::sync::Arc::new(crate::vcpu_loop::KernelState::new(
            dispatcher,
            std::sync::Arc::new(crate::vcpu_loop::tests::EndpointTestSignalPump),
            std::sync::Arc::new(crate::vcpu_loop::tests::EndpointTestSignalArrival),
            Some(process),
            None,
        ));
        let mm = context.shared().mm().id();
        let mut saved = pending_read();
        let GuestCpuState::Aarch64V1(cpu) = &mut saved else {
            panic!("AArch64 fixture");
        };
        std::sync::Arc::make_mut(cpu).mm_generation = mm.raw();
        let generation = context
            .thread()
            .publish_initial_task_state(carrick_kernel::kernel::objects::MigratableTaskState {
                cpu: saved,
                mm,
                asid_generation: 1,
            })
            .unwrap();
        let make_continuation = |seq| {
            crate::vcpu_loop::zone::owner_zone_continuation_for_resume(
                &crate::vcpu_loop::binding::OwnedSyscallResume::PreparedCopyout(
                    carrick_kernel::dispatch::PreparedCopyoutRestart::NoIntr,
                ),
                ContinuationCapture::new(
                    &context,
                    generation,
                    carrick_kernel::dispatch::SyscallRequest::new(
                        carrick_abi::syscall::nr::FSTAT.raw(),
                        crate::compat::SyscallArgs([3, 0x6000, 0, 0, 0, 0]),
                    ),
                    RestartClass::RestartNoIntr,
                )
                .unwrap(),
                ZoneWait::new(carrick_el1_abi::RecordRef::PLACEHOLDER, seq),
            )
        };
        let service = CarrierWaitService::new(std::sync::Arc::new(
            carrick_kernel::kernel::Scheduler::new(std::sync::Arc::clone(context.kernel())),
        ));
        let continuation = make_continuation(1);
        let mut registration = service.prepare_registration(&continuation);
        service.enroll(&mut registration).unwrap();
        let token = registration.wake_token();
        let stop =
            carrick_kernel::kernel::LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP)
                .unwrap();
        assert!(
            context
                .kernel()
                .post_signal_to_task(context.task().key().id, stop, None)
        );
        service.publish_signal_for_thread(context.thread().key());
        let event = owner_event_within(&service, token, std::time::Duration::from_secs(1))
            .expect("SIGSTOP must wake before owner release")
            .expect("SIGSTOP event");
        let mut result = continuation.resume(event, &context).unwrap();
        let effects = result.take_resume_effects();
        let mut engine = crate::vcpu_loop::tests::CrashCaptureTestEngine::default();
        crate::vcpu_loop::service_signals_threaded(
            &kernel,
            &context,
            &mut engine,
            carrick_hal::ThreadId::synthetic_for_tests(context.thread().key().tid.raw()),
            0,
            Some(carrick_abi::LINUX_EINTR.guest_retval()),
            None,
            effects.restart,
            effects.reserved_signal,
            0,
        )
        .unwrap();
        assert!(context.task().is_job_control_stopped());
        assert!(
            engine.completed_syscalls.is_empty(),
            "a stop changes task state without completing the parked syscall"
        );

        let cont =
            carrick_kernel::kernel::LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT)
                .unwrap();
        assert!(
            context
                .kernel()
                .post_signal_to_task(context.task().key().id, cont, None)
        );
        assert!(!context.task().is_job_control_stopped());
        crate::vcpu_loop::service_signals_threaded(
            &kernel,
            &context,
            &mut engine,
            carrick_hal::ThreadId::synthetic_for_tests(context.thread().key().tid.raw()),
            0,
            None,
            Some(0),
            None,
            None,
            0,
        )
        .unwrap();

        let retry = make_continuation(2);
        let mut retry_registration = service.prepare_registration(&retry);
        service.enroll(&mut retry_registration).unwrap();
        let retry_token = retry_registration.wake_token();
        service.publish_ready(retry_token);
        assert!(matches!(
            owner_event_within(&service, retry_token, std::time::Duration::from_secs(1))
                .expect("owner release must wake the continued retry")
                .expect("owner release event"),
            carrick_kernel::kernel::continuation::ContinuationEvent::Ready
        ));
    }

    #[test]
    fn signal_during_owner_memory_wait_completes_before_handler_and_keeps_restart_policy() {
        use carrick_hal::SyscallTrap;
        use carrick_kernel::kernel::continuation::{
            BlockedContinuation, ContinuationCapture, ContinuationEvent, ReservedSignal,
            RestartClass, ZoneWait,
        };
        for restart in [false, true] {
            let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
            let context = dispatcher.capture_one_task_context().unwrap();
            let mm = context.shared().mm().id();
            let mut saved = pending_read();
            let GuestCpuState::Aarch64V1(cpu) = &mut saved else {
                panic!("AArch64 fixture");
            };
            std::sync::Arc::make_mut(cpu).mm_generation = mm.raw();
            let generation = context
                .thread()
                .publish_initial_task_state(carrick_kernel::kernel::objects::MigratableTaskState {
                    cpu: saved.clone(),
                    mm,
                    asid_generation: 1,
                })
                .unwrap();
            let zone = zone();
            let key = ObjectWaitKey::metadata_request(17).unwrap();
            let complete =
                |owned: OwnedObjectWakeEffects<'_, carrick_el1_abi::Aarch64ParkedContext>| {
                    owned.deliver_handbacks(&mut |_| {});
                };
            zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &complete)
                .unwrap();
            let source = zone
                .admit_object_notification(key, &BoundedSpin(0), &complete)
                .unwrap();
            let record = zone
                .alloc_record(ThreadIdentity {
                    tid: context.thread().key().tid.raw() as u64,
                    serial: context.thread().key().serial.raw(),
                    mm: mm.raw(),
                    file_table: 1,
                    generation: 1,
                    affinity: 0,
                    lifecycle_page: 0,
                    control_slot: 0,
                })
                .unwrap();
            let reference = zone.record_ref(record);
            let seq = zone.next_seq(record);
            {
                let guard = zone
                    .object_wait_with_completion(key, &BoundedSpin(0), &complete)
                    .unwrap();
                guard
                    .park_host_rechecked(
                        guard.snapshot(),
                        record,
                        OperationToken::metadata_request(17).unwrap(),
                        || true,
                    )
                    .unwrap();
            }
            let capture = ContinuationCapture::new(
                &context,
                generation,
                carrick_kernel::dispatch::SyscallRequest::new(
                    63,
                    crate::compat::SyscallArgs([7, 0x6000, 0x2000, 0, 0, 0]),
                ),
                RestartClass::Never,
            )
            .unwrap();
            let continuation =
                BlockedContinuation::from_zone_park(capture, ZoneWait::new(reference, seq), None);

            // SIGUSR1 arrives while the exact owner operation is parked.
            let authority = context.signal_authority();
            let signal = carrick_kernel::kernel::LinuxSignal::for_signal_number(10).unwrap();
            let mut action = carrick_abi::LinuxSigaction::empty();
            action.sa_handler = 0x5000;
            action.sa_flags = if restart {
                carrick_abi::LINUX_SA_RESTART
            } else {
                0
            };
            authority.install_action(signal, action);
            authority.enqueue_thread_standard(signal, None);
            let dequeued = authority
                .take_lowest_in(carrick_abi::SigSet::EMPTY.with(10))
                .unwrap();
            let (action_generation, action) = authority.action_with_generation(signal);
            let reserved = ReservedSignal::kernel(
                authority.clone(),
                dequeued,
                action_generation,
                action,
                carrick_abi::SigSet::EMPTY,
            );
            source.publish(Waker::Host, &complete);
            let restored = materialize_zone_in(&zone, &saved, reference).unwrap();
            assert_eq!(restored, saved);
            let mut result = continuation
                .resume(ContinuationEvent::ReservedSignal(reserved), &context)
                .unwrap();
            let outcome = crate::vcpu_loop::zone::owner_wait_interruption(&result.completion, 0)
                .expect("a signal wake must complete the original call before handler delivery");
            let carrick_kernel::dispatch::DispatchOutcome::Errno { errno } = outcome else {
                panic!("interrupted owner wait must return EINTR");
            };
            assert_eq!(errno, carrick_abi::LINUX_EINTR);
            let reserved = result.take_reserved_signal().unwrap();
            let mut trap = SignalBoundaryTrap::default();
            trap.complete_syscall(errno.guest_retval()).unwrap();
            crate::vcpu_loop::signal::deliver_reserved_signal_with_restart(
                &mut trap,
                &dispatcher,
                &context,
                crate::vcpu_loop::signal::SignalRestartContext {
                    last_syscall_retval: Some(errno.guest_retval()),
                    interrupted_pc: None,
                    // The internal zone wait's Never policy cannot override
                    // the original read syscall's Linux restart policy.
                    continuation_restart: None,
                },
                carrick_hal::ThreadId::synthetic_for_tests(context.thread().key().tid.raw()),
                reserved,
            )
            .unwrap();
            assert_eq!(trap.injected, [(Some(-4), None, restart)]);
            assert_eq!(trap.completed, [-4]);
            // SAFETY: this test owns the exact host-handed-back record.
            assert!(unsafe { zone.record(record).take_object_operation() }.is_some());
            zone.free_record(record);
        }
    }
}
