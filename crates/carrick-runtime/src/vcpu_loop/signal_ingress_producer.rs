//! Owned host publication into the shared native signal ingress.

use carrick_core_abi::{EntryEventIdentity, ExecutionBinding};
use carrick_el1_abi::{
    ExternalSignalRecord, ExternalSignalSource, Lifecycle, SignalIngressAdmission,
    SignalIngressQueue,
};
use carrick_personality_linux::signal::policy::Signal;
use carrick_sched_core::RecordRef;

/// Exact host observation of one ring-serving native member. Its construction
/// comes from a captured KernelContext, not from a numeric Linux tid lookup.
#[derive(Clone, Copy)]
pub(crate) struct HostIngressTarget {
    binding: ExecutionBinding,
    record: RecordRef,
    bridge_thread: carrick_hal::ThreadId,
    process_id: carrick_core_abi::EntryTaskKey,
    process_birth: carrick_core_abi::BirthSerial,
}

impl HostIngressTarget {
    pub(crate) fn from_context(context: &carrick_kernel::kernel::KernelContext) -> Option<Self> {
        if !context.lifecycle_page().gate().serves_ring() {
            return None;
        }
        let thread = context.thread();
        let execution_generation = thread.execution_state().generation()?;
        let tid = thread.key().tid;
        let binding = ExecutionBinding {
            task: carrick_core_abi::EntryTaskKey::from_raw(tid.raw() as u64),
            generation: carrick_core_abi::SnapshotGeneration::from_raw(execution_generation.raw()),
            mm: carrick_core_abi::EntryMmKey::from_raw(context.shared().mm().id().raw()),
            thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(
                thread.key().serial.raw(),
            ),
        };
        if !binding.issued() {
            return None;
        }
        let control = thread.control_slot();
        if !control.native_signal_owner() {
            return None;
        }
        Some(Self {
            binding,
            record: control.zone_record()?,
            bridge_thread: thread.registry_id(),
            process_id: carrick_core_abi::EntryTaskKey::from_raw(
                context.task().key().id.raw() as u64
            ),
            process_birth: carrick_core_abi::BirthSerial::of_task(context.task().key().serial),
        })
    }

    fn thread_event(
        self,
        generation: carrick_el1_abi::SignalEventGeneration,
        signal: Signal,
        source: ExternalSignalSource,
    ) -> ExternalSignalRecord {
        ExternalSignalRecord::new(
            EntryEventIdentity::from_binding(self.binding),
            self.binding,
            self.record,
            generation,
            signal,
            source,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostIngressStep {
    Idle,
    Published,
    Parked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostIngressError {
    EventGenerationExhausted,
    InvalidBridgeSignal(i32),
    DeferredInZoneSignalPending,
}

/// The exact event survives queue fullness in this executor. Each boundary
/// tries at most one publication, so full admission never spins or consumes
/// another signal from the bridge while the first remains owned here.
#[derive(Default)]
pub(crate) struct HostSignalIngressProducer {
    pending: Option<SignalIngressAdmission>,
    deferred_in_zone: Option<SignalIngressAdmission>,
}

impl HostSignalIngressProducer {
    pub(crate) const fn new() -> Self {
        Self {
            pending: None,
            deferred_in_zone: None,
        }
    }

    pub(crate) fn pending_event(&self) -> Option<ExternalSignalRecord> {
        self.deferred_in_zone
            .as_ref()
            .or(self.pending.as_ref())
            .map(SignalIngressAdmission::event)
    }

    pub(crate) fn publish_deferred_in_zone<const N: usize>(
        &mut self,
        queue: &SignalIngressQueue<N>,
        target: HostIngressTarget,
        signal: Signal,
    ) -> Result<HostIngressStep, HostIngressError> {
        if self.deferred_in_zone.is_some() {
            return Err(HostIngressError::DeferredInZoneSignalPending);
        }
        let generation = queue
            .issue_event_generation()
            .ok_or(HostIngressError::EventGenerationExhausted)?;
        let event = target.thread_event(generation, signal, ExternalSignalSource::InZoneIpc);
        match queue.admit(event) {
            Ok(()) => Ok(HostIngressStep::Published),
            Err(pending) => {
                self.deferred_in_zone = Some(pending);
                Ok(HostIngressStep::Parked)
            }
        }
    }

    pub(crate) fn publish<const N: usize>(
        &mut self,
        queue: &SignalIngressQueue<N>,
        target: Option<HostIngressTarget>,
        take_bridge_signal: impl FnOnce(i32) -> Option<carrick_hal::PendingSignalEvent>,
    ) -> Result<HostIngressStep, HostIngressError> {
        if let Some(pending) = self.deferred_in_zone.take() {
            if queue.drain_generation() == pending.observed_drain() {
                self.deferred_in_zone = Some(pending);
                return Ok(HostIngressStep::Parked);
            }
            if let Err(pending) = pending.retry(queue) {
                self.deferred_in_zone = Some(pending);
                return Ok(HostIngressStep::Parked);
            }
            return Ok(HostIngressStep::Published);
        }
        if let Some(pending) = self.pending.take() {
            if queue.drain_generation() == pending.observed_drain() {
                self.pending = Some(pending);
                return Ok(HostIngressStep::Parked);
            }
            if let Err(pending) = pending.retry(queue) {
                self.pending = Some(pending);
                return Ok(HostIngressStep::Parked);
            }
            return Ok(HostIngressStep::Published);
        }
        let Some(target) = target else {
            return Ok(HostIngressStep::Idle);
        };
        let generation = queue
            .issue_event_generation()
            .ok_or(HostIngressError::EventGenerationExhausted)?;
        let Some(bridge_event) = take_bridge_signal(target.bridge_thread.raw()) else {
            return Ok(HostIngressStep::Idle);
        };
        let signum = bridge_event.signum;
        let signal =
            Signal::from_number(signum).ok_or(HostIngressError::InvalidBridgeSignal(signum))?;
        let (source, timer) = match bridge_event.origin {
            carrick_hal::PendingSignalOrigin::Host => (
                ExternalSignalSource::Terminal,
                carrick_el1_abi::ExternalSignalTimerInfo::default(),
            ),
            carrick_hal::PendingSignalOrigin::IntervalTimer => (
                ExternalSignalSource::IntervalTimer,
                carrick_el1_abi::ExternalSignalTimerInfo::default(),
            ),
            carrick_hal::PendingSignalOrigin::PosixTimer(info) => (
                ExternalSignalSource::PosixTimer,
                carrick_el1_abi::ExternalSignalTimerInfo {
                    id: info.id,
                    overrun: info.overrun,
                    value: info.value,
                },
            ),
        };
        let mut event = ExternalSignalRecord::new(
            EntryEventIdentity::from_binding(target.binding),
            target.binding,
            target.record,
            generation,
            signal,
            source,
        )
        .with_timer_info(timer);
        if bridge_event.scope == carrick_hal::PendingSignalScope::Process {
            event = event.for_process(target.process_id, target.process_birth);
        }
        match queue.admit(event) {
            Ok(()) => Ok(HostIngressStep::Published),
            Err(pending) => {
                // A guest drain may have raced the full observation before
                // it could see the backpressure marker. Retry once in that
                // case; later drains request the host boundary explicitly.
                if queue.drain_generation() != pending.observed_drain() {
                    match pending.retry(queue) {
                        Ok(()) => return Ok(HostIngressStep::Published),
                        Err(pending) => self.pending = Some(pending),
                    }
                } else {
                    self.pending = Some(pending);
                }
                Ok(HostIngressStep::Parked)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_core_abi::{
        BirthSerial, EntryEventIdentity, EntryMmKey, EntryTaskKey, EntryThreadGeneration,
        ExecutionBinding, SnapshotGeneration,
    };
    use carrick_el1_abi::{
        ExternalProcessTarget, ExternalSignalRecord, ExternalSignalSource, SignalEventGeneration,
        SignalIngressQueue,
    };
    use carrick_personality_linux::signal::policy::Signal;
    use carrick_sched_core::{RecordId, RecordRef, process::TaskSerial};
    use core::num::NonZeroU64;

    #[test]
    fn host_target_requires_native_signal_domain_after_zone_binding() {
        use carrick_kernel::kernel::continuation::test_support::publish;

        let bootstrap = carrick_kernel::kernel::RootBootstrap::for_reference_model(
            100,
            carrick_hal::ThreadId::synthetic_for_tests(217),
            "ingress-owner".to_owned(),
        )
        .unwrap();
        let (_kernel, context) = carrick_kernel::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
        assert_eq!(publish(&context, 0x700).raw(), 1);
        let control = context.thread().control_slot();
        control.bind_zone_record(RecordRef {
            id: RecordId::from_raw(4).unwrap(),
            incarnation: 9,
        });
        assert!(HostIngressTarget::from_context(&context).is_none());
        let custody = carrick_core::lifecycle::MemberControlCustody::retain(control).unwrap();
        custody.commit_registration();
        assert!(HostIngressTarget::from_context(&context).is_none());
        custody.commit_native_signal_owner();
        let target = HostIngressTarget::from_context(&context).unwrap();
        assert_eq!(target.binding.task.raw(), 100);
        assert_eq!(target.binding.generation.raw(), 1);
        assert_eq!(target.bridge_thread.raw(), 217);
        assert_eq!(
            target.process_birth,
            BirthSerial::of_task(context.task().key().serial)
        );
        assert_ne!(target.binding.generation.raw(), target.process_birth.raw());
    }

    #[test]
    fn deferred_in_zone_sigpipe_keeps_exact_thread_event_across_full_ingress() {
        use carrick_kernel::kernel::continuation::test_support::publish;

        let bootstrap = carrick_kernel::kernel::RootBootstrap::for_reference_model(
            109,
            carrick_hal::ThreadId::synthetic_for_tests(227),
            "in-zone-sigpipe".to_owned(),
        )
        .unwrap();
        let (_kernel, context) = carrick_kernel::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
        assert_eq!(publish(&context, 0x709).raw(), 1);
        let control = context.thread().control_slot();
        let record = RecordRef {
            id: RecordId::from_raw(4).unwrap(),
            incarnation: 9,
        };
        control.bind_zone_record(record);
        let custody = carrick_core::lifecycle::MemberControlCustody::retain(control).unwrap();
        custody.commit_registration();
        custody.commit_native_signal_owner();
        let target = HostIngressTarget::from_context(&context).unwrap();
        let queue = SignalIngressQueue::<2>::new();
        let mut producer = HostSignalIngressProducer::new();

        assert_eq!(
            producer
                .publish_deferred_in_zone(&queue, target, Signal::PIPE)
                .unwrap(),
            HostIngressStep::Published
        );
        assert_eq!(
            producer
                .publish_deferred_in_zone(&queue, target, Signal::PIPE)
                .unwrap(),
            HostIngressStep::Published
        );
        assert_eq!(
            producer
                .publish_deferred_in_zone(&queue, target, Signal::PIPE)
                .unwrap(),
            HostIngressStep::Parked
        );
        let retained = producer.pending_event().unwrap();
        assert_eq!(retained.signal(), Signal::PIPE);
        assert_eq!(retained.source(), ExternalSignalSource::InZoneIpc);
        assert_eq!(
            retained.scope(),
            carrick_el1_abi::ExternalSignalScope::Thread
        );
        assert_eq!(retained.record(), record);

        for _ in 0..2 {
            let queued = queue.take().unwrap();
            assert_eq!(queued.signal(), Signal::PIPE);
        }
        assert_eq!(
            producer.publish(&queue, None, |_| None).unwrap(),
            HostIngressStep::Published
        );
        assert!(producer.pending_event().is_none());
        let retried = queue.take().unwrap();
        assert_eq!(retried, retained);
    }

    #[test]
    fn serial_host_process_event_queued_across_exec_keeps_task_serial() {
        use carrick_kernel::kernel::continuation::test_support::publish;

        let bootstrap = carrick_kernel::kernel::RootBootstrap::for_reference_model(
            101,
            carrick_hal::ThreadId::synthetic_for_tests(218),
            "queued-exec-signal".to_owned(),
        )
        .unwrap();
        let (kernel, context) = carrick_kernel::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
        assert_eq!(publish(&context, 0x701).raw(), 1);
        let control = context.thread().control_slot();
        control.bind_zone_record(RecordRef {
            id: RecordId::from_raw(4).unwrap(),
            incarnation: 9,
        });
        let custody = carrick_core::lifecycle::MemberControlCustody::retain(control).unwrap();
        custody.commit_registration();
        custody.commit_native_signal_owner();
        let queue = SignalIngressQueue::<2>::new();
        let mut producer = HostSignalIngressProducer::new();
        carrick_signal_linux::publish_process_signal(2);
        assert_eq!(
            producer
                .publish(
                    &queue,
                    HostIngressTarget::from_context(&context),
                    carrick_signal_linux::take_pending_event_for,
                )
                .unwrap(),
            HostIngressStep::Published
        );
        let before = context.task().key();
        let prepared = kernel.prepare_exec(&context, None).unwrap();
        let replacement = kernel.commit_exec(prepared, None).unwrap();
        let queued = queue.take().unwrap();
        let expected_birth = BirthSerial::of_task(replacement.task().key().serial);
        assert_eq!(replacement.task().key().serial, before.serial);
        assert_eq!(queued.binding().generation.raw(), 1);
        assert_eq!(queued.process_birth(), Some(expected_birth));
        assert_ne!(queued.binding().generation.raw(), expected_birth.raw());
        assert_eq!(
            queued.process_id().raw(),
            replacement.task().key().id.raw() as u64
        );
        assert_eq!(
            queued.process_target(),
            ExternalProcessTarget::new(
                EntryTaskKey::from_raw(replacement.task().key().id.raw() as u64),
                expected_birth,
            )
        );
        assert_eq!(
            queued.scope(),
            carrick_el1_abi::ExternalSignalScope::Process
        );
    }

    #[test]
    fn serial_host_ingress_target_tracks_two_members_across_successive_execution_generations() {
        use carrick_abi::LinuxCloneFlags;
        use carrick_kernel::kernel::ClonePlan;
        use carrick_kernel::kernel::continuation::test_support::publish;
        use carrick_kernel::kernel::objects::ExecutorId;

        let bootstrap = carrick_kernel::kernel::RootBootstrap::for_reference_model(
            102,
            carrick_hal::ThreadId::synthetic_for_tests(219),
            "ingress-generations".to_owned(),
        )
        .unwrap();
        let (kernel, first) = carrick_kernel::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
        let second = kernel
            .reserve_thread_clone(
                &first,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .unwrap(),
                None,
            )
            .unwrap()
            .prepare(carrick_hal::ThreadId::synthetic_for_tests(220))
            .unwrap()
            .commit()
            .unwrap()
            .into_context()
            .unwrap();
        let child = kernel
            .reserve_fork(
                &first,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).unwrap(),
                "ingress-child".to_owned(),
                None,
            )
            .unwrap()
            .prepare_reference(carrick_hal::ThreadId::synthetic_for_tests(221))
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0;

        let bind_native = |context: &carrick_kernel::kernel::KernelContext,
                           raw_id: u32,
                           incarnation: u64| {
            let record = RecordRef {
                id: RecordId::from_raw(raw_id).unwrap(),
                incarnation,
            };
            let control = context.thread().control_slot();
            control.bind_zone_record(record);
            let custody = carrick_core::lifecycle::MemberControlCustody::retain(control).unwrap();
            custody.commit_registration();
            custody.commit_native_signal_owner();
            record
        };
        let first_record = bind_native(&first, 4, 9);
        let second_record = bind_native(&second, 5, 11);
        let child_record = bind_native(&child, 6, 13);

        assert!(
            HostIngressTarget::from_context(&first).is_none(),
            "uninitialized thread has no live execution snapshot generation"
        );

        assert_eq!(publish(&first, 0x701).raw(), 1);
        assert_eq!(publish(&second, 0x702).raw(), 1);
        assert_eq!(publish(&child, 0x703).raw(), 1);

        let advance_generation = |context: &carrick_kernel::kernel::KernelContext| {
            let thread = context.thread();
            let executor = ExecutorId::for_transitional_thread(thread.registry_id()).unwrap();
            let lease = thread.claim_runnable(executor).unwrap();
            thread.begin_switch_out(&lease).unwrap();
            thread.yield_from_executor(lease).unwrap();
            thread.execution_state().generation().unwrap()
        };

        // Advance first member to generation 2 and second member to generation 3
        // while both share the parent's durable task serial; forked child is at
        // generation 1 with a distinct durable task serial.
        assert_eq!(advance_generation(&first).raw(), 2);
        assert_eq!(advance_generation(&second).raw(), 2);
        assert_eq!(advance_generation(&second).raw(), 3);
        assert_eq!(second.task().key().serial, first.task().key().serial);
        assert_ne!(child.task().key().serial, first.task().key().serial);
        assert_ne!(first.task().key().serial.raw(), 2);
        assert_ne!(second.task().key().serial.raw(), 3);
        assert_ne!(child.task().key().serial.raw(), 1);

        let queue = SignalIngressQueue::<4>::new();
        let mut producer = HostSignalIngressProducer::new();

        for (context, record, expected_gen) in [
            (&first, first_record, 2u64),
            (&second, second_record, 3u64),
            (&child, child_record, 1u64),
        ] {
            let tid = context.thread().key().tid.raw();
            carrick_signal_linux::publish_pending_for(context.thread().registry_id().raw(), 10);
            assert_eq!(
                producer
                    .publish(
                        &queue,
                        HostIngressTarget::from_context(context),
                        carrick_signal_linux::take_pending_event_for,
                    )
                    .unwrap(),
                HostIngressStep::Published
            );
            let event = queue.take().unwrap();
            assert_eq!(event.scope(), carrick_el1_abi::ExternalSignalScope::Thread);
            assert_eq!(event.process_id(), EntryTaskKey::from_raw(0));
            assert_eq!(event.process_birth(), None);
            assert_eq!(event.process_target(), None);
            let live_binding = ExecutionBinding {
                task: EntryTaskKey::from_raw(tid as u64),
                generation: SnapshotGeneration::from_raw(expected_gen),
                mm: EntryMmKey::from_raw(context.shared().mm().id().raw()),
                thread_generation: EntryThreadGeneration::from_raw(
                    context.thread().key().serial.raw(),
                ),
            };
            assert_eq!(event.binding(), live_binding);
            assert!(event.matches_live(
                EntryEventIdentity::from_binding(live_binding),
                live_binding,
                record,
            ));
            let stale_binding = ExecutionBinding {
                generation: SnapshotGeneration::from_raw(expected_gen.saturating_sub(1).max(99)),
                ..live_binding
            };
            assert!(!event.matches_live(
                EntryEventIdentity::from_binding(stale_binding),
                stale_binding,
                record,
            ));
        }

        carrick_signal_linux::publish_process_signal(2);
        assert_eq!(
            producer
                .publish(
                    &queue,
                    HostIngressTarget::from_context(&second),
                    carrick_signal_linux::take_pending_event_for,
                )
                .unwrap(),
            HostIngressStep::Published
        );
        let proc_event = queue.take().unwrap();
        let expected_birth = BirthSerial::of_task(second.task().key().serial);
        assert_eq!(
            proc_event.scope(),
            carrick_el1_abi::ExternalSignalScope::Process
        );
        assert_eq!(proc_event.binding().generation.raw(), 3);
        assert_eq!(proc_event.process_birth(), Some(expected_birth));
        assert_ne!(proc_event.binding().generation.raw(), expected_birth.raw());
    }

    #[test]
    fn full_external_ingress_parks_exact_signal_and_continues_after_drain() {
        let queue = SignalIngressQueue::<2>::new();
        let binding = ExecutionBinding {
            task: EntryTaskKey::from_raw(41),
            generation: SnapshotGeneration::from_raw(11),
            mm: EntryMmKey::from_raw(301),
            thread_generation: EntryThreadGeneration::from_raw(101),
        };
        let record = RecordRef {
            id: RecordId::from_raw(4).unwrap(),
            incarnation: 9,
        };
        let event = |generation| {
            ExternalSignalRecord::new(
                EntryEventIdentity::from_binding(binding),
                binding,
                record,
                SignalEventGeneration::new(NonZeroU64::new(generation).unwrap()),
                Signal::from_number(2).unwrap(),
                ExternalSignalSource::Terminal,
            )
        };
        queue.admit(event(1)).unwrap();
        queue.admit(event(2)).unwrap();
        let target = HostIngressTarget {
            binding,
            record,
            bridge_thread: carrick_hal::ThreadId::synthetic_for_tests(41),
            process_id: EntryTaskKey::from_raw(41),
            process_birth: BirthSerial::of_task(TaskSerial::from_raw_u64(5).unwrap()),
        };
        let mut producer = HostSignalIngressProducer::new();
        let mut consumed = 0;
        assert_eq!(
            producer
                .publish(&queue, Some(target), |_| {
                    consumed += 1;
                    Some(carrick_hal::PendingSignalEvent {
                        signum: 2,
                        scope: carrick_hal::PendingSignalScope::Thread,
                        origin: carrick_hal::PendingSignalOrigin::Host,
                    })
                })
                .unwrap(),
            HostIngressStep::Parked
        );
        assert_eq!(consumed, 1);
        assert_eq!(
            producer.pending_event().map(|record| record.signal()),
            Some(Signal::from_number(2).unwrap())
        );
        assert_eq!(
            producer
                .publish(&queue, Some(target), |_| panic!("bridge dequeued twice"))
                .unwrap(),
            HostIngressStep::Parked
        );
        assert_eq!(queue.take(), Some(event(1)));
        assert_eq!(
            producer
                .publish(&queue, Some(target), |_| panic!("bridge dequeued twice"))
                .unwrap(),
            HostIngressStep::Published
        );
        assert!(producer.pending_event().is_none());
        assert_eq!(queue.take(), Some(event(2)));
        let delivered = queue.take().unwrap();
        assert_eq!(delivered.signal(), Signal::from_number(2).unwrap());
        assert_eq!(delivered.binding(), binding);
        assert_eq!(delivered.record(), record);
        assert_eq!(
            delivered.scope(),
            carrick_el1_abi::ExternalSignalScope::Thread
        );
        assert_eq!(delivered.process_birth(), None);
        assert!(queue.take().is_none());
    }

    #[test]
    fn serial_host_process_sigint_keeps_process_scope_through_producer() {
        let queue = SignalIngressQueue::<2>::new();
        let binding = ExecutionBinding {
            task: EntryTaskKey::from_raw(61),
            generation: SnapshotGeneration::from_raw(1),
            mm: EntryMmKey::from_raw(301),
            thread_generation: EntryThreadGeneration::from_raw(101),
        };
        let process_birth = BirthSerial::of_task(TaskSerial::from_raw_u64(5).unwrap());
        let target = HostIngressTarget {
            binding,
            record: RecordRef {
                id: RecordId::from_raw(4).unwrap(),
                incarnation: 9,
            },
            bridge_thread: carrick_hal::ThreadId::synthetic_for_tests(61),
            process_id: EntryTaskKey::from_raw(61),
            process_birth,
        };
        carrick_signal_linux::publish_process_signal(2);
        let mut producer = HostSignalIngressProducer::new();
        assert_eq!(
            producer
                .publish(
                    &queue,
                    Some(target),
                    carrick_signal_linux::take_pending_event_for
                )
                .unwrap(),
            HostIngressStep::Published
        );
        let sigint = queue.take().unwrap();
        assert_eq!(
            sigint.scope(),
            carrick_el1_abi::ExternalSignalScope::Process
        );
        assert_eq!(sigint.binding().generation.raw(), 1);
        assert_eq!(sigint.process_birth(), Some(process_birth));
        assert_ne!(sigint.binding().generation.raw(), process_birth.raw());

        let timer = carrick_signal_linux::PendingTimerInfo {
            id: 9,
            overrun: 2,
            value: 0x1234,
        };
        carrick_signal_linux::publish_process_timer_signal(14, Some(timer));
        assert_eq!(
            producer
                .publish(
                    &queue,
                    Some(target),
                    carrick_signal_linux::take_pending_event_for
                )
                .unwrap(),
            HostIngressStep::Published
        );
        let event = queue.take().unwrap();
        assert_eq!(event.scope(), carrick_el1_abi::ExternalSignalScope::Process);
        assert_eq!(event.binding().generation.raw(), 1);
        assert_eq!(event.process_birth(), Some(process_birth));
        assert_eq!(event.source(), ExternalSignalSource::PosixTimer);
        assert_eq!(event.timer_info().id, timer.id);
        assert_eq!(event.timer_info().overrun, timer.overrun);
        assert_eq!(event.timer_info().value, timer.value);
    }
}
