//! Owned host publication into the shared native signal ingress.

use carrick_core_abi::{EntryEventIdentity, ExecutionBinding};
use carrick_el1_abi::{
    ExternalSignalRecord, ExternalSignalSource, Lifecycle, SignalEventGeneration,
    SignalIngressAdmission, SignalIngressQueue,
};
use carrick_personality_linux::signal::policy::Signal;
use carrick_sched_core::RecordRef;
use core::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_EXTERNAL_EVENT: AtomicU64 = AtomicU64::new(1);

/// Exact host observation of one ring-serving native member. Its construction
/// comes from a captured KernelContext, not from a numeric Linux tid lookup.
#[derive(Clone, Copy)]
pub(crate) struct HostIngressTarget {
    binding: ExecutionBinding,
    record: RecordRef,
    bridge_thread: carrick_hal::ThreadId,
}

impl HostIngressTarget {
    pub(crate) fn from_context(context: &carrick_kernel::kernel::KernelContext) -> Option<Self> {
        if !context.lifecycle_page().gate().serves_ring() {
            return None;
        }
        let thread = context.thread();
        let tid = thread.key().tid;
        let binding = ExecutionBinding {
            task: carrick_core_abi::EntryTaskKey::from_raw(tid.raw() as u64),
            generation: carrick_core_abi::SnapshotGeneration::from_raw(
                context.task().key().serial.raw(),
            ),
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
        })
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
}

/// The exact event survives queue fullness in this executor. Each boundary
/// tries at most one publication, so full admission never spins or consumes
/// another signal from the bridge while the first remains owned here.
#[derive(Default)]
pub(crate) struct HostSignalIngressProducer {
    pending: Option<SignalIngressAdmission>,
}

impl HostSignalIngressProducer {
    pub(crate) const fn new() -> Self {
        Self { pending: None }
    }

    pub(crate) fn pending_event(&self) -> Option<ExternalSignalRecord> {
        self.pending.as_ref().map(SignalIngressAdmission::event)
    }

    pub(crate) fn publish<const N: usize>(
        &mut self,
        queue: &SignalIngressQueue<N>,
        target: Option<HostIngressTarget>,
        take_bridge_signal: impl FnOnce(i32) -> i32,
    ) -> Result<HostIngressStep, HostIngressError> {
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
        let generation = NEXT_EXTERNAL_EVENT
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| HostIngressError::EventGenerationExhausted)?;
        let signum = take_bridge_signal(target.bridge_thread.raw());
        if signum == 0 {
            return Ok(HostIngressStep::Idle);
        }
        let signal =
            Signal::from_number(signum).ok_or(HostIngressError::InvalidBridgeSignal(signum))?;
        let event = ExternalSignalRecord::new(
            EntryEventIdentity::from_binding(target.binding),
            target.binding,
            target.record,
            SignalEventGeneration::new(
                NonZeroU64::new(generation).ok_or(HostIngressError::EventGenerationExhausted)?,
            ),
            signal,
            ExternalSignalSource::Terminal,
        );
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
        EntryEventIdentity, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
        SnapshotGeneration,
    };
    use carrick_el1_abi::{
        ExternalSignalRecord, ExternalSignalSource, SignalEventGeneration, SignalIngressQueue,
    };
    use carrick_personality_linux::signal::policy::Signal;
    use carrick_sched_core::{RecordId, RecordRef};
    use core::num::NonZeroU64;

    #[test]
    fn host_target_requires_native_signal_domain_after_zone_binding() {
        let bootstrap = carrick_kernel::kernel::RootBootstrap::for_reference_model(
            100,
            carrick_hal::ThreadId::synthetic_for_tests(217),
            "ingress-owner".to_owned(),
        )
        .unwrap();
        let (_kernel, context) = carrick_kernel::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
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
        assert_eq!(target.bridge_thread.raw(), 217);
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
        };
        let mut producer = HostSignalIngressProducer::new();
        let mut consumed = 0;
        assert_eq!(
            producer
                .publish(&queue, Some(target), |_| {
                    consumed += 1;
                    2
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
        assert!(queue.take().is_none());
    }
}
