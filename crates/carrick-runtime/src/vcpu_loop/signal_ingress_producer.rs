//! Owned host publication into the shared native signal ingress.

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_core_abi::{
        EntryEventIdentity, EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration,
        ExecutionBinding,
    };
    use carrick_el1_abi::{
        ExternalSignalRecord, ExternalSignalSource, SignalEventGeneration, SignalIngressQueue,
    };
    use carrick_personality_linux::signal::policy::Signal;
    use carrick_sched_core::{RecordId, RecordRef};
    use core::num::NonZeroU64;

    #[test]
    fn full_external_ingress_parks_exact_signal_and_continues_after_drain() {
        let queue = SignalIngressQueue::<2>::new();
        let binding = ExecutionBinding {
            task: EntryTaskKey::from_raw(41),
            generation: EntryGeneration::from_raw(11),
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
            tid: ThreadId::synthetic_for_tests(41),
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
