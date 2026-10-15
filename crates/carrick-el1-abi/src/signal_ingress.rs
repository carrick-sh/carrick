//! Exact identity carried by an external event before native signal admission.
//!
//! The carrier publishes an event only for an admitted execution binding.
//! The native owner compares every identity component with current custody
//! before interpreting the source or admitting it to a pending queue.

use carrick_core_abi::ExecutionBinding;
use carrick_sched_core::RecordRef;
use carrick_sched_core::process::TaskKey;
use carrick_signal_core::policy::Signal;
use core::num::NonZeroU64;

/// Transport protocol for the shared ARM EL1 / x86 CPL0 ingress record.
pub const SIGNAL_INGRESS_PROTOCOL: u64 = 1;

/// Event sequence issued by the external source, never reused for one binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SignalEventGeneration(NonZeroU64);

impl SignalEventGeneration {
    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> u64 {
        self.0.get()
    }
}

/// The host facility that observed an external signal event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ExternalSignalSource {
    Terminal = 1,
    Timer = 2,
    HostFault = 3,
}

/// Identity and source of one external event. The source-specific payload is
/// added with the producer; this record does not authorize signal delivery by
/// itself. In particular, a numeric Linux tid is never an identity check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ExternalSignalRecord {
    task: TaskKey,
    binding: ExecutionBinding,
    record: RecordRef,
    event_generation: SignalEventGeneration,
    signal: Signal,
    source: ExternalSignalSource,
}

impl ExternalSignalRecord {
    pub const fn new(
        task: TaskKey,
        binding: ExecutionBinding,
        record: RecordRef,
        event_generation: SignalEventGeneration,
        signal: Signal,
        source: ExternalSignalSource,
    ) -> Self {
        Self {
            task,
            binding,
            record,
            event_generation,
            signal,
            source,
        }
    }

    pub const fn signal(self) -> Signal {
        self.signal
    }

    pub const fn source(self) -> ExternalSignalSource {
        self.source
    }

    pub const fn event_generation(self) -> SignalEventGeneration {
        self.event_generation
    }

    /// Authentication is an exact match with live owner custody, including
    /// the record incarnation. The caller must obtain these values afresh.
    pub fn matches_live(self, task: TaskKey, binding: ExecutionBinding, record: RecordRef) -> bool {
        self.task == task && self.binding == binding && self.record == record
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_core_abi::{EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration};
    use carrick_sched_core::RecordId;
    use carrick_sched_core::process::{TaskId, TaskSerial};
    use core::num::NonZeroI32;

    #[test]
    fn external_event_rejects_reused_task_binding_and_record() {
        let task = TaskKey {
            id: TaskId::from_registry_allocation(NonZeroI32::new(41).unwrap()),
            serial: TaskSerial::from_registry_allocation(NonZeroU64::new(7).unwrap()),
        };
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
        let event = ExternalSignalRecord::new(
            task,
            binding,
            record,
            SignalEventGeneration::new(NonZeroU64::new(1).unwrap()),
            Signal::SEGV,
            ExternalSignalSource::HostFault,
        );
        assert!(event.matches_live(task, binding, record));
        assert!(!event.matches_live(
            TaskKey {
                serial: TaskSerial::from_registry_allocation(NonZeroU64::new(8).unwrap()),
                ..task
            },
            binding,
            record
        ));
        assert!(!event.matches_live(
            task,
            ExecutionBinding {
                generation: EntryGeneration::from_raw(12),
                ..binding
            },
            record
        ));
        assert!(!event.matches_live(
            task,
            binding,
            RecordRef {
                incarnation: 10,
                ..record
            }
        ));
    }
}
