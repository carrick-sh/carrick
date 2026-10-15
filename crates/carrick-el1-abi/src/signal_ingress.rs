//! Exact identity carried by an external event before native signal admission.
//!
//! The carrier publishes an event only for an admitted execution binding.
//! The native owner compares every identity component with current custody
//! before interpreting the source or admitting it to a pending queue.

use carrick_core_abi::ExecutionBinding;
use carrick_sched_core::RecordRef;
use carrick_sched_core::process::TaskKey;
use carrick_signal_core::policy::Signal;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

/// Transport protocol for the shared ARM EL1 / x86 CPL0 ingress record.
pub const SIGNAL_INGRESS_PROTOCOL: u64 = 2;

/// Shared queue capacity; event producers must retain ownership on fullness.
pub const SIGNAL_INGRESS_CAPACITY: usize = 64;

pub type SharedSignalIngressQueue = SignalIngressQueue<SIGNAL_INGRESS_CAPACITY>;

/// Field offsets participate in the image/host ABI check, not only sizes.
pub const SIGNAL_INGRESS_OFFSETS_HASH: u64 = {
    let offsets = [
        core::mem::offset_of!(ExternalSignalRecord, task) as u64,
        core::mem::offset_of!(ExternalSignalRecord, binding) as u64,
        core::mem::offset_of!(ExternalSignalRecord, record) as u64,
        core::mem::offset_of!(ExternalSignalRecord, event_generation) as u64,
        core::mem::offset_of!(ExternalSignalRecord, signal) as u64,
        core::mem::offset_of!(ExternalSignalRecord, source) as u64,
        core::mem::offset_of!(SignalIngressSlot, sequence) as u64,
        core::mem::offset_of!(SignalIngressSlot, record) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue, head) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue, tail) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue, slots) as u64,
    ];
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut index = 0;
    while index < offsets.len() {
        hash = (hash ^ offsets[index]).wrapping_mul(0x100_0000_01b3);
        index += 1;
    }
    hash
};

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

#[repr(C)]
struct SignalIngressSlot {
    sequence: AtomicU64,
    record: UnsafeCell<MaybeUninit<ExternalSignalRecord>>,
}

// The sequence publishes exclusive ownership before either side touches the
// record. A producer writes only after claiming its head position, and a
// consumer reads only after claiming its tail position.
unsafe impl Sync for SignalIngressSlot {}

/// Bounded multi-producer/multi-consumer transport for external signal events.
/// Fullness returns the event to its producer; no event is dropped or copied
/// into a second pending authority. The caller owns its backpressure wait.
#[repr(C)]
pub struct SignalIngressQueue<const N: usize> {
    head: AtomicU64,
    tail: AtomicU64,
    slots: [SignalIngressSlot; N],
}

impl<const N: usize> Default for SignalIngressQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> SignalIngressQueue<N> {
    /// Initialize the shared storage once, before either host or guest uses it.
    pub fn new() -> Self {
        assert!(N >= 2 && N.is_power_of_two() && N < isize::MAX as usize);
        Self {
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            slots: core::array::from_fn(|index| SignalIngressSlot {
                sequence: AtomicU64::new(index as u64),
                record: UnsafeCell::new(MaybeUninit::uninit()),
            }),
        }
    }

    /// Publish once. On full, the exact event remains owned by the caller.
    pub fn try_publish(&self, event: ExternalSignalRecord) -> Result<(), ExternalSignalRecord> {
        let mut position = self.head.load(Ordering::Relaxed);
        loop {
            let slot = &self.slots[position as usize & (N - 1)];
            let sequence = slot.sequence.load(Ordering::Acquire);
            let difference = sequence.wrapping_sub(position) as i64;
            if difference == 0 {
                match self.head.compare_exchange_weak(
                    position,
                    position.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // SAFETY: the successful head claim uniquely owns this
                        // slot until release publication of its sequence.
                        unsafe { (*slot.record.get()).write(event) };
                        slot.sequence
                            .store(position.wrapping_add(1), Ordering::Release);
                        return Ok(());
                    }
                    Err(actual) => position = actual,
                }
            } else if difference < 0 {
                return Err(event);
            } else {
                position = self.head.load(Ordering::Relaxed);
            }
        }
    }

    /// Claim one published record. A concurrent unpublished producer does not
    /// make a partly written record visible.
    pub fn take(&self) -> Option<ExternalSignalRecord> {
        let mut position = self.tail.load(Ordering::Relaxed);
        loop {
            let slot = &self.slots[position as usize & (N - 1)];
            let sequence = slot.sequence.load(Ordering::Acquire);
            let difference = sequence.wrapping_sub(position.wrapping_add(1)) as i64;
            if difference == 0 {
                match self.tail.compare_exchange_weak(
                    position,
                    position.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // SAFETY: the tail claim uniquely owns the published
                        // value. The producer's release sequence made it live.
                        let event = unsafe { (*slot.record.get()).assume_init_read() };
                        slot.sequence
                            .store(position.wrapping_add(N as u64), Ordering::Release);
                        return Some(event);
                    }
                    Err(actual) => position = actual,
                }
            } else if difference < 0 {
                return None;
            } else {
                position = self.tail.load(Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
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

    #[test]
    fn full_ingress_returns_owned_event_and_preserves_fifo_order() {
        let queue = SignalIngressQueue::<2>::new();
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
        let make = |generation| {
            ExternalSignalRecord::new(
                task,
                binding,
                record,
                SignalEventGeneration::new(NonZeroU64::new(generation).unwrap()),
                Signal::SEGV,
                ExternalSignalSource::HostFault,
            )
        };
        assert_eq!(queue.try_publish(make(1)), Ok(()));
        assert_eq!(queue.try_publish(make(2)), Ok(()));
        assert_eq!(queue.try_publish(make(3)), Err(make(3)));
        assert_eq!(queue.take(), Some(make(1)));
        assert_eq!(queue.try_publish(make(3)), Ok(()));
        assert_eq!(queue.take(), Some(make(2)));
        assert_eq!(queue.take(), Some(make(3)));
        assert_eq!(queue.take(), None);
    }

    #[test]
    fn concurrent_ingress_delivers_every_record_once() {
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::{Duration, Instant};

        const PER_PRODUCER: u64 = 128;
        const TOTAL: usize = (PER_PRODUCER * 2) as usize;
        let queue = Arc::new(SharedSignalIngressQueue::new());
        let received = Arc::new(Mutex::new(std::vec::Vec::new()));
        let deadline = Instant::now() + Duration::from_secs(5);
        thread::scope(|scope| {
            for _ in 0..2 {
                let queue = queue.clone();
                let received = received.clone();
                scope.spawn(move || {
                    loop {
                        if let Some(event) = queue.take() {
                            let mut rows = received.lock().unwrap();
                            rows.push(event.event_generation().raw());
                            if rows.len() == TOTAL {
                                break;
                            }
                        } else {
                            if received.lock().unwrap().len() == TOTAL {
                                break;
                            }
                            assert!(Instant::now() < deadline, "ingress drain stalled");
                            thread::yield_now();
                        }
                    }
                });
            }
            for producer in 0..2u64 {
                let queue = queue.clone();
                scope.spawn(move || {
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
                    for index in 0..PER_PRODUCER {
                        let generation = producer * PER_PRODUCER + index + 1;
                        let mut pending = ExternalSignalRecord::new(
                            task,
                            binding,
                            record,
                            SignalEventGeneration::new(NonZeroU64::new(generation).unwrap()),
                            Signal::SEGV,
                            ExternalSignalSource::HostFault,
                        );
                        loop {
                            match queue.try_publish(pending) {
                                Ok(()) => break,
                                Err(owned) => {
                                    pending = owned;
                                    assert!(Instant::now() < deadline, "ingress admission stalled");
                                    thread::yield_now();
                                }
                            }
                        }
                    }
                });
            }
        });
        let mut rows = received.lock().unwrap().clone();
        rows.sort_unstable();
        assert_eq!(rows, (1..=TOTAL as u64).collect::<std::vec::Vec<_>>());
    }
}
