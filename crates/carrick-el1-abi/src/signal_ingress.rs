//! Exact identity carried by an external event before native signal admission.
//!
//! The carrier publishes an event only for an admitted execution binding.
//! The native owner compares every identity component with current custody
//! before interpreting the source or admitting it to a pending queue.

use carrick_core_abi::ExecutionBinding;
use carrick_sched_core::RecordRef;
use carrick_signal_core::policy::Signal;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

/// Transport protocol for the shared ARM EL1 / x86 CPL0 ingress record.
pub const SIGNAL_INGRESS_PROTOCOL: u64 = 2;

/// Shared queue capacity; event producers must retain ownership on fullness.
pub const SIGNAL_INGRESS_CAPACITY: usize = 64;

pub type SharedSignalIngressQueue<I> = SignalIngressQueue<I, SIGNAL_INGRESS_CAPACITY>;

/// Field offsets participate in the image/host ABI check, not only sizes.
pub const fn signal_ingress_offsets_hash<I: Copy + Eq + Send>() -> u64 {
    let offsets = [
        core::mem::offset_of!(ExternalSignalRecord<I>, identity) as u64,
        core::mem::offset_of!(ExternalSignalRecord<I>, binding) as u64,
        core::mem::offset_of!(ExternalSignalRecord<I>, record) as u64,
        core::mem::offset_of!(ExternalSignalRecord<I>, event_generation) as u64,
        core::mem::offset_of!(ExternalSignalRecord<I>, signal) as u64,
        core::mem::offset_of!(ExternalSignalRecord<I>, source) as u64,
        core::mem::offset_of!(SignalIngressSlot<I>, sequence) as u64,
        core::mem::offset_of!(SignalIngressSlot<I>, record) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue<I>, head) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue<I>, tail) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue<I>, drain_generation) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue<I>, slots) as u64,
    ];
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut index = 0;
    while index < offsets.len() {
        hash = (hash ^ offsets[index]).wrapping_mul(0x100_0000_01b3);
        index += 1;
    }
    hash
}

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
pub struct ExternalSignalRecord<I: Copy + Eq + Send> {
    identity: I,
    binding: ExecutionBinding,
    record: RecordRef,
    event_generation: SignalEventGeneration,
    signal: Signal,
    source: ExternalSignalSource,
}

/// A producer retains this exact record when shared admission is full. The
/// observed drain generation lets its host continuation subscribe before
/// parking without losing a drain that races the full result.
#[derive(Debug, Eq, PartialEq)]
pub struct SignalIngressAdmission<I: Copy + Eq + Send> {
    event: ExternalSignalRecord<I>,
    observed_drain: u64,
}

impl<I: Copy + Eq + Send> SignalIngressAdmission<I> {
    pub const fn event(&self) -> ExternalSignalRecord<I> {
        self.event
    }

    pub const fn observed_drain(&self) -> u64 {
        self.observed_drain
    }

    pub fn retry<const N: usize>(self, queue: &SignalIngressQueue<I, N>) -> Result<(), Self> {
        queue.admit(self.event)
    }

    pub const fn into_event(self) -> ExternalSignalRecord<I> {
        self.event
    }
}

impl<I: Copy + Eq + Send> ExternalSignalRecord<I> {
    pub const fn new(
        identity: I,
        binding: ExecutionBinding,
        record: RecordRef,
        event_generation: SignalEventGeneration,
        signal: Signal,
        source: ExternalSignalSource,
    ) -> Self {
        Self {
            identity,
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
    pub fn matches_live(self, identity: I, binding: ExecutionBinding, record: RecordRef) -> bool {
        self.identity == identity && self.binding == binding && self.record == record
    }
}

#[repr(C)]
struct SignalIngressSlot<I: Copy + Eq + Send> {
    sequence: AtomicU64,
    record: UnsafeCell<MaybeUninit<ExternalSignalRecord<I>>>,
}

// The sequence publishes exclusive ownership before either side touches the
// record. A producer writes only after claiming its head position, and a
// consumer reads only after claiming its tail position.
unsafe impl<I: Copy + Eq + Send> Sync for SignalIngressSlot<I> {}

/// Bounded multi-producer/multi-consumer transport for external signal events.
/// Fullness returns the event to its producer; no event is dropped or copied
/// into a second pending authority. The caller owns its backpressure wait.
#[repr(C)]
pub struct SignalIngressQueue<I: Copy + Eq + Send, const N: usize> {
    head: AtomicU64,
    tail: AtomicU64,
    drain_generation: AtomicU64,
    slots: [SignalIngressSlot<I>; N],
}

#[cfg(not(target_os = "none"))]
impl<I: Copy + Eq + Send, const N: usize> Default for SignalIngressQueue<I, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: Copy + Eq + Send, const N: usize> SignalIngressQueue<I, N> {
    /// Initialize a fresh shared reservation before either side publishes its
    /// address. Writes each slot directly, without a queue-sized stack value.
    ///
    /// # Safety
    /// `ptr` must be aligned writable storage for this queue, exclusively
    /// owned for the call, and kept mapped while either side may access it.
    pub unsafe fn initialize_at(ptr: *mut Self) {
        assert!(N >= 2 && N.is_power_of_two() && N < isize::MAX as usize);
        // SAFETY: the caller owns the full aligned reservation. Each field is
        // written once before the queue is made visible to another thread.
        unsafe {
            core::ptr::addr_of_mut!((*ptr).head).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr).tail).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr).drain_generation).write(AtomicU64::new(0));
            let slots = core::ptr::addr_of_mut!((*ptr).slots).cast::<SignalIngressSlot<I>>();
            for index in 0..N {
                slots.add(index).write(SignalIngressSlot {
                    sequence: AtomicU64::new(index as u64),
                    record: UnsafeCell::new(MaybeUninit::uninit()),
                });
            }
        }
    }

    /// Host-only convenience for isolated tests; production region setup uses
    /// [`Self::initialize_at`] to avoid a queue-sized EL1/CPL0 stack value.
    #[cfg(not(target_os = "none"))]
    pub fn new() -> Self {
        assert!(N >= 2 && N.is_power_of_two() && N < isize::MAX as usize);
        Self {
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            drain_generation: AtomicU64::new(0),
            slots: core::array::from_fn(|index| SignalIngressSlot {
                sequence: AtomicU64::new(index as u64),
                record: UnsafeCell::new(MaybeUninit::uninit()),
            }),
        }
    }

    pub fn drain_generation(&self) -> u64 {
        self.drain_generation.load(Ordering::Acquire)
    }

    /// Capture the drain generation before attempting admission. A caller
    /// that parks on fullness retains the event and can compare this epoch
    /// after subscribing to the host wake source.
    pub fn admit(&self, event: ExternalSignalRecord<I>) -> Result<(), SignalIngressAdmission<I>> {
        let observed_drain = self.drain_generation();
        self.try_publish(event)
            .map_err(|event| SignalIngressAdmission {
                event,
                observed_drain,
            })
    }

    /// Publish once. On full, the exact event remains owned by the caller.
    pub fn try_publish(
        &self,
        event: ExternalSignalRecord<I>,
    ) -> Result<(), ExternalSignalRecord<I>> {
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
    pub fn take(&self) -> Option<ExternalSignalRecord<I>> {
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
                        self.drain_generation.fetch_add(1, Ordering::AcqRel);
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
    use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial};
    use core::num::NonZeroI32;

    #[test]
    fn shared_ingress_initializes_in_place_before_publication() {
        let mut storage = core::mem::MaybeUninit::<SignalIngressQueue<TaskKey, 2>>::uninit();
        // SAFETY: this aligned storage is exclusively owned until initialization
        // returns; the test retains it for every queue access.
        unsafe { SignalIngressQueue::<TaskKey, 2>::initialize_at(storage.as_mut_ptr()) };
        // SAFETY: initialization completed before creating this reference.
        let queue = unsafe { storage.assume_init_ref() };
        assert_eq!(queue.drain_generation(), 0);
        assert_eq!(queue.take(), None);
    }

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
        let queue = SignalIngressQueue::<TaskKey, 2>::new();
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
    fn full_queue_retains_owned_admission_until_drain() {
        let queue = SignalIngressQueue::<TaskKey, 2>::new();
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
        let event = |generation| {
            ExternalSignalRecord::new(
                task,
                binding,
                record,
                SignalEventGeneration::new(NonZeroU64::new(generation).unwrap()),
                Signal::from_number(2).unwrap(),
                ExternalSignalSource::Terminal,
            )
        };
        queue.try_publish(event(1)).unwrap();
        queue.try_publish(event(2)).unwrap();
        let admission = queue.admit(event(3)).unwrap_err();
        assert_eq!(admission.event(), event(3));
        let observed = admission.observed_drain();
        assert_eq!(queue.take(), Some(event(1)));
        assert!(queue.drain_generation() != observed);
        admission.retry(&queue).unwrap();
        assert_eq!(queue.take(), Some(event(2)));
        assert_eq!(queue.take(), Some(event(3)));
        assert_eq!(queue.take(), None);
    }

    #[test]
    fn concurrent_ingress_delivers_every_record_once() {
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::{Duration, Instant};

        const PER_PRODUCER: u64 = 128;
        const TOTAL: usize = (PER_PRODUCER * 2) as usize;
        let queue = Arc::new(SharedSignalIngressQueue::<TaskKey>::new());
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
