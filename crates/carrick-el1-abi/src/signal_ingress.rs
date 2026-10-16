//! Exact identity carried by an external event before native signal admission.
//!
//! The carrier publishes an event only for an admitted execution binding.
//! The native owner compares every identity component with current custody
//! before interpreting the source or admitting it to a pending queue.

use carrick_core_abi::{EntryEventIdentity, ExecutionBinding};
use carrick_sched_core::RecordRef;
use carrick_signal_core::policy::Signal;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

/// Transport protocol for the shared ARM EL1 / x86 CPL0 ingress record.
pub const SIGNAL_INGRESS_PROTOCOL: u64 = 5;

/// Shared queue capacity; event producers must retain ownership on fullness.
pub const SIGNAL_INGRESS_CAPACITY: usize = 64;

pub type SharedSignalIngressQueue = SignalIngressQueue<SIGNAL_INGRESS_CAPACITY>;

/// Field offsets participate in the image/host ABI check, not only sizes.
pub const fn signal_ingress_offsets_hash() -> u64 {
    let offsets = [
        core::mem::offset_of!(ExternalSignalRecord, identity) as u64,
        core::mem::offset_of!(ExternalSignalRecord, binding) as u64,
        core::mem::offset_of!(ExternalSignalRecord, record) as u64,
        core::mem::offset_of!(ExternalSignalRecord, event_generation) as u64,
        core::mem::offset_of!(ExternalSignalRecord, signal) as u64,
        core::mem::offset_of!(ExternalSignalRecord, source) as u64,
        core::mem::offset_of!(SignalIngressSlot, sequence) as u64,
        core::mem::offset_of!(SignalIngressSlot, record) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue, head) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue, tail) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue, drain_generation) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue, backpressure) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue, next_event_generation) as u64,
        core::mem::offset_of!(SharedSignalIngressQueue, slots) as u64,
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
pub struct ExternalSignalRecord {
    identity: EntryEventIdentity,
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
pub struct SignalIngressAdmission {
    event: ExternalSignalRecord,
    observed_drain: u64,
}

impl SignalIngressAdmission {
    pub const fn event(&self) -> ExternalSignalRecord {
        self.event
    }

    pub const fn observed_drain(&self) -> u64 {
        self.observed_drain
    }

    pub fn retry<const N: usize>(self, queue: &SignalIngressQueue<N>) -> Result<(), Self> {
        queue.admit(self.event)
    }

    pub const fn into_event(self) -> ExternalSignalRecord {
        self.event
    }
}

impl ExternalSignalRecord {
    pub const fn new(
        identity: EntryEventIdentity,
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

    pub const fn identity(self) -> EntryEventIdentity {
        self.identity
    }

    pub const fn binding(self) -> ExecutionBinding {
        self.binding
    }

    pub const fn record(self) -> RecordRef {
        self.record
    }

    pub const fn source(self) -> ExternalSignalSource {
        self.source
    }

    pub const fn event_generation(self) -> SignalEventGeneration {
        self.event_generation
    }

    /// Authentication is an exact match with live owner custody, including
    /// the record incarnation. The caller must obtain these values afresh.
    pub fn matches_live(
        self,
        identity: EntryEventIdentity,
        binding: ExecutionBinding,
        record: RecordRef,
    ) -> bool {
        self.identity.issued()
            && self.identity == identity
            && self.identity.matches(binding)
            && self.binding == binding
            && self.record == record
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
    drain_generation: AtomicU64,
    /// Sticky until queue reset: a full admission needs a host boundary when
    /// any guest consumer frees space. Only event drains pay that boundary.
    backpressure: AtomicU64,
    next_event_generation: AtomicU64,
    slots: [SignalIngressSlot; N],
}

#[cfg(not(target_os = "none"))]
impl<const N: usize> Default for SignalIngressQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> SignalIngressQueue<N> {
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
            core::ptr::addr_of_mut!((*ptr).backpressure).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr).next_event_generation).write(AtomicU64::new(1));
            let slots = core::ptr::addr_of_mut!((*ptr).slots).cast::<SignalIngressSlot>();
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
            backpressure: AtomicU64::new(0),
            next_event_generation: AtomicU64::new(1),
            slots: core::array::from_fn(|index| SignalIngressSlot {
                sequence: AtomicU64::new(index as u64),
                record: UnsafeCell::new(MaybeUninit::uninit()),
            }),
        }
    }

    pub fn drain_generation(&self) -> u64 {
        self.drain_generation.load(Ordering::Acquire)
    }

    /// A producer retained an owned admission after observing full capacity.
    pub fn backpressure_waiting(&self) -> bool {
        self.backpressure.load(Ordering::Acquire) != 0
    }

    /// One transport-owned sequence shared by every host producer. An
    /// exhausted sequence refuses publication before the bridge is dequeued.
    pub fn issue_event_generation(&self) -> Option<SignalEventGeneration> {
        let raw = self
            .next_event_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()?;
        Some(SignalEventGeneration::new(NonZeroU64::new(raw)?))
    }

    /// Capture the drain generation before attempting admission. A caller
    /// that parks on fullness retains the event and can compare this epoch
    /// after subscribing to the host wake source.
    pub fn admit(&self, event: ExternalSignalRecord) -> Result<(), SignalIngressAdmission> {
        let observed_drain = self.drain_generation();
        self.try_publish(event).map_err(|event| {
            self.backpressure.store(1, Ordering::Release);
            SignalIngressAdmission {
                event,
                observed_drain,
            }
        })
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

    #[test]
    fn shared_ingress_issues_distinct_event_generations() {
        let queue = SignalIngressQueue::<2>::new();
        let first = queue.issue_event_generation().unwrap();
        let second = queue.issue_event_generation().unwrap();
        assert_ne!(first, second);
        assert!(first.raw() < second.raw());
    }
    use carrick_core_abi::{EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration};
    use carrick_sched_core::RecordId;

    #[test]
    fn shared_ingress_initializes_in_place_before_publication() {
        let mut storage = core::mem::MaybeUninit::<SignalIngressQueue<2>>::uninit();
        // SAFETY: this aligned storage is exclusively owned until initialization
        // returns; the test retains it for every queue access.
        unsafe { SignalIngressQueue::<2>::initialize_at(storage.as_mut_ptr()) };
        // SAFETY: initialization completed before creating this reference.
        let queue = unsafe { storage.assume_init_ref() };
        assert_eq!(queue.drain_generation(), 0);
        assert_eq!(queue.take(), None);
    }

    #[test]
    fn external_event_rejects_reused_task_binding_and_record() {
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
        let identity = EntryEventIdentity::from_binding(binding);
        let event = ExternalSignalRecord::new(
            identity,
            binding,
            record,
            SignalEventGeneration::new(NonZeroU64::new(1).unwrap()),
            Signal::SEGV,
            ExternalSignalSource::HostFault,
        );
        assert!(event.matches_live(identity, binding, record));
        assert!(
            !event.matches_live(
                EntryEventIdentity::from_parts(
                    binding.task,
                    SnapshotGeneration::from_raw(12),
                    binding.thread_generation,
                )
                .unwrap(),
                binding,
                record
            )
        );
        assert!(!event.matches_live(
            identity,
            ExecutionBinding {
                generation: SnapshotGeneration::from_raw(12),
                ..binding
            },
            record
        ));
        assert!(!event.matches_live(
            identity,
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
        let identity = EntryEventIdentity::from_binding(binding);
        let make = |generation| {
            ExternalSignalRecord::new(
                identity,
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
        let identity = EntryEventIdentity::from_binding(binding);
        let event = |generation| {
            ExternalSignalRecord::new(
                identity,
                binding,
                record,
                SignalEventGeneration::new(NonZeroU64::new(generation).unwrap()),
                Signal::from_number(2).unwrap(),
                ExternalSignalSource::Terminal,
            )
        };
        queue.try_publish(event(1)).unwrap();
        queue.try_publish(event(2)).unwrap();
        assert!(!queue.backpressure_waiting());
        let admission = queue.admit(event(3)).unwrap_err();
        assert!(queue.backpressure_waiting());
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
                    let identity = EntryEventIdentity::from_binding(binding);
                    for index in 0..PER_PRODUCER {
                        let generation = producer * PER_PRODUCER + index + 1;
                        let mut pending = ExternalSignalRecord::new(
                            identity,
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
