//! Linux pending-signal ownership, coalescing and delivery selection.
//!
//! Authority: signal(7), fork(2), execve(2). The owner serializes dequeue
//! and mask publication; signal-core supplies storage, not queue policy.

use alloc::collections::{BTreeMap, VecDeque};

use carrick_signal_core::policy::Signal;
use carrick_signal_core::{SignalSet, StandardSignalSlot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Queued,
    Coalesced,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingEntry<T> {
    pub signal: Signal,
    pub info: Option<T>,
}

/// One process- or thread-owned pending set. Extracts the kernel queue's
/// first-standard/FIFO-real-time algorithm. StandardSignalSlot explicitly
/// retains the first instance; real-time instances use a FIFO VecDeque. The
/// production PendingQueue's replacement flag is not used by this policy.
/// Presence selection and count are O(1), enqueue/dequeue O(log 64), never a
/// traversal of payloads or other owners. Allocation/RLIMIT admission is the
/// consuming owner's responsibility before enqueue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSignals<T> {
    present: SignalSet,
    standard: BTreeMap<Signal, StandardSignalSlot<Option<T>>>,
    realtime: BTreeMap<Signal, VecDeque<Option<T>>>,
    count: usize,
}

impl<T> Default for PendingSignals<T> {
    fn default() -> Self {
        Self {
            present: SignalSet::EMPTY,
            standard: BTreeMap::new(),
            realtime: BTreeMap::new(),
            count: 0,
        }
    }
}

impl<T> PendingSignals<T> {
    pub const fn present(&self) -> SignalSet {
        self.present
    }
    pub const fn len(&self) -> usize {
        self.count
    }
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn enqueue(&mut self, signal: Signal, info: Option<T>) -> EnqueueOutcome {
        if signal.is_realtime() {
            self.realtime.entry(signal).or_default().push_back(info);
        } else if !self.standard.entry(signal).or_default().publish_first(info) {
            return EnqueueOutcome::Coalesced;
        }
        self.present = self.present.with(signal);
        self.count += 1;
        EnqueueOutcome::Queued
    }

    pub fn take_in(&mut self, selected: SignalSet) -> Option<PendingEntry<T>> {
        let signal = Signal::from_number(self.present.intersect(selected).lowest()?)?;
        let info = if signal.is_realtime() {
            let queue = self.realtime.get_mut(&signal)?;
            let info = queue.pop_front()?;
            if queue.is_empty() {
                self.realtime.remove(&signal);
                self.present = self.present.without(signal);
            }
            info
        } else {
            let info = self.standard.remove(&signal)?.take()?;
            self.present = self.present.without(signal);
            info
        };
        self.count -= 1;
        Some(PendingEntry { signal, info })
    }

    /// Discard all selected instances (ignore installation/job control).
    /// Work depends on at most 64 signal keys, never queued payload population
    /// except destruction of the discarded payloads themselves.
    pub fn discard(&mut self, selected: SignalSet) {
        self.standard.retain(|signal, _| {
            if selected.contains(*signal) {
                self.count -= 1;
                false
            } else {
                true
            }
        });
        self.realtime.retain(|signal, queue| {
            if selected.contains(*signal) {
                self.count -= queue.len();
                false
            } else {
                true
            }
        });
        self.present = self.present.difference(selected);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingOwner {
    Thread,
    Process,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingDelivery<T> {
    pub owner: PendingOwner,
    pub entry: PendingEntry<T>,
}

/// Preserve the kernel's lowest-number selection and thread-first same-number
/// tie. signal(7) specifies RT number/FIFO ordering, not cross-owner ties.
pub fn take_pending<T>(
    thread: &mut PendingSignals<T>,
    process: &mut PendingSignals<T>,
    selected: SignalSet,
) -> Option<PendingDelivery<T>> {
    let thread_signal = thread.present.intersect(selected).lowest();
    let process_signal = process.present.intersect(selected).lowest();
    let owner = match (thread_signal, process_signal) {
        (None, None) => return None,
        (Some(_), None) => PendingOwner::Thread,
        (None, Some(_)) => PendingOwner::Process,
        (Some(t), Some(p)) if t <= p => PendingOwner::Thread,
        (Some(_), Some(_)) => PendingOwner::Process,
    };
    let entry = match owner {
        PendingOwner::Thread => thread.take_in(selected)?,
        PendingOwner::Process => process.take_in(selected)?,
    };
    Some(PendingDelivery { owner, entry })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaleTarget;

/// The owner key must carry its existing graph incarnation/generation. This
/// consumes an exact task key for a process queue, or exact thread key for a
/// thread queue, rather than inventing IDs or looking up a reusable raw PID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalInbox<K, T> {
    key: K,
    pending: PendingSignals<T>,
}

impl<K: Eq, T> SignalInbox<K, T> {
    pub fn new(key: K) -> Self {
        Self {
            key,
            pending: PendingSignals::default(),
        }
    }
    pub fn pending(&self) -> &PendingSignals<T> {
        &self.pending
    }
    pub fn pending_mut(&mut self) -> &mut PendingSignals<T> {
        &mut self.pending
    }

    pub fn enqueue_for(
        &mut self,
        target: K,
        signal: Signal,
        info: Option<T>,
    ) -> Result<EnqueueOutcome, StaleTarget> {
        if target != self.key {
            return Err(StaleTarget);
        }
        Ok(self.pending.enqueue(signal, info))
    }

    pub fn for_fork(&self, child: K) -> Self {
        Self::new(child)
    }
    // Exec keeps this owner and its pending queue unchanged.
}
