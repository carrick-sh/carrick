//! Host-free signal storage and Linux signal policy transitions.
//!
//! Storage slots are numbered 1 through 64. [`policy`] supplies typed Linux
//! asm-generic semantics; synchronization, ABI conversion, transport and guest
//! handler frames belong to the consuming owner. [`timer`] takes an injected
//! clock; it never reads a host clock or schedules a host wait.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod fasync;
pub mod policy;
pub mod timer;
pub mod wait;

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU64, Ordering};

/// Bit for a slot, or `None` outside the storage range.
pub fn pending_bit(slot: i32) -> Option<u64> {
    (1..=64).contains(&slot).then(|| 1u64 << (slot - 1))
}

/// A set of opaque signal slots, without disposition or numbering policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignalSet(u64);

impl SignalSet {
    pub const EMPTY: Self = Self(0);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn contains(self, signal: policy::Signal) -> bool {
        self.0 & signal.bit() != 0
    }

    pub const fn with(self, signal: policy::Signal) -> Self {
        Self(self.0 | signal.bit())
    }

    pub const fn without(self, signal: policy::Signal) -> Self {
        Self(self.0 & !signal.bit())
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub const fn lowest(self) -> Option<i32> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros() as i32 + 1)
        }
    }

    /// Apply caller-selected blocking and unmaskable sets.
    pub const fn deliverable(self, blocked: Self, unmaskable: Self) -> Self {
        Self(self.0 & (!blocked.0 | unmaskable.0))
    }
}

/// Atomic coalescing pending set. Publication and removal remain signal-safe.
#[derive(Default)]
pub struct PendingSet(AtomicU64);

impl PendingSet {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn load(&self) -> SignalSet {
        SignalSet::from_bits(self.0.load(Ordering::SeqCst))
    }

    pub fn publish(&self, set: SignalSet) {
        self.0.fetch_or(set.bits(), Ordering::SeqCst);
    }

    pub fn clear(&self) {
        self.0.store(0, Ordering::SeqCst);
    }

    /// Remove at most one selected slot, lowest first, even with concurrent consumers.
    pub fn take(&self, selected: SignalSet) -> Option<i32> {
        loop {
            let bits = self.0.load(Ordering::SeqCst);
            let slot = SignalSet::from_bits(bits & selected.bits()).lowest()?;
            let next = bits & !(1u64 << (slot - 1));
            if self
                .0
                .compare_exchange(bits, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(slot);
            }
        }
    }
}

/// Idempotent disposition-install bookkeeping. Routing eligibility is external.
#[derive(Default)]
pub struct DispositionSet(AtomicU64);

impl DispositionSet {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Invalid slots are treated as already installed, preserving a no-op.
    pub fn mark(&self, slot: i32) -> bool {
        pending_bit(slot).is_none_or(|bit| self.0.fetch_or(bit, Ordering::SeqCst) & bit != 0)
    }

    pub fn remove(&self, slot: i32) {
        if let Some(bit) = pending_bit(slot) {
            self.0.fetch_and(!bit, Ordering::SeqCst);
        }
    }

    pub fn contains(&self, slot: i32) -> bool {
        pending_bit(slot).is_some_and(|bit| self.bits() & bit != 0)
    }

    pub fn bits(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    pub fn clear(&self) {
        self.0.store(0, Ordering::SeqCst);
    }
}

/// Pending payload queue. Coalescing retains the first instance, including an
/// explicitly absent payload; otherwise instances are delivered FIFO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingQueue<T>(VecDeque<T>);

impl<T> Default for PendingQueue<T> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<T> PendingQueue<T> {
    pub fn publish(&mut self, value: T, coalesce: bool) {
        if coalesce && !self.0.is_empty() {
            return;
        }
        self.0.push_back(value);
    }
    pub fn take(&mut self) -> Option<T> {
        self.0.pop_front()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_personality_controls_unmaskable_slots() {
        let all = SignalSet::from_bits(u64::MAX);
        let custom = SignalSet::from_bits(pending_bit(42).unwrap());
        assert_eq!(all.deliverable(all, custom), custom);
        assert_eq!(all.deliverable(all, SignalSet::default()).bits(), 0);
        assert_eq!(pending_bit(0), None);
        assert_eq!(pending_bit(65), None);
        assert_eq!(pending_bit(64), Some(1 << 63));
    }

    #[test]
    fn pending_selection_preserves_other_slots_and_coalesces() {
        let pending = PendingSet::new();
        pending.publish(SignalSet::from_bits(5));
        pending.publish(SignalSet::from_bits(5));
        assert_eq!(pending.take(SignalSet::from_bits(4)), Some(3));
        assert_eq!(pending.take(SignalSet::from_bits(4)), None);
        assert_eq!(pending.take(SignalSet::from_bits(u64::MAX)), Some(1));
        assert_eq!(pending.load().bits(), 0);
    }

    #[test]
    fn concurrent_consumers_take_each_slot_once() {
        let pending = PendingSet::new();
        pending.publish(SignalSet::from_bits(u64::MAX));
        let count = core::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    while pending.take(SignalSet::from_bits(u64::MAX)).is_some() {
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(count.load(Ordering::SeqCst), 64);
    }

    #[test]
    fn disposition_install_reset_is_idempotent() {
        let installed = DispositionSet::new();
        assert!(!installed.mark(42));
        assert!(installed.mark(42));
        assert!(installed.mark(0));
        assert!(installed.contains(42));
        installed.remove(42);
        assert_eq!(installed.bits(), 0);
    }

    #[test]
    fn payload_policy_is_caller_selected() {
        let mut queue = PendingQueue::default();
        queue.publish(1, false);
        queue.publish(2, false);
        assert_eq!(queue.take(), Some(1));
        queue.publish(3, true);
        assert_eq!(queue.take(), Some(2));
        assert!(queue.is_empty());
    }

    #[test]
    fn standard_coalescing_retains_first_payload_including_absence() {
        let mut queue = PendingQueue::default();
        queue.publish(Some(1), true);
        queue.publish(Some(2), true);
        assert_eq!(queue.take(), Some(Some(1)));
        assert!(queue.is_empty());
        queue.publish(None, true);
        queue.publish(Some(3), true);
        assert_eq!(queue.take(), Some(None));
        assert!(queue.is_empty());
    }
}
