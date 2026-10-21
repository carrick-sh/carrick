//! Shared affinity mutation and exact execution-residency notification.
use crate::SlotId;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AffinityResidencyToken(u64);
impl AffinityResidencyToken {
    pub const fn raw(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AffinityNotification {
    pub token: AffinityResidencyToken,
    pub slot: Option<SlotId>,
    pub cpu: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AffinityEpochExhausted;
pub trait AffinityNotifier {
    fn notify(&mut self, notification: AffinityNotification);
    fn supports_unrouted(&self) -> bool {
        false
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct AffinityAuthority {
    mask: AtomicU64,
    metadata: AtomicU64,
    next_epoch: AtomicU64,
    active_epoch: AtomicU64,
}
// CPU+1 needs 33 bits for the complete u32 input domain. SlotId is u8;
// its optional encoding needs nine bits. The remaining state is internal.
const CPU_MASK: u64 = (1 << 33) - 1;
const SLOT_SHIFT: u32 = 33;
const SLOT_MASK: u64 = 0x1ff << SLOT_SHIFT;
const NOTIFIED: u64 = 1 << 42;
const LOCKED: u64 = 1 << 63;

impl Default for AffinityAuthority {
    fn default() -> Self {
        Self::new()
    }
}
impl AffinityAuthority {
    pub const fn new() -> Self {
        Self {
            mask: AtomicU64::new(0),
            metadata: AtomicU64::new(0),
            next_epoch: AtomicU64::new(0),
            active_epoch: AtomicU64::new(0),
        }
    }

    /// Read the sole mask without taking the mutation lock.
    pub fn load(&self) -> u64 {
        self.mask.load(Ordering::Acquire)
    }

    /// Initialize unpublished storage without replacing an installed mask.
    pub fn initialize(&self, mask: u64) {
        let _guard = self.lock();
        if self.load() == 0 {
            self.mask.store(mask, Ordering::Release);
        }
    }

    /// Publish a mask and discharge its newly excluded residency before
    /// returning. Transport callbacks run after releasing the mutation lock.
    pub fn change(&self, mask: u64, notifier: &mut impl AffinityNotifier) {
        let unrouted = notifier.supports_unrouted();
        let notification = {
            let mut guard = self.lock();
            self.mask.store(mask, Ordering::Release);
            guard.notification(unrouted)
        };
        if let Some(notification) = notification {
            notifier.notify(notification);
        }
    }

    /// Start a fresh host residency, before the backend has a mailbox route.
    /// An unrouted notifier can already reach the exact host executor binding.
    pub fn bind(
        &self,
        cpu: u32,
        notifier: &mut impl AffinityNotifier,
    ) -> Result<AffinityResidencyToken, AffinityEpochExhausted> {
        let unrouted = notifier.supports_unrouted();
        let (token, notification) = {
            let mut guard = self.lock();
            let epoch = self
                .next_epoch
                .load(Ordering::Relaxed)
                .checked_add(1)
                .ok_or(AffinityEpochExhausted)?;
            self.next_epoch.store(epoch, Ordering::Relaxed);
            self.active_epoch.store(epoch, Ordering::Relaxed);
            guard.metadata = u64::from(cpu) + 1;
            (AffinityResidencyToken(epoch), guard.notification(unrouted))
        };
        if let Some(notification) = notification {
            notifier.notify(notification);
        }
        Ok(token)
    }

    /// Attach the actual guest route before entry. A change made while that
    /// route was absent is notified here unless a host notifier already did it.
    /// A route cannot be replaced within one epoch: retire and bind anew.
    pub fn attach(
        &self,
        token: AffinityResidencyToken,
        slot: SlotId,
        notifier: &mut impl AffinityNotifier,
    ) -> bool {
        let unrouted = notifier.supports_unrouted();
        let notification = {
            let mut guard = self.lock();
            if self.active_epoch.load(Ordering::Relaxed) != token.0 {
                return false;
            }
            let encoded = (u64::from(slot.raw()) + 1) << SLOT_SHIFT;
            let previous = guard.metadata & SLOT_MASK;
            if previous != 0 && previous != encoded {
                return false;
            }
            guard.metadata = (guard.metadata & !SLOT_MASK) | encoded;
            guard.notification(unrouted)
        };
        if let Some(notification) = notification {
            notifier.notify(notification);
        }
        true
    }

    /// Retire only the residency named by this exact non-reused token.
    pub fn unbind(&self, token: AffinityResidencyToken) -> bool {
        let mut guard = self.lock();
        if self.active_epoch.load(Ordering::Relaxed) != token.0 {
            return false;
        }
        self.active_epoch.store(0, Ordering::Relaxed);
        guard.metadata = 0;
        true
    }

    /// Seed a pre-birth mask, refusing an authority with an active residency.
    pub fn initialize_quiescent(&self, mask: u64) -> bool {
        let _guard = self.lock();
        if self.active_epoch.load(Ordering::Relaxed) != 0 {
            return false;
        }
        self.mask.store(mask, Ordering::Release);
        true
    }

    /// Scrub exclusively owned pre-birth storage. Epochs survive reuse, so a
    /// delayed token can never authenticate the next occupant of this cell.
    pub fn reset_exclusive(&self) {
        let mut guard = self.lock();
        self.mask.store(0, Ordering::Release);
        self.active_epoch.store(0, Ordering::Relaxed);
        guard.metadata = 0;
    }

    fn lock(&self) -> MutationGuard<'_> {
        loop {
            let metadata = self.metadata.load(Ordering::Relaxed);
            if metadata & LOCKED == 0
                && self
                    .metadata
                    .compare_exchange_weak(
                        metadata,
                        metadata | LOCKED,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                return MutationGuard {
                    authority: self,
                    metadata,
                };
            }
            core::hint::spin_loop();
        }
    }
}

struct MutationGuard<'a> {
    authority: &'a AffinityAuthority,
    metadata: u64,
}
impl MutationGuard<'_> {
    fn notification(&mut self, unrouted: bool) -> Option<AffinityNotification> {
        let cpu_word = self.metadata & CPU_MASK;
        if cpu_word == 0 {
            return None;
        }
        let cpu = (cpu_word - 1) as u32;
        let mask = self.authority.load();
        if cpu < 64 && mask & (1u64 << cpu) != 0 {
            self.metadata &= !NOTIFIED;
            return None;
        }
        let slot = SlotId::from_plus_one(((self.metadata & SLOT_MASK) >> SLOT_SHIFT) as u32);
        if self.metadata & NOTIFIED != 0 || (slot.is_none() && !unrouted) {
            return None;
        }
        self.metadata |= NOTIFIED;
        Some(AffinityNotification {
            token: AffinityResidencyToken(self.authority.active_epoch.load(Ordering::Relaxed)),
            slot,
            cpu,
        })
    }
}
impl Drop for MutationGuard<'_> {
    fn drop(&mut self) {
        self.authority
            .metadata
            .store(self.metadata, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::vec::Vec;
    #[derive(Default)]
    struct Notifications {
        unrouted: bool,
        events: Vec<AffinityNotification>,
    }
    impl AffinityNotifier for Notifications {
        fn notify(&mut self, event: AffinityNotification) {
            self.events.push(event);
        }
        fn supports_unrouted(&self) -> bool {
            self.unrouted
        }
    }
    #[test]
    fn attached_remote_change_notifies_once_and_widening_rearms() {
        let authority = AffinityAuthority::new();
        authority.initialize(3);
        let mut sink = Notifications::default();
        let token = authority.bind(1, &mut sink).unwrap();
        assert!(authority.attach(token, SlotId::new(7), &mut sink));
        authority.change(1, &mut sink);
        authority.change(1, &mut sink);
        assert_eq!(
            sink.events,
            [AffinityNotification {
                token,
                slot: Some(SlotId::new(7)),
                cpu: 1
            }]
        );
        authority.change(3, &mut sink);
        assert_eq!(sink.events.len(), 1);
        authority.change(1, &mut sink);
        assert_eq!(sink.events.len(), 2);
    }
    #[test]
    fn ring_change_before_route_is_discharged_by_attach() {
        let authority = AffinityAuthority::new();
        authority.initialize(3);
        let mut ring = Notifications::default();
        let token = authority.bind(1, &mut ring).unwrap();
        authority.change(1, &mut ring);
        assert!(ring.events.is_empty());
        assert!(authority.attach(token, SlotId::new(9), &mut ring));
        assert_eq!(
            ring.events,
            [AffinityNotification {
                token,
                slot: Some(SlotId::new(9)),
                cpu: 1
            }]
        );
        assert!(authority.attach(token, SlotId::new(9), &mut ring));
        assert_eq!(ring.events.len(), 1);
    }
    #[test]
    fn bind_discharges_an_earlier_change_without_a_route() {
        let authority = AffinityAuthority::new();
        let mut ring = Notifications::default();
        authority.change(1, &mut ring);
        let mut host = Notifications {
            unrouted: true,
            ..Notifications::default()
        };
        let token = authority.bind(1, &mut host).unwrap();
        assert_eq!(
            host.events,
            [AffinityNotification {
                token,
                slot: None,
                cpu: 1
            }]
        );
        assert!(authority.attach(token, SlotId::new(3), &mut ring));
        assert!(ring.events.is_empty());
    }
    #[test]
    fn stale_tokens_cannot_attach_or_unbind_a_successor() {
        let authority = AffinityAuthority::new();
        authority.initialize(3);
        let mut sink = Notifications::default();
        let predecessor = authority.bind(0, &mut sink).unwrap();
        assert!(authority.unbind(predecessor));
        let successor = authority.bind(1, &mut sink).unwrap();
        assert_ne!(predecessor, successor);
        assert!(!authority.unbind(predecessor));
        assert!(!authority.attach(predecessor, SlotId::new(4), &mut sink));
        assert!(authority.attach(successor, SlotId::new(5), &mut sink));
        authority.change(1, &mut sink);
        assert_eq!(
            sink.events,
            [AffinityNotification {
                token: successor,
                slot: Some(SlotId::new(5)),
                cpu: 1
            }]
        );
    }
    #[test]
    fn quiescent_initialization_refuses_live_residency_and_reset_keeps_epoch() {
        let authority = AffinityAuthority::new();
        authority.initialize(1);
        authority.initialize(3);
        assert_eq!(authority.load(), 1);
        let mut sink = Notifications::default();
        let old = authority.bind(0, &mut sink).unwrap();
        assert!(!authority.initialize_quiescent(3));
        assert_eq!(authority.load(), 1);
        authority.reset_exclusive();
        assert_eq!(authority.load(), 0);
        assert!(authority.initialize_quiescent(3));
        let new = authority.bind(1, &mut sink).unwrap();
        assert!(new.raw() > old.raw());
        assert!(!authority.unbind(old));
    }
    #[test]
    fn epoch_exhaustion_preserves_current_residency() {
        let authority = AffinityAuthority::new();
        authority.initialize(3);
        let mut sink = Notifications::default();
        let token = authority.bind(1, &mut sink).unwrap();
        assert!(authority.attach(token, SlotId::new(2), &mut sink));
        authority.next_epoch.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(authority.bind(0, &mut sink), Err(AffinityEpochExhausted));
        authority.change(1, &mut sink);
        assert_eq!(sink.events[0].token, token);
    }
    #[test]
    fn notification_callback_can_reenter_the_authority() {
        struct Rearm<'a> {
            authority: &'a AffinityAuthority,
            calls: usize,
        }
        impl AffinityNotifier for Rearm<'_> {
            fn notify(&mut self, _: AffinityNotification) {
                assert_eq!(self.authority.metadata.load(Ordering::Acquire) & LOCKED, 0);
                self.calls += 1;
                self.authority.change(3, &mut Notifications::default());
            }
        }
        let authority = AffinityAuthority::new();
        authority.initialize(3);
        let mut idle = Notifications::default();
        let token = authority.bind(1, &mut idle).unwrap();
        assert!(authority.attach(token, SlotId::new(6), &mut idle));
        let mut callback = Rearm {
            authority: &authority,
            calls: 0,
        };
        authority.change(1, &mut callback);
        assert_eq!(authority.load(), 3);
        authority.change(1, &mut callback);
        assert_eq!(callback.calls, 2);
    }
    #[test]
    fn coordinated_remote_writer_during_load_cannot_lose_attach_notification() {
        use std::sync::{Arc, Barrier};
        let authority = Arc::new(AffinityAuthority::new());
        authority.initialize(3);
        let bound = Arc::new(Barrier::new(2));
        let changed = Arc::new(Barrier::new(2));
        let writer = {
            let authority = Arc::clone(&authority);
            let bound = Arc::clone(&bound);
            let changed = Arc::clone(&changed);
            std::thread::spawn(move || {
                let mut sink = Notifications::default();
                bound.wait();
                authority.change(1, &mut sink);
                changed.wait();
                assert!(sink.events.is_empty());
            })
        };
        let mut sink = Notifications::default();
        let token = authority.bind(1, &mut sink).unwrap();
        bound.wait();
        changed.wait();
        assert!(authority.attach(token, SlotId::new(11), &mut sink));
        writer.join().unwrap();
        assert_eq!(
            sink.events,
            [AffinityNotification {
                token,
                slot: Some(SlotId::new(11)),
                cpu: 1
            }]
        );
    }
    #[test]
    fn an_allowed_sibling_and_a_rejected_route_receive_no_notification() {
        let first = AffinityAuthority::new();
        let second = AffinityAuthority::new();
        first.initialize(3);
        second.initialize(3);
        let mut a = Notifications::default();
        let mut b = Notifications::default();
        let token = first.bind(0, &mut a).unwrap();
        assert!(first.attach(token, SlotId::new(0), &mut a));
        assert!(!first.attach(token, SlotId::new(1), &mut a));
        let peer = second.bind(1, &mut b).unwrap();
        assert!(second.attach(peer, SlotId::new(1), &mut b));
        first.change(1, &mut a);
        second.change(3, &mut b);
        assert!(a.events.is_empty());
        assert!(b.events.is_empty());
    }
}
