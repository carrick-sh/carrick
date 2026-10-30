//! Exact physical retirement completion. The owner records terminal release;
//! callbacks are explicitly published later, outside every owner guard.
use crate::completion::{CompletionCallback, CompletionCallbacks};
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// The only terminal writer, retained by the exact physical record owner.
/// Drop publishes abandonment, never success. Absence is not a retirement receipt.
#[derive(Debug)]
pub struct PhysicalRetirementCompletion<I> {
    wait: Arc<PhysicalRetirementWait<I>>,
}
#[derive(Debug)]
pub struct PhysicalRetirementWait<I> {
    identity: I,
    state: AtomicU8,
    callbacks: CompletionCallbacks,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetirementIdentityMismatch;

/// Why the exact producer could no longer provide a retirement receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementAbandonReason {
    ProducerDropped,
    RecordRemoved,
}

/// Absence of the producer is terminal but cannot authorize physical reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalRetirementState<I> {
    Pending,
    Retired(I),
    Abandoned(RetirementAbandonReason),
}

#[derive(Debug)]
struct RetirementEnrollment {
    active: Arc<AtomicBool>,
    _registration: crate::completion::CompletionEnrollment,
}
impl Drop for RetirementEnrollment {
    fn drop(&mut self) {
        // A publication may already own a snapshot of the callback. Revoke
        // this exact enrollment as well as removing the registry entry.
        self.active.store(false, Ordering::Release);
    }
}
impl<I> Drop for PhysicalRetirementCompletion<I> {
    fn drop(&mut self) {
        if self
            .wait
            .state
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // As with PhysicalGrantCompletion, callbacks notify their owner;
            // they must not perform physical retirement inside producer Drop.
            self.wait.callbacks.publish(0);
        }
    }
}

/// Notification effects retained by the same physical owner until its idle
/// boundary. Creating this value records readiness but invokes no callback.
#[must_use = "publish retirement notifications only after owner guards drop"]
pub struct RetirementPublication {
    callbacks: Vec<CompletionCallback>,
}
impl Debug for RetirementPublication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetirementPublication")
            .field("callbacks", &self.callbacks.len())
            .finish()
    }
}
impl RetirementPublication {
    pub fn publish(self) {
        for callback in self.callbacks {
            callback(0);
        }
    }
}
impl<I: Copy + Eq> PhysicalRetirementCompletion<I> {
    pub fn new(identity: I) -> Self {
        Self {
            wait: Arc::new(PhysicalRetirementWait {
                identity,
                state: AtomicU8::new(0),
                callbacks: CompletionCallbacks::default(),
            }),
        }
    }
    pub fn wait(&self) -> Arc<PhysicalRetirementWait<I>> {
        Arc::clone(&self.wait)
    }
    /// Record explicit producer removal while another holder may still retain
    /// the owner. Publish the returned effects after removal guards drop.
    pub fn abandon(
        &self,
        identity: I,
        reason: RetirementAbandonReason,
    ) -> Result<Option<RetirementPublication>, RetirementIdentityMismatch> {
        if identity != self.wait.identity {
            return Err(RetirementIdentityMismatch);
        }
        let state = match reason {
            RetirementAbandonReason::ProducerDropped => 2,
            RetirementAbandonReason::RecordRemoved => 3,
        };
        if self
            .wait
            .state
            .compare_exchange(0, state, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(None);
        }
        let callbacks = self.wait.callbacks.snapshot();
        Ok((!callbacks.is_empty()).then_some(RetirementPublication { callbacks }))
    }
    /// Called by the existing physical owner only after exact record
    /// finalization, including required allocation return, has succeeded.
    /// This records the result once; it never chooses retirement eligibility.
    pub fn complete(
        &self,
        identity: I,
    ) -> Result<Option<RetirementPublication>, RetirementIdentityMismatch> {
        if identity != self.wait.identity {
            return Err(RetirementIdentityMismatch);
        }
        if self
            .wait
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(None);
        }
        let callbacks = self.wait.callbacks.snapshot();
        Ok((!callbacks.is_empty()).then_some(RetirementPublication { callbacks }))
    }
}
impl<I: Copy> PhysicalRetirementWait<I> {
    pub fn state(&self) -> PhysicalRetirementState<I> {
        match self.state.load(Ordering::Acquire) {
            0 => PhysicalRetirementState::Pending,
            1 => PhysicalRetirementState::Retired(self.identity),
            2 => PhysicalRetirementState::Abandoned(RetirementAbandonReason::ProducerDropped),
            _ => PhysicalRetirementState::Abandoned(RetirementAbandonReason::RecordRemoved),
        }
    }
    /// Retain this exact proof across directory removal and IPA reuse.
    pub fn receipt(&self) -> Option<I> {
        (self.state.load(Ordering::Acquire) == 1).then_some(self.identity)
    }
}
impl<I: Debug + Send + Sync> carrick_guest_mem::PhysicalMemoryWait for PhysicalRetirementWait<I> {
    fn is_ready(&self) -> bool {
        self.state.load(Ordering::Acquire) != 0
    }
    fn enroll(&self, wake: Arc<dyn Fn() + Send + Sync>) -> (Box<dyn Debug + Send + Sync>, bool) {
        // Register before probing, including when terminal release raced with
        // enrollment. The caller either observes readiness or receives a wake.
        let active = Arc::new(AtomicBool::new(true));
        let callback_active = active.clone();
        let registration = self.callbacks.enroll(move |_| {
            if callback_active.swap(false, Ordering::AcqRel) {
                wake();
            }
        });
        let enrollment = RetirementEnrollment {
            active,
            _registration: registration,
        };
        (Box::new(enrollment), self.is_ready())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_guest_mem::PhysicalMemoryWait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Identity {
        vm: u64,
        record: u64,
        generation: u64,
    }
    fn identity() -> Identity {
        Identity {
            vm: 1,
            record: 2,
            generation: 3,
        }
    }
    fn enroll(
        wait: &PhysicalRetirementWait<Identity>,
        count: &Arc<AtomicUsize>,
    ) -> (Box<dyn std::fmt::Debug + Send + Sync>, bool) {
        let count = count.clone();
        wait.enroll(Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
        }))
    }

    #[test]
    fn retirement_enrollment_before_terminal_release_waits_for_publication() {
        let producer = PhysicalRetirementCompletion::new(identity());
        let wait = producer.wait();
        let count = Arc::new(AtomicUsize::new(0));
        let (_enrollment, ready) = enroll(&wait, &count);
        assert!(!ready);
        assert_eq!(wait.receipt(), None);
        let publication = producer.complete(identity()).unwrap().unwrap();
        assert_eq!(wait.receipt(), Some(identity()));
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "owner locks may still be held"
        );
        publication.publish();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(producer.complete(identity()).unwrap().is_none());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn retirement_completed_before_enrollment_is_observed_by_one_probe() {
        let producer = PhysicalRetirementCompletion::new(identity());
        let wait = producer.wait();
        assert!(producer.complete(identity()).unwrap().is_none());
        let count = Arc::new(AtomicUsize::new(0));
        let (_enrollment, ready) = enroll(&wait, &count);
        assert!(ready);
        assert_eq!(wait.receipt(), Some(identity()));
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unrelated_record_and_reused_generation_cannot_complete_a_wait() {
        let producer = PhysicalRetirementCompletion::new(identity());
        let wait = producer.wait();
        let count = Arc::new(AtomicUsize::new(0));
        let (_enrollment, ready) = enroll(&wait, &count);
        assert!(!ready);
        for wrong in [
            Identity {
                vm: 2,
                ..identity()
            },
            Identity {
                record: 3,
                ..identity()
            },
            Identity {
                generation: 4,
                ..identity()
            },
        ] {
            assert!(producer.complete(wrong).is_err());
            assert!(!wait.is_ready());
            assert_eq!(wait.receipt(), None);
        }
        let peer = PhysicalRetirementCompletion::new(Identity {
            record: 3,
            ..identity()
        });
        assert!(
            peer.complete(Identity {
                record: 3,
                ..identity()
            })
            .unwrap()
            .is_none()
        );
        assert!(!wait.is_ready());
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dropping_producer_is_not_success_and_cancelled_enrollment_has_no_callback() {
        let producer = PhysicalRetirementCompletion::new(identity());
        let wait = producer.wait();
        let count = Arc::new(AtomicUsize::new(0));
        let (enrollment, ready) = enroll(&wait, &count);
        assert!(!ready);
        drop(enrollment);
        assert!(producer.complete(identity()).unwrap().is_none());
        assert_eq!(count.load(Ordering::SeqCst), 0);
        let abandoned = PhysicalRetirementCompletion::new(identity());
        let pending = abandoned.wait();
        drop(abandoned);
        assert!(pending.is_ready());
        assert_eq!(pending.receipt(), None);
    }

    #[test]
    fn abandoned_producer_wakes_waiter_without_a_retired_receipt() {
        let producer = PhysicalRetirementCompletion::new(identity());
        let wait = producer.wait();
        let count = Arc::new(AtomicUsize::new(0));
        let (_enrollment, ready) = enroll(&wait, &count);
        assert!(!ready);
        drop(producer);
        assert!(wait.is_ready(), "abandonment must settle an enrolled wait");
        assert_eq!(wait.receipt(), None);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(
            wait.state(),
            PhysicalRetirementState::Abandoned(RetirementAbandonReason::ProducerDropped)
        );
    }

    #[test]
    fn explicit_record_removal_wakes_even_while_producer_is_retained() {
        let producer = PhysicalRetirementCompletion::new(identity());
        let wait = producer.wait();
        let count = Arc::new(AtomicUsize::new(0));
        let (_enrollment, _) = enroll(&wait, &count);
        let wrong = Identity {
            generation: 4,
            ..identity()
        };
        assert!(
            producer
                .abandon(wrong, RetirementAbandonReason::RecordRemoved)
                .is_err()
        );
        assert!(!wait.is_ready());
        let publication = producer
            .abandon(identity(), RetirementAbandonReason::RecordRemoved)
            .unwrap()
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 0);
        publication.publish();
        assert_eq!(
            wait.state(),
            PhysicalRetirementState::Abandoned(RetirementAbandonReason::RecordRemoved)
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(wait.receipt(), None);
        assert!(producer.complete(identity()).unwrap().is_none());
        assert!(
            producer
                .abandon(identity(), RetirementAbandonReason::RecordRemoved)
                .unwrap()
                .is_none()
        );
        drop(producer);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let (_late, ready) = enroll(&wait, &count);
        assert!(ready);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancelled_wait_drops_a_callback_captured_before_cancellation() {
        let producer = PhysicalRetirementCompletion::new(identity());
        let wait = producer.wait();
        let count = Arc::new(AtomicUsize::new(0));
        let (enrollment, _) = enroll(&wait, &count);
        let publication = producer.complete(identity()).unwrap().unwrap();
        drop(enrollment);
        publication.publish();
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn publication_callbacks_may_reenter_the_registry_after_owner_unlock() {
        let producer = PhysicalRetirementCompletion::new(identity());
        let wait = producer.wait();
        let reentry = wait.clone();
        let owner_lock = Arc::new(parking_lot::Mutex::new(()));
        let lock_in_callback = owner_lock.clone();
        let (_enrollment, ready) = wait.enroll(Arc::new(move || {
            assert!(lock_in_callback.try_lock().is_some());
            let (_nested, ready) = reentry.enroll(Arc::new(|| {}));
            assert!(ready);
        }));
        assert!(!ready);
        let guard = owner_lock.lock();
        let publication = producer.complete(identity()).unwrap().unwrap();
        drop(guard);
        publication.publish();
    }
}
