//! Physical first-touch readiness shared by the backend producer and owner
//! memory waiters. Preparation retains the sole producer on its stack, or
//! transfers it into the exact descriptor-receipt owner.

use crate::completion::CompletionCallbacks;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

#[derive(Debug, Default)]
pub struct PhysicalGrantWait {
    ready: AtomicBool,
    callbacks: CompletionCallbacks,
}

impl carrick_guest_mem::PhysicalMemoryWait for PhysicalGrantWait {
    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    fn enroll(
        &self,
        wake: Arc<dyn Fn() + Send + Sync>,
    ) -> (Box<dyn std::fmt::Debug + Send + Sync>, bool) {
        let enrollment = self.callbacks.enroll(move |_| wake());
        (Box::new(enrollment), self.is_ready())
    }
}

#[derive(Debug)]
struct PhysicalGrantProducer(Arc<PhysicalGrantWait>);

impl Drop for PhysicalGrantProducer {
    fn drop(&mut self) {
        self.0.ready.store(true, Ordering::Release);
        self.0.callbacks.publish(0);
    }
}

/// Last producer release signals readiness. This token is neither `Clone`
/// nor `Send`. An exact-receipt owner may consume it with `into_owned` after
/// preparation exclusion ends; ordinary continuations retain only the waiter.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<carrick_thread::physical_grant::PhysicalGrantCompletion>();
/// ```
#[derive(Debug)]
#[must_use = "retain physical grant custody through descriptor and inventory settlement"]
pub struct PhysicalGrantCompletion(Arc<PhysicalGrantProducer>, PhantomData<Rc<()>>);

impl PhysicalGrantCompletion {
    pub fn new() -> Self {
        Self(
            Arc::new(PhysicalGrantProducer(
                Arc::new(PhysicalGrantWait::default()),
            )),
            PhantomData,
        )
    }

    /// Transfer the sole producer to an exact-receipt owner. Preparation
    /// exclusion remains local; that owner retains readiness until its
    /// descriptor settlement or physical rollback completes. This consumes
    /// the stack token without publishing or creating another producer.
    pub fn into_owned(self) -> OwnedPhysicalGrantCompletion {
        OwnedPhysicalGrantCompletion { _producer: self.0 }
    }

    pub fn wait_weak(&self) -> Weak<PhysicalGrantWait> {
        Arc::downgrade(&self.0.0)
    }
}

impl Default for PhysicalGrantCompletion {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for PhysicalGrantCompletion {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for PhysicalGrantCompletion {}

/// The same sole readiness producer, retained by an owned physical grant.
/// There is no cloning API; its last release preserves the stack token's
/// publication ordering while permitting an authenticated service handoff.
#[derive(Debug)]
#[must_use = "retain custody through descriptor settlement or physical rollback"]
pub struct OwnedPhysicalGrantCompletion {
    _producer: Arc<PhysicalGrantProducer>,
}

#[cfg(test)]
mod owned_tests {
    use super::*;
    use carrick_guest_mem::PhysicalMemoryWait;

    #[test]
    fn owned_handoff_keeps_same_producer_until_cross_thread_release() {
        let completion = PhysicalGrantCompletion::new();
        let wait = completion.wait_weak().upgrade().unwrap();
        let owned = completion.into_owned();
        assert!(!wait.is_ready(), "handoff cannot signal physical readiness");
        let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let callback_wakes = wakes.clone();
        let (_subscription, ready) = wait.enroll(Arc::new(move || {
            callback_wakes.fetch_add(1, Ordering::AcqRel);
        }));
        assert!(!ready);
        std::thread::spawn(move || drop(owned)).join().unwrap();
        assert!(wait.is_ready());
        assert_eq!(wakes.load(Ordering::Acquire), 1);
    }
}
