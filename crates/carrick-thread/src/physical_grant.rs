//! Physical first-touch readiness shared by the backend producer and owner
//! memory waiters. The sole completion stays on the serving executor's stack.

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
/// nor `Send`, so an MM ledger or owned continuation cannot retain it.
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
