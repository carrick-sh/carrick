//! Shared callback enrollment used by kernel waits and backend completions.
//! Resource owners publish after unlocking; consumers enroll then recheck their
//! own readiness predicate. This registry supplies no readiness or task policy.
use parking_lot::Mutex;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
};
pub type CompletionCallback = Arc<dyn Fn(usize) + Send + Sync + 'static>;
#[derive(Default)]
struct Inner {
    callbacks: Mutex<BTreeMap<u64, CompletionCallback>>,
    next: AtomicU64,
}
#[derive(Clone, Default)]
pub struct CompletionCallbacks(Arc<Inner>);
impl std::fmt::Debug for CompletionCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionCallbacks")
            .field("len", &self.len())
            .finish()
    }
}
#[derive(Debug)]
pub struct CompletionEnrollment {
    queue: Weak<Inner>,
    token: u64,
}
impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionCallbacksInner")
            .finish_non_exhaustive()
    }
}
impl CompletionCallbacks {
    pub fn enroll(&self, callback: impl Fn(usize) + Send + Sync + 'static) -> CompletionEnrollment {
        let token = self.0.next.fetch_add(1, Ordering::Relaxed);
        self.0.callbacks.lock().insert(token, Arc::new(callback));
        CompletionEnrollment {
            queue: Arc::downgrade(&self.0),
            token,
        }
    }
    pub fn snapshot(&self) -> Vec<CompletionCallback> {
        self.0.callbacks.lock().values().cloned().collect()
    }
    pub fn publish(&self, depth: usize) {
        for callback in self.snapshot() {
            callback(depth);
        }
    }
    pub fn len(&self) -> usize {
        self.0.callbacks.lock().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl Drop for CompletionEnrollment {
    fn drop(&mut self) {
        if let Some(queue) = self.queue.upgrade() {
            queue.callbacks.lock().remove(&self.token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enrollment_drop_and_after_unlock_reentry_keep_snapshot_semantics() {
        let queue = CompletionCallbacks::default();
        let fired = Arc::new(AtomicU64::new(0));
        let count = fired.clone();
        let other = queue.clone();
        let enrolled = queue.enroll(move |depth| {
            assert_eq!(depth, 4);
            assert_eq!(other.len(), 1);
            let temporary = other.enroll(|_| unreachable!());
            drop(temporary);
            count.fetch_add(1, Ordering::Relaxed);
        });
        queue.publish(4);
        assert_eq!(fired.load(Ordering::Relaxed), 1);
        drop(enrolled);
        assert!(queue.is_empty());
        queue.publish(4);
        assert_eq!(fired.load(Ordering::Relaxed), 1);
    }
}
