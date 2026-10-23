//! Exercises the shipping settlement method with loom-controlled producers.
//! Signal selection, native mailbox entry and endpoint side effects are bound
//! by the production runtime witnesses, not replicated in this model.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::owner_wait::{OwnerWait, Settlement};
use carrick_core::cancellation::{
    CancellationAuthority, CancellationWord, ProcessCancellation, ProcessEffect,
};

struct ModelWord(loom::sync::atomic::AtomicU32);
impl CancellationWord for ModelWord {
    fn load(&self, order: Ordering) -> u32 {
        self.0.load(order)
    }
    fn compare_exchange(
        &self,
        old: u32,
        new: u32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u32, u32> {
        self.0.compare_exchange(old, new, success, failure)
    }
    fn fetch_sub(&self, value: u32, order: Ordering) -> u32 {
        self.0.fetch_sub(value, order)
    }
    fn fetch_or(&self, value: u32, order: Ordering) -> u32 {
        self.0.fetch_or(value, order)
    }
}
fn authority() -> CancellationAuthority<ModelWord> {
    CancellationAuthority::with_word(ModelWord(loom::sync::atomic::AtomicU32::new(0)))
}
use carrick_kernel::kernel::continuation::OwnerWaitCancellation;
use loom::{
    model::Builder,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

struct Dependency {
    ready: Arc<AtomicBool>,
    writers: Arc<AtomicUsize>,
}
impl Drop for Dependency {
    fn drop(&mut self) {
        assert_eq!(self.writers.fetch_sub(1, Ordering::SeqCst), 1);
    }
}

fn exercise(already_ready: bool, fatal: Option<OwnerWaitCancellation>) {
    let mut builder = Builder::new();
    builder.max_threads = 4;
    builder.max_branches = 1_000;
    builder.check(move || {
        let ready = Arc::new(AtomicBool::new(already_ready));
        let pending = Arc::new(authority());
        let ordinary = Arc::new(AtomicBool::new(false));
        let writers = Arc::new(AtomicUsize::new(1));
        let releases = Arc::new(AtomicUsize::new(0));
        let editor_ready = ready.clone();
        let editor_releases = releases.clone();
        let editor = thread::spawn(move || {
            // The editor owns no guest wait. Its only action is publication.
            editor_ready.store(true, Ordering::Release);
            editor_releases.fetch_add(1, Ordering::Relaxed);
        });
        let sibling_pending = pending.clone();
        let sibling_ordinary = ordinary.clone();
        let sibling = thread::spawn(move || {
            sibling_ordinary.store(true, Ordering::Release);
            if let Ok(_effect) = ProcessEffect::acquire(&*sibling_pending) {
                assert!(sibling_pending.published().is_none());
            }
            if fatal.is_some() {
                // Process-wide publication: no per-waiter delivery reservation.
                sibling_pending.publish(ProcessCancellation::FatalSignal, thread::yield_now);
            }
        });
        let dependency = Dependency {
            ready: ready.clone(),
            writers: writers.clone(),
        };
        let mut wait = OwnerWait::new(dependency, ());
        let mut sample = || pending.requested().and(fatal);
        let first = wait.settle(&mut sample, |dependency| {
            dependency.ready.load(Ordering::Acquire)
        });
        if matches!(&first, Settlement::Resume(()))
            && let Ok(_effect) = ProcessEffect::acquire(&*pending)
        {
            assert!(pending.published().is_none());
            assert_eq!(writers.load(Ordering::SeqCst), 0);
        }
        editor.join().unwrap();
        sibling.join().unwrap();
        match first {
            Settlement::Waiting(retained) => {
                assert_eq!(writers.load(Ordering::SeqCst), 1);
                wait = retained;
                match wait.settle(&mut sample, |dependency| {
                    dependency.ready.load(Ordering::Acquire)
                }) {
                    Settlement::Cancelled(reason) => assert_eq!(Some(reason), fatal),
                    Settlement::Resume(()) => assert!(fatal.is_none()),
                    Settlement::Waiting(_) => panic!("editor release was lost"),
                }
            }
            Settlement::Cancelled(reason) => assert_eq!(Some(reason), fatal),
            // Admission may have preceded the sibling's fatal publication.
            Settlement::Resume(()) => {}
        }
        assert_eq!(writers.load(Ordering::SeqCst), 0);
        assert_eq!(releases.load(Ordering::Relaxed), 1);
        assert!(ordinary.load(Ordering::Acquire));
        // A sibling waiter arriving after process cancellation must not need
        // the signal reservation assigned to the first thread.
        let sibling_wait = OwnerWait::new((), ());
        match sibling_wait.settle(sample, |()| true) {
            Settlement::Cancelled(reason) => assert_eq!(Some(reason), fatal),
            Settlement::Resume(()) => assert!(fatal.is_none()),
            Settlement::Waiting(_) => panic!("ready sibling parked"),
        }
    });
}

#[test]
fn physical_release_and_process_sigkill() {
    exercise(false, Some(OwnerWaitCancellation::Carrier));
}

#[test]
fn already_ready_still_settles_fatal_state() {
    exercise(true, Some(OwnerWaitCancellation::Carrier));
}

#[test]
fn native_and_group_exit_settle_without_signal_reservation() {
    exercise(false, Some(OwnerWaitCancellation::NativeFatal));
    exercise(true, Some(OwnerWaitCancellation::GroupExit));
}

#[test]
fn handled_signal_and_stop_cannot_complete_an_owner_wait() {
    exercise(false, None);
}

#[test]
fn cancellation_during_dependency_release_prevents_retry() {
    loom::model(|| {
        struct Release(Arc<CancellationAuthority<ModelWord>>);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0
                    .publish(ProcessCancellation::FatalSignal, thread::yield_now);
            }
        }
        let pending = Arc::new(authority());
        let wait = OwnerWait::new(Release(pending.clone()), ());
        assert!(matches!(
            wait.settle(
                || pending.requested().map(|_| OwnerWaitCancellation::Carrier),
                |_| true,
            ),
            Settlement::Cancelled(OwnerWaitCancellation::Carrier)
        ));
    });
}

/// The literal #802 commit invariant, over the shipping cancellation/effect
/// protocol. Fatal publication cannot overtake an admitted bounded effect.
#[test]
fn cancellation_pending_before_commit_forbids_consumption() {
    loom::model(|| {
        let fatal = Arc::new(authority());
        let producer_fatal = fatal.clone();
        let producer = thread::spawn(move || {
            producer_fatal.publish(ProcessCancellation::FatalSignal, thread::yield_now)
        });
        let wait = OwnerWait::new((), ());
        if let Settlement::Resume(()) = wait.settle(
            || fatal.requested().map(|_| OwnerWaitCancellation::Carrier),
            |()| true,
        ) && let Ok(_effect) = ProcessEffect::acquire(&*fatal)
        {
            // Resume is only eligibility. Secured output must acquire effect
            // custody before consuming; hold it through output and metadata.
            assert!(
                fatal.published().is_none(),
                "fatal publication overtook resume admission before consumption"
            );
        }
        producer.join().unwrap();
    });
}
