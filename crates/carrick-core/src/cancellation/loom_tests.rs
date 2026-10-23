use super::*;
use loom::{
    sync::{Arc, atomic::AtomicU32},
    thread,
};

struct Word(AtomicU32);
impl CancellationWord for Word {
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

#[test]
fn two_effects_cannot_commit_after_fatal_publication() {
    loom::model(|| {
        let authority = Arc::new(CancellationAuthority::with_word(Word(AtomicU32::new(0))));
        let publisher = authority.clone();
        let fatal = thread::spawn(move || {
            if let Ok(_permit) = ProcessEffect::acquire(&*publisher) {
                assert!(publisher.published().is_none());
            }
            let request = publisher.request(ProcessCancellation::FatalSignal);
            assert!(ProcessEffect::acquire(&*publisher).is_err());
            request.publish(thread::yield_now);
            publisher.consume();
            assert_eq!(
                publisher.requested(),
                Some(ProcessCancellation::FatalSignal)
            );
        });
        if let Ok(_permit) = ProcessEffect::acquire(&*authority) {
            assert!(authority.published().is_none());
        }
        fatal.join().unwrap();
        assert!(ProcessEffect::acquire(&*authority).is_err());
        authority.publish(ProcessCancellation::GroupExit, thread::yield_now);
        assert_eq!(
            authority.published(),
            Some(ProcessCancellation::FatalSignal)
        );
    });
}

#[test]
fn publication_drains_both_admitted_effects() {
    loom::model(|| {
        let authority = Arc::new(CancellationAuthority::with_word(Word(AtomicU32::new(0))));
        let (ready, admitted) = loom::sync::mpsc::channel();
        let (release_first, first_ready) = loom::sync::mpsc::channel();
        let (release_second, second_ready) = loom::sync::mpsc::channel();
        let effect = |authority: Arc<CancellationAuthority<Word>>,
                      ready: loom::sync::mpsc::Sender<()>,
                      release: loom::sync::mpsc::Receiver<()>| {
            thread::spawn(move || {
                let permit = ProcessEffect::acquire(&*authority).unwrap();
                ready.send(()).unwrap();
                // Test scheduling barrier: place both bounded effects before
                // the request, then explore both release orders against it.
                release.recv().unwrap();
                assert!(authority.published().is_none());
                drop(permit);
            })
        };
        let first = effect(authority.clone(), ready.clone(), first_ready);
        let second = effect(authority.clone(), ready, second_ready);
        admitted.recv().unwrap();
        admitted.recv().unwrap();
        let publication = authority.request(ProcessCancellation::FatalSignal);
        release_first.send(()).unwrap();
        release_second.send(()).unwrap();
        publication.publish(thread::yield_now);
        assert!(authority.published().is_some());
        first.join().unwrap();
        second.join().unwrap();
    });
}
