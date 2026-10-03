//! Intrusive MPSC custody queue. Producers publish with one exchange and one
//! link store; a single owner drains ready links without waiting for producers.
use core::sync::atomic::{AtomicU32, Ordering};
const STUB: u32 = u32::MAX;

#[repr(C)]
pub struct CompletionQueue {
    initialized: AtomicU32,
    head: AtomicU32,
    tail: AtomicU32,
    stub_next: AtomicU32,
}
impl CompletionQueue {
    /// Admission only. An in-progress initializer is a pre-effect refusal.
    pub fn initialize(&self) -> bool {
        match self
            .initialized
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire)
        {
            Ok(_) => {
                self.head.store(STUB, Ordering::Relaxed);
                self.tail.store(STUB, Ordering::Relaxed);
                self.stub_next.store(0, Ordering::Relaxed);
                self.initialized.store(2, Ordering::Release);
                true
            }
            Err(value) => value == 2,
        }
    }
    /// Caller owns this entire chain; its tail link is zero. Links remain
    /// alive until pop transfers each member to the unique consumer.
    pub fn push(&self, head: u32, tail: u32, link: impl FnOnce(u32, u32)) {
        assert!(head != 0 && tail != 0 && head != STUB && tail != STUB);
        assert_eq!(self.initialized.load(Ordering::Acquire), 2);
        self.push_inner(head, tail, link);
    }
    fn push_inner(&self, head: u32, tail: u32, link: impl FnOnce(u32, u32)) {
        let previous = self.tail.swap(tail, Ordering::AcqRel);
        if previous == STUB {
            self.stub_next.store(head, Ordering::Release);
        } else {
            link(previous, head);
        }
    }
    /// Caller exclusively owns the consumer. An exchange-to-link gap returns
    /// None immediately; queued custody remains live for the producer's kick.
    ///
    /// # Safety
    /// The caller holds exclusive consumer authority until this call returns.
    pub unsafe fn pop(&self, load: impl Fn(u32) -> u32, store: impl Fn(u32, u32)) -> Option<u32> {
        if self.initialized.load(Ordering::Acquire) != 2 {
            return None;
        }
        let mut head = self.head.load(Ordering::Relaxed);
        if head == STUB {
            let next = self.stub_next.load(Ordering::Acquire);
            if next == 0 {
                return None;
            }
            self.head.store(next, Ordering::Relaxed);
            head = next;
        }
        let next = load(head);
        if next != 0 {
            self.head.store(next, Ordering::Relaxed);
            return Some(head);
        }
        if head != self.tail.load(Ordering::Acquire) {
            return None;
        }
        self.stub_next.store(0, Ordering::Relaxed);
        self.push_inner(STUB, STUB, store);
        let next = load(head);
        if next == 0 {
            return None;
        }
        self.head.store(next, Ordering::Relaxed);
        Some(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    #[test]
    fn paused_producer_link_retains_custody_and_consumer_never_waits() {
        // SAFETY: shared queue bootstrap is the all-zero ABI state.
        let queue: CompletionQueue = unsafe { core::mem::zeroed() };
        assert!(queue.initialize());
        let links = [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];
        queue.push(1, 1, |id, next| {
            links[id as usize].store(next, Ordering::Release)
        });
        let exchanged = Barrier::new(2);
        let resume = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                queue.push(2, 2, |id, next| {
                    exchanged.wait();
                    resume.wait();
                    links[id as usize].store(next, Ordering::Release);
                })
            });
            exchanged.wait();
            assert_eq!(
                unsafe {
                    queue.pop(
                        |id| links[id as usize].load(Ordering::Acquire),
                        |id, next| links[id as usize].store(next, Ordering::Release),
                    )
                },
                None
            );
            assert_eq!(
                links[1].load(Ordering::Acquire),
                0,
                "first member cannot be reclaimed before producer links it"
            );
            resume.wait();
        });
        let pop = || unsafe {
            queue.pop(
                |id| links[id as usize].load(Ordering::Acquire),
                |id, next| links[id as usize].store(next, Ordering::Release),
            )
        };
        assert_eq!(pop(), Some(1));
        assert_eq!(pop(), Some(2));
        assert_eq!(pop(), None);
    }
}
