//! Bounded model of the production prepared-clear sequencer, with modeled
//! graph publication and futex observers. Kernel token/identity bindings and
//! actual owner waits are covered by the ordinary integration witnesses.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_guest_mem::{
    CurrentMmMemory, GuestMemory, GuestWriteRange, MemoryError, MemoryPrepareError,
    PreparedGuestWrite, UserMemoryVenue,
};
use carrick_hal::ThreadId;
use carrick_thread::thread::ThreadRegistry;
use loom::{
    model::Builder,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Graph {
    Live,
    Retired,
    Published,
}

struct State {
    graph: Mutex<Graph>,
    word: AtomicUsize,
    wakes: AtomicUsize,
    commits: AtomicUsize,
    cancellations: AtomicUsize,
}

struct Memory(Arc<State>);
struct Prepared {
    state: Arc<State>,
    committed: bool,
}

impl PreparedGuestWrite for Prepared {
    fn commit(mut self: Box<Self>, outputs: &[&[u8]]) {
        assert_eq!(outputs, &[&[0_u8; 4][..]]);
        assert_ne!(*self.state.graph.lock().unwrap(), Graph::Live);
        self.state.word.store(0, Ordering::Relaxed);
        self.state.commits.fetch_add(1, Ordering::Relaxed);
        self.committed = true;
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if !self.committed {
            self.state.cancellations.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl GuestMemory for Memory {
    fn user_memory_venue(&self) -> UserMemoryVenue {
        UserMemoryVenue::Owner
    }
    fn prepare_write(
        &mut self,
        ranges: &[GuestWriteRange],
    ) -> Result<Box<dyn PreparedGuestWrite + '_>, MemoryPrepareError> {
        assert_eq!(*self.0.graph.lock().unwrap(), Graph::Live);
        assert_eq!(ranges.len(), 1);
        Ok(Box::new(Prepared {
            state: self.0.clone(),
            committed: false,
        }))
    }
    fn read_bytes_raw(&self, _: u64, _: usize) -> Result<Vec<u8>, MemoryError> {
        panic!("terminal sequencing must not use raw reads");
    }
    fn write_bytes_raw(&mut self, _: u64, _: &[u8]) -> Result<(), MemoryError> {
        panic!("owner clear must commit its prepared permit");
    }
}
impl CurrentMmMemory for Memory {}

fn exercise(eager_publication: bool, graph_busy: bool) {
    let mut builder = Builder::new();
    builder.max_threads = 3; // model coordinator, exiting lane, observer
    builder.max_branches = 1_000;
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let state = Arc::new(State {
            graph: Mutex::new(Graph::Live),
            word: AtomicUsize::new(77),
            wakes: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            cancellations: AtomicUsize::new(0),
        });
        let writer = state.clone();
        let exiting = thread::spawn(move || {
            let tid = ThreadId::synthetic_for_tests(77);
            let registry = ThreadRegistry::new(tid);
            registry.set_clear_child_tid(tid, 0x1000);
            let clear = registry.claim_clear_child_tid(tid).unwrap();
            let result = super::threads::retire_with_child_tid_clear(
                &mut Memory(writer.clone()),
                &clear,
                || {
                    if graph_busy {
                        return Err(());
                    }
                    *writer.graph.lock().unwrap() = if eager_publication {
                        Graph::Published
                    } else {
                        Graph::Retired
                    };
                    Ok(())
                },
                || {
                    writer.wakes.fetch_add(1, Ordering::Release);
                },
            )
            .unwrap();
            if result.is_ok() {
                // Matches the caller's RetiredTaskExit::publish boundary.
                *writer.graph.lock().unwrap() = Graph::Published;
                clear.settle();
            }
        });
        let reader = state.clone();
        let observing = thread::spawn(move || {
            let graph = *reader.graph.lock().unwrap();
            if graph == Graph::Published {
                assert_eq!(
                    reader.word.load(Ordering::Relaxed),
                    0,
                    "parent observed exit before clear"
                );
                assert_eq!(
                    reader.wakes.load(Ordering::Acquire),
                    1,
                    "parent observed exit before wake"
                );
            }
            if reader.wakes.load(Ordering::Acquire) != 0 {
                assert_eq!(
                    reader.word.load(Ordering::Relaxed),
                    0,
                    "joiner woke before clear"
                );
                assert_ne!(*reader.graph.lock().unwrap(), Graph::Live);
            }
        });
        exiting.join().unwrap();
        observing.join().unwrap();
        assert_eq!(
            state.commits.load(Ordering::Relaxed),
            usize::from(!graph_busy)
        );
        assert_eq!(
            state.wakes.load(Ordering::Relaxed),
            usize::from(!graph_busy)
        );
        assert_eq!(
            state.cancellations.load(Ordering::Relaxed),
            usize::from(graph_busy)
        );
        assert_eq!(
            *state.graph.lock().unwrap(),
            if graph_busy {
                Graph::Live
            } else {
                Graph::Published
            }
        );
        assert_eq!(
            state.word.load(Ordering::Relaxed),
            if graph_busy { 77 } else { 0 }
        );
    });
}

#[test]
fn clear_and_wake_precede_observable_exit() {
    exercise(false, false);
}

#[test]
fn graph_refusal_cancels_without_clear_wake_or_publication() {
    exercise(false, true);
}

#[test]
#[should_panic(expected = "parent observed exit before")]
fn eager_exit_publication_is_rejected() {
    exercise(true, false);
}
