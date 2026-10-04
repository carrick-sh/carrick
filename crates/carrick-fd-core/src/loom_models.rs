//! Bounded witnesses over the production sequence and hold algorithms.
//! Two actors, one table/description. Loom does not establish ABI layout or
//! exhaustive kernel correctness; ordinary unit tests retain those bindings.
#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;
use loom::{model::Builder, sync::Arc, thread};

fn model(f: impl Fn() + Send + Sync + 'static) {
    let mut builder = Builder::new();
    builder.max_threads = 3; // coordinator plus two actors
    builder.max_branches = 1_000;
    builder.preemption_bound = Some(2);
    builder.check(f);
}

#[test]
fn table_sequence_publishes_a_complete_pair() {
    model(|| {
        let record = Arc::new(TableRecord::default());
        let writer = record.clone();
        let writing = thread::spawn(move || {
            writer.begin_write();
            writer.extent_token.store(7, Ordering::Relaxed);
            writer.extent_capacity.store(8, Ordering::Relaxed);
            writer.end_write();
        });
        let reader = record.clone();
        let reading = thread::spawn(move || {
            // Same bounded single lookup attempt as Authority::get: an odd
            // or changed sequence means retry, not an accepted torn view.
            let sequence = reader.seq.load(Ordering::Acquire);
            if sequence & 1 != 0 {
                return;
            }
            let token = reader.extent_token.load(Ordering::Relaxed);
            let capacity = reader.extent_capacity.load(Ordering::Relaxed);
            if reader.unchanged_since(sequence) {
                assert!(matches!((token, capacity), (0, 0) | (7, 8)));
                if sequence == 2 {
                    assert_eq!((token, capacity), (7, 8));
                }
            }
        });
        writing.join().unwrap();
        reading.join().unwrap();
        assert_eq!(record.seq.load(Ordering::Acquire), 2);
    });
}

struct Backing(OfdRecord);
impl SlotBacking for Backing {
    fn resolve(&self, _: Extent) -> Option<(&[DescriptorSlot], &[AtomicU64])> {
        None
    }
    fn ofd(&self, index: usize) -> Option<&OfdRecord> {
        (index == 0).then_some(&self.0)
    }
}
struct NoWait;
impl LockWait for NoWait {
    fn wait(&self, _: u32) -> bool {
        false
    }
}

#[test]
fn pin_racing_last_reference_releases_once_and_rejects_reuse() {
    model(|| {
        let core = Arc::new(Core::<1>::new().unwrap());
        let backing = Arc::new(Backing(OfdRecord::default()));
        let view = core.bind(&*backing, NoWait);
        view.publish_ofds(1).unwrap();
        let original = Description::new(
            BackingToken(7),
            AccessMode::ReadOnly,
            StatusFlags::default(),
        );
        let index = view.alloc_ofd(original).unwrap();
        let stale = RawOfdPin {
            authority: view.identity().unwrap(),
            index: u64::from(index),
            generation: backing.0.generation.load(Ordering::Acquire),
        };
        let closer_core = core.clone();
        let closer_backing = backing.clone();
        let closer = thread::spawn(move || {
            closer_core
                .bind(&*closer_backing, NoWait)
                .drop_hold(index, REF)
                .unwrap()
        });
        let pinner_core = core.clone();
        let pinner_backing = backing.clone();
        let pinner = thread::spawn(move || {
            let view = pinner_core.bind(&*pinner_backing, NoWait);
            if view.retain_unless_final(index, PIN).unwrap() {
                assert_eq!(view.snapshot(index).unwrap(), original);
                view.drop_hold(index, PIN).unwrap()
            } else {
                None
            }
        });
        let released = [closer.join().unwrap(), pinner.join().unwrap()];
        assert_eq!(released.iter().filter(|d| d.is_some()).count(), 1);
        assert_eq!(released.into_iter().flatten().next(), Some(original));
        assert_eq!(backing.0.holds.load(Ordering::Acquire), 0);
        let replacement = view
            .create_pinned(Description::new(
                BackingToken(9),
                AccessMode::ReadOnly,
                StatusFlags::default(),
            ))
            .unwrap();
        assert_eq!(u64::from(replacement.key.index), stale.index);
        assert_eq!(view.pinned(&OfdPin::from_raw(stale)), Err(Error::StalePin));
        assert_eq!(
            view.unpin(replacement).unwrap().unwrap().backing,
            BackingToken(9)
        );
    });
}
