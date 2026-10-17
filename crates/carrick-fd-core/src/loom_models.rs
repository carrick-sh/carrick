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

#[derive(Default)]
struct HandleLoomBacking {
    slots: [[DescriptorSlot; 2]; 2],
    bitmaps: [[AtomicU64; 1]; 2],
    objects: [ObjectRecord; 2],
}

use crate::handle::*;

impl SlotBacking for HandleLoomBacking {
    fn resolve(&self, extent: Extent) -> Option<(&[DescriptorSlot], &[AtomicU64])> {
        let idx = extent.token.checked_sub(1)? as usize;
        let slots = &self.slots.get(idx)?[..extent.capacity as usize];
        let bitmap = &self.bitmaps.get(idx)?[..];
        Some((slots, bitmap))
    }

    fn ofd(&self, _: usize) -> Option<&OfdRecord> {
        None
    }

    fn object(&self, index: usize) -> Option<&ObjectRecord> {
        self.objects.get(index)
    }
}

#[derive(Clone, Copy)]
struct YieldWait;
impl LockWait for YieldWait {
    fn wait(&self, attempt: u32) -> bool {
        if attempt > 4 {
            return false;
        }
        loom::thread::yield_now();
        true
    }
}

#[test]
fn handle_get_racing_close_retains_guard_and_finalizes_once() {
    model(|| {
        let core = Arc::new(Core::<1>::new().unwrap());
        let backing = Arc::new(HandleLoomBacking::default());
        let view = core.bind(&*backing, YieldWait);
        view.publish_objects(2).unwrap();
        let mut ext = Extent {
            token: 1,
            capacity: 2,
        };
        let table = view.create_handle_table(2, &mut ext).unwrap();
        let h = view
            .insert_handle(table, BackingToken(42), HandleFlags::DEFAULT)
            .unwrap();

        let closer_core = core.clone();
        let closer_backing = backing.clone();
        let closer = thread::spawn(move || {
            closer_core
                .bind(&*closer_backing, YieldWait)
                .close_handle(table, h)
                .unwrap()
        });

        let getter_core = core.clone();
        let getter_backing = backing.clone();
        let getter = thread::spawn(move || {
            let v = getter_core.bind(&*getter_backing, YieldWait);
            match v.get_handle(table, h) {
                Ok(guard) => {
                    assert_eq!(guard.backing(), BackingToken(42));
                    assert!(
                        !getter_backing.objects[0].lifetime.is_terminal(1),
                        "close_handle must not finalize object while ObjectGuard is live"
                    );
                    assert!(v.handle_pin_count(&guard).unwrap() >= 1);
                    v.release_handle_pin(guard).unwrap()
                }
                Err(HandleError::Stale | HandleError::Contended) => None,
                Err(other) => panic!("unexpected error from get_handle: {other:?}"),
            }
        });

        let released = [closer.join().unwrap(), getter.join().unwrap()];
        assert_eq!(released.iter().filter(|b| b.is_some()).count(), 1);
        assert_eq!(
            released.into_iter().flatten().next(),
            Some(BackingToken(42))
        );

        let h2 = view
            .insert_handle(table, BackingToken(99), HandleFlags::DEFAULT)
            .unwrap();
        assert_eq!(h2.slot(), h.slot());
        assert_ne!(h2.generation(), h.generation());
        assert_eq!(view.get_handle(table, h), Err(HandleError::Stale));
        assert_eq!(view.close_handle(table, h2), Ok(Some(BackingToken(99))));
    });
}

#[test]
fn handle_destroy_racing_close_from_second_table_releases_once() {
    model(|| {
        let core = Arc::new(Core::<2>::new().unwrap());
        let backing = Arc::new(HandleLoomBacking::default());
        let view = core.bind(&*backing, YieldWait);
        view.publish_objects(2).unwrap();

        let mut parent_ext = Extent {
            token: 1,
            capacity: 2,
        };
        let mut child_ext = Extent {
            token: 2,
            capacity: 2,
        };
        let parent_table = view.create_handle_table(2, &mut parent_ext).unwrap();
        let parent_h = view
            .insert_handle(parent_table, BackingToken(77), HandleFlags::INHERITABLE)
            .unwrap();
        let child_table = view
            .inherit_handle_table(
                parent_table,
                |_, _, _| true,
                &mut child_ext,
                |_| panic!("unexpected rollback release"),
            )
            .unwrap();
        let child_h = view.handle_at(child_table, parent_h.slot()).unwrap();

        let exiter_core = core.clone();
        let exiter_backing = backing.clone();
        let exiter = thread::spawn(move || {
            let mut finalized = None;
            exiter_core
                .bind(&*exiter_backing, YieldWait)
                .destroy_handle_table(parent_table, |b| {
                    assert!(finalized.replace(b).is_none());
                })
                .unwrap();
            finalized
        });

        let closer_core = core.clone();
        let closer_backing = backing.clone();
        let closer = thread::spawn(move || {
            closer_core
                .bind(&*closer_backing, YieldWait)
                .close_handle(child_table, child_h)
                .unwrap()
        });

        let released = [exiter.join().unwrap(), closer.join().unwrap()];
        assert_eq!(released.iter().filter(|b| b.is_some()).count(), 1);
        assert_eq!(
            released.into_iter().flatten().next(),
            Some(BackingToken(77))
        );
    });
}

#[test]
fn handle_inherit_racing_parent_close_retains_or_skips_and_finalizes_once() {
    model(|| {
        let core = Arc::new(Core::<2>::new().unwrap());
        let backing = Arc::new(HandleLoomBacking::default());
        let view = core.bind(&*backing, YieldWait);
        view.publish_objects(1).unwrap();

        let mut parent_ext = Extent {
            token: 1,
            capacity: 1,
        };
        let parent = view.create_handle_table(1, &mut parent_ext).unwrap();
        let h = view
            .insert_handle(parent, BackingToken(64), HandleFlags::INHERITABLE)
            .unwrap();

        let inheritor_core = core.clone();
        let inheritor_backing = backing.clone();
        let inheritor = thread::spawn(move || {
            let v = inheritor_core.bind(&*inheritor_backing, YieldWait);
            let mut child_ext = Extent {
                token: 2,
                capacity: 1,
            };
            let mut finalized = None;
            let child = v
                .inherit_handle_table(
                    parent,
                    |_pin, _tok, _flags| true,
                    &mut child_ext,
                    |b| {
                        assert!(finalized.replace(b).is_none());
                    },
                )
                .unwrap();
            v.destroy_handle_table(child, |b| {
                assert!(finalized.replace(b).is_none());
            })
            .unwrap();
            finalized
        });

        let closer_core = core.clone();
        let closer_backing = backing.clone();
        let closer = thread::spawn(move || {
            closer_core
                .bind(&*closer_backing, YieldWait)
                .close_handle(parent, h)
                .unwrap()
        });

        let released = [inheritor.join().unwrap(), closer.join().unwrap()];
        assert_eq!(released.iter().filter(|b| b.is_some()).count(), 1);
        assert_eq!(
            released.into_iter().flatten().next(),
            Some(BackingToken(64))
        );
    });
}
