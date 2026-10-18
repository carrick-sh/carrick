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
    slots: [[DescriptorSlot; 2]; 3],
    bitmaps: [[AtomicU64; 1]; 3],
    objects: [ObjectRecord; 2],
}

use crate::handle::*;
use carrick_sched_core::process::TaskKey;

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

fn loom_task_key(id: i32, serial: u64) -> TaskKey {
    use carrick_sched_core::process::{TaskId, TaskSerial};
    use core::num::NonZeroI32;
    TaskKey {
        id: TaskId::from_registry_allocation(NonZeroI32::new(id).unwrap()),
        serial: TaskSerial::from_raw_u64(serial).unwrap(),
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
fn task_exit_racing_close_from_second_live_task_releases_once() {
    model(|| {
        let task_core = Arc::new(TaskHandleCore::<2>::new().unwrap());
        let backing = Arc::new(HandleLoomBacking::default());
        let host = task_core.bind(&*backing, YieldWait);
        host.publish_objects(2).unwrap();

        let parent_task = loom_task_key(1, 1);
        let child_task = loom_task_key(2, 2);
        let mut parent_ext = Extent {
            token: 1,
            capacity: 2,
        };
        let mut child_ext = Extent {
            token: 2,
            capacity: 2,
        };
        host.create_task_table(parent_task, 2, &mut parent_ext)
            .unwrap();
        let parent_h = host
            .insert(parent_task, BackingToken(77), HandleFlags::INHERITABLE)
            .unwrap();
        host.inherit_task(
            parent_task,
            child_task,
            |_, _, _| true,
            &mut child_ext,
            |_| panic!("unexpected rollback release"),
        )
        .unwrap();
        let child_h = host.handle_at(child_task, parent_h.slot()).unwrap();

        let exiter_core = task_core.clone();
        let exiter_backing = backing.clone();
        let exiter = thread::spawn(move || {
            let mut finalized = None;
            exiter_core
                .bind(&*exiter_backing, YieldWait)
                .exit_task(parent_task, |b| {
                    assert!(finalized.replace(b).is_none());
                })
                .unwrap();
            finalized
        });

        let closer_core = task_core.clone();
        let closer_backing = backing.clone();
        let closer = thread::spawn(move || {
            closer_core
                .bind(&*closer_backing, YieldWait)
                .close(child_task, child_h)
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
fn task_exit_racing_same_task_close_releases_once() {
    model(|| {
        let task_core = Arc::new(TaskHandleCore::<1>::new().unwrap());
        let backing = Arc::new(HandleLoomBacking::default());
        let host = task_core.bind(&*backing, YieldWait);
        host.publish_objects(1).unwrap();

        let task = loom_task_key(1, 1);
        let mut ext = Extent {
            token: 1,
            capacity: 2,
        };
        host.create_task_table(task, 2, &mut ext).unwrap();
        let h = host
            .insert(task, BackingToken(55), HandleFlags::DEFAULT)
            .unwrap();

        let exiter_core = task_core.clone();
        let exiter_backing = backing.clone();
        let exiter = thread::spawn(move || {
            let mut finalized = None;
            exiter_core
                .bind(&*exiter_backing, YieldWait)
                .exit_task(task, |b| {
                    assert!(finalized.replace(b).is_none());
                })
                .unwrap();
            finalized
        });

        let closer_core = task_core.clone();
        let closer_backing = backing.clone();
        let closer = thread::spawn(move || {
            match closer_core.bind(&*closer_backing, YieldWait).close(task, h) {
                Ok(released) => released,
                Err(HandleError::Stale) => None,
                Err(other) => panic!("unexpected close error: {other:?}"),
            }
        });

        let released = [exiter.join().unwrap(), closer.join().unwrap()];
        assert_eq!(released.iter().filter(|b| b.is_some()).count(), 1);
        assert_eq!(
            released.into_iter().flatten().next(),
            Some(BackingToken(55))
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

#[test]
fn task_bucket_rebind_never_exposes_torn_table_id_to_lock_free_lookup() {
    model(|| {
        let t0 = loom_task_key(1, 1);
        let task_core = Arc::new(TaskHandleCore::<3>::new().unwrap());
        let backing = Arc::new(HandleLoomBacking::default());
        let host = task_core.bind(&*backing, YieldWait);
        let view = host.authority();

        // Allocate table index 0 as a placeholder so our bound tables use
        // non-zero table indices (`index == 1` and `index == 2`) with distinct
        // generations (`generation == 11` and `generation == 29`).
        let mut ext0 = Extent {
            token: 1,
            capacity: 1,
        };
        let _placeholder = view.create_handle_table(1, &mut ext0).unwrap();
        task_core.core().tables[1]
            .generation
            .store(10, Ordering::Relaxed);
        task_core.core().tables[2]
            .generation
            .store(28, Ordering::Relaxed);

        let mut ext1 = Extent {
            token: 2,
            capacity: 1,
        };
        let table1 = host.create_task_table(t0, 1, &mut ext1).unwrap();
        assert_eq!(table1.index, 1);
        assert_eq!(table1.generation, 11);

        let mut ext2 = Extent {
            token: 3,
            capacity: 1,
        };
        let table2 = view.create_handle_table(1, &mut ext2).unwrap();
        assert_eq!(table2.index, 2);
        assert_eq!(table2.generation, 29);

        let writer_tasks = task_core.clone();
        let writer_backing = backing.clone();
        let writer = thread::spawn(move || {
            let th = writer_tasks.bind(&*writer_backing, YieldWait);
            th.exit_task(t0, |_| {}).unwrap();
            th.attach_task_table(t0, table2).unwrap();
        });

        let reader_tasks = task_core.clone();
        let reader_backing = backing.clone();
        let reader = thread::spawn(move || {
            let th = reader_tasks.bind(&*reader_backing, NoWait);
            match th.table_id(t0) {
                Ok(observed) => {
                    assert!(
                        observed == table1 || observed == table2,
                        "torn TableId observed from lock-free TaskBucket lookup: {observed:?} (expected {table1:?} or {table2:?})"
                    );
                }
                Err(HandleError::Stale | HandleError::Contended) => {}
                Err(other) => panic!("unexpected table_id error: {other:?}"),
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();
        assert_eq!(host.table_id(t0), Ok(table2));
    });
}

#[test]
fn task_cross_bucket_recycle_authenticates_original_bucket_sequence() {
    model(|| {
        let tasks = Arc::new(TaskHandleCore::<3>::new().unwrap());
        let backing = Arc::new(HandleLoomBacking::default());
        let host = tasks.bind(&*backing, YieldWait);
        let old_task = loom_task_key(1, 1); // bucket 2
        let new_task = loom_task_key(2, 1); // bucket 1
        let anchor = loom_task_key(4, 1); // bucket 1, forces a cross-bucket next link
        tasks.core().tables[0]
            .generation
            .store(10, Ordering::Relaxed);
        tasks.core().tables[2]
            .generation
            .store(28, Ordering::Relaxed);
        let old_table = host
            .create_task_table(
                old_task,
                1,
                &mut Extent {
                    token: 1,
                    capacity: 1,
                },
            )
            .unwrap();
        let anchor_table = host
            .create_task_table(
                anchor,
                1,
                &mut Extent {
                    token: 2,
                    capacity: 1,
                },
            )
            .unwrap();
        let new_table = host
            .authority()
            .create_handle_table(
                1,
                &mut Extent {
                    token: 3,
                    capacity: 1,
                },
            )
            .unwrap();
        assert_eq!(tasks.buckets[2].head.load(Ordering::Relaxed), 1);
        assert_eq!(tasks.buckets[1].head.load(Ordering::Relaxed), 2);
        let writer_tasks = tasks.clone();
        let writer_backing = backing.clone();
        let writer = thread::spawn(move || {
            let h = writer_tasks.bind(&*writer_backing, YieldWait);
            h.exit_task(old_task, |_| {}).unwrap();
            h.attach_task_table(new_task, new_table).unwrap();
            // The same binding record now links into the other bucket.
            assert_eq!(writer_tasks.buckets[1].head.load(Ordering::Relaxed), 1);
            assert_eq!(
                writer_tasks.bindings[0].hash_next.load(Ordering::Relaxed),
                2
            );
        });
        let reader_tasks = tasks.clone();
        let reader_backing = backing.clone();
        let reader = thread::spawn(move || {
            let h = reader_tasks.bind(&*reader_backing, NoWait);
            for (task, expected) in [(old_task, old_table), (new_task, new_table)] {
                match h.table_id(task) {
                    Ok(table) => assert_eq!(
                        table, expected,
                        "cross-bucket recycled binding exposed a foreign table"
                    ),
                    Err(HandleError::Stale | HandleError::Contended) => {}
                    Err(other) => panic!("unexpected lookup error: {other:?}"),
                }
            }
        });
        writer.join().unwrap();
        reader.join().unwrap();
        assert_eq!(host.table_id(old_task), Err(HandleError::Stale));
        assert_eq!(host.table_id(new_task), Ok(new_table));
        assert_eq!(host.table_id(anchor), Ok(anchor_table));
    });
}
