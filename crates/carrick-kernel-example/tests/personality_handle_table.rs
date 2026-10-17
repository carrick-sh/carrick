//! VM-free kernel-semantics tests for the neutral personality handle table and
//! generation-keyed object pins in `carrick-fd-core` (`carrick-sh/carrick#225`).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use carrick_fd_core::handle::{
    Generation, HandleError, HandleFlags, HandleNumber, HandleNumberCodec, ObjectGuard, ObjectPin,
    ObjectRecord, SlotIndex, decode_handle_number, encode_handle_number,
};
use carrick_fd_core::{
    BackingToken, Core, DescriptorSlot, Extent, LockWait, OfdRecord, SlotBacking, bitmap_words,
};

type SliceExtent = (&'static [DescriptorSlot], &'static [AtomicU64]);

fn extent_arena() -> &'static Mutex<Vec<SliceExtent>> {
    static ARENA: OnceLock<Mutex<Vec<SliceExtent>>> = OnceLock::new();
    ARENA.get_or_init(|| Mutex::new(Vec::new()))
}

fn alloc_extent(capacity: usize) -> Extent {
    let slots: &'static [DescriptorSlot] = Box::leak(
        (0..capacity)
            .map(|_| DescriptorSlot::default())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    let bitmap: &'static [AtomicU64] = Box::leak(
        (0..bitmap_words(capacity))
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    let mut guard = extent_arena().lock().unwrap();
    guard.push((slots, bitmap));
    Extent {
        token: guard.len() as u64,
        capacity: capacity as u64,
    }
}

struct SharedVenue {
    objects: Vec<ObjectRecord>,
}

impl SharedVenue {
    fn new(object_capacity: usize) -> Self {
        Self {
            objects: (0..object_capacity).map(|_| ObjectRecord::new()).collect(),
        }
    }
}

impl SlotBacking for SharedVenue {
    fn resolve(&self, extent: Extent) -> Option<(&[DescriptorSlot], &[AtomicU64])> {
        let (slots, bitmap) = *extent_arena()
            .lock()
            .unwrap()
            .get(extent.token.checked_sub(1)? as usize)?;
        (slots.len() as u64 == extent.capacity).then_some((slots, bitmap))
    }

    fn ofd(&self, _index: usize) -> Option<&OfdRecord> {
        None
    }

    fn object(&self, index: usize) -> Option<&ObjectRecord> {
        self.objects.get(index)
    }
}

#[derive(Clone, Copy)]
struct SpinWait;

impl LockWait for SpinWait {
    fn wait(&self, _attempt: u32) -> bool {
        std::thread::yield_now();
        true
    }
}

/// Criterion 1: Insert, get, duplicate, and close preserve object lifetime
/// until the final reference drops, and handles are scoped to their owning table.
#[test]
fn test_handle_insert_get_duplicate_and_close_preserve_lifetime() {
    let venue = SharedVenue::new(16);
    let core = Core::<4>::new().unwrap();
    let auth = core.bind(&venue, SpinWait);
    auth.publish_objects(16).unwrap();

    let table_a = auth.create_handle_table(8, &mut alloc_extent(8)).unwrap();
    let table_b = auth.create_handle_table(8, &mut alloc_extent(8)).unwrap();

    let h1 = auth
        .insert_handle(table_a, BackingToken(101), HandleFlags::DEFAULT)
        .unwrap();
    assert_eq!(h1.slot(), SlotIndex::new(0));
    assert_eq!(h1.generation(), Generation::INITIAL);
    assert_eq!(auth.handle_table_live_count(table_a), Ok(1));

    // A handle from `table_a` is rejected when presented to `table_b`.
    assert_eq!(auth.get_handle(table_b, h1), Err(HandleError::Stale));
    assert_eq!(auth.close_handle(table_b, h1), Err(HandleError::Stale));

    // Resolve `h1` into a retained guard; pin count becomes 2 (1 slot + 1 guard).
    let guard1 = auth.get_handle(table_a, h1).unwrap();
    assert_eq!(guard1.backing(), BackingToken(101));
    assert_eq!(guard1.pin(), h1.pin());
    assert_eq!(auth.handle_pin_count(&guard1), Ok(2));

    // Duplicate `h1` into a second slot with custom flags; pin count becomes 3.
    let h2 = auth
        .duplicate_handle_with_flags(table_a, h1, HandleFlags::INHERITABLE)
        .unwrap();
    assert_eq!(h2.slot(), SlotIndex::new(1));
    assert_eq!(auth.handle_flags(table_a, h1), Ok(HandleFlags::DEFAULT));
    assert_eq!(auth.handle_flags(table_a, h2), Ok(HandleFlags::INHERITABLE));
    assert_eq!(auth.handle_pin_count(&guard1), Ok(3));

    // Release the guard first: object stays alive (2 table slots remain).
    assert_eq!(auth.release_handle_pin(guard1), Ok(None));

    // Close the original slot `h1`: object still stays alive via `h2`.
    assert_eq!(auth.close_handle(table_a, h1), Ok(None));
    assert_eq!(auth.get_handle(table_a, h1), Err(HandleError::Stale));

    // Duplicate `h2` STILL resolves to the live object.
    let guard2 = auth.get_handle(table_a, h2).unwrap();
    assert_eq!(guard2.backing(), BackingToken(101));
    assert_eq!(auth.release_handle_pin(guard2), Ok(None));

    // Closing the final slot `h2` drops the last reference and returns the token.
    assert_eq!(auth.close_handle(table_a, h2), Ok(Some(BackingToken(101))));
    assert_eq!(auth.handle_table_live_count(table_a), Ok(0));

    auth.destroy_handle_table(table_a, |_| panic!("already empty"))
        .unwrap();
    auth.destroy_handle_table(table_b, |_| panic!("already empty"))
        .unwrap();
}

/// Criterion 2: A closed and reused slot rejects an older `ObjectPin` and
/// older `Handle` (ABA protection).
#[test]
fn test_recycled_slot_rejects_stale_generation_pin_and_handle() {
    let venue = SharedVenue::new(8);
    let core = Core::<2>::new().unwrap();
    let auth = core.bind(&venue, SpinWait);
    auth.publish_objects(8).unwrap();

    let table = auth.create_handle_table(4, &mut alloc_extent(4)).unwrap();

    let h_first = auth
        .insert_handle(table, BackingToken(11), HandleFlags::DEFAULT)
        .unwrap();
    let pin_first: ObjectPin = h_first.pin();
    assert_eq!(pin_first.slot, SlotIndex::new(0));
    assert_eq!(pin_first.generation, Generation::new(1).unwrap());

    assert_eq!(
        auth.close_handle(table, h_first),
        Ok(Some(BackingToken(11)))
    );

    // Next insertion reuses slot 0 with generation 2.
    let h_second = auth
        .insert_handle(table, BackingToken(22), HandleFlags::DEFAULT)
        .unwrap();
    let pin_second = h_first.pin();
    assert_eq!(h_second.slot(), SlotIndex::new(0));
    assert_eq!(h_second.generation(), Generation::new(2).unwrap());

    // Old handle and old ObjectPin are rejected with HandleError::Stale.
    assert_eq!(auth.get_handle(table, h_first), Err(HandleError::Stale));
    assert_eq!(
        auth.get_handle_pin(table, pin_second),
        Err(HandleError::Stale)
    );
    assert_eq!(auth.close_handle(table, h_first), Err(HandleError::Stale));
    assert_eq!(
        auth.duplicate_handle(table, h_first),
        Err(HandleError::Stale)
    );
    assert_eq!(
        auth.set_handle_flags(table, h_first, HandleFlags::INHERITABLE),
        Err(HandleError::Stale)
    );

    // Current handle resolves to the new object.
    let guard = auth.get_handle(table, h_second).unwrap();
    assert_eq!(guard.backing(), BackingToken(22));
    assert_eq!(auth.release_handle_pin(guard), Ok(None));
    assert_eq!(
        auth.close_handle(table, h_second),
        Ok(Some(BackingToken(22)))
    );
    auth.destroy_handle_table(table, |_| {}).unwrap();
}

/// Criterion 3: Inheritance copies only inheritable entries accepted by the
/// filter, retains shared object lifetime, and scopes handles to their table.
#[test]
fn test_handle_inheritance_copies_only_inheritable_filtered_entries_and_retains_lifetime() {
    let venue = SharedVenue::new(16);
    let core = Core::<4>::new().unwrap();
    let auth = core.bind(&venue, SpinWait);
    auth.publish_objects(16).unwrap();

    let parent = auth.create_handle_table(8, &mut alloc_extent(8)).unwrap();

    // Slot 0: private (non-inheritable).
    let h_priv = auth
        .insert_handle(parent, BackingToken(10), HandleFlags::DEFAULT)
        .unwrap();
    // Slot 1: inheritable and accepted by filter.
    let h_inh_keep = auth
        .insert_handle(parent, BackingToken(20), HandleFlags::INHERITABLE)
        .unwrap();
    // Slot 2: inheritable but rejected by caller filter.
    let h_inh_drop = auth
        .insert_handle(parent, BackingToken(30), HandleFlags::INHERITABLE)
        .unwrap();

    let child = auth
        .inherit_handle_table(
            parent,
            |_pin, backing, _flags| backing != BackingToken(30),
            &mut alloc_extent(8),
            |_| panic!("unexpected rollback release"),
        )
        .unwrap();

    // Parent handle `h_inh_keep` is scoped to parent's TableId and cannot be used directly on child.
    assert_eq!(auth.get_handle(child, h_inh_keep), Err(HandleError::Stale));

    // Only slot 1 is populated in the child table.
    assert_eq!(auth.handle_table_live_count(child), Ok(1));
    assert_eq!(
        auth.handle_at(child, h_priv.slot()),
        Err(HandleError::Stale)
    );
    assert_eq!(
        auth.handle_at(child, h_inh_drop.slot()),
        Err(HandleError::Stale)
    );
    assert_eq!(
        auth.get_handle_pin(child, h_priv.pin()),
        Err(HandleError::Stale),
        "uninherited slot advances generation in child"
    );

    let child_h1 = auth.handle_at(child, h_inh_keep.slot()).unwrap();
    assert_eq!(child_h1.pin(), h_inh_keep.pin());

    // Closing `h_inh_keep` in parent does NOT finalize BackingToken(20) because child holds it.
    assert_eq!(auth.close_handle(parent, h_inh_keep), Ok(None));
    // Closing `h_priv` and `h_inh_drop` in parent DOES finalize them immediately.
    assert_eq!(
        auth.close_handle(parent, h_priv),
        Ok(Some(BackingToken(10)))
    );
    assert_eq!(
        auth.close_handle(parent, h_inh_drop),
        Ok(Some(BackingToken(30)))
    );

    // Child still resolves `child_h1` to BackingToken(20), and closing it finalizes it.
    let guard = auth.get_handle(child, child_h1).unwrap();
    assert_eq!(guard.backing(), BackingToken(20));
    assert_eq!(auth.release_handle_pin(guard), Ok(None));
    assert_eq!(
        auth.close_handle(child, child_h1),
        Ok(Some(BackingToken(20)))
    );

    auth.destroy_handle_table(parent, |_| panic!("nothing left"))
        .unwrap();
    auth.destroy_handle_table(child, |_| panic!("nothing left"))
        .unwrap();
}

/// Criterion 5 + P1-3: Table capacity limit refuses cleanly with `TableFull`,
/// and exhausted slot generations (`Generation::MAX`) permanently retire the
/// slot (releasing the object, never reusing the slot, and lowering reported
/// capacity) on close, exit, and inherit.
#[test]
fn test_table_capacity_limit_and_slot_generation_exhaustion_retire_permanently() {
    let venue = SharedVenue::new(16);
    let core = Core::<4>::new().unwrap();
    let auth = core.bind(&venue, SpinWait);
    auth.publish_objects(16).unwrap();

    let table = auth.create_handle_table(3, &mut alloc_extent(4)).unwrap();
    assert_eq!(auth.handle_table_capacity(table), Ok(3));

    // Seed slot 0 and slot 1 at Generation::MAX.
    auth.seed_handle_slot_generation(table, SlotIndex::new(0), Generation::MAX)
        .unwrap();
    auth.seed_handle_slot_generation(table, SlotIndex::new(1), Generation::MAX)
        .unwrap();

    let h0 = auth
        .insert_handle(table, BackingToken(1), HandleFlags::INHERITABLE)
        .unwrap();
    let h1 = auth
        .insert_handle(table, BackingToken(2), HandleFlags::INHERITABLE)
        .unwrap();
    let h2 = auth
        .insert_handle(table, BackingToken(3), HandleFlags::INHERITABLE)
        .unwrap();
    assert_eq!(h0.generation(), Generation::MAX);
    assert_eq!(h1.generation(), Generation::MAX);

    // Table is at capacity 3: fourth insert and duplicate both refuse with TableFull.
    assert_eq!(
        auth.insert_handle(table, BackingToken(4), HandleFlags::DEFAULT),
        Err(HandleError::TableFull)
    );
    assert_eq!(
        auth.duplicate_handle(table, h2),
        Err(HandleError::TableFull)
    );

    // 1. Close `h0` at Generation::MAX: object 1 is released, slot 0 is retired
    //    permanently, capacity drops from 3 to 2, and a new insert is refused!
    assert_eq!(auth.close_handle(table, h0), Ok(Some(BackingToken(1))));
    assert_eq!(auth.handle_table_capacity(table), Ok(2));
    assert_eq!(auth.handle_table_live_count(table), Ok(2));
    assert_eq!(
        auth.insert_handle(table, BackingToken(5), HandleFlags::DEFAULT),
        Err(HandleError::TableFull),
        "permanently retired slot 0 reduces usable capacity from 3 to 2"
    );

    // 2. Inherit into `child` while filtering out `h1` (which is at Generation::MAX):
    //    `child` inherits retired slot 0 AND retires filtered-out slot 1, so child's
    //    usable capacity is 3 - 2 = 1 (occupied by inherited `h2` at slot 2).
    let child = auth
        .inherit_handle_table(
            table,
            |_pin, backing, _flags| backing == BackingToken(3),
            &mut alloc_extent(4),
            |_| panic!("unexpected rollback release"),
        )
        .unwrap();
    assert_eq!(auth.handle_table_capacity(child), Ok(1));
    assert_eq!(auth.handle_table_live_count(child), Ok(1));
    assert_eq!(
        auth.insert_handle(child, BackingToken(6), HandleFlags::DEFAULT),
        Err(HandleError::TableFull),
        "child has 2 retired slots (0 and 1) and 1 live slot (2) out of limit 3"
    );

    // 3. Destroy `table`: releases remaining objects (2, while 3 stays retained in child).
    let mut parent_released = Vec::new();
    auth.destroy_handle_table(table, |tok| parent_released.push(tok))
        .unwrap();
    assert_eq!(parent_released, vec![BackingToken(2)]);

    let mut child_released = Vec::new();
    auth.destroy_handle_table(child, |tok| child_released.push(tok))
        .unwrap();
    assert_eq!(child_released, vec![BackingToken(3)]);
}

/// Criterion 6: Typed `HandleNumber` and `HandleNumberCodec` round-trip and
/// reject malformed user handle numbers.
#[test]
fn test_handle_number_codec_round_trip_and_invalid_number_rejection() {
    for raw in [0u32, 1, 7, 1024, 65_535] {
        let slot = SlotIndex::new(raw);
        let num = encode_handle_number(HandleNumberCodec::DIRECT, slot).unwrap();
        assert_eq!(num, HandleNumber::new(raw as u64));
        assert_eq!(
            decode_handle_number(HandleNumberCodec::DIRECT, num),
            Ok(slot)
        );
    }

    let codec = HandleNumberCodec::new(0x100, NonZeroU64::new(4).unwrap(), 0b11, 0b10).unwrap();
    let n0 = codec.encode(SlotIndex::new(0)).unwrap();
    let n5 = codec.encode(SlotIndex::new(5)).unwrap();
    assert_eq!(n0, HandleNumber::new(0x102));
    assert_eq!(n5, HandleNumber::new(0x116));
    assert_eq!(codec.decode(n0), Ok(SlotIndex::new(0)));
    assert_eq!(codec.decode(n5), Ok(SlotIndex::new(5)));

    assert_eq!(
        codec.decode(HandleNumber::new(0x100)),
        Err(HandleError::InvalidHandle)
    );
    assert_eq!(
        codec.decode(HandleNumber::new(0x02)),
        Err(HandleError::InvalidHandle)
    );
    assert_eq!(
        codec.decode(HandleNumber::new(0x104)),
        Err(HandleError::InvalidHandle)
    );

    let venue = SharedVenue::new(4);
    let core = Core::<2>::new().unwrap();
    let auth = core.bind(&venue, SpinWait);
    auth.publish_objects(4).unwrap();

    let table = auth.create_handle_table(8, &mut alloc_extent(8)).unwrap();
    let h = auth
        .insert_handle(table, BackingToken(900), HandleFlags::DEFAULT)
        .unwrap();
    let user_num = codec.encode(h.slot()).unwrap();
    let (resolved_h, guard) = auth.get_handle_by_number(table, codec, user_num).unwrap();
    assert_eq!(resolved_h, h);
    assert_eq!(guard.backing(), BackingToken(900));
    assert_eq!(auth.release_handle_pin(guard), Ok(None));
    assert_eq!(auth.close_handle(table, h), Ok(Some(BackingToken(900))));
    auth.destroy_handle_table(table, |_| {}).unwrap();
}

/// P1-1 & P1-2: `get_handle` returns a retained `ObjectGuard` that prevents
/// finalization across `close_handle` and `destroy_handle_table`, supports 16+
/// concurrent guards, is consumed by value on `release_handle_pin`, and
/// `RawObjectGuard::take` prevents double release across continuation slots.
#[test]
fn test_retained_guard_prevents_finalization_and_refuses_double_release() {
    let venue = SharedVenue::new(8);
    let core = Core::<2>::new().unwrap();
    let auth = core.bind(&venue, SpinWait);
    auth.publish_objects(8).unwrap();

    let table = auth.create_handle_table(4, &mut alloc_extent(4)).unwrap();
    let h = auth
        .insert_handle(table, BackingToken(777), HandleFlags::DEFAULT)
        .unwrap();

    let mut guards = Vec::with_capacity(16);
    for i in 0..16 {
        let g = if i == 0 {
            auth.get_handle(table, h).unwrap()
        } else {
            auth.retain_handle_pin(&guards[0]).unwrap()
        };
        guards.push(g);
    }
    assert_eq!(auth.handle_pin_count(&guards[0]), Ok(17));

    // Close the table handle while 16 guards are live: does NOT finalize.
    assert_eq!(auth.close_handle(table, h), Ok(None));
    assert_eq!(auth.handle_pin_count(&guards[0]), Ok(16));

    for g in guards.drain(..15) {
        assert_eq!(auth.release_handle_pin(g), Ok(None));
    }
    let last_guard = guards.pop().unwrap();
    assert_eq!(auth.handle_pin_count(&last_guard), Ok(1));

    // Convert last guard into move-only RawObjectGuard in a continuation slot and take once.
    let mut continuation_slot = last_guard.into_raw();
    let restored = ObjectGuard::from_raw(continuation_slot.take()).unwrap();
    assert_eq!(
        ObjectGuard::from_raw(continuation_slot.take()),
        Err(HandleError::Stale)
    );
    assert_eq!(
        auth.release_handle_pin(restored),
        Ok(Some(BackingToken(777)))
    );
    auth.destroy_handle_table(table, |_| {}).unwrap();
}

/// Concurrency: `inherit_handle_table` racing a concurrent `close_handle` on
/// the parent table, followed by `destroy_handle_table` racing a concurrent
/// `close_handle` on the child table, finalizes every object reference once.
#[test]
fn test_inherit_and_destroy_racing_concurrent_close_finalize_exactly_once() {
    let venue = SharedVenue::new(16);
    let core = Core::<4>::new().unwrap();
    let auth = core.bind(&venue, SpinWait);
    auth.publish_objects(16).unwrap();

    let mut parent_ext = alloc_extent(8);
    let mut child_ext = alloc_extent(8);

    for round in 1..=200u64 {
        let parent = auth.create_handle_table(8, &mut parent_ext).unwrap();

        let h0 = auth
            .insert_handle(parent, BackingToken(round * 2), HandleFlags::INHERITABLE)
            .unwrap();
        let h1 = auth
            .insert_handle(
                parent,
                BackingToken(round * 2 + 1),
                HandleFlags::INHERITABLE,
            )
            .unwrap();

        let releases_0 = AtomicUsize::new(0);
        let releases_1 = AtomicUsize::new(0);
        let tok0 = BackingToken(round * 2);
        let tok1 = BackingToken(round * 2 + 1);
        let record_release = |tok: BackingToken| {
            if tok == tok0 {
                releases_0.fetch_add(1, Ordering::Relaxed);
            } else if tok == tok1 {
                releases_1.fetch_add(1, Ordering::Relaxed);
            } else {
                panic!("unexpected token released: {tok:?}");
            }
        };

        let mut child_opt = None;
        std::thread::scope(|s| {
            s.spawn(|| {
                if let Some(tok) = auth.close_handle(parent, h0).unwrap() {
                    record_release(tok);
                }
            });
            child_opt = Some(
                auth.inherit_handle_table(
                    parent,
                    |_pin, _tok, _flags| {
                        std::thread::yield_now();
                        true
                    },
                    &mut child_ext,
                    &record_release,
                )
                .unwrap(),
            );
        });
        let child = child_opt.unwrap();

        let child_h1 = auth.handle_at(child, h1.slot()).unwrap();
        std::thread::scope(|s| {
            s.spawn(|| {
                if let Some(tok) = auth.close_handle(child, child_h1).unwrap() {
                    record_release(tok);
                }
            });
            parent_ext = auth.destroy_handle_table(parent, &record_release).unwrap();
        });

        child_ext = auth.destroy_handle_table(child, &record_release).unwrap();

        assert_eq!(
            releases_0.load(Ordering::Relaxed),
            1,
            "round {round}: token 0 must be released exactly once"
        );
        assert_eq!(
            releases_1.load(Ordering::Relaxed),
            1,
            "round {round}: token 1 must be released exactly once"
        );
    }
}
