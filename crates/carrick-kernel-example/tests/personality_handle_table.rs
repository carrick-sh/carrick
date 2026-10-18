//! VM-free kernel-semantics tests for the neutral personality handle table and
//! generation-keyed object pins in `carrick-fd-core` (`carrick-sh/carrick#225`).
//!
//! Acceptance criteria (`#225` + review rulings on `#554`):
//! 1. Insert, get, duplicate, and close preserve object lifetime until the
//!    final reference drops (`OpenLifetime`).
//! 2. A closed and reused slot rejects an older `ObjectPin` / `Handle` (ABA).
//! 3. Inheritance copies only inheritable entries accepted by the filter and
//!    retains object lifetime across parent/child tables.
//! 4. Task exit releases every remaining pin and removes the task entry so task
//!    slots can churn beyond `T`.
//! 5. Table capacity limit refuses cleanly without side effects, and exhausted
//!    slot generations (`Generation::MAX`) permanently retire the slot (lowering
//!    reported capacity by one) on close, exit, and inherit.
//! 6. Typed `HandleNumber` and `HandleNumberCodec` round-trip and reject
//!    malformed numbers without leaking host descriptors or pointers.
//! 7. `get_handle` / `TaskHandleHost::get` returns a retained `#[must_use]`
//!    `ObjectGuard` consumed by value on `release_handle_pin`, preventing
//!    finalization while a guard is live and refusing double release.
//! 8. `inherit_task` and `exit_task` safely race concurrent `close` calls from
//!    a second live task, finalizing every backing token exactly once.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::num::{NonZeroI32, NonZeroU64};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use carrick_fd_core::handle::{
    Generation, HandleError, HandleFlags, HandleNumber, HandleNumberCodec, ObjectGuard, ObjectPin,
    ObjectRecord, SlotIndex, TaskHandleCore, decode_handle_number, encode_handle_number,
};
use carrick_fd_core::{
    BackingToken, Core, DescriptorSlot, Extent, LockWait, OfdRecord, SlotBacking, bitmap_words,
};
use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial};

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

fn make_task_key(raw_id: i32, raw_serial: u64) -> TaskKey {
    TaskKey {
        id: TaskId::from_registry_allocation(NonZeroI32::new(raw_id).unwrap()),
        serial: TaskSerial::from_raw_u64(raw_serial).unwrap(),
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
    let task_core = TaskHandleCore::<4>::new().unwrap();
    let host = task_core.bind(&venue, SpinWait);
    host.publish_objects(16).unwrap();

    let parent = make_task_key(1, 1);
    let child = make_task_key(2, 1);
    host.create_task_table(parent, 8, &mut alloc_extent(8))
        .unwrap();

    // Slot 0: private (non-inheritable).
    let h_priv = host
        .insert(parent, BackingToken(10), HandleFlags::DEFAULT)
        .unwrap();
    // Slot 1: inheritable and accepted by filter.
    let h_inh_keep = host
        .insert(parent, BackingToken(20), HandleFlags::INHERITABLE)
        .unwrap();
    // Slot 2: inheritable but rejected by caller filter.
    let h_inh_drop = host
        .insert(parent, BackingToken(30), HandleFlags::INHERITABLE)
        .unwrap();

    host.inherit_task(
        parent,
        child,
        |_pin, backing, _flags| backing != BackingToken(30),
        &mut alloc_extent(8),
        |_| panic!("unexpected rollback release"),
    )
    .unwrap();

    // Parent handle `h_inh_keep` is scoped to parent's TableId and cannot be used directly on child.
    assert_eq!(host.get(child, h_inh_keep), Err(HandleError::Stale));

    // Only slot 1 is populated in the child table.
    assert_eq!(host.live_count(child), Ok(1));
    assert_eq!(
        host.handle_at(child, h_priv.slot()),
        Err(HandleError::Stale)
    );
    assert_eq!(
        host.handle_at(child, h_inh_drop.slot()),
        Err(HandleError::Stale)
    );
    assert_eq!(
        host.get_pin(child, h_priv.pin()),
        Err(HandleError::Stale),
        "uninherited slot advances generation in child"
    );

    let child_h1 = host.handle_at(child, h_inh_keep.slot()).unwrap();
    assert_eq!(child_h1.pin(), h_inh_keep.pin());

    // Closing `h_inh_keep` in parent does NOT finalize BackingToken(20) because child holds it.
    assert_eq!(host.close(parent, h_inh_keep), Ok(None));
    // Closing `h_priv` and `h_inh_drop` in parent DOES finalize them immediately.
    assert_eq!(host.close(parent, h_priv), Ok(Some(BackingToken(10))));
    assert_eq!(host.close(parent, h_inh_drop), Ok(Some(BackingToken(30))));

    // Child still resolves `child_h1` to BackingToken(20), and closing it finalizes it.
    let guard = host.get(child, child_h1).unwrap();
    assert_eq!(guard.backing(), BackingToken(20));
    assert_eq!(host.release_pin(guard), Ok(None));
    assert_eq!(host.close(child, child_h1), Ok(Some(BackingToken(20))));

    host.exit_task(parent, |_| panic!("nothing left")).unwrap();
    host.exit_task(child, |_| panic!("nothing left")).unwrap();
}

/// Criterion 4: Task exit releases every remaining pin and removes the task
/// entry; in-flight guards and child tables keep shared objects alive until
/// their own release.
#[test]
fn test_task_exit_releases_every_remaining_pin_and_reclaims_task_slot() {
    let venue = SharedVenue::new(16);
    let task_core = TaskHandleCore::<4>::new().unwrap();
    let host = task_core.bind(&venue, SpinWait);
    host.publish_objects(16).unwrap();

    let parent = make_task_key(10, 1);
    let child = make_task_key(11, 1);
    host.create_task_table(parent, 8, &mut alloc_extent(8))
        .unwrap();

    let h_only_parent = host
        .insert(parent, BackingToken(501), HandleFlags::DEFAULT)
        .unwrap();
    let h_guarded = host
        .insert(parent, BackingToken(502), HandleFlags::DEFAULT)
        .unwrap();
    let h_shared = host
        .insert(parent, BackingToken(503), HandleFlags::INHERITABLE)
        .unwrap();

    let inflight_guard = host.get(parent, h_guarded).unwrap();
    host.inherit_task(
        parent,
        child,
        |_, _, _| true,
        &mut alloc_extent(8),
        |_| panic!("unexpected rollback release"),
    )
    .unwrap();

    let mut parent_finalized = Vec::new();
    host.exit_task(parent, |tok| parent_finalized.push(tok))
        .unwrap();
    // Only `h_only_parent` (501) is finalized on parent exit:
    // 502 is retained by `inflight_guard`, and 503 is retained by `child`.
    assert_eq!(parent_finalized, vec![BackingToken(501)]);
    assert_eq!(host.table_id(parent), Err(HandleError::Stale));

    // Releasing the in-flight guard now finalizes 502.
    assert_eq!(
        host.release_pin(inflight_guard),
        Ok(Some(BackingToken(502)))
    );

    // Exiting the child now finalizes 503.
    let mut child_finalized = Vec::new();
    host.exit_task(child, |tok| child_finalized.push(tok))
        .unwrap();
    assert_eq!(child_finalized, vec![BackingToken(503)]);
    let _ = h_only_parent;
    let _ = h_shared;
}

/// Criterion 5 + P1-3: Table capacity limit refuses cleanly with `TableFull`,
/// and exhausted slot generations (`Generation::MAX`) permanently retire the
/// slot (releasing the object, never reusing the slot, and lowering reported
/// capacity) on close, exit, and inherit.
#[test]
fn test_table_capacity_limit_and_slot_generation_exhaustion_retire_permanently() {
    let venue = SharedVenue::new(16);
    let task_core = TaskHandleCore::<4>::new().unwrap();
    let host = task_core.bind(&venue, SpinWait);
    host.publish_objects(16).unwrap();

    let task = make_task_key(20, 1);
    host.create_task_table(task, 3, &mut alloc_extent(4))
        .unwrap();
    assert_eq!(host.capacity(task), Ok(3));

    // Seed slot 0 and slot 1 at Generation::MAX.
    host.seed_slot_generation(task, SlotIndex::new(0), Generation::MAX)
        .unwrap();
    host.seed_slot_generation(task, SlotIndex::new(1), Generation::MAX)
        .unwrap();

    let h0 = host
        .insert(task, BackingToken(1), HandleFlags::INHERITABLE)
        .unwrap();
    let h1 = host
        .insert(task, BackingToken(2), HandleFlags::INHERITABLE)
        .unwrap();
    let h2 = host
        .insert(task, BackingToken(3), HandleFlags::INHERITABLE)
        .unwrap();
    assert_eq!(h0.generation(), Generation::MAX);
    assert_eq!(h1.generation(), Generation::MAX);

    // Table is at capacity 3: fourth insert and duplicate both refuse with TableFull.
    assert_eq!(
        host.insert(task, BackingToken(4), HandleFlags::DEFAULT),
        Err(HandleError::TableFull)
    );
    assert_eq!(host.duplicate(task, h2), Err(HandleError::TableFull));

    // 1. Close `h0` at Generation::MAX: object 1 is released, slot 0 is retired
    //    permanently, capacity drops from 3 to 2, and a new insert is refused!
    assert_eq!(host.close(task, h0), Ok(Some(BackingToken(1))));
    assert_eq!(host.capacity(task), Ok(2));
    assert_eq!(host.live_count(task), Ok(2));
    assert_eq!(
        host.insert(task, BackingToken(5), HandleFlags::DEFAULT),
        Err(HandleError::TableFull),
        "permanently retired slot 0 reduces usable capacity from 3 to 2"
    );

    // 2. Inherit into `child` while filtering out `h1` (which is at Generation::MAX):
    //    `child` inherits retired slot 0 AND retires filtered-out slot 1, so child's
    //    usable capacity is 3 - 2 = 1 (occupied by inherited `h2` at slot 2).
    let child = make_task_key(21, 1);
    host.inherit_task(
        task,
        child,
        |_pin, backing, _flags| backing == BackingToken(3),
        &mut alloc_extent(4),
        |_| panic!("unexpected rollback release"),
    )
    .unwrap();
    assert_eq!(host.capacity(child), Ok(1));
    assert_eq!(host.live_count(child), Ok(1));
    assert_eq!(
        host.insert(child, BackingToken(6), HandleFlags::DEFAULT),
        Err(HandleError::TableFull),
        "child has 2 retired slots (0 and 1) and 1 live slot (2) out of limit 3"
    );

    // 3. Exit `task`: releases remaining objects (2 and strictly retains 3 in child)
    //    and retires slot 1 in `task`'s table before reclaiming it.
    let mut parent_released = Vec::new();
    host.exit_task(task, |tok| parent_released.push(tok))
        .unwrap();
    assert_eq!(parent_released, vec![BackingToken(2)]);

    let mut child_released = Vec::new();
    host.exit_task(child, |tok| child_released.push(tok))
        .unwrap();
    assert_eq!(child_released, vec![BackingToken(3)]);
}

/// Criterion 6: Typed `HandleNumber` and `HandleNumberCodec` round-trip and
/// reject malformed user handle numbers.
#[test]
fn test_handle_number_codec_round_trip_and_invalid_number_rejection() {
    // 1. Direct 1:1 codec.
    for raw in [0u32, 1, 7, 1024, 65_535] {
        let slot = SlotIndex::new(raw);
        let num = encode_handle_number(HandleNumberCodec::DIRECT, slot).unwrap();
        assert_eq!(num, HandleNumber::new(raw as u64));
        assert_eq!(
            decode_handle_number(HandleNumberCodec::DIRECT, num),
            Ok(slot)
        );
    }

    // 2. Tagged stride-4 codec with base 0x100 and low tag 0b10.
    let codec = HandleNumberCodec::new(0x100, NonZeroU64::new(4).unwrap(), 0b11, 0b10).unwrap();
    let n0 = codec.encode(SlotIndex::new(0)).unwrap();
    let n5 = codec.encode(SlotIndex::new(5)).unwrap();
    assert_eq!(n0, HandleNumber::new(0x102));
    assert_eq!(n5, HandleNumber::new(0x116));
    assert_eq!(codec.decode(n0), Ok(SlotIndex::new(0)));
    assert_eq!(codec.decode(n5), Ok(SlotIndex::new(5)));

    // Wrong tag bits, below base, or unaligned offset all fail with InvalidHandle.
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

    // Resolve through `TaskHandleHost::get_by_number`.
    let venue = SharedVenue::new(4);
    let task_core = TaskHandleCore::<2>::new().unwrap();
    let host = task_core.bind(&venue, SpinWait);
    host.publish_objects(4).unwrap();

    let task = make_task_key(30, 1);
    host.create_task_table(task, 8, &mut alloc_extent(8))
        .unwrap();
    let h = host
        .insert(task, BackingToken(900), HandleFlags::DEFAULT)
        .unwrap();
    let user_num = codec.encode(h.slot()).unwrap();
    let (resolved_h, guard) = host.get_by_number(task, codec, user_num).unwrap();
    assert_eq!(resolved_h, h);
    assert_eq!(guard.backing(), BackingToken(900));
    assert_eq!(host.release_pin(guard), Ok(None));
    assert_eq!(host.close(task, h), Ok(Some(BackingToken(900))));
    host.exit_task(task, |_| {}).unwrap();
}

/// P1-1 & P1-2: `get` returns a retained `ObjectGuard` that prevents
/// finalization across `close` and `exit_task`, is consumed by value on
/// `release_pin`, and refuses continuation-slot double-take with `HandleError::Stale`.
#[test]
fn test_retained_guard_prevents_finalization_and_refuses_double_release() {
    let venue = SharedVenue::new(8);
    let task_core = TaskHandleCore::<2>::new().unwrap();
    let host = task_core.bind(&venue, SpinWait);
    host.publish_objects(8).unwrap();

    let task = make_task_key(40, 1);
    host.create_task_table(task, 4, &mut alloc_extent(4))
        .unwrap();
    let h = host
        .insert(task, BackingToken(777), HandleFlags::DEFAULT)
        .unwrap();

    let guard1 = host.get(task, h).unwrap();
    let guard2 = host.retain_pin(&guard1).unwrap();
    assert_eq!(host.pin_count(&guard1), Ok(3));

    // Close the table handle while two guards are live: does NOT finalize.
    assert_eq!(host.close(task, h), Ok(None));
    assert_eq!(host.pin_count(&guard1), Ok(2));

    // Release first guard: one guard still remains.
    assert_eq!(host.release_pin(guard1), Ok(None));
    assert_eq!(host.pin_count(&guard2), Ok(1));

    // Convert second guard into RawObjectGuard (continuation boundary) and release once.
    let mut raw_slot = guard2.into_raw();
    let guard2_restored = ObjectGuard::from_raw(raw_slot.take()).unwrap();
    assert_eq!(
        host.release_pin(guard2_restored),
        Ok(Some(BackingToken(777)))
    );

    // Replaying the same continuation slot fails closed with HandleError::Stale.
    assert_eq!(
        ObjectGuard::from_raw(raw_slot.take()),
        Err(HandleError::Stale)
    );
    host.exit_task(task, |_| {}).unwrap();
}

/// P1-4: Task host removes entries on `exit_task` so task churn beyond `T`
/// succeeds, and rejects a stale `TaskSerial` when a `TaskId` is recycled.
#[test]
fn test_task_host_churn_beyond_max_tasks_and_recycled_task_id_rejection() {
    let venue = SharedVenue::new(16);
    let task_core = TaskHandleCore::<4>::new().unwrap();
    let host = task_core.bind(&venue, SpinWait);
    host.publish_objects(16).unwrap();

    let mut reusable_extent = alloc_extent(4);
    for round in 1..=64u64 {
        let raw_id = ((round - 1) % 4 + 1) as i32;
        let current_key = make_task_key(raw_id, round + 10);
        let stale_key = make_task_key(raw_id, round);

        host.create_task_table(current_key, 4, &mut reusable_extent)
            .unwrap();
        let h = host
            .insert(current_key, BackingToken(round), HandleFlags::DEFAULT)
            .unwrap();

        // Older serial for the same TaskId is rejected as Stale.
        assert_eq!(host.get(stale_key, h), Err(HandleError::Stale));
        assert_eq!(host.close(stale_key, h), Err(HandleError::Stale));
        assert_eq!(host.exit_task(stale_key, |_| {}), Err(HandleError::Stale));

        let guard = host.get(current_key, h).unwrap();
        assert_eq!(guard.backing(), BackingToken(round));
        assert_eq!(host.release_pin(guard), Ok(None));

        let mut finalized = Vec::new();
        reusable_extent = host
            .exit_task(current_key, |tok| finalized.push(tok))
            .unwrap();
        assert_eq!(finalized, vec![BackingToken(round)]);
    }
}

/// P1-4 & Concurrency: `inherit_task` racing a concurrent `close` on the
/// parent task, followed by `exit_task` racing a concurrent `close` from the
/// child task, finalizes every object reference exactly once.
#[test]
fn test_inherit_and_exit_racing_concurrent_close_finalize_exactly_once() {
    let venue = SharedVenue::new(16);
    let task_core = TaskHandleCore::<4>::new().unwrap();
    let host = task_core.bind(&venue, SpinWait);
    host.publish_objects(16).unwrap();

    let mut parent_ext = alloc_extent(8);
    let mut child_ext = alloc_extent(8);

    for round in 1..=200u64 {
        let parent = make_task_key(1, round);
        let child = make_task_key(2, round);
        host.create_task_table(parent, 8, &mut parent_ext).unwrap();

        let h0 = host
            .insert(parent, BackingToken(round * 2), HandleFlags::INHERITABLE)
            .unwrap();
        let h1 = host
            .insert(
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

        // Phase 1: `inherit_task` races a concurrent `close(parent, h0)`.
        std::thread::scope(|s| {
            s.spawn(|| {
                if let Some(tok) = host.close(parent, h0).unwrap() {
                    record_release(tok);
                }
            });
            host.inherit_task(
                parent,
                child,
                |_pin, _tok, _flags| {
                    std::thread::yield_now();
                    true
                },
                &mut child_ext,
                &record_release,
            )
            .unwrap();
        });

        // Phase 2: `exit_task(parent)` races a concurrent `close(child, child_h1)`.
        let child_h1 = host.handle_at(child, h1.slot()).unwrap();
        std::thread::scope(|s| {
            s.spawn(|| {
                if let Some(tok) = host.close(child, child_h1).unwrap() {
                    record_release(tok);
                }
            });
            parent_ext = host.exit_task(parent, &record_release).unwrap();
        });

        child_ext = host.exit_task(child, &record_release).unwrap();

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
