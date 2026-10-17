#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;
use std::sync::{Mutex, OnceLock};
use std::{boxed::Box, vec, vec::Vec};

// The red commit used two single installs here; the owner now uses one
// typed transaction without a temporary fd, host type or second table.
fn b_prep_install_pair<const T: usize>(
    c: &View<T>,
    table: TableId,
    pins: [&OfdPin; 2],
) -> Result<[Fd; 2], Error> {
    c.transaction(table)?.install_pair(Fd(0), pins, true)
}

#[test]
fn b_prep_pair_refusal_leaves_no_half_pair_at_1_8_64() {
    for population in [1, 8, 64] {
        let c = authority::<1, 66>();
        let table = c
            .create_table(population, &mut storage(population))
            .unwrap();
        for fd in 0..population - 1 {
            c.open(table, Fd(0), description(fd as u64), false).unwrap();
        }
        let reader = c.create_pinned(description(100)).unwrap();
        let writer = c.create_pinned(description(101)).unwrap();
        assert_eq!(
            b_prep_install_pair(&c, table, [&reader, &writer]),
            Err(Error::TooManyFiles)
        );
        assert_eq!(
            c.get(table, Fd((population - 1) as i32)),
            Err(Error::BadFd),
            "population {population}: a failed pair published its reader"
        );
        assert_eq!(c.holds(&reader), Ok((0, 1)));
        assert_eq!(c.holds(&writer), Ok((0, 1)));
        assert!(c.unpin(reader).unwrap().is_some());
        assert!(c.unpin(writer).unwrap().is_some());
        c.destroy_table(table, |_| {}).unwrap();
    }
}

#[test]
fn b_prep_pair_second_retain_refusal_preserves_slots_and_holds() {
    let c = authority::<1, 2>();
    let table = c.create_table(2, &mut storage(2)).unwrap();
    let reader = c.create_pinned(description(1)).unwrap();
    let writer = c.create_pinned(description(2)).unwrap();
    let ofd = c.ofd(writer.key().index).unwrap();
    ofd.holds.store((FREE_INDEX << 32) | PIN, Ordering::Relaxed);
    assert_eq!(
        b_prep_install_pair(&c, table, [&reader, &writer]),
        Err(Error::NoMemory)
    );
    assert_eq!(c.get(table, Fd(0)), Err(Error::BadFd));
    assert_eq!(c.holds(&reader), Ok((0, 1)));
    ofd.holds.store(PIN, Ordering::Relaxed);
    c.unpin(reader).unwrap();
    c.unpin(writer).unwrap();
    c.destroy_table(table, |_| {}).unwrap();
}

#[test]
fn b_prep_clone_files_fork_exec_and_reuse_at_1_8_64() {
    for population in [1, 8, 64] {
        let c = authority::<3, 65>();
        let parent = c
            .create_table(population, &mut storage(population))
            .unwrap();
        for fd in 0..population {
            c.open(parent, Fd(0), description(fd as u64), false)
                .unwrap();
        }
        let peer = parent; // CLONE_FILES owns exactly the same slot table.
        c.setfd(peer, Fd(0), true).unwrap();
        let child = c.fork(parent, &mut storage(population)).unwrap();
        let (operation, original) = c.pin(child, Fd(0)).unwrap();
        let raw = operation.into_raw();
        c.exec(child, |_| {
            panic!("parent and operation retain the description")
        })
        .unwrap();
        assert_eq!(c.get(child, Fd(0)), Err(Error::BadFd));
        assert_eq!(c.getfd(parent, Fd(0)), Ok(true));
        assert_eq!(c.close(peer, Fd(0)), Ok(None));
        assert_eq!(c.get(parent, Fd(0)), Err(Error::BadFd));
        assert_eq!(c.open(child, Fd(0), description(999), false), Ok(Fd(0)));
        let operation = OfdPin::from_raw(raw);
        assert_eq!(c.pinned(&operation), Ok(original));
        assert_eq!(c.unpin(operation), Ok(Some(original)));
        // Even after the old OFD index is recycled, its generation is dead.
        let replacement = c.create_pinned(description(1000)).unwrap();
        let stale = OfdPin::from_raw(raw);
        assert_eq!(c.pinned(&stale), Err(Error::StalePin));
        assert_eq!(
            c.install_pin(child, Fd(0), &stale, false),
            Err(Error::StalePin)
        );
        assert_eq!(c.get(child, Fd(0)).unwrap().backing, BackingToken(999));
        c.unpin(replacement).unwrap();
        c.destroy_table(child, |_| {}).unwrap();
        c.destroy_table(parent, |_| {}).unwrap();
    }
}

// Only test fixtures allocate; the substrate receives resolved slices.
// One process-wide arena of leaked extents: token = index + 1.
type Backing = (&'static [DescriptorSlot], &'static [AtomicU64]);
fn arena() -> &'static Mutex<Vec<Backing>> {
    static ARENA: OnceLock<Mutex<Vec<Backing>>> = OnceLock::new();
    ARENA.get_or_init(|| Mutex::new(Vec::new()))
}
/// Descriptor extents from the process-wide arena, and a fixed set of OFD
/// records (a venue that never grows past them).
pub(crate) struct TestArena {
    ofds: &'static [OfdRecord],
    objects: &'static [ObjectRecord],
}
impl TestArena {
    /// A leaked venue holding `ofds` zeroed OFD records.
    pub(crate) fn with_ofds(ofds: usize) -> &'static Self {
        Self::with_ofds_and_objects(ofds, 0)
    }
    /// A leaked venue holding `ofds` OFD records and `objects` object records.
    pub(crate) fn with_ofds_and_objects(ofds: usize, objects: usize) -> &'static Self {
        let records: &'static [OfdRecord] = Box::leak(
            (0..ofds)
                .map(|_| OfdRecord::default())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        let obj_records: &'static [ObjectRecord] = Box::leak(
            (0..objects)
                .map(|_| ObjectRecord::default())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        Box::leak(Box::new(Self {
            ofds: records,
            objects: obj_records,
        }))
    }
}
fn resolve_extent(extent: Extent) -> Option<Backing> {
    let (slots, bitmap) = *arena()
        .lock()
        .unwrap()
        .get(extent.token.checked_sub(1)? as usize)?;
    (slots.len() as u64 == extent.capacity).then_some((slots, bitmap))
}
impl SlotBacking for TestArena {
    fn resolve(&self, extent: Extent) -> Option<(&[DescriptorSlot], &[AtomicU64])> {
        resolve_extent(extent)
    }
    fn ofd(&self, index: usize) -> Option<&OfdRecord> {
        self.ofds.get(index)
    }
    fn object(&self, index: usize) -> Option<&ObjectRecord> {
        self.objects.get(index)
    }
}
pub(crate) fn storage(capacity: usize) -> Extent {
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
    let mut arena = arena().lock().unwrap();
    arena.push((slots, bitmap));
    Extent {
        token: arena.len() as u64,
        capacity: capacity as u64,
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Spin;
impl LockWait for Spin {
    fn wait(&self, _attempt: u32) -> bool {
        core::hint::spin_loop();
        true
    }
}
pub(crate) type View<const T: usize> = Authority<'static, TestArena, Spin, T>;
/// A published core with `ofds` published OFD records, and its venue.
pub(crate) fn core_with<const T: usize>(ofds: usize) -> (&'static Core<T>, &'static TestArena) {
    let core: &'static Core<T> = Box::leak(Box::new(Core::new().unwrap()));
    let arena = TestArena::with_ofds(ofds);
    core.bind(arena, Spin).publish_ofds(ofds).unwrap();
    (core, arena)
}
/// A published core with `objects` published object records, and its venue.
pub(crate) fn core_with_objects<const T: usize>(
    objects: usize,
) -> (&'static Core<T>, &'static TestArena) {
    let core: &'static Core<T> = Box::leak(Box::new(Core::new().unwrap()));
    let arena = TestArena::with_ofds_and_objects(0, objects);
    core.bind(arena, Spin).publish_objects(objects).unwrap();
    (core, arena)
}
/// `T` table identities and `O` OFD records, never grown.
pub(crate) fn authority<const T: usize, const O: usize>() -> View<T> {
    let (core, arena) = core_with::<T>(O);
    core.bind(arena, Spin)
}

#[test]
fn lowest_free_and_ceiling() {
    let core = authority::<2, 8>();
    let table = core.create_table(4, &mut storage(4)).unwrap();
    for expected in 0..4 {
        assert_eq!(
            core.open(table, Fd(0), description(expected as u64), false),
            Ok(Fd(expected))
        );
    }
    assert_eq!(
        core.open(table, Fd(0), description(9), false),
        Err(Error::TooManyFiles)
    );
    assert_eq!(
        core.close(table, Fd(1)).unwrap().unwrap().backing,
        BackingToken(1)
    );
    assert_eq!(core.dup(table, Fd(3)), Ok(Fd(1)));
}

fn description(token: u64) -> Description {
    Description::new(
        BackingToken(token),
        AccessMode::ReadWrite,
        StatusFlags::default(),
    )
}

#[test]
fn dup_variants_and_atomic_replacement() {
    for cloexec in [false, true] {
        let c = authority::<2, 4>();
        let t = c.create_table(8, &mut storage(8)).unwrap();
        let a = c.open(t, Fd(0), description(10), true).unwrap();
        let b = c.open(t, Fd(0), description(20), false).unwrap();
        assert_eq!(c.dup2(t, a, a), Ok(None));
        assert_eq!(c.getfd(t, a), Ok(true));
        assert_eq!(c.dup3(t, a, a, cloexec), Err(Error::InvalidArgument));
        assert_eq!(
            c.dup3(t, Fd(-1), Fd(-1), false),
            Err(Error::InvalidArgument)
        );
        assert_eq!(c.dup2(t, Fd(7), b), Err(Error::BadFd));
        assert_eq!(c.get(t, b).unwrap().backing, BackingToken(20));
        let released = c.dup3(t, a, b, cloexec).unwrap().unwrap();
        assert_eq!(released.backing, BackingToken(20));
        assert_eq!(c.getfd(t, b), Ok(cloexec));
        assert_eq!(c.refcount(t, a), Ok(2));
        assert_eq!(c.dup2(t, a, b), Ok(None));
        assert_eq!(c.refcount(t, a), Ok(2));
        assert_eq!(c.getfd(t, b), Ok(false));
        let d = c.dup(t, a).unwrap();
        assert_eq!(c.getfd(t, d), Ok(false));
        assert_eq!(c.close(t, a), Ok(None));
        assert_eq!(c.close(t, b), Ok(None));
        assert_eq!(c.close(t, d).unwrap().unwrap().backing, BackingToken(10));
        assert_eq!(c.close(t, d), Err(Error::BadFd));
    }
}

#[test]
fn bad_descriptors_and_minimum_errors() {
    let c = authority::<1, 1>();
    let t = c.create_table(4, &mut storage(4)).unwrap();
    let a = c.open(t, Fd(0), description(1), false).unwrap();
    for bad in [Fd(-1), Fd(1), Fd(4), Fd(i32::MAX)] {
        assert_eq!(c.get(t, bad), Err(Error::BadFd));
        assert_eq!(c.getfd(t, bad), Err(Error::BadFd));
        assert_eq!(c.setfd(t, bad, true), Err(Error::BadFd));
        assert_eq!(c.getfl(t, bad), Err(Error::BadFd));
        assert_eq!(c.setfl(t, bad, StatusFlags::default()), Err(Error::BadFd));
        assert_eq!(c.set_offset(t, bad, Offset(4)), Err(Error::BadFd));
        assert_eq!(c.close(t, bad), Err(Error::BadFd));
        assert_eq!(c.dup(t, bad), Err(Error::BadFd));
        assert_eq!(c.dup2(t, bad, a), Err(Error::BadFd));
        assert_eq!(c.dup2(t, bad, bad), Err(Error::BadFd));
        assert_eq!(c.dupfd(t, bad, Fd(-1), false), Err(Error::BadFd));
    }
    for min in [Fd(-1), Fd(4), Fd(i32::MAX)] {
        assert_eq!(c.dupfd(t, a, min, false), Err(Error::InvalidArgument));
        assert_eq!(c.dup2(t, a, min), Err(Error::BadFd));
    }
    for (min, cloexec, expected) in [(2, true, 2), (1, false, 1), (2, false, 3)] {
        let fd = c.dupfd(t, a, Fd(min), cloexec).unwrap();
        assert_eq!(fd, Fd(expected));
        assert_eq!(c.getfd(t, fd), Ok(cloexec));
    }
    assert_eq!(c.dupfd(t, a, Fd(0), false), Err(Error::TooManyFiles));
    assert_eq!(c.dup(t, a), Err(Error::TooManyFiles));
}

#[test]
fn fork_shares_description_but_not_descriptor_flags() {
    let c = authority::<3, 4>();
    let t = c.create_table(8, &mut storage(8)).unwrap();
    let a = c.open(t, Fd(0), description(1), false).unwrap();
    let alias = c.dup(t, a).unwrap();
    let child = c.fork(t, &mut storage(8)).unwrap();
    assert_eq!(c.refcount(t, a), Ok(4));
    c.set_offset(child, alias, Offset(123)).unwrap();
    assert_eq!(c.get(t, a).unwrap().offset, Offset(123));
    c.setfd(child, a, true).unwrap();
    assert_eq!(c.getfd(t, a), Ok(false));
    let flags = StatusFlags {
        append: true,
        nonblock: true,
        ..StatusFlags::default()
    };
    c.setfl(child, a, flags).unwrap();
    assert_eq!(c.getfl(t, alias), Ok((AccessMode::ReadWrite, flags)));
    c.destroy_table(child, |_| panic!("parent still retains OFD"))
        .unwrap();
    assert_eq!(c.refcount(t, a), Ok(2));
    let mut releases = 0;
    c.destroy_table(t, |d| {
        assert_eq!(d.backing, BackingToken(1));
        releases += 1;
    })
    .unwrap();
    assert_eq!(releases, 1);
    assert_eq!(c.get(t, a), Err(Error::StaleTable));
    let reused = c.create_table(8, &mut storage(8)).unwrap();
    assert_ne!(reused, t);
    assert_eq!(c.dup(t, a), Err(Error::StaleTable));
}

#[test]
fn setfl_preserves_immutable_flags_and_access() {
    for access in [
        AccessMode::ReadOnly,
        AccessMode::WriteOnly,
        AccessMode::ReadWrite,
    ] {
        let c = authority::<1, 2>();
        let t = c.create_table(4, &mut storage(4)).unwrap();
        let initial = StatusFlags {
            dsync: true,
            sync: true,
            immutable: 0x8000,
            ..StatusFlags::default()
        };
        let a = c
            .open(
                t,
                Fd(0),
                Description::new(BackingToken(0), access, initial),
                true,
            )
            .unwrap();
        let b = c.dup(t, a).unwrap();
        for enabled in [true, false] {
            c.setfl(
                t,
                b,
                StatusFlags {
                    append: enabled,
                    nonblock: enabled,
                    asynchronous: enabled,
                    direct: enabled,
                    noatime: enabled,
                    ..StatusFlags::default()
                },
            )
            .unwrap();
            let (actual_access, flags) = c.getfl(t, a).unwrap();
            assert_eq!(actual_access, access);
            assert_eq!(
                flags,
                StatusFlags {
                    append: enabled,
                    nonblock: enabled,
                    asynchronous: enabled,
                    direct: enabled,
                    noatime: enabled,
                    ..initial
                }
            );
            assert_eq!(c.getfd(t, a), Ok(true));
        }
    }
    let c = authority::<1, 1>();
    let t = c.create_table(1, &mut storage(1)).unwrap();
    let a = c
        .open(
            t,
            Fd(0),
            Description::new(BackingToken(0), AccessMode::Path, StatusFlags::default()),
            false,
        )
        .unwrap();
    assert_eq!(c.setfl(t, a, StatusFlags::default()), Err(Error::BadFd));
}

#[test]
fn close_range_and_exec_sweep() {
    for cloexec in [false, true] {
        let c = authority::<2, 8>();
        let t = c.create_table(8, &mut storage(8)).unwrap();
        for fd in 0..8 {
            c.open(t, Fd(0), description(fd), false).unwrap();
        }
        assert_eq!(
            c.close_range(t, 7, 2, cloexec, |_| {}),
            Err(Error::InvalidArgument)
        );
        c.close_range(t, u32::MAX, u32::MAX, cloexec, |_| panic!("out of range"))
            .unwrap();
        let mut released = 0;
        c.close_range(t, 2, 5, cloexec, |_| released += 1).unwrap();
        assert_eq!(released, if cloexec { 0 } else { 4 });
        for fd in 0..8 {
            let selected = (2..=5).contains(&fd);
            assert_eq!(
                c.getfd(t, Fd(fd)),
                if selected && !cloexec {
                    Err(Error::BadFd)
                } else {
                    Ok(selected)
                }
            );
        }
        c.exec(t, |_| released += 1).unwrap();
        assert_eq!(released, 4);
        c.close_range(t, 0, u32::MAX, false, |_| released += 1)
            .unwrap();
        assert_eq!(released, 8);
        c.exec(t, |_| panic!("already empty")).unwrap();
    }
}

#[test]
fn lowered_limit_preserves_existing_entries_and_exec() {
    let c = authority::<2, 8>();
    let t = c.create_table(8, &mut storage(8)).unwrap();
    let high = c.open(t, Fd(7), description(7), true).unwrap();
    c.set_limit(t, 0).unwrap();
    assert!(c.get(t, high).is_ok());
    assert_eq!(c.dup2(t, high, high), Ok(None));
    assert_eq!(c.dup(t, high), Err(Error::TooManyFiles));
    assert_eq!(c.dupfd(t, high, Fd(0), false), Err(Error::InvalidArgument));
    assert_eq!(c.dup2(t, high, Fd(0)), Err(Error::BadFd));
    c.set_limit(t, 2).unwrap();
    assert_eq!(c.dup(t, high), Ok(Fd(0)));
    let child = c.fork(t, &mut storage(8)).unwrap();
    c.exec(child, |_| panic!("parent retains")).unwrap();
    assert_eq!(c.get(child, high), Err(Error::BadFd));
    assert!(c.get(t, high).is_ok());
    c.set_limit(t, 8).unwrap();
    assert_eq!(c.dup(t, high), Ok(Fd(1)));
}

#[test]
fn capacity_failures_are_transactional_and_reclaim_storage() {
    let slots: Vec<DescriptorSlot> = (0..65).map(|_| DescriptorSlot::default()).collect();
    let words = [AtomicU64::new(0), AtomicU64::new(0)];
    assert!(TableStorage::new(&slots, &words).is_err());
    let c = authority::<1, 1>();
    assert_eq!(
        c.create_table(MAX_DESCRIPTORS + 1, &mut storage(4)),
        Err(Error::InvalidArgument)
    );
    let t = c.create_table(4, &mut storage(4)).unwrap();
    assert_eq!(
        c.set_limit(t, MAX_DESCRIPTORS + 1),
        Err(Error::InvalidArgument)
    );
    let a = c.open(t, Fd(0), description(1), false).unwrap();
    assert_eq!(c.fork(t, &mut storage(8)), Err(Error::NoMemory));
    assert_eq!(c.refcount(t, a), Ok(1));
    assert_eq!(
        c.open(t, Fd(0), description(2), false),
        Err(Error::NeedsOfds)
    );
    assert_eq!(c.dup(t, a), Ok(Fd(1)));
    c.destroy_table(t, |_| {}).unwrap();
    let t = c.create_table(4, &mut storage(4)).unwrap();
    assert_eq!(c.open(t, Fd(0), description(3), false), Ok(Fd(0)));
    let empty = authority::<1, 0>();
    let t = empty.create_table(1, &mut storage(1)).unwrap();
    assert_eq!(
        empty.open(t, Fd(0), description(0), false),
        Err(Error::NeedsOfds)
    );
}

fn structural<const F: usize>() {
    let c = authority::<1, 1>();
    let t = c.create_table(F, &mut storage(F)).unwrap();
    c.open(t, Fd(0), description(0), false).unwrap();
    for i in 1..F {
        assert_eq!(c.dup(t, Fd(0)), Ok(Fd(i as i32)));
    }
    assert_eq!(c.dup(t, Fd(0)), Err(Error::TooManyFiles));
    for i in (1..F).rev() {
        assert!(c.close(t, Fd(i as i32)).unwrap().is_none());
        let (found, words, levels) = c.probe_lowest(t, 0);
        assert_eq!(found, Some(i));
        assert!(words < 2 * levels, "bitmap work must be logarithmic");
        assert_eq!(c.dup(t, Fd(0)), Ok(Fd(i as i32)));
        assert_eq!(c.get(t, Fd(i as i32)).unwrap().backing, BackingToken(0));
    }
    // Every possible minimum, crossing all leaf and summary boundaries.
    for fd in (0..F).step_by(3) {
        let _ = c.close(t, Fd(fd as i32)).unwrap();
    }
    for min in 0..F {
        let (actual, words, levels) = c.probe_lowest(t, min);
        let expected = (min..F).find(|fd| fd % 3 == 0);
        assert_eq!(actual, expected);
        assert!(words < 2 * levels);
    }
}

#[test]
fn logarithmic_work_at_four_scales_without_an_allocator() {
    // Production crate has no alloc import, dependency, or allocator interface:
    // zero allocations is enforced by compilation, including a bare-metal target.
    structural::<65>();
    structural::<130>();
    structural::<4096>();
    structural::<65_536>();
}

#[test]
fn table_identity_cannot_cross_authorities() {
    let a = authority::<1, 1>();
    let b = authority::<1, 1>();
    let ta = a.create_table(4, &mut storage(4)).unwrap();
    let tb = b.create_table(4, &mut storage(4)).unwrap();
    a.open(ta, Fd(0), description(1), false).unwrap();
    b.open(tb, Fd(0), description(2), false).unwrap();
    assert_eq!(b.get(ta, Fd(0)), Err(Error::StaleTable));
    assert_eq!(a.close(tb, Fd(0)), Err(Error::StaleTable));
}

#[test]
fn unshare_close_range_keeps_siblings_intact() {
    for cloexec in [false, true] {
        let c = authority::<2, 1>();
        let parent = c.create_table(4, &mut storage(4)).unwrap();
        let a = c.open(parent, Fd(0), description(1), false).unwrap();
        assert_eq!(
            c.unshare_close_range(parent, 2, 1, cloexec, |_| {}, &mut storage(4)),
            Err(Error::InvalidArgument)
        );
        let child = c
            .unshare_close_range(
                parent,
                0,
                u32::MAX,
                cloexec,
                |_| panic!("parent retains"),
                &mut storage(4),
            )
            .unwrap();
        assert_eq!(c.getfd(parent, a), Ok(false));
        assert_eq!(
            c.getfd(child, a),
            if cloexec { Ok(true) } else { Err(Error::BadFd) }
        );
        assert_eq!(
            c.unshare_close_range(parent, 0, u32::MAX, false, |_| {}, &mut storage(4)),
            Err(Error::NoMemory)
        );
        assert_eq!(c.getfd(parent, a), Ok(false));
    }
}

#[test]
fn configured_ceiling_is_independent_of_backing() {
    let c = authority::<1, 1>();
    assert!(c.create_table(65_536, &mut storage(4)).is_ok());
}

#[test]
fn growth_preserves_identity_references_flags_and_lowest_holes() {
    let c = authority::<2, 2>();
    let t = c.create_table(65_536, &mut storage(4)).unwrap();
    let a = c.open(t, Fd(0), description(1), true).unwrap();
    for fd in 1..4 {
        assert_eq!(c.dup(t, a), Ok(Fd(fd)));
    }
    c.set_offset(t, a, Offset(91)).unwrap();
    assert_eq!(c.dup(t, a), Err(Error::NeedsBacking { descriptors: 5 }));
    assert_eq!(
        c.open(t, Fd(0), description(2), false),
        Err(Error::NeedsBacking { descriptors: 5 })
    );
    assert_eq!(
        c.dupfd(t, a, Fd(65_535), true),
        Err(Error::NeedsBacking {
            descriptors: 65_536
        })
    );
    assert_eq!(
        c.dup2(t, a, Fd(65_535)),
        Err(Error::NeedsBacking {
            descriptors: 65_536
        })
    );
    assert_eq!(c.refcount(t, a), Ok(4));
    assert_eq!(c.dup2(t, a, Fd(65_536)), Err(Error::BadFd));
    assert_eq!(
        c.dupfd(t, a, Fd(65_536), false),
        Err(Error::InvalidArgument)
    );
    let mut too_small = storage(3);
    assert_eq!(c.grow_table(t, &mut too_small), Err(Error::InvalidArgument));
    assert_eq!(too_small.capacity, 3);
    assert_eq!(c.refcount(t, a), Ok(4));
    assert_eq!(c.close(t, Fd(2)), Ok(None));
    let mut larger = storage(65_536);
    c.grow_table(t, &mut larger).unwrap();
    assert_eq!(larger.capacity, 4);
    assert_eq!(c.refcount(t, a), Ok(3));
    assert_eq!(c.getfd(t, a), Ok(true));
    assert_eq!(c.get(t, a).unwrap().offset, Offset(91));
    assert_eq!(c.dup(t, a), Ok(Fd(2)));
    assert_eq!(c.dup(t, a), Ok(Fd(4)));
    assert_eq!(c.dup3(t, a, Fd(65_535), true), Ok(None));
    c.set_limit(t, 4).unwrap();
    assert_eq!(c.dup(t, a), Err(Error::TooManyFiles));
    assert_eq!(c.get(t, Fd(65_535)).unwrap().offset, Offset(91));
    c.set_limit(t, 65_536).unwrap();
    assert_eq!(c.dupfd(t, a, Fd(65_534), false), Ok(Fd(65_534)));
    // Reuse retired storage for another table; no stale OFD refs survive.
    let other = c.create_table(65_536, &mut larger).unwrap();
    assert_eq!(c.open(other, Fd(0), description(2), false), Ok(Fd(0)));
    let mut releases = 0;
    c.destroy_table(t, |_| releases += 1).unwrap();
    c.destroy_table(other, |_| releases += 1).unwrap();
    assert_eq!(releases, 2);
}

#[test]
fn empty_backing_and_fork_growth_refuse_without_side_effects() {
    let c = authority::<2, 1>();
    let parent = c.create_table(1_048_576, &mut storage(0)).unwrap();
    assert_eq!(
        c.open(parent, Fd(0), description(1), false),
        Err(Error::NeedsBacking { descriptors: 1 })
    );
    let mut first = storage(65);
    c.grow_table(parent, &mut first).unwrap();
    let a = c.open(parent, Fd(64), description(1), true).unwrap();
    let mut small = storage(64);
    assert_eq!(
        c.fork(parent, &mut small),
        Err(Error::NeedsBacking { descriptors: 65 })
    );
    assert_eq!(small.capacity, 64);
    assert_eq!(c.refcount(parent, a), Ok(1));
    let child = c.fork(parent, &mut storage(130)).unwrap();
    c.grow_table(parent, &mut storage(65_536)).unwrap();
    c.set_offset(child, a, Offset(88)).unwrap();
    assert_eq!(c.get(parent, a).unwrap().offset, Offset(88));
    assert_eq!(
        c.dupfd(child, a, Fd(130), false),
        Err(Error::NeedsBacking { descriptors: 131 })
    );
    c.grow_table(child, &mut storage(1_048_576)).unwrap();
    assert_eq!(c.dup3(child, a, Fd(1_048_575), true), Ok(None));
    assert_eq!(c.refcount(parent, a), Ok(3));
    c.exec(child, |_| panic!("parent retains")).unwrap();
    assert_eq!(c.refcount(parent, a), Ok(1));
    assert_eq!(c.get(child, Fd(1_048_575)), Err(Error::BadFd));
    let mut count = 0;
    let backing = c.destroy_table(parent, |_| count += 1).unwrap();
    assert_eq!(count, 1);
    let (slots, bitmap) = resolve_extent(backing).unwrap();
    assert_eq!(slots.len(), 65_536);
    assert_eq!(bitmap.len(), bitmap_words(65_536));
}

// ---- contract kernel.el1.ipc-fd-authority (VM-free bindings) ----

fn table_with<const T: usize>(c: &View<T>, fds: i32) -> TableId {
    let t = c.create_table(1024, &mut storage(64)).unwrap();
    for i in 0..fds {
        assert_eq!(
            c.open(t, Fd(0), description(100 + i as u64), false),
            Ok(Fd(i))
        );
    }
    t
}

/// CLONE_FILES is a second live owner of the same table identity. The venue
/// must fork/unshare that identity before exec, not sweep its peer's table.
#[test]
fn m1_clone_files_exec_unshares_before_cloexec_sweep() {
    let c = authority::<3, 2>();
    let parent = table_with(&c, 1);
    let peer = parent;
    c.setfd(peer, Fd(0), true).unwrap();
    assert_eq!(c.getfd(parent, Fd(0)), Ok(true));
    let exec = c.fork(peer, &mut storage(64)).unwrap();
    c.exec(exec, |_| panic!("peer retains OFD")).unwrap();
    assert_eq!(c.get(exec, Fd(0)), Err(Error::BadFd));
    assert_eq!(c.getfd(parent, Fd(0)), Ok(true));
    assert_eq!(c.refcount(parent, Fd(0)), Ok(1));
}

#[test]
fn m1_rights_and_mapping_pins_outlive_dup2_and_numeric_reuse() {
    let c = authority::<2, 4>();
    let parent = table_with(&c, 2);
    let child = c.fork(parent, &mut storage(64)).unwrap();
    let (rights, original) = c.pin(parent, Fd(0)).unwrap();
    let (mapping, _) = c.pin(child, Fd(0)).unwrap();
    assert_eq!(c.dup2(parent, Fd(1), Fd(0)), Ok(None));
    assert_eq!(c.close(child, Fd(0)), Ok(None));
    assert_eq!(c.install_pin(child, Fd(0), &rights, true), Ok(()));
    assert_eq!(c.get(child, Fd(0)).unwrap().backing, original.backing);
    assert_eq!(c.getfd(child, Fd(0)), Ok(true));
    assert_eq!(c.close(child, Fd(0)), Ok(None));
    assert_eq!(c.unpin(rights), Ok(None));
    assert_eq!(c.unpin(mapping).unwrap().unwrap().backing, original.backing);
    c.destroy_table(parent, |_| panic!("child retains replacement"))
        .unwrap();
    let mut released = 0;
    c.destroy_table(child, |_| released += 1).unwrap();
    assert_eq!(released, 1);
}

/// Reconcile the populated-descriptor fork contract against the current core's
/// backed-capacity scan without widening its budget. Flips at M1 cutover.
#[test]
fn red_until_step3_m1_sparse_fork_visits_only_populated_descriptors() {
    for capacity in [65, 4096, 65_536] {
        let c = authority::<2, 1>();
        let parent = c.create_table(capacity, &mut storage(capacity)).unwrap();
        c.open(parent, Fd((capacity - 1) as i32), description(1), false)
            .unwrap();
        let mut backing = storage(capacity);
        let before = SLOT_READS.with(|n| n.get());
        let child = c.fork(parent, &mut backing).unwrap();
        let visits = SLOT_READS.with(|n| n.get()) - before;
        let result = if visits <= 1 {
            Ok(())
        } else {
            Err(("backed-capacity fork scan", visits))
        };
        assert_eq!(
            result.expect_err("M1 must invert this gate when sparse fork is fixed"),
            ("backed-capacity fork scan", capacity)
        );
        assert_eq!(
            c.get(child, Fd((capacity - 1) as i32)).unwrap().backing,
            BackingToken(1)
        );
        assert_eq!(c.refcount(parent, Fd((capacity - 1) as i32)), Ok(2));
    }
}

#[test]
fn el1_ipc_fd_reuse_during_blocked_io_keeps_pinned_description() {
    let c = authority::<2, 8>();
    let t = table_with(&c, 3);
    let a = c.open(t, Fd(0), description(7), false).unwrap();
    assert_eq!(a, Fd(3));
    let (pin, seen) = c.pin(t, a).unwrap();
    assert_eq!(seen.backing, BackingToken(7));
    // The blocked syscall's fd is closed and the number reused.
    assert_eq!(c.close(t, a), Ok(None), "a pinned description is not final");
    let b = c.open(t, Fd(0), description(8), false).unwrap();
    assert_eq!(b, a);
    assert_eq!(c.get(t, b).unwrap().backing, BackingToken(8));
    assert_ne!(
        pin.key(),
        c.pin(t, b)
            .map(|(p, _)| {
                let key = p.key();
                assert_eq!(c.unpin(p), Ok(None));
                key
            })
            .unwrap()
    );
    // The suspended operation still resolves exactly its own description.
    assert_eq!(c.pinned(&pin).unwrap().backing, BackingToken(7));
    assert_eq!(c.holds(&pin), Ok((0, 1)));
    assert_eq!(c.unpin(pin).unwrap().unwrap().backing, BackingToken(7));
    assert_eq!(c.get(t, b).unwrap().backing, BackingToken(8));
}

#[test]
fn el1_ipc_final_close_versus_inflight_pin_releases_once() {
    let c = authority::<3, 4>();
    let t = table_with(&c, 0);
    let a = c.open(t, Fd(0), description(1), false).unwrap();
    let alias = c.dup(t, a).unwrap();
    let child = c.fork(t, &mut storage(64)).unwrap();
    let (first, _) = c.pin(child, alias).unwrap();
    let (second, _) = c.pin(t, a).unwrap();
    assert_eq!(c.holds(&first), Ok((4, 2)));
    let raw = second.into_raw();
    // Every descriptor goes away while two operations are in flight.
    c.destroy_table(child, |_| panic!("pinned description finalized"))
        .unwrap();
    assert_eq!(c.close(t, a), Ok(None));
    assert_eq!(c.close(t, alias), Ok(None));
    assert_eq!(c.holds(&first), Ok((0, 2)));
    assert_eq!(c.unpin(first), Ok(None));
    let released = c.unpin(OfdPin::from_raw(raw)).unwrap();
    assert_eq!(
        released.unwrap().backing,
        BackingToken(1),
        "one final release"
    );
    // A copied raw pin is not a second pin: it fails closed, changes nothing.
    assert_eq!(c.unpin(OfdPin::from_raw(raw)), Err(Error::StalePin));
    assert_eq!(c.open(t, Fd(0), description(2), false), Ok(Fd(0)));
    assert_eq!(c.unpin(OfdPin::from_raw(raw)), Err(Error::StalePin));
    assert_eq!(c.refcount(t, Fd(0)), Ok(1));
}

#[test]
fn el1_ipc_fork_shares_status_flags_not_descriptor_flags() {
    let c = authority::<2, 2>();
    let parent = table_with(&c, 0);
    let a = c.open(parent, Fd(0), description(5), true).unwrap();
    let child = c.fork(parent, &mut storage(64)).unwrap();
    let (pin, before) = c.pin(parent, a).unwrap();
    assert!(!before.flags.nonblock);
    let nonblock = StatusFlags {
        nonblock: true,
        ..StatusFlags::default()
    };
    c.setfl(child, a, nonblock).unwrap();
    assert_eq!(c.getfl(parent, a).unwrap().1, nonblock);
    // A suspended operation observes the shared description's new flags.
    assert!(c.pinned(&pin).unwrap().flags.nonblock);
    c.setfd(child, a, false).unwrap();
    assert_eq!(c.getfd(parent, a), Ok(true));
    c.exec(parent, |_| panic!("child still references"))
        .unwrap();
    assert_eq!(c.getfd(child, a), Ok(false));
    assert_eq!(c.unpin(pin), Ok(None));
    let mut released = 0;
    c.destroy_table(child, |_| released += 1).unwrap();
    assert_eq!(released, 1);
}

#[test]
fn el1_ipc_growth_and_refusals_roll_back() {
    let c = authority::<2, 4>();
    let t = c.create_table(1024, &mut storage(2)).unwrap();
    let a = c.open(t, Fd(0), description(1), false).unwrap();
    c.dup(t, a).unwrap();
    assert_eq!(c.dup(t, a), Err(Error::NeedsBacking { descriptors: 3 }));
    // An unresolvable extent refuses with nothing consumed or changed.
    let mut bogus = Extent {
        token: u64::MAX,
        capacity: 8,
    };
    assert_eq!(c.grow_table(t, &mut bogus), Err(Error::BadBacking));
    assert_eq!(bogus.token, u64::MAX);
    assert_eq!(c.fork(t, &mut bogus), Err(Error::BadBacking));
    assert_eq!(c.refcount(t, a), Ok(2));
    // Table identities exhausted: fork refuses without retaining.
    let other = c.create_table(4, &mut storage(4)).unwrap();
    let mut spare = storage(8);
    assert_eq!(c.fork(t, &mut spare), Err(Error::NoMemory));
    assert_eq!(spare.capacity, 8);
    assert_eq!(c.refcount(t, a), Ok(2));
    c.destroy_table(other, |_| {}).unwrap();
    // Growth then succeeds and preserves references and holes.
    let mut larger = storage(8);
    c.grow_table(t, &mut larger).unwrap();
    assert_eq!(larger.capacity, 2, "the retired extent is handed back");
    assert_eq!(c.dup(t, a), Ok(Fd(2)));
    assert_eq!(c.refcount(t, a), Ok(3));
}

#[test]
fn el1_ipc_stale_generations_are_rejected() {
    let c = authority::<1, 2>();
    let t = table_with(&c, 1);
    let raw = t.to_raw();
    assert_eq!(TableId::from_raw(raw), t);
    c.destroy_table(t, |_| {}).unwrap();
    assert_eq!(c.get(t, Fd(0)), Err(Error::StaleTable));
    let reused = c.create_table(4, &mut storage(4)).unwrap();
    assert_eq!(
        reused.to_raw().index,
        raw.index,
        "same slot, new incarnation"
    );
    assert_eq!(
        c.open(TableId::from_raw(raw), Fd(0), description(1), false),
        Err(Error::StaleTable)
    );
    let forged = TableId::from_raw(RawTableId {
        authority: raw.authority ^ 1,
        ..reused.to_raw()
    });
    assert_eq!(c.get(forged, Fd(0)), Err(Error::StaleTable));
    // A pin from another authority never resolves here.
    let other = authority::<1, 2>();
    let ot = table_with(&other, 1);
    let (foreign, _) = other.pin(ot, Fd(0)).unwrap();
    let raw_foreign = foreign.into_raw();
    assert_eq!(
        c.pinned(&OfdPin::from_raw(raw_foreign)),
        Err(Error::StalePin)
    );
    assert_eq!(other.unpin(OfdPin::from_raw(raw_foreign)), Ok(None));
}

#[test]
fn el1_ipc_unpublished_core_fails_closed_and_initializes_in_place() {
    // Shared memory starts zeroed: a valid but unpublished core.
    let zeroed: Box<core::mem::MaybeUninit<Core<2>>> = Box::new_zeroed();
    // SAFETY: every field of Core is an atomic or integer; all-zero is valid.
    let core: &'static Core<2> = Box::leak(unsafe { zeroed.assume_init() });
    let arena = TestArena::with_ofds(4);
    let c = core.bind(arena, Spin);
    assert_eq!(c.create_table(4, &mut storage(4)), Err(Error::StaleTable));
    assert_eq!(c.publish_ofds(4), Err(Error::StaleTable));
    assert_eq!(core.initialize(0), Err(Error::InvalidArgument));
    core.initialize(0xC0DE).unwrap();
    assert_eq!(core.initialize(0xC0DE), Err(Error::InvalidArgument));
    assert_eq!(core.identity(), 0xC0DE);
    let t = c.create_table(4, &mut storage(4)).unwrap();
    assert_eq!(
        c.open(t, Fd(0), description(1), false),
        Err(Error::NeedsOfds),
        "no description record is published yet"
    );
    c.publish_ofds(4).unwrap();
    assert_eq!(c.open(t, Fd(0), description(1), false), Ok(Fd(0)));
    // Two venues bound to one core share one authority, not copies.
    let host_view = core.bind(arena, BoundedSpin(64));
    assert_eq!(host_view.get(t, Fd(0)).unwrap().backing, BackingToken(1));
}

/// Mutations take the table lock and refuse before effects when a bounded
/// wait gives up. Lookups take no lock: a holder the host stopped
/// mid-section (a vCPU taken out of the guest while it held the lock) never
/// makes EL1 forward a read or write it could serve (`el1_ipc_pairs_
/// blocking` lost served writes to `table_contended` under 64 pairs). Only a
/// writer changing the table's extent or identity makes lookups wait.
#[test]
fn el1_ipc_contended_table_lock_refuses_before_effects() {
    let (core, arena) = core_with::<1>(2);
    let host = core.bind(arena, Spin);
    let el1 = core.bind(arena, BoundedSpin(16));
    let t = host.create_table(4, &mut storage(4)).unwrap();
    host.open(t, Fd(0), description(1), false).unwrap();
    core.tables[0].lock.store(1, Ordering::Release); // another venue holds it
    assert_eq!(el1.dup(t, Fd(0)).map(|_| ()), Err(Error::Contended));
    assert_eq!(el1.get(t, Fd(0)).map(|d| d.backing), Ok(BackingToken(1)));
    let (pin, _) = el1
        .pin(t, Fd(0))
        .expect("a held lock does not stall a lookup");
    assert_eq!(el1.get(t, Fd(1)), Err(Error::BadFd));
    assert_eq!(el1.pin(t, Fd(1)).map(|_| ()), Err(Error::BadFd));
    // A writer mid-change of the extent (odd sequence) holds lookups off.
    let seq = core.tables[0].seq.load(Ordering::Relaxed);
    core.tables[0].seq.store(seq | 1, Ordering::Release);
    assert_eq!(el1.get(t, Fd(0)).map(|_| ()), Err(Error::Contended));
    assert_eq!(el1.pin(t, Fd(0)).map(|_| ()), Err(Error::Contended));
    core.tables[0].seq.store(seq, Ordering::Release);
    core.tables[0].lock.store(0, Ordering::Release);
    assert_eq!(el1.unpin(pin), Ok(None));
    assert_eq!(el1.refcount(t, Fd(0)), Ok(1));
    assert_eq!(el1.getfd(t, Fd(1)), Err(Error::BadFd));
}

#[test]
fn el1_ipc_direct_lookup_reads_one_slot_at_every_scale() {
    for scale in [65usize, 4096, 65_536] {
        let c = authority::<1, 1>();
        let t = c.create_table(scale, &mut storage(scale)).unwrap();
        c.open(t, Fd(0), description(3), false).unwrap();
        for _ in 1..scale {
            c.dup(t, Fd(0)).unwrap();
        }
        for fd in [0, scale / 2, scale - 1] {
            let before = SLOT_READS.with(|n| n.get());
            let (pin, _) = c.pin(t, Fd(fd as i32)).unwrap();
            // The slot, then the same slot again to confirm the incarnation.
            assert_eq!(SLOT_READS.with(|n| n.get()) - before, 2, "scale {scale}");
            assert_eq!(c.unpin(pin), Ok(None));
        }
    }
}

#[test]
fn el1_ipc_concurrent_pins_and_closes_release_exactly_once() {
    use std::sync::atomic::AtomicUsize;
    let (core, arena) = core_with::<2>(4);
    for round in 0..200u64 {
        let c = core.bind(arena, Spin);
        let parent = c.create_table(16, &mut storage(16)).unwrap();
        let fd = c.open(parent, Fd(0), description(round), false).unwrap();
        let child = c.fork(parent, &mut storage(16)).unwrap();
        let releases = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for table in [parent, child] {
                let releases = &releases;
                s.spawn(move || {
                    let c = core.bind(arena, Spin);
                    for _ in 0..8 {
                        match c.pin(table, fd) {
                            Ok((pin, d)) => {
                                assert_eq!(d.backing, BackingToken(round));
                                if c.unpin(pin).unwrap().is_some() {
                                    releases.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Err(e) => assert_eq!(e, Error::BadFd),
                        }
                    }
                    if c.close(table, fd).unwrap().is_some() {
                        releases.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(releases.load(Ordering::Relaxed), 1, "round {round}");
        c.destroy_table(parent, |_| panic!("empty")).unwrap();
        c.destroy_table(child, |_| panic!("empty")).unwrap();
    }
}

#[test]
fn el1_ipc_install_pin_shares_cross_table_flags_offsets_and_final_release() {
    let c = authority::<2, 4>();
    let a = c.create_table(4, &mut storage(4)).unwrap();
    let b = c.create_table(4, &mut storage(4)).unwrap();
    let pin = c.create_pinned(description(71)).unwrap();
    c.install_pin(a, Fd(1), &pin, false).unwrap();
    c.install_pin(b, Fd(2), &pin, true).unwrap();
    c.set_pinned_flags(
        &pin,
        StatusFlags {
            nonblock: true,
            ..StatusFlags::default()
        },
    )
    .unwrap();
    c.set_offset(a, Fd(1), Offset(12)).unwrap();
    assert_eq!(c.get(a, Fd(1)), c.get(b, Fd(2)));
    assert!(c.getfl(b, Fd(2)).unwrap().1.nonblock);
    assert!(!c.getfd(a, Fd(1)).unwrap());
    assert!(c.getfd(b, Fd(2)).unwrap());
    assert_eq!(c.close(a, Fd(1)).unwrap(), None);
    assert_eq!(c.close(b, Fd(2)).unwrap(), None);
    assert_eq!(c.unpin(pin).unwrap().unwrap().backing, BackingToken(71));
}

#[test]
fn el1_ipc_install_pin_refuses_full_table_and_stale_pin_before_effects() {
    let c = authority::<1, 4>();
    let table = c.create_table(1, &mut storage(1)).unwrap();
    let existing = c.open(table, Fd(0), description(1), false).unwrap();
    let pin = c.create_pinned(description(2)).unwrap();
    assert_eq!(
        c.install_pin(table, Fd(0), &pin, false),
        Err(Error::TooManyFiles)
    );
    assert_eq!(c.holds(&pin).unwrap(), (0, 1));
    assert_eq!(c.get(table, existing).unwrap().backing, BackingToken(1));
    let raw = pin.into_raw();
    assert_eq!(
        c.unpin(OfdPin::from_raw(raw)).unwrap().unwrap().backing,
        BackingToken(2)
    );
    let stale = OfdPin::from_raw(raw);
    assert_eq!(
        c.install_pin(table, Fd(0), &stale, false),
        Err(Error::StalePin)
    );
    assert_eq!(
        c.set_pinned_flags(&stale, StatusFlags::default()),
        Err(Error::StalePin)
    );
}

#[test]
fn el1_ipc_replace_pin_preserves_alias_and_displaced_operation() {
    let c = authority::<2, 4>();
    let table = c.create_table(8, &mut storage(8)).unwrap();
    let target = c.open(table, Fd(0), description(10), false).unwrap();
    let (old_pin, _) = c.pin(table, target).unwrap();
    let replacement = c.create_pinned(description(20)).unwrap();
    assert_eq!(c.replace_pin(table, target, &replacement, true), Ok(None));
    assert_eq!(c.get(table, target).unwrap().backing, BackingToken(20));
    assert_eq!(c.pinned(&old_pin).unwrap().backing, BackingToken(10));
    assert_eq!(c.holds(&old_pin).unwrap(), (0, 1));
    assert_eq!(c.holds(&replacement).unwrap(), (1, 1));
    assert_eq!(c.getfd(table, target), Ok(true));
    assert_eq!(c.replace_pin(table, target, &replacement, false), Ok(None));
    assert_eq!(c.holds(&replacement).unwrap(), (1, 1));
    assert_eq!(c.getfd(table, target), Ok(false));
    assert_eq!(c.unpin(old_pin).unwrap().unwrap().backing, BackingToken(10));
    assert_eq!(c.close(table, target), Ok(None));
    assert_eq!(
        c.unpin(replacement).unwrap().unwrap().backing,
        BackingToken(20)
    );
}

#[test]
fn el1_ipc_replace_pin_refusal_leaves_destination_and_holds_unchanged() {
    let c = authority::<1, 4>();
    let table = c.create_table(8, &mut storage(2)).unwrap();
    let target = c.open(table, Fd(0), description(10), true).unwrap();
    let replacement = c.create_pinned(description(20)).unwrap();
    assert_eq!(
        c.replace_pin(table, Fd(4), &replacement, false),
        Err(Error::NeedsBacking { descriptors: 5 })
    );
    assert_eq!(
        c.replace_pin(table, Fd(8), &replacement, false),
        Err(Error::BadFd)
    );
    let foreign = authority::<1, 4>();
    let foreign_pin = foreign.create_pinned(description(30)).unwrap();
    assert_eq!(
        c.replace_pin(table, target, &foreign_pin, false),
        Err(Error::StalePin)
    );
    assert_eq!(c.holds(&replacement).unwrap(), (0, 1));
    assert_eq!(c.get(table, target).unwrap().backing, BackingToken(10));
    assert_eq!(c.getfd(table, target), Ok(true));
    assert_eq!(
        c.replace_pin(table, target, &replacement, false)
            .unwrap()
            .unwrap()
            .backing,
        BackingToken(10)
    );
    assert_eq!(c.close(table, target), Ok(None));
    assert_eq!(
        c.unpin(replacement).unwrap().unwrap().backing,
        BackingToken(20)
    );
    assert_eq!(
        foreign.unpin(foreign_pin).unwrap().unwrap().backing,
        BackingToken(30)
    );
}

/// Open file descriptions are elastic venue records: the core hands out
/// only published records, asks for more with `NeedsOfds` (never an errno
/// by itself), and a later segment behaves exactly like the first.
#[test]
fn el1_ipc_ofd_records_grow_in_published_segments() {
    let (core, arena) = core_with::<1>(0);
    let c = core.bind(arena, Spin);
    assert_eq!(core.ofd_count(), 0);
    let t = c.create_table(64, &mut storage(64)).unwrap();
    assert_eq!(
        c.open(t, Fd(0), description(1), false),
        Err(Error::NeedsOfds)
    );
    assert_eq!(c.get(t, Fd(0)), Err(Error::BadFd), "refusal has no effect");
    // A venue cannot publish records it does not hold.
    let tiny = TestArena::with_ofds(2);
    let (other, _) = core_with::<1>(0);
    assert_eq!(
        other.bind(tiny, Spin).publish_ofds(3),
        Err(Error::BadBacking)
    );
    assert_eq!(other.ofd_count(), 0);
    let arena = TestArena::with_ofds(8);
    let c = core.bind(arena, Spin);
    for segment in 0..4 {
        c.publish_ofds(2).unwrap();
        assert_eq!(core.ofd_count(), 2 * (segment + 1));
        for fd in [2 * segment, 2 * segment + 1] {
            assert_eq!(
                c.open(t, Fd(0), description(fd as u64), false),
                Ok(Fd(fd as i32))
            );
        }
        assert_eq!(
            c.open(t, Fd(0), description(99), false),
            Err(Error::NeedsOfds)
        );
    }
    assert_eq!(c.publish_ofds(1), Err(Error::BadBacking), "venue is full");
    // Records of every segment pin, close and recycle alike.
    let (pin, d) = c.pin(t, Fd(7)).unwrap();
    assert_eq!(d.backing, BackingToken(7));
    assert_eq!(c.close(t, Fd(7)), Ok(None));
    assert_eq!(c.unpin(pin).unwrap().unwrap().backing, BackingToken(7));
    assert_eq!(c.open(t, Fd(0), description(70), false), Ok(Fd(7)));
    assert_eq!(c.get(t, Fd(7)).unwrap().backing, BackingToken(70));
}

/// Lock-free pins racing closes, reopens that reuse the same records, and
/// storage growth: every pin names a description the fd named during the
/// call (its backing token is one the fd held), and every description is
/// finally released exactly once, including a raced pin's (`PinRaced`).
#[test]
fn el1_ipc_lock_free_pins_race_close_reuse_and_growth() {
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    let (core, arena) = core_with::<1>(4);
    let host = core.bind(arena, Spin);
    let t = host.create_table(1024, &mut storage(4)).unwrap();
    let opened = AtomicUsize::new(0);
    let released = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        for _ in 0..2 {
            s.spawn(|| {
                let el1 = core.bind(arena, BoundedSpin(1 << 20));
                while !stop.load(Ordering::Acquire) {
                    match el1.pin(t, Fd(1)) {
                        Ok((pin, d)) => {
                            assert!(d.backing.0 >= 1, "a description the fd named");
                            if el1.unpin(pin).unwrap().is_some() {
                                released.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(Error::PinRaced(raw)) => {
                            // The reuse's pin is ours to release.
                            if el1.unpin(OfdPin::from_raw(raw)).unwrap().is_some() {
                                released.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(Error::BadFd) | Err(Error::Contended) => {}
                        Err(other) => panic!("pin: {other:?}"),
                    }
                }
            });
        }
        let mut capacity = 4;
        for round in 1..=4000u64 {
            let fd = host.open(t, Fd(1), description(round), false).unwrap();
            assert_eq!(fd, Fd(1));
            opened.fetch_add(1, Ordering::Relaxed);
            if round % 500 == 0 && capacity < 64 {
                capacity *= 2;
                let mut larger = storage(capacity);
                host.grow_table(t, &mut larger).unwrap();
            }
            if host.close(t, fd).unwrap().is_some() {
                released.fetch_add(1, Ordering::Relaxed);
            }
        }
        stop.store(true, Ordering::Release);
    });
    assert_eq!(
        released.load(Ordering::Relaxed),
        opened.load(Ordering::Relaxed),
        "every description released exactly once"
    );
}

#[test]
fn b_prep_pair_publication_hides_intermediate_slot_from_lock_free_readers() {
    let (core, arena) = core_with::<1>(2);
    let c = core.bind(arena, BoundedSpin(0));
    let table = c.create_table(2, &mut storage(2)).unwrap();
    let reader = c.create_pinned(description(10)).unwrap();
    let writer = c.create_pinned(description(11)).unwrap();
    let mut transaction = c.transaction(table).unwrap();
    transaction.after_first_publication = Some(|transaction| {
        let c = transaction.authority;
        let record = transaction.guard.record;
        let table = TableId {
            authority: c.core.identity(),
            index: 0,
            generation: record.generation.load(Ordering::Relaxed),
        };
        // Exactly after the first atomic slot store, the sequence is odd:
        // neither a description snapshot nor an owned pin can escape.
        assert_eq!(record.seq.load(Ordering::Acquire) & 1, 1);
        for fd in [Fd(0), Fd(1)] {
            assert_eq!(c.get(table, fd), Err(Error::Contended));
            assert_eq!(c.pin(table, fd), Err(Error::Contended));
        }
    });
    assert_eq!(
        transaction.install_pair(Fd(0), [&reader, &writer], true),
        Ok([Fd(0), Fd(1)])
    );
    drop(transaction);
    for (fd, token) in [(Fd(0), 10), (Fd(1), 11)] {
        assert_eq!(c.get(table, fd).unwrap().backing, BackingToken(token));
        assert_eq!(c.getfd(table, fd), Ok(true));
    }
    c.unpin(reader).unwrap();
    c.unpin(writer).unwrap();
    let mut releases = 0;
    c.destroy_table(table, |_| releases += 1).unwrap();
    assert_eq!(releases, 2);
}

#[test]
fn b_prep_pair_holes_backing_stale_pin_and_transaction_drop() {
    let c = authority::<2, 5>();
    let table = c.create_table(8, &mut storage(4)).unwrap();
    let reader = c.create_pinned(description(1)).unwrap();
    let writer = c.create_pinned(description(2)).unwrap();
    c.open(table, Fd(0), description(3), false).unwrap();
    c.open(table, Fd(2), description(4), false).unwrap();
    assert_eq!(
        b_prep_install_pair(&c, table, [&reader, &writer]),
        Ok([Fd(1), Fd(3)])
    );
    assert_eq!(c.holds(&reader), Ok((1, 1)));
    assert_eq!(c.holds(&writer), Ok((1, 1)));
    c.close(table, Fd(1)).unwrap();
    c.close(table, Fd(3)).unwrap();
    c.open(table, Fd(1), description(5), false).unwrap();
    assert_eq!(
        b_prep_install_pair(&c, table, [&reader, &writer]),
        Err(Error::NeedsBacking { descriptors: 5 })
    );
    assert_eq!(c.get(table, Fd(3)), Err(Error::BadFd));
    assert_eq!(c.holds(&reader), Ok((0, 1)));
    assert_eq!(c.holds(&writer), Ok((0, 1)));
    assert_eq!(
        c.transaction(table)
            .unwrap()
            .install_pair(Fd(-1), [&reader, &writer], false),
        Err(Error::InvalidArgument)
    );
    let raw = writer.into_raw();
    c.unpin(OfdPin::from_raw(raw)).unwrap();
    let writer = OfdPin::from_raw(raw);
    assert_eq!(
        b_prep_install_pair(&c, table, [&reader, &writer]),
        Err(Error::StalePin)
    );
    // Dropping a transaction without committing releases the table lock and
    // owns no scratch slots, description references or backing extents.
    drop(c.transaction(table).unwrap());
    c.setfd(table, Fd(0), true).unwrap();
    let retired = c.destroy_table(table, |_| {}).unwrap();
    assert!(matches!(c.transaction(table), Err(Error::StaleTable)));
    let replacement = c.create_table(8, &mut { retired }).unwrap();
    assert_ne!(replacement, table);
    c.unpin(reader).unwrap();
    c.destroy_table(replacement, |_| {}).unwrap();
}

#[test]
fn b_prep_pair_population_has_logarithmic_search_and_balanced_holds() {
    for population in [1, 8, 64] {
        let c = authority::<1, 128>();
        let table = c
            .create_table(2 * population, &mut storage(2 * population))
            .unwrap();
        let levels = c.lock(table).unwrap().1.storage.levels;
        let mut prepared = Vec::new();
        for pair in 0..population {
            let reader = c
                .create_pinned(Description::new(
                    BackingToken(2 * pair as u64),
                    AccessMode::ReadOnly,
                    StatusFlags::default(),
                ))
                .unwrap();
            let writer = c
                .create_pinned(Description::new(
                    BackingToken(2 * pair as u64 + 1),
                    AccessMode::WriteOnly,
                    StatusFlags::default(),
                ))
                .unwrap();
            let before = BITMAP_READS.with(|n| n.get());
            assert_eq!(
                b_prep_install_pair(&c, table, [&reader, &writer]),
                Ok([Fd(2 * pair as i32), Fd(2 * pair as i32 + 1)])
            );
            let reads = BITMAP_READS.with(|n| n.get()) - before;
            assert!(
                reads <= 2 * (2 * levels - 1),
                "pair search: {reads} at {population}"
            );
            assert_eq!(c.holds(&reader), Ok((1, 1)));
            assert_eq!(c.holds(&writer), Ok((1, 1)));
            prepared.push((reader, writer));
        }
        c.destroy_table(table, |_| panic!("preparation pins still retain endpoints"))
            .unwrap();
        let mut releases = 0;
        for (reader, writer) in prepared {
            releases += usize::from(c.unpin(reader).unwrap().is_some());
            releases += usize::from(c.unpin(writer).unwrap().is_some());
        }
        assert_eq!(releases, 2 * population);
    }
}

// ---- contract core.personality.handle-table (unit bindings) ----

use crate::handle::*;
use carrick_sched_core::process::TaskKey;

fn test_task_key(id: i32, serial: u64) -> TaskKey {
    use carrick_sched_core::process::{TaskId, TaskSerial};
    use core::num::NonZeroI32;
    TaskKey {
        id: TaskId::from_registry_allocation(NonZeroI32::new(id).unwrap()),
        serial: TaskSerial::from_raw_u64(serial).unwrap(),
    }
}

#[test]
fn handle_slot_generation_exhaustion_retires_slot_on_close_exit_and_inherit() {
    let (core, arena) = core_with_objects::<4>(8);
    let c = core.bind(arena, Spin);
    let table = c.create_handle_table(4, &mut storage(4)).unwrap();

    // Seed slot 0 and slot 1 at Generation::MAX before inserting handles.
    c.seed_handle_slot_generation(table, SlotIndex::new(0), Generation::MAX)
        .unwrap();
    c.seed_handle_slot_generation(table, SlotIndex::new(1), Generation::MAX)
        .unwrap();

    let h0 = c
        .insert_handle(table, BackingToken(10), HandleFlags::new(true, false))
        .unwrap();
    assert_eq!(h0.slot(), SlotIndex::new(0));
    assert_eq!(h0.generation(), Generation::MAX);
    assert_eq!(c.handle_table_capacity(table), Ok(4));

    // 1. Exhaustion on close_handle: releases object, retires slot 0 permanently, lowers capacity.
    assert_eq!(c.close_handle(table, h0), Ok(Some(BackingToken(10))));
    assert_eq!(c.handle_table_capacity(table), Ok(3));
    assert_eq!(c.handle_table_retired_count(table), Ok(1));

    let h1 = c
        .insert_handle(table, BackingToken(20), HandleFlags::new(true, false))
        .unwrap();
    assert_eq!(
        h1.slot(),
        SlotIndex::new(1),
        "retired slot 0 is never reused"
    );
    assert_eq!(h1.generation(), Generation::MAX);

    // Even after growing the table (which rebuilds the bitmap), slot 0 stays retired.
    let mut larger = storage(8);
    c.grow_handle_table(table, &mut larger).unwrap();
    assert_eq!(c.handle_table_capacity(table), Ok(3));
    let h2 = c
        .insert_handle(table, BackingToken(21), HandleFlags::new(true, false))
        .unwrap();
    assert_eq!(
        h2.slot(),
        SlotIndex::new(2),
        "retired slot 0 remains non-allocatable after grow"
    );
    assert_eq!(c.close_handle(table, h2), Ok(Some(BackingToken(21))));

    // 2. Exhaustion on inherit_handle_table when slot 1 is at Generation::MAX and filtered out.
    let child = c
        .inherit_handle_table(
            table,
            |_pin, _token, _flags| false,
            &mut storage(8),
            |_| panic!("unexpected rollback release"),
        )
        .unwrap();
    // Child inherited retired slot 0 AND retired filtered-out slot 1 (at Generation::MAX).
    assert_eq!(c.handle_table_capacity(child), Ok(2));
    assert_eq!(c.handle_table_retired_count(child), Ok(2));
    let child_h = c
        .insert_handle(child, BackingToken(30), HandleFlags::default())
        .unwrap();
    assert_eq!(
        child_h.slot(),
        SlotIndex::new(2),
        "child skips both retired slot 0 and exhausted filtered slot 1"
    );

    // 3. Exhaustion on close_all_handles (task exit path) in parent:
    let mut parent_released = Vec::new();
    c.close_all_handles(table, |tok| parent_released.push(tok))
        .unwrap();
    assert_eq!(parent_released, vec![BackingToken(20)]);
    // Parent had slot 0 retired, and now slot 1 also retired on close_all_handles!
    assert_eq!(c.handle_table_capacity(table), Ok(2));
    assert_eq!(c.handle_table_retired_count(table), Ok(2));

    let mut child_released = Vec::new();
    c.destroy_handle_table(child, |tok| child_released.push(tok))
        .unwrap();
    assert_eq!(child_released, vec![BackingToken(30)]);
    c.destroy_handle_table(table, |_| {}).unwrap();
}

#[test]
fn handle_pin_overflow_returns_pin_overflow_without_side_effects() {
    let (core, arena) = core_with_objects::<2>(4);
    let c = core.bind(arena, Spin);
    let table = c.create_handle_table(4, &mut storage(4)).unwrap();
    let h = c
        .insert_handle(table, BackingToken(55), HandleFlags::new(true, false))
        .unwrap();

    // Saturate the OpenLifetime pin count to MAX_OBJECT_PINS (0x7fff_ffff).
    let saved = arena.objects[0]
        .lifetime_word_for_test()
        .load(Ordering::Relaxed);
    let saturated = (saved & !(MAX_OBJECT_PINS as u64)) | (MAX_OBJECT_PINS as u64);
    arena.objects[0]
        .lifetime_word_for_test()
        .store(saturated, Ordering::Release);

    assert_eq!(c.get_handle(table, h), Err(HandleError::PinOverflow));
    assert_eq!(
        c.get_handle_pin(table, h.pin()),
        Err(HandleError::PinOverflow)
    );
    assert_eq!(c.duplicate_handle(table, h), Err(HandleError::PinOverflow));
    let mut child_ext = storage(4);
    assert_eq!(
        c.inherit_handle_table(table, |_, _, _| true, &mut child_ext, |_| {}),
        Err(HandleError::PinOverflow)
    );

    // Restore the original lifetime word and close cleanly.
    arena.objects[0]
        .lifetime_word_for_test()
        .store(saved, Ordering::Release);
    assert_eq!(c.close_handle(table, h), Ok(Some(BackingToken(55))));
    c.destroy_handle_table(table, |_| {}).unwrap();
}

#[test]
fn handle_raw_guard_double_release_fails_closed() {
    let (core, arena) = core_with_objects::<2>(4);
    let c = core.bind(arena, Spin);
    let table = c.create_handle_table(4, &mut storage(4)).unwrap();
    let h = c
        .insert_handle(table, BackingToken(77), HandleFlags::default())
        .unwrap();
    let h_dup = c.duplicate_handle(table, h).unwrap();
    let guard = c.get_handle(table, h).unwrap();
    assert_eq!(
        c.close_handle(table, h),
        Ok(None),
        "duplicate slot and guard retain object across close of original"
    );

    // 1. Continuation-slot take(): moving out of a continuation slot zeroes it
    // (slot_generation == 0), and a second `from_raw(slot.take())` fails closed.
    let mut continuation_slot = guard.into_raw();
    let forged_dup = continuation_slot.forged_copy_for_test();
    let first_guard = ObjectGuard::from_raw(continuation_slot.take()).unwrap();
    assert_eq!(
        ObjectGuard::from_raw(continuation_slot.take()),
        Err(HandleError::Stale),
        "zeroed continuation slot after take() must be rejected by from_raw"
    );
    assert_eq!(
        ObjectGuard::from_raw(RawObjectGuard::default()),
        Err(HandleError::Stale),
        "default zeroed RawObjectGuard must be rejected by from_raw"
    );

    // First release of the guard drops the guard's reference while `h_dup` stays live.
    assert_eq!(c.release_handle_pin(first_guard), Ok(None));

    // 2. P1-A witness: even if unsafe/corrupted memory duplicates a RawObjectGuard
    // while duplicate slot `h_dup` is still alive, releasing the duplicate must fail
    // closed with `Stale` and leave `h_dup`'s reference intact.
    let forged_guard = ObjectGuard::from_raw(forged_dup).unwrap();
    assert_eq!(
        c.release_handle_pin(forged_guard),
        Err(HandleError::Stale),
        "forged double release must not steal live slot reference"
    );
    let h_reused = c
        .insert_handle(table, BackingToken(88), HandleFlags::default())
        .unwrap();
    let dup_guard = c.get_handle(table, h_dup).unwrap();
    assert_eq!(dup_guard.backing(), BackingToken(77));
    assert_eq!(c.release_handle_pin(dup_guard), Ok(None));
    assert_eq!(c.close_handle(table, h_dup), Ok(Some(BackingToken(77))));
    assert_eq!(c.close_handle(table, h_reused), Ok(Some(BackingToken(88))));
    c.destroy_handle_table(table, |_| {}).unwrap();
}

#[test]
fn handle_concurrent_guards_exceed_eight_and_churn_without_exhaustion() {
    let (core, arena) = core_with_objects::<2>(4);
    let c = core.bind(arena, Spin);
    let table = c.create_handle_table(4, &mut storage(4)).unwrap();
    let h = c
        .insert_handle(table, BackingToken(99), HandleFlags::default())
        .unwrap();

    // P1-1 witness: hold 16 concurrent guards on one object (> 8), bounded only
    // by MAX_OBJECT_PINS.
    let mut guards = Vec::with_capacity(16);
    for i in 0..16 {
        let g = if i % 2 == 0 {
            c.get_handle(table, h).unwrap()
        } else {
            c.retain_handle_pin(&guards[0]).unwrap()
        };
        assert_eq!(g.backing(), BackingToken(99));
        guards.push(g);
    }
    assert_eq!(c.handle_pin_count(&guards[0]), Ok(17));

    // Churn guard acquire/release cycles to verify no counter exhausts over time.
    for _ in 0..256 {
        let g = c.get_handle(table, h).unwrap();
        let raw = g.into_raw();
        let restored = ObjectGuard::from_raw(raw).unwrap();
        assert_eq!(c.release_handle_pin(restored), Ok(None));
    }

    // Close the table slot while all 16 guards are still active.
    assert_eq!(c.close_handle(table, h), Ok(None));
    for g in guards.drain(..15) {
        assert_eq!(c.release_handle_pin(g), Ok(None));
    }
    let last = guards.pop().unwrap();
    assert_eq!(c.release_handle_pin(last), Ok(Some(BackingToken(99))));
    c.destroy_handle_table(table, |_| {}).unwrap();
}

#[test]
fn task_exit_contended_preserves_binding_until_retry_finalizes_once() {
    let arena = TestArena::with_ofds_and_objects(0, 8);
    let task_core: &'static TaskHandleCore<2> = Box::leak(Box::new(TaskHandleCore::new().unwrap()));
    let host_spin = task_core.bind(arena, Spin);
    let host_bounded = task_core.bind(arena, BoundedSpin(8));
    host_spin.publish_objects(8).unwrap();

    let task = test_task_key(1, 1);
    let table = host_spin
        .create_task_table(task, 4, &mut storage(4))
        .unwrap();
    let h1 = host_spin
        .insert(task, BackingToken(10), HandleFlags::default())
        .unwrap();
    let _h2 = host_spin
        .insert(task, BackingToken(20), HandleFlags::default())
        .unwrap();

    // Simulate a concurrent close holding the table lock while exit_task runs under BoundedSpin.
    task_core.core().tables[table.index]
        .lock
        .store(1, Ordering::Release);
    assert_eq!(
        host_bounded.exit_task(task, |_| panic!("must not finalize on Contended")),
        Err(HandleError::Contended)
    );
    // P1-B witness: Contended must leave the task binding and table intact.
    assert_eq!(host_spin.table_id(task), Ok(table));

    // Concurrent close releases the table lock and closes h1.
    task_core.core().tables[table.index]
        .lock
        .store(0, Ordering::Release);
    assert_eq!(host_spin.close(task, h1), Ok(Some(BackingToken(10))));

    // Retrying exit_task now succeeds and finalizes the remaining handle h2 once.
    let mut finalized = Vec::new();
    host_bounded
        .exit_task(task, |tok| finalized.push(tok))
        .unwrap();
    assert_eq!(finalized, vec![BackingToken(20)]);
    assert_eq!(host_spin.table_id(task), Err(HandleError::Stale));
}

#[test]
fn inherit_filter_parent_close_or_exit_finalizes_every_object_exactly_once() {
    let arena = TestArena::with_ofds_and_objects(0, 8);
    let task_core: &'static TaskHandleCore<4> = Box::leak(Box::new(TaskHandleCore::new().unwrap()));
    let host = task_core.bind(arena, Spin);
    host.publish_objects(8).unwrap();

    // Case 1: parent exits inside the inherit filter after slot 0 was already retained for child.
    let parent = test_task_key(1, 1);
    let child = test_task_key(2, 1);
    host.create_task_table(parent, 4, &mut storage(4)).unwrap();
    host.insert(parent, BackingToken(100), HandleFlags::INHERITABLE)
        .unwrap();
    host.insert(parent, BackingToken(200), HandleFlags::INHERITABLE)
        .unwrap();

    let mut exit_finalized = Vec::new();
    let mut rollback_finalized = Vec::new();
    let mut child_ext = storage(4);
    let res = host.inherit_task(
        parent,
        child,
        |pin, _tok, _flags| {
            if pin.slot == SlotIndex::new(1) {
                host.exit_task(parent, |b| exit_finalized.push(b)).unwrap();
            }
            true
        },
        &mut child_ext,
        |b| rollback_finalized.push(b),
    );
    assert_eq!(res, Err(HandleError::Stale));
    let mut finalized = [exit_finalized, rollback_finalized].concat();
    finalized.sort_by_key(|b| b.0);
    assert_eq!(
        finalized,
        vec![BackingToken(100), BackingToken(200)],
        "P1-C witness (rollback): parent exit in filter must finalize slot 0's token"
    );

    // Case 2: parent closes slot 0 inside the inherit filter after slot 0 was retained for child,
    // and attach_task_table fails because `child` already has a bound table.
    let parent2 = test_task_key(3, 1);
    let occupied_child = test_task_key(4, 1);
    host.create_task_table(parent2, 4, &mut storage(4)).unwrap();
    host.create_task_table(occupied_child, 4, &mut storage(4))
        .unwrap();
    let h_p0 = host
        .insert(parent2, BackingToken(300), HandleFlags::INHERITABLE)
        .unwrap();
    let h_p1 = host
        .insert(parent2, BackingToken(400), HandleFlags::INHERITABLE)
        .unwrap();

    let mut finalized2 = Vec::new();
    let mut child_ext2 = storage(4);
    let res2 = host.inherit_task(
        parent2,
        occupied_child,
        |pin, _tok, _flags| {
            if pin.slot == SlotIndex::new(1) {
                // Slot 0 was already retained by child; closing it in parent2 is Non-Terminal
                // because child holds the last reference.
                assert_eq!(host.close(parent2, h_p0), Ok(None));
            }
            true
        },
        &mut child_ext2,
        |b| finalized2.push(b),
    );
    assert_eq!(res2, Err(HandleError::InvalidHandle));
    assert_eq!(
        finalized2,
        vec![BackingToken(300)],
        "P1-C witness (attach failure): destroying unattached child table must finalize slot 0's token"
    );
    assert_eq!(host.close(parent2, h_p1), Ok(Some(BackingToken(400))));
    host.exit_task(parent2, |_| {}).unwrap();
    host.exit_task(occupied_child, |_| {}).unwrap();
}

#[test]
fn handle_write_paths_all_or_nothing_and_finalizer_lock_free_get_under_spin() {
    let (core, arena) = core_with_objects::<2>(4);
    let c = core.bind(arena, Spin);
    // Only 2 objects published initially.
    arena.objects[2].incarnation.store(0, Ordering::Relaxed);
    arena.objects[3].incarnation.store(0, Ordering::Relaxed);
    core.object_count.store(2, Ordering::Release);

    let table = c.create_handle_table(4, &mut storage(4)).unwrap();
    // 1. alloc_object pushes back the popped index on lifetime.initialize failure.
    let saved_word = arena.objects[0]
        .lifetime_word_for_test()
        .load(Ordering::Relaxed);
    arena.objects[0]
        .lifetime_word_for_test()
        .store((1u64 << 32) | 1, Ordering::Release);
    assert_eq!(
        c.insert_handle(table, BackingToken(1), HandleFlags::default()),
        Err(HandleError::BadBacking)
    );
    arena.objects[0]
        .lifetime_word_for_test()
        .store(saved_word, Ordering::Release);
    let h0 = c
        .insert_handle(table, BackingToken(10), HandleFlags::CLOSE_ON_EXEC)
        .unwrap();
    let _h1 = c
        .insert_handle(table, BackingToken(20), HandleFlags::CLOSE_ON_EXEC)
        .unwrap();
    assert_eq!(
        c.insert_handle(table, BackingToken(30), HandleFlags::default()),
        Err(HandleError::NeedsObjects)
    );

    // 2. All-or-nothing write paths (exec_handle_table, close_all_handles, destroy_handle_table):
    // if slot 1's object fails validation, slot 0 must NOT be closed and `seq` must stay even.
    let saved_obj1 = arena.objects[1]
        .lifetime_word_for_test()
        .load(Ordering::Relaxed);
    arena.objects[1]
        .lifetime_word_for_test()
        .store(0, Ordering::Release);
    assert_eq!(
        c.exec_handle_table(table, |_| panic!("must not release on validation failure")),
        Err(HandleError::Stale)
    );
    assert_eq!(
        c.close_all_handles(table, |_| panic!("must not release on validation failure")),
        Err(HandleError::Stale)
    );
    assert_eq!(
        c.destroy_handle_table(table, |_| panic!("must not release on validation failure")),
        Err(HandleError::Stale)
    );
    assert_eq!(
        core.tables[table.index].seq.load(Ordering::Acquire) & 1,
        0,
        "failed write path must leave table seq even"
    );
    let g0 = c.get_handle(table, h0).unwrap();
    assert_eq!(g0.backing(), BackingToken(10));
    assert_eq!(c.release_handle_pin(g0), Ok(None));

    arena.objects[1]
        .lifetime_word_for_test()
        .store(saved_obj1, Ordering::Release);

    // 3. P2 witness: finalizers in exec_handle_table, close_all_handles, and
    // destroy_handle_table run after `end_write` (`seq` even) so a finalizer
    // performing a lock-free `get_handle` on the same table completes under `Spin`.
    let mut exec_released = Vec::new();
    c.exec_handle_table(table, |tok| {
        assert_eq!(
            core.tables[table.index].seq.load(Ordering::Acquire) & 1,
            0,
            "exec_handle_table finalizer must run with seq even"
        );
        // Lock-free get_handle on the just-closed handle completes under Spin.
        assert_eq!(c.get_handle(table, h0), Err(HandleError::Stale));
        exec_released.push(tok);
    })
    .unwrap();
    assert_eq!(exec_released, vec![BackingToken(10), BackingToken(20)]);

    let h2 = c
        .insert_handle(table, BackingToken(30), HandleFlags::default())
        .unwrap();
    let mut close_all_released = Vec::new();
    c.close_all_handles(table, |tok| {
        assert_eq!(
            core.tables[table.index].seq.load(Ordering::Acquire) & 1,
            0,
            "close_all_handles finalizer must run with seq even"
        );
        assert_eq!(c.get_handle(table, h2), Err(HandleError::Stale));
        close_all_released.push(tok);
    })
    .unwrap();
    assert_eq!(close_all_released, vec![BackingToken(30)]);

    let h3 = c
        .insert_handle(table, BackingToken(40), HandleFlags::default())
        .unwrap();
    let mut destroy_released = Vec::new();
    c.destroy_handle_table(table, |tok| {
        assert_eq!(
            core.tables[table.index].seq.load(Ordering::Acquire) & 1,
            0,
            "destroy_handle_table finalizer must run with seq even"
        );
        assert_eq!(c.get_handle(table, h3), Err(HandleError::Stale));
        destroy_released.push(tok);
    })
    .unwrap();
    assert_eq!(destroy_released, vec![BackingToken(40)]);
}

#[test]
fn task_bound_table_refuses_direct_destroy_and_exit_task_allows_reattach_and_finalizer_lock_free_lookup()
 {
    // 1. TaskHandleCore::initialize refuses double-initialization without corrupting free_bindings.
    let zeroed: Box<core::mem::MaybeUninit<TaskHandleCore<4>>> = Box::new_zeroed();
    let task_core: &'static TaskHandleCore<4> = Box::leak(unsafe { zeroed.assume_init() });
    assert_eq!(task_core.initialize(0), Err(HandleError::InvalidHandle));
    task_core.initialize(0xABCD).unwrap();
    assert_eq!(
        task_core.initialize(0xABCD),
        Err(HandleError::InvalidHandle),
        "re-initializing a published TaskHandleCore must fail closed"
    );

    let arena = TestArena::with_ofds_and_objects(0, 8);
    let host = task_core.bind(arena, Spin);
    host.publish_objects(8).unwrap();
    let c = host.authority();

    let t0 = test_task_key(1, 1);
    let t1 = test_task_key(2, 1);

    // 2. attach_task_table validates that the table is a live unbound handle table:
    // - Linux fd table (TABLE_LIVE) -> Err(InvalidHandle)
    let fd_table = c.create_table(4, &mut storage(4)).unwrap();
    assert_eq!(
        host.attach_task_table(t0, fd_table),
        Err(HandleError::InvalidHandle)
    );
    c.destroy_table(fd_table, |_| {}).unwrap();

    // - Destroyed handle table (TABLE_FREE) -> Err(Stale)
    let dead_table = c.create_handle_table(4, &mut storage(4)).unwrap();
    c.destroy_handle_table(dead_table, |_| {}).unwrap();
    assert_eq!(
        host.attach_task_table(t0, dead_table),
        Err(HandleError::Stale)
    );

    // 3. Bound handle table refuses direct destroy_handle_table (preventing orphaned
    // bindings) and refuses attaching the same table to a second task.
    let bound_table = host.create_task_table(t0, 4, &mut storage(4)).unwrap();
    let h = host
        .insert(t0, BackingToken(500), HandleFlags::default())
        .unwrap();
    assert_eq!(
        host.attach_task_table(t1, bound_table),
        Err(HandleError::InvalidHandle),
        "already-bound handle table must not be attached to a second task"
    );
    assert_eq!(
        c.destroy_handle_table(bound_table, |_| panic!(
            "must refuse direct destroy on bound table"
        )),
        Err(HandleError::InvalidHandle),
        "direct destroy_handle_table on a task-bound table must be refused"
    );
    // Binding and handle remain intact after refused direct destroy.
    assert_eq!(host.table_id(t0), Ok(bound_table));
    let g = host.get(t0, h).unwrap();
    assert_eq!(g.backing(), BackingToken(500));
    assert_eq!(host.release_pin(g), Ok(None));

    // 4. exit_task unlinks the binding, drops the TaskBucket spinlock, sets
    // `record.seq` even, and runs the finalizer; inside the finalizer, lock-free
    // `host.table_id(t0)` and `c.get_handle(bound_table, h)` complete under Spin.
    let mut exit_released = Vec::new();
    host.exit_task(t0, |tok| {
        assert_eq!(
            host.table_id(t0),
            Err(HandleError::Stale),
            "exit_task finalizer must run outside TaskBucket lock after unlinking"
        );
        assert_eq!(
            c.get_handle(bound_table, h),
            Err(HandleError::Stale),
            "exit_task finalizer must run after table end_write (seq even)"
        );
        exit_released.push(tok);
    })
    .unwrap();
    assert_eq!(exit_released, vec![BackingToken(500)]);

    // 5. After exit_task, the same TaskKey `t0` is cleanly re-attachable.
    let rebound_table = host.create_task_table(t0, 4, &mut storage(4)).unwrap();
    assert_eq!(host.table_id(t0), Ok(rebound_table));
    host.exit_task(t0, |_| {}).unwrap();
}

#[test]
fn task_handle_host_constant_time_bucket_lookup_and_churn_beyond_max_tasks() {
    let arena = TestArena::with_ofds_and_objects(0, 32);
    let task_core: &'static TaskHandleCore<8> = Box::leak(Box::new(TaskHandleCore::new().unwrap()));
    let host = task_core.bind(arena, Spin);
    host.publish_objects(32).unwrap();

    // Populate all 8 task slots.
    let mut keys = Vec::new();
    for i in 1..=8i32 {
        let key = test_task_key(i, i as u64);
        host.create_task_table(key, 8, &mut storage(8)).unwrap();
        let h = host
            .insert(key, BackingToken(100 + i as u64), HandleFlags::default())
            .unwrap();
        keys.push((key, h));
    }

    // Verify lookup probes only its hash bucket chain (never an O(T) scan across all 8 slots).
    let mut total_steps = 0usize;
    for &(key, h) in &keys {
        TASK_LOOKUP_STEPS.with(|n| n.set(0));
        let guard = host.get(key, h).unwrap();
        let steps = TASK_LOOKUP_STEPS.with(|n| n.get());
        assert!(
            steps < 8,
            "bucket lookup must not scan all tasks (steps = {steps})"
        );
        total_steps += steps;
        assert_eq!(host.release_pin(guard), Ok(None));
    }
    assert!(
        total_steps <= 16,
        "average bucket probe across 8 tasks in 8 buckets was too high: {total_steps}"
    );

    // Exit all 8 tasks, then churn through 64 more task lifetimes on the 8-slot TaskHandleCore.
    for (key, _) in keys {
        let mut released = Vec::new();
        host.exit_task(key, |tok| released.push(tok)).unwrap();
        assert_eq!(released.len(), 1);
    }

    for round in 10..74i32 {
        let key = test_task_key(round, round as u64);
        host.create_task_table(key, 4, &mut storage(4)).unwrap();
        let h = host
            .insert(key, BackingToken(round as u64), HandleFlags::default())
            .unwrap();
        let guard = host.get(key, h).unwrap();
        assert_eq!(guard.backing(), BackingToken(round as u64));
        assert_eq!(host.release_pin(guard), Ok(None));
        let mut released = Vec::new();
        let _ext = host.exit_task(key, |tok| released.push(tok)).unwrap();
        assert_eq!(released, vec![BackingToken(round as u64)]);
    }
}
