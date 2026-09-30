#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;
use std::sync::{Mutex, OnceLock};
use std::{boxed::Box, vec::Vec};

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
}
impl TestArena {
    /// A leaked venue holding `ofds` zeroed OFD records.
    pub(crate) fn with_ofds(ofds: usize) -> &'static Self {
        let records: &'static [OfdRecord] = Box::leak(
            (0..ofds)
                .map(|_| OfdRecord::default())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        Box::leak(Box::new(Self { ofds: records }))
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

#[test]
fn el1_ipc_contended_table_lock_refuses_before_effects() {
    let (core, arena) = core_with::<1>(2);
    let host = core.bind(arena, Spin);
    let el1 = core.bind(arena, BoundedSpin(16));
    let t = host.create_table(4, &mut storage(4)).unwrap();
    host.open(t, Fd(0), description(1), false).unwrap();
    core.tables[0].lock.store(1, Ordering::Release); // another venue holds it
    assert_eq!(el1.dup(t, Fd(0)).map(|_| ()), Err(Error::Contended));
    assert_eq!(el1.pin(t, Fd(0)).map(|_| ()), Err(Error::Contended));
    core.tables[0].lock.store(0, Ordering::Release);
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
            assert_eq!(SLOT_READS.with(|n| n.get()) - before, 1, "scale {scale}");
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
