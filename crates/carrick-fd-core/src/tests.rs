#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;

#[test]
fn lowest_free_and_ceiling() {
    let mut core = Core::<2, 130, 8>::new().unwrap();
    let table = core.create_table(4).unwrap();
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
        let mut c = Core::<2, 8, 4>::new().unwrap();
        let t = c.create_table(8).unwrap();
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
    let mut c = Core::<1, 4, 1>::new().unwrap();
    let t = c.create_table(4).unwrap();
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
    let mut c = Core::<3, 8, 4>::new().unwrap();
    let t = c.create_table(8).unwrap();
    let a = c.open(t, Fd(0), description(1), false).unwrap();
    let alias = c.dup(t, a).unwrap();
    let child = c.fork(t).unwrap();
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
    let reused = c.create_table(8).unwrap();
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
        let mut c = Core::<1, 4, 2>::new().unwrap();
        let t = c.create_table(4).unwrap();
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
    let mut c = Core::<1, 1, 1>::new().unwrap();
    let t = c.create_table(1).unwrap();
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
        let mut c = Core::<2, 8, 8>::new().unwrap();
        let t = c.create_table(8).unwrap();
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
    let mut c = Core::<2, 8, 8>::new().unwrap();
    let t = c.create_table(8).unwrap();
    let high = c.open(t, Fd(7), description(7), true).unwrap();
    c.set_limit(t, 0).unwrap();
    assert!(c.get(t, high).is_ok());
    assert_eq!(c.dup2(t, high, high), Ok(None));
    assert_eq!(c.dup(t, high), Err(Error::TooManyFiles));
    assert_eq!(c.dupfd(t, high, Fd(0), false), Err(Error::InvalidArgument));
    assert_eq!(c.dup2(t, high, Fd(0)), Err(Error::BadFd));
    c.set_limit(t, 2).unwrap();
    assert_eq!(c.dup(t, high), Ok(Fd(0)));
    let child = c.fork(t).unwrap();
    c.exec(child, |_| panic!("parent retains")).unwrap();
    assert_eq!(c.get(child, high), Err(Error::BadFd));
    assert!(c.get(t, high).is_ok());
    c.set_limit(t, 8).unwrap();
    assert_eq!(c.dup(t, high), Ok(Fd(1)));
}

#[test]
fn capacity_failures_are_transactional_and_reclaim_storage() {
    assert!(matches!(
        Core::<1, 4097, 1>::new(),
        Err(Error::InvalidArgument)
    ));
    assert!(matches!(
        Core::<1, 0, 1>::new(),
        Err(Error::InvalidArgument)
    ));
    let mut c = Core::<1, 4, 1>::new().unwrap();
    assert_eq!(c.create_table(5), Err(Error::InvalidArgument));
    let t = c.create_table(4).unwrap();
    assert_eq!(c.set_limit(t, 5), Err(Error::InvalidArgument));
    let a = c.open(t, Fd(0), description(1), false).unwrap();
    assert_eq!(c.fork(t), Err(Error::NoMemory));
    assert_eq!(c.refcount(t, a), Ok(1));
    assert_eq!(
        c.open(t, Fd(0), description(2), false),
        Err(Error::NoMemory)
    );
    assert_eq!(c.dup(t, a), Ok(Fd(1)));
    c.destroy_table(t, |_| {}).unwrap();
    let t = c.create_table(4).unwrap();
    assert_eq!(c.open(t, Fd(0), description(3), false), Ok(Fd(0)));
    let mut empty = Core::<1, 1, 0>::new().unwrap();
    let t = empty.create_table(1).unwrap();
    assert_eq!(
        empty.open(t, Fd(0), description(0), false),
        Err(Error::NoMemory)
    );
}

fn structural<const F: usize>() {
    let mut c = Core::<1, F, 1>::new().unwrap();
    let t = c.create_table(F).unwrap();
    c.open(t, Fd(0), description(0), false).unwrap();
    for i in 1..F {
        assert_eq!(c.dup(t, Fd(0)), Ok(Fd(i as i32)));
    }
    for i in (1..F).rev() {
        assert!(c.close(t, Fd(i as i32)).unwrap().is_none());
        let table = c.table(t).unwrap();
        let (found, words) = table.lowest(0);
        assert_eq!(found, Some(i));
        assert!(words <= 3, "bitmap work must be independent of population");
        assert_eq!(c.dup(t, Fd(0)), Ok(Fd(i as i32)));
        assert_eq!(c.get(t, Fd(i as i32)).unwrap().backing, BackingToken(0));
    }
    // Every possible minimum, crossing all leaf and summary boundaries.
    for fd in (0..F).step_by(3) {
        let _ = c.close(t, Fd(fd as i32)).unwrap();
    }
    for min in 0..F {
        let (actual, words) = c.table(t).unwrap().lowest(min);
        let expected = (min..F).find(|fd| fd % 3 == 0);
        assert_eq!(actual, expected);
        assert!(words <= 3);
    }
}

#[test]
fn constant_work_at_three_scales_without_an_allocator() {
    // Production crate has no alloc import, dependency, or allocator interface:
    // zero allocations is enforced by compilation, including a bare-metal target.
    structural::<65>();
    structural::<130>();
    structural::<4096>();
}

#[test]
fn table_identity_cannot_cross_authorities() {
    let mut a = Core::<1, 4, 1>::new().unwrap();
    let mut b = Core::<1, 4, 1>::new().unwrap();
    let ta = a.create_table(4).unwrap();
    let tb = b.create_table(4).unwrap();
    a.open(ta, Fd(0), description(1), false).unwrap();
    b.open(tb, Fd(0), description(2), false).unwrap();
    assert_eq!(b.get(ta, Fd(0)), Err(Error::StaleTable));
    assert_eq!(a.close(tb, Fd(0)), Err(Error::StaleTable));
}

#[test]
fn unshare_close_range_keeps_siblings_intact() {
    for cloexec in [false, true] {
        let mut c = Core::<2, 4, 1>::new().unwrap();
        let parent = c.create_table(4).unwrap();
        let a = c.open(parent, Fd(0), description(1), false).unwrap();
        assert_eq!(
            c.unshare_close_range(parent, 2, 1, cloexec, |_| {}),
            Err(Error::InvalidArgument)
        );
        let child = c
            .unshare_close_range(parent, 0, u32::MAX, cloexec, |_| panic!("parent retains"))
            .unwrap();
        assert_eq!(c.getfd(parent, a), Ok(false));
        assert_eq!(
            c.getfd(child, a),
            if cloexec { Ok(true) } else { Err(Error::BadFd) }
        );
        assert_eq!(
            c.unshare_close_range(parent, 0, u32::MAX, false, |_| {}),
            Err(Error::NoMemory)
        );
        assert_eq!(c.getfd(parent, a), Ok(false));
    }
}
