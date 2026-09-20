//! inotify watch lifecycle semantics tests on the VM-free scripted backend.
//!
//! Citations:
//! - `man 2 inotify_init1`
//! - `man 2 inotify_add_watch`
//! - `man 2 inotify_rm_watch`

use carrick_abi::{
    LINUX_AT_FDCWD, LINUX_IN_CREATE, LINUX_IN_DELETE, LINUX_IN_MODIFY, LINUX_O_CREAT,
    LINUX_O_NONBLOCK, LINUX_O_WRONLY,
};
use carrick_vfs::fs_backend::HostFsBackend;

use crate::common::*;

#[test]
fn inotify_watch_lifecycle_in_host_fs() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    let mask = (LINUX_IN_CREATE | LINUX_IN_DELETE | LINUX_IN_MODIFY) as u32;

    let mut script = vec![Step::Sys(
        sys::mkdirat(LINUX_AT_FDCWD, "/watched", 0o755).ret(0),
    )];
    for i in 0..8 {
        script.push(Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                format!("/watched/file_{i}.txt"),
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .save(0),
        ));
        script.push(Step::Sys(sys::close(slot(0)).ret(0)));
    }
    script.extend(vec![
        Step::Sys(sys::inotify_init1(LINUX_O_NONBLOCK as i32).save(0)),
        Step::Sys(sys::inotify_add_watch(slot(0), "/watched", mask).save(1)),
        Step::Sys(sys::inotify_rm_watch(slot(0), slot(1)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("script run succeeds");

    assert_eq!(run.exit_code(), 0);
}

/// inotify(7) IN_MODIFY describes changed file contents. A rejected write must
/// neither enqueue a record nor consume an IN_ONESHOT watch.
#[test]
fn rejected_write_does_not_modify_or_consume_watch() {
    rejected_write_watch_case(true);
}

#[test]
fn rejected_write_does_not_modify_or_consume_watch_in_memory() {
    rejected_write_watch_case(false);
}

fn rejected_write_watch_case(host: bool) {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();
    let script = vec![
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/file",
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .save(0),
        ),
        Step::Sys(sys::openat(LINUX_AT_FDCWD, "/file", 0, 0).save(1)),
        Step::Sys(sys::inotify_init1(LINUX_O_NONBLOCK as i32).save(2)),
        Step::Sys(
            sys::inotify_add_watch(
                slot(2),
                "/file",
                (LINUX_IN_MODIFY | carrick_abi::LINUX_IN_ONESHOT) as u32,
            )
            .save(3),
        ),
        Step::Sys(sys::write(slot(0), b"").ret(0)),
        Step::Sys(sys::read(slot(2), 256).errno(carrick_abi::LINUX_EAGAIN)),
        Step::Sys(sys::write(slot(1), b"rejected").errno(carrick_abi::LINUX_EBADF)),
        Step::Sys(sys::read(slot(2), 256).errno(carrick_abi::LINUX_EAGAIN)),
        Step::Sys(sys::write(slot(0), b"changed").ret(7)),
        Step::Sys(sys::read_tagged(slot(2), 256, "events").ret(32)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let backend = if host {
        ScriptedBackend::new().with_fs_backend(Box::new(host_backend))
    } else {
        ScriptedBackend::new()
    };
    let report = backend
        .run_root(script)
        .expect("failed write leaves the watch active");
    let events = report.output_tagged("events");
    assert_eq!(
        u32::from_ne_bytes(events[4..8].try_into().unwrap()),
        LINUX_IN_MODIFY as u32
    );
    assert_eq!(
        u32::from_ne_bytes(events[20..24].try_into().unwrap()),
        carrick_abi::LINUX_IN_IGNORED as u32
    );
}

#[test]
fn partial_positive_write_notifies_on_both_backends() {
    for host in [false, true] {
        let scratch = tempfile::TempDir::new().unwrap();
        let mut limit = 3u64.to_le_bytes().to_vec();
        limit.extend_from_slice(&u64::MAX.to_le_bytes());
        let script = vec![
            Step::Sys(
                sys::openat(
                    LINUX_AT_FDCWD,
                    "/file",
                    (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                    0o644,
                )
                .save(0),
            ),
            Step::Sys(sys::inotify_init1(LINUX_O_NONBLOCK as i32).save(1)),
            Step::Sys(sys::inotify_add_watch(slot(1), "/file", LINUX_IN_MODIFY as u32).save(2)),
            alloc_buffer(3, limit),
            Step::Sys(sys::prlimit64(0, 1, slot(3), 0).ret(0)),
            Step::Sys(sys::write(slot(0), b"abcdef").ret(3)),
            Step::Sys(sys::read_tagged(slot(1), 256, "events").ret(16)),
            Step::Sys(sys::read(slot(1), 256).errno(carrick_abi::LINUX_EAGAIN)),
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ];
        let backend = if host {
            ScriptedBackend::new()
                .with_fs_backend(Box::new(HostFsBackend::new_in(scratch.path()).unwrap()))
        } else {
            ScriptedBackend::new()
        };
        let report = backend
            .run_root(script)
            .expect("partial write changes the file");
        assert_eq!(
            u32::from_ne_bytes(report.output_tagged("events")[4..8].try_into().unwrap()),
            LINUX_IN_MODIFY as u32
        );
    }
}

/// kernel.fs.write-seek: each positive write must invalidate cached metadata,
/// including metadata repopulated by stat since an earlier write on the same fd.
#[test]
fn repeated_host_writes_refresh_cached_size() {
    let scratch = tempfile::TempDir::new().unwrap();
    let script = vec![
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/file",
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .save(0),
        ),
        Step::Sys(sys::write(slot(0), b"first").ret(5)),
        Step::Sys(sys::newfstatat(LINUX_AT_FDCWD, "/file", 0).ret(0)),
        Step::Sys(sys::write(slot(0), b"second").ret(6)),
        Step::Sys(sys::newfstatat(LINUX_AT_FDCWD, "/file", 0).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let report = ScriptedBackend::new()
        .with_fs_backend(Box::new(HostFsBackend::new_in(scratch.path()).unwrap()))
        .run_root(script)
        .unwrap();
    let start = std::mem::offset_of!(carrick_abi::LinuxStat, st_size);
    let sizes: Vec<_> = report
        .outputs_for("newfstatat")
        .iter()
        .map(|out| i64::from_le_bytes(out.bytes[start..start + 8].try_into().unwrap()))
        .collect();
    assert_eq!(sizes, [5, 11]);
}
