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
