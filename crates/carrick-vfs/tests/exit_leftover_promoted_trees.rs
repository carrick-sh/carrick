//! Issue #1852 (PR #2140 P0): a `CARRICK_HOME` holding small leftover
//! `.carrick-trash-promoted-<pid>-<n>` trees made `carrick` spin forever in
//! `reclaim_scratch_root` at exit. The production exit path
//! (`finish_scratch_cleanup`, via the `atexit` hook a backend arms) must
//! return in bounded time and leave the trash reclaimed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use carrick_vfs::fs_backend::HostFsBackend;

const BACKLOG: u32 = 20_000;

fn mkdir(path: &Path, mode: u32) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn file(path: &Path, mode: u32) {
    std::fs::write(path, b"x").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The five trees the director found on a Mac, shape for shape.
fn plant_director_trash(scratch_root: &Path) {
    let trash = scratch_root.join(".carrick-trash");
    mkdir(&trash, 0o755);
    let tree = |n: u32| trash.join(format!(".carrick-trash-promoted-72498-{n}"));
    for dir in ["bin", "sbin", "local/bin", "local/sbin"] {
        mkdir(&tree(1).join(dir), 0o755);
    }
    mkdir(&tree(2), 0o755);
    file(&tree(2).join("hostname"), 0o644);
    file(&tree(2).join("hosts"), 0o644);
    mkdir(&tree(3).join("tmp"), 0o1777);
    mkdir(&tree(4), 0o755);
    mkdir(&tree(5), 0o1777);
    file(&tree(5).join("p"), 0o755);
    // The director's trash dir also held the backlog earlier crashed runs
    // promoted: many small retired trees beside the five above.
    for n in 6..BACKLOG {
        mkdir(&tree(n).join("tmp"), 0o1777);
    }
}

/// The `carrick run` shape: a backend exists, then `process::exit` with no
/// `Drop`. Only run by the test below.
#[test]
#[ignore = "child process of exit_returns_with_leftover_promoted_trees"]
fn exiting_run_child() {
    let root = PathBuf::from(std::env::var_os("CARRICK_TEST_SCRATCH_ROOT").expect("root"));
    let backend = HostFsBackend::new_in(&root).expect("scratch backend");
    std::mem::forget(backend);
    std::process::exit(0);
}

#[test]
fn exit_returns_with_leftover_promoted_trees() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run as a non-root user so permissions are real"
    );
    let root = tempfile::tempdir().unwrap();
    plant_director_trash(root.path());

    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "exiting_run_child"])
        .env("CARRICK_TEST_SCRATCH_ROOT", root.path())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("exit did not return within 10s: reclaim_scratch_root spins on leftover trees");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "exiting run child failed: {status}");

    let mut left = Vec::new();
    for dir in [".carrick-trash", ".carrick-cleanup-failures"] {
        if let Ok(entries) = std::fs::read_dir(root.path().join(dir)) {
            left.extend(entries.flatten().map(|entry| entry.path()));
        }
    }
    assert!(left.is_empty(), "leftover trees survived exit: {left:?}");
}
