//! Issue #1852: trash left by an earlier run (a failed or interrupted
//! promotion, `.carrick-trash/.carrick-trash-promoted-*`) is bounded per
//! start, so it was only ever reclaimed 256 entries at a time. A run that
//! leaves through `process::exit` must finish the job.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use carrick_vfs::fs_backend::HostFsBackend;

const FILES: usize = 40_000;

fn plant_promoted_trash(scratch_root: &Path) -> PathBuf {
    let promoted = scratch_root
        .join(".carrick-trash")
        .join(".carrick-trash-promoted-1-1");
    for dir in 0..40 {
        let dir = promoted.join(format!("d{dir}"));
        std::fs::create_dir_all(&dir).unwrap();
        for file in 0..FILES / 40 {
            std::fs::write(dir.join(format!("f{file}")), b"x").unwrap();
        }
    }
    promoted
}

/// The `carrick run` shape: a backend exists, then `process::exit` with no
/// `Drop`. Only run by the test below.
#[test]
#[ignore = "child process of exit_reclaims_promoted_trash"]
fn exiting_run_child() {
    let root = PathBuf::from(std::env::var_os("CARRICK_TEST_SCRATCH_ROOT").expect("root"));
    let backend = HostFsBackend::new_in(&root).expect("scratch backend");
    std::mem::forget(backend);
    std::process::exit(0);
}

#[test]
fn exit_reclaims_promoted_trash() {
    let root = tempfile::tempdir().unwrap();
    let promoted = plant_promoted_trash(root.path());
    assert!(promoted.is_dir());

    let started = std::time::Instant::now();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "exiting_run_child"])
        .env("CARRICK_TEST_SCRATCH_ROOT", root.path())
        .status()
        .unwrap();
    eprintln!(
        "exit with {FILES} planted trash files took {:?}",
        started.elapsed()
    );
    assert!(status.success(), "exiting run child failed: {status}");

    // The first bounded pass renames the planted tree's children to new
    // `promoted-*` names, so the planted name alone proves nothing.
    let left: Vec<_> = std::fs::read_dir(root.path().join(".carrick-trash"))
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    assert!(
        left.is_empty(),
        "trash must be reclaimed by the run that follows it, left: {left:?}"
    );
}
