//! Issue #1852: `carrick run` kept its per-run scratch and trash under
//! `$HOME/.carrick` whatever `CARRICK_HOME` said, and abandoned it when the
//! process exited. One test per binary: it owns the process environment and
//! the scratch-root resolution.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use carrick_vfs::fs_backend::{HostFsBackend, finish_scratch_cleanup};

fn layer(dir: &Path, name: &str, payload: usize, truncate_to: Option<usize>) -> PathBuf {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_mode(0o755);
    header.set_size(0);
    builder
        .append_data(&mut header, "etc/", std::io::empty())
        .unwrap();
    let data = vec![b'x'; payload];
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_size(data.len() as u64);
    builder
        .append_data(&mut header, "etc/payload", &data[..])
        .unwrap();
    let mut bytes = builder.into_inner().unwrap();
    if let Some(limit) = truncate_to {
        bytes.truncate(limit);
    }
    let path = dir.join(name);
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&bytes)
        .unwrap();
    path
}

/// Every entry under `root` with its size, so "returns to its starting size"
/// also catches a leftover empty directory.
fn census(root: &Path) -> BTreeMap<PathBuf, u64> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, u64>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let meta = std::fs::symlink_metadata(entry.path()).unwrap();
            let rel = entry.path().strip_prefix(root).unwrap().to_path_buf();
            out.insert(rel, if meta.is_dir() { 0 } else { meta.len() });
            if meta.is_dir() {
                walk(root, &entry.path(), out);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// The `carrick run` shape: extract, then leave through `process::exit`,
/// which runs no `Drop` and joins no worker. Only run by the test below.
#[test]
#[ignore = "child process of runs_keep_all_state_under_carrick_home_and_release_it"]
fn exiting_run_child() {
    let layer = PathBuf::from(std::env::var_os("CARRICK_TEST_LAYER").expect("layer"));
    let mut backend = HostFsBackend::new().expect("scratch backend");
    backend.extract_layers(&[layer]).expect("extract");
    std::mem::forget(backend);
    std::process::exit(0);
}

#[test]
fn runs_keep_all_state_under_carrick_home_and_release_it() {
    let carrick_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let layers = tempfile::tempdir().unwrap();
    // SAFETY: the only test in this binary, so no other thread reads the
    // environment while it is rewritten.
    unsafe {
        std::env::set_var("CARRICK_HOME", carrick_home.path());
        std::env::set_var("HOME", home.path());
    }
    let good = layer(layers.path(), "good.tar", 4 << 20, None);
    // The tar header promises 4 MiB; the blob ends inside it, the way a
    // layer fails mid-pull when the decoder errors or the disk fills.
    let bad = layer(layers.path(), "bad.tar", 4 << 20, Some(64 << 10));

    let run = |layer: &Path| {
        let mut backend = HostFsBackend::new().expect("scratch backend");
        let result = backend.extract_layers(&[layer.to_path_buf()]);
        drop(backend);
        finish_scratch_cleanup();
        result
    };

    run(&good).expect("good layer extracts");
    let scratch = carrick_home.path().join("scratch");
    let start = census(&scratch);

    assert!(run(&bad).is_err(), "the injected layer error must surface");
    run(&good).expect("good layer extracts after the failure");

    // A process that exits without dropping its backend still releases it.
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "exiting_run_child"])
        .env("CARRICK_TEST_LAYER", &good)
        .status()
        .unwrap();
    assert!(status.success(), "exiting run child failed: {status}");

    assert_eq!(
        census(home.path()),
        BTreeMap::new(),
        "nothing may be written under $HOME when CARRICK_HOME is set"
    );
    assert_eq!(
        census(&scratch),
        start,
        "scratch and trash must return to their starting size"
    );
}
