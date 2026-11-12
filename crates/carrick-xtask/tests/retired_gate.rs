//! End-to-end: a real git history with a renamed gated test.

use carrick_xtask::retired_gate::{RetiredTestsArgs, run};
use std::path::Path;
use std::process::Command;

fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn write(root: &Path, path: &str, body: &str) {
    let full = root.join(path);
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(full, body).unwrap();
}

fn commit(root: &Path, message: &str) -> String {
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", message]);
    git(root, &["rev-parse", "HEAD"])
}

#[test]
fn a_renamed_kvm_test_fails_until_a_retired_entry_is_added() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git(root, &["init", "-q"]);
    write(
        root,
        "crates/demo/Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.0.0\"\n[package.metadata.carrick.test-lanes]\nkvm_witness = \"kvm\"\n",
    );
    write(
        root,
        "crates/demo/tests/kvm_witness.rs",
        "#[test]\nfn old_name() {}\n#[test]\nfn kept() {}\n",
    );
    let base = commit(root, "base");

    write(
        root,
        "crates/demo/tests/kvm_witness.rs",
        "#[test]\nfn new_name() {}\n#[test]\nfn kept() {}\n",
    );
    let renamed = commit(root, "rename");
    let args = |head: &str| RetiredTestsArgs {
        base: Some(base.clone()),
        head: head.to_string(),
    };

    let err = run(root, &args(&renamed)).unwrap_err().to_string();
    assert!(err.contains("kvm_witness::old_name"), "{err}");
    assert!(err.contains("test = \"kvm_witness::old_name\""), "{err}");
    assert!(err.contains("(lane kvm)"), "{err}");
    assert!(!err.contains("kept"), "{err}");

    write(
        root,
        ".github/retired-tests.toml",
        "[[retired]]\ntest = \"kvm_witness::old_name\"\nreason = \"renamed\"\nreplaced_by = \"kvm_witness::new_name\"\npr = 1\n",
    );
    let declared = commit(root, "declare");
    run(root, &args(&declared)).unwrap();
}
