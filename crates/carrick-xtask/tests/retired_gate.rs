#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end: the built `retired-tests` command over a real git history.

use carrick_xtask::accept::AcceptReceipt;
use carrick_xtask::ci_receipt::{diff_with_retired, parse_retired_tests};
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

fn remove(root: &Path, path: &str) {
    std::fs::remove_file(root.join(path)).unwrap();
}

fn commit(root: &Path, message: &str) -> String {
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", message]);
    git(root, &["rev-parse", "HEAD"])
}

fn manifest(lanes: &str, extra: &str) -> String {
    format!(
        "[package]\nname = \"demo\"\nversion = \"0.0.0\"\n[package.metadata.carrick.test-lanes]\n{lanes}\n{extra}"
    )
}

fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    dir
}

/// The built command: exit code and combined output.
fn check(root: &Path, base: &str, head: &str) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .arg("--root")
        .arg(root)
        .args(["retired-tests", "--base", base, "--head", head])
        .env_remove("CARRICK_AUTHORITY_BASE")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap(), text)
}

#[test]
fn a_renamed_kvm_test_fails_until_a_retired_entry_is_added() {
    let dir = repo();
    let root = dir.path();
    write(
        root,
        "crates/demo/Cargo.toml",
        &manifest("kvm_witness = \"kvm\"", ""),
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

    let (code, err) = check(root, &base, &renamed);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("test = \"kvm_witness::old_name\""), "{err}");
    assert!(err.contains("(lane kvm)"), "{err}");
    assert!(!err.contains("kept"), "{err}");

    write(
        root,
        ".github/retired-tests.toml",
        "[[retired]]\ntest = \"kvm_witness::old_name\"\nreason = \"renamed\"\nreplaced_by = \"kvm_witness::new_name\"\npr = 1\n",
    );
    let declared = commit(root, "declare");
    assert_eq!(check(root, &base, &declared).0, 0);
}

/// A helper module moved out of its test binary's root file is still that
/// binary's test, with the same name.
#[test]
fn a_module_moved_to_its_own_file_is_the_same_test() {
    let dir = repo();
    let root = dir.path();
    write(
        root,
        "crates/demo/Cargo.toml",
        &manifest("witness = \"kvm\"", ""),
    );
    write(
        root,
        "crates/demo/tests/witness.rs",
        "mod common { #[test] fn kept() {} }\n",
    );
    let base = commit(root, "base");

    write(root, "crates/demo/tests/witness.rs", "mod common;\n");
    write(
        root,
        "crates/demo/tests/common/mod.rs",
        "#[test]\nfn kept() {}\n",
    );
    let moved = commit(root, "move the module out");
    let (code, out) = check(root, &base, &moved);
    assert_eq!(code, 0, "{out}");
}

/// The file's directory names no binary: a helper module of `witness` (kvm)
/// is not the independent `common` target (manual), so deleting its test is
/// seen, in the lane of the binary that runs it.
#[test]
fn a_helper_module_test_takes_its_owning_targets_lane() {
    let dir = repo();
    let root = dir.path();
    write(
        root,
        "crates/demo/Cargo.toml",
        &manifest(
            "witness = \"kvm\"\ncommon = \"manual\"",
            "[[test]]\nname = \"common\"\npath = \"tests/manual.rs\"\n",
        ),
    );
    write(root, "crates/demo/tests/witness.rs", "mod common;\n");
    write(
        root,
        "crates/demo/tests/common/mod.rs",
        "#[test]\nfn kept() {}\n",
    );
    write(root, "crates/demo/tests/manual.rs", "#[test]\nfn hw() {}\n");
    let base = commit(root, "base");

    remove(root, "crates/demo/tests/common/mod.rs");
    write(root, "crates/demo/tests/common/mod.rs", "// emptied\n");
    let dropped = commit(root, "drop the helper's test");
    let (code, out) = check(root, &base, &dropped);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("test = \"witness::common::kept\""), "{out}");
    assert!(out.contains("(lane kvm)"), "{out}");
    assert!(!out.contains("hw"), "{out}");
}

const NESTED_OLD: &str =
    "pub fn lib() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn old() {}\n}\n";

/// The printed entry is the one the receipt gate consumes: nested module path
/// included, accepted by the PR check and by `diff_with_retired`.
#[test]
fn the_printed_entry_for_a_nested_test_is_the_one_the_receipt_gate_consumes() {
    let dir = repo();
    let root = dir.path();
    write(root, "crates/demo/Cargo.toml", &manifest("", ""));
    write(root, "crates/demo/src/lib.rs", NESTED_OLD);
    let base = commit(root, "base");
    write(root, "crates/demo/src/lib.rs", "#[test]\nfn kept() {}\n");
    let removed = commit(root, "remove the test");

    let (code, out) = check(root, &base, &removed);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("test = \"demo::tests::old\""), "{out}");
    let printed = out
        .lines()
        .find_map(|l| l.trim().strip_prefix("test = "))
        .unwrap();

    let toml = format!("[[retired]]\ntest = {printed}\nreason = \"removed\"\npr = 1\n");
    write(root, ".github/retired-tests.toml", &toml);
    let declared = commit(root, "declare");
    let (code, out) = check(root, &base, &declared);
    assert_eq!(code, 0, "{out}");

    // The receipt gate reads the same entry as retiring the test.
    let trees = tempfile::tempdir().unwrap();
    let tree = |name: &str, rev: &str| {
        let path = trees.path().join(name);
        std::fs::create_dir_all(&path).unwrap();
        let archive = Command::new("git")
            .args(["archive", rev])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(archive.status.success());
        let mut tar = Command::new("tar")
            .args(["-x", "-C"])
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut tar.stdin.take().unwrap(), &archive.stdout).unwrap();
        assert!(tar.wait().unwrap().success());
        path
    };
    let (base_tree, cand_tree) = (tree("base", &base), tree("cand", &declared));
    let receipt = |started: &[&str]| -> AcceptReceipt {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "timestamp": "20261010-000000",
            "head": "a".repeat(40),
            "clean_tree": true,
            "phase": "host",
            "profile": "no-docker",
            "overall": "PASS", "failures": [],
            "steps": [{
                "name": "unit", "command": "just unit", "exit_code": 0, "log_path": "unit.log", "duration_s": 1.0, "passed": true,
                "started_tests": started, "finished_binaries": ["demo"],
            }],
        }))
        .unwrap()
    };
    let retired = parse_retired_tests(&toml, Path::new(".github/retired-tests.toml")).unwrap();
    let diff = diff_with_retired(
        &receipt(&["demo::kept", "demo::tests::old"]),
        &receipt(&["demo::kept"]),
        &retired,
        &base_tree,
        &cand_tree,
    )
    .unwrap();
    assert!(diff.new.is_empty(), "{:?}", diff.new);
}
