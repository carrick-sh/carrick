//! Exercise the public command against real git revisions, without a guest VM.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::Path;
use std::process::{Command, Output};

fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().into()
}
fn write(root: &Path, path: &str, source: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, source).unwrap();
}
fn commit(root: &Path) -> String {
    git(root, &["add", "."]);
    git(
        root,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            "fixture",
        ],
    );
    git(root, &["rev-parse", "HEAD"])
}
fn diff(root: &Path, base: &str, head: &str, arch: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .arg("--root")
        .arg(root)
        .args(["asm-diff", "--base", base, "--head", head, "--arch", arch])
        .output()
        .unwrap()
}

#[test]
fn revisions_moves_and_x86_additions_pass_changed_aarch64_fails() {
    let repo = tempfile::tempdir().unwrap();
    let root = repo.path();
    git(root, &["init", "-q"]);
    write(root, "crates/carrick-el1/src/lib.rs", "mod old;");
    write(
        root,
        "crates/carrick-el1/src/old.rs",
        "fn barrier() { asm!(\"dsb sy\", options(nostack)); }",
    );
    let base = commit(root);
    std::fs::rename(
        root.join("crates/carrick-el1/src/old.rs"),
        root.join("crates/carrick-el1/src/new.rs"),
    )
    .unwrap();
    write(
        root,
        "crates/carrick-el1/src/lib.rs",
        "mod new; #[cfg(all(target_arch = \"x86_64\", feature = \"unknown\"))] mod x86;",
    );
    write(
        root,
        "crates/carrick-el1/src/x86.rs",
        "fn pause() { asm!(\"pause\"); }",
    );
    write(
        root,
        "crates/carrick-x86/src/lib.rs",
        "fn halt() { asm!(\"hlt\"); }",
    );
    let moved = commit(root);
    // The command reads blobs, not dirty working-tree content.
    write(root, "crates/carrick-el1/src/new.rs", "not Rust");
    let out = diff(root, &base, &moved, "aarch64");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = String::from_utf8(out.stdout).unwrap();
    assert!(report.contains("MOVED"), "{report}");
    assert_eq!(report.matches("ADDED-X86").count(), 2, "{report}");
    assert!(!diff(root, &base, &moved, "all").status.success());

    write(
        root,
        "crates/carrick-el1/src/new.rs",
        "fn barrier() { asm!(\"isb\", options(nostack)); }",
    );
    let changed = commit(root);
    let out = diff(root, &moved, &changed, "aarch64");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stdout).unwrap().contains("CHANGED"));
    assert!(
        !diff(root, "missing-ref", &changed, "aarch64")
            .status
            .success()
    );
}

#[test]
fn unknown_cfg_and_nonliteral_templates_fail_closed() {
    let repo = tempfile::tempdir().unwrap();
    let root = repo.path();
    git(root, &["init", "-q"]);
    write(
        root,
        "crates/carrick-el1/src/lib.rs",
        "fn f() { asm!(\"nop\"); }",
    );
    let base = commit(root);
    write(
        root,
        "crates/carrick-el1/src/lib.rs",
        "fn f() { asm!(\"nop\"); } #[cfg(any(target_arch = \"x86_64\", feature = \"unknown\"))] fn g() { asm!(\"isb\"); }",
    );
    let added = commit(root);
    let out = diff(root, &base, &added, "aarch64");
    assert_eq!(out.status.code(), Some(1));
    let report = String::from_utf8(out.stdout).unwrap();
    assert!(report.contains("ADDED "), "{report}");
    assert!(!report.contains("ADDED-X86"), "{report}");
    write(
        root,
        "crates/carrick-el1/src/lib.rs",
        "global_asm!(include_str!(\"entry.S\"));",
    );
    let opaque = commit(root);
    let out = diff(root, &base, &opaque, "aarch64");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("literal instruction templates")
    );
    write(
        root,
        "crates/carrick-el1/src/lib.rs",
        "global_asm!(\"nop\", include_str!(\"entry.S\"));",
    );
    let mixed = commit(root);
    assert!(!diff(root, &base, &mixed, "aarch64").status.success());
}
