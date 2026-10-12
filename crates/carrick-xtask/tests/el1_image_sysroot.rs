//! Exercise the image build helper in isolated subprocess environments.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../../carrick-el1-image/build.rs"]
// Build-script diagnostics intentionally panic on build failures. This module
// is included only in the test target; the image entry point is never called.
#[allow(dead_code, clippy::panic)]
mod image_build;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn executable(path: &Path, script: &str) {
    std::fs::write(path, script).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn fixture() -> (tempfile::TempDir, Command) {
    // Spaces in executable paths must remain one argument, including wrappers.
    let root = tempfile::Builder::new()
        .prefix("image compiler ")
        .tempdir()
        .unwrap();
    executable(
        &root.path().join("rustc"),
        "#!/bin/sh\nprintf '/wrong/PATH/sysroot\\n'\n",
    );
    executable(
        &root.path().join("selected rustc"),
        "#!/bin/sh\n[ \"$#\" = 2 ] && [ \"$1\" = --print ] && [ \"$2\" = sysroot ] || exit 42\nprintf '/selected/sysroot\\n'\n",
    );
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args(["--exact", "sysroot_fixture", "--ignored", "--nocapture"])
        .env("PATH", root.path())
        .env("RUSTC", root.path().join("selected rustc"))
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env("EXPECTED_SYSROOT", "/selected/sysroot");
    (root, child)
}

fn passes(child: &mut Command) {
    let output = child.output().unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cargo_rustc_beats_path() {
    let (_root, mut child) = fixture();
    passes(&mut child);
}

#[test]
fn empty_wrappers_are_disabled() {
    let (_root, mut child) = fixture();
    child
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "");
    passes(&mut child);
}

#[test]
fn wrappers_nest_in_cargo_order() {
    let (root, mut child) = fixture();
    let outer = root.path().join("outer wrapper");
    let workspace = root.path().join("workspace wrapper");
    executable(
        &outer,
        "#!/bin/sh\n[ \"$1\" = \"$EXPECTED_WORKSPACE_WRAPPER\" ] || exit 43\nexec \"$@\"\n",
    );
    // Like clippy-driver, this wrapper is the compiler: it accepts the
    // nominal rustc argument but supplies its own sysroot instead of execing it.
    executable(
        &workspace,
        "#!/bin/sh\n[ \"$1\" = \"$RUSTC\" ] && [ \"$2\" = --print ] && [ \"$3\" = sysroot ] && [ \"$#\" = 3 ] || exit 44\nprintf '/wrapper/sysroot\\n'\n",
    );
    child
        .env("RUSTC_WRAPPER", &outer)
        .env("RUSTC_WORKSPACE_WRAPPER", &workspace)
        .env("EXPECTED_WORKSPACE_WRAPPER", &workspace)
        .env("EXPECTED_SYSROOT", "/wrapper/sysroot");
    passes(&mut child);
    // Each wrapper also works on its own.
    child.env_remove("RUSTC_WRAPPER");
    passes(&mut child);
    child
        .env("RUSTC_WRAPPER", &workspace)
        .env_remove("RUSTC_WORKSPACE_WRAPPER");
    passes(&mut child);
}

#[test]
fn failed_query_reports_status_and_stderr() {
    let (root, mut child) = fixture();
    executable(
        &root.path().join("selected rustc"),
        "#!/bin/sh\nprintf '/misleading/stdout\\n'\nprintf 'compiler rejected query\\n' >&2\nexit 45\n",
    );
    child.env("EXPECTED_SYSROOT", "ERROR");
    passes(&mut child);
}

#[test]
fn empty_sysroot_is_rejected() {
    let (root, mut child) = fixture();
    executable(
        &root.path().join("selected rustc"),
        "#!/bin/sh\nprintf '  \\n'\n",
    );
    child.env("EXPECTED_SYSROOT", "EMPTY");
    passes(&mut child);
}

#[test]
#[ignore = "subprocess fixture with compiler environment supplied by the parent"]
fn sysroot_fixture() {
    let expected = std::env::var("EXPECTED_SYSROOT").unwrap();
    match expected.as_str() {
        "ERROR" => {
            let error = image_build::get_sysroot().unwrap_err();
            assert!(error.contains("45"), "{error}");
            assert!(error.contains("compiler rejected query"), "{error}");
        }
        "EMPTY" => assert!(image_build::get_sysroot().unwrap_err().contains("empty")),
        _ => assert_eq!(image_build::get_sysroot().unwrap(), expected),
    }
}
