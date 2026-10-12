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
    // Spaces in the Cargo/compiler directory must remain one argument.
    let root = tempfile::Builder::new()
        .prefix("image compiler ")
        .tempdir()
        .unwrap();
    let toolchain_bin = root.path().join("toolchain bin");
    std::fs::create_dir(&toolchain_bin).unwrap();
    executable(
        &root.path().join("rustc"),
        "#!/bin/sh\nprintf '/wrong/PATH/sysroot\\n'\n",
    );
    executable(
        &toolchain_bin.join("rustc"),
        "#!/bin/sh\n[ \"$#\" = 2 ] && [ \"$1\" = --print ] && [ \"$2\" = sysroot ] || exit 42\nprintf '/selected/sysroot\\n'\n",
    );
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args(["--exact", "sysroot_fixture", "--ignored", "--nocapture"])
        .env("PATH", root.path())
        .env("TEST_CARGO", toolchain_bin.join("cargo"))
        .env("RUSTC", root.path().join("rustc"))
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
fn cargo_sibling_rustc_beats_path() {
    let (_root, mut child) = fixture();
    passes(&mut child);
}

#[test]
fn compiler_wrapper_environment_does_not_select_sysroot() {
    let (root, mut child) = fixture();
    let wrapper = root.path().join("compiler wrapper");
    executable(&wrapper, "#!/bin/sh\nprintf '/wrong/wrapper/sysroot\\n'\n");
    child
        .env("RUSTC_WRAPPER", &wrapper)
        .env("RUSTC_WORKSPACE_WRAPPER", &wrapper);
    passes(&mut child);
}

#[test]
fn missing_sibling_is_not_replaced_by_path_rustc() {
    let (root, mut child) = fixture();
    std::fs::remove_file(root.path().join("toolchain bin/rustc")).unwrap();
    child.env("EXPECTED_SYSROOT", "MISSING");
    passes(&mut child);
}

#[test]
fn failed_query_reports_status_and_stderr() {
    let (root, mut child) = fixture();
    executable(
        &root.path().join("toolchain bin/rustc"),
        "#!/bin/sh\nprintf '/misleading/stdout\\n'\nprintf 'compiler rejected query\\n' >&2\nexit 45\n",
    );
    child.env("EXPECTED_SYSROOT", "ERROR");
    passes(&mut child);
}

#[test]
fn empty_sysroot_is_rejected() {
    let (root, mut child) = fixture();
    executable(
        &root.path().join("toolchain bin/rustc"),
        "#!/bin/sh\nprintf '  \\n'\n",
    );
    child.env("EXPECTED_SYSROOT", "EMPTY");
    passes(&mut child);
}

#[test]
#[ignore = "subprocess fixture with compiler environment supplied by the parent"]
fn sysroot_fixture() {
    let expected = std::env::var("EXPECTED_SYSROOT").unwrap();
    let cargo = std::env::var_os("TEST_CARGO").unwrap();
    let cargo = Path::new(&cargo);
    match expected.as_str() {
        "ERROR" => {
            let error = image_build::get_sysroot(cargo).unwrap_err();
            assert!(error.contains("45"), "{error}");
            assert!(error.contains("compiler rejected query"), "{error}");
        }
        "MISSING" => assert!(
            image_build::get_sysroot(cargo)
                .unwrap_err()
                .contains("failed to query")
        ),
        "EMPTY" => assert!(
            image_build::get_sysroot(cargo)
                .unwrap_err()
                .contains("empty")
        ),
        _ => assert_eq!(image_build::get_sysroot(cargo).unwrap(), expected),
    }
}
