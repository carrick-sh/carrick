//! Exercise the image build helper in isolated subprocess environments.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../../carrick-el1-image/build.rs"]
// Build-script diagnostics intentionally panic on build failures. This module
// is included only in the test target; the image entry point is never called.
#[allow(dead_code, clippy::panic)]
mod image_build;

use std::path::Path;
use std::process::Command;

#[test]
fn loaded_image_budget_includes_trailing_bss_and_alignment() {
    let symbols = "\
00001000 g       .header 00000000 _image_start\n\
00001800 g       .data   00000000 last_file_byte\n\
00001c08 g       .bss    00000000 bss_end\n\
00001c10 g       .bss    00000000 _image_end\n";
    assert_eq!(image_build::loaded_image_size(symbols).unwrap(), 0xc10);
    assert!(image_build::loaded_image_size("00001000 _image_start").is_err());
    assert!(image_build::loaded_image_size("00002000 _image_start\n00001000 _image_end").is_err());
}

fn executable(path: &Path, script: &str) {
    carrick_test_support::executable::write_executable(path, script);
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

fn spawn_wrapper_fixture(fixture_name: &str) -> (tempfile::TempDir, std::path::PathBuf, String) {
    let root = tempfile::tempdir().unwrap();
    let env_log = root.path().join("cargo.env");
    let fake_cargo = root.path().join("cargo");
    executable(
        &fake_cargo,
        &format!(
            "#!/bin/sh\nset -eu\n{{\n  printf 'ARGS=%s\\n' \"$*\"\n  printf 'RUSTC_WORKSPACE_WRAPPER=%s\\n' \"${{RUSTC_WORKSPACE_WRAPPER:-}}\"\n  printf 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=%s\\n' \"${{CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER:-}}\"\n  printf 'CARGO_MAKEFLAGS=%s\\n' \"${{CARGO_MAKEFLAGS:-}}\"\n  printf 'CARGO_ENCODED_RUSTFLAGS=%s\\n' \"${{CARGO_ENCODED_RUSTFLAGS:-}}\"\n  printf 'RUSTC_WRAPPER=%s\\n' \"${{RUSTC_WRAPPER:-}}\"\n}} > {}\n",
            env_log.display()
        ),
    );
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args(["--exact", fixture_name, "--ignored", "--nocapture"])
        .env("TEST_ROOT", root.path())
        .env("TEST_CARGO", &fake_cargo)
        .env("RUSTC_WORKSPACE_WRAPPER", "/fake/clippy-driver")
        .env("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "/fake/clippy-driver")
        .env("CARGO_MAKEFLAGS", "-j9")
        .env("CARGO_ENCODED_RUSTFLAGS", "--cfg\x1fbad")
        .env("RUSTC_WRAPPER", "/keep/sccache");
    passes(&mut child);
    let recorded = std::fs::read_to_string(&env_log).unwrap();
    (root, env_log, recorded)
}

fn assert_workspace_wrappers_stripped(recorded: &str) {
    assert!(
        recorded.contains("RUSTC_WORKSPACE_WRAPPER=\n"),
        "expected RUSTC_WORKSPACE_WRAPPER stripped, got:\n{recorded}"
    );
    assert!(
        recorded.contains("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=\n"),
        "expected CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER stripped, got:\n{recorded}"
    );
    assert!(
        recorded.contains("CARGO_MAKEFLAGS=\n"),
        "expected CARGO_MAKEFLAGS stripped, got:\n{recorded}"
    );
    assert!(
        recorded.contains("CARGO_ENCODED_RUSTFLAGS=\n"),
        "expected CARGO_ENCODED_RUSTFLAGS stripped, got:\n{recorded}"
    );
    assert!(
        recorded.contains("RUSTC_WRAPPER=/keep/sccache\n"),
        "expected RUSTC_WRAPPER preserved, got:\n{recorded}"
    );
}

#[test]
fn nested_image_build_strips_workspace_wrappers() {
    let (_root, _log, recorded) = spawn_wrapper_fixture("nested_image_build_wrapper_fixture");
    assert_workspace_wrappers_stripped(&recorded);
    assert!(
        recorded.contains("--target aarch64-unknown-none-softfloat --profile el1-image"),
        "{recorded}"
    );
    assert!(
        recorded.contains("--features allocator-test-control"),
        "{recorded}"
    );
}

#[test]
fn package_guest_image_strips_workspace_wrappers() {
    let (_root, _log, recorded) = spawn_wrapper_fixture("package_guest_image_wrapper_fixture");
    assert_workspace_wrappers_stripped(&recorded);
    assert!(
        recorded.contains("--target aarch64-unknown-none-softfloat --release"),
        "{recorded}"
    );
}

#[test]
#[ignore = "subprocess fixture verifying nested_image_build env scrubbing"]
fn nested_image_build_wrapper_fixture() {
    let root = std::path::PathBuf::from(std::env::var_os("TEST_ROOT").unwrap());
    let cargo = std::path::PathBuf::from(std::env::var_os("TEST_CARGO").unwrap());
    let target_dir = root.join("el1-target");
    let status = image_build::nested_image_build(&cargo, &target_dir, true)
        .status()
        .unwrap();
    assert!(status.success(), "{status}");
}

#[test]
#[ignore = "subprocess fixture verifying package_guest_image env scrubbing"]
fn package_guest_image_wrapper_fixture() {
    use carrick_xtask::guest_image::{GuestImageBuildConfig, GuestTargetArch, package_guest_image};

    let root = std::path::PathBuf::from(std::env::var_os("TEST_ROOT").unwrap());
    let fake_cargo = root.join("cargo-guest");
    let env_log = root.join("cargo.env");
    let target_dir = root.join("guest-target");
    let bin_dir = root.join("bin");
    let sysroot = root.join("sysroot");
    let tool_bin = sysroot.join("lib/rustlib/fake-host/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(sysroot.join("lib/rustlib/aarch64-unknown-none-softfloat")).unwrap();
    std::fs::create_dir_all(&tool_bin).unwrap();

    executable(
        &bin_dir.join("rustc"),
        &format!(
            "#!/bin/sh\nif [ \"$1\" = --print ] && [ \"$2\" = sysroot ]; then\n  printf '%s\\n' {}\nelif [ \"$1\" = -vV ]; then\n  printf 'host: fake-host\\n'\nelse\n  exit 2\nfi\n",
            sysroot.display()
        ),
    );
    executable(&tool_bin.join("llvm-objdump"), "#!/bin/sh\nexit 0\n");
    executable(
        &tool_bin.join("rust-objcopy"),
        "#!/bin/sh\n# copy $3 -> $4\ncp \"$3\" \"$4\"\n",
    );

    let comp_root = root.join("guest-root");
    std::fs::create_dir_all(comp_root.join("src")).unwrap();
    std::fs::write(
        comp_root.join("Cargo.toml"),
        "[package]\nname = \"dummy-guest\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(comp_root.join("src/main.rs"), "fn main() {}\n").unwrap();

    let elf_out = target_dir.join("aarch64-unknown-none-softfloat/release/dummy-guest");
    executable(
        &fake_cargo,
        &format!(
            "#!/bin/sh\nset -eu\n{{\n  printf 'ARGS=%s\\n' \"$*\"\n  printf 'RUSTC_WORKSPACE_WRAPPER=%s\\n' \"${{RUSTC_WORKSPACE_WRAPPER:-}}\"\n  printf 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=%s\\n' \"${{CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER:-}}\"\n  printf 'CARGO_MAKEFLAGS=%s\\n' \"${{CARGO_MAKEFLAGS:-}}\"\n  printf 'CARGO_ENCODED_RUSTFLAGS=%s\\n' \"${{CARGO_ENCODED_RUSTFLAGS:-}}\"\n  printf 'RUSTC_WRAPPER=%s\\n' \"${{RUSTC_WRAPPER:-}}\"\n}} > {}\nmkdir -p {}\nprintf 'dummy-elf' > {}\n",
            env_log.display(),
            elf_out.parent().unwrap().display(),
            elf_out.display()
        ),
    );

    let out_dir = root.join("out");
    let mut config = GuestImageBuildConfig::new(&comp_root, GuestTargetArch::Aarch64, &out_dir);
    config.cargo_path = Some(fake_cargo);
    config.target_dir = Some(target_dir);

    // Subprocess fixture runs with fake rustc first on PATH before spawning threads.
    if std::env::var_os("INNER_GUEST").is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
            .env("INNER_GUEST", "1")
            .args([
                "--exact",
                "package_guest_image_wrapper_fixture",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let artifact = package_guest_image(&config).expect("package_guest_image succeeds");
    assert!(artifact.binary_path.exists());
}
