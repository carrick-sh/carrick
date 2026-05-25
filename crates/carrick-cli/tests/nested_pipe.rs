#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
#![allow(clippy::unwrap_used)]

use assert_cmd::Command;

#[test]
fn nested_pipe_writer_survives_reinit_after_fork() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let mut carrick = Command::cargo_bin("carrick").unwrap();
    let carrick_path = carrick.get_program().to_owned();
    let codesign = std::process::Command::new("codesign")
        .args([
            "--force",
            "--sign",
            "-",
            "--entitlements",
            "scripts/entitlements.plist",
        ])
        .arg(&carrick_path)
        .output()
        .unwrap();
    assert!(
        codesign.status.success(),
        "codesign failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&codesign.stdout),
        String::from_utf8_lossy(&codesign.stderr)
    );

    carrick
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-nested-pipe",
            "--raw",
            "--fs",
            "host",
            "--max-traps",
            "500",
        ])
        .assert()
        .success()
        .stdout("hi");
}
