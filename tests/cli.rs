use assert_cmd::Command;
use flate2::Compression;
use flate2::write::GzEncoder;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use std::io::Write;

#[test]
fn inspect_elf_command_prints_json_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hello");
    std::fs::write(&path, minimal_aarch64_elf()).unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .args(["inspect-elf", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("\"machine\": \"aarch64\""))
        .stdout(contains("\"entry\": 4194304"));
}

#[test]
fn plan_elf_load_command_prints_segment_plan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hello");
    std::fs::write(&path, minimal_aarch64_elf_with_load_segment()).unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .args(["plan-elf-load", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("\"virtual_address\": 4194304"))
        .stdout(contains("\"execute\": true"));
}

#[test]
fn rootfs_cli_lists_and_reads_composed_layers() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.tar.gz");
    let upper = dir.path().join("upper.tar.gz");
    std::fs::write(&base, gzip_tar([("etc/motd", b"base".as_slice())])).unwrap();
    std::fs::write(
        &upper,
        gzip_tar([
            ("etc/.wh.motd", b"".as_slice()),
            ("etc/os-release", b"NAME=upper\n".as_slice()),
        ]),
    )
    .unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "rootfs",
            "--layer",
            base.to_str().unwrap(),
            "--layer",
            upper.to_str().unwrap(),
            "ls",
            "/etc",
        ])
        .assert()
        .success()
        .stdout(contains("os-release"))
        .stdout(predicates::str::contains("motd").not());

    Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "rootfs",
            "--layer",
            base.to_str().unwrap(),
            "--layer",
            upper.to_str().unwrap(),
            "cat",
            "/etc/os-release",
        ])
        .assert()
        .success()
        .stdout(contains("NAME=upper"));
}

#[test]
fn dispatch_syscall_cli_exercises_write_path() {
    Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "dispatch-syscall",
            "64",
            "--args",
            "1,16384,5,0,0,0",
            "--memory-base",
            "16384",
            "--memory-text",
            "hello",
        ])
        .assert()
        .success()
        .stdout(contains("\"stdout\": \"hello\""))
        .stdout(contains("\"value\": 5"));
}

#[test]
fn load_elf_command_prints_address_space_summary() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "load-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello",
            "--find-text",
            "hello from carrick\n",
        ])
        .assert()
        .success()
        .stdout(contains("\"region_count\""))
        .stdout(contains("\"found_address\""));
}

#[test]
fn run_elf_command_executes_or_reports_hvf_backend_error() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello",
            "--max-traps",
            "8",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("hello from carrick"));
        assert!(stdout.contains("\"traps\": 2"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

fn minimal_aarch64_elf() -> Vec<u8> {
    let mut elf = vec![0_u8; 64];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&183_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf
}

fn minimal_aarch64_elf_with_load_segment() -> Vec<u8> {
    let mut elf = vec![0_u8; 0x1004];
    elf[0..64].copy_from_slice(&minimal_aarch64_elf());
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes());

    let ph = 64;
    elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
    elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes());
    elf[ph + 8..ph + 16].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[ph + 16..ph + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[ph + 32..ph + 40].copy_from_slice(&4_u64.to_le_bytes());
    elf[ph + 40..ph + 48].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[0x1000..0x1004].copy_from_slice(b"\x1f\x20\x03\xd5");
    elf
}

fn gzip_tar<const N: usize>(files: [(&str, &[u8]); N]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        builder.finish().unwrap();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}
