//! Production CLI binding for a native x86_64 guest on Linux/KVM.
//! The native execution below is the Linux oracle for the exact same ELF.
#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "platform-linux"
))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use assert_cmd::Command;

fn hello_elf() -> Vec<u8> {
    // _start: write(1, "hello\n", 6); exit(7). The RIP displacement points
    // at the six literal bytes after the final syscall instruction.
    let code: &[u8] = &[
        0xb8, 1, 0, 0, 0, // mov eax, 1
        0xbf, 1, 0, 0, 0, // mov edi, 1
        0x48, 0x8d, 0x35, 0x13, 0, 0, 0, // lea rsi, [rip+19]
        0xba, 6, 0, 0, 0, // mov edx, 6
        0x0f, 0x05, // syscall
        0xbf, 7, 0, 0, 0, // mov edi, 7
        0xb8, 60, 0, 0, 0, // mov eax, 60
        0x0f, 0x05, // syscall
        b'h', b'e', b'l', b'l', b'o', b'\n',
    ];
    let mut elf = vec![0_u8; 0x1000 + code.len()];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4..7].copy_from_slice(&[2, 1, 1]);
    elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x401000_u64.to_le_bytes());
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
    let ph = 64;
    elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
    elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes());
    elf[ph + 8..ph + 16].copy_from_slice(&0_u64.to_le_bytes());
    elf[ph + 16..ph + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
    let image_len = elf.len() as u64;
    elf[ph + 32..ph + 40].copy_from_slice(&image_len.to_le_bytes());
    elf[ph + 40..ph + 48].copy_from_slice(&image_len.to_le_bytes());
    elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[0x1000..].copy_from_slice(code);
    elf
}

fn append_tar(builder: &mut tar::Builder<&mut Vec<u8>>, name: &str, bytes: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, name, bytes).unwrap();
}

fn empty_image_archive() -> Vec<u8> {
    let mut layer = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut layer);
        append_tar(&mut tar, ".keep", b"");
        tar.finish().unwrap();
    }
    let config = br#"{"architecture":"amd64","os":"linux","config":{"Cmd":["/hello"]}}"#;
    let manifest =
        br#"[{"Config":"config.json","RepoTags":["x86-kvm-hello:latest"],"Layers":["layer.tar"]}]"#;
    let mut archive = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut archive);
        append_tar(&mut tar, "manifest.json", manifest);
        append_tar(&mut tar, "config.json", config);
        append_tar(&mut tar, "layer.tar", &layer);
        tar.finish().unwrap();
    }
    archive
}

fn kvm_host_available(present: bool, required: bool) -> bool {
    assert!(
        present || !required,
        "required KVM CLI gate cannot run: /dev/kvm is absent"
    );
    present
}

fn kvm_available() -> bool {
    if !kvm_host_available(
        std::path::Path::new("/dev/kvm").exists(),
        std::env::var_os("CARRICK_REQUIRE_KVM").is_some_and(|value| value == "1"),
    ) {
        let message = b"SKIP x86 KVM CLI run: /dev/kvm is absent on this host\n";
        // libtest captures eprintln! from passing tests. Write to the host
        // descriptor so an ordinary test invocation shows the skip reason.
        // SAFETY: message is a retained byte literal and fd 2 is the test
        // process's stderr; a short write affects only this diagnostic.
        unsafe { libc::write(libc::STDERR_FILENO, message.as_ptr().cast(), message.len()) };
        return false;
    }
    true
}

fn assert_shared_kernel_elf(
    bytes: &[u8],
    expected: &[u8],
    status: i32,
    run_id: &str,
) -> Option<u64> {
    if !kvm_available() {
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("hello");
    // Writing executables in this multithreaded process lets another test's
    // fork transiently inherit the writer fd, yielding ETXTBSY at exec even
    // after our own close. An owned publisher process closes and exits before
    // publication completes; guest tests retain their full concurrency.
    let writer_source = dir.path().join("publish.rs");
    let writer = dir.path().join("publish");
    std::fs::write(&writer_source, include_str!("fixtures/publish_elf.rs")).unwrap();
    let compiled = Command::new("rustc")
        .timeout(Duration::from_secs(30))
        .args(["--edition=2021", "-o"])
        .arg(&writer)
        .arg(&writer_source)
        .output()
        .expect("compile isolated executable publisher");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let published = Command::new(writer)
        .timeout(Duration::from_secs(5))
        .arg(&elf)
        .write_stdin(bytes.to_vec())
        .output()
        .expect("publish executable in owned process");
    assert!(
        published.status.success(),
        "{}",
        String::from_utf8_lossy(&published.stderr)
    );
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .expect("run native x86 Linux oracle");
    assert_eq!(native.stdout, expected);
    assert!(native.stderr.is_empty());
    assert_eq!(native.status.code(), Some(status));

    let archive = dir.path().join("image.tar");
    std::fs::write(&archive, empty_image_archive()).unwrap();
    let cli = assert_cmd::cargo::cargo_bin("carrick");
    let home = dir.path().join("home");
    let load = Command::new(&cli)
        .timeout(Duration::from_secs(5))
        .env("CARRICK_HOME", &home)
        .args(["load", "--input", archive.to_str().unwrap()])
        .output()
        .expect("load local image");
    assert!(
        load.status.success(),
        "load stderr: {}",
        String::from_utf8_lossy(&load.stderr)
    );

    let run = Command::new(&cli)
        .timeout(Duration::from_secs(5))
        .env("CARRICK_HOME", &home)
        .env("CARRICK_RUN_ID", run_id)
        .args([
            "run",
            "--platform",
            "linux/amd64",
            "--pull",
            "never",
            "--volume",
            &format!("{}:/hello:ro", elf.display()),
            "x86-kvm-hello:latest",
        ])
        .output()
        .expect("run mounted x86 ELF through carrick");
    assert_eq!(
        run.stdout,
        expected,
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        run.status.code(),
        Some(status),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        run.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    // The JSON run exposes a guest-entry receipt. Exact CPL0 lane identity
    // plus two shared-kernel entries and host forwards distinguish this from
    // the retired carrick-x86 bringup_fns trap path.
    let observed = Command::new(&cli)
        .timeout(Duration::from_secs(5))
        .env("CARRICK_HOME", &home)
        .env("CARRICK_RUN_ID", format!("{run_id}-receipt"))
        .args([
            "run",
            "--json",
            "--platform",
            "linux/amd64",
            "--pull",
            "never",
            "--volume",
            &format!("{}:/hello:ro", elf.display()),
            "x86-kvm-hello:latest",
        ])
        .output()
        .expect("observe shared CPL0 run receipt");
    assert_eq!(observed.status.code(), Some(status));
    let envelope = observed
        .stdout
        .strip_prefix(expected)
        .expect("guest stdout before JSON receipt");
    let json: serde_json::Value = serde_json::from_slice(envelope).expect("run JSON receipt");
    assert_eq!(
        json["report"]["execution_witness"]["backend"],
        "kvm-x86-cpl0"
    );
    assert!(
        json["report"]["execution_witness"]["guest_entries"]
            .as_u64()
            .is_some_and(|n| n >= 2)
    );
    assert!(
        json["report"]["execution_witness"]["host_forwards"]
            .as_u64()
            .is_some_and(|n| n >= 2)
    );
    json["report"]["execution_witness"]["host_forwards"].as_u64()
}

#[test]
fn mounted_static_x86_elf_writes_hello_and_exits_seven_through_shared_kernel() {
    let _ = assert_shared_kernel_elf(&hello_elf(), b"hello\n", 7, "x86-kvm-hello-test");
}

/// Migrated M2 coverage: compile the same Rust/std musl fixture rather than
/// silently skipping a missing prebuilt executable. This exercises libc
/// startup, TLS, poll and exit_group through the production shared kernel.
#[test]
#[ignore = "PR #81: shared host dispatch, startup memory/signals and terminal clear-tid custody"]
fn musl_static_hello_runs_through_shared_kernel() {
    if !kvm_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("hello.rs");
    let executable = dir.path().join("hello");
    std::fs::write(
        &source,
        include_str!("../../carrick-vmm-bhyve/fixtures/hello-x86_64/src/main.rs"),
    )
    .unwrap();
    let compile = Command::new("rustc")
        .timeout(Duration::from_secs(30))
        .arg(&source)
        .args([
            "--edition=2021",
            "--target",
            "x86_64-unknown-linux-musl",
            "-C",
            "relocation-model=static",
            "-C",
            "opt-level=z",
            "-C",
            "panic=abort",
            "-o",
        ])
        .arg(&executable)
        .output()
        .expect("compile migrated static musl fixture (requires Rust musl target)");
    assert!(
        compile.status.success(),
        "musl fixture compile stderr: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let _ = assert_shared_kernel_elf(
        &std::fs::read(&executable).unwrap(),
        include_bytes!("../../carrick-vmm-bhyve/fixtures/hello-x86_64/oracle.expected"),
        0,
        "x86-kvm-musl-test",
    );
}

#[test]
fn arch_prctl_tls_and_errno_match_native_linux_through_shared_kernel() {
    use carrick_abi::syscall_x86_64::{ARCH_PRCTL_X86_NR, ArchPrctlOperation};
    if !kvm_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("tls.S");
    let executable = dir.path().join("tls");
    std::fs::write(&source, include_str!("fixtures/x86_arch_prctl.S")).unwrap();
    let compile = Command::new("cc")
        .timeout(Duration::from_secs(30))
        .args(["-nostdlib", "-static", "-Wl,--build-id=none"])
        .args([
            format!("-DNR_ARCH_PRCTL={ARCH_PRCTL_X86_NR}"),
            format!("-DSET_FS={}", ArchPrctlOperation::SetFs as u32),
            format!("-DGET_FS={}", ArchPrctlOperation::GetFs as u32),
            format!("-DSET_GS={}", ArchPrctlOperation::SetGs as u32),
            format!("-DGET_GS={}", ArchPrctlOperation::GetGs as u32),
        ])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("compile native TLS witness");
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let forwards = assert_shared_kernel_elf(
        &std::fs::read(executable).unwrap(),
        b"tls-ok\n",
        0,
        "x86-kvm-tls-test",
    )
    .unwrap();
    assert_eq!(
        forwards, 2,
        "only stdout write and terminal exit cross to the host"
    );
}

#[test]
#[should_panic(expected = "required KVM CLI gate cannot run")]
fn required_gate_rejects_missing_kvm() {
    kvm_host_available(false, true);
}
