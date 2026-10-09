//! Production CLI binding for a native x86_64 guest on Linux/KVM.
//! The native execution below is the Linux oracle for the exact same ELF.
#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "platform-linux"
))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Stdio};
use std::time::Duration;

use assert_cmd::Command;

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

#[test]
fn mounted_static_x86_elf_writes_hello_and_exits_seven_through_shared_kernel() {
    let present = std::path::Path::new("/dev/kvm").exists();
    assert!(
        present || std::env::var_os("CARRICK_REQUIRE_KVM").is_none_or(|value| value != "1"),
        "CARRICK_REQUIRE_KVM=1 but /dev/kvm is absent: the KVM gate must not skip"
    );
    if !present {
        let message = b"SKIP x86 KVM CLI run: /dev/kvm is absent on this host\n";
        // libtest captures eprintln! from passing tests. Write to the host
        // descriptor so an ordinary test invocation shows the skip reason.
        // SAFETY: message is a retained byte literal and fd 2 is the test
        // process's stderr; a short write affects only this diagnostic.
        unsafe { libc::write(libc::STDERR_FILENO, message.as_ptr().cast(), message.len()) };
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("hello");
    // The completed compiler owns all writable ELF descriptors. A writer
    // in this process could be inherited by a concurrent fork and make the
    // native oracle fail ETXTBSY even after the parent closes its own fd.
    compile_assembly("x86_hello.S", &elf);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .expect("run native x86 Linux oracle");
    assert_eq!(native.stdout, b"hello\n");
    assert!(native.stderr.is_empty());
    assert_eq!(native.status.code(), Some(7));

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
        .env("CARRICK_RUN_ID", "x86-kvm-hello-test")
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
        b"hello\n",
        "status: {:?}; stderr: {}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        run.status.code(),
        Some(7),
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
        .env("CARRICK_RUN_ID", "x86-kvm-hello-receipt-test")
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
    assert_eq!(observed.status.code(), Some(7));
    let envelope = observed
        .stdout
        .strip_prefix(b"hello\n")
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
}

#[test]
fn mounted_static_x86_elf_matches_native_anonymous_memory() {
    compare_mounted_assembly_with_native("x86_memory_only.S", b"M\n");
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("memory-private");
    compile_assembly("x86_memory_only.S", &elf);
    let observed = run_mounted_binary(&elf, "x86-memory-private", true);
    assert_eq!(
        observed.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&observed.stderr)
    );
    let envelope = observed
        .stdout
        .strip_prefix(b"M\n")
        .expect("guest anonymous memory output");
    let report: serde_json::Value = serde_json::from_slice(envelope).unwrap();
    let witness = &report["report"]["execution_witness"];
    assert_eq!(witness["anonymous_private_pages"], 1);
    assert_eq!(
        witness["physical_crossing_families"],
        serde_json::json!([
            { "family": "owner_grant", "count": 2 }
        ])
    );
    assert_eq!(
        witness["host_forwards"], 2,
        "only write and exit cross host dispatch"
    );
    assert!(
        witness["guest_refusal_families"]
            .as_array()
            .is_none_or(|rows| rows.is_empty())
    );
}

#[test]
fn mounted_static_x86_adjacent_anonymous_memory_keeps_existing_leaf() {
    compare_mounted_assembly_with_native("x86_adjacent_memory.S", b"A\n");
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("adjacent-counted");
    compile_assembly("x86_adjacent_memory.S", &elf);
    let observed = run_mounted_binary(&elf, "x86-adjacent-counted", true);
    assert_eq!(observed.status.code(), Some(7));
    let report: serde_json::Value = serde_json::from_slice(
        observed
            .stdout
            .strip_prefix(b"A\n")
            .expect("adjacent output"),
    )
    .unwrap();
    let witness = &report["report"]["execution_witness"];
    assert_eq!(witness["anonymous_private_pages"], 2);
    assert_eq!(
        witness["physical_crossing_families"],
        serde_json::json!([
            { "family": "owner_grant", "count": 4 }
        ])
    );
    assert_eq!(witness["host_forwards"], 2);
    assert_eq!(witness["portal_exits"], 6);
}

#[test]
fn mounted_static_x86_bad_write_returns_efault_and_continues() {
    compare_mounted_assembly_with_native("x86_bad_write.S", b"E\n");
}

#[test]
fn mounted_static_x86_two_live_mms_have_private_anonymous_leaves() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("two-mm-private");
    compile_assembly("x86_two_mm_private.S", &elf);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .expect("native two-MM oracle");
    assert_eq!(native.status.code(), Some(7));
    assert_eq!(native.stdout, b"Q\n");
    let observed = run_mounted_binary(&elf, "x86-two-mm-private", true);
    assert_eq!(
        observed.status.code(),
        Some(7),
        "91 = fork refusal; 93 = mmap refusal; 94 = cross-MM/zero leaf; 95 = wait failure; stderr: {}; report: {}",
        String::from_utf8_lossy(&observed.stderr),
        String::from_utf8_lossy(&observed.stdout)
    );
    let report: serde_json::Value =
        serde_json::from_slice(observed.stdout.strip_prefix(b"Q\n").expect("two-MM stdout"))
            .unwrap();
    let witness = &report["report"]["execution_witness"];
    assert_eq!(witness["anonymous_private_pages"], 32);
    let owners = witness["anonymous_private_mms"]
        .as_array()
        .expect("live-authenticated per-MM PRIVATE witnesses");
    assert_eq!(owners.len(), 2);
    assert!(owners.iter().any(|owner| owner["cpu_mask"] == 1));
    assert!(owners.iter().any(|owner| owner["cpu_mask"] == 2));
    assert_ne!(owners[0]["mm"], owners[1]["mm"]);
    assert_ne!(owners[0]["root"], owners[1]["root"]);
    for owner in owners {
        assert_eq!(owner["private_pages"], 16);
        assert!(owner["incarnation"].as_u64().is_some_and(|n| n > 0));
        assert!(owner["generation"].as_u64().is_some_and(|n| n > 0));
    }
    assert_eq!(witness["cross_mm_private_aliases"], 0);
    assert!(
        witness["peer_active_private_grants"]
            .as_u64()
            .is_some_and(|n| n > 0)
    );
}

#[test]
fn mounted_static_x86_getpid_matches_guest_gettid() {
    compare_mounted_assembly_with_native("x86_dispatch_getpid.S", b"D\n");
}

#[test]
fn mounted_static_x86_guest_owned_calls_refuse_without_host_effects() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("authority-refusal");
    compile_assembly("x86_authority_refusal.S", &elf);
    let run = run_mounted_binary(&elf, "authority-refusal", true);
    assert_eq!(
        run.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let envelope = run
        .stdout
        .strip_prefix(b"R\n")
        .expect("guest refusal witness");
    let report: serde_json::Value = serde_json::from_slice(envelope).unwrap();
    let witness = &report["report"]["execution_witness"];
    assert_eq!(witness["host_forwards"], 1); // write; root exit is a physical crossing
    assert_eq!(witness["portal_exits"], 2);
    assert!(witness["guest_refusal_families"].is_null(), "{report}");
    assert_eq!(report["report"]["summary"]["distinct_partial_syscalls"], 0);
}

#[test]
#[ignore = "CPL0 mprotect needs the shared anonymous descriptor editor and x86 SIGSEGV delivery"]
fn mounted_static_x86_mprotect_none_faults_like_native() {
    compare_mounted_fault_with_native("x86_mprotect_fault.S");
}

#[test]
#[ignore = "CPL0 munmap needs the shared anonymous descriptor editor and x86 SIGSEGV delivery"]
fn mounted_static_x86_munmap_faults_like_native() {
    compare_mounted_fault_with_native("x86_munmap_fault.S");
}

#[test]
fn mounted_static_x86_arch_prctl_preserves_user_tls_bases() {
    compare_mounted_assembly_with_native("x86_dispatch_segments.S", b"T\n");
}

#[test]
fn mounted_static_x86_poll_stdio_matches_native() {
    compare_mounted_assembly_with_native("x86_poll_stdio.S", b"P\n");
}

#[test]
fn mounted_static_x86_sched_inring_matches_native() {
    compare_mounted_assembly_with_native("x86_sched_inring.S", b"S\n");
}

#[test]
fn mounted_static_x86_sched_unported_refusal_returns_enosys() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("sched-refusal");
    compile_assembly("x86_sched_refusal.S", &elf);
    let run = run_mounted_binary(&elf, "sched-refusal", false);
    assert_eq!(
        run.stdout,
        b"R\n",
        "status: {:?}; stderr: {}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        run.status.code(),
        Some(7),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn mounted_static_x86_poll_empty_stdin_matches_native() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("poll-empty-stdin");
    compile_assembly("x86_poll_empty_stdin.S", &elf);
    let native = run_poll_with_open_empty_stdin(std::process::Command::new(&elf));
    assert_eq!(native, (b"E\n".to_vec(), Some(7)));

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
        "{}",
        String::from_utf8_lossy(&load.stderr)
    );
    let mut command = std::process::Command::new(&cli);
    command
        .env("CARRICK_HOME", &home)
        .env("CARRICK_RUN_ID", "x86-kvm-empty-poll-test")
        .args([
            "run",
            "--platform",
            "linux/amd64",
            "--pull",
            "never",
            "--volume",
            &format!("{}:/hello:ro", elf.display()),
            "x86-kvm-hello:latest",
        ]);
    assert_eq!(run_poll_with_open_empty_stdin(command), native);
}

struct ReapChild(Child);

impl std::ops::Deref for ReapChild {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ReapChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ReapChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn run_poll_with_open_empty_stdin(mut command: std::process::Command) -> (Vec<u8>, Option<i32>) {
    let mut child = ReapChild(
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn empty-stdin poll witness"),
    );
    let mut stdout = child.stdout.take().unwrap();
    let completed = poll_readable(stdout.as_raw_fd(), 5_000);
    if !completed {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    assert!(completed, "empty-stdin poll did not complete");
    let mut output = Vec::new();
    stdout.read_to_end(&mut output).unwrap();
    let status = child.wait().unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.is_empty(), "{stderr}");
    (output, status.code())
}

#[test]
fn mounted_static_x86_blocking_stdin_read_matches_native() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("blocking-stdin");
    compile_assembly("x86_blocking_stdin.S", &elf);
    let native = run_with_empty_stdin_then_write(std::process::Command::new(&elf));
    assert_eq!(native.0, b"R\nB\n");
    assert_eq!(native.1, Some(7));

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
        "{}",
        String::from_utf8_lossy(&load.stderr)
    );
    let mut command = std::process::Command::new(&cli);
    command
        .env("CARRICK_HOME", &home)
        .env("CARRICK_RUN_ID", "x86-kvm-blocking-read-test")
        .args([
            "run",
            "--platform",
            "linux/amd64",
            "--pull",
            "never",
            "--volume",
            &format!("{}:/hello:ro", elf.display()),
            "x86-kvm-hello:latest",
        ]);
    let observed = run_with_empty_stdin_then_write(command);
    assert_eq!(
        observed, native,
        "blocking read must complete like native Linux"
    );
}

fn run_with_empty_stdin_then_write(mut command: std::process::Command) -> (Vec<u8>, Option<i32>) {
    let mut child = ReapChild(
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn blocking stdin witness"),
    );
    let mut stdout = child.stdout.take().unwrap();
    let mut first = [0; 2];
    assert!(
        poll_readable(stdout.as_raw_fd(), 5_000),
        "ready marker missing"
    );
    let marker = stdout.read_exact(&mut first);
    if let Err(ref error) = marker {
        let status = child.wait().unwrap();
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(
            marker.is_ok(),
            "ready marker read: {error}; status: {status}; stderr: {stderr}"
        );
    }
    assert_eq!(&first, b"R\n");
    // The write end remains open and empty. The guest must remain blocked
    // until the parent supplies its byte; EOF or an immediate error is red.
    let premature = poll_readable(stdout.as_raw_fd(), 50);
    if premature {
        drop(child.stdin.take());
        let mut rest = Vec::new();
        stdout.read_to_end(&mut rest).unwrap();
        let status = child.wait().unwrap();
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(
            !premature,
            "read completed before input: status={status}, stdout={rest:?}, stderr={stderr}"
        );
    }
    assert!(
        child.try_wait().unwrap().is_none(),
        "reader exited before input"
    );
    child.stdin.take().unwrap().write_all(b"X").unwrap();
    assert!(
        poll_readable(stdout.as_raw_fd(), 5_000),
        "completion marker missing"
    );
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).unwrap();
    let status = child.wait().unwrap();
    let mut output = first.to_vec();
    output.extend(rest);
    (output, status.code())
}

fn poll_readable(fd: i32, timeout_ms: i32) -> bool {
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pollfd is a valid stack allocation for one descriptor.
    let result = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
    assert!(
        result >= 0,
        "host poll failed: {}",
        std::io::Error::last_os_error()
    );
    result > 0
}

#[test]
#[ignore = "CPL0 startup needs guest rt_sigaction, lifecycle copy, and anonymous mprotect"]
fn mounted_static_x86_dispatches_libc_startup_calls() {
    compare_mounted_assembly_with_native("x86_dispatch_startup.S", b"S\n");
}

#[test]
#[ignore = "musl startup needs CPL0 signal actions and anonymous first-touch backing"]
fn mounted_static_x86_musl_hello_matches_native() {
    if skip_without_kvm() {
        return;
    }
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../carrick-vmm-bhyve/fixtures/hello-x86_64");
    // `just test-kvm` declares and builds this input before the test target.
    // A missing artifact is a gate error, not a passing skip or a nested
    // Cargo build inside an already running test process.
    let elf = fixture.join("target/x86_64-unknown-linux-musl/release/carrick-hello-x86_64");
    assert!(
        elf.is_file(),
        "missing KVM lane musl build input: {}",
        elf.display()
    );
    compare_mounted_binary_with_native(&elf, b"hello, x86_64 world\n", 0, "musl-hello");
}

#[test]
#[ignore = "fork returns a CPL0 lifecycle handoff; production fork wiring awaits #82"]
fn mounted_static_x86_memory_and_fork_wait_match_native() {
    compare_mounted_assembly_with_native("x86_memory_fork_wait.S", b"F\n");
}

fn skip_without_kvm() -> bool {
    let present = std::path::Path::new("/dev/kvm").exists();
    assert!(
        present || std::env::var_os("CARRICK_REQUIRE_KVM").is_none_or(|value| value != "1"),
        "CARRICK_REQUIRE_KVM=1 but /dev/kvm is absent: the KVM gate must not skip"
    );
    if !present {
        let message = b"SKIP x86 KVM CLI run: /dev/kvm is absent on this host\n";
        // SAFETY: fixed diagnostic bytes to the test process stderr.
        unsafe { libc::write(libc::STDERR_FILENO, message.as_ptr().cast(), message.len()) };
        return true;
    }
    false
}

fn compare_mounted_assembly_with_native(fixture: &str, expected_stdout: &[u8]) {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("assembly-guest");
    compile_assembly(fixture, &elf);
    compare_mounted_binary_with_native(&elf, expected_stdout, 7, fixture);
}

fn compare_mounted_fault_with_native(fixture: &str) {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("fault-guest");
    compile_assembly(fixture, &elf);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .expect("run native x86 fault oracle");
    assert_eq!(native.status.signal(), Some(libc::SIGSEGV));
    assert!(native.stdout.is_empty());
    let run = run_mounted_binary(&elf, fixture, false);
    assert!(run.stdout.is_empty());
    assert!(
        run.status.signal() == Some(libc::SIGSEGV)
            || run.status.code() == Some(128 + libc::SIGSEGV),
        "CPL0 must deliver SIGSEGV like native Linux; status: {:?}; stderr: {}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
}

fn compile_assembly(fixture: &str, elf: &std::path::Path) {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture);
    let compile = Command::new("cc")
        .timeout(Duration::from_secs(15))
        .args([
            "-nostdlib",
            "-static",
            "-no-pie",
            "-Wl,--build-id=none",
            "-o",
        ])
        .arg(elf)
        .arg(&source)
        .output()
        .expect("compile native x86 assembly oracle");
    assert!(
        compile.status.success(),
        "cc stderr: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
}

fn compare_mounted_binary_with_native(
    elf: &std::path::Path,
    expected_stdout: &[u8],
    expected_exit: i32,
    run_id: &str,
) {
    let native = Command::new(elf)
        .timeout(Duration::from_secs(5))
        .output()
        .expect("run native x86 Linux oracle");
    assert_eq!(native.stdout, expected_stdout);
    assert!(native.stderr.is_empty());
    assert_eq!(native.status.code(), Some(expected_exit));

    let run = run_mounted_binary(elf, run_id, false);
    assert_eq!(
        run.stdout,
        native.stdout,
        "Carrick status: {:?}; stderr: {}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        run.status.code(),
        native.status.code(),
        "Carrick stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(run.stderr.is_empty());
}

fn run_mounted_binary(elf: &std::path::Path, run_id: &str, json: bool) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
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
    let mut command = Command::new(&cli);
    command
        .timeout(Duration::from_secs(5))
        .env("CARRICK_HOME", &home)
        .env("CARRICK_RUN_ID", format!("x86-kvm-{run_id}-test"));
    if json {
        command.arg("run").arg("--json");
    } else {
        command.arg("run");
    }
    command.args([
        "--platform",
        "linux/amd64",
        "--pull",
        "never",
        "--volume",
        &format!("{}:/hello:ro", elf.display()),
        "x86-kvm-hello:latest",
    ]);
    command
        .output()
        .expect("run mounted x86 Linux binary through carrick")
}
