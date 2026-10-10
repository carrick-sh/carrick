//! Production CLI binding for a native x86_64 guest on Linux/KVM.
//! The native execution below is the Linux oracle for the exact same ELF.
#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "platform-linux"
))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::process::ExitStatusExt;
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
fn mounted_static_x86_startup_sequence_matches_native() {
    compare_mounted_assembly_with_native("x86_startup_sequence.S", b"S\n");
}

#[test]
fn mounted_static_x86_identity_eperm_matches_native() {
    compare_mounted_assembly_with_native("x86_identity_eperm.S", b"P\n");
}

#[test]
fn mounted_static_x86_identity_fork_matches_native() {
    compare_mounted_assembly_with_native("x86_identity_fork.S", b"K\n");
}

#[test]
fn mounted_static_x86_ipc_msg_round_trip_matches_native() {
    compare_mounted_assembly_with_native("x86_ipc_msg.S", b"M\n");
}

#[test]
fn mounted_static_x86_ipc_sem_blocked_waiter_matches_native() {
    compare_mounted_assembly_with_native("x86_ipc_sem.S", b"S\n");
}

#[test]
fn mounted_static_x86_ipc_sem_undo_matches_native() {
    compare_mounted_assembly_with_native("x86_ipc_sem_undo.S", b"U\n");
}

#[test]
fn mounted_static_x86_ipc_sem_rmid_matches_native() {
    compare_mounted_assembly_with_native("x86_ipc_sem_rmid.S", b"R\n");
}

#[test]
fn mounted_static_x86_ipc_shm_unrouted_refusal() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("shm-unrouted");
    compile_assembly("x86_ipc_shm_unrouted.S", &elf);
    let run = run_mounted_binary(&elf, "x86_ipc_shm_unrouted.S", false);
    assert_eq!(
        run.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.stdout, b"U\n");
}

#[test]
fn mounted_static_x86_ipc_perm_eacces_matches_native() {
    compare_mounted_assembly_with_native("x86_ipc_perm.S", b"P\n");
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
    assert_eq!(witness["host_forwards"], 2); // write and exit_group only
    assert_eq!(witness["portal_exits"], 5);
    assert_eq!(
        witness["guest_refusal_families"],
        serde_json::json!([
            {"family": "memory", "count": 1},
            {"family": "signal", "count": 1},
            {"family": "unclassified", "count": 1}
        ])
    );
    assert_eq!(report["report"]["summary"]["distinct_partial_syscalls"], 3);
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
        .timeout(Duration::from_secs(10))
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
