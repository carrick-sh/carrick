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
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use wait_timeout::ChildExt;

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
    // plus two shared-kernel entries and the write's host forward distinguish
    // this from the retired carrick-x86 bringup_fns trap path.
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
    assert_eq!(
        json["report"]["execution_witness"]["host_forwards"], 1,
        "only write crosses host dispatch; exit uses the owned root receipt"
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
            { "family": "owner_grant", "count": 2 },
            { "family": "root_exit", "count": 1 }
        ])
    );
    assert_eq!(
        witness["host_forwards"], 1,
        "only write crosses host dispatch"
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
            { "family": "owner_grant", "count": 4 },
            { "family": "root_exit", "count": 1 }
        ])
    );
    assert_eq!(witness["host_forwards"], 1);
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

/// Sequential fork/exit rounds beyond the eight x86 fork lifecycle records:
/// each round past eight needs a retired child's stock reclaimed (its CR3
/// registration, inventory rows and private memslots released) and its
/// record reissued clean. Matches native output and exit.
#[test]
fn mounted_static_x86_fork_rounds_beyond_lifecycle_stock_reuse_retired_children() {
    fork_rounds_beyond_stock(&[]);
}

#[test]
fn mounted_static_x86_nocldwait_fork_rounds_beyond_lifecycle_stock() {
    fork_rounds_beyond_stock(&["-DAUTOREAP"]);
}

#[test]
fn mounted_static_x86_sigign_fork_rounds_beyond_lifecycle_stock() {
    fork_rounds_beyond_stock(&["-DAUTOREAP", "-DIGNORE_SIGCHLD"]);
}

fn fork_rounds_beyond_stock(flags: &[&str]) {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("fork-reuse");
    compile_assembly_with_flags("x86_fork_reuse.S", &elf, flags);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .expect("native fork reuse oracle");
    assert_eq!(native.status.code(), Some(7));
    let expected_stdout: &[u8] = b"R\n";
    assert_eq!(native.stdout, expected_stdout);
    let run_id = if flags.is_empty() {
        "x86-fork-reuse"
    } else if flags.contains(&"-DIGNORE_SIGCHLD") {
        "x86-fork-reuse-sigign"
    } else {
        "x86-fork-reuse-nocldwait"
    };
    let observed = run_mounted_binary(&elf, run_id, true);
    assert_eq!(
        observed.status.code(),
        Some(7),
        "91 = fork refusal; 93 = mmap refusal; 94 = stale or lost leaf; 95 = wait failure; 96 = child status; stderr: {}; report: {}",
        String::from_utf8_lossy(&observed.stderr),
        String::from_utf8_lossy(&observed.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(
        observed
            .stdout
            .strip_prefix(expected_stdout)
            .expect("fork reuse stdout"),
    )
    .unwrap();
    let families = report["report"]["execution_witness"]["fork_stock_families"]
        .as_array()
        .expect("fork stock families")
        .iter()
        .map(|row| {
            (
                row["family"].as_str().unwrap().to_owned(),
                row["count"].as_u64().unwrap(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(families.get("loan"), Some(&12), "{families:?}");
    assert_eq!(families.get("quarantined_child"), Some(&12), "{families:?}");
    // Rounds nine to twelve each needed a reclaimed child.
    assert!(
        families.get("returned_child").is_some_and(|n| *n >= 4),
        "{families:?}"
    );
    for refused in [
        "retire_refusal",
        "capacity_refusal",
        "inventory_refusal",
        "withdrawn_lifecycle",
        "reclaim_deferral",
    ] {
        assert!(!families.contains_key(refused), "{refused}: {families:?}");
    }
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
fn mounted_static_x86_set_tid_address_returns_native_positive_tid() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("clear-tid-dependency");
    compile_assembly("x86_clear_tid_dependency.S", &elf);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .expect("run native set_tid_address oracle");
    assert_eq!(native.status.code(), Some(7));
    assert_eq!(native.stdout, b"T\n");
    assert!(native.stderr.is_empty());
    let run = run_mounted_binary(&elf, "clear-tid-dependency", false);
    assert_eq!(
        run.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        run.stdout, b"T\n",
        "CPL0 must serve set_tid_address despite the exit custody gap"
    );
    assert!(run.stderr.is_empty());
}

#[test]
#[ignore = "cpl0 exit custody: production thread exit must clear and futex-wake"]
fn mounted_static_x86_thread_exit_clears_and_wakes_clear_tid() {
    compare_mounted_assembly_with_native("x86_clear_tid_exit.S", b"J\n");
}

#[test]
fn mounted_static_x86_raise_uses_set_tid_address_returned_tid() {
    compare_mounted_assembly_with_native("x86_clear_tid_raise.S", b"S\n");
}

#[test]
fn mounted_static_x86_exec_refuses_before_replacement_identity() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("exec-dependency");
    compile_assembly("x86_exec_dependency.S", &elf);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .unwrap();
    assert_eq!(native.status.code(), Some(7));
    assert_eq!(native.stdout, b"E\n");
    assert!(native.stderr.is_empty());
    let guest = run_mounted_binary(&elf, "exec-dependency", false);
    assert_eq!(
        guest.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&guest.stderr)
    );
    assert_eq!(
        guest.stdout, b"F\n",
        "shared-owner-exec-completion: CPL0 must refuse exec before replacement"
    );
    assert!(guest.stderr.is_empty());
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
    assert_eq!(witness["host_forwards"], 1); // write only; exit uses its owned receipt
    assert_eq!(witness["portal_exits"], 2); // write and the owned root-exit receipt
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
fn mounted_static_x86_poll_closed_stdio_matches_native() {
    compare_mounted_assembly_with_native("x86_poll_closed_stdio.S", b"C\n");
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
fn mounted_static_x86_descriptor_stdio_matches_native() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("descriptor-stdio");
    compile_assembly("x86_descriptor_stdio.S", &elf);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .unwrap();
    assert_eq!(native.stdout, b"D\n");
    assert!(native.stderr.is_empty());
    assert_eq!(native.status.code(), Some(7));
    let run = run_mounted_binary(&elf, "descriptor-stdio", false);
    assert_eq!(
        run.stdout, native.stdout,
        "status: {:?}; stderr: {:?}",
        run.status, run.stderr
    );
    assert_eq!(run.stderr, native.stderr);
    assert_eq!(run.status.code(), native.status.code());
}

#[test]
fn mounted_static_x86_remapped_writev_is_refused_without_wrong_stream() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("descriptor-writev");
    compile_assembly("x86_descriptor_writev_refusal.S", &elf);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .unwrap();
    assert!(native.stdout.is_empty());
    assert_eq!(native.stderr, b"V\n");
    assert_eq!(native.status.code(), Some(7));
    let run = run_mounted_binary(&elf, "descriptor-writev", false);
    assert!(run.stdout.is_empty());
    assert!(run.stderr.is_empty());
    assert_eq!(run.status.code(), Some(8));
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

#[test]
fn mounted_static_x86_blocking_poll_wakes_once_on_stdin_data() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("poll-blocking-stdin");
    compile_assembly("x86_poll_blocking_stdin.S", &elf);
    let native = run_with_empty_stdin_then_write(std::process::Command::new(&elf));
    assert_eq!(native, (b"R\nP\n".to_vec(), Some(7)));
    let command = mounted_poll_command(dir.path(), &elf);
    assert_eq!(run_with_empty_stdin_then_write(command), native);
}

#[test]
fn mounted_static_x86_poll_timeout_returns_zero() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("poll-timeout");
    compile_assembly("x86_poll_timeout.S", &elf);
    let native = run_poll_with_open_empty_stdin(std::process::Command::new(&elf));
    assert_eq!(native, (b"T\n".to_vec(), Some(7)));
    let command = mounted_poll_command(dir.path(), &elf);
    assert_eq!(run_poll_with_open_empty_stdin(command), native);
}

#[test]
fn mounted_static_x86_poll_empty_sets_sleep_until_timeout() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("poll-empty-sets");
    compile_assembly("x86_poll_empty_sets.S", &elf);
    let native =
        run_poll_timeout_markers(std::process::Command::new(&elf), &[b"B\n", b"N\n", b"T\n"]);
    assert_eq!(native, (b"B\nN\nT\n".to_vec(), Some(7)));
    let command = mounted_poll_command(dir.path(), &elf);
    assert_eq!(
        run_poll_timeout_markers(command, &[b"B\n", b"N\n", b"T\n"]),
        native
    );
}

#[test]
fn mounted_static_x86_ppoll_waits_and_rejects_bad_nsec() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("ppoll-timeout");
    compile_assembly("x86_ppoll_timeout.S", &elf);
    let native = run_poll_timeout_markers(std::process::Command::new(&elf), &[b"B\n", b"T\n"]);
    assert_eq!(native, (b"B\nT\n".to_vec(), Some(7)));
    let command = mounted_poll_command(dir.path(), &elf);
    assert_eq!(run_poll_timeout_markers(command, &[b"B\n", b"T\n"]), native);
}

fn run_poll_timeout_markers(
    mut command: std::process::Command,
    markers: &[&[u8; 2]],
) -> (Vec<u8>, Option<i32>) {
    run_poll_timeout_markers_with(&mut command, markers, |_, _| ())
}

fn run_poll_timeout_markers_with(
    command: &mut std::process::Command,
    markers: &[&[u8; 2]],
    mut after_start: impl FnMut(i32, usize),
) -> (Vec<u8>, Option<i32>) {
    let mut child = ReapChild(
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn empty-set poll witness"),
    );
    let mut stdout = child.stdout.take().unwrap();
    let mut output = Vec::new();
    let mut start_epoch: Option<Instant> = None;
    for (index, expected) in markers.iter().enumerate() {
        assert!(
            poll_readable(stdout.as_raw_fd(), 5_000),
            "poll marker {index} missing"
        );
        let mut marker = [0u8; 2];
        let read_result = stdout.read_exact(&mut marker);
        if read_result.is_err() {
            let status = child.wait().unwrap();
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            assert!(
                read_result.is_ok(),
                "poll marker {index} read failed: {read_result:?}; status={status}; output={output:?}; stderr={stderr}"
            );
        }
        assert_eq!(&marker, *expected);
        output.extend_from_slice(&marker);
        if let Some(start) = start_epoch.take() {
            assert!(
                start.elapsed() >= Duration::from_millis(100),
                "poll returned before its 100ms deadline after marker {}",
                index - 1
            );
        }
        if index + 1 < markers.len() {
            start_epoch = Some(Instant::now());
            child.stdin.as_mut().unwrap().write_all(b"X").unwrap();
            after_start(stdout.as_raw_fd(), index);
        }
    }
    let status = child.wait().unwrap();
    (output, status.code())
}

#[test]
fn host_poll_observer_late_marker_uses_original_start_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("poll-empty-sets");
    compile_assembly("x86_poll_empty_sets.S", &elf);
    let mut native = std::process::Command::new(&elf);
    assert_eq!(
        run_poll_timeout_markers_with(&mut native, &[b"B\n", b"N\n", b"T\n"], |fd, _| {
            assert!(poll_readable(fd, 5_000), "native poll completion missing");
        }),
        (b"B\nN\nT\n".to_vec(), Some(7))
    );
}

fn mounted_poll_command(dir: &std::path::Path, elf: &std::path::Path) -> std::process::Command {
    let archive = dir.join("image.tar");
    std::fs::write(&archive, empty_image_archive()).unwrap();
    let cli = assert_cmd::cargo::cargo_bin("carrick");
    let home = dir.join("home");
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
    let scope = std::env::var("CARRICK_RUN_ID").unwrap_or_else(|_| "local".to_owned());
    let run_id = format!(
        "{scope}-x86-kvm-poll-{}-{}",
        std::process::id(),
        dir.file_name().unwrap().to_string_lossy()
    );
    command
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
        ]);
    command
}

#[test]
fn mounted_poll_commands_use_distinct_carrier_scopes() {
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let first = mounted_poll_command(first_dir.path(), &first_dir.path().join("hello"));
    let second = mounted_poll_command(second_dir.path(), &second_dir.path().join("hello"));
    let run_id = |command: &std::process::Command| {
        command
            .get_envs()
            .find(|(key, _)| *key == std::ffi::OsStr::new("CARRICK_RUN_ID"))
            .and_then(|(_, value)| value)
            .unwrap()
            .to_owned()
    };
    assert_ne!(
        run_id(&first),
        run_id(&second),
        "parallel poll carriers must not claim the same debug endpoint"
    );
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
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(completed, "empty-stdin poll did not complete: {stderr}");
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

/// A guest held in its read wait must remain inspectable before the test
/// releases stdin. This exercises the production carrier, not a model zone.
#[test]
fn mounted_static_x86_blocked_read_has_live_kernel_capture() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("blocked-read");
    compile_assembly("x86_blocking_stdin.S", &elf);
    let archive = dir.path().join("image.tar");
    std::fs::write(&archive, empty_image_archive()).unwrap();
    let cli = assert_cmd::cargo::cargo_bin("carrick");
    let home = dir.path().join("home");
    let load = Command::new(&cli)
        .timeout(Duration::from_secs(5))
        .env("CARRICK_HOME", &home)
        .args(["load", "--input", archive.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        load.status.success(),
        "{}",
        String::from_utf8_lossy(&load.stderr)
    );

    let run_id = format!("x86-kvm-blocked-capture-{}", std::process::id());
    let mut child = ReapChild(
        std::process::Command::new(&cli)
            .env("CARRICK_HOME", &home)
            .env("CARRICK_RUN_ID", &run_id)
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
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stdout = child.stdout.take().unwrap();
    assert!(
        poll_readable(stdout.as_raw_fd(), 5_000),
        "guest ready marker missing"
    );
    let mut marker = [0; 2];
    stdout.read_exact(&mut marker).unwrap();
    assert_eq!(&marker, b"R\n");

    let capture_dir = std::env::var_os("CARRICK_KVM_CAPTURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| dir.path().to_path_buf());
    std::fs::create_dir_all(&capture_dir).unwrap();
    let capture_dir = capture_dir.join(&run_id);
    let capture_path = capture_dir.join("post-mortem.json");
    let capture = Command::new(&cli)
        .timeout(Duration::from_secs(5))
        .args(["debug", "capture", "--run-id", &run_id, "--output-dir"])
        .arg(&capture_dir)
        .output()
        .unwrap();
    assert!(
        capture.status.success(),
        "live KVM capture failed: {}",
        String::from_utf8_lossy(&capture.stderr)
    );
    let snapshot: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&capture_path).unwrap()).unwrap();
    assert!(
        snapshot["degraded_kernel"]["tasks"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "capture did not name a task: {}",
        capture_path.display()
    );

    child.stdin.as_mut().unwrap().write_all(b"X").unwrap();
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"B\n");
    assert_eq!(child.wait().unwrap().code(), Some(7));
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
    poll_readable_with(fd, timeout_ms, |_, _| ())
}

fn poll_readable_with<Guard>(
    fd: i32,
    timeout_ms: i32,
    before_wait: impl FnOnce(&libc::timespec, &libc::sigset_t) -> Guard,
) -> bool {
    assert!(timeout_ms >= 0, "stdout observation must be bounded");
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = libc::timespec {
        tv_sec: (timeout_ms / 1_000).into(),
        tv_nsec: ((timeout_ms % 1_000) * 1_000_000).into(),
    };
    // SAFETY: a null input mask only queries this thread's mask into valid
    // storage, without changing thread or process signal state.
    let mut mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) },
        0
    );
    // assert_cmd's wait-timeout installs a process-wide SIGCHLD handler.
    // Any concurrent child exit can interrupt poll, even with SA_RESTART.
    // This observation waits for stdout, not child signals: defer SIGCHLD
    // atomically for one ppoll, preserving every other caller mask bit and
    // the original timeout. ppoll restores the mask before returning.
    // SAFETY: mask is initialized and SIGCHLD is a valid signal number.
    assert_eq!(unsafe { libc::sigaddset(&mut mask, libc::SIGCHLD) }, 0);
    let _guard = before_wait(&timeout, &mask);
    // SAFETY: initialized stack allocations borrowed only for this call.
    let result = unsafe { libc::ppoll(&mut pollfd, 1, &timeout, &mask) };
    assert!(
        result >= 0,
        "host poll failed: {}",
        std::io::Error::last_os_error()
    );
    result > 0
}

#[test]
fn host_poll_observation_defers_sigchld_without_retry() {
    struct RestoreMask(libc::sigset_t);
    impl Drop for RestoreMask {
        fn drop(&mut self) {
            // SAFETY: the saved mask belongs to this thread.
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) },
                0
            );
        }
    }
    // Hold the setup child alive until handler installation has completed.
    // Keep stdin outside Child: wait_timeout otherwise closes it before
    // initializing the handler, letting cat exit before registration.
    let mut setup_child = ReapChild(
        std::process::Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let _setup_input = setup_child.stdin.take().unwrap();
    // Install the same wait-timeout SIGCHLD handler used by mounted runs,
    // without replacing a process-wide disposition in this witness. The
    // handler is initialized before wait_timeout checks child status, even
    // for a zero duration. Child completion is not an initialization barrier:
    // a timed assert_cmd output can kill its child and fail before ppoll.
    // Keeping cat alive forces initialization-before-exit deterministically;
    // requiring a successful exit here instead is red on this ordering.
    assert_eq!(
        setup_child.wait_timeout(Duration::ZERO).unwrap(),
        None,
        "handler installation must not depend on child completion"
    );
    // SAFETY: query only, with valid output storage. Handler installation
    // belongs to wait-timeout, so no test replaces a shared disposition.
    unsafe {
        let mut action = std::mem::zeroed();
        assert_eq!(
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action),
            0
        );
        assert_ne!(action.sa_sigaction, libc::SIG_DFL);
        assert_ne!(action.sa_sigaction, libc::SIG_IGN);
    }
    // Give the caller an unrelated blocked signal. The observation must
    // preserve it, and must restore an initially unblocked SIGCHLD.
    // SAFETY: valid thread-local masks, no process-wide disposition change.
    let _caller_mask = unsafe {
        let mut original = std::mem::zeroed::<libc::sigset_t>();
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut original),
            0
        );
        let mut caller = original;
        assert_eq!(libc::sigaddset(&mut caller, libc::SIGUSR1), 0);
        assert_eq!(libc::sigdelset(&mut caller, libc::SIGCHLD), 0);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, &caller, std::ptr::null_mut()),
            0
        );
        RestoreMask(original)
    };
    let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
    for (timeout_ms, data_ready) in [(0, false), (50, false), (50, true)] {
        if data_ready {
            writer.write_all(b"X").unwrap();
        }
        let mut calls = 0;
        let ready = poll_readable_with(reader.as_raw_fd(), timeout_ms, |timeout, mask| {
            calls += 1;
            assert_eq!(timeout.tv_sec, 0);
            assert_eq!(timeout.tv_nsec, i64::from(timeout_ms) * 1_000_000);

            // Force a pending SIGCHLD at the native wait boundary. ppoll
            // installs the supplied mask atomically: an unmasked SIGCHLD
            // deterministically returns EINTR, even without scheduling delay.
            // SAFETY: initialized masks and a live calling-thread identity.
            unsafe {
                assert_eq!(libc::sigismember(mask, libc::SIGUSR1), 1);
                let mut blocked = *mask;
                assert_eq!(libc::sigaddset(&mut blocked, libc::SIGCHLD), 0);
                let mut original = std::mem::zeroed();
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_SETMASK, &blocked, &mut original),
                    0
                );
                let restore = RestoreMask(original);
                assert_eq!(libc::pthread_kill(libc::pthread_self(), libc::SIGCHLD), 0);
                let mut pending = std::mem::zeroed();
                assert_eq!(libc::sigpending(&mut pending), 0);
                assert_eq!(libc::sigismember(&pending, libc::SIGCHLD), 1);
                restore
            }
        });
        assert_eq!(ready, data_ready, "a child signal is not stdout readiness");
        assert_eq!(calls, 1, "one native wait, no retry or deadline reset");
        // SAFETY: query only; validate the caller's mask after the wait.
        unsafe {
            let mut after = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut after),
                0
            );
            assert_eq!(libc::sigismember(&after, libc::SIGCHLD), 0);
            assert_eq!(libc::sigismember(&after, libc::SIGUSR1), 1);
        }
    }
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

#[test]
fn mounted_static_x86_signal_handler_and_rt_sigreturn_match_native() {
    compare_mounted_assembly_with_native("x86_signal_handler.S", b"HK\n");
}

#[test]
fn mounted_static_x86_signal_block_pending_and_unblock_match_native() {
    compare_mounted_assembly_with_native("x86_signal_block_pending.S", b"BHU\n");
}

#[test]
fn mounted_static_x86_signal_kill_child_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_kill_child.S", b"W\n");
}

#[test]
fn mounted_static_x86_signal_timedwait_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_timedwait.S", b"PT\n");
}

#[test]
fn mounted_static_x86_signal_segv_fault_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_segv_fault.S", b"SC\n");
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
    compile_assembly_with_flags(fixture, elf, &[]);
}

fn compile_assembly_with_flags(fixture: &str, elf: &std::path::Path, flags: &[&str]) {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture);
    let compile = Command::new("cc")
        .timeout(Duration::from_secs(15))
        .args(flags)
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
    let mut native_command = std::process::Command::new(elf);
    if run_id == "x86_signal_abort.S" {
        // Only the native oracle child changes its limit. A core-class signal
        // must not imply that a core file was actually written.
        unsafe {
            native_command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let native = Command::from_std(native_command)
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
    run_mounted_binary_with_capture(elf, run_id, json).0
}

fn run_mounted_binary_with_capture(
    elf: &std::path::Path,
    run_id: &str,
    json: bool,
) -> (std::process::Output, Option<std::path::PathBuf>) {
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
    let mut command = std::process::Command::new(&cli);
    let scoped_run_id = match std::env::var("CARRICK_RUN_ID") {
        Ok(scope) => format!("{scope}-x86-kvm-{run_id}-test"),
        Err(_) => format!("x86-kvm-{run_id}-test"),
    };
    command
        .env("CARRICK_HOME", &home)
        .env("CARRICK_RUN_ID", &scoped_run_id);
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
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .expect("run mounted x86 Linux binary through carrick");
    if child
        .wait_timeout(Duration::from_secs(5))
        .expect("wait for mounted x86 Linux binary")
        .is_some()
    {
        return (
            child.wait_with_output().expect("collect mounted x86 run"),
            None,
        );
    }

    // The carrier is still live here. Request evidence before killing its
    // scoped process group; a failed capture is a named test failure.
    let capture_dir = std::env::var_os("CARRICK_KVM_CAPTURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("carrick-kvm-deadlines"));
    std::fs::create_dir_all(&capture_dir).expect("create KVM capture directory");
    let capture_dir = tempfile::Builder::new()
        .prefix("kvm-deadline-")
        .tempdir_in(&capture_dir)
        .expect("reserve KVM capture directory")
        .keep();
    let capture_path = capture_dir.join("post-mortem.json");
    let capture = Command::new(&cli)
        .timeout(Duration::from_secs(4))
        .args([
            "debug",
            "capture",
            "--run-id",
            &scoped_run_id,
            "--output-dir",
        ])
        .arg(&capture_dir)
        .output();
    let endpoint = carrick_kernel::kernel::debug::DebugEndpoint::for_run_id(&scoped_run_id)
        .expect("resolve KVM carrier endpoint");
    let stack_result = endpoint
        .live_owner_pid()
        .map_err(|error| error.to_string())
        .and_then(|pid| {
            let pid = i32::try_from(pid).expect("carrier PID fits i32");
            let request = carrick_kernel::wedge_capture::WedgeCaptureRequest {
                label: "kvm-deadline".to_owned(),
                pid,
                run_id: Some(scoped_run_id.clone()),
                budget_ms: 5_000,
                elapsed_ms: 5_000,
                out_root: capture_dir.clone(),
            };
            carrick_kernel::wedge_capture::capture_wedged_carrier(request)
                .map(|capture| capture.dir.display().to_string())
                .map_err(|error| error.to_string())
        });
    match stack_result {
        Ok(dir) => eprintln!("KVM deadline host stacks: {dir}"),
        Err(error) => eprintln!("KVM deadline host stack capture failed: {error}"),
    }
    // SAFETY: this test created an exclusive process group for this exact run.
    unsafe { libc::killpg(child.id() as i32, libc::SIGKILL) };
    let output = child.wait_with_output().expect("reap timed-out KVM run");
    let capture = capture.expect("run KVM deadline capture");
    assert!(
        capture.status.success(),
        "KVM deadline capture {} failed (child status {:?}, child stderr {:?}): {}",
        capture_path.display(),
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&capture.stderr)
    );
    eprintln!("KVM deadline capture: {}", capture_path.display());
    (output, Some(capture_path))
}

// Host stack capture may attach to and stop its carrier. Keep this witness
// outside the parallel KVM test population while preserving the normal
// parallelism of every other KVM test.
mod serial_host {
    use super::*;

    #[test]
    fn mounted_static_x86_deadline_captures_parked_wait() {
        if skip_without_kvm() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let elf = dir.path().join("wait-forever");
        compile_assembly("x86_wait_forever.S", &elf);
        let (output, capture_path) =
            run_mounted_binary_with_capture(&elf, "x86_wait_forever.S", false);
        assert_eq!(output.status.signal(), Some(libc::SIGKILL));
        let capture_path = capture_path.expect("deadline must write a capture");
        let capture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&capture_path).unwrap()).unwrap();
        let wedge_manifest = std::fs::read_dir(capture_path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("manifest.json"))
            .find(|path| path.is_file())
            .expect("deadline must invoke carrier host stack capture");
        let wedge: serde_json::Value =
            serde_json::from_slice(&std::fs::read(wedge_manifest).unwrap()).unwrap();
        assert_eq!(wedge["schema"], "carrick.wedge-capture.v1");
        assert_eq!(wedge["run_id"], capture["run_id"]);
        assert_eq!(capture["schema"], "carrick.kernel-post-mortem.v1");
        assert!(
            capture["event_ring"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty())
        );
        assert!(capture["physical"]["zone_census"].as_str().is_some());
        assert!(
            capture["physical"]["vcpus"]
                .as_array()
                .is_some_and(|rows| rows.len() == 2
                    && rows.iter().all(|row| row
                        .as_str()
                        .is_some_and(|text| text.contains("last_stopped_gprs="))))
        );
        assert!(capture["scheduler_aux"]["scheduler"].as_array().is_some());
        let named_wait = capture["degraded_kernel"]["tasks"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|task| task["threads"].as_array().into_iter().flatten())
            .any(|thread| {
                thread["key"]["tid"].as_u64().is_some()
                    && thread["execution"].as_str().is_some_and(|state| {
                        state.contains("Blocked") && state.contains("HostWait")
                    })
            });
        assert!(
            named_wait,
            "deadline capture did not name the parked task and wait: {}",
            capture_path.display()
        );
    }
}

#[test]
fn mounted_static_x86_signal_return_flags_match_native() {
    compare_mounted_assembly_with_native("x86_signal_return_flags.S", b"HK\n");
}

#[test]
fn mounted_static_x86_signal_return_badframe_matches_native() {
    compare_mounted_fault_with_native("x86_signal_return_badframe.S");
}

#[test]
fn mounted_static_x86_signal_sse_state_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_sse.S", b"HK\n");
}

#[test]
fn mounted_static_x86_signal_nested_without_nodefer_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_nested.S", b"HHK\n");
}
#[test]
fn mounted_static_x86_signal_handler_direction_flag_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_direction_flag.S", b"HK\n");
}

#[test]
fn mounted_static_x86_signal_altstack_overflow_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_altstack.S", b"S\n");
}

#[test]
fn mounted_static_x86_signal_failed_frame_setup_matches_native() {
    compare_mounted_fault_with_native("x86_signal_badstack.S");
}

#[test]
fn mounted_static_x86_signal_resethand_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_resethand.S", b"HK\n");
}

#[test]
#[ignore = "x86 child-MM retirement"]
fn mounted_static_x86_signal_sigsuspend_loop_matches_native() {
    // Three fork rounds also expose the shared child-MM stock retirement debt.
    compare_mounted_assembly_with_native("x86_signal_sigsuspend.S", b"S\n");
}
#[test]
#[ignore = "x86 child-MM retirement"]
fn mounted_static_x86_signal_wait_child_matches_native() {
    // Repeated child creation depends on shared child-MM stock retirement.
    compare_mounted_assembly_with_native("x86_signal_wait_child.S", b"W\n");
}

#[test]
fn mounted_static_x86_signal_wait_copyfault_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_wait_copyfault.S", b"F\n");
}

#[test]
fn mounted_static_x86_signal_sigsuspend_pingpong_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_sigsuspend_pingpong.S", b"S\n");
}
#[test]
fn mounted_static_x86_signal_wait_pingpong_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_wait_pingpong.S", b"W\n");
}

#[test]
#[ignore = "x86 child-MM retirement"]
fn mounted_static_x86_fork_reuses_retired_stock_matches_native() {
    compare_mounted_assembly_with_native("x86_fork_stock_reuse.S", b"R\n");
}

#[test]
fn mounted_static_x86_exiting_last_writer_reaches_host_eof() {
    // `compare_mounted_assembly_with_native` waits for the host stdout pipe's
    // EOF as well as the final writer's exit status.
    compare_mounted_assembly_with_native("x86_last_writer.S", b"E\n");
}

#[test]
fn mounted_static_x86_signal_thread_identity_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_thread_identity.S", b"T\n");
}

#[test]
fn mounted_static_x86_signal_thread_child_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_thread_child.S", b"T\n");
}

#[test]
fn mounted_static_x86_signal_kills_busy_child_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_kill_loop.S", b"K\n");
}

#[test]
#[ignore = "x86 in-ring pipe2/read fd-table continuations"]
fn mounted_static_x86_signal_kills_reading_child_matches_native() {
    // Red until the director-owned x86 in-zone pipe/fd-table lane admits pipe2.
    compare_mounted_assembly_with_native("x86_signal_kill_read.S", b"K\n");
}

#[test]
fn mounted_static_x86_signal_segv_resume_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_segv_resume.S", b"S\n");
}

#[test]
fn mounted_static_x86_signal_interrupts_owned_wait4_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_wait4_interrupt.S", b"I\n");
}

#[test]
fn mounted_static_x86_signal_restarts_owned_wait4_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_wait4_restart.S", b"R\n");
}

#[test]
#[ignore = "shared process-owner stop/continue wait events"]
fn mounted_static_x86_signal_stop_continue_matches_native() {
    // Red until shared process owners publish stop/continue wait events.
    compare_mounted_assembly_with_native("x86_signal_stop_continue.S", b"J\n");
}

#[test]
fn mounted_static_x86_signal_chld_exit_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_chld_exit.S", b"C\n");
}
#[test]
fn mounted_static_x86_signal_chld_killed_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_chld_killed.S", b"D\n");
}

#[test]
fn mounted_static_x86_signal_concurrent_timeouts_match_native() {
    compare_mounted_assembly_with_native("x86_signal_wait_concurrent.S", b"T\n");
}

#[test]
fn mounted_static_x86_signal_blocked_fault_forces_segv() {
    compare_mounted_assembly_with_native("x86_signal_blocked.S", b"F\n");
}
#[test]
fn mounted_static_x86_signal_ignored_fault_forces_segv() {
    compare_mounted_assembly_with_native("x86_signal_ignored.S", b"F\n");
}
#[test]
fn mounted_static_x86_signal_fault_badstack_forces_segv() {
    compare_mounted_assembly_with_native("x86_signal_fault_badstack.S", b"F\n");
}

#[test]
fn mounted_static_x86_signal_segv_child_action_and_resume_match_native() {
    compare_mounted_assembly_with_native("x86_signal_segv_child.S", b"S\nP");
}

#[test]
fn mounted_static_x86_signal_abort_without_core_matches_native() {
    compare_mounted_assembly_with_native("x86_signal_abort.S", b"A\n");
}

#[test]
fn mounted_static_x86_signal_noncanonical_handler_matches_native() {
    compare_mounted_fault_with_native("x86_signal_bad_handler.S");
    compare_mounted_fault_with_native("x86_signal_bad_fault_handler.S");
}

#[test]
#[ignore = "x86 CLONE_THREAD admission"]
fn mounted_static_x86_signal_group_exit_names_its_custody_dependency() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("group-exit");
    let fixture = "x86_signal_group_exit_dependency.S";
    compile_assembly(fixture, &elf);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .unwrap();
    assert_eq!(native.status.signal(), Some(libc::SIGTERM));
    let run = run_mounted_binary(&elf, fixture, false);
    assert_eq!(run.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(stderr.contains("x86 group exit custody"), "{stderr}");
    assert!(!stderr.contains("unexpected initial process port"));
    let run = run_mounted_binary(&elf, fixture, true);
    let json: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    assert!(
        json["report"]["execution_witness"]["physical_crossing_families"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["family"] == "run_failure" && row["count"] == 1)
    );
}
