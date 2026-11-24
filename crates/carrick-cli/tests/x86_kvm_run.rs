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

#[path = "fixtures/x86_process_entry.rs"]
mod x86_process_entry;

fn append_tar(builder: &mut tar::Builder<&mut Vec<u8>>, name: &str, bytes: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, name, bytes).unwrap();
}

fn empty_image_archive() -> Vec<u8> {
    image_archive_with_executable(None)
}

fn image_archive_with_executable(executable: Option<&std::path::Path>) -> Vec<u8> {
    let mut layer = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut layer);
        append_tar(&mut tar, ".keep", b"");
        if let Some(executable) = executable {
            tar.append_path_with_name(executable, "successor").unwrap();
        }
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

fn compile_dynamic_assembly(
    fixture: &str,
    elf: &std::path::Path,
    interp_and_dep: Option<(&str, &std::path::Path)>,
) {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture);
    let mut cmd = Command::new("cc");
    cmd.timeout(Duration::from_secs(15));
    if let Some((interp, dep)) = interp_and_dep {
        cmd.args([
            "-nostdlib",
            "-no-pie",
            &format!("-Wl,--dynamic-linker={interp}"),
            "-Wl,--no-as-needed",
            "-Wl,--build-id=none",
            "-o",
        ])
        .arg(elf)
        .arg(&source)
        .arg(dep);
    } else {
        cmd.args([
            "-nostdlib",
            "-shared",
            "-Wl,-e,_start",
            "-Wl,--build-id=none",
            "-o",
        ])
        .arg(elf)
        .arg(&source);
    }
    let compile = cmd.output().expect("compile dynamic x86 assembly fixture");
    assert!(
        compile.status.success(),
        "compile dynamic x86 assembly fixture {}: cc status: {}; stdout: {}; stderr: {}",
        source.display(),
        compile.status,
        String::from_utf8_lossy(&compile.stdout),
        String::from_utf8_lossy(&compile.stderr)
    );
    if let Some((interp, _)) = interp_and_dep {
        let bytes = std::fs::read(elf).unwrap();
        assert!(
            bytes.windows(interp.len()).any(|w| w == interp.as_bytes()),
            "linked ELF must carry PT_INTERP {interp}"
        );
    }
}

// This exercises image config, PATH lookup, shebang argv rewriting, PT_INTERP
// loading, and Docker 126/127 entrypoint error classification through the
// production CLI boundary, without depending on a registry or libc startup.
#[test]
fn image_path_and_shebang_entrypoints_use_the_shared_resolver() {
    assert!(std::path::Path::new("/dev/kvm").exists(), "requires KVM");
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("hello");
    compile_assembly("x86_entrypoint_argv.S", &elf);
    let ld_test = dir.path().join("ld-test.so");
    compile_dynamic_assembly("x86_entrypoint_argv.S", &ld_test, None);
    let interp_ok = dir.path().join("interp-ok");
    compile_dynamic_assembly(
        "x86_entrypoint_argv.S",
        &interp_ok,
        Some(("/opt/image/lib/ld-link.so", &ld_test)),
    );
    let missing_interp = dir.path().join("missing-interp");
    compile_dynamic_assembly(
        "x86_entrypoint_argv.S",
        &missing_interp,
        Some(("/opt/image/lib/missing-ld-linux.so.2", &ld_test)),
    );
    let bad_interp = dir.path().join("bad-interp");
    compile_dynamic_assembly(
        "x86_entrypoint_argv.S",
        &bad_interp,
        Some(("/opt/image/bin/not-elf", &ld_test)),
    );
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .args([
            "script-option",
            "/opt/image/bin/docker-entrypoint.sh",
            "argument",
        ])
        .output()
        .unwrap();
    assert_eq!(
        native.stdout,
        b"script-option\n/opt/image/bin/docker-entrypoint.sh\nargument\n"
    );
    assert_eq!(native.status.code(), Some(7));
    let bytes = std::fs::read(&elf).unwrap();
    let mut invalid_entry_bytes = bytes.clone();
    invalid_entry_bytes[24..32].copy_from_slice(&0u64.to_le_bytes());
    let ld_test_bytes = std::fs::read(&ld_test).unwrap();
    let interp_ok_bytes = std::fs::read(&interp_ok).unwrap();
    let missing_interp_bytes = std::fs::read(&missing_interp).unwrap();
    let bad_interp_bytes = std::fs::read(&bad_interp).unwrap();
    let mut layer = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut layer);
        for (name, contents) in [
            ("opt/image/bin/python3", bytes.as_slice()),
            ("opt/image/bin/go", bytes.as_slice()),
            (
                "opt/image/bin/invalid-entry",
                invalid_entry_bytes.as_slice(),
            ),
            (
                "opt/image/bin/docker-entrypoint.sh",
                b"#!/opt/image/bin/python3 script-option\n".as_slice(),
            ),
            (
                "opt/image/bin/not-elf",
                b"plain text without shebang\n".as_slice(),
            ),
            ("opt/image/bin/interp-ok", interp_ok_bytes.as_slice()),
            (
                "opt/image/bin/missing-interp",
                missing_interp_bytes.as_slice(),
            ),
            ("opt/image/bin/bad-interp", bad_interp_bytes.as_slice()),
            ("opt/image/lib/ld-test.so", ld_test_bytes.as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tar.append_data(&mut header, name, contents).unwrap();
        }
        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Symlink);
        link_header.set_size(0);
        link_header.set_mode(0o777);
        link_header
            .set_link_name("/opt/image/lib/ld-test.so")
            .unwrap();
        link_header.set_cksum();
        tar.append_data(
            &mut link_header,
            "opt/image/lib/ld-link.so",
            std::io::empty(),
        )
        .unwrap();
        tar.finish().unwrap();
    }
    let config = br#"{"architecture":"amd64","os":"linux","config":{"Env":["PATH=/missing:/opt/image/bin"],"Entrypoint":["docker-entrypoint.sh"],"Cmd":["argument"]}}"#;
    let manifest =
        br#"[{"Config":"config.json","RepoTags":["x86-path:latest"],"Layers":["layer.tar"]}]"#;
    let mut archive = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut archive);
        append_tar(&mut tar, "manifest.json", manifest);
        append_tar(&mut tar, "config.json", config);
        append_tar(&mut tar, "layer.tar", &layer);
        tar.finish().unwrap();
    }
    let archive_path = dir.path().join("image.tar");
    std::fs::write(&archive_path, archive).unwrap();
    let cli = assert_cmd::cargo::cargo_bin("carrick");
    let home = dir.path().join("home");
    let load = Command::new(&cli)
        .timeout(Duration::from_secs(10))
        .env("CARRICK_HOME", &home)
        .args(["load", "--input", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(load.status.success(), "load: {:?}", load);
    for command in [None, Some("python3"), Some("go"), Some("interp-ok")] {
        let mut run = Command::new(&cli);
        run.timeout(Duration::from_secs(10))
            .env("CARRICK_HOME", &home)
            .env("CARRICK_RUN_ID", "issue-1713-image-path")
            .args(["run", "--platform", "linux/amd64", "--pull", "never"]);
        if let Some(command) = command {
            run.args(["--entrypoint", command]);
        }
        let output = run.arg("x86-path:latest").output().unwrap();
        let expected: &[u8] = if command.is_none() {
            b"script-option\n/opt/image/bin/docker-entrypoint.sh\nargument\n"
        } else {
            b"argument\n"
        };
        assert_eq!(output.stdout, expected, "{command:?}: {output:?}");
        assert_eq!(output.status.code(), Some(7), "{command:?}: {output:?}");
    }
    // Names containing `/` (`./python3` from cwd `/` when only
    // `/opt/image/bin/python3` exists) must NOT search PATH and exit 127;
    // missing bare commands and missing PT_INTERP loaders exit 127; existing
    // non-executables (directory, non-ELF, bad PT_INTERP) exit 126 — never 125
    // `RuntimeError::Unsupported`.
    let mut failures = Vec::new();
    for (entrypoint, expected_exit) in [
        ("./python3", 127),
        ("missing-command", 127),
        ("missing-interp", 127),
        ("/opt/image/bin", 126),
        ("not-elf", 126),
        ("bad-interp", 126),
        ("invalid-entry", 126),
    ] {
        let output = Command::new(&cli)
            .timeout(Duration::from_secs(10))
            .env("CARRICK_HOME", &home)
            .env("CARRICK_RUN_ID", "issue-1713-image-path-err")
            .args([
                "run",
                "--platform",
                "linux/amd64",
                "--pull",
                "never",
                "--entrypoint",
                entrypoint,
                "x86-path:latest",
            ])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.code() != Some(expected_exit)
            || stderr.contains("unsupported in this backend")
            || !output.stdout.is_empty()
        {
            failures.push(format!(
                "{entrypoint}: expected exit {expected_exit}, got {:?}; stdout={:?}; stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                stderr.trim()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "entrypoint error classification mismatches:\n{}",
        failures.join("\n")
    );
}

#[test]
fn mounted_static_x86_elf_writes_hello_and_exits_seven_through_shared_kernel() {
    carrick_test_support::require_kvm!();
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
        .current_dir(dir.path())
        .env_remove("CARRICK_EL1_CENSUS")
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

    assert!(
        !dir.path().join("target/carrick-census").exists(),
        "carrick run without CARRICK_EL1_CENSUS must not emit a census"
    );

    // The JSON run exposes a guest-entry receipt. Exact CPL0 lane identity
    // plus two shared-kernel entries and the write's host forward distinguish
    // this from the retired carrick-x86 bringup_fns trap path.
    let observed = Command::new(&cli)
        .timeout(Duration::from_secs(5))
        .env("CARRICK_HOME", &home)
        .env("CARRICK_RUN_ID", "x86-kvm-hello-receipt-test")
        .env("CARRICK_EL1_CENSUS", dir.path().join("census"))
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
    assert_eq!(
        observed.status.code(),
        Some(7),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&observed.stdout),
        String::from_utf8_lossy(&observed.stderr),
    );
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
    let census_files: Vec<_> = std::fs::read_dir(dir.path().join("census"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(census_files.len(), 1);
    assert_eq!(census_files[0].extension().unwrap(), "json");
    let census: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&census_files[0]).unwrap()).unwrap();
    assert_eq!(census["refusal_evidence"]["complete"], true);
    assert_eq!(census["refusal_evidence"]["isa"], "x86_64");
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

/// Two live processes each take the first write to a page that was prepared
/// but untouched when the parent forked: the child on the idle peer, the
/// parent on its loaded lane. Before #2226 the fork-armed leaf refused its
/// write publication and the idle peer's fault doorbell killed the carrier.
#[test]
fn mounted_static_x86_fork_first_write_to_prepared_page_stays_private() {
    compare_mounted_assembly_with_native("x86_fork_prepared_cow_write.S", b"C\nP\n");
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

/// With #2142 serving the x86 run root's execve, mounted static self-exec
/// replaces the image and matches the native Linux oracle (`"E\n"`, exit 7).
/// Function name retained until `.github/retired-tests.toml` retires the old name.
#[test]
fn mounted_static_x86_native_executable_link_follows_fork_and_exec() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("exe-link");
    let successor = dir.path().join("successor");
    let fixture = "x86_native_executable_link.S";
    compile_assembly(fixture, &elf);
    compile_assembly_with_flags(fixture, &successor, &["-DSUCCESSOR"]);
    let archive = image_archive_with_executable(Some(&successor));
    let (guest, _) = run_mounted_binary_in_archive(&elf, "native-exe-link", true, &archive);
    assert_eq!(
        guest.status.code(),
        Some(7),
        concat!(
            "executable link: exit 218 is child ENOSYS, 219 is root ENOSYS, ",
            "220 is successor ENOSYS, 93 is exec failure, 94 is length/content, ",
            "95 is truncation. Stderr: {}"
        ),
        String::from_utf8_lossy(&guest.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&guest.stdout).unwrap();
    assert_eq!(
        report["report"]["execution_witness"]["backend"],
        "kvm-x86-cpl0"
    );
    assert_eq!(
        report["report"]["execution_witness"]["host_forwards"], 6,
        "only the root's three pairs of readlinks cross host dispatch"
    );
}

/// #2731: the first syscall an exec'd image makes arrives with host work
/// owed. A call declined for that work must run once the work has settled; it
/// was answered ENOSYS, which kills a static glibc image before `main`.
/// Sixteen fork children each exec the fixture to make one call first, then
/// the root execs itself: no row may be refused only because it was first.
#[test]
fn mounted_static_x86_first_call_after_exec_is_not_refused_for_owed_work() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("first-call");
    compile_assembly_with_flags(
        "x86_first_call_after_exec.c",
        &elf,
        &[
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-O1",
        ],
    );
    let rows = |stdout: &[u8], label: &str| -> Vec<(String, String)> {
        std::str::from_utf8(stdout)
            .unwrap_or_else(|e| panic!("{label} utf8: {e}"))
            .lines()
            .map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                assert_eq!(parts.len(), 4, "{label} malformed row: {line:?}");
                (parts[0].to_owned(), parts[3].to_owned())
            })
            .collect()
    };
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run native first-call oracle");
    assert_eq!(native.status.code(), Some(7), "native oracle");
    let native_rows = rows(&native.stdout, "native");
    assert!(
        native_rows.len() > 2 && native_rows.iter().all(|(_, verdict)| verdict == "same"),
        "native Linux refuses no first call: {native_rows:?}"
    );

    let guest = run_mounted_binary(&elf, "first-call-after-exec", false);
    let stdout = String::from_utf8_lossy(&guest.stdout);
    assert_eq!(
        guest.status.code(),
        Some(7),
        "93 is exec failure, 95 a child that did not exit 0. Stdout: {stdout} Stderr: {}",
        String::from_utf8_lossy(&guest.stderr)
    );
    assert_eq!(
        rows(&guest.stdout, "guest"),
        native_rows,
        "a first call was refused for owed work:\n{stdout}"
    );
}

/// `getcwd`, `uname`, `getrlimit`, `prlimit64`, `getrusage` and `sysinfo`
/// into a mapped page the guest never touched succeed on Linux: the copy
/// fills the page in. So do `clock_gettime`, `rt_sigprocmask`, `pipe2` and
/// `epoll_wait`. The root and a forked child (with a copy-on-write page
/// too) must report the native rows, never EFAULT and never a hang.
#[test]
fn mounted_static_x86_sysinfo_output_to_an_untouched_page_matches_native() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("sysinfo-output");
    compile_assembly_with_flags(
        "x86_sysinfo_unsupplied_output.c",
        &elf,
        &[
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-O1",
        ],
    );
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run native sysinfo-output oracle");
    let native_rows = String::from_utf8_lossy(&native.stdout).into_owned();
    assert_eq!(
        native.status.code(),
        Some(7),
        "native oracle: {native_rows}"
    );
    assert!(
        native_rows.lines().count() == 32 && !native_rows.contains("MISSING"),
        "native Linux fills every buffer: {native_rows}"
    );

    let guest = run_mounted_binary(&elf, "sysinfo-unsupplied-output", false);
    let guest_rows = String::from_utf8_lossy(&guest.stdout);
    assert_eq!(
        guest_rows,
        native_rows,
        "exit {:?} (95/96: a child did not exit 0). Stderr: {}",
        guest.status.code(),
        String::from_utf8_lossy(&guest.stderr)
    );
    assert_eq!(guest.status.code(), Some(7));
}

/// #2832: an exec'd fork child's thread asks the host for a file. The exec
/// gave the process leader a new execution generation; a thread born after
/// it carries its own. The host compared the two and ended the run
/// (`GenerationMismatch { stopped: 1, registered: 2 }`).
#[test]
fn mounted_static_x86_exec_child_member_reads_a_host_file() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("exec-child-member");
    compile_assembly_with_flags(
        "x86_exec_child_member_host_file.c",
        &elf,
        &[
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-O1",
        ],
    );
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run native exec-child-member oracle");
    assert_eq!(native.status.code(), Some(7), "native oracle");
    assert_eq!(native.stdout, b"ok=4\n", "native oracle");

    let guest = run_mounted_binary(&elf, "exec-child-member-host-file", false);
    assert_eq!(
        (guest.status.code(), guest.stdout.as_slice()),
        (native.status.code(), native.stdout.as_slice()),
        "93 is exec failure, 95 a child that did not exit 0. Stdout: {} Stderr: {}",
        String::from_utf8_lossy(&guest.stdout),
        String::from_utf8_lossy(&guest.stderr)
    );
}

/// #2851: seven threads of an exec'd fork child map, protect, advise and
/// unmap memory at once. A call that waited for another's edit reruns its
/// saved `SYSCALL`; a preemption before that instruction parked the rewound
/// context again, and the next resume rewound it once more. The thread then
/// ran the two bytes before `SYSCALL` and took a user page fault at the
/// syscall number (`kernel fault policy refused: reason 0x9`). Other
/// defects of the same workload end most runs first (#2832's records: a
/// refused mapping edit, an unregistered crossing CR3, a stopped forward
/// mismatch); run it with `--ignored` until they land.
#[test]
#[ignore = "#2832 records B, D, E and G end the run before #2851's rerun is checked"]
fn mounted_static_x86_exec_child_threads_rerun_contended_mapping_edits() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("exec-child-edits");
    compile_assembly_with_flags(
        "x86_exec_child_threads_edit_mappings.c",
        &elf,
        &[
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-O1",
        ],
    );
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run native exec-child-edits oracle");
    assert_eq!(native.status.code(), Some(7), "native oracle");
    assert_eq!(native.stdout, b"ok=4\n", "native oracle");

    let guest = run_mounted_binary(&elf, "exec-child-threads-edit-mappings", false);
    assert_eq!(
        (guest.status.code(), guest.stdout.as_slice()),
        (native.status.code(), native.stdout.as_slice()),
        "93 is exec failure, 95 a child that did not exit 0. Stdout: {} Stderr: {}",
        String::from_utf8_lossy(&guest.stdout),
        String::from_utf8_lossy(&guest.stderr)
    );
}

/// #2832 record B: the run root and its thread sleep. The sleep family
/// declined for the run root, leaving the call to a host continuation the
/// x86 crossing set does not carry, so every root `nanosleep` and
/// `clock_nanosleep` answered ENOSYS (-38) at once (`sleep 1` as a
/// container's entry point printed `cannot read realtime clock`).
#[test]
fn mounted_static_x86_root_and_its_thread_sleep_in_ring() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("root-threads-sleep");
    compile_assembly_with_flags(
        "x86_root_threads_sleep.c",
        &elf,
        &[
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-O1",
        ],
    );
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run native root-threads-sleep oracle");
    assert_eq!(native.status.code(), Some(7), "native oracle");
    assert_eq!(native.stdout, b"sleep=ok\n", "native oracle");

    let guest = run_mounted_binary(&elf, "root-threads-sleep", false);
    assert_eq!(
        (guest.status.code(), guest.stdout.as_slice()),
        (native.status.code(), native.stdout.as_slice()),
        "95 is a bad sleep (code 1..3 main, 11..13 thread, +100 early). Stdout: {} Stderr: {}",
        String::from_utf8_lossy(&guest.stdout),
        String::from_utf8_lossy(&guest.stderr)
    );
}

/// #2890: the Go runtime's `fork/exec` once it runs more than one P. A
/// thread forks with `clone(CLONE_VM | CLONE_VFORK)` on its own stack and
/// execs this image sixteen times (`x86_threads_vfork_exec.c`). `go build`
/// and `go vet` die with `fork/exec ...: bad address` or a carrier error
/// (`guest MMU publication live descriptor mismatch`, an unexpected physical
/// production port `0xcc`) on main, and on #2855's parent with
/// `GOMAXPROCS=2`. `flags` pick the shape: `-DWORKERS=0` drops the four
/// memory-editing siblings, `-DFROM_MAIN` forks from the root's own thread.
fn threads_vfork_exec_matches_native(flags: &[&str], run_id: &str) {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join(run_id);
    let mut all = vec![
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-O1",
    ];
    all.extend_from_slice(flags);
    compile_assembly_with_flags("x86_threads_vfork_exec.c", &elf, &all);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run native threads-vfork-exec oracle");
    assert_eq!(native.status.code(), Some(7), "native oracle");
    assert_eq!(native.stdout, b"ok=16\n", "native oracle");

    let guest = run_mounted_binary(&elf, run_id, false);
    assert_eq!(
        (guest.status.code(), guest.stdout.as_slice()),
        (native.status.code(), native.stdout.as_slice()),
        "94 is a failed vfork clone (its errno is the printed status), 95 a failed \
         round (the exec errno is the status's exit code), 98 threads past five \
         seconds, 99 a memory edit that did not answer as Linux does. \
         Stdout: {} Stderr: {}",
        String::from_utf8_lossy(&guest.stdout),
        String::from_utf8_lossy(&guest.stderr)
    );
}

/// The control: the root's only thread vforks and execs.
#[test]
fn mounted_static_x86_root_vfork_exec_matches_native() {
    threads_vfork_exec_matches_native(&["-DWORKERS=0", "-DFROM_MAIN"], "root-vfork-exec");
}

/// A second thread vforks while the root's thread sleeps. On main the
/// clone answers -EFAULT (status `0x000e`) in round 0 or 1: Go's
/// `fork/exec ...: bad address`.
#[test]
fn mounted_static_x86_thread_vfork_exec_matches_native() {
    threads_vfork_exec_matches_native(&["-DWORKERS=0"], "thread-vfork-exec");
}

/// A fifth thread vforks while four siblings map, touch and unmap memory.
/// On main a sibling's memory edit answers wrongly (99), or the carrier
/// dies (an unregistered forward CR3).
#[test]
#[ignore = "red until the #2890 siblings shape lands; see #2890"]
fn mounted_static_x86_thread_vfork_exec_beside_memory_editing_siblings() {
    threads_vfork_exec_matches_native(&[], "threads-vfork-exec-siblings");
}

/// #2792: a user page fault that ends in a fatal signal leaves its entry
/// frame for the scheduler. Its CPU must stop holding that fault: the next
/// task there takes its own page faults. Sixteen fork children die of
/// SIGSEGV beside three siblings that fault in fresh pages; the carrier
/// died on a CPL0 `ud2` (kernel fault vector 6) at the next sibling fault.
#[test]
fn mounted_static_x86_fault_death_leaves_the_cpu_to_faulting_siblings() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("fault-death");
    compile_assembly_with_flags(
        "x86_fault_death_beside_faulting_siblings.c",
        &elf,
        &[
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-O1",
        ],
    );
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run native fault-death oracle");
    assert_eq!(native.status.code(), Some(7), "native oracle");
    assert_eq!(native.stdout, b"segv=16 clean=3\n", "native oracle");

    let guest = run_mounted_binary(&elf, "fault-death-beside-siblings", false);
    assert_eq!(
        (guest.status.code(), guest.stdout.as_slice()),
        (native.status.code(), native.stdout.as_slice()),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&guest.stdout),
        String::from_utf8_lossy(&guest.stderr)
    );
}

/// #2813: a copy-on-write whose residency row finds no slot is not dropped.
/// Parent and child both write all 2048 pages of an anonymous mapping they
/// share after a fork. Each resolved write replaces the page's residency row; with the
/// table's probe chains full the replacement row was silently not
/// published, and the carrier refused the completion (`owner COW
/// replacement residency absent`), ending the run.
#[test]
fn mounted_static_x86_fork_cow_keeps_residency_when_the_table_is_full() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("fork-cow-residency");
    compile_assembly_with_flags(
        "x86_fork_cow_residency_capacity.c",
        &elf,
        &[
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-O1",
        ],
    );
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run native fork-COW residency oracle");
    assert_eq!(native.status.code(), Some(7), "native oracle");
    assert_eq!(native.stdout, b"rounds=1 ok\n", "native oracle");

    let guest = run_mounted_binary(&elf, "fork-cow-residency-capacity", false);
    assert_eq!(
        (guest.status.code(), guest.stdout.as_slice()),
        (native.status.code(), native.stdout.as_slice()),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&guest.stdout),
        String::from_utf8_lossy(&guest.stderr)
    );
}

/// #2813: a munmap that splits a residency row keeps the parts it leaves.
/// After a fork the parent unmaps every other page of an 8192-page
/// anonymous mapping, so each hole splits a row and the row count passes
/// what the table's probe chains hold. A part that found no slot was
/// silently dropped, and the parent's next write to such a page ended the
/// run (`owner COW source residency`).
#[test]
fn mounted_static_x86_munmap_split_keeps_residency_when_the_table_is_full() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("munmap-split-residency");
    compile_assembly_with_flags(
        "x86_munmap_split_residency_capacity.c",
        &elf,
        &[
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-O1",
        ],
    );
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run native munmap-split residency oracle");
    assert_eq!(native.status.code(), Some(7), "native oracle");
    assert_eq!(native.stdout, b"split ok\n", "native oracle");

    // 4096 one-page munmaps and 12288 copy-on-writes: about ten seconds on
    // a release carrier, so this fixture has its own deadline.
    let (guest, _) = run_mounted_binary_within(
        &elf,
        "munmap-split-residency-capacity",
        false,
        &empty_image_archive(),
        None,
        Duration::from_secs(90),
    );
    assert_eq!(
        (guest.status.code(), guest.stdout.as_slice()),
        (native.status.code(), native.stdout.as_slice()),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&guest.stdout),
        String::from_utf8_lossy(&guest.stderr)
    );
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
        guest.stdout, b"E\n",
        "x86 root self-exec must replace the image and match native stdout"
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

/// #1092: `sched_getaffinity` and `sched_setaffinity` by the x86 root, a
/// second live thread and a fork child print what the native run prints.
#[test]
fn mounted_static_x86_affinity_matches_native() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("affinity");
    let source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/x86_affinity.c");
    x86_process_entry::compile_static_fixture(&source, &elf, &[]);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .expect("run native x86 affinity oracle");
    assert_eq!(
        native.status.code(),
        Some(0),
        "native oracle stderr: {}",
        String::from_utf8_lossy(&native.stderr)
    );
    let guest = run_mounted_binary(&elf, "affinity", false);
    assert_eq!(
        String::from_utf8_lossy(&guest.stdout),
        String::from_utf8_lossy(&native.stdout),
        "guest stdout vs the native oracle; status: {:?}; stderr: {}",
        guest.status,
        String::from_utf8_lossy(&guest.stderr)
    );
    assert_eq!(guest.status.code(), Some(0));
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
fn mounted_static_x86_remapped_writev_matches_native() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("descriptor-writev");
    compile_assembly("x86_descriptor_writev.S", &elf);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .unwrap();
    assert!(native.stdout.is_empty());
    assert_eq!(native.stderr, b"V\n");
    assert_eq!(native.status.code(), Some(7));
    let run = run_mounted_binary(&elf, "descriptor-writev", false);
    assert_eq!(
        run.stdout, native.stdout,
        "status: {:?}; stderr: {:?}",
        run.status, run.stderr
    );
    assert_eq!(run.stderr, native.stderr);
    assert_eq!(run.status.code(), native.status.code());
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

const POLL_TIMEOUT_FLOOR: Duration = Duration::from_millis(100);

#[must_use]
struct PollStartEpoch<Stamp> {
    after_marker: usize,
    stamp: Stamp,
}

trait PollEpochClock {
    type Stamp;

    fn start_epoch(&mut self, after_marker: usize) -> PollStartEpoch<Self::Stamp>;
    fn elapsed_since(&mut self, epoch: PollStartEpoch<Self::Stamp>) -> Duration;
}

struct MonotonicPollClock;

impl PollEpochClock for MonotonicPollClock {
    type Stamp = Instant;

    fn start_epoch(&mut self, after_marker: usize) -> PollStartEpoch<Instant> {
        PollStartEpoch {
            after_marker,
            stamp: Instant::now(),
        }
    }

    fn elapsed_since(&mut self, epoch: PollStartEpoch<Instant>) -> Duration {
        epoch.stamp.elapsed()
    }
}

#[derive(Debug)]
enum PollObserverError {
    MissingMarker {
        index: usize,
    },
    ReadFailed {
        index: usize,
        error: std::io::Error,
        output: Vec<u8>,
    },
    UnexpectedMarker {
        index: usize,
        expected: [u8; 2],
        actual: [u8; 2],
    },
    ReleaseWriteFailed {
        after_marker: usize,
        error: std::io::Error,
    },
    PrematureCompletion {
        after_marker: usize,
        elapsed: Duration,
        minimum: Duration,
    },
}

impl std::fmt::Display for PollObserverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingMarker { index } => write!(f, "poll marker {index} missing"),
            Self::ReadFailed {
                index,
                error,
                output,
            } => write!(
                f,
                "poll marker {index} read failed: {error}; output={output:?}"
            ),
            Self::UnexpectedMarker {
                index,
                expected,
                actual,
            } => write!(
                f,
                "poll marker {index} mismatch: expected {expected:?}, got {actual:?}"
            ),
            Self::ReleaseWriteFailed {
                after_marker,
                error,
            } => write!(
                f,
                "poll release write after marker {after_marker} failed: {error}"
            ),
            Self::PrematureCompletion {
                after_marker,
                elapsed,
                minimum,
            } => write!(
                f,
                "poll returned after {elapsed:?}, before its {minimum:?} deadline after marker {after_marker}"
            ),
        }
    }
}

fn run_poll_timeout_markers(
    mut command: std::process::Command,
    markers: &[&[u8; 2]],
) -> (Vec<u8>, Option<i32>) {
    let mut child = ReapChild(
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn empty-set poll witness"),
    );
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut clock = MonotonicPollClock;
    let observed = observe_poll_timeout_markers(
        &mut stdin,
        &mut stdout,
        markers,
        5_000,
        &mut clock,
        |_, _, _| (),
    );
    drop(stdin);
    if let Err(ref error) = observed {
        let status = match child.wait_timeout(Duration::from_secs(1)).unwrap() {
            Some(status) => status,
            None => {
                let _ = child.kill();
                child.wait().unwrap()
            }
        };
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(
            observed.is_ok(),
            "{error}; status={status}; stderr={stderr}"
        );
    }
    let output = observed.unwrap();
    let status = child.wait().unwrap();
    (output, status.code())
}

fn observe_poll_timeout_markers<R, W, C>(
    stdin: &mut W,
    stdout: &mut R,
    markers: &[&[u8; 2]],
    wait_timeout_ms: i32,
    clock: &mut C,
    mut after_release: impl FnMut(&mut C, i32, usize),
) -> Result<Vec<u8>, PollObserverError>
where
    R: Read + AsRawFd,
    W: Write,
    C: PollEpochClock,
{
    assert!(
        !markers.is_empty(),
        "poll marker sequence must not be empty"
    );
    let mut output = Vec::with_capacity(markers.len() * 2);
    let mut start_epoch: Option<PollStartEpoch<C::Stamp>> = None;
    for (index, expected) in markers.iter().enumerate() {
        if !poll_readable(stdout.as_raw_fd(), wait_timeout_ms) {
            return Err(PollObserverError::MissingMarker { index });
        }
        let mut marker = [0u8; 2];
        if let Err(error) = stdout.read_exact(&mut marker) {
            return Err(PollObserverError::ReadFailed {
                index,
                error,
                output,
            });
        }
        if &marker != *expected {
            return Err(PollObserverError::UnexpectedMarker {
                index,
                expected: **expected,
                actual: marker,
            });
        }
        output.extend_from_slice(&marker);
        if let Some(epoch) = start_epoch.take() {
            let after_marker = epoch.after_marker;
            let elapsed = clock.elapsed_since(epoch);
            if elapsed < POLL_TIMEOUT_FLOOR {
                return Err(PollObserverError::PrematureCompletion {
                    after_marker,
                    elapsed,
                    minimum: POLL_TIMEOUT_FLOOR,
                });
            }
        }
        if index + 1 < markers.len() {
            assert!(
                start_epoch.is_none(),
                "previous poll start epoch must be consumed before minting the next"
            );
            start_epoch = Some(clock.start_epoch(index));
            stdin
                .write_all(b"X")
                .and_then(|()| stdin.flush())
                .map_err(|error| PollObserverError::ReleaseWriteFailed {
                    after_marker: index,
                    error,
                })?;
            after_release(clock, stdout.as_raw_fd(), index);
        }
    }
    assert!(
        start_epoch.is_none(),
        "final poll marker must consume the last start epoch"
    );
    Ok(output)
}

#[test]
fn host_poll_observer_late_marker_uses_original_start_epoch() {
    struct ScriptedPollClock {
        now: Duration,
        minted: Vec<(usize, Duration)>,
        consumed: Vec<(usize, Duration, Duration)>,
    }

    impl ScriptedPollClock {
        fn new() -> Self {
            Self {
                now: Duration::ZERO,
                minted: Vec::new(),
                consumed: Vec::new(),
            }
        }

        fn advance(&mut self, delta: Duration) {
            self.now += delta;
        }
    }

    impl PollEpochClock for ScriptedPollClock {
        type Stamp = Duration;

        fn start_epoch(&mut self, after_marker: usize) -> PollStartEpoch<Duration> {
            let stamp = self.now;
            self.minted.push((after_marker, stamp));
            PollStartEpoch {
                after_marker,
                stamp,
            }
        }

        fn elapsed_since(&mut self, epoch: PollStartEpoch<Duration>) -> Duration {
            let elapsed = self
                .now
                .checked_sub(epoch.stamp)
                .expect("scripted poll clock is monotonic");
            self.consumed
                .push((epoch.after_marker, epoch.stamp, self.now));
            elapsed
        }
    }

    // Late observer / already-buffered marker: each completion marker arrives
    // at +100ms, then the observer reaches poll_readable strictly later (+150ms
    // and +5ms) with zero clock progress between poll_readable and read_exact.
    // Measuring from poll_readable entry instead of the owned start epoch would
    // observe 0ms (< 100ms) and fail.
    let (mut peer_stdin, mut observer_stdin) = std::os::unix::net::UnixStream::pair().unwrap();
    let (mut observer_stdout, mut peer_stdout) = std::os::unix::net::UnixStream::pair().unwrap();
    peer_stdout.write_all(b"B\n").unwrap();
    let mut clock = ScriptedPollClock::new();
    let observed = observe_poll_timeout_markers(
        &mut observer_stdin,
        &mut observer_stdout,
        &[b"B\n", b"N\n", b"T\n"],
        0,
        &mut clock,
        |clock, stdout_fd, index| {
            assert!(
                !poll_readable(stdout_fd, 0),
                "completion marker must not precede release {index}"
            );
            assert_eq!(
                clock.minted.len(),
                index + 1,
                "start epoch must be minted before writing release byte"
            );
            assert!(
                poll_readable(peer_stdin.as_raw_fd(), 0),
                "release byte {index} must be readable by peer"
            );
            let mut release = [0u8; 1];
            peer_stdin.read_exact(&mut release).unwrap();
            assert_eq!(&release, b"X");
            assert!(
                !poll_readable(peer_stdin.as_raw_fd(), 0),
                "each epoch must emit exactly one release byte"
            );
            let (marker, observer_delay_ms): (&[u8; 2], u64) = match index {
                0 => (b"N\n", 150),
                1 => (b"T\n", 5),
                _ => (&[0, 0], 0),
            };
            assert_ne!(marker, &[0, 0], "unexpected release index {index}");
            clock.advance(POLL_TIMEOUT_FLOOR);
            peer_stdout.write_all(marker).unwrap();
            clock.advance(Duration::from_millis(observer_delay_ms));
            assert!(
                poll_readable(stdout_fd, 0),
                "completion marker after {index} must be buffered before observer polls"
            );
        },
    )
    .expect("late markers must measure elapsed time from their owned start epochs");
    assert_eq!(observed, b"B\nN\nT\n");
    assert_eq!(
        clock.minted,
        vec![(0, Duration::ZERO), (1, Duration::from_millis(250))]
    );
    assert_eq!(
        clock.consumed,
        vec![
            (0, Duration::ZERO, Duration::from_millis(250)),
            (1, Duration::from_millis(250), Duration::from_millis(355)),
        ]
    );

    // Owned epoch consumption: after a valid 250ms first wait, a 99ms second
    // wait must fail against the newly minted second epoch (250ms -> 349ms),
    // even though 349ms has elapsed since the first epoch.
    let (mut peer_stdin, mut observer_stdin) = std::os::unix::net::UnixStream::pair().unwrap();
    let (mut observer_stdout, mut peer_stdout) = std::os::unix::net::UnixStream::pair().unwrap();
    peer_stdout.write_all(b"B\n").unwrap();
    let mut clock = ScriptedPollClock::new();
    let premature = observe_poll_timeout_markers(
        &mut observer_stdin,
        &mut observer_stdout,
        &[b"B\n", b"N\n", b"T\n"],
        0,
        &mut clock,
        |clock, stdout_fd, index| {
            let mut release = [0u8; 1];
            peer_stdin.read_exact(&mut release).unwrap();
            assert_eq!(&release, b"X");
            if index == 0 {
                clock.advance(Duration::from_millis(250));
                peer_stdout.write_all(b"N\n").unwrap();
            } else {
                clock.advance(Duration::from_millis(99));
                peer_stdout.write_all(b"T\n").unwrap();
            }
            assert!(poll_readable(stdout_fd, 0));
        },
    );
    assert!(
        matches!(
            premature,
            Err(PollObserverError::PrematureCompletion {
                after_marker: 1,
                elapsed,
                minimum,
            }) if elapsed == Duration::from_millis(99) && minimum == POLL_TIMEOUT_FLOOR
        ),
        "expected premature completion on second epoch, got {premature:?}"
    );

    // Bounded wait without marker arrival returns MissingMarker without retry.
    let (mut peer_stdin, mut observer_stdin) = std::os::unix::net::UnixStream::pair().unwrap();
    let (mut observer_stdout, mut peer_stdout) = std::os::unix::net::UnixStream::pair().unwrap();
    peer_stdout.write_all(b"B\n").unwrap();
    let mut clock = ScriptedPollClock::new();
    let missing = observe_poll_timeout_markers(
        &mut observer_stdin,
        &mut observer_stdout,
        &[b"B\n", b"N\n"],
        0,
        &mut clock,
        |_, _, _| {
            let mut release = [0u8; 1];
            peer_stdin.read_exact(&mut release).unwrap();
            assert_eq!(&release, b"X");
        },
    );
    assert!(
        matches!(missing, Err(PollObserverError::MissingMarker { index: 1 })),
        "expected missing marker 1, got {missing:?}"
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
fn mounted_static_x86_glibc_hello_matches_native() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("glibc-hello");
    let source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/x86_glibc_hello.c");
    x86_process_entry::compile_static_fixture(&source, &elf, &[]);
    compare_mounted_binary_with_native(&elf, b"hello, x86_64 world\n", 0, "glibc-hello");
}

/// Root Prepare must borrow more than twelve linked tables from shared stock
/// through the real container entry point.
#[test]
fn mounted_static_x86_root_maps_sixteen_table_regions() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("root-tables");
    let source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/x86_root_tables.c");
    x86_process_entry::compile_static_fixture(&source, &elf, &[]);
    compare_mounted_binary_with_native(&elf, b"ROOT_TABLES_OK\n", 0, "root-tables");
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
    !carrick_test_support::kvm_host::usable_or_skip()
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
        "compile native x86 assembly oracle {}: cc status: {}; stdout: {}; stderr: {}",
        source.display(),
        compile.status,
        String::from_utf8_lossy(&compile.stdout),
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
    run_mounted_binary_in_archive(elf, run_id, json, &empty_image_archive())
}

fn run_mounted_binary_in_archive(
    elf: &std::path::Path,
    run_id: &str,
    json: bool,
    image_archive: &[u8],
) -> (std::process::Output, Option<std::path::PathBuf>) {
    run_mounted_binary_in_archive_with_census(elf, run_id, json, image_archive, None)
}

fn run_mounted_binary_in_archive_with_census(
    elf: &std::path::Path,
    run_id: &str,
    json: bool,
    image_archive: &[u8],
    census_dir: Option<&std::path::Path>,
) -> (std::process::Output, Option<std::path::PathBuf>) {
    run_mounted_binary_within(
        elf,
        run_id,
        json,
        image_archive,
        census_dir,
        Duration::from_secs(5),
    )
}

fn mounted_carrier_scope(label: &str, dir: &std::path::Path) -> String {
    // Parallel fixtures can reuse a label. Each launch owns its temp directory
    // until the carrier exits, including while timeout diagnostics look it up.
    let instance = dir.file_name().expect("mounted run directory name");
    let run_id = format!(
        "x86-kvm-{label}-{}-{}",
        std::process::id(),
        instance.to_string_lossy()
    );
    match std::env::var("CARRICK_RUN_ID") {
        Ok(scope) => format!("{scope}-{run_id}"),
        Err(_) => run_id,
    }
}

#[test]
fn mounted_carriers_with_the_same_label_publish_distinct_debug_endpoints() {
    use carrick_kernel::kernel::debug::DebugEndpoint;
    use std::os::unix::net::UnixListener;

    let base = tempfile::Builder::new()
        .prefix("ck")
        .tempdir_in("/tmp")
        .unwrap();
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let endpoint = |dir: &tempfile::TempDir| {
        let scope = mounted_carrier_scope("root-network", dir.path());
        DebugEndpoint::in_base(base.path().to_owned(), &scope).expect("resolve endpoint")
    };

    let first = endpoint(&first_dir);
    first.claim(1).expect("claim first endpoint");
    let _first_listener = UnixListener::bind(first.socket_path()).expect("bind first listener");
    first.write_owner(1).expect("publish first owner");

    let second = endpoint(&second_dir);
    second
        .claim(2)
        .expect("claim second endpoint with first still live");
    let _second_listener = UnixListener::bind(second.socket_path()).expect("bind second listener");
    second.write_owner(2).expect("publish second owner");

    for endpoint in [first, second] {
        assert_eq!(endpoint.live_owner_pid().unwrap(), std::process::id());
    }
}

/// One mounted run with its own deadline, for a fixture whose work is large
/// by design. Every other fixture keeps the five-second deadline.
fn run_mounted_binary_within(
    elf: &std::path::Path,
    run_id: &str,
    json: bool,
    image_archive: &[u8],
    census_dir: Option<&std::path::Path>,
    deadline: Duration,
) -> (std::process::Output, Option<std::path::PathBuf>) {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("image.tar");
    std::fs::write(&archive, image_archive).unwrap();
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
    let scoped_run_id = mounted_carrier_scope(run_id, dir.path());
    command
        .env("CARRICK_HOME", &home)
        .env("CARRICK_RUN_ID", &scoped_run_id);
    if let Some(census_dir) = census_dir {
        command.env("CARRICK_EL1_CENSUS", census_dir);
    }
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
        .wait_timeout(deadline)
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
    // #2646: the same live endpoint serves the zone dump; keep it beside the
    // capture for the deadline witness.
    let zonedump = Command::new(&cli)
        .timeout(Duration::from_secs(4))
        .args(["debug", "zonedump", "--run-id", &scoped_run_id])
        .output()
        .expect("run live KVM zonedump");
    std::fs::write(capture_dir.join("zonedump.txt"), &zonedump.stdout).expect("keep live zonedump");
    assert!(
        zonedump.status.success(),
        "live zonedump failed: {}",
        String::from_utf8_lossy(&zonedump.stderr)
    );
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
        let zone_census = capture["physical"]["zone_census"].as_str().unwrap();
        // #2646: the census names the slot maps and each vCPU's current task.
        assert!(
            zone_census.contains("zone maps: idle_slots=["),
            "{zone_census}"
        );
        assert!(
            zone_census.contains("el1 task slot ") && zone_census.contains(" service_notice="),
            "{zone_census}"
        );
        let live = std::fs::read_to_string(capture_path.with_file_name("zonedump.txt")).unwrap();
        assert!(live.starts_with("run: "), "{live}");
        assert!(live.contains("zone maps: idle_slots=["), "{live}");
        assert!(live.contains("el1 task slot "), "{live}");
        let cli = assert_cmd::cargo::cargo_bin("carrick");
        let replay = Command::new(&cli)
            .timeout(Duration::from_secs(5))
            .args(["debug", "zonedump", "--post-mortem"])
            .arg(&capture_path)
            .output()
            .expect("zonedump a written post-mortem");
        assert!(replay.status.success());
        let replay = String::from_utf8(replay.stdout).unwrap();
        assert!(replay.contains(zone_census), "{replay}");
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
fn mounted_static_x86_forked_child_stdout_matches_native_while_parent_waits() {
    compare_mounted_assembly_with_native("x86_forked_child_stdout.S", b"E");
}

/// A forked child execs the mounted ELF and reads its host-backed header
/// while the root remains alive in wait4.
#[test]
fn mounted_x86_fork_exec_child_reads_host_file() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("fork-exec-read");
    compile_assembly("x86_fork_exec_host_read.S", &elf);
    let guest = run_mounted_binary(&elf, "fork-exec-host-read", false);
    assert_eq!(
        guest.stdout,
        b"F",
        "{}",
        String::from_utf8_lossy(&guest.stderr)
    );
    assert_eq!(
        guest.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&guest.stderr)
    );
}

/// An issue number: a typed owner, checked OPEN by
/// `scripts/check-x86-child-gap-owners.sh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct IssueNumber(u32);

/// One allowlisted crossing that an exec'd native child still refuses with a
/// counted ENOSYS on x86_64.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChildCrossingGap {
    /// The canonical (AArch64) syscall number, validated against
    /// `carrick_abi::syscall`.
    canonical: u64,
    name: String,
    owner: IssueNumber,
    kind: ChildCrossingGapKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildCrossingGapKind {
    /// A counted ENOSYS refusal in the census for the exec'd child.
    Refusal,
    /// Served, but the guest result differs from the native oracle.
    Divergence,
}

/// Count ceiling for the gap table, in the manner of `AuthorityDebtCeilings`:
/// the table may only fall. Raising it needs a new entry in
/// `CHILD_CROSSING_GAP_ADMISSIONS` (count, linked issue, reason); the last
/// entry is the live ceiling. Lowering is automatic: the witness fails while
/// the table is shorter than the ceiling, so the same change that serves a
/// crossing removes its row and lowers the ceiling.
const CHILD_CROSSING_GAP_CEILING: usize = 30;
const CHILD_CROSSING_GAP_ADMISSIONS: &[(usize, IssueNumber, &str)] = &[(
    CHILD_CROSSING_GAP_CEILING,
    IssueNumber(2581),
    "initial typed ratchet of the exec'd-child crossing gaps",
)];

fn parse_child_crossing_gaps(text: &str) -> Result<Vec<ChildCrossingGap>, String> {
    let mut gaps = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let at = |what: &str| format!("gap table line {}: {what}: {line:?}", index + 1);
        let cols: Vec<&str> = line.split('\t').collect();
        let [canonical, name, owner, kind] = cols[..] else {
            return Err(at(
                "want 4 tab-separated columns (canonical, name, owner, kind)",
            ));
        };
        let kind = match kind {
            "refusal" => ChildCrossingGapKind::Refusal,
            "divergence" => ChildCrossingGapKind::Divergence,
            _ => return Err(at("kind must be refusal or divergence")),
        };
        let canonical: u64 = canonical
            .parse()
            .map_err(|_| at("canonical is not a number"))?;
        let owner: u32 = owner
            .strip_prefix('#')
            .unwrap_or(owner)
            .parse()
            .map_err(|_| at("owner is not an issue number"))?;
        match carrick_abi::syscall::lookup_aarch64(canonical) {
            Some(syscall) if syscall.name == name => {}
            other => {
                return Err(at(&format!(
                    "canonical number does not name this syscall in carrick-abi: {other:?}"
                )));
            }
        }
        gaps.push(ChildCrossingGap {
            canonical,
            name: name.to_owned(),
            owner: IssueNumber(owner),
            kind,
        });
    }
    Ok(gaps)
}

/// The allowlisted crossings named by the flip table, by canonical number.
fn parse_flip_allowlist(tsv: &str) -> Result<std::collections::BTreeMap<u64, &str>, String> {
    let mut lines = tsv.lines();
    let header: Vec<&str> = lines
        .next()
        .ok_or("flip table is empty")?
        .split('\t')
        .collect();
    let column = |name: &str| {
        header
            .iter()
            .position(|col| *col == name)
            .ok_or_else(|| format!("flip table has no {name:?} column: {header:?}"))
    };
    let (nr_col, name_col, routing_col) = (column("nr")?, column("name")?, column("flip_routing")?);
    let mut allowlist = std::collections::BTreeMap::new();
    for (index, line) in lines.enumerate() {
        let cols: Vec<&str> = line.split('\t').collect();
        let field = |col: usize| {
            cols.get(col)
                .copied()
                .ok_or_else(|| format!("flip table row {} is short: {line:?}", index + 2))
        };
        if matches!(
            field(routing_col)?,
            "Forward-Allowlist" | "Temporary-forward"
        ) {
            let nr = field(nr_col)?
                .parse()
                .map_err(|_| format!("flip table row {}: bad nr: {line:?}", index + 2))?;
            allowlist.insert(nr, field(name_col)?);
        }
    }
    Ok(allowlist)
}

/// How a served crossing's guest result is compared with the native Linux
/// oracle. Everything is `Exact` (same success value, or same errno) unless
/// the value depends on the host or the run, which is named here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OracleComparison {
    Exact,
    /// Same success or same errno; the success value differs by design.
    SuccessOrSameErrno(&'static str),
}

fn oracle_comparison(name: &str) -> OracleComparison {
    match name {
        "getcwd" => OracleComparison::SuccessOrSameErrno("length of a run-specific cwd path"),
        "readlinkat" => OracleComparison::SuccessOrSameErrno("length of the run-specific exe path"),
        "times" => {
            OracleComparison::SuccessOrSameErrno("clock ticks since an arbitrary past point")
        }
        "getdents64" => {
            OracleComparison::SuccessOrSameErrno("record sizes depend on the directory")
        }
        _ => OracleComparison::Exact,
    }
}

fn oracle_agrees(comparison: OracleComparison, native: i64, guest: i64) -> bool {
    match comparison {
        OracleComparison::Exact => native == guest,
        OracleComparison::SuccessOrSameErrno(_) => {
            if native < 0 || guest < 0 {
                native == guest
            } else {
                true
            }
        }
    }
}

#[test]
fn child_crossing_gap_table_is_typed_and_ratcheted() {
    let gaps = parse_child_crossing_gaps(include_str!("fixtures/x86_child_crossing_gaps.tsv"))
        .unwrap_or_else(|error| panic!("{error}"));
    let (ceiling, _, _) = *CHILD_CROSSING_GAP_ADMISSIONS.last().expect("admissions");
    assert_eq!(ceiling, CHILD_CROSSING_GAP_CEILING);
    assert!(
        CHILD_CROSSING_GAP_ADMISSIONS
            .iter()
            .all(|(_, _, reason)| !reason.is_empty()),
        "every ceiling admission states its reason"
    );
    assert!(
        gaps.len() <= CHILD_CROSSING_GAP_CEILING,
        "the gap table grew past its ceiling ({} > {}); a new gap needs a recorded admission in CHILD_CROSSING_GAP_ADMISSIONS",
        gaps.len(),
        CHILD_CROSSING_GAP_CEILING
    );
    assert_eq!(
        gaps.len(),
        CHILD_CROSSING_GAP_CEILING,
        "the gap table fell below its ceiling: lower CHILD_CROSSING_GAP_CEILING and record the admission"
    );
    let mut seen = std::collections::BTreeSet::new();
    assert!(
        gaps.iter().all(|gap| seen.insert(gap.canonical)),
        "duplicate gap rows"
    );
    assert!(
        parse_child_crossing_gaps("14\tremovexattr").is_err()
            && parse_child_crossing_gaps("14\tmkdirat\t1\trefusal").is_err()
            && parse_child_crossing_gaps("14\tremovexattr\t1\tother").is_err(),
        "a malformed or mislabelled row must fail the parse, not panic"
    );
    assert!(parse_flip_allowlist("nr\tname\tflip_routing\n1\tx\tForward-Allowlist\n").is_ok());
    assert!(
        parse_flip_allowlist("nr\tname\n").is_err(),
        "missing column"
    );
    assert!(
        parse_flip_allowlist("nr\tname\tflip_routing\n1\tx\n").is_err(),
        "short row"
    );
}

#[test]
fn mounted_x86_exec_child_allowlisted_crossings_class_witness() {
    if skip_without_kvm() {
        return;
    }
    let mut expected_allowlist =
        parse_flip_allowlist(include_str!("../../../docs/design/arm-ring-first-flip.tsv"))
            .unwrap_or_else(|error| panic!("{error}"));
    expected_allowlist.insert(93, "exit");
    expected_allowlist.insert(94, "exit_group");

    let parse_rows = |stdout: &[u8], label: &str| -> Vec<(u64, u64, String, i64)> {
        let text = std::str::from_utf8(stdout).unwrap_or_else(|e| panic!("{label} utf8: {e}"));
        let rows: Vec<_> = text
            .lines()
            .map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                assert_eq!(parts.len(), 4, "{label} malformed row: {line:?}");
                (
                    parts[0].parse::<u64>().unwrap(),
                    parts[1].parse::<u64>().unwrap(),
                    parts[2].to_owned(),
                    parts[3].parse::<i64>().unwrap(),
                )
            })
            .collect();
        let observed: std::collections::BTreeMap<u64, &str> = rows
            .iter()
            .map(|(canon, _, name, _)| (*canon, name.as_str()))
            .collect();
        assert_eq!(
            observed, expected_allowlist,
            "{label} must exercise every allowlisted crossing in crossing.rs / arm-ring-first-flip.tsv"
        );
        rows
    };

    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("child-crossing-class");
    compile_assembly_with_flags(
        "x86_child_crossing_class.c",
        &elf,
        &[
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-O2",
        ],
    );

    let work = dir.path().join("native-work");
    std::fs::create_dir(&work).unwrap();
    let native = Command::new(&elf)
        .current_dir(&work)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run native x86 Linux crossing class oracle");
    assert_eq!(
        native.status.code(),
        Some(7),
        "native oracle stderr: {}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(
        std::fs::read_dir(&work).unwrap().count(),
        0,
        "fixture must clean up its scratch directory"
    );
    let native_rows = parse_rows(&native.stdout, "native");
    let native_enosys: Vec<_> = native_rows
        .iter()
        .filter(|(_, _, _, ret)| *ret == -(libc::ENOSYS as i64))
        .collect();
    assert!(
        native_enosys.is_empty(),
        "native Linux returned ENOSYS for allowlisted crossings: {native_enosys:?}"
    );

    let census_dir = dir.path().join("census");
    let (guest, _) = run_mounted_binary_in_archive_with_census(
        &elf,
        "exec-child-crossing-class",
        false,
        &empty_image_archive(),
        Some(&census_dir),
    );
    assert_eq!(
        guest.status.code(),
        Some(7),
        "guest exit {:?}; stderr: {}; stdout: {}",
        guest.status.code(),
        String::from_utf8_lossy(&guest.stderr),
        String::from_utf8_lossy(&guest.stdout),
    );
    assert!(
        guest.stderr.is_empty(),
        "guest stderr: {}",
        String::from_utf8_lossy(&guest.stderr)
    );
    let guest_rows = parse_rows(&guest.stdout, "guest");

    // Routing, from the census refusal counters (#2650): which x86 ordinals
    // the exec'd child's crossings refused, whichever venue counted them.
    #[derive(serde::Deserialize)]
    struct Envelope {
        refusal_evidence: carrick_spec::syscall_census::RefusalEvidence,
    }
    let census_files: Vec<_> = std::fs::read_dir(&census_dir)
        .expect("census directory")
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(census_files.len(), 1, "{census_files:?}");
    let census: Envelope =
        serde_json::from_slice(&std::fs::read(&census_files[0]).unwrap()).expect("census json");
    let evidence = census.refusal_evidence;
    assert!(evidence.complete, "{evidence:?}");
    assert_eq!(
        evidence.isa,
        carrick_spec::syscall_census::CensusIsa::X86_64
    );
    let refused_by = |caller| -> std::collections::BTreeMap<u64, u64> {
        evidence
            .rows
            .iter()
            .filter(|row| row.caller == caller)
            .map(|row| (row.nr, row.refused + row.venue_refused))
            .filter(|&(_, total)| total != 0)
            .collect()
    };
    use carrick_spec::syscall_census::CallerClass;
    assert_eq!(
        refused_by(CallerClass::Root),
        Default::default(),
        "the root only forks, execs and waits: nothing of it may refuse"
    );
    let child_refused = refused_by(CallerClass::NativeChild);

    let gaps = parse_child_crossing_gaps(include_str!("fixtures/x86_child_crossing_gaps.tsv"))
        .unwrap_or_else(|error| panic!("{error}"));
    let mut failures = Vec::new();
    let mut expected_refusals = std::collections::BTreeMap::new();
    for ((canon, x86_nr, name, guest_ret), (_, _, _, native_ret)) in
        guest_rows.iter().zip(&native_rows)
    {
        let gap = gaps.iter().find(|gap| gap.canonical == *canon);
        let refused = child_refused.get(x86_nr).copied().unwrap_or(0);
        let comparison = oracle_comparison(name);
        match gap.map(|gap| (gap, gap.kind)) {
            Some((gap, ChildCrossingGapKind::Refusal)) => {
                expected_refusals.insert(*x86_nr, 1);
                if refused == 0 {
                    failures.push(format!(
                        "{name} (canonical={canon}, x86={x86_nr}, ret={guest_ret}) is now served; retire its row (owner #{}) and lower the ceiling",
                        gap.owner.0
                    ));
                } else if *guest_ret != -(libc::ENOSYS as i64) {
                    failures.push(format!(
                        "{name} (x86={x86_nr}) is a counted refusal but returned {guest_ret}, not -ENOSYS"
                    ));
                }
            }
            Some((gap, ChildCrossingGapKind::Divergence)) => {
                if refused != 0 {
                    failures.push(format!(
                        "{name} (x86={x86_nr}) is a divergence row but refused"
                    ));
                }
                if oracle_agrees(OracleComparison::Exact, *native_ret, *guest_ret) {
                    failures.push(format!(
                        "{name} (canonical={canon}) now matches the oracle ({guest_ret}); retire its row (owner #{}) and lower the ceiling",
                        gap.owner.0
                    ));
                } else if !oracle_agrees(
                    OracleComparison::SuccessOrSameErrno("known divergence"),
                    *native_ret,
                    *guest_ret,
                ) {
                    failures.push(format!(
                        "{name} (canonical={canon}): guest {guest_ret} vs native {native_ret} differ beyond the known divergence (owner #{})",
                        gap.owner.0
                    ));
                }
            }
            None => {
                if refused != 0 {
                    failures.push(format!(
                        "{name} (canonical={canon}, x86={x86_nr}) refused {refused}x in the census but is not a known gap"
                    ));
                }
                if !oracle_agrees(comparison, *native_ret, *guest_ret) {
                    failures.push(format!(
                        "{name} (canonical={canon}, x86={x86_nr}): guest returned {guest_ret}, native oracle {native_ret} ({comparison:?})"
                    ));
                }
            }
        }
    }
    assert_eq!(
        child_refused, expected_refusals,
        "census native_child refusals (x86 ordinal -> count) must be exactly the known gaps, once each"
    );
    assert!(
        failures.is_empty(),
        "exec'd native child crossings disagree with the oracle or the gap table ({}):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// The run root's host network family on x86 (#1906): a TCP connection to a
/// loopback listener and a UDP exchange (socket, bind, listen, connect,
/// accept and accept4, socket options and names, sendto/recvfrom,
/// sendmsg/recvmsg, sendmmsg/recvmmsg, shutdown), and readiness on a host
/// socket through poll, pselect6 and epoll. The root's sockets are
/// host-backed descriptions of its own ring table, served by the typed
/// socket venue its children use, so a fork child selects on, reads and
/// writes the sockets it inherits. Every line must match the native oracle,
/// and the census must show no refusal of the family by any caller (before
/// the venue admitted the root, `socket` and `pselect6` were counted ENOSYS
/// and the rest failed EBADF).
#[test]
fn mounted_static_x86_root_network_family_matches_native() {
    compare_socket_fixture_with_native("x86_root_network.c");
}

/// The netlink route socket glibc's resolver opens (#1906), made by the
/// run root and by a fork child, matches the native run, and no caller's
/// socket call is refused. Before the venue decoded its `socket`, it was a
/// counted ENOSYS for every caller. AF_UNIX is not here: a local socket is
/// a compat-zone object and has no in-zone owner yet (#2847).
#[test]
fn mounted_static_x86_netlink_sockets_match_native() {
    compare_socket_fixture_with_native("x86_local_sockets.c");
}

/// Blocking waits between the run root and a fork child, with no select
/// (#1051's gap 2): the child's socket write reaches the root's timed
/// receive; the root's blocking read of its accepted socket wakes on the
/// child's later write; and the root's pipe write wakes the child parked
/// in its poll. A root `O_NONBLOCK` set after the fork on a socket both
/// hold reaches the child, and the child's receive leaves it set for the
/// root, as on Linux, where the flag is the shared description's. Socket
/// receive and send timeouts that must wait answer EAGAIN when they pass,
/// and a write within a receive timeout wakes the receive (#2878). A signal
/// interrupting a timed receive or send answers EINTR even under
/// `SA_RESTART`, never a restart (#2920). Each wait is bounded by a
/// receive timeout, a poll timeout or the other process's later write, so
/// a lost wake prints a wrong line against the oracle instead of hanging.
#[test]
fn mounted_static_x86_child_socket_wake_matches_native() {
    compare_socket_fixture_with_native("x86_child_socket_wake.c");
}

/// Run a static socket fixture natively and as the mounted x86 root: the
/// two outputs match, and the census holds no refusal of the socket family
/// by any caller.
fn compare_socket_fixture_with_native(fixture: &str) {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("root-network");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture);
    x86_process_entry::compile_static_fixture(&source, &elf, &[]);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(5))
        .output()
        .expect("run native x86 network oracle");
    assert_eq!(
        native.status.code(),
        Some(0),
        "native oracle stderr: {}",
        String::from_utf8_lossy(&native.stderr)
    );

    let census_dir = dir.path().join("census");
    let (guest, _) = run_mounted_binary_in_archive_with_census(
        &elf,
        "root-network",
        false,
        &empty_image_archive(),
        Some(&census_dir),
    );
    let census_files: Vec<_> = std::fs::read_dir(&census_dir)
        .expect("census directory")
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(census_files.len(), 1, "{census_files:?}");
    #[derive(serde::Deserialize)]
    struct Envelope {
        refusal_evidence: carrick_spec::syscall_census::RefusalEvidence,
    }
    let census: Envelope =
        serde_json::from_slice(&std::fs::read(&census_files[0]).unwrap()).expect("census json");
    let evidence = census.refusal_evidence;
    assert!(evidence.complete, "{evidence:?}");
    // x86_64 socket..getsockopt, pselect6, accept4, recvmmsg, sendmmsg.
    let family: Vec<u64> = (41..=55).chain([270, 288, 299, 307]).collect();
    let root_refused: std::collections::BTreeMap<(String, u64), u64> = evidence
        .rows
        .iter()
        .filter(|row| family.contains(&row.nr))
        .map(|row| {
            (
                (format!("{:?}", row.caller), row.nr),
                row.refused + row.venue_refused,
            )
        })
        .filter(|&(_, total)| total != 0)
        .collect();
    assert_eq!(
        String::from_utf8_lossy(&guest.stdout),
        String::from_utf8_lossy(&native.stdout),
        "guest stdout vs the native oracle; refusals ((caller, x86 ordinal) -> count): {root_refused:?}; stderr: {}",
        String::from_utf8_lossy(&guest.stderr)
    );
    assert_eq!(
        root_refused,
        Default::default(),
        "no caller's network call may be refused"
    );
    assert_eq!(guest.status.code(), Some(0));
    assert!(
        guest.stderr.is_empty(),
        "guest stderr: {}",
        String::from_utf8_lossy(&guest.stderr)
    );
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

/// Run an x86 B1 host-crossing fixture (#2157): `under_carrick` false runs it
/// on the host with a fresh scratch directory as its cwd; otherwise carrick
/// runs it in the root file system's writable layer (a bind mount has no
/// `user.*` attributes, mknod or truncate under carrick), which is fresh per
/// run. Every fixture removes what it creates.
fn run_crossing_fixture(
    fixture: &str,
    flags: &[&str],
    under_carrick: bool,
) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("crossing-guest");
    compile_assembly_with_flags(fixture, &elf, flags);
    if under_carrick {
        // Tests run in parallel: each variant needs its own scoped run id.
        let run_id = format!("{fixture}{}", flags.concat());
        run_mounted_binary(&elf, &run_id, false)
    } else {
        let work = dir.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let output = Command::new(&elf)
            .current_dir(&work)
            .timeout(Duration::from_secs(5))
            .output()
            .expect("run native x86 Linux oracle");
        assert_eq!(
            std::fs::read_dir(&work).unwrap().count(),
            0,
            "{fixture} must remove what it creates"
        );
        output
    }
}

/// The run root performs a B1 crossing family's calls; carrick returns what
/// native Linux returns, step for step.
fn compare_root_crossings_with_native(fixture: &str) {
    if skip_without_kvm() {
        return;
    }
    let native = run_crossing_fixture(fixture, &[], false);
    assert_eq!(native.stdout, b"F\n", "native oracle {fixture}: {native:?}");
    assert_eq!(native.status.code(), Some(7));
    let run = run_crossing_fixture(fixture, &[], true);
    assert_eq!(
        run.stdout,
        native.stdout,
        "{fixture}: carrick exit {:?} (the exit code is the first step that differed from native); stderr: {}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.status.code(), native.status.code(), "{fixture}");
    assert!(run.stderr.is_empty(), "{fixture}: {:?}", run.stderr);
}

/// A forked child performs a B1 crossing family's calls. The root's fork
/// seeds the child's cwd (#2155), so the calls the child mutation venue serves
/// (mkdirat, truncate, newfstatat) run against it and the parent proves their
/// host effect; a path call with no child route is the ring's counted ENOSYS
/// (as on ARM) and a closed descriptor is EBADF. The fixture's own exit code
/// carries the first step that differed.
fn forked_child_crossings_refuse_in_ring(fixture: &str) {
    if skip_without_kvm() {
        return;
    }
    let run = run_crossing_fixture(fixture, &["-DCHILD"], true);
    assert_eq!(
        run.stdout,
        b"F\n",
        "{fixture} child: exit {:?} (the first step whose result differed); stderr: {}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.status.code(), Some(7), "{fixture} child");
    assert!(run.stderr.is_empty(), "{fixture} child: {:?}", run.stderr);
}

#[test]
fn mounted_static_x86_files_crossings_match_native() {
    compare_root_crossings_with_native("x86_b1_files.S");
}

/// A directory the root's staged `openat` holds is the ring's description:
/// its number names nothing in the root's host task. A relative pathname
/// resolves through that description on both Linux and Carrick (#2216).
/// The test keeps its historical identity for the gate's receipts.
#[test]
fn mounted_static_x86_ring_held_dirfd_relative_paths_are_a_counted_enosys() {
    if skip_without_kvm() {
        return;
    }
    let fixture = "x86_b1_files.S";
    let flags = ["-DRING_DIRFD"];
    let native = run_crossing_fixture(fixture, &flags, false);
    assert_eq!(native.stdout, b"F\n", "native ring dirfd: {native:?}");
    assert_eq!(native.status.code(), Some(7));
    let run = run_crossing_fixture(fixture, &flags, true);
    assert_eq!(
        run.stdout,
        b"F\n",
        "ring-held dirfd: exit {:?} (the first step whose result differed); stderr: {}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.status.code(), native.status.code());
    assert!(run.stderr.is_empty(), "{:?}", run.stderr);
}

#[test]
fn mounted_static_x86_files_crossings_in_a_fork_child_refuse_in_ring() {
    forked_child_crossings_refuse_in_ring("x86_b1_files.S");
}

#[test]
fn mounted_static_x86_metadata_crossings_match_native() {
    compare_root_crossings_with_native("x86_b1_metadata.S");
}

#[test]
fn mounted_static_x86_metadata_crossings_in_a_fork_child_refuse_in_ring() {
    forked_child_crossings_refuse_in_ring("x86_b1_metadata.S");
}

#[test]
fn mounted_static_x86_xattr_crossings_match_native() {
    compare_root_crossings_with_native("x86_b1_xattr.S");
}

#[test]
fn mounted_static_x86_xattr_crossings_in_a_fork_child_refuse_in_ring() {
    if skip_without_kvm() {
        return;
    }
    let fixture = "x86_b1_xattr.S";
    let native = run_crossing_fixture(fixture, &["-DCHILD", "-DNATIVE_ORACLE"], false);
    assert_eq!(native.stdout, b"F\n", "native child xattr: {native:?}");
    assert_eq!(native.status.code(), Some(7));

    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("xattr-child");
    compile_assembly_with_flags(fixture, &elf, &["-DCHILD"]);
    let archive = dir.path().join("image.tar");
    std::fs::write(&archive, empty_image_archive()).unwrap();
    let cli = assert_cmd::cargo::cargo_bin("carrick");
    let home = dir.path().join("home");
    let census_dir = dir.path().join("census");
    let load = Command::new(&cli)
        .timeout(Duration::from_secs(5))
        .env("CARRICK_HOME", &home)
        .args(["load", "--input", archive.to_str().unwrap()])
        .output()
        .expect("load local xattr image");
    assert!(
        load.status.success(),
        "load stderr: {}",
        String::from_utf8_lossy(&load.stderr)
    );
    let scoped_run_id = match std::env::var("CARRICK_RUN_ID") {
        Ok(scope) => format!("{scope}-x86-kvm-xattr-child-test"),
        Err(_) => "x86-kvm-xattr-child-test".to_owned(),
    };
    let run = Command::new(&cli)
        .timeout(Duration::from_secs(5))
        .env("CARRICK_HOME", &home)
        .env("CARRICK_RUN_ID", &scoped_run_id)
        .env("CARRICK_EL1_CENSUS", &census_dir)
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
        .expect("run child xattr crossing witness");
    assert_eq!(
        run.stdout,
        b"F\n",
        "{fixture} child: exit {:?}; stderr: {}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.status.code(), Some(7), "{fixture} child");
    assert!(run.stderr.is_empty(), "{fixture} child: {:?}", run.stderr);
    let census_files: Vec<_> = std::fs::read_dir(&census_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(census_files.len(), 1);
    let census: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&census_files[0]).unwrap()).unwrap();
    assert_eq!(census["refusal_evidence"]["complete"], true);
    assert_eq!(
        census["refusal_evidence"]["rows"],
        serde_json::json!([{
            "nr": 197,
            "caller": "native_child",
            "refused": 2,
            "venue_refused": 0,
            "allowlisted": true,
        }]),
        "only the two unrouted removexattr calls refuse in ring: {census}"
    );
    // #2646: the operator view ranks the child's refusal first, by name,
    // without anyone reading the counters by hand.
    let ranked = Command::new(&cli)
        .timeout(Duration::from_secs(5))
        .args(["debug", "el1-census", "--refusals"])
        .arg(&census_dir)
        .output()
        .expect("rank census refusals");
    let table = String::from_utf8_lossy(&ranked.stdout);
    assert!(
        ranked.status.success(),
        "--refusals failed: {}",
        String::from_utf8_lossy(&ranked.stderr)
    );
    let top = table
        .lines()
        .find(|line| line.starts_with("| 1 |"))
        .unwrap_or_else(|| panic!("no ranked refusal row: {table}"));
    assert_eq!(
        top, "| 1 | removexattr | x86_64 | 197 | 14 | native_child | 2 | 0 | 2 | yes |",
        "{table}"
    );
    let json = Command::new(&cli)
        .timeout(Duration::from_secs(5))
        .args(["debug", "el1-census", "--refusals", "--json"])
        .arg(&census_dir)
        .output()
        .expect("rank census refusals as JSON");
    assert!(json.status.success());
    let ranking: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(ranking["complete"], true);
    assert_eq!(ranking["rows"][0]["name"], "removexattr");
    assert_eq!(ranking["rows"][0]["caller"], "native_child");
    assert_eq!(ranking["rows"][0]["unrouted"], 2);
}

/// #2107: the mounted CLI root must share the host file authority, even
/// though the production pool's synthetic root already owns ring stdio.
#[test]
fn mounted_root_fcntl_redirect_restore_preserves_host_description_owner() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("root-fcntl");
    compile_assembly(
        "../../../carrick-vmm-kvm/tests/fixtures/native_root_fcntl.S",
        &elf,
    );
    let guest = run_mounted_binary(&elf, "root-fcntl", false);
    assert_eq!(
        guest.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&guest.stderr)
    );
    assert!(guest.stdout.is_empty(), "redirect must reach pipe");
}

/// #2848: empty-set select/pselect6 (and nfds=0 poll/ppoll) sleep for the
/// requested timeout or wake on a signal with -EINTR instead of returning
/// -ENOSYS (-38) for root and fork child.
#[test]
fn mounted_static_x86_empty_select_sleep() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("empty-select-sleep");
    compile_assembly_with_flags(
        "x86_empty_select_sleep.c",
        &elf,
        &[
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-O1",
        ],
    );
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run native empty-select-sleep oracle");
    let native_stdout = String::from_utf8_lossy(&native.stdout);
    assert_eq!(
        native.status.code(),
        Some(7),
        "native oracle failed: stdout={native_stdout} stderr={}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert!(
        !native_stdout.is_empty() && native_stdout.lines().all(|line| line.ends_with(" ok=1")),
        "native oracle must pass every row:\n{native_stdout}"
    );

    let guest = run_mounted_binary(&elf, "empty-select-sleep", false);
    let guest_stdout = String::from_utf8_lossy(&guest.stdout);
    assert_eq!(
        guest.status.code(),
        native.status.code(),
        "guest exit {:?} stderr={}\nstdout:\n{guest_stdout}",
        guest.status.code(),
        String::from_utf8_lossy(&guest.stderr)
    );
    assert_eq!(
        guest_stdout, native_stdout,
        "guest empty-set select/poll differed from native oracle"
    );
}

/// #2909: the run root's `select` and `pselect6` over host descriptors (a
/// host regular file, stdin and stdout, a host UDP socket) and over sets
/// that mix a ring pipe with a host descriptor, both already ready and
/// woken later by a fork child, match the native run line for line. The
/// ring poll owner admits the x86 root only for sets it can serve; a host
/// member must never answer EBADF or ENOSYS.
#[test]
fn mounted_static_x86_root_select_host_descriptors_match_native() {
    if skip_without_kvm() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("root-select-host");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/x86_root_select_host.c");
    x86_process_entry::compile_static_fixture(&source, &elf, &[]);
    let native = Command::new(&elf)
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run native root-select-host oracle");
    let native_stdout = String::from_utf8_lossy(&native.stdout);
    assert_eq!(
        native.status.code(),
        Some(0),
        "native oracle failed: stdout={native_stdout} stderr={}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert!(
        native_stdout.ends_with("done\n"),
        "native oracle must finish:\n{native_stdout}"
    );

    let guest = run_mounted_binary(&elf, "root-select-host", false);
    let guest_stdout = String::from_utf8_lossy(&guest.stdout);
    assert_eq!(
        guest.status.code(),
        native.status.code(),
        "guest exit {:?} stderr={}\nstdout:\n{guest_stdout}",
        guest.status.code(),
        String::from_utf8_lossy(&guest.stderr)
    );
    assert_eq!(
        guest_stdout, native_stdout,
        "the root's select over host descriptors differed from the native oracle"
    );
}
