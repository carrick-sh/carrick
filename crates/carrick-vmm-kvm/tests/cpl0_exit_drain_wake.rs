//! Live KVM witnesses for #2031: wakes from a native x86 process's exit
//! drain reach tasks parked in the carrier-scoped CPL0 zone.
//!
//! The child's exit retires its descriptor table in ring; the host drains
//! the retired table and releases the pipe end the child still held. That
//! release must wake the parent parked on the pipe lane in the carrier's
//! zone (EOF for a reader, EPIPE plus SIGPIPE for a writer), including when
//! the parent sits idle on the other CPU of the carrier.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used, clippy::panic)]

#[path = "common/kvm_pool_fixture.rs"]
#[allow(dead_code)] // each test file uses a subset of the shared fixture
mod kvm_pool_fixture;

/// Only CPU 0 (the loaded lane) schedules the root and its children.
const ROOT_AFFINITY_LOADED: u64 = 1;
/// Only the idle peer (CPU 1) schedules the root and its children, so the
/// parked parent is woken on a CPU that is idle when the drain runs.
const ROOT_AFFINITY_IDLE_PEER: u64 = 2;

fn exit_drain_wake(flags: &[&str], affinity: u64) {
    let elf = kvm_pool_fixture::assemble_fixture("native_pipe_exit_wake.S", flags);
    let dir = tempfile::tempdir().expect("oracle directory");
    let oracle = dir.path().join("oracle");
    std::fs::write(&oracle, &elf).expect("native oracle ELF");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&oracle, std::fs::Permissions::from_mode(0o700))
        .expect("executable oracle");
    let native = std::process::Command::new("timeout")
        .arg("10")
        .arg(&oracle)
        .status()
        .expect("bounded native oracle");
    assert_eq!(native.code(), Some(7), "native oracle: {native:?}");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
        let _ = tx.send(kvm_pool_fixture::try_run_program_with_root_affinity(
            &program,
            256,
            affinity,
            |_| {},
        ));
    });
    let outcome = rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("a task parked on the pipe must be woken by the peer's exit, not hang")
        .expect("exit-drain wake run");
    assert_eq!(
        outcome.run.exit_code, 7,
        "stdout {:?} stderr {:?}",
        outcome.run.stdout, outcome.run.stderr
    );
}

const FAILED_MSI_CHILD: &str = "CARRICK_TEST_FAILED_MSI_CHILD";

/// A reschedule MSI the carrier cannot deliver must surface as a carrier
/// error, not strand the parked parent behind a sleeping CPU. The child
/// process arms the test-support seam and runs the idle-peer wake; the
/// table owner must fail the carrier closed promptly.
#[test]
fn failed_resched_msi_is_a_carrier_error_not_a_hang() {
    if std::env::var_os(FAILED_MSI_CHILD).is_some() {
        carrick_x86_cpl0_host::cpl0_boot::anonymous_owner::fail_carrier_resched_for_test();
        exit_drain_wake(&["-DUSE_POLL"], ROOT_AFFINITY_IDLE_PEER);
        return;
    }
    let started = std::time::Instant::now();
    let output = std::process::Command::new("timeout")
        .args(["--signal=KILL", "30"])
        .arg(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "failed_resched_msi_is_a_carrier_error_not_a_hang",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(FAILED_MSI_CHILD, "1")
        .output()
        .expect("bounded failed-MSI child");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(25),
        "the failed MSI must settle in bounded time ({:?}): {stderr}",
        started.elapsed()
    );
    assert!(
        !output.status.success() && stderr.contains("ipc::table"),
        "the failed MSI must surface a carrier error: {:?} {stderr}",
        output.status
    );
}

#[test]
fn child_exit_closing_last_writer_wakes_parked_ppoll() {
    exit_drain_wake(&[], ROOT_AFFINITY_LOADED);
}

#[test]
fn child_exit_closing_last_writer_wakes_parked_poll() {
    exit_drain_wake(&["-DUSE_POLL"], ROOT_AFFINITY_LOADED);
}

#[test]
fn child_exit_wakes_ppoll_parked_on_idle_peer_cpu() {
    exit_drain_wake(&[], ROOT_AFFINITY_IDLE_PEER);
}

#[test]
fn child_exit_wakes_poll_parked_on_idle_peer_cpu() {
    exit_drain_wake(&["-DUSE_POLL"], ROOT_AFFINITY_IDLE_PEER);
}

/// x86 serves no zone pipe `read`/`write` in ring yet: both return EBADF
/// (exit 109 under `-DERRNO_EXIT`), so the EOF reader and the EPIPE writer
/// cannot park. They turn green with #1756's x86 IPC transfer venue.
#[test]
#[ignore = "#1756: x86 has no ring IPC venue for zone pipe read"]
fn child_exit_closing_last_writer_wakes_parked_reader_to_eof() {
    exit_drain_wake(&["-DREAD_EOF"], ROOT_AFFINITY_LOADED);
}

#[test]
#[ignore = "#1756: x86 has no ring IPC venue for zone pipe write"]
fn child_exit_closing_last_reader_wakes_parked_writer_with_epipe() {
    exit_drain_wake(&["-DLAST_READER"], ROOT_AFFINITY_LOADED);
}
