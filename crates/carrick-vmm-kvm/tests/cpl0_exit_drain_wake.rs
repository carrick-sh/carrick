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
