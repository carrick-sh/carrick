//! #2282: the parent must reap a fork child with two live members.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used, clippy::panic)]
#[path = "common/kvm_pool_fixture.rs"]
#[allow(dead_code)]
mod kvm_pool_fixture;

fn group_exit(flags: &[&str], test: &str) {
    group_exit_with_status(flags, test, 0);
}

/// `expected` is the run's exit code: the root's own status, or 0 when the
/// root parent reaped and checked the child's status itself.
fn group_exit_with_status(flags: &[&str], test: &str, expected: i32) {
    if std::env::var_os("CARRICK_GROUP_EXIT_CHILD").is_none() {
        let output = std::process::Command::new("timeout")
            .args(["--signal=KILL", "60"])
            .arg(std::env::current_exe().expect("test executable"))
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env("CARRICK_GROUP_EXIT_CHILD", "1")
            .output()
            .expect("bounded group-exit witness");
        assert!(
            output.status.success(),
            "group exit must finish: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let elf = kvm_pool_fixture::assemble_fixture("native_group_exit.S", flags);
    let outcome = kvm_pool_fixture::run_pool_fixture(&elf, 256);
    assert_eq!(
        outcome.run.exit_code, expected,
        "the group must end with its exact status"
    );
}

#[test]
fn fork_child_exit_group_retires_futex_worker() {
    group_exit(&[], "fork_child_exit_group_retires_futex_worker");
}

#[test]
fn fork_child_exit_group_retires_runnable_worker() {
    group_exit(
        &["-DRUNNABLE_WORKER"],
        "fork_child_exit_group_retires_runnable_worker",
    );
}

#[test]
fn fork_child_exit_group_retires_computing_worker() {
    group_exit(
        &["-DCOMPUTING_WORKER"],
        "fork_child_exit_group_retires_computing_worker",
    );
}

#[test]
fn fork_child_worker_exit_group_retires_entryless_leader() {
    group_exit(
        &["-DWORKER_EXITS"],
        "fork_child_worker_exit_group_retires_entryless_leader",
    );
}

/// #2420: a worker can exit the group while the leader is parked in a futex
/// wait, not only while it computes.
#[test]
fn fork_child_worker_exit_group_retires_parked_leader() {
    group_exit(
        &["-DWORKER_EXITS", "-DLEADER_PARKED"],
        "fork_child_worker_exit_group_retires_parked_leader",
    );
}

/// #2420 (node after a V8 fatal): the root's leader aborts with
/// `tgkill(self, SIGABRT)` while its worker is parked in a futex wait. The
/// group dies and the run ends with 128 + SIGABRT.
#[test]
fn root_leader_abort_ends_run_with_sigabrt_status() {
    group_exit_with_status(
        &["-DABORT_SIGNAL", "-DROOT_ABORT"],
        "root_leader_abort_ends_run_with_sigabrt_status",
        128 + 6,
    );
}

/// #2620: root forks a child and blocks in `wait4(-1)` while the child execs
/// into a static successor that spawns an `epoll_pwait` worker and calls
/// `exit_group(5)`. The worker must retire its installed IPC adapter operation,
/// the child must publish `NCHILD_EXIT` + `NCHILD_ZOMBIE` + `NCHILD_WAKE`, and
/// the parked root `wait4(-1)` must reap status `(5 << 8)` and exit `0`.
#[test]
fn fork_exec_child_exit_group_retires_epoll_worker_and_wakes_parked_root_wait4() {
    let test = "fork_exec_child_exit_group_retires_epoll_worker_and_wakes_parked_root_wait4";
    if std::env::var_os("CARRICK_GROUP_EXIT_CHILD").is_none() {
        let output = std::process::Command::new("timeout")
            .args(["--signal=KILL", "60"])
            .arg(std::env::current_exe().expect("test executable"))
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env("CARRICK_GROUP_EXIT_CHILD", "1")
            .output()
            .expect("bounded exec+epoll group-exit witness");
        assert!(
            output.status.success(),
            "exec+epoll group exit must finish: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let directory = tempfile::tempdir().expect("successor directory");
    let successor = directory.path().join("successor");
    let successor_elf = kvm_pool_fixture::assemble_fixture(
        "native_group_exit.S",
        &["-DROOT_ABORT", "-DEPOLL_WORKER"],
    );
    carrick_test_support::executable::write_executable_mode(&successor, &successor_elf, 0o700);
    let define = format!("-DEXEC_SUCCESSOR_PATH=\"{}\"", successor.display());
    let caller_elf =
        kvm_pool_fixture::assemble_fixture("native_group_exit.S", &["-DWAIT_ANY_CHILD", &define]);
    let program =
        carrick_mem::elf::ElfProgram::load(&caller_elf, 62, &|_| None).expect("caller ELF");
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::from_path(std::path::Path::new("/"))
            .expect("host filesystem"),
    ));
    let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
        &program,
        256,
        kvm_pool_fixture::ROOT_AFFINITY_ANY,
        |_| {},
        dispatcher,
    )
    .map_err(|failure| failure.error)
    .expect("live KVM exec+epoll child group exit");
    assert_eq!(outcome.run.exit_code, 0);

    let kinds: Vec<u8> = carrick_kernel::event_ring::drain_recent(512)
        .into_iter()
        .filter_map(Result::ok)
        .map(|rec| rec.kind)
        .filter(|kind| {
            (*kind >= carrick_kernel::event_ring::NATIVE_CHILD_FORK)
                && (*kind <= carrick_kernel::event_ring::NATIVE_CHILD_LOST)
        })
        .collect();
    for required in [
        carrick_kernel::event_ring::NATIVE_CHILD_FORK,
        carrick_kernel::event_ring::NATIVE_CHILD_EXEC,
        carrick_kernel::event_ring::NATIVE_CHILD_EXIT,
        carrick_kernel::event_ring::NATIVE_CHILD_ZOMBIE,
        carrick_kernel::event_ring::NATIVE_CHILD_WAKE,
        carrick_kernel::event_ring::NATIVE_CHILD_REAP,
    ] {
        assert!(
            kinds.contains(&required),
            "expected lifecycle ring kind {required} in {kinds:?}"
        );
    }
}
