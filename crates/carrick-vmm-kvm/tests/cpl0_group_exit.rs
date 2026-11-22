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
    group_exit_with_output(flags, test, expected, "");
}

/// As [`group_exit_with_status`], and the run's stdout must be exactly
/// `stdout`.
fn group_exit_with_output(flags: &[&str], test: &str, expected: i32, stdout: &str) {
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
    // An exec variant runs its successor from a host path; it is built from
    // the same source, with the parent's flags, as the group's process.
    let directory = tempfile::tempdir().expect("successor directory");
    let mut flags = flags.to_vec();
    let define;
    if flags.contains(&"-DEXEC_SUCCESSOR") {
        let successor = directory.path().join("successor");
        let successor_flags: Vec<&str> = flags
            .iter()
            .copied()
            .filter(|flag| *flag != "-DEXEC_SUCCESSOR")
            .chain(["-DSUCCESSOR"])
            .collect();
        let image = kvm_pool_fixture::assemble_fixture("native_group_exit.S", &successor_flags);
        carrick_test_support::executable::write_executable_mode(&successor, &image, 0o700);
        define = format!("-DSUCCESSOR_PATH=\"{}\"", successor.display());
        flags.push(&define);
    }
    let elf = kvm_pool_fixture::assemble_fixture("native_group_exit.S", &flags);
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
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
    .expect("production CPL0 group exit");
    assert_eq!(
        outcome.run.exit_code, expected,
        "the group must end with its exact status"
    );
    assert_eq!(
        String::from_utf8_lossy(&outcome.run.stdout),
        stdout,
        "the group's stdout"
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

/// #2620 (npm after a V8 fatal): the exec'd fork child's leader aborts while
/// one worker is parked in `epoll_pwait(-1)` on a ring epoll and another in a
/// futex wait. The close interrupts the epoll park; the worker must retire,
/// not replay its wait, so the parent's wait4 sees SIGABRT.
#[test]
fn exec_child_abort_retires_epoll_and_futex_workers() {
    group_exit(
        &["-DEPOLL_WORKER", "-DABORT_SIGNAL", "-DEXEC_SUCCESSOR"],
        "exec_child_abort_retires_epoll_and_futex_workers",
    );
}

/// #2620: the same exec'd group ended by its leader's `exit_group(5)`.
#[test]
fn exec_child_exit_group_retires_epoll_and_futex_workers() {
    group_exit(
        &["-DEPOLL_WORKER", "-DEXEC_SUCCESSOR"],
        "exec_child_exit_group_retires_epoll_and_futex_workers",
    );
}

/// #2620 without exec: the fork child itself aborts with the same members.
#[test]
fn fork_child_abort_retires_epoll_and_futex_workers() {
    group_exit(
        &["-DEPOLL_WORKER", "-DABORT_SIGNAL"],
        "fork_child_abort_retires_epoll_and_futex_workers",
    );
}

/// #2620 as the run's root: the run ends with 128 + SIGABRT.
#[test]
fn root_abort_retires_epoll_and_futex_workers() {
    group_exit_with_status(
        &["-DEPOLL_WORKER", "-DABORT_SIGNAL", "-DROOT_ABORT"],
        "root_abort_retires_epoll_and_futex_workers",
        128 + 6,
    );
}

/// #2780: a member of the run's root writes to stdout while its leader is
/// runnable. The write is the member's own host crossing; the carrier serves
/// it and the run ends with the leader's status.
#[test]
fn root_worker_stdout_write_is_served() {
    group_exit_with_output(
        &["-DWORKER_WRITES", "-DROOT_ABORT"],
        "root_worker_stdout_write_is_served",
        5,
        "w\n",
    );
}

/// #2780 (#2281): the same write from a member of a fork child, which the
/// parent then reaps with its exact status.
#[test]
fn fork_child_worker_stdout_write_is_served() {
    group_exit_with_output(
        &["-DWORKER_WRITES"],
        "fork_child_worker_stdout_write_is_served",
        0,
        "w\n",
    );
}

/// #2780: a member of the run's root ends the group with `exit_group(5)`
/// while the leader is parked in a futex wait.
#[test]
fn root_worker_exit_group_retires_parked_leader() {
    group_exit_with_status(
        &["-DWORKER_EXITS", "-DLEADER_PARKED", "-DROOT_ABORT"],
        "root_worker_exit_group_retires_parked_leader",
        5,
    );
}

/// #2780: a member of the run's root aborts (`tgkill(self, SIGABRT)`) while
/// the leader is parked in a futex wait: the run ends with 128 + SIGABRT.
#[test]
fn root_worker_abort_ends_run_with_sigabrt_status() {
    group_exit_with_status(
        &[
            "-DWORKER_EXITS",
            "-DLEADER_PARKED",
            "-DWORKER_ABORTS",
            "-DROOT_ABORT",
        ],
        "root_worker_abort_ends_run_with_sigabrt_status",
        128 + 6,
    );
}

/// #2780: the same member abort in a fork child; the parent's wait4 sees
/// SIGABRT.
#[test]
fn fork_child_worker_abort_retires_parked_leader() {
    group_exit(
        &["-DWORKER_EXITS", "-DLEADER_PARKED", "-DWORKER_ABORTS"],
        "fork_child_worker_abort_retires_parked_leader",
    );
}
