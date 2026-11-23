//! #2420: an executor worker's death on the production KVM pool, driven
//! through `prepare`'s run, its completion enrolment and its pool shutdown.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used, clippy::panic)]
#[path = "common/kvm_pool_fixture.rs"]
#[allow(dead_code)]
mod kvm_pool_fixture;

use carrick_runtime::prepare::{KvmInjectedExecutorDeath, KvmPoolTestControl};

/// Run `test` in a child bounded by a KILL timeout: a red run parks forever.
fn bounded(test: &str) -> bool {
    if std::env::var_os("CARRICK_EXECUTOR_DEATH_CHILD").is_some() {
        return false;
    }
    let output = std::process::Command::new("timeout")
        .args(["--signal=KILL", "60"])
        .arg(std::env::current_exe().expect("test executable"))
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env("CARRICK_EXECUTOR_DEATH_CHILD", "1")
        .output()
        .expect("bounded executor-death witness");
    assert!(
        output.status.success(),
        "the run must end with its verdict: {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

fn run(
    flags: &[&str],
    death: KvmInjectedExecutorDeath,
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_runtime::prepare::PreparedKvmPoolFailure,
> {
    let elf = kvm_pool_fixture::assemble_fixture("native_executor_death.S", flags);
    kvm_pool_fixture::try_run_pool_fixture_with_test_control(
        &elf,
        256,
        KvmPoolTestControl {
            loaded_pre_entry_hook: None,
            injected_death: Some(death),
        },
    )
}

/// A worker that dies outside any lane, holding no task, while the root is
/// parked in a futex wait nothing wakes: only `prepare`'s enrolment on the
/// scheduler's executor-death verdict ends the run, with the worker's error.
#[test]
fn idle_peer_death_ends_the_run_with_its_verdict() {
    if bounded("idle_peer_death_ends_the_run_with_its_verdict") {
        return;
    }
    let failure = run(
        &["-DPARK_FOREVER"],
        KvmInjectedExecutorDeath::IdlePeerFirstIdle,
    )
    .err()
    .expect("a dead executor's run ends with an error");
    let error = failure.error.to_string();
    assert!(
        error.contains("executor worker died index=")
            && error.contains("injected executor death at the idle peer's first guest idle"),
        "the run's error names the worker and its exact death: {error}"
    );
}

/// The guest's exit reached the run's completion first; the worker that sent
/// it dies right after. The exit stays the run's result: the death, and the
/// pool shutdown failure it leaves, do not turn a completed run into a
/// carrier error.
#[test]
fn executor_death_after_the_guest_exit_keeps_the_exit() {
    if bounded("executor_death_after_the_guest_exit_keeps_the_exit") {
        return;
    }
    let outcome = run(&[], KvmInjectedExecutorDeath::AfterGuestExit)
        .map_err(|failure| failure.error.to_string())
        .expect("a death after the guest exit keeps the exit");
    assert_eq!(outcome.run.exit_code, 7, "the guest's own exit status");
}

/// #2826: a worker dies after sealing an exec row (before the guest resumes
/// to adopt it), so `run_prepared_kvm_pool_with_debug` returns `Err`. The
/// carrier-exit drain must still run after `pool.shutdown()`, retiring the
/// sealed row (`carrier_exit == 1`, `unretired() == 0`) and rolling back its
/// staged frames to the pre-run baseline.
#[test]
fn exec_sealed_then_executor_death_drains_at_carrier_exit() {
    if bounded("exec_sealed_then_executor_death_drains_at_carrier_exit") {
        return;
    }
    let dir = tempfile::tempdir().expect("exec fixture directory");
    let successor = dir.path().join("successor");
    carrick_test_support::executable::write_executable_mode(
        &successor,
        kvm_pool_fixture::assemble_fixture("native_root_exec_successor.S", &[]),
        0o700,
    );
    let define = format!("-DEXEC_PATH=\"{}\"", successor.display());
    let elf = kvm_pool_fixture::assemble_fixture("native_root_exec.S", &[&define]);
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::from_path(std::path::Path::new("/"))
            .expect("host filesystem"),
    ));
    let authority = std::sync::Arc::new(carrick_kernel::kernel::FrameInventoryAuthority::new());
    let inventory = authority.physical_projection(std::sync::Arc::new(
        carrick_kernel::kernel::ObjectIdRegistry::new(),
    ));
    let baseline_mappings = std::cell::Cell::new(0usize);
    let failure =
        kvm_pool_fixture::try_run_pool_fixture_with_inventory_dispatcher_and_test_control(
            &elf,
            256,
            inventory,
            dispatcher,
            KvmPoolTestControl {
                loaded_pre_entry_hook: None,
                injected_death: Some(KvmInjectedExecutorDeath::AfterExecSealed),
            },
            || baseline_mappings.set(authority.snapshot().mappings.len()),
        )
        .err()
        .expect("injected executor death after exec seal must return Err");
    let error = failure.error.to_string();
    assert!(
        error.contains("injected executor death after exec seal"),
        "expected injected death error, got: {error}"
    );
    let physical = failure
        .physical
        .as_ref()
        .expect("failed KVM pool run returns physical carrier");
    let census = physical.exec_owner_census().expect("exec owner census");
    assert_eq!(
        (
            census.reserved,
            census.sealed,
            census.adopted,
            census.carrier_exit,
            census.unretired(),
        ),
        (1, 1, 0, 1, 0),
        "carrier-exit drain must retire the sealed, unadopted row on Err exit: {census:?}"
    );
    assert_eq!(
        authority.snapshot().mappings.len(),
        baseline_mappings.get(),
        "carrier-exit drain must roll back the sealed exec's staged frames to baseline"
    );
}
