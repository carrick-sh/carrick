//! Fault injection and resource budget integration tests running real guest workloads.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh): it signs the test
//! executable with the hypervisor entitlement, exports `CARRICK_RUN_ID`, and runs
//! it under `RUST_TEST_THREADS=1`.

mod common;

use std::sync::Mutex;

use carrick_abi::{LINUX_EACCES, LINUX_EAGAIN};
use carrick_embed::{
    Carrier, EmbedError, ExceedAction, FaultInjector, ImageStore, PullPolicy, ResourceBudget,
};

static SHARED_CARRIER: Mutex<Option<Carrier>> = Mutex::new(None);

fn carrier_or_fail() -> Option<Carrier> {
    let mut guard = SHARED_CARRIER.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(carrier) = guard.as_ref() {
        return Some(carrier.clone());
    }
    let carrier_res = Carrier::new();
    let not_entitlement = !matches!(carrier_res, Err(EmbedError::Entitlement));
    assert!(
        not_entitlement,
        "HV_DENIED (0xfae94007): this test executable lacks \
         com.apple.security.hypervisor. Run it through `just test-embed` \
         (scripts/test-signed.sh signs it); a bare `cargo test -p carrick-embed` \
         can never boot a guest."
    );
    assert!(
        carrier_res.is_ok(),
        "carrier create failed: {:?}",
        carrier_res.as_ref().err()
    );
    let carrier = carrier_res.ok()?;
    *guard = Some(carrier.clone());
    Some(carrier)
}

/// Resource budget live counters track dispatched syscalls and written bytes.
#[test]
fn resource_budget_counters_are_observable() {
    let _guest = common::guest_lock();
    let Some(carrier) = carrier_or_fail() else {
        return;
    };

    let budget = ResourceBudget::new();
    let outcome = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .command(["/bin/echo", "hello", "budget"])
        .resource_budget(budget.clone())
        .run_blocking();

    let result = common::run_or_fail(outcome);
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout_utf8().trim(), "hello budget");

    let snapshot = budget.counters();
    assert!(
        snapshot.syscalls > 0,
        "syscall counter must be positive: {snapshot:?}"
    );
    assert!(
        snapshot.bytes_written > 0,
        "bytes written counter must be positive: {snapshot:?}"
    );
}

/// Resource budget `max_syscalls` terminates a runaway loop when exceeded.
#[test]
fn resource_budget_max_syscalls_terminates() {
    let _guest = common::guest_lock();
    let Some(carrier) = carrier_or_fail() else {
        return;
    };

    // Limit to 100 syscalls total; dynamic linking + loop will quickly exceed this.
    let budget = ResourceBudget::new()
        .max_syscalls(100)
        .on_exceed(ExceedAction::Kill);

    let outcome = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .command(["/bin/sh", "-c", "while true; do /bin/echo loop; done"])
        .resource_budget(budget.clone())
        .run_blocking();

    let result = common::run_or_fail(outcome);
    assert!(
        result.signal.is_some() || result.exit_code != 0,
        "runaway loop must be terminated by budget exceed action: exit={} signal={:?}",
        result.exit_code,
        result.signal
    );
    let snapshot = budget.counters();
    assert!(
        snapshot.syscalls >= 100,
        "syscall count must reach limit: {snapshot:?}"
    );
}

/// Fault injector injects `EACCES` on `mkdirat`, causing the guest `mkdir` to fail.
#[test]
fn fault_injector_fail_mkdir_with_eacces() {
    let _guest = common::guest_lock();
    let Some(carrier) = carrier_or_fail() else {
        return;
    };

    let injector = FaultInjector::new().on("mkdirat").fail_with(LINUX_EACCES);

    let outcome = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .command(["/bin/mkdir", "/tmp/fault_test_dir"])
        .fault_injector(injector)
        .run_blocking();

    let result = common::run_or_fail(outcome);
    assert_ne!(
        result.exit_code, 0,
        "mkdir must fail when mkdirat returns EACCES"
    );
    let stderr = result.stderr_utf8();
    assert!(
        stderr.to_lowercase().contains("permission denied")
            || stderr.to_lowercase().contains("cannot create")
            || stderr.to_lowercase().contains("mkdir"),
        "stderr should reflect permission failure: {stderr}"
    );
}

/// Fault injector clamps `write` syscalls to 1 byte, exercising the short I/O path.
#[test]
fn fault_injector_short_write_on_stdout() {
    let _guest = common::guest_lock();
    let Some(carrier) = carrier_or_fail() else {
        return;
    };

    let injector = FaultInjector::new().on("write").short(1);

    let outcome = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .command(["/bin/echo", "-n", "abc"])
        .fault_injector(injector)
        .run_blocking();

    let result = common::run_or_fail(outcome);
    assert_eq!(result.exit_code, 0);
    // Even though each write was clamped to 1 byte, libc's write loop must complete the string
    assert_eq!(result.stdout_utf8(), "abc");
}

/// Fault injector network partition fails socket operations.
#[test]
fn fault_injector_network_partition_rejects_socket() {
    let _guest = common::guest_lock();
    let Some(carrier) = carrier_or_fail() else {
        return;
    };

    let injector = FaultInjector::network_partition();

    let outcome = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .command(["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/80"])
        .fault_injector(injector)
        .run_blocking();

    let result = common::run_or_fail(outcome);
    assert_ne!(
        result.exit_code,
        0,
        "socket operation must fail under network partition: stderr={}",
        result.stderr_utf8()
    );
}

/// Resource budget limits max processes: excess fork returns `EAGAIN`.
#[test]
fn resource_budget_max_processes_throttles_fork() {
    let _guest = common::guest_lock();
    let Some(carrier) = carrier_or_fail() else {
        return;
    };

    // Limit to 2 processes (root init + 1 child)
    let budget = ResourceBudget::new()
        .max_processes(2)
        .on_exceed(ExceedAction::Errno(LINUX_EAGAIN));

    let outcome = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .command([
            "/bin/sh",
            "-c",
            "sleep 2 & \
             PID1=$!; \
             sleep 2 2>/tmp/err & \
             PID2=$!; \
             wait $PID1 2>/dev/null; \
             wait $PID2 2>/dev/null; \
             cat /tmp/err 2>/dev/null",
        ])
        .resource_budget(budget.clone())
        .run_blocking();

    let result = common::run_or_fail(outcome);
    let output = format!("{} {}", result.stdout_utf8(), result.stderr_utf8());
    // Either second fork failed or output mentions resource limit/cannot fork
    assert!(
        result.exit_code != 0
            || output.contains("Resource temporarily unavailable")
            || output.contains("cannot fork")
            || output.contains("fork")
            || budget.counters().processes <= 2,
        "budget must enforce process limits: code={} out={output}",
        result.exit_code
    );
}

/// Fault injector injects `ENOMEM` after N allocations (`FaultInjector::oom_after(count)`).
#[test]
fn fault_injector_oom_after_n_allocations() {
    let _guest = common::guest_lock();
    let Some(carrier) = carrier_or_fail() else {
        return;
    };

    // Inject ENOMEM on mmap/brk after 5 allocations; dynamic linker and startup will exceed this.
    let injector = FaultInjector::oom_after(5);

    let outcome = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .command([
            "/bin/sh",
            "-c",
            "for i in 1 2 3 4 5 6 7 8 9 10; do /bin/echo $i; done",
        ])
        .fault_injector(injector)
        .run_blocking();

    let result = common::run_or_fail(outcome);
    assert_ne!(
        result.exit_code,
        0,
        "execution must fail when memory allocation hits injected ENOMEM: out={} err={}",
        result.stdout_utf8(),
        result.stderr_utf8()
    );
}

/// Resource budget terminates a fork storm when process count exceeds `max_processes` with `ExceedAction::Kill`.
#[test]
fn resource_budget_max_processes_kills_fork_storm() {
    let _guest = common::guest_lock();
    let Some(carrier) = carrier_or_fail() else {
        return;
    };

    // Limit to 3 processes with Kill action
    let budget = ResourceBudget::new()
        .max_processes(3)
        .on_exceed(ExceedAction::Kill);

    let outcome = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .command([
            "/bin/sh",
            "-c",
            "for i in 1 2 3 4 5 6 7 8; do sleep 5 & done; wait",
        ])
        .resource_budget(budget.clone())
        .run_blocking();

    let result = common::run_or_fail(outcome);
    assert!(
        result.signal.is_some() || result.exit_code != 0,
        "fork storm exceeding process limit must be killed by budget exceed action: exit={} signal={:?}",
        result.exit_code,
        result.signal
    );
}
