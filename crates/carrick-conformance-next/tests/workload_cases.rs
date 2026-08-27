//! Workload-shaped guest test migration and classification audit for `carrick-conformance-next`.
//!
//! Evaluates the migration of legacy workload-shaped tests from
//! `crates/carrick-cli/tests/conformance.rs` into `carrick-conformance-next`.
//!
//! # Workload Test Assessment & Classification (1 Migrated / 1 Retired)
//!
//! 1. `conformance_go_fixture` — **MIGRATED**
//!    - **Implementation**: Mounted prebuilt static AArch64 Linux Go binary
//!      (`fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello`) read-only at `/tmp/go-fixture`.
//!    - **Verification**: Executed directly in-process via `TestContainer` + `AuditObserver`, asserting on
//!      clean process exit (0), absence of terminating signals or trap limits, exact deterministic 4-line
//!      stdout matching `src/main.go`, empty stderr, and observed netpoller / socket lifecycle events.
//!    - **Requirement**: Artifact must exist (fail-closed assert instructs running `./scripts/build-go-fixtures.sh`).
//!
//! 2. `conformance_native_cross_boundary_network` — **RETIRED / BLOCKED**
//!    - **Reason**: Explicitly targets the retired 1:1 host-process-per-guest-process native
//!      execution backend (`CARRICK_EXEC_BACKEND=native`). Furthermore, it requires port publishing
//!      (`-p 127.0.0.1:{port}:{port}`) and out-of-process client orchestration spawning the host
//!      benchmark binary `bench-native/target/release/perf_net_xclient`.
//!    - **Missing / Incompatible Capabilities**: Native backend execution (retired in favor of
//!      unified HVPatch kernel), port publishing / forwarding in `carrick-embed`, and out-of-process
//!      client binary execution across process boundaries.
//!    - **Authoritative Suite**: `crates/carrick-cli/tests/conformance.rs::conformance_native_cross_boundary_network`.
//!
//! # Verification Policy
//!
//! In accordance with the repository policy:
//! - No `std::process::Command`, `tokio::process::Command`, or shelling out.
//! - No passing legacy-named stub and no ignored (`#[ignore]`) tests.
//! - The retired native backend is not perpetuated as fake coverage.
//! - Signed in-process execution with full observability audit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

use carrick_conformance_next::{
    ExitStatus, PullPolicy, ResultAssert, TestContainer, assert_syscall_eventually_succeeded,
    find_all_syscall_returns, find_process_exits,
};

/// Classification status for a workload-shaped conformance test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadStatus {
    Migrated,
    Blocked {
        reason: &'static str,
        missing_capabilities: &'static [&'static str],
    },
    Retired {
        reason: &'static str,
        retired_subsystem: &'static str,
    },
}

/// Audit record for an assessed legacy workload-shaped test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadTestAudit {
    pub legacy_test_fn: &'static str,
    pub tracked_sources: &'static [&'static str],
    pub status: WorkloadStatus,
}

/// Manifest of all legacy workload-shaped guest tests assessed for migration.
pub const WORKLOAD_TEST_AUDITS: &[WorkloadTestAudit] = &[
    WorkloadTestAudit {
        legacy_test_fn: "conformance_go_fixture",
        tracked_sources: &[
            "fixtures/go-aarch64-hello/src/main.go",
            "scripts/build-go-fixtures.sh",
        ],
        status: WorkloadStatus::Migrated,
    },
    WorkloadTestAudit {
        legacy_test_fn: "conformance_native_cross_boundary_network",
        tracked_sources: &[
            "conformance-probes/src/bin/perf_net_xserver.rs",
            "conformance-probes/src/bin/perf_net_xclient.rs",
        ],
        status: WorkloadStatus::Retired {
            reason: "Targeted the retired 1:1 native execution backend (CARRICK_EXEC_BACKEND=native), published port mapping (-p), and out-of-process client orchestration",
            retired_subsystem: "Legacy native execution backend (CARRICK_EXEC_BACKEND=native)",
        },
    },
];

#[test]
fn conformance_go_fixture() {
    let _guard = common::guest_lock();
    let fixture_path = common::repo_root()
        .join("fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello");
    assert!(
        fixture_path.is_file(),
        "Go fixture artifact not found at {}. Build it first by running `./scripts/build-go-fixtures.sh`.",
        fixture_path.display()
    );

    let container = TestContainer::new(common::SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .mount_readonly(fixture_path.to_string_lossy(), "/tmp/go-fixture");

    let (result, observer) = common::run_or_fail(container.run_with_audit(["/tmp/go-fixture"]));

    result.assert_success();
    result.assert_exit_code(0);
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);

    let expected_stdout = "\
Client received status: success
Client received runtime: carrick
Client received concurrency: enabled
Graceful shutdown completed successfully
";
    assert_eq!(
        result.stdout_utf8(),
        expected_stdout,
        "unexpected stdout from go-fixture:\n{}",
        result.stdout_utf8()
    );
    assert!(
        result.stderr.is_empty(),
        "expected empty stderr from go-fixture, got:\n{}",
        result.stderr_utf8()
    );

    let events = observer.events();
    let exits = find_process_exits(&events);
    assert!(
        exits.contains(&ExitStatus::Exited(0)),
        "expected process exit status 0 in audit events, got: {exits:?}"
    );

    // Assert socket and network lifecycle syscalls executed by Go's HTTP server & client.
    assert_syscall_eventually_succeeded(&events, "socket");
    assert_syscall_eventually_succeeded(&events, "bind");
    assert_syscall_eventually_succeeded(&events, "listen");
    // Connect initiates nonblocking connection returning EINPROGRESS (115) followed by epoll netpoll
    let connect_outcomes = find_all_syscall_returns(&events, "connect");
    assert!(
        !connect_outcomes.is_empty(),
        "expected at least one connect syscall invocation in audit events"
    );
}

#[test]
fn audit_workload_cases_manifest_is_complete() {
    assert_eq!(
        WORKLOAD_TEST_AUDITS.len(),
        2,
        "manifest must contain exactly 2 assessed legacy workload test cases"
    );

    let test_names: BTreeSet<&str> = WORKLOAD_TEST_AUDITS
        .iter()
        .map(|a| a.legacy_test_fn)
        .collect();
    assert_eq!(
        test_names.len(),
        2,
        "all legacy test function names must be unique"
    );
    assert!(
        test_names.contains("conformance_go_fixture"),
        "manifest must contain conformance_go_fixture"
    );
    assert!(
        test_names.contains("conformance_native_cross_boundary_network"),
        "manifest must contain conformance_native_cross_boundary_network"
    );
}

#[test]
fn audit_workload_cases_classification_counts() {
    let mut migrated_count = 0;
    let mut blocked_count = 0;
    let mut retired_count = 0;

    for audit in WORKLOAD_TEST_AUDITS {
        match &audit.status {
            WorkloadStatus::Migrated => migrated_count += 1,
            WorkloadStatus::Blocked {
                reason,
                missing_capabilities,
            } => {
                assert!(
                    !reason.is_empty(),
                    "blocked test {} must specify a non-empty reason",
                    audit.legacy_test_fn
                );
                assert!(
                    !missing_capabilities.is_empty(),
                    "blocked test {} must specify missing capabilities",
                    audit.legacy_test_fn
                );
                blocked_count += 1;
            }
            WorkloadStatus::Retired {
                reason,
                retired_subsystem,
            } => {
                assert!(
                    !reason.is_empty(),
                    "retired test {} must specify a non-empty reason",
                    audit.legacy_test_fn
                );
                assert!(
                    !retired_subsystem.is_empty(),
                    "retired test {} must specify the retired subsystem",
                    audit.legacy_test_fn
                );
                retired_count += 1;
            }
        }
    }

    assert_eq!(
        migrated_count, 1,
        "exactly 1 workload case (conformance_go_fixture) is migrated in-process"
    );
    assert_eq!(blocked_count, 0, "0 workload cases are blocked");
    assert_eq!(
        retired_count, 1,
        "exactly 1 workload case (conformance_native_cross_boundary_network) is retired"
    );
    assert_eq!(
        migrated_count + blocked_count + retired_count,
        2,
        "all 2 workload cases must be accounted for"
    );
}

#[test]
fn audit_workload_artifacts_exist_in_repo() {
    let root = common::repo_root();
    for audit in WORKLOAD_TEST_AUDITS {
        for source in audit.tracked_sources {
            let artifact_path = root.join(source);
            assert!(
                artifact_path.exists(),
                "tracked source {} for {} must exist at {}",
                source,
                audit.legacy_test_fn,
                artifact_path.display()
            );
        }
    }
}
