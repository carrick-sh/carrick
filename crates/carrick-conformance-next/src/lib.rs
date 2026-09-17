//! `carrick-conformance-next`: self-hosted Linux conformance framework for Carrick.
//!
//! Structured conformance testing built on `carrick-embed`'s [`TestContainer`]
//! and [`AuditObserver`]. Tests run in-process as standard `#[test]` functions,
//! asserting on both guest execution results ([`ContainerResult`]) and structural
//! kernel events ([`AuditEvent`]).

pub use carrick_abi::{CanonicalNr, LinuxErrno};
pub use carrick_embed::testing::{ResultAssert, TestContainer, run_in_container};
pub use carrick_embed::{
    AuditEvent, AuditObserver, ContainerBuilder, ContainerResult, EmbedError, ExitStatus,
    FastPathVisibility, ImageStore, PullPolicy, RunRequest, StdioConfig, StdioMode, SyscallAction,
    SyscallInfo, SyscallObserver, SyscallOutcome,
};

/// The wall-clock budget one probe carrier gets, in milliseconds.
///
/// MEASURED, not chosen. One green `just conformance-probes` on the canonical
/// Mac (2026-09-15, 902 generic probe runs over both libcs, quiet box) gave
/// p50 117 ms, p90 519 ms, p95 1347 ms, p99 4650 ms, p99.5 5379 ms — 19 probes
/// over 2 s and only two above 6 s. The budget is the embed default, which is
/// ~11x that p99.5, so scheduling noise cannot reach it while a wedge (29m45s
/// when one was last found by hand) is cut three orders of magnitude earlier.
pub const PROBE_CARRIER_BUDGET_MS: u64 = carrick_embed::testing::DEFAULT_CARRIER_BUDGET_MS;

/// Extra milliseconds the FIRST container in a probe process gets, for image
/// resolution and a cold guest.
pub const PROBE_COLD_START_ALLOWANCE_MS: u64 = carrick_embed::testing::COLD_START_ALLOWANCE_MS;

/// A probe whose measured cost does not fit the global budget, and why.
///
/// Typed rather than a bare tuple table: the reason is the part that stops the
/// next reader raising a budget to make a row pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeBudgetOverride {
    pub probe: &'static str,
    pub budget_ms: u64,
    pub reason: &'static str,
}

/// The complete set of probes whose steady budget differs from the global one.
///
/// Both entries are probes that SLEEP or churn by design, measured on the same
/// green gate as the global budget; each gets ~6x its measured cost, the same
/// shape of headroom the global budget has.
pub const PROBE_BUDGET_OVERRIDES: &[ProbeBudgetOverride] = &[
    ProbeBudgetOverride {
        probe: "mtidlesleep",
        budget_ms: 120_000,
        reason: "sleeps idle threads for ~20s by construction (measured 20122/20133ms)",
    },
    ProbeBudgetOverride {
        probe: "futexforkrequeue",
        budget_ms: 120_000,
        reason: "fork + requeue churn, measured 11174/14448ms with high variance",
    },
];

/// The steady budget for `probe`, before any cold-start allowance.
pub fn probe_steady_budget_ms(probe: &str) -> u64 {
    PROBE_BUDGET_OVERRIDES
        .iter()
        .find(|entry| entry.probe == probe)
        .map_or(PROBE_CARRIER_BUDGET_MS, |entry| entry.budget_ms)
}

/// The total budget a probe's carrier gets.
///
/// This is the harness's statement of the policy; `carrick-embed` resolves the
/// same number when the container runs (see the agreement test below), so the
/// two can never drift into two answers.
pub fn probe_carrier_budget(probe: &str, first_in_process: bool) -> std::time::Duration {
    let steady = std::time::Duration::from_millis(probe_steady_budget_ms(probe));
    if first_in_process {
        steady + std::time::Duration::from_millis(PROBE_COLD_START_ALLOWANCE_MS)
    } else {
        steady
    }
}

/// Filter all [`AuditEvent::SyscallReturn`] events for a specific syscall by name.
pub fn find_all_syscall_returns(events: &[AuditEvent], syscall_name: &str) -> Vec<SyscallOutcome> {
    events
        .iter()
        .filter_map(|event| match event {
            AuditEvent::SyscallReturn {
                syscall_name: name,
                outcome,
                ..
            } if *name == syscall_name => Some(*outcome),
            _ => None,
        })
        .collect()
}

/// Find the first [`AuditEvent::SyscallReturn`] outcome for a specific syscall by name.
pub fn find_first_syscall_return(
    events: &[AuditEvent],
    syscall_name: &str,
) -> Option<SyscallOutcome> {
    events.iter().find_map(|event| match event {
        AuditEvent::SyscallReturn {
            syscall_name: name,
            outcome,
            ..
        } if *name == syscall_name => Some(*outcome),
        _ => None,
    })
}

/// Find all [`AuditEvent::ProcessExit`] statuses recorded in `events`.
pub fn find_process_exits(events: &[AuditEvent]) -> Vec<ExitStatus> {
    events
        .iter()
        .filter_map(|event| match event {
            AuditEvent::ProcessExit { status, .. } => Some(*status),
            _ => None,
        })
        .collect()
}

/// Count the number of times a syscall was invoked in `events`.
pub fn count_syscall(events: &[AuditEvent], syscall_name: &str) -> usize {
    events
        .iter()
        .filter(|event| match event {
            AuditEvent::Syscall {
                syscall_name: name, ..
            } => *name == syscall_name,
            _ => false,
        })
        .collect::<Vec<_>>()
        .len()
}

/// Assert that a syscall occurred and that its first return outcome was successful (`outcome.is_ok()`).
#[allow(clippy::panic)]
pub fn assert_syscall_success(events: &[AuditEvent], syscall_name: &str) {
    let Some(outcome) = find_first_syscall_return(events, syscall_name) else {
        panic!("expected return event for syscall {syscall_name:?}, but none was recorded");
    };
    assert!(
        outcome.is_ok(),
        "expected syscall {syscall_name:?} to succeed, got errno {:?}",
        outcome.errno
    );
}

/// Assert that a syscall occurred and that at least one of its returns succeeded.
///
/// Use this, not [`assert_syscall_success`], for any syscall a shell pipeline
/// issues repeatedly against different paths. `newfstatat` is the standard
/// example: `sh -c "touch m && chmod 640 m && stat m"` stats paths that do not
/// exist long before it stats `m` — a loader probing a search path, a utility
/// checking for a file it is about to create — and every one of those misses is
/// correct Linux behaviour, not a divergence. Asserting on the FIRST return
/// there tests the order in which a shell happens to probe the filesystem,
/// which is not a property carrick owns.
#[allow(clippy::panic)]
pub fn assert_syscall_eventually_succeeded(events: &[AuditEvent], syscall_name: &str) {
    let outcomes = find_all_syscall_returns(events, syscall_name);
    if outcomes.is_empty() {
        panic!("expected return event for syscall {syscall_name:?}, but none was recorded");
    }
    assert!(
        outcomes.iter().any(|outcome| outcome.is_ok()),
        "expected at least one {syscall_name:?} to succeed; all {} returns failed: {:?}",
        outcomes.len(),
        outcomes.iter().map(|o| o.errno).collect::<Vec<_>>()
    );
}

/// Assert that a syscall occurred and its first return outcome had the exact return value `expected`.
#[allow(clippy::panic)]
pub fn assert_syscall_returned(events: &[AuditEvent], syscall_name: &str, expected: i64) {
    let Some(outcome) = find_first_syscall_return(events, syscall_name) else {
        panic!("expected return event for syscall {syscall_name:?}, but none was recorded");
    };
    assert_eq!(
        outcome.value, expected,
        "expected syscall {syscall_name:?} to return {expected}, got {}",
        outcome.value
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_embed::{LinuxTid, ObjectIdRegistry, TaskId, TaskKey, ThreadKey};

    fn dummy_task_key() -> TaskKey {
        let registry = ObjectIdRegistry::new();
        TaskKey {
            id: TaskId::for_root_bootstrap(1).unwrap(),
            serial: registry.task_serial().unwrap(),
        }
    }

    fn dummy_thread_key() -> ThreadKey {
        let registry = ObjectIdRegistry::new();
        ThreadKey {
            tid: LinuxTid::from_abi_positive(1).unwrap(),
            serial: registry.thread_serial().unwrap(),
        }
    }

    /// Every probe is bounded, named in the override table or not: the
    /// function is total, so a probe added tomorrow cannot arrive unbounded.
    #[test]
    fn every_generic_probe_has_a_carrier_budget() {
        for probe in PROBE_BUDGET_OVERRIDES.iter().map(|entry| entry.probe) {
            assert!(
                probe_carrier_budget(probe, false) >= std::time::Duration::from_millis(1),
                "{probe} must be bounded"
            );
        }
        assert_eq!(
            probe_carrier_budget("a-probe-nobody-has-written-yet", false),
            std::time::Duration::from_millis(PROBE_CARRIER_BUDGET_MS),
            "an unlisted probe falls back to the measured global budget"
        );
        for entry in PROBE_BUDGET_OVERRIDES {
            assert!(
                entry.budget_ms > PROBE_CARRIER_BUDGET_MS,
                "{} is in the override table but does not raise the budget",
                entry.probe
            );
            assert!(
                !entry.reason.is_empty(),
                "{} must say why it is slow",
                entry.probe
            );
        }
    }

    #[test]
    fn cold_start_allowance_exceeds_the_steady_budget() {
        const {
            // A compile-time refusal, so the pair cannot be edited into a
            // cold-start allowance smaller than one steady run.
            assert!(
                PROBE_COLD_START_ALLOWANCE_MS > PROBE_CARRIER_BUDGET_MS,
                "image resolution plus a cold guest costs more than a steady run"
            );
        }
        assert_eq!(
            probe_carrier_budget("telemetrymap", true)
                - probe_carrier_budget("telemetrymap", false),
            std::time::Duration::from_millis(PROBE_COLD_START_ALLOWANCE_MS)
        );
    }

    /// The harness names the steady budget; `carrick-embed` resolves what is
    /// actually applied. A second computation of the same number is a second
    /// answer waiting to drift, so they are checked against each other.
    #[test]
    fn the_harness_budget_matches_what_embed_will_apply() {
        for probe in ["telemetrymap", "mtidlesleep", "futexforkrequeue"] {
            let requested = std::time::Duration::from_millis(probe_steady_budget_ms(probe));
            for first in [false, true] {
                assert_eq!(
                    carrick_embed::testing::effective_carrier_budget(Some(requested), first),
                    Some(probe_carrier_budget(probe, first)),
                    "{probe} (first_in_process={first})"
                );
            }
        }
    }

    #[test]
    fn helper_filters_syscall_returns_correctly() {
        let events = vec![
            AuditEvent::Syscall {
                pid: 1,
                tid: 1,
                task_key: dummy_task_key(),
                thread_key: dummy_thread_key(),
                syscall_number: 172,
                syscall_name: "getpid",
                args: [0; 6],
                original_args: None,
            },
            AuditEvent::SyscallReturn {
                pid: 1,
                tid: 1,
                task_key: dummy_task_key(),
                thread_key: dummy_thread_key(),
                syscall_number: 172,
                syscall_name: "getpid",
                outcome: SyscallOutcome::returned(1),
            },
            AuditEvent::ProcessExit {
                pid: 1,
                task_key: dummy_task_key(),
                status: ExitStatus::Exited(0),
            },
        ];

        let outcomes = find_all_syscall_returns(&events, "getpid");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].value, 1);
        assert!(outcomes[0].is_ok());

        assert_eq!(count_syscall(&events, "getpid"), 1);
        assert_eq!(count_syscall(&events, "uname"), 0);

        let exits = find_process_exits(&events);
        assert_eq!(exits, vec![ExitStatus::Exited(0)]);

        assert_syscall_success(&events, "getpid");
        assert_syscall_returned(&events, "getpid", 1);
    }
}
