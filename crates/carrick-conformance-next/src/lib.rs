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
