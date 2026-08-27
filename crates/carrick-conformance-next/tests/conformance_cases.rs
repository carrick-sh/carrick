//! In-process structured Linux conformance test suite using `TestContainer` + `AuditObserver`.
//!
//! Port of the legacy conformance suite (`crates/carrick-cli/tests/conformance.rs`),
//! asserting on observable guest stdout/stderr/exit behavior and structural
//! syscall/lifecycle events without any subprocess shell-out or Docker oracle dependency.
//!
//! Run host-only verification via:
//!   cargo test -p carrick-conformance-next --test conformance_cases
//!
//! Run signed guest verification via:
//!   just test-conformance-next conformance_cases --nocapture
//! or:
//!   ./scripts/test-signed.sh carrick-conformance-next conformance_cases --nocapture
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;

use carrick_conformance_next::{
    ExitStatus, PullPolicy, ResultAssert, TestContainer, assert_syscall_eventually_succeeded,
    assert_syscall_returned, assert_syscall_success, find_all_syscall_returns,
    find_first_syscall_return, find_process_exits,
};

// ===========================================================================
// Parity mapping & denominator tracking
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacySource {
    /// From legacy `CASES` table in `crates/carrick-cli/tests/conformance.rs` (18 cases).
    CasesTable,
    /// From legacy `EXIT_CASES` table in `crates/carrick-cli/tests/conformance.rs` (5 cases).
    ExitCasesTable,
    /// Container-level PID namespace invariant test.
    ContainerInvariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStatus {
    Mapped,
    Gap,
}

#[derive(Debug, Clone, Copy)]
pub struct ConformanceCaseMapping {
    pub legacy_name: &'static str,
    pub legacy_source: LegacySource,
    pub snippet: &'static str,
    pub in_process_test: &'static str,
    pub in_initial_12_denominator: bool,
    pub status: MigrationStatus,
}

pub const LEGACY_CONFORMANCE_MAPPINGS: &[ConformanceCaseMapping] = &[
    // --- 18 CASES from crates/carrick-cli/tests/conformance.rs ---
    ConformanceCaseMapping {
        legacy_name: "uname_m",
        legacy_source: LegacySource::CasesTable,
        snippet: "uname -m",
        in_process_test: "case_03_uname_architecture",
        in_initial_12_denominator: true,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "dpkg_arch",
        legacy_source: LegacySource::CasesTable,
        snippet: "dpkg --print-architecture",
        in_process_test: "case_13_dpkg_print_architecture",
        in_initial_12_denominator: false,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "getcwd",
        legacy_source: LegacySource::CasesTable,
        snippet: "cd /tmp && mkdir -p a/b && cd a/b && pwd",
        in_process_test: "case_05_getcwd_and_mkdir_chdir",
        in_initial_12_denominator: true,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "mkdir_chdir",
        legacy_source: LegacySource::CasesTable,
        snippet: "mkdir -p /x/y/z && cd /x/y/z && pwd",
        in_process_test: "case_14_mkdir_chdir",
        in_initial_12_denominator: false,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "access_root",
        legacy_source: LegacySource::CasesTable,
        snippet: "test -w /var/lib/dpkg && echo W || echo noW; test -r /etc/passwd && echo R || echo noR; test -x /bin/sh && echo X || echo noX",
        in_process_test: "case_15_access_root_permissions",
        in_initial_12_denominator: false,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "readdir_created",
        legacy_source: LegacySource::CasesTable,
        snippet: "cd /tmp && touch zz_newfile && ls zz_newfile && ls | grep -c zz_newfile",
        in_process_test: "case_16_readdir_created_file",
        in_initial_12_denominator: false,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "pipe_cat",
        legacy_source: LegacySource::CasesTable,
        snippet: "echo hello | cat",
        in_process_test: "case_06_pipe_interprocess_communication",
        in_initial_12_denominator: true,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "rename",
        legacy_source: LegacySource::CasesTable,
        snippet: "cd /tmp && echo content > a.txt && mv a.txt b.txt && cat b.txt && (ls a.txt 2>&1 | sed 's/.*: //')",
        in_process_test: "case_17_file_rename_and_absence",
        in_initial_12_denominator: false,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "symlink",
        legacy_source: LegacySource::CasesTable,
        snippet: "cd /tmp && ln -sf /etc/hostname lnk && readlink lnk",
        in_process_test: "case_07_symlink_and_readlink",
        in_initial_12_denominator: true,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "hardlink",
        legacy_source: LegacySource::CasesTable,
        snippet: "cd /tmp && echo hl > f1 && ln f1 f2 && cat f2",
        in_process_test: "case_08_hardlink_creation_and_contents",
        in_initial_12_denominator: true,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "stat",
        legacy_source: LegacySource::CasesTable,
        snippet: "stat -c '%s %F %a' /etc/passwd",
        in_process_test: "case_18_file_stat_format",
        in_initial_12_denominator: false,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "copy_file_range",
        legacy_source: LegacySource::CasesTable,
        snippet: "cp /etc/hostname /tmp/h2 && cat /tmp/h2 >/dev/null && echo cp_ok",
        in_process_test: "case_19_file_copy_range",
        in_initial_12_denominator: false,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "fd_redirect",
        legacy_source: LegacySource::CasesTable,
        snippet: "exec 3>/tmp/fd3.txt; echo via3 >&3; exec 3>&-; cat /tmp/fd3.txt",
        in_process_test: "case_12_fd_redirection_and_close",
        in_initial_12_denominator: true,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "chmod",
        legacy_source: LegacySource::CasesTable,
        snippet: "cd /tmp && touch m && chmod 640 m && stat -c '%a' m",
        in_process_test: "case_09_file_permission_chmod_and_stat",
        in_initial_12_denominator: true,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "truncate",
        legacy_source: LegacySource::CasesTable,
        snippet: "cd /tmp && printf 'abcdef' > t && truncate -s 3 t && cat t && echo",
        in_process_test: "case_10_file_truncation_truncate",
        in_initial_12_denominator: true,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "append",
        legacy_source: LegacySource::CasesTable,
        snippet: "cd /tmp && echo one > ap && echo two >> ap && cat ap",
        in_process_test: "case_20_file_append_redirection",
        in_initial_12_denominator: false,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "mkdir_rmdir",
        legacy_source: LegacySource::CasesTable,
        snippet: "cd /tmp && mkdir rd && rmdir rd && (ls rd 2>&1 | sed 's/.*: //')",
        in_process_test: "case_21_mkdir_and_rmdir",
        in_initial_12_denominator: false,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "id_root",
        legacy_source: LegacySource::CasesTable,
        snippet: "id -u; id -g",
        in_process_test: "case_04_id_root_credentials",
        in_initial_12_denominator: true,
        status: MigrationStatus::Mapped,
    },
    // --- 5 EXIT_CASES from crates/carrick-cli/tests/conformance.rs ---
    ConformanceCaseMapping {
        legacy_name: "exit_zero",
        legacy_source: LegacySource::ExitCasesTable,
        snippet: "true",
        in_process_test: "case_22_exit_zero_contract",
        in_initial_12_denominator: false,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "exit_one",
        legacy_source: LegacySource::ExitCasesTable,
        snippet: "exit 1",
        in_process_test: "case_23_exit_one_contract",
        in_initial_12_denominator: false,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "exit_42",
        legacy_source: LegacySource::ExitCasesTable,
        snippet: "exit 42",
        in_process_test: "case_01_exit_status_propagation",
        in_initial_12_denominator: true,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "stdout_only",
        legacy_source: LegacySource::ExitCasesTable,
        snippet: "echo OUT",
        in_process_test: "case_24_stdout_only_contract",
        in_initial_12_denominator: false,
        status: MigrationStatus::Mapped,
    },
    ConformanceCaseMapping {
        legacy_name: "stream_separation",
        legacy_source: LegacySource::ExitCasesTable,
        snippet: "echo OUT; echo ERR 1>&2; exit 3",
        in_process_test: "case_11_stream_separation",
        in_initial_12_denominator: true,
        status: MigrationStatus::Mapped,
    },
    // --- 1 Container Invariant Case ---
    ConformanceCaseMapping {
        legacy_name: "pid_namespace_root_getpid",
        legacy_source: LegacySource::ContainerInvariant,
        snippet: "echo $$",
        in_process_test: "case_02_pid_namespace_root_getpid",
        in_initial_12_denominator: true,
        status: MigrationStatus::Mapped,
    },
];

/// Helper to parse named case definitions (`name: "...", snippet: "...",`) from legacy conformance.rs.
fn parse_legacy_cases_from_source(source: &str, const_name: &str) -> Vec<(String, String)> {
    let marker = format!("const {const_name}:");
    let Some(start_pos) = source.find(&marker) else {
        panic!("could not find constant {const_name} in legacy conformance.rs");
    };
    let slice = &source[start_pos..];
    let Some(open_bracket) = slice.find("&[") else {
        panic!("could not find array start `&[` in {const_name} definition");
    };
    let after_open = &slice[open_bracket + 2..];
    let Some(close_bracket) = after_open.find("];") else {
        panic!("could not find array end `];` in {const_name} definition");
    };
    let block = &after_open[..close_bracket];

    let mut cases = Vec::new();
    let mut lines = block.lines().map(str::trim).peekable();
    while let Some(line) = lines.next() {
        if line.starts_with("name:") {
            let name = extract_quoted_value(line, "name:");
            while let Some(s_line) = lines.next() {
                let s_line = s_line.trim();
                if s_line.starts_with("snippet:") {
                    let snippet = extract_quoted_value(s_line, "snippet:");
                    cases.push((name, snippet));
                    break;
                }
            }
        }
    }
    cases
}

fn extract_quoted_value(line: &str, prefix: &str) -> String {
    let remainder = line.trim_start_matches(prefix).trim();
    let start = remainder
        .find('"')
        .expect("expected opening double quote in case definition");
    let after_start = &remainder[start + 1..];
    let end = after_start
        .rfind('"')
        .expect("expected closing double quote in case definition");
    after_start[..end].to_string()
}

#[test]
fn legacy_conformance_cases_parity_and_denominator_audit() {
    let legacy_conformance_path =
        common::repo_root().join("crates/carrick-cli/tests/conformance.rs");
    let source = std::fs::read_to_string(&legacy_conformance_path).unwrap_or_else(|err| {
        panic!(
            "failed to read legacy conformance.rs at {}: {err}",
            legacy_conformance_path.display()
        )
    });

    let parsed_cases = parse_legacy_cases_from_source(&source, "CASES");
    let parsed_exit_cases = parse_legacy_cases_from_source(&source, "EXIT_CASES");

    assert_eq!(
        parsed_cases.len(),
        18,
        "legacy CASES table in conformance.rs must contain exactly 18 cases"
    );
    assert_eq!(
        parsed_exit_cases.len(),
        5,
        "legacy EXIT_CASES table in conformance.rs must contain exactly 5 cases"
    );

    let cases_table_mappings: BTreeMap<&str, &ConformanceCaseMapping> = LEGACY_CONFORMANCE_MAPPINGS
        .iter()
        .filter(|m| m.legacy_source == LegacySource::CasesTable)
        .map(|m| (m.legacy_name, m))
        .collect();

    assert_eq!(
        cases_table_mappings.len(),
        parsed_cases.len(),
        "mapped CASES entries count must equal parsed CASES entries count from conformance.rs"
    );

    for (legacy_name, legacy_snippet) in &parsed_cases {
        let Some(mapping) = cases_table_mappings.get(legacy_name.as_str()) else {
            panic!(
                "legacy CASES entry {legacy_name:?} from conformance.rs is missing from in-process mappings"
            );
        };
        assert_eq!(
            mapping.snippet, legacy_snippet,
            "snippet mismatch for legacy CASES entry {legacy_name:?}:\n  legacy: {legacy_snippet:?}\n  mapped: {:?}",
            mapping.snippet
        );
        assert_eq!(
            mapping.status,
            MigrationStatus::Mapped,
            "legacy CASES entry {legacy_name:?} must be marked Mapped"
        );
    }

    let exit_cases_table_mappings: BTreeMap<&str, &ConformanceCaseMapping> =
        LEGACY_CONFORMANCE_MAPPINGS
            .iter()
            .filter(|m| m.legacy_source == LegacySource::ExitCasesTable)
            .map(|m| (m.legacy_name, m))
            .collect();

    assert_eq!(
        exit_cases_table_mappings.len(),
        parsed_exit_cases.len(),
        "mapped EXIT_CASES entries count must equal parsed EXIT_CASES entries count from conformance.rs"
    );

    for (legacy_name, legacy_snippet) in &parsed_exit_cases {
        let Some(mapping) = exit_cases_table_mappings.get(legacy_name.as_str()) else {
            panic!(
                "legacy EXIT_CASES entry {legacy_name:?} from conformance.rs is missing from in-process mappings"
            );
        };
        assert_eq!(
            mapping.snippet, legacy_snippet,
            "snippet mismatch for legacy EXIT_CASES entry {legacy_name:?}:\n  legacy: {legacy_snippet:?}\n  mapped: {:?}",
            mapping.snippet
        );
        assert_eq!(
            mapping.status,
            MigrationStatus::Mapped,
            "legacy EXIT_CASES entry {legacy_name:?} must be marked Mapped"
        );
    }

    let container_invariant_count = LEGACY_CONFORMANCE_MAPPINGS
        .iter()
        .filter(|m| m.legacy_source == LegacySource::ContainerInvariant)
        .count();
    assert_eq!(
        container_invariant_count, 1,
        "exact 1 container PID1 invariant case must be accounted for"
    );

    let initial_12_count = LEGACY_CONFORMANCE_MAPPINGS
        .iter()
        .filter(|m| m.in_initial_12_denominator)
        .count();
    assert_eq!(
        initial_12_count, 12,
        "exact 12-case initial denominator must be drift-visible"
    );

    let newly_mapped_count = LEGACY_CONFORMANCE_MAPPINGS
        .iter()
        .filter(|m| !m.in_initial_12_denominator)
        .count();
    assert_eq!(
        newly_mapped_count, 12,
        "exact 12 newly mapped cases to close legacy gap"
    );

    let gaps_count = LEGACY_CONFORMANCE_MAPPINGS
        .iter()
        .filter(|m| m.status == MigrationStatus::Gap)
        .count();
    assert_eq!(
        gaps_count, 0,
        "all legacy cases must be fully mapped with zero gaps"
    );

    let total_mapped = LEGACY_CONFORMANCE_MAPPINGS
        .iter()
        .filter(|m| m.status == MigrationStatus::Mapped)
        .count();
    assert_eq!(total_mapped, 24, "total 24 in-process test cases mapped");
}

// ===========================================================================
// In-process conformance test cases
// ===========================================================================

#[test]
fn case_01_exit_status_propagation() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) =
        common::run_or_fail(container.run_with_audit(["/bin/sh", "-c", "exit 42"]));

    result.assert_exit_code(42);
    assert!(!result.success());
    assert_eq!(result.signal, None);
    assert_eq!(result.stdout_utf8(), "");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    let exits = find_process_exits(&events);
    assert!(
        exits.contains(&ExitStatus::Exited(42)),
        "expected process exit status 42 in audit log, got: {exits:?}"
    );
}

#[test]
fn case_02_pid_namespace_root_getpid() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) =
        common::run_or_fail(container.run_with_audit(["/bin/sh", "-c", "echo $$"]));

    result.assert_success().assert_stdout_contains("1");
    assert_eq!(result.stdout_utf8().trim(), "1");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_returned(&events, "getpid", 1);
}

#[test]
fn case_03_uname_architecture() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit(["uname", "-m"]));

    result.assert_success();
    assert_eq!(result.stdout_utf8().trim(), "aarch64");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_success(&events, "uname");
}

#[test]
fn case_04_id_root_credentials() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) =
        common::run_or_fail(container.run_with_audit(["/bin/sh", "-c", "id -u; id -g"]));

    result.assert_success();
    assert_eq!(result.stdout_utf8(), "0\n0\n");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_returned(&events, "getuid", 0);
    assert_syscall_returned(&events, "getgid", 0);
}

#[test]
fn case_05_getcwd_and_mkdir_chdir() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "cd /tmp && mkdir -p a/b && cd a/b && pwd",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8().trim(), "/tmp/a/b");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_success(&events, "mkdirat");
    assert_syscall_success(&events, "chdir");
    assert_syscall_success(&events, "getcwd");
}

#[test]
fn case_06_pipe_interprocess_communication() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) =
        common::run_or_fail(container.run_with_audit(["/bin/sh", "-c", "echo hello | cat"]));

    result.assert_success();
    assert_eq!(result.stdout_utf8(), "hello\n");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    let pipe_created = find_first_syscall_return(&events, "pipe2")
        .or_else(|| find_first_syscall_return(&events, "pipe"));
    assert!(
        pipe_created.is_some_and(|o| o.is_ok()),
        "expected successful pipe syscall"
    );

    let writes = find_all_syscall_returns(&events, "write");
    let reads = find_all_syscall_returns(&events, "read");
    assert!(writes.iter().any(|w| w.is_ok() && w.value > 0));
    assert!(reads.iter().any(|r| r.is_ok() && r.value > 0));
}

#[test]
fn case_07_symlink_and_readlink() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "cd /tmp && ln -sf /etc/hostname lnk && readlink lnk",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8().trim(), "/etc/hostname");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_success(&events, "symlinkat");
    assert_syscall_success(&events, "readlinkat");
}

#[test]
fn case_08_hardlink_creation_and_contents() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "cd /tmp && echo hl > f1 && ln f1 f2 && cat f2",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8(), "hl\n");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_success(&events, "linkat");
}

#[test]
fn case_09_file_permission_chmod_and_stat() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "cd /tmp && touch m && chmod 640 m && stat -c '%a' m",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8().trim(), "640");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_success(&events, "fchmodat");
    assert_syscall_eventually_succeeded(&events, "newfstatat");
}

#[test]
fn case_10_file_truncation_truncate() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "cd /tmp && printf 'abcdef' > t && truncate -s 3 t && cat t && echo",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8(), "abc\n");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    let truncate_ok = find_first_syscall_return(&events, "truncate")
        .or_else(|| find_first_syscall_return(&events, "ftruncate"));
    assert!(
        truncate_ok.is_some_and(|o| o.is_ok()),
        "expected successful truncate or ftruncate syscall"
    );
}

#[test]
fn case_11_stream_separation() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "echo OUT; echo ERR 1>&2; exit 3",
    ]));

    result
        .assert_exit_code(3)
        .assert_stdout_contains("OUT\n")
        .assert_stderr_contains("ERR\n");
    assert_eq!(result.stdout_utf8(), "OUT\n");
    assert_eq!(result.stderr_utf8(), "ERR\n");

    let events = observer.events();
    let exits = find_process_exits(&events);
    assert!(
        exits.contains(&ExitStatus::Exited(3)),
        "expected process exit status 3, got: {exits:?}"
    );
}

#[test]
fn case_12_fd_redirection_and_close() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "exec 3>/tmp/fd3.txt; echo via3 >&3; exec 3>&-; cat /tmp/fd3.txt",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8(), "via3\n");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_success(&events, "openat");
    assert_syscall_success(&events, "close");
}

#[test]
fn case_13_dpkg_print_architecture() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "dpkg --print-architecture",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8().trim(), "arm64");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    let exec_ok = find_first_syscall_return(&events, "execve")
        .or_else(|| find_first_syscall_return(&events, "execveat"));
    assert!(
        exec_ok.is_some_and(|o| o.is_ok()),
        "expected successful execve/execveat syscall for dpkg"
    );
}

#[test]
fn case_14_mkdir_chdir() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "mkdir -p /x/y/z && cd /x/y/z && pwd",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8().trim(), "/x/y/z");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_success(&events, "mkdirat");
    assert_syscall_success(&events, "chdir");
    assert_syscall_success(&events, "getcwd");
}

#[test]
fn case_15_access_root_permissions() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "test -w /var/lib/dpkg && echo W || echo noW; test -r /etc/passwd && echo R || echo noR; test -x /bin/sh && echo X || echo noX",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8(), "W\nR\nX\n");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    let access_or_stat = find_all_syscall_returns(&events, "faccessat2")
        .into_iter()
        .chain(find_all_syscall_returns(&events, "faccessat"))
        .chain(find_all_syscall_returns(&events, "newfstatat"))
        .any(|o| o.is_ok());
    assert!(
        access_or_stat,
        "expected successful access/faccessat2 or stat checks in audit log"
    );
}

#[test]
fn case_16_readdir_created_file() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "cd /tmp && touch zz_newfile && ls zz_newfile && ls | grep -c zz_newfile",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8(), "zz_newfile\n1\n");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_success(&events, "openat");
    let getdents_ok = find_first_syscall_return(&events, "getdents64")
        .or_else(|| find_first_syscall_return(&events, "getdents"));
    assert!(
        getdents_ok.is_some_and(|o| o.is_ok()),
        "expected successful getdents64/getdents syscall"
    );
}

#[test]
fn case_17_file_rename_and_absence() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "cd /tmp && echo content > a.txt && mv a.txt b.txt && cat b.txt && (ls a.txt 2>&1 | sed 's/.*: //')",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8(), "content\nNo such file or directory\n");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    let rename_ok = find_first_syscall_return(&events, "renameat2")
        .or_else(|| find_first_syscall_return(&events, "renameat"))
        .or_else(|| find_first_syscall_return(&events, "rename"));
    assert!(
        rename_ok.is_some_and(|o| o.is_ok()),
        "expected successful rename syscall"
    );
}

#[test]
fn case_18_file_stat_format() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "stat -c '%s %F %a' /etc/passwd",
    ]));

    result.assert_success();
    let out = result.stdout_utf8().trim().to_string();
    assert!(
        out.ends_with("regular file 644"),
        "expected stat output ending in 'regular file 644', got: {out:?}"
    );
    let parts: Vec<&str> = out.split_whitespace().collect();
    assert_eq!(
        parts.len(),
        4,
        "expected '<size> regular file 644', got {out:?}"
    );
    assert!(
        parts[0].parse::<u64>().is_ok(),
        "expected numeric file size in stat output, got {out:?}"
    );
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_eventually_succeeded(&events, "newfstatat");
}

#[test]
fn case_19_file_copy_range() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "cp /etc/hostname /tmp/h2 && cat /tmp/h2 >/dev/null && echo cp_ok",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8(), "cp_ok\n");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_success(&events, "openat");
    assert_syscall_eventually_succeeded(&events, "close");
}

#[test]
fn case_20_file_append_redirection() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "cd /tmp && echo one > ap && echo two >> ap && cat ap",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8(), "one\ntwo\n");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_success(&events, "openat");
    assert_syscall_eventually_succeeded(&events, "write");
}

#[test]
fn case_21_mkdir_and_rmdir() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit([
        "/bin/sh",
        "-c",
        "cd /tmp && mkdir rd && rmdir rd && (ls rd 2>&1 | sed 's/.*: //')",
    ]));

    result.assert_success();
    assert_eq!(result.stdout_utf8(), "No such file or directory\n");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_success(&events, "mkdirat");
    let rmdir_ok = find_first_syscall_return(&events, "rmdir")
        .or_else(|| find_first_syscall_return(&events, "unlinkat"));
    assert!(
        rmdir_ok.is_some_and(|o| o.is_ok()),
        "expected successful rmdir/unlinkat syscall"
    );
}

#[test]
fn case_22_exit_zero_contract() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) =
        common::run_or_fail(container.run_with_audit(["/bin/sh", "-c", "true"]));

    result.assert_exit_code(0);
    assert!(result.success());
    assert_eq!(result.signal, None);
    assert_eq!(result.stdout_utf8(), "");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    let exits = find_process_exits(&events);
    assert!(
        exits.contains(&ExitStatus::Exited(0)),
        "expected process exit status 0 in audit log, got: {exits:?}"
    );
}

#[test]
fn case_23_exit_one_contract() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) =
        common::run_or_fail(container.run_with_audit(["/bin/sh", "-c", "exit 1"]));

    result.assert_exit_code(1);
    assert!(!result.success());
    assert_eq!(result.signal, None);
    assert_eq!(result.stdout_utf8(), "");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    let exits = find_process_exits(&events);
    assert!(
        exits.contains(&ExitStatus::Exited(1)),
        "expected process exit status 1 in audit log, got: {exits:?}"
    );
}

#[test]
fn case_24_stdout_only_contract() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) =
        common::run_or_fail(container.run_with_audit(["/bin/sh", "-c", "echo OUT"]));

    result.assert_success();
    assert_eq!(result.stdout_utf8(), "OUT\n");
    assert_eq!(result.stderr_utf8(), "");

    let events = observer.events();
    assert_syscall_eventually_succeeded(&events, "write");
}
