//! In-process structured Linux conformance test suite using `TestContainer` + `AuditObserver`.
//!
//! Port of ~10 representative LTP and probe conformance cases from the existing
//! gate (`crates/carrick-cli/tests/conformance.rs`), asserting on both observable
//! guest stdout/stderr/exit behavior and structural syscall/lifecycle events.
//!
//! Run via the signed recipe:
//!   just test-conformance-next
//! or:
//!   ./scripts/test-signed.sh carrick-conformance-next
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use carrick_conformance_next::{
    ExitStatus, PullPolicy, ResultAssert, TestContainer, assert_syscall_returned,
    assert_syscall_success, find_all_syscall_returns, find_first_syscall_return,
    find_process_exits,
};

#[test]
fn case_01_exit_status_propagation() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) =
        common::run_or_fail(container.run_with_audit(["/bin/sh", "-c", "exit 42"]));

    result.assert_exit_code(42);
    assert!(!result.success());
    assert_eq!(result.signal, None);

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

    let events = observer.events();
    assert_syscall_returned(&events, "getpid", 1);
}

#[test]
fn case_03_uname_architecture() {
    let _guard = common::guest_lock();
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit(["uname", "-m"]));

    result.assert_success();
    let arch = result.stdout_utf8().trim().to_string();
    assert!(
        !arch.is_empty(),
        "expected non-empty architecture from uname -m"
    );

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

    let events = observer.events();
    // Pipe creation should succeed (pipe2 or pipe)
    let pipe_created = find_first_syscall_return(&events, "pipe2")
        .or_else(|| find_first_syscall_return(&events, "pipe"));
    assert!(
        pipe_created.is_some_and(|o| o.is_ok()),
        "expected successful pipe syscall"
    );

    // Read and write should both succeed
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

    let events = observer.events();
    assert_syscall_success(&events, "fchmodat");
    assert_syscall_success(&events, "newfstatat");
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

    let events = observer.events();
    assert_syscall_success(&events, "openat");
    assert_syscall_success(&events, "close");
}
