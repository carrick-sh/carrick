//! The goal scoreboard's two Go rows (`go-version`, `go-hello`) as signed,
//! in-process witnesses on the production entry (#2276, #2242).
//!
//! `go version` is not a trivial print. Go 1.23 opens its telemetry counter
//! file (a `MAP_SHARED` mapping), probes pidfd support, then starts the
//! telemetry sidecar from a multithreaded process: `clone(CLONE_VM |
//! CLONE_VFORK | SIGCHLD)` with a zero stack, so the child runs on the
//! parent's stack until it `execve`s `go "** telemetry **"` with `setsid`
//! and `/dev/null` stdio. The parent prints and `exit_group`s while the
//! sidecar runs on. Docker oracle (arm64 and amd64, default seccomp): exit
//! 0, one stdout line `go version go1.23.<n> linux/<arch>`, empty stderr.
//!
//! On failure each test prints the process lifecycle and every process's
//! last syscalls, so a signed run names the dying process and its last call.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;

use carrick_conformance_next::{AuditEvent, ContainerResult, PullPolicy, TestContainer};

const GO_IMAGE: &str = "docker.io/library/golang:1.23";
/// The last syscalls kept per process in a failure digest.
const TAIL: usize = 12;

fn digest(result: &ContainerResult, events: &[AuditEvent]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "exit_code={} signal={:?} terminal_reason={:?} trap_limit_hit={} traps={}",
        result.exit_code,
        result.signal,
        result.terminal_reason,
        result.trap_limit_hit,
        result.traps
    );
    let _ = writeln!(out, "stdout: {:?}", result.stdout_utf8());
    let _ = writeln!(out, "stderr: {:?}", result.stderr_utf8());
    let _ = writeln!(out, "compat: {:?}", result.compat);
    let mut tails: BTreeMap<i32, Vec<String>> = BTreeMap::new();
    for event in events {
        match event {
            AuditEvent::ProcessCreate { .. }
            | AuditEvent::Exec { .. }
            | AuditEvent::ProcessExit { .. } => {
                let _ = writeln!(out, "lifecycle: {event:?}");
            }
            AuditEvent::Syscall {
                pid,
                tid,
                syscall_name,
                args,
                ..
            } => {
                let tail = tails.entry(*pid).or_default();
                tail.push(format!("tid {tid} {syscall_name}{args:x?}"));
                if tail.len() > TAIL {
                    tail.remove(0);
                }
            }
            AuditEvent::SyscallReturn {
                pid,
                tid,
                syscall_name,
                outcome,
                ..
            } => {
                let tail = tails.entry(*pid).or_default();
                tail.push(format!("tid {tid} {syscall_name} -> {outcome:?}"));
                if tail.len() > TAIL {
                    tail.remove(0);
                }
            }
        }
    }
    for (pid, tail) in tails {
        let _ = writeln!(out, "pid {pid} last syscalls:");
        for line in tail {
            let _ = writeln!(out, "  {line}");
        }
    }
    out
}

fn run_go_row(args: &[&str]) -> (ContainerResult, String) {
    let container = TestContainer::new(GO_IMAGE).pull_policy(PullPolicy::Missing);
    let (result, observer) = common::run_or_fail(container.run_with_audit(args.iter().copied()));
    let digest = digest(&result, &observer.events());
    (result, digest)
}

/// Scoreboard row `go-version`: red on main `59a2b28ab` as a bare SIGSEGV
/// (exit 139, no Go panic text) after #2247.
#[test]
fn go_version_with_telemetry_sidecar_exits_zero() {
    let _guard = common::guest_lock();
    let (result, digest) = run_go_row(&["go", "version"]);
    assert_eq!(result.signal, None, "go version died of a signal\n{digest}");
    assert_eq!(result.exit_code, 0, "go version failed\n{digest}");
    let stdout = result.stdout_utf8();
    assert!(
        stdout.starts_with("go version go1.23.")
            && (stdout.ends_with(" linux/arm64\n") || stdout.ends_with(" linux/amd64\n")),
        "unexpected go version output\n{digest}"
    );
    assert!(result.stderr.is_empty(), "unexpected stderr\n{digest}");
}

/// Scoreboard row `go-hello`: `go run` from a shell, which needs GOROOT from
/// `/proc/self/exe` in an exec'd child (#2084) and then builds and runs.
#[test]
fn go_run_hello_from_shell_prints_go_ok() {
    let _guard = common::guest_lock();
    let (result, digest) = run_go_row(&[
        "sh",
        "-c",
        "cd /tmp && printf 'package main\\nimport \"fmt\"\\nfunc main(){fmt.Println(\"go-ok\")}\\n' > h.go && go run h.go",
    ]);
    assert_eq!(result.signal, None, "go run died of a signal\n{digest}");
    assert_eq!(result.exit_code, 0, "go run failed\n{digest}");
    assert_eq!(
        result.stdout_utf8(),
        "go-ok\n",
        "unexpected output\n{digest}"
    );
}
