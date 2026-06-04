//! Generate `scripts/conformance/suites.toml` for full (100%-coverage)
//! conformance. Wires up EVERY available module per ecosystem as a `[[suite]]`,
//! split into two tiers:
//!
//!   * `tier = "smoke"` — the FAST gate (`just conformance-quick`): a small,
//!     curated, reliable subset that stays green and runs in minutes.
//!   * `tier = "full"`  — the comprehensive 100%-coverage run (`just conformance`):
//!     every module, its carrick-vs-Docker status recorded in the support matrix
//!     (MATCH where carrick conforms, DIFF/known-gap where it doesn't — carrick is
//!     experimental, so many FULL modules legitimately DIFF; that IS the coverage).
//!
//! Enumeration is live (`docker`), so re-run after a container update:
//!   `cargo run -p carrick-conformance -- --generate-suites`
//!   `cargo run -p carrick-conformance -- --generate-suites --dry-run`  (counts only)
//!
//! Suites are built as `manifest::Suite` values and serialized with `toml`
//! (single source of truth for the schema — no hand-rolled TOML).

use crate::manifest::{Ecosystem, EnginePair, Manifest, Suite, Tier, VerdictKind, Weight};
use std::path::Path;
use std::process::Command;

const CPYTHON_IMG: &str = "localhost:5050/cpython-test:3.12.13";
const GO_IMG: &str = "localhost:5005/carrick-go-conformance:1.24";
const NODE_IMG: &str = "localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0";
const LTP_IMG: &str = "localhost:5050/ltp:arm64";

// The fast (smoke) tier is the quick PRE-MERGE gate — it must stay GREEN, so it
// holds only PROVEN-MATCH modules. New coverage lands in tier=full first; promote
// a module here once a full run shows it MATCHes.

/// CPython modules in the fast tier (proven MATCH).
const CPY_SMOKE: &[&str] = &[
    "test_subprocess",
    "test_threading",
    "test_math",
    "test_json",
    "test_glob",
    "test_fcntl",
];
/// Go packages in the fast tier (proven MATCH).
const GO_SMOKE: &[&str] = &["runtime", "sync", "context", "time"];
/// LTP testcases in the fast tier (proven MATCH).
const LTP_SMOKE: &[&str] = &[
    "rt_sigaction01",
    "gettid01",
    "clock_gettime01",
    "epoll_create01",
    "getcpu01",
    "sched_yield01",
    "eventfd01",
    "pipe01",
    "gettimeofday01",
    "sched_getaffinity01",
];

/// Syscall-ABI family stems carrick emulates. An LTP binary is included iff its
/// name (trailing digits/letter stripped) is one of these — the rest of LTP's
/// ~1457 binaries are fs-image/network-heavy and TBROK on setup (noise, not
/// coverage).
const LTP_FAMILY_STEMS: &[&str] = &[
    "fork",
    "vfork",
    "clone",
    "execve",
    "execveat",
    "execl",
    "execlp",
    "execvp",
    "exit",
    "exit_group",
    "wait",
    "wait4",
    "waitpid",
    "waitid",
    "signal",
    "sigaction",
    "rt_sigaction",
    "sigprocmask",
    "rt_sigprocmask",
    "sigsuspend",
    "sigpending",
    "sigwait",
    "sighold",
    "sigrelse",
    "sigignore",
    "sigaltstack",
    "kill",
    "tkill",
    "tgkill",
    "pause",
    "alarm",
    "setitimer",
    "getitimer",
    "mmap",
    "munmap",
    "mprotect",
    "mremap",
    "madvise",
    "msync",
    "mlock",
    "mlockall",
    "munlock",
    "brk",
    "sbrk",
    "futex",
    "futex_wait",
    "futex_wake",
    "futex_cmp_requeue",
    "epoll",
    "epoll_create",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "poll",
    "ppoll",
    "select",
    "pselect",
    "pipe",
    "pipe2",
    "dup",
    "dup2",
    "dup3",
    "fcntl",
    "flock",
    "read",
    "write",
    "pread",
    "pwrite",
    "readv",
    "writev",
    "preadv",
    "pwritev",
    "open",
    "openat",
    "close",
    "lseek",
    "creat",
    "stat",
    "fstat",
    "lstat",
    "statx",
    "access",
    "faccessat",
    "chdir",
    "fchdir",
    "getcwd",
    "getpid",
    "getppid",
    "gettid",
    "getpgid",
    "getpgrp",
    "setpgid",
    "setsid",
    "getsid",
    "nanosleep",
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "clock_settime",
    "timer_create",
    "timer_settime",
    "timer_gettime",
    "sched_setscheduler",
    "sched_getscheduler",
    "sched_yield",
    "sched_getaffinity",
    "sched_setaffinity",
    "sched_getparam",
    "sched_get_priority_max",
    "socket",
    "socketpair",
    "bind",
    "listen",
    "accept",
    "accept4",
    "connect",
    "send",
    "sendto",
    "sendmsg",
    "recv",
    "recvfrom",
    "recvmsg",
    "shutdown",
    "getsockopt",
    "setsockopt",
    "eventfd",
    "eventfd2",
    "timerfd_create",
    "timerfd_settime",
    "signalfd",
    "signalfd4",
    "inotify_init",
    "prctl",
    "setrlimit",
    "getrlimit",
    "prlimit",
    "getrusage",
    "times",
    "ptrace",
    "membarrier",
    "set_robust_list",
    "get_robust_list",
    "setresuid",
    "setreuid",
    "setuid",
    "setgid",
    "setresgid",
    "setregid",
    "umask",
    "getrandom",
    "memfd_create",
    "userfaultfd",
    "pidfd_open",
    "pidfd_send_signal",
    "gettimeofday",
    "settimeofday",
    "getcpu",
];

fn docker_stdout(args: &[&str]) -> String {
    Command::new("docker")
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn ltp_stem(name: &str) -> &str {
    let b = name.as_bytes();
    let mut end = b.len();
    if end > 1 && b[end - 1].is_ascii_lowercase() && b[end - 2].is_ascii_digit() {
        end -= 1;
    }
    while end > 0 && b[end - 1].is_ascii_digit() {
        end -= 1;
    }
    &name[..end]
}

#[allow(clippy::too_many_arguments)]
fn mk(
    name: String,
    eco: Ecosystem,
    image: &str,
    cmd: Vec<String>,
    verdict: VerdictKind,
    tier: Tier,
    weight: Weight,
    timeout_s: u64,
    workdir: Option<String>,
    entrypoint: Option<&str>,
) -> Suite {
    Suite {
        name,
        ecosystem: eco,
        image: image.to_string(),
        cmd,
        verdict,
        tier,
        weight,
        timeout_s,
        known_gaps: Vec::new(),
        carrick_flags: vec!["--raw".into(), "--fs".into(), "host".into()],
        docker_flags: Vec::new(),
        bind_mounts: Vec::new(),
        env: Vec::new(),
        env_carrick: Vec::new(),
        env_docker: Vec::new(),
        workdir,
        entrypoint: entrypoint.map(|e| EnginePair {
            both: Some(e.to_string()),
            carrick: None,
            docker: None,
        }),
    }
}

fn s(v: &str) -> String {
    v.to_string()
}

/// Build the full suite list. Returns the suites + (cpython, go, ltp) counts.
fn build() -> (Vec<Suite>, (usize, usize, usize)) {
    use Ecosystem::*;
    use Tier::*;
    use VerdictKind::*;
    use Weight::*;
    let smoke = |yes: bool| if yes { Smoke } else { Full };
    let mut suites = Vec::new();

    // ---- special / hand-shaped suites --------------------------------------
    let go_build_cmd = "cd /tmp && printf 'package main\\nfunc main(){println(\"ok\")}\\n' > h.go && \
         GOCACHE=/tmp/gc /usr/local/go/bin/go build -o /tmp/h ./h.go && /tmp/h && echo BUILD_OK";
    suites.push(mk(
        s("go-build"),
        Go,
        GO_IMG,
        vec![s("/bin/sh"), s("-c"), s(go_build_cmd)],
        Shell,
        Smoke,
        Heavy,
        120,
        Some(s("/tmp")),
        None,
    ));
    for name in ["app-smoke", "v8-smoke"] {
        suites.push(mk(
            format!("node-{name}"),
            Node,
            NODE_IMG,
            vec![
                s("--runner"),
                s("docker"),
                s("--suite"),
                s(name),
                s("--line"),
                s("24"),
                s("--timeout"),
                s("120"),
            ],
            Tap,
            Smoke,
            Heavy,
            180,
            None,
            Some("/usr/local/bin/nodejs-conformance"),
        ));
    }
    suites.push(mk(
        s("node-libuv"),
        Node,
        NODE_IMG,
        vec![
            s("--runner"),
            s("docker"),
            s("--suite"),
            s("libuv"),
            s("--line"),
            s("24"),
            s("--timeout"),
            s("180"),
        ],
        Tap,
        Full,
        Heavy,
        240,
        None,
        Some("/usr/local/bin/nodejs-conformance"),
    ));

    // ---- CPython: one suite per top-level test module ----------------------
    let list = docker_stdout(&[
        "run",
        "--rm",
        CPYTHON_IMG,
        "/usr/local/bin/python3",
        "-m",
        "test",
        "--list-tests",
    ]);
    let mut cpy: Vec<String> = list
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("test"))
        .map(|l| match l.strip_prefix("test.") {
            Some(rest) => rest.split('.').next().unwrap_or(rest).to_string(),
            None => l.to_string(),
        })
        .collect();
    cpy.sort();
    cpy.dedup();
    for m in &cpy {
        let short = m.strip_prefix("test_").unwrap_or(m);
        suites.push(mk(
            format!("cpython-{short}"),
            Cpython,
            CPYTHON_IMG,
            vec![
                s("/usr/local/bin/python3"),
                s("-m"),
                s("test"),
                s("-v"),
                s("--randseed"),
                s("0"),
                s(m),
            ],
            Regrtest,
            smoke(CPY_SMOKE.contains(&m.as_str())),
            Heavy,
            300,
            None,
            None,
        ));
    }

    // ---- Go: one suite per std package with a prebuilt .test ---------------
    let ls = docker_stdout(&[
        "run",
        "--rm",
        GO_IMG,
        "sh",
        "-c",
        "ls /conformance 2>/dev/null",
    ]);
    let pkglist = docker_stdout(&["run", "--rm", GO_IMG, "sh", "-c", "go list std 2>/dev/null"]);
    let pkgs: Vec<String> = pkglist.split_whitespace().map(String::from).collect();
    let mut go: Vec<(String, String)> = ls
        .split_whitespace()
        .filter_map(|b| b.strip_suffix(".test"))
        .map(|binn| {
            let pkg = pkgs
                .iter()
                .find(|p| p.replace('/', "_") == binn)
                .cloned()
                .unwrap_or_else(|| binn.replace('_', "/"));
            (binn.to_string(), pkg)
        })
        .collect();
    go.sort();
    for (binn, pkg) in &go {
        suites.push(mk(
            format!("go-{binn}"),
            Go,
            GO_IMG,
            vec![
                format!("/conformance/{binn}.test"),
                s("-test.v"),
                s("-test.run"),
                s("Test"),
                s("-test.short"),
            ],
            Gotest,
            smoke(GO_SMOKE.contains(&pkg.as_str())),
            Heavy,
            180,
            Some(format!("/usr/local/go/src/{pkg}")),
            None,
        ));
    }

    // ---- LTP: one suite per syscall-family testcase ------------------------
    let bins = docker_stdout(&[
        "run",
        "--rm",
        LTP_IMG,
        "sh",
        "-c",
        "ls /opt/ltp/testcases/bin",
    ]);
    let mut ltp: Vec<String> = bins
        .split_whitespace()
        .filter(|b| LTP_FAMILY_STEMS.contains(&ltp_stem(b)))
        .map(String::from)
        .collect();
    ltp.sort();
    for b in &ltp {
        suites.push(mk(
            format!("ltp-{b}"),
            Ecosystem::Ltp,
            LTP_IMG,
            vec![format!("/opt/ltp/testcases/bin/{b}")],
            VerdictKind::Ltp,
            smoke(LTP_SMOKE.contains(&b.as_str())),
            Light,
            40,
            None,
            None,
        ));
    }

    (suites, (cpy.len(), go.len(), ltp.len()))
}

pub fn generate_suites(out_path: &Path, check_only: bool) -> anyhow::Result<()> {
    let (suite, (c, g, l)) = build();
    let total = suite.len();
    eprintln!("counts: cpython={c} go={g} ltp={l} node=3 go-build=1  TOTAL={total}");
    if check_only {
        return Ok(());
    }
    let header = "# carrick conformance suites — GENERATED by `--generate-suites`\n\
        # (crates/carrick-conformance/src/generate.rs). Do NOT edit by hand;\n\
        # re-run after a container update. tier=smoke -> fast gate\n\
        # (just conformance-quick); tier=full -> 100% coverage.\n\n";
    let body = toml::to_string(&Manifest { suite })?;
    std::fs::write(out_path, format!("{header}{body}"))?;
    eprintln!("wrote {} ({total} suites)", out_path.display());
    Ok(())
}
