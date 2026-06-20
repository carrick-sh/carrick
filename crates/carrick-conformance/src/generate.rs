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

use crate::manifest::{Ecosystem, EnginePair, EnvKv, Manifest, Suite, Tier, VerdictKind, Weight};
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

/// CPython modules that make steady progress but exceed the default full-suite
/// budget under the four-worker HVF matrix run.
const CPYTHON_SLOW: &[&str] = &["test_tarfile"];

/// Go packages whose test suites are CPU-bound-slow (not stuck) under nested
/// KVM or full-load HVF — toolchain subprocess churn (importers' compile/cgo),
/// bulk TLS/HTTP handshakes, and large HTTP/2 test matrices — and need the
/// larger budget (see the timeout comment at the suite construction site).
const GO_SLOW: &[&str] = &[
    "crypto/tls",
    "go/internal/srcimporter",
    "net/http",
    "net/netip",
];
const GO_RUNTIME_SMOKE_RE: &str = "^(Test(FinalizerRegisterABI|UserArena.*|BitCursor|Callers.*|FPUnwindAfterRecovery|Chan|NonblockRecvRace|NonblockSelectRace2?|SelfSelect|SelectStress|SelectFairness|MultiConsumer|ShrinkStackDuringBlockedSend|NoShrinkStackWhileParking|SelectDuplicateChannel|SelectStackAdjust))$";
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

/// LTP binaries that are single manifests but multi-phase tests; the default
/// 40 s syscall-family budget can kill them after valid progress.
const LTP_SLOW: &[&str] = &["epoll-ltp"];

/// LTP coverage is DENYLIST-based: every test binary in the image is a suite
/// unless excluded here. (The original allowlist of syscall-family stems kept
/// the sweep small during bring-up; with both lanes at full parity on that
/// set, coverage now defaults to ON so LTP image updates are auto-covered.)
/// Exclusions, each with a reason:
///  - pure libc/string/allocator tests: exercise musl, not carrick's syscall
///    surface (memcmp/memcpy/memset/string/mallinfo/mallopt/gethostbyname_r).
///  - in-test HELPER binaries a parent test execs (never meaningful alone).
const LTP_EXCLUDED_STEMS: &[&str] = &[
    "memcmp",
    "memcpy",
    "memset",
    "string",
    "mallinfo",
    "mallopt",
    "gethostbyname_r",
];

/// Helper binaries shipped beside their parent test (run BY it, not a test).
const LTP_EXCLUDED_BINS: &[&str] = &["prctl06_execve", "landlock_exec"];

/// A bin is a runnable standalone test iff it has no file extension (scripts/
/// data carry one) and is not a documented helper/exclusion.
fn ltp_is_test(name: &str) -> bool {
    !name.contains('.')
        && !name.ends_with("_child")
        && !name.ends_with("_helper")
        && !LTP_EXCLUDED_BINS.contains(&name)
        && !LTP_EXCLUDED_STEMS.contains(&ltp_stem(name))
}

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

fn cpython_timeout_s(module: &str) -> u64 {
    if CPYTHON_SLOW.contains(&module) {
        600
    } else {
        300
    }
}

fn go_timeout_s(pkg: &str) -> u64 {
    if GO_SLOW.contains(&pkg) { 540 } else { 180 }
}

fn ltp_timeout_s(bin: &str) -> u64 {
    if LTP_SLOW.contains(&bin) { 900 } else { 40 }
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

fn node_suite(mut suite: Suite) -> Suite {
    suite.env.push(EnvKv {
        key: "NODEJS_CONFORMANCE_IN_IMAGE".into(),
        val: "1".into(),
    });
    suite.env_carrick.push(EnvKv {
        key: "NODEJS_CONFORMANCE_EFFECTIVE_RUNNER".into(),
        val: "carrick".into(),
    });
    suite.env_docker.push(EnvKv {
        key: "NODEJS_CONFORMANCE_EFFECTIVE_RUNNER".into(),
        val: "docker".into(),
    });
    suite
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
        suites.push(node_suite(mk(
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
        )));
    }
    let mut libuv = node_suite(mk(
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
    libuv.docker_flags = vec![s("--user"), s("65534")];
    suites.push(libuv);

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
        let mut suite = mk(
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
            cpython_timeout_s(m),
            None,
            None,
        );
        if m == "test_subprocess" {
            // CPython's test_no_leaking expects to hit EMFILE before 1026
            // opens. Docker defaults can be too high, causing the oracle to
            // skip the assertion Carrick exercises.
            suite.docker_flags = vec![s("--ulimit"), s("nofile=1024:1024")];
        }
        suites.push(suite);
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
        let test_run = if pkg == "runtime" {
            GO_RUNTIME_SMOKE_RE
        } else {
            "Test"
        };
        // CPU-bound toolchain/TLS/HTTP suites proven slow-not-stuck under nested
        // KVM or full-load HVF: at the kvm lane's 2x scale, 540 gives the
        // 1080 s ceiling the 6x-budget verification showed sufficient. Docker
        // and unloaded HVF usually finish much faster — upper bound only.
        let timeout_s = go_timeout_s(pkg);
        suites.push(mk(
            format!("go-{binn}"),
            Go,
            GO_IMG,
            vec![
                format!("/conformance/{binn}.test"),
                s("-test.v"),
                s("-test.run"),
                s(test_run),
                s("-test.short"),
            ],
            Gotest,
            smoke(GO_SMOKE.contains(&pkg.as_str())),
            Heavy,
            timeout_s,
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
        .filter(|b| ltp_is_test(b))
        .map(String::from)
        .collect();
    ltp.sort();
    for b in &ltp {
        let mut suite = mk(
            format!("ltp-{b}"),
            Ecosystem::Ltp,
            LTP_IMG,
            vec![format!("/opt/ltp/testcases/bin/{b}")],
            VerdictKind::Ltp,
            smoke(LTP_SMOKE.contains(&b.as_str())),
            Light,
            ltp_timeout_s(b),
            None,
            None,
        );
        if b == "fork09" {
            // fork09 opens fds to RLIMIT_NOFILE; Docker's default (1048576) is
            // far above carrick's, so align the oracle to the same bound the
            // carrick guest sees (same rationale as cpython test_no_leaking).
            suite.docker_flags = vec![s("--ulimit"), s("nofile=1024:1024")];
        }
        suites.push(suite);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_load_slow_suites_have_extended_budgets() {
        assert_eq!(cpython_timeout_s("test_tarfile"), 600);
        assert_eq!(go_timeout_s("net/http"), 540);
        assert_eq!(ltp_timeout_s("epoll-ltp"), 900);
    }

    #[test]
    fn ordinary_suites_keep_default_budgets() {
        assert_eq!(cpython_timeout_s("test_json"), 300);
        assert_eq!(go_timeout_s("net/url"), 180);
        assert_eq!(ltp_timeout_s("gettid01"), 40);
    }
}
