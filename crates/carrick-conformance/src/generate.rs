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

const LTP_NOFILE_4096: &[&str] = &["dup03", "dup06", "dup205"];

/// Oracle-fidelity docker_flags that must survive `--generate-suites`.
/// clone3 template: lift the container seccomp default so BOTH engines run the
/// real syscall (carrick then returns ENOSYS for unimplemented). Hand-edits to
/// the generated suites.toml do NOT survive regen — this table is their home.
/// Matched by EXACT suite name.
const DOCKER_FLAG_OVERRIDES: &[(&str, &[&str])] = &[
    ("ltp-clone301", &["--security-opt", "seccomp=unconfined"]),
    ("ltp-clone302", &["--security-opt", "seccomp=unconfined"]),
];

/// Oracle-fidelity docker_flags matched by suite-name PREFIX (family stem), so a
/// whole LTP family shares one entry (add_key01..05, keyctl01..09, …) without
/// enumerating every binary. Same intent as [`DOCKER_FLAG_OVERRIDES`]: run the
/// oracle against the REAL syscall (not the seccomp-blocked container) so the
/// comparison reflects true Linux capability, not the container's policy.
/// (`docker_flags` is part of the oracle cache determinant, so a changed entry
/// forces a live re-run — never a stale confined result.)
const DOCKER_FLAG_PREFIX_OVERRIDES: &[(&str, &[&str])] = &[
    // Keyring: real Linux allows UNPRIVILEGED user keyrings; the container's
    // default seccomp blocks add_key/request_key/keyctl. Unconfine so the
    // oracle runs the real syscall — carrick then honestly returns ENOSYS and
    // the suite's known_gap ("summary") keeps that divergence report-only.
    ("ltp-add_key", &["--security-opt", "seccomp=unconfined"]),
    ("ltp-request_key", &["--security-opt", "seccomp=unconfined"]),
    ("ltp-keyctl", &["--security-opt", "seccomp=unconfined"]),
    // pidfd_getfd additionally needs CAP_SYS_PTRACE to reach into the target
    // process's fd table.
    (
        "ltp-pidfd_getfd",
        &[
            "--security-opt",
            "seccomp=unconfined",
            "--cap-add",
            "SYS_PTRACE",
        ],
    ),
    // setrlimit: raising a previously-lowered hard cap needs CAP_SYS_RESOURCE.
    // Grant it (plus unconfine, template-consistent) so the root oracle matches
    // the now-privilege-gated root carrick guest. The raise-tests (setrlimit02/
    // 04/05) then MATCH honestly — that IS the euid-gate fix, verified. The
    // enforcement-tests (01/03) still DIFF on genuine carrick gaps and carry a
    // known_gap (see below). setrlimit06 is EXCLUDED entirely (see
    // OVERRIDE_EXCLUSIONS).
    (
        "ltp-setrlimit",
        &[
            "--security-opt",
            "seccomp=unconfined",
            "--cap-add",
            "SYS_RESOURCE",
        ],
    ),
    // fanotify_init needs CAP_SYS_ADMIN. Grant it (plus unconfine) so the
    // oracle can attempt the real syscall — carrick has no fanotify backend
    // and honestly returns ENOSYS, so the divergence is report-only (see
    // known_gap below), not a fabricated EPERM match against the container's
    // seccomp policy.
    (
        "ltp-fanotify",
        &[
            "--security-opt",
            "seccomp=unconfined",
            "--cap-add",
            "SYS_ADMIN",
        ],
    ),
];

/// Suites a prefix override would otherwise capture but MUST NOT: they need a
/// deeper runtime fix, not oracle-fidelity flags, and unconfining them would
/// only convert a fake match into a gating TIMEOUT/REGRESSION.
///  - setrlimit06 tests RLIMIT_CPU ENFORCEMENT: the child burns CPU expecting
///    SIGXCPU (soft limit) then SIGKILL (hard limit). carrick does not enforce
///    RLIMIT_CPU, so the runaway child is never killed and the test spins until
///    the LTP framework timeout. The real fix is CPU-limit enforcement (tracked
///    separately) — NOT a longer budget — so leave 06 exactly as committed.
const OVERRIDE_EXCLUSIONS: &[&str] = &["ltp-setrlimit06"];

/// Suites whose single LTP `"summary"` divergence is a TRACKED-unimplemented-
/// capability marker (maintainer-approved report-only), NOT an edge-case excuse.
/// keyring, pidfd_getfd, and fanotify have no carrick backend: with the oracle
/// unconfined the docker side runs the real syscall and SUCCEEDS while carrick
/// returns ENOSYS, so they legitimately DIFF. Stamping the `"summary"` id known
/// keeps the gate green while the gap stays visible. Matched by PREFIX.
/// `"summary"` is the ONLY id the LTP parser emits (see parsers/ltp.rs), so it
/// is the exact diverging id — verified empirically from a focused oracle run,
/// not invented.
const KNOWN_GAP_PREFIX_OVERRIDES: &[(&str, &[&str])] = &[
    ("ltp-add_key", &["summary"]),
    ("ltp-request_key", &["summary"]),
    ("ltp-keyctl", &["summary"]),
    ("ltp-pidfd_getfd", &["summary"]),
    ("ltp-fanotify", &["summary"]),
];

/// Exact-name known_gaps for suites that a whole-family prefix would over-mark.
/// The setrlimit family mostly MATCHes with the unconfined+cap oracle (the
/// euid-gate raise-fix); only this one DIFFs on a genuine, orthogonal carrick
/// gap, so ONLY it is report-only (02/03/04/05 stay clean MATCHes):
///  - setrlimit01: RLIMIT_FSIZE is not enforced — a child writes 26 bytes where
///    real Linux caps the file at the 10-byte limit (setrlimit01.c:184).
///
/// setrlimit03 (a privileged raise of RLIMIT_NOFILE above the system max must
/// return EPERM even for root) used to be report-only, but carrick now enforces
/// the nr_open ceiling on NOFILE hard-raises regardless of euid, so it MATCHes.
const KNOWN_GAP_EXACT_OVERRIDES: &[(&str, &[&str])] = &[("ltp-setrlimit01", &["summary"])];

fn docker_flag_overrides(name: &str) -> Option<Vec<String>> {
    if OVERRIDE_EXCLUSIONS.contains(&name) {
        return None;
    }
    DOCKER_FLAG_OVERRIDES
        .iter()
        .find(|(n, _)| *n == name)
        .or_else(|| {
            DOCKER_FLAG_PREFIX_OVERRIDES
                .iter()
                .find(|(p, _)| name.starts_with(p))
        })
        .map(|(_, f)| f.iter().map(|s| s.to_string()).collect())
}

fn known_gap_overrides(name: &str) -> Option<Vec<String>> {
    if OVERRIDE_EXCLUSIONS.contains(&name) {
        return None;
    }
    KNOWN_GAP_EXACT_OVERRIDES
        .iter()
        .find(|(n, _)| *n == name)
        .or_else(|| {
            KNOWN_GAP_PREFIX_OVERRIDES
                .iter()
                .find(|(p, _)| name.starts_with(p))
        })
        .map(|(_, g)| g.iter().map(|s| s.to_string()).collect())
}

/// LTP binaries that are single manifests but multi-phase tests; the default
/// 40 s syscall-family budget can kill them after valid progress. Keep these
/// budgets close to the oracle: a pathological failure must not hold a
/// fail-fast drain for many minutes.
const LTP_SLOW: &[&str] = &["epoll-ltp"];
const LTP_SLOW_TIMEOUT_S: u64 = 120;

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
    if LTP_SLOW.contains(&bin) {
        LTP_SLOW_TIMEOUT_S
    } else {
        40
    }
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
        let cmd = if LTP_NOFILE_4096.contains(&b.as_str()) {
            vec![format!("ulimit -n 4096; /opt/ltp/testcases/bin/{b}")]
        } else {
            vec![format!("/opt/ltp/testcases/bin/{b}")]
        };
        let mut suite = mk(
            format!("ltp-{b}"),
            Ecosystem::Ltp,
            LTP_IMG,
            cmd,
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

    for s in &mut suites {
        if let Some(f) = docker_flag_overrides(&s.name) {
            s.docker_flags = f;
        }
        if let Some(g) = known_gap_overrides(&s.name) {
            s.known_gaps = g;
        }
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
        assert_eq!(ltp_timeout_s("epoll-ltp"), 120);
    }

    #[test]
    fn ordinary_suites_keep_default_budgets() {
        assert_eq!(cpython_timeout_s("test_json"), 300);
        assert_eq!(go_timeout_s("net/url"), 180);
        assert_eq!(ltp_timeout_s("gettid01"), 40);
    }

    /// Guards against a repeat of the regen that silently dropped the
    /// `docker_flags = ["--security-opt", "seccomp=unconfined"]` lines from
    /// ltp-clone301/302: reads the COMMITTED manifest straight off disk (not
    /// `build()` — that shells to docker) and asserts the oracle-fidelity
    /// flag is still there.
    #[test]
    fn committed_suites_preserve_manual_docker_flags() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/conformance/suites.toml"
        ))
        .unwrap();
        let m = Manifest::from_toml(&text).unwrap();
        for name in ["ltp-clone301", "ltp-clone302"] {
            let s = m.suite.iter().find(|s| s.name == name).unwrap();
            assert!(
                s.docker_flags.iter().any(|f| f == "seccomp=unconfined"),
                "{name} lost seccomp=unconfined"
            );
        }
    }

    /// The keyring/pidfd_getfd/setrlimit/fanotify oracle-fidelity flags (and
    /// the keyring/pidfd/fanotify known_gaps) must be present in the COMMITTED
    /// manifest so a future regen without them is caught. Reads suites.toml off
    /// disk (not `build()`, which shells to docker).
    #[test]
    fn committed_suites_carry_oracle_fidelity_flags_and_gaps() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/conformance/suites.toml"
        ))
        .unwrap();
        let m = Manifest::from_toml(&text).unwrap();
        let find = |name: &str| m.suite.iter().find(|s| s.name == name).unwrap();
        // Keyring: unconfined oracle + known_gap "summary" (report-only).
        for name in ["ltp-add_key02", "ltp-keyctl01", "ltp-request_key01"] {
            let s = find(name);
            assert!(
                s.docker_flags.iter().any(|f| f == "seccomp=unconfined"),
                "{name} lost seccomp=unconfined"
            );
            assert!(
                s.known_gaps.iter().any(|g| g == "summary"),
                "{name} lost known_gap summary"
            );
        }
        // pidfd_getfd: unconfined + CAP_SYS_PTRACE + known_gap "summary".
        for name in ["ltp-pidfd_getfd01", "ltp-pidfd_getfd02"] {
            let s = find(name);
            assert!(
                s.docker_flags.iter().any(|f| f == "seccomp=unconfined"),
                "{name} lost seccomp=unconfined"
            );
            assert!(
                s.docker_flags.iter().any(|f| f == "SYS_PTRACE"),
                "{name} lost cap SYS_PTRACE"
            );
            assert!(
                s.known_gaps.iter().any(|g| g == "summary"),
                "{name} lost known_gap summary"
            );
        }
        // fanotify: unconfined + CAP_SYS_ADMIN + known_gap "summary" (no
        // carrick backend — report-only).
        for name in ["ltp-fanotify02", "ltp-fanotify04", "ltp-fanotify07"] {
            let s = find(name);
            assert!(
                s.docker_flags.iter().any(|f| f == "seccomp=unconfined"),
                "{name} lost seccomp=unconfined"
            );
            assert!(
                s.docker_flags.iter().any(|f| f == "SYS_ADMIN"),
                "{name} lost cap SYS_ADMIN"
            );
            assert!(
                s.known_gaps.iter().any(|g| g == "summary"),
                "{name} lost known_gap summary"
            );
        }
        // setrlimit01: unconfined + CAP_SYS_RESOURCE + known_gap "summary"
        // (genuine FSIZE-enforcement gap — report-only).
        for name in ["ltp-setrlimit01"] {
            let s = find(name);
            assert!(
                s.docker_flags.iter().any(|f| f == "SYS_RESOURCE"),
                "{name} lost cap SYS_RESOURCE"
            );
            assert!(
                s.known_gaps.iter().any(|g| g == "summary"),
                "{name} lost known_gap summary"
            );
        }
        // setrlimit02/03/04/05: unconfined + CAP_SYS_RESOURCE and DELIBERATELY no
        // gap. 02/04/05 are root-raise tests that MATCH via the euid-gate fix; 03
        // MATCHes now that carrick enforces the nr_open ceiling on NOFILE
        // hard-raises even for root (dropping its former report-only marker).
        for name in [
            "ltp-setrlimit02",
            "ltp-setrlimit03",
            "ltp-setrlimit04",
            "ltp-setrlimit05",
        ] {
            let s = find(name);
            assert!(
                s.docker_flags.iter().any(|f| f == "SYS_RESOURCE"),
                "{name} lost cap SYS_RESOURCE"
            );
            assert!(
                s.known_gaps.is_empty(),
                "{name} must not carry a known_gap (should MATCH)"
            );
        }
        // setrlimit06 is EXCLUDED (RLIMIT_CPU enforcement gap, needs a real fix
        // not a longer budget) — no docker_flags, no known_gap, untouched.
        let s6 = find("ltp-setrlimit06");
        assert!(
            s6.docker_flags.is_empty(),
            "ltp-setrlimit06 must stay unconfined-free (excluded)"
        );
        assert!(
            s6.known_gaps.is_empty(),
            "ltp-setrlimit06 must not carry a known_gap (excluded)"
        );
    }

    #[test]
    fn manual_docker_flag_overrides_survive_regen() {
        assert_eq!(
            docker_flag_overrides("ltp-clone301"),
            Some(vec!["--security-opt".into(), "seccomp=unconfined".into()])
        );
        assert_eq!(
            docker_flag_overrides("ltp-clone302"),
            Some(vec!["--security-opt".into(), "seccomp=unconfined".into()])
        );
        assert_eq!(docker_flag_overrides("ltp-clone303"), None);
    }

    /// Family-prefix / exact overrides cover the right binaries with the right
    /// caps and known_gaps, and honor the setrlimit06 exclusion.
    #[test]
    fn family_prefix_overrides_apply() {
        // keyring: unconfined, no cap, known_gap summary.
        for name in [
            "ltp-add_key01",
            "ltp-add_key05",
            "ltp-keyctl09",
            "ltp-request_key06",
        ] {
            let f = docker_flag_overrides(name).unwrap();
            assert!(f.iter().any(|x| x == "seccomp=unconfined"), "{name}");
            assert!(!f.iter().any(|x| x == "SYS_PTRACE"), "{name}");
            assert_eq!(
                known_gap_overrides(name),
                Some(vec!["summary".into()]),
                "{name}"
            );
        }
        // pidfd_getfd: unconfined + SYS_PTRACE + known_gap summary.
        let f = docker_flag_overrides("ltp-pidfd_getfd01").unwrap();
        assert!(f.iter().any(|x| x == "SYS_PTRACE"));
        assert_eq!(
            known_gap_overrides("ltp-pidfd_getfd02"),
            Some(vec!["summary".into()])
        );
        // pidfd_open/pidfd_send_signal are genuinely implemented — no override.
        assert_eq!(docker_flag_overrides("ltp-pidfd_open01"), None);
        assert_eq!(known_gap_overrides("ltp-pidfd_send_signal01"), None);
        // fanotify: unconfined + SYS_ADMIN + known_gap summary.
        let f = docker_flag_overrides("ltp-fanotify02").unwrap();
        assert!(f.iter().any(|x| x == "seccomp=unconfined"));
        assert!(f.iter().any(|x| x == "SYS_ADMIN"));
        assert_eq!(
            known_gap_overrides("ltp-fanotify07"),
            Some(vec!["summary".into()])
        );
        // setrlimit01-05: unconfined + SYS_RESOURCE. Only 01 (FSIZE-enforcement
        // gap) gets a known_gap; 02/03/04/05 MATCH -> no gap (03 now enforces the
        // nr_open ceiling on NOFILE hard-raises even for root).
        for name in [
            "ltp-setrlimit01",
            "ltp-setrlimit02",
            "ltp-setrlimit03",
            "ltp-setrlimit04",
            "ltp-setrlimit05",
        ] {
            let f = docker_flag_overrides(name).unwrap();
            assert!(f.iter().any(|x| x == "SYS_RESOURCE"), "{name}");
        }
        assert_eq!(
            known_gap_overrides("ltp-setrlimit01"),
            Some(vec!["summary".into()])
        );
        assert_eq!(known_gap_overrides("ltp-setrlimit02"), None);
        assert_eq!(known_gap_overrides("ltp-setrlimit03"), None);
        assert_eq!(known_gap_overrides("ltp-setrlimit04"), None);
        assert_eq!(known_gap_overrides("ltp-setrlimit05"), None);
        // setrlimit06: EXCLUDED from both overrides (RLIMIT_CPU enforcement gap).
        assert_eq!(docker_flag_overrides("ltp-setrlimit06"), None);
        assert_eq!(known_gap_overrides("ltp-setrlimit06"), None);
    }
}
