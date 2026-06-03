//! Differential perf gate: carrick vs Docker, serial adjacent-pair sampling.
//! Self-skips (passes) when the signed binary, Docker, or built probes are
//! absent — so `cargo test` stays green everywhere. Run it deliberately:
//!   just bench           # quick profile (this gate, env-tuned)
//!
//! HARD CONSTRAINT: carrick and Docker never run concurrently here. Every
//! timed sample is one engine process at a time; reps are carrick THEN docker.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod perf_support;

use perf_support::cases::{PerfCase, CASES};
use perf_support::invoke::{self, CPU_PIN, IMAGE};
use perf_support::metric::Metrics;
use perf_support::provenance::{self, HostFacts, ResultRow};
use perf_support::stats::{self, Summary};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

static PERF_LOCK: Mutex<()> = Mutex::new(());

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().and_then(|p| p.parent())
        .expect("carrick-cli under crates/")
        .to_path_buf()
}

fn carrick_bin(root: &Path) -> Option<PathBuf> {
    let p = root.join("target/release/carrick");
    p.exists().then_some(p)
}

fn probe_path(root: &Path, name: &str) -> PathBuf {
    root.join(format!(
        "conformance-probes/target/aarch64-unknown-linux-musl/release/{name}"
    ))
}

fn docker_ok() -> bool {
    Command::new("docker").arg("version")
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}

fn is_signed(bin: &Path) -> bool {
    Command::new("codesign").args(["-d", "--entitlements", "-"]).arg(bin).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("com.apple.security.hypervisor")
              || String::from_utf8_lossy(&o.stderr).contains("com.apple.security.hypervisor"))
        .unwrap_or(false)
}

fn ensure_signed(root: &Path, bin: &Path) {
    if is_signed(bin) { return; }
    let plist = root.join("scripts/entitlements.plist");
    let out = Command::new("codesign")
        .args(["--force", "--sign", "-", "--entitlements"]).arg(&plist).arg(bin)
        .output();
    match out {
        Ok(o) if o.status.success() => {}
        Ok(o) => panic!("codesign failed: {}", String::from_utf8_lossy(&o.stderr)),
        Err(e) => panic!("codesign could not run: {e}"),
    }
}

/// Profile knobs (env-overridable so `just bench` quick vs full can tune them
/// without recompiling). Defaults = quick profile.
fn reps() -> usize {
    std::env::var("CARRICK_PERF_REPS").ok().and_then(|s| s.parse().ok()).unwrap_or(5)
}
fn warmup_reps() -> usize {
    std::env::var("CARRICK_PERF_WARMUP").ok().and_then(|s| s.parse().ok()).unwrap_or(1)
}
fn cooldown() -> Duration {
    let secs = std::env::var("CARRICK_PERF_COOLDOWN_SECS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(15);
    Duration::from_secs(secs)
}

/// One engine's per-rep value plus the nproc it reported (for the norm gate).
struct Sample { value: Option<f64>, nproc: Option<u64> }

fn parse_sample(output: &str, metric_key: &str) -> Sample {
    let m = Metrics::parse(output);
    Sample { value: m.get_f64(metric_key), nproc: m.get_u64("nproc") }
}

fn run_case(root: &Path, bin: &PathBuf, case: &PerfCase) -> Vec<ResultRow> {
    use base64::Engine as _;
    let probe = probe_path(root, case.probe);
    let raw = std::fs::read(&probe).expect("read probe");
    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw).into_bytes();

    let n = reps();
    let warm = warmup_reps().min(n);
    let mut carrick_vals: Vec<f64> = Vec::new();
    let mut docker_vals: Vec<f64> = Vec::new();
    let mut carrick_nproc: Option<u64> = None;
    let mut docker_nproc: Option<u64> = None;
    let mut invalid = 0usize;

    for rep in 0..n {
        // --- carrick sample ---
        let c_id = invoke::perf_run_id();
        let c_out = invoke::run_carrick(bin, root, &c_id, &b64);
        std::thread::sleep(cooldown());
        // --- docker sample (adjacent, never concurrent) ---
        let d_id = invoke::perf_run_id();
        let d_out = invoke::run_docker(root, &d_id, &b64);
        std::thread::sleep(cooldown());

        let c = parse_sample(&c_out, case.metric_key);
        let d = parse_sample(&d_out, case.metric_key);
        carrick_nproc = c.nproc.or(carrick_nproc);
        docker_nproc = d.nproc.or(docker_nproc);

        // CPU-normalization gate: both engines must report nproc==CPU_PIN, else
        // the rep is INVALID and excluded (per the design's fail-fast rule).
        let normalized = c.nproc == Some(CPU_PIN as u64) && d.nproc == Some(CPU_PIN as u64);
        let usable = rep >= warm && normalized && c.value.is_some() && d.value.is_some();
        if rep >= warm && !normalized {
            invalid += 1;
            eprintln!("perf[{}] rep {rep}: INVALID (carrick nproc={:?}, docker nproc={:?}, want {CPU_PIN})",
                      case.workload, c.nproc, d.nproc);
        }
        if usable {
            carrick_vals.push(c.value.unwrap());
            docker_vals.push(d.value.unwrap());
        }
        eprintln!("perf[{}] rep {rep}/{n}: carrick={:?} docker={:?}{}",
                  case.workload, c.value, d.value,
                  if rep < warm { " (warmup, discarded)" } else { "" });
    }

    assert!(!carrick_vals.is_empty() && !docker_vals.is_empty(),
        "perf[{}]: no valid normalized samples ({} invalid of {} reps) — check nproc pinning",
        case.workload, invalid, n);

    let date = today_string();
    let host = HostFacts::capture();
    let digest = provenance::image_digest(IMAGE);
    let sha = provenance::git_sha();
    let mk = |engine: &str, lane: &str, vals: &[f64], nproc: Option<u64>| -> ResultRow {
        let s: Summary = stats::summarize(vals).expect("non-empty");
        ResultRow {
            schema: 1,
            epoch_secs: provenance::epoch_secs(),
            dimension: case.dimension.into(),
            workload: case.workload.into(),
            engine: engine.into(),
            lane: lane.into(),
            metric: case.metric_key.into(),
            unit: case.unit.into(),
            summary: s,
            samples: vals.to_vec(),
            noisy: stats::is_noisy(&s),
            nproc,
            cpu_pin: CPU_PIN,
            fs_mode: "host".into(),
            image: IMAGE.into(),
            image_digest: digest.clone(),
            git_sha: sha.clone(),
            run_id: format!("cr-perf-{}", std::process::id()),
            host: host.clone(),
        }
    };
    let rows = vec![
        mk("carrick", "cold", &carrick_vals, carrick_nproc),
        mk("docker", "docker", &docker_vals, docker_nproc),
    ];
    for r in &rows {
        provenance::append_row(root, &date, r).expect("append row");
        let ratio = rows[0].summary.p50 / rows[1].summary.p50;
        eprintln!("perf[{}] {} {}={:.3}{} p95={:.3} (n={}){}",
            case.workload, r.engine, r.metric, r.summary.p50, r.unit, r.summary.p95, r.summary.n,
            if r.engine == "docker" { format!("  RATIO carrick/docker={ratio:.2}") } else { String::new() });
    }
    rows
}

/// YYYY-MM-DD from `date` (avoids a chrono dep).
fn today_string() -> String {
    Command::new("date").args(["+%Y-%m-%d"]).output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown-date".into())
}

#[test]
fn perf_gate() {
    let _serial = PERF_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let root = repo_root();

    let Some(bin) = carrick_bin(&root) else {
        eprintln!("SKIP perf_gate: target/release/carrick not built (run `just build`)");
        return;
    };
    if !docker_ok() {
        eprintln!("SKIP perf_gate: Docker not reachable");
        return;
    }
    // All probes built?
    for case in CASES {
        if !probe_path(&root, case.probe).exists() {
            eprintln!("SKIP perf_gate: probe {} not built (run scripts/build-probes.sh)", case.probe);
            return;
        }
    }
    ensure_signed(&root, &bin);

    for case in CASES {
        run_case(&root, &bin, case);
    }
}
