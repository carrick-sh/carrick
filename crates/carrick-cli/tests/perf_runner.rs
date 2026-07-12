//! Differential perf gate: carrick vs Docker, serial adjacent-pair sampling.
//! Self-skips (passes) when the signed binary, Docker, or built probes are
//! absent — so `cargo test` stays green everywhere. Run it deliberately:
//!   just bench           # quick profile (this gate, env-tuned)
//!
//! HARD CONSTRAINT: carrick and Docker never run concurrently here. Every
//! timed sample is one engine process at a time; reps are carrick THEN docker.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod perf_support;

use perf_support::backend_pair::{
    ArtifactIdentity, BACKEND_PAIR_ORDER, BackendEvidenceRow, BackendMeasurement, BackendRun,
    CarrickBackend, collect_backend_pair, comparison_row, validate_same_artifact,
    write_backend_rows_atomic,
};
use perf_support::cases::{BackendPairSupport, CASES, PerfArtifact, PerfCase};
use perf_support::invoke::{self, CPU_PIN, IMAGE};
use perf_support::metric::Metrics;
use perf_support::provenance::{self, HostFacts, ResultRow};
use perf_support::stats::{self, Summary};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

static PERF_LOCK: Mutex<()> = Mutex::new(());

/// The in-memory fs backend is opt-in (`--features fs-memory`); skip perf cases
/// that require it on a default build so the harness never invokes `--fs memory`.
fn case_runnable(case: &PerfCase) -> bool {
    cfg!(feature = "fs-memory") || case.carrick_fs_mode != "memory"
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("carrick-cli under crates/")
        .to_path_buf()
}

fn carrick_bin(root: &Path) -> Option<PathBuf> {
    let p = root.join("target/release/carrick");
    p.exists().then_some(p)
}

fn probe_path(root: &Path, case: &PerfCase) -> PathBuf {
    match case.artifact {
        PerfArtifact::StaticMusl => root.join(format!(
            "conformance-probes/target/aarch64-unknown-linux-musl/release/{}",
            case.probe
        )),
        PerfArtifact::DynamicGlibc => root.join(format!(
            "perf-dynamic/target/aarch64-linux-gnu/release/{}",
            case.probe
        )),
    }
}

fn backend_pair_probe_path(root: &Path, case: &PerfCase) -> PathBuf {
    match case.artifact {
        PerfArtifact::StaticMusl => root.join(format!(
            "conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/{}",
            case.probe
        )),
        PerfArtifact::DynamicGlibc => probe_path(root, case),
    }
}

fn backend_pair_report_path(root: &Path, requested: &Path) -> PathBuf {
    if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        root.join(requested)
    }
}

#[test]
fn backend_pair_uses_native_pie_artifact() {
    let case = CASES
        .iter()
        .find(|case| case.workload == "trap_floor")
        .expect("trap floor case");
    assert_eq!(
        backend_pair_probe_path(Path::new("/repo"), case),
        Path::new(
            "/repo/conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_trap_floor"
        )
    );
}

#[test]
fn backend_pair_report_path_is_root_relative() {
    assert_eq!(
        backend_pair_report_path(Path::new("/repo"), Path::new("docs/perf-results/run.jsonl")),
        Path::new("/repo/docs/perf-results/run.jsonl")
    );
    assert_eq!(
        backend_pair_report_path(Path::new("/repo"), Path::new("/tmp/run.jsonl")),
        Path::new("/tmp/run.jsonl")
    );
}

fn docker_ok() -> bool {
    Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn is_signed(bin: &Path) -> bool {
    Command::new("codesign")
        .args(["-d", "--entitlements", "-"])
        .arg(bin)
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).contains("com.apple.security.hypervisor")
                || String::from_utf8_lossy(&o.stderr).contains("com.apple.security.hypervisor")
        })
        .unwrap_or(false)
}

#[allow(clippy::panic)]
fn ensure_signed(root: &Path, bin: &Path) {
    if is_signed(bin) {
        return;
    }
    let plist = root.join("scripts/entitlements.plist");
    let out = Command::new("codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(&plist)
        .arg(bin)
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
    std::env::var("CARRICK_PERF_REPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
}
fn warmup_reps() -> usize {
    std::env::var("CARRICK_PERF_WARMUP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}
fn cooldown() -> Duration {
    let secs = std::env::var("CARRICK_PERF_COOLDOWN_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);
    Duration::from_secs(secs)
}

/// One engine's per-rep value plus the nproc it reported (for the norm gate).
struct Sample {
    value: Option<f64>,
    nproc: Option<u64>,
}

fn parse_sample(output: &str, metric_key: &str) -> Sample {
    let m = Metrics::parse(output);
    Sample {
        value: m.get_f64(metric_key),
        nproc: m.get_u64("nproc"),
    }
}

fn parse_backend_pair_sample(output: &str, metric_key: &str) -> Result<f64, String> {
    let sample = parse_sample(output, metric_key);
    let nproc = sample
        .nproc
        .ok_or_else(|| "missing normalization metric nproc".to_owned())?;
    if nproc != CPU_PIN as u64 {
        return Err(format!("wrong nproc {nproc}; expected {CPU_PIN}"));
    }
    let value = sample
        .value
        .ok_or_else(|| format!("missing metric {metric_key}"))?;
    if !value.is_finite() {
        return Err(format!("non-finite metric {metric_key}: {value}"));
    }
    Ok(value)
}

#[test]
fn backend_pair_rejects_missing_metric() {
    let error = parse_backend_pair_sample("nproc=4", "trap_p50_us")
        .expect_err("a missing metric must invalidate the report");
    assert!(error.contains("missing metric trap_p50_us"));
}

#[test]
fn backend_pair_rejects_wrong_nproc() {
    let error = parse_backend_pair_sample("trap_p50_us=1.25\nnproc=10", "trap_p50_us")
        .expect_err("an unnormalized sample must invalidate the report");
    assert!(error.contains("wrong nproc 10"));
}

fn run_case(root: &Path, bin: &PathBuf, case: &PerfCase) -> Vec<ResultRow> {
    use base64::Engine as _;
    let probe = probe_path(root, case);
    let raw = std::fs::read(&probe).expect("read probe");
    let b64 = base64::engine::general_purpose::STANDARD
        .encode(&raw)
        .into_bytes();

    // Native (macOS host ceiling) build, if present — optional third engine.
    let native = native_probe_path(root, case.probe);
    let has_native = matches!(case.artifact, PerfArtifact::StaticMusl) && native.exists();
    // For bind-mount cases the native engine writes directly to the host scratch
    // dir (no /mnt); carrick/docker get the dir mounted at /mnt by invoke.
    let native_bench_dir: Option<String> = if case.mount_scratch {
        Some(root.join(".bench-scratch").to_string_lossy().into_owned())
    } else {
        None
    };

    let n = reps();
    let warm = warmup_reps().min(n);
    let mut native_vals: Vec<f64> = Vec::new();
    let mut carrick_vals: Vec<f64> = Vec::new();
    let mut docker_vals: Vec<f64> = Vec::new();
    let mut native_nproc: Option<u64> = None;
    let mut carrick_nproc: Option<u64> = None;
    let mut docker_nproc: Option<u64> = None;
    let mut invalid = 0usize;

    for rep in 0..n {
        // --- native (macos) sample: no carrick, no Docker, no VM (the ceiling) ---
        let nat = if has_native {
            let out = invoke::run_native(&native, native_bench_dir.as_deref());
            std::thread::sleep(cooldown());
            parse_sample(&out, case.metric_key)
        } else {
            Sample {
                value: None,
                nproc: None,
            }
        };
        // --- carrick sample ---
        let c_id = invoke::perf_run_id();
        let c_out = invoke::run_carrick(
            bin,
            root,
            &c_id,
            &probe,
            &b64,
            case.mount_scratch,
            case.carrick_fs_mode,
        );
        std::thread::sleep(cooldown());
        // --- docker sample (serial, never concurrent with carrick) ---
        let d_id = invoke::perf_run_id();
        let d_out = invoke::run_docker(root, &d_id, &b64, case.mount_scratch);
        std::thread::sleep(cooldown());

        let c = parse_sample(&c_out, case.metric_key);
        let d = parse_sample(&d_out, case.metric_key);
        native_nproc = nat.nproc.or(native_nproc);
        carrick_nproc = c.nproc.or(carrick_nproc);
        docker_nproc = d.nproc.or(docker_nproc);

        // CPU-normalization gates ONLY carrick+docker (native sees all host
        // cores — macOS has no cpuset; it is the unpinned ceiling reference).
        let normalized = c.nproc == Some(CPU_PIN as u64) && d.nproc == Some(CPU_PIN as u64);
        let usable = rep >= warm && normalized && c.value.is_some() && d.value.is_some();
        if rep >= warm && !normalized {
            invalid += 1;
            eprintln!(
                "perf[{}] rep {rep}: INVALID (carrick nproc={:?}, docker nproc={:?}, want {CPU_PIN})",
                case.workload, c.nproc, d.nproc
            );
        }
        if usable {
            carrick_vals.push(c.value.unwrap());
            docker_vals.push(d.value.unwrap());
            if let Some(v) = nat.value {
                native_vals.push(v);
            }
        }
        eprintln!(
            "perf[{}] rep {rep}/{n}: macos={:?} carrick={:?} docker={:?}{}",
            case.workload,
            nat.value,
            c.value,
            d.value,
            if rep < warm {
                " (warmup, discarded)"
            } else {
                ""
            }
        );
    }

    assert!(
        !carrick_vals.is_empty() && !docker_vals.is_empty(),
        "perf[{}]: no valid normalized samples ({} invalid of {} reps) — check nproc pinning",
        case.workload,
        invalid,
        n
    );

    let date = today_string();
    let host = HostFacts::capture();
    let digest = provenance::image_digest(IMAGE);
    let sha = provenance::git_sha();
    let mk = |engine: &str, lane: &str, vals: &[f64], nproc: Option<u64>| -> ResultRow {
        let s: Summary = stats::summarize(vals).expect("non-empty");
        let native = engine == "macos";
        ResultRow {
            schema: 2,
            epoch_secs: provenance::epoch_secs(),
            dimension: case.dimension.into(),
            workload: case.workload.into(),
            engine: engine.into(),
            lane: lane.into(),
            metric: case.metric_key.into(),
            unit: case.unit.into(),
            higher_is_better: case.higher_is_better,
            summary: s,
            samples: vals.to_vec(),
            noisy: stats::is_noisy(&s),
            nproc,
            // native is the unpinned host ceiling (macOS has no cpuset); cpu_pin=0
            // records that, while `nproc` carries the real host core count.
            cpu_pin: if native { 0 } else { CPU_PIN },
            fs_mode: match engine {
                "macos" => "native".into(),
                "carrick" => case.carrick_fs_mode.into(),
                _ => "host".into(),
            },
            image: match engine {
                "macos" => "(native macos host)".into(),
                "carrick" if case.carrick_fs_mode == "memory" => "(direct run-elf)".into(),
                _ => IMAGE.into(),
            },
            image_digest: if native || (engine == "carrick" && case.carrick_fs_mode == "memory") {
                None
            } else {
                digest.clone()
            },
            git_sha: sha.clone(),
            run_id: format!("cr-perf-{}", std::process::id()),
            host: host.clone(),
        }
    };
    let mut rows: Vec<ResultRow> = Vec::new();
    if !native_vals.is_empty() {
        rows.push(mk("macos", "native", &native_vals, native_nproc));
    }
    rows.push(mk("carrick", "cold", &carrick_vals, carrick_nproc));
    rows.push(mk("docker", "docker", &docker_vals, docker_nproc));
    // Direction-aware comparison. Locate engines by name (rows now lead with the
    // optional macos row), so the carrick/docker ratio is order-independent.
    let p50_of = |engine: &str| {
        rows.iter()
            .find(|r| r.engine == engine)
            .map(|r| r.summary.p50)
    };
    let cp = p50_of("carrick").unwrap_or(f64::NAN);
    let dp = p50_of("docker").unwrap_or(f64::NAN);
    let np = p50_of("macos");
    let ratio = if dp > 0.0 { cp / dp } else { f64::NAN };
    let winner_is_carrick = if case.higher_is_better {
        cp >= dp
    } else {
        cp <= dp
    };
    let winner = if ratio.is_nan() {
        "?"
    } else if winner_is_carrick {
        "carrick"
    } else {
        "docker"
    };
    // Fold advantage of the winner over the loser (>= 1.0); reads cleanly for
    // both small (1.2x) and huge (2589x) gaps, unlike a raw percentage.
    let factor = {
        let (hi, lo) = (cp.max(dp), cp.min(dp));
        if lo > 0.0 { hi / lo } else { f64::INFINITY }
    };
    for r in &rows {
        provenance::append_row(root, &date, r).expect("append row");
        let tail = if r.engine == "docker" {
            format!(
                "  ratio(c/d)={ratio:.3}  WINNER={winner} ({factor:.2}x {})",
                if case.higher_is_better {
                    "throughput"
                } else {
                    "latency"
                }
            )
        } else {
            String::new()
        };
        eprintln!(
            "perf[{}] {} {}={:.3}{} p95={:.3} (n={}){}{}",
            case.workload,
            r.engine,
            r.metric,
            r.summary.p50,
            r.unit,
            r.summary.p95,
            r.summary.n,
            if r.noisy { " NOISY" } else { "" },
            tail
        );
    }
    // vs-native efficiency: engine/macos on the raw metric (macos = unpinned host
    // ceiling). Throughput (higher better): <1 = below ceiling. Latency (lower
    // better): >1 = above the ceiling (carrick/docker overhead over native).
    if let Some(np) = np.filter(|v| *v > 0.0) {
        eprintln!(
            "perf[{}] vs-native: carrick={:.2}x docker={:.2}x (engine/macos; macos={:.3}{} ceiling, unpinned {} cores)",
            case.workload,
            cp / np,
            dp / np,
            np,
            case.unit,
            native_nproc
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into())
        );
    }
    rows
}

/// Native (aarch64-apple-darwin) build of a probe, from the standalone
/// `bench-native` crate. Optional third engine ("macos" = host ceiling).
fn native_probe_path(root: &Path, name: &str) -> PathBuf {
    root.join(format!("bench-native/target/release/{name}"))
}

/// YYYY-MM-DD from `date` (avoids a chrono dep).
fn today_string() -> String {
    Command::new("date")
        .args(["+%Y-%m-%d"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown-date".into())
}

const BACKEND_BOOTSTRAP_SEED: u64 = 0x4e31_364b_2d48_5646;
const BACKEND_BOOTSTRAP_RESAMPLES: usize = 10_000;

fn run_backend_pair_report() -> Result<(), String> {
    let _serial = PERF_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let root = repo_root();
    let bin = carrick_bin(&root)
        .ok_or_else(|| "target/release/carrick not built; run `just build`".to_owned())?;
    ensure_signed(&root, &bin);
    let requested_report = std::env::var_os("CARRICK_BACKEND_REPORT")
        .map(PathBuf::from)
        .ok_or_else(|| "CARRICK_BACKEND_REPORT is required".to_owned())?;
    let report = backend_pair_report_path(&root, &requested_report);
    if let Some(parent) = report.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create backend report directory: {error}"))?;
    }

    let filter = std::env::var("CARRICK_PERF_FILTER").ok();
    let mut rows = vec![BackendEvidenceRow::Run(BackendRun {
        schema: 1,
        epoch_secs: provenance::epoch_secs(),
        schedule: BACKEND_PAIR_ORDER,
        bootstrap_seed: BACKEND_BOOTSTRAP_SEED,
        bootstrap_resamples: BACKEND_BOOTSTRAP_RESAMPLES,
        git_sha: provenance::git_sha(),
        host: HostFacts::capture(),
    })];

    for case in CASES {
        if filter
            .as_ref()
            .is_some_and(|value| !case.workload.contains(value))
        {
            continue;
        }
        if let BackendPairSupport::Unsupported(reason) = case.backend_pair_support {
            rows.push(BackendEvidenceRow::Skip(
                perf_support::backend_pair::BackendSkip {
                    workload: case.workload.to_owned(),
                    reason: reason.to_owned(),
                },
            ));
            continue;
        }

        let probe = backend_pair_probe_path(&root, case);
        if !probe.exists() {
            return Err(format!(
                "backend pair probe {} is missing; run scripts/build-probes.sh",
                probe.display()
            ));
        }
        let artifact_before = ArtifactIdentity::from_file(case.probe, &probe)
            .map_err(|error| format!("identify probe {}: {error}", probe.display()))?;
        let mut run_sample = |backend| {
            let output =
                invoke::run_carrick_backend(&bin, &root, backend, &probe, case.guest_args)?;
            parse_backend_pair_sample(&output, case.metric_key)
                .map_err(|error| format!("{} {backend:?}: {error}", case.workload))
        };
        let warmups = warmup_reps();
        if warmups > 0 {
            collect_backend_pair(warmups, cooldown(), &mut run_sample)
                .map_err(|error| format!("{} warmup: {error}", case.workload))?;
        }
        let samples = collect_backend_pair(reps(), cooldown(), run_sample)?;
        let artifact_after = ArtifactIdentity::from_file(case.probe, &probe)
            .map_err(|error| format!("re-identify probe {}: {error}", probe.display()))?;
        validate_same_artifact(&artifact_before, &artifact_after)?;
        let native_summary = stats::summarize(&samples.native16k)
            .ok_or_else(|| format!("{}: too few native16k samples", case.workload))?;
        let hvf_summary = stats::summarize(&samples.hvf)
            .ok_or_else(|| format!("{}: too few HVF samples", case.workload))?;
        rows.push(BackendEvidenceRow::Measurement(BackendMeasurement {
            workload: case.workload.to_owned(),
            backend: CarrickBackend::Native16k,
            artifact: artifact_before.clone(),
            metric: case.metric_key.to_owned(),
            unit: case.unit.to_owned(),
            higher_is_better: case.higher_is_better,
            samples: samples.native16k.clone(),
            summary: native_summary,
        }));
        rows.push(BackendEvidenceRow::Measurement(BackendMeasurement {
            workload: case.workload.to_owned(),
            backend: CarrickBackend::Hvf,
            artifact: artifact_before,
            metric: case.metric_key.to_owned(),
            unit: case.unit.to_owned(),
            higher_is_better: case.higher_is_better,
            samples: samples.hvf.clone(),
            summary: hvf_summary,
        }));
        let mut comparison = comparison_row(
            case.workload,
            case.higher_is_better,
            &samples.native16k,
            &samples.hvf,
            BACKEND_BOOTSTRAP_SEED,
            BACKEND_BOOTSTRAP_RESAMPLES,
        )
        .ok_or_else(|| format!("{}: too few samples for comparison", case.workload))?;
        comparison.metric = case.metric_key.to_owned();
        comparison.unit = case.unit.to_owned();
        rows.push(BackendEvidenceRow::Comparison(comparison));
    }

    write_backend_rows_atomic(&report, &rows)
        .map_err(|error| format!("write {}: {error}", report.display()))
}

#[test]
#[ignore = "requires signed carrick and deliberate serial native16k/HVF sampling"]
fn backend_pair_report() {
    run_backend_pair_report().expect("backend-pair report");
}

#[test]
fn perf_gate() {
    // PERF_LOCK only serializes within THIS test binary. The hard constraint
    // (carrick and Docker never run concurrently during a timed sample) holds
    // because the benchmark is invoked as `just bench` == `cargo test --test
    // perf_runner perf_gate` ONLY — never alongside the conformance suite. Do
    // NOT run `cargo test -p carrick-cli` (all binaries) with the signed binary
    // + Docker + built probes present: that could let perf_gate overlap a
    // conformance case across the two test processes. The structural fix is a
    // cross-process flock (fd-lock) acquired by BOTH this gate and conformance;
    // it is a deferred hardening (see the benchmark design doc, §9 / deferred).
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
    // Optional subset: CARRICK_PERF_FILTER=<substr> runs only matching workloads.
    // Apply it to the availability check too, so a focused DSR measurement is
    // not skipped because an unrelated probe family has not been built.
    let filter = std::env::var("CARRICK_PERF_FILTER").ok();
    // All selected probes built?
    for case in CASES {
        if !case_runnable(case) {
            continue;
        }
        if let Some(f) = &filter
            && !case.workload.contains(f.as_str())
        {
            continue;
        }
        if !probe_path(&root, case).exists() {
            let build_hint = match case.artifact {
                PerfArtifact::StaticMusl => "scripts/build-probes.sh",
                PerfArtifact::DynamicGlibc => "scripts/build-dynamic-perf.sh",
            };
            eprintln!(
                "SKIP perf_gate: probe {} not built (run {build_hint})",
                case.probe,
            );
            return;
        }
    }
    ensure_signed(&root, &bin);

    let date = today_string();
    for case in CASES {
        if !case_runnable(case) {
            continue;
        }
        if let Some(f) = &filter
            && !case.workload.contains(f.as_str())
        {
            continue;
        }
        if case.cross_boundary {
            perf_support::xboundary::run_cross_boundary(
                &root,
                &bin,
                case,
                reps(),
                warmup_reps().min(reps()),
                cooldown(),
                &date,
            );
        } else {
            run_case(&root, &bin, case);
        }
    }
}
