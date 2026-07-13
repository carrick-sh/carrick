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
    CarrickBackend, collect_backend_pair, comparison_row, v8_artifact_identity,
    validate_same_artifact, write_backend_rows_atomic,
};
use perf_support::cases::{BackendPairSupport, CASES, PerfArtifact, PerfCase};
use perf_support::invoke::{self, CPU_PIN, IMAGE};
use perf_support::metric::Metrics;
use perf_support::provenance::{self, HostFacts, ResultRow};
use perf_support::stats::{self, Summary};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static PERF_LOCK: Mutex<()> = Mutex::new(());

const V8_IMAGE: &str = "localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0";
const V8_ENTRYPOINT: &str = "/opt/nodejs-conformance/bin/node24";
const V8_SCRIPT: &str = "/opt/nodejs-conformance/fixtures/v8-smoke.js";
const V8_MAX_TRAPS: &str = "18446744073709551615";
const V8_SAMPLE_DEADLINE: Duration = Duration::from_secs(120);

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

fn v8_backend_args(backend: CarrickBackend, immutable_image: &str) -> Vec<String> {
    let mut args = vec![
        "run".to_owned(),
        "--max-traps".to_owned(),
        V8_MAX_TRAPS.to_owned(),
        "--raw".to_owned(),
        "--fs".to_owned(),
        "host".to_owned(),
        "--entrypoint".to_owned(),
        V8_ENTRYPOINT.to_owned(),
    ];
    match backend {
        CarrickBackend::Native16k => args.extend([
            "--exec-backend".to_owned(),
            "native".to_owned(),
            "--native-page-profile".to_owned(),
            "native16k".to_owned(),
        ]),
        CarrickBackend::Hvf => {
            args.extend(["--exec-backend".to_owned(), "hvf".to_owned()]);
        }
    }
    args.extend([immutable_image.to_owned(), V8_SCRIPT.to_owned()]);
    args
}

fn immutable_v8_artifact(repo_digest: &str) -> Result<(String, ArtifactIdentity), String> {
    let (_, digest) = repo_digest
        .rsplit_once('@')
        .ok_or_else(|| "V8 image inspection did not return a repo@digest reference".to_owned())?;
    let identity = v8_artifact_identity(digest)?;
    Ok((repo_digest.to_owned(), identity))
}

fn resolve_v8_artifact() -> Result<(String, ArtifactIdentity), String> {
    let repo_digest = provenance::image_digest(V8_IMAGE)
        .ok_or_else(|| format!("local image {V8_IMAGE} has no immutable RepoDigest"))?;
    immutable_v8_artifact(&repo_digest)
}

#[cfg(test)]
fn backend_neutral_v8_args(arguments: &[String]) -> Vec<String> {
    let mut neutral = Vec::with_capacity(arguments.len());
    let mut index = 0;
    while index < arguments.len() {
        if matches!(
            arguments[index].as_str(),
            "--exec-backend" | "--native-page-profile"
        ) {
            index += 2;
        } else {
            neutral.push(arguments[index].clone());
            index += 1;
        }
    }
    neutral
}

fn v8_wall_millis(output: &str, elapsed: Duration) -> Result<f64, String> {
    if !output.lines().any(|line| line.trim() == "v8-smoke ok") {
        return Err("V8 sample did not print `v8-smoke ok`".to_owned());
    }
    Ok(elapsed.as_secs_f64() * 1_000.0)
}

fn cleanup_v8_sample(root: &Path, run_id: &str) {
    let _ = Command::new("sudo")
        .arg("-n")
        .arg(root.join("scripts/sudo/kill.sh"))
        .arg(run_id)
        .output();
}

fn run_v8_backend(
    bin: &Path,
    root: &Path,
    backend: CarrickBackend,
    immutable_image: &str,
) -> Result<f64, String> {
    let run_id = invoke::perf_run_id();
    let started = Instant::now();
    let child = Command::new(bin)
        .args(v8_backend_args(backend, immutable_image))
        .env("CARRICK_RUN_ID", &run_id)
        .env("CARRICK_EXPOSED_CPUS", CPU_PIN.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|error| format!("spawn direct V8 {backend:?} sample: {error}"))?;
    let pid = child.id() as i32;
    let done = Arc::new(AtomicBool::new(false));
    let watcher = {
        let done = Arc::clone(&done);
        let root = root.to_path_buf();
        let run_id = run_id.clone();
        std::thread::spawn(move || {
            let deadline_started = Instant::now();
            while !done.load(Ordering::Relaxed) {
                if deadline_started.elapsed() > V8_SAMPLE_DEADLINE {
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                    cleanup_v8_sample(&root, &run_id);
                    return true;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            false
        })
    };

    let wait_result = child.wait_with_output();
    if wait_result.is_err() {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        cleanup_v8_sample(root, &run_id);
    }
    done.store(true, Ordering::Relaxed);
    let timed_out = watcher
        .join()
        .map_err(|_| "direct V8 deadline watcher panicked".to_owned())?;
    let output = wait_result.map_err(|error| format!("wait for direct V8 sample: {error}"))?;
    let elapsed = started.elapsed();
    cleanup_v8_sample(root, &run_id);

    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    if timed_out {
        return Err(format!(
            "direct V8 {backend:?} sample timed out after {}s: {combined}",
            V8_SAMPLE_DEADLINE.as_secs()
        ));
    }
    if !output.status.success() {
        return Err(format!(
            "direct V8 {backend:?} sample exited with status {}: {combined}",
            output.status
        ));
    }
    v8_wall_millis(&combined, elapsed)
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
fn backend_pair_contains_required_process_cases() {
    for workload in ["fork", "fork_exec", "fork_scale_0m", "fork_scale_256m"] {
        let case = CASES
            .iter()
            .find(|case| case.workload == workload)
            .unwrap_or_else(|| panic!("missing {workload}"));
        assert_eq!(case.backend_pair_support, BackendPairSupport::DirectElf);
    }
}

#[test]
fn v8_pair_uses_one_immutable_image_digest() {
    let identity = v8_artifact_identity("sha256:abc").expect("digest");
    validate_same_artifact(&identity, &identity).expect("same image");
}

#[test]
fn v8_repo_digest_becomes_the_executed_image_reference() {
    let repo_digest = "localhost:5005/carrick-nodejs-conformance@sha256:abc";
    let (image, identity) = immutable_v8_artifact(repo_digest).expect("immutable V8 image");
    assert_eq!(image, repo_digest);
    assert_eq!(identity.sha256, "abc");
    assert!(immutable_v8_artifact(V8_IMAGE).is_err());
}

#[test]
fn v8_backend_commands_share_the_workload_contract() {
    let image = "localhost:5005/node@sha256:abc";
    let native = v8_backend_args(CarrickBackend::Native16k, image);
    let hvf = v8_backend_args(CarrickBackend::Hvf, image);

    for required in [
        "--max-traps",
        "18446744073709551615",
        "--raw",
        "--fs",
        "host",
        "--entrypoint",
        V8_ENTRYPOINT,
        image,
        V8_SCRIPT,
    ] {
        assert!(native.iter().any(|argument| argument == required));
        assert!(hvf.iter().any(|argument| argument == required));
    }
    assert_eq!(
        backend_neutral_v8_args(&native),
        backend_neutral_v8_args(&hvf)
    );
}

#[test]
fn v8_sample_requires_success_marker() {
    assert!(v8_wall_millis("startup noise", Duration::from_millis(12)).is_err());
    assert_eq!(
        v8_wall_millis("startup noise\nv8-smoke ok", Duration::from_millis(12))
            .expect("successful V8 output"),
        12.0
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

fn parse_backend_pair_case_sample(output: &str, case: &PerfCase) -> Result<f64, String> {
    let value = parse_backend_pair_sample(output, case.metric_key)?;
    if case.probe != "perf_fork_scale" {
        return Ok(value);
    }

    let expected_threads = case
        .guest_args
        .first()
        .ok_or_else(|| format!("{}: missing expected threads argument", case.workload))?
        .parse::<u64>()
        .map_err(|error| format!("{}: invalid expected threads: {error}", case.workload))?;
    let expected_mem_mb = case
        .guest_args
        .get(1)
        .ok_or_else(|| format!("{}: missing expected mem_mb argument", case.workload))?
        .parse::<u64>()
        .map_err(|error| format!("{}: invalid expected mem_mb: {error}", case.workload))?;
    let metrics = Metrics::parse(output);
    let threads = metrics
        .get_u64("threads")
        .ok_or_else(|| "missing fork-scale knob threads".to_owned())?;
    let mem_mb = metrics
        .get_u64("mem_mb")
        .ok_or_else(|| "missing fork-scale knob mem_mb".to_owned())?;
    if threads != expected_threads {
        return Err(format!(
            "wrong threads {threads}; expected {expected_threads}"
        ));
    }
    if mem_mb != expected_mem_mb {
        return Err(format!("wrong mem_mb {mem_mb}; expected {expected_mem_mb}"));
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

#[test]
fn fork_scale_rejects_wrong_echoed_knobs() {
    let case = CASES
        .iter()
        .find(|case| case.workload == "fork_scale_256m")
        .expect("fork scale case");
    let error =
        parse_backend_pair_case_sample("fork_p50_us=1.25\nthreads=0\nmem_mb=0\nnproc=4", case)
            .expect_err("wrong fork-scale memory must invalidate the report");
    assert!(error.contains("wrong mem_mb 0; expected 256"));
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
    let v8_artifact = match filter.as_deref() {
        None => Some(resolve_v8_artifact()?),
        Some(value) if "direct_v8".contains(value) => Some(resolve_v8_artifact()?),
        Some(_) => None,
    };

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
            parse_backend_pair_case_sample(&output, case)
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

    if let Some((immutable_image, artifact)) = v8_artifact {
        let mut run_sample = |backend| run_v8_backend(&bin, &root, backend, &immutable_image);
        let warmups = warmup_reps();
        if warmups > 0 {
            collect_backend_pair(warmups, cooldown(), &mut run_sample)
                .map_err(|error| format!("direct_v8 warmup: {error}"))?;
        }
        let samples = collect_backend_pair(reps(), cooldown(), run_sample)
            .map_err(|error| format!("direct_v8: {error}"))?;
        validate_same_artifact(&artifact, &artifact)?;
        let native_summary = stats::summarize(&samples.native16k)
            .ok_or_else(|| "direct_v8: too few native16k samples".to_owned())?;
        let hvf_summary = stats::summarize(&samples.hvf)
            .ok_or_else(|| "direct_v8: too few HVF samples".to_owned())?;
        rows.push(BackendEvidenceRow::Measurement(BackendMeasurement {
            workload: "direct_v8".to_owned(),
            backend: CarrickBackend::Native16k,
            artifact: artifact.clone(),
            metric: "wall_ms".to_owned(),
            unit: "ms".to_owned(),
            higher_is_better: false,
            samples: samples.native16k.clone(),
            summary: native_summary,
        }));
        rows.push(BackendEvidenceRow::Measurement(BackendMeasurement {
            workload: "direct_v8".to_owned(),
            backend: CarrickBackend::Hvf,
            artifact,
            metric: "wall_ms".to_owned(),
            unit: "ms".to_owned(),
            higher_is_better: false,
            samples: samples.hvf.clone(),
            summary: hvf_summary,
        }));
        let mut comparison = comparison_row(
            "direct_v8",
            false,
            &samples.native16k,
            &samples.hvf,
            BACKEND_BOOTSTRAP_SEED,
            BACKEND_BOOTSTRAP_RESAMPLES,
        )
        .ok_or_else(|| "direct_v8: too few samples for comparison".to_owned())?;
        comparison.metric = "wall_ms".to_owned();
        comparison.unit = "ms".to_owned();
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
