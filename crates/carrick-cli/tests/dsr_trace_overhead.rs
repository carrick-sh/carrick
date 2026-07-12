#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[path = "../src/perf_stats.rs"]
mod perf_stats;

use std::collections::BTreeMap;
use std::io::{BufWriter, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use perf_stats::{RatioInterval, Summary, bootstrap_median_ratio, summarize};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

const SCHEMA: &str = "carrick.dsr-overhead.v1";
const BOOTSTRAP_SEED: u64 = 0x4453_522d_4f56_4844;
const BOOTSTRAP_RESAMPLES: usize = 10_000;
const V8_IMAGE: &str = "localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0";
const V8_ENTRYPOINT: &str = "/opt/nodejs-conformance/bin/node24";
const V8_SCRIPT: &str = "/opt/nodejs-conformance/fixtures/v8-smoke.js";

static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
enum BinaryRole {
    Baseline,
    Candidate,
    Untraced,
    Profiled,
}

impl BinaryRole {
    const fn label(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Candidate => "candidate",
            Self::Untraced => "untraced",
            Self::Profiled => "profiled",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Workload {
    SyscallFloor,
    GatewayScalar,
    GatewaySimd,
    MonomorphicIndirect,
    DirectV8,
    ForkExec,
}

#[derive(Clone, Copy, Debug)]
struct ImprovementPolicy {
    upper_bound: f64,
    minimum_estimate_gain: f64,
}

#[derive(Clone, Copy, Debug)]
enum BinaryGatePolicy {
    NonInferiority { upper_bound: f64 },
    Improvement(ImprovementPolicy),
}

impl BinaryGatePolicy {
    const fn upper_bound(self) -> f64 {
        match self {
            Self::NonInferiority { upper_bound } => upper_bound,
            Self::Improvement(policy) => policy.upper_bound,
        }
    }

    const fn minimum_estimate_gain(self) -> Option<f64> {
        match self {
            Self::NonInferiority { .. } => None,
            Self::Improvement(policy) => Some(policy.minimum_estimate_gain),
        }
    }

    fn passes(self, interval: RatioInterval) -> bool {
        match self {
            Self::NonInferiority { upper_bound } => {
                interval.lower <= 1.0 && interval.upper <= upper_bound
            }
            Self::Improvement(policy) => passes_improvement(interval, policy),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct BinaryGate {
    workload: Workload,
    cycles: usize,
    policy: BinaryGatePolicy,
}

fn passes_improvement(interval: RatioInterval, policy: ImprovementPolicy) -> bool {
    interval.upper < policy.upper_bound && interval.estimate <= 1.0 - policy.minimum_estimate_gain
}

impl Workload {
    const fn label(self) -> &'static str {
        match self {
            Self::SyscallFloor => "syscall-floor",
            Self::GatewayScalar => "gateway-scalar",
            Self::GatewaySimd => "gateway-simd",
            Self::MonomorphicIndirect => "monomorphic-indirect",
            Self::DirectV8 => "direct-v8",
            Self::ForkExec => "fork-exec",
        }
    }

    const fn unit(self) -> &'static str {
        match self {
            Self::SyscallFloor | Self::GatewayScalar | Self::GatewaySimd => "us",
            Self::MonomorphicIndirect => "ns-per-call",
            Self::DirectV8 | Self::ForkExec => "ms-wall",
        }
    }

    const fn profile(self) -> &'static str {
        match self {
            Self::SyscallFloor => "dsr",
            Self::GatewayScalar | Self::GatewaySimd => "dsr",
            Self::MonomorphicIndirect => "dsr-indirect",
            Self::DirectV8 => "dsr-indirect",
            Self::ForkExec => "dsr-fork",
        }
    }

    const fn timeout_secs(self) -> u64 {
        match self {
            Self::SyscallFloor | Self::GatewayScalar | Self::GatewaySimd => 30,
            Self::MonomorphicIndirect => 30,
            Self::DirectV8 => 90,
            Self::ForkExec => 60,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct HostContext {
    model: Option<String>,
    macos: Option<String>,
    logical_cpus: Option<String>,
    power_source: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct BinaryProvenance {
    role: BinaryRole,
    path: String,
    commit: String,
    sha256: String,
    device: u64,
    inode: u64,
    codesign: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "record", rename_all = "kebab-case")]
enum EvidenceRow {
    Run {
        schema: &'static str,
        mode: &'static str,
        epoch_secs: u64,
        schedule: &'static str,
        bootstrap_seed: u64,
        bootstrap_resamples: usize,
        host: HostContext,
        binaries: Vec<BinaryProvenance>,
    },
    Sample {
        schema: &'static str,
        mode: &'static str,
        workload: &'static str,
        unit: &'static str,
        sequence: usize,
        cycle: usize,
        slot: usize,
        role: BinaryRole,
        value: f64,
        run_id: String,
    },
    Decision {
        schema: &'static str,
        mode: &'static str,
        workload: &'static str,
        unit: &'static str,
        baseline_role: BinaryRole,
        candidate_role: BinaryRole,
        baseline: Summary,
        candidate: Summary,
        ratio: RatioInterval,
        upper_bound_limit: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        minimum_estimate_gain: Option<f64>,
        pass: Option<bool>,
    },
}

#[test]
fn bootstrap_ratio() {
    let interval = bootstrap_median_ratio(
        &[100.0, 101.0, 102.0, 103.0, 104.0],
        &[99.0, 100.0, 101.0, 102.0, 103.0],
        42,
        2_000,
    )
    .expect("ratio interval");
    assert_eq!(interval.resamples, 2_000);
    assert!((interval.estimate - 0.990_196_078_431_372_6).abs() < 1e-12);
    assert!((interval.lower - 0.961_538_461_538_461_6).abs() < 1e-12);
    assert!((interval.upper - 1.019_801_980_198_019_8).abs() < 1e-12);
}

#[test]
fn improvement_policy_requires_supported_nonzero_gain() {
    let policy = ImprovementPolicy {
        upper_bound: 1.0,
        minimum_estimate_gain: 0.01,
    };
    assert!(passes_improvement(
        RatioInterval {
            estimate: 0.98,
            lower: 0.97,
            upper: 0.995,
            resamples: 10_000,
        },
        policy,
    ));
    assert!(!passes_improvement(
        RatioInterval {
            estimate: 0.995,
            lower: 0.98,
            upper: 0.999,
            resamples: 10_000,
        },
        policy,
    ));
    assert!(!passes_improvement(
        RatioInterval {
            estimate: 0.98,
            lower: 0.96,
            upper: 1.001,
            resamples: 10_000,
        },
        policy,
    ));
}

#[test]
fn relative_gate_paths_are_workspace_relative() {
    let root = Path::new("/workspace/carrick");
    assert_eq!(
        resolve_repo_path(PathBuf::from("target/perf/candidate"), root),
        PathBuf::from("/workspace/carrick/target/perf/candidate"),
    );
    assert_eq!(
        resolve_repo_path(PathBuf::from("/tmp/candidate"), root),
        PathBuf::from("/tmp/candidate"),
    );
}

#[test]
fn performance_surface_has_no_implicit_legacy_comparison() {
    let source = include_str!("dsr_trace_overhead.rs");
    let legacy_entrypoint = ["disabled_probe_", "overhead"].concat();
    let hard_coded_commit = ["const BASELINE_", "COMMIT"].concat();
    let legacy_mode = ["disabled-", "probe"].concat();
    assert!(!source.contains(&legacy_entrypoint));
    assert!(!source.contains(&hard_coded_commit));
    assert!(!source.contains(&legacy_mode));
}

#[test]
fn monomorphic_indirect_gate_uses_the_static_pie_probe() {
    let root = Path::new("/workspace/carrick");
    let args = workload_args(Workload::MonomorphicIndirect, root, "mono");
    assert_eq!(
        Workload::MonomorphicIndirect.label(),
        "monomorphic-indirect"
    );
    assert_eq!(Workload::MonomorphicIndirect.unit(), "ns-per-call");
    assert_eq!(
        args.last().map(String::as_str),
        Some(
            "/workspace/carrick/conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_dsr_indirect"
        ),
    );
}

#[test]
fn gateway_gate_uses_scalar_and_simd_metrics_from_static_pie() {
    let root = Path::new("/workspace/carrick");
    for (workload, label, unit) in [
        (Workload::GatewayScalar, "gateway-scalar", "us"),
        (Workload::GatewaySimd, "gateway-simd", "us"),
    ] {
        let args = workload_args(workload, root, "gateway");
        assert_eq!(workload.label(), label);
        assert_eq!(workload.unit(), unit);
        assert_eq!(
            args.last().map(String::as_str),
            Some(
                "/workspace/carrick/conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_dsr_gateway"
            ),
        );
    }
}

#[test]
#[ignore = "explicit opt-in indirect-cache performance gate"]
fn indirect_cache_improvement() {
    run_binary_gate(
        "indirect-cache-improvement",
        &[BinaryGate {
            workload: Workload::DirectV8,
            cycles: 5,
            policy: BinaryGatePolicy::Improvement(ImprovementPolicy {
                upper_bound: 1.0,
                minimum_estimate_gain: 0.01,
            }),
        }],
        "CARRICK_DSR_OPTIMIZATION_OUT",
    );
}

#[test]
#[ignore = "explicit opt-in indirect-cache hit-path non-inferiority gate"]
fn indirect_cache_hit_noninferiority() {
    run_binary_gate(
        "indirect-cache-hit-noninferiority",
        &[BinaryGate {
            workload: Workload::MonomorphicIndirect,
            cycles: 15,
            policy: BinaryGatePolicy::NonInferiority { upper_bound: 1.02 },
        }],
        "CARRICK_DSR_HIT_OUT",
    );
}

#[test]
#[ignore = "explicit opt-in prepare-cache performance gate"]
fn prepare_cache_improvement() {
    run_binary_gate(
        "prepare-cache-improvement",
        &[
            BinaryGate {
                workload: Workload::SyscallFloor,
                cycles: 15,
                policy: BinaryGatePolicy::Improvement(ImprovementPolicy {
                    upper_bound: 1.0,
                    minimum_estimate_gain: 0.01,
                }),
            },
            BinaryGate {
                workload: Workload::DirectV8,
                cycles: 5,
                policy: BinaryGatePolicy::Improvement(ImprovementPolicy {
                    upper_bound: 1.01,
                    minimum_estimate_gain: 0.0,
                }),
            },
        ],
        "CARRICK_DSR_OPTIMIZATION_OUT",
    );
}

#[test]
#[ignore = "explicit opt-in initialized-stack copy performance gate"]
fn stack_window_improvement() {
    run_binary_gate(
        "stack-window-improvement",
        &[
            BinaryGate {
                workload: Workload::ForkExec,
                cycles: 5,
                policy: BinaryGatePolicy::Improvement(ImprovementPolicy {
                    upper_bound: 0.95,
                    minimum_estimate_gain: 0.10,
                }),
            },
            BinaryGate {
                workload: Workload::SyscallFloor,
                cycles: 15,
                policy: BinaryGatePolicy::NonInferiority { upper_bound: 1.01 },
            },
            BinaryGate {
                workload: Workload::DirectV8,
                cycles: 5,
                policy: BinaryGatePolicy::NonInferiority { upper_bound: 1.01 },
            },
        ],
        "CARRICK_DSR_OPTIMIZATION_OUT",
    );
}

#[test]
#[ignore = "explicit opt-in batched syscall-floor audit"]
fn stack_window_batched_syscall_floor() {
    run_binary_gate(
        "stack-window-batched-syscall-floor",
        &[BinaryGate {
            workload: Workload::SyscallFloor,
            cycles: 15,
            policy: BinaryGatePolicy::NonInferiority { upper_bound: 1.01 },
        }],
        "CARRICK_DSR_OPTIMIZATION_OUT",
    );
}

#[test]
#[ignore = "explicit opt-in DSR gateway closure performance gate"]
fn gateway_closure_improvement() {
    run_binary_gate(
        "gateway-closure-improvement",
        &[
            BinaryGate {
                workload: Workload::GatewayScalar,
                cycles: 15,
                policy: BinaryGatePolicy::Improvement(ImprovementPolicy {
                    upper_bound: 1.0,
                    minimum_estimate_gain: 0.05,
                }),
            },
            BinaryGate {
                workload: Workload::GatewaySimd,
                cycles: 15,
                policy: BinaryGatePolicy::NonInferiority { upper_bound: 1.01 },
            },
            BinaryGate {
                workload: Workload::SyscallFloor,
                cycles: 15,
                policy: BinaryGatePolicy::NonInferiority { upper_bound: 1.01 },
            },
            BinaryGate {
                workload: Workload::DirectV8,
                cycles: 5,
                policy: BinaryGatePolicy::NonInferiority { upper_bound: 1.01 },
            },
        ],
        "CARRICK_DSR_GATEWAY_OUT",
    );
}

#[test]
#[ignore = "explicit opt-in DTrace profile cost measurement"]
fn enabled_profile_overhead() {
    let root = repo_root();
    let candidate_path = required_path("CARRICK_DSR_CANDIDATE_BIN");
    let output = required_path("CARRICK_DSR_ENABLED_OUT");
    let candidate = binary_provenance(
        BinaryRole::Candidate,
        &candidate_path,
        std::env::var("CARRICK_DSR_CANDIDATE_COMMIT")
            .unwrap_or_else(|_| git_head().unwrap_or_else(|| "unknown".to_owned())),
    );
    let mut rows = vec![EvidenceRow::Run {
        schema: SCHEMA,
        mode: "enabled-profile",
        epoch_secs: epoch_secs(),
        schedule: "ABBA",
        bootstrap_seed: BOOTSTRAP_SEED,
        bootstrap_resamples: BOOTSTRAP_RESAMPLES,
        host: host_context(),
        binaries: vec![candidate],
    }];
    let cycles = std::env::var("CARRICK_DSR_ENABLED_CYCLES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(2);
    for workload in [
        Workload::SyscallFloor,
        Workload::DirectV8,
        Workload::ForkExec,
    ] {
        let collected = collect_abba(
            "enabled-profile",
            workload,
            cycles,
            &candidate_path,
            &candidate_path,
            BinaryRole::Untraced,
            BinaryRole::Profiled,
            true,
            &root,
            &mut rows,
        );
        let ratio = bootstrap_median_ratio(
            &collected[&BinaryRole::Untraced],
            &collected[&BinaryRole::Profiled],
            BOOTSTRAP_SEED ^ workload_seed(workload),
            BOOTSTRAP_RESAMPLES,
        )
        .expect("bootstrap enabled-profile ratio");
        rows.push(EvidenceRow::Decision {
            schema: SCHEMA,
            mode: "enabled-profile",
            workload: workload.label(),
            unit: "ms-wall",
            baseline_role: BinaryRole::Untraced,
            candidate_role: BinaryRole::Profiled,
            baseline: summarize(&collected[&BinaryRole::Untraced]).expect("untraced summary"),
            candidate: summarize(&collected[&BinaryRole::Profiled]).expect("profiled summary"),
            ratio,
            upper_bound_limit: None,
            minimum_estimate_gain: None,
            pass: None,
        });
    }
    write_jsonl_atomic(&output, &rows);
}

fn run_binary_gate(mode: &'static str, gates: &[BinaryGate], output_env: &str) {
    let root = repo_root();
    let baseline_path = required_path("CARRICK_DSR_BASELINE_BIN");
    let candidate_path = required_path("CARRICK_DSR_CANDIDATE_BIN");
    let output = required_path(output_env);
    let baseline_commit = std::env::var("CARRICK_DSR_BASELINE_COMMIT")
        .expect("CARRICK_DSR_BASELINE_COMMIT is required for optimization evidence");
    let candidate_commit = std::env::var("CARRICK_DSR_CANDIDATE_COMMIT")
        .expect("CARRICK_DSR_CANDIDATE_COMMIT is required for optimization evidence");
    let baseline = binary_provenance(BinaryRole::Baseline, &baseline_path, baseline_commit);
    let candidate = binary_provenance(BinaryRole::Candidate, &candidate_path, candidate_commit);
    assert_distinct_binaries(&baseline, &candidate);

    let mut rows = vec![EvidenceRow::Run {
        schema: SCHEMA,
        mode,
        epoch_secs: epoch_secs(),
        schedule: "ABBA",
        bootstrap_seed: BOOTSTRAP_SEED,
        bootstrap_resamples: BOOTSTRAP_RESAMPLES,
        host: host_context(),
        binaries: vec![baseline, candidate],
    }];
    let mut decisions = Vec::new();
    for gate in gates {
        let collected = collect_abba(
            mode,
            gate.workload,
            gate.cycles,
            &baseline_path,
            &candidate_path,
            BinaryRole::Baseline,
            BinaryRole::Candidate,
            false,
            &root,
            &mut rows,
        );
        let ratio = bootstrap_median_ratio(
            &collected[&BinaryRole::Baseline],
            &collected[&BinaryRole::Candidate],
            BOOTSTRAP_SEED ^ workload_seed(gate.workload),
            BOOTSTRAP_RESAMPLES,
        )
        .expect("bootstrap signed-binary ratio");
        let pass = gate.policy.passes(ratio);
        rows.push(EvidenceRow::Decision {
            schema: SCHEMA,
            mode,
            workload: gate.workload.label(),
            unit: gate.workload.unit(),
            baseline_role: BinaryRole::Baseline,
            candidate_role: BinaryRole::Candidate,
            baseline: summarize(&collected[&BinaryRole::Baseline]).expect("baseline summary"),
            candidate: summarize(&collected[&BinaryRole::Candidate]).expect("candidate summary"),
            ratio,
            upper_bound_limit: Some(gate.policy.upper_bound()),
            minimum_estimate_gain: gate.policy.minimum_estimate_gain(),
            pass: Some(pass),
        });
        decisions.push((gate.workload, gate.policy, pass, ratio));
    }
    write_jsonl_atomic(&output, &rows);
    for (workload, policy, pass, ratio) in decisions {
        assert!(
            pass,
            "{} {mode} failed: estimate {:.6}, interval [{:.6}, {:.6}], policy {policy:?}",
            workload.label(),
            ratio.estimate,
            ratio.lower,
            ratio.upper,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_abba(
    mode: &'static str,
    workload: Workload,
    cycles: usize,
    first_binary: &Path,
    second_binary: &Path,
    first_role: BinaryRole,
    second_role: BinaryRole,
    profile_second: bool,
    root: &Path,
    rows: &mut Vec<EvidenceRow>,
) -> BTreeMap<BinaryRole, Vec<f64>> {
    let mut samples = BTreeMap::from([(first_role, Vec::new()), (second_role, Vec::new())]);
    let mut sequence = 0;
    for cycle in 0..cycles {
        for (slot, (role, binary, profiled)) in [
            (first_role, first_binary, false),
            (second_role, second_binary, profile_second),
            (second_role, second_binary, profile_second),
            (first_role, first_binary, false),
        ]
        .into_iter()
        .enumerate()
        {
            let run_id = next_run_id(mode, workload, role);
            let wall_time_metric = mode == "enabled-profile";
            let value = run_workload(binary, workload, profiled, wall_time_metric, root, &run_id);
            let unit = if wall_time_metric {
                "ms-wall"
            } else {
                workload.unit()
            };
            eprintln!(
                "dsr-overhead[{mode}/{}] cycle={cycle} slot={slot} role={} value={value:.6} {}",
                workload.label(),
                role.label(),
                unit
            );
            samples.get_mut(&role).expect("known role").push(value);
            rows.push(EvidenceRow::Sample {
                schema: SCHEMA,
                mode,
                workload: workload.label(),
                unit,
                sequence,
                cycle,
                slot,
                role,
                value,
                run_id,
            });
            sequence += 1;
            std::thread::sleep(cooldown());
        }
    }
    samples
}

fn run_workload(
    binary: &Path,
    workload: Workload,
    profiled: bool,
    wall_time_metric: bool,
    root: &Path,
    run_id: &str,
) -> f64 {
    let inner = workload_args(workload, root, run_id);
    let args = if profiled {
        let mut args = vec![
            "trace".to_owned(),
            "--profile".to_owned(),
            workload.profile().to_owned(),
            "--".to_owned(),
        ];
        args.extend(inner);
        args
    } else {
        inner
    };
    let started = Instant::now();
    let output = Command::new("timeout")
        .arg(workload.timeout_secs().to_string())
        .arg(binary)
        .args(&args)
        .env("CARRICK_RUN_ID", run_id)
        .env("CARRICK_EXPOSED_CPUS", "4")
        .env_remove("CARRICK_DSR_PROFILE")
        .output()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", binary.display()));
    let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    scoped_cleanup(root, run_id);
    assert!(
        output.status.success(),
        "{} {} failed status={:?}:\n{text}",
        binary.display(),
        workload.label(),
        output.status.code()
    );
    match workload {
        Workload::SyscallFloor if !wall_time_metric => {
            parse_metric(&text, "trap_batch_trimmed_mean_us").expect("trap_batch_trimmed_mean_us")
        }
        Workload::SyscallFloor => elapsed_ms,
        Workload::GatewayScalar => {
            parse_metric(&text, "gateway_scalar_p50_us").expect("gateway_scalar_p50_us")
        }
        Workload::GatewaySimd => {
            parse_metric(&text, "gateway_simd_p50_us").expect("gateway_simd_p50_us")
        }
        Workload::MonomorphicIndirect => {
            parse_metric(&text, "indirect_p50_ns").expect("indirect_p50_ns")
        }
        Workload::DirectV8 => {
            assert!(
                text.contains("v8-smoke ok"),
                "missing V8 success marker:\n{text}"
            );
            elapsed_ms
        }
        Workload::ForkExec => {
            assert!(
                text.contains("fork_exec_p50_us="),
                "missing fork output:\n{text}"
            );
            elapsed_ms
        }
    }
}

fn workload_args(workload: Workload, root: &Path, run_id: &str) -> Vec<String> {
    match workload {
        Workload::SyscallFloor => vec![
            "run-elf".to_owned(),
            "--raw".to_owned(),
            "--exec-backend".to_owned(),
            "native".to_owned(),
            "--native-page-profile".to_owned(),
            "native16k".to_owned(),
            root.join("conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_trap_floor")
                .to_string_lossy()
                .into_owned(),
        ],
        Workload::GatewayScalar | Workload::GatewaySimd => vec![
            "run-elf".to_owned(),
            "--raw".to_owned(),
            "--exec-backend".to_owned(),
            "native".to_owned(),
            "--native-page-profile".to_owned(),
            "native16k".to_owned(),
            root.join("conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_dsr_gateway")
                .to_string_lossy()
                .into_owned(),
        ],
        Workload::MonomorphicIndirect => vec![
            "run-elf".to_owned(),
            "--raw".to_owned(),
            "--exec-backend".to_owned(),
            "native".to_owned(),
            "--native-page-profile".to_owned(),
            "native16k".to_owned(),
            root.join("conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_dsr_indirect")
                .to_string_lossy()
                .into_owned(),
        ],
        Workload::DirectV8 => vec![
            "run".to_owned(),
            "--name".to_owned(),
            format!("{run_id}-v8"),
            "--max-traps".to_owned(),
            u64::MAX.to_string(),
            "--raw".to_owned(),
            "--fs".to_owned(),
            "host".to_owned(),
            "--entrypoint".to_owned(),
            V8_ENTRYPOINT.to_owned(),
            "--exec-backend".to_owned(),
            "native".to_owned(),
            "--native-page-profile".to_owned(),
            "native16k".to_owned(),
            V8_IMAGE.to_owned(),
            V8_SCRIPT.to_owned(),
        ],
        Workload::ForkExec => vec![
            "run-elf".to_owned(),
            "--raw".to_owned(),
            "--exec-backend".to_owned(),
            "native".to_owned(),
            "--native-page-profile".to_owned(),
            "native16k".to_owned(),
            root.join("conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_fork_exec")
                .to_string_lossy()
                .into_owned(),
        ],
    }
}

fn binary_provenance(role: BinaryRole, path: &Path, commit: String) -> BinaryProvenance {
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonicalize {}: {error}", path.display()));
    let metadata = std::fs::metadata(&canonical).expect("binary metadata");
    let bytes = std::fs::read(&canonical).expect("read binary");
    let codesign = command_text("codesign", &["-dv", "--verbose=4"], Some(&canonical));
    assert!(
        codesign.contains("Signature=") || codesign.contains("adhoc"),
        "{} is not signed:\n{codesign}",
        canonical.display()
    );
    BinaryProvenance {
        role,
        path: canonical.to_string_lossy().into_owned(),
        commit,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        device: metadata.dev(),
        inode: metadata.ino(),
        codesign,
    }
}

fn assert_distinct_binaries(left: &BinaryProvenance, right: &BinaryProvenance) {
    assert_ne!((left.device, left.inode), (right.device, right.inode));
    assert_ne!(left.sha256, right.sha256);
    assert_ne!(left.path, right.path);
}

fn parse_metric(output: &str, key: &str) -> Option<f64> {
    output.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate.trim() == key)
            .then(|| value.trim().parse::<f64>().ok())
            .flatten()
    })
}

fn scoped_cleanup(root: &Path, run_id: &str) {
    let _ = Command::new(root.join("scripts/sudo/kill.sh"))
        .arg(run_id)
        .output();
}

fn next_run_id(mode: &str, workload: Workload, role: BinaryRole) -> String {
    format!(
        "dsr-oh-{}-{}-{}-{}-{}",
        std::process::id(),
        mode,
        workload.label(),
        role.label(),
        RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

fn cooldown() -> Duration {
    Duration::from_millis(
        std::env::var("CARRICK_DSR_OVERHEAD_COOLDOWN_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(250),
    )
}

fn workload_seed(workload: Workload) -> u64 {
    match workload {
        Workload::SyscallFloor => 1,
        Workload::DirectV8 => 2,
        Workload::ForkExec => 3,
        Workload::MonomorphicIndirect => 4,
        Workload::GatewayScalar => 5,
        Workload::GatewaySimd => 6,
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn required_path(key: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(key).unwrap_or_else(|| panic!("{key} is required")));
    resolve_repo_path(path, &repo_root())
}

fn resolve_repo_path(path: PathBuf, root: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn host_context() -> HostContext {
    HostContext {
        model: command_stdout("sysctl", &["-n", "hw.model"]),
        macos: command_stdout("sw_vers", &["-productVersion"]),
        logical_cpus: command_stdout("sysctl", &["-n", "hw.logicalcpu"]),
        power_source: command_stdout("pmset", &["-g", "batt"]),
    }
}

fn git_head() -> Option<String> {
    command_stdout("git", &["rev-parse", "HEAD"])
}

fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn command_text(program: &str, args: &[&str], trailing: Option<&Path>) -> String {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(path) = trailing {
        command.arg(path);
    }
    let output = command.output().expect("run provenance command");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text.trim().to_owned()
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn write_jsonl_atomic(path: &Path, rows: &[EvidenceRow]) {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).expect("create evidence directory");
    let mut temporary = NamedTempFile::new_in(parent).expect("create evidence temporary");
    {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        for row in rows {
            serde_json::to_writer(&mut writer, row).expect("serialize evidence row");
            writer.write_all(b"\n").expect("terminate evidence row");
        }
        writer.flush().expect("flush evidence JSONL");
    }
    temporary.as_file().sync_all().expect("sync evidence JSONL");
    temporary.persist(path).expect("publish evidence JSONL");
}
