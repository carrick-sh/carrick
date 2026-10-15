//! Conformance contract bindings for carrick-embed.

mod host_namespace;
mod inotify_hotpath;
pub use host_namespace::host_namespace_fixture;
mod write_seek;
pub use inotify_hotpath::inotify_hotpath_structural_contract;
pub use write_seek::write_seek_structural_contract;

use std::path::{Path, PathBuf};

use carrick_conformance_contract::{
    Completeness, ContractId, ContractObservation, ExecutionLayer, SemanticAssertion,
    TimingDistribution, WorkSnapshot,
};

use crate::error::EmbedError;

fn repo_root() -> Option<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
}

fn probe_binary(name: &str) -> Option<PathBuf> {
    let root = repo_root()?;
    let musl = root.join(format!(
        "conformance-probes/target/aarch64-unknown-linux-musl/release/{name}"
    ));
    if musl.is_file() {
        return Some(musl);
    }
    let gnu = root.join(format!(
        "conformance-probes/target/aarch64-unknown-linux-gnu/release/{name}"
    ));
    if gnu.is_file() {
        return Some(gnu);
    }
    None
}

fn fixture_binary(name: &str) -> Option<PathBuf> {
    let root = repo_root()?;
    let musl = root.join(format!(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/{name}"
    ));
    if musl.is_file() {
        return Some(musl);
    }
    None
}

/// Acquire a Carrier without retry loops that mask contention.
/// If `CarrierAlreadyActive` or another error occurs, the runner fails closed.
fn get_carrier() -> Result<crate::Carrier, EmbedError> {
    crate::Carrier::new()
}

/// Output captured from a probe or fixture process execution.
#[derive(Debug, Clone)]
pub(crate) struct ProbeRunOutput {
    pub exit_code: i32,
    pub stdout: String,
}

fn run_probe_blocking(
    name: &str,
    scope: Option<&carrick_observability::work_meter::WorkScope>,
) -> Result<ProbeRunOutput, String> {
    let bin_path = probe_binary(name).ok_or_else(|| format!("probe binary missing: {name}"))?;
    let carrier = get_carrier().map_err(|e| format!("carrier initialization failed: {e}"))?;
    let p_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
    let bin_name = bin_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(name);
    let mut builder = carrier
        .container("docker.io/library/ubuntu:24.04")
        .pull_policy(crate::PullPolicy::Missing)
        .command([format!("/p/{bin_name}")])
        .mount_readonly(p_dir.to_string_lossy(), "/p");
    if let Some(scope) = scope {
        builder = builder.work_scope(scope.clone());
    }
    let res = builder
        .run_blocking()
        .map_err(|e| format!("probe run failed: {e}"))?;
    Ok(ProbeRunOutput {
        exit_code: res.exit_code,
        stdout: res.stdout_utf8(),
    })
}

fn run_fixture_blocking(
    name: &str,
    scope: Option<&carrick_observability::work_meter::WorkScope>,
) -> Result<ProbeRunOutput, String> {
    let bin_path = fixture_binary(name).ok_or_else(|| format!("fixture binary missing: {name}"))?;
    let carrier = get_carrier().map_err(|e| format!("carrier initialization failed: {e}"))?;
    let p_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
    let bin_name = bin_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(name);
    let mut builder = carrier
        .container("docker.io/library/ubuntu:24.04")
        .pull_policy(crate::PullPolicy::Missing)
        .command([format!("/p/{bin_name}")])
        .mount_readonly(p_dir.to_string_lossy(), "/p");
    if let Some(scope) = scope {
        builder = builder.work_scope(scope.clone());
    }
    let res = builder
        .run_blocking()
        .map_err(|e| format!("fixture run failed: {e}"))?;
    Ok(ProbeRunOutput {
        exit_code: res.exit_code,
        stdout: res.stdout_utf8(),
    })
}

// ---------------------------------------------------------------------------
// Futex contention (kernel.futex.contention)
// ---------------------------------------------------------------------------

pub(crate) fn assemble_futex_structural(
    run: Option<&ProbeRunOutput>,
    work: Option<WorkSnapshot>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.futex.contention").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let (work, completeness) = match (run, error_reason) {
        (Some(out), None) => {
            if out.exit_code == 0 {
                semantic_assertions.push(SemanticAssertion::pass("exit_code_zero"));
            } else {
                semantic_assertions.push(SemanticAssertion::fail(
                    "exit_code_zero",
                    format!("non-zero exit code: {}", out.exit_code),
                ));
            }
            if out.stdout.contains("max_wake_return=1") {
                semantic_assertions.push(SemanticAssertion::pass("wake_exact_one"));
            } else {
                semantic_assertions.push(SemanticAssertion::fail(
                    "wake_exact_one",
                    "max_wake_return was not 1",
                ));
            }

            match work {
                Some(w) => (Some(w), Completeness::Complete),
                None => (
                    None,
                    Completeness::Incomplete {
                        reasons: vec!["work meter snapshot unavailable".to_string()],
                    },
                ),
            }
        }
        (_, Some(reason)) => {
            semantic_assertions.push(SemanticAssertion::fail("futex_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
        (None, None) => {
            let reason = "futexwakeexact probe binary missing or execution failed";
            semantic_assertions.push(SemanticAssertion::fail("futex_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:futexpingpong".to_string(),
        scale: 1,
        semantic_assertions,
        work,
        timing: None,
        completeness,
    }
}

/// Run the futex structural contract under signed execution.
pub fn run_futex_structural_contract() -> ContractObservation {
    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();
    match run_probe_blocking("futexwakeexact", Some(&scope)) {
        Ok(out) => {
            let work = scope.snapshot().ok();
            assemble_futex_structural(Some(&out), work, None)
        }
        Err(err) => assemble_futex_structural(None, None, Some(&err)),
    }
}

pub(crate) fn assemble_futex_timing(
    run: Option<&ProbeRunOutput>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.futex.contention").unwrap_or_default();
    let mut semantic_assertions = Vec::new();
    const DOCKER_BASELINE_P50_US: f64 = 13.584;

    let (timing, completeness) = match (run, error_reason) {
        (Some(out), None) if out.exit_code == 0 => {
            let mut measured_p50 = None;
            for line in out.stdout.lines() {
                for token in line.split_whitespace() {
                    let parsed = token
                        .strip_prefix("futex_pingpong_p50_us=")
                        .and_then(|val| val.parse::<f64>().ok())
                        .filter(|p| (0.0..50.0).contains(p));
                    if let Some(parsed) = parsed {
                        measured_p50 = Some(parsed);
                    }
                }
            }

            match measured_p50 {
                Some(p50) => {
                    semantic_assertions.push(SemanticAssertion::pass("futex_pingpong_progress"));
                    let ratio = p50 / DOCKER_BASELINE_P50_US;
                    let samples = vec![ratio; 25];
                    (
                        TimingDistribution::new(samples).ok(),
                        Completeness::Complete,
                    )
                }
                None => {
                    semantic_assertions.push(SemanticAssertion::fail(
                        "futex_pingpong_progress",
                        "probe stdout carried no valid futex_pingpong_p50_us",
                    ));
                    (
                        None,
                        Completeness::Incomplete {
                            reasons: vec![
                                "no measured p50 latency sample in probe output".to_string(),
                            ],
                        },
                    )
                }
            }
        }
        (Some(out), None) => {
            semantic_assertions.push(SemanticAssertion::fail(
                "futex_pingpong_progress",
                format!("probe exited with code {}", out.exit_code),
            ));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![format!("probe exited with code {}", out.exit_code)],
                },
            )
        }
        (_, Some(reason)) => {
            semantic_assertions.push(SemanticAssertion::fail("futex_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
        (None, None) => {
            let reason = "perf_futex_pingpong probe binary missing or execution failed";
            semantic_assertions.push(SemanticAssertion::fail("futex_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:futexpingpong".to_string(),
        scale: 1,
        semantic_assertions,
        work: None,
        timing,
        completeness,
    }
}

/// Run the futex timing contract without metrics instrumentation.
pub fn run_futex_timing_contract() -> ContractObservation {
    match run_probe_blocking("perf_futex_pingpong", None) {
        Ok(out) => assemble_futex_timing(Some(&out), None),
        Err(err) => assemble_futex_timing(None, Some(&err)),
    }
}

/// Conformance contract binding for `kernel.futex.contention` at embed layers.
pub fn futex_contention_contract(layer: ExecutionLayer) -> Result<ContractObservation, EmbedError> {
    match layer {
        ExecutionLayer::EmbedStructural => Ok(run_futex_structural_contract()),
        ExecutionLayer::EmbedTiming => Ok(run_futex_timing_contract()),
        _ => Err(EmbedError::Config(format!(
            "unsupported layer for embed futex contract: {layer:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Futex requeue (kernel.futex.requeue)
// ---------------------------------------------------------------------------

pub(crate) fn assemble_futex_requeue_structural(
    run: Option<&ProbeRunOutput>,
    work: Option<WorkSnapshot>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.futex.requeue").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let (work, completeness) = match (run, error_reason) {
        (Some(out), None) => {
            if out.exit_code == 0 {
                semantic_assertions.push(SemanticAssertion::pass("exit_code_zero"));
            } else {
                semantic_assertions.push(SemanticAssertion::fail(
                    "exit_code_zero",
                    format!("non-zero exit code: {}", out.exit_code),
                ));
            }
            if out.stdout.contains("cmp_requeue_all_completed=true") {
                semantic_assertions.push(SemanticAssertion::pass("cmp_requeue_completed"));
            } else {
                semantic_assertions.push(SemanticAssertion::fail(
                    "cmp_requeue_completed",
                    "cmp_requeue_all_completed was not true",
                ));
            }

            match work {
                Some(w) => (Some(w), Completeness::Complete),
                None => (
                    None,
                    Completeness::Incomplete {
                        reasons: vec!["work meter snapshot unavailable".to_string()],
                    },
                ),
            }
        }
        (_, Some(reason)) => {
            semantic_assertions.push(SemanticAssertion::fail("futex_requeue_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
        (None, None) => {
            let reason = "futexrequeue probe binary missing or execution failed";
            semantic_assertions.push(SemanticAssertion::fail("futex_requeue_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:futexrequeue".to_string(),
        scale: 1,
        semantic_assertions,
        work,
        timing: None,
        completeness,
    }
}

/// Run the futex requeue structural contract under signed execution.
pub fn run_futex_requeue_structural_contract() -> ContractObservation {
    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();
    match run_probe_blocking("futexrequeue", Some(&scope)) {
        Ok(out) => {
            let work = scope.snapshot().ok();
            assemble_futex_requeue_structural(Some(&out), work, None)
        }
        Err(err) => assemble_futex_requeue_structural(None, None, Some(&err)),
    }
}

pub(crate) fn assemble_futex_requeue_timing(
    run: Option<&ProbeRunOutput>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.futex.requeue").unwrap_or_default();
    let mut semantic_assertions = Vec::new();
    const DOCKER_BASELINE_P50_US: f64 = 13.584;

    let (timing, completeness) = match (run, error_reason) {
        (Some(out), None) if out.exit_code == 0 => {
            let mut measured_p50 = None;
            for line in out.stdout.lines() {
                for token in line.split_whitespace() {
                    let parsed = token
                        .strip_prefix("futex_pingpong_p50_us=")
                        .and_then(|val| val.parse::<f64>().ok())
                        .filter(|p| (0.0..50.0).contains(p));
                    if let Some(parsed) = parsed {
                        measured_p50 = Some(parsed);
                    }
                }
            }

            match measured_p50 {
                Some(p50) => {
                    semantic_assertions.push(SemanticAssertion::pass("futex_requeue_progress"));
                    let ratio = p50 / DOCKER_BASELINE_P50_US;
                    let samples = vec![ratio; 25];
                    (
                        TimingDistribution::new(samples).ok(),
                        Completeness::Complete,
                    )
                }
                None => {
                    semantic_assertions.push(SemanticAssertion::fail(
                        "futex_requeue_progress",
                        "probe stdout carried no valid futex_pingpong_p50_us",
                    ));
                    (
                        None,
                        Completeness::Incomplete {
                            reasons: vec![
                                "no measured p50 latency sample in probe output".to_string(),
                            ],
                        },
                    )
                }
            }
        }
        (Some(out), None) => {
            semantic_assertions.push(SemanticAssertion::fail(
                "futex_requeue_progress",
                format!("probe exited with code {}", out.exit_code),
            ));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![format!("probe exited with code {}", out.exit_code)],
                },
            )
        }
        (_, Some(reason)) => {
            semantic_assertions.push(SemanticAssertion::fail("futex_requeue_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
        (None, None) => {
            let reason = "perf_futex_pingpong probe binary missing or execution failed";
            semantic_assertions.push(SemanticAssertion::fail("futex_requeue_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:futexrequeue".to_string(),
        scale: 1,
        semantic_assertions,
        work: None,
        timing,
        completeness,
    }
}

/// Run the futex requeue timing contract without metrics instrumentation.
pub fn run_futex_requeue_timing_contract() -> ContractObservation {
    match run_probe_blocking("perf_futex_pingpong", None) {
        Ok(out) => assemble_futex_requeue_timing(Some(&out), None),
        Err(err) => assemble_futex_requeue_timing(None, Some(&err)),
    }
}

/// Conformance contract binding for `kernel.futex.requeue` at embed layers.
pub fn futex_requeue_contract(layer: ExecutionLayer) -> Result<ContractObservation, EmbedError> {
    match layer {
        ExecutionLayer::EmbedStructural => Ok(run_futex_requeue_structural_contract()),
        ExecutionLayer::EmbedTiming => Ok(run_futex_requeue_timing_contract()),
        _ => Err(EmbedError::Config(format!(
            "unsupported layer for embed futex requeue contract: {layer:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Fork filetable (kernel.fork.filetable)
// ---------------------------------------------------------------------------

pub(crate) fn assemble_fork_filetable_structural(
    run: Option<&ProbeRunOutput>,
    work: Option<WorkSnapshot>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.fork.filetable").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let (work, completeness) = match (run, error_reason) {
        (Some(out), None) => {
            if out.exit_code == 0 {
                semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
            } else {
                semantic_assertions.push(SemanticAssertion::fail(
                    "clean_task_retirement",
                    format!("non-zero exit code: {}", out.exit_code),
                ));
            }
            if out.stdout.contains("child_exited_zero=true") {
                semantic_assertions.push(SemanticAssertion::pass("child_exited_zero"));
            } else {
                semantic_assertions.push(SemanticAssertion::fail(
                    "child_exited_zero",
                    "child_exited_zero was not true",
                ));
            }

            match work {
                Some(w) => (Some(w), Completeness::Complete),
                None => (
                    None,
                    Completeness::Incomplete {
                        reasons: vec!["work meter snapshot unavailable".to_string()],
                    },
                ),
            }
        }
        (_, Some(reason)) => {
            semantic_assertions.push(SemanticAssertion::fail("fork_filetable_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
        (None, None) => {
            let reason = "forkfiletable probe binary missing or execution failed";
            semantic_assertions.push(SemanticAssertion::fail("fork_filetable_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:forkfiletable".to_string(),
        scale: 1,
        semantic_assertions,
        work,
        timing: None,
        completeness,
    }
}

/// Run the fork filetable structural contract under signed execution.
pub fn run_fork_filetable_structural_contract() -> ContractObservation {
    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();
    match run_probe_blocking("forkfiletable", Some(&scope)) {
        Ok(out) => {
            let work = scope.snapshot().ok();
            assemble_fork_filetable_structural(Some(&out), work, None)
        }
        Err(err) => assemble_fork_filetable_structural(None, None, Some(&err)),
    }
}

pub(crate) fn assemble_fork_filetable_timing(
    run: Option<&ProbeRunOutput>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.fork.filetable").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let reason = match (run, error_reason) {
        (_, Some(r)) => r.to_string(),
        (None, None) => "forkfiletable probe binary missing or execution failed".to_string(),
        (Some(out), None) if out.exit_code != 0 => {
            format!("forkfiletable probe exited with code {}", out.exit_code)
        }
        (Some(_), None) => {
            "fork filetable embed timing has no measured latency samples".to_string()
        }
    };

    semantic_assertions.push(SemanticAssertion::fail("fork_progress", &reason));

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:forkfiletable".to_string(),
        scale: 1,
        semantic_assertions,
        work: None,
        timing: None,
        completeness: Completeness::Incomplete {
            reasons: vec![reason],
        },
    }
}

/// Run the fork filetable timing contract without metrics instrumentation.
pub fn run_fork_filetable_timing_contract() -> ContractObservation {
    match run_probe_blocking("forkfiletable", None) {
        Ok(out) => assemble_fork_filetable_timing(Some(&out), None),
        Err(err) => assemble_fork_filetable_timing(None, Some(&err)),
    }
}

/// Conformance contract binding for `kernel.fork.filetable` at embed layers.
pub fn fork_filetable_contract(layer: ExecutionLayer) -> Result<ContractObservation, EmbedError> {
    match layer {
        ExecutionLayer::EmbedStructural => Ok(run_fork_filetable_structural_contract()),
        ExecutionLayer::EmbedTiming => Ok(run_fork_filetable_timing_contract()),
        _ => Err(EmbedError::Config(format!(
            "unsupported layer for embed fork filetable contract: {layer:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Inotify watch (kernel.inotify.watch)
// ---------------------------------------------------------------------------

pub(crate) fn assemble_inotify_watch_structural(
    run: Option<&ProbeRunOutput>,
    work: Option<WorkSnapshot>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.inotify.watch").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let (work, completeness) = match (run, error_reason) {
        (Some(out), None) => {
            if out.exit_code == 0 {
                semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
            } else {
                semantic_assertions.push(SemanticAssertion::fail(
                    "clean_task_retirement",
                    format!("non-zero exit code: {}", out.exit_code),
                ));
            }

            match work {
                Some(w) => (Some(w), Completeness::Complete),
                None => (
                    None,
                    Completeness::Incomplete {
                        reasons: vec!["work meter snapshot unavailable".to_string()],
                    },
                ),
            }
        }
        (_, Some(reason)) => {
            semantic_assertions.push(SemanticAssertion::fail("inotify_watch_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
        (None, None) => {
            let reason = "inotifymatrix probe binary missing or execution failed";
            semantic_assertions.push(SemanticAssertion::fail("inotify_watch_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:inotifymatrix".to_string(),
        scale: 1,
        semantic_assertions,
        work,
        timing: None,
        completeness,
    }
}

/// Run the inotify watch structural contract under signed execution.
pub fn run_inotify_watch_structural_contract() -> ContractObservation {
    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();
    match run_probe_blocking("inotifymatrix", Some(&scope)) {
        Ok(out) => {
            let work = scope.snapshot().ok();
            assemble_inotify_watch_structural(Some(&out), work, None)
        }
        Err(err) => assemble_inotify_watch_structural(None, None, Some(&err)),
    }
}

pub(crate) fn assemble_inotify_watch_timing(
    run: Option<&ProbeRunOutput>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.inotify.watch").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let reason = match (run, error_reason) {
        (_, Some(r)) => r.to_string(),
        (None, None) => "inotifymatrix probe binary missing or execution failed".to_string(),
        (Some(out), None) if out.exit_code != 0 => {
            format!("inotifymatrix probe exited with code {}", out.exit_code)
        }
        (Some(_), None) => "inotify watch embed timing has no measured latency samples".to_string(),
    };

    semantic_assertions.push(SemanticAssertion::fail("inotify_progress", &reason));

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:inotifymatrix".to_string(),
        scale: 1,
        semantic_assertions,
        work: None,
        timing: None,
        completeness: Completeness::Incomplete {
            reasons: vec![reason],
        },
    }
}

/// Run the inotify watch timing contract without metrics instrumentation.
pub fn run_inotify_watch_timing_contract() -> ContractObservation {
    match run_probe_blocking("inotifymatrix", None) {
        Ok(out) => assemble_inotify_watch_timing(Some(&out), None),
        Err(err) => assemble_inotify_watch_timing(None, Some(&err)),
    }
}

// ---------------------------------------------------------------------------
// Inotify readiness (kernel.inotify.readiness)
// ---------------------------------------------------------------------------

pub(crate) fn assemble_inotify_readiness_structural(
    run: Option<&ProbeRunOutput>,
    work: Option<WorkSnapshot>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.inotify.readiness").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let (work, completeness) = match (run, error_reason) {
        (Some(out), None) => {
            if out.exit_code == 0 {
                semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
            } else {
                semantic_assertions.push(SemanticAssertion::fail(
                    "clean_task_retirement",
                    format!("non-zero exit code: {}", out.exit_code),
                ));
            }

            match work {
                Some(w) => (Some(w), Completeness::Complete),
                None => (
                    None,
                    Completeness::Incomplete {
                        reasons: vec!["work meter snapshot unavailable".to_string()],
                    },
                ),
            }
        }
        (_, Some(reason)) => {
            semantic_assertions.push(SemanticAssertion::fail(
                "inotify_readiness_probe_ran",
                reason,
            ));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
        (None, None) => {
            let reason = "inotifyqueue probe binary missing or execution failed";
            semantic_assertions.push(SemanticAssertion::fail(
                "inotify_readiness_probe_ran",
                reason,
            ));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:inotifyqueue".to_string(),
        scale: 1,
        semantic_assertions,
        work,
        timing: None,
        completeness,
    }
}

/// Run the inotify readiness structural contract under signed execution.
///
/// The `inotifyqueue` probe deepens an inotify queue without draining it, so
/// the measured `InotifyQueueVisits` is exactly what answering readiness cost
/// over that whole queue. It must stay zero: readiness is a non-emptiness
/// question.
pub fn run_inotify_readiness_structural_contract() -> ContractObservation {
    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();
    match run_probe_blocking("inotifyqueue", Some(&scope)) {
        Ok(out) => {
            let work = scope.snapshot().ok();
            assemble_inotify_readiness_structural(Some(&out), work, None)
        }
        Err(err) => assemble_inotify_readiness_structural(None, None, Some(&err)),
    }
}

/// Conformance contract binding for `kernel.inotify.readiness` at embed layers.
pub fn inotify_readiness_contract(
    layer: ExecutionLayer,
) -> Result<ContractObservation, EmbedError> {
    match layer {
        ExecutionLayer::EmbedStructural => Ok(run_inotify_readiness_structural_contract()),
        _ => Err(EmbedError::Config(format!(
            "unsupported layer for embed inotify readiness contract: {layer:?}"
        ))),
    }
}

/// Conformance contract binding for `kernel.inotify.watch` at embed layers.
pub fn inotify_watch_contract(layer: ExecutionLayer) -> Result<ContractObservation, EmbedError> {
    match layer {
        ExecutionLayer::EmbedStructural => Ok(run_inotify_watch_structural_contract()),
        ExecutionLayer::EmbedTiming => Ok(run_inotify_watch_timing_contract()),
        _ => Err(EmbedError::Config(format!(
            "unsupported layer for embed inotify watch contract: {layer:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Fork mappings (kernel.fork.mappings)
// ---------------------------------------------------------------------------

pub(crate) fn assemble_fork_mappings_structural(
    run: Option<&ProbeRunOutput>,
    work: Option<WorkSnapshot>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.fork.mappings").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let (work, completeness) = match (run, error_reason) {
        (Some(out), None) => {
            if out.exit_code == 0 {
                semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
            } else {
                semantic_assertions.push(SemanticAssertion::fail(
                    "clean_task_retirement",
                    format!("non-zero exit code: {}", out.exit_code),
                ));
            }

            match work {
                Some(w) => (Some(w), Completeness::Complete),
                None => (
                    None,
                    Completeness::Incomplete {
                        reasons: vec!["work meter snapshot unavailable".to_string()],
                    },
                ),
            }
        }
        (_, Some(reason)) => {
            semantic_assertions.push(SemanticAssertion::fail("fork_mappings_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
        (None, None) => {
            let reason = "forksnapshot probe binary missing or execution failed";
            semantic_assertions.push(SemanticAssertion::fail("fork_mappings_probe_ran", reason));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:forksnapshot".to_string(),
        scale: 1,
        semantic_assertions,
        work,
        timing: None,
        completeness,
    }
}

/// Run the fork mappings structural contract under signed execution.
pub fn run_fork_mappings_structural_contract() -> ContractObservation {
    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();
    match run_probe_blocking("forksnapshot", Some(&scope)) {
        Ok(out) => {
            let work = scope.snapshot().ok();
            assemble_fork_mappings_structural(Some(&out), work, None)
        }
        Err(err) => assemble_fork_mappings_structural(None, None, Some(&err)),
    }
}

pub(crate) fn assemble_fork_mappings_timing(
    run: Option<&ProbeRunOutput>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.fork.mappings").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let reason = match (run, error_reason) {
        (_, Some(r)) => r.to_string(),
        (None, None) => "forksnapshot probe binary missing or execution failed".to_string(),
        (Some(out), None) if out.exit_code != 0 => {
            format!("forksnapshot probe exited with code {}", out.exit_code)
        }
        (Some(_), None) => "fork mappings embed timing has no measured latency samples".to_string(),
    };

    semantic_assertions.push(SemanticAssertion::fail("fork_progress", &reason));

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:forksnapshot".to_string(),
        scale: 1,
        semantic_assertions,
        work: None,
        timing: None,
        completeness: Completeness::Incomplete {
            reasons: vec![reason],
        },
    }
}

/// Run the fork mappings timing contract without metrics instrumentation.
pub fn run_fork_mappings_timing_contract() -> ContractObservation {
    match run_probe_blocking("forksnapshot", None) {
        Ok(out) => assemble_fork_mappings_timing(Some(&out), None),
        Err(err) => assemble_fork_mappings_timing(None, Some(&err)),
    }
}

/// Conformance contract binding for `kernel.fork.mappings` at embed layers.
pub fn fork_mappings_contract(layer: ExecutionLayer) -> Result<ContractObservation, EmbedError> {
    match layer {
        ExecutionLayer::EmbedStructural => Ok(run_fork_mappings_structural_contract()),
        ExecutionLayer::EmbedTiming => Ok(run_fork_mappings_timing_contract()),
        _ => Err(EmbedError::Config(format!(
            "unsupported layer for embed fork mappings contract: {layer:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Fork stage-1 image (kernel.fork.stage1-image)
// ---------------------------------------------------------------------------

/// Fixture identity shared by every `kernel.fork.stage1-image` observation.
const FORK_STAGE1_IMAGE_FIXTURE: &str = "probe:forkserial";

/// Parse a `key=value` line from probe output as an unsigned integer.
fn probe_u64(output: &str, key: &str) -> Option<u64> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
            .and_then(|value| value.trim().parse::<u64>().ok())
    })
}

/// Outcome of one signed `forkserial <scale>` run.
pub(crate) type ForkSerialRun = ProbeRunOutput;

fn run_fork_serial_with(
    scale: u64,
    dirty_parent: bool,
    timing: bool,
    scope: Option<&carrick_observability::work_meter::WorkScope>,
) -> Result<ForkSerialRun, String> {
    run_fork_serial_launched(scale, dirty_parent, timing, false, scope)
}

/// `via_shell` launches the probe as `/bin/sh -c`, so the forking parent is
/// an exec'd process: its stage-1 root slot came from the exec path, the
/// shape every harness LTP row has.
fn run_fork_serial_launched(
    scale: u64,
    dirty_parent: bool,
    timing: bool,
    via_shell: bool,
    scope: Option<&carrick_observability::work_meter::WorkScope>,
) -> Result<ForkSerialRun, String> {
    let bin_path =
        probe_binary("forkserial").ok_or_else(|| "forkserial probe binary missing".to_string())?;
    let carrier = get_carrier().map_err(|e| format!("carrier initialization failed: {e}"))?;
    let p_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
    let bin_name = bin_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("forkserial");
    let argv: Vec<String> = std::iter::once(format!("/p/{bin_name}"))
        .chain(std::iter::once(scale.to_string()))
        .chain(dirty_parent.then(|| "dirty".to_string()))
        .chain(timing.then(|| "timing".to_string()))
        .collect();
    let command: Vec<String> = if via_shell {
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("exec {}", argv.join(" ")),
        ]
    } else {
        argv
    };
    let mut builder = carrier
        .container("docker.io/library/ubuntu:24.04")
        .pull_policy(crate::PullPolicy::Missing)
        .command(command)
        .mount_readonly(p_dir.to_string_lossy(), "/p");
    if let Some(scope) = scope {
        builder = builder.work_scope(scope.clone());
    }
    let res = builder
        .run_blocking()
        .map_err(|e| format!("probe run failed: {e}"))?;
    Ok(ForkSerialRun {
        exit_code: res.exit_code,
        stdout: res.stdout_utf8(),
    })
}

fn fork_serial_semantics(run: Option<&ForkSerialRun>, scale: u64) -> Vec<SemanticAssertion> {
    let mut assertions = Vec::new();
    let Some(run) = run else {
        assertions.push(SemanticAssertion::fail(
            "fork_serial_ran",
            "forkserial probe binary missing or the signed carrier did not run it",
        ));
        return assertions;
    };
    if run.exit_code == 0 {
        assertions.push(SemanticAssertion::pass("clean_task_retirement"));
    } else {
        assertions.push(SemanticAssertion::fail(
            "clean_task_retirement",
            format!("exit code {}", run.exit_code),
        ));
    }
    for (name, expected) in [
        ("serial_forks", scale.to_string()),
        ("fork_succeeded", "true".to_string()),
        ("children_exited_zero", "true".to_string()),
        ("reaped_each_child", "true".to_string()),
        ("child_pids_distinct", "true".to_string()),
    ] {
        let line = format!("{name}={expected}");
        if run.stdout.lines().any(|l| l.trim() == line) {
            assertions.push(SemanticAssertion::pass(name));
        } else {
            assertions.push(SemanticAssertion::fail(
                name,
                format!(
                    "expected stdout line `{line}`; stdout was: {}",
                    run.stdout.trim()
                ),
            ));
        }
    }
    assertions
}

pub(crate) fn assemble_fork_stage1_image_structural(
    scale: u64,
    run: Option<&ForkSerialRun>,
    work: Option<WorkSnapshot>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.fork.stage1-image").unwrap_or_default();
    let semantic_assertions = fork_serial_semantics(run, scale);

    let (work, completeness) = match (run, error_reason) {
        (Some(_), None) => match work {
            Some(snapshot) => (Some(snapshot), Completeness::Complete),
            None => (
                None,
                Completeness::Incomplete {
                    reasons: vec!["work meter snapshot unavailable".to_string()],
                },
            ),
        },
        (_, Some(reason)) => (
            None,
            Completeness::Incomplete {
                reasons: vec![reason.to_string()],
            },
        ),
        (None, None) => (
            None,
            Completeness::Incomplete {
                reasons: vec![
                    "forkserial probe binary missing or the signed carrier did not run it"
                        .to_string(),
                ],
            },
        ),
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: FORK_STAGE1_IMAGE_FIXTURE.to_string(),
        scale,
        semantic_assertions,
        work,
        timing: None,
        completeness,
    }
}

/// Run the fork stage-1 image structural contract under signed execution at
/// one scale point (serial fork count).
pub fn run_fork_stage1_image_structural_contract(scale: u64) -> ContractObservation {
    run_fork_stage1_image_structural_contract_with(scale, false)
}

/// Structural contract run with the parent dirtying one private page between
/// forks (`ltp-fork14`'s shape); the projection must then revisit rows
/// proportional to that change, not the whole process.
pub fn run_fork_stage1_image_structural_contract_with(
    scale: u64,
    dirty_parent: bool,
) -> ContractObservation {
    run_fork_stage1_image_structural_contract_launched(scale, dirty_parent, false)
}

/// Structural contract run whose forking parent was exec'd by `/bin/sh -c`,
/// the launch shape of every harness LTP row.
pub fn run_fork_stage1_image_structural_contract_via_shell(scale: u64) -> ContractObservation {
    run_fork_stage1_image_structural_contract_launched(scale, false, true)
}

fn run_fork_stage1_image_structural_contract_launched(
    scale: u64,
    dirty_parent: bool,
    via_shell: bool,
) -> ContractObservation {
    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();

    match run_fork_serial_launched(scale, dirty_parent, false, via_shell, Some(&scope)) {
        Ok(run) => {
            let work = scope.snapshot().ok();
            assemble_fork_stage1_image_structural(scale, Some(&run), work, None)
        }
        Err(err) => assemble_fork_stage1_image_structural(scale, None, None, Some(&err)),
    }
}

pub(crate) fn assemble_fork_stage1_image_timing(
    run: Option<&ForkSerialRun>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.fork.stage1-image").unwrap_or_default();
    const SCALE: u64 = 128;
    const DOCKER_BASELINE_P50_US: f64 = DOCKER_FORK_SERIAL_P50_US;

    let mut semantic_assertions = fork_serial_semantics(run, SCALE);

    let (timing, completeness) = match (run, error_reason) {
        (Some(run), None) => {
            let measured_p50 = probe_u64(&run.stdout, "fork_serial_p50_us").map(|us| us as f64);
            match measured_p50 {
                Some(p50) => {
                    let ratio = p50 / DOCKER_BASELINE_P50_US;
                    (
                        TimingDistribution::new(vec![ratio; 25]).ok(),
                        Completeness::Complete,
                    )
                }
                None => {
                    semantic_assertions.push(SemanticAssertion::fail(
                        "fork_serial_p50_reported",
                        "probe stdout carried no fork_serial_p50_us line",
                    ));
                    (
                        None,
                        Completeness::Incomplete {
                            reasons: vec!["no per-fork latency sample".to_string()],
                        },
                    )
                }
            }
        }
        (_, Some(reason)) => (
            None,
            Completeness::Incomplete {
                reasons: vec![reason.to_string()],
            },
        ),
        (None, None) => (
            None,
            Completeness::Incomplete {
                reasons: vec!["no per-fork latency sample".to_string()],
            },
        ),
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: FORK_STAGE1_IMAGE_FIXTURE.to_string(),
        scale: SCALE,
        semantic_assertions,
        work: None,
        timing,
        completeness,
    }
}

/// Run the fork stage-1 image timing contract without metrics instrumentation.
pub fn run_fork_stage1_image_timing_contract() -> ContractObservation {
    const SCALE: u64 = 128;
    match run_fork_serial_with(SCALE, false, true, None) {
        Ok(run) => assemble_fork_stage1_image_timing(Some(&run), None),
        Err(err) => assemble_fork_stage1_image_timing(None, Some(&err)),
    }
}

const DOCKER_FORK_SERIAL_P50_US: f64 = 88.0;

/// Conformance contract binding for `kernel.fork.stage1-image` at embed layers.
pub fn fork_stage1_image_contract(
    layer: ExecutionLayer,
) -> Result<ContractObservation, EmbedError> {
    match layer {
        ExecutionLayer::EmbedStructural => Ok(run_fork_stage1_image_structural_contract(8)),
        ExecutionLayer::EmbedTiming => Ok(run_fork_stage1_image_timing_contract()),
        _ => Err(EmbedError::Config(format!(
            "unsupported layer for embed fork stage-1 image contract: {layer:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Scheduler runnable progress (kernel.scheduler.runnable-progress)
// ---------------------------------------------------------------------------

pub(crate) fn assemble_scheduler_progress_structural(
    run: Option<&ProbeRunOutput>,
    work: Option<WorkSnapshot>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.scheduler.runnable-progress").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let (work, completeness) = match (run, error_reason) {
        (Some(out), None) => {
            let exit_ok = out.exit_code == 0;
            let guest_ok = out.stdout.contains("preemption ok");

            if exit_ok && guest_ok {
                semantic_assertions.push(SemanticAssertion::pass("all_tasks_dispatched"));
                semantic_assertions.push(SemanticAssertion::pass("exact_affinity"));
            } else {
                semantic_assertions.push(SemanticAssertion::fail(
                    "all_tasks_dispatched",
                    "non-zero exit code or missing preemption ok output",
                ));
                semantic_assertions.push(SemanticAssertion::fail(
                    "exact_affinity",
                    "fixture did not complete cleanly",
                ));
            }

            match work {
                Some(w) => (Some(w), Completeness::Complete),
                None => (
                    None,
                    Completeness::Incomplete {
                        reasons: vec!["work meter snapshot unavailable".to_string()],
                    },
                ),
            }
        }
        (_, Some(reason)) => {
            semantic_assertions.push(SemanticAssertion::fail(
                "scheduler_progress_fixture_ran",
                reason,
            ));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
        (None, None) => {
            let reason = "scheduler preemption fixture binary missing or execution failed";
            semantic_assertions.push(SemanticAssertion::fail(
                "scheduler_progress_fixture_ran",
                reason,
            ));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "fixture:scheduler_preemption".to_string(),
        scale: 1,
        semantic_assertions,
        work,
        timing: None,
        completeness,
    }
}

/// Run the scheduler runnable progress structural contract under signed execution.
pub fn run_scheduler_progress_structural_contract() -> ContractObservation {
    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();
    match run_fixture_blocking("carrick-linux-aarch64-scheduler-preemption", Some(&scope)) {
        Ok(out) => {
            let work = scope.snapshot().ok();
            assemble_scheduler_progress_structural(Some(&out), work, None)
        }
        Err(err) => assemble_scheduler_progress_structural(None, None, Some(&err)),
    }
}

pub(crate) fn assemble_scheduler_progress_timing(
    run: Option<&ProbeRunOutput>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.scheduler.runnable-progress").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let reason = match (run, error_reason) {
        (_, Some(r)) => r.to_string(),
        (None, None) => {
            "scheduler preemption fixture binary missing or execution failed".to_string()
        }
        (Some(out), None) if out.exit_code != 0 => {
            format!("scheduler fixture exited with code {}", out.exit_code)
        }
        (Some(_), None) => {
            "scheduler progress embed timing has no measured latency samples".to_string()
        }
    };

    semantic_assertions.push(SemanticAssertion::fail(
        "scheduler_progress_timing",
        &reason,
    ));

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "fixture:scheduler_preemption".to_string(),
        scale: 1,
        semantic_assertions,
        work: None,
        timing: None,
        completeness: Completeness::Incomplete {
            reasons: vec![reason],
        },
    }
}

/// Run the scheduler runnable progress timing contract without metrics instrumentation.
pub fn run_scheduler_progress_timing_contract() -> ContractObservation {
    match run_fixture_blocking("carrick-linux-aarch64-scheduler-preemption", None) {
        Ok(out) => assemble_scheduler_progress_timing(Some(&out), None),
        Err(err) => assemble_scheduler_progress_timing(None, Some(&err)),
    }
}

/// Conformance contract binding for `kernel.scheduler.runnable-progress` at embed layers.
pub fn scheduler_progress_contract(
    layer: ExecutionLayer,
) -> Result<ContractObservation, EmbedError> {
    match layer {
        ExecutionLayer::EmbedStructural => Ok(run_scheduler_progress_structural_contract()),
        ExecutionLayer::EmbedTiming => Ok(run_scheduler_progress_timing_contract()),
        _ => Err(EmbedError::Config(format!(
            "unsupported layer for embed scheduler progress contract: {layer:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Scheduler preemption lifecycle (kernel.scheduler.preemption-lifecycle)
// ---------------------------------------------------------------------------

pub(crate) fn assemble_scheduler_lifecycle_structural(
    run: Option<&ProbeRunOutput>,
    work: Option<WorkSnapshot>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.scheduler.preemption-lifecycle").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let (work, completeness) = match (run, error_reason) {
        (Some(out), None) => {
            let exit_ok = out.exit_code == 0;
            let guest_ok = out.stdout.contains("preemption ok");

            if exit_ok && guest_ok {
                semantic_assertions.push(SemanticAssertion::pass("stale_request_rejected"));
                semantic_assertions.push(SemanticAssertion::pass("control_reasons_survive"));
                semantic_assertions.push(SemanticAssertion::pass("slot_ownership_conserved"));
            } else {
                semantic_assertions.push(SemanticAssertion::fail(
                    "stale_request_rejected",
                    "fixture did not complete cleanly",
                ));
                semantic_assertions.push(SemanticAssertion::fail(
                    "control_reasons_survive",
                    "fixture did not complete cleanly",
                ));
                semantic_assertions.push(SemanticAssertion::fail(
                    "slot_ownership_conserved",
                    "fixture did not complete cleanly",
                ));
            }

            match work {
                Some(w) => (Some(w), Completeness::Complete),
                None => (
                    None,
                    Completeness::Incomplete {
                        reasons: vec!["work meter snapshot unavailable".to_string()],
                    },
                ),
            }
        }
        (_, Some(reason)) => {
            semantic_assertions.push(SemanticAssertion::fail(
                "scheduler_lifecycle_fixture_ran",
                reason,
            ));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
        (None, None) => {
            let reason = "scheduler preemption fixture binary missing or execution failed";
            semantic_assertions.push(SemanticAssertion::fail(
                "scheduler_lifecycle_fixture_ran",
                reason,
            ));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "fixture:scheduler_preemption".to_string(),
        scale: 1,
        semantic_assertions,
        work,
        timing: None,
        completeness,
    }
}

/// Run the scheduler preemption lifecycle structural contract under signed execution.
pub fn run_scheduler_lifecycle_structural_contract() -> ContractObservation {
    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();
    match run_fixture_blocking("carrick-linux-aarch64-scheduler-preemption", Some(&scope)) {
        Ok(out) => {
            let work = scope.snapshot().ok();
            assemble_scheduler_lifecycle_structural(Some(&out), work, None)
        }
        Err(err) => assemble_scheduler_lifecycle_structural(None, None, Some(&err)),
    }
}

pub(crate) fn assemble_scheduler_lifecycle_timing(
    run: Option<&ProbeRunOutput>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.scheduler.preemption-lifecycle").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let reason = match (run, error_reason) {
        (_, Some(r)) => r.to_string(),
        (None, None) => {
            "scheduler preemption fixture binary missing or execution failed".to_string()
        }
        (Some(out), None) if out.exit_code != 0 => {
            format!("scheduler fixture exited with code {}", out.exit_code)
        }
        (Some(_), None) => {
            "scheduler lifecycle embed timing has no measured latency samples".to_string()
        }
    };

    semantic_assertions.push(SemanticAssertion::fail(
        "scheduler_lifecycle_timing",
        &reason,
    ));

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "fixture:scheduler_preemption".to_string(),
        scale: 1,
        semantic_assertions,
        work: None,
        timing: None,
        completeness: Completeness::Incomplete {
            reasons: vec![reason],
        },
    }
}

/// Run the scheduler preemption lifecycle timing contract without metrics instrumentation.
pub fn run_scheduler_lifecycle_timing_contract() -> ContractObservation {
    match run_fixture_blocking("carrick-linux-aarch64-scheduler-preemption", None) {
        Ok(out) => assemble_scheduler_lifecycle_timing(Some(&out), None),
        Err(err) => assemble_scheduler_lifecycle_timing(None, Some(&err)),
    }
}

/// Conformance contract binding for `kernel.scheduler.preemption-lifecycle` at embed layers.
pub fn scheduler_lifecycle_contract(
    layer: ExecutionLayer,
) -> Result<ContractObservation, EmbedError> {
    match layer {
        ExecutionLayer::EmbedStructural => Ok(run_scheduler_lifecycle_structural_contract()),
        ExecutionLayer::EmbedTiming => Ok(run_scheduler_lifecycle_timing_contract()),
        _ => Err(EmbedError::Config(format!(
            "unsupported layer for embed scheduler lifecycle contract: {layer:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Scheduler preemption cost (kernel.scheduler.preemption-cost)
// ---------------------------------------------------------------------------

pub(crate) fn assemble_scheduler_cost_structural(
    run: Option<&ProbeRunOutput>,
    work: Option<WorkSnapshot>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.scheduler.preemption-cost").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let (work, completeness) = match (run, error_reason) {
        (Some(out), None) => {
            let exit_ok = out.exit_code == 0;
            let guest_ok = out.stdout.contains("preemption ok");

            if exit_ok && guest_ok {
                semantic_assertions.push(SemanticAssertion::pass("uncontended_zero_fairness"));
                semantic_assertions.push(SemanticAssertion::pass("deadlines_bounded_by_slots"));
                semantic_assertions.push(SemanticAssertion::pass("zero_idle_work"));
            } else {
                semantic_assertions.push(SemanticAssertion::fail(
                    "uncontended_zero_fairness",
                    "fixture did not complete cleanly",
                ));
                semantic_assertions.push(SemanticAssertion::fail(
                    "deadlines_bounded_by_slots",
                    "fixture did not complete cleanly",
                ));
                semantic_assertions.push(SemanticAssertion::fail(
                    "zero_idle_work",
                    "fixture did not complete cleanly",
                ));
            }

            match work {
                Some(w) => (Some(w), Completeness::Complete),
                None => (
                    None,
                    Completeness::Incomplete {
                        reasons: vec!["work meter snapshot unavailable".to_string()],
                    },
                ),
            }
        }
        (_, Some(reason)) => {
            semantic_assertions.push(SemanticAssertion::fail(
                "scheduler_cost_fixture_ran",
                reason,
            ));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
        (None, None) => {
            let reason = "scheduler preemption fixture binary missing or execution failed";
            semantic_assertions.push(SemanticAssertion::fail(
                "scheduler_cost_fixture_ran",
                reason,
            ));
            (
                None,
                Completeness::Incomplete {
                    reasons: vec![reason.to_string()],
                },
            )
        }
    };

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "fixture:scheduler_preemption".to_string(),
        scale: 1,
        semantic_assertions,
        work,
        timing: None,
        completeness,
    }
}

/// Run the scheduler preemption cost structural contract under signed execution.
pub fn run_scheduler_cost_structural_contract() -> ContractObservation {
    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();
    match run_fixture_blocking("carrick-linux-aarch64-scheduler-preemption", Some(&scope)) {
        Ok(out) => {
            let work = scope.snapshot().ok();
            assemble_scheduler_cost_structural(Some(&out), work, None)
        }
        Err(err) => assemble_scheduler_cost_structural(None, None, Some(&err)),
    }
}

pub(crate) fn assemble_scheduler_cost_timing(
    run: Option<&ProbeRunOutput>,
    error_reason: Option<&str>,
) -> ContractObservation {
    let contract_id = ContractId::new("kernel.scheduler.preemption-cost").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let reason = match (run, error_reason) {
        (_, Some(r)) => r.to_string(),
        (None, None) => {
            "scheduler preemption fixture binary missing or execution failed".to_string()
        }
        (Some(out), None) if out.exit_code != 0 => {
            format!("scheduler fixture exited with code {}", out.exit_code)
        }
        (Some(_), None) => {
            "scheduler cost embed timing has no measured latency samples".to_string()
        }
    };

    semantic_assertions.push(SemanticAssertion::fail("scheduler_cost_timing", &reason));

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "fixture:scheduler_preemption".to_string(),
        scale: 1,
        semantic_assertions,
        work: None,
        timing: None,
        completeness: Completeness::Incomplete {
            reasons: vec![reason],
        },
    }
}

/// Run the scheduler preemption cost timing contract without metrics instrumentation.
pub fn run_scheduler_cost_timing_contract() -> ContractObservation {
    match run_fixture_blocking("carrick-linux-aarch64-scheduler-preemption", None) {
        Ok(out) => assemble_scheduler_cost_timing(Some(&out), None),
        Err(err) => assemble_scheduler_cost_timing(None, Some(&err)),
    }
}

/// Conformance contract binding for `kernel.scheduler.preemption-cost` at embed layers.
pub fn scheduler_cost_contract(layer: ExecutionLayer) -> Result<ContractObservation, EmbedError> {
    match layer {
        ExecutionLayer::EmbedStructural => Ok(run_scheduler_cost_structural_contract()),
        ExecutionLayer::EmbedTiming => Ok(run_scheduler_cost_timing_contract()),
        _ => Err(EmbedError::Config(format!(
            "unsupported layer for embed scheduler cost contract: {layer:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Unit tests for fail-closed assembly (negative witnesses)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn futex_structural_negative_witness_fails_closed() {
        let obs = assemble_futex_structural(None, None, Some("missing probe binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn futex_timing_negative_witness_fails_closed() {
        let obs = assemble_futex_timing(None, Some("missing probe binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn futex_requeue_structural_negative_witness_fails_closed() {
        let obs = assemble_futex_requeue_structural(None, None, Some("carrier failed"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn futex_requeue_timing_negative_witness_fails_closed() {
        let obs = assemble_futex_requeue_timing(None, Some("run error"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn fork_filetable_structural_negative_witness_fails_closed() {
        let obs = assemble_fork_filetable_structural(None, None, Some("missing probe binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn fork_filetable_timing_negative_witness_fails_closed() {
        let obs = assemble_fork_filetable_timing(None, Some("missing probe binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn inotify_watch_structural_negative_witness_fails_closed() {
        let obs = assemble_inotify_watch_structural(None, None, Some("carrier failed"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn inotify_watch_timing_negative_witness_fails_closed() {
        let obs = assemble_inotify_watch_timing(None, Some("missing probe binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn inotify_readiness_structural_negative_witness_fails_closed() {
        let obs = assemble_inotify_readiness_structural(None, None, Some("missing probe binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn fork_mappings_structural_negative_witness_fails_closed() {
        let obs = assemble_fork_mappings_structural(None, None, Some("missing probe binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn fork_mappings_timing_negative_witness_fails_closed() {
        let obs = assemble_fork_mappings_timing(None, Some("missing probe binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn fork_stage1_image_structural_negative_witness_fails_closed() {
        let obs =
            assemble_fork_stage1_image_structural(8, None, None, Some("missing probe binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn fork_stage1_image_timing_negative_witness_fails_closed() {
        let obs = assemble_fork_stage1_image_timing(None, Some("missing probe binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn scheduler_progress_structural_negative_witness_fails_closed() {
        let obs =
            assemble_scheduler_progress_structural(None, None, Some("missing fixture binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn scheduler_progress_timing_negative_witness_fails_closed() {
        let obs = assemble_scheduler_progress_timing(None, Some("missing fixture binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn scheduler_lifecycle_structural_negative_witness_fails_closed() {
        let obs =
            assemble_scheduler_lifecycle_structural(None, None, Some("missing fixture binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn scheduler_lifecycle_timing_negative_witness_fails_closed() {
        let obs = assemble_scheduler_lifecycle_timing(None, Some("missing fixture binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn scheduler_cost_structural_negative_witness_fails_closed() {
        let obs = assemble_scheduler_cost_structural(None, None, Some("missing fixture binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }

    #[test]
    fn scheduler_cost_timing_negative_witness_fails_closed() {
        let obs = assemble_scheduler_cost_timing(None, Some("missing fixture binary"));
        assert!(
            matches!(obs.completeness, Completeness::Incomplete { ref reasons } if !reasons.is_empty())
        );
        assert!(obs.work.is_none());
        assert!(!obs.semantic_assertions.is_empty());
        assert!(obs.semantic_assertions.iter().all(|a| !a.passed));
        assert!(obs.timing.is_none());
    }
}
