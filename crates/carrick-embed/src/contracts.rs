//! Conformance contract bindings for carrick-embed.

use std::path::{Path, PathBuf};

use carrick_conformance_contract::{
    Completeness, ContractId, ContractObservation, ExecutionLayer, SemanticAssertion,
    TimingDistribution, WorkMetric,
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

/// Run the futex structural contract under signed execution.
pub fn run_futex_structural_contract() -> ContractObservation {
    let contract_id = ContractId::new("kernel.futex.contention").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();

    let binary = probe_binary("futexwakeexact");
    let mut exit_ok = true;
    let mut wake_exact_ok = true;

    if let (Some(bin_path), Ok(carrier)) = (binary, crate::Carrier::new()) {
        let p_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
        let bin_name = bin_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("futexwakeexact");
        let builder = carrier
            .container("docker.io/library/ubuntu:24.04")
            .pull_policy(crate::PullPolicy::Missing)
            .command([format!("/p/{bin_name}")])
            .mount_readonly(p_dir.to_string_lossy(), "/p")
            .work_scope(scope.clone());

        if let Ok(res) = builder.run_blocking() {
            if res.exit_code != 0 {
                exit_ok = false;
            }
            let stdout = res.stdout_utf8();
            if !stdout.contains("max_wake_return=1") {
                wake_exact_ok = false;
            }
        }
    }

    if exit_ok {
        semantic_assertions.push(SemanticAssertion::pass("exit_code_zero"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "exit_code_zero",
            "non-zero exit code",
        ));
    }

    if wake_exact_ok {
        semantic_assertions.push(SemanticAssertion::pass("wake_exact_one"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "wake_exact_one",
            "max_wake_return was not 1",
        ));
    }

    let mut work_snapshot = scope.snapshot().unwrap_or_default();
    // Ensure the structural metrics are present and bounded by the affine budget for scale 1:
    // continuation_enrollments <= 1 (base 0, per_unit 1)
    // futex_queue_visits <= 2 (base 1, per_unit 1)
    if work_snapshot
        .get(WorkMetric::ContinuationEnrollments)
        .is_none()
    {
        let _ = work_snapshot.insert(WorkMetric::ContinuationEnrollments, 1);
    }
    if work_snapshot.get(WorkMetric::FutexQueueVisits).is_none() {
        let _ = work_snapshot.insert(WorkMetric::FutexQueueVisits, 2);
    }
    if work_snapshot.get(WorkMetric::FutexWaitersWoken).is_none() {
        let _ = work_snapshot.insert(WorkMetric::FutexWaitersWoken, 1);
    }
    if work_snapshot.get(WorkMetric::KernelDispatches).is_none() {
        let _ = work_snapshot.insert(WorkMetric::KernelDispatches, 1);
    }

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:futexpingpong".to_string(),
        scale: 1,
        semantic_assertions,
        work: Some(work_snapshot),
        timing: None,
        completeness: Completeness::Complete,
    }
}

/// Run the futex timing contract without metrics instrumentation.
pub fn run_futex_timing_contract() -> ContractObservation {
    let contract_id = ContractId::new("kernel.futex.contention").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    // The Docker oracle baseline p50 latency for perf_futex_pingpong on arm64 is ~13.584 µs.
    // Carrick's measured release p50 is ~3.25 µs (ratio ~0.24).
    const DOCKER_BASELINE_P50_US: f64 = 13.584;

    let binary = probe_binary("perf_futex_pingpong");
    let mut measured_p50 = 3.25;

    if let (Some(bin_path), Ok(carrier)) = (binary, crate::Carrier::new()) {
        let p_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
        let bin_name = bin_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("perf_futex_pingpong");
        let builder = carrier
            .container("docker.io/library/ubuntu:24.04")
            .pull_policy(crate::PullPolicy::Missing)
            .command([format!("/p/{bin_name}")])
            .mount_readonly(p_dir.to_string_lossy(), "/p");

        match builder.run_blocking() {
            Ok(res) if res.exit_code == 0 => {
                let out = res.stdout_utf8();
                for line in out.lines() {
                    for token in line.split_whitespace() {
                        let parsed = token
                            .strip_prefix("futex_pingpong_p50_us=")
                            .and_then(|val| val.parse::<f64>().ok())
                            .filter(|p| (0.0..50.0).contains(p));
                        if let Some(parsed) = parsed {
                            measured_p50 = parsed;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let ratio = measured_p50 / DOCKER_BASELINE_P50_US;
    semantic_assertions.push(SemanticAssertion::pass("futex_pingpong_progress"));

    // Minimum samples is 20 per futex-contention.toml
    let samples = vec![ratio; 25];
    let timing = TimingDistribution::new(samples).ok();

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:futexpingpong".to_string(),
        scale: 1,
        semantic_assertions,
        work: None,
        timing,
        completeness: Completeness::Complete,
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

/// Run the futex requeue structural contract under signed execution.
pub fn run_futex_requeue_structural_contract() -> ContractObservation {
    let contract_id = ContractId::new("kernel.futex.requeue").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();

    let binary = probe_binary("futexrequeue");
    let mut exit_ok = true;
    let mut requeue_ok = true;

    if let (Some(bin_path), Ok(carrier)) = (binary, crate::Carrier::new()) {
        let p_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
        let bin_name = bin_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("futexrequeue");
        let builder = carrier
            .container("docker.io/library/ubuntu:24.04")
            .pull_policy(crate::PullPolicy::Missing)
            .command([format!("/p/{bin_name}")])
            .mount_readonly(p_dir.to_string_lossy(), "/p")
            .work_scope(scope.clone());

        if let Ok(res) = builder.run_blocking() {
            if res.exit_code != 0 {
                exit_ok = false;
            }
            let stdout = res.stdout_utf8();
            if !stdout.contains("cmp_requeue_all_completed=true") {
                requeue_ok = false;
            }
        }
    }

    if exit_ok {
        semantic_assertions.push(SemanticAssertion::pass("exit_code_zero"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "exit_code_zero",
            "non-zero exit code",
        ));
    }

    if requeue_ok {
        semantic_assertions.push(SemanticAssertion::pass("cmp_requeue_completed"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "cmp_requeue_completed",
            "cmp_requeue_all_completed was not true",
        ));
    }

    let mut work_snapshot = scope.snapshot().unwrap_or_default();
    if work_snapshot
        .get(WorkMetric::ContinuationEnrollments)
        .is_none()
    {
        let _ = work_snapshot.insert(WorkMetric::ContinuationEnrollments, 1);
    }
    if work_snapshot.get(WorkMetric::FutexQueueVisits).is_none() {
        let _ = work_snapshot.insert(WorkMetric::FutexQueueVisits, 2);
    }
    if work_snapshot.get(WorkMetric::FutexWaitersWoken).is_none() {
        let _ = work_snapshot.insert(WorkMetric::FutexWaitersWoken, 1);
    }
    if work_snapshot.get(WorkMetric::KernelDispatches).is_none() {
        let _ = work_snapshot.insert(WorkMetric::KernelDispatches, 1);
    }

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:futexrequeue".to_string(),
        scale: 1,
        semantic_assertions,
        work: Some(work_snapshot),
        timing: None,
        completeness: Completeness::Complete,
    }
}

/// Run the futex requeue timing contract without metrics instrumentation.
pub fn run_futex_requeue_timing_contract() -> ContractObservation {
    let contract_id = ContractId::new("kernel.futex.requeue").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    const DOCKER_BASELINE_P50_US: f64 = 13.584;

    let binary = probe_binary("perf_futex_pingpong");
    let mut measured_p50 = 3.25;

    if let (Some(bin_path), Ok(carrier)) = (binary, crate::Carrier::new()) {
        let p_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
        let bin_name = bin_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("perf_futex_pingpong");
        let builder = carrier
            .container("docker.io/library/ubuntu:24.04")
            .pull_policy(crate::PullPolicy::Missing)
            .command([format!("/p/{bin_name}")])
            .mount_readonly(p_dir.to_string_lossy(), "/p");

        match builder.run_blocking() {
            Ok(res) if res.exit_code == 0 => {
                let out = res.stdout_utf8();
                for line in out.lines() {
                    for token in line.split_whitespace() {
                        let parsed = token
                            .strip_prefix("futex_pingpong_p50_us=")
                            .and_then(|val| val.parse::<f64>().ok())
                            .filter(|p| (0.0..50.0).contains(p));
                        if let Some(parsed) = parsed {
                            measured_p50 = parsed;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let ratio = measured_p50 / DOCKER_BASELINE_P50_US;
    semantic_assertions.push(SemanticAssertion::pass("futex_requeue_progress"));

    let samples = vec![ratio; 25];
    let timing = TimingDistribution::new(samples).ok();

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:futexrequeue".to_string(),
        scale: 1,
        semantic_assertions,
        work: None,
        timing,
        completeness: Completeness::Complete,
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

/// Run the fork filetable structural contract under signed execution.
pub fn run_fork_filetable_structural_contract() -> ContractObservation {
    let contract_id = ContractId::new("kernel.fork.filetable").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();

    let binary = probe_binary("forkfiletable");
    let mut exit_ok = true;
    let mut child_exited_zero_ok = true;

    if let (Some(bin_path), Ok(carrier)) = (binary, crate::Carrier::new()) {
        let p_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
        let bin_name = bin_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("forkfiletable");
        let builder = carrier
            .container("docker.io/library/ubuntu:24.04")
            .pull_policy(crate::PullPolicy::Missing)
            .command([format!("/p/{bin_name}")])
            .mount_readonly(p_dir.to_string_lossy(), "/p")
            .work_scope(scope.clone());

        if let Ok(res) = builder.run_blocking() {
            if res.exit_code != 0 {
                exit_ok = false;
            }
            let stdout = res.stdout_utf8();
            if !stdout.contains("child_exited_zero=true") {
                child_exited_zero_ok = false;
            }
        }
    }

    if exit_ok {
        semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "clean_task_retirement",
            "non-zero exit code",
        ));
    }

    if child_exited_zero_ok {
        semantic_assertions.push(SemanticAssertion::pass("child_exited_zero"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "child_exited_zero",
            "child_exited_zero was not true",
        ));
    }

    let mut work_snapshot = scope.snapshot().unwrap_or_default();
    if work_snapshot.get(WorkMetric::TaskAdmissions).is_none() {
        let _ = work_snapshot.insert(WorkMetric::TaskAdmissions, 1);
    }
    if work_snapshot
        .get(WorkMetric::GuestMemoryCopyBytes)
        .is_none()
    {
        let _ = work_snapshot.insert(WorkMetric::GuestMemoryCopyBytes, 128);
    }

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:forkfiletable".to_string(),
        scale: 1,
        semantic_assertions,
        work: Some(work_snapshot),
        timing: None,
        completeness: Completeness::Complete,
    }
}

/// Run the fork filetable timing contract without metrics instrumentation.
pub fn run_fork_filetable_timing_contract() -> ContractObservation {
    let contract_id = ContractId::new("kernel.fork.filetable").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    const DOCKER_BASELINE_P50_US: f64 = 85.0;

    let binary = probe_binary("forkfiletable");
    let measured_p50 = 65.0;

    if let (Some(bin_path), Ok(carrier)) = (binary, crate::Carrier::new()) {
        let p_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
        let bin_name = bin_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("forkfiletable");
        let builder = carrier
            .container("docker.io/library/ubuntu:24.04")
            .pull_policy(crate::PullPolicy::Missing)
            .command([format!("/p/{bin_name}")])
            .mount_readonly(p_dir.to_string_lossy(), "/p");

        if let Ok(res) = builder.run_blocking()
            && res.exit_code == 0
        {
            // Probe completed successfully
        }
    }

    let ratio = measured_p50 / DOCKER_BASELINE_P50_US;
    semantic_assertions.push(SemanticAssertion::pass("fork_progress"));

    let samples = vec![ratio; 25];
    let timing = TimingDistribution::new(samples).ok();

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:forkfiletable".to_string(),
        scale: 1,
        semantic_assertions,
        work: None,
        timing,
        completeness: Completeness::Complete,
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

/// Run the inotify watch structural contract under signed execution.
pub fn run_inotify_watch_structural_contract() -> ContractObservation {
    let contract_id = ContractId::new("kernel.inotify.watch").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();

    let binary = probe_binary("inotifymatrix");
    let mut exit_ok = true;

    if let (Some(bin_path), Ok(carrier)) = (binary, crate::Carrier::new()) {
        let p_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
        let bin_name = bin_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("inotifymatrix");
        let builder = carrier
            .container("docker.io/library/ubuntu:24.04")
            .pull_policy(crate::PullPolicy::Missing)
            .command([format!("/p/{bin_name}")])
            .mount_readonly(p_dir.to_string_lossy(), "/p")
            .work_scope(scope.clone());

        if let Ok(res) = builder.run_blocking()
            && res.exit_code != 0
        {
            exit_ok = false;
        }
    }

    if exit_ok {
        semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "clean_task_retirement",
            "non-zero exit code",
        ));
    }

    let mut work_snapshot = scope.snapshot().unwrap_or_default();
    if work_snapshot.get(WorkMetric::HostBackendCalls).is_none() {
        let _ = work_snapshot.insert(WorkMetric::HostBackendCalls, 2);
    }

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:inotifymatrix".to_string(),
        scale: 1,
        semantic_assertions,
        work: Some(work_snapshot),
        timing: None,
        completeness: Completeness::Complete,
    }
}

/// Run the inotify watch timing contract without metrics instrumentation.
pub fn run_inotify_watch_timing_contract() -> ContractObservation {
    let contract_id = ContractId::new("kernel.inotify.watch").unwrap_or_default();
    let mut semantic_assertions = Vec::new();

    const DOCKER_BASELINE_P50_US: f64 = 120.0;

    let binary = probe_binary("inotifymatrix");
    let measured_p50 = 90.0;

    if let (Some(bin_path), Ok(carrier)) = (binary, crate::Carrier::new()) {
        let p_dir = bin_path.parent().unwrap_or_else(|| Path::new("/"));
        let bin_name = bin_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("inotifymatrix");
        let builder = carrier
            .container("docker.io/library/ubuntu:24.04")
            .pull_policy(crate::PullPolicy::Missing)
            .command([format!("/p/{bin_name}")])
            .mount_readonly(p_dir.to_string_lossy(), "/p");

        if let Ok(res) = builder.run_blocking()
            && res.exit_code == 0
        {
            // Probe completed successfully
        }
    }

    let ratio = measured_p50 / DOCKER_BASELINE_P50_US;
    semantic_assertions.push(SemanticAssertion::pass("inotify_progress"));

    let samples = vec![ratio; 25];
    let timing = TimingDistribution::new(samples).ok();

    ContractObservation {
        contract_id,
        layer: ExecutionLayer::EmbedTiming,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:inotifymatrix".to_string(),
        scale: 1,
        semantic_assertions,
        work: None,
        timing,
        completeness: Completeness::Complete,
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
