// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fail-closed signed binding for the LTP inotify09 four-syscall reduction.

use crate::EmbedError;
use carrick_conformance_contract::{
    Completeness, ContractId, ContractObservation, ExecutionLayer, SemanticAssertion, WorkMetric,
};

fn assertions(stdout: &str, scale: u64) -> Result<Vec<SemanticAssertion>, EmbedError> {
    let expected = [
        ("contract_scale", scale.to_string()),
        ("completed_iterations", scale.to_string()),
        ("probe_complete", "1".into()),
    ];
    let lines = stdout.lines().collect::<Vec<_>>();
    if lines.len() != expected.len() {
        return Err(EmbedError::Config(
            "incomplete or extra inotify hotpath output".into(),
        ));
    }
    let mut result = Vec::new();
    for (key, expected_value) in expected {
        let prefix = format!("{key}=");
        let values = lines
            .iter()
            .filter_map(|line| line.strip_prefix(&prefix))
            .collect::<Vec<_>>();
        if values.len() != 1 {
            return Err(EmbedError::Config(format!(
                "missing or duplicate inotify hotpath field {key}"
            )));
        }
        result.push(SemanticAssertion {
            name: key.into(),
            passed: values[0] == expected_value,
            detail: Some(format!("expected {expected_value}, observed {}", values[0])),
        });
    }
    Ok(result)
}

/// Run one registered scale against a fresh private rootfs. Missing artifacts,
/// malformed transcripts, failed execution, and unavailable work metrics fail.
pub fn inotify_hotpath_structural_contract(scale: u64) -> Result<ContractObservation, EmbedError> {
    if ![1, 8, 32, 128].contains(&scale) {
        return Err(EmbedError::Config(
            "unregistered inotify hotpath scale".into(),
        ));
    }
    if !cfg!(feature = "conformance-metrics") {
        return Err(EmbedError::Config(
            "inotify hotpath binding requires conformance-metrics".into(),
        ));
    }
    let identity = std::env::var("CARRICK_OBSERVATION_SOURCE")
        .map_err(|_| EmbedError::Config("CARRICK_OBSERVATION_SOURCE required".into()))?;
    if identity.len() != 64 || !identity.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EmbedError::Config("source identity must be SHA-256".into()));
    }
    let image = std::env::var("CARRICK_INOTIFY_HOTPATH_IMAGE")
        .map_err(|_| EmbedError::Config("pinned CARRICK_INOTIFY_HOTPATH_IMAGE required".into()))?;
    if !image.split_once("@sha256:").is_some_and(|(_, digest)| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err(EmbedError::Config(
            "inotify hotpath image must be digest-pinned".into(),
        ));
    }
    let binary = super::probe_binary("perf_inotify09_scale")
        .ok_or_else(|| EmbedError::Config("perf_inotify09_scale probe binary missing".into()))?;
    let directory = binary
        .parent()
        .ok_or_else(|| EmbedError::Config("probe has no parent".into()))?;
    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();
    let carrier = crate::Carrier::new()?;
    let result = carrier
        .container(image)
        .pull_policy(crate::PullPolicy::Missing)
        .mount_readonly(directory.to_string_lossy(), "/p")
        .command([
            "/p/perf_inotify09_scale".into(),
            "contract-scale".into(),
            scale.to_string(),
        ])
        .max_traps(100_000)
        .work_scope(scope.clone())
        .run_blocking();
    let shutdown = carrick_engine::block_on_oci(carrier.shutdown());
    let result = result?;
    shutdown?;
    let result = result.ensure_success()?;
    let semantic_assertions = assertions(&result.stdout_utf8(), scale)?;
    let work = scope
        .snapshot()
        .map_err(|error| EmbedError::Config(error.to_string()))?;
    if work.get(WorkMetric::HostBackendCalls).is_none() {
        return Err(EmbedError::Config(
            "host backend call meter unavailable".into(),
        ));
    }
    Ok(ContractObservation {
        contract_id: ContractId::new("kernel.inotify.mark-race-hotpath")
            .map_err(|error| EmbedError::Config(error.to_string()))?,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: identity,
        fixture_identity: "probe:perf_inotify09_scale".into(),
        scale,
        semantic_assertions,
        work: Some(work),
        timing: None,
        completeness: Completeness::Complete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_rejects_missing_duplicate_and_incomplete_runs() {
        let good = "contract_scale=8\ncompleted_iterations=8\nprobe_complete=1\n";
        assert!(assertions(good, 8).unwrap().iter().all(|item| item.passed));
        assert!(assertions("", 8).is_err());
        assert!(assertions(&good.replace("probe_complete=1", "contract_scale=8"), 8).is_err());
        assert!(
            !assertions(
                &good.replace("completed_iterations=8", "completed_iterations=7"),
                8
            )
            .unwrap()
            .iter()
            .all(|item| item.passed)
        );
    }
}
