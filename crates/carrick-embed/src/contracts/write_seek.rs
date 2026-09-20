//! Fail-closed signed binding for the regular-file write/seek reduction.
use crate::EmbedError;
use carrick_conformance_contract::{
    Completeness, ContractId, ContractObservation, ExecutionLayer, SemanticAssertion,
};

fn assertions(stdout: &str, scale: u64) -> Result<Vec<SemanticAssertion>, EmbedError> {
    let expected = [
        ("iterations", scale.to_string()),
        ("completed_writes", scale.to_string()),
        ("completed_rewinds", scale.to_string()),
        ("file_limit_unlimited", "true".into()),
        ("bytes_match", "true".into()),
        ("offset_matches", "true".into()),
        ("length_matches", "true".into()),
        ("closed", "true".into()),
        ("removed", "true".into()),
    ];
    let lines: Vec<_> = stdout.lines().collect();
    if lines.len() != expected.len() {
        return Err(EmbedError::Config(
            "incomplete or extra write/seek output".into(),
        ));
    }
    let mut result = Vec::new();
    for (key, expected_value) in expected {
        let prefix = format!("{key}=");
        let values: Vec<_> = lines
            .iter()
            .filter_map(|line| line.strip_prefix(&prefix))
            .collect();
        if values.len() != 1 {
            return Err(EmbedError::Config(format!(
                "missing or duplicate write/seek field {key}"
            )));
        }
        result.push(SemanticAssertion {
            name: key.into(),
            passed: values[0] == expected_value,
            detail: Some(format!("expected {expected_value}, observed {}", values[0])),
        });
    }
    let active = result
        .iter()
        .filter(|a| {
            matches!(
                a.name.as_str(),
                "iterations" | "completed_writes" | "completed_rewinds"
            )
        })
        .all(|a| a.passed);
    result.push(SemanticAssertion {
        name: "fixture.active".into(),
        passed: active,
        detail: None,
    });
    Ok(result)
}

/// Run exactly one scale on a fresh writable host-backed mount. Missing binaries,
/// failed execution, malformed transcripts and unavailable meters are errors.
pub fn write_seek_structural_contract(scale: u64) -> Result<ContractObservation, EmbedError> {
    if ![1, 8, 32, 128].contains(&scale) {
        return Err(EmbedError::Config("unregistered write/seek scale".into()));
    }
    if !cfg!(feature = "conformance-metrics") {
        return Err(EmbedError::Config(
            "write/seek binding requires conformance-metrics".into(),
        ));
    }
    let identity = std::env::var("CARRICK_OBSERVATION_SOURCE")
        .map_err(|_| EmbedError::Config("CARRICK_OBSERVATION_SOURCE required".into()))?;
    if identity.len() != 64 || !identity.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(EmbedError::Config("source identity must be SHA-256".into()));
    }
    let image = std::env::var("CARRICK_WRITE_SEEK_IMAGE")
        .map_err(|_| EmbedError::Config("pinned CARRICK_WRITE_SEEK_IMAGE required".into()))?;
    if !image.split_once("@sha256:").is_some_and(|(_, digest)| {
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
    }) {
        return Err(EmbedError::Config(
            "write/seek image must be digest-pinned".into(),
        ));
    }
    let binary = super::probe_binary("writeseek")
        .ok_or_else(|| EmbedError::Config("writeseek probe binary missing".into()))?;
    let directory = binary
        .parent()
        .ok_or_else(|| EmbedError::Config("probe has no parent".into()))?;
    let scratch = tempfile::tempdir().map_err(|e| EmbedError::Config(e.to_string()))?;
    let meter = carrick_observability::work_meter::WorkMeter::default();
    let scope = meter.new_scope();
    // No carrier retry: another active carrier is an admission failure.
    let carrier = crate::Carrier::new()?;
    let result = carrier
        .container(image)
        .pull_policy(crate::PullPolicy::Missing)
        .mount_readonly(directory.to_string_lossy(), "/p")
        .mount(scratch.path().to_string_lossy(), "/work")
        .command([
            "/p/writeseek".into(),
            scale.to_string(),
            "/work/file".into(),
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
        .map_err(|e| EmbedError::Config(e.to_string()))?;
    if work
        .get(carrick_conformance_contract::WorkMetric::HostWritePositionQueries)
        .is_none()
    {
        return Err(EmbedError::Config(
            "host write position meter unavailable".into(),
        ));
    }
    Ok(ContractObservation {
        contract_id: ContractId::new("kernel.fs.write-seek")
            .map_err(|e| EmbedError::Config(e.to_string()))?,
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: identity,
        fixture_identity: "script:write-seek-host-file".into(),
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
    const GOOD: &str = "iterations=8\ncompleted_writes=8\ncompleted_rewinds=8\nfile_limit_unlimited=true\nbytes_match=true\noffset_matches=true\nlength_matches=true\nclosed=true\nremoved=true\n";
    #[test]
    fn write_seek_output_rejects_missing_duplicate_and_unexecuted_fixture() {
        assert!(assertions("", 8).is_err());
        assert!(
            assertions(
                &GOOD.replace("completed_rewinds=8", "completed_writes=8"),
                8
            )
            .is_err()
        );
        let inactive =
            assertions(&GOOD.replace("completed_writes=8", "completed_writes=0"), 8).unwrap();
        assert!(
            !inactive
                .iter()
                .find(|a| a.name == "fixture.active")
                .unwrap()
                .passed
        );
        assert!(assertions(GOOD, 8).unwrap().iter().all(|a| a.passed));
    }
}
