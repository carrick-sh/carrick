//! Receipt validation fixtures exercise the runner and evaluator. They are not
//! guest-defect evidence; the live write/seek producer is the separate pilot.
use carrick_conformance_contract::ContractId;
use carrick_investigation::evidence::{capture_vm_free, source_identity, validate_red};
use serde_json::json;
use std::{path::PathBuf, process::Command, time::Duration};

#[allow(clippy::unwrap_used)]
fn fixture(active: bool, queries: u64) -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(root)
            .status()
            .unwrap()
            .success()
    );
    let contracts = root.join("conformance-contracts/contracts");
    std::fs::create_dir_all(&contracts).unwrap();
    std::fs::write(
        contracts.join("write-seek.toml"),
        include_str!("../../../conformance-contracts/contracts/write-seek.toml"),
    )
    .unwrap();
    std::fs::write(
        root.join("conformance-contracts/surfaces.toml"),
        "schema_version = 1\nsurfaces = []\n",
    )
    .unwrap();
    assert!(
        Command::new("git")
            .current_dir(root)
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "fixture"
            ])
            .status()
            .unwrap()
            .success()
    );
    let identity = source_identity(root).unwrap();
    let input = root.join("observation.json");
    std::fs::write(&input, serde_json::to_vec(&json!([{
        "contract_id": "kernel.fs.write-seek", "layer": "vm-free",
        "implementation_revision": identity, "fixture_identity": "script:write-seek-host-file", "scale": 1,
        "semantic_assertions": [{"name": "fixture.active", "passed": active, "detail": null}],
        "work": {"values": {"host_write_position_queries": queries}, "unknown_metrics": [], "overflowed_metrics": [], "dropped_events": 0},
        "timing": null, "completeness": {"status": "complete"}
    }])).unwrap()).unwrap();
    let path = capture_vm_free(
        root,
        std::path::Path::new("/bin/cat"),
        &[input.to_string_lossy().into_owned()],
        &root.join("run"),
        ContractId::new("kernel.fs.write-seek").unwrap(),
        Duration::from_secs(5),
    )
    .unwrap();
    (temp, path)
}

#[test]
fn executed_red_is_accepted_but_changed_output_is_rejected() {
    let (_temp, receipt) = fixture(true, 1);
    let valid = validate_red(&receipt).unwrap();
    std::fs::write(valid.stdout, b"[]").unwrap();
    assert!(validate_red(&receipt).is_err());
}

#[test]
fn green_observation_is_not_red_evidence() {
    let (_temp, receipt) = fixture(true, 0);
    assert!(validate_red(&receipt).is_err());
}

#[test]
fn inactive_fixture_is_not_semantic_red() {
    let (_temp, receipt) = fixture(false, 1);
    assert!(validate_red(&receipt).is_err());
}

#[test]
fn changed_source_invalidates_red() {
    let (temp, receipt) = fixture(true, 1);
    std::fs::create_dir(temp.path().join("crates")).unwrap();
    std::fs::write(temp.path().join("crates/new.rs"), "// changed").unwrap();
    assert!(validate_red(&receipt).is_err());
}
