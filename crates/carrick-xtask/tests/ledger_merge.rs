#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::process::Command;

use carrick_xtask::ledger_merge::{MergeConflict, merge_ledger};

#[test]
fn disjoint_probe_additions_merge() {
    let path = "conformance-probes/probe-inventory.json";
    let base = r#"{
  "probe_b": {
    "class": "conformance",
    "excluded": false,
    "runner": "generic"
  }
}"#;
    let ours = r#"{
  "probe_a": {
    "class": "conformance",
    "excluded": false,
    "runner": "generic"
  },
  "probe_b": {
    "class": "conformance",
    "excluded": false,
    "runner": "generic"
  }
}"#;
    let theirs = r#"{
  "probe_b": {
    "class": "conformance",
    "excluded": false,
    "runner": "generic"
  },
  "probe_c": {
    "class": "conformance",
    "excluded": false,
    "runner": "generic"
  }
}"#;

    let merged =
        merge_ledger(path, base, ours, theirs).expect("disjoint probe additions should merge");
    let val: serde_json::Value = serde_json::from_str(merged.to_json()).expect("valid json");
    let obj = val.as_object().expect("object");
    assert_eq!(obj.len(), 3);
    assert!(obj.contains_key("probe_a"));
    assert!(obj.contains_key("probe_b"));
    assert!(obj.contains_key("probe_c"));
    assert_eq!(merged.summary().rows_added, 2);
}

#[test]
fn duplicate_json_key_fails() {
    let path = "conformance-probes/probe-inventory.json";
    let base = r#"{"probe_a": {"class": "c", "excluded": false, "runner": "g"}}"#;
    let ours_with_duplicate = r#"{
  "probe_a": {"class": "c", "excluded": false, "runner": "g"},
  "probe_a": {"class": "c", "excluded": false, "runner": "g"}
}"#;
    let theirs = base;

    let err =
        merge_ledger(path, base, ours_with_duplicate, theirs).expect_err("duplicate key must fail");
    match err {
        MergeConflict::DuplicateJsonKey { key, .. } => assert_eq!(key, "probe_a"),
        other => panic!("expected DuplicateJsonKey, got {other:?}"),
    }
}

#[test]
fn cli_ledger_merge_success() {
    let temp = tempfile::tempdir().expect("tempdir");
    let base_file = temp.path().join("base.json");
    let ours_file = temp.path().join("ours.json");
    let theirs_file = temp.path().join("theirs.json");
    let output_file = temp.path().join("output.json");

    let base = r#"{"probe_b": {"class": "conformance", "excluded": false, "runner": "generic"}}"#;
    let ours = r#"{"probe_a": {"class": "conformance", "excluded": false, "runner": "generic"}, "probe_b": {"class": "conformance", "excluded": false, "runner": "generic"}}"#;
    let theirs = r#"{"probe_b": {"class": "conformance", "excluded": false, "runner": "generic"}, "probe_c": {"class": "conformance", "excluded": false, "runner": "generic"}}"#;

    fs::write(&base_file, base).expect("write base");
    fs::write(&ours_file, ours).expect("write ours");
    fs::write(&theirs_file, theirs).expect("write theirs");

    let bin = env!("CARGO_BIN_EXE_carrick-xtask");
    let output = Command::new(bin)
        .args([
            "ledger-merge",
            "--path",
            "conformance-probes/probe-inventory.json",
            "--base",
            base_file.to_str().unwrap(),
            "--ours",
            ours_file.to_str().unwrap(),
            "--theirs",
            theirs_file.to_str().unwrap(),
            "--output",
            output_file.to_str().unwrap(),
        ])
        .output()
        .expect("spawn carrick-xtask ledger-merge");

    assert!(
        output.status.success(),
        "disjoint probe additions merge via CLI failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let content = fs::read_to_string(&output_file).expect("read merged output");
    assert!(content.contains("probe_a"));
    assert!(content.contains("probe_b"));
    assert!(content.contains("probe_c"));
}
