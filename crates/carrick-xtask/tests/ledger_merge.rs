#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use carrick_xtask::command::{CommandError, CommandOutput};
use carrick_xtask::ledger_merge::{MergeConflict, merge_ledger, regenerate_contracts_with_runner};

const SAMPLE_ABORT_ROW_1: &str = r#"{
  "file": "crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs",
  "function": "attach_task_only_engine",
  "ordinal_in_function": 1,
  "fingerprint": "522d1350a169ac84061d7e3b2a617f3c70c608b998ad3fc3f11705cc6ad02442",
  "verdict": "carrier_fault",
  "failure_domain": "hvpatch::runtime_projection",
  "rationale": "Missing runtime projection authority during task-only engine attach indicates double-attachment.",
  "sink": "fatal",
  "domain": "hvpatch::runtime_projection"
}"#;

const SAMPLE_ABORT_ROW_2: &str = r#"{
  "file": "crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs",
  "function": "attach_task_only_engine",
  "ordinal_in_function": 2,
  "fingerprint": "633e2461b270bd95171e8f4c81d71705cc6ad02442522d1350a169ac84061d7e",
  "verdict": "carrier_fault",
  "failure_domain": "hvpatch::runtime_projection",
  "rationale": "Secondary check failure during task-only engine attach.",
  "sink": "fatal",
  "domain": "hvpatch::runtime_projection"
}"#;

const SAMPLE_ABORT_ROW_3: &str = r#"{
  "file": "crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs",
  "function": "attach_task_only_engine",
  "ordinal_in_function": 3,
  "fingerprint": "744f3572c381ce06282f9a5d92e82816dd7be13553633e2461b270bd95171e8f",
  "verdict": "carrier_fault",
  "failure_domain": "hvpatch::runtime_projection",
  "rationale": "Tertiary check failure during task-only engine attach.",
  "sink": "fatal",
  "domain": "hvpatch::runtime_projection"
}"#;

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
fn adjacent_abort_additions_merge() {
    let path = "scripts/migrate/runtime-aborts/hvf.json";
    let base = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let ours = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1},
    {SAMPLE_ABORT_ROW_2}
  ]
}}"#
    );
    let theirs = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1},
    {SAMPLE_ABORT_ROW_3}
  ]
}}"#
    );

    let merged =
        merge_ledger(path, &base, &ours, &theirs).expect("adjacent abort additions should merge");
    let val: serde_json::Value = serde_json::from_str(merged.to_json()).expect("valid json");
    let rows = val
        .get("rows")
        .and_then(|r| r.as_array())
        .expect("rows array");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["ordinal_in_function"], 1);
    assert_eq!(rows[1]["ordinal_in_function"], 2);
    assert_eq!(rows[2]["ordinal_in_function"], 3);
    assert_eq!(merged.summary().rows_added, 2);
}

#[test]
fn identical_changes_merge() {
    let path = "scripts/migrate/runtime-aborts/hvf.json";
    let base = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let updated_row = SAMPLE_ABORT_ROW_1.replace(
        "Missing runtime projection authority",
        "Updated rationale identically",
    );
    let ours = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {updated_row}
  ]
}}"#
    );
    let theirs = ours.clone();

    let merged = merge_ledger(path, &base, &ours, &theirs).expect("identical changes should merge");
    let val: serde_json::Value = serde_json::from_str(merged.to_json()).expect("valid json");
    let rows = val
        .get("rows")
        .and_then(|r| r.as_array())
        .expect("rows array");
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0]["rationale"]
            .as_str()
            .unwrap()
            .contains("Updated rationale identically")
    );
    assert_eq!(merged.summary().rows_modified, 1);
}

#[test]
fn single_sided_edit_preserves_all_fields() {
    let path = "scripts/migrate/runtime-aborts/hvf.json";
    let base_row = r#"{
  "custom_metadata_tag": "preserve_this_value",
  "domain": "hvpatch::runtime_projection",
  "failure_domain": "hvpatch::runtime_projection",
  "file": "crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs",
  "fingerprint": "522d1350a169ac84061d7e3b2a617f3c70c608b998ad3fc3f11705cc6ad02442",
  "function": "attach_task_only_engine",
  "ordinal_in_function": 1,
  "rationale": "Original rationale.",
  "review_status": {"approved_by": "alice", "score": 10},
  "sink": "fatal",
  "verdict": "carrier_fault"
}"#;

    let base = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "unknown_top_level_meta": "top_preserved",
  "rows": [
    {base_row}
  ]
}}"#
    );

    let ours_row = base_row.replace("Original rationale.", "New reviewed rationale by Bob.");
    let ours = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "unknown_top_level_meta": "top_preserved",
  "rows": [
    {ours_row}
  ]
}}"#
    );
    let theirs = base.clone();

    let merged = merge_ledger(path, &base, &ours, &theirs).expect("single sided edit should merge");
    let val: serde_json::Value = serde_json::from_str(merged.to_json()).expect("valid json");
    assert_eq!(val["unknown_top_level_meta"], "top_preserved");
    let rows = val
        .get("rows")
        .and_then(|r| r.as_array())
        .expect("rows array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["rationale"], "New reviewed rationale by Bob.");
    assert_eq!(rows[0]["custom_metadata_tag"], "preserve_this_value");
    assert_eq!(rows[0]["review_status"]["approved_by"], "alice");
    assert_eq!(rows[0]["review_status"]["score"], 10);
    assert_eq!(merged.summary().rows_modified, 1);
}

#[test]
fn same_key_divergent_edit_fails() {
    let path = "scripts/migrate/runtime-aborts/hvf.json";
    let base = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let ours_row = SAMPLE_ABORT_ROW_1.replace(
        "Missing runtime projection authority",
        "Rationale change by Alice",
    );
    let ours = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {ours_row}
  ]
}}"#
    );
    let theirs_row = SAMPLE_ABORT_ROW_1.replace(
        "Missing runtime projection authority",
        "Rationale change by Bob",
    );
    let theirs = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {theirs_row}
  ]
}}"#
    );

    let err = merge_ledger(path, &base, &ours, &theirs)
        .expect_err("divergent edits on same key must fail");
    match err {
        MergeConflict::RowConflict {
            key,
            ours: o,
            theirs: t,
            ..
        } => {
            assert!(key.contains("attach_task_only_engine"));
            assert!(o.is_some());
            assert!(t.is_some());
        }
        other => panic!("expected RowConflict, got {other:?}"),
    }
}

#[test]
fn delete_edit_conflict_fails() {
    let path = "scripts/migrate/runtime-aborts/hvf.json";
    let base = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let ours = r#"{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": []
}"#;
    let theirs_row =
        SAMPLE_ABORT_ROW_1.replace("Missing runtime projection authority", "Edited by reviewer");
    let theirs = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {theirs_row}
  ]
}}"#
    );

    let err = merge_ledger(path, &base, ours, &theirs).expect_err("delete vs edit must fail");
    match err {
        MergeConflict::RowConflict {
            ours: None,
            theirs: Some(_),
            ..
        } => {}
        other => panic!("expected RowConflict with delete/edit, got {other:?}"),
    }
}

#[test]
fn single_sided_delete_is_preserved() {
    let path = "scripts/migrate/runtime-aborts/hvf.json";
    let base = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1},
    {SAMPLE_ABORT_ROW_2}
  ]
}}"#
    );
    let ours = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_2}
  ]
}}"#
    );
    let theirs = base.clone();

    let merged =
        merge_ledger(path, &base, &ours, &theirs).expect("single sided delete should merge");
    let val: serde_json::Value = serde_json::from_str(merged.to_json()).expect("valid json");
    let rows = val
        .get("rows")
        .and_then(|r| r.as_array())
        .expect("rows array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["ordinal_in_function"], 2);
    assert_eq!(merged.summary().rows_deleted, 1);
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
fn duplicate_abort_identity_fails() {
    let path = "scripts/migrate/runtime-aborts/hvf.json";
    let base = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let ours_duplicate = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1},
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let theirs = base.clone();

    let err = merge_ledger(path, &base, &ours_duplicate, &theirs)
        .expect_err("duplicate row identity must fail");
    match err {
        MergeConflict::DuplicateAbortIdentity { ordinal, .. } => assert_eq!(ordinal, 1),
        other => panic!("expected DuplicateAbortIdentity, got {other:?}"),
    }
}

#[test]
fn incompatible_schema_fails() {
    let path = "scripts/migrate/runtime-aborts/hvf.json";
    let base = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let ours_incompatible = format!(
        r#"{{
  "schema": 2,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let theirs = base.clone();

    let err = merge_ledger(path, &base, &ours_incompatible, &theirs)
        .expect_err("incompatible schema must fail");
    match err {
        MergeConflict::IncompatibleSchema { found, .. } => assert_eq!(found, "2"),
        other => panic!("expected IncompatibleSchema, got {other:?}"),
    }
}

#[test]
fn wrong_shard_fails() {
    let path = "scripts/migrate/runtime-aborts/hvf.json";
    let base = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let ours_wrong_shard = format!(
        r#"{{
  "schema": 1,
  "shard": "vcpu-loop.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let theirs = base.clone();

    let err =
        merge_ledger(path, &base, &ours_wrong_shard, &theirs).expect_err("wrong shard must fail");
    match err {
        MergeConflict::WrongShard {
            expected, actual, ..
        } => {
            assert_eq!(expected, "hvf.json");
            assert_eq!(actual, "vcpu-loop.json");
        }
        other => panic!("expected WrongShard, got {other:?}"),
    }
}

#[test]
fn divergent_debt_ceiling_fails() {
    let path = "scripts/migrate/runtime-aborts/hvf.json";
    let base = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let ours = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 1,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let theirs = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 2,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );

    let err =
        merge_ledger(path, &base, &ours, &theirs).expect_err("divergent debt ceiling must fail");
    match err {
        MergeConflict::DivergentDebtCeiling {
            base: b,
            ours: o,
            theirs: t,
        } => {
            assert_eq!(b, 0);
            assert_eq!(o, 1);
            assert_eq!(t, 2);
        }
        other => panic!("expected DivergentDebtCeiling, got {other:?}"),
    }
}

#[test]
fn generated_contract_inventory_requires_regeneration() {
    let path = "conformance-contracts/inventory.json";
    let dummy = r#"{"entries": []}"#;
    let err = merge_ledger(path, dummy, dummy, dummy)
        .expect_err("contract inventory must require regeneration");
    match err {
        MergeConflict::GeneratedArtifactNeedsRegeneration { path: p } => {
            assert!(p.contains("conformance-contracts/inventory.json"));
        }
        other => panic!("expected GeneratedArtifactNeedsRegeneration, got {other:?}"),
    }
}

#[test]
fn output_is_deterministic() {
    let path = "scripts/migrate/runtime-aborts/hvf.json";
    let base = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let ours = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_3},
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let theirs = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1},
    {SAMPLE_ABORT_ROW_2}
  ]
}}"#
    );

    let res1 = merge_ledger(path, &base, &ours, &theirs).expect("merge 1");
    let res2 = merge_ledger(path, &base, &theirs, &ours).expect("merge 2");
    assert_eq!(res1.to_json(), res2.to_json());
}

#[test]
fn failed_merge_leaves_output_unchanged() {
    let temp = tempfile::tempdir().expect("tempdir");
    let base_file = temp.path().join("base.json");
    let ours_file = temp.path().join("ours.json");
    let theirs_file = temp.path().join("theirs.json");
    let output_file = temp.path().join("output.json");

    let base = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {SAMPLE_ABORT_ROW_1}
  ]
}}"#
    );
    let ours_row =
        SAMPLE_ABORT_ROW_1.replace("Missing runtime projection authority", "Rationale Alice");
    let theirs_row =
        SAMPLE_ABORT_ROW_1.replace("Missing runtime projection authority", "Rationale Bob");
    let ours = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {ours_row}
  ]
}}"#
    );
    let theirs = format!(
        r#"{{
  "schema": 1,
  "shard": "hvf.json",
  "typed_error_debt_ceiling": 0,
  "rows": [
    {theirs_row}
  ]
}}"#
    );

    fs::write(&base_file, &base).expect("write base");
    fs::write(&ours_file, &ours).expect("write ours");
    fs::write(&theirs_file, &theirs).expect("write theirs");

    let canary = "EXISTING_CONTENT_MUST_NOT_BE_MODIFIED";
    fs::write(&output_file, canary).expect("write output initial");

    let bin = env!("CARGO_BIN_EXE_carrick-xtask");
    let output = Command::new(bin)
        .args([
            "ledger-merge",
            "--path",
            "scripts/migrate/runtime-aborts/hvf.json",
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
        !output.status.success(),
        "conflicting merge must exit nonzero"
    );
    let content_after = fs::read_to_string(&output_file).expect("read output after");
    assert_eq!(
        content_after, canary,
        "output file must remain completely untouched on conflict"
    );
}

#[test]
fn disposable_root_stub_process_runner_regenerate_contracts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let disposable_root = temp.path().join("disposable_repo");
    fs::create_dir_all(&disposable_root).expect("create dir");

    let call_count = Arc::new(AtomicUsize::new(0));
    let calls_log = Arc::new(Mutex::new(Vec::new()));

    let count_clone = Arc::clone(&call_count);
    let log_clone = Arc::clone(&calls_log);

    let runner = move |prog: &str,
                       args: &[&str],
                       _cwd: Option<&Path>|
          -> Result<CommandOutput, CommandError> {
        count_clone.fetch_add(1, Ordering::SeqCst);
        let arg_vec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        log_clone.lock().unwrap().push((prog.to_string(), arg_vec));

        // Return simulated exit success
        #[cfg(unix)]
        use std::os::unix::process::ExitStatusExt;
        let status = std::process::ExitStatus::from_raw(0);

        Ok(CommandOutput {
            status,
            stdout: "simulated success".to_string(),
            stderr: "".to_string(),
        })
    };

    let res = regenerate_contracts_with_runner(&disposable_root, runner);
    assert!(
        res.is_ok(),
        "stub runner with disposable root should succeed"
    );
    assert_eq!(call_count.load(Ordering::SeqCst), 2);

    let logs = calls_log.lock().unwrap();
    assert_eq!(logs[0].0, "cargo");
    assert!(logs[0].1.contains(&"--root".to_string()));
    assert!(!logs[0].1.contains(&"--check".to_string()));

    assert_eq!(logs[1].0, "cargo");
    assert!(logs[1].1.contains(&"--root".to_string()));
    assert!(logs[1].1.contains(&"--check".to_string()));
}

#[test]
fn real_contract_inventory_check_on_repository() {
    // Verifies that carrick-xtask ledger-regenerate-contracts passes on the real repository.
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let bin = env!("CARGO_BIN_EXE_carrick-xtask");
    let output = Command::new(bin)
        .current_dir(repo_root)
        .args([
            "ledger-regenerate-contracts",
            "--root",
            repo_root.to_str().unwrap(),
        ])
        .output()
        .expect("spawn carrick-xtask ledger-regenerate-contracts");

    assert!(
        output.status.success(),
        "ledger-regenerate-contracts failed on repo root: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
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
