use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn check_contracts_bin() -> &'static str {
    env!("CARGO_BIN_EXE_check-contracts")
}

const VALID_CONTRACT: &str = r#"
schema_version = 1
id = "test.contract.one"
title = "Test contract"
guest_surfaces = ["syscall:test"]
semantic_authority = ["man 2 test"]
fixture = "probe:test"
scale_points = [1, 8, 32]
rationale = "test rationale"

[bindings]
vm_free = "carrick-conformance-contract::test_binding"
embed = "carrick-embed::test_binding"
docker = "probe:test"
ecosystem = ["go:test"]

[bindings.unresolved]
embed_structural = "structural counters require USDT probe harness"

[[structural_budgets]]
kind = "affine"
metric = "continuation_enrollments"
base = 0
per_unit = 1
rationale = "Each blocking waiter enrolls exactly once before parking."
"#;

#[test]
fn check_contracts_runs_without_persisted_inventory_file() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();

    let contracts_dir = root.join("conformance-contracts/contracts");
    fs::create_dir_all(&contracts_dir).expect("create contracts dir");
    fs::write(contracts_dir.join("valid.toml"), VALID_CONTRACT).expect("write contract");

    let surface_target = root.join("src/lib.rs");
    if let Some(parent) = surface_target.parent() {
        fs::create_dir_all(parent).expect("create surface parent");
    }
    fs::write(&surface_target, "// surface file").expect("write surface");

    let surfaces_content = r#"
schema_version = 1

[[surfaces]]
path = "src/lib.rs"
contracts = ["test.contract.one"]
"#;
    fs::write(
        root.join("conformance-contracts/surfaces.toml"),
        surfaces_content,
    )
    .expect("write surfaces.toml");

    fs::create_dir_all(root.join("crates/carrick-conformance-contract")).expect("create crate dir");

    let inventory_file = root.join("conformance-contracts/inventory.json");
    assert!(
        !inventory_file.exists(),
        "isolated fixture root must not contain inventory.json"
    );

    let output = Command::new(check_contracts_bin())
        .arg("--root")
        .arg(root)
        .output()
        .expect("run check-contracts");

    assert!(
        output.status.success(),
        "check-contracts failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("conformance contracts checked:"));
    assert!(stdout.contains("inventory: 338 syscalls"));
}

#[test]
fn check_contracts_runs_against_workspace_repo() {
    let root = repo_root();
    let output = Command::new(check_contracts_bin())
        .arg("--root")
        .arg(&root)
        .output()
        .expect("run check-contracts");

    assert!(
        output.status.success(),
        "check-contracts failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("conformance contracts checked:"));
    assert!(stdout.contains("inventory: 338 syscalls"));
}

#[test]
fn check_contracts_rejects_missing_concrete_binding_crate() {
    let temp = TempDir::new().expect("tempdir");
    let contracts_dir = temp.path().join("conformance-contracts/contracts");
    fs::create_dir_all(&contracts_dir).expect("create contracts dir");
    fs::write(
        temp.path().join("conformance-contracts/surfaces.toml"),
        "schema_version = 1\nsurfaces = []\n",
    )
    .expect("write surfaces.toml");

    let bad_binding_contract = VALID_CONTRACT.replace(
        "vm_free = \"carrick-conformance-contract::test_binding\"",
        "vm_free = \"nonexistent-crate-12345::test_binding\"",
    );
    fs::write(
        contracts_dir.join("missing-crate.toml"),
        bad_binding_contract,
    )
    .expect("write contract");

    let output = Command::new(check_contracts_bin())
        .arg("--root")
        .arg(temp.path())
        .output()
        .expect("run check-contracts");

    assert!(
        !output.status.success(),
        "expected failure for missing vm_free target crate"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing vm_free target crate"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn check_contracts_rejects_absent_surface_path() {
    let temp = TempDir::new().expect("tempdir");
    let contracts_dir = temp.path().join("conformance-contracts/contracts");
    fs::create_dir_all(&contracts_dir).expect("create contracts dir");
    fs::write(contracts_dir.join("valid.toml"), VALID_CONTRACT).expect("write contract");

    let bad_surfaces = r#"
schema_version = 1

[[surfaces]]
path = "nonexistent/file/path/that/does/not/exist.rs"
contracts = ["test.contract.one"]
"#;
    fs::write(
        temp.path().join("conformance-contracts/surfaces.toml"),
        bad_surfaces,
    )
    .expect("write surfaces.toml");

    // Create the crates directory so the binding crate check passes
    fs::create_dir_all(temp.path().join("crates/carrick-conformance-contract"))
        .expect("create crate dir");

    let output = Command::new(check_contracts_bin())
        .arg("--root")
        .arg(temp.path())
        .output()
        .expect("run check-contracts");

    assert!(
        !output.status.success(),
        "expected failure for absent surface path"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("vacuous pattern: surface path"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn check_contracts_rejects_unknown_contract_reference() {
    let temp = TempDir::new().expect("tempdir");
    let contracts_dir = temp.path().join("conformance-contracts/contracts");
    fs::create_dir_all(&contracts_dir).expect("create contracts dir");
    fs::write(contracts_dir.join("valid.toml"), VALID_CONTRACT).expect("write contract");

    let bad_surfaces = r#"
schema_version = 1

[[surfaces]]
path = "conformance-contracts/surfaces.toml"
contracts = ["unknown.contract.id"]
"#;
    fs::write(
        temp.path().join("conformance-contracts/surfaces.toml"),
        bad_surfaces,
    )
    .expect("write surfaces.toml");

    let output = Command::new(check_contracts_bin())
        .arg("--root")
        .arg(temp.path())
        .output()
        .expect("run check-contracts");

    assert!(
        !output.status.success(),
        "expected failure for unknown contract reference"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("references unknown contract family"),
        "unexpected stderr: {stderr}"
    );
}
