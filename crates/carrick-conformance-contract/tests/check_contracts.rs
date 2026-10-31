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
vm_free = [
  "carrick-conformance-contract::test_binding",
]
embed = [
  "carrick-embed::test_binding",
]
docker = [
  "probe:test",
]
ecosystem = [
  "go:test",
]

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

    let surfaces_content = r#"schema_version = 1
surfaces = [
  { path = "src/lib.rs", contract = "test.contract.one" },
]
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
    fs::create_dir_all(temp.path().join("crates/carrick-conformance-contract"))
        .expect("create existing crate dir");

    let bad_binding_contract = VALID_CONTRACT.replace(
        "  \"carrick-conformance-contract::test_binding\",",
        "  \"carrick-conformance-contract::test_binding\",\n  \"nonexistent-crate-12345::second_binding\",",
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
        "expected failure for missing second vm_free target crate"
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

    let bad_surfaces = r#"schema_version = 1
surfaces = [
  { path = "nonexistent/file/path/that/does/not/exist.rs", contract = "test.contract.one" },
]
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

    let bad_surfaces = r#"schema_version = 1
surfaces = [
  { path = "conformance-contracts/surfaces.toml", contract = "unknown.contract.id" },
]
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

#[test]
fn two_prs_adding_surfaces_and_contract_bindings_merge_without_conflict() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();

    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .expect("run git");
        assert!(
            out.status.success(),
            "git {:?} failed: stdout={}, stderr={}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };

    git(&["init", "-b", "main"]);
    git(&["config", "user.name", "Test"]);
    git(&["config", "user.email", "test@carrick.invalid"]);

    let gitattributes =
        fs::read_to_string(repo_root().join(".gitattributes")).expect("read .gitattributes");
    fs::write(root.join(".gitattributes"), gitattributes).expect("write .gitattributes");

    let contracts_dir = root.join("conformance-contracts/contracts");
    fs::create_dir_all(&contracts_dir).expect("create contracts dir");
    fs::write(contracts_dir.join("one.toml"), VALID_CONTRACT).expect("write one.toml");
    let second_contract =
        VALID_CONTRACT.replace("id = \"test.contract.one\"", "id = \"test.contract.two\"");
    fs::write(contracts_dir.join("two.toml"), second_contract).expect("write two.toml");

    fs::create_dir_all(root.join("crates/carrick-conformance-contract")).expect("create crate 1");
    fs::create_dir_all(root.join("crates/carrick-alpha")).expect("create crate 2");
    fs::create_dir_all(root.join("crates/carrick-beta")).expect("create crate 3");
    fs::create_dir_all(root.join("src")).expect("create src");
    for file in ["src/a.rs", "src/hot.rs", "src/z.rs"] {
        fs::write(root.join(file), "// base\n").expect("write base surface");
    }

    let base_surfaces = r#"schema_version = 1
surfaces = [
  { path = "src/a.rs", contract = "test.contract.one" },
  { path = "src/hot.rs", contract = "test.contract.one" },
  { path = "src/z.rs", contract = "test.contract.one" },
]
"#;
    fs::write(
        root.join("conformance-contracts/surfaces.toml"),
        base_surfaces,
    )
    .expect("write base surfaces");

    git(&["add", "."]);
    git(&["commit", "-m", "base"]);

    // PR 1 adds a new surface in the middle gap AND a new vm_free binding in one.toml.
    git(&["checkout", "-b", "pr-one"]);
    fs::write(root.join("src/mid_one.rs"), "// pr-one\n").expect("write mid_one.rs");
    fs::write(
        root.join("conformance-contracts/surfaces.toml"),
        r#"schema_version = 1
surfaces = [
  { path = "src/a.rs", contract = "test.contract.one" },
  { path = "src/hot.rs", contract = "test.contract.one" },
  { path = "src/mid_one.rs", contract = "test.contract.one" },
  { path = "src/z.rs", contract = "test.contract.one" },
]
"#,
    )
    .expect("update surfaces on pr-one");
    fs::write(
        contracts_dir.join("one.toml"),
        VALID_CONTRACT.replace(
            "  \"carrick-conformance-contract::test_binding\",",
            "  \"carrick-alpha::pr_one_binding\",\n  \"carrick-conformance-contract::test_binding\",",
        ),
    )
    .expect("update one.toml on pr-one");
    git(&["add", "."]);
    git(&["commit", "-m", "pr-one"]);

    // PR 2 branches from main, touches the exact same insertion gap in both
    // surfaces.toml (plus adding a second contract on src/hot.rs) and one.toml.
    git(&["checkout", "-b", "pr-two", "main"]);
    fs::write(root.join("src/mid_two.rs"), "// pr-two\n").expect("write mid_two.rs");
    fs::write(
        root.join("conformance-contracts/surfaces.toml"),
        r#"schema_version = 1
surfaces = [
  { path = "src/a.rs", contract = "test.contract.one" },
  { path = "src/hot.rs", contract = "test.contract.one" },
  { path = "src/hot.rs", contract = "test.contract.two" },
  { path = "src/mid_two.rs", contract = "test.contract.two" },
  { path = "src/z.rs", contract = "test.contract.one" },
]
"#,
    )
    .expect("update surfaces on pr-two");
    fs::write(
        contracts_dir.join("one.toml"),
        VALID_CONTRACT.replace(
            "  \"carrick-conformance-contract::test_binding\",",
            "  \"carrick-beta::pr_two_binding\",\n  \"carrick-conformance-contract::test_binding\",",
        ),
    )
    .expect("update one.toml on pr-two");
    git(&["add", "."]);
    git(&["commit", "-m", "pr-two"]);

    // Merge PR 1 into PR 2: must succeed without conflict and pass check-contracts.
    git(&["merge", "--no-edit", "pr-one"]);

    let merged_surfaces =
        fs::read_to_string(root.join("conformance-contracts/surfaces.toml")).expect("surfaces");
    let merged_contract = fs::read_to_string(contracts_dir.join("one.toml")).expect("one.toml");
    assert!(!merged_surfaces.contains("<<<<<<<"));
    assert!(!merged_contract.contains("<<<<<<<"));

    let output = Command::new(check_contracts_bin())
        .arg("--root")
        .arg(root)
        .output()
        .expect("run check-contracts on merged tree");
    assert!(
        output.status.success(),
        "check-contracts failed after union merge: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
