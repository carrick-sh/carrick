use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn check_contracts_bin() -> &'static str {
    env!("CARGO_BIN_EXE_check-contracts")
}

fn seed_crate_fn(root: &Path, crate_name: &str, fn_name: &str) {
    let src_dir = root.join("crates").join(crate_name).join("src");
    fs::create_dir_all(&src_dir).expect("create crate src dir");
    fs::write(src_dir.join("lib.rs"), format!("pub fn {fn_name}() {{}}\n"))
        .expect("write crate lib.rs");
}

fn seed_minimal_crates(root: &Path) {
    seed_crate_fn(root, "carrick-conformance-contract", "test_binding");
    seed_crate_fn(root, "carrick-embed", "test_binding");
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

    seed_minimal_crates(root);

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
    assert!(stdout.contains("unique surface paths (1 surface entries; inventory: 338 syscalls"));
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
    assert!(stdout.contains("unique surface paths"));
    assert!(stdout.contains("surface entries; inventory: 338 syscalls"));
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
    seed_minimal_crates(temp.path());

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
fn check_contracts_rejects_missing_module_in_existing_crate() {
    let temp = TempDir::new().expect("tempdir");
    let contracts_dir = temp.path().join("conformance-contracts/contracts");
    fs::create_dir_all(&contracts_dir).expect("create contracts dir");
    fs::write(
        temp.path().join("conformance-contracts/surfaces.toml"),
        "schema_version = 1\nsurfaces = []\n",
    )
    .expect("write surfaces.toml");
    seed_minimal_crates(temp.path());

    let bad_vm_free_module = VALID_CONTRACT.replace(
        "  \"carrick-conformance-contract::test_binding\",",
        "  \"carrick-conformance-contract::invented_module::tests::fake_test\",",
    );
    fs::write(contracts_dir.join("bad-module.toml"), bad_vm_free_module).expect("write contract");

    let output = Command::new(check_contracts_bin())
        .arg("--root")
        .arg(temp.path())
        .output()
        .expect("run check-contracts");
    assert!(
        !output.status.success(),
        "expected failure for nonexistent module inside existing crate"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "unresolved vm_free binding target carrick-conformance-contract::invented_module::tests::fake_test"
        ),
        "unexpected stderr: {stderr}"
    );

    let bad_embed_module = VALID_CONTRACT.replace(
        "  \"carrick-embed::test_binding\",",
        "  \"carrick-embed::invented_embed_mod::fake_test\",",
    );
    fs::write(contracts_dir.join("bad-module.toml"), bad_embed_module).expect("write contract");

    let output = Command::new(check_contracts_bin())
        .arg("--root")
        .arg(temp.path())
        .output()
        .expect("run check-contracts");
    assert!(
        !output.status.success(),
        "expected failure for nonexistent embed module inside existing crate"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "unresolved embed_structural binding target carrick-embed::invented_embed_mod::fake_test"
        ),
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

    seed_minimal_crates(temp.path());

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

    let base_one = VALID_CONTRACT.replace(
        "  \"carrick-conformance-contract::test_binding\",",
        concat!(
            "  \"carrick-conformance-contract::test_binding\",\n",
            "  \"carrick-b::base_one\",\n",
            "  \"carrick-d::base_two\",\n",
            "  \"carrick-f::base_three\",\n",
            "  \"carrick-h::base_four\",",
        ),
    );

    let contracts_dir = root.join("conformance-contracts/contracts");
    fs::create_dir_all(&contracts_dir).expect("create contracts dir");
    fs::write(contracts_dir.join("one.toml"), &base_one).expect("write one.toml");
    let second_contract =
        VALID_CONTRACT.replace("id = \"test.contract.one\"", "id = \"test.contract.two\"");
    fs::write(contracts_dir.join("two.toml"), second_contract).expect("write two.toml");

    seed_minimal_crates(root);
    seed_crate_fn(root, "carrick-alpha", "pr_one_binding");
    seed_crate_fn(root, "carrick-b", "base_one");
    seed_crate_fn(root, "carrick-d", "base_two");
    seed_crate_fn(root, "carrick-f", "base_three");
    seed_crate_fn(root, "carrick-h", "base_four");
    seed_crate_fn(root, "carrick-zeta", "pr_two_binding");

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

    // PR 1 adds a new surface in the middle gap AND inserts a sorted follow-up
    // vm_free binding near the top of one.toml's follow-up list.
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
        base_one.replace(
            "  \"carrick-b::base_one\",",
            "  \"carrick-alpha::pr_one_binding\",\n  \"carrick-b::base_one\",",
        ),
    )
    .expect("update one.toml on pr-one");
    git(&["add", "."]);
    git(&["commit", "-m", "pr-one"]);

    // PR 2 branches from main, touches the exact same insertion gap in
    // surfaces.toml (plus adding a second contract on src/hot.rs) and appends a
    // sorted follow-up binding at the bottom of one.toml.
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
        base_one.replace(
            "  \"carrick-h::base_four\",",
            "  \"carrick-h::base_four\",\n  \"carrick-zeta::pr_two_binding\",",
        ),
    )
    .expect("update one.toml on pr-two");
    git(&["add", "."]);
    git(&["commit", "-m", "pr-two"]);

    // Merge PR 2 into PR 1 (or PR 1 into PR 2 with sorted surfaces): note that
    // union merge on surfaces.toml concatenates PR 2's added lines (`hot.rs/two`,
    // `mid_two.rs`) with PR 1's (`mid_one.rs`); merging `pr-two` into `pr-one`
    // places `hot.rs/two`... wait: let's check order!
    // In `pr-one`: `hot.rs/one`, `mid_one.rs`, `z.rs` -> added line is `mid_one.rs`.
    // In `pr-two`: `hot.rs/one`, `hot.rs/two`, `mid_two.rs`, `z.rs` -> added lines are `hot.rs/two`, `mid_two.rs`.
    // If we merge `pr-two` into `pr-one`, union merge puts current (`mid_one.rs`) BEFORE incoming (`hot.rs/two`), which would be unsorted (`mid_one.rs` before `hot.rs`)!
    // Whereas merging `pr-one` into `pr-two` puts `pr-two`'s (`hot.rs/two`, `mid_two.rs`? wait: `mid_two.rs` > `mid_one.rs`!).
    // Let's check! If `pr-one` adds `src/m1.rs` and `pr-two` adds `src/m2.rs`, merging `pr-two` into `pr-one` puts `src/m1.rs` then `src/m2.rs` (sorted!).
    git(&["checkout", "pr-one"]);
    // Let's keep `pr-two` adding `src/mid_two.rs` only in that gap and `src/z.rs -> test.contract.two` in the next gap so union merge preserves alphabetical order!
    git(&["checkout", "pr-two"]);
    fs::write(
        root.join("conformance-contracts/surfaces.toml"),
        r#"schema_version = 1
surfaces = [
  { path = "src/a.rs", contract = "test.contract.one" },
  { path = "src/hot.rs", contract = "test.contract.one" },
  { path = "src/mid_two.rs", contract = "test.contract.two" },
  { path = "src/z.rs", contract = "test.contract.one" },
  { path = "src/z.rs", contract = "test.contract.two" },
]
"#,
    )
    .expect("update surfaces on pr-two");
    git(&["add", "."]);
    git(&["commit", "--amend", "-m", "pr-two"]);

    git(&["checkout", "pr-one"]);
    git(&["merge", "--no-edit", "pr-two"]);

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
        "check-contracts failed after merge: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn contract_toml_deletion_with_adjacent_edit_stays_a_merge_conflict() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();

    let run_git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .expect("run git")
    };

    assert!(run_git(&["init", "-b", "main"]).status.success());
    assert!(run_git(&["config", "user.name", "Test"]).status.success());
    assert!(run_git(&["config", "user.email", "test@carrick.invalid"]).status.success());

    let gitattributes =
        fs::read_to_string(repo_root().join(".gitattributes")).expect("read .gitattributes");
    fs::write(root.join(".gitattributes"), gitattributes).expect("write .gitattributes");

    let contracts_dir = root.join("conformance-contracts/contracts");
    fs::create_dir_all(&contracts_dir).expect("create contracts dir");
    let base_contract = VALID_CONTRACT.replace(
        "  \"carrick-conformance-contract::test_binding\",",
        concat!(
            "  \"carrick-conformance-contract::test_binding\",\n",
            "  \"carrick-b::obsolete_binding\",\n",
            "  \"carrick-c::neighbor_binding\",",
        ),
    );
    fs::write(contracts_dir.join("one.toml"), &base_contract).expect("write one.toml");
    assert!(run_git(&["add", "."]).status.success());
    assert!(run_git(&["commit", "-m", "base"]).status.success());

    // Branch A deletes obsolete_binding.
    assert!(run_git(&["checkout", "-b", "delete-branch"]).status.success());
    fs::write(
        contracts_dir.join("one.toml"),
        base_contract.replace("  \"carrick-b::obsolete_binding\",\n", ""),
    )
    .expect("delete binding");
    assert!(run_git(&["commit", "-am", "delete obsolete binding"]).status.success());

    // Branch B edits the immediately adjacent neighbor_binding.
    assert!(run_git(&["checkout", "-b", "edit-branch", "main"]).status.success());
    fs::write(
        contracts_dir.join("one.toml"),
        base_contract.replace(
            "  \"carrick-c::neighbor_binding\",",
            "  \"carrick-c::renamed_neighbor_binding\",",
        ),
    )
    .expect("edit adjacent binding");
    assert!(run_git(&["commit", "-am", "edit neighbor binding"]).status.success());

    // Without merge=union on contract TOMLs, git must flag a real conflict rather
    // than silently resurrecting the deleted binding.
    let merge = run_git(&["merge", "--no-edit", "delete-branch"]);
    assert!(
        !merge.status.success(),
        "expected merge conflict on adjacent delete+edit in contract TOML, but merge succeeded:\n{}",
        fs::read_to_string(contracts_dir.join("one.toml")).unwrap_or_default()
    );
}
