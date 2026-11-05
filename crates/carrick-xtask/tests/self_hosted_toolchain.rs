#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{fs, path::Path, process::Command};
use yaml_rust2::{Yaml, YamlLoader};

const PATCH_PATH: &str = "docs/ci/patches/1648-bounded-rustup.patch";

fn load_workflow(dir: &Path, rel_path: &str) -> Yaml {
    let text = fs::read_to_string(dir.join(rel_path))
        .unwrap_or_else(|e| panic!("failed to read {rel_path}: {e}"));
    let docs = YamlLoader::load_from_str(&text)
        .unwrap_or_else(|e| panic!("failed to parse YAML in {rel_path}: {e}"));
    docs.into_iter().next().expect("workflow must not be empty")
}

struct PreparedTree {
    root: std::path::PathBuf,
    _temp: Option<tempfile::TempDir>,
}

fn prepare_tree() -> PreparedTree {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let patch = root.join(PATCH_PATH);
    if patch.exists() {
        let temp = tempfile::tempdir().unwrap();
        let init = Command::new("git")
            .current_dir(temp.path())
            .args(["init", "-q"])
            .output()
            .unwrap();
        assert!(init.status.success(), "git init failed in tempdir");

        let workflows_dir = temp.path().join(".github/workflows");
        fs::create_dir_all(&workflows_dir).unwrap();

        for entry in fs::read_dir(root.join(".github/workflows")).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "yml") {
                fs::copy(&path, workflows_dir.join(entry.file_name())).unwrap();
            }
        }
        let actionlint_cfg = root.join(".github/actionlint.yaml");
        if actionlint_cfg.exists() {
            fs::copy(&actionlint_cfg, temp.path().join(".github/actionlint.yaml")).unwrap();
        }

        let applied = Command::new("git")
            .current_dir(temp.path())
            .args(["apply", patch.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            applied.status.success(),
            "git apply failed: {}",
            String::from_utf8_lossy(&applied.stderr)
        );

        PreparedTree {
            root: temp.path().to_path_buf(),
            _temp: Some(temp),
        }
    } else {
        PreparedTree { root, _temp: None }
    }
}

fn assert_self_hosted_macos_cargo_job(workflow_path: &str, job_name: &str, job: &Yaml) {
    let steps = job["steps"]
        .as_vec()
        .unwrap_or_else(|| panic!("{workflow_path}: {job_name} missing steps"));

    let toolchain_step_pos = steps
        .iter()
        .position(|s| {
            let name = s["name"].as_str().unwrap_or("").to_lowercase();
            name.contains("toolchain")
        })
        .unwrap_or_else(|| panic!("{workflow_path}: {job_name} missing toolchain step"));

    let toolchain_step = &steps[toolchain_step_pos];
    let run = toolchain_step["run"]
        .as_str()
        .unwrap_or_else(|| panic!("{workflow_path}: {job_name} toolchain step missing run script"));

    assert!(
        run.contains("rustup show active-toolchain"),
        "{workflow_path}: {job_name} toolchain step must run `rustup show active-toolchain`"
    );

    assert!(
        run.contains("timeout") || run.contains("timeout="),
        "{workflow_path}: {job_name} toolchain step must be bounded by timeout"
    );

    assert!(
        run.contains("75"),
        "{workflow_path}: {job_name} toolchain step must exit 75 on failure"
    );

    assert!(
        run.contains("RUSTUP_AUTO_INSTALL=0"),
        "{workflow_path}: {job_name} toolchain step must set RUSTUP_AUTO_INSTALL=0"
    );

    for (idx, step) in steps.iter().enumerate() {
        if idx < toolchain_step_pos {
            let run_script = step["run"].as_str().unwrap_or("");
            assert!(
                !run_script.contains("cargo ") && !run_script.starts_with("cargo "),
                "{workflow_path}: {job_name} step {idx} runs cargo before toolchain step: {run_script}"
            );
        }
    }
}

#[test]
fn director_patch_applies_cleanly() {
    let _tree = prepare_tree();
}

#[test]
fn actionlint_clean_on_workflows() {
    let tree = prepare_tree();
    if Command::new("actionlint").arg("--version").output().is_ok() {
        let mut cmd = Command::new("actionlint");
        cmd.current_dir(&tree.root);
        for entry in fs::read_dir(tree.root.join(".github/workflows")).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "yml") {
                cmd.arg(format!(
                    ".github/workflows/{}",
                    entry.file_name().to_string_lossy()
                ));
            }
        }
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "actionlint failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn self_hosted_macos_cargo_jobs_have_bounded_toolchain_and_auto_install_disabled() {
    let tree = prepare_tree();

    let signed_gate = load_workflow(&tree.root, ".github/workflows/signed-gate.yml");
    assert_self_hosted_macos_cargo_job(
        ".github/workflows/signed-gate.yml",
        "gate",
        &signed_gate["jobs"]["gate"],
    );

    let kernel_runtime = load_workflow(&tree.root, ".github/workflows/kernel-runtime.yml");
    assert_self_hosted_macos_cargo_job(
        ".github/workflows/kernel-runtime.yml",
        "hvf-kernel",
        &kernel_runtime["jobs"]["hvf-kernel"],
    );
    assert_self_hosted_macos_cargo_job(
        ".github/workflows/kernel-runtime.yml",
        "hvf-closure",
        &kernel_runtime["jobs"]["hvf-closure"],
    );

    let ci = load_workflow(&tree.root, ".github/workflows/ci.yml");
    let ci_jobs = [
        "macos-clippy",
        "macos-authority",
        "macos-build",
        "macos-unit-a",
        "macos-unit-b",
        "macos-integration",
    ];
    for job_name in ci_jobs {
        assert_self_hosted_macos_cargo_job(
            ".github/workflows/ci.yml",
            job_name,
            &ci["jobs"][job_name],
        );
    }
}

#[test]
fn live_unpatched_workflows_fail_toolchain_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let patch = root.join(PATCH_PATH);
    if patch.exists() {
        let signed_gate = load_workflow(&root, ".github/workflows/signed-gate.yml");
        let gate_steps = signed_gate["jobs"]["gate"]["steps"].as_vec().unwrap();
        let gate_has_toolchain = gate_steps.iter().any(|s| {
            s["name"]
                .as_str()
                .unwrap_or("")
                .to_lowercase()
                .contains("toolchain")
        });
        assert!(
            !gate_has_toolchain,
            "live unpatched signed-gate.yml must lack toolchain step on main"
        );

        let ci = load_workflow(&root, ".github/workflows/ci.yml");
        let clippy_steps = ci["jobs"]["macos-clippy"]["steps"].as_vec().unwrap();
        let clippy_toolchain = clippy_steps
            .iter()
            .find(|s| {
                s["name"]
                    .as_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains("toolchain")
            })
            .unwrap();
        let clippy_run = clippy_toolchain["run"].as_str().unwrap();
        assert!(
            !clippy_run.contains("RUSTUP_AUTO_INSTALL=0"),
            "live unpatched ci.yml must lack RUSTUP_AUTO_INSTALL=0"
        );

        let kernel_runtime = load_workflow(&root, ".github/workflows/kernel-runtime.yml");
        let hvf_steps = kernel_runtime["jobs"]["hvf-kernel"]["steps"]
            .as_vec()
            .unwrap();
        let hvf_toolchain = hvf_steps
            .iter()
            .find(|s| {
                s["name"]
                    .as_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains("toolchain")
            })
            .unwrap();
        let hvf_run = hvf_toolchain["run"].as_str().unwrap();
        assert!(
            !hvf_run.contains("RUSTUP_AUTO_INSTALL=0"),
            "live unpatched kernel-runtime.yml must lack RUSTUP_AUTO_INSTALL=0"
        );
    }
}
