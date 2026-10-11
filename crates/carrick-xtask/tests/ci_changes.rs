#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::fs;
use std::process::Command;

struct TestRepo {
    dir: tempfile::TempDir,
    base_commit: String,
}

impl TestRepo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let run_git = |args: &[&str]| {
            let output = Command::new("git")
                .current_dir(dir.path())
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            output
        };

        run_git(&["init"]);
        run_git(&["config", "user.name", "Test User"]);
        run_git(&["config", "user.email", "test@example.com"]);

        // Copy root justfile into the test repo so just ci-changes can run
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let root_justfile = fs::read_to_string(root.join("justfile")).unwrap();
        fs::write(dir.path().join("justfile"), root_justfile).unwrap();
        fs::create_dir_all(dir.path().join("scripts/lib")).unwrap();
        let env_script = fs::read_to_string(root.join("scripts/lib/build-env.sh")).unwrap();
        fs::write(dir.path().join("scripts/lib/build-env.sh"), env_script).unwrap();

        fs::write(dir.path().join("README.md"), "initial").unwrap();
        run_git(&["add", "."]);
        run_git(&["commit", "-m", "initial base commit"]);

        let base_commit = String::from_utf8(run_git(&["rev-parse", "HEAD"]).stdout)
            .unwrap()
            .trim()
            .to_string();

        Self { dir, base_commit }
    }

    fn evaluate(
        &self,
        event: &str,
        files_to_create_or_modify: &[(&str, &str)],
    ) -> HashMap<String, String> {
        let run_git = |args: &[&str]| {
            let output = Command::new("git")
                .current_dir(self.dir.path())
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?} failed: stdout={}, stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            output
        };

        run_git(&["checkout", "-B", "test-branch", &self.base_commit]);

        for (rel_path, content) in files_to_create_or_modify {
            let full_path = self.dir.path().join(rel_path);
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(full_path, content).unwrap();
        }

        if !files_to_create_or_modify.is_empty() {
            run_git(&["add", "."]);
            run_git(&["commit", "-m", "test commit"]);
        }

        let output_dir = tempfile::tempdir().unwrap();
        let output_file = output_dir.path().join("github_output");
        let status = Command::new("just")
            .current_dir(self.dir.path())
            .args(["ci-changes"])
            .env("CI_EVENT", event)
            .env("CI_BASE", &self.base_commit)
            .env("GITHUB_OUTPUT", &output_file)
            .status()
            .unwrap();

        assert!(status.success(), "just ci-changes failed");

        let output_str = fs::read_to_string(&output_file).unwrap();
        let mut map = HashMap::new();
        for line in output_str.lines() {
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        map
    }
}

#[test]
fn docs_only_pr_classifies_as_not_heavy_and_not_workflows() {
    let repo = TestRepo::new();
    let outputs = repo.evaluate(
        "pull_request",
        &[
            ("docs/architecture.md", "architecture guide"),
            ("README.md", "updated readme"),
            ("LICENSE-MIT", "license text"),
        ],
    );
    assert_eq!(outputs.get("heavy").map(|s| s.as_str()), Some("false"));
    assert_eq!(outputs.get("macos").map(|s| s.as_str()), Some("false"));
    assert_eq!(outputs.get("workflows").map(|s| s.as_str()), Some("false"));
}

#[test]
fn workflow_only_pr_classifies_as_workflows_and_not_heavy() {
    let repo = TestRepo::new();
    let outputs = repo.evaluate(
        "pull_request",
        &[
            (".github/workflows/ci.yml", "# workflow edit"),
            (".github/actionlint.yaml", "# actionlint edit"),
        ],
    );
    assert_eq!(outputs.get("heavy").map(|s| s.as_str()), Some("false"));
    assert_eq!(outputs.get("macos").map(|s| s.as_str()), Some("false"));
    assert_eq!(outputs.get("workflows").map(|s| s.as_str()), Some("true"));
}

#[test]
fn docs_and_workflows_pr_classifies_as_workflows_and_not_heavy() {
    let repo = TestRepo::new();
    let outputs = repo.evaluate(
        "pull_request",
        &[
            ("docs/index.md", "docs"),
            (".github/workflows/ci.yml", "# workflow edit"),
        ],
    );
    assert_eq!(outputs.get("heavy").map(|s| s.as_str()), Some("false"));
    assert_eq!(outputs.get("macos").map(|s| s.as_str()), Some("false"));
    assert_eq!(outputs.get("workflows").map(|s| s.as_str()), Some("true"));
}

#[test]
fn code_changes_under_crates_classify_as_heavy() {
    let repo = TestRepo::new();
    let outputs = repo.evaluate(
        "pull_request",
        &[("crates/carrick-kernel/src/lib.rs", "pub fn dummy() {}")],
    );
    assert_eq!(outputs.get("heavy").map(|s| s.as_str()), Some("true"));
    assert_eq!(outputs.get("macos").map(|s| s.as_str()), Some("false"));
    assert_eq!(outputs.get("workflows").map(|s| s.as_str()), Some("false"));
}

#[test]
fn conservative_code_paths_all_trigger_heavy() {
    let conservative_files = [
        "Cargo.toml",
        "Cargo.lock",
        "justfile",
        "scripts/build-signed.sh",
        "rust-toolchain.toml",
        "conformance-contracts/file.md",
        "fixtures/archive.tar.gz",
    ];
    for path in conservative_files {
        let repo = TestRepo::new();
        let content = if path == "justfile" {
            let existing = fs::read_to_string(repo.dir.path().join("justfile")).unwrap();
            format!("{existing}\n# appended comment\n")
        } else {
            "modified content".to_string()
        };
        let outputs = repo.evaluate("pull_request", &[(path, &content)]);
        assert_eq!(
            outputs.get("heavy").map(|s| s.as_str()),
            Some("true"),
            "path {path} must trigger heavy=true"
        );
    }
}

#[test]
fn code_plus_workflow_changes_classify_as_heavy_and_workflows() {
    let repo = TestRepo::new();
    let outputs = repo.evaluate(
        "pull_request",
        &[
            ("crates/carrick-core/src/lib.rs", "code"),
            (".github/workflows/ci.yml", "# workflow edit"),
        ],
    );
    assert_eq!(outputs.get("heavy").map(|s| s.as_str()), Some("true"));
    assert_eq!(outputs.get("macos").map(|s| s.as_str()), Some("false"));
    assert_eq!(outputs.get("workflows").map(|s| s.as_str()), Some("true"));
}

#[test]
fn non_pr_events_run_all_matrix() {
    let repo = TestRepo::new();
    for event in ["merge_group", "schedule", "workflow_dispatch"] {
        let outputs = repo.evaluate(event, &[]);
        assert_eq!(
            outputs.get("heavy").map(|s| s.as_str()),
            Some("true"),
            "event {event} must run heavy"
        );
        assert_eq!(
            outputs.get("macos").map(|s| s.as_str()),
            Some("true"),
            "event {event} must run macos"
        );
        assert_eq!(
            outputs.get("workflows").map(|s| s.as_str()),
            Some("true"),
            "event {event} must run workflows"
        );
    }
}

#[test]
fn workflow_wiring_and_ci_results_consistency() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workflow = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let documents = yaml_rust2::YamlLoader::load_from_str(&workflow).unwrap();
    let jobs = &documents[0]["jobs"];

    // actionlint job must exist and run on workflows == 'true'
    assert_eq!(
        jobs["actionlint"]["if"].as_str(),
        Some("needs.changes.outputs.workflows == 'true'")
    );
    assert_eq!(
        jobs["actionlint"]["runs-on"].as_str(),
        Some("ubuntu-latest")
    );

    // ci-ok must depend on actionlint
    let needs = jobs["ci-ok"]["needs"].as_vec().unwrap();
    assert!(
        needs.iter().any(|v| v.as_str() == Some("actionlint")),
        "ci-ok must depend on actionlint"
    );

    // changes job must output heavy, macos, and workflows
    let outputs = &jobs["changes"]["outputs"];
    assert!(outputs["heavy"].as_str().is_some());
    assert!(outputs["macos"].as_str().is_some());
    assert!(outputs["workflows"].as_str().is_some());
}
