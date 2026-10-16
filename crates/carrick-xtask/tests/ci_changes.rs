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

    // lint must run on draft PRs too (with fmt, clippy, and lint-domains-source), while
    // expensive Linux/cross and hosted macOS jobs gate on non-draft PRs.
    assert_eq!(
        jobs["lint"]["if"].as_str(),
        Some("needs.changes.outputs.heavy == 'true'")
    );
    let lint_steps = jobs["lint"]["steps"].as_vec().unwrap();
    for cmd in ["just fmt-check", "just clippy", "just lint-domains-source"] {
        assert!(
            lint_steps.iter().any(|s| s["run"].as_str() == Some(cmd)),
            "lint job must run `{cmd}`"
        );
    }
    for expensive_job in [
        "portable",
        "linux-doc",
        "macos-clippy",
        "macos-build",
        "macos-unit-a",
        "macos-unit-b",
        "macos-integration",
        "cross-check-linux",
        "kernel-linux-native",
        "cross-check-freebsd",
        "cross-check-netbsd",
    ] {
        let cond = jobs[expensive_job]["if"].as_str().unwrap();
        assert!(
            cond.contains(
                "github.event_name != 'pull_request' || github.event.pull_request.draft == false"
            ),
            "{expensive_job} must gate on non-draft PRs, got: {cond}"
        );
    }

    // kernel-runtime.yml must also wire the trusted changes job to skip hardware lanes on docs/CI-only merge groups
    let kr_workflow =
        fs::read_to_string(root.join(".github/workflows/kernel-runtime.yml")).unwrap();
    let kr_docs = yaml_rust2::YamlLoader::load_from_str(&kr_workflow).unwrap();
    let kr_jobs = &kr_docs[0]["jobs"];
    assert_eq!(
        kr_jobs["changes"]["runs-on"].as_str(),
        Some("ubuntu-latest")
    );
    assert!(kr_jobs["changes"]["outputs"]["heavy"].as_str().is_some());
    for lane_job in ["signed-fixtures", "kvm-tests", "kvm-tests-willow"] {
        let needs = kr_jobs[lane_job]["needs"].as_vec().unwrap();
        assert!(
            needs.iter().any(|v| v.as_str() == Some("changes")),
            "{lane_job} must depend on changes"
        );
        let cond = kr_jobs[lane_job]["if"].as_str().unwrap();
        assert!(
            cond.contains("needs.changes.outputs.heavy == 'true'"),
            "{lane_job} must gate on needs.changes.outputs.heavy == 'true'"
        );
    }
    let ok_needs = kr_jobs["trusted-hardware-ok"]["needs"].as_vec().unwrap();
    assert!(ok_needs.iter().any(|v| v.as_str() == Some("changes")));
}

#[test]
fn docs_and_agents_and_xtask_ci_only_merge_group_skips_heavy_and_macos() {
    let repo = TestRepo::new();
    let docs_mg = repo.evaluate(
        "merge_group",
        &[
            ("docs/architecture.md", "architecture guide"),
            (".agents/skills/carrick-stacked-prs/SKILL.md", "skill doc"),
            (".agents/config.toml", "agent config"),
            ("README.md", "updated readme"),
            ("LICENSE-MIT", "license text"),
        ],
    );
    assert_eq!(docs_mg.get("heavy").map(|s| s.as_str()), Some("false"));
    assert_eq!(docs_mg.get("macos").map(|s| s.as_str()), Some("false"));
    assert_eq!(docs_mg.get("workflows").map(|s| s.as_str()), Some("false"));

    let ci_only_mg = repo.evaluate(
        "merge_group",
        &[
            (".github/workflows/ci.yml", "# workflow edit"),
            ("crates/carrick-xtask/src/ci_receipt.rs", "// xtask ci edit"),
            ("crates/carrick-xtask/src/test_shards.rs", "// shards edit"),
            ("crates/carrick-xtask/tests/ci_changes.rs", "// test edit"),
            ("scripts/ci/require-linked-issue.sh", "#!/bin/sh\n"),
        ],
    );
    assert_eq!(ci_only_mg.get("heavy").map(|s| s.as_str()), Some("false"));
    assert_eq!(ci_only_mg.get("macos").map(|s| s.as_str()), Some("false"));
    assert_eq!(
        ci_only_mg.get("workflows").map(|s| s.as_str()),
        Some("true")
    );

    // Non-CI xtask modules that affect acceptance or fixture bundles must still run heavy + macos
    for non_ci_xtask in [
        "crates/carrick-xtask/src/accept.rs",
        "crates/carrick-xtask/src/fixtures.rs",
    ] {
        let out = repo.evaluate("merge_group", &[(non_ci_xtask, "// non-ci xtask")]);
        assert_eq!(
            out.get("heavy").map(|s| s.as_str()),
            Some("true"),
            "{non_ci_xtask}"
        );
        assert_eq!(
            out.get("macos").map(|s| s.as_str()),
            Some("true"),
            "{non_ci_xtask}"
        );
    }
}

#[test]
fn cumulative_merge_group_with_shallower_code_and_deeper_docs_runs_heavy_and_macos() {
    let repo = TestRepo::new();
    let run_git = |args: &[&str]| {
        let output = Command::new("git")
            .current_dir(repo.dir.path())
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
    run_git(&["checkout", "-B", "queue-entry-1", &repo.base_commit]);
    let code_path = repo.dir.path().join("crates/carrick-kernel/src/lib.rs");
    fs::create_dir_all(code_path.parent().unwrap()).unwrap();
    fs::write(&code_path, "pub fn entry_one() {}\n").unwrap();
    run_git(&["add", "."]);
    run_git(&["commit", "-m", "entry 1: code change"]);
    let entry_1_sha = String::from_utf8(run_git(&["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();

    run_git(&["checkout", "-B", "queue-entry-2", &entry_1_sha]);
    fs::write(repo.dir.path().join("README.md"), "entry 2: docs only\n").unwrap();
    run_git(&["add", "."]);
    run_git(&["commit", "-m", "entry 2: docs change"]);

    let output_dir = tempfile::tempdir().unwrap();
    let output_file = output_dir.path().join("github_output");
    // Entry 2 has CI_BASE = entry_1_sha (preceding queue entry) and CI_BASE_REF = base_commit (main).
    let status = Command::new("just")
        .current_dir(repo.dir.path())
        .args(["ci-changes"])
        .env("CI_EVENT", "merge_group")
        .env("CI_BASE", &entry_1_sha)
        .env("CI_BASE_REF", &repo.base_commit)
        .env("GITHUB_OUTPUT", &output_file)
        .status()
        .unwrap();
    assert!(status.success());
    let output_str = fs::read_to_string(&output_file).unwrap();
    assert!(output_str.contains("heavy=true"), "{output_str}");
    assert!(output_str.contains("macos=true"), "{output_str}");
}

#[test]
fn ci_results_accepts_fast_path_merge_group_and_rejects_unlicensed_skips() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let run_results = |event: &str, draft: &str, needs_json: serde_json::Value| -> bool {
        Command::new("just")
            .current_dir(&root)
            .args(["ci-results"])
            .env("CI_EVENT", event)
            .env("CI_DRAFT", draft)
            .env("CI_NEEDS", needs_json.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    };

    // Docs-only merge_group: heavy=false, macos=false, workflows=false -> macos-* and linux heavy skipped
    assert!(run_results(
        "merge_group",
        "false",
        serde_json::json!({
            "changes": {"result": "success", "outputs": {"heavy": "false", "macos": "false", "workflows": "false"}},
            "actionlint": {"result": "skipped"},
            "linked-issue": {"result": "success"},
            "commit-trailers": {"result": "success"},
            "lint": {"result": "skipped"},
            "portable": {"result": "skipped"},
            "macos-clippy": {"result": "skipped"},
            "macos-build": {"result": "skipped"},
            "macos-unit-a": {"result": "skipped"},
            "macos-unit-b": {"result": "skipped"},
            "macos-integration": {"result": "skipped"}
        })
    ));

    // Code merge_group without workflow edits: heavy=true, macos=true, workflows=false -> actionlint skipped, others success
    assert!(run_results(
        "merge_group",
        "false",
        serde_json::json!({
            "changes": {"result": "success", "outputs": {"heavy": "true", "macos": "true", "workflows": "false"}},
            "actionlint": {"result": "skipped"},
            "linked-issue": {"result": "success"},
            "commit-trailers": {"result": "success"},
            "lint": {"result": "success"},
            "portable": {"result": "success"},
            "macos-clippy": {"result": "success"},
            "macos-build": {"result": "success"},
            "macos-unit-a": {"result": "success"},
            "macos-unit-b": {"result": "success"},
            "macos-integration": {"result": "success"}
        })
    ));

    // Unlicensed skip on code merge_group must fail closed
    assert!(!run_results(
        "merge_group",
        "false",
        serde_json::json!({
            "changes": {"result": "success", "outputs": {"heavy": "true", "macos": "true", "workflows": "false"}},
            "actionlint": {"result": "skipped"},
            "linked-issue": {"result": "success"},
            "commit-trailers": {"result": "success"},
            "lint": {"result": "success"},
            "portable": {"result": "success"},
            "macos-clippy": {"result": "success"},
            "macos-build": {"result": "success"},
            "macos-unit-a": {"result": "success"},
            "macos-unit-b": {"result": "skipped"},
            "macos-integration": {"result": "success"}
        })
    ));

    // Draft PR with code changes: lint + cheap Linux checks succeed, expensive + macOS skipped -> passes
    assert!(run_results(
        "pull_request",
        "true",
        serde_json::json!({
            "changes": {"result": "success", "outputs": {"heavy": "true", "macos": "false", "workflows": "false"}},
            "actionlint": {"result": "skipped"},
            "linked-issue": {"result": "success"},
            "commit-trailers": {"result": "success"},
            "lint": {"result": "success"},
            "portable": {"result": "skipped"},
            "macos-clippy": {"result": "skipped"},
            "macos-build": {"result": "skipped"},
            "macos-unit-a": {"result": "skipped"},
            "macos-unit-b": {"result": "skipped"},
            "macos-integration": {"result": "skipped"}
        })
    ));

    // Draft PR with code changes where lint failed or was skipped -> fails closed
    assert!(!run_results(
        "pull_request",
        "true",
        serde_json::json!({
            "changes": {"result": "success", "outputs": {"heavy": "true", "macos": "false", "workflows": "false"}},
            "actionlint": {"result": "skipped"},
            "linked-issue": {"result": "success"},
            "commit-trailers": {"result": "success"},
            "lint": {"result": "skipped"},
            "portable": {"result": "skipped"},
            "macos-clippy": {"result": "skipped"},
            "macos-build": {"result": "skipped"},
            "macos-unit-a": {"result": "skipped"},
            "macos-unit-b": {"result": "skipped"},
            "macos-integration": {"result": "skipped"}
        })
    ));

    // Non-draft PR with code changes where portable was skipped -> fails closed
    assert!(!run_results(
        "pull_request",
        "false",
        serde_json::json!({
            "changes": {"result": "success", "outputs": {"heavy": "true", "macos": "false", "workflows": "false"}},
            "actionlint": {"result": "skipped"},
            "linked-issue": {"result": "success"},
            "commit-trailers": {"result": "success"},
            "lint": {"result": "success"},
            "portable": {"result": "skipped"},
            "macos-clippy": {"result": "skipped"},
            "macos-build": {"result": "skipped"},
            "macos-unit-a": {"result": "skipped"},
            "macos-unit-b": {"result": "skipped"},
            "macos-integration": {"result": "skipped"}
        })
    ));
}
