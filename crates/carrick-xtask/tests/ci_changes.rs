#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::ci_changes::{
    CiChangesOutputs, PathClass, ReferencedDocs, child_lookup_allowed, classify_path,
    evaluate_changes, scan_script_or_workflow,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

struct TempRepo {
    dir: TempDir,
    base_sha: String,
}

impl TempRepo {
    fn new(files: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let run_git = |args: &[&str]| {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .output()
                .expect("git command");
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        run_git(&["init", "-b", "main"]);
        run_git(&["config", "user.email", "test@example.com"]);
        run_git(&["config", "user.name", "Test"]);

        fs::write(dir.path().join("README.md"), "initial").unwrap();
        run_git(&["add", "README.md"]);
        run_git(&["commit", "-m", "initial"]);
        let base_sha = run_git(&["rev-parse", "HEAD"]);

        for (rel_path, content) in files {
            let full_path = dir.path().join(rel_path);
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&full_path, content).unwrap();
            run_git(&["add", rel_path]);
        }
        run_git(&["commit", "-m", "change"]);

        Self { dir, base_sha }
    }

    fn run_ci_changes(&self, event: &str, draft: Option<&str>, base_ref: Option<&str>) -> String {
        self.run_ci_changes_with_env(event, draft, base_ref, &[])
    }

    fn run_ci_changes_with_env(
        &self,
        event: &str,
        draft: Option<&str>,
        base_ref: Option<&str>,
        extra_env: &[(&str, &str)],
    ) -> String {
        let output_file = self.dir.path().join("github_output.txt");
        let class_json = self.dir.path().join("ci-class.json");
        let _ = fs::remove_file(&output_file);
        let _ = fs::remove_file(&class_json);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
        cmd.arg("--root")
            .arg(self.dir.path())
            .arg("ci-changes")
            .env_remove("CI_DRAFT")
            .env_remove("CI_BASE_REF")
            .env_remove("CI_HEAD_REF")
            .env_remove("GITHUB_STEP_SUMMARY")
            .env("CI_EVENT", event)
            .env("CI_BASE", &self.base_sha)
            .env("GITHUB_OUTPUT", &output_file)
            .env("CI_CLASS_JSON", &class_json);
        if let Some(d) = draft {
            cmd.env("CI_DRAFT", d);
        }
        if let Some(br) = base_ref {
            cmd.env("CI_BASE_REF", br);
        }
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("carrick-xtask ci-changes");
        assert!(
            out.status.success(),
            "carrick-xtask ci-changes failed: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let written_json: CiChangesOutputs =
            serde_json::from_slice(&fs::read(&class_json).expect("ci-class.json")).unwrap();
        let text = fs::read_to_string(&output_file).expect("read GITHUB_OUTPUT");
        let text_without_child_pr: String = text
            .lines()
            .filter(|line| !line.starts_with("child_pr="))
            .map(|line| format!("{line}\n"))
            .collect();
        assert_eq!(text_without_child_pr, written_json.format_github_output());
        text
    }
}

fn run_ci_results(event: &str, draft: Option<&str>, ci_needs_json: &str) -> bool {
    run_ci_results_with_env(event, draft, ci_needs_json, &[]).0
}

fn run_ci_results_with_env(
    event: &str,
    draft: Option<&str>,
    ci_needs_json: &str,
    extra_env: &[(&str, &str)],
) -> (bool, String) {
    let justfile = workspace_root().join("justfile");
    let mut cmd = Command::new("just");
    cmd.arg("--justfile")
        .arg(&justfile)
        .arg("--working-directory")
        .arg(workspace_root())
        .arg("ci-results")
        .env_remove("CI_DRAFT")
        .env_remove("CI_LOWER_LAYER")
        .env_remove("CI_CHILD_PR")
        .env_remove("GITHUB_STEP_SUMMARY")
        .env("CI_EVENT", event)
        .env("CI_NEEDS", ci_needs_json);
    if let Some(d) = draft {
        cmd.env("CI_DRAFT", d);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("just ci-results");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn referenced_docs_and_census_files_in_workspace_flip_to_heavy() {
    let root = workspace_root();
    let refs = ReferencedDocs::discover(&root).expect("discover referenced docs in workspace");

    // Required by review P1-1:
    // - `docs/design/arm-ring-first-flip.tsv` (`include_str!` in `crossing.rs`)
    // - `docs/design/arm-ring-first-flip.md` (`include_str!` in `native_process_runtime.rs`)
    // - `docs/design/arm-fork-stock-crossing.md` (`include_str!` in `cpl0_boot.rs`)
    // - `docs/superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md` (`include_str!` in `file_authority/root.rs`)
    // - `docs/support-matrix.md` (`read_to_string` in `carrick-conformance`)
    // - `docs/conformance-contracts.md` (`scripts/tests/test_conformance_contract_policy.py`)
    // - `AGENTS.md` (`scripts/tests/test_conformance_contract_policy.py`)
    for referenced in [
        "docs/design/arm-ring-first-flip.tsv",
        "docs/design/arm-ring-first-flip.md",
        "docs/design/arm-fork-stock-crossing.md",
        "docs/superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md",
        "docs/support-matrix.md",
        "docs/conformance-contracts.md",
        "AGENTS.md",
        ".agents/skills/carrick-conformance-contract/SKILL.md",
    ] {
        assert_eq!(
            classify_path(referenced, &refs),
            PathClass::Full,
            "`{referenced}` is compiled or read by code/tests/scripts and must classify as Full (heavy)"
        );
        let pr_out = evaluate_changes(
            "pull_request",
            false,
            false,
            Some(&[referenced.to_string()]),
            &refs,
        );
        assert_eq!(
            pr_out,
            CiChangesOutputs {
                heavy: true,
                macos: false,
                workflows: false,
                hardware: true,
                lower_layer: false,
            },
            "PR touching `{referenced}` must set heavy=true, hardware=true"
        );
        let mg_out = evaluate_changes(
            "merge_group",
            false,
            false,
            Some(&[referenced.to_string()]),
            &refs,
        );
        assert_eq!(
            mg_out,
            CiChangesOutputs {
                heavy: true,
                macos: true,
                workflows: true,
                hardware: true,
                lower_layer: false,
            },
            "merge_group touching `{referenced}` must set heavy=true, macos=true, workflows=true, hardware=true"
        );
    }

    // Piecewise path joins in `scripts/conformance/check-contract-change.py`
    // (`root / "docs" / "conformance-exemptions"`) and `scripts/coverage-metric.py`
    // (`os.path.join(ROOT, "docs", "conformance-coverage.md")`) resolve to their exact
    // directory prefix and file path.
    assert_eq!(
        classify_path("docs/conformance-exemptions/example.toml", &refs),
        PathClass::Full
    );
    assert_eq!(
        classify_path("docs/conformance-exemptions/README.md", &refs),
        PathClass::Full
    );
    assert_eq!(
        classify_path("docs/conformance-coverage.md", &refs),
        PathClass::Full
    );

    // Unreferenced prose under `docs/**`, `.agents/**`, root `README.md`, and `LICENSE*` remain Prose!
    for prose in [
        "README.md",
        "docs/unreferenced-prose-note.md",
        ".agents/notes/unreferenced-note.md",
        "LICENSE",
    ] {
        assert_eq!(
            classify_path(prose, &refs),
            PathClass::Prose,
            "`{prose}` is unreferenced prose and must classify as Prose"
        );
    }
}

#[test]
fn piecewise_path_joins_in_check_contract_change_and_coverage_metric_mark_docs_heavy() {
    let root = workspace_root();
    let check_contract_script =
        fs::read_to_string(root.join("scripts/conformance/check-contract-change.py"))
            .expect("read check-contract-change.py");
    let coverage_metric_script = fs::read_to_string(root.join("scripts/coverage-metric.py"))
        .expect("read coverage-metric.py");

    let mut check_refs = ReferencedDocs::default();
    scan_script_or_workflow(&check_contract_script, true, &mut check_refs);
    assert_eq!(
        classify_path("docs/conformance-exemptions/any.md", &check_refs),
        PathClass::Full,
        "check-contract-change.py `root / \"docs\" / \"conformance-exemptions\"` must mark `docs/conformance-exemptions/**` heavy"
    );

    let mut cov_refs = ReferencedDocs::default();
    scan_script_or_workflow(&coverage_metric_script, true, &mut cov_refs);
    assert_eq!(
        classify_path("docs/conformance-coverage.md", &cov_refs),
        PathClass::Full,
        "coverage-metric.py `os.path.join(ROOT, \"docs\", \"conformance-coverage.md\")` must mark `docs/conformance-coverage.md` heavy"
    );

    // A bare `docs` path segment or unresolvable dynamic join (`root / "docs" / dynamic_var` or
    // `os.path.join(ROOT, "docs", dynamic_var)`) marks every `docs/**` file heavy.
    for dynamic_script in [
        "target = root / \"docs\" / dynamic_subpath\n",
        "target = os.path.join(ROOT, \"docs\", dynamic_subpath)\n",
        "docs_root = root / \"docs\"\n",
    ] {
        let mut dyn_refs = ReferencedDocs::default();
        scan_script_or_workflow(dynamic_script, true, &mut dyn_refs);
        assert!(
            dyn_refs.dir_prefixes.contains("docs"),
            "unresolvable join `{dynamic_script}` must add bare `docs` prefix"
        );
        assert_eq!(
            classify_path("docs/any-prose-doc.md", &dyn_refs),
            PathClass::Full,
            "unresolvable join `{dynamic_script}` must flip every `docs/**` file to Full (heavy)"
        );
    }
}

#[test]
fn scripts_justfile_and_xtask_classify_as_full_heavy_macos_and_hardware() {
    let refs = ReferencedDocs::default();
    for full_path in [
        "scripts/test-signed.sh",
        "scripts/build-signed.sh",
        "scripts/entitlements.plist",
        "scripts/lib/post-link-sign.sh",
        "scripts/ci/gcp-kvm-run.sh",
        "justfile",
        "crates/carrick-xtask/src/accept.rs",
        "crates/carrick-xtask/src/ci_receipt.rs",
        "crates/carrick-xtask/src/test_batch.rs",
        "crates/carrick-xtask/src/test_lanes.rs",
        "crates/carrick-xtask/src/test_shards.rs",
    ] {
        assert_eq!(
            classify_path(full_path, &refs),
            PathClass::Full,
            "`{full_path}` must classify as Full so heavy, macos, and hardware all run"
        );
        let pr_out = evaluate_changes(
            "pull_request",
            false,
            false,
            Some(&[full_path.to_string()]),
            &refs,
        );
        assert_eq!(
            pr_out,
            CiChangesOutputs {
                heavy: true,
                macos: false,
                workflows: false,
                hardware: true,
                lower_layer: false,
            },
            "PR touching `{full_path}` must run heavy=true, hardware=true"
        );
        let mg_out = evaluate_changes(
            "merge_group",
            false,
            false,
            Some(&[full_path.to_string()]),
            &refs,
        );
        assert_eq!(
            mg_out,
            CiChangesOutputs {
                heavy: true,
                macos: true,
                workflows: true,
                hardware: true,
                lower_layer: false,
            },
            "merge_group touching `{full_path}` must run heavy=true, macos=true, workflows=true, hardware=true"
        );
    }
}

#[test]
fn prose_only_pr_skips_heavy_macos_and_hardware_but_merge_group_runs_full() {
    let repo = TempRepo::new(&[
        ("README.md", "updated readme"),
        ("docs/architecture.md", "some docs"),
        (".agents/skills/foo/SKILL.md", "skill doc"),
        ("LICENSE-MIT", "license text"),
    ]);

    assert_eq!(
        repo.run_ci_changes("pull_request", Some("false"), None),
        "heavy=false\nmacos=false\nworkflows=false\nhardware=false\nlower_layer=false\n"
    );
    assert_eq!(
        repo.run_ci_changes("merge_group", None, None),
        "heavy=true\nmacos=true\nworkflows=true\nhardware=true\nlower_layer=false\n"
    );
}

#[test]
fn workflows_run_full_heavy_macos_hardware_plus_actionlint() {
    let ci_yml_repo = TempRepo::new(&[(".github/workflows/ci.yml", "name: CI\n")]);
    assert_eq!(
        ci_yml_repo.run_ci_changes("pull_request", Some("false"), None),
        "heavy=true\nmacos=false\nworkflows=true\nhardware=true\nlower_layer=false\n"
    );
    assert_eq!(
        ci_yml_repo.run_ci_changes("merge_group", None, None),
        "heavy=true\nmacos=true\nworkflows=true\nhardware=true\nlower_layer=false\n"
    );

    let kr_yml_repo = TempRepo::new(&[(
        ".github/workflows/kernel-runtime.yml",
        "name: Kernel runtime\n",
    )]);
    assert_eq!(
        kr_yml_repo.run_ci_changes("pull_request", Some("false"), None),
        "heavy=true\nmacos=false\nworkflows=true\nhardware=true\nlower_layer=false\n"
    );
    assert_eq!(
        kr_yml_repo.run_ci_changes("merge_group", None, None),
        "heavy=true\nmacos=true\nworkflows=true\nhardware=true\nlower_layer=false\n"
    );
}

#[test]
fn unknown_or_rust_product_path_fails_safe_and_runs_everything() {
    let rust_repo = TempRepo::new(&[("crates/carrick-kernel/src/lib.rs", "pub fn f() {}\n")]);
    assert_eq!(
        rust_repo.run_ci_changes("pull_request", Some("false"), None),
        "heavy=true\nmacos=false\nworkflows=false\nhardware=true\nlower_layer=false\n"
    );
    assert_eq!(
        rust_repo.run_ci_changes("merge_group", None, None),
        "heavy=true\nmacos=true\nworkflows=true\nhardware=true\nlower_layer=false\n"
    );

    let unknown_repo = TempRepo::new(&[("Cargo.lock", "# lockfile\n")]);
    assert_eq!(
        unknown_repo.run_ci_changes("merge_group", None, None),
        "heavy=true\nmacos=true\nworkflows=true\nhardware=true\nlower_layer=false\n"
    );
}

#[test]
fn cumulative_merge_group_diff_runs_everything_when_ahead_entry_touched_code() {
    let dir = tempfile::tempdir().expect("tempdir");
    let run_git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .output()
            .expect("git command");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    run_git(&["init", "-b", "main"]);
    run_git(&["config", "user.email", "test@example.com"]);
    run_git(&["config", "user.name", "Test"]);

    fs::write(dir.path().join("README.md"), "base\n").unwrap();
    run_git(&["add", "README.md"]);
    run_git(&["commit", "-m", "main tip"]);
    let main_sha = run_git(&["rev-parse", "HEAD"]);

    // Entry 1 in queue changes Rust code.
    fs::create_dir_all(dir.path().join("crates/foo/src")).unwrap();
    fs::write(dir.path().join("crates/foo/src/lib.rs"), "pub fn a() {}\n").unwrap();
    run_git(&["add", "crates/foo/src/lib.rs"]);
    run_git(&["commit", "-m", "entry 1: code"]);
    let entry1_sha = run_git(&["rev-parse", "HEAD"]);

    // Entry 2 in queue only changes README.md on top of Entry 1.
    fs::write(dir.path().join("README.md"), "entry 2: docs only\n").unwrap();
    run_git(&["add", "README.md"]);
    run_git(&["commit", "-m", "entry 2: docs"]);

    let repo = TempRepo {
        dir,
        base_sha: entry1_sha,
    };

    // Merge group always runs everything: heavy, macos, workflows, and hardware are all true.
    assert_eq!(
        repo.run_ci_changes("merge_group", None, Some(&main_sha)),
        "heavy=true\nmacos=true\nworkflows=true\nhardware=true\nlower_layer=false\n"
    );
}

#[test]
fn draft_pr_runs_cheap_linux_checks_and_ci_results_accepts_skipped_heavy_jobs() {
    let repo = TempRepo::new(&[(
        "crates/carrick-kernel/src/lib.rs",
        "pub fn draft_change() {}\n",
    )]);

    assert_eq!(
        repo.run_ci_changes("pull_request", Some("true"), None),
        "heavy=true\nmacos=false\nworkflows=false\nhardware=true\nlower_layer=false\n"
    );

    let draft_needs = r#"{
      "changes": {
        "result": "success",
        "outputs": { "heavy": "true", "macos": "false", "workflows": "false", "hardware": "true", "lower_layer": "false" }
      },
      "actionlint": { "result": "skipped" },
      "linked-issue": { "result": "success" },
      "commit-trailers": { "result": "success" },
      "lint": { "result": "success" },
      "portable": { "result": "skipped" },
      "linux-doc": { "result": "skipped" },
      "macos-clippy": { "result": "skipped" },
      "macos-build": { "result": "skipped" },
      "macos-unit-a": { "result": "skipped" },
      "macos-unit-b": { "result": "skipped" },
      "macos-integration": { "result": "skipped" },
      "cross-check-freebsd": { "result": "skipped" },
      "cross-check-netbsd": { "result": "skipped" },
      "cross-check-macos": { "result": "skipped" },
      "kernel-linux-native": { "result": "skipped" }
    }"#;
    assert!(
        run_ci_results("pull_request", Some("true"), draft_needs),
        "draft PR with passing lint and skipped expensive jobs must pass ci-results"
    );
    assert!(
        !run_ci_results("pull_request", Some("false"), draft_needs),
        "non-draft PR with skipped expensive jobs must fail ci-results"
    );

    let draft_failed_lint = draft_needs.replace(
        r#""lint": { "result": "success" }"#,
        r#""lint": { "result": "failure" }"#,
    );
    assert!(
        !run_ci_results("pull_request", Some("true"), &draft_failed_lint),
        "draft PR with failing lint must fail ci-results"
    );
}

#[cfg(unix)]
fn write_mock_gh(bin_dir: &Path, body: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let gh_path = bin_dir.join("gh");
    fs::write(&gh_path, body).expect("write mock gh");
    let mut perms = fs::metadata(&gh_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&gh_path, perms).unwrap();
    let old_path = std::env::var("PATH").unwrap_or_default();
    format!("{}:{old_path}", bin_dir.display())
}

#[test]
#[cfg(unix)]
fn stack_layer_detection_and_ci_results_gating() {
    let refs = ReferencedDocs::default();
    let code_paths = vec!["crates/carrick-kernel/src/lib.rs".to_string()];

    // 1. Unit-level evaluate_changes checks:
    // Lower layer on pull_request -> lower_layer=true, heavy=true (so lint still runs, expensive jobs gated by lower_layer != 'true').
    assert_eq!(
        evaluate_changes("pull_request", false, true, Some(&code_paths), &refs),
        CiChangesOutputs {
            heavy: true,
            macos: false,
            workflows: false,
            hardware: true,
            lower_layer: true,
        }
    );
    // Top layer on pull_request -> lower_layer=false, heavy=true.
    assert_eq!(
        evaluate_changes("pull_request", false, false, Some(&code_paths), &refs),
        CiChangesOutputs {
            heavy: true,
            macos: false,
            workflows: false,
            hardware: true,
            lower_layer: false,
        }
    );
    // merge_group, push, schedule with a child -> lower_layer=false, full suite.
    for non_pr_event in ["merge_group", "push", "schedule"] {
        assert_eq!(
            evaluate_changes(non_pr_event, false, true, Some(&code_paths), &refs),
            CiChangesOutputs {
                heavy: true,
                macos: true,
                workflows: true,
                hardware: true,
                lower_layer: false,
            },
            "{non_pr_event} with a child must run full suite with lower_layer=false"
        );
    }

    // 2. Subprocess ci-changes checks with mock gh:
    let repo = TempRepo::new(&[("crates/carrick-kernel/src/lib.rs", "pub fn layer() {}\n")]);
    let bin_dir = tempfile::tempdir().expect("mock gh bin dir");
    let summary_file = repo.dir.path().join("step_summary.md");

    // 2a. Lower layer (child PR #610 open against work/layer-1)
    let path_with_child = write_mock_gh(
        bin_dir.path(),
        "#!/usr/bin/env bash\nprintf '[{\"number\":610,\"state\":\"open\",\"base\":{\"ref\":\"work/layer-1\"}}]\\n'\n",
    );
    let _ = fs::remove_file(&summary_file);
    let out_lower = repo.run_ci_changes_with_env(
        "pull_request",
        Some("false"),
        None,
        &[
            ("CI_HEAD_REF", "work/layer-1"),
            ("CI_HEAD_REPO", "carrick-sh/carrick"),
            ("PATH", &path_with_child),
            ("GITHUB_STEP_SUMMARY", summary_file.to_str().unwrap()),
        ],
    );
    assert_eq!(
        out_lower,
        "heavy=true\nmacos=false\nworkflows=false\nhardware=true\nlower_layer=true\nchild_pr=610\n"
    );
    let summary_text = fs::read_to_string(&summary_file).expect("step summary written");
    assert!(
        summary_text.contains("lower stack layer: child PR #610"),
        "expected lower stack layer reason in summary, got: {summary_text}"
    );

    // 2b. Top layer (no open child PR)
    let path_top = write_mock_gh(bin_dir.path(), "#!/usr/bin/env bash\nprintf '[]\\n'\n");
    let _ = fs::remove_file(&summary_file);
    let out_top = repo.run_ci_changes_with_env(
        "pull_request",
        Some("false"),
        None,
        &[
            ("CI_HEAD_REF", "work/layer-top"),
            ("CI_HEAD_REPO", "carrick-sh/carrick"),
            ("PATH", &path_top),
            ("GITHUB_STEP_SUMMARY", summary_file.to_str().unwrap()),
        ],
    );
    assert_eq!(
        out_top,
        "heavy=true\nmacos=false\nworkflows=false\nhardware=true\nlower_layer=false\n"
    );
    assert!(
        !summary_file.exists(),
        "top layer should not write lower stack layer summary"
    );

    // 2c. Lookup error fails closed to full suite (heavy=true, lower_layer=false) even on prose-only PR
    let path_err = write_mock_gh(
        bin_dir.path(),
        "#!/usr/bin/env bash\necho 'HTTP 502 Bad Gateway' >&2\nexit 1\n",
    );
    let out_err = repo.run_ci_changes_with_env(
        "pull_request",
        Some("false"),
        None,
        &[
            ("CI_HEAD_REF", "work/layer-1"),
            ("CI_HEAD_REPO", "carrick-sh/carrick"),
            ("PATH", &path_err),
        ],
    );
    assert_eq!(
        out_err,
        "heavy=true\nmacos=false\nworkflows=false\nhardware=true\nlower_layer=false\n"
    );
    let prose_repo = TempRepo::new(&[("docs/unreferenced-note.md", "prose only\n")]);
    let out_prose_err = prose_repo.run_ci_changes_with_env(
        "pull_request",
        Some("false"),
        None,
        &[
            ("CI_HEAD_REF", "work/layer-prose"),
            ("CI_HEAD_REPO", "carrick-sh/carrick"),
            ("PATH", &path_err),
        ],
    );
    assert_eq!(
        out_prose_err,
        "heavy=true\nmacos=false\nworkflows=false\nhardware=true\nlower_layer=false\n",
        "child lookup error on prose PR must fail closed to heavy=true, hardware=true, lower_layer=false"
    );

    // 2d. merge_group with a child PR still runs full suite
    let out_mg_with_child = repo.run_ci_changes_with_env(
        "merge_group",
        None,
        None,
        &[
            ("CI_HEAD_REF", "work/layer-1"),
            ("CI_HEAD_REPO", "carrick-sh/carrick"),
            ("PATH", &path_with_child),
        ],
    );
    assert_eq!(
        out_mg_with_child,
        "heavy=true\nmacos=true\nworkflows=true\nhardware=true\nlower_layer=false\n"
    );

    // 3. ci-results check: lower layer passes with skipped heavy jobs and writes reason to summary;
    // top layer does not.
    let lower_layer_needs = r#"{
      "changes": {
        "result": "success",
        "outputs": {
          "heavy": "true",
          "macos": "false",
          "workflows": "false",
          "hardware": "true",
          "lower_layer": "true",
          "child_pr": "610"
        }
      },
      "actionlint": { "result": "skipped" },
      "linked-issue": { "result": "success" },
      "commit-trailers": { "result": "success" },
      "lint": { "result": "success" },
      "portable": { "result": "skipped" },
      "linux-doc": { "result": "skipped" },
      "macos-clippy": { "result": "skipped" },
      "macos-build": { "result": "skipped" },
      "macos-unit-a": { "result": "skipped" },
      "macos-unit-b": { "result": "skipped" },
      "macos-integration": { "result": "skipped" },
      "cross-check-linux": { "result": "skipped" },
      "cross-check-freebsd": { "result": "skipped" },
      "cross-check-netbsd": { "result": "skipped" },
      "kernel-linux-native": { "result": "skipped" }
    }"#;
    let ci_ok_summary = repo.dir.path().join("ci_ok_summary.md");
    let _ = fs::remove_file(&ci_ok_summary);
    let (ok_lower, stdout_lower) = run_ci_results_with_env(
        "pull_request",
        Some("false"),
        lower_layer_needs,
        &[("GITHUB_STEP_SUMMARY", ci_ok_summary.to_str().unwrap())],
    );
    assert!(
        ok_lower,
        "lower layer PR with passing cheap checks and skipped heavy jobs must pass ci-results"
    );
    assert!(
        stdout_lower.contains("lower stack layer: child PR #610"),
        "ci-results stdout must report lower stack layer reason, got: {stdout_lower}"
    );
    let ci_ok_summary_text = fs::read_to_string(&ci_ok_summary).expect("ci-ok step summary");
    assert!(
        ci_ok_summary_text.contains("lower stack layer: child PR #610"),
        "ci-results step summary must contain lower stack layer reason, got: {ci_ok_summary_text}"
    );

    let top_layer_needs_with_skips =
        lower_layer_needs.replace(r#""lower_layer": "true""#, r#""lower_layer": "false""#);
    assert!(
        !run_ci_results("pull_request", Some("false"), &top_layer_needs_with_skips),
        "top layer PR with skipped heavy jobs must fail ci-results"
    );
}

#[test]
fn merge_group_requires_full_suite_in_ci_results() {
    let full_mg_needs = r#"{
      "changes": {
        "result": "success",
        "outputs": { "heavy": "true", "macos": "true", "workflows": "true", "hardware": "true", "lower_layer": "false" }
      },
      "actionlint": { "result": "success" },
      "linked-issue": { "result": "success" },
      "commit-trailers": { "result": "success" },
      "lint": { "result": "success" },
      "portable": { "result": "success" },
      "linux-doc": { "result": "success" },
      "macos-clippy": { "result": "success" },
      "macos-build": { "result": "success" },
      "macos-unit-a": { "result": "success" },
      "macos-unit-b": { "result": "success" },
      "macos-integration": { "result": "success" },
      "cross-check-linux": { "result": "success" },
      "cross-check-freebsd": { "result": "success" },
      "cross-check-netbsd": { "result": "success" },
      "cross-check-macos": { "result": "success" },
      "kernel-linux-native": { "result": "success" }
    }"#;
    assert!(
        run_ci_results("merge_group", None, full_mg_needs),
        "full merge_group must pass ci-results"
    );

    // Any skipped job on merge_group must be rejected by ci-results.
    let skipped_macos_mg_needs = full_mg_needs.replace(
        r#""macos-integration": { "result": "success" }"#,
        r#""macos-integration": { "result": "skipped" }"#,
    );
    assert!(
        !run_ci_results("merge_group", None, &skipped_macos_mg_needs),
        "skipped macos job on merge_group must fail ci-results"
    );

    let skipped_heavy_mg_needs = full_mg_needs.replace(
        r#""portable": { "result": "success" }"#,
        r#""portable": { "result": "skipped" }"#,
    );
    assert!(
        !run_ci_results("merge_group", None, &skipped_heavy_mg_needs),
        "skipped heavy job on merge_group must fail ci-results"
    );

    let docs_mg_needs = full_mg_needs.replace(
        r#""heavy": "true", "macos": "true""#,
        r#""heavy": "false", "macos": "false""#,
    );
    assert!(
        !run_ci_results("merge_group", None, &docs_mg_needs),
        "docs-only merge_group must fail ci-results"
    );
}

#[test]
fn fork_prs_never_look_up_child_layers() {
    let repo = "carrick-sh/carrick";
    // Same-repository PR with a head branch: lookup allowed.
    assert!(child_lookup_allowed(
        "pull_request",
        "work/x-1",
        "carrick-sh/carrick",
        repo
    ));
    assert!(child_lookup_allowed(
        "pull_request",
        "work/x-1",
        "Carrick-sh/Carrick",
        repo
    ));
    // A fork whose branch is named like one of our base branches must never match.
    assert!(!child_lookup_allowed(
        "pull_request",
        "main",
        "someone/carrick",
        repo
    ));
    assert!(!child_lookup_allowed(
        "pull_request",
        "work/x-1",
        "someone/carrick",
        repo
    ));
    // Unknown head repo or empty head ref fails closed to the full suite.
    assert!(!child_lookup_allowed("pull_request", "work/x-1", "", repo));
    assert!(!child_lookup_allowed("pull_request", "", repo, repo));
    // Non-PR events never take the lower-layer path.
    for event in ["merge_group", "push", "schedule", "workflow_dispatch"] {
        assert!(!child_lookup_allowed(event, "work/x-1", repo, repo));
    }
}

/// `just ci-results` requires every heavy pull-request job except `lint` (and
/// the `macos-*` jobs, which never run on pull requests) to be skipped on a
/// lower stack layer. A heavy job without the matching `lower_layer` guard runs
/// anyway and turns `ci-ok` red on every lower layer, which blocks the stack.
#[test]
fn every_heavy_pr_job_skips_on_lower_stack_layers() {
    let workflow = fs::read_to_string(workspace_root().join(".github/workflows/ci.yml")).unwrap();
    let mut unguarded = Vec::new();
    let mut job: Option<String> = None;
    let mut in_jobs = false;
    for line in workflow.lines() {
        if line == "jobs:" {
            in_jobs = true;
            continue;
        }
        if !in_jobs {
            continue;
        }
        if let Some(name) = line
            .strip_prefix("  ")
            .filter(|rest| !rest.starts_with(' '))
            .and_then(|rest| rest.strip_suffix(':'))
        {
            job = Some(name.to_owned());
            continue;
        }
        let Some(condition) = line.trim_start().strip_prefix("if:") else {
            continue;
        };
        let Some(name) = job.as_deref() else {
            continue;
        };
        if name == "lint" || name.starts_with("macos-") {
            continue;
        }
        if condition.contains("needs.changes.outputs.heavy == 'true'")
            && !condition.contains("needs.changes.outputs.lower_layer != 'true'")
        {
            unguarded.push(name.to_owned());
        }
    }
    assert!(
        unguarded.is_empty(),
        "heavy jobs without a lower_layer guard: {unguarded:?}"
    );
}
