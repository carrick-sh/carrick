//! Contract witness for the nightly goal scoreboard steps in `kernel-runtime.yml` (#2127).

#![allow(clippy::expect_used)]

use carrick_test_support::executable::write_executable;
use std::fs;
use std::path::Path;
use std::process::Command;
use yaml_rust2::{Yaml, YamlLoader};

const RUN_STEP_NAME: &str = "Goal scoreboard (nightly)";
const UPLOAD_STEP_NAME: &str = "Upload scoreboard receipt";
const POST_STEP_NAME: &str = "Post scoreboard to #231";

fn load_kernel_runtime_workflow() -> Yaml {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = root.join(".github/workflows/kernel-runtime.yml");
    let text = fs::read_to_string(&path).expect("read kernel-runtime.yml");
    let mut docs = YamlLoader::load_from_str(&text).expect("parse kernel-runtime.yml");
    assert_eq!(docs.len(), 1, "expected single YAML document");
    docs.remove(0)
}

fn collect_yaml_strings(node: &Yaml, out: &mut Vec<String>) {
    match node {
        Yaml::String(s) => out.push(s.clone()),
        Yaml::Array(items) => {
            for item in items {
                collect_yaml_strings(item, out);
            }
        }
        Yaml::Hash(map) => {
            for (k, v) in map {
                collect_yaml_strings(k, out);
                collect_yaml_strings(v, out);
            }
        }
        _ => {}
    }
}

fn step_by_name<'a>(steps: &'a [Yaml], name: &str) -> (usize, &'a Yaml) {
    let pos = steps.iter().position(|s| s["name"].as_str() == Some(name));
    assert!(pos.is_some(), "missing step `{name}` in hvf-kernel");
    let idx = pos.expect("checked above");
    (idx, &steps[idx])
}

fn squash_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_nightly_or_owner_dispatch_guard(label: &str, step: &Yaml) {
    let raw_if = step["if"].as_str().unwrap_or("");
    assert!(!raw_if.is_empty(), "{label}: missing `if` guard");
    let guard = squash_ws(raw_if);
    assert!(
        guard.contains("!cancelled()"),
        "{label}: `if` must include `!cancelled()`: {guard}"
    );
    assert!(
        guard.contains("github.event_name == 'schedule'"),
        "{label}: `if` must include `schedule` guard: {guard}"
    );
    assert!(
        guard.contains("github.event_name == 'workflow_dispatch'")
            && guard.contains("github.actor == 'tjfontaine'")
            && guard.contains("github.triggering_actor == 'tjfontaine'"),
        "{label}: `if` must include owner `workflow_dispatch` + `tjfontaine` guard: {guard}"
    );
    assert!(
        guard.contains("github.ref == 'refs/heads/main'"),
        "{label}: `if` must restrict to `refs/heads/main`: {guard}"
    );
    assert!(
        !guard.contains("push") && !guard.contains("pull_request"),
        "{label}: `if` must never allow `push` or `pull_request`: {guard}"
    );
}

#[test]
fn hvf_kernel_wires_nightly_scoreboard_with_event_guards_and_token_isolation() {
    let workflow = load_kernel_runtime_workflow();

    // Workflow-level permissions stay read-only; `issues: write` belongs only to `hvf-kernel`.
    let wf_perms = workflow["permissions"]
        .as_hash()
        .expect("workflow-level permissions hash");
    assert_eq!(
        wf_perms.get(&Yaml::from_str("contents")),
        Some(&Yaml::from_str("read"))
    );
    assert_eq!(
        wf_perms.get(&Yaml::from_str("actions")),
        Some(&Yaml::from_str("read"))
    );
    assert!(
        !wf_perms.contains_key(&Yaml::from_str("issues")),
        "workflow-level permissions must not grant issues access"
    );

    let jobs = workflow["jobs"].as_hash().expect("jobs hash");
    let mut jobs_with_issues_write = Vec::new();
    for (job_id, job) in jobs {
        let id = job_id.as_str().expect("job id string");
        if let Some(perms) = job["permissions"].as_hash()
            && perms.contains_key(&Yaml::from_str("issues"))
        {
            jobs_with_issues_write.push((
                id.to_owned(),
                perms
                    .get(&Yaml::from_str("issues"))
                    .and_then(Yaml::as_str)
                    .unwrap_or("")
                    .to_owned(),
            ));
        }
    }
    assert_eq!(
        jobs_with_issues_write,
        vec![("hvf-kernel".to_owned(), "write".to_owned())],
        "`issues: write` must appear only in hvf-kernel's job permissions"
    );

    let hvf = &workflow["jobs"]["hvf-kernel"];
    let hvf_perms = hvf["permissions"]
        .as_hash()
        .expect("hvf-kernel job permissions");
    assert_eq!(
        hvf_perms.len(),
        3,
        "unexpected permissions on hvf-kernel: {hvf_perms:?}"
    );
    assert_eq!(
        hvf_perms.get(&Yaml::from_str("contents")),
        Some(&Yaml::from_str("read"))
    );
    assert_eq!(
        hvf_perms.get(&Yaml::from_str("actions")),
        Some(&Yaml::from_str("read"))
    );
    assert_eq!(
        hvf_perms.get(&Yaml::from_str("issues")),
        Some(&Yaml::from_str("write"))
    );

    let steps = hvf["steps"].as_vec().expect("hvf-kernel steps");
    let build_idx = steps
        .iter()
        .position(|s| {
            s["run"]
                .as_str()
                .is_some_and(|r| r.lines().any(|line| line.trim() == "just build"))
        })
        .expect("step running `just build` in hvf-kernel");
    let (_, failure_evidence_step) = step_by_name(steps, "Upload signed failure evidence");
    let failure_idx = steps
        .iter()
        .position(|s| std::ptr::eq(s, failure_evidence_step))
        .expect("failure evidence step index");

    let (run_idx, run_step) = step_by_name(steps, RUN_STEP_NAME);
    let (upload_idx, upload_step) = step_by_name(steps, UPLOAD_STEP_NAME);
    let (post_idx, post_step) = step_by_name(steps, POST_STEP_NAME);

    assert!(
        build_idx < run_idx
            && run_idx < upload_idx
            && upload_idx < post_idx
            && post_idx < failure_idx,
        "expected step order: just build ({build_idx}) < run ({run_idx}) < upload ({upload_idx}) < post ({post_idx}) < failure evidence ({failure_idx})"
    );

    // Every step in the workflow that touches scoreboard must be one of these three.
    for (job_id, job) in jobs {
        let id = job_id.as_str().expect("job id");
        for (idx, step) in job["steps"].as_vec().into_iter().flatten().enumerate() {
            let mut strings = Vec::new();
            collect_yaml_strings(step, &mut strings);
            if strings.iter().any(|s| s.contains("scoreboard")) {
                assert_eq!(id, "hvf-kernel", "unexpected scoreboard step in job {id}");
                assert!(
                    [run_idx, upload_idx, post_idx].contains(&idx),
                    "unexpected scoreboard reference in hvf-kernel step index {idx}: {:?}",
                    step["name"].as_str()
                );
            }
        }
    }

    // Run step contract.
    let run_script = run_step["run"].as_str().expect("scoreboard run script");
    assert!(
        run_script.contains("\"$CARRICK_XTASK_BIN\" scoreboard")
            || run_script.contains("scoreboard"),
        "run step must invoke `scoreboard`: {run_script}"
    );
    assert!(
        squash_ws(run_script).contains("scoreboard --carrick target/release/carrick"),
        "run step must pass `--carrick target/release/carrick`: {run_script}"
    );
    assert!(
        run_script.contains("--sha \"$GITHUB_SHA\"")
            && run_script.contains("--out target/scoreboard/receipt.json"),
        "run step must pass `--sha \"$GITHUB_SHA\"` and `--out target/scoreboard/receipt.json`: {run_script}"
    );
    assert!(
        run_script.contains("just lease gate"),
        "run step must hold `just lease gate`: {run_script}"
    );
    assert!(
        run_script.contains("CARRICK_RUN_ID"),
        "run step must stamp `CARRICK_RUN_ID`: {run_script}"
    );
    assert!(
        run_script.contains("target/scoreboard/table.txt"),
        "run step must tee stdout to `target/scoreboard/table.txt`: {run_script}"
    );
    for forbidden_pipe in ["| tail", "| grep", "| head"] {
        assert!(
            !run_script.contains(forbidden_pipe),
            "run step must not pipe output through `{forbidden_pipe}`: {run_script}"
        );
    }

    // Upload step contract.
    assert_eq!(
        upload_step["uses"].as_str(),
        Some("actions/upload-artifact@v4")
    );
    assert_eq!(
        upload_step["with"]["name"].as_str(),
        Some("scoreboard-${{ github.sha }}-${{ github.run_attempt }}")
    );
    assert_eq!(
        upload_step["with"]["path"].as_str(),
        Some("target/scoreboard/")
    );
    assert_eq!(
        upload_step["with"]["if-no-files-found"].as_str(),
        Some("warn")
    );

    // Post step contract.
    let post_script = post_step["run"].as_str().expect("scoreboard post script");
    assert!(
        post_script.contains(
            "gh issue comment 231 --repo \"$GITHUB_REPOSITORY\" --body-file target/scoreboard/comment.md"
        ),
        "post step must comment on #231 via --body-file: {post_script}"
    );
    assert!(
        post_script.contains("<<'"),
        "post step must write body with a quoted heredoc: {post_script}"
    );

    // All three steps share the explicit event guard and `continue-on-error: true`.
    let triad = [
        (RUN_STEP_NAME, run_step),
        (UPLOAD_STEP_NAME, upload_step),
        (POST_STEP_NAME, post_step),
    ];
    for (label, step) in triad {
        assert_nightly_or_owner_dispatch_guard(label, step);
        assert_eq!(
            step["continue-on-error"].as_bool(),
            Some(true),
            "{label}: must set `continue-on-error: true`"
        );
    }

    // Token and secret isolation across the three steps.
    for (label, step) in [(RUN_STEP_NAME, run_step), (UPLOAD_STEP_NAME, upload_step)] {
        let mut all_strings = Vec::new();
        collect_yaml_strings(step, &mut all_strings);
        for needle in ["GH_TOKEN", "GITHUB_TOKEN", "github.token", "secrets."] {
            assert!(
                all_strings.iter().all(|s| !s.contains(needle)),
                "{label} must not reference `{needle}`: {all_strings:?}"
            );
        }
    }

    let token_steps: Vec<&str> = triad
        .iter()
        .filter_map(|(label, step)| {
            let mut strings = Vec::new();
            collect_yaml_strings(step, &mut strings);
            strings
                .iter()
                .any(|s| {
                    s.contains("github.token")
                        || s.contains("GH_TOKEN")
                        || s.contains("GITHUB_TOKEN")
                })
                .then_some(*label)
        })
        .collect();
    assert_eq!(
        token_steps,
        vec![POST_STEP_NAME],
        "exactly the post step may reference github.token / GH_TOKEN"
    );

    let post_env = post_step["env"].as_hash().expect("post step env");
    assert_eq!(
        post_env.len(),
        1,
        "unexpected env keys on post step: {post_env:?}"
    );
    assert_eq!(
        post_step["env"]["GH_TOKEN"].as_str(),
        Some("${{ github.token }}")
    );
    let mut post_strings = Vec::new();
    collect_yaml_strings(post_step, &mut post_strings);
    assert!(
        post_strings.iter().all(|s| !s.contains("secrets.")),
        "post step must not reference `secrets.*`: {post_strings:?}"
    );
    assert!(
        !post_script.contains("GH_TOKEN") && !post_script.contains("github.token"),
        "post script must never reference or echo GH_TOKEN: {post_script}"
    );
}

#[test]
fn scoreboard_workflow_scripts_execute_expected_run_and_post_paths() {
    let workflow = load_kernel_runtime_workflow();
    let steps = workflow["jobs"]["hvf-kernel"]["steps"]
        .as_vec()
        .expect("hvf-kernel steps");
    let (_, run_step) = step_by_name(steps, RUN_STEP_NAME);
    let (_, post_step) = step_by_name(steps, POST_STEP_NAME);
    let run_script = run_step["run"].as_str().expect("run script");
    let post_script = post_step["run"].as_str().expect("post script");

    let dir = tempfile::tempdir().expect("tempdir");
    let bin = dir.path().join("bin");
    let ws = dir.path().join("ws");
    fs::create_dir_all(&bin).expect("mkdir bin");
    fs::create_dir_all(ws.join("target/release")).expect("mkdir target/release");
    write_executable(ws.join("target/release/carrick"), "#!/bin/sh\nexit 0\n");

    let xtask = bin.join("fake-xtask");
    write_executable(
        &xtask,
        "#!/bin/sh\n\
         set -eu\n\
         [ -n \"${CARRICK_RUN_ID:-}\" ] || exit 41\n\
         printf '%s\\n' \"$*\" > \"$XTASK_ARGS_OUT\"\n\
         [ \"${FAKE_XTASK_FAIL:-0}\" = 1 ] && exit 17\n\
         mkdir -p target/scoreboard\n\
         printf '{\"schema\":\"carrick.scoreboard.v1\",\"main_sha\":\"%s\",\"binary_sha256\":\"deadbeef\",\"rows\":[]}\\n' \"$5\" > target/scoreboard/receipt.json\n\
         printf 'main 0123456789  sha256=deadbeef\\npy-version       exit=0    3.12.7 ($GH_TOKEN)\\n'\n",
    );
    let just = bin.join("just");
    write_executable(
        &just,
        "#!/bin/sh\n\
         set -eu\n\
         [ \"$1\" = lease ] && [ \"$2\" = gate ] || exit 42\n\
         shift 2\n\
         exec \"$@\"\n",
    );
    let gh = bin.join("gh");
    write_executable(
        &gh,
        "#!/bin/sh\n\
         set -eu\n\
         printf '%s\\n' \"$@\" > \"$GH_ARGS_OUT\"\n\
         cp target/scoreboard/comment.md \"$GH_BODY_OUT\"\n",
    );

    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let gh_args_out = dir.path().join("gh.args");
    let gh_body_out = dir.path().join("gh.body");
    let xtask_args_out = dir.path().join("xtask.args");

    // 1. Missing receipt: post step exits 0 and does not call `gh`.
    let missing = Command::new("bash")
        .args(["-c", post_script])
        .current_dir(&ws)
        .env("PATH", &path_env)
        .env("GH_TOKEN", "canary-secret-token-value")
        .env("GITHUB_SHA", sha)
        .env("GITHUB_SERVER_URL", "https://github.com")
        .env("GITHUB_REPOSITORY", "carrick-sh/carrick")
        .env("GITHUB_RUN_ID", "424242")
        .env("GH_ARGS_OUT", &gh_args_out)
        .env("GH_BODY_OUT", &gh_body_out)
        .output()
        .expect("run post_script on missing receipt");
    assert!(
        missing.status.success(),
        "missing receipt must skip cleanly: {}",
        String::from_utf8_lossy(&missing.stderr)
    );
    assert!(
        !gh_args_out.exists(),
        "gh must not run when receipt is missing"
    );

    // 2. Run step executes xtask scoreboard under `just lease gate` and tees table.txt.
    let ok_run = Command::new("bash")
        .args(["-c", run_script])
        .current_dir(&ws)
        .env("PATH", &path_env)
        .env("CARRICK_XTASK_BIN", &xtask)
        .env("GITHUB_SHA", sha)
        .env("GITHUB_RUN_ID", "424242")
        .env("GITHUB_RUN_ATTEMPT", "1")
        .env("XTASK_ARGS_OUT", &xtask_args_out)
        .output()
        .expect("run scoreboard step");
    assert!(
        ok_run.status.success(),
        "scoreboard run failed: {}",
        String::from_utf8_lossy(&ok_run.stderr)
    );
    assert_eq!(
        fs::read_to_string(&xtask_args_out)
            .expect("xtask args")
            .trim(),
        format!(
            "scoreboard --carrick target/release/carrick --sha {sha} --out target/scoreboard/receipt.json"
        )
    );
    let table_txt = fs::read_to_string(ws.join("target/scoreboard/table.txt")).expect("table.txt");
    assert!(table_txt.contains("py-version       exit=0    3.12.7 ($GH_TOKEN)"));

    // 3. Post step builds comment.md with SHA, run URL and fenced table without expanding $GH_TOKEN.
    let ok_post = Command::new("bash")
        .args(["-c", post_script])
        .current_dir(&ws)
        .env("PATH", &path_env)
        .env("GH_TOKEN", "canary-secret-token-value")
        .env("GITHUB_SHA", sha)
        .env("GITHUB_SERVER_URL", "https://github.com")
        .env("GITHUB_REPOSITORY", "carrick-sh/carrick")
        .env("GITHUB_RUN_ID", "424242")
        .env("GH_ARGS_OUT", &gh_args_out)
        .env("GH_BODY_OUT", &gh_body_out)
        .output()
        .expect("run post_script with receipt");
    assert!(
        ok_post.status.success(),
        "post step failed: {}",
        String::from_utf8_lossy(&ok_post.stderr)
    );
    let gh_args: Vec<String> = fs::read_to_string(&gh_args_out)
        .expect("gh args")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        gh_args,
        vec![
            "issue",
            "comment",
            "231",
            "--repo",
            "carrick-sh/carrick",
            "--body-file",
            "target/scoreboard/comment.md",
        ]
    );
    let body = fs::read_to_string(&gh_body_out).expect("comment body");
    assert!(body.contains(sha), "comment missing full SHA: {body}");
    assert!(
        body.contains("https://github.com/carrick-sh/carrick/actions/runs/424242"),
        "comment missing run URL: {body}"
    );
    assert!(
        body.contains("```"),
        "comment missing fenced code block: {body}"
    );
    assert!(
        body.contains("py-version       exit=0    3.12.7 ($GH_TOKEN)"),
        "comment missing table text: {body}"
    );
    assert!(
        !body.contains("canary-secret-token-value")
            && !String::from_utf8_lossy(&ok_post.stdout).contains("canary-secret-token-value")
            && !String::from_utf8_lossy(&ok_post.stderr).contains("canary-secret-token-value"),
        "GH_TOKEN leaked into output or comment body"
    );

    // 4. Non-zero exit from scoreboard is not masked by `tee`.
    let fail_run = Command::new("bash")
        .args(["-c", run_script])
        .current_dir(&ws)
        .env("PATH", &path_env)
        .env("CARRICK_XTASK_BIN", &xtask)
        .env("FAKE_XTASK_FAIL", "1")
        .env("GITHUB_SHA", sha)
        .env("GITHUB_RUN_ID", "424242")
        .env("GITHUB_RUN_ATTEMPT", "1")
        .env("XTASK_ARGS_OUT", &xtask_args_out)
        .output()
        .expect("run failing scoreboard step");
    assert!(
        !fail_run.status.success(),
        "failing xtask must return non-zero from the tee pipeline"
    );
}
