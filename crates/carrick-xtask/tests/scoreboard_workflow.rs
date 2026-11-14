//! Contract witness for the nightly goal scoreboard in `kernel-runtime.yml` (#2127; both ISAs, #2327).

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
    assert!(pos.is_some(), "missing step `{name}`");
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

    // Workflow-level permissions stay read-only.
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
    // Only the two posters, which run no repository code, may write issues
    // (#2327 moved the nightly post out of `hvf-kernel`, which builds and runs
    // main's code, into `scoreboard-post`). Neither scoring job holds a write
    // token: not `hvf-kernel`, `kvm-scoreboard` or the branch `hvf-scoreboard`.
    jobs_with_issues_write.sort();
    assert_eq!(
        jobs_with_issues_write,
        vec![
            ("scoreboard-post".to_owned(), "write".to_owned()),
            ("scoreboard-publish".to_owned(), "write".to_owned()),
        ],
        "`issues: write` must appear only in scoreboard-post's and scoreboard-publish's job permissions"
    );
    assert_scoreboard_branch_jobs_isolate_the_token(jobs);

    let hvf = &workflow["jobs"]["hvf-kernel"];
    let hvf_perms = hvf["permissions"]
        .as_hash()
        .expect("hvf-kernel job permissions");
    assert_eq!(
        hvf_perms.len(),
        2,
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

    // #2347: hvf-kernel uploads the binary signed acceptance built, before the
    // long embedded tests; the nightly scoreboard is its own job with its own
    // budget, scoring that binary whether or not the embedded tests pass.
    let kernel_steps = hvf["steps"].as_vec().expect("hvf-kernel steps");
    let (receipt_idx, _) = step_by_name(kernel_steps, "Signed acceptance receipt");
    let (binary_idx, binary_step) = step_by_name(
        kernel_steps,
        "Upload the signed binary for the nightly scoreboard",
    );
    let (embed_idx, _) = step_by_name(kernel_steps, "Signed embedded guest tests");
    assert!(
        receipt_idx < binary_idx && binary_idx < embed_idx,
        "the binary uploads after acceptance ({receipt_idx}) and before the embedded tests ({embed_idx}): {binary_idx}"
    );
    assert_nightly_or_owner_dispatch_guard("binary upload", binary_step);
    assert_eq!(
        binary_step["with"]["path"].as_str(),
        Some("target/release/carrick")
    );

    let sb = &workflow["jobs"]["hvf-scoreboard-nightly"];
    assert_nightly_or_owner_dispatch_guard("hvf-scoreboard-nightly", sb);
    let needs: Vec<&str> = sb["needs"]
        .as_vec()
        .expect("hvf-scoreboard-nightly needs")
        .iter()
        .filter_map(Yaml::as_str)
        .collect();
    assert_eq!(needs, ["hvf-kernel"]);
    assert!(
        sb["timeout-minutes"].as_i64().is_some_and(|t| t >= 60 + 10),
        "the scoreboard job's budget covers the 60-min lease wait plus its run"
    );
    let sb_perms = sb["permissions"]
        .as_hash()
        .expect("scoreboard job permissions");
    assert_eq!(sb_perms.len(), 2, "unexpected permissions: {sb_perms:?}");
    let steps = sb["steps"].as_vec().expect("hvf-scoreboard-nightly steps");
    let (download_idx, download) = step_by_name(steps, "Download the signed binary");
    assert_eq!(download["with"]["name"], binary_step["with"]["name"]);
    let (verify_idx, _) = step_by_name(steps, "Verify the signed binary");

    let (run_idx, run_step) = step_by_name(steps, RUN_STEP_NAME);
    let (upload_idx, upload_step) = step_by_name(steps, UPLOAD_STEP_NAME);
    assert!(
        download_idx < verify_idx && verify_idx < run_idx && run_idx < upload_idx,
        "expected step order: download ({download_idx}) < verify ({verify_idx}) < run ({run_idx}) < upload ({upload_idx})"
    );

    // Every step in the workflow that touches scoreboard is one of the known ones.
    for (job_id, job) in jobs {
        let id = job_id.as_str().expect("job id");
        for (idx, step) in job["steps"].as_vec().into_iter().flatten().enumerate() {
            let mut strings = Vec::new();
            collect_yaml_strings(step, &mut strings);
            if strings.iter().any(|s| s.contains("scoreboard")) {
                // The owner's branch scoreboard lives in its own three jobs,
                // the trusted-hardware aggregate requires their results, and
                // the x86 block and the poster are their own jobs (#2327).
                if [
                    "scoreboard-target",
                    "hvf-scoreboard",
                    "scoreboard-publish",
                    "trusted-hardware-ok",
                    "kvm-scoreboard",
                    "scoreboard-post",
                    "hvf-scoreboard-nightly",
                ]
                .contains(&id)
                {
                    continue;
                }
                assert_eq!(id, "hvf-kernel", "unexpected scoreboard step in job {id}");
                assert_eq!(
                    idx,
                    binary_idx,
                    "unexpected scoreboard reference in hvf-kernel step index {idx}: {:?}",
                    step["name"].as_str()
                );
            }
        }
    }

    // Run step contract.
    let run_script = run_step["run"].as_str().expect("scoreboard run script");
    assert!(
        squash_ws(run_script).contains("scoreboard --carrick target/release/carrick"),
        "run step must pass `--carrick target/release/carrick`: {run_script}"
    );
    assert!(
        run_script.contains("--sha \"$GITHUB_SHA\"")
            && run_script.contains("--out target/scoreboard/receipt.json"),
        "run step must pass `--sha \"$GITHUB_SHA\"` and `--out target/scoreboard/receipt.json`: {run_script}"
    );
    assert_scoring_script_discipline(
        "hvf-scoreboard-nightly run step",
        run_script,
        "target/scoreboard/table.txt",
    );

    // Upload step contract: the poster downloads this exact name.
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

    // Both steps share the explicit event guard and `continue-on-error: true`,
    // and neither references a token.
    for (label, step) in [(RUN_STEP_NAME, run_step), (UPLOAD_STEP_NAME, upload_step)] {
        assert_nightly_or_owner_dispatch_guard(label, step);
        assert_eq!(
            step["continue-on-error"].as_bool(),
            Some(true),
            "{label}: must set `continue-on-error: true`"
        );
        assert_no_token(label, step);
    }
}

/// A scoring script holds the gate lease, stamps a run id, tees its table and never pipes its output away.
fn assert_scoring_script_discipline(label: &str, script: &str, table: &str) {
    assert!(
        script.contains("just lease gate"),
        "{label} must hold `just lease gate`: {script}"
    );
    assert!(
        script.contains("CARRICK_RUN_ID"),
        "{label} must stamp `CARRICK_RUN_ID`: {script}"
    );
    assert!(
        script.contains(&format!("tee {table}")),
        "{label} must tee stdout to `{table}`: {script}"
    );
    for forbidden_pipe in ["| tail", "| grep", "| head"] {
        assert!(
            !script.contains(forbidden_pipe),
            "{label} must not pipe output through `{forbidden_pipe}`: {script}"
        );
    }
}

fn assert_no_token(label: &str, node: &Yaml) {
    let mut all_strings = Vec::new();
    collect_yaml_strings(node, &mut all_strings);
    for needle in ["GH_TOKEN", "GITHUB_TOKEN", "github.token", "secrets."] {
        assert!(
            all_strings.iter().all(|s| !s.contains(needle)),
            "{label} must not reference `{needle}`: {all_strings:?}"
        );
    }
}

/// #2327: the x86 block is scored on the KVM lane by the same runner, for the
/// same events, with no write token.
#[test]
fn kvm_scoreboard_scores_x86_on_the_kvm_lane_with_no_write_token() {
    let workflow = load_kernel_runtime_workflow();
    let job = &workflow["jobs"]["kvm-scoreboard"];
    assert_nightly_or_owner_dispatch_guard("kvm-scoreboard", job);
    let labels: Vec<&str> = job["runs-on"]
        .as_vec()
        .expect("kvm-scoreboard runs-on")
        .iter()
        .filter_map(Yaml::as_str)
        .collect();
    assert_eq!(labels, ["self-hosted", "Linux", "X64", "willow-kvm"]);
    assert_eq!(job["continue-on-error"].as_bool(), Some(true));
    let perms = job["permissions"]
        .as_hash()
        .expect("kvm-scoreboard permissions");
    assert_eq!(perms.len(), 1, "unexpected permissions: {perms:?}");
    assert_eq!(
        perms.get(&Yaml::from_str("contents")),
        Some(&Yaml::from_str("read"))
    );
    assert_no_token("kvm-scoreboard", job);
    let steps = job["steps"].as_vec().expect("kvm-scoreboard steps");
    let (build_idx, build) =
        step_by_name(steps, "Build carrick (platform-linux) and carrick-xtask");
    let (run_idx, run) = step_by_name(steps, "Goal scoreboard (x86 KVM)");
    let (upload_idx, upload) = step_by_name(steps, "Upload x86 scoreboard receipt");
    assert!(build_idx < run_idx && run_idx < upload_idx);
    let build_script = build["run"].as_str().expect("build script");
    assert!(
        build_script.lines().any(|l| l.trim() == "just build"),
        "{build_script}"
    );
    let script = run["run"].as_str().expect("x86 scoreboard script");
    let squashed = squash_ws(script);
    for needle in [
        "carrick-xtask scoreboard --isa x86_64",
        "--carrick target/release/carrick",
        "--sha \"$GITHUB_SHA\"",
        "--out target/scoreboard-x86/receipt.json",
    ] {
        assert!(
            squashed.contains(needle),
            "x86 scoreboard must pass `{needle}`: {script}"
        );
    }
    assert_scoring_script_discipline("kvm-scoreboard", script, "target/scoreboard-x86/table.txt");
    assert_eq!(
        upload["with"]["name"].as_str(),
        Some("scoreboard-x86-${{ github.sha }}-${{ github.run_attempt }}")
    );
    assert_eq!(
        upload["with"]["path"].as_str(),
        Some("target/scoreboard-x86/")
    );
}

/// #2327: one #231 comment carries both ISAs; the poster runs no repository code.
#[test]
fn scoreboard_post_publishes_both_isas_and_runs_no_repository_code() {
    let workflow = load_kernel_runtime_workflow();
    let job = &workflow["jobs"]["scoreboard-post"];
    assert_nightly_or_owner_dispatch_guard("scoreboard-post", job);
    let needs: Vec<&str> = job["needs"]
        .as_vec()
        .expect("scoreboard-post needs")
        .iter()
        .filter_map(Yaml::as_str)
        .collect();
    assert_eq!(needs, ["hvf-scoreboard-nightly", "kvm-scoreboard"]);
    assert_eq!(job["runs-on"].as_str(), Some("ubuntu-latest"));
    let perms = job["permissions"]
        .as_hash()
        .expect("scoreboard-post permissions");
    assert_eq!(perms.len(), 3, "unexpected permissions: {perms:?}");
    assert_eq!(
        perms.get(&Yaml::from_str("issues")),
        Some(&Yaml::from_str("write"))
    );
    let steps = job["steps"].as_vec().expect("scoreboard-post steps");
    for step in steps {
        if let Some(uses) = step["uses"].as_str() {
            assert_eq!(
                uses, "actions/download-artifact@v4",
                "the poster runs no repository code and no other action"
            );
        }
    }
    let (_, arm) = step_by_name(steps, "Download the arm64 scoreboard");
    let (_, x86) = step_by_name(steps, "Download the x86_64 scoreboard");
    assert_eq!(
        arm["with"]["name"].as_str(),
        Some("scoreboard-${{ github.sha }}-${{ github.run_attempt }}")
    );
    assert_eq!(
        x86["with"]["name"].as_str(),
        Some("scoreboard-x86-${{ github.sha }}-${{ github.run_attempt }}")
    );
    let (_, post) = step_by_name(steps, POST_STEP_NAME);
    let env = post["env"].as_hash().expect("post env");
    let mut keys: Vec<&str> = env.keys().filter_map(Yaml::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["GH_TOKEN", "HVF_RESULT", "KVM_RESULT"]);
    assert_eq!(
        post["env"]["GH_TOKEN"].as_str(),
        Some("${{ github.token }}")
    );
    let script = post["run"].as_str().expect("post script");
    assert!(
        !script.contains("GH_TOKEN")
            && !script.contains("github.token")
            && !script.contains("secrets."),
        "post script must never reference or echo the token: {script}"
    );
}

#[test]
fn scoreboard_workflow_scripts_execute_expected_run_and_post_paths() {
    let workflow = load_kernel_runtime_workflow();
    let steps = workflow["jobs"]["hvf-scoreboard-nightly"]["steps"]
        .as_vec()
        .expect("hvf-scoreboard-nightly steps");
    let (_, run_step) = step_by_name(steps, RUN_STEP_NAME);
    let run_script = run_step["run"].as_str().expect("run script");
    let post_steps = workflow["jobs"]["scoreboard-post"]["steps"]
        .as_vec()
        .expect("scoreboard-post steps");
    let (_, post_step) = step_by_name(post_steps, POST_STEP_NAME);
    let post_script = post_step["run"].as_str().expect("post script");

    let dir = tempfile::tempdir().expect("tempdir");
    let bin = dir.path().join("bin");
    let ws = dir.path().join("ws");
    let temp = dir.path().join("runner-temp");
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
         printf 'main 0123456789  sha256=deadbeef  isa=arm64\\narm64   py-version       exit=0    3.12.7 ($GH_TOKEN)\\n'\n",
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
         cp \"$RUNNER_TEMP/scoreboard/comment.md\" \"$GH_BODY_OUT\"\n",
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

    // 1. Run step executes xtask scoreboard under `just lease gate` and tees table.txt.
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
    assert!(table_txt.contains("arm64   py-version       exit=0    3.12.7 ($GH_TOKEN)"));

    let post = |hvf: &str, kvm: &str| {
        let _ = fs::remove_file(&gh_args_out);
        Command::new("bash")
            .args(["-c", post_script])
            .current_dir(&ws)
            .env("PATH", &path_env)
            .env("GH_TOKEN", "canary-secret-token-value")
            .env("HVF_RESULT", hvf)
            .env("KVM_RESULT", kvm)
            .env("RUNNER_TEMP", &temp)
            .env("GITHUB_STEP_SUMMARY", dir.path().join("summary.md"))
            .env("GITHUB_SHA", sha)
            .env("GITHUB_SERVER_URL", "https://github.com")
            .env("GITHUB_REPOSITORY", "carrick-sh/carrick")
            .env("GITHUB_RUN_ID", "424242")
            .env("GH_ARGS_OUT", &gh_args_out)
            .env("GH_BODY_OUT", &gh_body_out)
            .output()
            .expect("run post_script")
    };

    // 2. Both ISAs' tables (downloaded artifacts): one comment with both blocks.
    for (isa, table) in [
        ("arm64", table_txt.as_str()),
        (
            "x86_64",
            "main 0123456789  sha256=feedface  isa=x86_64\nx86_64  py-thread        exit=139  \n",
        ),
    ] {
        let d = temp.join("scoreboard").join(isa);
        fs::create_dir_all(&d).expect("mkdir artifact");
        fs::write(d.join("table.txt"), table).expect("write table");
    }
    // The x86 receipt carries a failing row's key stderr line (#2327: exit code and key stderr per row).
    fs::write(
        temp.join("scoreboard/x86_64/receipt.json"),
        r#"{"rows":[{"name":"py-version","passed":true,"key_stderr_line":"carrick: image pulling"},{"name":"py-fork","passed":false,"key_stderr_line":""},{"name":"py-thread","passed":false,"key_stderr_line":"carrick: guest killed by SIGSEGV $(echo injected)"}]}"#,
    )
    .expect("write x86 receipt");
    let ok_post = post("success", "success");
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
    let body_file = temp.join("scoreboard/comment.md");
    assert_eq!(
        gh_args,
        vec![
            "issue".to_owned(),
            "comment".to_owned(),
            "231".to_owned(),
            "--repo".to_owned(),
            "carrick-sh/carrick".to_owned(),
            "--body-file".to_owned(),
            body_file.display().to_string(),
        ]
    );
    let body = fs::read_to_string(&gh_body_out).expect("comment body");
    assert!(body.starts_with("### Goal scoreboard (nightly)"), "{body}");
    assert!(body.contains(sha), "comment missing full SHA: {body}");
    assert!(
        body.contains("https://github.com/carrick-sh/carrick/actions/runs/424242"),
        "comment missing run URL: {body}"
    );
    let arm_at = body.find("#### arm64 (HVF)").expect("arm64 block");
    let x86_at = body.find("#### x86_64 (KVM)").expect("x86_64 block");
    assert!(arm_at < x86_at, "arm64 block first: {body}");
    assert!(
        body.contains("arm64   py-version       exit=0    3.12.7 ($GH_TOKEN)"),
        "{body}"
    );
    assert!(body.contains("x86_64  py-thread        exit=139"), "{body}");
    assert!(
        body.contains(
            "```stderr\npy-thread: carrick: guest killed by SIGSEGV $(echo injected)\n```"
        ),
        "the x86 block lists the failing row's key stderr, verbatim and unexpanded: {body}"
    );
    assert!(
        !body.contains("py-version: "),
        "rows without stderr are not listed: {body}"
    );
    assert!(
        !body.contains("canary-secret-token-value")
            && !String::from_utf8_lossy(&ok_post.stdout).contains("canary-secret-token-value")
            && !String::from_utf8_lossy(&ok_post.stderr).contains("canary-secret-token-value"),
        "GH_TOKEN leaked into output or comment body"
    );

    // 3. A lane with no table is reported missing with its job result, not dropped.
    fs::remove_dir_all(temp.join("scoreboard/x86_64")).expect("remove x86 artifact");
    let partial = post("success", "failure");
    assert!(
        partial.status.success(),
        "{}",
        String::from_utf8_lossy(&partial.stderr)
    );
    let body = fs::read_to_string(&gh_body_out).expect("comment body");
    assert!(
        body.contains("missing: no x86_64 scoreboard table (job result: failure)"),
        "{body}"
    );
    assert!(body.contains("arm64   py-version"), "{body}");

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

/// The branch scoreboard splits building from posting: `hvf-scoreboard`
/// builds and scores an owner-named branch head with a read-only token,
/// and only `scoreboard-publish`, which runs no branch code, may post.
/// Both run only on the owner's `workflow_dispatch` on main.
fn assert_scoreboard_branch_jobs_isolate_the_token(jobs: &yaml_rust2::yaml::Hash) {
    let job = |id: &str| &jobs[&Yaml::from_str(id)];
    for id in ["hvf-scoreboard", "scoreboard-publish"] {
        let guard = squash_ws(job(id)["if"].as_str().unwrap_or(""));
        assert!(
            guard.contains("github.event_name == 'workflow_dispatch'")
                && guard.contains("github.ref == 'refs/heads/main'")
                && guard.contains("github.actor == 'tjfontaine'")
                && guard.contains("github.triggering_actor == 'tjfontaine'"),
            "{id}: `if` must restrict to the owner's workflow_dispatch on main: {guard}"
        );
        assert!(
            !guard.contains("'push'")
                && !guard.contains("pull_request")
                && !guard.contains("'schedule'"),
            "{id}: `if` must never allow push, pull_request or schedule: {guard}"
        );
    }
    let scorer = job("hvf-scoreboard")["permissions"]
        .as_hash()
        .expect("hvf-scoreboard has explicit permissions");
    for (scope, level) in scorer {
        assert_ne!(
            level.as_str(),
            Some("write"),
            "hvf-scoreboard runs branch code and must hold no write scope ({scope:?})"
        );
    }
}
