//! Actions plumbing for the signed lane. Only the authorized execution job runs PR code.
use crate::accept::{
    AcceptReceipt, ArtifactIdentity, CleanupCount, inspect_artifact, parse_cleanup_count,
};
use crate::ci_receipt::{ReceiptError, load};
use crate::ci_scaler::REPOSITORY;
use crate::command::run_checked;
use crate::host_lease::{HostLease, HostLeaseMode};
use crate::signed_receipt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const WORKFLOW: &str = ".github/workflows/signed-gate.yml";
// Only the owner may request a signed gate. The carrick-workers App is held
// by agents and worker VMs; admitting it would let agent-written code run on a
// gate runner at the agent's own request (#654).
const OWNER: &str = "tjfontaine";
const STEPS: &[&str] = &[
    "fixtures",
    "build",
    "el1-embed",
    "fresh-executable-page",
    "generic-probe-shards",
    "probe-cases",
];

#[derive(clap::Args, Debug)]
pub struct SignedGateArgs {
    #[command(subcommand)]
    pub action: SignedGateAction,
}
#[derive(clap::Subcommand, Debug)]
pub enum SignedGateAction {
    /// Authorize an Actions event and download the exact merge-base baseline.
    Prepare {
        #[arg(long)]
        event: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Run on macOS in a new detached worktree, under the exclusive host lease.
    Execute {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Runner-provisioned immutable archive; restore checks fixture input identity.
        #[arg(long, env = "CARRICK_SIGNED_FIXTURE_BUNDLE")]
        fixture_bundle: PathBuf,
    },
    /// Compare on a hosted runner and publish a PR comment and commit status.
    Publish {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        results: PathBuf,
        #[arg(long)]
        run_url: String,
        #[arg(long)]
        execution_result: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub pr: Option<u64>,
    pub sha: String,
    pub base: String,
    pub baseline_run: Option<u64>,
}
fn fail(message: impl Into<String>) -> ReceiptError {
    ReceiptError::Baseline(message.into())
}
fn checked(program: &str, args: &[&str], cwd: Option<&Path>) -> Result<String, ReceiptError> {
    run_checked(program, args, cwd)
        .map(|o| o.stdout)
        .map_err(|e| fail(e.to_string()))
}
fn read_json(path: &Path) -> Result<Value, ReceiptError> {
    let bytes = fs::read(path).map_err(|e| fail(format!("{}: {e}", path.display())))?;
    serde_json::from_slice(&bytes).map_err(|e| fail(e.to_string()))
}
fn write(path: &Path, data: impl AsRef<[u8]>) -> Result<(), ReceiptError> {
    fs::write(path, data).map_err(|e| fail(format!("{}: {e}", path.display())))
}
fn api(endpoint: &str) -> Result<Value, ReceiptError> {
    let text = checked("gh", &["api", "--method", "GET", endpoint], None)?;
    serde_json::from_str(&text).map_err(|e| fail(e.to_string()))
}
fn pages(endpoint: &str, field: Option<&str>) -> Result<Vec<Value>, ReceiptError> {
    let text = checked("gh", &["api", "--paginate", "--slurp", endpoint], None)?;
    let pages: Vec<Value> = serde_json::from_str(&text).map_err(|e| fail(e.to_string()))?;
    let mut result = Vec::new();
    for page in pages {
        let rows = field
            .map_or(&page, |key| &page[key])
            .as_array()
            .ok_or_else(|| fail("incomplete API listing"))?;
        result.extend(rows.iter().cloned());
    }
    Ok(result)
}
fn post(endpoint: &str, body: Value) -> Result<(), ReceiptError> {
    use std::io::Write;
    let mut child = Command::new("gh")
        .args(["api", "--method", "POST", endpoint, "--input", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| fail(e.to_string()))?;
    let bytes = serde_json::to_vec(&body).map_err(|e| fail(e.to_string()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| fail("gh stdin missing"))?
        .write_all(&bytes)
        .map_err(|e| fail(e.to_string()))?;
    let status = child.wait().map_err(|e| fail(e.to_string()))?;
    if !status.success() {
        return Err(fail(format!("gh POST {endpoint}: {status}")));
    }
    Ok(())
}

pub fn allowed(actor: &str) -> bool {
    actor == OWNER
}
fn sha(value: &str) -> Result<String, ReceiptError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(fail("sha must be a full lowercase 40-character commit SHA"));
    }
    Ok(value.into())
}

/// Label authorization uses the API's most recent label transition, not a PR author's labels.
pub fn label_authorized(events: &[Value], sender: &str) -> bool {
    events
        .iter()
        .filter(|e| {
            e["label"]["name"] == "gate:signed"
                && (e["event"] == "labeled" || e["event"] == "unlabeled")
        })
        .max_by_key(|e| e["id"].as_u64().unwrap_or(0))
        .is_some_and(|e| {
            e["event"] == "labeled" && e["actor"]["login"] == sender && allowed(sender)
        })
}
fn prepare(event_path: &Path, output: &Path) -> Result<(), ReceiptError> {
    let event = read_json(event_path)?;
    let actor = std::env::var("GITHUB_ACTOR").map_err(|e| fail(e.to_string()))?;
    let triggering = std::env::var("GITHUB_TRIGGERING_ACTOR").unwrap_or_else(|_| actor.clone());
    if !allowed(&actor) || !allowed(&triggering) || event["repository"]["full_name"] != REPOSITORY {
        return Err(fail(
            "only the owner (tjfontaine) may start or rerun signed gates",
        ));
    }
    let event_name = std::env::var("GITHUB_EVENT_NAME").map_err(|e| fail(e.to_string()))?;
    let (pr, requested_sha) = match event_name.as_str() {
        "workflow_dispatch" => {
            if std::env::var("GITHUB_REF").unwrap_or_default() != "refs/heads/main" {
                return Err(fail("dispatch the trusted workflow from main"));
            }
            let input = event["inputs"]["pr"].as_str().unwrap_or_default();
            let pr = if input == "main" {
                None
            } else {
                Some(
                    input
                        .parse::<u64>()
                        .map_err(|_| fail("pr must be a PR number or main"))?,
                )
            };
            (
                pr,
                sha(event["inputs"]["sha"].as_str().unwrap_or_default())?,
            )
        }
        "pull_request_target" => {
            if event["action"] != "labeled"
                || event["label"]["name"] != "gate:signed"
                || event["sender"]["login"] != actor
            {
                return Err(fail("not an authorized gate:signed label event"));
            }
            let pr = event["number"]
                .as_u64()
                .ok_or_else(|| fail("missing PR number"))?;
            let events = pages(
                &format!("repos/{REPOSITORY}/issues/{pr}/events?per_page=100"),
                None,
            )?;
            if !label_authorized(&events, &actor) {
                return Err(fail(
                    "latest gate:signed label transition was not applied by the authorized event actor",
                ));
            }
            (
                Some(pr),
                sha(event["pull_request"]["head"]["sha"]
                    .as_str()
                    .unwrap_or_default())?,
            )
        }
        _ => return Err(fail("unsupported trigger")),
    };
    if let Some(pr) = pr {
        let pull = api(&format!("repos/{REPOSITORY}/pulls/{pr}"))?;
        if pull["state"] != "open"
            || pull["head"]["sha"] != requested_sha
            || pull["base"]["ref"] != "main"
        {
            return Err(fail(
                "request must name the current head of an open PR targeting main; relabel after a head change",
            ));
        }
    }
    let comparison = api(&format!(
        "repos/{REPOSITORY}/compare/main...{requested_sha}"
    ))?;
    let base = sha(comparison["merge_base_commit"]["sha"]
        .as_str()
        .unwrap_or_default())?;
    if pr.is_none() && base != requested_sha {
        return Err(fail("main baseline SHA must be on main"));
    }
    fs::create_dir_all(output).map_err(|e| fail(e.to_string()))?;
    let mut request = Request {
        pr,
        sha: requested_sha,
        base,
        baseline_run: None,
    };
    if request.pr.is_some() {
        request.baseline_run = Some(download_baseline(&request.base, output)?);
        validate_receipt(&load(&output.join("base.json"))?, &request.base)?;
    }
    write(
        &output.join("request.json"),
        serde_json::to_vec_pretty(&request).map_err(|e| fail(e.to_string()))?,
    )?;
    if let Ok(path) = std::env::var("GITHUB_OUTPUT") {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|e| fail(e.to_string()))?;
        writeln!(
            file,
            "sha={}\nbase={}\nmain={}",
            request.sha,
            request.base,
            request.pr.is_none()
        )
        .map_err(|e| fail(e.to_string()))?;
    }
    Ok(())
}

pub fn trusted_run(run: &Value) -> bool {
    run["path"] == WORKFLOW
        && run["head_branch"] == "main"
        && run["event"] == "workflow_dispatch"
        && run["status"] == "completed"
        && run["repository"]["full_name"] == REPOSITORY
        && run["head_repository"]["full_name"] == REPOSITORY
        && run["actor"]["login"].as_str().is_some_and(allowed)
        && run["triggering_actor"]["login"]
            .as_str()
            .is_some_and(allowed)
}
fn download_baseline(base: &str, output: &Path) -> Result<u64, ReceiptError> {
    let mut runs = pages(
        &format!(
            "repos/{REPOSITORY}/actions/workflows/signed-gate.yml/runs?event=workflow_dispatch&branch=main&per_page=100"
        ),
        Some("workflow_runs"),
    )?;
    runs.sort_by_key(|r| std::cmp::Reverse(r["id"].as_u64().unwrap_or(0)));
    let prefix = format!("signed-baseline-{base}-");
    for run in runs.iter().filter(|r| trusted_run(r)) {
        let id = run["id"].as_u64().ok_or_else(|| fail("missing run ID"))?;
        let artifacts = pages(
            &format!("repos/{REPOSITORY}/actions/runs/{id}/artifacts?per_page=100"),
            Some("artifacts"),
        )?;
        let artifact = artifacts
            .iter()
            .filter(|a| a["expired"] == false)
            .filter_map(|a| {
                let name = a["name"].as_str()?;
                let attempt = name.strip_prefix(&prefix)?.parse::<u64>().ok()?;
                Some((attempt, name))
            })
            .max();
        if let Some((_, name)) = artifact {
            let dir = tempfile::tempdir().map_err(|e| fail(e.to_string()))?;
            checked(
                "gh",
                &[
                    "run",
                    "download",
                    &id.to_string(),
                    "--repo",
                    REPOSITORY,
                    "--name",
                    name,
                    "--dir",
                    &dir.path().to_string_lossy(),
                ],
                None,
            )?;
            fs::copy(dir.path().join("candidate.json"), output.join("base.json"))
                .map_err(|e| fail(e.to_string()))?;
            return Ok(id);
        }
    }
    Err(fail(format!(
        "no signed baseline for merge-base {base}; dispatch signed-gate.yml on main with pr=main and sha={base}, then rerun this request"
    )))
}

/// An empty, truncated or unsigned receipt can never seed a baseline or stand for a gate.
pub fn validate_receipt(receipt: &AcceptReceipt, expected: &str) -> Result<(), ReceiptError> {
    if receipt.head != expected
        || receipt.phase != "signed"
        || receipt.profile != "no-docker"
        || !receipt.clean_tree
        || !receipt.skipped_steps.is_empty()
    {
        return Err(fail(
            "receipt SHA, phase, profile or checkout admission mismatch",
        ));
    }
    let identity = receipt
        .artifact
        .as_ref()
        .ok_or_else(|| fail("missing signed artifact identity"))?;
    if identity.sha256.len() != 64
        || identity.cdhash.is_empty()
        || identity.lc_uuid.is_empty()
        || identity.lc_uuid == "unknown"
        || !identity.hypervisor_entitlement
        || !identity.dof_present
    {
        return Err(fail("incomplete signed artifact identity"));
    }
    if receipt.fixture_validation.is_none() || receipt.el1.is_none() {
        return Err(fail("missing fixture validation or EL1 comparison"));
    }
    for name in STEPS {
        let matches: Vec<_> = receipt.steps.iter().filter(|s| s.name == *name).collect();
        if matches.len() != 1 {
            return Err(fail(format!("expected exactly one {name} step")));
        }
        let step = matches[0];
        if *name == "fixtures" || *name == "build" {
            if !step.passed {
                return Err(fail(format!("{name} failed")));
            }
        } else {
            if step.started_tests.is_empty() || step.finished_binaries.is_empty() {
                return Err(fail(format!("{name} has no test/completion population")));
            }
        }
        if *name != "fixtures"
            && !receipt
                .cleanup_counts
                .iter()
                .any(|c| c.step == *name && c.remaining_count == 0)
        {
            return Err(fail(format!("missing scoped cleanup for {name}")));
        }
    }
    if receipt
        .cleanup_counts
        .iter()
        .any(|c| c.remaining_count != 0)
    {
        return Err(fail("scoped cleanup left processes alive"));
    }
    Ok(())
}

fn logged(command: &mut Command, lease: &HostLease, log: &Path) -> Result<bool, ReceiptError> {
    let stdout = fs::File::create(log).map_err(|e| fail(e.to_string()))?;
    let stderr = stdout.try_clone().map_err(|e| fail(e.to_string()))?;
    lease
        .configure_command(command)
        .map_err(|e| fail(e.to_string()))?;
    let status = command
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .status()
        .map_err(|e| fail(e.to_string()))?;
    Ok(status.success())
}
fn execute(
    root: &Path,
    request_path: &Path,
    output: &Path,
    bundle: &Path,
) -> Result<(), ReceiptError> {
    if std::env::consts::OS != "macos" || std::env::consts::ARCH != "aarch64" {
        return Err(fail("requires macOS ARM64"));
    }
    let request: Request =
        serde_json::from_value(read_json(request_path)?).map_err(|e| fail(e.to_string()))?;
    sha(&request.sha)?;
    fs::create_dir_all(output).map_err(|e| fail(e.to_string()))?;
    let output = fs::canonicalize(output).map_err(|e| fail(e.to_string()))?;
    let bundle = fs::canonicalize(bundle).map_err(|e| fail(e.to_string()))?;
    checked(
        "git",
        &["fetch", "--no-tags", "origin", &request.sha],
        Some(root),
    )?;
    let temp = tempfile::tempdir().map_err(|e| fail(e.to_string()))?;
    let tree = temp.path().join("checkout");
    checked(
        "git",
        &[
            "worktree",
            "add",
            "--detach",
            &tree.to_string_lossy(),
            &request.sha,
        ],
        Some(root),
    )?;
    // macOS TMPDIR may use /var while git reports /private/var. Use the
    // repository's physical path for exact artifact-path comparisons.
    let tree = fs::canonicalize(&tree).map_err(|e| fail(e.to_string()))?;
    let result = (|| {
        crate::host_load::check().map_err(|e| fail(e.to_string()))?;
        let lease = HostLease::acquire(HostLeaseMode::Gate).map_err(|e| fail(e.to_string()))?;
        let xtask = std::env::current_exe().map_err(|e| fail(e.to_string()))?;
        let mut fetch = Command::new(&xtask);
        fetch
            .current_dir(&tree)
            .args(["--root", &tree.to_string_lossy(), "fixtures", "fetch"]);
        if !logged(&mut fetch, &lease, &output.join("fixture-fetch.log"))? {
            return Err(fail("fixture dependency fetch failed"));
        }
        let mut restore = Command::new(&xtask);
        restore.current_dir(&tree).args([
            "--root",
            &tree.to_string_lossy(),
            "fixtures",
            "restore",
            "--bundle",
            &bundle.to_string_lossy(),
        ]);
        if !logged(&mut restore, &lease, &output.join("fixture-restore.log"))? {
            return Err(fail(
                "fixture restore failed; provision a bundle matching this SHA's fixture input identity",
            ));
        }
        let mut build = Command::new("just");
        build.current_dir(&tree).arg("build");
        if !logged(&mut build, &lease, &output.join("build.log"))? {
            return Err(fail("just build failed"));
        }
        let mut accept = Command::new("cargo");
        accept.current_dir(&tree).args([
            "run",
            "--locked",
            "-p",
            "carrick-xtask",
            "--",
            "accept",
            "--profile",
            "no-docker",
            "--phase",
            "signed",
            "--receipt",
            &output.join("candidate.json").to_string_lossy(),
        ]);
        let accepted = logged(&mut accept, &lease, &output.join("accept.log"))?;
        write(
            &output.join("accept-exit.json"),
            json!({"success": accepted}).to_string(),
        )?;
        // accept rebuilds once under the same lease before testing. Its receipt
        // names that artifact; inspect it independently before releasing the lease.
        let receipt = load(&output.join("candidate.json"))?;
        // Older accept receipts encode an unknown reap as remaining_count=0
        // plus human diagnostics. Prove cleanup again without parsing those
        // diagnostics or allowing them to disappear behind known test failures.
        for (index, count) in receipt.cleanup_counts.iter().enumerate() {
            let log = output.join(format!("cleanup-{index}.log"));
            let mut reap = Command::new(tree.join("scripts/sudo/kill.sh"));
            reap.current_dir(&tree).arg(&count.run_id);
            if !logged(&mut reap, &lease, &log)?
                || parse_cleanup_count(&fs::read_to_string(&log).map_err(|e| fail(e.to_string()))?)
                    != Some(0)
            {
                return Err(fail(format!(
                    "independent scoped cleanup failed for {}",
                    count.step
                )));
            }
        }
        write(
            &output.join("cleanup.json"),
            serde_json::to_vec_pretty(&receipt.cleanup_counts).map_err(|e| fail(e.to_string()))?,
        )?;
        let identity = inspect_artifact(&tree).map_err(fail)?;
        if receipt.artifact.as_ref() != Some(&identity) {
            return Err(fail("post-gate artifact identity differs from the receipt"));
        }
        write(
            &output.join("identity.json"),
            serde_json::to_vec_pretty(&identity).map_err(|e| fail(e.to_string()))?,
        )?;
        validate_receipt(&receipt, &request.sha)
    })();
    // Preserve logs even on errors before dropping the detached worktree.
    let logs = tree.join("target/el1-gate");
    let log_copy = if logs.exists() {
        checked(
            "cp",
            &[
                "-R",
                &logs.to_string_lossy(),
                &output.join("steps").to_string_lossy(),
            ],
            None,
        )
        .map(|_| ())
    } else {
        Ok(())
    };
    let cleanup = checked(
        "git",
        &["worktree", "remove", "--force", &tree.to_string_lossy()],
        Some(root),
    );
    if let Err(error) = &result {
        write(&output.join("execution-error.txt"), error.to_string())?;
    }
    result?;
    log_copy?;
    cleanup?;
    Ok(())
}

fn publish(
    request_path: &Path,
    results: &Path,
    run_url: &str,
    execution_result: &str,
) -> Result<(), ReceiptError> {
    let request: Request =
        serde_json::from_value(read_json(request_path)?).map_err(|e| fail(e.to_string()))?;
    let comparison = (|| {
        let candidate = load(&results.join("candidate.json"))?;
        let base = if request.pr.is_none() {
            candidate.clone()
        } else {
            load(&request_path.with_file_name("base.json"))?
        };
        validate_receipt(&base, &request.base)?;
        let diff = signed_receipt::compare(&base, &candidate)?;
        write(
            &results.join("diff.json"),
            serde_json::to_vec_pretty(&diff).map_err(|e| fail(e.to_string()))?,
        )?;
        let mut body = diff.markdown();
        let valid = validate_receipt(&candidate, &request.sha);
        if let Err(error) = &valid {
            body.push_str(&format!("\nReceipt admission failed: {error}\n"));
        }
        let identity: Result<ArtifactIdentity, ReceiptError> =
            read_json(&results.join("identity.json"))
                .and_then(|value| serde_json::from_value(value).map_err(|e| fail(e.to_string())))
                .and_then(|identity| {
                    if candidate.artifact.as_ref() == Some(&identity) {
                        Ok(identity)
                    } else {
                        Err(fail(
                            "independent artifact identity does not match candidate receipt",
                        ))
                    }
                });
        if let Err(error) = &identity {
            body.push_str(&format!("\nIdentity admission failed: {error}\n"));
        }
        if let Ok(identity) = &identity {
            body.push_str(&format!(
                "\nArtifact identity:\n```json\n{}\n```\n",
                serde_json::to_string_pretty(identity).map_err(|e| fail(e.to_string()))?
            ));
        }
        let cleanup: Result<Vec<CleanupCount>, ReceiptError> =
            read_json(&results.join("cleanup.json"))
                .and_then(|value| serde_json::from_value(value).map_err(|e| fail(e.to_string())))
                .and_then(|counts| {
                    if counts == candidate.cleanup_counts {
                        Ok(counts)
                    } else {
                        Err(fail("independent cleanup evidence differs from receipt"))
                    }
                });
        if let Err(error) = &cleanup {
            body.push_str(&format!("\nCleanup admission failed: {error}\n"));
        }
        let passed = diff.passed
            && valid.is_ok()
            && identity.is_ok()
            && cleanup.is_ok()
            && execution_result == "success";
        Ok::<_, ReceiptError>((passed, body))
    })();
    let (passed, mut body) = match comparison {
        Ok(result) => result,
        Err(error) => (
            false,
            format!(
                "Signed gate: **FAIL**\n\nCandidate `{}`; base `{}`\n\nNo valid comparison: {error}\n",
                request.sha, request.base
            ),
        ),
    };
    if !passed && !body.starts_with("Signed gate: **FAIL**") {
        body.insert_str(
            0,
            "Signed gate: **FAIL** (receipt or execution admission)\n\n",
        );
    }
    if let Ok(error) = fs::read_to_string(results.join("execution-error.txt")) {
        body.push_str(&format!("\nExecution diagnostic: {error}\n"));
    }
    body.push_str(&format!(
        "\nExecution job: `{execution_result}`. [Receipts and logs]({run_url}).\n"
    ));
    write(&results.join("comment.md"), &body)?;
    println!("{body}");
    // Status is written even if comment publication fails.
    let status = post(
        &format!("repos/{REPOSITORY}/statuses/{}", request.sha),
        json!({"state": if passed {"success"} else {"failure"}, "context": "signed-gate", "description": if passed {"No new failures; populations and completion preserved"} else {"Signed receipt regression or incomplete gate"}, "target_url": run_url}),
    );
    let comment = if let Some(pr) = request.pr {
        post(
            &format!("repos/{REPOSITORY}/issues/{pr}/comments"),
            json!({"body": body}),
        )
    } else {
        Ok(())
    };
    status?;
    comment?;
    if !passed {
        return Err(fail("signed gate FAIL; see comment and artifacts"));
    }
    Ok(())
}

pub fn run(root: &Path, args: SignedGateArgs) -> Result<(), ReceiptError> {
    match args.action {
        SignedGateAction::Prepare { event, output } => prepare(&event, &output),
        SignedGateAction::Execute {
            request,
            output,
            fixture_bundle,
        } => execute(root, &request, &output, &fixture_bundle),
        SignedGateAction::Publish {
            request,
            results,
            run_url,
            execution_result,
        } => publish(&request, &results, &run_url, &execution_result),
    }
}
