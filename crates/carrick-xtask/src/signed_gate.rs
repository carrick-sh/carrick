//! Actions plumbing for the signed lane. Only the authorized execution job runs PR code.
use crate::accept::{
    AcceptReceipt, ArtifactIdentity, CleanupCount, NO_DOCKER_EXCLUSIONS, inspect_artifact,
    parse_cleanup_count,
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
        /// Same-run exact-SHA archive; admission also checks fixture input identity.
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
    pub kind: RequestKind,
    pub prs: Vec<u64>,
    pub sha: String,
    pub base: String,
    pub baseline_run: Option<u64>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestKind {
    Main,
    PullRequest,
    MergeGroup,
}

/// Automatic authorization is tied to GitHub's event identity, never its actor.
/// Manual requests and label events retain the owner-only policy.
fn automatic_request(
    event: &Value,
    name: &str,
    git_ref: &str,
    head: &str,
) -> Result<(String, String), ReceiptError> {
    if event["repository"]["full_name"] != REPOSITORY {
        return Err(fail("automatic signed gate requires this repository"));
    }
    let (candidate, base) = match name {
        "merge_group"
            if event["action"] == "checks_requested"
                && event["merge_group"]["base_ref"] == "refs/heads/main"
                && git_ref.starts_with("refs/heads/gh-readonly-queue/main/")
                && parse_queue_ref_pr(git_ref).is_some()
                && event["merge_group"]["head_ref"] == git_ref =>
        {
            (
                event["merge_group"]["head_sha"]
                    .as_str()
                    .unwrap_or_default(),
                event["merge_group"]["base_sha"]
                    .as_str()
                    .unwrap_or_default(),
            )
        }
        "push"
            if git_ref == "refs/heads/main"
                && event["ref"] == git_ref
                && event["deleted"] == false =>
        {
            (
                event["after"].as_str().unwrap_or_default(),
                event["after"].as_str().unwrap_or_default(),
            )
        }
        _ => {
            return Err(fail(
                "automatic signed gate must target the main queue or main push",
            ));
        }
    };
    let candidate = sha(candidate)?;
    let base = sha(base)?;
    if candidate != head {
        return Err(fail("event SHA differs from Actions head"));
    }
    Ok((candidate, base))
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
const MERGE_QUEUE_QUERY: &str = "query { repository(owner: \"carrick-sh\", name: \"carrick\") { mergeQueue(branch: \"main\") { entries(first: 100) { nodes { baseCommit { oid } headCommit { oid } pullRequest { number baseRefName baseRepository { nameWithOwner } } } pageInfo { hasNextPage } } } } }";

fn merge_queue_entries() -> Result<Vec<Value>, ReceiptError> {
    let graphql_text = checked(
        "gh",
        &[
            "api",
            "graphql",
            "-f",
            &format!("query={MERGE_QUEUE_QUERY}"),
        ],
        None,
    )?;
    let graphql: Value = serde_json::from_str(&graphql_text).map_err(|e| fail(e.to_string()))?;
    if !graphql["errors"].is_null() {
        return Err(fail("mergeQueue GraphQL query returned errors"));
    }
    let entries = &graphql["data"]["repository"]["mergeQueue"]["entries"];
    let nodes = entries["nodes"]
        .as_array()
        .ok_or_else(|| fail("mergeQueue response is missing entry nodes"))?;
    if entries["pageInfo"]["hasNextPage"]
        .as_bool()
        .ok_or_else(|| fail("mergeQueue response is missing pagination data"))?
    {
        return Err(fail(
            "mergeQueue has more than 100 entries; refusing partial authorization",
        ));
    }
    Ok(nodes.clone())
}

fn live_main_queue_entry(entries: &[Value], sha: &str) -> bool {
    entries.iter().any(|node| {
        node["baseCommit"]["oid"] == sha
            && node["pullRequest"]["baseRefName"] == "main"
            && node["pullRequest"]["baseRepository"]["nameWithOwner"] == REPOSITORY
            && node["pullRequest"]["number"].as_u64().is_some()
    })
}

fn parse_queue_ref_pr(git_ref: &str) -> Option<u64> {
    let rest = git_ref
        .strip_prefix("refs/heads/gh-readonly-queue/main/pr-")
        .or_else(|| git_ref.strip_prefix("gh-readonly-queue/main/pr-"))?;
    let (digits, suffix) = rest.split_once('-')?;
    if digits.is_empty()
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || suffix.is_empty()
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return None;
    }
    digits.parse::<u64>().ok().filter(|&n| n > 0)
}

fn is_ancestor(graph: &Path, ancestor: &str, descendant: &str) -> Result<bool, ReceiptError> {
    let status = Command::new("git")
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .current_dir(graph)
        .status()
        .map_err(|error| fail(error.to_string()))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(fail(format!(
            "git merge-base --is-ancestor failed with {status}"
        ))),
    }
}

fn resolve_merge_group_prs(
    graph: &Path,
    base: &str,
    requested_sha: &str,
    git_ref: &str,
    queue_entries: &[Value],
) -> Result<Vec<u64>, ReceiptError> {
    let rev_list = checked(
        "git",
        &[
            "rev-list",
            "--first-parent",
            "--reverse",
            &format!("{base}..{requested_sha}"),
        ],
        Some(graph),
    )?;
    let queued_ordered: Vec<&str> = rev_list.lines().filter(|s| !s.is_empty()).collect();
    let group_commits: std::collections::BTreeSet<&str> = queued_ordered.iter().copied().collect();
    let mut prs = std::collections::BTreeSet::new();
    let mut covered_commits = std::collections::BTreeSet::new();
    let queue_pr = parse_queue_ref_pr(git_ref)
        .ok_or_else(|| fail("merge-group ref does not contain a valid queue PR number"))?;
    let remote_refs = checked(
        "git",
        &[
            "ls-remote",
            "--refs",
            "https://github.com/carrick-sh/carrick.git",
            "refs/heads/gh-readonly-queue/main/*",
        ],
        None,
    )?;
    for line in remote_refs.lines() {
        if let Some((oid, refname)) = line.split_once('\t')
            && group_commits.contains(oid)
            && let Some(number) = parse_queue_ref_pr(refname)
        {
            prs.insert(number);
        }
    }
    for node in queue_entries {
        if let Some(oid) = node["headCommit"]["oid"].as_str()
            && let Some(base_oid) = node["baseCommit"]["oid"].as_str()
            && group_commits.contains(oid)
            && node["pullRequest"]["baseRefName"] == "main"
            && node["pullRequest"]["baseRepository"]["nameWithOwner"] == REPOSITORY
            && let Some(number) = node["pullRequest"]["number"].as_u64()
        {
            prs.insert(number);
            if let Some(head_index) = queued_ordered.iter().position(|commit| *commit == oid) {
                let first_index = if base_oid == base {
                    Some(0)
                } else {
                    let base_position = queued_ordered
                        .iter()
                        .position(|commit| *commit == base_oid)
                        .map(|index| index + 1);
                    match base_position {
                        Some(index) => Some(index),
                        None if is_ancestor(graph, base_oid, base)? => Some(0),
                        None => None,
                    }
                };
                if let Some(first_index) = first_index.filter(|index| *index <= head_index) {
                    covered_commits.extend(
                        queued_ordered[first_index..=head_index]
                            .iter()
                            .map(|commit| (*commit).to_owned()),
                    );
                }
            }
        }
    }
    if !queue_entries.iter().any(|node| {
        node["headCommit"]["oid"] == requested_sha
            && node["pullRequest"]["number"].as_u64() == Some(queue_pr)
            && node["pullRequest"]["baseRefName"] == "main"
            && node["pullRequest"]["baseRepository"]["nameWithOwner"] == REPOSITORY
    }) {
        return Err(fail(
            "merge-group head is not the live entry named by its main queue ref",
        ));
    }
    // If an earlier group (or this group) merged onto main before mergeQueue was
    // queried, its queue entry disappeared and /commits/{sha}/pulls now links it.
    // Queue entries merge strictly FIFO from main, so any already-merged entries
    // form a prefix before the earliest commit still present in mergeQueue.
    let fallback_end = if covered_commits.contains(requested_sha) {
        queued_ordered
            .iter()
            .position(|commit| covered_commits.contains(*commit))
            .unwrap_or(queued_ordered.len())
    } else {
        queued_ordered.len()
    };
    for &commit_sha in &queued_ordered[..fallback_end] {
        if covered_commits.contains(commit_sha) {
            continue;
        }
        let mut attributed = false;
        for pull in pages(
            &format!("repos/{REPOSITORY}/commits/{commit_sha}/pulls?per_page=100"),
            None,
        )? {
            if pull["base"]["ref"] == "main"
                && pull["base"]["repo"]["full_name"] == REPOSITORY
                && pull["merged_at"].as_str().is_some()
                && let Some(number) = pull["number"].as_u64()
            {
                prs.insert(number);
                attributed = true;
            }
        }
        if !attributed {
            return Err(fail(format!(
                "predecessor commit {commit_sha} is not attributed to a merged main PR"
            )));
        }
    }
    if prs.is_empty() {
        return Err(fail("merge_group resolved no pull requests"));
    }
    Ok(prs.into_iter().collect())
}

fn prepare(event_path: &Path, output: &Path) -> Result<(), ReceiptError> {
    let event = read_json(event_path)?;
    let actor = std::env::var("GITHUB_ACTOR").map_err(|e| fail(e.to_string()))?;
    let triggering = std::env::var("GITHUB_TRIGGERING_ACTOR").unwrap_or_else(|_| actor.clone());
    let event_name = std::env::var("GITHUB_EVENT_NAME").map_err(|e| fail(e.to_string()))?;
    let automatic = matches!(event_name.as_str(), "merge_group" | "push");
    if (!automatic && (!allowed(&actor) || !allowed(&triggering)))
        || event["repository"]["full_name"] != REPOSITORY
    {
        return Err(fail(
            "only the owner (tjfontaine) may start or rerun signed gates",
        ));
    }
    let git_ref = std::env::var("GITHUB_REF").unwrap_or_default();
    let automatic_pair = if automatic {
        Some(automatic_request(
            &event,
            &event_name,
            &git_ref,
            &std::env::var("GITHUB_SHA").unwrap_or_default(),
        )?)
    } else {
        None
    };
    let (pr, requested_sha) = match event_name.as_str() {
        "merge_group" | "push" => (
            None,
            automatic_pair
                .as_ref()
                .ok_or_else(|| fail("missing automatic identity"))?
                .0
                .clone(),
        ),
        "workflow_dispatch" => {
            if git_ref != "refs/heads/main" {
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
    let comparison_sha = automatic_pair
        .as_ref()
        .map_or(requested_sha.as_str(), |pair| pair.1.as_str());
    let (kind, base, prs) = if event_name == "merge_group" {
        // Authorization checks out trusted main with shallow history. Fetch
        // real refs/heads/main and candidate graph objects into an isolated
        // bare repo; never check out queue code or trust all-parents compare.
        let graph = tempfile::tempdir().map_err(|e| fail(e.to_string()))?;
        checked("git", &["init", "--bare", "."], Some(graph.path()))?;
        checked(
            "git",
            &[
                "fetch",
                "--no-tags",
                "--filter=blob:none",
                "https://github.com/carrick-sh/carrick.git",
                "+refs/heads/main:refs/heads/main",
                &requested_sha,
            ],
            Some(graph.path()),
        )?;
        let ancestor = crate::ci_receipt::resolve_main_ancestor(
            graph.path(),
            "refs/heads/main",
            &requested_sha,
        )?;
        let main_tip = checked(
            "git",
            &["rev-parse", "--verify", "refs/heads/main^{commit}"],
            Some(graph.path()),
        )?;
        let queue_entries = merge_queue_entries()?;
        // A current main tip is the ordinary first-in-line base. Every other
        // base must be witnessed as a live entry in this repository's main
        // merge queue; ancestry and queue-ref spelling are not authorization.
        if comparison_sha != main_tip.trim()
            && !live_main_queue_entry(&queue_entries, comparison_sha)
        {
            return Err(fail(
                "merge-group base is not a live entry in the main merge queue",
            ));
        }
        if comparison_sha != main_tip.trim() {
            let base_ancestor = crate::ci_receipt::resolve_main_ancestor(
                graph.path(),
                "refs/heads/main",
                comparison_sha,
            )?;
            if base_ancestor.before_sha != ancestor.before_sha {
                return Err(fail(
                    "live merge-group base does not share the candidate's main chain",
                ));
            }
        }
        let base = if comparison_sha == ancestor.before_sha {
            ancestor.before_sha
        } else {
            // Reuse select-baseline's first-parent validation of the event base.
            // Only the exact main ancestor is eligible: signed receipts must not
            // silently fall back to an older baseline.
            let selected = crate::ci_receipt::select_baseline(
                graph.path(),
                crate::ci_receipt::Lane::Hvf,
                comparison_sha,
                &requested_sha,
                |_, candidate| {
                    if candidate == ancestor.before_sha {
                        Ok(crate::ci_receipt::Baseline::Found(0, String::new()))
                    } else {
                        Ok(crate::ci_receipt::Baseline::Missing)
                    }
                },
            )?;
            selected.baseline_sha
        };
        let queue_ref = event["merge_group"]["head_ref"]
            .as_str()
            .filter(|r| parse_queue_ref_pr(r).is_some())
            .unwrap_or(&git_ref);
        let prs = resolve_merge_group_prs(
            graph.path(),
            &base,
            &requested_sha,
            queue_ref,
            &queue_entries,
        )?;
        (RequestKind::MergeGroup, base, prs)
    } else {
        let comparison = api(&format!(
            "repos/{REPOSITORY}/compare/main...{comparison_sha}"
        ))?;
        let base = sha(comparison["merge_base_commit"]["sha"]
            .as_str()
            .unwrap_or_default())?;
        if pr.is_none() && base != comparison_sha {
            return Err(fail("main baseline SHA must be on main"));
        }
        let kind = if pr.is_some() {
            RequestKind::PullRequest
        } else {
            RequestKind::Main
        };
        (kind, base, pr.into_iter().collect())
    };
    let mut request = Request {
        kind,
        prs,
        sha: requested_sha,
        base,
        baseline_run: None,
    };
    fs::create_dir_all(output).map_err(|e| fail(e.to_string()))?;
    if request.kind != RequestKind::Main {
        request.baseline_run = Some(download_baseline(
            &request.base,
            output,
            request.kind == RequestKind::MergeGroup,
        )?);
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
            request.kind == RequestKind::Main
        )
        .map_err(|e| fail(e.to_string()))?;
    }
    Ok(())
}

pub fn trusted_run(run: &Value) -> bool {
    run["path"] == WORKFLOW
        && run["head_branch"] == "main"
        && (run["event"] == "push" || run["event"] == "workflow_dispatch")
        && run["status"] == "completed"
        && run["repository"]["full_name"] == REPOSITORY
        && run["head_repository"]["full_name"] == REPOSITORY
        && (run["event"] == "push"
            || (run["actor"]["login"].as_str().is_some_and(allowed)
                && run["triggering_actor"]["login"]
                    .as_str()
                    .is_some_and(allowed)))
}
fn baseline_runs() -> Result<Vec<Value>, ReceiptError> {
    let mut runs = pages(
        &format!(
            "repos/{REPOSITORY}/actions/workflows/signed-gate.yml/runs?branch=main&per_page=100"
        ),
        Some("workflow_runs"),
    )?;
    runs.sort_by_key(|r| std::cmp::Reverse(r["id"].as_u64().unwrap_or(0)));
    Ok(runs)
}

fn download_run_baseline(
    run: &Value,
    base: &str,
    output: &Path,
) -> Result<Option<u64>, ReceiptError> {
    if !trusted_run(run) || (run["event"] == "push" && run["head_sha"] != base) {
        return Ok(None);
    }
    let id = run["id"].as_u64().ok_or_else(|| fail("missing run ID"))?;
    let artifacts = pages(
        &format!("repos/{REPOSITORY}/actions/runs/{id}/artifacts?per_page=100"),
        Some("artifacts"),
    )?;
    let prefix = format!("signed-baseline-{base}-");
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
        return Ok(Some(id));
    }
    Ok(None)
}

fn exact_base_push(run: &Value, base: &str) -> bool {
    run["path"] == WORKFLOW
        && run["event"] == "push"
        && run["head_branch"] == "main"
        && run["head_sha"] == base
        && run["repository"]["full_name"] == REPOSITORY
        && run["head_repository"]["full_name"] == REPOSITORY
}

fn download_baseline(base: &str, output: &Path, wait_for_push: bool) -> Result<u64, ReceiptError> {
    let runs = baseline_runs()?;
    for run in &runs {
        if let Some(id) = download_run_baseline(run, base, output)? {
            return Ok(id);
        }
    }
    if wait_for_push {
        // The queue event may precede registration of the base's push workflow.
        // Bound discovery of that exact run; never rerun tests or build a second
        // baseline. Authorization's workflow timeout also bounds `gh run watch`.
        let mut pending = runs.into_iter().find(|r| exact_base_push(r, base));
        for _ in 0..60 {
            if pending.is_some() {
                break;
            }
            pending = baseline_runs()?
                .into_iter()
                .find(|r| exact_base_push(r, base));
            if pending.is_none() {
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
        if let Some(run) = pending {
            let id = run["id"]
                .as_u64()
                .ok_or_else(|| fail("missing baseline run ID"))?;
            if run["status"] != "completed" {
                checked(
                    "gh",
                    &["run", "watch", &id.to_string(), "--repo", REPOSITORY],
                    None,
                )?;
            }
            let terminal = api(&format!("repos/{REPOSITORY}/actions/runs/{id}"))?;
            if !exact_base_push(&terminal, base) {
                return Err(fail("base push identity changed while waiting"));
            }
            if let Some(id) = download_run_baseline(&terminal, base, output)? {
                return Ok(id);
            }
        }
    }
    Err(fail(format!(
        "no signed baseline for merge-base {base}; dispatch signed-gate.yml on main with pr=main and sha={base}, then rerun this request"
    )))
}

/// An empty, truncated or unsigned receipt can never seed a baseline or stand for a gate.
pub fn validate_receipt(receipt: &AcceptReceipt, expected: &str) -> Result<(), ReceiptError> {
    for (field, actual, expected) in [
        ("head", receipt.head.as_str(), expected),
        ("phase", receipt.phase.as_str(), "signed"),
        ("profile", receipt.profile.as_str(), "no-docker"),
    ] {
        if actual != expected {
            return Err(fail(format!(
                "receipt {field} mismatch: expected {expected:?}, got {actual:?}"
            )));
        }
    }
    if !receipt.clean_tree {
        return Err(fail(
            "receipt clean_tree mismatch: expected true, got false",
        ));
    }
    // Compare the complete lists as unordered sets without discarding duplicate
    // entries: only the profile's declared exclusions may be skipped.
    let mut actual_skips: Vec<_> = receipt.skipped_steps.iter().map(String::as_str).collect();
    let mut expected_skips = NO_DOCKER_EXCLUSIONS.to_vec();
    actual_skips.sort_unstable();
    expected_skips.sort_unstable();
    if actual_skips != expected_skips {
        return Err(fail(format!(
            "receipt skipped_steps mismatch: expected {expected_skips:?}, got {actual_skips:?}"
        )));
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
/// Admit the same-run fixture archive before any installation or guest work.
/// General fixture reuse permits equal inputs across commits; this Actions
/// lane additionally requires the authorized publisher's exact commit.
pub fn verify_fixture_artifact(
    root: &Path,
    bundle: &Path,
    expected: &str,
) -> Result<(), ReceiptError> {
    let (manifest, _) = crate::fixtures::archive::verify(root, bundle, expected)
        .map_err(|e| fail(e.to_string()))?;
    let expected = crate::fixtures::CommitSha::try_from(expected.to_owned())
        .map_err(|e| fail(e.to_string()))?;
    if manifest.source_head != expected {
        return Err(fail(
            "signed fixture artifact source SHA differs from authorized SHA",
        ));
    }
    Ok(())
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
        verify_fixture_artifact(&tree, &bundle, &request.sha)?;
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
                "fixture restore failed for the authorized exact-SHA artifact",
            ));
        }
        let mut build = Command::new("just");
        build.current_dir(&tree).arg("build");
        if !logged(&mut build, &lease, &output.join("build.log"))? {
            return Err(fail("just build failed"));
        }
        let mut accept = crate::command::locked_cargo();
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
        let base = if request.kind == RequestKind::Main {
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
    if !request.prs.is_empty() {
        let prs = request
            .prs
            .iter()
            .map(|pr| format!("#{pr}"))
            .collect::<Vec<_>>()
            .join(", ");
        body.push_str(&format!("\nPull requests: {prs}\n"));
    }
    if let Ok(error) = fs::read_to_string(results.join("execution-error.txt")) {
        body.push_str(&format!("\nExecution diagnostic: {error}\n"));
    }
    body.push_str(&format!(
        "\nExecution job: `{execution_result}`. [Receipts and logs]({run_url}).\n"
    ));
    write(&results.join("comment.md"), &body)?;
    println!("{body}");
    if let Ok(summary) = std::env::var("GITHUB_STEP_SUMMARY") {
        write(Path::new(&summary), &body)?;
    }
    // Status is written even if comment publication fails.
    let status = post(
        &format!("repos/{REPOSITORY}/statuses/{}", request.sha),
        json!({"state": if passed {"success"} else {"failure"}, "context": "signed-gate", "description": if passed {"No new failures; populations and completion preserved"} else {"Signed receipt regression or incomplete gate"}, "target_url": run_url}),
    );
    let comment = request.prs.iter().try_for_each(|pr| {
        post(
            &format!("repos/{REPOSITORY}/issues/{pr}/comments"),
            json!({"body": body}),
        )
    });
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
