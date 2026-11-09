//! Actions plumbing for the signed lane. Only the authorized execution job runs PR code.
use crate::accept::{
    AcceptReceipt, ArtifactIdentity, CleanupCount, NO_DOCKER_EXCLUSIONS, inspect_artifact,
    parse_cleanup_count,
};
use crate::ci_receipt::{ReceiptError, load};
use crate::ci_scaler::REPOSITORY;
use crate::command::{CommandError, CommandOutput, run_checked};
use crate::host_lease::{HostLease, HostLeaseMode};
use crate::signed_receipt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

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
    /// Authorize an Actions event and name the exact candidate and merge base.
    Prepare {
        #[arg(long)]
        event: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Fetch the merge base's fixture bundle from an authenticated main-push
    /// run of the trusted fixture publisher (kernel-runtime.yml), keyed by
    /// `request.base`. A missing trusted bundle blocks.
    BaseFixtures {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Bound on waiting for main's publisher to upload the bundle.
        #[arg(long, default_value_t = 75)]
        wait_minutes: u64,
    },
    /// On Linux ARM64, build only the probes the candidate adds relative to
    /// the merge base's trusted bundle, from candidate code with main's
    /// publisher build code (#1980). Writes `candidate-probes.json` and, when
    /// probes were built, one candidate probe set archive.
    CandidateProbes {
        #[arg(long)]
        request: PathBuf,
        /// The merge base's trusted archive (`base-fixtures`).
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Run the merge base and the candidate on macOS, each in a new detached
    /// worktree, under one exclusive host lease and one fixture bundle.
    Execute {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// The merge base's trusted archive (`base-fixtures`); admission checks
        /// its publishing SHA and each checkout's fixture input identity.
        #[arg(long, env = "CARRICK_SIGNED_FIXTURE_BUNDLE")]
        fixture_bundle: PathBuf,
        /// The candidate's added probes (`candidate-probes`), served beside
        /// the bundle to the candidate run only.
        #[arg(long)]
        candidate_probes: Option<PathBuf>,
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
/// Whether a failed `git fetch` is worth another attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchFailure {
    Transient,
    Permanent,
}

/// Total attempts (first try plus two retries) and the pauses between them.
const FETCH_ATTEMPTS: usize = 3;
const FETCH_BACKOFF: [Duration; FETCH_ATTEMPTS - 1] =
    [Duration::from_secs(2), Duration::from_secs(4)];

fn classify_fetch_failure(err: &CommandError) -> FetchFailure {
    // Network-layer messages git prints when GitHub or the path to it hiccups.
    const TRANSIENT_NEEDLES: &[&str] = &[
        "recv failure",
        "operation timed out",
        "connection reset",
        "could not resolve host",
        "ssl_connect",
        "ssl_error",
        "tls",
        "ssl connection",
    ];
    let CommandError::NonZeroExit { status, stderr, .. } = err else {
        return FetchFailure::Permanent;
    };
    let stderr = stderr.to_lowercase();
    if status.code() == Some(128) && TRANSIENT_NEEDLES.iter().any(|n| stderr.contains(n)) {
        FetchFailure::Transient
    } else {
        FetchFailure::Permanent
    }
}

/// Run a `git fetch` up to `FETCH_ATTEMPTS` times, retrying only transient
/// transport errors. Infrastructure retry only: no test verdict depends on it.
fn fetch_with_retry(
    mut run: impl FnMut() -> Result<CommandOutput, CommandError>,
    mut sleep: impl FnMut(Duration),
) -> Result<CommandOutput, ReceiptError> {
    let mut attempt = 1;
    loop {
        let err = match run() {
            Ok(output) => return Ok(output),
            Err(err) => err,
        };
        let class = classify_fetch_failure(&err);
        let first_line = err
            .stderr()
            .and_then(|s| s.lines().next())
            .unwrap_or("")
            .chars()
            .take(200)
            .collect::<String>();
        eprintln!("git fetch attempt {attempt}/{FETCH_ATTEMPTS}: {class:?}: {first_line}");
        if class == FetchFailure::Permanent || attempt == FETCH_ATTEMPTS {
            return Err(fail(err.to_string()));
        }
        sleep(FETCH_BACKOFF[attempt - 1]);
        attempt += 1;
    }
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

fn not_live() -> ReceiptError {
    fail("merge-group head is not the live entry named by its main queue ref")
}

/// Authorizes the merge-group head against the live merge-queue entries.
pub fn validate_queue_entries(
    queue_entries: &[Value],
    requested_sha: &str,
    queue_pr: u64,
) -> Result<(), ReceiptError> {
    let Some((index, own)) = queue_entries
        .iter()
        .enumerate()
        .find(|(_, node)| node["headCommit"]["oid"] == requested_sha)
    else {
        return Err(not_live());
    };
    if own["baseCommit"]["oid"].as_str().is_none()
        || own["pullRequest"]["number"].as_u64().is_none()
        || own["pullRequest"]["baseRefName"].as_str().is_none()
        || own["pullRequest"]["baseRepository"]["nameWithOwner"]
            .as_str()
            .is_none()
    {
        return Err(fail(format!(
            "mergeQueue entry {index} (the merge-group head) is null or incomplete"
        )));
    }
    if own["pullRequest"]["number"].as_u64() != Some(queue_pr)
        || own["pullRequest"]["baseRefName"] != "main"
        || own["pullRequest"]["baseRepository"]["nameWithOwner"] != REPOSITORY
    {
        return Err(not_live());
    }
    for (other, node) in queue_entries.iter().enumerate() {
        if other != index && node["headCommit"]["oid"].as_str().is_none() {
            eprintln!("signed-gate: ignoring incomplete sibling mergeQueue entry {other}");
        }
    }
    Ok(())
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
    validate_queue_entries(queue_entries, requested_sha, queue_pr)?;
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
    // Any commit not covered by a live queue entry may have merged onto main
    // between event creation and this query. Resolve every such commit through
    // REST, regardless of where it appears in the candidate range.
    for &commit_sha in &queued_ordered {
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
        let base = if comparison_sha == ancestor.before_sha.as_str() {
            ancestor.before_sha.as_str().to_owned()
        } else {
            // Reuse select-baseline's first-parent validation of the event base.
            // Only the exact main ancestor is eligible: signed receipts must not
            // silently fall back to an older baseline.
            let selected = crate::ci_receipt::select_baseline(
                graph.path(),
                crate::ci_receipt::Lane::Hvf,
                comparison_sha,
                &ancestor.before_sha,
                &requested_sha,
                |_, candidate| {
                    if candidate == ancestor.before_sha.as_str() {
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
    let request = Request {
        kind,
        prs,
        sha: requested_sha,
        base,
    };
    // The gate job executes this base beside the candidate on one Mac; no
    // stored receipt from another host is downloaded here (#1884).
    fs::create_dir_all(output).map_err(|e| fail(e.to_string()))?;
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
/// main's own fixture publisher: kernel-runtime.yml uploads
/// `signed-fixtures-<sha>` on every push to main (#1581).
const FIXTURE_WORKFLOW: &str = ".github/workflows/kernel-runtime.yml";
const FIXTURE_POLL: std::time::Duration = std::time::Duration::from_secs(30);

/// A run may supply the base's fixture authority only if it is main's own
/// fixture publisher building exactly `base` in this repository: a push to
/// main, or an owner dispatch on main.
pub fn trusted_fixture_run(run: &Value, base: &str) -> bool {
    run["path"] == FIXTURE_WORKFLOW
        && run["head_branch"] == "main"
        && run["head_sha"] == base
        && run["repository"]["full_name"] == REPOSITORY
        && run["head_repository"]["full_name"] == REPOSITORY
        && (run["event"] == "push"
            || (run["event"] == "workflow_dispatch"
                && run["actor"]["login"].as_str().is_some_and(allowed)
                && run["triggering_actor"]["login"]
                    .as_str()
                    .is_some_and(allowed)))
}

/// Download the merge base's bundle from its trusted producer. The newest
/// trusted run holding a live artifact wins; untrusted runs are never asked.
/// Waits (bounded) while a trusted run may still upload; blocks when none can.
fn base_fixtures(
    request_path: &Path,
    output: &Path,
    wait_minutes: u64,
) -> Result<(), ReceiptError> {
    let request: Request =
        serde_json::from_value(read_json(request_path)?).map_err(|e| fail(e.to_string()))?;
    let base = sha(&request.base)?;
    let name = format!("signed-fixtures-{base}");
    let refuse = |why: String| fail(format!("no trusted base fixture bundle for {base}: {why}"));
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(wait_minutes.saturating_mul(60));
    loop {
        let mut runs: Vec<Value> = pages(
            &format!(
                "repos/{REPOSITORY}/actions/workflows/kernel-runtime.yml/runs?branch=main&head_sha={base}&per_page=100"
            ),
            Some("workflow_runs"),
        )?
        .into_iter()
        .filter(|run| trusted_fixture_run(run, &base))
        .collect();
        runs.sort_by_key(|run| std::cmp::Reverse(run["id"].as_u64().unwrap_or(0)));
        let mut pending = false;
        for run in &runs {
            let id = run["id"]
                .as_u64()
                .ok_or_else(|| refuse("trusted run without an ID".into()))?;
            let artifacts = pages(
                &format!("repos/{REPOSITORY}/actions/runs/{id}/artifacts?per_page=100"),
                Some("artifacts"),
            )?;
            if artifacts
                .iter()
                .any(|a| a["name"] == name.as_str() && a["expired"] == false)
            {
                return download_base_fixtures(run, id, &name, output);
            }
            pending |= run["status"] != "completed";
        }
        if !runs.is_empty() && !pending {
            return Err(refuse(format!(
                "{} trusted main run(s) completed without a live {name} artifact",
                runs.len()
            )));
        }
        if std::time::Instant::now() >= deadline {
            return Err(refuse(if runs.is_empty() {
                format!("no main-push run of {FIXTURE_WORKFLOW} for this commit")
            } else {
                format!("timed out after {wait_minutes} min waiting for {name}")
            }));
        }
        std::thread::sleep(FIXTURE_POLL);
    }
}

fn download_base_fixtures(
    run: &Value,
    id: u64,
    name: &str,
    output: &Path,
) -> Result<(), ReceiptError> {
    fs::create_dir_all(output).map_err(|e| fail(e.to_string()))?;
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
            &output.to_string_lossy(),
        ],
        None,
    )?;
    let bundles = fs::read_dir(output)
        .map_err(|e| fail(e.to_string()))?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tar.gz"))
        .count();
    if bundles != 1 {
        return Err(fail(format!(
            "trusted base fixture artifact {name} held {bundles} archives, expected one"
        )));
    }
    write(
        &output.join("provenance.json"),
        serde_json::to_vec_pretty(&json!({
            "run_id": id,
            "workflow": run["path"],
            "event": run["event"],
            "head_branch": run["head_branch"],
            "head_sha": run["head_sha"],
            "artifact": name,
        }))
        .map_err(|e| fail(e.to_string()))?,
    )
}

/// Admit the trusted fixture archive before any installation or guest work.
/// General fixture reuse permits equal inputs across commits; this Actions
/// lane additionally requires the authorized publisher's exact commit. Both
/// paired runs restore the bundle main published for the merge base
/// (`publisher`): the base checkout must match it exactly, and the candidate
/// checkout (`checkout`) must have equal fixture inputs, or the pair is
/// refused rather than served by a candidate-built bundle (#1889). The one
/// exception (#1980): a candidate that only adds probes is served those
/// probes from `candidate`, a set built from exactly `checkout`.
pub fn verify_fixture_artifact(
    root: &Path,
    bundle: &Path,
    candidate: Option<&Path>,
    checkout: &str,
    publisher: &str,
) -> Result<(), ReceiptError> {
    let (manifest, set, _) = crate::fixtures::archive::verify(root, bundle, candidate, checkout)
        .map_err(|e| fail(e.to_string()))?;
    if let Some(set) = set
        && String::from(set.candidate_head) != checkout
    {
        return Err(fail(
            "candidate probe set was built from a commit other than the checkout",
        ));
    }
    let publisher = crate::fixtures::CommitSha::try_from(publisher.to_owned())
        .map_err(|e| fail(e.to_string()))?;
    if manifest.source_head != publisher {
        return Err(fail(
            "signed fixture artifact source SHA differs from authorized SHA",
        ));
    }
    Ok(())
}

/// What the candidate probe build decided, for the gate job and its readers.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateProbesOutcome {
    pub sha: String,
    pub base: String,
    pub outcome: CandidateProbesVerdict,
    /// The refusal the Mac will report again, when `refused`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    /// The set archive's file name in the output directory, when `built`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateProbesVerdict {
    /// Fixture inputs equal the bundle's: nothing to build.
    Equal,
    /// A difference other than added probes: nothing built.
    Refused,
    /// The added probes were built into `archive`.
    Built,
}

/// Build the candidate's added probes beside the merge base's trusted bundle
/// (#1980), in a detached worktree of the candidate, with this (main's)
/// publisher build code. A refusal is recorded, not raised: the Mac admits
/// fixtures independently and reports the same input identity refusal on the
/// PR, as it does today.
fn candidate_probes(
    root: &Path,
    request_path: &Path,
    bundle: &Path,
    output: &Path,
) -> Result<(), ReceiptError> {
    use crate::fixtures::candidate_probes::CandidateBuild;
    let request: Request =
        serde_json::from_value(read_json(request_path)?).map_err(|e| fail(e.to_string()))?;
    sha(&request.sha)?;
    sha(&request.base)?;
    fs::create_dir_all(output).map_err(|e| fail(e.to_string()))?;
    let output = fs::canonicalize(output).map_err(|e| fail(e.to_string()))?;
    let bundle = fs::canonicalize(bundle).map_err(|e| fail(e.to_string()))?;
    let mut outcome = CandidateProbesOutcome {
        sha: request.sha.clone(),
        base: request.base.clone(),
        outcome: CandidateProbesVerdict::Equal,
        refusal: None,
        archive: None,
    };
    if request.kind != RequestKind::Main && request.sha != request.base {
        fetch_with_retry(
            || {
                run_checked(
                    "git",
                    ["fetch", "--no-tags", "origin", &request.base, &request.sha],
                    Some(root),
                )
            },
            std::thread::sleep,
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
        let tree = fs::canonicalize(&tree).map_err(|e| fail(e.to_string()))?;
        let built = crate::fixtures::build_candidate_probes(&tree, &bundle, &request.sha, &output);
        let removed = checked(
            "git",
            &["worktree", "remove", "--force", &tree.to_string_lossy()],
            Some(root),
        );
        match built.map_err(|e| fail(e.to_string()))? {
            CandidateBuild::Equal => {}
            CandidateBuild::Refused(error) => {
                outcome.outcome = CandidateProbesVerdict::Refused;
                outcome.refusal = Some(error.to_string());
            }
            CandidateBuild::Build(archive) => {
                outcome.outcome = CandidateProbesVerdict::Built;
                outcome.archive = archive
                    .strip_prefix(&output)
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned());
            }
        }
        removed?;
    }
    write(
        &output.join("candidate-probes.json"),
        serde_json::to_vec_pretty(&outcome).map_err(|e| fail(e.to_string()))?,
    )
}

/// The acceptance exit status `execute_one` recorded beside a receipt.
fn accept_exit(dir: &Path) -> Result<bool, ReceiptError> {
    read_json(&dir.join(ACCEPT_EXIT))?["success"]
        .as_bool()
        .ok_or_else(|| fail(format!("{ACCEPT_EXIT} lacks a boolean success")))
}

/// A paired base is a baseline only when it ran to completion. Completed
/// tests with known failures stay comparable: the gate is differential. A
/// step that did not run (a killed or unfinished binary, a build failure,
/// zero tests selected), tests skipped after a budget expired, or a failing
/// acceptance exit that no completed failure explains is refused before any
/// comparison, so a missing base result can never read as FIXED.
pub fn admit_paired_base(receipt: &AcceptReceipt, accepted: bool) -> Result<(), ReceiptError> {
    let refuse =
        |why: String| ReceiptError::IncomparableBase(format!("paired base incomplete: {why}"));
    let mut completed_failure = !receipt.probe_diffs.is_empty();
    for step in &receipt.steps {
        match step.execution_outcome() {
            crate::accept::StepOutcome::NotRun { reason } => {
                return Err(refuse(format!(
                    "step {} did not run to completion: {reason}",
                    step.name
                )));
            }
            crate::accept::StepOutcome::Failed { .. } => completed_failure = true,
            crate::accept::StepOutcome::Passed => {}
        }
        if !step.not_run_tests.is_empty() {
            return Err(refuse(format!(
                "step {} was interrupted before {} test(s) ran",
                step.name,
                step.not_run_tests.len()
            )));
        }
    }
    if !accepted && !completed_failure {
        return Err(refuse(
            "acceptance exited nonzero with no completed failure to explain it (infrastructure failure)"
                .into(),
        ));
    }
    Ok(())
}

/// Receipt file names inside one execution's output directory.
const CANDIDATE_RECEIPT: &str = "candidate.json";
const BASE_RECEIPT: &str = "base.json";
/// The paired base's evidence lives beside the candidate's, in this subdirectory.
const BASE_DIR: &str = "base";
/// Acceptance exit status recorded by the trusted executor for each run.
const ACCEPT_EXIT: &str = "accept-exit.json";
/// Sealed record of the base evidence, written after the candidate run.
const BASE_SEAL: &str = "base-seal.json";

/// Which side of the pair a run is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairSide {
    Base,
    Candidate,
}

/// One side of a paired execution, as the pairing hands it to the runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedRun {
    pub side: PairSide,
    /// Exact commit checked out, built and accepted.
    pub commit: String,
    /// Commit whose published fixture bundle this run must restore.
    pub fixture_publisher: String,
    /// Evidence directory for this run's receipt, identity and logs.
    pub output: PathBuf,
    /// Receipt file name inside `output`.
    pub receipt_name: &'static str,
}

/// Run the merge base (unless this is a main baseline) and then the candidate
/// on this Mac, under one exclusive host lease and with the merge base's
/// trusted fixture bundle. Publication compares the candidate only with this paired
/// base, so host or fixture differences cannot surface as NEW failures (#1884).
fn execute(
    root: &Path,
    request_path: &Path,
    output: &Path,
    bundle: &Path,
    candidate_probes: Option<&Path>,
) -> Result<(), ReceiptError> {
    if std::env::consts::OS != "macos" || std::env::consts::ARCH != "aarch64" {
        return Err(fail("requires macOS ARM64"));
    }
    let request: Request =
        serde_json::from_value(read_json(request_path)?).map_err(|e| fail(e.to_string()))?;
    sha(&request.sha)?;
    sha(&request.base)?;
    fs::create_dir_all(output).map_err(|e| fail(e.to_string()))?;
    let output = fs::canonicalize(output).map_err(|e| fail(e.to_string()))?;
    let bundle = fs::canonicalize(bundle).map_err(|e| fail(e.to_string()))?;
    let candidate_probes = candidate_probes
        .map(fs::canonicalize)
        .transpose()
        .map_err(|e| fail(e.to_string()))?;
    let lease = (|| {
        crate::host_load::check().map_err(|e| fail(e.to_string()))?;
        HostLease::acquire(HostLeaseMode::Gate).map_err(|e| fail(e.to_string()))
    })();
    let lease = match lease {
        Ok(lease) => lease,
        Err(error) => {
            write(&output.join("execution-error.txt"), error.to_string())?;
            return Err(error);
        }
    };
    execute_pair(&request, &output, |run| {
        execute_one(
            root,
            &lease,
            &run.commit,
            &run.fixture_publisher,
            FixtureSources {
                bundle: &bundle,
                candidate_probes: match run.side {
                    PairSide::Base => None,
                    PairSide::Candidate => candidate_probes.as_deref(),
                },
            },
            &run.output,
            run.receipt_name,
        )
    })
}

/// The pairing itself: the base (unless this is a main baseline) and then the
/// candidate, each handed to `run`, which builds, accepts and inspects one
/// commit. `execute` supplies the real runner under one exclusive lease.
/// Any error is recorded in `execution-error.txt` for publication.
pub fn execute_pair(
    request: &Request,
    output: &Path,
    mut run: impl FnMut(&PairedRun) -> Result<(), ReceiptError>,
) -> Result<(), ReceiptError> {
    let result = (|| {
        let mut sealed = None;
        if request.kind != RequestKind::Main {
            let base_dir = output.join(BASE_DIR);
            fs::create_dir_all(&base_dir).map_err(|e| fail(e.to_string()))?;
            run(&PairedRun {
                side: PairSide::Base,
                commit: request.base.clone(),
                fixture_publisher: request.base.clone(),
                output: base_dir.clone(),
                receipt_name: BASE_RECEIPT,
            })
            .map_err(|error| fail(format!("paired base {}: {error}", request.base)))?;
            // An incomplete base cannot serve as a baseline; refuse before
            // spending a candidate run on a comparison that cannot pass.
            let receipt = load(&base_dir.join(BASE_RECEIPT))?;
            admit_paired_base(&receipt, accept_exit(&base_dir)?)?;
            // Seal the base now, before any candidate code runs. The
            // expected inventory lives only in this process's memory.
            sealed = Some((base_dir.clone(), evidence_inventory(&base_dir)?));
        }
        run(&PairedRun {
            side: PairSide::Candidate,
            commit: request.sha.clone(),
            fixture_publisher: request.base.clone(),
            output: output.to_path_buf(),
            receipt_name: CANDIDATE_RECEIPT,
        })?;
        if let Some((base_dir, files)) = sealed {
            // The candidate run, including its worktree cleanup, is over:
            // the base evidence must be byte-for-byte what was sealed.
            verify_inventory(&base_dir, &files)?;
            let record = BaseSeal {
                base: request.base.clone(),
                files,
            };
            write_fresh(
                &output.join(BASE_SEAL),
                serde_json::to_vec_pretty(&record).map_err(|e| fail(e.to_string()))?,
            )?;
        }
        Ok::<_, ReceiptError>(())
    })();
    if let Err(error) = &result {
        write(&output.join("execution-error.txt"), error.to_string())?;
    }
    result
}

/// The paired base's evidence as sealed by the trusted executor between the
/// base run and the candidate run. Publication compares it with what it loads.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseSeal {
    base: String,
    files: std::collections::BTreeMap<String, String>,
}

/// SHA-256 of every regular file under `dir`, keyed by `/`-separated relative
/// path. Symlinks and other special files are refused, never followed.
fn evidence_inventory(
    dir: &Path,
) -> Result<std::collections::BTreeMap<String, String>, ReceiptError> {
    fn walk(
        root: &Path,
        dir: &Path,
        files: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<(), ReceiptError> {
        let seal = |message: String| fail(format!("base evidence seal: {message}"));
        let entries = fs::read_dir(dir).map_err(|e| seal(format!("{}: {e}", dir.display())))?;
        for entry in entries {
            let path = entry
                .map_err(|e| seal(format!("{}: {e}", dir.display())))?
                .path();
            let kind = fs::symlink_metadata(&path)
                .map_err(|e| seal(format!("{}: {e}", path.display())))?
                .file_type();
            if kind.is_dir() {
                walk(root, &path, files)?;
                continue;
            }
            if !kind.is_file() {
                return Err(seal(format!("{} is not a regular file", path.display())));
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|e| seal(e.to_string()))?
                .components()
                .map(|c| {
                    c.as_os_str()
                        .to_str()
                        .ok_or_else(|| seal(format!("non-UTF-8 path {}", path.display())))
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("/");
            let digest = crate::provision::compute_sha256(&path)
                .map_err(|e| seal(format!("{}: {e}", path.display())))?;
            files.insert(relative, digest);
        }
        Ok(())
    }
    let mut files = std::collections::BTreeMap::new();
    walk(dir, dir, &mut files)?;
    Ok(files)
}

/// Refuse changed, missing or added files relative to a sealed inventory.
fn verify_inventory(
    dir: &Path,
    sealed: &std::collections::BTreeMap<String, String>,
) -> Result<(), ReceiptError> {
    let current = evidence_inventory(dir)?;
    let mut problems = Vec::new();
    for (path, digest) in sealed {
        match current.get(path) {
            None => problems.push(format!("missing {path}")),
            Some(now) if now != digest => problems.push(format!("changed {path}")),
            Some(_) => {}
        }
    }
    problems.extend(
        current
            .keys()
            .filter(|path| !sealed.contains_key(*path))
            .map(|path| format!("added {path}")),
    );
    if problems.is_empty() {
        Ok(())
    } else {
        Err(fail(format!(
            "base evidence seal: base evidence differs from its seal: {}",
            problems.join(", ")
        )))
    }
}

/// Check the published paired base against the executor's sealed record.
fn verify_base_seal(results: &Path, base: &str) -> Result<(), ReceiptError> {
    let record: BaseSeal = read_json(&results.join(BASE_SEAL))
        .and_then(|value| serde_json::from_value(value).map_err(|e| fail(e.to_string())))
        .map_err(|error| fail(format!("base evidence seal: {error}")))?;
    if record.base != base {
        return Err(fail(format!(
            "base evidence seal: record names base {}, request names {base}",
            record.base
        )));
    }
    verify_inventory(&results.join(BASE_DIR), &record.files)
}

/// Replace whatever is at `path` (including a planted symlink) with a new file.
fn write_fresh(path: &Path, data: impl AsRef<[u8]>) -> Result<(), ReceiptError> {
    use std::io::Write;
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(fail(format!("{}: {error}", path.display()))),
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(data.as_ref()))
        .map_err(|e| fail(format!("{}: {e}", path.display())))
}

/// The fixtures one paired run restores: the base's trusted bundle and, for
/// the candidate only, its added probes (#1980).
#[derive(Debug, Clone, Copy)]
struct FixtureSources<'a> {
    bundle: &'a Path,
    candidate_probes: Option<&'a Path>,
}

/// Build, accept and independently inspect one commit in a fresh detached
/// worktree. The caller holds the exclusive gate lease for the whole pair.
fn execute_one(
    root: &Path,
    lease: &HostLease,
    commit: &str,
    publisher: &str,
    fixtures: FixtureSources<'_>,
    output: &Path,
    receipt_name: &str,
) -> Result<(), ReceiptError> {
    let FixtureSources {
        bundle,
        candidate_probes,
    } = fixtures;
    fetch_with_retry(
        || run_checked("git", ["fetch", "--no-tags", "origin", commit], Some(root)),
        std::thread::sleep,
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
            commit,
        ],
        Some(root),
    )?;
    // macOS TMPDIR may use /var while git reports /private/var. Use the
    // repository's physical path for exact artifact-path comparisons.
    let tree = fs::canonicalize(&tree).map_err(|e| fail(e.to_string()))?;
    let receipt_path = output.join(receipt_name);
    let result = (|| {
        let xtask = std::env::current_exe().map_err(|e| fail(e.to_string()))?;
        let mut fetch = Command::new(&xtask);
        fetch
            .current_dir(&tree)
            .args(["--root", &tree.to_string_lossy(), "fixtures", "fetch"]);
        if !logged(&mut fetch, lease, &output.join("fixture-fetch.log"))? {
            return Err(fail("fixture dependency fetch failed"));
        }
        verify_fixture_artifact(&tree, bundle, candidate_probes, commit, publisher)?;
        let mut restore = Command::new(&xtask);
        restore.current_dir(&tree).args([
            "--root",
            &tree.to_string_lossy(),
            "fixtures",
            "restore",
            "--bundle",
            &bundle.to_string_lossy(),
        ]);
        if let Some(set) = candidate_probes {
            restore.arg("--candidate-probes").arg(set);
        }
        if !logged(&mut restore, lease, &output.join("fixture-restore.log"))? {
            return Err(fail(
                "fixture restore failed for the authorized exact-SHA artifact",
            ));
        }
        let mut build = Command::new("just");
        build.current_dir(&tree).arg("build");
        if !logged(&mut build, lease, &output.join("build.log"))? {
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
            &receipt_path.to_string_lossy(),
        ]);
        let accepted = logged(&mut accept, lease, &output.join("accept.log"))?;
        write(
            &output.join(ACCEPT_EXIT),
            json!({"success": accepted}).to_string(),
        )?;
        // accept rebuilds once under the same lease before testing. Its receipt
        // names that artifact; inspect it independently before releasing the lease.
        let mut receipt = load(&receipt_path)?;
        // Capture on the execution Mac, including when the commit predates
        // host-aware accept receipts. Never infer identity on the hosted publisher.
        receipt.host_identity = crate::accept::SignedHostIdentity::capture();
        // Both runs of a pair restore the base's trusted bundle. Record its
        // identity with this trusted executor's validation, so a base commit
        // whose accept predates content identity remains comparable.
        let trusted = crate::accept::verify_signed_fixtures(&tree)
            .map_err(|e| fail(format!("trusted fixture validation: {e}")))?;
        if let Some(recorded) = &receipt.fixture_validation
            && recorded.inputs_sha256 != trusted.inputs_sha256
        {
            return Err(fail(
                "accept recorded fixture inputs that differ from the restored bundle",
            ));
        }
        receipt.fixture_validation = Some(trusted);
        write(
            &receipt_path,
            serde_json::to_vec_pretty(&receipt).map_err(|e| fail(e.to_string()))?,
        )?;
        // Older accept receipts encode an unknown reap as remaining_count=0
        // plus human diagnostics. Prove cleanup again without parsing those
        // diagnostics or allowing them to disappear behind known test failures.
        for (index, count) in receipt.cleanup_counts.iter().enumerate() {
            let log = output.join(format!("cleanup-{index}.log"));
            let mut reap = Command::new(tree.join("scripts/sudo/kill.sh"));
            reap.current_dir(&tree).arg(&count.run_id);
            if !logged(&mut reap, lease, &log)?
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
        validate_receipt(&receipt, commit)
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
    result?;
    log_copy?;
    cleanup?;
    Ok(())
}

/// Independent execution evidence must match the receipt it accompanies.
fn admit_evidence(dir: &Path, receipt: &AcceptReceipt) -> Result<ArtifactIdentity, ReceiptError> {
    let identity: ArtifactIdentity = read_json(&dir.join("identity.json"))
        .and_then(|value| serde_json::from_value(value).map_err(|e| fail(e.to_string())))?;
    if receipt.artifact.as_ref() != Some(&identity) {
        return Err(fail(
            "independent artifact identity does not match the receipt",
        ));
    }
    let cleanup: Vec<CleanupCount> = read_json(&dir.join("cleanup.json"))
        .and_then(|value| serde_json::from_value(value).map_err(|e| fail(e.to_string())))?;
    if cleanup != receipt.cleanup_counts {
        return Err(fail("independent cleanup evidence differs from receipt"));
    }
    Ok(identity)
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
        // A refused rerun must not upload a prior run's NEW/FIXED artifact.
        match fs::remove_file(results.join("diff.json")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(fail(format!("cannot clear stale comparison: {error}"))),
        }
        let candidate = load(&results.join(CANDIDATE_RECEIPT))?;
        // Compare only with the base executed in this run, on the same Mac and
        // with the same fixture bundle. A stored receipt from another host is
        // never a substitute; comparability is still checked below.
        let (base, base_evidence) = if request.kind == RequestKind::Main {
            (candidate.clone(), Ok(()))
        } else {
            let dir = results.join(BASE_DIR);
            verify_base_seal(results, &request.base)?;
            let base = load(&dir.join(BASE_RECEIPT))?;
            admit_paired_base(&base, accept_exit(&dir)?)?;
            let evidence = admit_evidence(&dir, &base).map(|_| ());
            (base, evidence)
        };
        validate_receipt(&base, &request.base)?;
        let diff = signed_receipt::compare(&base, &candidate)?;
        write(
            &results.join("diff.json"),
            serde_json::to_vec_pretty(&diff).map_err(|e| fail(e.to_string()))?,
        )?;
        let mut body = diff.markdown();
        body.push_str(&format!(
            "\nExecution host: {:?}\nFixture bundle: {:?}\n",
            candidate.host_identity, candidate.fixture_validation
        ));
        if request.kind != RequestKind::Main {
            body.push_str(&format!(
                "Paired base `{}` ran on the same host in this job.\n",
                request.base
            ));
        }
        if let Err(error) = &base_evidence {
            body.push_str(&format!("\nBase evidence admission failed: {error}\n"));
        }
        let valid = validate_receipt(&candidate, &request.sha);
        if let Err(error) = &valid {
            body.push_str(&format!("\nReceipt admission failed: {error}\n"));
        }
        let identity = admit_evidence(results, &candidate);
        match &identity {
            Err(error) => body.push_str(&format!("\nEvidence admission failed: {error}\n")),
            Ok(identity) => body.push_str(&format!(
                "\nArtifact identity:\n```json\n{}\n```\n",
                serde_json::to_string_pretty(identity).map_err(|e| fail(e.to_string()))?
            )),
        }
        let passed = diff.passed
            && valid.is_ok()
            && identity.is_ok()
            && base_evidence.is_ok()
            && execution_result == "success";
        Ok::<_, ReceiptError>((passed, body))
    })();
    let (passed, mut body, incomparable) = match comparison {
        Ok((passed, body)) => (passed, body, false),
        Err(error @ ReceiptError::IncomparableBase(_)) => (
            false,
            format!(
                "Signed gate: **INCOMPARABLE BASE — BLOCKED**\n\nCandidate `{}`; base `{}`\n\n{error}\n",
                request.sha, request.base
            ),
            true,
        ),
        Err(error) => (
            false,
            format!(
                "Signed gate: **FAIL**\n\nCandidate `{}`; base `{}`\n\nNo valid comparison: {error}\n",
                request.sha, request.base
            ),
            false,
        ),
    };
    if !passed && !body.starts_with("Signed gate: **FAIL**") && !incomparable {
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
    let description = if incomparable {
        "Incomparable base: host, fixture or incomplete base run; blocked"
    } else if passed {
        "No new failures; populations and completion preserved"
    } else {
        "Signed receipt regression or incomplete gate"
    };
    let status = post(
        &format!("repos/{REPOSITORY}/statuses/{}", request.sha),
        json!({"state": if passed {"success"} else {"failure"}, "context": "signed-gate", "description": description, "target_url": run_url}),
    );
    let comment = request.prs.iter().try_for_each(|pr| {
        post(
            &format!("repos/{REPOSITORY}/issues/{pr}/comments"),
            json!({"body": body}),
        )
    });
    status?;
    comment?;
    if incomparable {
        return Err(ReceiptError::IncomparableBase(
            "see comment and artifacts".into(),
        ));
    }
    if !passed {
        return Err(fail("signed gate FAIL; see comment and artifacts"));
    }
    Ok(())
}

pub fn run(root: &Path, args: SignedGateArgs) -> Result<(), ReceiptError> {
    match args.action {
        SignedGateAction::Prepare { event, output } => prepare(&event, &output),
        SignedGateAction::BaseFixtures {
            request,
            output,
            wait_minutes,
        } => base_fixtures(&request, &output, wait_minutes),
        SignedGateAction::CandidateProbes {
            request,
            bundle,
            output,
        } => candidate_probes(root, &request, &bundle, &output),
        SignedGateAction::Execute {
            request,
            output,
            fixture_bundle,
            candidate_probes,
        } => execute(
            root,
            &request,
            &output,
            &fixture_bundle,
            candidate_probes.as_deref(),
        ),
        SignedGateAction::Publish {
            request,
            results,
            run_url,
            execution_result,
        } => publish(&request, &results, &run_url, &execution_result),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    const TIMEOUT: &str = "fatal: unable to access 'https://github.com/carrick-sh/carrick/': Recv failure: Operation timed out";

    fn exit(code: i32, stderr: &str) -> CommandError {
        CommandError::NonZeroExit {
            program: "git".into(),
            status: ExitStatus::from_raw(code << 8),
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
    fn ok() -> CommandOutput {
        CommandOutput {
            status: ExitStatus::from_raw(0),
            stdout: String::new(),
            stderr: String::new(),
        }
    }
    /// Run `fetch_with_retry` against scripted results; returns the result,
    /// the invocation count and the recorded sleeps.
    fn drive(
        script: Vec<Result<CommandOutput, CommandError>>,
    ) -> (Result<CommandOutput, ReceiptError>, usize, Vec<Duration>) {
        let mut script = script.into_iter();
        let mut calls = 0;
        let mut sleeps = Vec::new();
        let result = fetch_with_retry(
            || {
                calls += 1;
                script.next().expect("more invocations than scripted")
            },
            |d| sleeps.push(d),
        );
        (result, calls, sleeps)
    }

    #[test]
    fn transient_failure_then_success_retries_once() {
        let (r, calls, sleeps) = drive(vec![Err(exit(128, TIMEOUT)), Ok(ok())]);
        assert!(r.is_ok());
        assert_eq!(calls, 2);
        assert_eq!(sleeps, vec![Duration::from_secs(2)]);
    }

    #[test]
    fn missing_ref_is_permanent() {
        let (r, calls, sleeps) = drive(vec![Err(exit(
            128,
            "fatal: couldn't find remote ref abc123",
        ))]);
        assert!(r.is_err());
        assert_eq!(calls, 1);
        assert!(sleeps.is_empty());
    }

    #[test]
    fn auth_failure_is_permanent() {
        let (r, calls, sleeps) = drive(vec![Err(exit(
            128,
            "remote: Authentication failed for 'https://github.com/x'",
        ))]);
        assert!(r.is_err());
        assert_eq!(calls, 1);
        assert!(sleeps.is_empty());
    }

    #[test]
    fn exhausted_transient_failures_return_last_error() {
        let (r, calls, sleeps) = drive(vec![
            Err(exit(128, TIMEOUT)),
            Err(exit(128, TIMEOUT)),
            Err(exit(128, TIMEOUT)),
        ]);
        assert!(r.is_err());
        assert_eq!(calls, 3);
        assert_eq!(sleeps, vec![Duration::from_secs(2), Duration::from_secs(4)]);
    }

    #[test]
    fn classifier_table() {
        for needle in [
            "Recv failure",
            "Operation timed out",
            "Connection reset by peer",
            "Could not resolve host: github.com",
            "SSL_connect: SSL_ERROR_SYSCALL",
            "gnutls_handshake() failed: The TLS connection was non-properly terminated",
            "OpenSSL SSL connection error",
            "operation timed out",
        ] {
            assert_eq!(
                classify_fetch_failure(&exit(128, &format!("fatal: {needle}"))),
                FetchFailure::Transient,
                "{needle}"
            );
            assert_eq!(
                classify_fetch_failure(&exit(1, &format!("fatal: {needle}"))),
                FetchFailure::Permanent,
                "exit 1: {needle}"
            );
        }
        assert_eq!(
            classify_fetch_failure(&exit(128, "fatal: Repository not found")),
            FetchFailure::Permanent
        );
        let spawn = CommandError::Spawn {
            program: "git".into(),
            source: std::io::Error::other("Recv failure"),
        };
        assert_eq!(classify_fetch_failure(&spawn), FetchFailure::Permanent);
    }
}
