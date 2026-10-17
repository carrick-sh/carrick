//! Work-order admission only, not a second PR bus. `/carrick-helper v1`
//! requests, conversation resumption and CI routing remain in agy_worker.py.
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use thiserror::Error;
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Debug, Error)]
pub enum WorkOrderError {
    // Never reflect public comment text or API error bodies into a prompt/comment.
    #[error("{0}")]
    Invalid(&'static str),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON transport failed")]
    Json(#[from] serde_json::Error),
}
type Result<T> = std::result::Result<T, WorkOrderError>;
fn invalid(message: &'static str) -> WorkOrderError {
    WorkOrderError::Invalid(message)
}

#[derive(Args, Debug)]
pub struct WorkOrderArgs {
    #[command(subcommand)]
    pub action: Action,
}
#[derive(Subcommand, Debug)]
pub enum Action {
    Lint {
        issue: u64,
        #[arg(long, default_value = "carrick-sh/carrick")]
        repo: String,
        /// Post a fixed ok/fail diagnostic, never public input text.
        #[arg(long)]
        post: bool,
    },
    Labels {
        /// Update existing labels whose color or description differs from the spec.
        #[arg(long)]
        overwrite: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Route {
    Design,
    Mechanical,
    Kvm,
    Hvf,
    Infra,
}
impl Route {
    fn label(&self) -> &'static str {
        match self {
            Self::Design => "route:design",
            Self::Mechanical => "route:mechanical",
            Self::Kvm => "route:kvm",
            Self::Hvf => "route:hvf",
            Self::Infra => "route:infra",
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Gate {
    Portable,
    Kvm,
    Signed,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub red_first: String,
    pub checks: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOrder {
    pub acceptance: Acceptance,
    pub fence: Vec<String>,
    pub route: Route,
    #[serde(default)]
    pub depends: Vec<String>,
    #[serde(default, rename = "stack-on")]
    pub stack_on: Option<String>,
    pub base: String,
    pub gates: Vec<Gate>,
    pub size_budget: u32,
    pub decisions: Vec<String>,
}

fn yaml_value(value: &Yaml) -> Result<Value> {
    Ok(match value {
        Yaml::String(s) => Value::String(s.clone()),
        Yaml::Integer(i) => json!(i),
        Yaml::Boolean(b) => json!(b),
        Yaml::Null => Value::Null,
        Yaml::Array(items) => Value::Array(items.iter().map(yaml_value).collect::<Result<_>>()?),
        Yaml::Hash(entries) => {
            let mut map = serde_json::Map::new();
            for (key, value) in entries {
                let key = key
                    .as_str()
                    .ok_or_else(|| invalid("YAML keys must be strings"))?;
                if map.insert(key.to_owned(), yaml_value(value)?).is_some() {
                    return Err(invalid("duplicate YAML key"));
                }
            }
            Value::Object(map)
        }
        _ => return Err(invalid("unsupported YAML value")),
    })
}

fn nonempty(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 2048 && !value.contains('\0')
}
fn github_link(value: &str, kind: &str) -> bool {
    ["carrick", "carrick-nt"].iter().any(|repo| {
        value
            .strip_prefix(&format!("https://github.com/carrick-sh/{repo}/{kind}/"))
            .is_some_and(|tail| {
                !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) && tail != "0"
            })
    })
}
fn relative_pattern(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_./-*?".contains(&c))
        && value
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}

fn is_order(body: &str) -> bool {
    body.lines().any(|line| {
        line.trim()
            .strip_prefix("work-order v")
            .is_some_and(|version| {
                !version.is_empty() && version.bytes().all(|c| c.is_ascii_digit())
            })
    })
}

pub fn parse(body: &str) -> Result<WorkOrder> {
    if body.len() > 16 * 1024 {
        return Err(invalid("work order exceeds 16 KiB"));
    }
    let lines: Vec<_> = body.trim().lines().collect();
    if lines.len() < 4
        || lines[0] != "work-order v1"
        || lines[1] != "```yaml"
        || lines.last() != Some(&"```")
        || lines[2..lines.len() - 1]
            .iter()
            .any(|line| line.trim().starts_with("```"))
    {
        return Err(invalid(
            "expected work-order v1 and exactly one fenced YAML document",
        ));
    }
    let yaml = lines[2..lines.len() - 1].join("\n");
    let documents =
        YamlLoader::load_from_str(&yaml).map_err(|_| invalid("invalid or duplicate-key YAML"))?;
    if documents.len() != 1 {
        return Err(invalid("expected one YAML document"));
    }
    let order: WorkOrder = serde_json::from_value(yaml_value(&documents[0])?)
        .map_err(|_| invalid("missing, unknown or wrongly typed work-order field"))?;
    if !nonempty(&order.acceptance.red_first)
        || order.acceptance.checks.is_empty()
        || order.acceptance.checks.len() > 64
        || !order.acceptance.checks.iter().all(|s| nonempty(s))
    {
        return Err(invalid(
            "acceptance requires a named red_first witness and 1-64 checks",
        ));
    }
    if order.fence.is_empty()
        || order.fence.len() > 64
        || !order.fence.iter().all(|s| relative_pattern(s))
    {
        return Err(invalid(
            "fence requires 1-64 relative globs using *, ** or ?",
        ));
    }
    if order.size_budget == 0 || order.size_budget > 4000 {
        return Err(invalid("size_budget must be 1-4000 changed lines"));
    }
    if order.gates.is_empty()
        || order.gates.len() > 3
        || order
            .gates
            .iter()
            .enumerate()
            .any(|(i, gate)| order.gates[..i].contains(gate))
        || (order.route == Route::Hvf && !order.gates.contains(&Gate::Signed))
        || (order.route == Route::Kvm && !order.gates.contains(&Gate::Kvm))
    {
        return Err(invalid(
            "invalid gates; hvf requires signed, kvm requires kvm",
        ));
    }
    if !order
        .depends
        .iter()
        .all(|s| github_link(s, "issues") || github_link(s, "pull"))
        || order.depends.len() > 64
        || order
            .stack_on
            .as_ref()
            .is_some_and(|s| !github_link(s, "pull"))
        || (order.stack_on.is_some() && !order.depends.is_empty())
        || (order.stack_on.is_none() && order.base != "main")
        || !relative_pattern(&order.base)
        || order.base.contains(['*', '?'])
        || order.base.starts_with('-')
        || order.base.contains("..")
        || order.base.ends_with(".lock")
    {
        return Err(invalid(
            "invalid dependencies or base; non-main base requires stack-on PR",
        ));
    }
    if !order.decisions.iter().all(|s| {
        s.strip_prefix("https://github.com/carrick-sh/carrick/issues/231#issuecomment-")
            .is_some_and(|id| !id.is_empty() && id.bytes().all(|c| c.is_ascii_digit()))
    }) {
        return Err(invalid("decisions must link to decision-log #231 comments"));
    }
    Ok(order)
}

#[derive(Debug, Serialize)]
pub struct Admission {
    pub comment_id: u64,
    pub updated_at: String,
    pub workorder_sha256: String,
    pub label_event_ids: Vec<u64>,
    pub order: WorkOrder,
}

pub const HOLD_LABELS: [&str; 3] = ["needs-owner", "blocked", "stalled"];

pub fn validate_hold_definitions(definitions: &[Value]) -> Result<()> {
    if definitions.len() != HOLD_LABELS.len() {
        return Err(invalid("hold-label definition missing or renamed"));
    }
    for (expected, definition) in HOLD_LABELS.iter().zip(definitions.iter()) {
        if definition["name"].as_str() != Some(*expected) {
            return Err(invalid("hold-label definition missing or renamed"));
        }
    }
    Ok(())
}

/// `writers` is populated by the PR bus's same write/maintain/admin permission
/// rule, not by author_association or the label's mere presence.
pub fn validate_provenance(
    labels: &[String],
    comments: &[Value],
    events: &[Value],
    allowlist: &BTreeSet<String>,
    writers: &BTreeSet<String>,
) -> Result<Admission> {
    let trusted = |login: &str| allowlist.contains(login) && writers.contains(login);
    if !labels.iter().any(|l| l == "ready")
        || labels.iter().any(|l| HOLD_LABELS.contains(&l.as_str()))
        || labels.iter().filter(|l| l.starts_with("route:")).count() != 1
    {
        return Err(invalid(
            "requires ready, one route label and no blocked/needs-owner/stalled",
        ));
    }
    for hold in HOLD_LABELS {
        let latest = events.iter().rev().find(|event| {
            event["label"]["name"].as_str() == Some(hold)
                && matches!(event["event"].as_str(), Some("labeled" | "unlabeled"))
        });
        let event_held = latest.is_some_and(|event| event["event"] == "labeled");
        let currently_held = labels.iter().any(|l| l == hold);
        if event_held != currently_held || event_held || currently_held {
            return Err(invalid(
                "hold label active or event-derived hold state disagrees with current labels",
            ));
        }
        if let Some(event) = latest
            && event["event"] == "unlabeled"
            && !trusted(event["actor"]["login"].as_str().unwrap_or(""))
        {
            return Err(invalid(
                "hold-label removal requires an allowlisted write identity",
            ));
        }
    }
    if let Some(event) = events
        .iter()
        .rev()
        .find(|event| matches!(event["event"].as_str(), Some("closed" | "reopened")))
        && event["event"] == "reopened"
        && !trusted(event["actor"]["login"].as_str().unwrap_or(""))
    {
        return Err(invalid(
            "issue reopen requires an allowlisted write identity",
        ));
    }
    let mut candidates = Vec::new();
    for comment in comments {
        let author = comment["user"]["login"].as_str().unwrap_or("");
        if !trusted(author) {
            continue;
        }
        let body = comment["body"]
            .as_str()
            .ok_or_else(|| invalid("missing comment body"))?;
        if !is_order(body) {
            continue;
        }
        let order = match parse(body) {
            Ok(order) => order,
            Err(err) => {
                eprintln!(
                    "workorder: skipping comment {} with invalid work-order syntax: {err}",
                    comment["id"].as_u64().unwrap_or(0)
                );
                continue;
            }
        };
        let created = comment["created_at"]
            .as_str()
            .ok_or_else(|| invalid("missing comment timestamp"))?;
        if created.is_empty()
            || comment["updated_at"].as_str() != Some(created)
            || comment.get("lastEditedAt") != Some(&Value::Null)
        {
            return Err(invalid(
                "work-order comments must be unedited; post a replacement after retiring the old order",
            ));
        }
        if !labels.iter().any(|label| label == order.route.label()) {
            return Err(invalid("work-order route does not match current label"));
        }
        let mut label_event_ids = Vec::new();
        let mut ready_index = 0;
        for label in ["ready", order.route.label()] {
            let (idx, event) = events
                .iter()
                .enumerate()
                .rev()
                .find(|(_, event)| {
                    event["label"]["name"].as_str() == Some(label)
                        && matches!(event["event"].as_str(), Some("labeled" | "unlabeled"))
                })
                .ok_or_else(|| invalid("missing current label event"))?;
            if event["event"] != "labeled"
                || !trusted(event["actor"]["login"].as_str().unwrap_or(""))
            {
                return Err(invalid(
                    "current ready and route label events require allowlisted write identities",
                ));
            }
            if label == "ready" {
                ready_index = idx;
            }
            label_event_ids.push(
                event["id"]
                    .as_u64()
                    .ok_or_else(|| invalid("missing label event id"))?,
            );
        }
        for event in &events[ready_index + 1..] {
            let actor = event["actor"]["login"].as_str().unwrap_or("");
            let kind = event["event"].as_str().unwrap_or("");
            if matches!(kind, "unlabeled" | "reopened" | "comment_deleted") && !trusted(actor) {
                return Err(invalid(
                    "untrusted label removal, reopen or comment deletion after ready invalidates admission",
                ));
            }
        }
        candidates.push(Admission {
            comment_id: comment["id"]
                .as_u64()
                .ok_or_else(|| invalid("missing comment id"))?,
            updated_at: created.to_owned(),
            workorder_sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            label_event_ids,
            order,
        });
    }
    if candidates.len() != 1 {
        return Err(invalid(
            "expected exactly one trusted, unedited work-order comment",
        ));
    }
    candidates
        .pop()
        .ok_or_else(|| invalid("missing work order"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    allowlist: BTreeSet<String>,
    repositories: BTreeSet<String>,
}

fn git_stdout(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .current_dir(root)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

fn load_policy(root: &Path) -> Result<Policy> {
    let raw = if let Some(text) =
        git_stdout(root, &["show", "origin/main:.github/pull-claims.toml"])
    {
        text
    } else {
        let head = git_stdout(root, &["symbolic-ref", "-q", "HEAD"])
            .ok_or_else(|| invalid("trusted policy requires origin/main or clean main checkout"))?;
        let status = git_stdout(root, &["status", "--porcelain"])
            .ok_or_else(|| invalid("trusted policy requires origin/main or clean main checkout"))?;
        if head.trim() != "refs/heads/main" || !status.trim().is_empty() {
            return Err(invalid(
                "trusted policy requires origin/main or clean main checkout",
            ));
        }
        git_stdout(root, &["show", "HEAD:.github/pull-claims.toml"])
            .ok_or_else(|| invalid("trusted policy missing on main"))?
    };
    let policy: Policy = toml::from_str(&raw).map_err(|_| invalid("invalid trusted policy"))?;
    if policy.repositories.is_empty()
        || policy.allowlist.is_empty()
        || policy.allowlist.iter().any(|login| {
            login.is_empty()
                || !login
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err(invalid("invalid trusted policy"));
    }
    Ok(policy)
}

fn request(method: &str, endpoint: &str, body: Option<Value>, paginate: bool) -> Result<Value> {
    let mut cmd = Command::new("gh");
    cmd.args(["api", "--method", method, endpoint]);
    if paginate {
        cmd.args(["--paginate", "--slurp"]);
    }
    let mut input = tempfile::tempfile()?;
    if let Some(body) = body {
        serde_json::to_writer(&mut input, &body)?;
        use std::io::{Seek, SeekFrom};
        input.seek(SeekFrom::Start(0))?;
        cmd.args(["--input", "-"]);
    }
    let out = cmd.stdin(Stdio::from(input)).output()?;
    if !out.status.success() {
        return Err(invalid("GitHub API unavailable or permission denied"));
    }
    serde_json::from_slice(&out.stdout).map_err(|_| invalid("invalid GitHub API JSON"))
}
fn pages(endpoint: &str) -> Result<Vec<Value>> {
    let pages = request("GET", endpoint, None, true)?;
    let mut result = Vec::new();
    for page in pages
        .as_array()
        .ok_or_else(|| invalid("invalid API pages"))?
    {
        result.extend(
            page.as_array()
                .ok_or_else(|| invalid("invalid API page"))?
                .iter()
                .cloned(),
        );
    }
    Ok(result)
}
fn labels(issue: &Value) -> Result<Vec<String>> {
    issue["labels"]
        .as_array()
        .ok_or_else(|| invalid("missing issue labels"))?
        .iter()
        .map(|label| {
            label["name"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("invalid label"))
        })
        .collect()
}
fn edit_status(comment: &mut Value) -> Result<()> {
    let id = comment["node_id"]
        .as_str()
        .ok_or_else(|| invalid("missing comment node id"))?;
    let value = request(
        "POST",
        "graphql",
        Some(json!({
            "query": "query($id: ID!) { node(id: $id) { ... on IssueComment { lastEditedAt } } }",
            "variables": {"id": id}
        })),
        false,
    )?;
    let edited = value
        .pointer("/data/node/lastEditedAt")
        .ok_or_else(|| invalid("comment edit provenance unavailable"))?;
    comment["lastEditedAt"] = edited.clone();
    Ok(())
}

fn same_comment(left: &Value, right: &Value) -> bool {
    left["id"].as_u64() == right["id"].as_u64()
        && left["user"]["id"].as_u64() == right["user"]["id"].as_u64()
        && left["user"]["login"].as_str() == right["user"]["login"].as_str()
        && left["body"].as_str() == right["body"].as_str()
        && left["created_at"].as_str() == right["created_at"].as_str()
        && left["updated_at"].as_str() == right["updated_at"].as_str()
        && left.get("lastEditedAt") == right.get("lastEditedAt")
}

fn same_issue(left: &Value, right: &Value) -> Result<bool> {
    Ok(left["id"].as_u64() == right["id"].as_u64()
        && left["state"].as_str() == right["state"].as_str()
        && left.get("pull_request").is_some() == right.get("pull_request").is_some()
        && labels(left)? == labels(right)?)
}

fn lint(root: &Path, repo: &str, issue: u64) -> Result<Admission> {
    let policy = load_policy(root)?;
    if issue == 0 || !policy.repositories.contains(repo) {
        return Err(invalid(
            "issue/repository or trusted identity is not allowed",
        ));
    }
    let endpoint = format!("repos/{repo}/issues/{issue}");
    let original = request("GET", &endpoint, None, false)?;
    if original["state"] != "open" || original.get("pull_request").is_some() {
        return Err(invalid("work orders require an open issue, not a PR"));
    }
    let mut hold_definitions = Vec::with_capacity(HOLD_LABELS.len());
    for hold in HOLD_LABELS {
        hold_definitions.push(request(
            "GET",
            &format!("repos/{repo}/labels/{hold}"),
            None,
            false,
        )?);
    }
    validate_hold_definitions(&hold_definitions)?;
    let mut writers = BTreeSet::new();
    for login in &policy.allowlist {
        let permission = request(
            "GET",
            &format!("repos/{repo}/collaborators/{login}/permission"),
            None,
            false,
        )?;
        if matches!(
            permission["permission"].as_str(),
            Some("write" | "maintain" | "admin")
        ) {
            writers.insert(login.clone());
        }
    }
    let mut comments = pages(&format!("{endpoint}/comments?per_page=100"))?;
    // Drop public input before parsing or inspecting it, as the PR bus does.
    comments.retain(|c| {
        c["user"]["login"]
            .as_str()
            .is_some_and(|login| writers.contains(login))
    });
    for comment in &mut comments {
        if comment["body"].as_str().is_some_and(is_order) {
            edit_status(comment)?;
        }
    }
    let events = pages(&format!("{endpoint}/events?per_page=100"))?;
    let admission = validate_provenance(
        &labels(&original)?,
        &comments,
        &events,
        &policy.allowlist,
        &writers,
    )?;
    let mut current = request(
        "GET",
        &format!("repos/{repo}/issues/comments/{}", admission.comment_id),
        None,
        false,
    )?;
    edit_status(&mut current)?;
    let fresh = request("GET", &endpoint, None, false)?;
    let admitted = comments
        .iter()
        .find(|c| c["id"].as_u64() == Some(admission.comment_id))
        .ok_or_else(|| invalid("admitted comment missing"))?;
    if !same_issue(&fresh, &original)? || !same_comment(admitted, &current) {
        return Err(invalid(
            "issue or work order changed during lint; admission refused",
        ));
    }
    Ok(admission)
}

const REQUIRED_LABELS: [(&str, &str, &str); 9] = [
    (
        "ready",
        "0E8A16",
        "Claimable only with trusted label provenance and a valid work-order v1",
    ),
    (
        "route:design",
        "5319E7",
        "Strong design-capable worker: shared kernel, mm, fork, signals, carrier or seams",
    ),
    (
        "route:mechanical",
        "5319E7",
        "Precisely specified mechanical work for a fast worker",
    ),
    (
        "route:kvm",
        "5319E7",
        "Requires build and tests on a Linux x86_64 KVM host",
    ),
    (
        "route:hvf",
        "5319E7",
        "Requires a macOS build and the signed gate",
    ),
    (
        "route:infra",
        "5319E7",
        "Hosts, CI and scripts; no guest-visible change",
    ),
    (
        "needs-review",
        "FBCA04",
        "Independent-review job for the current PR head",
    ),
    (
        "needs-signed-gate",
        "FBCA04",
        "Queued for the Mac signed-gate service at the current PR head",
    ),
    (
        "stalled",
        "D93F0B",
        "Claim expired twice or exhausted its budget; return to triage",
    ),
];

const CARRICK_NT_MIRROR_LABELS: [(&str, &str, &str); 2] = [
    (
        "needs-owner",
        "B60205",
        "Blocked pending an owner decision recorded in the decision log",
    ),
    (
        "seam",
        "1D76DB",
        "Depends on a personality-neutral seam tracked in carrick",
    ),
];

fn sync_labels(root: &Path, overwrite: bool, writer: &mut impl Write) -> Result<()> {
    let policy = load_policy(root)?;
    let mut operations = Vec::new();
    for repo in &policy.repositories {
        let existing = pages(&format!("repos/{repo}/labels?per_page=100"))?;
        let extra = if repo == "carrick-sh/carrick-nt" {
            &CARRICK_NT_MIRROR_LABELS[..]
        } else {
            &[][..]
        };
        for &(name, color, description) in REQUIRED_LABELS.iter().chain(extra.iter()) {
            if let Some(found) = existing
                .iter()
                .find(|label| label["name"].as_str() == Some(name))
            {
                let same_color = found["color"]
                    .as_str()
                    .is_some_and(|c| c.eq_ignore_ascii_case(color));
                let same_desc = found["description"].as_str().unwrap_or("") == description;
                if same_color && same_desc {
                    continue;
                }
                if !overwrite {
                    return Err(invalid(
                        "existing label definition differs; pass --overwrite to update",
                    ));
                }
                operations.push((
                    "PATCH",
                    format!("repos/{repo}/labels/{name}"),
                    json!({"new_name": name, "color": color, "description": description}),
                ));
            } else {
                operations.push((
                    "POST",
                    format!("repos/{repo}/labels"),
                    json!({"name": name, "color": color, "description": description}),
                ));
            }
        }
    }
    for (method, endpoint, payload) in &operations {
        request(method, endpoint, Some(payload.clone()), false)?;
    }
    writeln!(
        writer,
        "synchronized {} label operation(s)",
        operations.len()
    )?;
    Ok(())
}

pub fn run(root: &Path, args: WorkOrderArgs, writer: &mut impl Write) -> Result<()> {
    match args.action {
        Action::Labels { overwrite } => sync_labels(root, overwrite, writer),
        Action::Lint { issue, repo, post } => {
            let result = lint(root, &repo, issue);
            if post {
                // Validate the destination independently, even when lint failed.
                let policy = load_policy(root)?;
                if issue == 0 || !policy.repositories.contains(&repo) {
                    return Err(invalid("invalid comment destination"));
                }
                let body = match &result {
                    Ok(admission) => format!(
                        "work-order v1 lint: **ok**\n\nComment {} (updated_at `{}`), SHA-256 `{}`. This is a lint receipt, not a claim or landing authorization.",
                        admission.comment_id, admission.updated_at, admission.workorder_sha256
                    ),
                    Err(_) => "work-order v1 lint: **fail**\n\nSchema or provenance validation failed; see the hosted run. No claim is authorized.".into(),
                };
                request(
                    "POST",
                    &format!("repos/{repo}/issues/{issue}/comments"),
                    Some(json!({"body": body})),
                    false,
                )?;
            }
            let admission = result?;
            serde_json::to_writer_pretty(&mut *writer, &admission)?;
            writeln!(writer)?;
            Ok(())
        }
    }
}
