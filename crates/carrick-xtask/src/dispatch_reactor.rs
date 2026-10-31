//! Dispatch reactor (#1193): a poll loop on the owner's Mac that turns new PR
//! conversation into at most one visible `/agent` round or reply per PR.
//!
//! The agent only proposes a JSON decision. Every effect is checked here: a
//! round needs an adoptable or owned PR, no dispatch run in flight for it and
//! fewer than [`GLOBAL_CAP`] runs in flight overall; a reply may not be a
//! command. The reactor never merges, pushes, edits, labels or closes.
use super::{AdoptionRead, REPOSITORY, ScalerError, adopted_pr, dispatch_branch};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[path = "dispatch_reactor_session.rs"]
mod session;

pub(crate) const MARKER: &str = "<!-- carrick-reactor -->";
const GLOBAL_CAP: usize = 4;
const QUIET_SECS: u64 = 15 * 60;
const SEEN_LIMIT: usize = 200;
const BODY_LIMIT: usize = 1500;
const CLOSES_ASK: &str = "This PR needs exactly one closing reference (`Closes #N`, an open owner-authored issue) before dispatch can adopt it for a round.";

#[derive(clap::Subcommand, Debug)]
pub enum Mode {
    /// One poll cycle.
    Once(Opts),
    /// Poll every 60 seconds until killed.
    Run(Opts),
    /// Append new PR events to a mailbox for a listening session.
    Feed(session::FeedOpts),
    /// Stdio MCP server with the session's read and act tools.
    Mcp(session::McpOpts),
}
#[derive(clap::Args, Debug)]
pub struct Opts {
    /// Print decisions and would-be comments; post nothing, keep state unchanged.
    #[arg(long)]
    dry_run: bool,
    /// State file (cursor and per-PR memory).
    #[arg(long)]
    state: Option<PathBuf>,
    /// Reactor epoch override (`YYYY-MM-DDTHH:MM:SSZ`): only PRs created since
    /// get quiet pickup and the closing-reference ask.
    #[arg(long)]
    since: Option<String>,
    /// Model for the deciding agent (`claude -p --model`).
    #[arg(long, default_value = "sonnet")]
    model: String,
}

/// GitHub reads and the one write the reactor may make.
pub(crate) trait Github {
    /// REST open pull requests.
    fn open_prs(&mut self) -> Result<Vec<Value>, ScalerError>;
    /// GraphQL open PR nodes: number, last commit (date, CI), reviews, comments.
    fn pr_facts(&mut self) -> Result<Vec<Value>, ScalerError>;
    /// REST issue comments and PR review comments updated at or after `since`.
    fn comments(&mut self, since: &str) -> Result<Vec<Value>, ScalerError>;
    fn adoption(&mut self, read: AdoptionRead) -> Result<Value, ScalerError>;
    /// `gh run list --workflow dispatch-worker.yml` rows.
    fn runs(&mut self) -> Result<Vec<Value>, ScalerError>;
    fn post(&mut self, pr: u64, body: &str) -> Result<(), ScalerError>;
}
/// The deciding agent; tests substitute a fake.
pub(crate) trait Agent {
    fn decide(&mut self, context: &str) -> Result<Decision, ScalerError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Act {
    Ignore,
    Reply,
    Round,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Decision {
    pub action: Act,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct State {
    /// First real run; automatic pickup and asks apply only to PRs created since.
    epoch: Option<String>,
    cursor: Option<String>,
    prs: BTreeMap<u64, Memory>,
}
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct Memory {
    rounds: u32,
    closes_asked: bool,
    candidate_head: Option<String>,
    last_round_head: Option<String>,
    last_round_at: Option<String>,
    /// A non-bot, non-reactor comment arrived after the last reactor round.
    human_since_round: bool,
    seen: Vec<String>,
}

/// What the rule layer knows about one PR when executing a decision.
pub(crate) struct Gate {
    pub eligible: bool,
    pub pr_run_active: bool,
    pub active_total: usize,
    /// The reactor already posted a round on this head and no human spoke since.
    pub repeat_round: bool,
}
/// The only effects the rule layer can produce.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Effect {
    None,
    Post(String),
    Refused(&'static str),
}

/// Hard rules: the agent's decision becomes a comment only through here.
pub(crate) fn enforce(decision: &Decision, gate: &Gate) -> Effect {
    let text = decision.text.trim();
    match decision.action {
        Act::Ignore => Effect::None,
        Act::Reply if text.is_empty() => Effect::Refused("empty reply"),
        Act::Reply if text.starts_with("/agent") => Effect::Refused("reply may not be a command"),
        Act::Reply => Effect::Post(format!("{text}\n\n{MARKER}")),
        Act::Round if !gate.eligible => Effect::Refused("PR is neither adoptable nor owned"),
        Act::Round if gate.pr_run_active => Effect::Refused("dispatch run in flight for this PR"),
        Act::Round if gate.active_total >= GLOBAL_CAP => Effect::Refused("global dispatch cap"),
        Act::Round if gate.repeat_round => {
            Effect::Refused("already rounded this head; waiting for a human comment")
        }
        Act::Round if text.is_empty() || text.contains(MARKER) => Effect::Refused("invalid brief"),
        Act::Round => Effect::Post(format!("/agent {text}\n\n{MARKER}")),
    }
}

fn bot(user: &Value) -> bool {
    user["type"] == "Bot"
        || user["__typename"] == "Bot"
        || user["login"].as_str().is_none_or(|l| l.ends_with("[bot]"))
}
/// Bots whose dispatch outcome comments are events.
const OUTCOME_BOTS: [&str; 2] = ["github-actions[bot]", "carrick-workers[bot]"];
/// How a comment or review counts: `None` is not an event (reactor-marked, or
/// a bot other than a dispatch outcome). `trigger` asks for a decision; an
/// owner `/agent` command does not (the dispatch workflow handles it) but is
/// still `human`, which re-enables a round on the same head.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Class {
    pub trigger: bool,
    pub human: bool,
}
/// The owner's account, which director sessions also post as. The repository
/// is public: text from anyone else could steer an `/agent` brief posted with
/// owner authority, so only this author is an event, counts as human or has
/// its body shown to the session.
pub(crate) fn trusted_owner(user: &Value) -> bool {
    user["login"] == "tjfontaine" && (user["type"] == "User" || user["__typename"] == "User")
}
/// An allowlisted workflow bot, whose dispatch outcome comments are events.
pub(crate) fn outcome_bot(user: &Value) -> bool {
    bot(user) && OUTCOME_BOTS.contains(&user["login"].as_str().unwrap_or_default())
}
pub(crate) fn classify(user: &Value, body: &str) -> Option<Class> {
    if body.contains(MARKER) {
        return None;
    }
    if outcome_bot(user) && body.contains("Dispatch outcome") {
        return Some(Class {
            trigger: true,
            human: false,
        });
    }
    // Everyone else, bot or stranger, is dropped and advances no guard.
    trusted_owner(user).then(|| Class {
        trigger: !body.trim_start().starts_with("/agent"),
        human: true,
    })
}

/// Same-repository `work/*` PR into main by the owner or publish App: the
/// PRs this owner-local reactor watches. Adoption itself no longer checks
/// the PR author (#1214); the reactor posts `/agent` as the owner, so it
/// deliberately stays on the owner's and the App's PRs.
fn director_pr(pr: &Value) -> bool {
    let branch = pr["head"]["ref"].as_str().unwrap_or_default();
    pr["head"]["repo"]["full_name"] == REPOSITORY
        && pr["base"]["ref"] == "main"
        && branch.starts_with("work/")
        && dispatch_branch(branch).is_none()
        && ((pr["user"]["login"] == "tjfontaine" && pr["user"]["type"] == "User")
            || super::publish_app_author(&pr["user"]))
}
fn owned_pr(pr: &Value) -> bool {
    pr["head"]["repo"]["full_name"] == REPOSITORY
        && dispatch_branch(pr["head"]["ref"].as_str().unwrap_or_default()).is_some()
}

fn clip(text: &str) -> String {
    let mut end = text.len().min(BODY_LIMIT);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

pub(super) struct Event {
    pub id: String,
    pub who: String,
    pub kind: &'static str,
    pub body: String,
    pub class: Class,
    pub at: String,
    pub url: String,
}

/// Everything one poll reads, shared by `cycle` and the session feed.
pub(super) struct Gathered {
    pub prs: Vec<Value>,
    pub facts: BTreeMap<u64, Value>,
    pub active: Vec<Value>,
    pub events: BTreeMap<u64, Vec<Event>>,
    pub cursor: String,
}
pub(super) fn gather(gh: &mut dyn Github, since: &str) -> Result<Gathered, ScalerError> {
    let since = since.to_owned();
    let prs = gh.open_prs()?;
    let facts: BTreeMap<u64, Value> = gh
        .pr_facts()?
        .into_iter()
        .filter_map(|n| Some((n["number"].as_u64()?, n)))
        .collect();
    let comments = gh.comments(&since)?;
    let active: Vec<Value> = gh
        .runs()?
        .into_iter()
        .filter(|r| r["status"] != "completed")
        .collect();
    let mut cursor = since.clone();
    let mut events: BTreeMap<u64, Vec<Event>> = BTreeMap::new();
    for c in &comments {
        let url = c["pull_request_url"]
            .as_str()
            .or(c["issue_url"].as_str())
            .unwrap_or_default();
        let (Some(pr), Some(at)) = (
            url.rsplit('/').next().and_then(|n| n.parse().ok()),
            c["updated_at"].as_str(),
        ) else {
            continue;
        };
        if at > cursor.as_str() {
            cursor = at.to_owned();
        }
        let kind = if c.get("pull_request_url").is_some() {
            "review_comment"
        } else {
            "comment"
        };
        let body = c["body"].as_str().unwrap_or_default();
        if let Some(class) = classify(&c["user"], body) {
            events.entry(pr).or_default().push(Event {
                id: format!("{kind}:{}:{at}", c["id"]),
                who: c["user"]["login"].as_str().unwrap_or("?").to_owned(),
                kind,
                body: body.to_owned(),
                class,
                at: c["created_at"].as_str().unwrap_or(at).to_owned(),
                url: c["html_url"].as_str().unwrap_or_default().to_owned(),
            });
        }
    }
    for (number, node) in &facts {
        for r in node["reviews"]["nodes"].as_array().into_iter().flatten() {
            let (at, body) = (
                r["submittedAt"].as_str().unwrap_or_default(),
                r["body"].as_str().unwrap_or_default(),
            );
            if at < since.as_str() {
                continue;
            }
            if let Some(class) = classify(&r["author"], body) {
                events.entry(*number).or_default().push(Event {
                    id: format!("review:{}", r["databaseId"]),
                    who: r["author"]["login"].as_str().unwrap_or("?").to_owned(),
                    kind: "review",
                    body: format!("[{}] {body}", r["state"].as_str().unwrap_or("")),
                    class,
                    at: at.to_owned(),
                    url: r["url"].as_str().unwrap_or_default().to_owned(),
                });
            }
        }
    }
    Ok(Gathered {
        prs,
        facts,
        active,
        events,
        cursor,
    })
}

/// Adoption verdict and closing-reference count for a director PR.
pub(super) fn adoption_facts(
    gh: &mut dyn Github,
    pr: &Value,
) -> Result<(bool, Option<usize>), ScalerError> {
    let mut closing = None;
    let adoption = adopted_pr(pr, |read| {
        let value = gh.adoption(read)?;
        if value.get("data").is_some() {
            closing = Some(value.clone());
        }
        Ok(value)
    })?;
    let count = closing
        .as_ref()
        .and_then(|c| super::parse_closing_references(c).ok())
        .map(|r| r.all.len());
    Ok((adoption.is_some(), count))
}

/// One poll cycle. Returns the human log lines it would print.
pub(crate) fn cycle(
    gh: &mut dyn Github,
    agent: &mut dyn Agent,
    state: &mut State,
    now: u64,
    epoch: &str,
    dry_run: bool,
) -> Result<Vec<String>, ScalerError> {
    let mut log = Vec::new();
    let since = state
        .cursor
        .clone()
        .unwrap_or_else(|| iso(now.saturating_sub(3600)));
    let Gathered {
        prs,
        facts,
        active,
        mut events,
        cursor,
    } = gather(gh, &since)?;
    let open: Vec<u64> = prs.iter().filter_map(|p| p["number"].as_u64()).collect();
    state.prs.retain(|n, _| open.contains(n));
    let mut active_total = active.len();
    for pr in &prs {
        let Some(number) = pr["number"].as_u64() else {
            continue;
        };
        if pr["labels"]
            .as_array()
            .is_some_and(|l| l.iter().any(|l| l["name"] == "agent:hold"))
        {
            continue;
        }
        let memory = state.prs.entry(number).or_default();
        let mut fresh: Vec<Event> = events
            .remove(&number)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| !memory.seen.contains(&e.id))
            .collect();
        let head = pr["head"]["sha"].as_str().unwrap_or_default().to_owned();
        let owned = owned_pr(pr);
        let director = director_pr(pr);
        let node = facts.get(&number).cloned().unwrap_or(Value::Null);
        let commit = &node["commits"]["nodes"][0]["commit"];
        let mut adoptable = false;
        // Automatic behaviours only for PRs created since the reactor's epoch.
        let recent = pr["created_at"].as_str().is_some_and(|c| c >= epoch);
        if director {
            let (verdict, count) = adoption_facts(gh, pr)?;
            adoptable = verdict;
            if recent && count != Some(1) && !memory.closes_asked {
                memory.closes_asked = true;
                let body = format!("{CLOSES_ASK}\n\n{MARKER}");
                log.push(format!("#{number}: ask for a closing reference"));
                emit(gh, number, &body, dry_run, &mut log)?;
            }
            let quiet = commit["committedDate"]
                .as_str()
                .is_some_and(|d| d <= iso(now.saturating_sub(QUIET_SECS)).as_str());
            if adoptable
                && recent
                && quiet
                && memory.rounds == 0
                && memory.candidate_head.as_deref() != Some(head.as_str())
            {
                memory.candidate_head = Some(head.clone());
                fresh.push(Event {
                    id: format!("candidate:{head}"),
                    who: "reactor".into(),
                    kind: "candidate",
                    body: "Adoptable director PR, no push for 15 minutes, no reactor round yet."
                        .into(),
                    class: Class {
                        trigger: true,
                        human: false,
                    },
                    at: iso(now),
                    url: String::new(),
                });
            }
        }
        for e in &fresh {
            memory.seen.push(e.id.clone());
            memory.human_since_round |= e.class.human;
        }
        let excess = memory.seen.len().saturating_sub(SEEN_LIMIT);
        memory.seen.drain(..excess);
        if !fresh.iter().any(|e| e.class.trigger) {
            continue;
        }
        let title = pr["title"].as_str().unwrap_or_default();
        let branch = pr["head"]["ref"].as_str().unwrap_or_default();
        let pr_run_active = active
            .iter()
            .any(|r| r["displayTitle"] == title || r["headBranch"] == branch);
        let mut context = format!(
            "PR #{number}: {title}\nbranch {branch} head {head}\nCI: {}\nadoptable: {adoptable}, owned dispatch PR: {owned}, reactor rounds so far: {}, dispatch run in flight: {pr_run_active}\n\n## Recent comments\n",
            commit["statusCheckRollup"]["state"]
                .as_str()
                .unwrap_or("none"),
            memory.rounds
        );
        for c in node["comments"]["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| classify(&c["author"], c["body"].as_str().unwrap_or_default()).is_some())
        {
            context.push_str(&format!(
                "\n### {}\n{}\n",
                c["author"]["login"].as_str().unwrap_or("?"),
                clip(c["body"].as_str().unwrap_or_default())
            ));
        }
        context.push_str("\n## New events\n");
        for e in &fresh {
            context.push_str(&format!(
                "\n### {} by {}\n{}\n",
                e.kind,
                e.who,
                clip(&e.body)
            ));
        }
        let decision = agent.decide(&context)?;
        log.push(format!(
            "#{number}: decision {:?}: {}",
            decision.action, decision.reason
        ));
        let gate = Gate {
            eligible: adoptable || owned,
            pr_run_active,
            active_total,
            repeat_round: memory.last_round_head.as_deref() == Some(head.as_str())
                && !memory.human_since_round,
        };
        match enforce(&decision, &gate) {
            Effect::None => {}
            Effect::Refused(why) => log.push(format!("#{number}: refused: {why}")),
            Effect::Post(body) => {
                if decision.action == Act::Round {
                    memory.rounds += 1;
                    memory.last_round_head = Some(head.clone());
                    memory.last_round_at = Some(iso(now));
                    memory.human_since_round = false;
                    active_total += 1;
                }
                emit(gh, number, &body, dry_run, &mut log)?;
            }
        }
    }
    state.cursor = Some(cursor);
    Ok(log)
}
fn emit(
    gh: &mut dyn Github,
    number: u64,
    body: &str,
    dry_run: bool,
    log: &mut Vec<String>,
) -> Result<(), ScalerError> {
    if dry_run {
        log.push(format!("#{number}: would post:\n{body}"));
        Ok(())
    } else {
        log.push(format!("#{number}: posted"));
        gh.post(number, body)
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ`, the only epoch spelling accepted.
fn rfc3339(text: &str) -> bool {
    regex::Regex::new(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$").is_ok_and(|re| re.is_match(text))
}

/// UTC `YYYY-MM-DDTHH:MM:SSZ`, the shape GitHub returns (sorts lexically).
pub(crate) fn iso(secs: u64) -> String {
    let (days, rem) = ((secs / 86400) as i64, secs % 86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

struct Live<'a> {
    root: &'a Path,
}
const FACTS_QUERY: &str = r#"query{repository(owner:"carrick-sh",name:"carrick"){pullRequests(states:OPEN,first:100){nodes{number commits(last:1){nodes{commit{committedDate statusCheckRollup{state}}}} reviews(last:10){nodes{databaseId url state body submittedAt author{login __typename}}} comments(last:5){nodes{body author{login __typename}}}}}}}"#;
impl Github for Live<'_> {
    fn open_prs(&mut self) -> Result<Vec<Value>, ScalerError> {
        Ok(serde_json::from_str(&super::gh(
            self.root,
            &[
                "api",
                &format!("repos/{REPOSITORY}/pulls?state=open&per_page=100"),
            ],
        )?)?)
    }
    fn pr_facts(&mut self) -> Result<Vec<Value>, ScalerError> {
        let v: Value = serde_json::from_str(&super::gh(
            self.root,
            &["api", "graphql", "-f", &format!("query={FACTS_QUERY}")],
        )?)?;
        Ok(v["data"]["repository"]["pullRequests"]["nodes"]
            .as_array()
            .cloned()
            .unwrap_or_default())
    }
    fn comments(&mut self, since: &str) -> Result<Vec<Value>, ScalerError> {
        let mut all = Vec::new();
        for kind in ["issues", "pulls"] {
            let page: Vec<Value> = serde_json::from_str(&super::gh(
                self.root,
                &[
                    "api",
                    &format!(
                        "repos/{REPOSITORY}/{kind}/comments?since={since}&sort=updated&direction=asc&per_page=100"
                    ),
                ],
            )?)?;
            all.extend(page);
        }
        Ok(all)
    }
    /// Authenticated through the owner's `gh` login: `adoption_read` falls
    /// back to anonymous curl without `GH_TOKEN`, whose 60-per-hour quota a
    /// 60 s poll exhausts (HTTP 403).
    fn adoption(&mut self, read: AdoptionRead) -> Result<Value, ScalerError> {
        match read {
            AdoptionRead::ClosingReferences(number) => {
                super::closing_references_response(self.root, number)
            }
            AdoptionRead::Issue(number) => Ok(serde_json::from_str(&super::gh(
                self.root,
                &["api", &format!("repos/{REPOSITORY}/issues/{number}")],
            )?)?),
        }
    }
    fn runs(&mut self) -> Result<Vec<Value>, ScalerError> {
        Ok(serde_json::from_str(&super::gh(
            self.root,
            &[
                "run",
                "list",
                "-R",
                REPOSITORY,
                "--workflow",
                "dispatch-worker.yml",
                "--limit",
                "50",
                "--json",
                "databaseId,status,headBranch,displayTitle",
            ],
        )?)?)
    }
    fn post(&mut self, pr: u64, body: &str) -> Result<(), ScalerError> {
        super::gh(
            self.root,
            &[
                "api",
                &format!("repos/{REPOSITORY}/issues/{pr}/comments"),
                "-f",
                &format!("body={body}"),
            ],
        )
        .map(drop)
    }
}

const PROMPT: &str = "You are the Carrick dispatch reactor. Read the PR context and choose ONE action.\n\
- ignore: nothing needs doing (default; most events need nothing).\n\
- reply: a short factual answer to a direct question; plain text, never a command.\n\
- round: start one worker round on this PR; `text` is the brief for the worker (what to fix and how to prove it). Only when the owner or a reviewer asked for changes, CI failed on the PR's own code, or this is a quiet new director PR that clearly needs work.\n\
Code enforces eligibility and caps; never merge, push, label or close.\n\n";
struct Claude {
    model: String,
}
impl Agent for Claude {
    fn decide(&mut self, context: &str) -> Result<Decision, ScalerError> {
        let schema = json!({"type":"object","required":["action","text","reason"],"additionalProperties":false,
            "properties":{"action":{"enum":["ignore","reply","round"]},"text":{"type":"string"},"reason":{"type":"string"}}});
        let dir = tempfile::tempdir()?;
        let out = dir.path().join("out");
        let mut child = Command::new("claude")
            .args([
                "-p",
                "--output-format",
                "json",
                "--tools",
                "",
                "--no-session-persistence",
            ])
            .args(["--model", &self.model, "--json-schema", &schema.to_string()])
            .current_dir(dir.path())
            .stdin(Stdio::piped())
            .stdout(std::fs::File::create(&out)?)
            .stderr(Stdio::null())
            .spawn()?;
        {
            use std::io::Write;
            let mut stdin = child
                .stdin
                .take()
                .ok_or(ScalerError::Guard("agent stdin"))?;
            stdin.write_all(format!("{PROMPT}{context}").as_bytes())?;
        }
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    return Err(ScalerError::Guard("agent exited unsuccessfully"));
                }
                break;
            }
            if Instant::now() > deadline {
                child.kill()?;
                child.wait()?;
                return Err(ScalerError::Guard("agent timed out"));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let reply: Value = serde_json::from_slice(&std::fs::read(&out)?)?;
        let decision = match reply.get("structured_output") {
            Some(v) if !v.is_null() => v.clone(),
            _ => serde_json::from_str(reply["result"].as_str().unwrap_or_default())?,
        };
        Ok(serde_json::from_value(decision)?)
    }
}

fn state_path(opts: &Opts) -> Result<PathBuf, ScalerError> {
    if let Some(path) = &opts.state {
        return Ok(path.clone());
    }
    let home = std::env::var_os("HOME").ok_or(ScalerError::Guard("HOME unset"))?;
    Ok(PathBuf::from(home).join("Library/Application Support/carrick-reactor/state.json"))
}
fn once(root: &Path, opts: &Opts) -> Result<(), ScalerError> {
    let path = state_path(opts)?;
    let mut state: State = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
        Err(e) => return Err(e.into()),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ScalerError::Guard("clock before epoch"))?
        .as_secs();
    if let Some(since) = &opts.since
        && !rfc3339(since)
    {
        return Err(ScalerError::Usage(format!(
            "--since must be YYYY-MM-DDTHH:MM:SSZ, got {since:?}"
        )));
    }
    if !opts.dry_run && state.epoch.is_none() {
        state.epoch = Some(iso(now));
    }
    let epoch = opts
        .since
        .clone()
        .or_else(|| state.epoch.clone())
        .unwrap_or_else(|| iso(now));
    println!("reactor: epoch {epoch}");
    let log = cycle(
        &mut Live { root },
        &mut Claude {
            model: opts.model.clone(),
        },
        &mut state,
        now,
        &epoch,
        opts.dry_run,
    )?;
    for line in &log {
        println!("{line}");
    }
    println!(
        "reactor: cycle done at {}{}",
        iso(now),
        if opts.dry_run {
            " (dry run, state unchanged)"
        } else {
            ""
        }
    );
    if !opts.dry_run {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&state)?)?;
        std::fs::rename(&tmp, &path)?;
    }
    Ok(())
}
/// Every reactor GitHub read goes through the owner's `gh` login, never the
/// anonymous curl fallback in `dispatch_worker::api` (60 requests an hour,
/// which a 60 s poll exhausts with HTTP 403). Refuse to start without one.
fn require_gh_login(root: &Path) -> Result<(), ScalerError> {
    let token = super::gh(root, &["auth", "token"]).map_err(|_| {
        ScalerError::Guard("reactor needs an authenticated gh login (gh auth token failed)")
    })?;
    if token.trim().is_empty() {
        return Err(ScalerError::Guard(
            "reactor needs an authenticated gh login (empty gh auth token)",
        ));
    }
    Ok(())
}
pub(crate) fn run(root: &Path, mode: Mode) -> Result<(), ScalerError> {
    require_gh_login(root)?;
    match mode {
        Mode::Once(opts) => once(root, &opts),
        Mode::Feed(opts) => session::feed(root, &opts),
        Mode::Mcp(opts) => session::mcp(root, &opts),
        Mode::Run(opts) => loop {
            if let Err(error) = once(root, &opts) {
                eprintln!("reactor: cycle failed: {error}");
            }
            std::thread::sleep(Duration::from_secs(60));
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    pub(super) struct FakeGh {
        pub prs: Vec<Value>,
        pub facts: Vec<Value>,
        pub comments: Vec<Value>,
        pub runs: Vec<Value>,
        pub closing: Vec<u64>,
        pub posted: Vec<(u64, String)>,
    }
    impl Github for FakeGh {
        fn open_prs(&mut self) -> Result<Vec<Value>, ScalerError> {
            Ok(self.prs.clone())
        }
        fn pr_facts(&mut self) -> Result<Vec<Value>, ScalerError> {
            Ok(self.facts.clone())
        }
        fn comments(&mut self, _: &str) -> Result<Vec<Value>, ScalerError> {
            Ok(self.comments.clone())
        }
        fn adoption(&mut self, read: AdoptionRead) -> Result<Value, ScalerError> {
            Ok(match read {
                AdoptionRead::ClosingReferences(_) => {
                    let nodes: Vec<Value> = self
                        .closing
                        .iter()
                        .map(|n| json!({"number":n,"repository":{"nameWithOwner":REPOSITORY}}))
                        .collect();
                    let c = json!({"nodes":nodes,"pageInfo":{"hasNextPage":false}});
                    json!({"data":{"repository":{"pullRequest":{"closingIssuesReferences":c,"bodyReferences":c}}}})
                }
                AdoptionRead::Issue(n) => {
                    json!({"number":n,"state":"open","user":{"login":"tjfontaine","type":"User"}})
                }
            })
        }
        fn runs(&mut self) -> Result<Vec<Value>, ScalerError> {
            Ok(self.runs.clone())
        }
        fn post(&mut self, pr: u64, body: &str) -> Result<(), ScalerError> {
            self.posted.push((pr, body.to_owned()));
            Ok(())
        }
    }
    struct FakeAgent {
        decision: Decision,
        calls: usize,
    }
    impl Agent for FakeAgent {
        fn decide(&mut self, _: &str) -> Result<Decision, ScalerError> {
            self.calls += 1;
            Ok(self.decision.clone())
        }
    }
    fn agent(action: Act, text: &str) -> FakeAgent {
        FakeAgent {
            decision: Decision {
                action,
                text: text.into(),
                reason: "test".into(),
            },
            calls: 0,
        }
    }
    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const NOW: u64 = 1_793_404_800; // 2026-10-31T00:00:00Z
    const EPOCH: &str = "2026-10-30T23:00:00Z";
    pub(super) fn pr(number: u64, branch: &str) -> Value {
        json!({"number":number,"state":"open","title":format!("PR {number}"),
            "created_at":"2026-10-30T23:10:00Z",
            "user":{"login":"tjfontaine","type":"User"},"labels":[],
            "head":{"ref":branch,"sha":SHA,"repo":{"full_name":REPOSITORY}},
            "base":{"ref":"main","repo":{"full_name":REPOSITORY}}})
    }
    pub(super) fn comment(number: u64, id: u64, login: &str, kind: &str, body: &str) -> Value {
        json!({"id":id,"issue_url":format!("https://api.github.com/repos/{REPOSITORY}/issues/{number}"),
            "user":{"login":login,"type":kind},"body":body,"updated_at":"2026-10-30T23:59:00Z"})
    }
    pub(super) fn gh(prs: Vec<Value>, comments: Vec<Value>) -> FakeGh {
        FakeGh {
            prs,
            comments,
            closing: vec![7],
            ..FakeGh::default()
        }
    }

    #[test]
    fn dispatch_reactor_round_needs_eligible_quiet_capacity() {
        let d = Decision {
            action: Act::Round,
            text: "fix the test".into(),
            reason: String::new(),
        };
        let gate = |eligible, pr_run_active, active_total| Gate {
            eligible,
            pr_run_active,
            active_total,
            repeat_round: false,
        };
        assert_eq!(
            enforce(&d, &gate(false, false, 0)),
            Effect::Refused("PR is neither adoptable nor owned")
        );
        assert_eq!(
            enforce(&d, &gate(true, true, 1)),
            Effect::Refused("dispatch run in flight for this PR")
        );
        assert_eq!(
            enforce(&d, &gate(true, false, GLOBAL_CAP)),
            Effect::Refused("global dispatch cap")
        );
        assert_eq!(
            enforce(&d, &gate(true, false, GLOBAL_CAP - 1)),
            Effect::Post(format!("/agent fix the test\n\n{MARKER}"))
        );
    }

    #[test]
    fn dispatch_reactor_reply_may_not_be_a_command() {
        let gate = Gate {
            eligible: true,
            pr_run_active: false,
            active_total: 0,
            repeat_round: false,
        };
        for text in ["/agent do it", "  /agent"] {
            let d = Decision {
                action: Act::Reply,
                text: text.into(),
                reason: String::new(),
            };
            assert_eq!(
                enforce(&d, &gate),
                Effect::Refused("reply may not be a command")
            );
        }
    }

    #[test]
    fn dispatch_reactor_cycle_refuses_round_on_non_adoptable_pr() {
        // Closes two issues: not adoptable; the closing ask fires once, the round is refused.
        let mut fake = gh(
            vec![pr(10, "work/x")],
            vec![comment(10, 1, "tjfontaine", "User", "please fix CI")],
        );
        fake.closing = vec![7, 8];
        let mut a = agent(Act::Round, "fix CI");
        let mut state = State::default();
        let log = cycle(&mut fake, &mut a, &mut state, NOW, EPOCH, false).unwrap();
        assert_eq!(a.calls, 1);
        assert_eq!(fake.posted.len(), 1);
        assert!(fake.posted[0].1.starts_with(CLOSES_ASK));
        assert!(
            log.iter()
                .any(|l| l.contains("neither adoptable nor owned"))
        );
    }

    #[test]
    fn dispatch_reactor_cycle_refuses_round_when_runs_in_flight() {
        let busy = |runs: Vec<Value>, why: &str| {
            let mut fake = gh(
                vec![pr(11, "work/y")],
                vec![comment(11, 2, "tjfontaine", "User", "go")],
            );
            fake.runs = runs;
            let mut state = State::default();
            let log = cycle(
                &mut fake,
                &mut agent(Act::Round, "go"),
                &mut state,
                NOW,
                EPOCH,
                false,
            )
            .unwrap();
            assert!(fake.posted.is_empty(), "{log:?}");
            assert!(log.iter().any(|l| l.contains(why)), "{log:?}");
        };
        busy(
            vec![json!({"status":"in_progress","displayTitle":"PR 11","headBranch":"main"})],
            "in flight for this PR",
        );
        busy(
            (0..4)
                .map(|i| json!({"status":"queued","displayTitle":format!("other {i}"),"headBranch":"main"}))
                .collect(),
            "global dispatch cap",
        );
        // Control: the same PR with no runs posts the round.
        let mut fake = gh(
            vec![pr(11, "work/y")],
            vec![comment(11, 2, "tjfontaine", "User", "go")],
        );
        cycle(
            &mut fake,
            &mut agent(Act::Round, "go"),
            &mut State::default(),
            NOW,
            EPOCH,
            false,
        )
        .unwrap();
        assert_eq!(fake.posted, vec![(11, format!("/agent go\n\n{MARKER}"))]);
    }

    #[test]
    fn dispatch_reactor_ignores_bot_and_own_comments() {
        let mut fake = gh(
            vec![pr(12, "work/z")],
            vec![
                comment(12, 3, "github-actions[bot]", "Bot", "CI done"),
                comment(12, 4, "carrick-dispatch", "Bot", "outcome"),
                comment(
                    12,
                    5,
                    "tjfontaine",
                    "User",
                    &format!("earlier note\n\n{MARKER}"),
                ),
            ],
        );
        let mut a = agent(Act::Reply, "hello");
        let mut state = State::default();
        cycle(&mut fake, &mut a, &mut state, NOW, EPOCH, false).unwrap();
        assert_eq!(a.calls, 0);
        assert!(fake.posted.is_empty());
        assert_eq!(state.cursor.as_deref(), Some("2026-10-30T23:59:00Z"));
    }

    #[test]
    fn dispatch_reactor_asks_for_closing_reference_once() {
        let mut fake = gh(vec![pr(13, "work/no-closes")], vec![]);
        fake.closing = vec![];
        let mut state = State::default();
        let mut a = agent(Act::Ignore, "");
        cycle(&mut fake, &mut a, &mut state, NOW, EPOCH, false).unwrap();
        cycle(&mut fake, &mut a, &mut state, NOW, EPOCH, false).unwrap();
        assert_eq!(fake.posted.len(), 1);
        assert!(fake.posted[0].1.ends_with(MARKER));
        assert!(state.prs[&13].closes_asked);
        // Dry run reports the ask but posts nothing.
        let mut dry = gh(vec![pr(13, "work/no-closes")], vec![]);
        dry.closing = vec![];
        let log = cycle(&mut dry, &mut a, &mut State::default(), NOW, EPOCH, true).unwrap();
        assert!(dry.posted.is_empty());
        assert!(log.iter().any(|l| l.contains("would post")));
    }

    #[test]
    fn dispatch_reactor_quiet_adoptable_pr_is_a_candidate_once() {
        let mut fake = gh(vec![pr(14, "work/new")], vec![]);
        fake.facts = vec![
            json!({"number":14,"commits":{"nodes":[{"commit":{"committedDate":"2026-10-30T23:00:00Z"}}]}}),
        ];
        let mut a = agent(Act::Ignore, "");
        let mut state = State::default();
        cycle(&mut fake, &mut a, &mut state, NOW, EPOCH, false).unwrap();
        cycle(&mut fake, &mut a, &mut state, NOW, EPOCH, false).unwrap();
        assert_eq!(a.calls, 1);
        assert!(fake.posted.is_empty());
    }

    #[test]
    fn dispatch_reactor_outcome_comment_produces_a_decision() {
        let mut fake = gh(
            vec![pr(15, "work/o")],
            vec![
                comment(
                    15,
                    6,
                    "carrick-workers[bot]",
                    "Bot",
                    "## Dispatch outcome: blocked\nWhich base?",
                ),
                comment(
                    15,
                    7,
                    "carrick-workers[bot]",
                    "Bot",
                    "unrelated bot chatter",
                ),
            ],
        );
        let mut a = agent(Act::Ignore, "");
        cycle(&mut fake, &mut a, &mut State::default(), NOW, EPOCH, false).unwrap();
        assert_eq!(a.calls, 1);
    }

    #[test]
    fn dispatch_reactor_one_round_per_head_until_a_human_speaks() {
        let mut fake = gh(
            vec![pr(16, "work/r")],
            vec![comment(16, 8, "tjfontaine", "User", "please fix CI")],
        );
        let mut a = agent(Act::Round, "fix CI");
        let mut state = State::default();
        cycle(&mut fake, &mut a, &mut state, NOW, EPOCH, false).unwrap();
        assert_eq!(fake.posted.len(), 1);
        assert_eq!(state.prs[&16].last_round_head.as_deref(), Some(SHA));
        assert_eq!(
            state.prs[&16].last_round_at.as_deref(),
            Some("2026-10-31T00:00:00Z")
        );
        // An outcome on the same head asks again; the second round is refused.
        fake.comments = vec![comment(
            16,
            9,
            "github-actions[bot]",
            "Bot",
            "Dispatch outcome: failed",
        )];
        let log = cycle(&mut fake, &mut a, &mut state, NOW, EPOCH, false).unwrap();
        assert_eq!(a.calls, 2);
        assert_eq!(fake.posted.len(), 1, "{log:?}");
        assert!(
            log.iter().any(|l| l.contains("already rounded this head")),
            "{log:?}"
        );
        // A human comment after the round re-enables one more round.
        fake.comments = vec![comment(
            16,
            10,
            "tjfontaine",
            "User",
            "try the other approach",
        )];
        cycle(&mut fake, &mut a, &mut state, NOW, EPOCH, false).unwrap();
        assert_eq!(fake.posted.len(), 2);
    }

    #[test]
    fn dispatch_reactor_old_pr_gets_no_automatic_behaviour() {
        let mut old = pr(17, "work/old");
        old["created_at"] = json!("2026-10-01T00:00:00Z");
        let mut unclosed = pr(18, "work/old-unclosed");
        unclosed["created_at"] = json!("2026-10-01T00:00:00Z");
        let mut fake = gh(vec![old, unclosed], vec![]);
        fake.facts = vec![
            json!({"number":17,"commits":{"nodes":[{"commit":{"committedDate":"2026-10-01T00:00:00Z"}}]}}),
        ];
        let mut a = agent(Act::Round, "go");
        let mut state = State::default();
        // FakeGh answers closing references for every PR alike; run each case.
        cycle(&mut fake, &mut a, &mut state, NOW, EPOCH, false).unwrap();
        fake.closing = vec![];
        cycle(&mut fake, &mut a, &mut state, NOW, EPOCH, false).unwrap();
        assert_eq!(a.calls, 0);
        assert!(fake.posted.is_empty());
        // An explicit owner comment on an old PR is still an event.
        fake.closing = vec![7];
        fake.comments = vec![comment(17, 11, "tjfontaine", "User", "please fix")];
        cycle(&mut fake, &mut a, &mut state, NOW, EPOCH, false).unwrap();
        assert_eq!(a.calls, 1);
        assert_eq!(fake.posted.len(), 1);
    }

    /// The anonymous curl branch lives only in `dispatch_worker::api` and
    /// `adoption_read`, which calls it. Reactor sources must never reach
    /// either; their GitHub traffic goes through `super::gh` (the owner's
    /// login) or the `Github`/`Remote` traits.
    #[test]
    fn dispatch_reactor_never_takes_the_anonymous_curl_branch() {
        for (name, source) in [
            ("dispatch_reactor.rs", include_str!("dispatch_reactor.rs")),
            (
                "dispatch_reactor_session.rs",
                include_str!("dispatch_reactor_session.rs"),
            ),
        ] {
            let code = source.split("#[cfg(test)]").next().unwrap();
            for forbidden in [
                "super::api(",
                "super::super::api(",
                "adoption_read(",
                "\"curl\"",
            ] {
                assert!(!code.contains(forbidden), "{name} uses {forbidden}");
            }
        }
    }

    #[test]
    fn dispatch_reactor_iso_matches_github_shape() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(NOW), "2026-10-31T00:00:00Z");
        assert_eq!(iso(951_782_400), "2000-02-29T00:00:00Z");
    }
}
