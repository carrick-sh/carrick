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
/// Reactor rounds allowed on one PR before the owner must comment again: a
/// round pushes a new head, so the per-head guard alone cannot stop a
/// red-CI, round, red-CI loop.
pub(crate) const UNATTENDED_ROUNDS: u32 = 3;
/// Completed runs are listed by creation time; a run that finishes after the
/// cursor may have started this long before it.
const RUN_LOOKBACK_SECS: u64 = 3 * 3600;
/// Warn when an interaction limit expires within this long.
const LIMIT_WARN_SECS: u64 = 30 * 86400;
const GLOBAL_CAP: usize = 6;
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
    /// REST completed workflow runs created at or after `created`.
    fn workflow_runs(&mut self, created: &str) -> Result<Vec<Value>, ScalerError>;
    /// REST in-progress workflow runs on `branch`.
    fn active_runs(&mut self, branch: &str) -> Result<Vec<Value>, ScalerError>;
    /// REST jobs of one run's latest attempt.
    fn run_jobs(&mut self, run: u64) -> Result<Vec<Value>, ScalerError>;
    fn post(&mut self, pr: u64, body: &str) -> Result<(), ScalerError>;
    fn capacity(&mut self) -> Option<Value> {
        None
    }
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
    /// Reactor rounds since the last owner comment.
    #[serde(default)]
    unattended_rounds: u32,
    seen: Vec<String>,
    #[serde(default)]
    waiting_on: Option<String>,
    #[serde(default)]
    last_continued_outcome: Option<String>,
    #[serde(default)]
    deferred_outcome: Option<String>,
}

/// What the rule layer knows about one PR when executing a decision.
pub(crate) struct Gate {
    pub eligible: bool,
    pub pr_run_active: bool,
    pub active_total: usize,
    /// The reactor already posted a round on this head and no human spoke since.
    pub repeat_round: bool,
    /// [`UNATTENDED_ROUNDS`] reactor rounds since the last owner comment.
    pub unattended: bool,
    /// A reply answers something: the PR is trusted and an owner event on
    /// it is not yet answered.
    pub reply_allowed: bool,
}
/// The only effects the rule layer can produce.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Effect {
    None,
    Post(String),
    Refused(&'static str),
}

/// Hard rules: the agent's decision becomes a comment only through here.
/// Reply and brief length caps, in characters.
const REPLY_LIMIT: usize = 2000;
const BRIEF_LIMIT: usize = 4000;
/// Prefixes of credentials that must never be posted (GitHub tokens, PEM
/// keys, AWS access keys). Everything the reactor posts is public.
const SECRET_SHAPES: [&str; 9] = [
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "-----BEGIN",
    "AKIA",
    "ASIA",
];
/// Case and whitespace don't hide a prefix: a token split across lines or
/// upper-cased still matches.
fn secret_shaped(text: &str) -> bool {
    let folded: String = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    SECRET_SHAPES
        .iter()
        .any(|shape| folded.contains(&shape.to_lowercase()))
}
pub(crate) fn enforce(decision: &Decision, gate: &Gate) -> Effect {
    let text = decision.text.trim();
    match decision.action {
        Act::Ignore => Effect::None,
        _ if secret_shaped(text) => Effect::Refused("text looks like a credential"),
        Act::Reply if text.is_empty() => Effect::Refused("empty reply"),
        Act::Reply if text.chars().count() > REPLY_LIMIT => Effect::Refused("reply too long"),
        Act::Reply if !gate.reply_allowed => {
            Effect::Refused("no unanswered owner message on a trusted PR")
        }
        Act::Reply if text.starts_with("/agent") => Effect::Refused("reply may not be a command"),
        Act::Reply => Effect::Post(format!("{text}\n\n{MARKER}")),
        Act::Round if !gate.eligible => Effect::Refused("PR is neither adoptable nor owned"),
        Act::Round if gate.pr_run_active => Effect::Refused("dispatch run in flight for this PR"),
        Act::Round if gate.active_total >= GLOBAL_CAP => Effect::Refused("global dispatch cap"),
        Act::Round if gate.repeat_round => {
            Effect::Refused("already rounded this head; waiting for a human comment")
        }
        Act::Round if gate.unattended => {
            Effect::Refused("unattended round limit; waiting for a human comment")
        }
        Act::Round if text.is_empty() || text.contains(MARKER) => Effect::Refused("invalid brief"),
        Act::Round if text.chars().count() > BRIEF_LIMIT => Effect::Refused("brief too long"),
        Act::Round => Effect::Post(format!("/agent {text}\n\n{MARKER}")),
    }
}

/// A repeated named prerequisite is a wait, rather than another worker round.
/// Only the server section of trusted outcome comments is considered.
pub(super) fn repeated_blocker<'a>(bodies: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let mut previous: Option<String> = None;
    let mut waiting = None;
    for body in bodies {
        let blocker = (super::agent_loop::outcome_status(body) == Some("Blocked"))
            .then(|| {
                super::agent_loop::server_part(body)
                    .lines()
                    .find_map(|line| line.strip_prefix("External blocker: "))
                    .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
            })
            .flatten();
        let identity = blocker.as_deref().map(blocker_identity);
        waiting = blocker.filter(|_| identity == previous && identity.is_some());
        previous = identity;
    }
    waiting
}

// Issue and PR URLs share GitHub's repository-wide number namespace. A
// comment fragment identifies an owner decision on that thread, so keep it.
fn blocker_identity(blocker: &str) -> String {
    let reference = blocker.split_whitespace().next().unwrap_or_default();
    for prefix in [
        "https://github.com/carrick-sh/carrick/issues/",
        "https://github.com/carrick-sh/carrick/pull/",
        "#",
    ] {
        if let Some(number) = reference.strip_prefix(prefix) {
            return format!("#{}", number.trim_end_matches('/'));
        }
    }
    blocker
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[cfg(test)]
mod blocker_replay_tests {
    #[test]
    fn replay_1763_1737_waits_on_1755() {
        let body = "Dispatch outcome: Blocked\n\nExternal blocker: #1755 robust-list walker\n";
        assert_eq!(super::repeated_blocker([body]), None);
        let reworded = "Dispatch outcome: Blocked\n\nExternal blocker: https://github.com/carrick-sh/carrick/pull/1755 waiting for exit cleanup to land\n";
        assert_eq!(
            super::repeated_blocker([body, reworded]),
            Some(
                "https://github.com/carrick-sh/carrick/pull/1755 waiting for exit cleanup to land"
                    .into()
            )
        );
        let other = "Dispatch outcome: Blocked\n\nExternal blocker: #1754 different dependency\n";
        assert_eq!(super::repeated_blocker([body, other]), None);
        assert_eq!(
            super::repeated_blocker([body, body]),
            Some("#1755 robust-list walker".into())
        );
        assert_eq!(super::repeated_blocker([body, body, ""]), None);
        assert_eq!(
            super::repeated_blocker([body, "Dispatch outcome: Continuing", body]),
            None
        );
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
fn signed_gate_bot_comment(body: &str) -> bool {
    body.contains("Signed gate:") || body.contains("<!-- carrick-signed-gate -->")
}
pub(crate) fn classify(user: &Value, body: &str) -> Option<Class> {
    if body.contains(MARKER) {
        return None;
    }
    if outcome_bot(user) && (body.contains("Dispatch outcome") || signed_gate_bot_comment(body)) {
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

/// Root ecosystem-blocker issues (sweep guard 19): Done implementation rounds on
/// these PRs or their split/successor PRs wait for a signed scoreboard on the
/// current PR head before starting an independent review round (#1825).
const ECOSYSTEM_BLOCKERS: [u64; 6] = [887, 1733, 1791, 1506, 1671, 1756];
const SELF_REVIEW_DISCLAIMER: &str =
    "This is the worker's own review; it is not an independent review.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RoundKind {
    Implementation,
    Review,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReviewVerdict {
    Approved,
    ChangesRequested,
}

pub(super) struct CommentView<'a> {
    pub url: &'a str,
    pub user: &'a Value,
    pub body: &'a str,
}

pub(super) struct OutcomeSummary {
    pub key: String,
    pub status: String,
    pub kind: RoundKind,
    pub verdict: Option<ReviewVerdict>,
    pub author_tier: Option<super::worker_tier::WorkerTier>,
    pub author_backends: Vec<String>,
    pub review_url: Option<String>,
    pub issue: Option<u64>,
    pub findings: String,
    pub index: usize,
}

pub(super) fn is_review_brief(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("review only") && lower.contains("push nothing")
}

pub(super) fn is_signed_scoreboard_text(body: &str) -> bool {
    !body.contains("Signed gate: **FAIL**")
        && (body.to_ascii_lowercase().contains("signed scoreboard")
            || body.contains("Signed gate: **PASS**"))
}

fn mentions_head_sha(body: &str, head: &str) -> bool {
    if head.len() < 7 {
        return false;
    }
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_hexdigit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        let tok = &body[start..i];
        if (7..=40).contains(&tok.len())
            && head.len() >= tok.len()
            && head[..tok.len()].eq_ignore_ascii_case(tok)
        {
            return true;
        }
    }
    false
}

pub(super) fn has_signed_scoreboard_on_head(comments: &[CommentView<'_>], head: &str) -> bool {
    if head.len() < 7 {
        return false;
    }
    comments.iter().any(|c| {
        if c.body.contains(MARKER) {
            return false;
        }
        let trimmed = c.body.trim_start();
        let valid_source = if trusted_owner(c.user) {
            !super::has_agent_command(c.body) && is_signed_scoreboard_text(c.body)
        } else if outcome_bot(c.user) {
            !trimmed.starts_with("Dispatch outcome:")
                && !trimmed.starts_with("Dispatch run:")
                && c.body.contains("Signed gate: **PASS**")
        } else {
            false
        };
        if !valid_source {
            return false;
        }
        let sha_scope = if trimmed.starts_with("Signed gate:") {
            trimmed.split_once('→').map_or(c.body, |(_, rest)| rest)
        } else {
            c.body
        };
        mentions_head_sha(sha_scope, head)
    })
}

fn mentions_issue(text: &str, target: u64) -> bool {
    for pattern in [
        format!("#{target}"),
        format!("/issues/{target}"),
        format!("/pull/{target}"),
    ] {
        let mut start = 0;
        while let Some(pos) = text[start..].find(&pattern) {
            let idx = start + pos;
            let end = idx + pattern.len();
            let before_ok = !pattern.starts_with('#')
                || idx == 0
                || !text.as_bytes()[idx - 1].is_ascii_alphanumeric();
            let after_ok = end == text.len() || !text.as_bytes()[end].is_ascii_digit();
            if before_ok && after_ok {
                return true;
            }
            start = idx + 1;
        }
    }
    false
}

pub(super) fn resolve_pr_issues(
    pr: &Value,
    pr_number: u64,
    known_closing: &[u64],
    receipt_issue: Option<u64>,
    read_adoption: &mut dyn FnMut(AdoptionRead) -> Result<Value, ScalerError>,
) -> Result<Vec<u64>, ScalerError> {
    fn push_unique(issues: &mut Vec<u64>, n: u64) {
        if n > 0 && !issues.contains(&n) {
            issues.push(n);
        }
    }
    let mut issues = Vec::new();
    let branch = pr["head"]["ref"].as_str().unwrap_or_default();
    if let Some(issue) = dispatch_branch(branch) {
        push_unique(&mut issues, issue);
    }
    for &n in known_closing {
        push_unique(&mut issues, n);
    }
    if let Some(n) = receipt_issue {
        push_unique(&mut issues, n);
    }
    if issues.is_empty() && trusted_pr(pr) {
        let raw = read_adoption(AdoptionRead::ClosingReferences(pr_number))?;
        if let Ok(refs) = super::parse_closing_references(&raw) {
            for r in refs.all {
                if r.repository == REPOSITORY {
                    push_unique(&mut issues, r.number);
                }
            }
        }
    }
    Ok(issues)
}

pub(super) fn ecosystem_wait_reason(
    pr: &Value,
    pr_number: u64,
    head: &str,
    known_closing: &[u64],
    receipt_issue: Option<u64>,
    comments: &[CommentView<'_>],
    read_adoption: &mut dyn FnMut(AdoptionRead) -> Result<Value, ScalerError>,
) -> Result<Option<String>, ScalerError> {
    let issues = resolve_pr_issues(pr, pr_number, known_closing, receipt_issue, read_adoption)?;
    let mut matched = issues
        .iter()
        .copied()
        .find(|n| ECOSYSTEM_BLOCKERS.contains(n));
    if matched.is_none() && trusted_pr(pr) {
        let pr_text = format!(
            "{}\n{}",
            pr["title"].as_str().unwrap_or_default(),
            pr["body"].as_str().unwrap_or_default()
        );
        matched = ECOSYSTEM_BLOCKERS
            .into_iter()
            .find(|&b| mentions_issue(&pr_text, b));
    }
    if matched.is_none() {
        for issue in issues {
            let doc = read_adoption(AdoptionRead::Issue(issue))?;
            if trusted_owner(&doc["user"]) {
                let text = format!(
                    "{}\n{}",
                    doc["title"].as_str().unwrap_or_default(),
                    doc["body"].as_str().unwrap_or_default()
                );
                if let Some(b) = ECOSYSTEM_BLOCKERS
                    .into_iter()
                    .find(|&b| mentions_issue(&text, b))
                {
                    matched = Some(b);
                    break;
                }
            }
        }
    }
    let Some(blocker) = matched else {
        return Ok(None);
    };
    if has_signed_scoreboard_on_head(comments, head) {
        return Ok(None);
    }
    let short = head.get(..12).unwrap_or(head);
    Ok(Some(format!(
        "signed scoreboard on `{short}` for #{blocker}"
    )))
}

fn fenced_block_after(body: &str, heading: &str) -> Option<String> {
    let rest = body.split_once(heading)?.1;
    let mut lines = rest.lines();
    lines.find(|line| line.trim_start().starts_with("```"))?;
    let mut buf = String::new();
    for line in lines {
        if line.trim_start().starts_with("```") {
            return Some(buf);
        }
        buf.push_str(line);
        buf.push('\n');
    }
    None
}

fn fenced_json_after(body: &str, heading: &str) -> Option<Value> {
    fenced_block_after(body, heading).and_then(|buf| serde_json::from_str(&buf).ok())
}

/// Extracts `"<key>": "<string>"` even when the fenced worker-contract preview
/// was clipped at 2,000 characters before the closing quote or brace.
fn extract_json_string_prefix(raw: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let after_key = raw.split_once(&needle)?.1.trim_start();
    let after_colon = after_key.strip_prefix(':')?.trim_start();
    let mut chars = after_colon.strip_prefix('"')?.chars();
    let mut out = String::new();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => break,
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if let Some(decoded) =
                        u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                    {
                        out.push(decoded);
                    }
                }
                other => out.push(other),
            },
            other => out.push(other),
        }
    }
    Some(out)
}

fn parse_author_tier(server: &str) -> Option<super::worker_tier::WorkerTier> {
    let raw = server
        .lines()
        .find_map(|l| l.strip_prefix("Worker tier: "))?;
    let word = raw.split_whitespace().next()?.trim();
    if word.eq_ignore_ascii_case("strong") {
        Some(super::worker_tier::WorkerTier::Strong)
    } else if word.eq_ignore_ascii_case("standard") {
        Some(super::worker_tier::WorkerTier::Standard)
    } else {
        None
    }
}

fn parse_author_backends(server: &str) -> Vec<String> {
    let Some(line) = server
        .lines()
        .find_map(|l| l.strip_prefix("Workers this round: "))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for segment in line.split(',') {
        let mut parts = segment.split('`');
        let _ = parts.next();
        if let Some(backend) = parts.next().map(str::trim).filter(|b| !b.is_empty())
            && !out.iter().any(|existing| existing == backend)
        {
            out.push(backend.to_owned());
        }
    }
    out
}

fn parse_commits_pushed(server: &str) -> Option<u64> {
    server.lines().find_map(|l| {
        let rest = l.split_once("commits pushed this round: ")?.1;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    })
}

fn parse_worker_review_url(server: &str) -> Option<String> {
    server.lines().find_map(|l| {
        let rest = l.strip_prefix("- Worker review: ")?;
        let after = rest.split_once("([review](")?.1;
        let url = after.split_once("))")?.0.trim();
        (!url.is_empty()).then(|| url.to_owned())
    })
}

fn parse_loop_claims(body: &str) -> String {
    let Some(after) = body.split_once("Loop claims (unverified):").map(|p| p.1) else {
        return String::new();
    };
    after
        .lines()
        .skip_while(|l| l.trim().is_empty())
        .map_while(|l| {
            l.strip_prefix("> ")
                .or_else(|| (l.trim() == ">").then_some(""))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn starts_with_verdict_keyword(upper: &str, keyword: &str) -> bool {
    upper
        .strip_prefix(keyword)
        .is_some_and(|rest| rest.chars().next().is_none_or(|c| !c.is_ascii_alphabetic()))
}

fn parse_verdict_keyword(raw: &str) -> Option<ReviewVerdict> {
    let upper = raw
        .trim()
        .trim_start_matches(['*', '_', '`'])
        .trim()
        .to_ascii_uppercase();
    if [
        "CHANGES REQUESTED",
        "CHANGES_REQUESTED",
        "REQUEST CHANGES",
        "REQUEST_CHANGES",
    ]
    .iter()
    .any(|kw| starts_with_verdict_keyword(&upper, kw))
    {
        Some(ReviewVerdict::ChangesRequested)
    } else if starts_with_verdict_keyword(&upper, "APPROVED")
        || starts_with_verdict_keyword(&upper, "APPROVE")
    {
        Some(ReviewVerdict::Approved)
    } else {
        None
    }
}

fn clean_verdict_line(line: &str) -> &str {
    line.trim()
        .trim_start_matches(['#', '*', '_', '`', '>', '-', ' '])
        .trim()
}

fn explicit_verdict_line(text: &str) -> Option<ReviewVerdict> {
    for raw in text.lines() {
        let cleaned = raw
            .trim()
            .trim_start_matches(['#', '*', '_', '>', '-', ' '])
            .trim();
        if let Some(rest) = cleaned
            .get(..8)
            .filter(|p| p.eq_ignore_ascii_case("verdict:"))
            .and_then(|_| cleaned.get(8..))
            && let Some(verdict) = parse_verdict_keyword(rest)
        {
            return Some(verdict);
        }
    }
    None
}

fn inline_verdict_tag(text: &str) -> Option<ReviewVerdict> {
    for raw in text.lines() {
        let lower = raw.to_ascii_lowercase();
        let mut offset = 0;
        while let Some(pos) = lower[offset..].find("verdict:") {
            let idx = offset + pos;
            let before_ok = idx == 0
                || (!raw.as_bytes()[idx - 1].is_ascii_alphanumeric()
                    && raw.as_bytes()[idx - 1] != b'`'
                    && raw.as_bytes()[idx - 1] != b'"');
            if before_ok
                && let Some(rest) = raw.get(idx + 8..)
                && let Some(verdict) = parse_verdict_keyword(rest)
            {
                return Some(verdict);
            }
            offset = idx + 8;
        }
    }
    None
}

fn is_review_boilerplate_line(cleaned: &str) -> bool {
    cleaned.is_empty()
        || cleaned.eq_ignore_ascii_case("worker review")
        || cleaned.starts_with("Reviewed head:")
        || cleaned.starts_with(SELF_REVIEW_DISCLAIMER)
        || cleaned
            .get(..13)
            .is_some_and(|p| p.eq_ignore_ascii_case("loop claimed:"))
}

fn classify_verdict_text(text: &str) -> Option<ReviewVerdict> {
    if let Some(explicit) = explicit_verdict_line(text) {
        return Some(explicit);
    }
    let mut first_content: Option<&str> = None;
    for raw in text.lines() {
        let cleaned = clean_verdict_line(raw);
        if is_review_boilerplate_line(cleaned) {
            continue;
        }
        if first_content.is_none() {
            first_content = Some(cleaned);
        }
        if let Some(rest) = cleaned
            .get(..8)
            .filter(|p| p.eq_ignore_ascii_case("verdict:"))
            .and_then(|_| cleaned.get(8..))
            && let Some(verdict) = parse_verdict_keyword(rest)
        {
            return Some(verdict);
        }
        let upper = cleaned.to_ascii_uppercase();
        if ["CHANGES REQUESTED", "CHANGES_REQUESTED", "REQUEST_CHANGES"]
            .iter()
            .any(|kw| starts_with_verdict_keyword(&upper, kw))
        {
            return Some(ReviewVerdict::ChangesRequested);
        }
    }
    if let Some(first) = first_content {
        let upper = first.to_ascii_uppercase();
        if starts_with_verdict_keyword(&upper, "APPROVED")
            || starts_with_verdict_keyword(&upper, "APPROVE")
        {
            return Some(ReviewVerdict::Approved);
        }
    }
    inline_verdict_tag(text)
}

fn text_has_review_verdict_marker(text: &str) -> bool {
    classify_verdict_text(text).is_some()
        || text
            .to_ascii_lowercase()
            .contains("completed independent review round")
}

fn text_requests_changes(text: &str) -> bool {
    classify_verdict_text(text) == Some(ReviewVerdict::ChangesRequested)
}

fn is_verdict_header_line(line: &str) -> bool {
    let cleaned = clean_verdict_line(line);
    if is_review_boilerplate_line(cleaned) {
        return true;
    }
    let upper = cleaned.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CHANGES REQUESTED" | "CHANGES_REQUESTED" | "REQUEST_CHANGES" | "APPROVED" | "APPROVE"
    ) || cleaned
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case("verdict:"))
}

pub(super) fn parse_outcomes(
    comments: &[CommentView<'_>],
    reviews: &[Value],
) -> Vec<OutcomeSummary> {
    let mut out = Vec::new();
    for (index, c) in comments.iter().enumerate() {
        if !outcome_bot(c.user) || c.body.contains(MARKER) {
            continue;
        }
        let Some(status) = super::agent_loop::outcome_status(c.body) else {
            continue;
        };
        let server = super::agent_loop::server_part(c.body);
        let round_kind_line = server
            .lines()
            .find_map(|l| l.strip_prefix("Round kind: "))
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let published_verdict = server
            .lines()
            .find_map(|l| l.strip_prefix("Published review verdict: "))
            .and_then(parse_verdict_keyword);
        let trigger_url = server
            .lines()
            .find_map(|l| l.strip_prefix("Round trigger: "))
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let commits_pushed = parse_commits_pushed(server);
        let pr_body_not_updated = server.lines().any(|l| l.trim() == "- PR body: not updated.");
        let outcome_contract = fenced_json_after(c.body, "Outcome contract:");
        let pub_receipt = fenced_json_after(c.body, "Publication receipt:");
        let wc_raw = fenced_block_after(c.body, "Worker contract (claims for review):");
        let worker_contract = wc_raw
            .as_deref()
            .and_then(|buf| serde_json::from_str::<Value>(buf).ok());
        let loop_claims = parse_loop_claims(c.body);
        let oc_summary = outcome_contract
            .as_ref()
            .and_then(|v| v["summary"].as_str())
            .unwrap_or_default();
        let oc_loop_summary = outcome_contract
            .as_ref()
            .and_then(|v| v["loop_summary"].as_str())
            .unwrap_or_default();
        let wc_summary = worker_contract
            .as_ref()
            .and_then(|v| v["summary"].as_str().map(str::to_owned))
            .or_else(|| {
                wc_raw
                    .as_deref()
                    .and_then(|buf| extract_json_string_prefix(buf, "summary"))
            })
            .unwrap_or_default();
        let wc_verdict = worker_contract
            .as_ref()
            .and_then(|v| v["review"]["verdict"].as_str())
            .unwrap_or_default();
        let review_url = parse_worker_review_url(server);
        let linked_review = review_url.as_deref().and_then(|u| {
            reviews.iter().find(|r| {
                r["url"]
                    .as_str()
                    .or_else(|| r["html_url"].as_str())
                    .unwrap_or_default()
                    == u
            })
        });
        let linked_review_body = linked_review
            .and_then(|r| r["body"].as_str())
            .unwrap_or_default();
        let explicit_verdict = [
            wc_summary.as_str(),
            oc_loop_summary,
            loop_claims.as_str(),
            linked_review_body,
        ]
        .into_iter()
        .find_map(explicit_verdict_line);

        let kind = if let Some(rk) = round_kind_line {
            if rk.eq_ignore_ascii_case("review") {
                RoundKind::Review
            } else {
                RoundKind::Implementation
            }
        } else if published_verdict.is_some() {
            RoundKind::Review
        } else if let Some(trig) = trigger_url.and_then(|u| comments.iter().find(|tc| tc.url == u))
        {
            if is_review_brief(trig.body) {
                RoundKind::Review
            } else {
                RoundKind::Implementation
            }
        } else if (commits_pushed == Some(0) || pr_body_not_updated) && explicit_verdict.is_some() {
            RoundKind::Review
        } else if commits_pushed == Some(0)
            && (text_has_review_verdict_marker(oc_summary)
                || text_has_review_verdict_marker(oc_loop_summary)
                || text_has_review_verdict_marker(&wc_summary)
                || text_has_review_verdict_marker(&loop_claims)
                || matches!(
                    wc_verdict.to_ascii_lowercase().as_str(),
                    "changes_requested" | "request_changes"
                )
                || linked_review.is_some_and(|r| {
                    matches!(r["state"].as_str(), Some("APPROVED" | "CHANGES_REQUESTED"))
                        || classify_verdict_text(linked_review_body).is_some()
                }))
        {
            RoundKind::Review
        } else {
            RoundKind::Implementation
        };

        let verdict =
            (kind == RoundKind::Review && status.eq_ignore_ascii_case("done")).then(|| {
                if let Some(pv) = published_verdict {
                    return pv;
                }
                let review_says_cr = linked_review.is_some_and(|r| {
                    r["state"] == "CHANGES_REQUESTED" || text_requests_changes(linked_review_body)
                });
                if text_requests_changes(oc_summary)
                    || text_requests_changes(oc_loop_summary)
                    || text_requests_changes(&wc_summary)
                    || text_requests_changes(&loop_claims)
                    || matches!(
                        wc_verdict.to_ascii_lowercase().as_str(),
                        "changes_requested" | "request_changes"
                    )
                    || review_says_cr
                {
                    ReviewVerdict::ChangesRequested
                } else {
                    ReviewVerdict::Approved
                }
            });

        let non_server_oc_summary = (!oc_summary.starts_with("Server ")
            && !oc_summary.starts_with("Published:"))
        .then_some(oc_summary)
        .unwrap_or_default();
        let prioritized_review =
            text_requests_changes(linked_review_body).then_some(linked_review_body);
        let raw_findings = [
            prioritized_review.unwrap_or_default(),
            wc_summary.as_str(),
            oc_loop_summary,
            loop_claims.as_str(),
            non_server_oc_summary,
        ]
        .into_iter()
        .find(|s| !s.trim().is_empty())
        .unwrap_or_default();
        let findings = raw_findings
            .lines()
            .filter(|l| !is_verdict_header_line(l))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(400)
            .collect::<String>();

        let key = if !c.url.is_empty() {
            c.url.to_owned()
        } else {
            let prefix: String = c.body.chars().take(80).collect();
            format!("outcome:{index}:{prefix}")
        };
        out.push(OutcomeSummary {
            key,
            status: status.to_owned(),
            kind,
            verdict,
            author_tier: parse_author_tier(server),
            author_backends: parse_author_backends(server),
            review_url,
            issue: pub_receipt.as_ref().and_then(|v| v["issue"].as_u64()),
            findings,
            index,
        });
    }
    out
}

pub(super) fn last_independent_review_oid(
    reviews: &[Value],
    outcomes: &[OutcomeSummary],
) -> Option<String> {
    let review_round_urls: Vec<&str> = outcomes
        .iter()
        .filter(|o| o.kind == RoundKind::Review)
        .filter_map(|o| o.review_url.as_deref())
        .collect();
    let mut last_oid = None;
    for r in reviews {
        let oid = r["commit"]["oid"]
            .as_str()
            .or_else(|| r["commit_id"].as_str())
            .unwrap_or_default();
        if oid.is_empty() {
            continue;
        }
        let author = r
            .get("author")
            .or_else(|| r.get("user"))
            .unwrap_or(&Value::Null);
        let url = r["url"]
            .as_str()
            .or_else(|| r["html_url"].as_str())
            .unwrap_or_default();
        let body = r["body"].as_str().unwrap_or_default();
        let independent = trusted_owner(author)
            || (!url.is_empty() && review_round_urls.contains(&url))
            || (outcome_bot(author) && !body.contains(SELF_REVIEW_DISCLAIMER));
        if independent {
            last_oid = Some(oid.to_owned());
        }
    }
    last_oid
}

fn backend_usable_for_review(
    backend: &str,
    entry: &Value,
    tier: super::worker_tier::WorkerTier,
    author_backends: &[String],
    require_different_backend: bool,
    distinct_tier_models: bool,
) -> bool {
    use super::worker_tier::{WorkerTier, strong_model};
    let positive = |v: &Value| v.as_f64().is_some_and(|n| n.is_finite() && n > 0.0);
    if entry["installed"] != true
        || !positive(&entry["free_slots"])
        || !positive(&entry["quota_free"])
        || (entry["score"].is_number() && !positive(&entry["score"]))
        || (tier == WorkerTier::Standard && backend == "copilot")
        || (require_different_backend && author_backends.iter().any(|b| b == backend))
    {
        return false;
    }
    let agy_group_usable = |group: &str| {
        let quota_ok = if entry["quota"]["groups"].is_object() {
            positive(&entry["quota"]["groups"][group]["quota_free"])
        } else {
            true
        };
        let score_ok = if entry["group_scores"].is_object() {
            positive(&entry["group_scores"][group])
        } else {
            true
        };
        quota_ok && score_ok
    };
    if let Some(models) = entry["models"].as_array() {
        return models.iter().filter_map(Value::as_str).any(|model| {
            if backend == "agy" {
                let group = if model.starts_with("gemini-") {
                    Some("gemini")
                } else if model.starts_with("claude-") || model.starts_with("gpt-oss") {
                    Some("claude")
                } else {
                    None
                };
                if group.is_some_and(|g| !agy_group_usable(g)) {
                    return false;
                }
            }
            match tier {
                WorkerTier::Strong => strong_model(backend, model),
                WorkerTier::Standard if distinct_tier_models => !strong_model(backend, model),
                WorkerTier::Standard => true,
            }
        });
    }
    if !entry["models"].is_null() {
        return false;
    }
    // Raw `agy_worker.py capacity --json` reports omit `models` (populated by
    // separate `models --backend` probes in `dispatch_loop`). Infer tier
    // eligibility from the backend and its group quotas.
    match backend {
        "codex" => tier == WorkerTier::Strong || !distinct_tier_models,
        "copilot" => tier == WorkerTier::Strong,
        "agy" => match tier {
            WorkerTier::Strong => agy_group_usable("claude"),
            WorkerTier::Standard if distinct_tier_models => agy_group_usable("gemini"),
            WorkerTier::Standard => agy_group_usable("gemini") || agy_group_usable("claude"),
        },
        _ => false,
    }
}

pub(super) fn select_reviewer_tier(
    author_tier: super::worker_tier::WorkerTier,
    author_backends: &[String],
    capacity: Option<&Value>,
) -> (super::worker_tier::WorkerTier, Option<String>) {
    use super::worker_tier::WorkerTier;
    let opposite = match author_tier {
        WorkerTier::Strong => WorkerTier::Standard,
        WorkerTier::Standard => WorkerTier::Strong,
    };
    let Some(backends) = capacity.and_then(|c| c["backends"].as_object()) else {
        return (opposite, None);
    };
    if backends.iter().any(|(name, entry)| {
        backend_usable_for_review(name, entry, opposite, author_backends, false, true)
    }) {
        return (opposite, None);
    }
    let mut best: Option<(&str, f64)> = None;
    for (name, entry) in backends {
        if backend_usable_for_review(name, entry, author_tier, author_backends, true, false) {
            let score = entry["score"]
                .as_f64()
                .or_else(|| entry["quota_free"].as_f64())
                .unwrap_or(0.0);
            if best.is_none_or(|(_, prev)| score > prev) {
                best = Some((name.as_str(), score));
            }
        }
    }
    if let Some((backend, _)) = best {
        (author_tier, Some(backend.to_owned()))
    } else {
        (opposite, None)
    }
}

fn tier_name(tier: super::worker_tier::WorkerTier) -> &'static str {
    match tier {
        super::worker_tier::WorkerTier::Standard => "standard",
        super::worker_tier::WorkerTier::Strong => "strong",
    }
}

fn build_review_brief(
    pr_number: u64,
    issue: Option<u64>,
    head: &str,
    prev_review_oid: Option<&str>,
    tier: super::worker_tier::WorkerTier,
    fallback_backend: Option<&str>,
) -> String {
    let issue_clause = issue.map_or_else(String::new, |n| format!(" for #{n}"));
    let acceptance_target = issue.map_or_else(
        || "the linked issue's acceptance criteria".to_owned(),
        |n| format!("#{n}'s acceptance criteria"),
    );
    let head_short = head.get(..12).unwrap_or(head);
    let diff_scope = match prev_review_oid.filter(|oid| !oid.is_empty() && *oid != head) {
        Some(prev) => {
            let prev_short = prev.get(..12).unwrap_or(prev);
            format!(
                "and scope the review to the diff since the last published review (`{prev_short}..{head_short}`)."
            )
        }
        None => format!("across the PR diff at head `{head_short}`."),
    };
    let mut brief = format!(
        "Independent review of PR #{pr_number}{issue_clause}: review only, push nothing.\n\
         Worker tier: {}\n\
         Focus on {acceptance_target} {diff_scope}\n\
         Publish a review verdict (`Verdict: APPROVE` or `Verdict: CHANGES REQUESTED`), or make the verdict (`APPROVED` or `CHANGES REQUESTED`) the first line of the summary. Rate any findings P0/P1/P2.",
        tier_name(tier),
    );
    if let Some(backend) = fallback_backend {
        brief.push_str(&format!(
            "\nPreferred reviewer backend: `{backend}` (opposite tier has no quota; use a different backend from the author round)."
        ));
    }
    brief
}

pub(super) fn canonicalize_review_brief(
    brief: &str,
    head: &str,
    prev_review_oid: Option<&str>,
    tier: super::worker_tier::WorkerTier,
    fallback_backend: Option<&str>,
) -> String {
    let tier_line = format!("Worker tier: {}", tier_name(tier));
    let mut lines: Vec<String> = brief
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.starts_with("Worker tier:") && !t.starts_with("Preferred reviewer backend:")
        })
        .map(str::to_owned)
        .collect();
    let insert_at = usize::from(!lines.is_empty());
    lines.insert(insert_at, tier_line);
    let mut out = lines.join("\n");
    if let Some(prev) = prev_review_oid.filter(|oid| !oid.is_empty() && *oid != head) {
        let prev_short = prev.get(..12).unwrap_or(prev);
        let head_short = head.get(..12).unwrap_or(head);
        if !out.contains(prev_short) {
            out.push_str(&format!(
                "\nScope the review to the diff since the last published review (`{prev_short}..{head_short}`)."
            ));
        }
    }
    let lower = out.to_ascii_lowercase();
    if !lower.contains("verdict") && !out.contains("APPROVED") && !out.contains("CHANGES REQUESTED")
    {
        out.push_str(
            "\nPublish a review verdict (`Verdict: APPROVE` or `Verdict: CHANGES REQUESTED`), or make the verdict (`APPROVED` or `CHANGES REQUESTED`) the first line of the summary.",
        );
    }
    if let Some(backend) = fallback_backend {
        out.push_str(&format!(
            "\nPreferred reviewer backend: `{backend}` (opposite tier has no quota; use a different backend from the author round)."
        ));
    }
    out
}

fn build_fix_brief(
    pr_number: u64,
    issue: Option<u64>,
    impl_tier: Option<super::worker_tier::WorkerTier>,
    review_ref: &str,
    findings: &str,
) -> String {
    let issue_clause = issue.map_or_else(String::new, |n| format!(" for #{n}"));
    let mut brief =
        format!("Address the `CHANGES REQUESTED` findings on PR #{pr_number}{issue_clause}.");
    if let Some(tier) = impl_tier {
        brief.push_str(&format!("\nWorker tier: {}", tier_name(tier)));
    }
    brief.push_str(&format!(
        "\nFix every P0/P1 defect from {review_ref}, add or update regression witnesses, run focused verification gates, and commit onto the PR branch."
    ));
    let clean = findings.replace(MARKER, "");
    if !clean.is_empty()
        && !secret_shaped(&clean)
        && !clean.to_ascii_lowercase().contains("review only")
    {
        brief.push_str(&format!("\nRequested changes: {clean}"));
    }
    brief
}

/// Same-repository `work/*` PR by the owner or publish App: the
/// PRs this owner-local reactor watches. Adoption itself no longer checks
/// the PR author (#1214); the reactor posts `/agent` as the owner, so it
/// deliberately stays on the owner's and the App's PRs.
fn director_pr(pr: &Value) -> bool {
    let branch = pr["head"]["ref"].as_str().unwrap_or_default();
    pr["head"]["repo"]["full_name"] == REPOSITORY
        && (pr["base"]["ref"] == "main"
            || (pr["base"]["repo"]["full_name"] == REPOSITORY
                && pr["base"]["ref"]
                    .as_str()
                    .is_some_and(super::valid_ref_branch)))
        && branch.starts_with("work/")
        && dispatch_branch(branch).is_none()
        && ((pr["user"]["login"] == "tjfontaine" && pr["user"]["type"] == "User")
            || super::publish_app_author(&pr["user"]))
}
/// A PR whose author's text may reach the session: the owner or the
/// publish App.
pub(crate) fn trusted_pr(pr: &Value) -> bool {
    trusted_owner(&pr["user"]) || super::publish_app_author(&pr["user"])
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

/// Adoption verdict, closing-reference count, and same-repo closing issues for a director PR.
pub(super) fn adoption_facts(
    gh: &mut dyn Github,
    pr: &Value,
) -> Result<(bool, Option<usize>, Vec<u64>), ScalerError> {
    let mut closing = None;
    let adoption = adopted_pr(pr, |read| {
        let value = gh.adoption(read)?;
        if value.get("data").is_some() {
            closing = Some(value.clone());
        }
        Ok(value)
    })?;
    let parsed = closing
        .as_ref()
        .and_then(|c| super::parse_closing_references(c).ok());
    let count = parsed.as_ref().map(|r| r.all.len());
    let issues = parsed
        .into_iter()
        .flat_map(|r| r.all)
        .filter(|r| r.repository == REPOSITORY)
        .map(|r| r.number)
        .collect();
    Ok((adoption.is_some(), count, issues))
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
        let mut closing_issues = Vec::new();
        // Automatic behaviours only for PRs created since the reactor's epoch.
        let recent = pr["created_at"].as_str().is_some_and(|c| c >= epoch);
        if director {
            let (verdict, count, issues) = adoption_facts(gh, pr)?;
            adoptable = verdict;
            closing_issues = issues;
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
            if e.class.human {
                memory.human_since_round = true;
                memory.unattended_rounds = 0;
            }
        }
        let excess = memory.seen.len().saturating_sub(SEEN_LIMIT);
        memory.seen.drain(..excess);
        let title = pr["title"].as_str().unwrap_or_default();
        let branch = pr["head"]["ref"].as_str().unwrap_or_default();
        let pr_run_active = active
            .iter()
            .any(|r| r["displayTitle"] == title || r["headBranch"] == branch);
        let has_trigger = fresh.iter().any(|e| e.class.trigger);
        let retry_deferred =
            memory.deferred_outcome.is_some() && !pr_run_active && active_total < GLOBAL_CAP;
        if !has_trigger && !retry_deferred {
            continue;
        }
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
        let fresh_users: Vec<Value> = fresh
            .iter()
            .map(|e| {
                json!({
                    "login": e.who,
                    "type": if e.class.human { "User" } else { "Bot" },
                })
            })
            .collect();
        let mut all_comments: Vec<CommentView<'_>> = node["comments"]["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| CommentView {
                url: c["url"].as_str().unwrap_or_default(),
                user: &c["author"],
                body: c["body"].as_str().unwrap_or_default(),
            })
            .collect();
        for (e, user) in fresh.iter().zip(&fresh_users) {
            if e.kind == "comment"
                && !all_comments.iter().any(|c| {
                    (!e.url.is_empty() && c.url == e.url) || (e.url.is_empty() && c.body == e.body)
                })
            {
                all_comments.push(CommentView {
                    url: &e.url,
                    user,
                    body: &e.body,
                });
            }
        }
        let waiting = repeated_blocker(
            all_comments
                .iter()
                .filter(|c| classify(c.user, c.body).is_some())
                .map(|c| if trusted_owner(c.user) { "" } else { c.body }),
        );
        if let Some(blocker) = waiting {
            memory.waiting_on = Some(blocker.clone());
            log.push(format!(
                "#{number}: waiting on {blocker}; repeated external blocker"
            ));
            continue;
        }
        let reviews = node["reviews"]["nodes"]
            .as_array()
            .map_or(&[][..], Vec::as_slice);
        let outcomes = parse_outcomes(&all_comments, reviews);
        let mut outcome_continuation = false;
        let mut continued_key = None;
        let mut auto_decision = None;
        if let Some(last) = outcomes.last() {
            let after = &all_comments[last.index + 1..];
            let round_triggered_after = after
                .iter()
                .any(|c| trusted_owner(c.user) && c.body.trim_start().starts_with("/agent"));
            let owner_chat_after = after.iter().any(|c| {
                trusted_owner(c.user)
                    && !c.body.contains(MARKER)
                    && !c.body.trim_start().starts_with("/agent")
                    && !is_signed_scoreboard_text(c.body)
            });
            if last.status.eq_ignore_ascii_case("done")
                && !round_triggered_after
                && !owner_chat_after
            {
                if last.kind == RoundKind::Review && last.verdict == Some(ReviewVerdict::Approved) {
                    memory.waiting_on = None;
                    log.push(format!(
                        "#{number}: independent review approved; no further round"
                    ));
                    continue;
                }
                if last.kind == RoundKind::Implementation
                    && memory.last_continued_outcome.as_deref() != Some(last.key.as_str())
                {
                    if let Some(wait) = ecosystem_wait_reason(
                        pr,
                        number,
                        &head,
                        &closing_issues,
                        last.issue,
                        &all_comments,
                        &mut |r| gh.adoption(r),
                    )? {
                        memory.waiting_on = Some(wait.clone());
                        log.push(format!("#{number}: waiting on {wait}"));
                        continue;
                    }
                    let issues =
                        resolve_pr_issues(pr, number, &closing_issues, last.issue, &mut |r| {
                            gh.adoption(r)
                        })?;
                    let cap = gh.capacity();
                    let author_tier = last
                        .author_tier
                        .unwrap_or(super::worker_tier::WorkerTier::Strong);
                    let (rev_tier, fallback) =
                        select_reviewer_tier(author_tier, &last.author_backends, cap.as_ref());
                    let prev_oid = last_independent_review_oid(reviews, &outcomes);
                    outcome_continuation = true;
                    continued_key = Some(last.key.clone());
                    auto_decision = Some(Decision {
                        action: Act::Round,
                        text: build_review_brief(
                            number,
                            issues.first().copied(),
                            &head,
                            prev_oid.as_deref(),
                            rev_tier,
                            fallback.as_deref(),
                        ),
                        reason: "independent review after Done implementation round".into(),
                    });
                } else if last.kind == RoundKind::Review
                    && last.verdict == Some(ReviewVerdict::ChangesRequested)
                    && memory.last_continued_outcome.as_deref() != Some(last.key.as_str())
                {
                    let issues =
                        resolve_pr_issues(pr, number, &closing_issues, last.issue, &mut |r| {
                            gh.adoption(r)
                        })?;
                    let impl_tier = outcomes
                        .iter()
                        .rev()
                        .find(|o| o.kind == RoundKind::Implementation)
                        .and_then(|o| o.author_tier);
                    outcome_continuation = true;
                    continued_key = Some(last.key.clone());
                    auto_decision = Some(Decision {
                        action: Act::Round,
                        text: build_fix_brief(
                            number,
                            issues.first().copied(),
                            impl_tier,
                            last.review_url.as_deref().unwrap_or(last.key.as_str()),
                            &last.findings,
                        ),
                        reason: "fix round after CHANGES REQUESTED review".into(),
                    });
                }
            }
        }
        memory.waiting_on = None;
        let decision = match auto_decision {
            Some(d) => d,
            None if !has_trigger => {
                memory.deferred_outcome = None;
                continue;
            }
            None => agent.decide(&context)?,
        };
        log.push(format!(
            "#{number}: decision {:?}: {}",
            decision.action, decision.reason
        ));
        let gate = Gate {
            eligible: adoptable || owned,
            pr_run_active,
            active_total,
            repeat_round: !outcome_continuation
                && memory.last_round_head.as_deref() == Some(head.as_str())
                && !memory.human_since_round,
            unattended: memory.unattended_rounds >= UNATTENDED_ROUNDS,
            reply_allowed: trusted_pr(pr) && fresh.iter().any(|e| e.class.human),
        };
        match enforce(&decision, &gate) {
            Effect::None => memory.deferred_outcome = None,
            Effect::Refused(why) => {
                memory.deferred_outcome = if gate.pr_run_active || gate.active_total >= GLOBAL_CAP {
                    continued_key
                } else {
                    None
                };
                log.push(format!("#{number}: refused: {why}"));
            }
            Effect::Post(body) => {
                memory.deferred_outcome = None;
                if decision.action == Act::Round {
                    memory.rounds += 1;
                    memory.last_round_head = Some(head.clone());
                    memory.last_round_at = Some(iso(now));
                    memory.human_since_round = false;
                    memory.unattended_rounds += 1;
                    if let Some(key) =
                        continued_key.or_else(|| outcomes.last().map(|o| o.key.clone()))
                    {
                        memory.last_continued_outcome = Some(key);
                    }
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

/// `at` minus [`RUN_LOOKBACK_SECS`], for the runs list `created` filter.
pub(crate) fn lookback(at: &str) -> String {
    parse_iso(at).map_or_else(
        || at.to_owned(),
        |s| iso(s.saturating_sub(RUN_LOOKBACK_SECS)),
    )
}
/// Inverse of [`iso`] for the same shape.
pub(crate) fn parse_iso(at: &str) -> Option<u64> {
    let n = |r: std::ops::Range<usize>| at.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86400 + n(11..13)? * 3600 + n(14..16)? * 60 + n(17..19)?).ok()
}
/// A log warning when an interaction limit (`GET .../interaction-limits`) no
/// longer keeps outsiders from commenting, or is about to lapse.
pub(crate) fn limit_warning(scope: &str, limit: &Value, now: u64) -> Option<String> {
    if limit["limit"] != "collaborators_only" {
        return Some(format!(
            "reactor: WARNING: {scope} interaction limit is not collaborators_only"
        ));
    }
    let expires = limit["expires_at"].as_str().unwrap_or_default();
    parse_iso(expires)
        .is_none_or(|at| at <= now + LIMIT_WARN_SECS)
        .then(|| format!("reactor: WARNING: {scope} interaction limit expires {expires}; renew it"))
}
/// [`limit_warning`] for the repository and the organization.
pub(crate) fn limit_warnings(root: &Path, now: u64) -> Vec<String> {
    [
        ("repo", format!("repos/{REPOSITORY}/interaction-limits")),
        ("org", "orgs/carrick-sh/interaction-limits".to_owned()),
    ]
    .into_iter()
    .filter_map(|(scope, path)| {
        super::gh(root, &["api", &path])
            .ok()
            .and_then(|out| serde_json::from_str(&out).ok())
            .map_or_else(
                || {
                    Some(format!(
                        "reactor: WARNING: cannot read the {scope} interaction limit"
                    ))
                },
                |limit| limit_warning(scope, &limit, now),
            )
    })
    .collect()
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
const FACTS_QUERY: &str = r#"query{repository(owner:"carrick-sh",name:"carrick"){pullRequests(states:OPEN,first:100){nodes{number commits(last:1){nodes{commit{committedDate statusCheckRollup{state}}}} reviews(last:50){nodes{databaseId url state body submittedAt commit{oid} author{login __typename}}} comments(last:50){nodes{databaseId url body author{login __typename}}}}}}}"#;
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
    fn workflow_runs(&mut self, created: &str) -> Result<Vec<Value>, ScalerError> {
        let pages: Value = serde_json::from_str(&super::gh(
            self.root,
            &[
                "api",
                "--paginate",
                "--slurp",
                &format!(
                    "repos/{REPOSITORY}/actions/runs?status=completed&created=%3E%3D{created}&per_page=100"
                ),
            ],
        )?)?;
        Ok(pages
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|p| p["workflow_runs"].as_array().into_iter().flatten())
            .cloned()
            .collect())
    }
    fn active_runs(&mut self, branch: &str) -> Result<Vec<Value>, ScalerError> {
        let page: Value = serde_json::from_str(&super::gh(
            self.root,
            &[
                "api",
                "-X",
                "GET",
                &format!("repos/{REPOSITORY}/actions/runs"),
                "-f",
                &format!("branch={branch}"),
                "-f",
                "status=in_progress",
                "-f",
                "per_page=50",
            ],
        )?)?;
        Ok(page["workflow_runs"]
            .as_array()
            .cloned()
            .unwrap_or_default())
    }
    fn run_jobs(&mut self, run: u64) -> Result<Vec<Value>, ScalerError> {
        let page: Value = serde_json::from_str(&super::gh(
            self.root,
            &[
                "api",
                &format!("repos/{REPOSITORY}/actions/runs/{run}/jobs?filter=latest&per_page=100"),
            ],
        )?)?;
        Ok(page["jobs"].as_array().cloned().unwrap_or_default())
    }
    fn adoption(&mut self, read: AdoptionRead) -> Result<Value, ScalerError> {
        match read {
            AdoptionRead::ClosingReferences(number) => {
                super::closing_references_response(self.root, number)
            }
            AdoptionRead::Parent(endpoint) => Ok(serde_json::from_str(&super::gh(
                self.root,
                &["api", &endpoint],
            )?)?),
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
    fn capacity(&mut self) -> Option<Value> {
        let dir = tempfile::tempdir().ok()?;
        let out = dir.path().join("capacity.json");
        let mut child = Command::new("agy_worker.py")
            .args(["capacity", "--json"])
            .current_dir(self.root)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out).ok()?)
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return None;
                    }
                    break;
                }
                Ok(None) => {
                    if Instant::now() > deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
        let parsed: Value = serde_json::from_slice(&std::fs::read(&out).ok()?).ok()?;
        parsed["backends"].is_object().then_some(parsed)
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
        pub workflow_runs: Vec<Value>,
        pub active_runs: Vec<Value>,
        pub jobs: std::collections::BTreeMap<u64, Vec<Value>>,
        pub closing: Vec<u64>,
        pub issues: std::collections::BTreeMap<u64, Value>,
        pub capacity: Option<Value>,
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
                AdoptionRead::Parent(_) => panic!("unexpected stack read"),
                AdoptionRead::Issue(n) => self.issues.get(&n).cloned().unwrap_or_else(|| {
                    json!({"number":n,"state":"open","user":{"login":"tjfontaine","type":"User"}})
                }),
            })
        }
        fn workflow_runs(&mut self, _: &str) -> Result<Vec<Value>, ScalerError> {
            Ok(self.workflow_runs.clone())
        }
        fn active_runs(&mut self, branch: &str) -> Result<Vec<Value>, ScalerError> {
            Ok(self
                .active_runs
                .iter()
                .filter(|r| r["head_branch"] == branch)
                .cloned()
                .collect())
        }
        fn run_jobs(&mut self, run: u64) -> Result<Vec<Value>, ScalerError> {
            Ok(self.jobs.get(&run).cloned().unwrap_or_default())
        }
        fn runs(&mut self) -> Result<Vec<Value>, ScalerError> {
            Ok(self.runs.clone())
        }
        fn post(&mut self, pr: u64, body: &str) -> Result<(), ScalerError> {
            self.posted.push((pr, body.to_owned()));
            Ok(())
        }
        fn capacity(&mut self) -> Option<Value> {
            self.capacity.clone()
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
    fn dispatch_reactor_limit_warning_and_iso_round_trip() {
        let now = 1_793_404_800; // 2026-10-31T00:00:00Z
        for secs in [0, 951_782_400, now, now + 86_399] {
            assert_eq!(parse_iso(&iso(secs)), Some(secs));
        }
        assert_eq!(parse_iso("garbage"), None);
        assert_eq!(lookback("2026-10-31T00:00:00Z"), "2026-10-30T21:00:00Z");
        let limit = |l: &str, at: &str| json!({"limit":l,"expires_at":at});
        assert_eq!(
            limit_warning(
                "org",
                &limit("collaborators_only", "2027-05-01T03:55:09Z"),
                now
            ),
            None
        );
        assert!(
            limit_warning(
                "org",
                &limit("collaborators_only", "2026-11-15T00:00:00Z"),
                now
            )
            .is_some_and(|w| w.contains("renew"))
        );
        assert!(limit_warning("repo", &json!({}), now).is_some());
        assert!(
            limit_warning(
                "repo",
                &limit("existing_users", "2027-05-01T00:00:00Z"),
                now
            )
            .is_some()
        );
    }

    #[test]
    fn dispatch_reactor_never_posts_credentials_or_unasked_replies() {
        let gate = |reply_allowed| Gate {
            eligible: true,
            pr_run_active: false,
            active_total: 0,
            repeat_round: false,
            unattended: false,
            reply_allowed,
        };
        let decide = |action, text: &str| Decision {
            action,
            text: text.into(),
            reason: String::new(),
        };
        assert_eq!(
            enforce(&decide(Act::Reply, "CI is green."), &gate(false)),
            Effect::Refused("no unanswered owner message on a trusted PR")
        );
        for text in [
            "see ghs_0123",
            "github_pat_11AB",
            "-----BEGIN RSA PRIVATE KEY",
            "AKIAIOSFODNN7",
            "split gh\np_0123 across lines",
            "GHP_UPPER",
            "- - - - - BEGIN spaced",
        ] {
            for action in [Act::Reply, Act::Round] {
                assert_eq!(
                    enforce(&decide(action, text), &gate(true)),
                    Effect::Refused("text looks like a credential"),
                    "{text}"
                );
            }
        }
        assert_eq!(
            enforce(&decide(Act::Round, &"b".repeat(4001)), &gate(true)),
            Effect::Refused("brief too long")
        );
        assert_eq!(
            enforce(&decide(Act::Reply, "CI is green."), &gate(true)),
            Effect::Post(format!("CI is green.\n\n{MARKER}"))
        );
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
            unattended: false,
            reply_allowed: true,
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
            unattended: false,
            reply_allowed: true,
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
            (0..GLOBAL_CAP)
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

    fn fixture_1825() -> Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/dispatch-1825-outcomes.json"
        ))
        .unwrap()
    }

    fn dispatch_pr(number: u64, issue: u64, run: u64, sha: &str) -> Value {
        let mut p = pr(number, &format!("work/dispatch-{issue}-{run}"));
        p["user"] = json!({"login":"carrick-workers[bot]","type":"Bot"});
        p["head"]["sha"] = json!(sha);
        p["body"] = json!(format!("Closes #{issue}"));
        p
    }

    fn outcome_event(pr_num: u64, record: &Value, at: &str) -> Value {
        json!({
            "id": record["id"],
            "issue_url": format!("https://api.github.com/repos/{REPOSITORY}/issues/{pr_num}"),
            "html_url": record["url"],
            "user": {"login": "carrick-workers[bot]", "type": "Bot"},
            "body": record["body"],
            "created_at": at,
            "updated_at": at,
        })
    }

    #[test]
    fn replay_1825_done_implementation_starts_one_review_round_on_opposite_tier() {
        let fx = fixture_1825();
        let impl_done = &fx["pr_1781_impl_done"];
        let head = impl_done["head"].as_str().unwrap();

        // Strong-tier implementation Done -> starts one standard-tier review round.
        // Author worker self-reviews (even on an earlier Continuing commit) must not
        // masquerade as an independent review or shrink the first review's diff.
        let mut fake = FakeGh {
            prs: vec![dispatch_pr(1781, 1780, 42300000001, head)],
            facts: vec![json!({
                "number": 1781,
                "commits": {"nodes": [{"commit": {"committedDate": "2026-10-30T23:50:00Z", "statusCheckRollup": {"state": "SUCCESS"}}}]},
                "reviews": {"nodes": [
                    {
                        "databaseId": 9000,
                        "url": "https://github.com/carrick-sh/carrick/pull/1781#pullrequestreview-9000",
                        "state": "COMMENTED",
                        "commit": {"oid": "a000000000000000000000000000000000000000"},
                        "body": "## Worker review\n\nReviewed head: a000000000000000000000000000000000000000\n\nThis is the worker's own review; it is not an independent review.\n\nEarlier checkpoint self-review.",
                        "submittedAt": "2026-10-30T23:40:00Z",
                        "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                    },
                    {
                        "databaseId": 9001,
                        "url": "https://github.com/carrick-sh/carrick/pull/1781#pullrequestreview-9001",
                        "state": "COMMENTED",
                        "commit": {"oid": head},
                        "body": format!("## Worker review\n\nReviewed head: {head}\n\nThis is the worker's own review; it is not an independent review.\n\nAuthor self-review."),
                        "submittedAt": "2026-10-30T23:58:00Z",
                        "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                    }
                ]},
                "comments": {"nodes": [{
                    "databaseId": 7001,
                    "url": impl_done["url"],
                    "body": impl_done["body"],
                    "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                }]}
            })],
            comments: vec![outcome_event(1781, impl_done, "2026-10-30T23:59:00Z")],
            closing: vec![1780],
            ..FakeGh::default()
        };
        let mut inert = agent(Act::Ignore, "");
        let mut state = State::default();
        let log = cycle(&mut fake, &mut inert, &mut state, NOW, EPOCH, false).unwrap();
        assert_eq!(fake.posted.len(), 1, "{log:?}");
        let posted = &fake.posted[0].1;
        assert_eq!(
            crate::dispatch_worker::worker_tier::decide("", "", posted, &[]).tier,
            crate::dispatch_worker::worker_tier::WorkerTier::Standard,
            "author strong must select standard reviewer tier:\n{posted}"
        );
        let lower = posted.to_ascii_lowercase();
        assert!(lower.contains("review only"), "{posted}");
        assert!(lower.contains("push nothing"), "{posted}");
        assert!(lower.contains("verdict"), "{posted}");
        assert!(lower.contains("first line of the summary"), "{posted}");
        assert!(posted.contains("#1780"), "{posted}");
        assert!(
            !posted.contains("a00000000000.."),
            "author self-review must not narrow first independent review:\n{posted}"
        );
        // Subsequent poll starts no second review round.
        cycle(&mut fake, &mut inert, &mut state, NOW + 60, EPOCH, false).unwrap();
        assert_eq!(fake.posted.len(), 1);

        // Reverse direction: standard-tier author Done -> strong-tier review round.
        let std_done = &fx["pr_1815_standard_impl_done"];
        let std_head = std_done["head"].as_str().unwrap();
        let mut std_gh = FakeGh {
            prs: vec![dispatch_pr(1815, 1814, 42300000010, std_head)],
            facts: vec![json!({
                "number": 1815,
                "comments": {"nodes": [{
                    "databaseId": 7101,
                    "url": std_done["url"],
                    "body": std_done["body"],
                    "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                }]}
            })],
            comments: vec![outcome_event(1815, std_done, "2026-10-30T23:59:00Z")],
            closing: vec![1814],
            ..FakeGh::default()
        };
        cycle(
            &mut std_gh,
            &mut inert,
            &mut State::default(),
            NOW,
            EPOCH,
            false,
        )
        .unwrap();
        assert_eq!(std_gh.posted.len(), 1);
        assert_eq!(
            crate::dispatch_worker::worker_tier::decide("", "", &std_gh.posted[0].1, &[]).tier,
            crate::dispatch_worker::worker_tier::WorkerTier::Strong,
            "author standard must select strong reviewer tier:\n{}",
            std_gh.posted[0].1
        );

        // Fallback when opposite tier has no quota: same tier with a different backend.
        let mut no_std_quota = FakeGh {
            prs: vec![dispatch_pr(1781, 1780, 42300000001, head)],
            facts: vec![json!({
                "number": 1781,
                "comments": {"nodes": [{
                    "databaseId": 7001,
                    "url": impl_done["url"],
                    "body": impl_done["body"],
                    "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                }]}
            })],
            comments: vec![outcome_event(1781, impl_done, "2026-10-30T23:59:00Z")],
            closing: vec![1780],
            capacity: Some(json!({
                "backends": {
                    "agy": {
                        "installed": true,
                        "free_slots": 2,
                        "quota_free": 0.0,
                        "score": 0.0,
                        "quota": {"groups": {"gemini": {"quota_free": 0.0}, "claude": {"quota_free": 0.0}}},
                        "models": ["gemini-4-argon-high", "claude-opus-4-6-thinking"]
                    },
                    "codex": {
                        "installed": true,
                        "free_slots": 2,
                        "quota_free": 0.7,
                        "score": 0.7,
                        "models": ["gpt-6.1-sol"]
                    },
                    "copilot": {
                        "installed": true,
                        "free_slots": 2,
                        "quota_free": 1.0,
                        "score": 1.0,
                        "models": ["claude-opus-4-6"]
                    }
                }
            })),
            ..FakeGh::default()
        };
        cycle(
            &mut no_std_quota,
            &mut inert,
            &mut State::default(),
            NOW,
            EPOCH,
            false,
        )
        .unwrap();
        assert_eq!(no_std_quota.posted.len(), 1);
        let fallback_brief = &no_std_quota.posted[0].1;
        assert_eq!(
            crate::dispatch_worker::worker_tier::decide("", "", fallback_brief, &[]).tier,
            crate::dispatch_worker::worker_tier::WorkerTier::Strong,
            "exhausted opposite tier must stay on author tier:\n{fallback_brief}"
        );
        assert!(
            fallback_brief.contains("copilot"),
            "fallback brief must select a non-author backend:\n{fallback_brief}"
        );
    }

    #[test]
    fn replay_1825_review_round_ending_done_does_not_start_another() {
        let fx = fixture_1825();
        let impl_done = &fx["pr_1781_impl_done"];
        let rev_done = &fx["pr_1781_review_approved"];
        let head = rev_done["head"].as_str().unwrap();

        // Even on a fresh State (e.g. director-started review round or restarted reactor)
        // and even if the agent would return Round, a review round ending Done starts none.
        let mut fake = FakeGh {
            prs: vec![dispatch_pr(1781, 1780, 42300000001, head)],
            facts: vec![json!({
                "number": 1781,
                "comments": {"nodes": [
                    {"databaseId": 7001, "url": impl_done["url"], "body": impl_done["body"], "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}},
                    {"databaseId": 7002, "url": "https://github.com/carrick-sh/carrick/pull/1781#issuecomment-7002", "body": "/agent\nWorker tier: standard\nIndependent review (review only, push nothing).", "author": {"login": "tjfontaine", "__typename": "User"}},
                    {"databaseId": 7003, "url": rev_done["url"], "body": rev_done["body"], "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}}
                ]}
            })],
            comments: vec![outcome_event(1781, rev_done, "2026-10-30T23:59:00Z")],
            closing: vec![1780],
            ..FakeGh::default()
        };
        let mut eager = agent(Act::Round, "spurious second review");
        let mut state = State::default();
        let log = cycle(&mut fake, &mut eager, &mut state, NOW, EPOCH, false).unwrap();
        assert!(fake.posted.is_empty(), "{log:?}");
        assert_eq!(
            eager.calls, 0,
            "review Done must not consult LLM to start another round"
        );

        // Also coordinates with #1813 / PR #1816 typed `Round kind: review` server line.
        let mut typed_body = rev_done["body"].as_str().unwrap().replacen(
            "Worker tier: standard",
            "Round kind: review\nWorker tier: standard",
            1,
        );
        // Even if someone contrived a non-zero commit count, explicit `Round kind: review` wins.
        typed_body = typed_body.replacen(
            "commits pushed this round: 0;",
            "commits pushed this round: 1;",
            1,
        );
        let typed_record = json!({
            "id": 7099,
            "url": "https://github.com/carrick-sh/carrick/pull/1781#issuecomment-7099",
            "body": typed_body,
        });
        let mut typed_gh = FakeGh {
            prs: vec![dispatch_pr(1781, 1780, 42300000001, head)],
            facts: vec![json!({
                "number": 1781,
                "comments": {"nodes": [
                    {"databaseId": 7099, "url": typed_record["url"], "body": typed_record["body"], "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}}
                ]}
            })],
            comments: vec![outcome_event(1781, &typed_record, "2026-10-30T23:59:00Z")],
            closing: vec![1780],
            ..FakeGh::default()
        };
        cycle(
            &mut typed_gh,
            &mut eager,
            &mut State::default(),
            NOW,
            EPOCH,
            false,
        )
        .unwrap();
        assert!(typed_gh.posted.is_empty());
    }

    #[test]
    fn replay_1825_ecosystem_pr_without_signed_scoreboard_records_named_wait() {
        let fx = fixture_1825();
        let eco_done = &fx["pr_1740_ecosystem_impl_done"];
        let eco_head = eco_done["head"].as_str().unwrap();

        // Direct ecosystem blocker (#1506, plus sweep guard 19's full root set).
        for blocker in [887_u64, 1733, 1791, 1506, 1671, 1756] {
            let mut fake = FakeGh {
                prs: vec![dispatch_pr(1740, blocker, 42205586763, eco_head)],
                facts: vec![json!({
                    "number": 1740,
                    "comments": {"nodes": [{
                        "databaseId": 7201,
                        "url": eco_done["url"],
                        "body": eco_done["body"].as_str().unwrap().replace("1506", &blocker.to_string()),
                        "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                    }]}
                })],
                comments: vec![outcome_event(1740, eco_done, "2026-10-30T23:59:00Z")],
                closing: vec![blocker],
                ..FakeGh::default()
            };
            let mut state = State::default();
            let log = cycle(
                &mut fake,
                &mut agent(Act::Round, "must not fire"),
                &mut state,
                NOW,
                EPOCH,
                false,
            )
            .unwrap();
            assert!(fake.posted.is_empty(), "blocker #{blocker}: {log:?}");
            let wait = state.prs[&1740].waiting_on.as_deref().unwrap_or_default();
            assert!(
                wait.contains("signed scoreboard") && wait.contains(&format!("#{blocker}")),
                "blocker #{blocker} missing named wait: {wait:?}"
            );
        }

        // Stale scoreboard on an older commit does not unlock the current head;
        // a signed scoreboard on the current head clears the wait and starts review.
        let mut fake = FakeGh {
            prs: vec![dispatch_pr(1740, 1506, 42205586763, eco_head)],
            facts: vec![json!({
                "number": 1740,
                "comments": {"nodes": [
                    {
                        "databaseId": 7199,
                        "url": "https://github.com/carrick-sh/carrick/pull/1740#issuecomment-7199",
                        "body": "Signed scoreboard on `5e9780c5c634`: cpython/go smoke PASS.",
                        "author": {"login": "tjfontaine", "__typename": "User"}
                    },
                    {
                        "databaseId": 7201,
                        "url": eco_done["url"],
                        "body": eco_done["body"],
                        "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                    }
                ]}
            })],
            comments: vec![outcome_event(1740, eco_done, "2026-10-30T23:59:00Z")],
            closing: vec![1506],
            ..FakeGh::default()
        };
        let mut state = State::default();
        let mut inert = agent(Act::Ignore, "");
        cycle(&mut fake, &mut inert, &mut state, NOW, EPOCH, false).unwrap();
        assert!(fake.posted.is_empty());
        assert!(state.prs[&1740].waiting_on.is_some());

        // Director records signed scoreboard on current head -> review round starts.
        let board = json!({
            "id": 7202,
            "issue_url": format!("https://api.github.com/repos/{REPOSITORY}/issues/1740"),
            "html_url": "https://github.com/carrick-sh/carrick/pull/1740#issuecomment-7202",
            "user": {"login": "tjfontaine", "type": "User"},
            "body": format!("Signed scoreboard on `{}`: smoke-signed PASS, Go child ENOSYS=0.", &eco_head[..12]),
            "created_at": "2026-10-31T00:02:00Z",
            "updated_at": "2026-10-31T00:02:00Z",
        });
        fake.comments = vec![board];
        fake.facts[0]["comments"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "databaseId": 7202,
                "url": "https://github.com/carrick-sh/carrick/pull/1740#issuecomment-7202",
                "body": format!("Signed scoreboard on `{}`: smoke-signed PASS, Go child ENOSYS=0.", &eco_head[..12]),
                "author": {"login": "tjfontaine", "__typename": "User"}
            }));
        cycle(&mut fake, &mut inert, &mut state, NOW + 120, EPOCH, false).unwrap();
        assert_eq!(state.prs[&1740].waiting_on, None);
        assert_eq!(fake.posted.len(), 1);
        assert_eq!(
            crate::dispatch_worker::worker_tier::decide("", "", &fake.posted[0].1, &[]).tier,
            crate::dispatch_worker::worker_tier::WorkerTier::Standard
        );

        // Successor issue/PR (#1829 split from #1733) is also gated until signed scoreboard,
        // and unblocks when `Signed gate: **PASS**` lands on its head.
        let succ_done = &fx["pr_1830_ecosystem_successor_done"];
        let succ_head = succ_done["head"].as_str().unwrap();
        let mut issues = std::collections::BTreeMap::new();
        issues.insert(
            1829,
            json!({
                "number": 1829,
                "state": "open",
                "title": "Split constructor slice",
                "body": "Split from #1733 so the base PR stays small.",
                "user": {"login": "tjfontaine", "type": "User"}
            }),
        );
        let mut succ_gh = FakeGh {
            prs: vec![dispatch_pr(1830, 1829, 42300000030, succ_head)],
            facts: vec![json!({
                "number": 1830,
                "comments": {"nodes": [{
                    "databaseId": 7301,
                    "url": succ_done["url"],
                    "body": succ_done["body"],
                    "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                }]}
            })],
            comments: vec![outcome_event(1830, succ_done, "2026-10-30T23:59:00Z")],
            closing: vec![1829],
            issues,
            ..FakeGh::default()
        };
        let mut succ_state = State::default();
        cycle(&mut succ_gh, &mut inert, &mut succ_state, NOW, EPOCH, false).unwrap();
        assert!(succ_gh.posted.is_empty());
        assert!(
            succ_state.prs[&1830]
                .waiting_on
                .as_deref()
                .is_some_and(|w| w.contains("signed scoreboard") && w.contains("#1733")),
            "{:?}",
            succ_state.prs[&1830].waiting_on
        );
        let gate_pass = format!("Signed gate: **PASS**\n\n- Candidate: `{succ_head}`\n");
        succ_gh.comments = vec![json!({
            "id": 7302,
            "issue_url": format!("https://api.github.com/repos/{REPOSITORY}/issues/1830"),
            "html_url": "https://github.com/carrick-sh/carrick/pull/1830#issuecomment-7302",
            "user": {"login": "github-actions[bot]", "type": "Bot"},
            "body": gate_pass,
            "created_at": "2026-10-31T00:05:00Z",
            "updated_at": "2026-10-31T00:05:00Z",
        })];
        succ_gh.facts[0]["comments"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "databaseId": 7302,
                "url": "https://github.com/carrick-sh/carrick/pull/1830#issuecomment-7302",
                "body": gate_pass,
                "author": {"login": "github-actions[bot]", "__typename": "Bot"}
            }));
        cycle(
            &mut succ_gh,
            &mut inert,
            &mut succ_state,
            NOW + 300,
            EPOCH,
            false,
        )
        .unwrap();
        assert_eq!(succ_state.prs[&1830].waiting_on, None);
        assert_eq!(succ_gh.posted.len(), 1);
    }

    #[test]
    fn replay_1825_changes_requested_starts_fix_round_and_scopes_next_review_diff() {
        let fx = fixture_1825();
        let impl_done = &fx["pr_1781_impl_done"];
        let rev_cr = &fx["pr_1781_review_changes_requested"];
        let fix_done = &fx["pr_1781_fix_done"];
        let h1 = impl_done["head"].as_str().unwrap();
        let h2 = fix_done["head"].as_str().unwrap();

        let mut fake = FakeGh {
            prs: vec![dispatch_pr(1781, 1780, 42300000001, h1)],
            facts: vec![json!({
                "number": 1781,
                "reviews": {"nodes": []},
                "comments": {"nodes": [{
                    "databaseId": 7001,
                    "url": impl_done["url"],
                    "body": impl_done["body"],
                    "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                }]}
            })],
            comments: vec![outcome_event(1781, impl_done, "2026-10-30T23:59:00Z")],
            closing: vec![1780],
            ..FakeGh::default()
        };
        let mut state = State::default();
        let mut inert = agent(Act::Ignore, "");

        // Step 1: Done implementation round on H1 -> Review Round 1 on H1.
        cycle(&mut fake, &mut inert, &mut state, NOW, EPOCH, false).unwrap();
        assert_eq!(fake.posted.len(), 1);

        // Step 2: Review Round 1 finishes on H1 with CHANGES REQUESTED -> Fix Round 2 on H1.
        let review_trigger_body = fake.posted[0].1.clone();
        fake.facts[0]["reviews"]["nodes"] = json!([{
            "databaseId": 9002,
            "url": "https://github.com/carrick-sh/carrick/pull/1781#pullrequestreview-9002",
            "state": "COMMENTED",
            "commit": {"oid": h1},
            "body": format!("## Worker review\n\nReviewed head: {h1}\n\nThis is the worker's own review; it is not an independent review.\n\nCHANGES REQUESTED\nP1: off-by-one in boundary validation."),
            "submittedAt": "2026-10-31T00:05:00Z",
            "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
        }]);
        fake.facts[0]["comments"]["nodes"]
            .as_array_mut()
            .unwrap()
            .extend([
                json!({
                    "databaseId": 7002,
                    "url": "https://github.com/carrick-sh/carrick/pull/1781#issuecomment-7002",
                    "body": review_trigger_body,
                    "author": {"login": "tjfontaine", "__typename": "User"}
                }),
                json!({
                    "databaseId": 7004,
                    "url": rev_cr["url"],
                    "body": rev_cr["body"],
                    "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                }),
            ]);
        fake.comments = vec![outcome_event(1781, rev_cr, "2026-10-31T00:06:00Z")];
        let log = cycle(&mut fake, &mut inert, &mut state, NOW + 360, EPOCH, false).unwrap();
        assert_eq!(
            fake.posted.len(),
            2,
            "CHANGES REQUESTED must start a fix round on H1: {log:?}"
        );
        let fix_brief = &fake.posted[1].1;
        assert!(
            !fix_brief.to_ascii_lowercase().contains("review only"),
            "fix round must not be a review-only brief:\n{fix_brief}"
        );

        // Step 3: Fix Round 2 pushes H2 and ends Done (with its own worker self-review #9003 on H2)
        // -> Review Round 3 starts on H2 scoped to H1..H2 (since #pullrequestreview-9002).
        fake.prs[0]["head"]["sha"] = json!(h2);
        fake.facts[0]["reviews"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "databaseId": 9003,
                "url": "https://github.com/carrick-sh/carrick/pull/1781#pullrequestreview-9003",
                "state": "COMMENTED",
                "commit": {"oid": h2},
                "body": format!("## Worker review\n\nReviewed head: {h2}\n\nThis is the worker's own review; it is not an independent review.\n\nAuthor self-review of fix."),
                "submittedAt": "2026-10-31T00:15:00Z",
                "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
            }));
        fake.facts[0]["comments"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "databaseId": 7006,
                "url": fix_done["url"],
                "body": fix_done["body"],
                "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
            }));
        fake.comments = vec![outcome_event(1781, fix_done, "2026-10-31T00:16:00Z")];
        let log = cycle(&mut fake, &mut inert, &mut state, NOW + 960, EPOCH, false).unwrap();
        assert_eq!(fake.posted.len(), 3, "{log:?}");
        let second_review = &fake.posted[2].1;
        assert!(
            second_review.contains(&format!("{}..{}", &h1[..12], &h2[..12])),
            "second review round must scope diff since last published review ({h1}..{h2}):\n{second_review}"
        );
    }

    #[test]
    fn replay_1825_round_loop_guard_caps_chains() {
        let fx = fixture_1825();
        let impl_done = &fx["pr_1781_impl_done"];
        let rev1_cr = &fx["pr_1781_review_changes_requested"];
        let fix_done = &fx["pr_1781_fix_done"];
        let rev2_cr = &fx["pr_1781_review2_changes_requested"];
        let h1 = impl_done["head"].as_str().unwrap();
        let h2 = fix_done["head"].as_str().unwrap();

        let mut fake = FakeGh {
            prs: vec![dispatch_pr(1781, 1780, 42300000001, h1)],
            facts: vec![json!({
                "number": 1781,
                "reviews": {"nodes": []},
                "comments": {"nodes": [{
                    "databaseId": 7001,
                    "url": impl_done["url"],
                    "body": impl_done["body"],
                    "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                }]}
            })],
            comments: vec![outcome_event(1781, impl_done, "2026-10-30T23:59:00Z")],
            closing: vec![1780],
            ..FakeGh::default()
        };
        let mut state = State::default();
        let mut inert = agent(Act::Ignore, "");

        // Round 1 (unattended = 1): review on H1.
        cycle(&mut fake, &mut inert, &mut state, NOW, EPOCH, false).unwrap();
        assert_eq!(state.prs[&1781].unattended_rounds, 1);

        // Round 2 (unattended = 2): fix on H1 after CHANGES REQUESTED.
        let r1_brief = fake.posted[0].1.clone();
        fake.facts[0]["comments"]["nodes"]
            .as_array_mut()
            .unwrap()
            .extend([
                json!({"databaseId": 7002, "url": "https://github.com/carrick-sh/carrick/pull/1781#issuecomment-7002", "body": r1_brief, "author": {"login": "tjfontaine", "__typename": "User"}}),
                json!({"databaseId": 7004, "url": rev1_cr["url"], "body": rev1_cr["body"], "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}}),
            ]);
        fake.comments = vec![outcome_event(1781, rev1_cr, "2026-10-31T00:06:00Z")];
        cycle(&mut fake, &mut inert, &mut state, NOW + 360, EPOCH, false).unwrap();
        assert_eq!(state.prs[&1781].unattended_rounds, 2);

        // Round 3 (unattended = 3 == UNATTENDED_ROUNDS): review on H2 after fix Done.
        fake.prs[0]["head"]["sha"] = json!(h2);
        fake.facts[0]["comments"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"databaseId": 7006, "url": fix_done["url"], "body": fix_done["body"], "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}}));
        fake.comments = vec![outcome_event(1781, fix_done, "2026-10-31T00:16:00Z")];
        cycle(&mut fake, &mut inert, &mut state, NOW + 960, EPOCH, false).unwrap();
        assert_eq!(state.prs[&1781].unattended_rounds, UNATTENDED_ROUNDS);
        assert_eq!(fake.posted.len(), 3);

        // Round 4 attempt: Review 2 requests changes again -> capped by UNATTENDED_ROUNDS!
        let r2_brief = fake.posted[2].1.clone();
        fake.facts[0]["comments"]["nodes"]
            .as_array_mut()
            .unwrap()
            .extend([
                json!({"databaseId": 7007, "url": "https://github.com/carrick-sh/carrick/pull/1781#issuecomment-7007", "body": r2_brief, "author": {"login": "tjfontaine", "__typename": "User"}}),
                json!({"databaseId": 7008, "url": rev2_cr["url"], "body": rev2_cr["body"], "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}}),
            ]);
        fake.comments = vec![outcome_event(1781, rev2_cr, "2026-10-31T00:26:00Z")];
        let log = cycle(&mut fake, &mut inert, &mut state, NOW + 1560, EPOCH, false).unwrap();
        assert_eq!(
            fake.posted.len(),
            3,
            "round-loop guard must cap unattended review/fix chain at {UNATTENDED_ROUNDS}: {log:?}"
        );
        assert!(
            log.iter().any(|l| l.contains("unattended round limit")),
            "{log:?}"
        );
    }

    #[test]
    fn replay_1825_transient_in_flight_or_cap_defers_then_starts_review() {
        let fx = fixture_1825();
        let impl_done = &fx["pr_1781_impl_done"];
        let head = impl_done["head"].as_str().unwrap();

        // Outcome comment arrives a few seconds before its dispatch-worker job marks
        // itself completed: poll 1 refuses while in-flight, poll 2 starts the review
        // once the job finishes even with no new comments.
        let mut fake = FakeGh {
            prs: vec![dispatch_pr(1781, 1780, 42300000001, head)],
            facts: vec![json!({
                "number": 1781,
                "comments": {"nodes": [{
                    "databaseId": 7001,
                    "url": impl_done["url"],
                    "body": impl_done["body"],
                    "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                }]}
            })],
            comments: vec![outcome_event(1781, impl_done, "2026-10-30T23:59:00Z")],
            runs: vec![json!({
                "status": "in_progress",
                "displayTitle": "PR 1781",
                "headBranch": "work/dispatch-1780-42300000001"
            })],
            closing: vec![1780],
            ..FakeGh::default()
        };
        let mut state = State::default();
        let mut inert = agent(Act::Ignore, "");
        let log1 = cycle(&mut fake, &mut inert, &mut state, NOW, EPOCH, false).unwrap();
        assert!(fake.posted.is_empty(), "{log1:?}");
        assert!(
            log1.iter().any(|l| l.contains("in flight for this PR")),
            "{log1:?}"
        );
        // Job finishes before next poll; no new comments arrive.
        fake.runs.clear();
        fake.comments.clear();
        let log2 = cycle(&mut fake, &mut inert, &mut state, NOW + 60, EPOCH, false).unwrap();
        assert_eq!(fake.posted.len(), 1, "{log2:?}");
        // Poll 3 is a no-op.
        cycle(&mut fake, &mut inert, &mut state, NOW + 120, EPOCH, false).unwrap();
        assert_eq!(fake.posted.len(), 1);
    }

    #[test]
    fn replay_1825_verdict_parsing_raw_capacity_and_recorded_1740_outcome() {
        use crate::dispatch_worker::worker_tier::WorkerTier;
        let fx = fixture_1825();
        let impl_done = &fx["pr_1781_impl_done"];
        let rev_done = &fx["pr_1781_review_approved"];
        let head = rev_done["head"].as_str().unwrap();

        // 1. "Verdict: APPROVE ... no changes requested." must NOT trigger a false-positive fix round.
        let approve_no_cr = rev_done["body"].as_str().unwrap().replace(
            "APPROVED\\n\\nVerified #1780 acceptance criteria",
            "Verdict: APPROVE\\n\\nAll checks pass; no changes requested.",
        );
        let rec_ok = json!({
            "id": 7401,
            "url": "https://github.com/carrick-sh/carrick/pull/1781#issuecomment-7401",
            "body": approve_no_cr,
        });
        let mut ok_gh = FakeGh {
            prs: vec![dispatch_pr(1781, 1780, 42300000001, head)],
            facts: vec![json!({
                "number": 1781,
                "comments": {"nodes": [
                    {"databaseId": 7001, "url": impl_done["url"], "body": impl_done["body"], "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}},
                    {"databaseId": 7401, "url": rec_ok["url"], "body": rec_ok["body"], "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}}
                ]}
            })],
            comments: vec![outcome_event(1781, &rec_ok, "2026-10-30T23:59:00Z")],
            closing: vec![1780],
            ..FakeGh::default()
        };
        let mut state = State::default();
        cycle(
            &mut ok_gh,
            &mut agent(Act::Ignore, ""),
            &mut state,
            NOW,
            EPOCH,
            false,
        )
        .unwrap();
        assert!(
            ok_gh.posted.is_empty(),
            "Verdict: APPROVE with 'no changes requested.' must not start a fix round: {:?}",
            ok_gh.posted
        );

        // Linked PR review with Verdict: CHANGES_REQUESTED starts a fix round.
        let neutral_summary = rev_done["body"].as_str().unwrap().replace(
            "APPROVED\\n\\nVerified #1780 acceptance criteria",
            "Completed review; see linked PR review.",
        );
        let rec_cr = json!({
            "id": 7402,
            "url": "https://github.com/carrick-sh/carrick/pull/1781#issuecomment-7402",
            "body": neutral_summary,
        });
        let mut cr_gh = FakeGh {
            prs: vec![dispatch_pr(1781, 1780, 42300000001, head)],
            facts: vec![json!({
                "number": 1781,
                "reviews": {"nodes": [{
                    "databaseId": 9001,
                    "url": "https://github.com/carrick-sh/carrick/pull/1781#pullrequestreview-9001",
                    "state": "COMMENTED",
                    "commit": {"oid": head},
                    "body": "## Worker review\n\nVerdict: CHANGES_REQUESTED\n\nP1: missing boundary validation.",
                    "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                }]},
                "comments": {"nodes": [
                    {"databaseId": 7402, "url": rec_cr["url"], "body": rec_cr["body"], "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}}
                ]}
            })],
            comments: vec![outcome_event(1781, &rec_cr, "2026-10-30T23:59:00Z")],
            closing: vec![1780],
            ..FakeGh::default()
        };
        cycle(
            &mut cr_gh,
            &mut agent(Act::Ignore, ""),
            &mut State::default(),
            NOW,
            EPOCH,
            false,
        )
        .unwrap();
        assert_eq!(cr_gh.posted.len(), 1);

        // 2. Raw `agy_worker.py capacity --json` (no `models` array) selects opposite tier or
        //    falls back to a non-author backend on the same tier when opposite-tier group quota is 0.
        let raw_cap_ok = json!({
            "backends": {
                "codex": {"installed": true, "free_slots": 4, "quota_free": 0.7, "score": 0.7},
                "agy": {
                    "installed": true,
                    "free_slots": 4,
                    "quota_free": 0.85,
                    "score": 0.85,
                    "quota": {"groups": {"gemini": {"quota_free": 0.85}, "claude": {"quota_free": 0.1}}},
                    "group_scores": {"gemini": 0.85, "claude": 0.1}
                },
                "copilot": {"installed": true, "free_slots": 2, "quota_free": 0.5, "score": 0.5}
            }
        });
        assert_eq!(
            select_reviewer_tier(WorkerTier::Strong, &["codex".into()], Some(&raw_cap_ok)),
            (WorkerTier::Standard, None)
        );
        let raw_cap_gemini_exhausted = json!({
            "backends": {
                "codex": {"installed": true, "free_slots": 4, "quota_free": 0.7, "score": 0.7},
                "agy": {
                    "installed": true,
                    "free_slots": 4,
                    "quota_free": 0.8,
                    "score": 0.8,
                    "quota": {"groups": {"gemini": {"quota_free": 0.0}, "claude": {"quota_free": 0.8}}},
                    "group_scores": {"gemini": 0.0, "claude": 0.8}
                },
                "copilot": {"installed": true, "free_slots": 2, "quota_free": 0.4, "score": 0.4}
            }
        });
        assert_eq!(
            select_reviewer_tier(
                WorkerTier::Strong,
                &["codex".into()],
                Some(&raw_cap_gemini_exhausted)
            ),
            (WorkerTier::Strong, Some("agy".into()))
        );
        assert_eq!(
            select_reviewer_tier(
                WorkerTier::Standard,
                &["agy".into()],
                Some(&raw_cap_gemini_exhausted)
            ),
            (WorkerTier::Strong, None)
        );

        // 3. 0-commit Done implementation round after an earlier reactor round on the same head
        //    still starts its one independent review round.
        let mut same_head_state = State::default();
        same_head_state.prs.insert(
            1781,
            Memory {
                rounds: 1,
                unattended_rounds: 1,
                last_round_head: Some(head.to_owned()),
                last_round_at: Some("2026-10-30T23:40:00Z".into()),
                last_continued_outcome: Some(
                    "https://github.com/carrick-sh/carrick/pull/1781#issuecomment-6999".into(),
                ),
                ..Memory::default()
            },
        );
        let mut same_head_gh = FakeGh {
            prs: vec![dispatch_pr(1781, 1780, 42300000001, head)],
            facts: vec![json!({
                "number": 1781,
                "comments": {"nodes": [
                    {"databaseId": 7001, "url": impl_done["url"], "body": impl_done["body"], "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}}
                ]}
            })],
            comments: vec![outcome_event(1781, impl_done, "2026-10-30T23:59:00Z")],
            closing: vec![1780],
            ..FakeGh::default()
        };
        cycle(
            &mut same_head_gh,
            &mut agent(Act::Ignore, ""),
            &mut same_head_state,
            NOW,
            EPOCH,
            false,
        )
        .unwrap();
        assert_eq!(same_head_gh.posted.len(), 1);
        assert_eq!(same_head_state.prs[&1781].unattended_rounds, 2);

        // 4. Recorded multi-worker PR #1740 (#1506) outcome from dispatch-1763-outcomes.json
        //    adapted to Done waits on signed scoreboard, then starts a standard-tier review.
        let recorded_1763: Vec<Value> = serde_json::from_str(include_str!(
            "../tests/fixtures/dispatch-1763-outcomes.json"
        ))
        .unwrap();
        let rec_1740 = recorded_1763
            .iter()
            .find(|e| e["source"].as_str().unwrap().contains("/pull/1740#"))
            .unwrap();
        let rec_1740_done = json!({
            "id": 6688992437_u64,
            "url": rec_1740["source"],
            "body": rec_1740["body"]
                .as_str()
                .unwrap()
                .replacen("Dispatch outcome: Blocked", "Dispatch outcome: Done", 1)
                .replacen("\"status\": \"blocked\"", "\"status\": \"done\"", 1),
        });
        let head_1740 = "537d60de93ec5bdc39bb0f168ab784111be6af8e";
        let mut gh_1740 = FakeGh {
            prs: vec![dispatch_pr(1740, 1506, 42205586763, head_1740)],
            facts: vec![json!({
                "number": 1740,
                "comments": {"nodes": [{
                    "databaseId": 6688992437_u64,
                    "url": rec_1740_done["url"],
                    "body": rec_1740_done["body"],
                    "author": {"login": "carrick-workers[bot]", "__typename": "Bot"}
                }]}
            })],
            comments: vec![outcome_event(1740, &rec_1740_done, "2026-10-30T23:59:00Z")],
            closing: vec![1506],
            ..FakeGh::default()
        };
        let mut st_1740 = State::default();
        cycle(
            &mut gh_1740,
            &mut agent(Act::Ignore, ""),
            &mut st_1740,
            NOW,
            EPOCH,
            false,
        )
        .unwrap();
        assert!(gh_1740.posted.is_empty());
        assert!(
            st_1740.prs[&1740]
                .waiting_on
                .as_deref()
                .is_some_and(|w| w.contains("signed scoreboard") && w.contains("#1506"))
        );
    }
}
