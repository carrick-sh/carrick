//! Reactor session mode (#1193): a listening Claude Code session instead of
//! one `claude -p` decision per cycle.
//!
//! `feed` is the reactor poller without the decision step: it appends one
//! JSON line per new PR event to a mailbox. `mcp` is a stdio MCP server whose
//! read tools let per-PR subagents investigate and whose two act tools,
//! `reply` and `request_round`, are the only effects, each checked by
//! [`super::enforce`] under the same gates as the poll loop.
use super::{
    Act, AdoptionRead, Class, Decision, Effect, Gate, Github, Live, MARKER, QUIET_SECS, REPOSITORY,
    ScalerError, adopted_pr, adoption_facts, bot, classify, clip, director_pr, enforce, gather,
    iso, owned_pr,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const EXCERPT: usize = 300;
const SEEN_LIMIT: usize = 200;

#[derive(clap::Args, Debug)]
pub struct FeedOpts {
    /// Mailbox (JSON lines, appended).
    #[arg(long)]
    mailbox: Option<PathBuf>,
    /// Feed state (cursor, epoch, per-PR memory); separate from `run`'s state.
    #[arg(long)]
    state: Option<PathBuf>,
    /// Epoch override (`YYYY-MM-DDTHH:MM:SSZ`) for new/quiet/needs-closes events.
    #[arg(long)]
    since: Option<String>,
    /// One poll, then exit (otherwise poll every 60 s).
    #[arg(long)]
    once: bool,
}
#[derive(clap::Args, Debug)]
pub struct McpOpts {
    /// Tool server state (round heads and times).
    #[arg(long)]
    state: Option<PathBuf>,
    /// Report would-be comments instead of posting them.
    #[arg(long)]
    dry_run: bool,
}

fn support(name: &str) -> Result<PathBuf, ScalerError> {
    let home = std::env::var_os("HOME").ok_or(ScalerError::Guard("HOME unset"))?;
    Ok(PathBuf::from(home)
        .join("Library/Application Support/carrick-reactor")
        .join(name))
}
fn now() -> Result<u64, ScalerError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ScalerError::Guard("clock before epoch"))?
        .as_secs())
}
fn load<T: Default + for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ScalerError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e.into()),
    }
}
fn save<T: Serialize>(path: &Path, value: &T) -> Result<(), ScalerError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
fn held(pr: &Value) -> bool {
    pr["labels"]
        .as_array()
        .is_some_and(|l| l.iter().any(|l| l["name"] == "agent:hold"))
}

// ---------------------------------------------------------------- feed

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct FeedState {
    epoch: Option<String>,
    cursor: Option<String>,
    prs: BTreeMap<u64, FeedMemory>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
struct FeedMemory {
    seen: Vec<String>,
    announced: bool,
    ci_red_head: Option<String>,
    quiet_head: Option<String>,
    closes_flagged: bool,
}

/// One poll: the new mailbox lines, in order.
pub(super) fn feed_cycle(
    gh: &mut dyn Github,
    state: &mut FeedState,
    now: u64,
    epoch: &str,
) -> Result<Vec<Value>, ScalerError> {
    let since = state
        .cursor
        .clone()
        .unwrap_or_else(|| iso(now.saturating_sub(3600)));
    let mut g = gather(gh, &since)?;
    let open: Vec<u64> = g.prs.iter().filter_map(|p| p["number"].as_u64()).collect();
    state.prs.retain(|n, _| open.contains(n));
    let mut out = Vec::new();
    for pr in &g.prs {
        let Some(number) = pr["number"].as_u64() else {
            continue;
        };
        if held(pr) {
            continue;
        }
        let head = pr["head"]["sha"].as_str().unwrap_or_default();
        let memory = state.prs.entry(number).or_default();
        let line = |id: String, kind: &str, author: &str, url: &str, at: &str, text: &str| {
            json!({"id":id,"pr":number,"kind":kind,"author":author,"url":url,
                "created_at":at,"head":head,"excerpt":text.chars().take(EXCERPT).collect::<String>()})
        };
        for e in g.events.remove(&number).unwrap_or_default() {
            if memory.seen.contains(&e.id) {
                continue;
            }
            memory.seen.push(e.id.clone());
            // An owner `/agent` command is the dispatch workflow's, not ours.
            if e.class.trigger {
                let kind = if e.class.human { e.kind } else { "outcome" };
                out.push(line(e.id, kind, &e.who, &e.url, &e.at, &e.body));
            }
        }
        let excess = memory.seen.len().saturating_sub(SEEN_LIMIT);
        memory.seen.drain(..excess);
        let director = director_pr(pr);
        let recent = pr["created_at"].as_str().is_some_and(|c| c >= epoch);
        let url = pr["html_url"].as_str().unwrap_or_default();
        let author = pr["user"]["login"].as_str().unwrap_or("?");
        let title = pr["title"].as_str().unwrap_or_default();
        let at = iso(now);
        if director && recent && !memory.announced {
            memory.announced = true;
            out.push(line(
                format!("new_pr:{number}"),
                "new_pr",
                author,
                url,
                pr["created_at"].as_str().unwrap_or_default(),
                title,
            ));
        }
        let commit = &g.facts.get(&number).unwrap_or(&Value::Null)["commits"]["nodes"][0]["commit"];
        let ci = commit["statusCheckRollup"]["state"]
            .as_str()
            .unwrap_or_default();
        if (director || owned_pr(pr))
            && matches!(ci, "FAILURE" | "ERROR")
            && memory.ci_red_head.as_deref() != Some(head)
        {
            memory.ci_red_head = Some(head.to_owned());
            out.push(line(
                format!("ci_red:{number}:{head}"),
                "ci_red",
                "ci",
                url,
                &at,
                &format!("CI {ci} on {head}"),
            ));
        }
        if director && recent {
            let (adoptable, count) = adoption_facts(gh, pr)?;
            if count != Some(1) && !memory.closes_flagged {
                memory.closes_flagged = true;
                out.push(line(
                    format!("needs_closes:{number}"),
                    "needs_closes",
                    author,
                    url,
                    &at,
                    &format!(
                        "{} closing references; adoption needs exactly one",
                        count.map_or("unknown".into(), |c| c.to_string())
                    ),
                ));
            }
            let quiet = commit["committedDate"]
                .as_str()
                .is_some_and(|d| d <= iso(now.saturating_sub(QUIET_SECS)).as_str());
            if adoptable && quiet && memory.quiet_head.as_deref() != Some(head) {
                memory.quiet_head = Some(head.to_owned());
                out.push(line(
                    format!("quiet_pr:{number}:{head}"),
                    "quiet_pr",
                    author,
                    url,
                    &at,
                    "Adoptable director PR with no push for 15 minutes",
                ));
            }
        }
    }
    state.cursor = Some(g.cursor);
    Ok(out)
}

fn feed_once(root: &Path, opts: &FeedOpts) -> Result<(), ScalerError> {
    let state_path = opts
        .state
        .clone()
        .map_or_else(|| support("feed-state.json"), Ok)?;
    let mailbox = opts
        .mailbox
        .clone()
        .map_or_else(|| support("mailbox.jsonl"), Ok)?;
    let mut state: FeedState = load(&state_path)?;
    let now = now()?;
    if let Some(since) = &opts.since
        && !super::rfc3339(since)
    {
        return Err(ScalerError::Usage(format!(
            "--since must be YYYY-MM-DDTHH:MM:SSZ, got {since:?}"
        )));
    }
    let epoch = state.epoch.get_or_insert_with(|| iso(now)).clone();
    let epoch = opts.since.clone().unwrap_or(epoch);
    let lines = feed_cycle(&mut Live { root }, &mut state, now, &epoch)?;
    if let Some(parent) = mailbox.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&mailbox)?;
    for line in &lines {
        writeln!(file, "{line}")?;
    }
    file.flush()?;
    save(&state_path, &state)?;
    println!(
        "reactor feed: {} event(s) at {} (epoch {epoch})",
        lines.len(),
        iso(now)
    );
    Ok(())
}
pub(super) fn feed(root: &Path, opts: &FeedOpts) -> Result<(), ScalerError> {
    if opts.once {
        return feed_once(root, opts);
    }
    loop {
        if let Err(error) = feed_once(root, opts) {
            eprintln!("reactor feed: cycle failed: {error}");
        }
        std::thread::sleep(Duration::from_secs(60));
    }
}

// ---------------------------------------------------------------- mcp

/// GitHub transport for the tool server; tests substitute a fake.
pub(super) trait Remote {
    /// One REST object.
    fn get(&mut self, endpoint: &str) -> Result<Value, ScalerError>;
    /// Every page of a REST list.
    fn list(&mut self, endpoint: &str) -> Result<Vec<Value>, ScalerError>;
    /// Raw `gh` output (diff, run log, PR JSON fields).
    fn text(&mut self, args: &[&str]) -> Result<String, ScalerError>;
    fn adoption(&mut self, read: AdoptionRead) -> Result<Value, ScalerError>;
    fn runs(&mut self) -> Result<Vec<Value>, ScalerError>;
    fn post(&mut self, pr: u64, body: &str) -> Result<(), ScalerError>;
}
impl Remote for Live<'_> {
    fn get(&mut self, endpoint: &str) -> Result<Value, ScalerError> {
        Ok(serde_json::from_str(&super::super::gh(
            self.root,
            &["api", endpoint],
        )?)?)
    }
    fn list(&mut self, endpoint: &str) -> Result<Vec<Value>, ScalerError> {
        let pages: Vec<Vec<Value>> = serde_json::from_str(&super::super::gh(
            self.root,
            &["api", "--paginate", "--slurp", endpoint],
        )?)?;
        Ok(pages.into_iter().flatten().collect())
    }
    fn text(&mut self, args: &[&str]) -> Result<String, ScalerError> {
        super::super::gh(self.root, args)
    }
    fn adoption(&mut self, read: AdoptionRead) -> Result<Value, ScalerError> {
        Github::adoption(self, read)
    }
    fn runs(&mut self) -> Result<Vec<Value>, ScalerError> {
        Github::runs(self)
    }
    fn post(&mut self, pr: u64, body: &str) -> Result<(), ScalerError> {
        Github::post(self, pr, body)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct ToolState {
    prs: BTreeMap<u64, RoundMemory>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
struct RoundMemory {
    rounds: u32,
    last_round_head: Option<String>,
    last_round_at: Option<String>,
}

pub(super) struct Server<'a> {
    pub remote: &'a mut dyn Remote,
    pub state: PathBuf,
    pub now: u64,
    pub dry_run: bool,
}

fn schema(props: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":props,"required":required,"additionalProperties":false})
}
pub(super) fn tools() -> Value {
    let pr = json!({"type":"integer","description":"PR number"});
    json!([
        {"name":"read_pr","description":"PR title, body, head, base, labels, CI rollup, closing references, adoptable/owned.",
         "inputSchema":schema(json!({"pr":pr}),&["pr"])},
        {"name":"read_thread","description":"Issue comments, reviews and review comments, newest last.",
         "inputSchema":schema(json!({"pr":pr,"limit":{"type":"integer","description":"default 30, max 100"}}),&["pr"])},
        {"name":"read_diff","description":"Unified diff of the PR, truncated to max_bytes.",
         "inputSchema":schema(json!({"pr":pr,"max_bytes":{"type":"integer","description":"default 60000, max 400000"}}),&["pr"])},
        {"name":"read_ci","description":"Failing checks and a bounded tail of the failing job logs.",
         "inputSchema":schema(json!({"pr":pr}),&["pr"])},
        {"name":"read_outcomes","description":"Dispatch outcome comments on the PR.",
         "inputSchema":schema(json!({"pr":pr}),&["pr"])},
        {"name":"read_issue","description":"An issue's title, state, labels and body.",
         "inputSchema":schema(json!({"n":{"type":"integer","description":"issue number"}}),&["n"])},
        {"name":"reply","description":"Post a plain-text reply on the PR as the owner, marked as the reactor's. Never a command.",
         "inputSchema":schema(json!({"pr":pr,"text":{"type":"string"}}),&["pr","text"])},
        {"name":"request_round","description":"Post `/agent <brief>` to start one dispatch round. Refused unless the PR is adoptable or owned, no dispatch run is in flight for it, fewer than 4 runs are in flight, and no reactor round already ran on this head without a human comment since.",
         "inputSchema":schema(json!({"pr":pr,"brief":{"type":"string","description":"what the worker should do and how to prove it"}}),&["pr","brief"])}
    ])
}

fn ci_rollup(remote: &mut dyn Remote, pr: u64) -> Result<Value, ScalerError> {
    let raw: Value = serde_json::from_str(&remote.text(&[
        "pr",
        "view",
        &pr.to_string(),
        "-R",
        REPOSITORY,
        "--json",
        "statusCheckRollup",
    ])?)?;
    let (mut failing, mut pending, mut passed) = (Vec::new(), 0, 0);
    for c in raw["statusCheckRollup"].as_array().into_iter().flatten() {
        let name = c["name"].as_str().or(c["context"].as_str()).unwrap_or("?");
        let verdict = c["conclusion"]
            .as_str()
            .filter(|s| !s.is_empty())
            .or(c["state"].as_str())
            .unwrap_or("");
        match verdict {
            "FAILURE" | "ERROR" | "TIMED_OUT" | "CANCELLED" | "ACTION_REQUIRED"
            | "STARTUP_FAILURE" => {
                failing.push(json!({"name":name,"verdict":verdict,
                    "url":c["detailsUrl"].as_str().or(c["targetUrl"].as_str()).unwrap_or_default()}));
            }
            "SUCCESS" | "NEUTRAL" | "SKIPPED" => passed += 1,
            _ => pending += 1,
        }
    }
    Ok(json!({"failing":failing,"pending":pending,"passed":passed}))
}
fn closing(remote: &mut dyn Remote, pr: u64) -> Result<Vec<String>, ScalerError> {
    let refs = super::super::parse_closing_references(
        &remote.adoption(AdoptionRead::ClosingReferences(pr))?,
    )?;
    Ok(refs
        .all
        .iter()
        .map(|r| format!("{}#{}", r.repository, r.number))
        .collect())
}
fn eligible(remote: &mut dyn Remote, pr: &Value) -> Result<(bool, bool), ScalerError> {
    let owned = pr["state"] == "open" && owned_pr(pr);
    let adoptable = adopted_pr(pr, |read| remote.adoption(read))?.is_some();
    Ok((owned, adoptable))
}
fn thread(remote: &mut dyn Remote, pr: u64) -> Result<Vec<Value>, ScalerError> {
    let mut all = Vec::new();
    for c in remote.list(&format!(
        "repos/{REPOSITORY}/issues/{pr}/comments?per_page=100"
    ))? {
        all.push(
            json!({"kind":"comment","author":c["user"]["login"],"bot":bot(&c["user"]),
            "at":c["created_at"],"url":c["html_url"],"body":c["body"]}),
        );
    }
    for r in remote.list(&format!(
        "repos/{REPOSITORY}/pulls/{pr}/reviews?per_page=100"
    ))? {
        all.push(
            json!({"kind":"review","author":r["user"]["login"],"bot":bot(&r["user"]),
            "at":r["submitted_at"],"url":r["html_url"],"state":r["state"],"body":r["body"]}),
        );
    }
    for c in remote.list(&format!(
        "repos/{REPOSITORY}/pulls/{pr}/comments?per_page=100"
    ))? {
        all.push(json!({"kind":"review_comment","author":c["user"]["login"],"bot":bot(&c["user"]),
            "at":c["created_at"],"url":c["html_url"],"path":c["path"],"line":c["line"],"body":c["body"]}));
    }
    all.sort_by(|a, b| a["at"].as_str().cmp(&b["at"].as_str()));
    Ok(all)
}
fn arg_u64(args: &Value, key: &str) -> Result<u64, String> {
    args[key]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(format!("`{key}` must be a positive integer"))
}
fn arg_str<'v>(args: &'v Value, key: &str) -> Result<&'v str, String> {
    args[key]
        .as_str()
        .ok_or(format!("`{key}` must be a string"))
}

impl Server<'_> {
    /// One tool call: `Ok` text for the model, `Err` a refusal or failure.
    pub(super) fn call(&mut self, name: &str, args: &Value) -> Result<String, String> {
        let fail = |e: ScalerError| e.to_string();
        let remote = &mut *self.remote;
        match name {
            "read_pr" => {
                let n = arg_u64(args, "pr")?;
                let pr = remote
                    .get(&format!("repos/{REPOSITORY}/pulls/{n}"))
                    .map_err(fail)?;
                let (owned, adoptable) = eligible(remote, &pr).map_err(fail)?;
                let out = json!({"number":n,"title":pr["title"],"state":pr["state"],"draft":pr["draft"],
                    "author":pr["user"]["login"],"head":{"ref":pr["head"]["ref"],"sha":pr["head"]["sha"]},
                    "base":pr["base"]["ref"],"labels":pr["labels"].as_array().into_iter().flatten().map(|l| l["name"].clone()).collect::<Vec<_>>(),
                    "closing":closing(remote, n).map_err(fail)?,"ci":ci_rollup(remote, n).map_err(fail)?,
                    "adoptable":adoptable,"owned_dispatch_pr":owned,"agent_hold":held(&pr),
                    "body":clip(pr["body"].as_str().unwrap_or_default())});
                Ok(out.to_string())
            }
            "read_thread" => {
                let n = arg_u64(args, "pr")?;
                let limit = args["limit"].as_u64().unwrap_or(30).clamp(1, 100) as usize;
                let mut all = thread(remote, n).map_err(fail)?;
                let skip = all.len().saturating_sub(limit);
                for item in &mut all {
                    item["body"] = json!(clip(item["body"].as_str().unwrap_or_default()));
                }
                Ok(Value::from(all.split_off(skip)).to_string())
            }
            "read_diff" => {
                let n = arg_u64(args, "pr")?;
                let max = args["max_bytes"]
                    .as_u64()
                    .unwrap_or(60_000)
                    .clamp(1, 400_000) as usize;
                let diff = remote
                    .text(&["pr", "diff", &n.to_string(), "-R", REPOSITORY])
                    .map_err(fail)?;
                let mut end = diff.len().min(max);
                while !diff.is_char_boundary(end) {
                    end -= 1;
                }
                let note = if end < diff.len() {
                    format!("\n[truncated at {end} of {} bytes]", diff.len())
                } else {
                    String::new()
                };
                Ok(format!("{}{note}", &diff[..end]))
            }
            "read_ci" => {
                let n = arg_u64(args, "pr")?;
                let mut rollup = ci_rollup(remote, n).map_err(fail)?;
                let pattern =
                    regex::Regex::new(r"/actions/runs/(\d+)").map_err(|e| e.to_string())?;
                let mut runs: Vec<String> = Vec::new();
                for f in rollup["failing"].as_array().into_iter().flatten() {
                    if let Some(id) = pattern
                        .captures(f["url"].as_str().unwrap_or_default())
                        .map(|c| c[1].to_owned())
                        && !runs.contains(&id)
                        && runs.len() < 2
                    {
                        runs.push(id);
                    }
                }
                let mut logs = Vec::new();
                for id in runs {
                    let log = remote
                        .text(&["run", "view", &id, "-R", REPOSITORY, "--log-failed"])
                        .unwrap_or_else(|e| format!("log unavailable: {e}"));
                    let mut start = log.len().saturating_sub(6000);
                    while !log.is_char_boundary(start) {
                        start += 1;
                    }
                    logs.push(json!({"run":id,"tail":&log[start..]}));
                }
                rollup["logs"] = json!(logs);
                Ok(rollup.to_string())
            }
            "read_outcomes" => {
                let n = arg_u64(args, "pr")?;
                let outcomes: Vec<Value> = remote
                    .list(&format!("repos/{REPOSITORY}/issues/{n}/comments?per_page=100"))
                    .map_err(fail)?
                    .into_iter()
                    .filter(|c| classify(&c["user"], c["body"].as_str().unwrap_or_default()) == Some(Class { trigger: true, human: false }))
                    .map(|c| json!({"at":c["created_at"],"url":c["html_url"],"body":c["body"].as_str().unwrap_or_default().chars().take(4000).collect::<String>()}))
                    .collect();
                let skip = outcomes.len().saturating_sub(10);
                Ok(Value::from(outcomes[skip..].to_vec()).to_string())
            }
            "read_issue" => {
                let n = arg_u64(args, "n")?;
                let i = remote
                    .get(&format!("repos/{REPOSITORY}/issues/{n}"))
                    .map_err(fail)?;
                Ok(json!({"number":n,"title":i["title"],"state":i["state"],"author":i["user"]["login"],
                    "labels":i["labels"].as_array().into_iter().flatten().map(|l| l["name"].clone()).collect::<Vec<_>>(),
                    "body":i["body"].as_str().unwrap_or_default().chars().take(6000).collect::<String>()}).to_string())
            }
            "reply" | "request_round" => self.act(name, args),
            _ => Err(format!("unknown tool {name}")),
        }
    }

    fn act(&mut self, name: &str, args: &Value) -> Result<String, String> {
        let fail = |e: ScalerError| e.to_string();
        let n = arg_u64(args, "pr")?;
        let pr = self
            .remote
            .get(&format!("repos/{REPOSITORY}/pulls/{n}"))
            .map_err(fail)?;
        if held(&pr) {
            return Err("refused: PR is labelled agent:hold".into());
        }
        let head = pr["head"]["sha"].as_str().unwrap_or_default().to_owned();
        let mut state: ToolState = load(&self.state).map_err(fail)?;
        let (decision, gate) = if name == "reply" {
            let decision = Decision {
                action: Act::Reply,
                text: arg_str(args, "text")?.into(),
                reason: String::new(),
            };
            (
                decision,
                Gate {
                    eligible: false,
                    pr_run_active: false,
                    active_total: 0,
                    repeat_round: false,
                },
            )
        } else {
            let decision = Decision {
                action: Act::Round,
                text: arg_str(args, "brief")?.into(),
                reason: String::new(),
            };
            let (owned, adoptable) = eligible(self.remote, &pr).map_err(fail)?;
            let active: Vec<Value> = self
                .remote
                .runs()
                .map_err(fail)?
                .into_iter()
                .filter(|r| r["status"] != "completed")
                .collect();
            let pr_run_active = active
                .iter()
                .any(|r| r["displayTitle"] == pr["title"] || r["headBranch"] == pr["head"]["ref"]);
            let memory = state.prs.get(&n);
            let repeat_round = match memory
                .and_then(|m| Some((m.last_round_head.as_deref()?, m.last_round_at.clone()?)))
            {
                Some((last, at)) if last == head => !self.human_since(n, &at).map_err(fail)?,
                _ => false,
            };
            (
                decision,
                Gate {
                    eligible: owned || adoptable,
                    pr_run_active,
                    active_total: active.len(),
                    repeat_round,
                },
            )
        };
        match enforce(&decision, &gate) {
            Effect::None => Ok("nothing to do".into()),
            Effect::Refused(why) => Err(format!("refused: {why}")),
            Effect::Post(body) => {
                if self.dry_run {
                    return Ok(format!("dry run, would post on #{n}:\n{body}"));
                }
                self.remote.post(n, &body).map_err(fail)?;
                if decision.action == Act::Round {
                    let memory = state.prs.entry(n).or_default();
                    memory.rounds += 1;
                    memory.last_round_head = Some(head);
                    memory.last_round_at = Some(iso(self.now));
                    save(&self.state, &state).map_err(fail)?;
                }
                Ok(format!("posted on #{n}"))
            }
        }
    }
    /// A non-bot, non-reactor comment or review after `at`.
    fn human_since(&mut self, pr: u64, at: &str) -> Result<bool, ScalerError> {
        Ok(thread(self.remote, pr)?.iter().any(|item| {
            item["at"].as_str().is_some_and(|t| t > at)
                && item["kind"] != "review_comment"
                && !item["bot"].as_bool().unwrap_or(true)
                && !item["body"].as_str().unwrap_or_default().contains(MARKER)
        }))
    }

    /// One JSON-RPC message; `None` for notifications.
    pub(super) fn handle(&mut self, msg: &Value) -> Option<Value> {
        let id = msg.get("id")?.clone();
        let result = match msg["method"].as_str().unwrap_or_default() {
            "initialize" => json!({
                "protocolVersion": msg["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "carrick-reactor", "version": env!("CARGO_PKG_VERSION")}
            }),
            "ping" => json!({}),
            "tools/list" => json!({"tools": tools()}),
            "tools/call" => {
                let name = msg["params"]["name"].as_str().unwrap_or_default();
                let args = msg["params"]
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let (text, error) = match self.call(name, &args) {
                    Ok(text) => (text, false),
                    Err(text) => (text, true),
                };
                json!({"content":[{"type":"text","text":text}],"isError":error})
            }
            method => {
                return Some(json!({"jsonrpc":"2.0","id":id,
                    "error":{"code":-32601,"message":format!("method not found: {method}")}}));
            }
        };
        Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
    }
}

pub(super) fn mcp(root: &Path, opts: &McpOpts) -> Result<(), ScalerError> {
    let state = opts
        .state
        .clone()
        .map_or_else(|| support("tools-state.json"), Ok)?;
    let mut live = Live { root };
    let stdout = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => Server {
                remote: &mut live,
                state: state.clone(),
                now: now()?,
                dry_run: opts.dry_run,
            }
            .handle(&msg),
            Err(_) => Some(
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}),
            ),
        };
        if let Some(reply) = reply {
            let mut out = stdout.lock();
            writeln!(out, "{reply}")?;
            out.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::GLOBAL_CAP;
    use super::super::tests::{FakeGh, comment, gh, pr};
    use super::*;

    const EPOCH: &str = "2026-10-30T23:00:00Z";
    const NOW: u64 = 1_793_404_800;

    #[test]
    fn dispatch_reactor_feed_writes_event_lines() {
        let mut fake = gh(
            vec![pr(20, "work/feed")],
            vec![
                comment(20, 1, "tjfontaine", "User", "why is this red?"),
                comment(
                    20,
                    2,
                    "carrick-workers[bot]",
                    "Bot",
                    "## Dispatch outcome: blocked",
                ),
                comment(20, 3, "github-actions[bot]", "Bot", "unrelated"),
                comment(20, 4, "tjfontaine", "User", &format!("mine\n\n{MARKER}")),
                comment(20, 5, "tjfontaine", "User", "/agent fix it"),
            ],
        );
        fake.facts = vec![json!({"number":20,"commits":{"nodes":[{"commit":{
            "committedDate":"2026-10-30T23:00:00Z","statusCheckRollup":{"state":"FAILURE"}}}]}})];
        let mut state = FeedState::default();
        let lines = feed_cycle(&mut fake, &mut state, NOW, EPOCH).unwrap();
        let kinds: Vec<&str> = lines.iter().map(|l| l["kind"].as_str().unwrap()).collect();
        assert_eq!(
            kinds,
            ["comment", "outcome", "new_pr", "ci_red", "quiet_pr"],
            "{lines:#?}"
        );
        for key in [
            "id",
            "pr",
            "kind",
            "author",
            "url",
            "created_at",
            "head",
            "excerpt",
        ] {
            assert!(lines.iter().all(|l| l.get(key).is_some()), "missing {key}");
        }
        assert_eq!(lines[0]["excerpt"], "why is this red?");
        assert_eq!(lines[1]["author"], "carrick-workers[bot]");
        // The next poll sees the same data and emits nothing new.
        assert!(
            feed_cycle(&mut fake, &mut state, NOW, EPOCH)
                .unwrap()
                .is_empty()
        );
        // A PR without exactly one closing reference is flagged once.
        let mut unclosed = gh(vec![pr(21, "work/unclosed")], vec![]);
        unclosed.closing = vec![];
        let mut state = FeedState::default();
        let lines = feed_cycle(&mut unclosed, &mut state, NOW, EPOCH).unwrap();
        assert_eq!(
            lines.iter().filter(|l| l["kind"] == "needs_closes").count(),
            1
        );
        assert!(
            feed_cycle(&mut unclosed, &mut state, NOW, EPOCH)
                .unwrap()
                .is_empty()
        );
        // Old PRs get no automatic events; held PRs get none at all.
        let mut old = pr(22, "work/old");
        old["created_at"] = json!("2026-10-01T00:00:00Z");
        let mut hold = pr(23, "work/hold");
        hold["labels"] = json!([{"name":"agent:hold"}]);
        let mut quiet = gh(
            vec![old, hold],
            vec![comment(23, 6, "tjfontaine", "User", "hi")],
        );
        quiet.closing = vec![];
        assert!(
            feed_cycle(&mut quiet, &mut FeedState::default(), NOW, EPOCH)
                .unwrap()
                .is_empty()
        );
    }

    #[derive(Default)]
    struct FakeRemote {
        prs: BTreeMap<u64, Value>,
        comments: Vec<Value>,
        closing: Vec<u64>,
        runs: Vec<Value>,
        posted: Vec<(u64, String)>,
    }
    impl Remote for FakeRemote {
        fn get(&mut self, endpoint: &str) -> Result<Value, ScalerError> {
            let n: u64 = endpoint
                .rsplit('/')
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or(ScalerError::Guard("bad endpoint"))?;
            self.prs.get(&n).cloned().ok_or(ScalerError::GithubGone)
        }
        fn list(&mut self, endpoint: &str) -> Result<Vec<Value>, ScalerError> {
            Ok(if endpoint.contains("/issues/") {
                self.comments.clone()
            } else {
                Vec::new()
            })
        }
        fn text(&mut self, _: &[&str]) -> Result<String, ScalerError> {
            Ok(r#"{"statusCheckRollup":[]}"#.into())
        }
        fn adoption(&mut self, read: AdoptionRead) -> Result<Value, ScalerError> {
            let mut fake = FakeGh {
                closing: self.closing.clone(),
                ..FakeGh::default()
            };
            Github::adoption(&mut fake, read)
        }
        fn runs(&mut self) -> Result<Vec<Value>, ScalerError> {
            Ok(self.runs.clone())
        }
        fn post(&mut self, pr: u64, body: &str) -> Result<(), ScalerError> {
            self.posted.push((pr, body.into()));
            Ok(())
        }
    }
    fn remote() -> FakeRemote {
        let mut prs = BTreeMap::new();
        prs.insert(30, pr(30, "work/adopt"));
        let mut hold = pr(31, "work/hold");
        hold["labels"] = json!([{"name":"agent:hold"}]);
        prs.insert(31, hold);
        FakeRemote {
            prs,
            closing: vec![7],
            ..FakeRemote::default()
        }
    }
    fn call(remote: &mut FakeRemote, state: &Path, name: &str, args: Value) -> (bool, String) {
        let msg = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}});
        let reply = Server {
            remote,
            state: state.into(),
            now: NOW,
            dry_run: false,
        }
        .handle(&msg)
        .unwrap();
        let result = &reply["result"];
        (
            result["isError"].as_bool().unwrap(),
            result["content"][0]["text"].as_str().unwrap().into(),
        )
    }

    #[test]
    fn dispatch_reactor_mcp_lists_tool_schemas() {
        let dir = tempfile::tempdir().unwrap();
        let mut fake = remote();
        let mut server = Server {
            remote: &mut fake,
            state: dir.path().join("s.json"),
            now: NOW,
            dry_run: false,
        };
        let init = server.handle(&json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}})).unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "carrick-reactor");
        assert!(
            server
                .handle(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                .is_none()
        );
        let list = server
            .handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
            .unwrap();
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "read_pr",
                "read_thread",
                "read_diff",
                "read_ci",
                "read_outcomes",
                "read_issue",
                "reply",
                "request_round"
            ]
        );
        assert!(
            list["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .all(|t| t["inputSchema"]["type"] == "object")
        );
        let unknown = server
            .handle(&json!({"jsonrpc":"2.0","id":2,"method":"nope"}))
            .unwrap();
        assert_eq!(unknown["error"]["code"], -32601);
    }

    #[test]
    fn dispatch_reactor_mcp_reply_enforces_rules() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("s.json");
        let mut fake = remote();
        let (err, text) = call(
            &mut fake,
            &state,
            "reply",
            json!({"pr":30,"text":"/agent go"}),
        );
        assert!(err && text.contains("may not be a command"), "{text}");
        let (err, text) = call(&mut fake, &state, "reply", json!({"pr":31,"text":"hello"}));
        assert!(err && text.contains("agent:hold"), "{text}");
        let (err, _) = call(
            &mut fake,
            &state,
            "reply",
            json!({"pr":30,"text":"CI is red on the clippy job."}),
        );
        assert!(!err);
        assert_eq!(
            fake.posted,
            vec![(30, format!("CI is red on the clippy job.\n\n{MARKER}"))]
        );
    }

    #[test]
    fn dispatch_reactor_mcp_request_round_enforces_gates() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("s.json");
        let brief = json!({"pr":30,"brief":"fix the clippy failure"});
        // Not adoptable: two closing references.
        let mut fake = remote();
        fake.closing = vec![7, 8];
        let (err, text) = call(&mut fake, &state, "request_round", brief.clone());
        assert!(
            err && text.contains("neither adoptable nor owned"),
            "{text}"
        );
        // In flight for this PR, then at the global cap.
        let mut fake = remote();
        fake.runs = vec![json!({"status":"queued","displayTitle":"PR 30","headBranch":"main"})];
        let (err, text) = call(&mut fake, &state, "request_round", brief.clone());
        assert!(err && text.contains("in flight for this PR"), "{text}");
        fake.runs = (0..GLOBAL_CAP).map(|i| json!({"status":"in_progress","displayTitle":format!("x{i}"),"headBranch":"main"})).collect();
        let (err, text) = call(&mut fake, &state, "request_round", brief.clone());
        assert!(err && text.contains("global dispatch cap"), "{text}");
        // Held PR.
        let (err, text) = call(
            &mut fake,
            &state,
            "request_round",
            json!({"pr":31,"brief":"x"}),
        );
        assert!(err && text.contains("agent:hold"), "{text}");
        // Success, then the same head is refused until a human comments.
        fake.runs.clear();
        let (err, text) = call(&mut fake, &state, "request_round", brief.clone());
        assert!(!err, "{text}");
        assert_eq!(
            fake.posted,
            vec![(30, format!("/agent fix the clippy failure\n\n{MARKER}"))]
        );
        let saved: ToolState = load(&state).unwrap();
        assert_eq!(
            saved.prs[&30].last_round_at.as_deref(),
            Some("2026-10-31T00:00:00Z")
        );
        fake.comments = vec![json!({"user":{"login":"carrick-workers[bot]","type":"Bot"},
            "created_at":"2026-10-31T00:10:00Z","body":"Dispatch outcome: failed"})];
        let (err, text) = call(&mut fake, &state, "request_round", brief.clone());
        assert!(err && text.contains("already rounded this head"), "{text}");
        fake.comments
            .push(json!({"user":{"login":"tjfontaine","type":"User"},
            "created_at":"2026-10-31T00:20:00Z","body":"try the other approach"}));
        let (err, text) = call(&mut fake, &state, "request_round", brief);
        assert!(!err, "{text}");
        assert_eq!(fake.posted.len(), 2);
    }
}
