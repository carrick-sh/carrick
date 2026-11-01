//! Collaborator-authorized dispatch driver (#1214). Workflow input never becomes shell source.
use crate::ci_scaler::{REPOSITORY, ScalerError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[path = "dispatch_loop.rs"]
mod agent_loop;
#[path = "dispatch_live_log.rs"]
mod live_log;
#[path = "dispatch_reactor.rs"]
mod reactor;
#[path = "dispatch_round_inbox.rs"]
mod round_inbox;
#[path = "dispatch_worker_tier.rs"]
mod worker_tier;

const LOOP_USER: &str = "carrick-dispatch-loop";
const AGENT_USER: &str = "carrick-dispatch-agent";

#[derive(clap::Args, Debug)]
pub struct DispatchArgs {
    #[command(subcommand)]
    pub action: DispatchAction,
}
#[derive(clap::Subcommand, Debug)]
pub enum DispatchAction {
    /// Credentialed review coordinator and policy-enforcing Unix tool server.
    Loop {
        #[arg(long)]
        event: PathBuf,
        #[arg(long, default_value = "success/success")]
        setup_status: String,
    },
    /// Token-free client: one JSON argument object on stdin.
    Tool { name: String },
    /// Hosted, credential-free guard. Repeated on the clone before any work.
    Guard {
        #[arg(long)]
        event: PathBuf,
        #[arg(long)]
        admit: bool,
        #[arg(long, conflicts_with = "admit")]
        retire: bool,
    },
    /// Hosted chain job (#1241 part 3): when this run's outcome on the issue
    /// is an admissible Continuing outcome, dispatch the next round.
    Chain {
        #[arg(long)]
        issue: u64,
    },
    /// Owner-local poll loop that answers PR conversation with `/agent` rounds (#1193).
    Reactor {
        #[command(subcommand)]
        mode: reactor::Mode,
    },
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Worker {
    pub backend: String,
    pub model: String,
    pub effort: Option<String>,
    pub coauthor: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoopConfig {
    #[serde(rename = "loop")]
    loop_policy: agent_loop::Policy,
}

/// Who may trigger dispatch (#1214, owner decision on #231): a repository
/// collaborator with `write`, `maintain` or `admin` permission, read live
/// from `GET repos/{REPOSITORY}/collaborators/{login}/permission`. Callers
/// supply the transport so the validators stay pure. `read`, `triage` and
/// `none`, a malformed login, a 404 and any other API error are refused.
pub(crate) fn write_collaborator(
    login: &str,
    read: impl FnOnce(&str) -> Result<Value, ScalerError>,
) -> bool {
    let Some(endpoint) = permission_endpoint(login) else {
        return false;
    };
    read(&endpoint).is_ok_and(|v| {
        matches!(
            v["permission"].as_str(),
            Some("admin" | "maintain" | "write")
        )
    })
}
/// The permission endpoint for a syntactically valid GitHub login only, so
/// event text can never reshape the request path.
pub(crate) fn permission_endpoint(login: &str) -> Option<String> {
    let valid = !login.is_empty()
        && login.len() <= 39
        && !login.starts_with('-')
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    valid.then(|| format!("repos/{REPOSITORY}/collaborators/{login}/permission"))
}
/// A per-event trusted-login predicate over one transport, caching each
/// login's answer (refusals included) for the life of the predicate.
pub(crate) fn collaborators<'a>(
    mut read: impl FnMut(&str) -> Result<Value, ScalerError> + 'a,
) -> impl FnMut(&str) -> bool + 'a {
    let mut cache = std::collections::BTreeMap::<String, bool>::new();
    move |login: &str| {
        if let Some(trusted) = cache.get(login) {
            return *trusted;
        }
        let trusted = write_collaborator(login, &mut read);
        cache.insert(login.to_owned(), trusted);
        trusted
    }
}
/// A human account that [`write_collaborator`] trusts.
pub(crate) fn trusted_user(user: &Value, trusted: &mut dyn FnMut(&str) -> bool) -> bool {
    user["type"] == "User" && user["login"].as_str().is_some_and(trusted)
}
/// Test transport for [`collaborators`]: each listed login answers its
/// permission; any other login gets the API's 404.
#[cfg(test)]
pub(crate) fn fake_collaborators(
    table: &'static [(&'static str, &'static str)],
) -> impl FnMut(&str) -> bool {
    collaborators(move |endpoint| {
        table
            .iter()
            .find(|(login, _)| permission_endpoint(login).as_deref() == Some(endpoint))
            .map(|(_, permission)| json!({"permission":permission}))
            .ok_or(ScalerError::Guard("gh: Not Found (HTTP 404)"))
    })
}
/// The fixtures' usual actor, `tjfontaine`, as an admin collaborator.
#[cfg(test)]
pub(crate) fn owner_collaborator() -> impl FnMut(&str) -> bool {
    fake_collaborators(&[("tjfontaine", "admin")])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dispatch {
    pub issue: u64,
    pub title: String,
    pub body: String,
    pub branch: String,
    pub resume: bool,
    pub selected_tip: Option<String>,
    pub worker: Worker,
    pub base: String,
    pub review: bool,
    pub review_text: String,
    pub continuation: Continuation,
    #[serde(skip)]
    pub worker_seconds: Option<u64>,
    #[serde(skip)]
    pub loop_deadline: Option<std::time::Instant>,
    #[serde(skip)]
    pub harvest_deadline: Option<std::time::Instant>,
}

/// Which branch this run may write, and under which lease. The push target of
/// an adopted PR comes only from here, never from issue, comment or model text.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Continuation {
    /// A run-named `work/dispatch-<issue>-<run>` branch: a creation run or
    /// the continuation of a PR an earlier dispatch run opened.
    #[default]
    Owned,
    /// A director PR adopted for one round by an owner `/agent` comment.
    /// `tip` is the head admitted by the guard and the only push lease.
    Adopted {
        pr: u64,
        branch: String,
        tip: String,
        /// The owner's trigger said `Rebase: allowed` (#1215): publication
        /// may replace the admitted history with one rebased onto admitted
        /// main, still only under the lease that starts at `tip`.
        #[serde(default)]
        rebase: bool,
    },
}

/// Proof that a live PR passed [`adopted_pr`]. Fields stay private, so only
/// that predicate can create one.
pub(crate) struct Adoption {
    number: u64,
    branch: String,
    tip: String,
    issue: Value,
}
impl Adoption {
    pub(crate) fn issue_number(&self) -> Option<u64> {
        self.issue["number"].as_u64()
    }
    fn continuation(&self, rebase: bool) -> Continuation {
        Continuation::Adopted {
            pr: self.number,
            branch: self.branch.clone(),
            tip: self.tip.clone(),
            rebase,
        }
    }
}
/// Server reads [`adopted_pr`] needs; each caller supplies its own transport.
pub(crate) enum AdoptionRead {
    /// GraphQL response for [`CLOSING_REFERENCES_QUERY`] on this PR number.
    ClosingReferences(u64),
    /// REST issue object.
    Issue(u64),
}

/// The one adoption predicate, shared by the hosted guard, clone admission,
/// the controller and the loop. A same-repository `work/*` PR into main that
/// no dispatch run named, closing exactly one open issue in this repository.
/// Authorship is not checked (#1214): a same-repository head already needs
/// write access to push, and the trusted `/agent` comment is the approval.
/// Head freshness is the caller's expected-tip check, exactly as for owned PRs.
pub(crate) fn adopted_pr(
    pr: &Value,
    mut read: impl FnMut(AdoptionRead) -> Result<Value, ScalerError>,
) -> Result<Option<Adoption>, ScalerError> {
    let branch = pr["head"]["ref"].as_str().unwrap_or_default();
    let (Some(number), Some(tip)) = (
        pr["number"].as_u64().filter(|n| *n > 0),
        pr["head"]["sha"].as_str().filter(|s| sha(s)),
    ) else {
        return Ok(None);
    };
    if pr["state"] != "open"
        || pr["head"]["repo"]["full_name"] != REPOSITORY
        || pr["base"]["repo"]["full_name"] != REPOSITORY
        || pr["base"]["ref"] != "main"
        || !valid_branch(branch)
        || dispatch_branch(branch).is_some()
    {
        return Ok(None);
    }
    let references = parse_closing_references(&read(AdoptionRead::ClosingReferences(number))?)?;
    let [reference] = references.all.iter().collect::<Vec<_>>()[..] else {
        return Ok(None);
    };
    if reference.repository != REPOSITORY {
        return Ok(None);
    }
    let issue = read(AdoptionRead::Issue(reference.number))?;
    if issue["number"].as_u64() != Some(reference.number)
        || issue["state"] != "open"
        || issue.get("pull_request").is_some()
    {
        return Ok(None);
    }
    Ok(Some(Adoption {
        number,
        branch: branch.to_owned(),
        tip: tip.to_owned(),
        issue,
    }))
}
/// The issue title and body with their last writers, read in one GraphQL
/// response so the checks and the admitted [`Dispatch`] fields cannot diverge
/// (#1218, #1220). `lastEditedAt` tracks body edits only, so title changes are
/// checked through the latest `RENAMED_TITLE_EVENT` timeline item.
pub(crate) const ISSUE_BRIEF_QUERY: &str = r#"query($number:Int!){repository(owner:"carrick-sh",name:"carrick"){issue(number:$number){number author{login} title lastEditedAt editor{__typename login} body renames:timelineItems(last:1,itemTypes:[RENAMED_TITLE_EVENT]){pageInfo{hasPreviousPage} nodes{__typename ... on RenamedTitleEvent{actor{__typename login} currentTitle}}}}}}"#;
/// Verified issue title and body from one [`ISSUE_BRIEF_QUERY`] snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedBrief {
    pub title: String,
    pub body: String,
}
/// A GraphQL `Actor` for a human account (`__typename == "User"`) that
/// [`write_collaborator`] trusts.
fn trusted_graphql_actor(actor: &Value, trusted: &mut dyn FnMut(&str) -> bool) -> bool {
    actor["__typename"] == "User" && actor["login"].as_str().is_some_and(trusted)
}
/// The issue title and body a worker round may admit. Any issue author may be
/// approved by a collaborator's label, comment or review (#1214), but the
/// approval covers only text a collaborator saw or wrote:
/// - the body must be unedited since filing (`lastEditedAt` null), or last
///   edited by a human account that passes `trusted` ([`write_collaborator`]);
/// - the title must be unrenamed since filing (no `RENAMED_TITLE_EVENT`), or
///   last renamed to the current `title` by a human account that passes
///   `trusted`.
///
/// Errors, a different issue, a title mismatch and any missing field are
/// refused.
pub(crate) fn trusted_brief(
    response: &Value,
    number: u64,
    trusted: &mut dyn FnMut(&str) -> bool,
) -> Result<TrustedBrief, ScalerError> {
    if response.get("errors").is_some() {
        return Err(ScalerError::Guard("issue brief query returned errors"));
    }
    let issue = &response["data"]["repository"]["issue"];
    if issue["number"].as_u64() != Some(number) {
        return Err(ScalerError::Guard("issue brief unavailable"));
    }
    let (Some(title), Some(body)) = (issue["title"].as_str(), issue["body"].as_str()) else {
        return Err(ScalerError::Guard("issue brief unavailable"));
    };
    match issue.get("lastEditedAt") {
        Some(Value::Null) => {}
        Some(Value::String(at)) if !at.is_empty() => {
            if !trusted_graphql_actor(&issue["editor"], trusted) {
                return Err(ScalerError::Guard(
                    "issue body was last edited by a non-collaborator; a collaborator must edit or re-file it",
                ));
            }
        }
        _ => return Err(ScalerError::Guard("issue brief edit history unavailable")),
    }
    let renames = &issue["renames"];
    let (Some(has_previous), Some(nodes)) = (
        renames["pageInfo"]["hasPreviousPage"].as_bool(),
        renames["nodes"].as_array(),
    ) else {
        return Err(ScalerError::Guard("issue title rename history unavailable"));
    };
    match nodes.as_slice() {
        [] if !has_previous => {}
        [rename]
            if rename["__typename"] == "RenamedTitleEvent"
                && rename["currentTitle"].as_str() == Some(title) =>
        {
            if !trusted_graphql_actor(&rename["actor"], trusted) {
                return Err(ScalerError::Guard(
                    "issue title was last edited by a non-collaborator; a collaborator must retitle or re-file it",
                ));
            }
        }
        _ => return Err(ScalerError::Guard("issue title rename history unavailable")),
    }
    Ok(TrustedBrief {
        title: title.to_owned(),
        body: body.to_owned(),
    })
}
/// Replace the event's issue title and body with the [`trusted_brief`] for
/// that issue. Every path that admits a round (label, comment, review,
/// adoption) ends here, so neither field enters [`Dispatch`] unchecked.
fn apply_trusted_brief(
    event: &mut Value,
    read: impl FnOnce(u64) -> Result<Value, ScalerError>,
    trusted: &mut dyn FnMut(&str) -> bool,
) -> Result<(), ScalerError> {
    let number = event["issue"]["number"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(ScalerError::Guard("missing issue number"))?;
    let brief = trusted_brief(&read(number)?, number, trusted)?;
    event["issue"]["title"] = brief.title.into();
    event["issue"]["body"] = brief.body.into();
    Ok(())
}
fn issue_brief_response(root: &Path, number: u64) -> Result<Value, ScalerError> {
    let response = gh(
        root,
        &[
            "api",
            "graphql",
            "-f",
            &format!("query={ISSUE_BRIEF_QUERY}"),
            "-F",
            &format!("number={number}"),
        ],
    )?;
    if response.len() > 256 * 1024 {
        return Err(ScalerError::Guard("issue brief response exceeds 256 KiB"));
    }
    Ok(serde_json::from_str(&response)?)
}
fn adoption_read(root: &Path, read: AdoptionRead) -> Result<Value, ScalerError> {
    match read {
        AdoptionRead::ClosingReferences(number) => closing_references_response(root, number),
        AdoptionRead::Issue(number) => api(root, &format!("repos/{REPOSITORY}/issues/{number}")),
    }
}

/// Runner-private result of credentialed admission; provider setup and the
/// coordinator consume this snapshot rather than re-resolving mutable labels.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmittedDispatch {
    pub dispatch: Dispatch,
    pub trigger: Value,
    event_digest: String,
    /// Set only for a round the server chained from a Continuing outcome.
    #[serde(default)]
    pub chain: Option<ChainFacts>,
    /// The admitted issue's label names: an input to the worker tier
    /// (#1275), read from this snapshot, never re-queried after admission.
    #[serde(default)]
    pub labels: Vec<String>,
}
/// Rounds per owner trigger: the owner's round and three chained ones
/// (owner decision on #1241, #231).
pub(crate) const CHAIN_ROUNDS: u32 = 4;
/// Server facts a chained round starts from, all read back from the
/// authenticated Continuing outcome (#1241 part 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChainFacts {
    /// This round's place in the chain: 2..=[`CHAIN_ROUNDS`].
    pub round: u32,
    /// The Continuing outcome this round was chained from.
    pub from: String,
    /// The branch and head that outcome's round pushed.
    pub branch: String,
    pub head: String,
    /// The previous coordinator's brief: model text, information only.
    pub brief: String,
}
fn event_digest(path: &Path) -> Result<String, ScalerError> {
    use sha2::{Digest, Sha256};
    Ok(format!(
        "{:x}",
        Sha256::digest(regular_text(path)?.as_bytes())
    ))
}
fn persist_admission(
    dispatch: &Dispatch,
    event: &Value,
    path: &Path,
    chain: Option<&ChainLink>,
) -> Result<(), ScalerError> {
    let state = crate::agent_runner::state()?;
    std::fs::create_dir_all(&state)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
    let admission = AdmittedDispatch {
        dispatch: dispatch.clone(),
        trigger: if let Some(link) = chain {
            link.outcome.clone()
        } else if event.get("review").is_some() {
            event["review"].clone()
        } else if event.get("comment").is_some() {
            event["comment"].clone()
        } else {
            event["label"].clone()
        },
        event_digest: event_digest(path)?,
        chain: chain.map(|link| link.facts.clone()),
        labels: event["issue"]["labels"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|label| label["name"].as_str().map(str::to_owned))
            .collect(),
    };
    crate::agent_runner::secret_file(
        &state.join("admission.json"),
        &serde_json::to_vec(&admission)?,
    )?;
    Ok(())
}
pub(crate) fn read_admission(event: &Path) -> Result<AdmittedDispatch, ScalerError> {
    let admission: AdmittedDispatch = serde_json::from_str(&regular_text(
        &crate::agent_runner::state()?.join("admission.json"),
    )?)?;
    if admission.event_digest != event_digest(event)? {
        return Err(ScalerError::Guard("admission belongs to another event"));
    }
    Ok(admission)
}

pub(crate) fn dispatch_label(label: &str) -> bool {
    label == "dispatch" || label.starts_with("dispatch:")
}

/// Used by the guard and controller; text is context, never executable policy.
/// The author must be a trusted collaborator ([`write_collaborator`]).
pub(crate) fn agent_comment(comment: &Value, trusted: &mut dyn FnMut(&str) -> bool) -> bool {
    let body = comment["body"].as_str().unwrap_or_default();
    trusted_user(&comment["user"], trusted)
        && comment["created_at"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
        && comment["created_at"] == comment["updated_at"]
        && (body == "/agent"
            || body
                .strip_prefix("/agent")
                .is_some_and(|s| s.starts_with(char::is_whitespace)))
}

/// Director consent to rebase an adopted PR (owner decision, #1215): the
/// admitted `/agent` comment is the owner account's, which director
/// sessions post as, and has a line that is exactly `Rebase: allowed`.
/// Write collaborators can trigger a round but not consent to a rewrite.
fn rebase_consent(comment: &Value) -> bool {
    comment["user"]["login"] == crate::ci_scaler::DISPATCH_OWNER
        && comment["user"]["type"] == "User"
        && comment["body"]
            .as_str()
            .is_some_and(|body| body.lines().any(|line| line.trim() == "Rebase: allowed"))
}

pub(crate) fn comment_digest(comment: &Value) -> String {
    use sha2::{Digest, Sha256};
    let data = json!({"id":comment["id"],"body":comment["body"],"created_at":comment["created_at"],"updated_at":comment["updated_at"]});
    format!("{:x}", Sha256::digest(data.to_string().as_bytes()))
}

#[cfg(test)]
pub(crate) fn validate_event(
    event: &Value,
    triggering_actor: &str,
    trusted: &mut dyn FnMut(&str) -> bool,
) -> Result<Dispatch, ScalerError> {
    validate_event_with_publication(event, triggering_actor, trusted, None, None, None)
}
fn validate_event_with_publication(
    event: &Value,
    triggering_actor: &str,
    trusted: &mut dyn FnMut(&str) -> bool,
    publication: Option<&PublishedPr>,
    adoption: Option<&Adoption>,
    chain: Option<&ChainLink>,
) -> Result<Dispatch, ScalerError> {
    let review = event.get("review").is_some();
    let comment = event.get("comment").is_some();
    let chained = event.get("chain").is_some();
    if chained != chain.is_some()
        || chain.is_some_and(|link| {
            review
                || comment
                || adoption.is_some()
                || link.outcome["id"] != event["chain"]["id"]
                || event["issue"]["number"].as_u64() != Some(link.issue)
        })
    {
        return Err(ScalerError::Guard(
            "a chained round needs its verified chain proof",
        ));
    }
    // Any issue author is fine (#1214): the trusted label, comment or review
    // is the approval. The issue must still be an issue, not a PR. A chained
    // round's actors are the Actions bot; its approval is the chain rule.
    let actors = if chained {
        event["sender"]["login"] == CHAIN_ACTOR
            && event["sender"]["type"] == "Bot"
            && triggering_actor == CHAIN_ACTOR
    } else {
        trusted_user(&event["sender"], trusted)
            && !triggering_actor.is_empty()
            && trusted(triggering_actor)
    };
    if event["repository"]["full_name"] != REPOSITORY
        || !actors
        || event["issue"].get("pull_request").is_some()
    {
        return Err(ScalerError::Guard(
            "dispatch requires collaborator actors with write access",
        ));
    }
    let issue = event["issue"]["number"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(ScalerError::Guard("missing issue number"))?;
    if chained {
        if event["issue"]["state"] != "open" {
            return Err(ScalerError::Guard("trigger requires an open issue"));
        }
    } else if review {
        if event["action"] != "submitted"
            || event["review"]["state"] != "changes_requested"
            || !trusted_user(&event["review"]["user"], trusted)
        {
            return Err(ScalerError::Guard(
                "review requires collaborator changes_requested",
            ));
        }
    } else if comment {
        if event["action"] != "created"
            || event["issue"]["state"] != "open"
            || !agent_comment(&event["comment"], trusted)
        {
            return Err(ScalerError::Guard(
                "comment requires an unedited collaborator /agent creation",
            ));
        }
    } else if event["action"] != "labeled"
        || !event["label"]["name"].as_str().is_some_and(dispatch_label)
    {
        return Err(ScalerError::Guard("not a dispatch label event"));
    }
    let resume = event.get("pull_request").is_some();
    let (branch, continuation) = if resume {
        let pr = &event["pull_request"];
        let branch = pr["head"]["ref"].as_str().unwrap_or_default();
        if event["issue"]["state"] != "open" {
            return Err(ScalerError::Guard("trigger requires an open issue"));
        }
        if let Some(adoption) = adoption {
            // Adoption is an owner /agent comment only; reviews stay owned.
            if !comment
                || review
                || adoption.issue["number"].as_u64() != Some(issue)
                || pr["number"].as_u64() != Some(adoption.number)
                || branch != adoption.branch
                || pr["head"]["sha"] != adoption.tip.as_str()
            {
                return Err(ScalerError::Guard(
                    "adoption proof does not match the triggering PR",
                ));
            }
            (
                branch.to_owned(),
                adoption.continuation(rebase_consent(&event["comment"])),
            )
        } else if owned_pr(
            pr,
            &event["dispatch_run"],
            issue,
            branch,
            publication,
            trusted,
        ) {
            (branch.to_owned(), Continuation::Owned)
        } else {
            return Err(ScalerError::Guard(
                "trigger requires an open issue and owned dispatch PR",
            ));
        }
    } else {
        (
            format!("work/dispatch-{issue}-pending"),
            Continuation::Owned,
        )
    };
    Ok(Dispatch {
        issue,
        title: event["issue"]["title"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        body: event["issue"]["body"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        branch,
        resume,
        selected_tip: event["pull_request"]["head"]["sha"]
            .as_str()
            .map(str::to_owned),
        worker: Worker::default(),
        base: String::new(),
        review,
        review_text: String::new(),
        continuation,
        worker_seconds: None,
        loop_deadline: None,
        harvest_deadline: None,
    })
}

pub fn valid_branch(branch: &str) -> bool {
    branch.starts_with("work/")
        && branch.len() > 5
        && branch.len() <= 180
        && branch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
        && !branch.contains("..")
        && !branch.contains("//")
        && branch
            .split('/')
            .all(|part| !part.starts_with('.') && !part.ends_with('.') && !part.ends_with(".lock"))
        && !branch.ends_with('/')
}

/// Built by `scripts/ci/build-template-debian.sh` for the agent profile.
pub const CODEX_SDK_VENV: &str = "/opt/carrick-agent/codex-sdk";

fn schema() -> Value {
    json!({"type":"object","additionalProperties":false,
        "required":["status","summary","tests","risks"],"properties":{
            "status":{"type":"string","enum":["done","blocked","failed"]},
            "summary":{"type":"string"},"tests":{"type":"array","items":{"type":"string"}},
            "risks":{"type":"array","items":{"type":"string"}}}})
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub status: ContractStatus,
    pub summary: String,
    pub tests: Vec<String>,
    pub risks: Vec<String>,
    /// Server-retained loop claims, separate from the applied report in summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loop_summary: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContractStatus {
    Done,
    Blocked,
    Failed,
}

/// The contract's schema fields only. agy appends its own tool metadata
/// (`toolAction`, `toolSummary`) to an otherwise valid structured output, and
/// the contract type refuses unknown fields (#768, run 39799036716).
fn schema_fields(output: &Value) -> Value {
    let schema = schema();
    let mut kept = serde_json::Map::new();
    if let (Some(fields), Some(required)) = (output.as_object(), schema["required"].as_array()) {
        for name in required.iter().filter_map(Value::as_str) {
            if let Some(value) = fields.get(name) {
                kept.insert(name.to_owned(), value.clone());
            }
        }
    }
    Value::Object(kept)
}

/// Bound on the agent's final message kept as `raw.log` evidence.
const RESULT_RESPONSE_TAIL: usize = 4000;

/// The worker contract plus the launcher verdict as `raw.log` evidence. The
/// clone is destroyed after the job, so a missing or unparseable contract is
/// only diagnosable from what this records (#768: an empty agent log).
fn read_result(result: &Path) -> (Contract, String) {
    let value = regular_text(result).and_then(|text| Ok(serde_json::from_str::<Value>(&text)?));
    // Preserve a completed work contract even on transport failure. The
    // launcher exit code independently prevents a successful dispatch verdict.
    let contract = value
        .as_ref()
        .ok()
        .and_then(|value| serde_json::from_value(schema_fields(&value["structured_output"])).ok())
        .unwrap_or(Contract {
            loop_summary: None,
            status: ContractStatus::Failed,
            summary: "No valid worker contract".into(),
            tests: vec![],
            risks: vec!["Worker output is incomplete".into()],
        });
    let evidence = match value {
        Ok(mut value) => {
            if let Some(fields) = value.as_object_mut() {
                fields.remove("json_schema");
                fields.remove("structured_output");
                if let Some(Value::String(response)) = fields.get_mut("response") {
                    let skip = response
                        .chars()
                        .count()
                        .saturating_sub(RESULT_RESPONSE_TAIL);
                    *response = response.chars().skip(skip).collect();
                }
            }
            serde_json::to_string_pretty(&value).unwrap_or_default()
        }
        Err(error) => format!("unreadable: {error}"),
    };
    (contract, format!("=== result.json ===\n{evidence}\n"))
}

fn wait_agent(command: &mut Command, limit: std::time::Duration) -> std::io::Result<i32> {
    wait_account(command, limit, AGENT_USER)
}
fn wait_account(
    command: &mut Command,
    limit: std::time::Duration,
    user: &str,
) -> std::io::Result<i32> {
    wait_account_serving(command, limit, user, || Ok(false))
}
fn wait_account_serving(
    command: &mut Command,
    limit: std::time::Duration,
    user: &str,
    mut serve: impl FnMut() -> Result<bool, ScalerError>,
) -> std::io::Result<i32> {
    use std::os::unix::process::CommandExt;
    let mut child = command.process_group(0).spawn()?;
    let pgid = i32::try_from(child.id()).map_err(std::io::Error::other)?;
    let deadline = std::time::Instant::now() + limit;
    let mut stopped = false;
    let mut serving_error = None;
    loop {
        live_log::pump();
        round_inbox::pump();
        // The owner's `/agent stop` ends whatever is running (#1241).
        if round_inbox::stop_requested().is_some() {
            stopped = true;
        }
        if !stopped {
            match serve() {
                Ok(stop) => stopped = stop,
                Err(error) => {
                    serving_error = Some(std::io::Error::other(error));
                    stopped = true;
                }
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // SAFETY: the foreground child created this dedicated group.
                unsafe {
                    libc::kill(-pgid, libc::SIGKILL);
                }
                return serving_error.map_or_else(|| Ok(status.code().unwrap_or(1)), Err);
            }
            Ok(None) if !stopped && std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(error) => return Err(error),
            Ok(None) => {
                // The sudo wrapper and its agent belong to different UIDs.
                // Stop every agent process before waiting for that wrapper.
                let (_helper, mut retirement) =
                    retirement_command(user).map_err(std::io::Error::other)?;
                crate::process_helper::run_checked(&mut retirement)
                    .map_err(std::io::Error::other)?;
                // A sudo monitor can stop on the agent's job-control notification.
                // Kill the unreaped child's dedicated group with runner privilege.
                // SAFETY: the unreaped foreground child owns this dedicated group.
                unsafe {
                    libc::kill(-pgid, libc::SIGKILL);
                }
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                loop {
                    if child.try_wait()?.is_some() {
                        return serving_error.map_or(Ok(if stopped { 0 } else { 124 }), Err);
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(std::io::Error::other(
                            "agent foreground wrapper did not retire",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
    }
}

pub(crate) fn private_environment(command: &mut Command) {
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        // Empty values override Cargo configuration, including repository config.
        // No compiler-cache service is part of the agent execution boundary.
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "")
        .env("CARRICK_SCCACHE", "0");
}

struct Foreground<'a> {
    run: &'a str,
    name: &'a str,
    backend: &'a str,
    model: &'a str,
    effort: Option<&'a str>,
    schema: Option<&'a Path>,
    limit: std::time::Duration,
}
/// Both model accounts use the same pinned foreground launcher protocol.
fn foreground_command(state: &Path, root: &Path, launch: Foreground<'_>) -> Command {
    let mut command = Command::new("python3");
    command
        .arg(state.join("director/agy-director/scripts/agy_worker.py"))
        .arg("--home")
        .arg(state.join("runtime"))
        .args([
            "--run",
            launch.run,
            "dispatch",
            "--foreground",
            "--result-file",
        ])
        .arg(state.join("result.json"))
        .args(["--name", launch.name, "--dir"])
        .arg(root)
        .arg("--prompt-file")
        .arg(state.join("prompt.md"));
    if let Some(schema) = launch.schema {
        command.arg("--schema").arg(schema);
    }
    command.args([
        "--timeout",
        &format!("{}s", launch.limit.as_secs()),
        "--no-profile",
        "--backend",
        launch.backend,
        "--model",
        launch.model,
    ]);
    if let Some(effort) = launch.effort {
        command.args(["--effort", effort]);
    }
    command
}
/// Enter an account only after clearing both the wrapper and model environments.
/// A host-lease handoff adds only its own variables and scope writer.
fn account_command(
    command: &Command,
    user: &str,
    root: &Path,
    lease: Option<crate::host_lease::AccountHandoff>,
) -> Command {
    let mut isolated = Command::new("/usr/bin/sudo");
    private_environment(&mut isolated);
    isolated.args(["-n", "-u", user, "--"]);
    if let Some(lease) = &lease {
        isolated.args(lease.launcher());
    }
    isolated.args(["/usr/bin/env", "-i", "-C"]).arg(root);
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            let mut assignment = key.to_os_string();
            assignment.push("=");
            assignment.push(value);
            isolated.arg(assignment);
        }
    }
    if let Some(lease) = &lease {
        isolated.args(lease.assignments());
    }
    isolated
        .arg(command.get_program())
        .args(command.get_args())
        .current_dir("/")
        .stdin(lease.map_or_else(Stdio::null, crate::host_lease::AccountHandoff::stdin));
    isolated
}

/// The loop's inherited lease, shared with the agent account's group. Nested
/// `just lease carrick` in the agent then reuses this lease on the one lock path.
fn agent_lease() -> Result<
    Option<(
        crate::host_lease::HostLease,
        crate::host_lease::AccountHandoff,
    )>,
    ScalerError,
> {
    let Some(lease) =
        crate::host_lease::HostLease::inherited(crate::host_lease::HostLeaseMode::Carrick)
            .map_err(std::io::Error::other)?
    else {
        return Ok(None);
    };
    let group = output(Command::new("/usr/bin/id").args(["-g", AGENT_USER]))?;
    let group = String::from_utf8_lossy(&group)
        .trim()
        .parse::<libc::gid_t>()
        .map_err(|_| ScalerError::Guard("invalid pre-created agent gid"))?;
    let handoff = lease.account_handoff(group)?;
    Ok(Some((lease, handoff)))
}

fn worker_prompt(dispatch: &Dispatch) -> String {
    let history = match &dispatch.continuation {
        Continuation::Owned => format!(
            "Rebase onto admitted main {} (refs/carrick/dispatch-main) before working.\n\
            Resolve any conflicts in this isolated checkout; preserve earlier workers' commits.\n",
            dispatch.base
        ),
        Continuation::Adopted {
            pr,
            tip,
            rebase: true,
            ..
        } => format!(
            "This continues PR #{pr}, which the director owns. The director consented to a rebase:\n\
            rebase the admitted PR head {tip} onto admitted main {} (refs/carrick/dispatch-main),\n\
            resolve conflicts in this isolated checkout, and keep every commit and its author.\n\
            Publication refuses a HEAD that descends from neither {tip} nor admitted main.\n\
            The PR body is not yours to change.\n",
            dispatch.base
        ),
        Continuation::Adopted { pr, tip, .. } => format!(
            "This continues PR #{pr}, which the director owns. Add commits on top of the admitted PR head {tip};\n\
            do not rebase or rewrite existing commits; the director owns keeping the branch current with main.\n\
            Publication refuses any HEAD that does not descend from {tip}. The PR body is not yours to change.\n"
        ),
    };
    // The owner can steer a running round (#1241): new comments land here.
    let inbox = round_inbox::worker_path()
        .map(|path| {
            format!(
                "Comments the owner posts on this issue or PR while you work are appended to {}\n\
                as they arrive; it is empty until one does.\n",
                path.display()
            )
        })
        .unwrap_or_default();
    format!(
        "Work issue {REPOSITORY}#{} on branch {}. Read AGENTS.md in full.\n\
        {history}{inbox}\
        Implement and verify this brief. Commit your work with a Why/What/Verified body and\n\
        Co-Authored-By: {}\nDo not push, open a PR, or post comments; the workflow publishes those.\n\
        Never use --no-verify, git stash or git add -A. Keep conformance-probes/target out of commits.\n\
        This is an ephemeral runner. Use local shared carrick leases for builds.\n\
        Contabo leases are per VM under owner decision #639; never acquire a hypervisor lease.\n\
        Run only gates supported by this host; report unavailable Docker, KVM or HVF honestly.\n\
        Prove your slice as AGENTS.md \"Workers prove their slice\" says: focused suites of the\n\
        crates you touched, just check-contract-change {} HEAD, just xtask authority-debt\n\
        --source-only, plus just cross-check-macos for macOS-cfg code and just check-linux for\n\
        KVM/HAL code. Leave whole-workspace just lint-domains and just test-kernel to CI.\n\
        To propose a PR body, write ../pr-body.md beside result.json (relative to the checkout root).\n\
        Keep it at most 8 KiB, write for people, and omit closing references and dispatch footers; the server adds them.\n\
        Return the requested JSON contract, stating unrun gates and blockers honestly.\n\n{}{}",
        dispatch.issue,
        dispatch.branch,
        dispatch.worker.coauthor,
        dispatch.base,
        dispatch.body,
        dispatch.review_text
    )
}

fn agent(root: &Path, dispatch: &Dispatch) -> Result<i32, ScalerError> {
    let state = root
        .parent()
        .ok_or(ScalerError::Guard("missing agent home"))?
        .to_owned();
    let home = state.join("home");
    let schema_path = state.join("schema.json");
    let prompt_file = state.join("prompt.md");
    std::fs::write(&schema_path, serde_json::to_vec_pretty(&schema())?)?;
    let prompt = worker_prompt(dispatch);
    std::fs::write(&prompt_file, prompt)?;
    // Deduct checkout/build/bootstrap time rather than starting a fresh
    // 30-minute turn against a token snapshot taken at job admission.
    let limit = dispatch.worker_seconds.map_or_else(
        || crate::agent_runner::job_remaining(30),
        |seconds| Ok(std::time::Duration::from_secs(seconds)),
    )?;
    let mut command = foreground_command(
        &state,
        root,
        Foreground {
            run: "dispatch",
            name: "worker",
            backend: &dispatch.worker.backend,
            model: &dispatch.worker.model,
            effort: dispatch.worker.effort.as_deref(),
            schema: Some(&schema_path),
            limit,
        },
    );
    // Only explicit provider files enter the agent command; no runner env,
    // Actions write channels, GitHub token or inherited credential mechanism.
    private_environment(&mut command);
    crate::agent_runner::isolate_rust_homes(&mut command, &state)?;
    command.env(
        "PATH",
        format!(
            "{}:{}:/usr/local/bin:/usr/bin:/bin",
            state.join("bin").display(),
            state.join("rust/cargo/bin").display()
        ),
    );
    command
        .env_remove("GITHUB_OUTPUT")
        .env_remove("GITHUB_ENV")
        .env_remove("GITHUB_PATH")
        .env_remove("GITHUB_STEP_SUMMARY")
        .env("HOME", &home)
        .env("CODEX_HOME", home.join(".codex"))
        .env("AGY_CLI_DISABLE_AUTO_UPDATE", "1")
        .env("AGY_BIN", state.join("bin/agy"))
        // The template's read-only, hash-locked SDK (#773) carries the whole
        // codex package (codex, codex-code-mode-host, rg, bwrap); a lone
        // codex binary override cannot run tools. The loop names the
        // backend, so the launcher's own route default must not report the
        // dispatch as overriding an owner pause.
        .env("AGY_DIRECTOR_CODEX_VENV", CODEX_SDK_VENV)
        .env("AGY_DIRECTOR_ROUTES", "default")
        .env(
            "AGY_MODELS_SEED",
            state
                .join("director")
                .join(crate::agent_runner::MODELS_SEED),
        )
        .current_dir(root);
    // Held until the agent retires; the agent only validates and joins it.
    let (_lease, handoff) = agent_lease()?.unzip();
    let mut isolated = account_command(&command, AGENT_USER, root, handoff);
    hand_over(&state)?;
    let logs = crate::agent_runner::state()?;
    let label = format!(
        "worker {}/{}",
        dispatch.worker.backend, dispatch.worker.model
    );
    let label_err = format!("{label} stderr");
    round_inbox::set_worker_file(round_inbox::worker_path().as_deref());
    isolated
        .stdout(live_log::create(
            &format!("{label} stdout"),
            &logs.join("agent.out"),
        )?)
        .stderr(live_log::create(
            &format!("{label} launcher"),
            &logs.join("agent.err"),
        )?);
    // The worker's transcript is the file its launcher writes under the
    // agent-owned state; its stdout stays empty (#1292).
    let agent_uid = String::from_utf8_lossy(&output(
        Command::new("/usr/bin/id").args(["-u", AGENT_USER]),
    )?)
    .trim()
    .parse::<libc::uid_t>()
    .map_err(|_| ScalerError::Guard("invalid agent uid"))?;
    let transcript = state.join("runtime/dispatch");
    live_log::follow(&label, &transcript.join("worker.log"), agent_uid);
    live_log::follow(&label_err, &transcript.join("worker.err"), agent_uid);
    let remaining = dispatch
        .loop_deadline
        .map(|d| d.saturating_duration_since(std::time::Instant::now()))
        .unwrap_or(limit);
    let outcome = wait_agent(
        &mut isolated,
        remaining
            .min(limit)
            .min(crate::agent_runner::job_remaining(83)?),
    );
    live_log::unfollow(&label);
    live_log::unfollow(&label_err);
    live_log::unfollow(&format!("{label} stdout"));
    live_log::unfollow(&format!("{label} launcher"));
    round_inbox::set_worker_file(None);
    let _harvest = dispatch.harvest_deadline.map(CommandWindow::until);
    retire_agent()?;
    let code = outcome?;
    Ok(code)
}

fn admissible_file(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|p| matches!(p, std::path::Component::Normal(_)))
        && !path
            .split('/')
            .any(|part| matches!(part, "target" | ".git"))
}
fn checkpoint(root: &Path, dispatch: &Dispatch) -> Result<bool, ScalerError> {
    let files = git(
        root,
        &[
            "ls-files",
            "--modified",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    )?;
    for file in files
        .split('\0')
        .filter(|p| !p.is_empty() && admissible_file(p))
    {
        // Explicit paths, including deleted files. Never stage a generated
        // target symlink or sweep a sibling worktree with git add -A.
        git(root, &["add", "--", file])?;
    }
    let staged = git(root, &["diff", "--cached", "--name-only", "-z"])?;
    if staged
        .split('\0')
        .any(|p| !p.is_empty() && !admissible_file(p))
    {
        return Err(ScalerError::Guard("worker staged a generated target path"));
    }
    if staged.is_empty() {
        return Ok(false);
    }
    let message = format!(
        "chore(ci): checkpoint issue {} worker progress\n\nWhy: preserve unfinished work before this ephemeral clone is destroyed.\n\nWhat: record the worker's current changes for review and continuation.\n\nVerified: see the dispatch issue contract; this is a WIP checkpoint.\n\nCo-Authored-By: {}",
        dispatch.issue, dispatch.worker.coauthor
    );
    git(root, &["commit", "-m", &message])?;
    Ok(true)
}

const LOOP_LOG_BYTES: usize = 64 * 1024;
const TRANSCRIPT_BYTES: usize = 512 * 1024;
/// Each worker's full stream-json session, uploaded beside the clipped
/// `raw.log` so a reader can replay the whole turn. Kept under the 20 MiB
/// `regular_text` bound that `mask_artifacts` reads with.
const WORKER_SESSION_BYTES: usize = 16 * 1024 * 1024;

fn clip_diagnostic(mut text: String, limit: usize) -> String {
    if text.len() > limit {
        let end = text.as_bytes()[..limit.saturating_sub(32)]
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |n| n + 1);
        text.truncate(end);
        text.push_str("[diagnostic truncated]\n");
    }
    text
}
/// The caller owns the ancestors and retires the model before reading model
/// files. Refuse entry links/devices; retain complete lines at the byte bound.
/// `worker-<n>.jsonl`: the upload name of the n-th worker session in a run.
fn worker_session_name(name: &str) -> bool {
    name.strip_prefix("worker-")
        .and_then(|rest| rest.strip_suffix(".jsonl"))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Copy a worker's stream-json session into the upload as the next
/// `worker-<n>.jsonl`, keeping whole lines and redacting like every other
/// diagnostic. The bound applies to the redacted text, because lossy UTF-8
/// decoding and redaction can grow it; an over-long session ends with one
/// `truncated` event. The session is worker-written evidence, so a missing or
/// unreadable log is skipped rather than failing the whole upload.
fn record_worker_session(log: &Path, package: &Path) -> Result<(), ScalerError> {
    use std::io::Read;
    let mut bytes = Vec::new();
    let read = crate::safe_copy::open_text(log).and_then(|file| {
        file.take(WORKER_SESSION_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
    });
    if read.is_err() {
        return Ok(());
    }
    let mut truncated = bytes.len() > WORKER_SESSION_BYTES;
    let mut text = crate::dispatch_redaction::redact(&bytes);
    if let Ok(token) = std::env::var("GH_TOKEN")
        && !token.is_empty()
    {
        text = text.replace(&token, "[REDACTED]");
    }
    if truncated || text.len() > WORKER_SESSION_BYTES {
        truncated = true;
        let mut end = WORKER_SESSION_BYTES.min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let end = text[..end].rfind('\n').map_or(0, |n| n + 1);
        text.truncate(end);
    }
    if truncated {
        text.push_str(&format!(
            "{}\n",
            json!({"event": "truncated", "limit_bytes": WORKER_SESSION_BYTES})
        ));
    }
    let mut index = 1;
    for entry in std::fs::read_dir(package)? {
        if entry?.file_name().to_str().is_some_and(worker_session_name) {
            index += 1;
        }
    }
    std::fs::write(package.join(format!("worker-{index}.jsonl")), text)?;
    Ok(())
}

fn diagnostic_text(path: &Path) -> Result<String, ScalerError> {
    use std::io::Read;
    let file = crate::safe_copy::open_text(path)?;
    let mut bytes = Vec::new();
    file.take(TRANSCRIPT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > TRANSCRIPT_BYTES {
        let end = bytes[..TRANSCRIPT_BYTES]
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |n| n + 1);
        bytes.truncate(end);
        bytes.extend_from_slice(b"[diagnostic truncated]\n");
    }
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if let Ok(token) = std::env::var("GH_TOKEN")
        && !token.is_empty()
    {
        text = text.replace(&token, "[REDACTED]");
    }
    Ok(clip_diagnostic(
        crate::dispatch_redaction::redact(text.as_bytes()),
        TRANSCRIPT_BYTES,
    ))
}
fn loop_log(event: Value) -> Result<(), ScalerError> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::OpenOptionsExt;
    let package =
        PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or(ScalerError::Guard("runner temp"))?)
            .join("dispatch-output");
    std::fs::create_dir_all(&package)?;
    std::fs::set_permissions(&package, std::fs::Permissions::from_mode(0o700))?;
    let line = crate::dispatch_redaction::redact(format!("{event}\n").as_bytes());
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(package.join("loop.log"))?;
    if !file.metadata()?.is_file() {
        return Err(ScalerError::Guard("loop.log is not a regular file"));
    }
    let size = file.metadata()?.len() as usize;
    if size.saturating_add(line.len()) <= LOOP_LOG_BYTES {
        file.write_all(line.as_bytes())?;
    } else {
        // Keep the opening context and most recent records so a verbose source
        // census cannot displace the worker's later harvest diagnostics.
        file.seek(SeekFrom::Start(0))?;
        let mut previous = String::new();
        (&mut file)
            .take(LOOP_LOG_BYTES as u64)
            .read_to_string(&mut previous)?;
        let prefix_limit = previous.len().min(8192);
        let prefix_end = previous.as_bytes()[..prefix_limit]
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |n| n + 1);
        let marker = "[older loop.log records truncated]\n";
        let available = LOOP_LOG_BYTES.saturating_sub(prefix_end + marker.len());
        let mut tail = format!("{}{line}", &previous[prefix_end..]);
        while tail.len() > available {
            let end = tail.find('\n').map_or(tail.len(), |n| n + 1);
            tail.drain(..end);
        }
        file.set_len(0)?;
        file.write_all(&previous.as_bytes()[..prefix_end])?;
        file.write_all(marker.as_bytes())?;
        file.write_all(tail.as_bytes())?;
    }
    Ok(())
}
fn timed_phase<T>(
    phase: &str,
    operation: impl FnOnce() -> Result<T, ScalerError>,
) -> Result<T, ScalerError> {
    let started = std::time::Instant::now();
    let _ = loop_log(json!({"phase":phase,"outcome":"started"}));
    let result = operation();
    let outcome = result
        .as_ref()
        .err()
        .map_or_else(|| "ok".to_owned(), |error| error.to_string());
    let _ = loop_log(
        json!({"phase":phase,"outcome":outcome,"duration_ms":started.elapsed().as_millis()}),
    );
    result
}
fn capture_loop_foreground(actor: &Path) -> Result<(), ScalerError> {
    let state = crate::agent_runner::state()?;
    for (source, target) in [
        ("result.json", "loop-result.json"),
        ("runtime/dispatch-loop/loop.log", "loop-events.log"),
        ("runtime/dispatch-loop/loop.err", "loop-events.err"),
    ] {
        let text = diagnostic_text(&actor.join(source))
            .unwrap_or_else(|error| format!("unavailable: {error}\n"));
        std::fs::write(state.join(target), text)?;
    }
    Ok(())
}
fn bounded_transcript(mut value: Value) -> Result<String, ScalerError> {
    let quota = (TRANSCRIPT_BYTES - 4096) / 5;
    if let Some(sections) = value["sections"].as_object_mut() {
        for section in sections.values_mut() {
            let text = section["text"].as_str().unwrap_or_default();
            let mut low = 0;
            let mut high = text.len();
            while low < high {
                let mid = low + (high - low).div_ceil(2);
                let mut end = mid;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                if serde_json::to_vec(&text[..end])?.len() <= quota.saturating_sub(64) {
                    low = mid;
                } else {
                    high = mid - 1;
                }
            }
            while !text.is_char_boundary(low) {
                low -= 1;
            }
            let clipped = low < text.len();
            let retained = text[..low].to_owned();
            section["text"] = retained.into();
            section["truncated"] = (clipped || section["truncated"] == true).into();
        }
    }
    let text = serde_json::to_string_pretty(&value)?;
    if text.len() > TRANSCRIPT_BYTES {
        return Err(ScalerError::Guard("loop transcript exceeds bound"));
    }
    Ok(text)
}
fn loop_transcript() -> Result<(), ScalerError> {
    let state = crate::agent_runner::state()?;
    let mut sections = serde_json::Map::new();
    for name in [
        "loop-result.json",
        "loop-events.log",
        "loop-events.err",
        "loop.out",
        "loop.err",
    ] {
        let text = diagnostic_text(&state.join(name))
            .unwrap_or_else(|error| format!("unavailable: {error}\n"));
        sections.insert(name.into(), json!({"untrusted":true,"text":text}));
    }
    let package =
        PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or(ScalerError::Guard("runner temp"))?)
            .join("dispatch-output");
    std::fs::create_dir_all(&package)?;
    std::fs::write(
        package.join("loop-transcript.log"),
        bounded_transcript(json!({"sections":sections}))?,
    )?;
    Ok(())
}
fn record_worker_failure(error: &ScalerError, dispatch: &Dispatch) -> Result<(), ScalerError> {
    let state = crate::agent_runner::state()?;
    let package =
        PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or(ScalerError::Guard("runner temp"))?)
            .join("dispatch-output");
    std::fs::create_dir_all(&package)?;
    // Failed candidates never replace the last successfully harvested pair.
    // Remove only orphaned/invalid state, so later workers can start afresh.
    if worker_checkpoint(&state, dispatch).is_err() {
        if state.join("work").is_dir() {
            std::fs::remove_dir_all(state.join("work"))?;
        }
        if state.join("receipt.json").exists() {
            std::fs::remove_file(state.join("receipt.json"))?;
        }
    }
    let contract = Contract {
        loop_summary: None,
        status: ContractStatus::Failed,
        summary: format!("Worker production/harvest failed: {error}"),
        tests: vec![],
        risks: vec![
            "Harvest incomplete; candidate discarded, last good checkpoint retained if available"
                .into(),
        ],
    };
    std::fs::write(
        package.join("contract.json"),
        serde_json::to_vec_pretty(&contract)?,
    )?;
    let previous = diagnostic_text(&package.join("raw.log")).unwrap_or_default();
    let mut raw = format!("Worker production/harvest failed: {error}\n");
    for name in ["agent.out", "agent.err"] {
        raw.push_str(&format!("=== {name} ===\n"));
        raw.push_str(
            &diagnostic_text(&state.join(name)).unwrap_or_else(|e| format!("unavailable: {e}\n")),
        );
    }
    raw.push_str("=== Earlier worker evidence ===\n");
    raw.push_str(&previous);
    std::fs::write(
        package.join("raw.log"),
        clip_diagnostic(raw, TRANSCRIPT_BYTES),
    )?;
    std::fs::write(package.join("transcript.md"), &contract.summary)?;
    if !package.join("diffstat.txt").exists() {
        std::fs::write(package.join("diffstat.txt"), "")?;
    }
    Ok(())
}

std::thread_local! {
    static GITHUB_FAILURES: std::cell::RefCell<std::collections::BTreeMap<String, String>> = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
    static COMMAND_DEADLINE: std::cell::Cell<Option<std::time::Instant>> = const { std::cell::Cell::new(None) };
}
/// Bounds synchronous tool work as well as the foreground model. Retirement
/// and mandatory reporting run after this window is dropped.
struct CommandWindow(Option<std::time::Instant>);
impl CommandWindow {
    fn until(deadline: std::time::Instant) -> Self {
        Self(COMMAND_DEADLINE.with(|slot| slot.replace(Some(deadline))))
    }
}
impl Drop for CommandWindow {
    fn drop(&mut self) {
        COMMAND_DEADLINE.with(|slot| slot.set(self.0));
    }
}
fn output(command: &mut Command) -> Result<Vec<u8>, ScalerError> {
    let limit = COMMAND_DEADLINE
        .with(|slot| {
            slot.get()
                .map(|d| d.saturating_duration_since(std::time::Instant::now()))
        })
        .unwrap_or(std::time::Duration::from_secs(120))
        .min(std::time::Duration::from_secs(120));
    if limit.is_zero() {
        return Err(ScalerError::Guard("loop wall budget exhausted"));
    }
    crate::ci_scaler::execute(command, &[], limit)
}
pub(crate) fn git_invocation(root: &Path, args: &[&str]) -> Command {
    // Worktree .gitattributes is honored; it has no driver without config.
    let mut command = crate::safe_copy::git_command(root, args);
    command
        .env_remove("DISPATCH_BOARD_TOKEN")
        .env_remove("DISPATCH_PUBLISH_TOKEN");
    command
}

fn git(root: &Path, args: &[&str]) -> Result<String, ScalerError> {
    String::from_utf8(output(&mut git_invocation(root, args))?)
        .map_err(|_| ScalerError::Guard("non-UTF8 git output"))
}
fn draft_pr_title(work: &Path, base: &str, issue: u64, token: &str) -> Result<String, ScalerError> {
    // Only read the runner's reconstructed repository, through the same
    // hardened Git invocation as completion's other repository operations.
    let commits = git(
        work,
        &[
            "rev-list",
            "--reverse",
            "--topo-order",
            &format!("{base}..HEAD"),
        ],
    )?;
    let subject = match commits.lines().next() {
        Some(first) => git(work, &["show", "--no-patch", "--format=%s", first])?,
        None => String::new(),
    };
    // Remove only Git's record terminator; trimming would hide controls.
    let subject = subject.strip_suffix('\n').unwrap_or(&subject);
    let title = if subject.trim().is_empty()
        || subject.chars().count() > 100
        || subject.chars().any(char::is_control)
    {
        format!("chore(ci): work issue {issue}")
    } else {
        subject.to_owned()
    };
    Ok(title.replace(token, "[REDACTED]"))
}

fn gh(root: &Path, args: &[&str]) -> Result<String, ScalerError> {
    gh_with_token(root, args, None)
}
/// Only publication writes use the scoped App credential. Reads and comments
/// continue to inherit the job token from the runner's environment.
#[derive(Clone, Copy)]
enum PublishEvent {
    BranchPush,
    PrPush,
    PrCreate,
    BodyPatch,
}
impl PublishEvent {
    fn label(self) -> &'static str {
        match self {
            Self::BranchPush => "branch_push",
            Self::PrPush => "pr_push",
            Self::PrCreate => "pr_create",
            Self::BodyPatch => "body_patch",
        }
    }
}
/// Why a publication wrote with the job token instead of the scoped App token.
/// The error class is a fixed marker, never the error text, so it is safe to
/// record in artifacts and comments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TokenFallback {
    /// The controller refused the on-demand publish mint (#1012).
    MintRefused {
        reason: crate::ci_scaler::mint::MintRefusal,
    },
    /// The controller's mint channel was absent or did not answer in time.
    MintUnavailable {
        reason: crate::dispatch_mint::MintUnavailable,
    },
    /// The PR is created for an earlier run's branch, deliberately with the
    /// job token (that run's artifacts cannot gain an App binding).
    PriorRunRecovery,
    /// An App-token operation failed with an authentication error.
    Rejected { operation: String, class: String },
}
impl TokenFallback {
    fn describe(&self) -> String {
        use crate::dispatch_mint::MintFailure;
        match self {
            Self::MintRefused { reason } => format!(
                "the controller refused the publish token: {}",
                MintFailure::Refused(*reason).describe()
            ),
            Self::MintUnavailable { reason } => format!(
                "the publish token could not be minted: {}",
                MintFailure::Unavailable(*reason).describe()
            ),
            Self::PriorRunRecovery => {
                "the publish token was not used: the PR belongs to an earlier run's branch".into()
            }
            Self::Rejected { operation, class } => {
                format!("the publish token was rejected during {operation} ({class})")
            }
        }
    }
}
impl From<crate::dispatch_mint::MintFailure> for TokenFallback {
    fn from(failure: crate::dispatch_mint::MintFailure) -> Self {
        match failure {
            crate::dispatch_mint::MintFailure::Refused(reason) => Self::MintRefused { reason },
            crate::dispatch_mint::MintFailure::Unavailable(reason) => {
                Self::MintUnavailable { reason }
            }
        }
    }
}
/// The publish App token is minted on demand at the first write and reused
/// for this publication; it never comes from the job environment.
struct PublishCredential<'a> {
    app: Option<crate::ci_scaler::mint::AppToken>,
    minted: bool,
    job: &'a str,
    wrote: bool,
    ci_triggered: bool,
    fallback: Option<TokenFallback>,
}
impl<'a> PublishCredential<'a> {
    fn new(job: &'a str) -> Self {
        Self {
            app: None,
            minted: false,
            job,
            wrote: false,
            ci_triggered: false,
            fallback: None,
        }
    }
    /// Use the job token for the rest of this publication without minting.
    fn job_only(&mut self) {
        if self.app.is_some() || !self.minted {
            self.fallback = Some(TokenFallback::PriorRunRecovery);
        }
        self.app = None;
        self.minted = true;
    }
    fn write<T>(
        &mut self,
        event: PublishEvent,
        mut operation: impl FnMut(&str) -> Result<T, ScalerError>,
    ) -> Result<T, ScalerError> {
        if !self.minted {
            self.minted = true;
            match crate::dispatch_mint::app_token(crate::ci_scaler::mint::MintScope::Publish) {
                Ok(token) => self.app = Some(token),
                Err(failure) => self.fallback = Some(failure.into()),
            }
        }
        let mut result = operation(
            self.app
                .as_ref()
                .map_or(self.job, crate::ci_scaler::mint::AppToken::secret),
        );
        let class = match (&self.app, &result) {
            (Some(_), Err(e)) => publish_auth_marker(&e.to_string()),
            _ => None,
        };
        if let Some(class) = class {
            self.app = None;
            self.fallback = Some(TokenFallback::Rejected {
                operation: event.label().into(),
                class: class.into(),
            });
            result = operation(self.job);
        }
        if result.is_ok() {
            self.wrote = true;
            self.ci_triggered |= self.app.is_some()
                && matches!(event, PublishEvent::PrPush | PublishEvent::PrCreate);
        }
        if self.wrote {
            Applied::record(|a| {
                a.ci_requires_owner = self.app.is_none() && !self.ci_triggered;
                a.token_fallback = self.fallback.clone();
            })?;
        }
        result
    }
    fn gh(
        &mut self,
        root: &Path,
        args: &[&str],
        event: PublishEvent,
    ) -> Result<String, ScalerError> {
        self.write(event, |token| gh_with_token(root, args, Some(token)))
    }
}
/// The fixed marker that classified `error` as an authentication failure.
fn publish_auth_marker(error: &str) -> Option<&'static str> {
    let error = error.to_ascii_lowercase();
    if [
        "http 403",
        "http/1.1 403",
        "http/2 403",
        "returned error: 403",
        "[rejected]",
        "stale info",
        "lease rejection",
    ]
    .iter()
    .any(|marker| error.contains(marker))
    {
        return None;
    }
    [
        "bad credentials",
        "http 401",
        "http/1.1 401",
        "http/2 401",
        "returned error: 401",
        "authentication failed",
        "could not read username",
    ]
    .into_iter()
    .find(|marker| error.contains(marker))
}
fn publish_permission_failure(error: &str) -> bool {
    let error = error.to_ascii_lowercase().replace(['`', '\'', '"'], "");
    [
        "http 403",
        "http/1.1 403",
        "http/2 403",
        "returned error: 403",
        "permission denied",
        "workflows permission",
        "workflow permission",
        "write access to repository not granted",
    ]
    .iter()
    .any(|marker| error.contains(marker))
}
fn gh_with_token(root: &Path, args: &[&str], token: Option<&str>) -> Result<String, ScalerError> {
    let endpoint = match args {
        ["api", rest @ ..] => rest
            .iter()
            .find(|s| !s.starts_with('-'))
            .copied()
            .unwrap_or("api")
            .to_owned(),
        ["issue", "comment", number, ..] => format!("repos/{REPOSITORY}/issues/{number}/comments"),
        ["pr", "create", ..] => format!("repos/{REPOSITORY}/pulls"),
        ["run", "download", number, ..] => {
            format!("repos/{REPOSITORY}/actions/runs/{number}/artifacts")
        }
        _ => "GitHub operation".into(),
    };
    let result = timed_phase(&format!("github:{endpoint}"), || {
        let mut command = Command::new("gh");
        command
            .args(args)
            .current_dir(root)
            .env_remove("DISPATCH_BOARD_TOKEN")
            .env_remove("DISPATCH_PUBLISH_TOKEN");
        if let Some(token) = token {
            command.env("GH_TOKEN", token).env_remove("GITHUB_TOKEN");
        }
        output(&mut command)
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|_| ScalerError::Guard("non-UTF8 GitHub output"))
            })
            .map_err(|error| {
                // execute already drains and redacts a bounded stderr prefix. Mask
                // again before clipping so a cut credential cannot escape.
                let detail = crate::dispatch_redaction::redact(error.to_string().as_bytes());
                ScalerError::Usage(format!(
                    "GitHub {endpoint}: {}",
                    detail.chars().take(2048).collect::<String>()
                ))
            })
    });
    GITHUB_FAILURES.with(|failures| {
        let mut failures = failures.borrow_mut();
        match &result {
            Ok(_) => {
                failures.remove(&endpoint);
            }
            Err(error) => {
                failures.insert(endpoint, error.to_string());
            }
        }
    });
    result
}
fn sudo(args: &[&str]) -> Result<(), ScalerError> {
    sudo_as(AGENT_USER, args)
}
fn sudo_as(user: &str, args: &[&str]) -> Result<(), ScalerError> {
    let mut command = Command::new("/usr/bin/sudo");
    private_environment(&mut command);
    output(command.args(["-n", "-u", user, "--"]).args(args))?;
    Ok(())
}
fn hand_over(path: &Path) -> Result<(), ScalerError> {
    hand_over_to(path, AGENT_USER)
}
fn hand_over_to(path: &Path, user: &str) -> Result<(), ScalerError> {
    let parent = path
        .parent()
        .ok_or(ScalerError::Guard("agent staging parent"))?;
    for (program, args) in [
        ("/usr/bin/chgrp", ["-hR", user]),
        ("/usr/bin/chmod", ["-R", "ug+rwX,o-rwx"]),
    ] {
        output(Command::new(program).args(args).arg(parent))?;
    }
    let owned = parent.join("owned");
    sudo_as(
        user,
        &[
            "/usr/bin/cp",
            "-a",
            "--no-preserve=ownership",
            "--",
            path.to_str().ok_or(ScalerError::Guard("agent path"))?,
            owned
                .to_str()
                .ok_or(ScalerError::Guard("agent staging path"))?,
        ],
    )?;
    let old = parent.join("runner-staging");
    std::fs::rename(path, &old)?;
    std::fs::rename(owned, path)?;
    std::fs::remove_dir_all(old)?;
    Ok(())
}
fn retirement_command(user: &str) -> Result<(tempfile::TempDir, Command), ScalerError> {
    let helper = tempfile::Builder::new()
        .prefix("carrick-retire-")
        .tempdir_in("/var/tmp")?;
    let executable = std::env::current_exe()?;
    #[cfg(test)]
    let executable = executable.with_file_name("../carrick-xtask");
    let binary = helper.path().join("driver");
    std::fs::copy(executable, &binary)?;
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o555))?;
    std::fs::set_permissions(helper.path(), std::fs::Permissions::from_mode(0o755))?;
    // Retirement must remain available after the tool command deadline.
    let identity = crate::ci_scaler::execute(
        Command::new("/usr/bin/id").args(["-u", user]),
        &[],
        std::time::Duration::from_secs(10),
    )?;
    let uid = String::from_utf8_lossy(&identity)
        .trim()
        .parse::<libc::uid_t>()
        .map_err(|_| ScalerError::Guard("invalid agent uid"))?;
    let mut command = crate::process_helper::command(&binary, user, uid);
    private_environment(&mut command);
    Ok((helper, command))
}
fn retire_agent() -> Result<(), ScalerError> {
    retire_account(AGENT_USER)
}
fn retire_account(user: &str) -> Result<(), ScalerError> {
    let (_helper, mut command) = retirement_command(user)?;
    retire_agent_with(&mut command, user)
}
fn retire_agent_with(command: &mut Command, user: &str) -> Result<(), ScalerError> {
    // The census reads each process's state from /proc; without it a
    // listed pid could not be told from a gone one, so fail closed.
    if !Path::new("/proc/self/stat").is_file() {
        return Err(ScalerError::Guard("cannot verify agent process retirement"));
    }
    let mut survivors = Vec::new();
    for _ in 0..100 {
        crate::process_helper::run_checked(command)?;
        let mut entries = Vec::new();
        for selector in ["-u", "-U"] {
            let status = Command::new("/usr/bin/pgrep")
                .args([selector, user])
                .output()?;
            match status.status.code() {
                Some(1) if status.stdout.is_empty() && status.stderr.is_empty() => {}
                Some(0) => {
                    for pid in String::from_utf8_lossy(&status.stdout).split_whitespace() {
                        let pid = pid
                            .parse::<libc::pid_t>()
                            .map_err(|_| ScalerError::Guard("invalid retirement census pid"))?;
                        // Reap only this uid's adopted children. A loop launcher may
                        // exit while a worker retires; its Child still owns its wait.
                        // SAFETY: WNOHANG reaps only this named completed child.
                        unsafe {
                            libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG);
                        }
                        if let Some(entry) = census_entry(pid) {
                            entries.push(entry);
                        }
                    }
                }
                _ => return Err(ScalerError::Guard("cannot verify agent process retirement")),
            }
        }
        survivors = live_survivors(entries);
        if survivors.is_empty() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err(ScalerError::Usage(format!(
        "agent user still has processes; packaging refused: {}",
        survivors
            .iter()
            .map(CensusEntry::describe)
            .collect::<Vec<_>>()
            .join("; ")
    )))
}

/// One process the retirement census found (#1286), read from
/// `/proc/<pid>/stat`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CensusEntry {
    pid: libc::pid_t,
    state: char,
    parent: libc::pid_t,
    command: String,
    /// A thread of this process is in a live state: a zombie thread-group
    /// leader whose other threads still run is not dead.
    live_thread: bool,
}
impl CensusEntry {
    fn describe(&self) -> String {
        format!(
            "pid {} `{}` state {} parent {}",
            self.pid, self.command, self.state, self.parent
        )
    }
}
/// The census entry for `pid`, or `None` only once the process is gone
/// (`/proc/<pid>` not found). Anything unreadable or unparseable is a
/// survivor: the census fails closed (#1286 review).
fn census_entry(pid: libc::pid_t) -> Option<CensusEntry> {
    let unverified = |why: &str| CensusEntry {
        pid,
        state: '?',
        parent: 0,
        command: format!("<{why}>"),
        live_thread: true,
    };
    let stat = match std::fs::read(format!("/proc/{pid}/stat")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return Some(unverified("stat unreadable")),
    };
    let Some(mut entry) = parse_stat(pid, &String::from_utf8_lossy(&stat)) else {
        return Some(unverified("stat unparseable"));
    };
    if entry.state == 'Z' {
        entry.live_thread = match std::fs::read_dir(format!("/proc/{pid}/task")) {
            Ok(tasks) => tasks.flatten().any(|task| {
                std::fs::read(task.path().join("stat")).map_or(true, |bytes| {
                    parse_stat(pid, &String::from_utf8_lossy(&bytes))
                        .is_none_or(|thread| !matches!(thread.state, 'Z' | 'X' | 'x'))
                })
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => true,
        };
    }
    Some(entry)
}
/// `/proc/<pid>/stat`: `pid (comm) state ppid ...`; `comm` may hold spaces
/// and parentheses, so it ends at the last `)`.
fn parse_stat(pid: libc::pid_t, stat: &str) -> Option<CensusEntry> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let mut rest = stat.get(close + 1..)?.split_whitespace();
    let state = rest.next()?.chars().next()?;
    let parent = rest.next()?.parse().ok()?;
    Some(CensusEntry {
        pid,
        state,
        parent,
        command: stat.get(open + 1..close)?.to_owned(),
        live_thread: false,
    })
}
/// The census entries that can still run (#1286). After the helper's
/// SIGKILL the agent uid can't run anything; a zombie (`Z`) or a fully
/// dead (`X`) entry holds no code that could write the worktree, only a
/// pid its parent has yet to reap, so it doesn't block packaging.
fn live_survivors(entries: Vec<CensusEntry>) -> Vec<CensusEntry> {
    let mut live: Vec<CensusEntry> = entries
        .into_iter()
        .filter(|entry| entry.live_thread || !matches!(entry.state, 'Z' | 'X' | 'x'))
        .collect();
    live.sort_by_key(|entry| entry.pid);
    live.dedup_by_key(|entry| entry.pid);
    live
}
pub(crate) fn cleanup_dispatch_users() -> Result<(), ScalerError> {
    // Attempt both retirements even when one account census fails.
    let agent = cleanup_agent_user();
    let coordinator = cleanup_account(LOOP_USER);
    agent.and(coordinator)
}
pub(crate) fn cleanup_agent_user() -> Result<(), ScalerError> {
    cleanup_account(AGENT_USER)
}
fn cleanup_account(user: &str) -> Result<(), ScalerError> {
    let status = Command::new("/usr/bin/id").args(["-u", user]).output()?;
    if status.status.success() {
        let uid = String::from_utf8_lossy(&status.stdout)
            .trim()
            .parse::<libc::uid_t>()
            .map_err(|_| ScalerError::Guard("invalid agent account identity"))?;
        // Nested auth fixtures may clean their files, never their own uid.
        // SAFETY: geteuid has no preconditions.
        if uid == 0 {
            return Err(ScalerError::Guard("agent account must not be root"));
        }
        if uid != unsafe { libc::geteuid() } {
            retire_account(user)?;
        }
    } else if status.status.code() != Some(1) {
        return Err(ScalerError::Guard("cannot verify agent account cleanup"));
    }
    Ok(())
}
fn sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn run_id() -> Result<String, ScalerError> {
    std::env::var("GITHUB_RUN_ID")
        .ok()
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .ok_or(ScalerError::Guard("invalid run ID"))
}
fn assigned_branch(dispatch: &mut Dispatch) -> Result<(), ScalerError> {
    if !dispatch.resume {
        dispatch.branch = format!("work/dispatch-{}-{}", dispatch.issue, run_id()?);
    }
    Ok(())
}
pub(crate) fn branch_run(issue: u64, branch: &str) -> Result<&str, ScalerError> {
    branch
        .strip_prefix(&format!("work/dispatch-{issue}-"))
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
        .ok_or(ScalerError::Guard(
            "branch is not derived from this issue's run",
        ))
}

fn open_prs(root: &Path, branch: &str) -> Result<Value, ScalerError> {
    branch_prs(root, branch, "open")
}
fn branch_prs(root: &Path, branch: &str, state: &str) -> Result<Value, ScalerError> {
    let filter = if state == "open" {
        "&base=main"
    } else {
        "&per_page=100"
    };
    let prs: Value = serde_json::from_str(&gh(
        root,
        &[
            "api",
            &format!("repos/{REPOSITORY}/pulls?state={state}{filter}&head=carrick-sh:{branch}"),
        ],
    )?)?;
    if state == "all" && prs.as_array().is_some_and(|prs| prs.len() >= 100) {
        return Err(ScalerError::Guard("branch PR history exceeds bound"));
    }
    if state == "all"
        && prs.as_array().is_some_and(|prs| {
            prs.iter()
                .any(|pr| pr["state"] == "closed" || pr["merged_at"].as_str().is_some())
        })
    {
        return Err(ScalerError::Guard("branch had a closed or merged PR"));
    }
    Ok(prs)
}

/// Run shape for controller admission and #799 PR ownership: repository,
/// workflow, event and ref, and human actors. It does not decide trust:
/// authority callers use [`dispatch_run_admitted`], which adds the live
/// collaborator check (#1214). Artifact and publication provenance
/// additionally authenticate main workflow and jobs. The issue constraint is
/// checked against every available issue/branch mapping.
pub(crate) fn dispatch_run_identity(run: &Value, issue: Option<u64>) -> bool {
    let branch = run["head_branch"].as_str().unwrap_or_default();
    let review_issue = dispatch_branch(branch);
    if run["repository"]["full_name"] != REPOSITORY
        || run["head_repository"]["full_name"] != REPOSITORY
        || run["path"] != ".github/workflows/dispatch-worker.yml"
        || !run["head_sha"]
            .as_str()
            .is_some_and(crate::ci_scaler::full_sha)
        || !(chain_run(run)
            || ([&run["actor"], &run["triggering_actor"]]
                .iter()
                .all(|actor| {
                    actor["type"] == "User"
                        && actor["login"]
                            .as_str()
                            .is_some_and(|l| permission_endpoint(l).is_some())
                })
                && ((matches!(run["event"].as_str(), Some("issues" | "issue_comment"))
                    && branch == "main")
                    || (run["event"] == "pull_request_review" && review_issue.is_some()))))
    {
        return false;
    }
    let Some(issue) = issue else {
        return true;
    };
    let mapped_numbers = [
        run.pointer("/issue/number"),
        run.pointer("/event_payload/issue/number"),
    ];
    if review_issue.is_some_and(|mapped| mapped != issue)
        || mapped_numbers
            .into_iter()
            .flatten()
            .any(|n| n.as_u64() != Some(issue))
    {
        return false;
    }
    run["pull_requests"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(run.pointer("/event_payload/pull_request"))
        .all(|pr| {
            pr["head"]["ref"]
                .as_str()
                .and_then(dispatch_branch)
                .is_none_or(|mapped| mapped == issue)
        })
}

/// [`dispatch_run_identity`] plus a live trust check on both the run's
/// actor and its triggering actor. A chained run's actors are the Actions
/// bot by construction ([`chain_run`]): only the chain job holds
/// `actions: write`, and only after [`verify_chain`]. Admitting one still
/// needs that rule: the controller re-verifies its outcome before any
/// runner, and history callers require its guard's `Chain outcome` marker.
pub(crate) fn dispatch_run_admitted(
    run: &Value,
    issue: Option<u64>,
    trusted: &mut dyn FnMut(&str) -> bool,
) -> bool {
    dispatch_run_identity(run, issue)
        && (chain_run(run)
            || (trusted_user(&run["actor"], trusted)
                && trusted_user(&run["triggering_actor"], trusted)))
}

/// The account a chained run starts as: `workflow_dispatch` sent with a
/// job's `GITHUB_TOKEN` runs as the Actions bot (#1241 part 3).
pub(crate) const CHAIN_ACTOR: &str = "github-actions[bot]";

/// The only run shape a chained round has: `workflow_dispatch` of this
/// workflow on `main`, started and triggered by [`CHAIN_ACTOR`]. Shared by
/// the guard (runner environment), the controller (REST run) and job start
/// (hook context). It says nothing about the outcome the run names; that is
/// [`verify_chain`]'s.
pub(crate) fn chain_context(
    event: &str,
    git_ref: &str,
    workflow_ref: &str,
    actor: &str,
    triggering_actor: &str,
) -> bool {
    event == "workflow_dispatch"
        && git_ref == "refs/heads/main"
        && workflow_ref
            == format!(
                "{REPOSITORY}/{}@refs/heads/main",
                crate::ci_scaler::DISPATCH_WORKFLOW
            )
        && actor == CHAIN_ACTOR
        && triggering_actor == CHAIN_ACTOR
}
/// [`chain_context`] for a REST workflow run.
pub(crate) fn chain_run(run: &Value) -> bool {
    let branch = run["head_branch"].as_str().unwrap_or_default();
    fn login(actor: &Value) -> &str {
        if actor["type"] == "Bot" {
            actor["login"].as_str().unwrap_or_default()
        } else {
            ""
        }
    }
    run["repository"]["full_name"] == REPOSITORY
        && run["head_repository"]["full_name"] == REPOSITORY
        && run["head_sha"]
            .as_str()
            .is_some_and(crate::ci_scaler::full_sha)
        && chain_context(
            run["event"].as_str().unwrap_or_default(),
            &format!("refs/heads/{branch}"),
            &format!(
                "{REPOSITORY}/{}@refs/heads/{branch}",
                run["path"].as_str().unwrap_or_default()
            ),
            login(&run["actor"]),
            login(&run["triggering_actor"]),
        )
}

/// Proof that a Continuing outcome may start the next round (#1241 part 3).
/// Only [`verify_chain`] makes one, from live API reads alone.
#[derive(Debug, Clone)]
pub(crate) struct ChainLink {
    /// The dispatch issue the chain belongs to.
    pub(crate) issue: u64,
    /// The issue or dispatch PR the outcome was posted on.
    pub(crate) thread: u64,
    /// The live outcome comment, the chained round's trigger.
    pub(crate) outcome: Value,
    pub(crate) facts: ChainFacts,
}
type Read<'a> = dyn FnMut(&str) -> Result<Value, ScalerError> + 'a;
/// Every page of a list endpoint, read through `read`.
fn read_pages(read: &mut Read<'_>, path: &str) -> Result<Vec<Value>, ScalerError> {
    let mut items = Vec::new();
    for page in 1..=20 {
        let join = if path.contains('?') { '&' } else { '?' };
        let data = read(&format!("{path}{join}per_page=100&page={page}"))?;
        let entries = data
            .as_array()
            .ok_or(ScalerError::Guard("invalid list page"))?;
        items.extend(entries.iter().cloned());
        if entries.len() < 100 {
            return Ok(items);
        }
    }
    Err(ScalerError::Guard("list too long to verify"))
}
/// The threads a dispatch issue's rounds post on: the issue and its open
/// dispatch PRs.
fn chain_threads(read: &mut Read<'_>, issue: u64) -> Result<Vec<u64>, ScalerError> {
    let mut threads = vec![issue];
    for pr in read_pages(
        read,
        &format!("repos/{REPOSITORY}/pulls?state=open&base=main"),
    )? {
        if pr["head"]["ref"].as_str().and_then(dispatch_branch) == Some(issue)
            && pr["head"]["repo"]["full_name"] == REPOSITORY
            && let Some(number) = pr["number"].as_u64()
        {
            threads.push(number);
        }
    }
    Ok(threads)
}
fn dispatch_outcome_author(user: &Value) -> bool {
    dispatch_comment_author(user) || publish_app_author(user)
}
/// `https://github.com/{REPOSITORY}/{issues|pull}/{n}#{anchor}{id}`.
fn anchored(url: &str, anchor: &str) -> Option<(u64, u64)> {
    let rest = url.strip_prefix(&format!("https://github.com/{REPOSITORY}/"))?;
    let rest = rest
        .strip_prefix("issues/")
        .or_else(|| rest.strip_prefix("pull/"))?;
    let (number, id) = rest.split_once(&format!("#{anchor}"))?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    (digits(number) && digits(id)).then(|| Some((number.parse().ok()?, id.parse().ok()?)))?
}
fn comment_thread(comment: &Value) -> Option<u64> {
    comment["issue_url"]
        .as_str()?
        .strip_prefix(&format!(
            "https://api.github.com/repos/{REPOSITORY}/issues/"
        ))?
        .parse()
        .ok()
}
fn owner_user(user: &Value) -> bool {
    user["login"] == crate::ci_scaler::DISPATCH_OWNER && user["type"] == "User"
}
/// The chain rule (#1241 part 3, director conditions on the design): the
/// named comment is an authentic, unedited Continuing dispatch outcome below
/// the chain limit, with a pushed checkpoint on a dispatch branch of its
/// issue; it is the latest outcome on the issue and its open dispatch PRs;
/// no owner comment, review or dispatch label, no `/agent` command and no
/// changes-requested review came after it; no outcome already chained from
/// it; and its `Chained from:` links, each an authentic Continuing outcome
/// one round earlier, reach within three hops a round whose `Round trigger:`
/// is the owner's `/agent` comment, changes-requested review or dispatch
/// label on one of those threads. The guard, the controller and the chain
/// job all decide through this one function; the dispatch input is the
/// comment id only, and everything else is re-read here.
pub(crate) fn verify_chain(id: u64, read: &mut Read<'_>) -> Result<ChainLink, ScalerError> {
    let refused = |why: &'static str| ScalerError::Guard(why);
    let outcome = read(&format!("repos/{REPOSITORY}/issues/comments/{id}"))?;
    let body = outcome["body"].as_str().unwrap_or_default();
    let section = agent_loop::chain_section(body).ok_or(refused("not a dispatch outcome"))?;
    let url = outcome["html_url"].as_str().unwrap_or_default().to_owned();
    let at = outcome["created_at"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    if outcome["id"].as_u64() != Some(id)
        || !dispatch_comment_author(&outcome["user"])
        || at.is_empty()
        || outcome["updated_at"] != outcome["created_at"]
        || anchored(&url, "issuecomment-").map(|(_, c)| c) != Some(id)
    {
        return Err(refused(
            "chain outcome is not an authentic dispatch outcome",
        ));
    }
    if section.status != "Continuing" {
        return Err(refused("chain outcome is not Continuing"));
    }
    if section.round >= CHAIN_ROUNDS {
        return Err(refused("chain is at its round limit"));
    }
    let (branch, head) = section
        .checkpoint
        .clone()
        .ok_or(refused("Continuing outcome names no checkpoint"))?;
    let thread = comment_thread(&outcome).ok_or(refused("chain outcome thread"))?;
    let item = read(&format!("repos/{REPOSITORY}/issues/{thread}"))?;
    let issue = if item.get("pull_request").is_some() {
        let pr = read(&format!("repos/{REPOSITORY}/pulls/{thread}"))?;
        pr["head"]["ref"]
            .as_str()
            .and_then(dispatch_branch)
            .ok_or(refused("chains continue dispatch PRs only"))?
    } else {
        thread
    };
    let issue_item = if issue == thread {
        item
    } else {
        read(&format!("repos/{REPOSITORY}/issues/{issue}"))?
    };
    if issue_item["state"] != "open" || issue_item.get("pull_request").is_some() {
        return Err(refused("chain issue is not an open issue"));
    }
    if dispatch_branch(&branch) != Some(issue) {
        return Err(refused(
            "checkpoint is not on a dispatch branch of the issue",
        ));
    }
    let threads = chain_threads(read, issue)?;
    if !threads.contains(&thread) {
        return Err(refused(
            "chain outcome is not on the issue or its open dispatch PR",
        ));
    }
    // Second-resolution timestamps: an item in the outcome's own second
    // counts as after it, so a tie fails closed.
    let named = |line: &str| {
        line.strip_prefix(agent_loop::CHAINED_FROM_LINE)
            .is_some_and(|rest| rest.starts_with(&format!("{url} (")))
    };
    for &t in &threads {
        for comment in read_pages(read, &format!("repos/{REPOSITORY}/issues/{t}/comments"))? {
            if comment["id"].as_u64() == Some(id) {
                continue;
            }
            let text = comment["body"].as_str().unwrap_or_default();
            let after = comment["created_at"]
                .as_str()
                .is_some_and(|c| c >= at.as_str());
            if dispatch_outcome_author(&comment["user"])
                && let Some(_) = agent_loop::outcome_status(text)
            {
                if agent_loop::server_part(text).lines().any(named) {
                    return Err(refused("another round already chained from this outcome"));
                }
                if after {
                    return Err(refused("chain outcome is not the latest dispatch outcome"));
                }
            }
            // Only the owner breaks a chain (#1262): any other account's
            // comment, `/agent` included, is not the owner's direction.
            if after && owner_user(&comment["user"]) {
                if text.trim() == round_inbox::STOP {
                    return Err(refused(
                        "`/agent stop` after the chain outcome ends the chain",
                    ));
                }
                return Err(refused(
                    "an owner comment or trigger after the chain outcome ends the chain",
                ));
            }
        }
        if t != issue {
            for review in read_pages(read, &format!("repos/{REPOSITORY}/pulls/{t}/reviews"))? {
                if review["submitted_at"]
                    .as_str()
                    .is_some_and(|s| s >= at.as_str())
                    && owner_user(&review["user"])
                {
                    return Err(refused(
                        "an owner review after the chain outcome ends the chain",
                    ));
                }
            }
        }
        for event in read_pages(read, &format!("repos/{REPOSITORY}/issues/{t}/timeline"))? {
            if event["event"] == "labeled"
                && event["label"]["name"].as_str().is_some_and(dispatch_label)
                && event["created_at"]
                    .as_str()
                    .is_some_and(|c| c >= at.as_str())
            {
                return Err(refused(
                    "a dispatch label after the chain outcome ends the chain",
                ));
            }
        }
    }
    // Back to the owner's trigger, one authentic Continuing outcome per hop.
    let mut link = section.clone();
    for _ in 0..CHAIN_ROUNDS {
        let Some(previous) = link.from.clone() else {
            return chain_root(read, &link, &threads).map(|()| ChainLink {
                issue,
                thread,
                outcome: outcome.clone(),
                facts: ChainFacts {
                    round: section.round + 1,
                    from: url.clone(),
                    branch: branch.clone(),
                    head: head.clone(),
                    brief: section.brief.clone(),
                },
            });
        };
        let (_, previous_id) =
            anchored(&previous, "issuecomment-").ok_or(refused("invalid Chained from link"))?;
        let comment = read(&format!("repos/{REPOSITORY}/issues/comments/{previous_id}"))?;
        let earlier = comment["body"]
            .as_str()
            .and_then(agent_loop::chain_section)
            .ok_or(refused("Chained from names no dispatch outcome"))?;
        // The same authenticity the head outcome needs (#1262): unedited,
        // and checkpointed on a dispatch branch of this issue.
        if comment["id"].as_u64() != Some(previous_id)
            || comment["html_url"] != previous.as_str()
            || !dispatch_comment_author(&comment["user"])
            || comment["created_at"].as_str().is_none()
            || comment["updated_at"] != comment["created_at"]
            || !comment_thread(&comment).is_some_and(|n| threads.contains(&n))
            || earlier.status != "Continuing"
            || earlier.round + 1 != link.round
            || earlier
                .checkpoint
                .as_ref()
                .is_none_or(|(branch, _)| dispatch_branch(branch) != Some(issue))
        {
            return Err(refused(
                "Chained from link is not the previous Continuing round",
            ));
        }
        link = earlier;
    }
    Err(refused("chain has no owner root within its hop limit"))
}
/// A first round's trigger: the owner's `/agent` comment, changes-requested
/// review or dispatch label on one of the chain's threads.
fn chain_root(
    read: &mut Read<'_>,
    root: &agent_loop::ChainSection,
    threads: &[u64],
) -> Result<(), ScalerError> {
    let refused = || ScalerError::Guard("chain has no owner root");
    let trigger = root.trigger.as_deref().ok_or_else(refused)?;
    if root.round != 1 {
        return Err(refused());
    }
    let rooted = if let Some((n, id)) = anchored(trigger, "issuecomment-") {
        let c = read(&format!("repos/{REPOSITORY}/issues/comments/{id}"))?;
        c["id"].as_u64() == Some(id)
            && comment_thread(&c) == Some(n)
            && owner_user(&c["user"])
            && c["body"].as_str().is_some_and(|b| b.starts_with("/agent"))
    } else if let Some((n, id)) = anchored(trigger, "pullrequestreview-") {
        let r = read(&format!("repos/{REPOSITORY}/pulls/{n}/reviews/{id}"))?;
        r["id"].as_u64() == Some(id) && owner_user(&r["user"]) && r["state"] == "CHANGES_REQUESTED"
    } else if let Some((n, id)) = anchored(trigger, "event-") {
        let e = read(&format!("repos/{REPOSITORY}/issues/events/{id}"))?;
        e["id"].as_u64() == Some(id)
            && e["event"] == "labeled"
            && e["issue"]["number"].as_u64() == Some(n)
            && owner_user(&e["actor"])
            && e["label"]["name"].as_str().is_some_and(dispatch_label)
    } else {
        false
    };
    let n = anchored(trigger, "issuecomment-")
        .or_else(|| anchored(trigger, "pullrequestreview-"))
        .or_else(|| anchored(trigger, "event-"))
        .map(|(n, _)| n);
    if rooted && n.is_some_and(|n| threads.contains(&n)) {
        Ok(())
    } else {
        Err(refused())
    }
}

fn dispatch_comment_author(user: &Value) -> bool {
    user["type"] == "Bot" && user["login"] == "github-actions[bot]"
}
fn publish_app_author(user: &Value) -> bool {
    user["type"] == "Bot" && user["login"] == "carrick-workers[bot]"
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationRecord {
    issue: u64,
    branch: String,
    publication_pr: u64,
}
/// Created only from a successful server write or authenticated run evidence.
pub(crate) struct PublishedPr(PublicationRecord);
impl PublishedPr {
    fn matches(&self, pr: &Value, issue: u64, branch: &str) -> bool {
        self.0.issue == issue
            && self.0.branch == branch
            && pr["number"].as_u64() == Some(self.0.publication_pr)
    }
}
pub(crate) type PublicationLookup<'a> =
    dyn FnMut(&Value, &Value, u64, &str) -> Option<PublishedPr> + 'a;
/// The controller uses the same authenticated artifact/comment resolver as the
/// hosted guard and tool server. Every gh destination is repository-explicit.
pub(crate) fn recorded_publication(
    pr: &Value,
    run: &Value,
    issue: u64,
    branch: &str,
) -> Option<PublishedPr> {
    let limit = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let deadline = COMMAND_DEADLINE.with(|slot| slot.get().map_or(limit, |d| d.min(limit)));
    let _window = CommandWindow::until(deadline);
    agent_loop::RunCache::for_controller().publication(Path::new("."), pr, run, issue, branch)
}

pub(crate) fn owned_pr(
    pr: &Value,
    run: &Value,
    issue: u64,
    branch: &str,
    publication: Option<&PublishedPr>,
    trusted: &mut dyn FnMut(&str) -> bool,
) -> bool {
    let Ok(id) = branch_run(issue, branch) else {
        return false;
    };
    (dispatch_comment_author(&pr["user"])
        || (publish_app_author(&pr["user"])
            && publication.is_some_and(|p| p.matches(pr, issue, branch))))
        && pr["head"]["repo"]["full_name"] == REPOSITORY
        && pr["head"]["ref"] == branch
        && pr["base"]["ref"] == "main"
        && pr["draft"] == true
        && run["id"].as_u64().map(|n| n.to_string()).as_deref() == Some(id)
        // A chained run never owns a branch (#1262): it continues the
        // checkpoint branch of the owner-rooted round it chains from, so
        // ownership keeps that run's live collaborator re-check.
        && !chain_run(run)
        && dispatch_run_admitted(run, Some(issue), trusted)
        && pr["body"].as_str().is_some_and(|body| {
            body.lines().any(|line| line == format!("Closes #{issue}"))
                && body.lines().any(|line| {
                    line == format!(
                        "Dispatch run: https://github.com/{REPOSITORY}/actions/runs/{id}"
                    )
                })
        })
}

fn require_owned_pr(root: &Path, dispatch: &Dispatch) -> Result<Value, ScalerError> {
    let id = branch_run(dispatch.issue, &dispatch.branch)?;
    let run: Value = serde_json::from_str(&gh(
        root,
        &["api", &format!("repos/{REPOSITORY}/actions/runs/{id}")],
    )?)?;
    for pr in open_prs(root, &dispatch.branch)?
        .as_array()
        .into_iter()
        .flatten()
    {
        let publication = if publish_app_author(&pr["user"]) {
            let local = branch_run(dispatch.issue, &dispatch.branch)? == run_id()?
                && Applied::load()?.publication_pr == pr["number"].as_u64();
            if local {
                pr["number"].as_u64().map(|number| {
                    PublishedPr(PublicationRecord {
                        issue: dispatch.issue,
                        branch: dispatch.branch.clone(),
                        publication_pr: number,
                    })
                })
            } else {
                agent_loop::RunCache::default().publication(
                    root,
                    pr,
                    &run,
                    dispatch.issue,
                    &dispatch.branch,
                )
            }
        } else {
            None
        };
        if owned_pr(
            pr,
            &run,
            dispatch.issue,
            &dispatch.branch,
            publication.as_ref(),
            &mut collaborators(|endpoint| authenticated_api(root, endpoint)),
        ) {
            return Ok(pr.clone());
        }
    }
    Err(ScalerError::Guard(
        "branch lacks a draft PR created by its dispatch run",
    ))
}

/// The PR this run continues, re-resolved from the server: an owned dispatch
/// PR, or the adopted PR re-checked against the one adoption predicate. The
/// head is not compared here: it moves when this run publishes, and the push
/// lease is what protects the admitted tip.
pub(crate) fn require_target_pr(root: &Path, dispatch: &Dispatch) -> Result<Value, ScalerError> {
    let Continuation::Adopted { pr, branch, .. } = &dispatch.continuation else {
        return require_owned_pr(root, dispatch);
    };
    let live = api(root, &format!("repos/{REPOSITORY}/pulls/{pr}"))?;
    let adoption = adopted_pr(&live, |read| adoption_read(root, read))?.ok_or(
        ScalerError::Guard("adopted PR no longer qualifies for adoption"),
    )?;
    if adoption.number != *pr
        || adoption.branch != *branch
        || dispatch.branch != *branch
        || adoption.issue["number"].as_u64() != Some(dispatch.issue)
    {
        return Err(ScalerError::Guard("adopted PR scope changed"));
    }
    Ok(live)
}

fn regular_text(path: &Path) -> Result<String, ScalerError> {
    Ok(crate::safe_copy::text(path, 20 * 1024 * 1024)?)
}

/// How a worker's launcher ended, from its exit code (#1253): 124 is the
/// server's timeout, 0 a clean exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LauncherExit {
    Clean,
    TimedOut,
    Code(i32),
}
impl LauncherExit {
    pub(crate) fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Clean,
            124 => Self::TimedOut,
            code => Self::Code(code),
        }
    }
}
impl std::fmt::Display for LauncherExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "the worker's launcher exited cleanly"),
            Self::TimedOut => write!(f, "the worker timed out"),
            Self::Code(code) => write!(f, "the worker's launcher exited with code {code}"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Receipt {
    head: String,
    checkpointed: bool,
    base: String,
    branch: String,
    exit_code: i32,
    expected_tip: String,
    // The proposal belongs to the same atomic checkpoint as the tree.
    #[serde(default)]
    pr_body: Option<String>,
    worker: Worker,
    contract: Contract,
}

/// One predicate for continuation and publication: a scoped receipt and tree.
fn worker_checkpoint(state: &Path, dispatch: &Dispatch) -> Result<Option<Receipt>, ScalerError> {
    let work = state.join("work");
    let receipt_path = state.join("receipt.json");
    if !work.exists() && !receipt_path.exists() {
        return Ok(None);
    }
    if !work.is_dir() || !receipt_path.is_file() {
        return Err(ScalerError::Guard(
            "incomplete worker checkpoint: tree and receipt required",
        ));
    }
    let receipt: Receipt = regular_text(&receipt_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .ok_or(ScalerError::Guard("invalid worker checkpoint receipt"))?;
    if !sha(&receipt.head)
        || git(&work, &["rev-parse", "HEAD"])?.trim() != receipt.head
        || receipt.base != dispatch.base
        || receipt.branch != dispatch.branch
        || (!receipt.expected_tip.is_empty() && !sha(&receipt.expected_tip))
    {
        return Err(ScalerError::Guard("worker checkpoint scope refused"));
    }
    Ok(Some(receipt))
}

/// Where this run's lease starts: the admitted PR tip on an adopted run, else
/// the branch tip the first worker checked out (empty for a new branch).
fn admitted_tip<'a>(dispatch: &'a Dispatch, receipt: &'a Receipt) -> &'a str {
    match &dispatch.continuation {
        Continuation::Adopted { tip, .. } => tip,
        Continuation::Owned => &receipt.expected_tip,
    }
}
/// Whether the harvested head adds nothing to what the run started from.
fn produced_nothing(dispatch: &Dispatch, receipt: &Receipt) -> bool {
    let admitted = admitted_tip(dispatch, receipt);
    receipt.head == admitted || (admitted.is_empty() && receipt.head == receipt.base)
}

/// Commit, on top of the harvested work, `.github/workflows/` as it is on
/// admitted main, so the rest of the work can be pushed when dispatch's
/// credentials can't publish the workflow changes (#1241). Returns the
/// workflow paths left out; empty when there were none.
fn strip_workflow_changes(work: &Path, base: &str) -> Result<Vec<String>, ScalerError> {
    let changed: Vec<String> = git(
        work,
        &[
            "diff",
            "--name-only",
            "--no-renames",
            "-z",
            base,
            "HEAD",
            "--",
            ".github/workflows/",
        ],
    )?
    .split('\0')
    .filter(|p| !p.is_empty())
    .map(str::to_owned)
    .collect();
    if changed.is_empty() {
        return Ok(changed);
    }
    for path in &changed {
        let at_base = git(work, &["cat-file", "-e", &format!("{base}:{path}")]).is_ok();
        if at_base {
            git(work, &["checkout", base, "--", path])?;
        } else {
            git(work, &["rm", "-q", "--", path])?;
        }
    }
    git(
        work,
        &[
            "commit",
            "-q",
            "--no-verify",
            "-m",
            "chore(dispatch): leave workflow changes out of the WIP checkpoint\n\nDispatch credentials can't publish .github/workflows/*; the full patch\nis in the run's harvest.patch artifact.",
        ],
    )?;
    Ok(changed)
}

/// Re-pair the checkpoint receipt with the tree after publication moved HEAD.
fn refresh_checkpoint_head(state: &Path, work: &Path) -> Result<(), ScalerError> {
    use std::io::Write;
    let path = state.join("receipt.json");
    let mut receipt: Value = serde_json::from_str(&regular_text(&path)?)?;
    receipt["head"] = git(work, &["rev-parse", "HEAD"])?.trim().into();
    let mut next = tempfile::NamedTempFile::new_in(state)?;
    next.write_all(&serde_json::to_vec(&receipt)?)?;
    next.persist(&path).map_err(|error| error.error)?;
    Ok(())
}

/// Publish a fully validated candidate, rolling back the tree if receipt commit
/// fails. The last good pair remains untouched during harvesting and rendering.
fn install_worker_checkpoint(
    state: &Path,
    candidate: &Path,
    receipt: &Receipt,
) -> Result<(), ScalerError> {
    install_worker_checkpoint_with(
        state,
        candidate,
        receipt,
        |file, path| file.persist(path).map(|_| ()).map_err(|error| error.error),
        |path| std::fs::remove_dir_all(path),
    )
}
fn install_worker_checkpoint_with(
    state: &Path,
    candidate: &Path,
    receipt: &Receipt,
    persist: impl FnOnce(tempfile::NamedTempFile, &Path) -> Result<(), std::io::Error>,
    remove_tree: impl FnOnce(&Path) -> Result<(), std::io::Error>,
) -> Result<(), ScalerError> {
    use std::io::Write;
    let mut next_receipt = tempfile::NamedTempFile::new_in(state)?;
    next_receipt.write_all(&serde_json::to_vec(receipt)?)?;
    let backup = candidate.with_file_name("previous");
    let work = state.join("work");
    let had_work = work.exists();
    if had_work {
        std::fs::rename(&work, &backup)?;
    }
    let commit = (|| -> Result<(), ScalerError> {
        std::fs::rename(candidate, &work)?;
        persist(next_receipt, &state.join("receipt.json"))?;
        Ok(())
    })();
    if let Err(error) = commit {
        let rollback = (|| -> Result<(), std::io::Error> {
            if work.exists() {
                remove_tree(&work)?;
            }
            if had_work {
                std::fs::rename(&backup, &work)?;
            }
            Ok(())
        })();
        if let Err(rollback) = rollback {
            // A surviving new tree must never inherit the old receipt.
            match std::fs::remove_file(state.join("receipt.json")) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            return Err(ScalerError::Usage(format!(
                "{error}; checkpoint rollback failed: {rollback}; receipt invalidated"
            )));
        }
        return Err(error);
    }
    Ok(())
}

fn admitted_base(resolved_main: bool) -> Result<String, ScalerError> {
    select_base(
        resolved_main,
        std::env::var("CARRICK_DISPATCH_BASE").ok().as_deref(),
        std::env::var("GITHUB_SHA").ok().as_deref(),
    )
}
fn select_base(
    resolved_main: bool,
    main: Option<&str>,
    github_sha: Option<&str>,
) -> Result<String, ScalerError> {
    (if resolved_main { main } else { github_sha })
        .filter(|s| sha(s))
        .map(str::to_owned)
        .ok_or(ScalerError::Guard("missing admitted base SHA"))
}

fn authenticated_api(root: &Path, endpoint: &str) -> Result<Value, ScalerError> {
    Ok(serde_json::from_str(&gh(root, &["api", endpoint])?)?)
}

fn api(root: &Path, endpoint: &str) -> Result<Value, ScalerError> {
    let response = if std::env::var_os("GH_TOKEN").is_some() {
        gh(root, &["api", endpoint])?
    } else {
        String::from_utf8(output(Command::new("curl").args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            &format!("https://api.github.com/{endpoint}"),
        ]))?)
        .map_err(|_| ScalerError::Guard("non-UTF8 public GitHub response"))?
    };
    Ok(serde_json::from_str(&response)?)
}

/// The head the hosted guard observed (`CARRICK_DISPATCH_HEAD` on the clone),
/// else the event's own PR head. Admission refuses any other live head.
fn admitted_head(event: &Value) -> Option<String> {
    std::env::var("CARRICK_DISPATCH_HEAD")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            event["pull_request"]["head"]["sha"]
                .as_str()
                .map(str::to_owned)
        })
        .filter(|s| sha(s))
}

/// Resolve only server-owned scope. Model text is never parsed for branches.
/// An `/agent` comment on a PR no dispatch run named also returns the
/// adoption proof that `validate_event_with_publication` requires.
pub(crate) fn load_event(
    root: &Path,
    path: &Path,
    trusted: &mut dyn FnMut(&str) -> bool,
) -> Result<(Value, Option<Adoption>, Option<ChainLink>), ScalerError> {
    let (mut event, adoption, chain) = resolve_event(root, path, trusted)?;
    // Whatever path resolved the issue (the label payload, a live re-read for
    // an owned PR, or the adopted PR's closing issue), its title and body
    // enter Dispatch only through the last-writer checks.
    apply_trusted_brief(
        &mut event,
        |number| issue_brief_response(root, number),
        trusted,
    )?;
    Ok((event, adoption, chain))
}
/// The runner's own run shape ([`chain_context`]), from the environment
/// GitHub sets for every step.
fn runner_chain_context() -> bool {
    let var = |key: &str| std::env::var(key).unwrap_or_default();
    chain_context(
        &var("GITHUB_EVENT_NAME"),
        &var("GITHUB_REF"),
        &var("GITHUB_WORKFLOW_REF"),
        &var("GITHUB_ACTOR"),
        &var("GITHUB_TRIGGERING_ACTOR"),
    )
}
/// A `workflow_dispatch` payload: the chain job's dispatch, never a trigger
/// of its own. Its one input names the Continuing outcome.
fn dispatch_event(event: &Value) -> bool {
    event.get("inputs").is_some() && event.get("workflow").is_some()
}
/// The one open PR whose head is `branch` in this repository, if any.
fn checkpoint_pr(root: &Path, branch: &str) -> Result<Option<Value>, ScalerError> {
    let prs = api(
        root,
        &format!("repos/{REPOSITORY}/pulls?state=open&base=main&head=carrick-sh:{branch}"),
    )?;
    Ok(match prs.as_array().map(Vec::as_slice) {
        Some([pr]) if pr["head"]["ref"] == branch => {
            let number = pr["number"]
                .as_u64()
                .ok_or(ScalerError::Guard("missing PR number"))?;
            Some(api(root, &format!("repos/{REPOSITORY}/pulls/{number}"))?)
        }
        _ => None,
    })
}
fn resolve_event(
    root: &Path,
    path: &Path,
    trusted: &mut dyn FnMut(&str) -> bool,
) -> Result<(Value, Option<Adoption>, Option<ChainLink>), ScalerError> {
    let mut event: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let mut chain = None;
    if dispatch_event(&event) {
        // A chained round (#1241 part 3): admitted by the chain rule alone,
        // re-read from the API; the input is only the outcome's id.
        if !runner_chain_context() || event["ref"] != "refs/heads/main" {
            return Err(ScalerError::Guard(
                "a dispatch-worker workflow_dispatch must be the chain job's, on main",
            ));
        }
        let id = event["inputs"]["outcome"]
            .as_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or(ScalerError::Guard(
                "chain input must be an outcome comment id",
            ))?;
        let link = verify_chain(id, &mut |endpoint| authenticated_api(root, endpoint))?;
        event["issue"] = api(root, &format!("repos/{REPOSITORY}/issues/{}", link.thread))?;
        if link.thread != link.issue {
            event["pull_request"] =
                api(root, &format!("repos/{REPOSITORY}/pulls/{}", link.thread))?;
        } else if let Some(pr) = checkpoint_pr(root, &link.facts.branch)? {
            // Continue the checkpoint's open PR, owned by the owner-rooted
            // run that made it, rather than start a branch this chained run
            // would own (#1262).
            event["issue"] = api(root, &format!("repos/{REPOSITORY}/issues/{}", pr["number"]))?;
            event["pull_request"] = pr;
        }
        event["chain"] = link.outcome.clone();
        chain = Some(link);
    } else if !trusted_user(&event["sender"], trusted) {
        return Err(ScalerError::Guard("untrusted event actor"));
    }
    if event.get("comment").is_some() {
        let id = event["comment"]["id"]
            .as_u64()
            .ok_or(ScalerError::Guard("missing comment id"))?;
        let live = api(root, &format!("repos/{REPOSITORY}/issues/comments/{id}"))?;
        if !agent_comment(&live, trusted)
            || ["id", "body", "created_at", "updated_at"]
                .iter()
                .any(|k| live[k] != event["comment"][k])
        {
            return Err(ScalerError::Guard("triggering comment changed"));
        }
        if event["issue"].get("pull_request").is_some() {
            let number = event["issue"]["number"]
                .as_u64()
                .ok_or(ScalerError::Guard("missing PR number"))?;
            event["pull_request"] = api(root, &format!("repos/{REPOSITORY}/pulls/{number}"))?;
        }
    }
    if event.get("pull_request").is_some() {
        let branch = event["pull_request"]["head"]["ref"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let number = event["pull_request"]["number"]
            .as_u64()
            .ok_or(ScalerError::Guard("missing PR number"))?;
        let Some(issue) = dispatch_branch(&branch) else {
            // Only a collaborator /agent comment adopts; reviews need a dispatch ref.
            if event.get("comment").is_none() {
                return Err(ScalerError::Guard("not a dispatch head ref"));
            }
            let live = api(root, &format!("repos/{REPOSITORY}/pulls/{number}"))?;
            if !admitted_head(&event).is_some_and(|expected| live["head"]["sha"] == expected) {
                return Err(ScalerError::Guard("stale PR head"));
            }
            let adoption = adopted_pr(&live, |read| adoption_read(root, read))?.ok_or(
                ScalerError::Guard("PR is neither an owned dispatch PR nor adoptable"),
            )?;
            event["pull_request"] = live;
            event["issue"] = adoption.issue.clone();
            return Ok((event, Some(adoption), chain));
        };
        let id = branch_run(issue, &branch)?;
        let live = api(root, &format!("repos/{REPOSITORY}/pulls/{number}"))?;
        if !admitted_head(&event).is_some_and(|expected| live["head"]["sha"] == expected) {
            return Err(ScalerError::Guard("stale PR head"));
        }
        event["pull_request"] = live;
        event["dispatch_run"] = api(root, &format!("repos/{REPOSITORY}/actions/runs/{id}"))?;
        // Validate the exact App PR against server evidence before producing a
        // private admission. validate_event receives that proof separately.
        event["issue"] = api(root, &format!("repos/{REPOSITORY}/issues/{issue}"))?;
    }
    Ok((event, None, chain))
}

/// Select a single open owned PR, authenticating the original branch run.
fn select_owned_pr(
    issue: u64,
    prs: &[Value],
    mut run: impl FnMut(&Value, &str) -> Result<(Value, Option<PublishedPr>), ScalerError>,
    trusted: &mut dyn FnMut(&str) -> bool,
) -> Result<Option<Value>, ScalerError> {
    let mut selected = None;
    for pr in prs.iter().filter(|pr| pr["state"] == "open") {
        let branch = pr["head"]["ref"].as_str().unwrap_or_default();
        if dispatch_branch(branch) != Some(issue) {
            continue;
        }
        let (original, publication) = run(pr, branch_run(issue, branch)?)?;
        if owned_pr(pr, &original, issue, branch, publication.as_ref(), trusted) {
            if selected.is_some() {
                return Err(ScalerError::Guard("multiple open owned dispatch PRs"));
            }
            selected = Some(pr.clone());
        }
    }
    Ok(selected)
}

fn linked_prs(root: &Path, issue: u64, state: &str) -> Result<Vec<Value>, ScalerError> {
    let mut result = Vec::new();
    for page in 1.. {
        let data = api(
            root,
            &format!("repos/{REPOSITORY}/pulls?state={state}&base=main&per_page=100&page={page}"),
        )?;
        let prs = data
            .as_array()
            .ok_or(ScalerError::Guard("invalid PR list"))?;
        result.extend(
            prs.iter()
                .filter(|pr| pr["head"]["ref"].as_str().and_then(dispatch_branch) == Some(issue))
                .cloned(),
        );
        if prs.len() < 100 {
            break;
        }
    }
    Ok(result)
}

pub(crate) fn dispatch_branch(branch: &str) -> Option<u64> {
    let (issue, run) = branch.strip_prefix("work/dispatch-")?.split_once('-')?;
    if run.is_empty() || !run.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    issue.parse::<u64>().ok().filter(|n| *n > 0)
}

/// Hosted guard (`admit == false`) and clone admission (`admit == true`):
/// resolve the event, validate it, and on the clone re-check the target PR
/// and persist the private admission the loop reads.
/// The chain job: dispatch the next round when the latest dispatch outcome
/// on the issue's threads is this run's own and [`verify_chain`] admits
/// it. The one write is the dispatch, whose only input is the outcome id.
fn chain(root: &Path, issue: u64) -> Result<(), ScalerError> {
    let run = std::env::var("GITHUB_RUN_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or(ScalerError::Guard("missing run id"))?;
    let chained = chain_next(
        issue,
        &run,
        &mut |endpoint| authenticated_api(root, endpoint),
        &mut |id| {
            gh(
                root,
                &[
                    "api",
                    "-X",
                    "POST",
                    &format!("repos/{REPOSITORY}/actions/workflows/dispatch-worker.yml/dispatches"),
                    "-f",
                    "ref=main",
                    "-f",
                    &format!("inputs[outcome]={id}"),
                ],
            )
            .map(drop)
        },
    )?;
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        use std::io::Write;
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "{}",
            chained.map_or_else(
                || "No Continuing outcome from this run: nothing to chain.".to_owned(),
                |url| format!("Chained the next round from {url}.")
            )
        )?;
    }
    Ok(())
}
/// [`chain`] over a transport: `Some(outcome url)` after exactly one
/// dispatch, `None` (no call) when the latest outcome is not this run's
/// Continuing one; a Continuing outcome the rule refuses is an error.
pub(crate) fn chain_next(
    issue: u64,
    run: &str,
    read: &mut Read<'_>,
    dispatch: &mut dyn FnMut(u64) -> Result<(), ScalerError>,
) -> Result<Option<String>, ScalerError> {
    let mut latest: Option<Value> = None;
    for thread in chain_threads(read, issue)? {
        for comment in read_pages(
            read,
            &format!("repos/{REPOSITORY}/issues/{thread}/comments"),
        )? {
            let key = |c: &Value| {
                (
                    c["created_at"].as_str().map(str::to_owned),
                    c["id"].as_u64(),
                )
            };
            if dispatch_outcome_author(&comment["user"])
                && comment["body"]
                    .as_str()
                    .and_then(agent_loop::outcome_status)
                    .is_some()
                && latest.as_ref().is_none_or(|l| key(&comment) > key(l))
            {
                latest = Some(comment);
            }
        }
    }
    let Some(latest) = latest else {
        return Ok(None);
    };
    let body = latest["body"].as_str().unwrap_or_default();
    if agent_loop::outcome_status(body) != Some("Continuing")
        || agent_loop::run_from_body(body) != Some(run)
    {
        return Ok(None);
    }
    let id = latest["id"]
        .as_u64()
        .ok_or(ScalerError::Guard("outcome id"))?;
    let link = verify_chain(id, read)?;
    if link.issue != issue {
        return Err(ScalerError::Guard("chain outcome belongs to another issue"));
    }
    dispatch(id)?;
    Ok(Some(link.facts.from))
}

/// A label trigger with the `labeled` event's URL, read from the issue
/// timeline, so its outcome names a `Round trigger:` a chain can be rooted
/// in (#1241 part 3). Best effort: without it the round runs, unchainable.
fn label_trigger(root: &Path, mut event: Value) -> Value {
    if event.get("label").is_none()
        || event.get("comment").is_some()
        || event.get("review").is_some()
    {
        return event;
    }
    let issue = event["issue"]["number"].as_u64().unwrap_or_default();
    let found = read_pages(
        &mut |endpoint| authenticated_api(root, endpoint),
        &format!("repos/{REPOSITORY}/issues/{issue}/timeline"),
    )
    .ok()
    .and_then(|events| {
        events.into_iter().rev().find(|e| {
            e["event"] == "labeled"
                && e["label"]["name"] == event["label"]["name"]
                && e["actor"]["login"] == event["sender"]["login"]
        })
    });
    if let Some(item) = found.and_then(|e| round_inbox::label_item(issue, &e)) {
        event["label"]["html_url"] = item["html_url"].clone();
    }
    event
}

fn guard_admission(
    root: &Path,
    event_path: &Path,
    admit: bool,
    retire_previous_agent: impl FnOnce() -> Result<(), ScalerError>,
) -> Result<(Value, Dispatch), ScalerError> {
    // Both guard phases hold the job token (the endpoint answers 401
    // without one); the live permission read fails closed.
    let mut trusted = collaborators(|endpoint| authenticated_api(root, endpoint));
    let (event, adoption, chain) = load_event(root, event_path, &mut trusted)?;
    let publication = if adoption.is_none() && publish_app_author(&event["pull_request"]["user"]) {
        let branch = event["pull_request"]["head"]["ref"]
            .as_str()
            .unwrap_or_default();
        let issue = event["issue"]["number"].as_u64().unwrap_or_default();
        agent_loop::RunCache::for_guard(admit).publication(
            root,
            &event["pull_request"],
            &event["dispatch_run"],
            issue,
            branch,
        )
    } else {
        None
    };
    let mut dispatch = validate_event_with_publication(
        &event,
        &std::env::var("GITHUB_TRIGGERING_ACTOR").unwrap_or_default(),
        &mut trusted,
        publication.as_ref(),
        adoption.as_ref(),
        chain.as_ref(),
    )?;
    dispatch.base =
        admitted_base(dispatch.review || event.get("comment").is_some() || chain.is_some())?;
    if admit {
        retire_previous_agent()?;
    }
    assigned_branch(&mut dispatch)?;
    if dispatch.continuation == Continuation::Owned {
        branch_run(dispatch.issue, &dispatch.branch)?;
    }
    if admit {
        if dispatch.resume {
            require_target_pr(root, &dispatch)?;
        }
        persist_admission(
            &dispatch,
            &label_trigger(root, event.clone()),
            event_path,
            chain.as_ref(),
        )?;
    }
    Ok((event, dispatch))
}

pub fn run(root: &Path, args: DispatchArgs) -> Result<(), ScalerError> {
    let args = match args.action {
        DispatchAction::Reactor { mode } => return reactor::run(root, mode),
        action => DispatchArgs { action },
    };
    if let DispatchAction::Tool { name } = &args.action {
        return agent_loop::client(name);
    }
    if matches!(&args.action, DispatchAction::Guard { retire: true, .. }) {
        if ["GH_TOKEN", "GITHUB_TOKEN"]
            .iter()
            .any(|key| std::env::var_os(key).is_some())
        {
            return Err(ScalerError::Guard("agent phase received a job token"));
        }
        return cleanup_dispatch_users();
    }
    let root = root.canonicalize()?;
    let (event_path, admit) = match args.action {
        DispatchAction::Chain { issue } => return chain(&root, issue),
        DispatchAction::Tool { .. } | DispatchAction::Reactor { .. } => {
            return Err(ScalerError::Guard("action already handled"));
        }
        DispatchAction::Loop {
            event,
            setup_status,
        } => return agent_loop::run(&root, &event, &setup_status),
        DispatchAction::Guard { event, admit, .. } => (event, admit),
    };
    let (event, dispatch) = guard_admission(&root, &event_path, admit, cleanup_agent_user)?;
    // `/agent stop` acts only on a running round, whose mailbox reads it
    // (#1241); it never starts or queues a round of its own.
    if event["comment"]["body"]
        .as_str()
        .is_some_and(|b| b.trim() == round_inbox::STOP)
    {
        return Err(ScalerError::Guard(
            "`/agent stop` stops a running round through its mailbox; it never starts one",
        ));
    }
    if let Some(path) = std::env::var_os("GITHUB_OUTPUT") {
        use std::io::Write;
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "base={}\nhead={}\nissue={}\ncomment={}\nchain={}",
            dispatch.base,
            event["pull_request"]["head"]["sha"]
                .as_str()
                .unwrap_or_default(),
            dispatch.issue,
            comment_digest(&event["comment"]),
            event["chain"]["id"]
                .as_u64()
                .map(|id| id.to_string())
                .unwrap_or_default()
        )?;
    }
    Ok(())
}

use crate::safe_copy::Links as TreeLinks;
fn copy_tree(
    source: &Path,
    target: &Path,
    count: &mut usize,
    links: TreeLinks,
) -> Result<(), ScalerError> {
    Ok(crate::safe_copy::tree(source, target, count, links)?)
}
fn snapshot(source: &Path, target: &Path, branch: &str) -> Result<(), ScalerError> {
    crate::safe_copy::repository(
        source,
        target,
        branch,
        COMMAND_DEADLINE.with(std::cell::Cell::get),
    )
}

fn seal_runner(root: &Path) -> Result<(), ScalerError> {
    let temporary =
        PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or(ScalerError::Guard("runner temp"))?);
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Clone only reconstructed data. A later worker starts at its predecessor's
/// commits, preserving the first fetched remote tip as publication authority.
fn worker_checkout(
    root: &Path,
    previous_work: &Path,
    target: &Path,
    dispatch: &Dispatch,
    previous: Option<&Receipt>,
) -> Result<String, ScalerError> {
    let source = if previous.is_some() {
        previous_work
    } else {
        root
    };
    let parent = target
        .parent()
        .ok_or(ScalerError::Guard("worker target parent"))?;
    git(
        parent,
        &[
            "clone",
            "--no-local",
            "--no-hardlinks",
            "--no-checkout",
            source.to_str().ok_or(ScalerError::Guard("worker source"))?,
            "work",
        ],
    )?;
    git(
        target,
        &[
            "fetch",
            "--no-tags",
            root.to_str()
                .ok_or(ScalerError::Guard("main checkout path"))?,
            &format!("{}:refs/carrick/dispatch-main", dispatch.base),
        ],
    )?;
    if previous.is_some() || dispatch.resume {
        let reference = format!("origin/{}", dispatch.branch);
        let tip = git(target, &["rev-parse", &reference])?.trim().to_owned();
        if previous.is_none()
            && dispatch
                .selected_tip
                .as_ref()
                .is_some_and(|expected| *expected != tip)
        {
            return Err(ScalerError::Guard(
                "selected branch moved before worker admission",
            ));
        }
        git(target, &["checkout", "-B", &dispatch.branch, &reference])?;
        if let Some(previous) = previous {
            return Ok(previous.expected_tip.clone());
        }
        Ok(tip)
    } else {
        git(
            target,
            &["checkout", "-B", &dispatch.branch, &dispatch.base],
        )?;
        Ok(String::new())
    }
}

fn prepare_worker_actor(state: &Path, actor: &Path, backend: &str) -> Result<(), ScalerError> {
    let credential = match backend {
        "codex" => ".codex",
        "agy" => ".gemini",
        _ => return Err(ScalerError::Guard("worker credential backend refused")),
    };
    std::fs::create_dir(actor.join("home"))?;
    std::fs::set_permissions(actor.join("home"), std::fs::Permissions::from_mode(0o700))?;
    copy_tree(
        &state.join("home").join(credential),
        &actor.join("home").join(credential),
        &mut 0,
        TreeLinks::Preserve,
    )?;
    for name in ["bin", "director"] {
        copy_tree(
            &state.join(name),
            &actor.join(name),
            &mut 0,
            TreeLinks::Preserve,
        )?;
    }
    Ok(())
}
struct HarvestedWorker {
    contract: Contract,
    checkpointed: bool,
    diffstat: String,
    exit_code: i32,
}

/// Read candidate data only after the caller has verified uid retirement.
fn harvest_worker(
    actor: &Path,
    work: &Path,
    dispatch: &Dispatch,
    result: Result<i32, ScalerError>,
) -> Result<HarvestedWorker, ScalerError> {
    if work.exists() {
        std::fs::remove_dir_all(work)?;
    }
    timed_phase("worker.snapshot", || {
        snapshot(&actor.join("work"), work, &dispatch.branch)
    })?;
    let (mut contract, _) = timed_phase("worker.read_result", || {
        Ok(read_result(&actor.join("result.json")))
    })?;
    let code = match result {
        Ok(124) => {
            contract.status = ContractStatus::Failed;
            contract
                .summary
                .push_str("\nWorker timed out; partial work harvested for continuation");
            124
        }
        Ok(code) => {
            if code != 0 {
                contract.status = ContractStatus::Failed;
                contract
                    .risks
                    .push(format!("Worker launcher exited with code {code}"));
            }
            code
        }
        Err(error) => {
            contract.status = ContractStatus::Failed;
            contract.summary = format!("Worker failed: {error}");
            1
        }
    };
    let checkpointed = timed_phase("worker.checkpoint", || checkpoint(work, dispatch))?;
    if checkpointed {
        contract.status = ContractStatus::Failed;
        contract
            .risks
            .push("Workflow checkpointed unfinished changes".into());
    }
    let diffstat = git(work, &["diff", "--stat", &dispatch.base, "HEAD"])?;
    Ok(HarvestedWorker {
        contract,
        checkpointed,
        diffstat,
        exit_code: code,
    })
}

trait WorkerHost {
    fn initialize(&mut self) -> Result<(), ScalerError>;
    fn prepare(&mut self, state: &Path, actor: &Path, backend: &str) -> Result<(), ScalerError>;
    // A host may shorten the foreground deadline, never extend admission.
    fn agent_deadline(&self, allotted: std::time::Instant) -> std::time::Instant {
        allotted
    }
    fn agent(&mut self, root: &Path, dispatch: &Dispatch) -> Result<i32, ScalerError>;
    fn retire(&mut self) -> Result<(), ScalerError>;
    fn hand_back(&mut self, actor: &Path) -> Result<(), ScalerError>;
}
struct NativeWorkerHost;
impl WorkerHost for NativeWorkerHost {
    fn initialize(&mut self) -> Result<(), ScalerError> {
        #[cfg(target_os = "linux")]
        // SAFETY: adopt and reap detached children before scanning agent bytes.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let identity = output(Command::new("/usr/bin/id").args(["-u", AGENT_USER]))?;
        let uid = String::from_utf8_lossy(&identity)
            .trim()
            .parse::<libc::uid_t>()
            .map_err(|_| ScalerError::Guard("invalid pre-created agent uid"))?;
        // SAFETY: geteuid has no preconditions.
        if uid == 0 || uid == unsafe { libc::geteuid() } {
            return Err(ScalerError::Guard(
                "agent uid must be separate and unprivileged",
            ));
        }
        cleanup_agent_user()?;
        Ok(())
    }
    fn prepare(&mut self, state: &Path, actor: &Path, backend: &str) -> Result<(), ScalerError> {
        prepare_worker_actor(state, actor, backend)
    }
    fn agent(&mut self, root: &Path, dispatch: &Dispatch) -> Result<i32, ScalerError> {
        agent(root, dispatch)
    }
    fn retire(&mut self) -> Result<(), ScalerError> {
        cleanup_agent_user()
    }
    fn hand_back(&mut self, actor: &Path) -> Result<(), ScalerError> {
        let actor_path = actor.to_str().ok_or(ScalerError::Guard("agent state"))?;
        sudo(&["/usr/bin/chgrp", "-hR", AGENT_USER, actor_path])?;
        sudo(&["/usr/bin/chmod", "-R", "ug+rwX,o-rwx", actor_path])?;
        Ok(())
    }
}
fn produce(
    root: &Path,
    dispatch: &Dispatch,
    setup: &str,
    host: &mut dyn WorkerHost,
) -> Result<(), ScalerError> {
    let base = dispatch.base.clone();
    if !sha(&base)
        || (setup == "success/success" && git(root, &["rev-parse", "HEAD"])?.trim() != base)
    {
        return Err(ScalerError::Guard("checkout differs from admitted SHA"));
    }
    let state = crate::agent_runner::state()?;
    std::fs::create_dir_all(&state)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
    seal_runner(root)?;
    let work = state.join("work");
    let package =
        PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or(ScalerError::Guard("runner temp"))?)
            .join("dispatch-output");
    std::fs::create_dir_all(&package)?;
    std::fs::set_permissions(&package, std::fs::Permissions::from_mode(0o700))?;
    let mut contract = Contract {
        loop_summary: None,
        status: ContractStatus::Failed,
        summary: format!("Worker setup did not complete: {setup}"),
        tests: vec![],
        risks: vec![],
    };
    let mut code = 1;
    let previous = worker_checkpoint(&state, dispatch)?;
    let mut expected_tip = previous
        .as_ref()
        .map(|receipt| receipt.expected_tip.clone())
        .unwrap_or_default();
    let mut candidate = None;
    let mut checkpointed = false;
    let mut proposed_body = None;
    let mut raw = if package.join("raw.log").is_file() {
        regular_text(&package.join("raw.log"))?
    } else {
        String::new()
    };
    let mut diffstat = String::new();
    if setup == "success/success" {
        let preparation_commands = dispatch.loop_deadline.map(CommandWindow::until);
        host.initialize()?;
        let outer = tempfile::Builder::new()
            .prefix("carrick-dispatch-")
            .tempdir_in("/var/tmp")?;
        std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o711))?;
        let actor = outer.path().join("agent");
        std::fs::create_dir(&actor)?;
        std::fs::set_permissions(&actor, std::fs::Permissions::from_mode(0o700))?;
        timed_phase("worker.prepare", || {
            host.prepare(&state, &actor, &dispatch.worker.backend)
        })?;
        let actor_work = actor.join("work");
        expected_tip = timed_phase("worker.checkout", || {
            worker_checkout(root, &work, &actor_work, dispatch, previous.as_ref())
        })?;
        git(&actor_work, &["config", "user.name", "github-actions[bot]"])?;
        git(
            &actor_work,
            &[
                "config",
                "user.email",
                "41898282+github-actions[bot]@users.noreply.github.com",
            ],
        )?;
        drop(preparation_commands);
        let mut agent_dispatch = dispatch.clone();
        if let Some(body) = previous
            .as_ref()
            .and_then(|receipt| receipt.pr_body.as_ref())
        {
            agent_dispatch.body.push_str(&format!(
                "\n## Earlier PR body proposal (untrusted worker claims)\nThe server retains this proposal if you write no pr-body.md. Write that file to revise it.\n```json\n{}\n```\n",
                serde_json::to_string(&agent_loop::masked(body, &std::env::var("GH_TOKEN").unwrap_or_default()))?
            ));
        }
        agent_dispatch.loop_deadline = dispatch
            .loop_deadline
            .map(|allotted| host.agent_deadline(allotted).min(allotted));
        let commands = agent_dispatch.loop_deadline.map(CommandWindow::until);
        let result = timed_phase("worker.agent", || host.agent(&actor_work, &agent_dispatch));
        drop(commands);
        // Dropping the agent window restores NativeLauncher's harvest window.
        // This is mandatory even on launcher failure, before scanning or hand-back.
        timed_phase("worker.retirement", || host.retire())?;
        // Read agent files only as data after verified uid retirement. The
        // pre-created private group lets runner read without becoming root.
        timed_phase("worker.hand_back", || host.hand_back(&actor))?;
        let (_, evidence) = read_result(&actor.join("result.json"));
        record_worker_session(&actor.join("runtime/dispatch/worker.log"), &package)?;
        let prior_raw = std::mem::take(&mut raw);
        raw.push_str(&evidence);
        for name in ["runtime/dispatch/worker.log", "runtime/dispatch/worker.err"] {
            raw.push_str(&format!("=== {name} ===\n"));
            raw.push_str(
                &diagnostic_text(&actor.join(name))
                    .unwrap_or_else(|e| format!("unavailable: {e}\n")),
            );
        }
        for name in ["agent.out", "agent.err"] {
            raw.push_str(&format!("=== {name} ===\n"));
            raw.push_str(
                &diagnostic_text(&state.join(name))
                    .unwrap_or_else(|e| format!("unavailable: {e}\n")),
            );
        }
        raw.push_str("=== Earlier worker evidence ===\n");
        raw.push_str(&prior_raw);
        // Retain bounded foreground evidence even if snapshot/checkpoint fails.
        raw = clip_diagnostic(
            crate::dispatch_redaction::redact(raw.as_bytes()),
            TRANSCRIPT_BYTES,
        );
        std::fs::write(package.join("raw.log"), &raw)?;
        let staging = tempfile::Builder::new()
            .prefix("harvest-")
            .tempdir_in(&state)?;
        let harvested = timed_phase("worker.harvest", || {
            harvest_worker(&actor, &staging.path().join("candidate"), dispatch, result)
        })?;
        contract = harvested.contract;
        diffstat = harvested.diffstat;
        code = harvested.exit_code;
        checkpointed = harvested.checkpointed;
        proposed_body = read_pr_body(&actor)?.or_else(|| {
            previous
                .as_ref()
                .and_then(|receipt| receipt.pr_body.clone())
        });
        candidate = Some(staging);
    }
    std::fs::write(package.join("raw.log"), &raw)?;
    let transcript = format!(
        "# Dispatch issue {}\n\n{}\n\nTests (agent claims):\n{}\n\nRisks:\n{}\n",
        dispatch.issue,
        contract.summary,
        contract.tests.join("\n"),
        contract.risks.join("\n")
    );
    let rendered_log = raw
        .lines()
        .map(|line| format!("    {line}\n"))
        .collect::<String>();
    std::fs::write(
        package.join("transcript.md"),
        clip_diagnostic(
            crate::dispatch_redaction::redact(
                format!("{transcript}\n## Agent transcript\n\n{rendered_log}").as_bytes(),
            ),
            TRANSCRIPT_BYTES,
        ),
    )?;
    std::fs::write(
        package.join("contract.json"),
        serde_json::to_vec_pretty(&contract)?,
    )?;
    std::fs::write(package.join("diffstat.txt"), diffstat)?;
    // This receipt stays on the disposable runner; it is not uploaded.
    if let Some(candidate) = candidate {
        let head = git(&candidate.path().join("candidate"), &["rev-parse", "HEAD"])?
            .trim()
            .to_owned();
        let checkpointed = checkpointed
            || previous
                .as_ref()
                .is_some_and(|receipt| receipt.head == head && receipt.checkpointed);
        install_worker_checkpoint(
            &state,
            &candidate.path().join("candidate"),
            &Receipt {
                head,
                checkpointed,
                base,
                branch: dispatch.branch.clone(),
                exit_code: code,
                expected_tip,
                pr_body: proposed_body,
                worker: dispatch.worker.clone(),
                contract: contract.clone(),
            },
        )?;
    }
    // Mirror only the installed checkpoint proposal into the upload population.
    if let Some(receipt) = worker_checkpoint(&state, dispatch)? {
        if let Some(body) = receipt.pr_body {
            std::fs::write(package.join("pr-body.md"), body)?;
        } else if package.join("pr-body.md").exists() {
            std::fs::remove_file(package.join("pr-body.md"))?;
        }
    }
    Ok(())
}

/// The push lease of one run. It starts at the tip admitted for the run and
/// advances to each tip this run pushed, so a later push in the same run (a
/// WIP checkpoint, then the final push) is still a lease, never a force.
/// `published-tip` is server-owned run state; worker output never writes it.
struct RunLease {
    admitted: String,
    pushed: Option<String>,
}
impl RunLease {
    #[cfg(test)]
    fn admitted(tip: &str) -> Self {
        Self {
            admitted: tip.to_owned(),
            pushed: None,
        }
    }
    fn load(state: &Path, admitted: &str) -> Result<Self, ScalerError> {
        let path = state.join("published-tip");
        let pushed = if path.exists() {
            let tip = regular_text(&path)?.trim().to_owned();
            if !sha(&tip) {
                return Err(ScalerError::Guard("invalid published tip"));
            }
            Some(tip)
        } else {
            None
        };
        Ok(Self {
            admitted: admitted.to_owned(),
            pushed,
        })
    }
    fn current(&self) -> &str {
        self.pushed.as_deref().unwrap_or(&self.admitted)
    }
}

/// The destination is derived from the admitted event, never from agent output.
fn push_command(
    root: &Path,
    dispatch: &Dispatch,
    id: &str,
    lease: &RunLease,
) -> Result<Command, ScalerError> {
    let expected = lease.current();
    let branch = match &dispatch.continuation {
        Continuation::Owned => {
            let branch = format!("work/dispatch-{}-{id}", dispatch.issue);
            branch_run(dispatch.issue, &branch)?;
            branch
        }
        // The adopted ref and its lease come only from the admitted type.
        Continuation::Adopted { branch, tip, .. } => {
            if !valid_branch(branch) || dispatch_branch(branch).is_some() {
                return Err(ScalerError::Guard("invalid adopted branch"));
            }
            if lease.admitted != *tip {
                return Err(ScalerError::Guard(
                    "adopted push lease must start at the admitted PR tip",
                ));
            }
            branch.clone()
        }
    };
    if dispatch.branch != branch
        || git(root, &["symbolic-ref", "--short", "HEAD"])?.trim() != branch
    {
        return Err(ScalerError::Guard(
            "refusing push outside the assigned run branch",
        ));
    }
    if !expected.is_empty() && !sha(expected) {
        return Err(ScalerError::Guard("invalid expected branch tip"));
    }
    Ok(git_invocation(
        root,
        &[
            "-c",
            "credential.helper=!gh auth git-credential",
            "push",
            "--no-follow-tags",
            "--recurse-submodules=no",
            &format!("--force-with-lease=refs/heads/{branch}:{expected}"),
            "https://github.com/carrick-sh/carrick",
            &format!("HEAD:refs/heads/{branch}"),
        ],
    ))
}

#[cfg(test)]
std::thread_local! {
    static LAST_SCANNED_ARTIFACTS: std::cell::RefCell<std::collections::BTreeMap<String, Vec<u8>>> = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}
/// Mask exact job-token bytes, then scan the complete upload population.
fn mask_artifacts(package: &Path, token: &str) -> Result<(), ScalerError> {
    if token.is_empty() {
        return Err(ScalerError::Guard("missing job token"));
    }
    let mut names = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(package)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(ScalerError::Guard("invalid artifact name"))?;
        if ![
            "raw.log",
            "transcript.md",
            "contract.json",
            "diffstat.txt",
            "handoff.json",
            "loop.log",
            "loop-transcript.log",
            "pr-body.md",
            HARVEST_PATCH,
        ]
        .contains(&name)
            && !worker_session_name(name)
        {
            return Err(ScalerError::Guard("unexpected dispatch artifact"));
        }
        let text = regular_text(&entry.path())?;
        let mask = |text: &str| agent_loop::masked(text, token);
        let masked = if name == "contract.json" {
            let mut contract: Contract = serde_json::from_str(&text)?;
            contract.summary = mask(&contract.summary);
            contract.loop_summary = contract.loop_summary.as_deref().map(mask);
            contract.tests = contract.tests.iter().map(|s| mask(s)).collect();
            contract.risks = contract.risks.iter().map(|s| mask(s)).collect();
            serde_json::to_string_pretty(&contract)?
        } else if name == "handoff.json" || name == "loop-transcript.log" {
            fn redact(value: &mut Value, mask: &impl Fn(&str) -> String) {
                match value {
                    Value::String(s) => *s = mask(s),
                    Value::Array(a) => {
                        for v in a {
                            redact(v, mask);
                        }
                    }
                    Value::Object(o) => {
                        for v in o.values_mut() {
                            redact(v, mask);
                        }
                    }
                    _ => {}
                }
            }
            let mut value: Value = serde_json::from_str(&text)?;
            redact(&mut value, &mask);
            if name == "loop-transcript.log" {
                bounded_transcript(value)?
            } else {
                serde_json::to_string_pretty(&value)?
            }
        } else {
            mask(&text)
        };
        let masked = match name {
            "loop.log" => clip_diagnostic(masked, LOOP_LOG_BYTES),
            "raw.log" | "transcript.md" => clip_diagnostic(masked, TRANSCRIPT_BYTES),
            _ => masked,
        };
        std::fs::write(entry.path(), masked)?;
        names.insert(name.to_owned());
    }
    if !["raw.log", "transcript.md", "contract.json", "diffstat.txt"]
        .iter()
        .all(|name| names.contains(*name))
    {
        return Err(ScalerError::Guard("incomplete dispatch artifacts"));
    }
    for name in &names {
        let text = regular_text(&package.join(name))?;
        if text.contains(token) {
            return Err(ScalerError::Guard("job token found in upload"));
        }
        crate::dispatch_redaction::DiagnosticSecrets::capture()?.check(text.as_bytes())?;
    }
    #[cfg(test)]
    LAST_SCANNED_ARTIFACTS.with(|scanned| {
        *scanned.borrow_mut() = names
            .iter()
            .map(|name| Ok((name.clone(), std::fs::read(package.join(name))?)))
            .collect::<Result<_, std::io::Error>>()?;
        Ok::<_, std::io::Error>(())
    })?;
    Ok(())
}

#[derive(Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AppliedBody {
    #[default]
    NotUpdated,
    Created,
    Updated,
    Refused {
        reason: String,
        template_created: bool,
    },
    Failed(String),
}
/// Runner-owned evidence of successful side effects, including partial publication.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Applied {
    commits: Vec<String>,
    #[serde(default)]
    new_commits: Vec<String>,
    #[serde(default)]
    published_checkpoint: bool,
    #[serde(default)]
    rebased_onto: Option<String>,
    /// Director commits whose patch changed in a consented rebase (#1215).
    #[serde(default)]
    rebase_changed: Vec<String>,
    /// The rebased counterpart of the admitted tip; the run's own commits
    /// start above it.
    #[serde(default)]
    rebase_tip: Option<String>,
    /// `git range-diff -s` of the director's commits across the rebase.
    #[serde(default)]
    rebase_range_diff: Option<String>,
    body: AppliedBody,
    board_changes: Vec<String>,
    #[serde(default)]
    board_left: Vec<String>,
    #[serde(default)]
    publication_pr: Option<u64>,
    #[serde(default)]
    manual_repair: Option<String>,
    #[serde(default)]
    ci_requires_owner: bool,
    #[serde(default)]
    token_fallback: Option<TokenFallback>,
    /// An adopted PR moved or its history was rewritten; the round ends blocked.
    #[serde(default)]
    adoption_blocked: Option<String>,
    /// The last tip the server pushed as a WIP checkpoint after a worker.
    #[serde(default)]
    wip_pushed: Option<String>,
    /// How that worker's launcher ended, from the server's receipt (#1253).
    #[serde(default)]
    wip_exit: Option<LauncherExit>,
    /// Workflow files a WIP checkpoint left out, because dispatch can't
    /// publish `.github/workflows/*` (#1241); the owner publishes them.
    #[serde(default)]
    workflow_left_out: Vec<String>,
}
impl Applied {
    fn load() -> Result<Self, ScalerError> {
        let path = crate::agent_runner::state()?.join("applied.json");
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
            Ok(_) => Ok(serde_json::from_str(&regular_text(&path)?)?),
        }
    }
    fn record(update: impl FnOnce(&mut Self)) -> Result<(), ScalerError> {
        let mut applied = Self::load()?;
        update(&mut applied);
        std::fs::write(
            crate::agent_runner::state()?.join("applied.json"),
            serde_json::to_vec(&applied)?,
        )?;
        Ok(())
    }
    fn report(&self) -> String {
        format!(
            "{}{}- PR commits: {}.{}\n- PR body: {}.\n- Board status: {}.{}",
            self.adoption_blocked
                .as_ref()
                .map(|reason| format!("- Push refused: {reason}.\n"))
                .unwrap_or_default(),
            self.wip_pushed
                .as_ref()
                .map(|tip| {
                    let left = if self.workflow_left_out.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " It leaves out the run's workflow changes ({}), which dispatch can't publish: the owner publishes them from `{HARVEST_PATCH}`",
                            self.workflow_left_out
                                .iter()
                                .map(|p| p.escape_debug().to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    };
                    format!("- Pushed WIP at `{tip}`.{left}\n")
                })
                .unwrap_or_default(),
            if self.commits.is_empty() {
                "none".into()
            } else {
                self.commits
                    .iter()
                    .map(|s| {
                        let short = s.chars().take(12).collect::<String>();
                        if self.new_commits.contains(s) {
                            format!("{short} (new in this run)")
                        } else {
                            short
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            self.rebased_onto
                .as_ref()
                .map(|base| {
                    let changed = if self.rebase_changed.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " Director commits whose patch changed while rebasing (review these): {}.",
                            self.rebase_changed.join(", ")
                        )
                    };
                    let range = self
                        .rebase_range_diff
                        .as_ref()
                        .filter(|r| !r.is_empty())
                        .map(|r| format!("\n\n<details><summary>Director commits before and after the rebase</summary>\n\n```\n{r}\n```\n</details>"))
                        .unwrap_or_default();
                    format!("\n- Rebased onto main at {base}.{changed}{range}")
                })
                .unwrap_or_default(),
            match &self.body {
                AppliedBody::NotUpdated => "not updated".into(),
                AppliedBody::Created => "created".into(),
                AppliedBody::Updated => "updated".into(),
                AppliedBody::Refused {
                    reason,
                    template_created,
                } => format!(
                    "refused ({reason}){}",
                    if *template_created {
                        "; default template created"
                    } else {
                        ""
                    }
                ),
                AppliedBody::Failed(reason) => format!("failed ({reason})"),
            },
            if self.board_changes.is_empty() && self.board_left.is_empty() {
                "not changed".into()
            } else {
                self.board_changes
                    .iter()
                    .chain(&self.board_left)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            if self.ci_requires_owner {
                let why = self
                    .token_fallback
                    .as_ref()
                    .map_or_else(|| "reason not recorded".into(), TokenFallback::describe);
                format!(
                    "\n- CI won't start automatically: publication used the job token ({why}); mark the PR ready to start CI."
                )
            } else {
                String::new()
            }
        )
    }
}
/// Remove template instructions before publishing prose for people to read.
fn body_without_comments(text: &str) -> Result<String, ScalerError> {
    let mut body = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("<!--") {
        body.push_str(&rest[..start]);
        rest = rest[start + 4..]
            .split_once("-->")
            .ok_or(ScalerError::Guard("unterminated PR body comment"))?
            .1;
    }
    body.push_str(rest);
    Ok(body)
}
fn closing_target(reference: &str) -> bool {
    let lower = reference.to_ascii_lowercase();
    reference.contains('#')
        || lower.contains("https://github.com/")
        || lower.contains("www.github.com/")
        || ["github.com", "http://", "gh-"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
}
/// Share the conservative keyword/target filter between prose and commits.
/// Include further references on the same line, so a list cannot smuggle a
/// second issue after an otherwise permitted local reference.
fn closing_targets(text: &str) -> Vec<&str> {
    let lower = text.to_ascii_lowercase();
    let mut targets = Vec::new();
    for keyword in [
        "close", "closes", "closed", "fix", "fixes", "fixed", "resolve", "resolves", "resolved",
    ] {
        for (start, _) in lower.match_indices(keyword) {
            let end = start + keyword.len();
            if text[..start].ends_with(|c: char| c.is_ascii_alphabetic())
                || text[end..].starts_with(|c: char| c.is_ascii_alphabetic())
            {
                continue;
            }
            let rest = text[end..]
                .trim_start_matches(|c: char| c.is_whitespace() || ":*_`[('\"".contains(c));
            let line = rest.lines().next().unwrap_or_default();
            let mut words = line.split_whitespace();
            if let Some(first) = words.next().filter(|reference| closing_target(reference)) {
                targets.push(first);
                targets.extend(words.filter(|reference| closing_target(reference)));
            }
        }
    }
    targets
}
fn closing_reference(text: &str) -> bool {
    !closing_targets(text).is_empty()
}
fn check_commit_closures(
    work: &Path,
    base: &str,
    published_tip: Option<&str>,
    issue: u64,
) -> Result<(), ScalerError> {
    let range = format!("{base}..HEAD");
    let mut args = vec!["log", "--format=%H%x00%B%x00", &range];
    if let Some(tip) = published_tip {
        args.extend(["--not", tip]);
    }
    let log = git(work, &args)?;
    let mut fields = log.split('\0');
    while let Some(commit) = fields.next().map(str::trim).filter(|s| !s.is_empty()) {
        if !sha(commit) {
            return Err(ScalerError::Guard("invalid publication commit id"));
        }
        let message = fields
            .next()
            .ok_or(ScalerError::Guard("missing publication commit message"))?;
        let allowed = [
            format!("#{issue}"),
            format!("{REPOSITORY}#{issue}"),
            format!("https://github.com/{REPOSITORY}/issues/{issue}"),
        ];
        if closing_targets(message).iter().any(|target| {
            let target = target.trim_end_matches(|c: char| ",.;:)]>\"'`".contains(c));
            !allowed.iter().any(|own| target.eq_ignore_ascii_case(own))
        }) {
            return Err(ScalerError::Usage(format!(
                "Refused commit {commit}: closing keyword targets another issue or repository; only {REPOSITORY}#{issue} is allowed"
            )));
        }
    }
    Ok(())
}
fn read_pr_body(directory: &Path) -> Result<Option<String>, ScalerError> {
    let path = directory.join("pr-body.md");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    Ok(Some(crate::safe_copy::text(&path, 8192)?))
}
fn proposed_pr_body(
    proposal: Option<&str>,
    issue: u64,
    id: &str,
    token: &str,
) -> Result<Option<String>, ScalerError> {
    let Some(text) = proposal else {
        return Ok(None);
    };
    if text.len() > 8192 {
        return Err(ScalerError::Guard("PR body exceeds 8 KiB"));
    }
    if text.contains("Outcome contract:") || text.contains("Publication receipt:") {
        return Err(ScalerError::Guard(
            "PR body contains a reserved server report marker",
        ));
    }
    let canonical = format!("Closes #{issue}");
    let mut closing = false;
    let mut lines = Vec::new();
    for line in body_without_comments(text)?.lines() {
        if line.trim() == canonical && !closing {
            closing = true;
            continue;
        }
        if line.contains("Dispatch run:") || closing_reference(line) {
            return Err(ScalerError::Guard(
                "PR body contains an extra closing reference or dispatch footer",
            ));
        }
        lines.push(line.to_owned());
    }
    let text = lines.join("\n");
    if closing_reference(&text) {
        return Err(ScalerError::Guard(
            "PR body contains an extra closing reference",
        ));
    }
    Ok(Some(final_pr_body(&text, issue, id, token)))
}
/// Markdown treats bare carriage returns as line endings as well as LF/CRLF.
fn markdown_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}
/// Decode only the HTML references for @, including numeric forms with leading
/// zeroes or omitted semicolons. Other entities keep their original spelling.
fn decode_mention_entities(text: &str) -> String {
    let mut result = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        result.push_str(&rest[..at]);
        rest = &rest[at..];
        if rest.starts_with("&commat;") {
            result.push('@');
            rest = &rest[8..];
            continue;
        }
        if let Some(numeric) = rest.strip_prefix("&#") {
            let hex = numeric.starts_with(['x', 'X']);
            let digits = if hex { &numeric[1..] } else { numeric };
            let count = digits
                .bytes()
                .take_while(|b| {
                    if hex {
                        b.is_ascii_hexdigit()
                    } else {
                        b.is_ascii_digit()
                    }
                })
                .count();
            if count > 0
                && digits[..count]
                    .trim_start_matches('0')
                    .eq_ignore_ascii_case(if hex { "40" } else { "64" })
            {
                let consumed =
                    2 + usize::from(hex) + count + usize::from(digits[count..].starts_with(';'));
                result.push('@');
                rest = &rest[consumed..];
                continue;
            }
        }
        result.push('&');
        rest = &rest[1..];
    }
    result.push_str(rest);
    result
}
/// A word joiner breaks mentions even in raw HTML and code, where Markdown
/// backticks are not reliable. Alphanumeric prefixes identify addresses instead.
fn neutralize_mentions(text: &str) -> String {
    let text = decode_mention_entities(&markdown_newlines(text));
    let mut result = String::new();
    let mut previous = None;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        result.push(c);
        if c == '@'
            && previous.is_none_or(|p: char| !(p.is_ascii_alphanumeric() || p == '_'))
            && chars
                .peek()
                .is_some_and(|c| c.is_ascii_alphanumeric() || "-_/".contains(*c))
        {
            result.push('\u{2060}');
        }
        previous = Some(c);
    }
    result
}
fn final_pr_body(text: &str, issue: u64, id: &str, token: &str) -> String {
    format!(
        "{}\n\nCloses #{issue}\n\nDispatch run: https://github.com/{REPOSITORY}/actions/runs/{id}\n",
        neutralize_mentions(&agent_loop::masked(text, token)).trim()
    )
}
fn template_pr_body(
    contract: &Contract,
    issue: u64,
    id: &str,
    token: &str,
) -> Result<String, ScalerError> {
    let summary = if closing_reference(&contract.summary)
        || contract.summary.contains("Dispatch run:")
        || contract.summary.contains("Outcome contract:")
    {
        "Worker claims are available in the dispatch outcome.".to_owned()
    } else {
        contract.summary.chars().take(4_000).collect::<String>()
    };
    let template = include_str!("../../../.github/pull_request_template.md")
        .replace("Closes #\n", "")
        .replace(
            "<!-- Approach and any candid divergence from Linux. -->",
            &summary,
        )
        .replace("NEW: none / FIXED: none", "Not compared")
        .replace("NEW: / FIXED:", "Not compared")
        .replace("HEAD, SHA-256, CDHash", "Not collected");
    // Claims can contain closing syntax too; never promote them into linkage.
    let text = body_without_comments(&template)?
        .lines()
        .filter(|line| !closing_reference(line) && !line.contains("Dispatch run:"))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(final_pr_body(&text, issue, id, token))
}

fn patch_pr_body(
    root: &Path,
    number: u64,
    body: &str,
    credential: &mut PublishCredential<'_>,
) -> Result<(), ScalerError> {
    // Recovery may restore text written before mention protection was installed.
    let body = neutralize_mentions(&agent_loop::masked(body, credential.job));
    let path = crate::agent_runner::state()?.join("pr-body.md");
    std::fs::write(&path, body)?;
    credential.gh(
        root,
        &[
            "api",
            "-X",
            "PATCH",
            &format!("repos/{REPOSITORY}/pulls/{number}"),
            "-F",
            &format!("body=@{}", path.display()),
        ],
        PublishEvent::BodyPatch,
    )?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ClosingIssue {
    repository: String,
    number: u64,
}
type ClosingIssues = std::collections::BTreeSet<ClosingIssue>;
struct ClosingReferences {
    all: ClosingIssues,
    body: ClosingIssues,
}
fn issue_reference(issue: u64) -> ClosingIssue {
    ClosingIssue {
        repository: REPOSITORY.into(),
        number: issue,
    }
}
/// GitHub supplies the body-derived view, so manual sidebar links do not depend
/// on our approximation of GitHub's Markdown closing-keyword parser.
fn read_closing_references(root: &Path, number: u64) -> Result<ClosingReferences, ScalerError> {
    parse_closing_references(&closing_references_response(root, number)?)
}
pub(crate) const CLOSING_REFERENCES_QUERY: &str = r#"query($number:Int!){repository(owner:"carrick-sh",name:"carrick"){pullRequest(number:$number){closingIssuesReferences(first:100){nodes{number repository{nameWithOwner}} pageInfo{hasNextPage}} bodyReferences:closingIssuesReferences(first:100,excludeUserLinked:true){nodes{number repository{nameWithOwner}} pageInfo{hasNextPage}}}}}"#;
/// The controller sends the same query through its own POST transport.
pub(crate) fn closing_references_request(number: u64) -> Value {
    json!({"query":CLOSING_REFERENCES_QUERY,"variables":{"number":number}})
}
fn closing_references_response(root: &Path, number: u64) -> Result<Value, ScalerError> {
    let response = gh(
        root,
        &[
            "api",
            "graphql",
            "-f",
            &format!("query={CLOSING_REFERENCES_QUERY}"),
            "-F",
            &format!("number={number}"),
        ],
    )?;
    if response.len() > 64 * 1024 {
        return Err(ScalerError::Guard(
            "closing-reference response exceeds 64 KiB",
        ));
    }
    Ok(serde_json::from_str(&response)?)
}
fn parse_closing_references(value: &Value) -> Result<ClosingReferences, ScalerError> {
    if value.get("errors").is_some() {
        return Err(ScalerError::Guard(
            "closing-reference query returned errors",
        ));
    }
    let pr = &value["data"]["repository"]["pullRequest"];
    let parse = |connection: &Value| -> Result<ClosingIssues, ScalerError> {
        if connection["pageInfo"]["hasNextPage"] != false {
            return Err(ScalerError::Guard(
                "closing-reference connection unavailable or truncated",
            ));
        }
        connection["nodes"]
            .as_array()
            .ok_or(ScalerError::Guard("closing-reference nodes unavailable"))?
            .iter()
            .map(|node| {
                Ok(ClosingIssue {
                    number: node["number"]
                        .as_u64()
                        .filter(|n| *n > 0)
                        .ok_or(ScalerError::Guard("invalid closing issue number"))?,
                    repository: node["repository"]["nameWithOwner"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .ok_or(ScalerError::Guard("invalid closing issue repository"))?
                        .into(),
                })
            })
            .collect()
    };
    let references = ClosingReferences {
        all: parse(&pr["closingIssuesReferences"])?,
        body: parse(&pr["bodyReferences"])?,
    };
    if !references.body.is_subset(&references.all) {
        return Err(ScalerError::Guard("closing-reference views disagree"));
    }
    Ok(references)
}
/// Time and sleeping are injected so consistency tests never compare epochs
/// from separate processes, or spend real seconds waiting for a fake index.
trait ReferenceHost {
    fn now(&self) -> std::time::Instant;
    fn sleep(&mut self, delay: std::time::Duration);
    fn read(&mut self, root: &Path, number: u64) -> Result<ClosingReferences, ScalerError> {
        read_closing_references(root, number)
    }
}
#[cfg(not(test))]
struct SystemReferenceHost;
#[cfg(not(test))]
impl ReferenceHost for SystemReferenceHost {
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
    fn sleep(&mut self, delay: std::time::Duration) {
        std::thread::sleep(delay);
    }
}
#[cfg(not(test))]
fn reference_host() -> impl ReferenceHost {
    SystemReferenceHost
}
#[cfg(test)]
std::thread_local! {
    static REFERENCE_DELAYS: std::cell::RefCell<Vec<std::time::Duration>> = const { std::cell::RefCell::new(Vec::new()) };
    static REFERENCE_READ_TIMES: std::cell::RefCell<Vec<std::time::Duration>> = const { std::cell::RefCell::new(Vec::new()) };
}
#[cfg(test)]
struct TestReferenceHost {
    epoch: std::time::Instant,
    elapsed: std::time::Duration,
}
#[cfg(test)]
impl Default for TestReferenceHost {
    fn default() -> Self {
        Self {
            epoch: std::time::Instant::now(),
            elapsed: std::time::Duration::ZERO,
        }
    }
}
#[cfg(test)]
impl ReferenceHost for TestReferenceHost {
    fn now(&self) -> std::time::Instant {
        self.epoch + self.elapsed
    }
    fn sleep(&mut self, delay: std::time::Duration) {
        REFERENCE_DELAYS.with(|delays| delays.borrow_mut().push(delay));
        self.elapsed += delay;
    }
    fn read(&mut self, root: &Path, number: u64) -> Result<ClosingReferences, ScalerError> {
        REFERENCE_READ_TIMES.with(|times| times.borrow_mut().push(self.elapsed));
        read_closing_references(root, number)
    }
}
#[cfg(test)]
fn reference_host() -> impl ReferenceHost {
    TestReferenceHost::default()
}
fn primary_reference_deadline(deadline: std::time::Instant) -> std::time::Instant {
    deadline - std::time::Duration::from_secs(30)
}
#[derive(Debug)]
enum ReferenceFailure {
    Deadline,
    Read(String),
    Extra,
}
impl std::fmt::Display for ReferenceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deadline => f.write_str("closing references unverified (deadline): index did not settle within the publish command window"),
            Self::Read(reason) => write!(f, "closing references unverified: {reason}"),
            Self::Extra => f.write_str("closing references unverified: unexpected extra reference"),
        }
    }
}
struct ReferenceCheck<C> {
    clock: C,
    publish_deadline: std::time::Instant,
    recovery: bool,
}
impl<C: ReferenceHost> ReferenceCheck<C> {
    fn new(clock: C) -> Self {
        let publish_deadline = COMMAND_DEADLINE
            .with(|slot| slot.get())
            .unwrap_or_else(|| clock.now() + std::time::Duration::from_secs(120));
        Self {
            clock,
            publish_deadline,
            recovery: false,
        }
    }
    fn deadline(&self) -> std::time::Instant {
        if self.recovery {
            self.publish_deadline
        } else {
            primary_reference_deadline(self.publish_deadline)
        }
    }
    fn delay(
        &mut self,
        delay: std::time::Duration,
        deadline: std::time::Instant,
    ) -> Result<(), ReferenceFailure> {
        if deadline.saturating_duration_since(self.clock.now()) <= delay {
            return Err(ReferenceFailure::Deadline);
        }
        self.clock.sleep(delay);
        Ok(())
    }
    /// The index lags writes: delay three seconds, then require two matches
    /// two seconds apart. Each read gets one retry, within the same deadline.
    fn verify(
        &mut self,
        root: &Path,
        number: u64,
        expected: &ClosingIssues,
    ) -> Result<(), ReferenceFailure> {
        let deadline = self
            .deadline()
            .min(self.clock.now() + std::time::Duration::from_secs(20));
        let _window = CommandWindow::until(deadline);
        self.delay(std::time::Duration::from_secs(3), deadline)?;
        let mut matched = false;
        loop {
            let mut current = self.clock.read(root, number);
            if current.is_err() && self.clock.now() < deadline {
                current = self.clock.read(root, number);
            }
            let current = current.map_err(|e| {
                if self.clock.now() >= deadline {
                    ReferenceFailure::Deadline
                } else {
                    ReferenceFailure::Read(e.to_string())
                }
            })?;
            // An observed extra reference always wins over a simultaneous
            // deadline, so a known unsafe write is never kept as merely late.
            if !current.all.is_subset(expected) {
                return Err(ReferenceFailure::Extra);
            }
            if self.clock.now() >= deadline {
                return Err(ReferenceFailure::Deadline);
            }
            if current.all == *expected {
                if matched {
                    return Ok(());
                }
                matched = true;
            } else {
                matched = false;
            }
            self.delay(std::time::Duration::from_secs(2), deadline)?;
        }
    }
}
/// A deadline without an observed extra reference is not evidence of a bad
/// body. Keep locally validated prose and report the verification gap honestly.
fn keep_unverified_body(failure: &ReferenceFailure, token: &str) -> Result<String, ScalerError> {
    let reason = agent_loop::masked(
        &format!("{failure}; new body kept, not restored (no extra reference observed)"),
        token,
    );
    Applied::record(|a| a.body = AppliedBody::Failed(reason.clone()))?;
    Ok(reason)
}
/// Recovery is a body write too: verify it with the same consistency protocol.
/// Keep byte restoration and reference verification distinct in the report.
fn restore_pr_body(
    root: &Path,
    number: u64,
    replacement: (&str, &str),
    expected: &ClosingIssues,
    failure: &str,
    credential: &mut PublishCredential<'_>,
    check: &mut ReferenceCheck<impl ReferenceHost>,
) -> Result<String, ScalerError> {
    check.recovery = true;
    let _window = CommandWindow::until(check.deadline());
    let (body, label) = replacement;
    let (reason, manual) = match patch_pr_body(root, number, body, credential) {
        Err(error) => (
            format!("{failure}; {label} was not restored: {error}"),
            true,
        ),
        Ok(()) => match check.verify(root, number, expected) {
            Ok(()) => (format!("{failure}; {label} restored and verified"), false),
            Err(error) => (
                format!(
                    "{failure}; {label} restored, but closing references remain unverified: {error}"
                ),
                true,
            ),
        },
    };
    let reason = agent_loop::masked(&reason, credential.job);
    Applied::record(|a| {
        a.body = AppliedBody::Failed(reason.clone());
        a.manual_repair = manual.then(|| reason.clone());
    })?;
    Ok(reason)
}

fn live_publication_main(work: &Path, token: &str) -> Result<String, ScalerError> {
    let authenticated_git = |args: &[&str]| -> Result<String, ScalerError> {
        let mut command = git_invocation(work, args);
        command.env("GH_TOKEN", token);
        String::from_utf8(output(&mut command)?)
            .map_err(|_| ScalerError::Guard("non-UTF8 live main response"))
    };
    let remote = authenticated_git(&[
        "-c",
        "credential.helper=!gh auth git-credential",
        "ls-remote",
        "--heads",
        "https://github.com/carrick-sh/carrick",
        "refs/heads/main",
    ])?;
    let fields: Vec<_> = remote.split_whitespace().collect();
    let [main, "refs/heads/main"] = fields.as_slice() else {
        return Err(ScalerError::Guard("live main ref missing or ambiguous"));
    };
    if !sha(main) {
        return Err(ScalerError::Guard("invalid live main SHA"));
    }
    authenticated_git(&[
        "-c",
        "credential.helper=!gh auth git-credential",
        "fetch",
        "--no-tags",
        "https://github.com/carrick-sh/carrick",
        main,
    ])?;
    Ok((*main).to_owned())
}

/// An adopted PR moved after admission, or the worker rewrote its history.
/// Nothing is overwritten and the round ends blocked with the reason.
/// What a consented rebase kept of the director's history (#1215).
struct KeptRebase {
    /// The rebased counterpart of the admitted tip: the run's own commits
    /// start above it, so every later check measures from here.
    director_tip: String,
    /// Director commits whose patch changed while resolving conflicts.
    changed: Vec<String>,
    /// `git range-diff -s` of the director's commits, for the reviewer.
    range_diff: String,
}
/// A consented rebase must keep the director's history: the director's
/// commits from the merge-base with main to the admitted tip come first
/// above admitted main, in order, each with the same author email and
/// subject. Commits main already has (`git cherry` `-`) count as kept. A
/// commit replaced by an empty one, or a path the director changed that the
/// rebased history neither changes nor already matches, is refused. A
/// changed patch is allowed (conflict resolution) and listed. `Err` says
/// what was lost.
fn rebase_kept_commits(
    work: &Path,
    admitted: &str,
    base: &str,
) -> Result<Result<KeptRebase, String>, ScalerError> {
    let fork = git(work, &["merge-base", admitted, base])?
        .trim()
        .to_owned();
    let empty = |sha: &str| -> Result<bool, ScalerError> {
        Ok(git(
            work,
            &["diff-tree", "--no-commit-id", "--name-only", "-r", sha],
        )?
        .trim()
        .is_empty())
    };
    // Every empty commit shares one patch-id, so an empty director commit
    // is never "already in main".
    let mut upstream = Vec::new();
    for line in git(work, &["cherry", base, admitted, &fork])?.lines() {
        if let Some(sha) = line.strip_prefix("- ")
            && !empty(sha)?
        {
            upstream.push(sha.to_owned());
        }
    }
    // Each commit's author and whole message are read on their own, never
    // split out of one log stream a message could forge separators in; the
    // whole message, so a rebased director commit can't gain a closing
    // keyword.
    let commits = |range: &str| -> Result<Vec<(String, String)>, ScalerError> {
        git(work, &["rev-list", "--reverse", "--no-merges", range])?
            .lines()
            .filter(|sha| !sha.is_empty())
            .map(|sha| {
                let author = git(work, &["log", "-1", "--format=%ae", sha])?;
                let message = git(work, &["log", "-1", "--format=%B", sha])?;
                Ok((
                    sha.to_owned(),
                    format!("{}\0{}", author.trim(), message.trim_end()),
                ))
            })
            .collect()
    };
    let original: Vec<_> = commits(&format!("{fork}..{admitted}"))?
        .into_iter()
        .filter(|(sha, _)| !upstream.contains(sha))
        .collect();
    // A rebase is linear: a merge above main could carry a closing keyword
    // or changes past every check below.
    let merges = git(work, &["rev-list", "--merges", &format!("{base}..HEAD")])?;
    if let Some(merge) = merges.lines().next() {
        return Ok(Err(format!(
            "left a merge commit `{}` above main",
            merge.chars().take(12).collect::<String>()
        )));
    }
    let rebased = commits(&format!("{base}..HEAD"))?;
    let short = |sha: &str| sha.chars().take(12).collect::<String>();
    for (index, (sha, key)) in original.iter().enumerate() {
        let subject = key
            .split('\0')
            .nth(1)
            .and_then(|message| message.lines().next())
            .unwrap_or_default();
        let named = format!("`{}` (\"{subject}\")", short(sha));
        let Some((new, new_key)) = rebased.get(index) else {
            return Ok(Err(format!("dropped the director's commit {named}")));
        };
        if new_key != key {
            return Ok(Err(format!(
                "dropped or reordered the director's commit {named}"
            )));
        }
        if empty(new)? && !empty(sha)? {
            return Ok(Err(format!(
                "replaced the director's commit {named} with an empty commit"
            )));
        }
    }
    let director_tip = original
        .len()
        .checked_sub(1)
        .and_then(|last| rebased.get(last))
        .map_or_else(|| base.to_owned(), |(sha, _)| sha.clone());
    let paths = |from: &str, to: &str| -> Result<Vec<String>, ScalerError> {
        Ok(git(
            work,
            &["diff", "--name-only", "--no-renames", "-z", from, to],
        )?
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect())
    };
    let touched = paths(base, &director_tip)?;
    // Conflict resolution only edits files the director's own commits
    // change; any other path in them would be the run's own work hidden
    // from the run's checks.
    let director = paths(&fork, admitted)?;
    if let Some(path) = touched.iter().find(|p| !director.contains(p)) {
        return Ok(Err(format!(
            "changed `{path}` in the director's commits, which the director never changed"
        )));
    }
    for path in director {
        let same = |rev: &str| git(work, &["rev-parse", &format!("{rev}:{path}")]).ok();
        if !touched.contains(&path) && same(&director_tip) != same(admitted) {
            return Ok(Err(format!("dropped the director's change to `{path}`")));
        }
    }
    let changed = git(work, &["cherry", &director_tip, admitted, &fork])?
        .lines()
        .filter_map(|line| line.strip_prefix("+ "))
        .filter(|sha| !upstream.iter().any(|u| u == sha))
        .map(short)
        .collect();
    // range-diff refuses an empty range: then there is nothing to compare.
    let range_diff = if fork == admitted || base == director_tip {
        String::new()
    } else {
        git(
            work,
            &[
                "range-diff",
                "--no-color",
                "-s",
                &format!("{fork}..{admitted}"),
                &format!("{base}..{director_tip}"),
            ],
        )?
        .lines()
        .take(30)
        .map(|line| line.chars().take(200).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
    };
    Ok(Ok(KeptRebase {
        director_tip,
        changed,
        range_diff,
    }))
}
fn adopted_publication_blocked(number: u64, why: &str) -> Result<ScalerError, ScalerError> {
    let reason = format!("Adopted PR #{number}: {why}");
    Applied::record(|a| a.adoption_blocked = Some(reason.clone()))?;
    Ok(ScalerError::Usage(reason))
}
/// `ls-remote` output for one branch; empty when the branch is absent.
fn live_branch_tip(work: &Path, branch: &str) -> Result<String, ScalerError> {
    git(
        work,
        &[
            "-c",
            "credential.helper=!gh auth git-credential",
            "ls-remote",
            "--heads",
            "https://github.com/carrick-sh/carrick",
            &format!("refs/heads/{branch}"),
        ],
    )
}

fn publication_body(body: &str, source: &str, issue: u64) -> Result<String, ScalerError> {
    let closing = format!("\n\nCloses #{issue}\n");
    let (human, footer) = body.rsplit_once(&closing).ok_or(ScalerError::Guard(
        "publication body lacks canonical footer",
    ))?;
    Ok(format!("{human}\n\n{source}{closing}{footer}"))
}

/// Publish the harvested work. A refusal never costs the commits: they are
/// kept as a patch series in the handoff artifact so a continuation or the
/// director can resume from them.
fn publish(
    root: &Path,
    dispatch: &Dispatch,
    receipt: &Receipt,
    contract: &Contract,
    report_path: &Path,
    token: &str,
    runs: &mut agent_loop::RunCache,
) -> Result<Option<u64>, ScalerError> {
    publish_with(
        root,
        dispatch,
        receipt,
        contract,
        report_path,
        token,
        runs,
        PublishMode::Full,
    )
}

/// What one publication may change on GitHub.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PublishMode {
    /// Push commits, then create the PR or apply the body proposal.
    Full,
    /// The server's WIP checkpoint after a worker: push commits only, never
    /// create a PR or touch a body, so turn-end work is never lost.
    CommitsOnly,
}

#[expect(clippy::too_many_arguments, reason = "one publication request")]
fn publish_with(
    root: &Path,
    dispatch: &Dispatch,
    receipt: &Receipt,
    contract: &Contract,
    report_path: &Path,
    token: &str,
    runs: &mut agent_loop::RunCache,
    mode: PublishMode,
) -> Result<Option<u64>, ScalerError> {
    let mut preserve = None;
    let result = publish_commits(
        root,
        dispatch,
        receipt,
        contract,
        report_path,
        token,
        runs,
        &mut preserve,
        mode,
    );
    let (Err(error), Some(base)) = (&result, preserve) else {
        return result;
    };
    let work = crate::agent_runner::state()?.join("work");
    match preserve_harvest(&work, &base, token) {
        // The workflow refusal keeps its type, so a checkpoint can push the
        // rest of the work (#1241).
        Ok(Some(note)) => Err(match error {
            ScalerError::WorkflowRefused(paths, _) => {
                ScalerError::WorkflowRefused(paths.clone(), format!("; {note}"))
            }
            _ => ScalerError::Usage(format!("{error}; {note}")),
        }),
        Ok(None) => result,
        Err(saving) => Err(ScalerError::Usage(format!(
            "{error}; harvested commits could not be kept: {saving}"
        ))),
    }
}

const HARVEST_PATCH: &str = "harvest.patch";
const HARVEST_PATCH_BYTES: usize = 8 * 1024 * 1024;

/// Write `base..HEAD` as a text patch series into the upload population and
/// scan it like every other artifact. A bundle is binary and cannot pass the
/// text-only scan; `git am` resumes from this series.
fn preserve_harvest(work: &Path, base: &str, token: &str) -> Result<Option<String>, ScalerError> {
    let Some(runner_temp) = std::env::var_os("RUNNER_TEMP") else {
        return Ok(None);
    };
    let package = PathBuf::from(runner_temp).join("dispatch-output");
    if !package.is_dir() {
        return Ok(None);
    }
    let series = output(&mut git_invocation(
        work,
        &[
            "format-patch",
            "--stdout",
            "--binary",
            "--no-signature",
            &format!("{base}..HEAD"),
        ],
    ))?;
    if series.is_empty() {
        return Ok(None);
    }
    if series.len() > HARVEST_PATCH_BYTES {
        return Ok(Some(format!(
            "harvested commits exceed {HARVEST_PATCH_BYTES} bytes and were not kept"
        )));
    }
    if std::str::from_utf8(&series).is_err() {
        return Ok(Some(
            "harvested commits are not text-safe and were not kept".into(),
        ));
    }
    let path = package.join(HARVEST_PATCH);
    std::fs::write(&path, series)?;
    if let Err(error) = mask_artifacts(&package, token) {
        std::fs::remove_file(&path)?;
        return Err(error);
    }
    Ok(Some(format!(
        "harvested commits are kept in artifact {HARVEST_PATCH}; resume with `git am`"
    )))
}

#[expect(clippy::too_many_arguments, reason = "one publication request")]
fn publish_commits(
    root: &Path,
    dispatch: &Dispatch,
    receipt: &Receipt,
    _contract: &Contract,
    report_path: &Path,
    token: &str,
    runs: &mut agent_loop::RunCache,
    preserve: &mut Option<String>,
    mode: PublishMode,
) -> Result<Option<u64>, ScalerError> {
    let mut credential = PublishCredential::new(token);
    let mut check = ReferenceCheck::new(reference_host());
    // Push, snapshot and write share the primary window; recovery alone may
    // use its reserved thirty seconds, without extending the caller's budget.
    let _primary_window = CommandWindow::until(check.deadline());
    let adopted = match &dispatch.continuation {
        Continuation::Adopted { pr, tip, .. } => Some((*pr, tip.as_str())),
        Continuation::Owned => None,
    };
    let rebase_allowed = matches!(
        dispatch.continuation,
        Continuation::Adopted { rebase: true, .. }
    );
    if adopted.is_some() {
        require_target_pr(root, dispatch)?;
    } else if dispatch.resume {
        agent_loop::verified_branch_cached(root, dispatch.issue, &dispatch.branch, runs)?;
    } else {
        branch_prs(root, &dispatch.branch, "all")?;
    }
    let state = crate::agent_runner::state()?;
    let work = state.join("work");
    let id = if adopted.is_some() {
        ""
    } else {
        branch_run(dispatch.issue, &dispatch.branch)?
    };
    // Invalid prose cannot consume the run's only chance to publish commits.
    let proposal = if mode == PublishMode::CommitsOnly {
        None
    } else if adopted.is_some() {
        // An adopted PR belongs to its author: push commits, never the body.
        if receipt.pr_body.is_some() {
            Applied::record(|a| {
                a.body = AppliedBody::Refused {
                    reason: "dispatch never edits the body of an adopted PR".into(),
                    template_created: false,
                }
            })?;
        }
        None
    } else {
        match proposed_pr_body(receipt.pr_body.as_deref(), dispatch.issue, id, token) {
            Ok(body) => body,
            Err(error) => {
                let reason = agent_loop::masked(&error.to_string(), token);
                Applied::record(|a| {
                    a.body = AppliedBody::Refused {
                        reason,
                        template_created: false,
                    }
                })?;
                None
            }
        }
    };
    let lease = RunLease::load(&state, admitted_tip(dispatch, receipt))?;
    // After a consented rebase the run's own commits start above the
    // rebased director tip, never above the admitted one (main's commits
    // between the two are not the run's).
    let mut rebased_director_tip: Option<String> = None;
    if work.is_dir()
        && (dispatch.resume || git(&work, &["rev-parse", "HEAD"])?.trim() != receipt.base)
    {
        if let Some((number, admitted)) = adopted {
            // The director owns the adopted history: the run may only add
            // commits on top of the admitted tip, never rebase or rewrite it.
            *preserve = Some(admitted.to_owned());
            if git(&work, &["merge-base", "--is-ancestor", admitted, "HEAD"]).is_err() {
                // With the director's consent the one allowed rewrite is a
                // rebase onto admitted main, pushed under the same lease.
                let onto_main = git(
                    &work,
                    &["merge-base", "--is-ancestor", &dispatch.base, "HEAD"],
                )
                .is_ok();
                if !rebase_allowed {
                    return Err(adopted_publication_blocked(
                        number,
                        &format!(
                            "the worker rewrote history: HEAD does not descend from the admitted tip `{admitted}`, and the trigger did not consent to a rebase (`Rebase: allowed`). Nothing was pushed"
                        ),
                    )?);
                }
                if !onto_main {
                    return Err(adopted_publication_blocked(
                        number,
                        &format!(
                            "the rebased HEAD does not descend from admitted main `{}`. Nothing was pushed",
                            dispatch.base
                        ),
                    )?);
                }
                match rebase_kept_commits(&work, admitted, &dispatch.base)? {
                    Err(lost) => {
                        return Err(adopted_publication_blocked(
                            number,
                            &format!("the rebase {lost}. Nothing was pushed"),
                        )?);
                    }
                    Ok(kept) => {
                        Applied::record(|a| {
                            a.rebased_onto = Some(dispatch.base.clone());
                            a.rebase_tip = Some(kept.director_tip.clone());
                            a.rebase_changed = kept.changed;
                            a.rebase_range_diff = Some(kept.range_diff);
                        })?;
                        rebased_director_tip = Some(kept.director_tip);
                    }
                }
            }
            // Fast-forward only, also over this run's own earlier pushes.
            if let Some(pushed) = &lease.pushed
                && git(&work, &["merge-base", "--is-ancestor", pushed, "HEAD"]).is_err()
            {
                return Err(adopted_publication_blocked(
                    number,
                    &format!(
                        "the worker rewrote history: HEAD does not descend from this run's pushed tip `{pushed}`. Nothing was pushed"
                    ),
                )?);
            }
        } else {
            // Keep the commits on any later refusal, even before main is known.
            *preserve = Some(receipt.base.clone());
            git(
                &work,
                &["merge-base", "--is-ancestor", &receipt.base, "HEAD"],
            )
            .map_err(|_| {
                ScalerError::Guard("worker must rebase onto admitted main before publication")
            })?;
        }
        let live_main = live_publication_main(&work, token)?;
        // An adopted run is measured from its admitted tip, so the
        // director's own commits are never charged to it.
        let mut base = match adopted {
            Some((_, admitted)) => rebased_director_tip
                .clone()
                .unwrap_or_else(|| admitted.to_owned()),
            None => git(&work, &["merge-base", &live_main, "HEAD"])?
                .trim()
                .to_owned(),
        };
        *preserve = Some(base.clone());
        // Main and the branch tip admitted before this run are trusted history.
        // A worker may rebase across either without owning their messages.
        check_commit_closures(
            &work,
            &base,
            (!receipt.expected_tip.is_empty()).then_some(receipt.expected_tip.as_str()),
            dispatch.issue,
        )?;
        let workflow_files = |from: &str, to: &str| -> Result<Vec<String>, ScalerError> {
            Ok(git(
                &work,
                &[
                    "diff",
                    "--name-only",
                    "--no-renames",
                    "-z",
                    from,
                    to,
                    "--",
                    ".github/workflows/",
                ],
            )?
            .split('\0')
            .filter(|path| !path.is_empty())
            .map(str::to_owned)
            .collect())
        };
        let own = workflow_files(&base, "HEAD")?;
        if !own.is_empty() {
            // Worker-chosen path names: shown escaped, never raw.
            let shown = own.iter().map(|p| p.escape_debug().to_string()).collect();
            return Err(ScalerError::WorkflowRefused(shown, String::new()));
        }
        // GitHub refuses an App push when the branch's workflow files differ
        // from the default branch, even if none of the pushed commits touch
        // them. A base that is merely behind such a change is not a blocker:
        // replay the run's commits onto current main.
        // Never on an adopted PR: keeping it current with main is the director's.
        if adopted.is_none() && base != live_main && !workflow_files(&base, &live_main)?.is_empty()
        {
            let rebase = output(&mut git_invocation(
                &work,
                &["rebase", "--rebase-merges", "--onto", &live_main, &base],
            ));
            if let Err(error) = rebase {
                let conflicts = git(&work, &["diff", "--name-only", "--diff-filter=U"])
                    .unwrap_or_default()
                    .lines()
                    .collect::<Vec<_>>()
                    .join(", ");
                // The abort must not hide why the rebase failed.
                let aborted = git(&work, &["rebase", "--abort"]);
                return Err(ScalerError::Usage(format!(
                    "Rebase onto current main conflicts (main changed workflow files after the run's base){}; the run's commits are intact. Conflicting files: {conflicts}: {error}",
                    if aborted.is_err() {
                        ", and the rebase could not be aborted"
                    } else {
                        ""
                    }
                )));
            }
            if git(&work, &["rev-parse", "HEAD"])?.trim() == live_main {
                return Err(ScalerError::Usage(
                    "Nothing left to publish: every run commit is already in current main".into(),
                ));
            }
            // The tree and receipt are one pair: a later publish or worker turn
            // reads the checkpoint and must see the rebased head.
            refresh_checkpoint_head(&state, &work)?;
            base = live_main.clone();
            *preserve = Some(base.clone());
        }
        let tip = live_branch_tip(&work, &dispatch.branch)?;
        let head = git(&work, &["rev-parse", "HEAD"])?;
        let source = neutralize_mentions(&agent_loop::masked(
            &format!(
                "Published tree: worker `{}/{}` at `{}` (last successfully harvested checkpoint).",
                receipt.worker.backend,
                receipt.worker.model,
                head.trim()
            ),
            token,
        ));
        let proposal = proposal
            .map(|body| publication_body(&body, &source, dispatch.issue))
            .transpose()?;
        let prs = open_prs(root, &dispatch.branch)?;
        let push_event = if prs.as_array().is_some_and(|prs| !prs.is_empty()) {
            PublishEvent::PrPush
        } else {
            PublishEvent::BranchPush
        };
        let existing = tip.split_whitespace().next();
        if let Some((number, admitted)) = adopted
            && existing != Some(lease.current())
            && existing != Some(head.trim())
        {
            return Err(adopted_publication_blocked(
                number,
                &format!(
                    "the PR moved after admission (live head differs from the admitted tip `{admitted}`). Nothing was pushed or overwritten; comment `/agent` again to continue from the new head"
                ),
            )?);
        }
        let retained =
            existing.is_some() && lease.current().is_empty() && existing != Some(head.trim());
        if retained {
            let pr = require_owned_pr(root, dispatch)?;
            use std::io::Write;
            writeln!(
                std::fs::OpenOptions::new().append(true).open(report_path)?,
                "\nExisting dispatch branch `{}` and PR #{} retained; this rerun did not replace it.",
                dispatch.branch,
                pr["number"]
            )?;
        } else {
            let commits: Vec<_> = git(&work, &["rev-list", "--reverse", &format!("{base}..HEAD")])?
                .lines()
                .filter(|s| sha(s))
                .map(str::to_owned)
                .collect();
            let mut new_commits = Vec::new();
            let mut rebased_onto = None;
            if existing != Some(head.trim()) {
                let leased = lease.current();
                let prior_base = if leased.is_empty() {
                    receipt.base.clone()
                } else {
                    git(&work, &["merge-base", &live_main, leased])?
                        .trim()
                        .to_owned()
                };
                // Main must be on the primary history, and a published old tip
                // must have been rewritten. Merging main retains that old tip.
                let rewritten = leased.is_empty()
                    || git(&work, &["merge-base", leased, "HEAD"])?.trim() != leased;
                if prior_base != base
                    && rewritten
                    && git(
                        &work,
                        &["rev-list", "--first-parent", &format!("{prior_base}..HEAD")],
                    )?
                    .lines()
                    .any(|commit| commit == base)
                {
                    rebased_onto = Some(base.to_owned());
                }
                new_commits = if let Some(previous) = existing {
                    git(
                        &work,
                        &[
                            "rev-list",
                            "--reverse",
                            &format!("{base}..HEAD"),
                            "--not",
                            previous,
                        ],
                    )?
                    .lines()
                    .filter(|s| sha(s))
                    .map(str::to_owned)
                    .collect()
                } else {
                    commits.clone()
                };
                credential.write(push_event, |token| {
                    let mut push = push_command(&work, dispatch, id, &lease)?;
                    push.env("GH_TOKEN", token).env_remove("GITHUB_TOKEN");
                    output(&mut push)
                }).or_else(|error| match adopted {
                    // Decide from the server, never from git's localized text.
                    Some((number, _))
                        if live_branch_tip(&work, &dispatch.branch)?
                            .split_whitespace()
                            .next()
                            != Some(lease.current()) =>
                    {
                        Err(adopted_publication_blocked(
                            number,
                            &format!(
                                "the PR moved after admission (the push lease on `{}` was rejected). Nothing was overwritten; comment `/agent` again to continue from the new head",
                                lease.current()
                            ),
                        )?)
                    }
                    _ => Err(error),
                }).map_err(|error| {
                    if credential.app.is_some() && publish_permission_failure(&error.to_string()) {
                        ScalerError::Usage(format!("App token push refused (requires contents write; workflow files are not permitted): {error}"))
                    } else { error }
                })?;
            }
            Applied::record(|a| {
                a.commits = commits;
                // A WIP checkpoint may already have pushed some of them.
                for commit in new_commits {
                    if !a.new_commits.contains(&commit) {
                        a.new_commits.push(commit);
                    }
                }
                a.published_checkpoint = receipt.checkpointed;
                // An adopted round records its own consented rebase above;
                // the owned-branch rebase detection does not apply to it.
                if adopted.is_none() {
                    a.rebased_onto = rebased_onto;
                }
            })?;
        }
        if !retained {
            std::fs::write(state.join("published-tip"), head.trim())?;
        }
        if let Some((number, _)) = adopted {
            // Commits only: no PR creation, body edit or draft change.
            return Ok(Some(number));
        }
        if mode == PublishMode::CommitsOnly {
            return Ok(None);
        }
        if prs.as_array().is_some_and(|prs| !prs.is_empty()) {
            let pr = require_owned_pr(root, dispatch)?;
            if !retained && let Some(body) = &proposal {
                let number = pr["number"]
                    .as_u64()
                    .ok_or(ScalerError::Guard("invalid PR number"))?;
                // Retain the creation footer for ownership and credit this edit
                // to the current run with the final footer.
                let current_run = run_id()?;
                let body = if current_run == id {
                    body.clone()
                } else {
                    format!(
                        "{}\n\nDispatch run: https://github.com/{REPOSITORY}/actions/runs/{current_run}\n",
                        body.trim_end()
                    )
                };
                Applied::record(|a| a.publication_pr = Some(number))?;
                let previous = match read_closing_references(root, number) {
                    Ok(previous) => previous,
                    Err(error) => {
                        let reason = agent_loop::masked(
                            &format!(
                                "body not updated: closing references unverified before edit: {error}"
                            ),
                            token,
                        );
                        Applied::record(|a| a.body = AppliedBody::Failed(reason.clone()))?;
                        return Err(ScalerError::Usage(reason));
                    }
                };
                let mut expected: ClosingIssues =
                    previous.all.difference(&previous.body).cloned().collect();
                expected.insert(issue_reference(dispatch.issue));
                patch_pr_body(root, number, &body, &mut credential)?;
                if let Err(error) = check.verify(root, number, &expected) {
                    if matches!(error, ReferenceFailure::Deadline) {
                        return Err(ScalerError::Usage(keep_unverified_body(&error, token)?));
                    }
                    let reason = restore_pr_body(
                        root,
                        number,
                        (pr["body"].as_str().unwrap_or_default(), "previous body"),
                        &expected,
                        &error.to_string(),
                        &mut credential,
                        &mut check,
                    )?;
                    return Err(ScalerError::Usage(reason));
                }
                Applied::record(|a| a.body = AppliedBody::Updated)?;
            }
            return Ok(Some(
                pr["number"]
                    .as_u64()
                    .ok_or(ScalerError::Guard("invalid PR number"))?,
            ));
        } else {
            let body = match proposal {
                Some(body) => body,
                None => publication_body(
                    &template_pr_body(&receipt.contract, dispatch.issue, id, token)?,
                    &source,
                    dispatch.issue,
                )?,
            };
            let path = state.join("pr-body.md");
            std::fs::write(&path, body)?;
            // A later run cannot add a publication binding to the immutable
            // creation run's artifacts. Use Actions identity for this recovery
            // create so the original run's branch remains independently owned.
            if id != run_id()? {
                credential.job_only();
            }
            let created = credential.gh(
                root,
                &[
                    "pr",
                    "create",
                    "--repo",
                    REPOSITORY,
                    "--draft",
                    "--base",
                    "main",
                    "--head",
                    &dispatch.branch,
                    "--title",
                    &draft_pr_title(&work, &base, dispatch.issue, token)?,
                    "--body-file",
                    path.to_str().ok_or(ScalerError::Guard("body path"))?,
                ],
                PublishEvent::PrCreate,
            )?;
            let created_number = created
                .trim()
                .strip_prefix(&format!("https://github.com/{REPOSITORY}/pull/"))
                .filter(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()))
                .and_then(|n| n.parse::<u64>().ok())
                .filter(|n| *n > 0)
                .ok_or(ScalerError::Guard("invalid created PR URL"))?;
            Applied::record(|a| a.publication_pr = Some(created_number))?;
            let number = require_owned_pr(root, dispatch)?["number"]
                .as_u64()
                .ok_or(ScalerError::Guard("invalid PR number"))?;
            Applied::record(|a| a.publication_pr = Some(number))?;
            let expected = ClosingIssues::from([issue_reference(dispatch.issue)]);
            if let Err(error) = check.verify(root, number, &expected) {
                if matches!(error, ReferenceFailure::Deadline) {
                    return Err(ScalerError::Usage(keep_unverified_body(&error, token)?));
                }
                // Recovery prose is server-owned, independent of worker claims.
                let recovery = Contract {
                    summary: "The server restored this template because the proposed body's closing references could not be verified.".into(),
                    ..receipt.contract.clone()
                };
                let fallback = publication_body(
                    &template_pr_body(&recovery, dispatch.issue, id, token)?,
                    &source,
                    dispatch.issue,
                )?;
                let reason = restore_pr_body(
                    root,
                    number,
                    (&fallback, "default template"),
                    &expected,
                    &error.to_string(),
                    &mut credential,
                    &mut check,
                )?;
                return Err(ScalerError::Usage(reason));
            }
            Applied::record(|a| {
                // Preserve a refused proposal even when creation used the fallback.
                if let AppliedBody::Refused {
                    template_created, ..
                } = &mut a.body
                {
                    *template_created = true;
                } else {
                    a.body = AppliedBody::Created;
                }
            })?;
            return Ok(Some(number));
        }
    }
    Ok(None)
}

/// A three-round chain on issue 799 and its dispatch PR 800 (#1241 part 3),
/// as live API reads: the owner's `/agent` (comment 10 on the issue), round
/// 1's Continuing outcome (20, on the PR) and round 2's (30), which names 20.
/// [`chain_case`] then breaks one rule at a time.
#[cfg(test)]
pub(crate) mod chain_fixture {
    use super::*;
    use std::collections::BTreeMap;
    pub(crate) fn url(thread: u64, anchor: &str) -> String {
        let kind = if thread == 800 { "pull" } else { "issues" };
        format!("https://github.com/{REPOSITORY}/{kind}/{thread}#{anchor}")
    }
    pub(crate) fn outcome_body(
        status: &str,
        round: u32,
        trigger: Option<&str>,
        from: Option<&str>,
        run: u64,
    ) -> String {
        let mut section = format!("Dispatch outcome: {status}\n\n");
        if let Some(trigger) = trigger {
            section.push_str(&format!("Round trigger: {trigger}\n"));
        }
        section.push_str(&format!("Chain: round {round} of at most 4\n"));
        if let Some(from) = from {
            section.push_str(&format!("Chained from: {from} (hop {}/3)\n", round - 1));
        }
        section.push_str(&format!(
            "Checkpoint: work/dispatch-799-42 at {}\nOwner comments during this round:\n\nContinuation brief:\n> next step {round}\n\n<details><summary>x</summary>\n\nOutcome contract:\n```json\n{{}}\n```\n</details>\n\nLoop claims (unverified):\n> continue\n\n\nDispatch run: https://github.com/{REPOSITORY}/actions/runs/{run}\n",
            "c".repeat(40)
        ));
        section
    }
    pub(crate) fn comment(id: u64, thread: u64, login: &str, at: &str, body: &str) -> Value {
        let kind = if login.ends_with("[bot]") {
            "Bot"
        } else {
            "User"
        };
        json!({"id":id,"user":{"login":login,"type":kind},"created_at":at,"updated_at":at,
            "issue_url":format!("https://api.github.com/repos/{REPOSITORY}/issues/{thread}"),
            "html_url":url(thread, &format!("issuecomment-{id}")),"body":body})
    }
    fn page(path: &str) -> String {
        let join = if path.contains('?') { '&' } else { '?' };
        format!("repos/{REPOSITORY}/{path}{join}per_page=100&page=1")
    }
    pub(crate) fn pr() -> Value {
        json!({"number":800,"state":"open","draft":true,"user":{"login":"github-actions[bot]","type":"Bot"},
            "head":{"ref":"work/dispatch-799-42","sha":"c".repeat(40),"repo":{"full_name":REPOSITORY}},
            "base":{"ref":"main","repo":{"full_name":REPOSITORY}},
            "body":format!("Closes #799\nDispatch run: https://github.com/{REPOSITORY}/actions/runs/42")})
    }
    /// The authentic chain, keyed by endpoint.
    pub(crate) fn base() -> BTreeMap<String, Value> {
        let trigger = comment(
            10,
            799,
            "tjfontaine",
            "2026-10-31T10:00:00Z",
            "/agent do the slice",
        );
        let first = comment(
            20,
            800,
            "github-actions[bot]",
            "2026-10-31T11:00:00Z",
            &outcome_body(
                "Continuing",
                1,
                Some(&url(799, "issuecomment-10")),
                None,
                51,
            ),
        );
        let second = comment(
            30,
            800,
            "github-actions[bot]",
            "2026-10-31T12:00:00Z",
            &outcome_body(
                "Continuing",
                2,
                Some(&url(800, "issuecomment-20")),
                Some(&url(800, "issuecomment-20")),
                52,
            ),
        );
        let mut map = BTreeMap::new();
        let mut put = |path: String, value: Value| {
            map.insert(path, value);
        };
        put(
            format!("repos/{REPOSITORY}/issues/comments/10"),
            trigger.clone(),
        );
        put(
            format!("repos/{REPOSITORY}/issues/comments/20"),
            first.clone(),
        );
        put(
            format!("repos/{REPOSITORY}/issues/comments/30"),
            second.clone(),
        );
        put(
            format!("repos/{REPOSITORY}/issues/800"),
            json!({"number":800,"state":"open","pull_request":{"url":"pr"}}),
        );
        put(format!("repos/{REPOSITORY}/pulls/800"), pr());
        put(
            format!("repos/{REPOSITORY}/issues/799"),
            json!({"number":799,"state":"open","title":"Fixture","body":"Do it","user":{"login":"tjfontaine","type":"User"}}),
        );
        put(page("pulls?state=open&base=main"), json!([pr()]));
        put(page("issues/799/comments"), json!([trigger]));
        put(page("issues/800/comments"), json!([first, second]));
        put(page("pulls/800/reviews"), json!([]));
        put(page("issues/799/timeline"), json!([]));
        put(page("issues/800/timeline"), json!([]));
        map
    }
    /// Each case breaks one rule; `None` is the authentic chain. The text
    /// is part of the refusal the rule gives.
    pub(crate) const CASES: &[(&str, Option<&str>)] = &[
        ("authentic", None),
        ("authentic label root", None),
        ("authentic review root", None),
        ("round limit", Some("round limit")),
        ("not continuing", Some("not Continuing")),
        ("forged author", Some("not an authentic dispatch outcome")),
        ("edited outcome", Some("not an authentic dispatch outcome")),
        ("stale outcome", Some("not the latest dispatch outcome")),
        ("owner comment after", Some("owner comment")),
        ("owner comment in the same second", Some("owner comment")),
        ("owner review after", Some("owner review")),
        ("dispatch label after", Some("dispatch label")),
        ("agent stop after", Some("`/agent stop`")),
        // Only the owner breaks a chain (#1262).
        ("stranger agent after", None),
        ("stranger changes-requested review after", None),
        // Every hop is held to the head outcome's checks (#1262).
        (
            "edited earlier hop",
            Some("not the previous Continuing round"),
        ),
        (
            "earlier hop checkpoint elsewhere",
            Some("not the previous Continuing round"),
        ),
        ("already chained", Some("already chained")),
        (
            "already chained in the same second",
            Some("already chained"),
        ),
        ("skipped round", Some("not the previous Continuing round")),
        ("collaborator root", Some("no owner root")),
        ("root not a trigger", Some("no owner root")),
        (
            "previous round not continuing",
            Some("not the previous Continuing round"),
        ),
        ("inconsistent hop", Some("not a dispatch outcome")),
        ("closed issue", Some("not an open issue")),
    ];
    pub(crate) fn chain_case(case: &str) -> BTreeMap<String, Value> {
        let mut map = base();
        let key = |path: &str| page(path);
        let comment_key = |id: u64| format!("repos/{REPOSITORY}/issues/comments/{id}");
        let push = |map: &mut BTreeMap<String, Value>, path: &str, item: Value| {
            let list = map.entry(key(path)).or_insert_with(|| json!([]));
            list.as_array_mut().unwrap().push(item);
        };
        let set_body = |map: &mut BTreeMap<String, Value>, id: u64, body: String| {
            map.get_mut(&comment_key(id)).unwrap()["body"] = body.clone().into();
            for item in map
                .get_mut(&key("issues/800/comments"))
                .unwrap()
                .as_array_mut()
                .unwrap()
            {
                if item["id"] == id {
                    item["body"] = body.clone().into();
                }
            }
        };
        let later = "2026-10-31T12:30:00Z";
        match case {
            "authentic" => {}
            "authentic label root" | "root not a trigger" => {
                let trigger = url(799, "event-61");
                set_body(
                    &mut map,
                    20,
                    outcome_body("Continuing", 1, Some(&trigger), None, 51),
                );
                let mut event = json!({"id":61,"event":"labeled","label":{"name":"dispatch:opus"},
                    "actor":{"login":"tjfontaine","type":"User"},"created_at":"2026-10-31T10:00:00Z",
                    "issue":{"number":799}});
                if case == "root not a trigger" {
                    event["label"]["name"] = "bug".into();
                }
                map.insert(format!("repos/{REPOSITORY}/issues/events/61"), event);
            }
            "authentic review root" => {
                let trigger = url(800, "pullrequestreview-62");
                set_body(
                    &mut map,
                    20,
                    outcome_body("Continuing", 1, Some(&trigger), None, 51),
                );
                map.insert(
                    format!("repos/{REPOSITORY}/pulls/800/reviews/62"),
                    json!({"id":62,"state":"CHANGES_REQUESTED","user":{"login":"tjfontaine","type":"User"},"submitted_at":"2026-10-31T10:00:00Z"}),
                );
            }
            "round limit" => {
                // A consistent four-round chain: 15 (round 1), 16, 20, 30.
                let first = comment(
                    15,
                    800,
                    "github-actions[bot]",
                    "2026-10-31T10:30:00Z",
                    &outcome_body(
                        "Continuing",
                        1,
                        Some(&url(799, "issuecomment-10")),
                        None,
                        49,
                    ),
                );
                let second = comment(
                    16,
                    800,
                    "github-actions[bot]",
                    "2026-10-31T10:45:00Z",
                    &outcome_body(
                        "Continuing",
                        2,
                        None,
                        Some(&url(800, "issuecomment-15")),
                        50,
                    ),
                );
                for item in [first, second] {
                    map.insert(comment_key(item["id"].as_u64().unwrap()), item.clone());
                    push(&mut map, "issues/800/comments", item);
                }
                set_body(
                    &mut map,
                    20,
                    outcome_body(
                        "Continuing",
                        3,
                        None,
                        Some(&url(800, "issuecomment-16")),
                        51,
                    ),
                );
                set_body(
                    &mut map,
                    30,
                    outcome_body(
                        "Continuing",
                        4,
                        None,
                        Some(&url(800, "issuecomment-20")),
                        52,
                    ),
                );
            }
            "skipped round" => set_body(
                &mut map,
                30,
                outcome_body(
                    "Continuing",
                    3,
                    None,
                    Some(&url(800, "issuecomment-20")),
                    52,
                ),
            ),
            "already chained in the same second" => push(
                &mut map,
                "issues/800/comments",
                comment(
                    44,
                    800,
                    "github-actions[bot]",
                    "2026-10-31T12:00:00Z",
                    &outcome_body("Done", 3, None, Some(&url(800, "issuecomment-30")), 53),
                ),
            ),
            "not continuing" => set_body(
                &mut map,
                30,
                outcome_body("Blocked", 2, None, Some(&url(800, "issuecomment-20")), 52),
            ),
            "forged author" => {
                map.get_mut(&comment_key(30)).unwrap()["user"] =
                    json!({"login":"tjfontaine","type":"User"});
            }
            "edited outcome" => {
                map.get_mut(&comment_key(30)).unwrap()["updated_at"] = later.into();
            }
            "stale outcome" => push(
                &mut map,
                "issues/799/comments",
                comment(
                    40,
                    799,
                    "github-actions[bot]",
                    later,
                    "Dispatch outcome: Done\n\nRound trigger: x\n",
                ),
            ),
            "owner comment after" => push(
                &mut map,
                "issues/800/comments",
                comment(41, 800, "tjfontaine", later, "looks good so far"),
            ),
            // Second-resolution timestamps: a tie counts as after (#1241).
            "owner comment in the same second" => push(
                &mut map,
                "issues/800/comments",
                comment(
                    45,
                    800,
                    "tjfontaine",
                    "2026-10-31T12:00:00Z",
                    "wait, one more thing",
                ),
            ),
            "agent stop after" => push(
                &mut map,
                "issues/799/comments",
                comment(42, 799, "tjfontaine", later, "/agent stop"),
            ),
            "stranger agent after" => push(
                &mut map,
                "issues/799/comments",
                comment(46, 799, "someone", later, "/agent stop this"),
            ),
            "stranger changes-requested review after" => push(
                &mut map,
                "pulls/800/reviews",
                json!({"id":65,"state":"CHANGES_REQUESTED","user":{"login":"someone","type":"User"},"submitted_at":later}),
            ),
            "edited earlier hop" => {
                map.get_mut(&comment_key(20)).unwrap()["updated_at"] = later.into();
            }
            "earlier hop checkpoint elsewhere" => {
                let first = map.get_mut(&comment_key(20)).unwrap();
                let body = first["body"].as_str().unwrap().replace(
                    "Checkpoint: work/dispatch-799-42",
                    "Checkpoint: work/dispatch-900-42",
                );
                first["body"] = body.into();
            }
            "owner review after" => push(
                &mut map,
                "pulls/800/reviews",
                json!({"id":63,"state":"COMMENTED","user":{"login":"tjfontaine","type":"User"},"submitted_at":later}),
            ),
            "dispatch label after" => push(
                &mut map,
                "issues/799/timeline",
                json!({"id":64,"event":"labeled","label":{"name":"dispatch"},"actor":{"login":"tjfontaine","type":"User"},"created_at":later}),
            ),
            "already chained" => push(
                &mut map,
                "issues/800/comments",
                comment(
                    43,
                    800,
                    "github-actions[bot]",
                    later,
                    &outcome_body("Done", 3, None, Some(&url(800, "issuecomment-30")), 53),
                ),
            ),
            "collaborator root" => {
                map.get_mut(&comment_key(10)).unwrap()["user"] =
                    json!({"login":"collaborator","type":"User"});
            }
            "previous round not continuing" => set_body(
                &mut map,
                20,
                outcome_body("Done", 1, Some(&url(799, "issuecomment-10")), None, 51),
            ),
            "inconsistent hop" => {
                let body = outcome_body(
                    "Continuing",
                    2,
                    None,
                    Some(&url(800, "issuecomment-20")),
                    52,
                )
                .replace("(hop 1/3)", "(hop 2/3)");
                set_body(&mut map, 30, body);
            }
            "closed issue" => {
                map.get_mut(&format!("repos/{REPOSITORY}/issues/799"))
                    .unwrap()["state"] = "closed".into();
            }
            other => panic!("unknown chain case {other}"),
        }
        map
    }
    /// A read transport over a case: a missing endpoint is the API's 404.
    pub(crate) fn serve(
        map: &BTreeMap<String, Value>,
    ) -> impl FnMut(&str) -> Result<Value, ScalerError> + '_ {
        |endpoint: &str| {
            map.get(endpoint)
                .cloned()
                .ok_or(ScalerError::Guard("gh: Not Found (HTTP 404)"))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    /// #1286: only a process that can still run blocks packaging; a zombie
    /// left for another parent to reap does not. Survivors are named.
    #[test]
    fn retirement_census_ignores_zombies_and_names_live_survivors() {
        let zombie = parse_stat(41, "41 (cargo) Z 1 41 41 0 -1").unwrap();
        assert_eq!(
            zombie,
            CensusEntry {
                pid: 41,
                state: 'Z',
                parent: 1,
                command: "cargo".into(),
                live_thread: false,
            }
        );
        // A command name can hold spaces and parentheses.
        let odd = parse_stat(42, "42 (rustc (worker) 2) D 40 42 42 0 -1").unwrap();
        assert_eq!(
            (odd.command.as_str(), odd.state, odd.parent),
            ("rustc (worker) 2", 'D', 40)
        );
        assert!(live_survivors(vec![zombie.clone()]).is_empty());
        let live = live_survivors(vec![zombie, odd.clone(), odd]);
        assert_eq!(live.len(), 1);
        assert_eq!(
            live[0].describe(),
            "pid 42 `rustc (worker) 2` state D parent 40"
        );
        assert!(parse_stat(43, "garbage").is_none());
        // A zombie leader whose other threads still run is a survivor.
        let leader = CensusEntry {
            live_thread: true,
            ..parse_stat(44, "44 (worker) Z 1 44 44 0 -1").unwrap()
        };
        assert_eq!(live_survivors(vec![leader]).len(), 1);
        // Gone means only "not found": a pid that can't exist is gone.
        assert!(census_entry(libc::pid_t::MAX).is_none());
    }
    /// #1229: a running agent's output reaches the step log while it runs,
    /// through the production serve loop, masked, line by line, with a
    /// final partial line only once the writer exits.
    #[test]
    fn live_log_streams_an_agent_through_the_serve_loop() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("agent.out");
        let sink = live_log::capture();
        live_log::set_token("fixture-token");
        let writer = live_log::create("worker agy/m", &log).unwrap();
        let mut seen_while_running = String::new();
        // The child writes through the followed handle, then swaps the path
        // for a link to a secret: the stream must keep reading the handle.
        std::fs::write(dir.path().join("secret"), "SECRET-CONTENT\n").unwrap();
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(format!(
                "printf 'first fixture-token\\n::add-mask::x\\n'; sleep 1; rm {p}; ln -s {s} {p}; printf 'tail'",
                p = log.display(),
                s = dir.path().join("secret").display()
            ))
            .stdout(writer);
        let mut ticks = 0;
        let code = wait_account_serving(
            &mut command,
            std::time::Duration::from_secs(20),
            "nobody",
            || {
                ticks += 1;
                if ticks == 6 {
                    seen_while_running = String::from_utf8(sink.borrow().clone()).unwrap();
                }
                Ok(false)
            },
        )
        .unwrap();
        assert_eq!(code, 0);
        // The token is registered with the runner and commands suspended
        // before any transcript line; then the complete lines stream.
        let stop = seen_while_running
            .lines()
            .find_map(|l| l.strip_prefix("::stop-commands::"))
            .expect("commands suspended while streaming")
            .to_owned();
        assert_eq!(
            seen_while_running,
            format!(
                "::add-mask::fixture-token\n::stop-commands::{stop}\n[worker agy/m] first [REDACTED]\n[worker agy/m] ::add-mask::x\n"
            ),
            "complete lines stream while the agent runs; the partial waits"
        );
        live_log::unfollow("worker agy/m");
        let all = String::from_utf8(sink.borrow().clone()).unwrap();
        assert!(
            all.ends_with(&format!("[worker agy/m] tail\n::{stop}::\n")),
            "commands resume once nothing streams: {all}"
        );
        assert!(
            all.lines()
                .filter(|l| l.starts_with("[worker"))
                .all(|l| !l.contains("fixture-token")),
            "{all}"
        );
        assert!(
            !all.contains("SECRET-CONTENT"),
            "followed a swapped path: {all}"
        );
    }
    #[test]
    fn agent_account_command_adds_only_the_host_lease_handoff() {
        let mut command = Command::new("python3");
        private_environment(&mut command);
        command.arg("agy_worker.py").env("HOME", "/private/home");
        let args = |lease| {
            account_command(&command, AGENT_USER, Path::new("/private/root"), lease)
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        let plain = args(None);
        let handed = args(Some(
            crate::host_lease::AccountHandoff::fixture(true).unwrap(),
        ));
        let at = plain.iter().position(|a| a == "--").unwrap() + 1;
        let program = plain.iter().position(|a| a == "python3").unwrap();
        let launcher = &handed[at..at + 4];
        assert_eq!(launcher[0], "/bin/sh");
        assert_eq!(launcher[2], "exec 3>&0 0</dev/null; exec \"$@\"");
        let lease = &handed[program + 4..program + 7];
        assert_eq!(
            lease,
            [
                "CARRICK_HOST_LEASE_SOCKET=/tmp/carrick-lease-fixture/lease.sock",
                "CARRICK_HOST_LEASE_PATH=/tmp/carrick-host-lease.lock",
                "CARRICK_HOST_LEASE_SCOPE_FD=3",
            ]
        );
        // Removing exactly the launcher and lease assignments gives the
        // unchanged credential-free command; nothing else was added.
        let mut stripped = handed.clone();
        stripped.drain(program + 4..program + 7);
        stripped.drain(at..at + 4);
        assert_eq!(stripped, plain);
        assert!(!plain.iter().any(|a| a.starts_with("CARRICK_HOST_LEASE")));
        // An unscoped holder needs no descriptor and therefore no shell.
        let unscoped = args(Some(
            crate::host_lease::AccountHandoff::fixture(false).unwrap(),
        ));
        assert_eq!(unscoped.len(), plain.len() + 2);
        assert_eq!(unscoped[at], "/usr/bin/env");
    }
    #[test]
    fn proposed_body_is_bounded_and_cannot_add_linkage_or_provenance() {
        let body = proposed_pr_body(
            Some("A concrete explanation.\n\nCloses #634\n"),
            634,
            "42",
            "fixture-token",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            body.lines()
                .filter(|line| line.starts_with("Closes #"))
                .count(),
            1
        );
        for text in [
            "Closes #634\nCloses #634",
            "Fixes #800",
            "Fixes:#800",
            "cLoSeS#800",
            "Resolves: [issue](https://github.com/carrick-sh/carrick/issues/800)",
            "Closes\n#800",
            "Closes #634 and #800",
            "Dispatch run: forged",
            "<!-- unterminated",
        ] {
            assert!(
                proposed_pr_body(Some(text), 634, "42", "fixture-token").is_err(),
                "unsafe proposal admitted: {text}"
            );
        }
        assert!(proposed_pr_body(Some(&"x".repeat(8193)), 634, "42", "fixture-token").is_err());
        let directory = tempfile::tempdir().unwrap();
        assert!(read_pr_body(directory.path()).unwrap().is_none());
        std::os::unix::fs::symlink("elsewhere", directory.path().join("pr-body.md")).unwrap();
        assert!(read_pr_body(directory.path()).is_err());
    }
    #[test]
    fn failed_body_edit_keeps_confirmed_push_evidence() {
        publication_fixture("edit-failure");
    }
    #[test]
    fn merge_conflicted_branch_reaches_the_isolated_worker_checkout() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("base");
        std::fs::create_dir(&root).unwrap();
        git(&root, &["init", "-b", "main"]).unwrap();
        std::fs::write(root.join("conflict"), "base\n").unwrap();
        git(&root, &["add", "conflict"]).unwrap();
        git(&root, &["commit", "-m", "base"]).unwrap();
        git(&root, &["checkout", "-b", "work/dispatch-634-42"]).unwrap();
        std::fs::write(root.join("conflict"), "worker branch\n").unwrap();
        git(&root, &["commit", "-am", "branch change"]).unwrap();
        let tip = git(&root, &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .to_owned();
        git(&root, &["checkout", "main"]).unwrap();
        std::fs::write(root.join("conflict"), "main change\n").unwrap();
        git(&root, &["commit", "-am", "main change"]).unwrap();
        let mut dispatch =
            validate_event(&event(), "tjfontaine", &mut owner_collaborator()).unwrap();
        dispatch.base = git(&root, &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .to_owned();
        dispatch.branch = "work/dispatch-634-42".into();
        dispatch.resume = true;
        dispatch.selected_tip = Some(tip.clone());
        let actor = temp.path().join("actor");
        std::fs::create_dir(&actor).unwrap();
        let work = actor.join("work");
        let result = worker_checkout(&root, &temp.path().join("unused"), &work, &dispatch, None);
        assert!(
            result.is_ok(),
            "merge-conflicted dispatch branch refused before worker: {result:?}"
        );
        assert_eq!(git(&work, &["rev-parse", "HEAD"]).unwrap().trim(), tip);
        assert_eq!(
            regular_text(&work.join("conflict")).unwrap(),
            "worker branch\n"
        );
        let prompt = worker_prompt(&dispatch);
        assert!(prompt.contains(&dispatch.base) && prompt.contains("Resolve any conflicts"));
        assert!(prompt.contains(&format!(
            "just check-contract-change {} HEAD",
            dispatch.base
        )));
        assert!(prompt.contains("just cross-check-macos") && prompt.contains("just check-linux"));
        assert!(
            prompt.contains("Leave whole-workspace just lint-domains and just test-kernel to CI")
        );
        assert_eq!(
            git(&work, &["rev-parse", "refs/carrick/dispatch-main"])
                .unwrap()
                .trim(),
            dispatch.base
        );
        assert!(!work.join(".git/rebase-merge").exists());
    }
    #[test]
    fn label_publication_creates_draft_and_continues_the_owned_branch() {
        publication_fixture("original");
    }
    #[test]
    fn created_pr_has_one_closing_line() {
        publication_fixture("closing");
    }
    #[test]
    fn continuation_applies_proposed_body() {
        publication_fixture("body");
    }
    #[test]
    fn p2_rejected_body_still_pushes() {
        publication_fixture("refused");
    }
    #[test]
    fn p2_server_checks_closing_references() {
        publication_fixture("references");
    }
    #[test]
    fn p2_edit_uses_patch_and_retains_ownership() {
        publication_fixture("footer");
    }
    #[test]
    fn p2_body_mentions_are_neutralized() {
        let body = proposed_pr_body(Some("Thanks @alice and @org/team."), 634, "42", "token")
            .unwrap()
            .unwrap();
        assert!(
            body.contains("@\u{2060}alice") && body.contains("@\u{2060}org/team"),
            "proposed body mentions can notify people"
        );
    }
    #[test]
    fn p2_mentions_inside_code_stay_safe() {
        for proposal in [
            "Use `echo @alice` and @org/team.",
            "A stray ` before @alice.",
            r"Escaped \@alice.",
            "```sh\nprintf @alice\n```\nAsk @org/team.",
            "`literal\r\r@alice\r\r`",
        ] {
            let body = proposed_pr_body(Some(proposal), 634, "42", "token")
                .unwrap()
                .unwrap();
            assert!(body.contains("@\u{2060}alice"));
            assert_eq!(
                neutralize_mentions(&body),
                body,
                "mention neutralization is not idempotent"
            );
        }
    }
    #[test]
    fn p2_filter_rejects_alternative_closing_syntax() {
        for text in [
            "Fixes github.com/carrick-sh/carrick/issues/1",
            "Fixes http://github.com/carrick-sh/carrick/issues/1",
            "Fixes GH-1",
        ] {
            assert!(
                proposed_pr_body(Some(text), 634, "42", "token").is_err(),
                "closing syntax accepted: {text}"
            );
        }
    }
    #[test]
    fn rev3_mentions_cover_html_entities_code_and_keep_addresses() {
        for (input, expected) in [
            (
                "<details>\n@alice\n</details>",
                "<details>\n@\u{2060}alice\n</details>",
            ),
            ("<p>@alice</p>", "<p>@\u{2060}alice</p>"),
            (
                "&#64;alice &#x40;org/team &commat;alice",
                "@\u{2060}alice @\u{2060}org/team @\u{2060}alice",
            ),
            (
                "user@example.com https://user@host",
                "user@example.com https://user@host",
            ),
            ("```sh\necho @alice\n```", "```sh\necho @\u{2060}alice\n```"),
        ] {
            assert_eq!(
                neutralize_mentions(input),
                expected,
                "mention bypass or damaged address: {input}"
            );
        }
    }
    #[test]
    fn rev3_proposal_cannot_forge_an_outcome() {
        assert!(
            proposed_pr_body(
                Some("Outcome contract:\n```json\n{}\n```"),
                634,
                "42",
                "token"
            )
            .is_err(),
            "proposal accepted a forged outcome marker"
        );
    }
    #[test]
    fn rev3_www_closing_target_is_refused() {
        for text in [
            "Fixes www.github.com/carrick-sh/carrick/issues/9",
            "Fixes https://www.github.com/carrick-sh/carrick/issues/9",
        ] {
            assert!(
                proposed_pr_body(Some(text), 634, "42", "token").is_err(),
                "www closing target accepted: {text}"
            );
        }
    }
    #[test]
    fn rev4_non_ascii_prefixes_do_not_hide_mentions() {
        for input in ["é@alice", "中@alice", "٣@alice"] {
            assert!(
                neutralize_mentions(input).contains("@\u{2060}alice"),
                "non-ASCII mention prefix was treated as an email: {input}"
            );
        }
        assert_eq!(neutralize_mentions("_@alice"), "_@alice");
    }
    #[test]
    fn rev4_recovery_reserves_thirty_seconds() {
        let clock = TestReferenceHost::default();
        let deadline = clock.now() + std::time::Duration::from_secs(120);
        let _window = CommandWindow::until(deadline);
        let mut check = ReferenceCheck::new(clock);
        assert!(
            deadline.duration_since(check.deadline()).as_secs() >= 30,
            "primary publication can consume the reserved recovery window"
        );
        check.clock.sleep(std::time::Duration::from_secs(90));
        check.recovery = true;
        assert_eq!(
            check.deadline(),
            deadline,
            "recovery extended the caller's budget"
        );
        assert_eq!(
            check.deadline().duration_since(check.clock.now()).as_secs(),
            30,
            "recovery did not retain its own window after primary time was spent"
        );
    }
    #[test]
    fn rev4_commit_filter_allows_own_issue_and_excludes_inherited_commits() {
        let temp = tempfile::tempdir().unwrap();
        fixture_repository(temp.path());
        git(
            temp.path(),
            &["commit", "--allow-empty", "-m", "Fixes #999"],
        )
        .unwrap();
        let since = git(temp.path(), &["rev-parse", "HEAD"]).unwrap();
        for message in [
            "Fixes #634",
            "Closes carrick-sh/carrick#634",
            "Resolves https://github.com/carrick-sh/carrick/issues/634",
        ] {
            git(temp.path(), &["commit", "--allow-empty", "-m", message]).unwrap();
        }
        assert!(check_commit_closures(temp.path(), since.trim(), None, 634).is_ok());
        let safe_tip = git(temp.path(), &["rev-parse", "HEAD"]).unwrap();
        for message in [
            "Fixes #999",
            "Closes other/repo#634",
            "Fixes #634, #999",
            "Fixes https://github.com/other/repo/issues/634",
            "Fixes GH-999",
        ] {
            git(temp.path(), &["commit", "--allow-empty", "-m", message]).unwrap();
            let bad = git(temp.path(), &["rev-parse", "HEAD"]).unwrap();
            let error = check_commit_closures(temp.path(), safe_tip.trim(), None, 634)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(bad.trim()),
                "unsafe commit was not named: {message}"
            );
        }
    }
    #[test]
    fn p823_failed_harvest_body_describes_published_checkpoint() {
        publication_fixture("failed-harvest-body");
    }
    #[test]
    fn p823_double_checkpoint_failure_invalidates_receipt() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        std::fs::create_dir_all(state.join("work")).unwrap();
        let candidate = root.path().join("candidate");
        fixture_repository(&state.join("work"));
        git(
            &state.join("work"),
            &["clone", ".", candidate.to_str().unwrap()],
        )
        .unwrap();
        std::fs::write(candidate.join("new-tree"), "new").unwrap();
        git(&candidate, &["add", "new-tree"]).unwrap();
        git(&candidate, &["commit", "-m", "fix(ci): new candidate"]).unwrap();
        let mut dispatch =
            validate_event(&event(), "tjfontaine", &mut owner_collaborator()).unwrap();
        dispatch.base = git(&state.join("work"), &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .into();
        dispatch.branch = "work/dispatch-634-42".into();
        let receipt = Receipt {
            head: dispatch.base.clone(),
            checkpointed: false,
            base: dispatch.base.clone(),
            branch: dispatch.branch.clone(),
            exit_code: 0,
            expected_tip: String::new(),
            pr_body: None,
            worker: dispatch.worker.clone(),
            contract: Contract {
                loop_summary: None,
                status: ContractStatus::Done,
                summary: "old checkpoint".into(),
                tests: vec![],
                risks: vec![],
            },
        };
        std::fs::write(
            state.join("receipt.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        assert!(
            worker_checkpoint(&state, &dispatch).unwrap().is_some(),
            "old pair was not valid before injection"
        );
        let error = install_worker_checkpoint_with(
            &state,
            &candidate,
            &receipt,
            |_, _| Err(std::io::Error::other("fixture receipt commit failed")),
            |_| Err(std::io::Error::other("fixture rollback removal failed")),
        );
        assert!(error.is_err());
        assert!(
            state.join("work/new-tree").is_file(),
            "double failure was not reached"
        );
        assert!(
            worker_checkpoint(&state, &dispatch).is_err(),
            "double checkpoint failure left a new tree paired with an old receipt"
        );
    }
    #[test]
    fn publish_rebases_onto_main_after_it_changes_workflow_files() {
        publication_fixture("rebase-clean");
    }
    #[test]
    fn publish_keeps_commits_when_the_rebase_conflicts() {
        publication_fixture("rebase-conflict");
    }
    #[test]
    fn followup_worker_workflow_changes_remain_refused() {
        publication_fixture("worker-workflow");
    }
    #[test]
    fn followup_live_main_rebase_excludes_upstream_commits() {
        publication_fixture("live-main-rebase");
    }
    #[test]
    fn followup_live_main_workflows_are_not_worker_edits() {
        publication_fixture("live-main-workflow");
    }
    #[test]
    fn followup_live_main_closures_are_trusted() {
        publication_fixture("live-main-closure");
    }
    #[test]
    fn followup_publication_refuses_worker_closing_another_issue() {
        publication_fixture("worker-closure");
    }
    #[test]
    fn followup_previously_published_closures_are_trusted() {
        publication_fixture("published-closure");
    }
    #[test]
    fn followup_merge_of_main_is_not_reported_as_rebase() {
        publication_fixture("merge-evidence");
    }
    #[test]
    fn followup_pr_commits_mark_only_new_commits() {
        publication_fixture("commit-labels");
    }
    #[test]
    fn followup_proposal_summary_precedes_provenance() {
        publication_fixture("summary-first");
    }
    #[test]
    fn followup_template_summary_precedes_provenance() {
        publication_fixture("template-summary-first");
    }
    #[test]
    fn followup_checkpoint_rejects_mismatched_head() {
        let root = tempfile::tempdir().unwrap();
        let work = root.path().join("work");
        std::fs::create_dir(&work).unwrap();
        fixture_repository(&work);
        let mut dispatch =
            validate_event(&event(), "tjfontaine", &mut owner_collaborator()).unwrap();
        dispatch.base = git(&work, &["rev-parse", "HEAD"]).unwrap().trim().into();
        dispatch.branch = "work/dispatch-634-42".into();
        git(&work, &["checkout", "-b", &dispatch.branch]).unwrap();
        let receipt = Receipt {
            head: dispatch.base.clone(),
            checkpointed: false,
            base: dispatch.base.clone(),
            branch: dispatch.branch.clone(),
            exit_code: 0,
            expected_tip: String::new(),
            pr_body: None,
            worker: Worker::default(),
            contract: Contract {
                loop_summary: None,
                status: ContractStatus::Done,
                summary: "old tree".into(),
                tests: vec![],
                risks: vec![],
            },
        };
        let mut value = serde_json::to_value(&receipt).unwrap();
        value["head"] = dispatch.base.clone().into();
        std::fs::write(root.path().join("receipt.json"), value.to_string()).unwrap();
        assert!(worker_checkpoint(root.path(), &dispatch).unwrap().is_some());
        git(
            &work,
            &["commit", "--allow-empty", "-m", "fix(ci): replace tree"],
        )
        .unwrap();
        assert!(
            worker_checkpoint(root.path(), &dispatch).is_err(),
            "checkpoint admitted a tree whose HEAD differs from its receipt"
        );
    }
    #[test]
    fn p849_rebase_reports_only_pr_commits_and_names_main_base() {
        publication_fixture("rebase-evidence");
    }
    #[test]
    fn rev4_transient_reference_read_is_retried() {
        publication_fixture("transient");
    }
    #[test]
    fn rev4_failed_snapshot_still_pushes_and_names_the_skip() {
        publication_fixture("snapshot-fail");
    }
    #[test]
    fn rev3_create_waits_for_two_settled_reads() {
        publication_fixture("lag");
    }
    #[test]
    fn rev3_any_extra_reference_fails_even_after_a_match() {
        publication_fixture("extra-after-match");
    }
    #[test]
    fn rev3_create_failure_restores_default_body() {
        publication_fixture("create-repair");
    }
    #[test]
    fn rev3_restored_body_neutralizes_legacy_mentions() {
        publication_fixture("restore-html");
    }
    #[test]
    fn rev3_manual_owner_links_survive_a_body_edit() {
        publication_fixture("manual");
    }
    #[test]
    fn rev3_reference_wait_uses_command_window() {
        publication_fixture("window");
    }
    #[test]
    fn rev3_reference_wait_has_a_deadline() {
        publication_fixture("timeout");
    }
    #[test]
    fn shared_app_pr_without_publication_binding_is_not_owned() {
        let event = review_event();
        let mut pr = event["pull_request"].clone();
        pr["user"]["login"] = "carrick-workers[bot]".into();
        assert!(
            !owned_pr(
                &pr,
                &event["dispatch_run"],
                634,
                "work/dispatch-634-42",
                None,
                &mut owner_collaborator(),
            ),
            "shared App PR without authenticated publication_pr is owned"
        );
    }
    #[test]
    fn publish_recovery_create_on_prior_branch_remains_owned() {
        publication_fixture("publish-token-recovery-create");
    }
    #[test]
    fn adopted_publication_pushes_commits_only() {
        publication_fixture("adopted");
    }
    #[test]
    fn adopted_publication_refuses_a_moved_head_without_pushing() {
        publication_fixture("adopted-moved");
    }
    #[test]
    fn adopted_publication_lease_rejection_ends_blocked() {
        publication_fixture("adopted-race");
    }
    #[test]
    fn adopted_publication_refuses_a_rewritten_history() {
        publication_fixture("adopted-rewrite");
    }
    #[test]
    fn adopted_publication_pushes_a_consented_rebase_under_the_lease() {
        publication_fixture("adopted-rebase");
    }
    #[test]
    fn adopted_publication_refuses_a_consented_rebase_that_drops_director_commits() {
        publication_fixture("adopted-rebase-drop");
    }
    #[test]
    fn adopted_publication_measures_a_consented_rebase_from_the_rebased_director_tip() {
        publication_fixture("adopted-rebase-main-moved");
    }
    #[test]
    fn adopted_publication_refuses_a_consented_rebase_that_empties_a_director_commit() {
        publication_fixture("adopted-rebase-empty");
    }
    #[test]
    fn adopted_publication_refuses_a_consented_rebase_that_drops_a_director_path() {
        publication_fixture("adopted-rebase-path");
    }
    #[test]
    fn adopted_publication_keeps_a_consented_rebase_that_main_already_contains() {
        publication_fixture("adopted-rebase-upstream");
    }
    #[test]
    fn adopted_publication_refuses_run_work_hidden_in_a_rebased_director_commit() {
        publication_fixture("adopted-rebase-hidden");
    }
    #[test]
    fn adopted_publication_refuses_a_rebased_director_commit_with_a_new_message() {
        publication_fixture("adopted-rebase-message");
    }
    #[test]
    fn adopted_publication_refuses_a_merge_in_a_consented_rebase() {
        publication_fixture("adopted-rebase-merge");
    }
    #[test]
    fn adopted_publication_refuses_a_consented_rewrite_off_main() {
        publication_fixture("adopted-rebase-off-main");
    }
    #[test]
    fn adopted_publication_is_not_charged_for_director_history() {
        publication_fixture("adopted-director-history");
    }
    #[test]
    fn adopted_second_push_in_one_run_advances_the_lease() {
        publication_fixture("adopted-second-push");
    }
    #[test]
    fn adopted_second_push_refuses_a_foreign_push_between() {
        publication_fixture("adopted-second-moved");
    }
    #[test]
    fn adopted_second_push_refuses_rewriting_the_pushed_tip() {
        publication_fixture("adopted-second-rewrite");
    }
    #[test]
    fn publish_auth_failure_on_push_falls_back_once() {
        publication_fixture("publish-token-auth-push");
    }
    #[test]
    fn publish_auth_failure_on_create_after_push_falls_back_once() {
        publication_fixture("publish-token-auth-create");
    }
    #[test]
    fn publish_auth_failure_on_patch_falls_back_once() {
        publication_fixture("publish-token-auth-patch");
    }
    #[test]
    fn publish_auth_failure_on_patch_without_push_needs_ci_note() {
        publication_fixture("publish-token-auth-patch-no-push");
    }
    #[test]
    fn job_token_report_names_why_the_app_token_was_not_used() {
        let mut applied = Applied {
            ci_requires_owner: true,
            ..Applied::default()
        };
        assert!(applied.report().contains("reason not recorded"));
        applied.token_fallback = Some(TokenFallback::MintUnavailable {
            reason: crate::dispatch_mint::MintUnavailable::Timeout,
        });
        assert!(
            applied
                .report()
                .contains("could not be minted: controller did not answer in time")
        );
        applied.token_fallback = Some(TokenFallback::MintRefused {
            reason: crate::ci_scaler::mint::MintRefusal::BudgetExhausted,
        });
        assert!(
            applied
                .report()
                .contains("refused the publish token: per-job mint budget exhausted")
        );
        applied.token_fallback = Some(TokenFallback::Rejected {
            operation: PublishEvent::PrCreate.label().into(),
            class: "http 401".into(),
        });
        assert!(
            applied
                .report()
                .contains("rejected during pr_create (http 401)")
        );
    }
    #[test]
    fn publish_lease_rejection_is_not_retried_or_labelled_permission() {
        publication_fixture("publish-token-lease");
    }
    #[test]
    fn publish_network_error_is_not_labelled_permission() {
        publication_fixture("publish-token-network");
    }
    #[test]
    fn publish_noop_does_not_claim_job_token_fallback() {
        publication_fixture("publish-empty-noop");
    }
    #[test]
    fn publish_token_app_pr_retains_authenticated_dispatch_ownership() {
        let event = review_event();
        let mut pr = event["pull_request"].clone();
        let publication = PublishedPr(PublicationRecord {
            issue: 634,
            branch: "work/dispatch-634-42".into(),
            publication_pr: 800,
        });
        pr["user"]["login"] = "carrick-workers[bot]".into();
        assert!(owned_pr(
            &pr,
            &event["dispatch_run"],
            634,
            "work/dispatch-634-42",
            Some(&publication),
            &mut owner_collaborator(),
        ));
        pr["user"]["login"] = "another-app[bot]".into();
        assert!(!owned_pr(
            &pr,
            &event["dispatch_run"],
            634,
            "work/dispatch-634-42",
            Some(&publication),
            &mut owner_collaborator(),
        ));
    }
    #[test]
    fn publish_token_authenticates_create_and_continuation_writes() {
        publication_fixture("publish-token");
    }
    #[test]
    fn publish_token_push_refusal_names_app_permissions() {
        publication_fixture("publish-token-refused");
    }
    #[test]
    fn missing_publish_token_keeps_publication_and_reports_ci_gap() {
        publication_fixture("publish-missing");
    }
    #[test]
    fn refused_publish_mint_keeps_publication_and_records_its_reason() {
        publication_fixture("publish-mint-refused");
    }
    fn publication_fixture(witness: &str) {
        publication_fixture_outcome(witness, |_, _| {});
    }
    pub(super) fn publication_fixture_outcome(witness: &str, outcome: impl Fn(&Path, &Dispatch)) {
        const CHILD: &str = "CARRICK_TEST_DISPATCH_PUBLICATION";
        if std::env::var_os(CHILD).is_none() {
            let temp = tempfile::tempdir().unwrap();
            let bin = temp.path().join("bin");
            std::fs::create_dir(&bin).unwrap();
            for (name, script) in [
                (
                    "git",
                    r#"#!/bin/sh
authenticated=0
for arg do
 case "$arg" in
 'credential.helper=!gh auth git-credential') authenticated=1 ;;
 fetch)
   if test "$authenticated" = 1; then
     test "$GH_TOKEN" = fixture-token || exit 96
     for ref do :; done
     printf '%s\n' "$@" >> "$RUNNER_TEMP/server-fetch.args"
     exec /usr/bin/git fetch --no-tags "$RUNNER_TEMP/live-main.git" "$ref"
   fi ;;
 ls-remote)
   for ref do :; done
   if test "$ref" = refs/heads/main; then
     test "$GH_TOKEN" = fixture-token || exit 96
     exec /usr/bin/git ls-remote "$RUNNER_TEMP/live-main.git" refs/heads/main
   fi
   if test -f "$RUNNER_TEMP/remote-tip"; then cat "$RUNNER_TEMP/remote-tip"; fi; exit 0 ;;
 push)
 kind=app; test "$GH_TOKEN" != fixture-token || kind=job
 printf '%s\n' "$kind" >> "$RUNNER_TEMP/push-attempts"
 if test -f "$RUNNER_TEMP/publish-mode"; then
  mode=$(cat "$RUNNER_TEMP/publish-mode")
  if test "$mode" = publish-token-auth-push && test "$kind" = app; then touch "$RUNNER_TEMP/publish-fallback"; echo 'fatal: Authentication failed' >&2; exit 87; fi
  if test "$mode" = publish-token-lease; then test ! -f "$RUNNER_TEMP/race-tip" || cp "$RUNNER_TEMP/race-tip" "$RUNNER_TEMP/remote-tip"; echo 'rejected: stale info (lease rejection)' >&2; exit 86; fi
  if test "$mode" = publish-token-network; then echo 'fatal: unable to access remote: Could not resolve host' >&2; exit 85; fi
 fi
 if test -f "$RUNNER_TEMP/publish-fallback"; then expected=fixture-token; else expected=${DISPATCH_TEST_WRITE_TOKEN:-fixture-token}; fi
 test "$GH_TOKEN" = "$expected" || { echo 'push did not use publish credential' >&2; exit 89; }
 if test -f "$RUNNER_TEMP/refuse-push"; then echo 'refusing to allow a GitHub App to create or update workflow without `workflows` permission' >&2; exit 88; fi
 printf '%s\n' "$@" >> "$RUNNER_TEMP/push.args"; /usr/bin/git rev-parse HEAD > "$RUNNER_TEMP/remote-tip"; exit 0 ;;
 esac
done
exec /usr/bin/git "$@"
"#,
                ),
                (
                    "gh",
                    r#"#!/bin/sh
printf '%s\n' "$@" >> "$RUNNER_TEMP/gh.args"
case "$1 $2 $3" in
 'pr create '*|'api -X PATCH') expected=${DISPATCH_TEST_WRITE_TOKEN:-fixture-token} ;;
 *) expected=fixture-token ;;
esac
if test -f "$RUNNER_TEMP/publish-fallback"; then expected=fixture-token; fi
if test "$1 $2" = 'pr create' && test -f "$RUNNER_TEMP/publish-mode" && test "$(cat "$RUNNER_TEMP/publish-mode")" = publish-token-recovery-create; then expected=fixture-token; fi
if test "$1 $2" = 'pr create' && test -f "$RUNNER_TEMP/publish-mode"; then
 kind=app; test "$GH_TOKEN" != fixture-token || kind=job
 printf '%s\n' "$kind" >> "$RUNNER_TEMP/create-attempts"
 if test "$(cat "$RUNNER_TEMP/publish-mode")" = publish-token-auth-create && test "$kind" = app; then touch "$RUNNER_TEMP/publish-fallback"; echo 'gh: Bad credentials (HTTP 401)' >&2; exit 84; fi
fi
test "$GH_TOKEN" = "$expected" || { echo 'GitHub call used wrong credential' >&2; exit 89; }
if test "$1" = api; then
 case "$2" in
 -X)
 test "$3" = PATCH || exit 96
 if test -f "$RUNNER_TEMP/publish-mode"; then
  kind=app; test "$GH_TOKEN" != fixture-token || kind=job
  printf '%s\n' "$kind" >> "$RUNNER_TEMP/patch-attempts"
  if test "$(cat "$RUNNER_TEMP/publish-mode")" = publish-token-auth-patch && test "$kind" = app; then touch "$RUNNER_TEMP/publish-fallback"; echo 'gh: Bad credentials (HTTP 401)' >&2; exit 84; fi
 fi
 test ! -f "$RUNNER_TEMP/fail-edit" || exit 94
 if test -f "$RUNNER_TEMP/reference-mode" && test "$(cat "$RUNNER_TEMP/reference-mode")" = restore-fail && test "$(cat "$RUNNER_TEMP/body-writes")" = 2; then exit 98; fi
 cp "${6#body=@}" "$RUNNER_TEMP/applied-body.md"
 /usr/bin/python3 -c 'import pathlib,sys;r=pathlib.Path(sys.argv[1]);p=r/"body-writes";p.write_text(str(int(p.read_text())+1));(r/"phase-reads").unlink(missing_ok=True)' "$RUNNER_TEMP"
 ;;
 graphql)
 test "$GH_TOKEN" = fixture-token || exit 97
 /usr/bin/python3 - "$RUNNER_TEMP" <<'REFS'
import json,pathlib,sys
r=pathlib.Path(sys.argv[1]); m=(r/"reference-mode").read_text() if (r/"reference-mode").exists() else ""
w=int((r/"body-writes").read_text()) if (r/"body-writes").exists() else 0
p=r/"phase-reads"; n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))
with (r/"reference-reads.jsonl").open("a") as f:f.write(json.dumps({"write":w,"read":n})+"\n")
all_refs=body_refs=[634]
if (r/"two-references").exists(): all_refs=body_refs=[634,999]
if m=="transient" and w==1 and n%2==1: sys.exit(95)
if m=="snapshot-fail" and w==1: sys.exit(95)
if m=="lag" and w==1 and n<=2: all_refs=body_refs=[]
if m=="extra-after-match" and w==1 and n>=2: all_refs=body_refs=[634,999]
if m=="create-repair" and w==1: all_refs=body_refs=[634,999]
if m=="timeout" and w==1: all_refs=body_refs=[]
if m=="manual": all_refs=[634,999]; body_refs=[634]
if m=="restore-fail" and w==2: all_refs=body_refs=[634,999]
def conn(ns):return {"nodes":[{"number":n,"repository":{"nameWithOwner":"carrick-sh/carrick"}} for n in ns],"pageInfo":{"hasNextPage":False}}
print(json.dumps({"data":{"repository":{"pullRequest":{"closingIssuesReferences":conn(all_refs),"bodyReferences":conn(body_refs)}}}}))
REFS
 ;;
 */collaborators/tjfontaine/permission) echo '{"permission":"admin","role_name":"admin"}' ;;
 */pulls/800) cat "$RUNNER_TEMP/adopted-pr.json" ;;
 */issues/634) cat "$RUNNER_TEMP/adopted-issue.json" ;;
 */actions/runs/42) cat "$RUNNER_TEMP/original.json" ;;
 */actions/runs/42/jobs*) echo '{"jobs":[{"name":"worker","status":"completed","runner_name":"carrick-agent-123","steps":[{"name":"Run actions/upload-artifact@v4","status":"completed","conclusion":"success"}]}]}' ;;
 *'/pulls?'*) if test -f "$RUNNER_TEMP/created"; then cat "$RUNNER_TEMP/pr.json"; else echo '[]'; fi ;;
 *) exit 91 ;;
 esac
elif test "$1 $2" = 'issue comment'; then
 printf '%s' "$3" > "$RUNNER_TEMP/posted-on"
 while test "$1" != --body-file; do shift; done
 cp "$2" "$RUNNER_TEMP/posted.md"
elif test "$1 $2" = 'pr edit'; then
 test ! -f "$RUNNER_TEMP/fail-edit" || exit 94
 while test "$1" != --body-file; do shift; done
 cp "$2" "$RUNNER_TEMP/applied-body.md"
elif test "$1 $2" = 'pr create'; then
 test ! -f "$RUNNER_TEMP/created" || exit 92
 touch "$RUNNER_TEMP/created"
 if test "$GH_TOKEN" = fixture-token; then
  /usr/bin/python3 - "$RUNNER_TEMP/pr.json" <<'AUTHOR'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);prs=json.loads(p.read_text());prs[0]["user"]["login"]="github-actions[bot]";p.write_text(json.dumps(prs))
AUTHOR
 fi
 echo 1 > "$RUNNER_TEMP/body-writes"
 rm -f "$RUNNER_TEMP/phase-reads"
 while test "$1" != --body-file; do shift; done
 cp "$2" "$RUNNER_TEMP/created-body.md"
 echo 'https://github.com/carrick-sh/carrick/pull/800'
else exit 93
fi
"#,
                ),
            ] {
                let path = bin.join(name);
                crate::lock_file::tests::write_test_executable(
                    path,
                    script,
                    std::fs::Permissions::from_mode(0o700),
                );
            }
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    std::thread::current().name().unwrap(),
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env_remove("DISPATCH_PUBLISH_TOKEN")
                .env_remove("CARRICK_TEST_MINT_PUBLISH")
                .env_remove("CARRICK_TEST_MINT_STATE")
                .envs(if witness.starts_with("publish-token") {
                    vec![
                        ("CARRICK_TEST_MINT_PUBLISH", "opaque-publish-credential"),
                        ("DISPATCH_TEST_WRITE_TOKEN", "opaque-publish-credential"),
                    ]
                } else if witness == "publish-mint-refused" {
                    vec![("CARRICK_TEST_MINT_PUBLISH", "refused:job_not_in_progress")]
                } else {
                    vec![]
                })
                .env("GH_TOKEN", "fixture-token")
                .env("RUNNER_TEMP", temp.path())
                .env(
                    "GITHUB_RUN_ID",
                    if matches!(witness, "footer" | "publish-token-recovery-create") {
                        "999"
                    } else {
                        "42"
                    },
                )
                .env("GITHUB_RUN_ATTEMPT", "1")
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout).to_string()
                    + &String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let outer = PathBuf::from(std::env::var_os("RUNNER_TEMP").unwrap());
        let state = crate::agent_runner::state().unwrap();
        let work = state.join("work");
        std::fs::create_dir_all(&work).unwrap();
        fixture_repository(&work);
        git(
            &work,
            &[
                "clone",
                "--bare",
                ".",
                outer.join("live-main.git").to_str().unwrap(),
            ],
        )
        .unwrap();
        git(
            &work,
            &[
                "--git-dir",
                outer.join("live-main.git").to_str().unwrap(),
                "update-ref",
                "refs/heads/main",
                "HEAD",
            ],
        )
        .unwrap();
        // #1215 review P1: main moves after the director forked, with a
        // workflow change and another issue's closing keyword; neither is
        // the round's.
        let director_fork = git(&work, &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .to_owned();
        if witness == "adopted-rebase-upstream" {
            // Main already has the director's patch, under another subject.
            std::fs::write(work.join("slice.txt"), "director v1\n").unwrap();
            git(&work, &["add", "slice.txt"]).unwrap();
            git(&work, &["commit", "-m", "chore: land the slice on main"]).unwrap();
            git(
                &work,
                &[
                    "--git-dir",
                    outer.join("live-main.git").to_str().unwrap(),
                    "fetch",
                    work.to_str().unwrap(),
                    "HEAD:refs/heads/main",
                ],
            )
            .unwrap();
        }
        if witness == "adopted-rebase-main-moved" {
            std::fs::create_dir_all(work.join(".github/workflows")).unwrap();
            std::fs::write(work.join(".github/workflows/main.yml"), "on: push\n").unwrap();
            git(&work, &["add", ".github/workflows/main.yml"]).unwrap();
            git(&work, &["commit", "-m", "ci: main workflow"]).unwrap();
            git(
                &work,
                &[
                    "commit",
                    "--allow-empty",
                    "-m",
                    "fix(core): main fix\n\nCloses #999",
                ],
            )
            .unwrap();
            git(
                &work,
                &[
                    "--git-dir",
                    outer.join("live-main.git").to_str().unwrap(),
                    "fetch",
                    work.to_str().unwrap(),
                    "HEAD:refs/heads/main",
                ],
            )
            .unwrap();
        }
        let base = git(&work, &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .to_owned();
        let mut event = event();
        event["label"]["name"] = "dispatch".into();
        let mut dispatch = validate_event(&event, "tjfontaine", &mut owner_collaborator()).unwrap();
        dispatch.base = base.clone();
        assigned_branch(&mut dispatch).unwrap();
        if matches!(witness, "footer" | "publish-token-recovery-create") {
            dispatch.branch = "work/dispatch-634-42".into();
        }
        assert_eq!(dispatch.branch, "work/dispatch-634-42");
        git(&work, &["checkout", "-b", &dispatch.branch]).unwrap();
        let subject = "fix(ci): implement the owner issue";
        git(&work, &["commit", "--allow-empty", "-m", subject]).unwrap();
        let mut pr = json!({"state":"open","number":800,"user":{"login":"github-actions[bot]","type":"Bot"},"head":{"ref":dispatch.branch,"repo":{"full_name":REPOSITORY}},"base":{"ref":"main"},"draft":true,"body":format!("Closes #634\nDispatch run: https://github.com/{REPOSITORY}/actions/runs/42")});
        if witness == "restore-html" {
            pr["body"] = format!("Legacy <p>@alice</p>\nCloses #634\nDispatch run: https://github.com/{REPOSITORY}/actions/runs/42").into();
        }
        if witness.starts_with("publish-token") {
            pr["user"]["login"] = "carrick-workers[bot]".into();
        }
        let mut run = review_event()["dispatch_run"].clone();
        run["status"] = "completed".into();
        std::fs::write(outer.join("original.json"), run.to_string()).unwrap();
        std::fs::write(outer.join("pr.json"), json!([pr.clone()]).to_string()).unwrap();
        let mut contract = Contract {
            loop_summary: None,
            status: ContractStatus::Done,
            summary: "implemented".into(),
            tests: vec![],
            risks: vec![],
        };
        let mut receipt = Receipt {
            checkpointed: false,
            head: git(&work, &["rev-parse", "HEAD"]).unwrap().trim().into(),
            base,
            branch: dispatch.branch.clone(),
            exit_code: 0,
            expected_tip: String::new(),
            pr_body: None,
            worker: dispatch.worker.clone(),
            contract: contract.clone(),
        };
        if witness == "failed-harvest-body" {
            contract.summary =
                "Worker production/harvest failed: latest candidate discarded".into();
            contract.status = ContractStatus::Failed;
        }
        let report = state.join("report.md");
        std::fs::write(&report, "").unwrap();
        if witness.starts_with("adopted") {
            let branch = "work/634-slice";
            git(&work, &["checkout", "-B", branch, &director_fork]).unwrap();
            if witness == "adopted-director-history" {
                // Director history below the tip: a closing reference to
                // another issue and a workflow change main does not have.
                std::fs::create_dir_all(work.join(".github/workflows")).unwrap();
                std::fs::write(work.join(".github/workflows/director.yml"), "on: push\n").unwrap();
                git(&work, &["add", ".github/workflows/director.yml"]).unwrap();
                git(
                    &work,
                    &["commit", "-m", "ci: director workflow\n\nFixes #999"],
                )
                .unwrap();
            }
            // Content witnesses give the director's slice a real change.
            let content = matches!(
                witness,
                "adopted-rebase-main-moved"
                    | "adopted-rebase-empty"
                    | "adopted-rebase-path"
                    | "adopted-rebase-hidden"
                    | "adopted-rebase-upstream"
            );
            if content {
                std::fs::write(work.join("slice.txt"), "director v1\n").unwrap();
                git(&work, &["add", "slice.txt"]).unwrap();
            }
            if witness == "adopted-rebase-path" {
                std::fs::write(work.join("keep.txt"), "director v1\n").unwrap();
                git(&work, &["add", "keep.txt"]).unwrap();
            }
            git(
                &work,
                &[
                    "commit",
                    "--allow-empty",
                    "-m",
                    "refactor(core): director slice",
                ],
            )
            .unwrap();
            let tip = git(&work, &["rev-parse", "HEAD"])
                .unwrap()
                .trim()
                .to_owned();
            let live = if witness == "adopted-moved" {
                "d".repeat(40)
            } else {
                tip.clone()
            };
            std::fs::write(
                outer.join("remote-tip"),
                format!("{live}\trefs/heads/{branch}\n"),
            )
            .unwrap();
            git(
                &work,
                &[
                    "commit",
                    "--allow-empty",
                    "-m",
                    "fix(core): continue the slice",
                ],
            )
            .unwrap();
            if matches!(
                witness,
                "adopted-rebase-main-moved"
                    | "adopted-rebase-empty"
                    | "adopted-rebase-path"
                    | "adopted-rebase-hidden"
            ) {
                git(&work, &["reset", "--hard", &receipt.base]).unwrap();
                // main-moved: the conflict was resolved, so the patch
                // changed. empty: the commit kept its name, lost its work.
                // path: the work landed in another file.
                match witness {
                    "adopted-rebase-main-moved" => {
                        std::fs::write(work.join("slice.txt"), "director v1 resolved\n").unwrap();
                        git(&work, &["add", "slice.txt"]).unwrap();
                    }
                    "adopted-rebase-path" => {
                        // Keeps one of the director's two files.
                        std::fs::write(work.join("keep.txt"), "director v1\n").unwrap();
                        git(&work, &["add", "keep.txt"]).unwrap();
                    }
                    "adopted-rebase-hidden" => {
                        // The director's change, plus the run's own work
                        // hidden inside the director's commit.
                        std::fs::write(work.join("slice.txt"), "director v1\n").unwrap();
                        std::fs::write(work.join("elsewhere.txt"), "run work\n").unwrap();
                        git(&work, &["add", "slice.txt", "elsewhere.txt"]).unwrap();
                    }
                    _ => {}
                }
                for subject in [
                    "refactor(core): director slice",
                    "fix(core): continue the slice",
                ] {
                    git(
                        &work,
                        &[
                            "commit",
                            "--allow-empty",
                            "--date=2026-01-01T00:00:00Z",
                            "-m",
                            subject,
                        ],
                    )
                    .unwrap();
                }
            }
            if witness == "adopted-rebase-merge" {
                // The director's commit re-created, then merged with a side
                // commit whose message closes another issue.
                git(&work, &["reset", "--hard", &receipt.base]).unwrap();
                git(
                    &work,
                    &[
                        "commit",
                        "--allow-empty",
                        "--date=2026-01-01T00:00:00Z",
                        "-m",
                        "refactor(core): director slice",
                    ],
                )
                .unwrap();
                let director = git(&work, &["rev-parse", "HEAD"]).unwrap();
                git(&work, &["checkout", "-q", "--detach", &receipt.base]).unwrap();
                git(&work, &["commit", "--allow-empty", "-m", "side"]).unwrap();
                let side = git(&work, &["rev-parse", "HEAD"]).unwrap();
                git(&work, &["checkout", "-q", branch]).unwrap();
                git(&work, &["reset", "--hard", director.trim()]).unwrap();
                git(
                    &work,
                    &[
                        "merge",
                        "--no-ff",
                        "-m",
                        "merge\n\nCloses #999",
                        side.trim(),
                    ],
                )
                .unwrap();
            }
            if witness == "adopted-rebase-message" {
                // Same author and subject, but the message gained another
                // issue's closing keyword.
                git(&work, &["reset", "--hard", &receipt.base]).unwrap();
                git(
                    &work,
                    &[
                        "commit",
                        "--allow-empty",
                        "--date=2026-01-01T00:00:00Z",
                        "-m",
                        "refactor(core): director slice\n\nCloses #999",
                    ],
                )
                .unwrap();
            }
            if witness == "adopted-rebase-upstream" {
                // A plain rebase drops the director's commit main already
                // has; only the worker's commit remains above main.
                git(&work, &["reset", "--hard", &receipt.base]).unwrap();
                git(
                    &work,
                    &[
                        "commit",
                        "--allow-empty",
                        "-m",
                        "fix(core): continue the slice",
                    ],
                )
                .unwrap();
            }
            if witness == "adopted-rebase" {
                // A real rebase: the director's commit is re-created above
                // admitted main (same author and subject, new SHA), then the
                // worker's own commit.
                git(&work, &["reset", "--hard", &receipt.base]).unwrap();
                for subject in [
                    "refactor(core): director slice",
                    "fix(core): continue the slice",
                ] {
                    // A new date makes a new SHA, as a real rebase would.
                    git(
                        &work,
                        &[
                            "commit",
                            "--allow-empty",
                            "--date=2026-01-01T00:00:00Z",
                            "-m",
                            subject,
                        ],
                    )
                    .unwrap();
                }
            }
            if matches!(witness, "adopted-rewrite" | "adopted-rebase-drop") {
                // The worker replaced the director's tip instead of adding
                // to it: the director's commit is gone.
                git(&work, &["reset", "--hard", &receipt.base]).unwrap();
                git(
                    &work,
                    &[
                        "commit",
                        "--allow-empty",
                        "-m",
                        "refactor(core): rewritten slice",
                    ],
                )
                .unwrap();
            }
            if witness == "adopted-rebase-off-main" {
                // A consented rewrite that is not a rebase onto main.
                let tree = git(&work, &["hash-object", "-t", "tree", "/dev/null"]).unwrap();
                let orphan = git(
                    &work,
                    &["commit-tree", tree.trim(), "-m", "chore: unrelated history"],
                )
                .unwrap();
                git(&work, &["reset", "--hard", orphan.trim()]).unwrap();
            }
            if witness == "adopted-race" {
                // Someone pushes while ours is in flight: the lease rejects it.
                std::fs::write(outer.join("publish-mode"), "publish-token-lease").unwrap();
                std::fs::write(
                    outer.join("race-tip"),
                    format!("{}\trefs/heads/{branch}\n", "e".repeat(40)),
                )
                .unwrap();
            }
            dispatch.branch = branch.into();
            dispatch.resume = true;
            dispatch.continuation = Continuation::Adopted {
                rebase: witness.starts_with("adopted-rebase"),

                pr: 800,
                branch: branch.into(),
                tip: tip.clone(),
            };
            let adopted = json!({"state":"open","number":800,"draft":true,"user":{"login":"carrick-workers[bot]","type":"Bot"},
                "head":{"ref":branch,"sha":live,"repo":{"full_name":REPOSITORY}},
                "base":{"ref":"main","repo":{"full_name":REPOSITORY}},"body":"Director body\n\nCloses #634"});
            std::fs::write(outer.join("adopted-pr.json"), adopted.to_string()).unwrap();
            std::fs::write(
                outer.join("adopted-issue.json"),
                json!({"number":634,"state":"open","user":{"login":"tjfontaine","type":"User"}})
                    .to_string(),
            )
            .unwrap();
            std::fs::write(outer.join("pr.json"), json!([adopted]).to_string()).unwrap();
            std::fs::write(outer.join("created"), "").unwrap();
            receipt.head = git(&work, &["rev-parse", "HEAD"]).unwrap().trim().into();
            receipt.branch = branch.into();
            receipt.expected_tip = tip.clone();
            receipt.pr_body = Some("A worker's rewrite of the director's body.".into());
            let result = publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token",
                &mut agent_loop::RunCache::default(),
            );
            let calls = regular_text(&outer.join("gh.args")).unwrap_or_default();
            assert!(
                !calls.contains("create") && !calls.contains("PATCH") && !calls.contains("edit"),
                "adopted publication wrote PR metadata: {calls}"
            );
            let applied = Applied::load().unwrap();
            assert_eq!(applied.publication_pr, None);
            if witness.starts_with("adopted-second") {
                // The first push of the run fast-forwards from the admitted tip.
                assert_eq!(result.unwrap(), Some(800));
                let first = receipt.head.clone();
                assert_eq!(regular_text(&state.join("published-tip")).unwrap(), first);
                std::fs::write(outer.join("push.args"), "").unwrap();
                match witness {
                    "adopted-second-moved" => std::fs::write(
                        outer.join("remote-tip"),
                        format!("{}\trefs/heads/{branch}\n", "f".repeat(40)),
                    )
                    .unwrap(),
                    "adopted-second-rewrite" => {
                        git(&work, &["reset", "--hard", &tip]).unwrap();
                    }
                    _ => {}
                }
                git(
                    &work,
                    &["commit", "--allow-empty", "-m", "fix(core): second worker"],
                )
                .unwrap();
                receipt.head = git(&work, &["rev-parse", "HEAD"]).unwrap().trim().into();
                let second = publish(
                    &work,
                    &dispatch,
                    &receipt,
                    &contract,
                    &report,
                    "fixture-token",
                    &mut agent_loop::RunCache::default(),
                );
                let push = regular_text(&outer.join("push.args")).unwrap();
                if witness == "adopted-second-push" {
                    assert_eq!(second.unwrap(), Some(800));
                    assert!(
                        push.contains(&format!("--force-with-lease=refs/heads/{branch}:{first}\n")),
                        "second push did not lease the run's own pushed tip: {push}"
                    );
                    assert_eq!(
                        regular_text(&state.join("published-tip")).unwrap(),
                        receipt.head
                    );
                    assert_eq!(Applied::load().unwrap().adoption_blocked, None);
                } else {
                    let error = second.unwrap_err().to_string();
                    let expected = if witness == "adopted-second-rewrite" {
                        "rewrote history"
                    } else {
                        "moved after admission"
                    };
                    assert!(error.contains(expected), "{error}");
                    assert!(
                        push.is_empty(),
                        "pushed over a moved or rewritten tip: {push}"
                    );
                    assert!(Applied::load().unwrap().adoption_blocked.is_some());
                    assert_eq!(regular_text(&state.join("published-tip")).unwrap(), first);
                }
                return;
            }
            if matches!(
                witness,
                "adopted-rebase" | "adopted-rebase-main-moved" | "adopted-rebase-upstream"
            ) {
                // Consent (#1215): the rebased history is pushed, still only
                // under the lease that starts at the admitted tip.
                assert_eq!(result.unwrap(), Some(800), "{}", applied.report());
                let push = regular_text(&outer.join("push.args")).unwrap();
                assert!(
                    push.contains(&format!("--force-with-lease=refs/heads/{branch}:{tip}\n")),
                    "{push}"
                );
                assert_eq!(
                    applied.rebased_onto.as_deref(),
                    Some(dispatch.base.as_str())
                );
                assert!(
                    applied.report().contains("Rebased onto main"),
                    "{}",
                    applied.report()
                );
                assert_eq!(applied.adoption_blocked, None);
                // Only the worker's own commit is the round's: main's
                // workflow and closing commits and the rebased director
                // commit are not.
                assert_eq!(applied.commits.len(), 1, "{}", applied.report());
                assert!(applied.rebase_tip.is_some());
                assert!(
                    witness == "adopted-rebase-upstream"
                        || applied
                            .rebase_range_diff
                            .as_deref()
                            .is_some_and(|r| r.contains("director slice")),
                    "{:?}",
                    applied.rebase_range_diff
                );
                if witness == "adopted-rebase-main-moved" {
                    // The resolved director commit is listed for review.
                    assert_eq!(applied.rebase_changed.len(), 1, "{}", applied.report());
                    assert!(
                        applied.report().contains("patch changed while rebasing"),
                        "{}",
                        applied.report()
                    );
                }
                return;
            }
            if matches!(witness, "adopted" | "adopted-director-history") {
                assert_eq!(result.unwrap(), Some(800));
                assert_eq!(
                    applied.commits,
                    vec![receipt.head.clone()],
                    "director commits charged to the run"
                );
                let push = regular_text(&outer.join("push.args")).unwrap();
                assert!(
                    push.contains(&format!("HEAD:refs/heads/{branch}\n")),
                    "{push}"
                );
                assert!(
                    push.contains(&format!("--force-with-lease=refs/heads/{branch}:{tip}\n")),
                    "{push}"
                );
                assert!(
                    matches!(&applied.body, AppliedBody::Refused { reason, template_created: false } if reason.contains("adopted PR")),
                    "{}",
                    applied.report()
                );
                assert_eq!(applied.adoption_blocked, None);
            } else {
                let error = result.unwrap_err().to_string();
                let expected = match witness {
                    "adopted-rewrite" => "did not consent to a rebase",
                    "adopted-rebase-off-main" => "does not descend from admitted main",
                    "adopted-rebase-drop" => "dropped or reordered the director's commit",
                    "adopted-rebase-empty" => "with an empty commit",
                    "adopted-rebase-path" => "dropped the director's change to `slice.txt`",
                    "adopted-rebase-hidden" => {
                        "changed `elsewhere.txt` in the director's commits, which the director never changed"
                    }
                    "adopted-rebase-message" => "dropped or reordered the director's commit",
                    "adopted-rebase-merge" => "left a merge commit",
                    _ => "moved after admission",
                };
                assert!(error.contains(expected), "{error}");
                assert!(
                    applied.report().contains("Push refused"),
                    "{}",
                    applied.report()
                );
                assert!(applied.adoption_blocked.is_some());
                assert!(applied.commits.is_empty());
                assert!(!state.join("published-tip").exists());
                if matches!(
                    witness,
                    "adopted-moved"
                        | "adopted-rewrite"
                        | "adopted-rebase-off-main"
                        | "adopted-rebase-drop"
                        | "adopted-rebase-empty"
                        | "adopted-rebase-path"
                        | "adopted-rebase-hidden"
                        | "adopted-rebase-message"
                        | "adopted-rebase-merge"
                ) {
                    assert!(
                        !outer.join("push-attempts").exists(),
                        "pushed over a moved head"
                    );
                }
            }
            return;
        }
        if matches!(
            witness,
            "publish-token-auth-push"
                | "publish-token-recovery-create"
                | "publish-token-auth-create"
                | "publish-token-auth-patch"
                | "publish-token-auth-patch-no-push"
                | "publish-token-lease"
                | "publish-token-network"
                | "publish-empty-noop"
        ) {
            let mode = if witness.starts_with("publish-token-auth-patch") {
                "publish-token-auth-patch"
            } else {
                witness
            };
            std::fs::write(outer.join("publish-mode"), mode).unwrap();
            if witness == "publish-token-recovery-create" {
                std::fs::write(outer.join("remote-tip"), &receipt.head).unwrap();
                receipt.expected_tip = receipt.head.clone();
            }
            if witness == "publish-empty-noop" {
                std::fs::write(outer.join("created"), "").unwrap();
                std::fs::write(
                    outer.join("remote-tip"),
                    git(&work, &["rev-parse", "HEAD"]).unwrap(),
                )
                .unwrap();
            }
            if witness.starts_with("publish-token-auth-patch") {
                std::fs::remove_file(outer.join("publish-mode")).unwrap();
                publish(
                    &work,
                    &dispatch,
                    &receipt,
                    &contract,
                    &report,
                    "fixture-token",
                    &mut agent_loop::RunCache::default(),
                )
                .unwrap();
                std::fs::write(outer.join("publish-mode"), mode).unwrap();
                receipt.expected_tip = git(&work, &["rev-parse", "HEAD"]).unwrap().trim().into();
                if witness != "publish-token-auth-patch-no-push" {
                    git(
                        &work,
                        &["commit", "--allow-empty", "-m", "fix(ci): continue App PR"],
                    )
                    .unwrap();
                }
                receipt.pr_body = Some("Update the explanation.".into());
            }
            let result = publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token",
                &mut agent_loop::RunCache::default(),
            );
            if matches!(witness, "publish-token-lease" | "publish-token-network") {
                let error = result.unwrap_err().to_string();
                assert!(
                    !error.contains("App token push refused"),
                    "non-permission error labelled as App permission refusal: {error}"
                );
                assert_eq!(regular_text(&outer.join("push-attempts")).unwrap(), "app\n");
                assert!(
                    !Applied::load()
                        .unwrap()
                        .report()
                        .contains("CI won't start automatically")
                );
            } else {
                assert_eq!(result.unwrap(), Some(800));
                let applied = Applied::load().unwrap().report();
                if witness == "publish-empty-noop" || witness == "publish-token-auth-patch" {
                    assert!(
                        !applied.contains("CI won't start automatically"),
                        "App synchronize or no-op publication claimed CI would not start"
                    );
                } else {
                    assert!(
                        applied.contains("CI won't start automatically"),
                        "auth fallback omitted CI note"
                    );
                    assert!(
                        applied.contains("the publish token was"),
                        "auth fallback omitted its reason: {applied}"
                    );
                    if witness == "publish-token-auth-push" {
                        assert!(
                            applied.contains("rejected during branch_push (")
                                && !applied.contains("opaque-publish-credential"),
                            "{applied}"
                        );
                    }
                    let file = if witness == "publish-token-auth-push" {
                        "push-attempts"
                    } else if witness.starts_with("publish-token-auth-patch") {
                        "patch-attempts"
                    } else {
                        "create-attempts"
                    };
                    assert_eq!(
                        regular_text(&outer.join(file)).unwrap(),
                        if witness == "publish-token-recovery-create" {
                            "job\n"
                        } else {
                            "app\njob\n"
                        }
                    );
                }
                if witness == "publish-token-auth-patch" {
                    assert_eq!(
                        regular_text(&outer.join("push-attempts")).unwrap(),
                        "app\napp\n"
                    );
                    assert_eq!(
                        regular_text(&outer.join("patch-attempts")).unwrap(),
                        "app\njob\n"
                    );
                }
            }
            return;
        }
        if witness.starts_with("publish-") {
            receipt.pr_body = Some("Publish the owner's change.".into());
            if witness == "publish-token-refused" {
                std::fs::write(outer.join("refuse-push"), "").unwrap();
                let error = publish(
                    &work,
                    &dispatch,
                    &receipt,
                    &contract,
                    &report,
                    "fixture-token",
                    &mut agent_loop::RunCache::default(),
                )
                .unwrap_err();
                assert!(
                    error.to_string().contains("App token push refused"),
                    "{error}"
                );
                assert!(!error.to_string().contains("opaque-publish-credential"));
                assert_eq!(
                    regular_text(&outer.join("push-attempts")).unwrap(),
                    "app\n",
                    "permission refusal was retried"
                );
                return;
            }
            for continuation in [false, true] {
                if continuation {
                    receipt.expected_tip =
                        git(&work, &["rev-parse", "HEAD"]).unwrap().trim().into();
                    git(
                        &work,
                        &["commit", "--allow-empty", "-m", "fix(ci): continue work"],
                    )
                    .unwrap();
                }
                assert_eq!(
                    publish(
                        &work,
                        &dispatch,
                        &receipt,
                        &contract,
                        &report,
                        "fixture-token",
                        &mut agent_loop::RunCache::default()
                    )
                    .unwrap(),
                    Some(800)
                );
            }
            let calls = regular_text(&outer.join("gh.args")).unwrap();
            assert!(
                calls.contains("create") && calls.contains("PATCH") && calls.contains("graphql")
            );
            assert!(
                regular_text(&outer.join("push.args"))
                    .unwrap()
                    .contains("--force-with-lease=")
            );
            let applied = Applied::load().unwrap().report();
            if witness != "publish-token" {
                assert!(
                    applied.contains("CI won't start automatically"),
                    "missing fallback note: {applied}"
                );
                assert!(applied.contains("mark the PR ready"));
            }
            match witness {
                "publish-missing" => assert!(
                    applied.contains("could not be minted: no controller mint channel"),
                    "{applied}"
                ),
                "publish-mint-refused" => assert!(
                    applied.contains("refused the publish token: assigned job is no longer"),
                    "{applied}"
                ),
                _ => {}
            }
            assert!(!applied.contains("opaque-publish-credential"));
            return;
        }
        if matches!(
            witness,
            "rebase-clean" | "rebase-conflict" | "worker-workflow"
        ) {
            let package = outer.join("dispatch-output");
            std::fs::create_dir_all(&package).unwrap();
            for name in ["raw.log", "transcript.md", "diffstat.txt"] {
                std::fs::write(package.join(name), "").unwrap();
            }
            std::fs::write(
                package.join("contract.json"),
                serde_json::to_string(&contract).unwrap(),
            )
            .unwrap();
        }
        if matches!(witness, "rebase-clean" | "rebase-conflict") {
            let conflict = witness == "rebase-conflict";
            let worker_file = if conflict { "base" } else { "work.txt" };
            std::fs::write(work.join(worker_file), "worker\n").unwrap();
            git(&work, &["add", worker_file]).unwrap();
            git(
                &work,
                &["commit", "-m", "fix(ci): implement the owner issue"],
            )
            .unwrap();
            receipt.head = git(&work, &["rev-parse", "HEAD"]).unwrap().trim().into();
            // Main moves on after the worker's base and changes a workflow file.
            git(&work, &["checkout", "-b", "advance", &receipt.base]).unwrap();
            std::fs::create_dir_all(work.join(".github/workflows")).unwrap();
            std::fs::write(work.join(".github/workflows/ci.yml"), "name: ci\n").unwrap();
            git(&work, &["add", ".github/workflows/ci.yml"]).unwrap();
            if conflict {
                std::fs::write(work.join("base"), "main\n").unwrap();
                git(&work, &["add", "base"]).unwrap();
            }
            git(&work, &["commit", "-m", "ci: change a workflow"]).unwrap();
            let main = git(&work, &["rev-parse", "HEAD"])
                .unwrap()
                .trim()
                .to_owned();
            git(&work, &["checkout", &dispatch.branch]).unwrap();
            git(
                &work,
                &[
                    "--git-dir",
                    outer.join("live-main.git").to_str().unwrap(),
                    "fetch",
                    work.to_str().unwrap(),
                    "advance:refs/heads/main",
                    "--force",
                ],
            )
            .unwrap();
            receipt.pr_body = Some("Publish the owner's change.".into());
            std::fs::write(
                state.join("receipt.json"),
                serde_json::to_vec(&receipt).unwrap(),
            )
            .unwrap();
            let result = publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token",
                &mut agent_loop::RunCache::default(),
            );
            if conflict {
                let error = result.unwrap_err().to_string();
                assert!(
                    error.contains("Rebase onto current main conflicts"),
                    "{error}"
                );
                assert!(error.contains("Conflicting files: base"), "{error}");
                assert!(error.contains(HARVEST_PATCH), "{error}");
                assert!(!outer.join("push.args").exists());
                assert_eq!(
                    git(&work, &["rev-parse", "HEAD"]).unwrap().trim(),
                    receipt.head
                );
                let patch =
                    regular_text(&outer.join("dispatch-output").join(HARVEST_PATCH)).unwrap();
                assert!(
                    patch.contains("fix(ci): implement the owner issue"),
                    "{patch}"
                );
            } else {
                assert_eq!(result.unwrap(), Some(800));
                assert_eq!(
                    git(&work, &["rev-parse", "HEAD~2"]).unwrap().trim(),
                    main,
                    "commits were not replayed onto current main"
                );
                assert_eq!(
                    std::fs::read_to_string(work.join("work.txt")).unwrap(),
                    "worker\n"
                );
                assert!(outer.join("push.args").exists());
                // The rebased tree and its receipt stay one valid checkpoint.
                let paired = worker_checkpoint(&state, &dispatch).unwrap().unwrap();
                assert_eq!(
                    paired.head,
                    git(&work, &["rev-parse", "HEAD"]).unwrap().trim()
                );
                assert_eq!(
                    Applied::load().unwrap().rebased_onto.as_deref(),
                    Some(main.as_str())
                );
                assert!(!outer.join("dispatch-output").join(HARVEST_PATCH).exists());
            }
            return;
        }
        if witness == "worker-workflow" {
            std::fs::create_dir_all(work.join(".github/workflows")).unwrap();
            std::fs::write(work.join(".github/workflows/worker.yml"), "name: worker\n").unwrap();
            git(&work, &["add", ".github/workflows/worker.yml"]).unwrap();
            git(&work, &["commit", "-m", "fix(ci): worker workflow edit"]).unwrap();
            let result = publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token",
                &mut agent_loop::RunCache::default(),
            );
            assert!(
                result
                    .as_ref()
                    .is_err_and(|e| e.to_string().contains("Refused workflow changes")),
                "worker workflow edit was published: {result:?}"
            );
            assert!(!outer.join("push.args").exists());
            let error = result.unwrap_err().to_string();
            assert!(error.contains(".github/workflows/worker.yml"), "{error}");
            assert!(error.contains(HARVEST_PATCH), "{error}");
            let patch = regular_text(&outer.join("dispatch-output").join(HARVEST_PATCH)).unwrap();
            assert!(patch.contains("fix(ci): worker workflow edit"), "{patch}");
            return;
        }
        if matches!(
            witness,
            "lag" | "extra-after-match" | "create-repair" | "timeout" | "transient"
        ) {
            std::fs::write(outer.join("reference-mode"), witness).unwrap();
            receipt.pr_body = Some("Proposed explanation.".into());
            let result = publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token",
                &mut agent_loop::RunCache::default(),
            );
            if witness == "transient" {
                assert!(
                    result.is_ok(),
                    "transient reference read blocked publication: {result:?}"
                );
            } else if witness == "lag" {
                assert!(
                    result.is_ok(),
                    "created PR rejected a lagging reference index: {result:?}"
                );
                let rows: Vec<Value> = regular_text(&outer.join("reference-reads.jsonl"))
                    .unwrap()
                    .lines()
                    .map(|s| serde_json::from_str(s).unwrap())
                    .collect();
                assert!(
                    rows.len() >= 4,
                    "publication did not require two settled reads"
                );
                REFERENCE_DELAYS.with(|delays| assert_eq!(
                    *delays.borrow(),
                    [3, 2, 2, 2].map(std::time::Duration::from_secs),
                    "settle did not request the initial three-second delay and two-second spacing"
                ));
                REFERENCE_READ_TIMES.with(|times| {
                    assert_eq!(
                        *times.borrow(),
                        [3, 5, 7, 9].map(std::time::Duration::from_secs),
                        "closing-reference reads did not follow the requested delays"
                    )
                });
            } else {
                assert!(
                    result.is_err(),
                    "create accepted an index that later exposed an extra reference"
                );
                outcome(&work, &dispatch);
                if witness == "timeout" {
                    assert!(
                        !outer.join("applied-body.md").exists(),
                        "deadline-only verification reverted the locally validated body"
                    );
                    assert!(
                        Applied::load().unwrap().report().contains("kept"),
                        "unverified outcome did not say the new body was kept"
                    );
                    assert!(
                        Applied::load()
                            .unwrap()
                            .report()
                            .contains("closing references unverified")
                    );
                    REFERENCE_DELAYS.with(|delays| {
                        assert!(
                            delays.borrow().iter().sum::<std::time::Duration>()
                                < std::time::Duration::from_secs(20),
                            "reference wait exceeded its twenty-second verification window"
                        )
                    });
                    return;
                }
                let fallback = regular_text(&outer.join("applied-body.md"))
                    .expect("new PR kept the rejected body instead of the default template");
                assert!(
                    fallback.contains("## Why") && !fallback.contains("Proposed explanation."),
                    "create did not restore the default template"
                );
                assert!(
                    Applied::load().unwrap().report().contains("restored"),
                    "outcome did not say whether the body was restored"
                );
            }
            return;
        }
        assert_eq!(
            publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token",
                &mut agent_loop::RunCache::default(),
            )
            .unwrap(),
            Some(800)
        );
        if witness == "window" {
            let _window =
                CommandWindow::until(std::time::Instant::now() + std::time::Duration::from_secs(1));
            assert!(
                ReferenceCheck::new(reference_host())
                    .verify(&work, 800, &ClosingIssues::from([issue_reference(634)]))
                    .is_err(),
                "closing-reference wait escaped the command window"
            );
            return;
        }
        let body = regular_text(&state.join("pr-body.md")).unwrap();
        assert!(body.contains("Closes #634") && body.contains("Dispatch run:"));
        if witness == "failed-harvest-body" {
            assert!(
                body.contains("implemented") && !body.contains("latest candidate discarded"),
                "PR body describes the failed harvest instead of the published tree"
            );
            assert!(
                body.contains("Published tree: worker"),
                "PR body does not identify the harvested worker"
            );
        }
        if witness == "template-summary-first" {
            assert!(
                body.find("implemented").unwrap() < body.find("Published tree:").unwrap(),
                "template leads with provenance instead of the human summary"
            );
        }
        if witness == "closing" {
            assert_eq!(
                body.lines().filter(|s| s.starts_with("Closes #")).count(),
                1,
                "created PR has duplicate closing lines"
            );
        }
        let calls = regular_text(&outer.join("gh.args")).unwrap();
        assert!(calls.contains(&format!(
            "--draft\n--base\nmain\n--head\n{}\n--title\n{subject}",
            dispatch.branch
        )));
        let selected = select_owned_pr(
            dispatch.issue,
            std::slice::from_ref(&pr),
            |_, _| Ok((run.clone(), None)),
            &mut owner_collaborator(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected["head"]["ref"], dispatch.branch);
        let mut unowned = pr;
        unowned["user"]["login"] = "outsider".into();
        assert!(
            select_owned_pr(
                dispatch.issue,
                &[unowned],
                |_, _| Ok((run.clone(), None)),
                &mut owner_collaborator()
            )
            .unwrap()
            .is_none()
        );
        // A later run starts with fresh run state: its own evidence and lease.
        std::fs::remove_file(state.join("applied.json")).unwrap();
        std::fs::remove_file(state.join("published-tip")).unwrap();
        dispatch.resume = true;
        receipt.expected_tip = git(&work, &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .to_owned();
        if witness == "published-closure" {
            git(&work, &["commit", "--allow-empty", "-m", "Closes #999"]).unwrap();
            receipt.expected_tip = git(&work, &["rev-parse", "HEAD"])
                .unwrap()
                .trim()
                .to_owned();
            std::fs::write(outer.join("remote-tip"), &receipt.expected_tip).unwrap();
        }
        if matches!(
            witness,
            "rebase-evidence"
                | "live-main-rebase"
                | "live-main-workflow"
                | "merge-evidence"
                | "live-main-closure"
        ) {
            git(&work, &["checkout", "-b", "advanced-main", &receipt.base]).unwrap();
            for subject in ["main one", "main two", "main three"] {
                git(&work, &["commit", "--allow-empty", "-m", subject]).unwrap();
            }
            if witness == "live-main-closure" {
                git(&work, &["commit", "--allow-empty", "-m", "Closes #999"]).unwrap();
            }
            if witness == "live-main-workflow" {
                std::fs::create_dir_all(work.join(".github/workflows")).unwrap();
                std::fs::write(
                    work.join(".github/workflows/upstream.yml"),
                    "name: upstream\n",
                )
                .unwrap();
                git(&work, &["add", ".github/workflows/upstream.yml"]).unwrap();
                git(&work, &["commit", "-m", "fix(ci): main workflow update"]).unwrap();
            }
            let new_base = git(&work, &["rev-parse", "HEAD"])
                .unwrap()
                .trim()
                .to_owned();
            git(&work, &["checkout", &dispatch.branch]).unwrap();
            if witness == "merge-evidence" {
                git(&work, &["merge", "--no-ff", &new_base, "-m", "merge main"]).unwrap();
            } else {
                git(&work, &["rebase", "--onto", &new_base, &receipt.base]).unwrap();
            }
            git(
                &work,
                &[
                    "--git-dir",
                    outer.join("live-main.git").to_str().unwrap(),
                    "fetch",
                    work.to_str().unwrap(),
                    "advanced-main:refs/heads/main",
                ],
            )
            .unwrap();
            std::fs::write(outer.join("live-base"), &new_base).unwrap();
            if matches!(witness, "rebase-evidence" | "merge-evidence") {
                dispatch.base = new_base.clone();
                receipt.base = new_base;
            }
        }
        git(
            &work,
            &[
                "commit",
                "--allow-empty",
                "-m",
                if witness == "worker-closure" {
                    "Fixes #999"
                } else {
                    "fix(ci): apply owner follow-up"
                },
            ],
        )
        .unwrap();
        if matches!(
            witness,
            "body"
                | "summary-first"
                | "edit-failure"
                | "references"
                | "footer"
                | "refused"
                | "manual"
                | "restore-fail"
                | "restore-html"
                | "snapshot-fail"
        ) {
            let package = outer.join("dispatch-output");
            std::fs::create_dir_all(&package).unwrap();
            std::fs::write(
                package.join("pr-body.md"),
                "Explain the implemented fix. fixture-token\n",
            )
            .unwrap();
        }
        if matches!(
            witness,
            "body"
                | "summary-first"
                | "edit-failure"
                | "references"
                | "footer"
                | "refused"
                | "manual"
                | "restore-fail"
                | "restore-html"
                | "snapshot-fail"
        ) {
            receipt.pr_body = read_pr_body(&outer.join("dispatch-output")).unwrap();
        }
        if matches!(
            witness,
            "manual" | "restore-fail" | "restore-html" | "snapshot-fail"
        ) {
            std::fs::write(outer.join("reference-mode"), witness).unwrap();
        }
        if witness == "snapshot-fail" {
            let result = publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token",
                &mut agent_loop::RunCache::default(),
            );
            let applied = Applied::load().unwrap();
            assert_eq!(
                applied.commits.len(),
                2,
                "snapshot failure prevented the push"
            );
            assert!(
                applied.report().contains("before edit"),
                "snapshot refusal was absent from the applied report: {result:?}"
            );
            assert!(!outer.join("applied-body.md").exists());
            return;
        }
        if witness == "restore-fail" {
            let result = publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token",
                &mut agent_loop::RunCache::default(),
            );
            assert!(result.is_err());
            outcome(&work, &dispatch);
            return;
        }
        if witness == "refused" {
            receipt.pr_body = Some("Explain the fix.\nFixes #999".into());
        }
        if matches!(witness, "live-main-workflow" | "live-main-closure") {
            let actor = tempfile::tempdir().unwrap();
            snapshot(&work, &actor.path().join("work"), &dispatch.branch).unwrap();
            std::fs::write(actor.path().join("result.json"), json!({"structured_output":{"status":"done","summary":"own fix","tests":[],"risks":[]}}).to_string()).unwrap();
            let harvested = harvest_worker(
                actor.path(),
                &actor.path().join("candidate"),
                &dispatch,
                Ok(0),
            );
            assert!(
                harvested.is_ok(),
                "harvest refused a trusted live-main closing reference"
            );
        }
        receipt.head = git(&work, &["rev-parse", "HEAD"]).unwrap().trim().into();
        if witness == "worker-closure" {
            let result = publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token",
                &mut agent_loop::RunCache::default(),
            );
            assert!(
                result
                    .as_ref()
                    .is_err_and(|e| e.to_string().contains(&receipt.head)),
                "publication accepted the worker's own unrelated closing reference"
            );
            return;
        }
        if matches!(witness, "references" | "restore-html") {
            std::fs::write(outer.join("two-references"), "").unwrap();
            let result = publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token",
                &mut agent_loop::RunCache::default(),
            );
            assert!(
                result
                    .as_ref()
                    .is_err_and(|e| e.to_string().contains("closing references")),
                "edit accepted two closing references: {result:?}"
            );
            assert!(
                Applied::load()
                    .unwrap()
                    .report()
                    .contains("closing references")
            );
            let restored = regular_text(&outer.join("applied-body.md")).unwrap();
            if witness == "restore-html" {
                assert!(
                    restored.contains("<p>@\u{2060}alice</p>"),
                    "restoration reintroduced an HTML mention"
                );
            } else {
                assert!(
                    restored.starts_with("Closes #634"),
                    "previous body was not restored"
                );
            }
            return;
        }
        if witness == "edit-failure" {
            std::fs::write(outer.join("fail-edit"), "").unwrap();
            assert!(
                publish(
                    &work,
                    &dispatch,
                    &receipt,
                    &contract,
                    &report,
                    "fixture-token",
                    &mut agent_loop::RunCache::default()
                )
                .is_err()
            );
            let applied = Applied::load().unwrap();
            assert!(applied.body == AppliedBody::NotUpdated);
            assert_eq!(
                applied.commits,
                git(
                    &work,
                    &["rev-list", "--reverse", &format!("{}..HEAD", receipt.base)]
                )
                .unwrap()
                .lines()
                .collect::<Vec<_>>()
            );
            return;
        }
        assert_eq!(
            publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token",
                &mut agent_loop::RunCache::default(),
            )
            .unwrap(),
            Some(800),
            "publication blamed live main workflow changes on the worker"
        );
        let applied = Applied::load().unwrap();
        if matches!(witness, "live-main-rebase" | "live-main-workflow") {
            let live = regular_text(&outer.join("live-base")).unwrap();
            assert_eq!(
                applied.commits.len(),
                2,
                "PR commit list includes commits from live main"
            );
            let fetches = regular_text(&outer.join("server-fetch.args")).unwrap();
            assert!(
                fetches.lines().any(|line| line == live),
                "server did not fetch its authenticated live-main snapshot"
            );
            assert!(
                applied
                    .report()
                    .contains(&format!("Rebased onto main at {live}")),
                "rebase report names the admitted base instead of live main"
            );
        }
        if witness == "merge-evidence" {
            assert!(
                !applied.report().contains("Rebased onto main at"),
                "merge of main was reported as a rebase"
            );
        }
        if witness == "commit-labels" {
            let report = applied.report();
            let old = &receipt.expected_tip[..12];
            let head = git(&work, &["rev-parse", "HEAD"]).unwrap();
            assert!(
                report.starts_with("- PR commits: "),
                "outcome still labels the list as pushed commits"
            );
            assert!(
                report.contains(&format!("{} (new in this run)", &head[..12]))
                    && !report.contains(&format!("{old} (new in this run)")),
                "PR commit report does not distinguish new commits from prior commits"
            );
        }
        if witness == "summary-first" {
            let body = regular_text(&outer.join("applied-body.md")).unwrap();
            assert!(
                body.starts_with("Explain the implemented fix."),
                "proposal leads with provenance instead of the human summary"
            );
        }
        if witness == "rebase-evidence" {
            let expected = git(
                &work,
                &["rev-list", "--reverse", &format!("{}..HEAD", receipt.base)],
            )
            .unwrap();
            assert_eq!(
                applied.commits,
                expected.lines().collect::<Vec<_>>(),
                "rebased main commits were reported as pushed"
            );
            assert!(
                applied
                    .report()
                    .contains(&format!("Rebased onto main at {}", receipt.base)),
                "rebase base missing from applied report"
            );
        }
        if witness == "refused" {
            assert_eq!(
                applied.commits.len(),
                2,
                "rejected proposal blocked commit push"
            );
            assert!(
                applied.report().contains("PR body: refused (")
                    && applied.report().contains("extra closing reference"),
                "refusal absent from outcome report"
            );
        } else {
            assert_eq!(
                applied.body == AppliedBody::Updated,
                matches!(witness, "body" | "footer" | "manual" | "summary-first")
            );
        }
        if witness == "footer" {
            let calls = regular_text(&outer.join("gh.args")).unwrap();
            assert!(
                calls.contains("api\n-X\nPATCH\nrepos/carrick-sh/carrick/pulls/800\n-F\nbody=@"),
                "body edit did not use REST PATCH"
            );
            let body = regular_text(&outer.join("applied-body.md")).unwrap();
            assert_eq!(
                body.lines().last(),
                Some("Dispatch run: https://github.com/carrick-sh/carrick/actions/runs/999")
            );
            let mut edited = selected.clone();
            edited["body"] = body.into();
            assert!(
                select_owned_pr(
                    dispatch.issue,
                    &[edited],
                    |_, _| Ok((run.clone(), None)),
                    &mut owner_collaborator()
                )
                .unwrap()
                .is_some(),
                "edited PR lost dispatch ownership"
            );
        }
        let sha = git(&work, &["rev-parse", "HEAD"]).unwrap();
        assert!(applied.report().contains(&sha[..12]));
        if witness == "body" {
            let applied = regular_text(&outer.join("applied-body.md"))
                .expect("continuation did not apply proposed PR body");
            assert!(applied.contains("Explain the implemented fix."));
            assert!(!applied.contains("fixture-token"));
            assert_eq!(
                applied
                    .lines()
                    .filter(|s| s.starts_with("Closes #"))
                    .count(),
                1
            );
            assert!(applied.contains("Dispatch run:"));
        }
        let calls = regular_text(&outer.join("gh.args")).unwrap();
        assert_eq!(calls.lines().filter(|s| *s == "create").count(), 1);
        let pushes = regular_text(&outer.join("push.args")).unwrap();
        assert_eq!(
            pushes
                .lines()
                .filter(|s| *s == "HEAD:refs/heads/work/dispatch-634-42")
                .count(),
            2
        );
        assert!(pushes.contains(&format!(
            "--force-with-lease=refs/heads/{}:{}",
            dispatch.branch, receipt.expected_tip
        )));
    }
    #[test]
    fn draft_pr_title_uses_the_first_branch_commit_subject() {
        let temp = tempfile::tempdir().unwrap();
        fixture_repository(temp.path());
        let base = git(temp.path(), &["rev-parse", "HEAD"]).unwrap();
        let subject = "fix(ci): title dispatch drafts from the first commit";
        git(temp.path(), &["commit", "--allow-empty", "-m", subject]).unwrap();
        git(
            temp.path(),
            &["commit", "--allow-empty", "-m", "test(ci): add coverage"],
        )
        .unwrap();
        assert_eq!(
            draft_pr_title(temp.path(), base.trim(), 792, "fixture-job-token").unwrap(),
            subject
        );
    }

    #[test]
    fn draft_pr_title_validates_subjects_and_masks_the_job_token() {
        let token = "fixture-job-token";
        let fallback = "chore(ci): work issue 792";
        for (subject, expected) in [
            (String::new(), fallback.to_owned()),
            ("x".repeat(101), fallback.to_owned()),
            ("fix(ci): reject\tcontrols".into(), fallback.to_owned()),
            ("fix(ci): reject\u{7f}controls".into(), fallback.to_owned()),
            ("fix(ci): reject\u{85}controls".into(), fallback.to_owned()),
            ("é".repeat(100), "é".repeat(100)),
            (
                format!("fix(ci): hide {token}"),
                "fix(ci): hide [REDACTED]".into(),
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            fixture_repository(temp.path());
            let base = git(temp.path(), &["rev-parse", "HEAD"]).unwrap();
            assert_eq!(
                draft_pr_title(temp.path(), base.trim(), 792, token).unwrap(),
                fallback
            );
            git(
                temp.path(),
                &[
                    "commit",
                    "--allow-empty",
                    "--allow-empty-message",
                    "--cleanup=verbatim",
                    "-m",
                    &subject,
                ],
            )
            .unwrap();
            let title = draft_pr_title(temp.path(), base.trim(), 792, token).unwrap();
            assert_eq!(title, expected, "subject: {subject:?}");
            assert!(!title.contains(token));
        }
    }

    #[test]
    fn launcher_result_is_kept_as_bounded_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("result.json");
        let (contract, evidence) = read_result(&path);
        assert_eq!(contract.status, ContractStatus::Failed);
        assert!(evidence.starts_with("=== result.json ===\nunreadable: "));

        let response = format!("{}tail", "x".repeat(RESULT_RESPONSE_TAIL * 2));
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({"status":"ERROR","structured_output":null,
                "error":"turn failed","response":response,"json_schema":schema(),
                "transport":{"exit_code":1,"timed_out":false,"interrupted":false}}))
            .unwrap(),
        )
        .unwrap();
        let (contract, evidence) = read_result(&path);
        assert_eq!(contract.summary, "No valid worker contract");
        let kept: Value =
            serde_json::from_str(evidence.strip_prefix("=== result.json ===\n").unwrap()).unwrap();
        assert_eq!(kept["error"], "turn failed");
        assert_eq!(kept["transport"]["exit_code"], 1);
        assert!(kept.get("json_schema").is_none());
        let kept_response = kept["response"].as_str().unwrap();
        assert_eq!(kept_response.chars().count(), RESULT_RESPONSE_TAIL);
        assert!(kept_response.ends_with("tail"));

        std::fs::write(
            &path,
            serde_json::to_vec(&json!({"status":"SUCCESS","structured_output":
                {"status":"done","summary":"ok","tests":["t"],"risks":[]}}))
            .unwrap(),
        )
        .unwrap();
        let (contract, evidence) = read_result(&path);
        assert_eq!(contract.status, ContractStatus::Done);
        assert!(!evidence.contains("structured_output"));

        // agy's live output: a valid contract plus its own tool metadata.
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({"status":"SUCCESS","structured_output":
                {"status":"done","summary":"ok","tests":["t"],"risks":["r"],
                 "toolAction":"Finishing task and reporting contract",
                 "toolSummary":"Finish task and report contract"}}))
            .unwrap(),
        )
        .unwrap();
        let (contract, _) = read_result(&path);
        assert_eq!(contract.status, ContractStatus::Done);
        assert_eq!(contract.risks, vec!["r".to_string()]);

        // A missing schema field still fails closed.
        std::fs::write(
            &path,
            serde_json::to_vec(
                &json!({"structured_output":{"status":"done","summary":"ok","tests":[]}}),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(read_result(&path).0.status, ContractStatus::Failed);
    }
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "runner-only OS account witness; run with --include-ignored"]
    fn serial_host_timeout_retires_detached_and_signal_resistant_agent() {
        let account = Command::new("/usr/bin/id")
            .args(["-u", AGENT_USER])
            .output()
            .unwrap();
        if account.status.code() == Some(1) {
            eprintln!("UNRUN: pre-created carrick-dispatch-agent account absent");
            return;
        }
        assert!(account.status.success());
        cleanup_agent_user().unwrap();
        // SAFETY: this serial runner-only fixture owns its foreground/adopted children.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
        let temp = tempfile::tempdir().unwrap();
        let log = temp.path().join("pids");
        let mut command = Command::new("/usr/bin/sudo");
        private_environment(&mut command);
        command.args(["-n", "-u", AGENT_USER, "--", "/usr/bin/env", "-i", "/usr/bin/python3", "-c",
            "import os,signal,subprocess,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); signal.signal(signal.SIGHUP,signal.SIG_IGN); p=subprocess.Popen(['/usr/bin/setsid','/bin/sleep','10'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); print(os.getpid(),p.pid,flush=True); time.sleep(5)"])
            .stdin(Stdio::null()).stdout(std::fs::File::create(&log).unwrap()).stderr(Stdio::null());
        let start = std::time::Instant::now();
        let result = wait_agent(&mut command, std::time::Duration::from_secs(1));
        let elapsed = start.elapsed();
        let retirement = retire_agent();
        let pids = std::fs::read_to_string(log)
            .unwrap()
            .split_whitespace()
            .map(|pid| pid.parse::<i32>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(pids.len(), 2, "agent did not reach the timeout fixture");
        let survivors = pids
            .iter()
            .copied()
            .filter(|pid| Path::new(&format!("/proc/{pid}")).try_exists().unwrap())
            .collect::<Vec<_>>();
        // Cleanup also owns the intentionally broken retirement control run.
        for pid in &survivors {
            sudo(&["/usr/bin/kill", "-KILL", "--", &pid.to_string()]).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while Path::new(&format!("/proc/{pid}")).try_exists().unwrap()
                && std::time::Instant::now() < deadline
            {
                // SAFETY: only this fixture's adopted PID is reaped, never another test's child.
                unsafe {
                    libc::waitpid(*pid, std::ptr::null_mut(), libc::WNOHANG);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        cleanup_agent_user().unwrap();
        assert_eq!(result.unwrap(), 124);
        assert!(
            elapsed < std::time::Duration::from_secs(4),
            "foreground wait blocked before retirement: {elapsed:?}"
        );
        assert!(retirement.is_ok(), "{retirement:?}");
        assert!(
            survivors.is_empty(),
            "agent processes survived timeout: {survivors:?}"
        );
    }
    #[test]
    fn runner_reads_agent_tree_without_executing_hooks_filters_or_scripts() {
        let temp = tempfile::tempdir().unwrap();
        let actor = temp.path().join("actor");
        let target = temp.path().join("snapshot");
        let marker = temp.path().join("runner-executed-agent-code");
        std::fs::create_dir(&actor).unwrap();
        git(&actor, &["init"]).unwrap();
        git(&actor, &["checkout", "-b", "work/dispatch-42"]).unwrap();
        std::fs::write(actor.join("data"), "base").unwrap();
        git(&actor, &["add", "."]).unwrap();
        git(&actor, &["commit", "-m", "base"]).unwrap();
        let base = git(&actor, &["rev-parse", "HEAD"]).unwrap();
        let poison = format!("#!/bin/sh\ntouch '{}'\ncat\n", marker.display());
        for script in [actor.join("poison.sh"), actor.join(".git/hooks/pre-commit")] {
            crate::lock_file::tests::write_test_executable(
                script,
                &poison,
                std::fs::Permissions::from_mode(0o700),
            );
        }
        git(&actor, &["config", "filter.poison.clean", "./poison.sh"]).unwrap();
        std::fs::write(actor.join(".gitattributes"), "data filter=poison\n").unwrap();
        std::fs::write(actor.join("data"), "agent modification").unwrap();
        git(&actor, &["pack-refs", "--all", "--prune"]).unwrap();
        snapshot(&actor, &target, "work/dispatch-42").unwrap();
        git(&target, &["add", "."]).unwrap();
        git(&target, &["commit", "-m", "read agent data"]).unwrap();
        assert_eq!(
            draft_pr_title(&target, base.trim(), 42, "fixture-job-token").unwrap(),
            "read agent data"
        );
        assert!(
            !marker.exists(),
            "runner executed agent-written hook, config or script"
        );
        assert_eq!(
            std::fs::read_to_string(target.join("data")).unwrap(),
            "agent modification"
        );
    }
    #[test]
    fn worker_disables_compiler_servers_for_every_runner_step() {
        let documents = yaml_rust2::YamlLoader::load_from_str(include_str!(
            "../../../.github/workflows/dispatch-worker.yml"
        ))
        .unwrap();
        let worker = &documents[0]["jobs"]["worker"];
        let environment = &worker["env"];
        for key in [
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "SCCACHE_SERVER_UDS",
        ] {
            assert_eq!(environment[key].as_str(), Some(""), "{key}");
        }
        assert_eq!(environment["CARRICK_SCCACHE"].as_str(), Some("0"));
        assert_eq!(environment["SCCACHE_DISABLE"].as_str(), Some("1"));
        assert_eq!(environment["SCCACHE_SERVER_PORT"].as_str(), Some("0"));
        let steps = worker["steps"].as_vec().unwrap();
        let admission = steps[0]["run"].as_str().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let pgrep = temp.path().join("pgrep");
        crate::lock_file::tests::write_test_executable(
            &pgrep,
            "#!/bin/sh\nexit \"$PGREP_RESULT\"\n",
            std::fs::Permissions::from_mode(0o700),
        );
        for (result, admitted) in [("0", false), ("1", true), ("2", false)] {
            let output = Command::new("/bin/sh")
                .args(["-eu", "-c", admission])
                .env_clear()
                .env("PATH", format!("{}:/usr/bin:/bin", temp.path().display()))
                .env("PGREP_RESULT", result)
                .output()
                .unwrap();
            assert_eq!(output.status.success(), admitted, "pgrep exit {result}");
        }
        for step in steps {
            assert!(!step["uses"].as_str().unwrap_or("").contains("rust-cache"));
            if let Some(overrides) = step["env"].as_hash() {
                for key in overrides.keys() {
                    assert!(
                        environment[key.as_str().unwrap()].is_badvalue(),
                        "step overrides job compiler isolation"
                    );
                }
            }
        }
    }
    #[test]
    fn agent_environment_has_no_github_token_or_config() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.env("GH_TOKEN", "planted")
            .env("GITHUB_TOKEN", "planted")
            .env("AGENT_DIRECTOR_TOKEN", "planted")
            .env("DISPATCH_BOARD_TOKEN", "planted")
            .env("DISPATCH_PUBLISH_TOKEN", "planted")
            .env("GITHUB_OUTPUT", "/runner/set_output")
            .env("GIT_CONFIG_GLOBAL", "/credential/helper")
            .env("RUSTC_WRAPPER", "/runner/sccache")
            .env("SCCACHE_SERVER_UDS", "/runner/sccache.sock");
        private_environment(&mut cmd);
        for key in [
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "AGENT_DIRECTOR_TOKEN",
            "DISPATCH_BOARD_TOKEN",
            "DISPATCH_PUBLISH_TOKEN",
        ] {
            assert!(
                !cmd.get_envs()
                    .any(|(name, value)| name == key && value.is_some()),
                "{key}"
            );
        }
        let output = cmd.output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "CARRICK_SCCACHE=0\nPATH=/usr/local/bin:/usr/bin:/bin\nRUSTC_WORKSPACE_WRAPPER=\nRUSTC_WRAPPER=\n"
        );
    }
    #[test]
    fn push_is_only_the_admitted_run_ref_and_refuses_another_lane() {
        let temp = tempfile::tempdir().unwrap();
        fixture_repository(temp.path());
        let mut dispatch =
            validate_event(&event(), "tjfontaine", &mut owner_collaborator()).unwrap();
        dispatch.branch = "work/dispatch-634-42".into();
        git(temp.path(), &["checkout", "-b", &dispatch.branch]).unwrap();
        let command = push_command(temp.path(), &dispatch, "42", &RunLease::admitted("")).unwrap();
        let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(args.last(), Some(&"HEAD:refs/heads/work/dispatch-634-42"));
        assert_eq!(args.iter().filter(|s| s.starts_with("HEAD:")).count(), 1);
        assert!(args.contains(&"--force-with-lease=refs/heads/work/dispatch-634-42:"));
        assert!(args.contains(&"--no-follow-tags"));
        assert!(!args.contains(&"--all") && !args.contains(&"--mirror"));
        assert!(push_command(temp.path(), &dispatch, "43", &RunLease::admitted("")).is_err());
        git(temp.path(), &["checkout", "-b", "work/another-lane"]).unwrap();
        assert!(push_command(temp.path(), &dispatch, "42", &RunLease::admitted("")).is_err());
        dispatch.branch = "work/another-lane".into();
        assert!(push_command(temp.path(), &dispatch, "42", &RunLease::admitted("")).is_err());
        for branch in [
            "main",
            "work/dispatch-633-42",
            "work/dispatch-634-pending",
            "work/dispatch-634-42:main",
        ] {
            assert!(branch_run(634, branch).is_err(), "{branch}");
        }
    }

    #[test]
    fn continuation_requires_the_dispatch_run_and_its_bot_draft_pr() {
        let branch = "work/dispatch-634-42";
        let pr = json!({"user":{"login":"github-actions[bot]", "type":"Bot"},
            "head":{"ref":branch,"repo":{"full_name":REPOSITORY}},
            "base":{"ref":"main"},"draft":true,
            "body":format!("Closes #634\nDispatch run: https://github.com/{REPOSITORY}/actions/runs/42")});
        let run = json!({"id":42,"path":".github/workflows/dispatch-worker.yml",
            "event":"issues","head_branch":"main","repository":{"full_name":REPOSITORY},
            "actor":{"login":"tjfontaine","type":"User"},"triggering_actor":{"login":"tjfontaine","type":"User"},"head_repository":{"full_name":REPOSITORY},"head_sha":"a".repeat(40)});
        assert!(owned_pr(
            &pr,
            &run,
            634,
            branch,
            None,
            &mut owner_collaborator()
        ));
        assert!(!owned_pr(
            &pr,
            &run,
            635,
            branch,
            None,
            &mut owner_collaborator()
        ));
        assert!(!owned_pr(
            &pr,
            &run,
            634,
            "work/dispatch-634-43",
            None,
            &mut owner_collaborator()
        ));
        for pointer in [
            "/user/login",
            "/user/type",
            "/head/ref",
            "/head/repo/full_name",
            "/base/ref",
            "/body",
        ] {
            let mut bad = pr.clone();
            *bad.pointer_mut(pointer).unwrap() = "foreign".into();
            assert!(
                !owned_pr(&bad, &run, 634, branch, None, &mut owner_collaborator()),
                "{pointer}"
            );
        }
        let mut ready = pr.clone();
        ready["draft"] = false.into();
        assert!(!owned_pr(
            &ready,
            &run,
            634,
            branch,
            None,
            &mut owner_collaborator()
        ));
        for pointer in [
            "/path",
            "/event",
            "/head_branch",
            "/repository/full_name",
            "/actor/login",
        ] {
            let mut bad = run.clone();
            *bad.pointer_mut(pointer).unwrap() = "foreign".into();
            assert!(
                !owned_pr(&pr, &bad, 634, branch, None, &mut owner_collaborator()),
                "{pointer}"
            );
        }
    }

    #[test]
    fn artifacts_mask_job_token_without_destroying_the_contract() {
        let temp = tempfile::tempdir().unwrap();
        let token = "fixture-job-token";
        for name in ["raw.log", "transcript.md", "diffstat.txt"] {
            std::fs::write(temp.path().join(name), format!("before {token} after\n")).unwrap();
        }
        let contract = Contract {
            loop_summary: None,
            status: ContractStatus::Done,
            summary: format!("Authorization: Bearer {token}"),
            tests: vec![format!("passed {token}")],
            risks: vec![],
        };
        std::fs::write(
            temp.path().join("contract.json"),
            serde_json::to_vec(&contract).unwrap(),
        )
        .unwrap();
        mask_artifacts(temp.path(), token).unwrap();
        for entry in std::fs::read_dir(temp.path()).unwrap() {
            assert!(
                !regular_text(&entry.unwrap().path())
                    .unwrap()
                    .contains(token)
            );
        }
        let masked: Contract =
            serde_json::from_str(&regular_text(&temp.path().join("contract.json")).unwrap())
                .unwrap();
        assert_eq!(masked.status, ContractStatus::Done);
        std::fs::write(temp.path().join("extra"), "unexpected").unwrap();
        assert!(mask_artifacts(temp.path(), token).is_err());
    }

    #[test]
    fn worker_sessions_upload_whole_lines_masked_and_numbered() {
        let temp = tempfile::tempdir().unwrap();
        let (package, logs) = (temp.path().join("package"), temp.path().join("logs"));
        std::fs::create_dir_all(&package).unwrap();
        std::fs::create_dir_all(&logs).unwrap();
        let token = "fixture-job-token";
        for name in ["raw.log", "transcript.md", "diffstat.txt"] {
            std::fs::write(package.join(name), "evidence\n").unwrap();
        }
        let contract = Contract {
            loop_summary: None,
            status: ContractStatus::Done,
            summary: "done".into(),
            tests: vec![],
            risks: vec![],
        };
        std::fs::write(
            package.join("contract.json"),
            serde_json::to_vec(&contract).unwrap(),
        )
        .unwrap();
        let first = logs.join("first.log");
        std::fs::write(
            &first,
            format!("{{\"event\":\"init\"}}\n{{\"event\":\"tool\",\"text\":\"{token}\"}}\n"),
        )
        .unwrap();
        record_worker_session(&first, &package).unwrap();
        record_worker_session(&first, &package).unwrap();
        // A worker that never started leaves no log and no session file.
        record_worker_session(&logs.join("missing.log"), &package).unwrap();
        mask_artifacts(&package, token).unwrap();
        for index in [1, 2] {
            let text = regular_text(&package.join(format!("worker-{index}.jsonl"))).unwrap();
            assert!(!text.contains(token));
            assert_eq!(
                text.lines()
                    .map(|line| serde_json::from_str::<Value>(line).unwrap()["event"].clone())
                    .collect::<Vec<_>>(),
                [json!("init"), json!("tool")]
            );
        }
        assert!(!package.join("worker-3.jsonl").exists());
        // Invalid bytes under the read bound triple in size when decoded; the
        // bound still holds on the redacted text and the upload still masks.
        let junk = logs.join("junk.log");
        let mut bytes = Vec::new();
        while bytes.len() + 1001 < WORKER_SESSION_BYTES {
            bytes.extend_from_slice(&[0xff; 1000]);
            bytes.push(b'\n');
        }
        std::fs::write(&junk, &bytes).unwrap();
        record_worker_session(&junk, &package).unwrap();
        let clipped = regular_text(&package.join("worker-3.jsonl")).unwrap();
        assert!(clipped.len() <= WORKER_SESSION_BYTES + 128);
        assert!(clipped.ends_with("\"event\":\"truncated\",\"limit_bytes\":16777216}\n"));
        mask_artifacts(&package, token).unwrap();
        for name in ["worker-.jsonl", "worker-x.jsonl", "worker-1.json"] {
            std::fs::write(package.join(name), "{}\n").unwrap();
            assert!(mask_artifacts(&package, token).is_err(), "{name}");
            std::fs::remove_file(package.join(name)).unwrap();
        }
    }

    #[test]
    fn worker_actor_receives_only_selected_backend_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        for name in [
            "home/.codex",
            "home/.gemini/antigravity-cli",
            "bin",
            "director",
        ] {
            std::fs::create_dir_all(state.join(name)).unwrap();
        }
        std::fs::write(state.join("home/.codex/auth.json"), "codex-secret").unwrap();
        std::fs::write(
            state.join("home/.gemini/antigravity-cli/antigravity-oauth-token"),
            "agy-secret",
        )
        .unwrap();
        let mut leaked = Vec::new();
        for (backend, wanted, forbidden) in
            [("agy", ".gemini", ".codex"), ("codex", ".codex", ".gemini")]
        {
            let actor = temp.path().join(backend);
            std::fs::create_dir(&actor).unwrap();
            prepare_worker_actor(&state, &actor, backend).unwrap();
            assert!(actor.join("home").join(wanted).is_dir());
            if actor.join("home").join(forbidden).exists() {
                leaked.push(backend);
            }
        }
        assert!(
            leaked.is_empty(),
            "worker homes leaked other backend credentials: {leaked:?}"
        );
    }
    fn event() -> Value {
        json!({"repository":{"full_name":REPOSITORY},"action":"labeled",
            "sender":{"login":"tjfontaine","type":"User"},"label":{"name":"dispatch:sol-high"},
            "issue":{"number":634,"user":{"login":"tjfontaine"},"title":"Dispatch workers!","body":"## Why\ncontext\n## Brief\nImplement it\n### Verify\nCheck it\n## Notes\nnot prompt"}})
    }
    #[test]
    fn issue_587_as_written_reaches_the_loop() {
        let mut value = event();
        value["issue"]["number"] = json!(587);
        value["issue"]["body"] = json!(
            "From the #548 independent review: `crates/carrick-xtask/src/ci_scaler/security_tests.rs` (around :47 and the new test near :428) still sets `set_read_timeout(2s)` on the fixture stream.\n\nFailure: if curl is descheduled for more than 2 s between connect and sending its request, `stream.read().unwrap()` panics and the test fails on speed rather than correctness. That is a load-dependent verdict.\n\nAcceptance: use the same 60 s hang bound as `execute`/`http_fixture`, or an event-driven bound; no wall-clock speed assertion."
        );
        assert!(
            validate_event(&value, "tjfontaine", &mut owner_collaborator()).is_ok(),
            "#587 free-form body refused"
        );
    }
    #[test]
    fn unsuffixed_dispatch_is_owner_context() {
        let mut value = event();
        for label in ["dispatch", "dispatch:any owner context"] {
            value["label"]["name"] = label.into();
            assert!(
                validate_event(&value, "tjfontaine", &mut owner_collaborator()).is_ok(),
                "label {label} refused"
            );
        }
    }
    #[test]
    fn agent_comment_requires_owner_and_unedited_creation() {
        let mut value = event();
        value.as_object_mut().unwrap().remove("label");
        value["action"] = "created".into();
        value["issue"]["state"] = "open".into();
        value["comment"] = json!({"user":{"login":"tjfontaine","type":"User"},"body":"/agent please continue","created_at":"2026-10-24T00:00:00Z","updated_at":"2026-10-24T00:00:00Z"});
        assert!(
            validate_event(&value, "tjfontaine", &mut owner_collaborator()).is_ok(),
            "owner /agent refused"
        );
        let mut admitted = Vec::new();
        for (pointer, bad) in [
            ("/comment/user/login", "outsider"),
            ("/comment/updated_at", "2026-10-24T00:01:00Z"),
            ("/action", "edited"),
            ("/comment/body", "/agentish"),
            ("/issue/state", "closed"),
        ] {
            let mut other = value.clone();
            *other.pointer_mut(pointer).unwrap() = bad.into();
            if validate_event(&other, "tjfontaine", &mut owner_collaborator()).is_ok() {
                admitted.push(pointer);
            }
        }
        assert!(
            admitted.is_empty(),
            "unsafe comments admitted: {admitted:?}"
        );
    }
    /// Logins with each GitHub permission level; anyone else gets a 404.
    const PERMISSIONS: &[(&str, &str)] = &[
        ("tjfontaine", "admin"),
        ("maintainer", "maintain"),
        ("writer", "write"),
        ("triager", "triage"),
        ("reader", "read"),
        ("nobody", "none"),
    ];
    fn as_actor(mut value: Value, login: &str) -> Value {
        value["sender"]["login"] = login.into();
        if value.get("comment").is_some() {
            value["comment"]["user"]["login"] = login.into();
        }
        value
    }
    #[test]
    fn collaborators_with_write_access_trigger_and_others_are_refused() {
        // #1214: trust is a live write-or-higher collaborator check, not a
        // fixed login; the issue author no longer matters.
        let mut app_issue = event();
        app_issue["issue"]["user"] = json!({"login":"carrick-workers[bot]","type":"Bot"});
        let mut comment = app_issue.clone();
        comment["action"] = "created".into();
        comment["issue"]["state"] = "open".into();
        comment["comment"] = json!({"user":{"login":"tjfontaine","type":"User"},"body":"/agent go","created_at":"2026-10-30T00:00:00Z","updated_at":"2026-10-30T00:00:00Z"});
        for trigger in [&app_issue, &comment] {
            for login in ["tjfontaine", "maintainer", "writer"] {
                let mut trusted = fake_collaborators(PERMISSIONS);
                validate_event(&as_actor(trigger.clone(), login), login, &mut trusted)
                    .unwrap_or_else(|e| panic!("{login} refused: {e}"));
            }
            for login in ["triager", "reader", "nobody", "stranger"] {
                let mut trusted = fake_collaborators(PERMISSIONS);
                assert!(
                    validate_event(&as_actor(trigger.clone(), login), login, &mut trusted).is_err(),
                    "{login} admitted"
                );
                // A trusted sender cannot carry an untrusted rerun actor.
                assert!(
                    validate_event(&as_actor(trigger.clone(), "writer"), login, &mut trusted)
                        .is_err(),
                    "{login} rerun admitted"
                );
            }
            // Any permission API failure refuses (fail closed).
            let mut failing = collaborators(|_| Err(ScalerError::Guard("API unavailable")));
            assert!(validate_event(trigger, "tjfontaine", &mut failing).is_err());
        }
        // The comment author is checked on its own, beyond the sender.
        let mut foreign = as_actor(comment.clone(), "writer");
        foreign["comment"]["user"]["login"] = "reader".into();
        assert!(validate_event(&foreign, "writer", &mut fake_collaborators(PERMISSIONS)).is_err());
        // A collaborator Bot account is not a human trigger.
        let mut bot = as_actor(app_issue, "writer");
        bot["sender"]["type"] = "Bot".into();
        assert!(validate_event(&bot, "writer", &mut fake_collaborators(PERMISSIONS)).is_err());
    }
    #[test]
    fn collaborator_permission_reads_only_a_well_formed_endpoint() {
        let mut reads = Vec::new();
        for login in [
            "../../orgs/x",
            "a/b",
            "",
            "-lead",
            &"x".repeat(40),
            "ok?x=1",
        ] {
            assert!(!write_collaborator(login, |endpoint| {
                reads.push(endpoint.to_owned());
                Ok(json!({"permission":"admin"}))
            }));
        }
        assert!(reads.is_empty(), "{reads:?}");
        assert!(write_collaborator("Mixed-Case-1", |endpoint| {
            assert_eq!(
                endpoint,
                "repos/carrick-sh/carrick/collaborators/Mixed-Case-1/permission"
            );
            Ok(json!({"permission":"write","role_name":"write"}))
        }));
        for answer in [
            json!({}),
            json!({"permission":null}),
            json!({"role_name":"admin"}),
        ] {
            assert!(!write_collaborator("writer", |_| Ok(answer.clone())));
        }
        // Each login is read once per predicate, refusals included.
        let mut count = 0;
        let mut trusted = collaborators(|_| {
            count += 1;
            Ok(json!({"permission":"read"}))
        });
        assert!(!trusted("reader") && !trusted("reader"));
        drop(trusted);
        assert_eq!(count, 1);
    }
    #[test]
    fn dispatch_runs_need_collaborator_actors_live() {
        let run = json!({"id":42,"path":".github/workflows/dispatch-worker.yml","event":"issues","head_branch":"main",
            "repository":{"full_name":REPOSITORY},"head_repository":{"full_name":REPOSITORY},"head_sha":"a".repeat(40),
            "actor":{"login":"writer","type":"User"},"triggering_actor":{"login":"writer","type":"User"}});
        assert!(dispatch_run_admitted(
            &run,
            Some(634),
            &mut fake_collaborators(PERMISSIONS)
        ));
        for (pointer, login) in [
            ("/actor/login", "reader"),
            ("/triggering_actor/login", "stranger"),
            ("/triggering_actor/login", "triager"),
        ] {
            let mut bad = run.clone();
            *bad.pointer_mut(pointer).unwrap() = login.into();
            assert!(dispatch_run_identity(&bad, Some(634)), "{pointer}");
            assert!(
                !dispatch_run_admitted(&bad, Some(634), &mut fake_collaborators(PERMISSIONS)),
                "{pointer}={login}"
            );
        }
        let mut bot = run.clone();
        bot["actor"]["type"] = "Bot".into();
        assert!(!dispatch_run_identity(&bot, Some(634)));
        assert!(!dispatch_run_admitted(
            &run,
            Some(634),
            &mut collaborators(|_| Err(ScalerError::Guard("API unavailable")))
        ));
    }
    #[test]
    fn app_authored_pr_with_one_closing_issue_is_adoptable() {
        let pr = json!({"number":1150,"state":"open","user":{"login":"carrick-workers[bot]","type":"Bot"},
            "head":{"ref":"work/986-slice4","sha":"a".repeat(40),"repo":{"full_name":REPOSITORY}},
            "base":{"ref":"main","repo":{"full_name":REPOSITORY}}});
        let issue = json!({"number":986,"state":"open","user":{"login":"carrick-workers[bot]","type":"Bot"}});
        let read = |refs: &'static [u64]| {
            let issue = issue.clone();
            move |read: AdoptionRead| match read {
                AdoptionRead::ClosingReferences(1150) => {
                    let nodes: Vec<_> = refs
                        .iter()
                        .map(|n| json!({"number":n,"repository":{"nameWithOwner":REPOSITORY}}))
                        .collect();
                    let connection = json!({"nodes":nodes,"pageInfo":{"hasNextPage":false}});
                    Ok(
                        json!({"data":{"repository":{"pullRequest":{"closingIssuesReferences":connection,"bodyReferences":connection}}}}),
                    )
                }
                AdoptionRead::Issue(986) => Ok(issue.clone()),
                _ => Err(ScalerError::Guard("unexpected read")),
            }
        };
        let adoption = adopted_pr(&pr, read(&[986]))
            .unwrap()
            .expect("App PR refused");
        assert_eq!(adoption.issue_number(), Some(986));
        assert!(adopted_pr(&pr, read(&[])).unwrap().is_none());
        assert!(adopted_pr(&pr, read(&[986, 987])).unwrap().is_none());
        let mut fork = pr.clone();
        fork["head"]["repo"]["full_name"] = "outsider/carrick".into();
        assert!(adopted_pr(&fork, read(&[986])).unwrap().is_none());
    }
    fn fixture_repository(root: &Path) {
        git(root, &["init", "-b", "work/dispatch-634-pending"]).unwrap();
        std::fs::write(root.join("base"), "base").unwrap();
        git(root, &["add", "base"]).unwrap();
        git(root, &["commit", "-m", "fixture base"]).unwrap();
        git(root, &["update-ref", "refs/remotes/origin/main", "HEAD"]).unwrap();
    }
    #[test]
    fn dispatch_rejects_unknown_labels_untrusted_actors_forks_and_prs() {
        let base = event();
        for pointer in [
            "/sender/login",
            "/label/name",
            "/repository/full_name",
            "/action",
        ] {
            let mut bad = base.clone();
            *bad.pointer_mut(pointer).unwrap() = "untrusted".into();
            assert!(
                validate_event(&bad, "tjfontaine", &mut owner_collaborator()).is_err(),
                "{pointer}"
            );
        }
        assert!(
            validate_event(&base, "someone-else", &mut owner_collaborator()).is_err(),
            "rerun actor"
        );
        let mut pr = base.clone();
        pr["issue"]["pull_request"] = json!({});
        assert!(validate_event(&pr, "tjfontaine", &mut owner_collaborator()).is_err());
        let mut bot = base;
        bot["sender"] = json!({"login":"carrick-workers[bot]","type":"Bot"});
        assert!(validate_event(&bot, "carrick-workers[bot]", &mut owner_collaborator()).is_err());
        bot["sender"]["type"] = "User".into();
        assert!(validate_event(&bot, "carrick-workers[bot]", &mut owner_collaborator()).is_err());
    }
    #[test]
    fn collaborator_label_admits_an_issue_by_any_author() {
        // #1214 reversed the old owner-authored-issue rule: the trusted
        // label is the approval, whoever filed the issue.
        let mut value = event();
        value["issue"]["user"]["login"] = "someone-else".into();
        assert!(validate_event(&value, "tjfontaine", &mut owner_collaborator()).is_ok());
        value["issue"]["user"] = json!({"login":"carrick-workers[bot]","type":"Bot"});
        assert!(validate_event(&value, "tjfontaine", &mut owner_collaborator()).is_ok());
        value["issue"].as_object_mut().unwrap().remove("user");
        assert!(validate_event(&value, "tjfontaine", &mut owner_collaborator()).is_ok());
    }
    #[test]
    fn wip_checkpoint_preserves_trailer_and_excludes_target_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture_repository(root);
        std::fs::remove_file(root.join("base")).unwrap();
        std::fs::write(root.join("new file"), "work in progress").unwrap();
        std::fs::create_dir(root.join("conformance-probes")).unwrap();
        std::os::unix::fs::symlink("/tmp", root.join("conformance-probes/target")).unwrap();
        let mut d = validate_event(&event(), "tjfontaine", &mut owner_collaborator()).unwrap();
        d.worker.coauthor = "GPT-6.1 Sol <noreply@openai.com>".into();
        assert!(checkpoint(root, &d).unwrap());
        let message = git(root, &["log", "-1", "--format=%B"]).unwrap();
        assert!(message.contains("Co-Authored-By: GPT-6.1 Sol <noreply@openai.com>"));
        assert_eq!(
            git(root, &["ls-tree", "--name-only", "HEAD"])
                .unwrap()
                .trim(),
            "new file"
        );
        assert!(!checkpoint(root, &d).unwrap());
    }
    fn review_event() -> Value {
        let mut event = event();
        event["action"] = "submitted".into();
        event["review"] = json!({"id":77,"state":"changes_requested","body":"Owner review verbatim","user":{"login":"tjfontaine","type":"User"}});
        event["issue"]["state"] = "open".into();
        event["issue"]["labels"] = json!([{"name":"dispatch:sol-high"}]);
        event["pull_request"] = json!({"number":800,"user":{"login":"github-actions[bot]","type":"Bot"},"head":{"ref":"work/dispatch-634-42","repo":{"full_name":REPOSITORY}},"base":{"ref":"main"},"draft":true,"body":format!("Closes #634\nDispatch run: https://github.com/{REPOSITORY}/actions/runs/42")});
        event["dispatch_run"] = json!({"id":42,"path":".github/workflows/dispatch-worker.yml","event":"issues","head_branch":"main","repository":{"full_name":REPOSITORY},"actor":{"login":"tjfontaine","type":"User"},"triggering_actor":{"login":"tjfontaine","type":"User"},"head_repository":{"full_name":REPOSITORY},"head_sha":"a".repeat(40)});
        event
    }
    #[test]
    fn review_admission_requires_trusted_reviewer_and_owned_pr() {
        let event = review_event();
        let dispatch = validate_event(&event, "tjfontaine", &mut owner_collaborator())
            .expect("owner review must continue its PR");
        assert_eq!(dispatch.branch, "work/dispatch-634-42");
        assert!(dispatch.resume);
        let mut legacy = event.clone();
        legacy["issue"]["body"] =
            "## Brief\nBranch: work/dispatch-634-99\nBranch: work/elsewhere\nDo the review".into();
        assert_eq!(
            validate_event(&legacy, "tjfontaine", &mut owner_collaborator())
                .unwrap()
                .branch,
            dispatch.branch
        );
        let mut admitted = Vec::new();
        for (pointer, value) in [
            ("/review/user/login", json!("outsider")),
            ("/sender/login", json!("outsider")),
            ("/review/state", json!("approved")),
            ("/review/state", json!("commented")),
            (
                "/pull_request/head/repo/full_name",
                json!("outsider/carrick"),
            ),
            ("/pull_request/head/ref", json!("work/arbitrary")),
            ("/pull_request/draft", json!(false)),
            ("/dispatch_run/path", json!("other.yml")),
            ("/dispatch_run/actor/login", json!("outsider")),
            ("/dispatch_run/triggering_actor/login", json!("outsider")),
            ("/issue/state", json!("closed")),
        ] {
            let mut bad = event.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            if validate_event(&bad, "tjfontaine", &mut owner_collaborator()).is_ok() {
                admitted.push(pointer);
            }
        }
        if validate_event(&event, "outsider", &mut owner_collaborator()).is_ok() {
            admitted.push("triggering_actor");
        }
        assert!(admitted.is_empty(), "unsafe reviews admitted: {admitted:?}");
        // #1214: any write collaborator's review continues the PR; a
        // read-only reviewer does not, and the issue author is not checked.
        let mut collaborator = event.clone();
        collaborator["sender"]["login"] = "writer".into();
        collaborator["review"]["user"]["login"] = "writer".into();
        collaborator["issue"]["user"] = json!({"login":"carrick-workers[bot]","type":"Bot"});
        assert!(
            validate_event(
                &collaborator,
                "writer",
                &mut fake_collaborators(PERMISSIONS)
            )
            .is_ok()
        );
        let mut reader = collaborator.clone();
        reader["sender"]["login"] = "reader".into();
        reader["review"]["user"]["login"] = "reader".into();
        assert!(validate_event(&reader, "reader", &mut fake_collaborators(PERMISSIONS)).is_err());
    }

    #[test]
    fn agent_comment_on_an_unowned_pr_is_refused() {
        let mut event = review_event();
        event.as_object_mut().unwrap().remove("review");
        event["action"] = "created".into();
        event["comment"] = json!({"user":{"login":"tjfontaine","type":"User"},"body":"/agent fix the conflict","created_at":"2026-10-24","updated_at":"2026-10-24"});
        assert!(validate_event(&event, "tjfontaine", &mut owner_collaborator()).is_ok());
        event["pull_request"]["user"]["login"] = "outsider".into();
        assert!(
            validate_event(&event, "tjfontaine", &mut owner_collaborator()).is_err(),
            "unowned PR admitted"
        );
    }
    #[test]
    fn agent_comment_adopts_a_director_pr_through_guard_admission() {
        const CHILD: &str = "CARRICK_TEST_DISPATCH_ADOPTION";
        if std::env::var_os(CHILD).is_none() {
            let temp = tempfile::tempdir().unwrap();
            let bin = temp.path().join("bin");
            std::fs::create_dir(&bin).unwrap();
            crate::lock_file::tests::write_test_executable(
                bin.join("gh"),
                r#"#!/bin/sh
test "$1" = api || exit 93
if test "$2" = graphql; then
 case "$*" in *lastEditedAt*) cat "$ADOPTION_FIXTURE/issue-graphql.json" ;; *) cat "$ADOPTION_FIXTURE/graphql.json" ;; esac
 exit 0
fi
file="$ADOPTION_FIXTURE/$(printf '%s' "$2" | tr '/' '_')"
test -f "$file" || { echo "unexpected endpoint $2" >&2; exit 91; }
cat "$file"
"#,
                std::fs::Permissions::from_mode(0o700),
            );
            for (head, admission) in [
                (None, false),
                (Some("b".repeat(40)), false),
                (Some("a".repeat(40)), true),
            ] {
                let mut command = Command::new(std::env::current_exe().unwrap());
                command
                    .args([
                        "--exact",
                        std::thread::current().name().unwrap(),
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .env("ADOPTION_FIXTURE", temp.path())
                    .env("GH_TOKEN", "fixture-token")
                    .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                    .env_remove("CARRICK_DISPATCH_HEAD");
                if let Some(head) = &head {
                    command.env("CARRICK_DISPATCH_HEAD", head);
                }
                if admission {
                    let runner = tempfile::tempdir_in(temp.path()).unwrap().keep();
                    command
                        .env("ADOPTION_ADMIT", "1")
                        .env("GITHUB_TRIGGERING_ACTOR", "tjfontaine")
                        .env("CARRICK_DISPATCH_BASE", "f".repeat(40))
                        .env("RUNNER_TEMP", runner)
                        .env("GITHUB_RUN_ID", "77")
                        .env("GITHUB_RUN_ATTEMPT", "1");
                }
                let output = command.output().unwrap();
                assert!(
                    output.status.success(),
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        }
        let fixture = PathBuf::from(std::env::var_os("ADOPTION_FIXTURE").unwrap());
        let tip = "a".repeat(40);
        let comment = json!({"id":123,"user":{"login":"tjfontaine","type":"User"},"body":"/agent continue the slice","created_at":"2026-10-30T00:00:00Z","updated_at":"2026-10-30T00:00:00Z"});
        let event = json!({"action":"created","repository":{"full_name":REPOSITORY},
            "sender":{"login":"tjfontaine","type":"User"},
            "issue":{"number":1150,"state":"open","title":"refactor: slice 4","body":"","user":{"login":"carrick-workers[bot]","type":"Bot"},"pull_request":{"url":"pr"}},
            "comment":comment});
        let pr = json!({"number":1150,"state":"open","draft":false,"user":{"login":"carrick-workers[bot]","type":"Bot"},
            "head":{"ref":"work/986-slice4","sha":tip,"repo":{"full_name":REPOSITORY}},
            "base":{"ref":"main","repo":{"full_name":REPOSITORY}},"body":"Closes #986"});
        let issue = json!({"number":986,"state":"open","title":"Slice the kernel","body":"## Brief\nDo it","user":{"login":"tjfontaine","type":"User"}});
        let references = |numbers: &[u64]| {
            let nodes: Vec<_> = numbers
                .iter()
                .map(|n| json!({"number":n,"repository":{"nameWithOwner":REPOSITORY}}))
                .collect();
            let connection = json!({"nodes":nodes,"pageInfo":{"hasNextPage":false}});
            json!({"data":{"repository":{"pullRequest":{"closingIssuesReferences":connection,"bodyReferences":connection}}}})
        };
        let write = |name: &str, value: &Value| {
            std::fs::write(
                fixture.join(format!("repos/{REPOSITORY}/{name}").replace('/', "_")),
                value.to_string(),
            )
            .unwrap();
        };
        let event_path = fixture.join("event.json");
        let admit =
            |event: &Value, pr: &Value, issue: &Value, live_comment: &Value, refs: &[u64]| {
                write("issues/comments/123", live_comment);
                write("pulls/1150", pr);
                write("issues/986", issue);
                std::fs::write(
                    fixture.join("issue-graphql.json"),
                    issue_brief(issue, None).to_string(),
                )
                .unwrap();
                std::fs::write(fixture.join("graphql.json"), references(refs).to_string()).unwrap();
                std::fs::write(&event_path, event.to_string()).unwrap();
                let (loaded, adoption, _) =
                    load_event(&fixture, &event_path, &mut owner_collaborator())?;
                validate_event_with_publication(
                    &loaded,
                    "tjfontaine",
                    &mut owner_collaborator(),
                    None,
                    adoption.as_ref(),
                    None,
                )
            };
        if std::env::var_os("ADOPTION_ADMIT").is_some() {
            // The production guard, then clone admission: require_target_pr
            // re-checks the PR and the private admission round-trips the type.
            admit(&event, &pr, &issue, &comment, &[986]).unwrap();
            // The guard's live permission read goes through the same gh.
            write(
                "collaborators/tjfontaine/permission",
                &json!({"permission":"admin"}),
            );
            let (_, hosted) = guard_admission(&fixture, &event_path, false, || {
                panic!("the hosted guard never retires an agent")
            })
            .unwrap();
            let mut retired = false;
            let (_, admitted) = guard_admission(&fixture, &event_path, true, || {
                retired = true;
                Ok(())
            })
            .unwrap();
            assert!(retired);
            let expected = Continuation::Adopted {
                rebase: false,
                pr: 1150,
                branch: "work/986-slice4".into(),
                tip: tip.clone(),
            };
            assert_eq!(hosted.continuation, expected);
            assert_eq!(admitted.continuation, expected);
            assert_eq!(admitted.base, "f".repeat(40));
            let stored = read_admission(&event_path).unwrap();
            assert_eq!(stored.dispatch.continuation, expected);
            assert_eq!(stored.dispatch.issue, 986);
            assert_eq!(stored.dispatch.branch, "work/986-slice4");
            assert_eq!(stored.trigger["id"], 123);
            // A PR that stops qualifying is refused at clone admission.
            let mut closed = issue.clone();
            closed["state"] = "closed".into();
            write("issues/986", &closed);
            assert!(guard_admission(&fixture, &event_path, true, || Ok(())).is_err());
            return;
        }
        if std::env::var_os("CARRICK_DISPATCH_HEAD").is_some() {
            let error = admit(&event, &pr, &issue, &comment, &[986]).unwrap_err();
            assert!(error.to_string().contains("stale PR head"), "{error}");
            return;
        }
        let dispatch = admit(&event, &pr, &issue, &comment, &[986])
            .expect("owner /agent on a director PR must adopt it");
        assert_eq!(dispatch.issue, 986);
        assert_eq!(dispatch.branch, "work/986-slice4");
        assert!(dispatch.resume);
        assert_eq!(dispatch.selected_tip.as_deref(), Some(tip.as_str()));
        assert_eq!(
            dispatch.continuation,
            Continuation::Adopted {
                rebase: false,
                pr: 1150,
                branch: "work/986-slice4".into(),
                tip: tip.clone()
            }
        );
        // #1214: neither the PR nor the issue author matters any more; a
        // collaborator's unedited /agent comment is the approval.
        for author in [
            json!({"login":"tjfontaine","type":"User"}),
            json!({"login":"outsider","type":"User"}),
            json!({"login":"carrick-workers[bot]","type":"Bot"}),
        ] {
            let mut any_pr = pr.clone();
            any_pr["user"] = author.clone();
            let mut any_issue = issue.clone();
            any_issue["user"] = author;
            assert!(admit(&event, &any_pr, &any_issue, &comment, &[986]).is_ok());
        }
        // #1215: only the owner account's exact `Rebase: allowed` line is
        // consent to rewrite an adopted PR's history.
        let rebase_of = |body: &str| {
            let mut consent = comment.clone();
            consent["body"] = json!(body);
            let mut with = event.clone();
            with["comment"] = consent.clone();
            match admit(&with, &pr, &issue, &consent, &[986])
                .unwrap()
                .continuation
            {
                Continuation::Adopted { rebase, .. } => rebase,
                Continuation::Owned => panic!("adoption lost"),
            }
        };
        assert!(rebase_of("/agent rebase onto main\nRebase: allowed"));
        assert!(rebase_of("/agent rebase onto main\n  Rebase: allowed  \n"));
        assert!(!rebase_of("/agent rebase onto main"));
        assert!(!rebase_of(
            "/agent rebase onto main\nRebase: allowed, please"
        ));
        assert!(!rebase_of("/agent rebase onto main\nrebase: allowed"));
        assert!(!rebase_of("/agent Rebase: allowed"));
        let mut collaborator = comment.clone();
        collaborator["user"] = json!({"login":"collab","type":"User"});
        collaborator["body"] = json!("/agent rebase\nRebase: allowed");
        assert!(!rebase_consent(&collaborator));
        collaborator["user"] = json!({"login":"tjfontaine","type":"Bot"});
        assert!(!rebase_consent(&collaborator));

        let mut admitted = Vec::new();
        let mut refuse = |case: &str, result: Result<Dispatch, ScalerError>| {
            if result.is_ok() {
                admitted.push(case.to_owned());
            }
        };
        for (pointer, value) in [
            ("/head/repo/full_name", json!("outsider/carrick")),
            ("/base/repo/full_name", json!("outsider/carrick")),
            ("/head/ref", json!("main")),
            ("/head/ref", json!("feature/slice4")),
            ("/head/ref", json!("work/../main")),
            ("/base/ref", json!("release")),
            ("/state", json!("closed")),
        ] {
            let mut bad = pr.clone();
            *bad.pointer_mut(pointer).unwrap() = value.clone();
            refuse(
                &format!("pr {pointer}={value}"),
                admit(&event, &bad, &issue, &comment, &[986]),
            );
        }
        for refs in [&[][..], &[986, 987][..]] {
            refuse(
                &format!("references {refs:?}"),
                admit(&event, &pr, &issue, &comment, refs),
            );
        }
        for (pointer, value) in [("/state", json!("closed")), ("/number", json!(987))] {
            let mut bad = issue.clone();
            *bad.pointer_mut(pointer).unwrap() = value.clone();
            refuse(
                &format!("issue {pointer}={value}"),
                admit(&event, &pr, &bad, &comment, &[986]),
            );
        }
        let mut edited = comment.clone();
        edited["updated_at"] = "2026-10-30T00:01:00Z".into();
        refuse(
            "live comment edited",
            admit(&event, &pr, &issue, &edited, &[986]),
        );
        for (pointer, value) in [
            ("/comment/user/login", json!("outsider")),
            ("/comment/updated_at", json!("2026-10-30T00:01:00Z")),
            ("/sender/login", json!("outsider")),
        ] {
            let mut bad = event.clone();
            *bad.pointer_mut(pointer).unwrap() = value.clone();
            let mut live = comment.clone();
            if let Some(field) = pointer.strip_prefix("/comment") {
                *live.pointer_mut(field).unwrap() = value.clone();
            }
            refuse(
                &format!("event {pointer}={value}"),
                admit(&bad, &pr, &issue, &live, &[986]),
            );
        }
        assert!(admitted.is_empty(), "unsafe adoptions: {admitted:?}");
        // A dispatch-named ref is never adopted: it takes the owned path,
        // which needs the run that created the branch.
        let mut named = pr.clone();
        named["head"]["ref"] = "work/dispatch-986-42".into();
        let error = admit(&event, &named, &issue, &comment, &[986])
            .unwrap_err()
            .to_string();
        assert!(error.contains("actions/runs/42"), "{error}");
        // The proof binds to the PR it was made for.
        let (loaded, adoption, _) = {
            write("pulls/1150", &pr);
            std::fs::write(&event_path, event.to_string()).unwrap();
            load_event(&fixture, &event_path, &mut owner_collaborator()).unwrap()
        };
        let mut moved = loaded.clone();
        moved["pull_request"]["head"]["sha"] = "c".repeat(40).into();
        assert!(
            validate_event_with_publication(
                &moved,
                "tjfontaine",
                &mut owner_collaborator(),
                None,
                adoption.as_ref(),
                None,
            )
            .is_err()
        );
        let mut review = loaded;
        review["review"] =
            json!({"state":"changes_requested","user":{"login":"tjfontaine","type":"User"}});
        review["action"] = "submitted".into();
        assert!(
            validate_event_with_publication(
                &review,
                "tjfontaine",
                &mut owner_collaborator(),
                None,
                adoption.as_ref(),
                None,
            )
            .is_err()
        );
    }
    /// The [`ISSUE_BRIEF_QUERY`] response for `issue`, unedited when
    /// `editor` is `None` and unrenamed unless [`issue_brief_renamed`] adds a
    /// `RENAMED_TITLE_EVENT`.
    /// #1241 part 3 through the production guard (`guard_admission`, hosted
    /// and clone phases) over the real `gh` transport: the chain rule admits
    /// an authentic chain and refuses each broken rule, and the run shape
    /// must be the chain job's dispatch.
    #[test]
    fn guard_admits_only_an_authentic_chain() {
        const CHILD: &str = "CARRICK_TEST_CHAIN_GUARD";
        let case = std::env::var("CHAIN_CASE").ok();
        let Some(case) = case.filter(|_| std::env::var_os(CHILD).is_some()) else {
            let mut wrong = Vec::new();
            let mut runs = chain_fixture::CASES
                .iter()
                .map(|(case, refused)| (case.to_string(), *refused, Vec::<(&str, &str)>::new()))
                .collect::<Vec<_>>();
            for (name, env) in [
                ("wrong actor", ("GITHUB_ACTOR", "tjfontaine")),
                (
                    "wrong triggering actor",
                    ("GITHUB_TRIGGERING_ACTOR", "tjfontaine"),
                ),
                ("wrong ref", ("GITHUB_REF", "refs/heads/work/x")),
                (
                    "wrong workflow",
                    (
                        "GITHUB_WORKFLOW_REF",
                        "carrick-sh/carrick/.github/workflows/ci.yml@refs/heads/main",
                    ),
                ),
                ("wrong event", ("GITHUB_EVENT_NAME", "issue_comment")),
            ] {
                runs.push((name.to_owned(), Some("chain job's"), vec![env]));
            }
            for (case, refused, overrides) in runs {
                let temp = tempfile::tempdir().unwrap();
                let bin = temp.path().join("bin");
                std::fs::create_dir(&bin).unwrap();
                crate::lock_file::tests::write_test_executable(
                    bin.join("gh"),
                    r#"#!/bin/sh
test "$1" = api || exit 93
if test "$2" = graphql; then cat "$CHAIN_FIXTURE/issue-graphql.json"; exit 0; fi
file="$CHAIN_FIXTURE/$(printf '%s' "$2" | tr '/' '_')"
test -f "$file" || { echo "gh: Not Found (HTTP 404) $2" >&2; exit 91; }
cat "$file"
"#,
                    std::fs::Permissions::from_mode(0o700),
                );
                let mut command = Command::new(std::env::current_exe().unwrap());
                command
                    .args([
                        "--exact",
                        std::thread::current().name().unwrap(),
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .env("CHAIN_CASE", &case)
                    .env("CHAIN_FIXTURE", temp.path())
                    .env("GH_TOKEN", "fixture-token")
                    .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                    .env("GITHUB_EVENT_NAME", "workflow_dispatch")
                    .env("GITHUB_REF", "refs/heads/main")
                    .env(
                        "GITHUB_WORKFLOW_REF",
                        "carrick-sh/carrick/.github/workflows/dispatch-worker.yml@refs/heads/main",
                    )
                    .env("GITHUB_ACTOR", CHAIN_ACTOR)
                    .env("GITHUB_TRIGGERING_ACTOR", CHAIN_ACTOR)
                    .env("CARRICK_DISPATCH_BASE", "f".repeat(40))
                    .env("RUNNER_TEMP", temp.path())
                    .env("GITHUB_RUN_ID", "77")
                    .env("GITHUB_RUN_ATTEMPT", "1")
                    .env_remove("CARRICK_DISPATCH_HEAD");
                for (key, value) in overrides {
                    command.env(key, value);
                }
                let output = command.output().unwrap();
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                let verdict = text
                    .lines()
                    .find_map(|l| l.strip_prefix("CHAIN-VERDICT: "))
                    .unwrap_or("no verdict")
                    .to_owned();
                let right = match refused {
                    None => verdict == "admitted",
                    Some(reason) => verdict.starts_with("refused") && verdict.contains(reason),
                };
                if !right || !output.status.success() {
                    wrong.push(format!("{case}: {verdict}\n{text}"));
                }
            }
            assert!(wrong.is_empty(), "{}", wrong.join("\n---\n"));
            return;
        };
        let fixture = PathBuf::from(std::env::var_os("CHAIN_FIXTURE").unwrap());
        // Run-shape cases keep the authentic chain and change the runner.
        let fixture_case = if chain_fixture::CASES.iter().any(|(c, _)| *c == case) {
            case.as_str()
        } else {
            "authentic"
        };
        let mut map = chain_fixture::chain_case(fixture_case);
        map.insert(
            format!("repos/{REPOSITORY}/actions/runs/42"),
            json!({"id":42,"status":"completed","repository":{"full_name":REPOSITORY},"head_repository":{"full_name":REPOSITORY},
                "path":".github/workflows/dispatch-worker.yml","event":"issues","head_branch":"main","head_sha":"a".repeat(40),
                "actor":{"login":"tjfontaine","type":"User"},"triggering_actor":{"login":"tjfontaine","type":"User"}}),
        );
        map.insert(
            format!("repos/{REPOSITORY}/collaborators/tjfontaine/permission"),
            json!({"permission":"admin"}),
        );
        map.insert(
            format!(
                "repos/{REPOSITORY}/pulls?state=open&base=main&head=carrick-sh:work/dispatch-799-42"
            ),
            json!([chain_fixture::pr()]),
        );
        for (endpoint, value) in &map {
            std::fs::write(fixture.join(endpoint.replace('/', "_")), value.to_string()).unwrap();
        }
        std::fs::write(
            fixture.join("issue-graphql.json"),
            issue_brief(&map[&format!("repos/{REPOSITORY}/issues/799")], None).to_string(),
        )
        .unwrap();
        let event_path = fixture.join("event.json");
        std::fs::write(
            &event_path,
            json!({"inputs":{"outcome":"30"},"workflow":".github/workflows/dispatch-worker.yml",
                "ref":"refs/heads/main","repository":{"full_name":REPOSITORY},
                "sender":{"login":CHAIN_ACTOR,"type":"Bot"}})
            .to_string(),
        )
        .unwrap();
        let root = fixture.canonicalize().unwrap();
        let hosted = guard_admission(&root, &event_path, false, || Ok(()));
        let verdict = match &hosted {
            Ok((event, dispatch)) => {
                // The clone repeats the rule and persists the chain facts
                // the loop starts from.
                let admitted = guard_admission(&root, &event_path, true, || Ok(())).unwrap();
                assert_eq!(admitted.1.branch, "work/dispatch-799-42");
                assert!(dispatch.resume && event["chain"]["id"] == 30);
                let admission = read_admission(&event_path).unwrap();
                let facts = admission.chain.unwrap();
                assert_eq!(facts.round, 3);
                assert_eq!(facts.from, chain_fixture::url(800, "issuecomment-30"));
                assert_eq!(facts.head, "c".repeat(40));
                assert_eq!(facts.brief, "next step 2");
                assert_eq!(admission.trigger["id"], 30);
                "admitted".to_owned()
            }
            Err(error) => format!("refused: {error}"),
        };
        println!("CHAIN-VERDICT: {verdict}");
    }
    /// #1241 part 3: the chain job sends exactly one dispatch, naming only
    /// the outcome id, for this run's Continuing outcome, and none for
    /// anything else; a Continuing outcome the rule refuses fails the job.
    #[test]
    fn chain_job_dispatches_once_for_its_own_continuing_outcome() {
        let attempt = |case: &str, run: &str| {
            let map = chain_fixture::chain_case(case);
            let mut calls = Vec::new();
            let result = chain_next(799, run, &mut chain_fixture::serve(&map), &mut |id| {
                calls.push(id);
                Ok(())
            });
            (result, calls)
        };
        let (result, calls) = attempt("authentic", "52");
        assert_eq!(calls, vec![30]);
        assert_eq!(
            result.unwrap().as_deref(),
            Some(chain_fixture::url(800, "issuecomment-30").as_str())
        );
        // Another run's outcome, a later Done, or nothing Continuing: no call.
        for (case, run) in [
            ("authentic", "51"),
            ("stale outcome", "52"),
            ("not continuing", "52"),
        ] {
            let (result, calls) = attempt(case, run);
            assert!(matches!(result, Ok(None)), "{case}: {result:?}");
            assert!(calls.is_empty(), "{case}: {calls:?}");
        }
        for case in ["owner comment after", "agent stop after", "round limit"] {
            let (result, calls) = attempt(case, "52");
            assert!(result.is_err(), "{case}: {result:?}");
            assert!(calls.is_empty(), "{case}: {calls:?}");
        }
    }
    fn issue_brief(issue: &Value, editor: Option<&str>) -> Value {
        json!({"data":{"repository":{"issue":{
            "number":issue["number"],
            "author":{"login":issue["user"]["login"]},
            "title":issue["title"].as_str().unwrap_or("Fixture issue"),
            "lastEditedAt":editor.map(|_| "2026-10-30T01:00:00Z"),
            "editor":editor.map(|login| json!({"__typename":"User","login":login})),
            "body":issue["body"],
            "renames":{"pageInfo":{"hasPreviousPage":false},"nodes":[]}}}}})
    }
    fn issue_brief_renamed(
        issue: &Value,
        editor: Option<&str>,
        renamer: &str,
        has_previous: bool,
    ) -> Value {
        let mut response = issue_brief(issue, editor);
        let title = response["data"]["repository"]["issue"]["title"]
            .as_str()
            .unwrap()
            .to_owned();
        response["data"]["repository"]["issue"]["renames"] = json!({
            "pageInfo":{"hasPreviousPage":has_previous},
            "nodes":[{
                "__typename":"RenamedTitleEvent",
                "actor":{"__typename":"User","login":renamer},
                "currentTitle":title,
            }],
        });
        response
    }
    const BRIEF_PERMISSIONS: &[(&str, &str)] = &[("tjfontaine", "admin"), ("writer", "write")];
    #[test]
    fn issue_brief_must_be_unedited_or_last_written_by_a_collaborator() {
        let issue = json!({"number":634,"title":"Initial title","body":"## Brief\nDo it","user":{"login":"outsider"}});
        let check = |response: &Value| {
            trusted_brief(response, 634, &mut fake_collaborators(BRIEF_PERMISSIONS))
        };
        // Unedited and unrenamed: title and body are what the collaborator saw.
        assert_eq!(
            check(&issue_brief(&issue, None)).unwrap(),
            TrustedBrief {
                title: "Initial title".into(),
                body: "## Brief\nDo it".into(),
            }
        );
        // Body edited or title renamed by a collaborator (including recovery
        // after an earlier rename where `hasPreviousPage` is true).
        for editor in ["writer", "tjfontaine"] {
            assert!(
                check(&issue_brief(&issue, Some(editor))).is_ok(),
                "{editor}"
            );
            for has_previous in [false, true] {
                assert_eq!(
                    check(&issue_brief_renamed(&issue, None, editor, has_previous)).unwrap(),
                    TrustedBrief {
                        title: "Initial title".into(),
                        body: "## Brief\nDo it".into(),
                    },
                    "{editor} has_previous={has_previous}"
                );
            }
        }
        // Body edited by the outsider (or anyone without write, or a Bot).
        for editor in ["outsider", "reader", "github-actions[bot]", ""] {
            let error = check(&issue_brief(&issue, Some(editor))).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("issue body was last edited by a non-collaborator"),
                "{editor}: {error}"
            );
        }
        let mut bot_editor = issue_brief(&issue, Some("writer"));
        bot_editor["data"]["repository"]["issue"]["editor"]["__typename"] = "Bot".into();
        assert!(
            check(&bot_editor)
                .unwrap_err()
                .to_string()
                .contains("issue body was last edited by a non-collaborator")
        );
        // Title renamed by the outsider, a reader, a Bot, or a deleted user,
        // even when the body is untouched or was edited by a collaborator.
        for renamer in ["outsider", "reader", "github-actions[bot]", ""] {
            for body_editor in [None, Some("writer")] {
                let error =
                    check(&issue_brief_renamed(&issue, body_editor, renamer, false)).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("issue title was last edited by a non-collaborator"),
                    "{renamer} ({body_editor:?}): {error}"
                );
            }
        }
        let mut bot_renamer = issue_brief_renamed(&issue, None, "writer", false);
        bot_renamer["data"]["repository"]["issue"]["renames"]["nodes"][0]["actor"]["__typename"] =
            "Bot".into();
        assert!(
            check(&bot_renamer)
                .unwrap_err()
                .to_string()
                .contains("issue title was last edited by a non-collaborator")
        );
        let mut deleted_renamer = issue_brief_renamed(&issue, None, "writer", false);
        deleted_renamer["data"]["repository"]["issue"]["renames"]["nodes"][0]["actor"] =
            Value::Null;
        assert!(
            check(&deleted_renamer)
                .unwrap_err()
                .to_string()
                .contains("issue title was last edited by a non-collaborator")
        );
        // Fail closed: errors, another issue, title/timeline skew, and missing fields.
        let mut refused = vec![
            json!({"errors":[{"message":"rate limited"}],"data":null}),
            json!({"data":{"repository":{"issue":null}}}),
            json!({}),
        ];
        let mut other = issue_brief(&issue, None);
        other["data"]["repository"]["issue"]["number"] = 635.into();
        refused.push(other);
        for field in ["number", "title", "body", "lastEditedAt", "renames"] {
            let mut missing = issue_brief(&issue, None);
            missing["data"]["repository"]["issue"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            refused.push(missing);
        }
        let mut no_editor = issue_brief(&issue, Some("writer"));
        no_editor["data"]["repository"]["issue"]["editor"] = Value::Null;
        refused.push(no_editor);
        let mut empty_time = issue_brief(&issue, None);
        empty_time["data"]["repository"]["issue"]["lastEditedAt"] = "".into();
        refused.push(empty_time);
        let mut truncated_renames = issue_brief(&issue, None);
        truncated_renames["data"]["repository"]["issue"]["renames"]["pageInfo"]["hasPreviousPage"] =
            true.into();
        refused.push(truncated_renames);
        let mut null_rename_node = issue_brief(&issue, None);
        null_rename_node["data"]["repository"]["issue"]["renames"]["nodes"] = json!([null]);
        refused.push(null_rename_node);
        let mut wrong_typename = issue_brief_renamed(&issue, None, "writer", false);
        wrong_typename["data"]["repository"]["issue"]["renames"]["nodes"][0]["__typename"] =
            "LabeledEvent".into();
        refused.push(wrong_typename);
        let mut stale_rename = issue_brief_renamed(&issue, None, "writer", false);
        stale_rename["data"]["repository"]["issue"]["renames"]["nodes"][0]["currentTitle"] =
            "Earlier title".into();
        refused.push(stale_rename);
        let mut two_renames = issue_brief_renamed(&issue, None, "writer", false);
        let node = two_renames["data"]["repository"]["issue"]["renames"]["nodes"][0].clone();
        two_renames["data"]["repository"]["issue"]["renames"]["nodes"] = json!([node, node]);
        refused.push(two_renames);
        for response in refused {
            assert!(check(&response).is_err(), "admitted {response}");
        }
        // Both title and body come from the checked response, never the event's copy.
        let mut event =
            json!({"issue":{"number":634,"title":"stale event title","body":"stale event body"}});
        apply_trusted_brief(
            &mut event,
            |n| {
                Ok(issue_brief(
                    &json!({"number":n,"title":"live title","body":"live","user":{"login":"x"}}),
                    None,
                ))
            },
            &mut fake_collaborators(BRIEF_PERMISSIONS),
        )
        .unwrap();
        assert_eq!(event["issue"]["title"], "live title");
        assert_eq!(event["issue"]["body"], "live");
        assert!(
            apply_trusted_brief(
                &mut event,
                |_| Err(ScalerError::Guard("gh: HTTP 502")),
                &mut fake_collaborators(BRIEF_PERMISSIONS),
            )
            .is_err()
        );
    }
    /// The production `load_event` on every path that turns an issue into a
    /// [`Dispatch`]: a label, an `/agent` comment on the issue, an `/agent`
    /// follow-up on an owned dispatch PR, and adoption of a director PR.
    #[test]
    fn every_brief_path_refuses_an_issue_body_an_outsider_edited() {
        const CHILD: &str = "CARRICK_TEST_DISPATCH_BRIEF";
        if std::env::var_os(CHILD).is_none() {
            let temp = tempfile::tempdir().unwrap();
            let bin = temp.path().join("bin");
            std::fs::create_dir(&bin).unwrap();
            crate::lock_file::tests::write_test_executable(
                bin.join("gh"),
                r#"#!/bin/sh
test "$1" = api || exit 93
test "$GH_TOKEN" = fixture-token || exit 92
if test "$2" = graphql; then
 case "$*" in *lastEditedAt*) cat "$BRIEF_FIXTURE/issue-graphql.json" ;; *) cat "$BRIEF_FIXTURE/graphql.json" ;; esac
 exit 0
fi
file="$BRIEF_FIXTURE/$(printf '%s' "$2" | tr '/' '_')"
test -f "$file" || { echo "unexpected endpoint $2" >&2; exit 91; }
cat "$file"
"#,
                std::fs::Permissions::from_mode(0o700),
            );
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    std::thread::current().name().unwrap(),
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("BRIEF_FIXTURE", temp.path())
                .env("GH_TOKEN", "fixture-token")
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .env("CARRICK_DISPATCH_HEAD", "a".repeat(40))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let fixture = PathBuf::from(std::env::var_os("BRIEF_FIXTURE").unwrap());
        let write = |name: &str, value: &Value| {
            std::fs::write(
                fixture.join(format!("repos/{REPOSITORY}/{name}").replace('/', "_")),
                value.to_string(),
            )
            .unwrap();
        };
        let tip = "a".repeat(40);
        let comment = json!({"id":123,"user":{"login":"tjfontaine","type":"User"},"body":"/agent go","created_at":"2026-10-30T00:00:00Z","updated_at":"2026-10-30T00:00:00Z"});
        write("issues/comments/123", &comment);
        // An outsider filed #634; REST and webhook copies have distinct titles
        // and bodies so only the verified GraphQL snapshot can match both.
        let rest_issue = json!({"number":634,"state":"open","title":"untrusted REST title","body":"untrusted REST body","user":{"login":"outsider","type":"User"}});
        write("issues/634", &rest_issue);
        let graphql_issue = json!({"number":634,"state":"open","title":"verified GraphQL title","body":"edited by outsider","user":{"login":"outsider","type":"User"}});
        let event_issue = json!({"number":634,"state":"open","title":"stale event title","body":"approved text","user":{"login":"outsider","type":"User"}});
        let base = json!({"repository":{"full_name":REPOSITORY},"sender":{"login":"tjfontaine","type":"User"}});
        let mut label = base.clone();
        label["action"] = "labeled".into();
        label["label"] = json!({"name":"dispatch"});
        label["issue"] = event_issue.clone();
        let mut on_issue = base.clone();
        on_issue["action"] = "created".into();
        on_issue["comment"] = comment.clone();
        on_issue["issue"] = event_issue.clone();
        // Owned follow-up: `/agent` on the dispatch PR re-reads issue 634.
        let owned_pr = json!({"number":800,"state":"open","user":{"login":"github-actions[bot]","type":"Bot"},
            "head":{"ref":"work/dispatch-634-42","sha":tip,"repo":{"full_name":REPOSITORY}},
            "base":{"ref":"main","repo":{"full_name":REPOSITORY}},"draft":true,
            "body":format!("Closes #634\nDispatch run: https://github.com/{REPOSITORY}/actions/runs/42")});
        write("pulls/800", &owned_pr);
        write(
            "actions/runs/42",
            &json!({"id":42,"path":".github/workflows/dispatch-worker.yml","event":"issues","head_branch":"main","head_sha":tip,"repository":{"full_name":REPOSITORY},"head_repository":{"full_name":REPOSITORY},"actor":{"login":"tjfontaine","type":"User"},"triggering_actor":{"login":"tjfontaine","type":"User"}}),
        );
        let mut owned = on_issue.clone();
        owned["issue"] = json!({"number":800,"state":"open","pull_request":{"url":"pr"}});
        // Adoption: `/agent` on a director PR closing issue 634.
        let director_pr = json!({"number":1150,"state":"open","user":{"login":"tjfontaine","type":"User"},
            "head":{"ref":"work/634-slice","sha":tip,"repo":{"full_name":REPOSITORY}},
            "base":{"ref":"main","repo":{"full_name":REPOSITORY}},"body":"Closes #634"});
        write("pulls/1150", &director_pr);
        let connection = json!({"nodes":[{"number":634,"repository":{"nameWithOwner":REPOSITORY}}],"pageInfo":{"hasNextPage":false}});
        std::fs::write(
            fixture.join("graphql.json"),
            json!({"data":{"repository":{"pullRequest":{"closingIssuesReferences":connection,"bodyReferences":connection}}}}).to_string(),
        )
        .unwrap();
        let mut adopt = on_issue.clone();
        adopt["issue"] = json!({"number":1150,"state":"open","pull_request":{"url":"pr"}});
        let event_path = fixture.join("event.json");
        for (path, event) in [
            ("label", &label),
            ("issue comment", &on_issue),
            ("owned follow-up", &owned),
            ("adoption", &adopt),
        ] {
            std::fs::write(&event_path, event.to_string()).unwrap();
            let load = || {
                let (loaded, adoption, _) = load_event(
                    &fixture,
                    &event_path,
                    &mut fake_collaborators(BRIEF_PERMISSIONS),
                )?;
                validate_event_with_publication(
                    &loaded,
                    "tjfontaine",
                    &mut fake_collaborators(BRIEF_PERMISSIONS),
                    None,
                    adoption.as_ref(),
                    None,
                )
            };
            // Unedited and unrenamed since filing: accepted, and both
            // Dispatch.title and Dispatch.body come from the GraphQL snapshot.
            std::fs::write(
                fixture.join("issue-graphql.json"),
                issue_brief(&graphql_issue, None).to_string(),
            )
            .unwrap();
            let dispatch = load().unwrap_or_else(|e| panic!("{path}: unedited refused: {e}"));
            assert_eq!(dispatch.title, "verified GraphQL title", "{path}");
            assert_eq!(dispatch.body, "edited by outsider", "{path}");
            // Body edited by a collaborator: accepted.
            std::fs::write(
                fixture.join("issue-graphql.json"),
                issue_brief(&graphql_issue, Some("writer")).to_string(),
            )
            .unwrap();
            assert!(load().is_ok(), "{path}: collaborator edit refused");
            // Retitled by a collaborator (even after an earlier rename): accepted.
            std::fs::write(
                fixture.join("issue-graphql.json"),
                issue_brief_renamed(&graphql_issue, None, "writer", true).to_string(),
            )
            .unwrap();
            let dispatch =
                load().unwrap_or_else(|e| panic!("{path}: collaborator retitle refused: {e}"));
            assert_eq!(dispatch.title, "verified GraphQL title", "{path}");
            // Retitled by the outsider without touching the body: refused.
            std::fs::write(
                fixture.join("issue-graphql.json"),
                issue_brief_renamed(&graphql_issue, None, "outsider", false).to_string(),
            )
            .unwrap();
            let error = load().map(|_| ()).unwrap_err().to_string();
            assert!(
                error.contains("issue title was last edited by a non-collaborator"),
                "{path}: {error}"
            );
            // Body edited by the outsider after approval: refused.
            std::fs::write(
                fixture.join("issue-graphql.json"),
                issue_brief(&graphql_issue, Some("outsider")).to_string(),
            )
            .unwrap();
            let error = load().map(|_| ()).unwrap_err().to_string();
            assert!(
                error.contains("issue body was last edited by a non-collaborator"),
                "{path}: {error}"
            );
            // GraphQL failure: refused.
            std::fs::write(
                fixture.join("issue-graphql.json"),
                r#"{"errors":[{"message":"boom"}]}"#,
            )
            .unwrap();
            assert!(load().is_err(), "{path}: GraphQL error admitted");
        }
    }
    #[test]
    fn adoption_predicate_refuses_dispatch_named_refs_before_any_read() {
        let pr = json!({"number":1150,"state":"open","user":{"login":"tjfontaine","type":"User"},
            "head":{"ref":"work/dispatch-986-42","sha":"a".repeat(40),"repo":{"full_name":REPOSITORY}},
            "base":{"ref":"main","repo":{"full_name":REPOSITORY}}});
        let refused = adopted_pr(&pr, |_| -> Result<Value, ScalerError> {
            panic!("a dispatch-named ref must be refused before any server read")
        })
        .unwrap();
        assert!(refused.is_none());
    }
    #[test]
    fn adopted_push_targets_only_the_adopted_ref_under_the_admitted_lease() {
        let temp = tempfile::tempdir().unwrap();
        fixture_repository(temp.path());
        let tip = "a".repeat(40);
        let mut dispatch =
            validate_event(&event(), "tjfontaine", &mut owner_collaborator()).unwrap();
        dispatch.issue = 986;
        dispatch.branch = "work/986-slice4".into();
        dispatch.resume = true;
        dispatch.continuation = Continuation::Adopted {
            rebase: false,
            pr: 1150,
            branch: dispatch.branch.clone(),
            tip: tip.clone(),
        };
        git(temp.path(), &["checkout", "-b", &dispatch.branch]).unwrap();
        let command = push_command(temp.path(), &dispatch, "", &RunLease::admitted(&tip)).unwrap();
        let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(args.last(), Some(&"HEAD:refs/heads/work/986-slice4"));
        assert_eq!(args.iter().filter(|s| s.starts_with("HEAD:")).count(), 1);
        let lease = format!("--force-with-lease=refs/heads/work/986-slice4:{tip}");
        assert!(args.contains(&lease.as_str()), "{args:?}");
        // Any lease but the admitted tip, including none, is refused.
        assert!(push_command(temp.path(), &dispatch, "", &RunLease::admitted("")).is_err());
        assert!(
            push_command(
                temp.path(),
                &dispatch,
                "",
                &RunLease::admitted(&"b".repeat(40))
            )
            .is_err()
        );
        // The run id of an owned branch never redirects an adopted push.
        assert!(push_command(temp.path(), &dispatch, "42", &RunLease::admitted(&tip)).is_ok());
        // Any other checked-out or requested branch is refused.
        for branch in ["work/dispatch-986-42", "work/another-lane", "main"] {
            git(temp.path(), &["checkout", "-B", branch]).unwrap();
            assert!(
                push_command(temp.path(), &dispatch, "42", &RunLease::admitted(&tip)).is_err(),
                "{branch}"
            );
            let mut other = dispatch.clone();
            other.branch = branch.into();
            assert!(
                push_command(temp.path(), &other, "42", &RunLease::admitted(&tip)).is_err(),
                "{branch}"
            );
        }
        git(temp.path(), &["checkout", "-B", "work/dispatch-986-42"]).unwrap();
        let mut forged = dispatch.clone();
        forged.branch = "work/dispatch-986-42".into();
        forged.continuation = Continuation::Adopted {
            rebase: false,
            pr: 1150,
            branch: forged.branch.clone(),
            tip: tip.clone(),
        };
        assert!(push_command(temp.path(), &forged, "42", &RunLease::admitted(&tip)).is_err());
    }
    #[test]
    fn review_base_uses_admitted_main_and_never_the_merge_sha() {
        let main = "a".repeat(40);
        let merge = "b".repeat(40);
        assert_eq!(select_base(true, Some(&main), Some(&merge)).unwrap(), main);
        assert_eq!(
            select_base(false, Some(&main), Some(&merge)).unwrap(),
            merge
        );
        assert!(select_base(true, None, Some(&merge)).is_err());
    }
    #[test]
    fn snapshot_obeys_harvest_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        fixture_repository(&source);
        let branch = git(&source, &["symbolic-ref", "--short", "HEAD"]).unwrap();
        let _window = CommandWindow::until(std::time::Instant::now());
        assert!(
            snapshot(&source, &temp.path().join("snapshot"), branch.trim()).is_err(),
            "snapshot ignored expired harvest deadline"
        );
    }
    #[test]
    fn loop_deadline_refuses_commands_before_they_execute() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("executed");
        {
            let _window = CommandWindow::until(std::time::Instant::now());
            assert!(output(Command::new("/usr/bin/touch").arg(&marker)).is_err());
        }
        assert!(!marker.exists());
        // Reporting commands can run after the tool window closes.
        assert!(output(&mut Command::new("/usr/bin/true")).is_ok());
    }
}
