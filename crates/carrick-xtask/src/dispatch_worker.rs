//! Owner-authorized dispatch driver. Workflow input never becomes shell source.
use crate::ci_scaler::{REPOSITORY, ScalerError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[path = "dispatch_loop.rs"]
mod agent_loop;

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

pub fn trusted_actor(actor: &str) -> bool {
    actor == "tjfontaine"
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
    #[serde(skip)]
    pub worker_seconds: Option<u64>,
    #[serde(skip)]
    pub loop_deadline: Option<std::time::Instant>,
}

/// Runner-private result of credentialed admission; provider setup and the
/// coordinator consume this snapshot rather than re-resolving mutable labels.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmittedDispatch {
    pub dispatch: Dispatch,
    pub trigger: Value,
    event_digest: String,
}
fn event_digest(path: &Path) -> Result<String, ScalerError> {
    use sha2::{Digest, Sha256};
    Ok(format!(
        "{:x}",
        Sha256::digest(regular_text(path)?.as_bytes())
    ))
}
fn persist_admission(dispatch: &Dispatch, event: &Value, path: &Path) -> Result<(), ScalerError> {
    let state = crate::agent_runner::state()?;
    std::fs::create_dir_all(&state)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
    let admission = AdmittedDispatch {
        dispatch: dispatch.clone(),
        trigger: if event.get("review").is_some() {
            event["review"].clone()
        } else if event.get("comment").is_some() {
            event["comment"].clone()
        } else {
            event["label"].clone()
        },
        event_digest: event_digest(path)?,
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
pub(crate) fn agent_comment(comment: &Value) -> bool {
    let body = comment["body"].as_str().unwrap_or_default();
    comment["user"]["login"] == "tjfontaine"
        && comment["user"]["type"] == "User"
        && comment["created_at"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
        && comment["created_at"] == comment["updated_at"]
        && (body == "/agent"
            || body
                .strip_prefix("/agent")
                .is_some_and(|s| s.starts_with(char::is_whitespace)))
}

pub(crate) fn comment_digest(comment: &Value) -> String {
    use sha2::{Digest, Sha256};
    let data = json!({"id":comment["id"],"body":comment["body"],"created_at":comment["created_at"],"updated_at":comment["updated_at"]});
    format!("{:x}", Sha256::digest(data.to_string().as_bytes()))
}

pub fn validate_event(event: &Value, triggering_actor: &str) -> Result<Dispatch, ScalerError> {
    let review = event.get("review").is_some();
    let comment = event.get("comment").is_some();
    if event["repository"]["full_name"] != REPOSITORY
        || !trusted_actor(event["sender"]["login"].as_str().unwrap_or_default())
        || !trusted_actor(triggering_actor)
        || event["sender"]["type"] != "User"
        || event["issue"]["user"]["login"] != "tjfontaine"
        || event["issue"].get("pull_request").is_some()
    {
        return Err(ScalerError::Guard(
            "dispatch requires owner actors and an owner-authored issue",
        ));
    }
    let issue = event["issue"]["number"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(ScalerError::Guard("missing issue number"))?;
    if review {
        if event["action"] != "submitted"
            || event["review"]["state"] != "changes_requested"
            || event["review"]["user"]["login"] != "tjfontaine"
            || event["review"]["user"]["type"] != "User"
        {
            return Err(ScalerError::Guard(
                "review requires owner changes_requested",
            ));
        }
    } else if comment {
        if event["action"] != "created"
            || event["issue"]["state"] != "open"
            || !agent_comment(&event["comment"])
        {
            return Err(ScalerError::Guard(
                "comment requires an unedited owner /agent creation",
            ));
        }
    } else if event["action"] != "labeled"
        || !event["label"]["name"].as_str().is_some_and(dispatch_label)
    {
        return Err(ScalerError::Guard("not a dispatch label event"));
    }
    let resume = event.get("pull_request").is_some();
    let branch = if resume {
        let pr = &event["pull_request"];
        let branch = pr["head"]["ref"].as_str().unwrap_or_default();
        if event["issue"]["state"] != "open" || !owned_pr(pr, &event["dispatch_run"], issue, branch)
        {
            return Err(ScalerError::Guard(
                "trigger requires an open issue and owned dispatch PR",
            ));
        }
        branch.to_owned()
    } else {
        format!("work/dispatch-{issue}-pending")
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
        worker_seconds: None,
        loop_deadline: None,
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
fn account_command(command: &Command, user: &str, root: &Path) -> Command {
    let mut isolated = Command::new("/usr/bin/sudo");
    private_environment(&mut isolated);
    isolated
        .args(["-n", "-u", user, "--", "/usr/bin/env", "-i", "-C"])
        .arg(root);
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            let mut assignment = key.to_os_string();
            assignment.push("=");
            assignment.push(value);
            isolated.arg(assignment);
        }
    }
    isolated
        .arg(command.get_program())
        .args(command.get_args())
        .current_dir("/")
        .stdin(Stdio::null());
    isolated
}

fn worker_prompt(dispatch: &Dispatch) -> String {
    format!(
        "Work issue {REPOSITORY}#{} on branch {}. Read AGENTS.md in full.\n\
        Rebase onto admitted main {} (refs/carrick/dispatch-main) before working.\n\
        Resolve any conflicts in this isolated checkout; preserve earlier workers' commits.\n\
        Implement and verify this brief. Commit your work with a Why/What/Verified body and\n\
        Co-Authored-By: {}\nDo not push, open a PR, or post comments; the workflow publishes those.\n\
        Never use --no-verify, git stash or git add -A. Keep conformance-probes/target out of commits.\n\
        This is an ephemeral runner. Use local shared carrick leases for builds.\n\
        Contabo leases are per VM under owner decision #639; never acquire a hypervisor lease.\n\
        Run only gates supported by this host; report unavailable Docker, KVM or HVF honestly.\n\
        Return the requested JSON contract, stating unrun gates and blockers honestly.\n\n{}{}",
        dispatch.issue,
        dispatch.branch,
        dispatch.base,
        dispatch.worker.coauthor,
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
        .current_dir(root);
    let mut isolated = account_command(&command, AGENT_USER, root);
    hand_over(&state)?;
    let logs = crate::agent_runner::state()?;
    isolated
        .stdout(std::fs::File::create(logs.join("agent.out"))?)
        .stderr(std::fs::File::create(logs.join("agent.err"))?);
    let remaining = dispatch
        .loop_deadline
        .map(|d| d.saturating_duration_since(std::time::Instant::now()))
        .unwrap_or(limit);
    let outcome = wait_agent(
        &mut isolated,
        remaining
            .min(limit)
            .min(crate::agent_runner::job_remaining(58)?),
    );
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

std::thread_local! {
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
    crate::safe_copy::git_command(root, args)
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
    String::from_utf8(output(Command::new("gh").args(args).current_dir(root))?)
        .map_err(|_| ScalerError::Guard("non-UTF8 GitHub output"))
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
    for _ in 0..100 {
        crate::process_helper::run_checked(command)?;
        let mut empty = true;
        for selector in ["-u", "-U"] {
            let status = Command::new("/usr/bin/pgrep")
                .args([selector, user])
                .output()?;
            match status.status.code() {
                Some(1) if status.stdout.is_empty() && status.stderr.is_empty() => {}
                Some(0) => {
                    empty = false;
                    // Reap only this uid's adopted children. A loop launcher may
                    // exit while a worker retires; its Child still owns its wait.
                    for pid in String::from_utf8_lossy(&status.stdout).split_whitespace() {
                        let pid = pid
                            .parse::<libc::pid_t>()
                            .map_err(|_| ScalerError::Guard("invalid retirement census pid"))?;
                        // SAFETY: WNOHANG reaps only this named completed child.
                        unsafe {
                            libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG);
                        }
                    }
                }
                _ => return Err(ScalerError::Guard("cannot verify agent process retirement")),
            }
        }
        if empty {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err(ScalerError::Guard(
        "agent user still has processes; packaging refused",
    ))
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

/// Run identity for controller admission and #799 PR ownership. Artifact and
/// publication provenance additionally authenticate main workflow and jobs.
/// The issue constraint is checked against every available issue/branch mapping.
pub(crate) fn dispatch_run_identity(run: &Value, issue: Option<u64>) -> bool {
    let branch = run["head_branch"].as_str().unwrap_or_default();
    let review_issue = dispatch_branch(branch);
    if run["repository"]["full_name"] != REPOSITORY
        || run["head_repository"]["full_name"] != REPOSITORY
        || run["path"] != ".github/workflows/dispatch-worker.yml"
        || !run["head_sha"]
            .as_str()
            .is_some_and(crate::ci_scaler::full_sha)
        || ![&run["actor"], &run["triggering_actor"]]
            .iter()
            .all(|actor| actor["login"] == "tjfontaine" && actor["type"] == "User")
        || !((matches!(run["event"].as_str(), Some("issues" | "issue_comment"))
            && branch == "main")
            || (run["event"] == "pull_request_review" && review_issue.is_some()))
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

pub(crate) fn owned_pr(pr: &Value, run: &Value, issue: u64, branch: &str) -> bool {
    let Ok(id) = branch_run(issue, branch) else {
        return false;
    };
    pr["user"]["login"] == "github-actions[bot]"
        && pr["user"]["type"] == "Bot"
        && pr["head"]["repo"]["full_name"] == REPOSITORY
        && pr["head"]["ref"] == branch
        && pr["base"]["ref"] == "main"
        && pr["draft"] == true
        && run["id"].as_u64().map(|n| n.to_string()).as_deref() == Some(id)
        && dispatch_run_identity(run, Some(issue))
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
        if owned_pr(pr, &run, dispatch.issue, &dispatch.branch) {
            return Ok(pr.clone());
        }
    }
    Err(ScalerError::Guard(
        "branch lacks a draft PR created by its dispatch run",
    ))
}

fn regular_text(path: &Path) -> Result<String, ScalerError> {
    Ok(crate::safe_copy::text(path, 20 * 1024 * 1024)?)
}

#[derive(Serialize, Deserialize)]
struct Receipt {
    base: String,
    branch: String,
    exit_code: i32,
    expected_tip: String,
    refused_workflow: bool,
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

/// Resolve only server-owned scope. Model text is never parsed for branches.
pub(crate) fn load_event(root: &Path, path: &Path) -> Result<Value, ScalerError> {
    let mut event: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    if !trusted_actor(event["sender"]["login"].as_str().unwrap_or_default()) {
        return Err(ScalerError::Guard("untrusted event actor"));
    }
    if event.get("comment").is_some() {
        let id = event["comment"]["id"]
            .as_u64()
            .ok_or(ScalerError::Guard("missing comment id"))?;
        let live = api(root, &format!("repos/{REPOSITORY}/issues/comments/{id}"))?;
        if !agent_comment(&live)
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
        let issue =
            dispatch_branch(&branch).ok_or(ScalerError::Guard("not a dispatch head ref"))?;
        let id = branch_run(issue, &branch)?;
        let number = event["pull_request"]["number"]
            .as_u64()
            .ok_or(ScalerError::Guard("missing PR number"))?;
        let live = api(root, &format!("repos/{REPOSITORY}/pulls/{number}"))?;
        let expected = std::env::var("CARRICK_DISPATCH_HEAD")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                event["pull_request"]["head"]["sha"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned()
            });
        if !sha(&expected) || live["head"]["sha"] != expected {
            return Err(ScalerError::Guard("stale PR head"));
        }
        event["pull_request"] = live;
        event["dispatch_run"] = api(root, &format!("repos/{REPOSITORY}/actions/runs/{id}"))?;
        event["issue"] = api(root, &format!("repos/{REPOSITORY}/issues/{issue}"))?;
    }
    Ok(event)
}

/// Select a single open owned PR, authenticating the original branch run.
fn select_owned_pr(
    issue: u64,
    prs: &[Value],
    mut run: impl FnMut(&str) -> Result<Value, ScalerError>,
) -> Result<Option<Value>, ScalerError> {
    let mut selected = None;
    for pr in prs.iter().filter(|pr| pr["state"] == "open") {
        let branch = pr["head"]["ref"].as_str().unwrap_or_default();
        if dispatch_branch(branch) != Some(issue) {
            continue;
        }
        let original = run(branch_run(issue, branch)?)?;
        if owned_pr(pr, &original, issue, branch) {
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

pub fn run(root: &Path, args: DispatchArgs) -> Result<(), ScalerError> {
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
        DispatchAction::Tool { .. } => return Err(ScalerError::Guard("tool already handled")),
        DispatchAction::Loop {
            event,
            setup_status,
        } => return agent_loop::run(&root, &event, &setup_status),
        DispatchAction::Guard { event, admit, .. } => (event, admit),
    };
    let event = load_event(&root, &event_path)?;
    let mut dispatch = validate_event(
        &event,
        &std::env::var("GITHUB_TRIGGERING_ACTOR").unwrap_or_default(),
    )?;
    dispatch.base = admitted_base(dispatch.review || event.get("comment").is_some())?;
    if admit {
        cleanup_agent_user()?;
    }
    assigned_branch(&mut dispatch)?;
    branch_run(dispatch.issue, &dispatch.branch)?;
    if admit {
        if dispatch.resume {
            require_owned_pr(&root, &dispatch)?;
        }
        persist_admission(&dispatch, &event, &event_path)?;
    }
    if let Some(path) = std::env::var_os("GITHUB_OUTPUT") {
        use std::io::Write;
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "base={}\nhead={}\nissue={}\ncomment={}",
            dispatch.base,
            event["pull_request"]["head"]["sha"]
                .as_str()
                .unwrap_or_default(),
            dispatch.issue,
            comment_digest(&event["comment"])
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
    crate::safe_copy::repository(source, target, branch)
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
fn produce(root: &Path, dispatch: &Dispatch, setup: &str) -> Result<(), ScalerError> {
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
        status: ContractStatus::Failed,
        summary: format!("Worker setup did not complete: {setup}"),
        tests: vec![],
        risks: vec![],
    };
    let mut code = 1;
    let mut expected_tip = if work.is_dir() && state.join("receipt.json").exists() {
        let previous: Receipt = serde_json::from_str(&regular_text(&state.join("receipt.json"))?)?;
        if previous.base != base || previous.branch != dispatch.branch {
            return Err(ScalerError::Guard("previous worker scope changed"));
        }
        previous.expected_tip
    } else {
        String::new()
    };
    let mut raw = if package.join("raw.log").is_file() {
        regular_text(&package.join("raw.log"))?
    } else {
        String::new()
    };
    let mut diffstat = String::new();
    let mut refused_workflow = setup != "success/success";
    if setup == "success/success" {
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
        let outer = tempfile::Builder::new()
            .prefix("carrick-dispatch-")
            .tempdir_in("/var/tmp")?;
        std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o711))?;
        let actor = outer.path().join("agent");
        std::fs::create_dir(&actor)?;
        std::fs::set_permissions(&actor, std::fs::Permissions::from_mode(0o700))?;
        prepare_worker_actor(&state, &actor, &dispatch.worker.backend)?;
        let actor_work = actor.join("work");
        let previous: Option<Receipt> = if work.is_dir() {
            Some(serde_json::from_str(&regular_text(
                &state.join("receipt.json"),
            )?)?)
        } else {
            None
        };
        expected_tip = worker_checkout(root, &work, &actor_work, dispatch, previous.as_ref())?;
        git(&actor_work, &["config", "user.name", "github-actions[bot]"])?;
        git(
            &actor_work,
            &[
                "config",
                "user.email",
                "41898282+github-actions[bot]@users.noreply.github.com",
            ],
        )?;
        let result = agent(&actor_work, dispatch);
        // This is mandatory even on launcher failure, before scanning or hand-back.
        cleanup_agent_user()?;
        // Read agent files only as data after verified uid retirement. The
        // pre-created private group lets runner read without becoming root.
        let actor_path = actor.to_str().ok_or(ScalerError::Guard("agent state"))?;
        sudo(&["/usr/bin/chgrp", "-hR", AGENT_USER, actor_path])?;
        sudo(&["/usr/bin/chmod", "-R", "ug+rwX,o-rwx", actor_path])?;
        code = result?;
        if work.exists() {
            std::fs::remove_dir_all(&work)?;
        }
        snapshot(&actor_work, &work, &dispatch.branch)?;
        let evidence;
        (contract, evidence) = read_result(&actor.join("result.json"));
        for name in ["agent.out", "agent.err"] {
            raw.push_str(&format!("=== {name} ===\n"));
            raw.push_str(&regular_text(&state.join(name))?);
        }
        raw.push_str(&evidence);
        if checkpoint(&work, dispatch)? {
            contract.status = ContractStatus::Failed;
            contract
                .risks
                .push("Workflow checkpointed unfinished changes".into());
        }
        refused_workflow = git(
            &work,
            &["diff", "--name-only", "--no-renames", "-z", &base, "HEAD"],
        )?
        .split('\0')
        .any(|path| path.starts_with(".github/workflows/"));
        if refused_workflow {
            contract.status = ContractStatus::Failed;
            contract.risks.push(
                "Refused workflow changes: job token cannot publish .github/workflows/*".into(),
            );
        }
        diffstat = git(&work, &["diff", "--stat", &base, "HEAD"])?;
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
        format!("{transcript}\n## Agent transcript\n\n{rendered_log}"),
    )?;
    std::fs::write(
        package.join("contract.json"),
        serde_json::to_vec_pretty(&contract)?,
    )?;
    std::fs::write(package.join("diffstat.txt"), diffstat)?;
    // This receipt stays on the disposable runner; it is not transferred or uploaded.
    std::fs::write(
        state.join("receipt.json"),
        serde_json::to_vec(&Receipt {
            base,
            branch: dispatch.branch.clone(),
            exit_code: code,
            expected_tip,
            refused_workflow,
        })?,
    )?;
    Ok(())
}

/// The destination is derived from the admitted event, never from agent output.
fn push_command(
    root: &Path,
    dispatch: &Dispatch,
    id: &str,
    expected: &str,
) -> Result<Command, ScalerError> {
    let branch = format!("work/dispatch-{}-{id}", dispatch.issue);
    branch_run(dispatch.issue, &branch)?;
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
        ]
        .contains(&name)
        {
            return Err(ScalerError::Guard("unexpected dispatch artifact"));
        }
        let text = regular_text(&entry.path())?;
        let mask = |text: &str| {
            crate::dispatch_redaction::redact(text.replace(token, "[REDACTED]").as_bytes())
        };
        let masked = if name == "contract.json" {
            let mut contract: Contract = serde_json::from_str(&text)?;
            contract.summary = mask(&contract.summary);
            contract.tests = contract.tests.iter().map(|s| mask(s)).collect();
            contract.risks = contract.risks.iter().map(|s| mask(s)).collect();
            serde_json::to_string_pretty(&contract)?
        } else if name == "handoff.json" {
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
            serde_json::to_string_pretty(&value)?
        } else {
            mask(&text)
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
    for name in names {
        if regular_text(&package.join(name))?.contains(token) {
            return Err(ScalerError::Guard("job token found in upload"));
        }
    }
    Ok(())
}

fn publish(
    root: &Path,
    dispatch: &Dispatch,
    receipt: &Receipt,
    contract: &Contract,
    report_path: &Path,
    token: &str,
) -> Result<Option<u64>, ScalerError> {
    let state = crate::agent_runner::state()?;
    let work = state.join("work");
    let id = branch_run(dispatch.issue, &dispatch.branch)?;
    if !receipt.refused_workflow
        && work.is_dir()
        && git(&work, &["rev-parse", "HEAD"])?.trim() != receipt.base
    {
        if dispatch.resume {
            agent_loop::verified_branch(root, dispatch.issue, &dispatch.branch)?;
        } else {
            branch_prs(root, &dispatch.branch, "all")?;
        }
        git(
            &work,
            &["merge-base", "--is-ancestor", &receipt.base, "HEAD"],
        )
        .map_err(|_| {
            ScalerError::Guard("worker must rebase onto admitted main before publication")
        })?;
        let tip = git(
            &work,
            &[
                "-c",
                "credential.helper=!gh auth git-credential",
                "ls-remote",
                "--heads",
                "https://github.com/carrick-sh/carrick",
                &format!("refs/heads/{}", dispatch.branch),
            ],
        )?;
        let head = git(&work, &["rev-parse", "HEAD"])?;
        let existing = tip.split_whitespace().next();
        let retained =
            existing.is_some() && receipt.expected_tip.is_empty() && existing != Some(head.trim());
        if existing.is_some() && receipt.expected_tip.is_empty() && existing != Some(head.trim()) {
            let pr = require_owned_pr(root, dispatch)?;
            use std::io::Write;
            writeln!(
                std::fs::OpenOptions::new().append(true).open(report_path)?,
                "\nExisting dispatch branch `{}` and PR #{} retained; this rerun did not replace it.",
                dispatch.branch,
                pr["number"]
            )?;
        } else if existing != Some(head.trim()) {
            output(&mut push_command(
                &work,
                dispatch,
                id,
                &receipt.expected_tip,
            )?)?;
        }
        if !retained {
            std::fs::write(state.join("published-tip"), head.trim())?;
        }
        let prs = open_prs(root, &dispatch.branch)?;
        if prs.as_array().is_some_and(|prs| !prs.is_empty()) {
            let pr = require_owned_pr(root, dispatch)?;
            return Ok(Some(
                pr["number"]
                    .as_u64()
                    .ok_or(ScalerError::Guard("invalid PR number"))?,
            ));
        } else {
            let template = include_str!("../../../.github/pull_request_template.md")
                .replace("Closes #\n", &format!("Closes #{}\n", dispatch.issue))
                .replace(
                    "<!-- Approach and any candid divergence from Linux. -->",
                    &contract.summary.chars().take(4_000).collect::<String>(),
                )
                .replace("NEW: none / FIXED: none", "Not compared")
                .replace("NEW: / FIXED:", "Not compared")
                .replace("HEAD, SHA-256, CDHash", "Not collected");
            let body = format!(
                "{template}\nCloses #{}\n\nDispatch run: https://github.com/{REPOSITORY}/actions/runs/{id}\n",
                dispatch.issue
            );
            let path = state.join("pr-body.md");
            std::fs::write(&path, body.replace(token, "[REDACTED]"))?;
            gh(
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
                    &draft_pr_title(&work, &receipt.base, dispatch.issue, token)?,
                    "--body-file",
                    path.to_str().ok_or(ScalerError::Guard("body path"))?,
                ],
            )?;
            return Ok(require_owned_pr(root, dispatch)?["number"].as_u64());
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
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
        let mut dispatch = validate_event(&event(), "tjfontaine").unwrap();
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
        const CHILD: &str = "CARRICK_TEST_DISPATCH_PUBLICATION";
        if std::env::var_os(CHILD).is_none() {
            let temp = tempfile::tempdir().unwrap();
            let bin = temp.path().join("bin");
            std::fs::create_dir(&bin).unwrap();
            for (name, script) in [
                (
                    "git",
                    r#"#!/bin/sh
for arg do
 case "$arg" in
 ls-remote) if test -f "$RUNNER_TEMP/remote-tip"; then cat "$RUNNER_TEMP/remote-tip"; fi; exit 0 ;;
 push) printf '%s\n' "$@" >> "$RUNNER_TEMP/push.args"; /usr/bin/git rev-parse HEAD > "$RUNNER_TEMP/remote-tip"; exit 0 ;;
 esac
done
exec /usr/bin/git "$@"
"#,
                ),
                (
                    "gh",
                    r#"#!/bin/sh
printf '%s\n' "$@" >> "$RUNNER_TEMP/gh.args"
if test "$1" = api; then
 case "$2" in
 */actions/runs/42) cat "$RUNNER_TEMP/original.json" ;;
 */actions/runs/42/jobs*) echo '{"jobs":[{"name":"worker","status":"completed","runner_name":"carrick-agent-123","steps":[{"name":"Run actions/upload-artifact@v4","status":"completed","conclusion":"success"}]}]}' ;;
 *'/pulls?'*) if test -f "$RUNNER_TEMP/created"; then cat "$RUNNER_TEMP/pr.json"; else echo '[]'; fi ;;
 *) exit 91 ;;
 esac
elif test "$1 $2" = 'pr create'; then
 test ! -f "$RUNNER_TEMP/created" || exit 92
 touch "$RUNNER_TEMP/created"
 echo 'https://github.com/carrick-sh/carrick/pull/800'
else exit 93
fi
"#,
                ),
            ] {
                let path = bin.join(name);
                std::fs::write(&path, script).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "dispatch_worker::tests::label_publication_creates_draft_and_continues_the_owned_branch", "--nocapture"])
                .env(CHILD, "1")
                .env("GH_TOKEN", "fixture-token").env("RUNNER_TEMP", temp.path())
                .env("GITHUB_RUN_ID", "42").env("GITHUB_RUN_ATTEMPT", "1")
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .output().unwrap();
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
        let base = git(&work, &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .to_owned();
        let mut event = event();
        event["label"]["name"] = "dispatch".into();
        let mut dispatch = validate_event(&event, "tjfontaine").unwrap();
        dispatch.base = base.clone();
        assigned_branch(&mut dispatch).unwrap();
        assert_eq!(dispatch.branch, "work/dispatch-634-42");
        git(&work, &["checkout", "-b", &dispatch.branch]).unwrap();
        let subject = "fix(ci): implement the owner issue";
        git(&work, &["commit", "--allow-empty", "-m", subject]).unwrap();
        let pr = json!({"state":"open","number":800,"user":{"login":"github-actions[bot]","type":"Bot"},"head":{"ref":dispatch.branch,"repo":{"full_name":REPOSITORY}},"base":{"ref":"main"},"draft":true,"body":format!("Closes #634\nDispatch run: https://github.com/{REPOSITORY}/actions/runs/42")});
        let mut run = review_event()["dispatch_run"].clone();
        run["status"] = "completed".into();
        std::fs::write(outer.join("original.json"), run.to_string()).unwrap();
        std::fs::write(outer.join("pr.json"), json!([pr.clone()]).to_string()).unwrap();
        let contract = Contract {
            status: ContractStatus::Done,
            summary: "implemented".into(),
            tests: vec![],
            risks: vec![],
        };
        let mut receipt = Receipt {
            base,
            branch: dispatch.branch.clone(),
            exit_code: 0,
            expected_tip: String::new(),
            refused_workflow: false,
        };
        let report = state.join("report.md");
        std::fs::write(&report, "").unwrap();
        assert_eq!(
            publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token"
            )
            .unwrap(),
            Some(800)
        );
        let body = regular_text(&state.join("pr-body.md")).unwrap();
        assert!(body.contains("Closes #634") && body.contains("Dispatch run:"));
        let calls = regular_text(&outer.join("gh.args")).unwrap();
        assert!(calls.contains(&format!(
            "--draft\n--base\nmain\n--head\n{}\n--title\n{subject}",
            dispatch.branch
        )));
        let selected = select_owned_pr(dispatch.issue, std::slice::from_ref(&pr), |_| {
            Ok(run.clone())
        })
        .unwrap()
        .unwrap();
        assert_eq!(selected["head"]["ref"], dispatch.branch);
        let mut unowned = pr;
        unowned["user"]["login"] = "outsider".into();
        assert!(
            select_owned_pr(dispatch.issue, &[unowned], |_| Ok(run.clone()))
                .unwrap()
                .is_none()
        );
        dispatch.resume = true;
        receipt.expected_tip = git(&work, &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .to_owned();
        git(
            &work,
            &[
                "commit",
                "--allow-empty",
                "-m",
                "fix(ci): apply owner follow-up",
            ],
        )
        .unwrap();
        assert_eq!(
            publish(
                &work,
                &dispatch,
                &receipt,
                &contract,
                &report,
                "fixture-token"
            )
            .unwrap(),
            Some(800)
        );
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
            std::fs::write(&script, &poison).unwrap();
            std::fs::set_permissions(script, std::fs::Permissions::from_mode(0o700)).unwrap();
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
        std::fs::write(&pgrep, "#!/bin/sh\nexit \"$PGREP_RESULT\"\n").unwrap();
        std::fs::set_permissions(&pgrep, std::fs::Permissions::from_mode(0o700)).unwrap();
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
            .env("GITHUB_OUTPUT", "/runner/set_output")
            .env("GIT_CONFIG_GLOBAL", "/credential/helper")
            .env("RUSTC_WRAPPER", "/runner/sccache")
            .env("SCCACHE_SERVER_UDS", "/runner/sccache.sock");
        private_environment(&mut cmd);
        for key in ["GITHUB_TOKEN", "GH_TOKEN", "AGENT_DIRECTOR_TOKEN"] {
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
        let mut dispatch = validate_event(&event(), "tjfontaine").unwrap();
        dispatch.branch = "work/dispatch-634-42".into();
        git(temp.path(), &["checkout", "-b", &dispatch.branch]).unwrap();
        let command = push_command(temp.path(), &dispatch, "42", "").unwrap();
        let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(args.last(), Some(&"HEAD:refs/heads/work/dispatch-634-42"));
        assert_eq!(args.iter().filter(|s| s.starts_with("HEAD:")).count(), 1);
        assert!(args.contains(&"--force-with-lease=refs/heads/work/dispatch-634-42:"));
        assert!(args.contains(&"--no-follow-tags"));
        assert!(!args.contains(&"--all") && !args.contains(&"--mirror"));
        assert!(push_command(temp.path(), &dispatch, "43", "").is_err());
        git(temp.path(), &["checkout", "-b", "work/another-lane"]).unwrap();
        assert!(push_command(temp.path(), &dispatch, "42", "").is_err());
        dispatch.branch = "work/another-lane".into();
        assert!(push_command(temp.path(), &dispatch, "42", "").is_err());
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
        assert!(owned_pr(&pr, &run, 634, branch));
        assert!(!owned_pr(&pr, &run, 635, branch));
        assert!(!owned_pr(&pr, &run, 634, "work/dispatch-634-43"));
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
            assert!(!owned_pr(&bad, &run, 634, branch), "{pointer}");
        }
        let mut ready = pr.clone();
        ready["draft"] = false.into();
        assert!(!owned_pr(&ready, &run, 634, branch));
        for pointer in [
            "/path",
            "/event",
            "/head_branch",
            "/repository/full_name",
            "/actor/login",
        ] {
            let mut bad = run.clone();
            *bad.pointer_mut(pointer).unwrap() = "foreign".into();
            assert!(!owned_pr(&pr, &bad, 634, branch), "{pointer}");
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
            validate_event(&value, "tjfontaine").is_ok(),
            "#587 free-form body refused"
        );
    }
    #[test]
    fn unsuffixed_dispatch_is_owner_context() {
        let mut value = event();
        for label in ["dispatch", "dispatch:any owner context"] {
            value["label"]["name"] = label.into();
            assert!(
                validate_event(&value, "tjfontaine").is_ok(),
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
            validate_event(&value, "tjfontaine").is_ok(),
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
            if validate_event(&other, "tjfontaine").is_ok() {
                admitted.push(pointer);
            }
        }
        assert!(
            admitted.is_empty(),
            "unsafe comments admitted: {admitted:?}"
        );
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
            assert!(validate_event(&bad, "tjfontaine").is_err(), "{pointer}");
        }
        assert!(
            validate_event(&base, "someone-else").is_err(),
            "rerun actor"
        );
        let mut pr = base.clone();
        pr["issue"]["pull_request"] = json!({});
        assert!(validate_event(&pr, "tjfontaine").is_err());
        let mut bot = base;
        bot["sender"] = json!({"login":"carrick-workers[bot]","type":"Bot"});
        assert!(validate_event(&bot, "carrick-workers[bot]").is_err());
        bot["sender"]["type"] = "User".into();
        assert!(validate_event(&bot, "carrick-workers[bot]").is_err());
    }
    #[test]
    fn owner_label_does_not_admit_an_issue_owned_by_another_author() {
        let mut value = event();
        value["issue"]["user"]["login"] = "someone-else".into();
        assert!(validate_event(&value, "tjfontaine").is_err());
        value["issue"].as_object_mut().unwrap().remove("user");
        assert!(validate_event(&value, "tjfontaine").is_err());
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
        let mut d = validate_event(&event(), "tjfontaine").unwrap();
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
    fn review_admission_requires_owner_owned_pr() {
        let event = review_event();
        let dispatch =
            validate_event(&event, "tjfontaine").expect("owner review must continue its PR");
        assert_eq!(dispatch.branch, "work/dispatch-634-42");
        assert!(dispatch.resume);
        let mut legacy = event.clone();
        legacy["issue"]["body"] =
            "## Brief\nBranch: work/dispatch-634-99\nBranch: work/elsewhere\nDo the review".into();
        assert_eq!(
            validate_event(&legacy, "tjfontaine").unwrap().branch,
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
            ("/issue/state", json!("closed")),
            ("/issue/user/login", json!("outsider")),
        ] {
            let mut bad = event.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            if validate_event(&bad, "tjfontaine").is_ok() {
                admitted.push(pointer);
            }
        }
        if validate_event(&event, "outsider").is_ok() {
            admitted.push("triggering_actor");
        }
        assert!(admitted.is_empty(), "unsafe reviews admitted: {admitted:?}");
    }

    #[test]
    fn agent_comment_on_an_unowned_pr_is_refused() {
        let mut event = review_event();
        event.as_object_mut().unwrap().remove("review");
        event["action"] = "created".into();
        event["comment"] = json!({"user":{"login":"tjfontaine","type":"User"},"body":"/agent fix the conflict","created_at":"2026-10-24","updated_at":"2026-10-24"});
        assert!(validate_event(&event, "tjfontaine").is_ok());
        event["pull_request"]["user"]["login"] = "outsider".into();
        assert!(
            validate_event(&event, "tjfontaine").is_err(),
            "unowned PR admitted"
        );
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
