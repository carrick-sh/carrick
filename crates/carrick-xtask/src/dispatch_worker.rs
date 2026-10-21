//! Issue-label dispatch driver. Workflow input never becomes shell source.
use crate::ci_scaler::{REPOSITORY, ScalerError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const AGENT_USER: &str = "carrick-dispatch-agent";

#[derive(clap::Args, Debug)]
pub struct DispatchArgs {
    #[command(subcommand)]
    pub action: DispatchAction,
}
#[derive(clap::Subcommand, Debug)]
pub enum DispatchAction {
    /// Hosted, credential-free guard. Repeated on the clone before any work.
    Guard {
        #[arg(long)]
        event: PathBuf,
    },
    /// Finish this job: scan artifacts, push its branch and report the contract.
    Complete {
        #[arg(long)]
        event: PathBuf,
    },
    /// Foreground worker and artifact producer.
    Run {
        #[arg(long)]
        event: PathBuf,
        /// Actions bootstrap/auth outcomes; failure reports without starting tools.
        #[arg(long, default_value = "success/success")]
        setup_status: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tier {
    pub backend: String,
    pub model: String,
    pub effort: Option<String>,
    pub coauthor: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tiers {
    tiers: std::collections::BTreeMap<String, Tier>,
}

pub fn trusted_actor(actor: &str) -> bool {
    actor == "tjfontaine"
}

#[derive(Debug)]
pub struct Dispatch {
    pub issue: u64,
    pub title: String,
    pub brief: String,
    pub branch: String,
    pub resume: bool,
    pub tier: Tier,
}

pub fn validate_event(
    event: &Value,
    tiers: &str,
    triggering_actor: &str,
) -> Result<Dispatch, ScalerError> {
    let sender = event["sender"]["login"].as_str().unwrap_or_default();
    let kind = event["sender"]["type"].as_str().unwrap_or_default();
    if event["repository"]["full_name"] != REPOSITORY
        || event["action"] != "labeled"
        || event["issue"].get("pull_request").is_some()
        || !trusted_actor(sender)
        || !trusted_actor(triggering_actor)
        || kind != "User"
        || event["issue"]["user"]["login"] != "tjfontaine"
    {
        return Err(ScalerError::Guard(
            "dispatch requires the owner labeling an owner-authored issue",
        ));
    }
    let tiers: Tiers =
        toml::from_str(tiers).map_err(|_| ScalerError::Guard("invalid dispatch tier table"))?;
    let tier = event["label"]["name"]
        .as_str()
        .and_then(|label| tiers.tiers.get(label))
        .cloned()
        .ok_or(ScalerError::Guard("dispatch label is not allowlisted"))?;
    if !matches!(tier.backend.as_str(), "codex" | "agy") {
        return Err(ScalerError::Guard("unknown dispatch backend"));
    }
    let issue = event["issue"]["number"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(ScalerError::Guard("missing issue number"))?;
    let title = event["issue"]["title"]
        .as_str()
        .ok_or(ScalerError::Guard("missing issue title"))?
        .to_owned();
    let body = event["issue"]["body"].as_str().unwrap_or_default();
    let brief = brief_section(body)?;
    let branches = branch_directives(&brief);
    if branches.len() > 1 {
        return Err(ScalerError::Guard("multiple branch directives"));
    }
    let branch = if let Some(branch) = branches.first() {
        if !valid_branch(branch) {
            return Err(ScalerError::Guard("brief branch must be a valid work/ ref"));
        }
        (*branch).to_owned()
    } else {
        format!("work/dispatch-{issue}-pending")
    };
    let resume = !branches.is_empty();
    Ok(Dispatch {
        issue,
        title,
        brief,
        branch,
        resume,
        tier,
    })
}

fn branch_directives(brief: &str) -> Vec<&str> {
    let mut fence: Option<(char, usize)> = None;
    let mut branches = Vec::new();
    let mut comment = false;
    for line in brief.lines() {
        if line.contains("<!--") {
            comment = true;
        }
        if comment {
            if line.contains("-->") {
                comment = false;
            }
            continue;
        }
        let trimmed = line.trim();
        if advance_fence(trimmed, &mut fence) {
            continue;
        }
        if fence.is_none()
            && let Some(branch) = line.strip_prefix("Branch: ")
        {
            branches.push(branch);
        }
    }
    branches
}
fn advance_fence(trimmed: &str, fence: &mut Option<(char, usize)>) -> bool {
    let Some(marker @ ('`' | '~')) = trimmed.chars().next() else {
        return false;
    };
    let count = trimmed.chars().take_while(|c| *c == marker).count();
    if count < 3 {
        return false;
    }
    match *fence {
        None => *fence = Some((marker, count)),
        Some((open, length))
            if open == marker && count >= length && trimmed[count..].trim().is_empty() =>
        {
            *fence = None
        }
        _ => {}
    }
    true
}

pub fn brief_section(body: &str) -> Result<String, ScalerError> {
    let mut in_brief = false;
    let mut found = false;
    let mut lines = Vec::new();
    // Markdown fences may contain headings; they do not delimit sections.
    let mut fence = None;
    let mut comment = false;
    for line in body.lines() {
        if line.contains("<!--") {
            comment = true;
        }
        if comment {
            if line.contains("-->") {
                comment = false;
            }
            if in_brief {
                lines.push(line);
            }
            continue;
        }
        let trimmed = line.trim();
        if advance_fence(trimmed, &mut fence) {
            if in_brief {
                lines.push(line);
            }
            continue;
        }
        if fence.is_none() && trimmed == "## Brief" {
            if found {
                return Err(ScalerError::Guard("multiple Brief sections"));
            }
            found = true;
            in_brief = true;
            continue;
        }
        if fence.is_none() && (trimmed.starts_with("## ") || trimmed.starts_with("# ")) {
            in_brief = false;
        }
        if in_brief {
            lines.push(line);
        }
    }
    let brief = lines.join("\n").trim().to_owned();
    if brief.is_empty() {
        return Err(ScalerError::Guard(
            "issue requires a nonempty ## Brief section",
        ));
    }
    Ok(brief)
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

fn schema() -> Value {
    json!({"type":"object","additionalProperties":false,
        "required":["status","summary","tests","risks"],"properties":{
            "status":{"type":"string","enum":["done","blocked","failed"]},
            "summary":{"type":"string"},"tests":{"type":"array","items":{"type":"string"}},
            "risks":{"type":"array","items":{"type":"string"}}}})
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub status: ContractStatus,
    pub summary: String,
    pub tests: Vec<String>,
    pub risks: Vec<String>,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContractStatus {
    Done,
    Blocked,
    Failed,
}

fn read_contract(result: &Path) -> Result<Contract, ScalerError> {
    let value: Value = serde_json::from_str(&regular_text(result)?)?;
    // Preserve a completed work contract even on transport failure. The
    // launcher exit code independently prevents a successful dispatch verdict.
    Ok(serde_json::from_value(value["structured_output"].clone())?)
}

fn wait_agent(command: &mut Command, limit: std::time::Duration) -> std::io::Result<i32> {
    use std::os::unix::process::CommandExt;
    let mut child = command.process_group(0).spawn()?;
    let pgid = i32::try_from(child.id()).map_err(std::io::Error::other)?;
    let deadline = std::time::Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // SAFETY: the foreground child created this dedicated group.
                unsafe {
                    libc::kill(-pgid, libc::SIGKILL);
                }
                return Ok(status.code().unwrap_or(1));
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(error) => return Err(error),
            Ok(None) => {
                // The sudo wrapper and its agent belong to different UIDs.
                // Stop every agent process before waiting for that wrapper.
                stop_agent_processes();
                // A sudo monitor can stop on the agent's job-control notification.
                // Kill the unreaped child's dedicated group with runner privilege.
                let _ = sudo(&["/usr/bin/kill", "-KILL", "--", &format!("-{pgid}")]);
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                loop {
                    if child.try_wait()?.is_some() {
                        return Ok(124);
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

fn agent(root: &Path, dispatch: &Dispatch) -> Result<i32, ScalerError> {
    let state = root
        .parent()
        .ok_or(ScalerError::Guard("missing agent home"))?
        .to_owned();
    let home = state.join("home");
    let schema_path = state.join("schema.json");
    let result = state.join("result.json");
    let prompt_file = state.join("prompt.md");
    std::fs::write(&schema_path, serde_json::to_vec_pretty(&schema())?)?;
    let prompt = format!(
        "Work issue {REPOSITORY}#{} on branch {}. Read AGENTS.md in full.\n\
        Implement and verify this brief. Commit your work with a Why/What/Verified body and\n\
        Co-Authored-By: {}\nDo not push, open a PR, or post comments; the workflow publishes those.\n\
        Never use --no-verify, git stash or git add -A. Keep conformance-probes/target out of commits.\n\
        This is an ephemeral runner. Use local shared carrick leases for builds.\n\
        Contabo leases are per VM under owner decision #639; never acquire a hypervisor lease.\n\
        Run only gates supported by this host; report unavailable Docker, KVM or HVF honestly.\n\
        Return the requested JSON contract, stating unrun gates and blockers honestly.\n\n{}",
        dispatch.issue, dispatch.branch, dispatch.tier.coauthor, dispatch.brief
    );
    std::fs::write(&prompt_file, prompt)?;
    // Deduct checkout/build/bootstrap time rather than starting a fresh
    // 30-minute turn against a token snapshot taken at job admission.
    let turn_timeout = format!("{}s", crate::agent_runner::job_remaining(30)?.as_secs());
    let mut command = Command::new("python3");
    command
        .arg(state.join("director/agy-director/scripts/agy_worker.py"))
        .arg("--home")
        .arg(state.join("runtime"))
        .args([
            "--run",
            "dispatch",
            "dispatch",
            "--foreground",
            "--result-file",
        ])
        .arg(&result)
        .args(["--name", "worker", "--dir"])
        .arg(root)
        .arg("--prompt-file")
        .arg(prompt_file)
        .arg("--schema")
        .arg(schema_path)
        .args([
            "--timeout",
            &turn_timeout,
            "--no-profile",
            "--backend",
            &dispatch.tier.backend,
            "--model",
            &dispatch.tier.model,
        ]);
    if let Some(effort) = &dispatch.tier.effort {
        command.args(["--effort", effort]);
    }
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
        .env("AGY_DIRECTOR_CODEX_SDK_BIN", state.join("bin/codex"))
        .current_dir(root);
    let mut isolated = Command::new("/usr/bin/sudo");
    private_environment(&mut isolated);
    // Enter the private worktree only after sudo has switched credentials.
    isolated
        .args(["-n", "-u", AGENT_USER, "--", "/usr/bin/env", "-i", "-C"])
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
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(state.join("agent.out"))?)
        .stderr(std::fs::File::create(state.join("agent.err"))?);
    hand_over(&state)?;
    let outcome = wait_agent(&mut isolated, crate::agent_runner::job_remaining(32)?);
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
        dispatch.issue, dispatch.tier.coauthor
    );
    git(root, &["commit", "-m", &message])?;
    Ok(true)
}

fn output(command: &mut Command) -> Result<Vec<u8>, ScalerError> {
    crate::ci_scaler::execute(command, &[], std::time::Duration::from_secs(120))
}
pub(crate) fn git_invocation(root: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    // Repository-local config still applies. After agent retirement, snapshot()
    // copies objects and files into a fresh repo before any runner Git command.
    // No candidate .git/config, alternates, hooks, attributes or env is trusted.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(key);
        }
    }
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_GRAFT_FILE", "/dev/null")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "credential.helper=",
            "-c",
            "filter.lfs.clean=",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "filter.lfs.process=",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "user.name=github-actions[bot]",
            "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        ])
        .args(args)
        .current_dir(root);
    cmd
}
fn git(root: &Path, args: &[&str]) -> Result<String, ScalerError> {
    String::from_utf8(output(&mut git_invocation(root, args))?)
        .map_err(|_| ScalerError::Guard("non-UTF8 git output"))
}
fn gh(root: &Path, args: &[&str]) -> Result<String, ScalerError> {
    String::from_utf8(output(Command::new("gh").args(args).current_dir(root))?)
        .map_err(|_| ScalerError::Guard("non-UTF8 GitHub output"))
}
fn sudo(args: &[&str]) -> Result<(), ScalerError> {
    output(Command::new("/usr/bin/sudo").arg("-n").args(args))?;
    Ok(())
}
fn hand_over(path: &Path) -> Result<(), ScalerError> {
    sudo(&[
        "/usr/bin/chown",
        "-hR",
        AGENT_USER,
        path.to_str().ok_or(ScalerError::Guard("agent path"))?,
    ])
}
fn stop_agent_processes() {
    // Include real and effective UIDs (setuid tools), regardless of sessions.
    for selector in ["-u", "-U"] {
        let _ = sudo(&["/usr/bin/pkill", "-STOP", selector, AGENT_USER]);
        let _ = sudo(&["/usr/bin/pkill", "-KILL", selector, AGENT_USER]);
    }
}
fn retire_agent() -> Result<(), ScalerError> {
    stop_agent_processes();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        // SAFETY: the driver is a subreaper and has already waited for its
        // foreground child. Reap only completed adopted children.
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
        let mut empty = true;
        for selector in ["-u", "-U"] {
            let status = Command::new("/usr/bin/sudo")
                .args(["-n", "/usr/bin/pgrep", selector, AGENT_USER])
                .output()?;
            match status.status.code() {
                Some(1) if status.stdout.is_empty() && status.stderr.is_empty() => {}
                Some(0) => empty = false,
                _ => return Err(ScalerError::Guard("cannot verify agent process retirement")),
            }
        }
        if empty {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(ScalerError::Guard(
                "agent user still has processes; packaging refused",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
pub(crate) fn cleanup_agent_user() -> Result<(), ScalerError> {
    let status = Command::new("/usr/bin/id")
        .args(["-u", AGENT_USER])
        .output()?;
    if status.status.success() {
        let uid = String::from_utf8_lossy(&status.stdout)
            .trim()
            .parse::<libc::uid_t>()
            .map_err(|_| ScalerError::Guard("invalid agent account identity"))?;
        // Auth fixtures also run inside the worker. Only its separate runner
        // retires the account; a worker may clean its own credential state.
        // SAFETY: geteuid has no preconditions.
        if uid == unsafe { libc::geteuid() } {
            return Ok(());
        }
        retire_agent()?;
        sudo(&["/usr/sbin/userdel", AGENT_USER])?;
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
fn branch_run(issue: u64, branch: &str) -> Result<&str, ScalerError> {
    branch
        .strip_prefix(&format!("work/dispatch-{issue}-"))
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
        .ok_or(ScalerError::Guard(
            "branch is not derived from this issue's run",
        ))
}

fn open_prs(root: &Path, branch: &str) -> Result<Value, ScalerError> {
    Ok(serde_json::from_str(&gh(
        root,
        &[
            "api",
            &format!("repos/{REPOSITORY}/pulls?state=open&base=main&head=carrick-sh:{branch}"),
        ],
    )?)?)
}

fn owned_pr(pr: &Value, run: &Value, issue: u64, branch: &str) -> bool {
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
        && run["path"] == ".github/workflows/dispatch-worker.yml"
        && run["event"] == "issues"
        && run["head_branch"] == "main"
        && run["repository"]["full_name"] == REPOSITORY
        && run["actor"]["login"] == "tjfontaine"
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
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > 20 * 1024 * 1024 {
        return Err(ScalerError::Guard("unsafe or oversized dispatch output"));
    }
    Ok(std::fs::read_to_string(path)?)
}

#[derive(Serialize, Deserialize)]
struct Receipt {
    base: String,
    branch: String,
    exit_code: i32,
    expected_tip: String,
    refused_workflow: bool,
}

pub fn run(root: &Path, args: DispatchArgs) -> Result<(), ScalerError> {
    let root = root.canonicalize()?;
    let (event_path, setup, complete) = match args.action {
        DispatchAction::Guard { event } => (event, None, false),
        DispatchAction::Run {
            event,
            setup_status,
        } => (event, Some(setup_status), false),
        DispatchAction::Complete { event } => (event, None, true),
    };
    let event: Value = serde_json::from_slice(&std::fs::read(event_path)?)?;
    let mut dispatch = validate_event(
        &event,
        include_str!("../../../.github/dispatch-tiers.toml"),
        &std::env::var("GITHUB_TRIGGERING_ACTOR").unwrap_or_default(),
    )?;
    assigned_branch(&mut dispatch)?;
    branch_run(dispatch.issue, &dispatch.branch)?;
    if complete {
        return finish(&root, &dispatch);
    }
    if let Some(setup) = setup {
        produce(&root, &dispatch, &setup)?;
    } else if let Some(path) = std::env::var_os("GITHUB_OUTPUT") {
        use std::io::Write;
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "backend={}",
            dispatch.tier.backend
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TreeLinks {
    Preserve,
    Refuse,
}
fn copy_tree(
    source: &Path,
    target: &Path,
    count: &mut usize,
    links: TreeLinks,
) -> Result<(), ScalerError> {
    std::fs::create_dir(target)?;
    std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o700))?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        if matches!(entry.file_name().to_str(), Some("target" | ".git")) {
            continue;
        }
        *count += 1;
        if *count > 100_000 {
            return Err(ScalerError::Guard("snapshot file count exceeded"));
        }
        let kind = entry.file_type()?;
        let dest = target.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &dest, count, links)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), dest)?;
        } else if kind.is_symlink() && matches!(links, TreeLinks::Preserve) {
            std::os::unix::fs::symlink(std::fs::read_link(entry.path())?, dest)?;
        } else {
            return Err(ScalerError::Guard("snapshot refused nonregular file"));
        }
    }
    Ok(())
}
fn snapshot(source: &Path, target: &Path, branch: &str) -> Result<(), ScalerError> {
    let dotgit = source.join(".git");
    if !std::fs::symlink_metadata(&dotgit)?.is_dir() {
        return Err(ScalerError::Guard("agent git directory redirected"));
    }
    let head = regular_text(&dotgit.join("HEAD"))?;
    let expected = format!("ref: refs/heads/{branch}");
    if head.trim() != expected {
        return Err(ScalerError::Guard("agent changed branch"));
    }
    // Loose ref is guaranteed by preparation. Ref directories must not be links.
    let mut path = dotgit.clone();
    for part in format!("refs/heads/{branch}").split('/') {
        path.push(part);
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err(ScalerError::Guard("redirected candidate ref"));
        }
    }
    let head = regular_text(&path)?.trim().to_owned();
    if !sha(&head) {
        return Err(ScalerError::Guard("invalid candidate head"));
    }
    copy_tree(source, target, &mut 0, TreeLinks::Preserve)?;
    git(target, &["init"])?;
    // Deliberately omit info/alternates, config, grafts, shallow, index and refs.
    let objects = dotgit.join("objects");
    if std::fs::symlink_metadata(&objects)?
        .file_type()
        .is_symlink()
    {
        return Err(ScalerError::Guard("redirected objects"));
    }
    for entry in std::fs::read_dir(objects)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(ScalerError::Guard("object path"))?;
        if name == "info" {
            continue;
        }
        if name != "pack" && !(name.len() == 2 && name.bytes().all(|b| b.is_ascii_hexdigit())) {
            return Err(ScalerError::Guard("unexpected object directory"));
        }
        if !entry.file_type()?.is_dir() {
            return Err(ScalerError::Guard("object directory link"));
        }
        let dest = target.join(".git/objects").join(name);
        if dest.exists() {
            std::fs::remove_dir(&dest)?;
        }
        copy_tree(&entry.path(), &dest, &mut 0, TreeLinks::Refuse)?;
    }
    git(
        target,
        &["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")],
    )?;
    git(target, &["update-ref", "HEAD", &head])?;
    git(target, &["read-tree", "HEAD"])?;
    Ok(())
}

fn produce(root: &Path, dispatch: &Dispatch, setup: &str) -> Result<(), ScalerError> {
    let base =
        std::env::var("GITHUB_SHA").map_err(|_| ScalerError::Guard("missing admitted SHA"))?;
    if !sha(&base) || git(root, &["rev-parse", "HEAD"])?.trim() != base {
        return Err(ScalerError::Guard("checkout differs from admitted SHA"));
    }
    let state = crate::agent_runner::state()?;
    std::fs::create_dir_all(&state)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
    let temporary =
        PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or(ScalerError::Guard("runner temp"))?);
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    let work = state.join("work");
    let package =
        PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or(ScalerError::Guard("runner temp"))?)
            .join("dispatch-output");
    std::fs::create_dir(&package)?;
    std::fs::set_permissions(&package, std::fs::Permissions::from_mode(0o700))?;
    let mut contract = Contract {
        status: ContractStatus::Failed,
        summary: format!("Worker setup did not complete: {setup}"),
        tests: vec![],
        risks: vec![],
    };
    let mut code = 1;
    let mut expected_tip = String::new();
    let mut raw = String::new();
    let mut diffstat = String::new();
    let mut refused_workflow = false;
    if setup == "success/success" {
        if dispatch.resume {
            require_owned_pr(root, dispatch)?;
        }
        #[cfg(target_os = "linux")]
        // SAFETY: adopt and reap detached children before scanning agent bytes.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        cleanup_agent_user()?;
        sudo(&[
            "/usr/sbin/useradd",
            "--system",
            "--user-group",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            AGENT_USER,
        ])?;
        let outer = tempfile::Builder::new()
            .prefix("carrick-dispatch-")
            .tempdir_in("/var/tmp")?;
        std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o711))?;
        let actor = outer.path().join("agent");
        std::fs::create_dir(&actor)?;
        std::fs::set_permissions(&actor, std::fs::Permissions::from_mode(0o700))?;
        for name in ["home", "bin", "director"] {
            copy_tree(
                &state.join(name),
                &actor.join(name),
                &mut 0,
                TreeLinks::Preserve,
            )?;
        }
        let actor_work = actor.join("work");
        git(
            &actor,
            &[
                "clone",
                "--no-local",
                "--no-hardlinks",
                "--no-checkout",
                root.to_str().ok_or(ScalerError::Guard("checkout path"))?,
                "work",
            ],
        )?;
        if dispatch.resume {
            git(
                &actor_work,
                &[
                    "-c",
                    "credential.helper=!gh auth git-credential",
                    "fetch",
                    "--no-tags",
                    "https://github.com/carrick-sh/carrick",
                    &format!("refs/heads/{}", dispatch.branch),
                ],
            )?;
            expected_tip = git(&actor_work, &["rev-parse", "FETCH_HEAD"])?
                .trim()
                .to_owned();
            git(
                &actor_work,
                &["checkout", "-b", &dispatch.branch, "FETCH_HEAD"],
            )?;
            git(&actor_work, &["rebase", &base])?;
        } else {
            git(&actor_work, &["checkout", "-b", &dispatch.branch, &base])?;
        }
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
        sudo(&[
            "/usr/bin/chmod",
            "700",
            actor.to_str().ok_or(ScalerError::Guard("agent state"))?,
        ])?;
        // SAFETY: geteuid has no preconditions.
        sudo(&[
            "/usr/bin/chown",
            "-hR",
            &unsafe { libc::geteuid() }.to_string(),
            actor.to_str().ok_or(ScalerError::Guard("agent state"))?,
        ])?;
        code = result?;
        snapshot(&actor_work, &work, &dispatch.branch)?;
        contract = read_contract(&actor.join("result.json")).unwrap_or(Contract {
            status: ContractStatus::Failed,
            summary: "No valid worker contract".into(),
            tests: vec![],
            risks: vec!["Worker output is incomplete".into()],
        });
        for name in ["agent.out", "agent.err"] {
            raw.push_str(&format!("=== {name} ===\n"));
            raw.push_str(&regular_text(&actor.join(name))?);
        }
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
        if !["raw.log", "transcript.md", "contract.json", "diffstat.txt"].contains(&name) {
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
        } else {
            mask(&text)
        };
        std::fs::write(entry.path(), masked)?;
        names.insert(name.to_owned());
    }
    if names.len() != 4 {
        return Err(ScalerError::Guard("incomplete dispatch artifacts"));
    }
    for name in names {
        if regular_text(&package.join(name))?.contains(token) {
            return Err(ScalerError::Guard("job token found in upload"));
        }
    }
    Ok(())
}

fn finish(root: &Path, dispatch: &Dispatch) -> Result<(), ScalerError> {
    cleanup_agent_user()?;
    let token = std::env::var("GH_TOKEN").map_err(|_| ScalerError::Guard("missing job token"))?;
    let state = crate::agent_runner::state()?;
    let package =
        PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or(ScalerError::Guard("runner temp"))?)
            .join("dispatch-output");
    mask_artifacts(&package, &token)?;
    let receipt: Receipt = serde_json::from_str(&regular_text(&state.join("receipt.json"))?)?;
    if receipt.branch != dispatch.branch
        || !sha(&receipt.base)
        || std::env::var("GITHUB_SHA").ok().as_deref() != Some(&receipt.base)
    {
        return Err(ScalerError::Guard("dispatch receipt mismatch"));
    }
    let contract: Contract = serde_json::from_str(&regular_text(&package.join("contract.json"))?)?;
    let id = if dispatch.resume {
        require_owned_pr(root, dispatch)?;
        branch_run(dispatch.issue, &dispatch.branch)?.to_owned()
    } else {
        run_id()?
    };
    let report_path = state.join("report.md");
    let details = serde_json::to_string_pretty(&contract)?;
    // Keep API comments below GitHub's body limit; full logs/contract are artifacts.
    let excerpt = details.chars().take(8_000).collect::<String>();
    let report = format!(
        "Dispatch run: https://github.com/{REPOSITORY}/actions/runs/{}\n\nWorker contract (claims for review):\n\n```json\n{excerpt}\n```\n\nFull contract and transcript are attached to the workflow run.\n",
        run_id()?
    );
    std::fs::write(&report_path, report.replace(&token, "[REDACTED]"))?;
    let work = state.join("work");
    let publication = (|| -> Result<(), ScalerError> {
        if !receipt.refused_workflow
            && work.is_dir()
            && git(&work, &["rev-parse", "HEAD"])?.trim() != receipt.base
        {
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
            if existing.is_some()
                && receipt.expected_tip.is_empty()
                && existing != Some(head.trim())
            {
                let pr = require_owned_pr(root, dispatch)?;
                use std::io::Write;
                writeln!(
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&report_path)?,
                    "\nExisting dispatch branch `{}` and PR #{} retained; this rerun did not replace it.",
                    dispatch.branch,
                    pr["number"]
                )?;
            } else if existing != Some(head.trim()) {
                output(&mut push_command(
                    &work,
                    dispatch,
                    &id,
                    &receipt.expected_tip,
                )?)?;
            }
            let prs = open_prs(root, &dispatch.branch)?;
            if prs.as_array().is_some_and(|prs| !prs.is_empty()) {
                let pr = require_owned_pr(root, dispatch)?;
                gh(
                    root,
                    &[
                        "pr",
                        "comment",
                        &pr["number"].to_string(),
                        "--repo",
                        REPOSITORY,
                        "--body-file",
                        report_path
                            .to_str()
                            .ok_or(ScalerError::Guard("transcript path"))?,
                    ],
                )?;
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
                std::fs::write(&path, body.replace(&token, "[REDACTED]"))?;
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
                        &format!("chore(ci): work issue {}", dispatch.issue),
                        "--body-file",
                        path.to_str().ok_or(ScalerError::Guard("body path"))?,
                    ],
                )?;
            }
        }
        Ok(())
    })();
    if let Err(error) = &publication {
        use std::io::Write;
        let diagnostic = crate::dispatch_redaction::redact(error.to_string().as_bytes());
        writeln!(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&report_path)?,
            "\nPublication failed: {}",
            diagnostic.chars().take(4_000).collect::<String>()
        )?;
    }
    if let Some(summary) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(summary)?
            .write_all(regular_text(&report_path)?.as_bytes())?;
    }
    // The workflow owns reporting. The agent cannot access its command-file channels.
    gh(
        root,
        &[
            "issue",
            "comment",
            &dispatch.issue.to_string(),
            "--repo",
            REPOSITORY,
            "--body-file",
            report_path
                .to_str()
                .ok_or(ScalerError::Guard("transcript path"))?,
        ],
    )?;
    if publication.is_err() || receipt.exit_code != 0 || contract.status != ContractStatus::Done {
        // Report failure separately, so scanned artifacts remain available on failed runs.
        if let Some(path) = std::env::var_os("GITHUB_OUTPUT") {
            use std::io::Write;
            writeln!(
                std::fs::OpenOptions::new().append(true).open(path)?,
                "worker_failed=true"
            )?;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "runner-only OS account witness; run with --include-ignored"]
    fn serial_host_timeout_retires_detached_and_signal_resistant_agent() {
        cleanup_agent_user().unwrap();
        sudo(&[
            "/usr/sbin/useradd",
            "--system",
            "--user-group",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            AGENT_USER,
        ])
        .unwrap();
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
        std::fs::create_dir(&target).unwrap();
        git(&actor, &["init"]).unwrap();
        git(&actor, &["checkout", "-b", "work/dispatch-42"]).unwrap();
        std::fs::write(actor.join("data"), "base").unwrap();
        git(&actor, &["add", "."]).unwrap();
        git(&actor, &["commit", "-m", "base"]).unwrap();
        let poison = format!("#!/bin/sh\ntouch '{}'\ncat\n", marker.display());
        for script in [actor.join("poison.sh"), actor.join(".git/hooks/pre-commit")] {
            std::fs::write(&script, &poison).unwrap();
            std::fs::set_permissions(script, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        git(&actor, &["config", "filter.poison.clean", "./poison.sh"]).unwrap();
        std::fs::write(actor.join(".gitattributes"), "data filter=poison\n").unwrap();
        std::fs::write(actor.join("data"), "agent modification").unwrap();
        snapshot(&actor, &target, "work/dispatch-42").unwrap();
        git(&target, &["add", "."]).unwrap();
        git(&target, &["commit", "-m", "read agent data"]).unwrap();
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
    fn html_comments_do_not_select_a_branch() {
        assert!(
            branch_directives(
                "<!--
Branch: work/foreign
-->
Do it"
            )
            .is_empty()
        );
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
        let mut dispatch = validate_event(&event(), TIERS, "tjfontaine").unwrap();
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
            "actor":{"login":"tjfontaine"}});
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

    const TIERS: &str = include_str!("../../../.github/dispatch-tiers.toml");
    fn event() -> Value {
        json!({"repository":{"full_name":REPOSITORY},"action":"labeled",
            "sender":{"login":"tjfontaine","type":"User"},"label":{"name":"dispatch:sol-high"},
            "issue":{"number":634,"user":{"login":"tjfontaine"},"title":"Dispatch workers!","body":"## Why\ncontext\n## Brief\nImplement it\n### Verify\nCheck it\n## Notes\nnot prompt"}})
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
                validate_event(&bad, TIERS, "tjfontaine").is_err(),
                "{pointer}"
            );
        }
        assert!(
            validate_event(&base, TIERS, "someone-else").is_err(),
            "rerun actor"
        );
        let mut pr = base.clone();
        pr["issue"]["pull_request"] = json!({});
        assert!(validate_event(&pr, TIERS, "tjfontaine").is_err());
        let mut bot = base;
        bot["sender"] = json!({"login":"carrick-workers[bot]","type":"Bot"});
        assert!(validate_event(&bot, TIERS, "carrick-workers[bot]").is_err());
        bot["sender"]["type"] = "User".into();
        assert!(validate_event(&bot, TIERS, "carrick-workers[bot]").is_err());
    }
    #[test]
    fn owner_label_does_not_admit_an_issue_owned_by_another_author() {
        let mut value = event();
        value["issue"]["user"]["login"] = "someone-else".into();
        assert!(validate_event(&value, TIERS, "tjfontaine").is_err());
        value["issue"].as_object_mut().unwrap().remove("user");
        assert!(validate_event(&value, TIERS, "tjfontaine").is_err());
    }
    #[test]
    fn brief_and_branch_syntax() {
        assert!(brief_section("## Brief\n\n## Other\nx").is_err());
        assert!(brief_section("## Brief\nx\n## Brief\ny").is_err());
        for branch in [
            "main",
            "work/",
            "work/x..y",
            "work/.x",
            "work/x.lock",
            "work/x;id",
            "work/$(id)",
            "work/x\ny",
            "work//x",
            "work/x/",
        ] {
            assert!(!valid_branch(branch), "{branch}");
        }
        assert!(valid_branch("work/existing-634"));
    }
    #[test]
    fn branch_directives_inside_fences_do_not_select_a_branch() {
        let mut value = event();
        value["issue"]["body"] =
            "## Brief\nImplement it\n```text\nBranch: work/foreign-799\n```".into();
        assert_eq!(
            validate_event(&value, TIERS, "tjfontaine").unwrap().branch,
            "work/dispatch-634-pending"
        );
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
        let d = validate_event(&event(), TIERS, "tjfontaine").unwrap();
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
}
