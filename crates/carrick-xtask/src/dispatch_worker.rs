//! Issue-label dispatch driver. Workflow input never becomes shell source.
use crate::ci_scaler::{REPOSITORY, ScalerError};
use crate::dispatch_redaction::{Gate, MAX_FILE_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
    /// Hosted publisher; never checks out or executes candidate code.
    Publish {
        #[arg(long)]
        event: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
    },
    /// Credential-free foreground worker and artifact producer.
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
impl Contract {
    fn check(&self, gate: &Gate) -> Result<(), ScalerError> {
        for text in std::iter::once(&self.summary)
            .chain(&self.tests)
            .chain(&self.risks)
        {
            gate.check(text.as_bytes())?;
        }
        Ok(())
    }
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
            Ok(Some(status)) => return Ok(status.code().unwrap_or(1)),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            result => {
                // SAFETY: the unreaped foreground child owns this process group.
                // All detached descendants are retired separately by UID.
                unsafe {
                    libc::kill(-pgid, libc::SIGKILL);
                }
                child.wait()?;
                return result.map(|_| 124);
            }
        }
    }
}

fn private_environment(command: &mut Command) {
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin");
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
    // Only explicit provider files cross the user boundary; no runner env,
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
fn gate_work(root: &Path, gate: &Gate) -> Result<(), ScalerError> {
    gate_work_inner(root, gate)
        .map_err(|_| ScalerError::Guard("redaction gate refused sensitive or unsafe output"))
}
fn gate_work_inner(root: &Path, gate: &Gate) -> Result<(), ScalerError> {
    let refusal = || ScalerError::Guard("redaction gate refused sensitive or unsafe output");
    if git(root, &["ls-files", "--modified", "-z"])?
        .split('\0')
        .any(|p| !p.is_empty() && !admissible_file(p))
    {
        return Err(refusal());
    }
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
    let mut total = 0;
    for file in files
        .split('\0')
        .filter(|p| !p.is_empty() && admissible_file(p))
    {
        gate.check(file.as_bytes())?;
        let path = root.join(file);
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
                return Err(refusal());
            }
            total += gate.file(&path)?;
            if total > 20 * MAX_FILE_BYTES {
                return Err(refusal());
            }
        }
    }

    Ok(())
}
fn gate_changes<'a>(raw: &'a str, gate: &Gate) -> Result<Vec<&'a str>, ScalerError> {
    let refusal = || ScalerError::Guard("redaction gate refused repository tree shape");
    let mut parts = raw.split('\0');
    let mut paths = Vec::new();
    while let Some(header) = parts.next().filter(|s| !s.is_empty()) {
        let mode = header
            .strip_prefix(':')
            .and_then(|s| s.split_whitespace().nth(1))
            .ok_or_else(refusal)?;
        if !matches!(mode, "100644" | "100755" | "000000") {
            return Err(refusal());
        }
        let path = parts.next().ok_or_else(refusal)?;
        if !admissible_file(path) {
            return Err(refusal());
        }
        gate.check(path.as_bytes())?;
        paths.push(path);
    }
    Ok(paths)
}
fn gate_object(root: &Path, gate: &Gate, id: &str) -> Result<u64, ScalerError> {
    let size: u64 = git(root, &["cat-file", "-s", id])?
        .trim()
        .parse()
        .map_err(|_| ScalerError::Guard("redaction gate refused object size"))?;
    if size > MAX_FILE_BYTES {
        return Err(ScalerError::Guard(
            "redaction gate refused oversized object",
        ));
    }
    let bytes = crate::ci_scaler::execute(
        &mut git_invocation(root, &["cat-file", "-p", id]),
        &[],
        std::time::Duration::from_secs(30),
    )?;
    gate.check(&bytes)?;
    Ok(size)
}
fn checkpoint(root: &Path, dispatch: &Dispatch, gate: &Gate) -> Result<bool, ScalerError> {
    gate_work(root, gate)?;
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

const AGENT_USER: &str = "carrick-dispatch-agent";
const MAX_BUNDLE_BYTES: u64 = 20 * MAX_FILE_BYTES;
const BUNDLE_REF: &str = "refs/heads/dispatch-output";

fn output(command: &mut Command) -> Result<Vec<u8>, ScalerError> {
    crate::ci_scaler::execute(command, &[], std::time::Duration::from_secs(120))
}
pub(crate) fn git_invocation(root: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    // All repositories used by the driver have freshly created configuration.
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
            "user.name=carrick-workers[bot]",
            "-c",
            "user.email=carrick-workers[bot]@users.noreply.github.com",
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
        "chown",
        "-hR",
        AGENT_USER,
        path.to_str().ok_or(ScalerError::Guard("agent path"))?,
    ])
}
fn retire_agent() -> Result<(), ScalerError> {
    // Include real and effective UIDs (setuid tools), regardless of sessions.
    for selector in ["-u", "-U"] {
        let _ = sudo(&["pkill", "-STOP", selector, AGENT_USER]);
        let _ = sudo(&["pkill", "-KILL", selector, AGENT_USER]);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        // SAFETY: the driver is a subreaper and has already waited for its
        // foreground child. Reap only completed adopted children.
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
        let mut empty = true;
        for selector in ["-u", "-U"] {
            let status = Command::new("/usr/bin/sudo")
                .args(["-n", "pgrep", selector, AGENT_USER])
                .output()?;
            match status.status.code() {
                Some(1) => {}
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
        retire_agent()?;
        sudo(&["userdel", AGENT_USER])?;
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
fn open_prs(root: &Path, branch: &str) -> Result<Value, ScalerError> {
    Ok(serde_json::from_str(&gh(
        root,
        &[
            "pr",
            "list",
            "--repo",
            REPOSITORY,
            "--head",
            branch,
            "--state",
            "open",
            "--base",
            "main",
            "--json",
            "number,url,author,headRepository,headRepositoryOwner",
        ],
    )?)?)
}
fn marker(issue: u64, branch: &str) -> String {
    format!("<!-- carrick-dispatch-owner:v1 issue={issue} branch={branch} -->")
}
fn owned_pr(pr: &Value, comments: &Value, issue: u64, branch: &str) -> bool {
    pr["author"]["login"] == "app/carrick-workers"
        && pr["author"]["is_bot"] == true
        && pr["headRepositoryOwner"]["login"] == "carrick-sh"
        && pr["headRepository"]["name"] == "carrick"
        && comments.as_array().is_some_and(|comments| {
            comments.iter().any(|c| {
                c["user"]["login"] == "carrick-workers[bot]"
                    && c["user"]["type"] == "Bot"
                    && c["performed_via_github_app"]["slug"] == "carrick-workers"
                    && c["body"].as_str() == Some(marker(issue, branch).as_str())
            })
        })
}
fn require_owned_pr(root: &Path, dispatch: &Dispatch) -> Result<Value, ScalerError> {
    for pr in open_prs(root, &dispatch.branch)?
        .as_array()
        .into_iter()
        .flatten()
    {
        let number = pr["number"]
            .as_u64()
            .ok_or(ScalerError::Guard("missing PR number"))?;
        let comments: Value = serde_json::from_str(&gh(
            root,
            &[
                "api",
                "--paginate",
                "--slurp",
                &format!("repos/{REPOSITORY}/issues/{number}/comments"),
            ],
        )?)?;
        let comments = Value::Array(
            comments
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|page| page.as_array().into_iter().flatten().cloned())
                .collect(),
        );
        if owned_pr(pr, &comments, dispatch.issue, &dispatch.branch) {
            return Ok(pr.clone());
        }
    }
    Err(ScalerError::Guard(
        "branch lacks an App-authored ownership marker",
    ))
}

// Copy bytes, never aliases. The producer is dead and cannot write the
// runner-owned destination. No Git command opens the candidate configuration.
fn copy_tree(source: &Path, target: &Path, count: &mut usize) -> Result<(), ScalerError> {
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
            copy_tree(&entry.path(), &dest, count)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), dest)?;
        } else {
            return Err(ScalerError::Guard("snapshot refused nonregular file"));
        }
    }
    Ok(())
}
fn regular_text(path: &Path) -> Result<String, ScalerError> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return Err(ScalerError::Guard("unsafe metadata"));
    }
    Ok(std::fs::read_to_string(path)?)
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
    copy_tree(source, target, &mut 0)?;
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
        copy_tree(&entry.path(), &dest, &mut 0)?;
    }
    git(target, &["update-ref", "HEAD", &head])?;
    git(target, &["read-tree", "HEAD"])?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    base: String,
    head: String,
    issue: u64,
    branch: String,
    exit_code: i32,
    expected_tip: String,
    contract: Contract,
}
fn validate_bundle(
    root: &Path,
    path: &Path,
    base: &str,
    gate: &Gate,
) -> Result<String, ScalerError> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > MAX_BUNDLE_BYTES {
        return Err(ScalerError::Guard("bundle size cap or file type"));
    }
    let bytes = std::fs::read(path)?;
    let end = bytes
        .windows(2)
        .position(|w| w == b"\n\n")
        .filter(|n| *n < 65536)
        .ok_or(ScalerError::Guard("invalid bundle header"))?;
    gate.check(&bytes)?;
    let header = std::str::from_utf8(&bytes[..end])
        .map_err(|_| ScalerError::Guard("bundle header encoding"))?;
    let lines: Vec<_> = header.lines().collect();
    if lines.len() != 3
        || lines[0] != "# v2 git bundle"
        || lines[1].split_whitespace().next() != Some(format!("-{base}").as_str())
    {
        return Err(ScalerError::Guard(
            "bundle must require exactly the recorded base",
        ));
    }
    let (head, reference) = lines[2]
        .split_once(' ')
        .ok_or(ScalerError::Guard("missing bundle ref"))?;
    if !sha(head) || reference != BUNDLE_REF {
        return Err(ScalerError::Guard("bundle tags or extra refs refused"));
    }
    let all_objects = |root: &Path| -> Result<std::collections::BTreeSet<String>, ScalerError> {
        Ok(git(
            root,
            &[
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname)",
            ],
        )?
        .lines()
        .map(str::to_owned)
        .collect())
    };
    let before = all_objects(root)?;
    let path = path.to_str().ok_or(ScalerError::Guard("bundle path"))?;
    git(root, &["bundle", "verify", path])?;
    git(root, &["bundle", "unbundle", path])?;
    git(root, &["merge-base", "--is-ancestor", base, head])?;
    let reachable: std::collections::BTreeSet<_> = git(
        root,
        &[
            "rev-list",
            "--objects",
            "--no-object-names",
            head,
            &format!("^{base}"),
        ],
    )?
    .lines()
    .map(str::to_owned)
    .collect();
    let after = all_objects(root)?;
    let imported: std::collections::BTreeSet<_> = after.difference(&before).cloned().collect();
    if reachable != imported || imported.len() > 4096 {
        return Err(ScalerError::Guard(
            "bundle contains extra or excessive objects",
        ));
    }
    let mut total = 0;
    let mut commits = 0;
    for id in &imported {
        match git(root, &["cat-file", "-t", id])?.trim() {
            "commit" => {
                commits += 1;
                // A merge cannot smuggle in unrelated side-branch history.
                git(root, &["merge-base", "--is-ancestor", base, id])?;
                let paths = git(
                    root,
                    &[
                        "diff-tree",
                        "--no-commit-id",
                        "--root",
                        "-r",
                        "--raw",
                        "--no-renames",
                        "--no-ext-diff",
                        "--no-textconv",
                        "-m",
                        "-z",
                        id,
                    ],
                )?;
                gate_changes(&paths, gate)?;
            }
            "blob" | "tree" => {}
            _ => {
                return Err(ScalerError::Guard(
                    "bundle contains a tag or unknown object",
                ));
            }
        }
        total += gate_object(root, gate, id)?;
        if total > MAX_BUNDLE_BYTES || commits > 256 {
            return Err(ScalerError::Guard(
                "bundle decoded size or commit cap exceeded",
            ));
        }
    }
    git(root, &["update-ref", "HEAD", head])?;
    Ok(head.to_owned())
}

pub fn run(root: &Path, args: DispatchArgs) -> Result<(), ScalerError> {
    let root = root.canonicalize()?;
    let (event_path, setup, artifact) = match args.action {
        DispatchAction::Guard { event } => (event, None, None),
        DispatchAction::Run {
            event,
            setup_status,
        } => (event, Some(setup_status), None),
        DispatchAction::Publish { event, artifact } => (event, None, Some(artifact)),
    };
    let event: Value = serde_json::from_slice(&std::fs::read(event_path)?)?;
    let mut dispatch = validate_event(
        &event,
        include_str!("../../../.github/dispatch-tiers.toml"),
        &std::env::var("GITHUB_TRIGGERING_ACTOR").unwrap_or_default(),
    )?;
    assigned_branch(&mut dispatch)?;
    if let Some(artifact) = artifact {
        return publish(&root, &dispatch, &artifact);
    }
    let Some(setup) = setup else {
        return Ok(());
    };
    if std::env::var_os("GH_TOKEN").is_some() || std::env::var_os("AGENT_WORKER_TOKEN").is_some() {
        return Err(ScalerError::Guard(
            "agent job must have no GitHub publish credential",
        ));
    }
    produce(&root, &dispatch, &setup)
}
fn produce(root: &Path, dispatch: &Dispatch, setup: &str) -> Result<(), ScalerError> {
    let base =
        std::env::var("GITHUB_SHA").map_err(|_| ScalerError::Guard("missing admitted SHA"))?;
    if !sha(&base) || git(root, &["rev-parse", "HEAD"])?.trim() != base {
        return Err(ScalerError::Guard("checkout differs from admitted SHA"));
    }
    let mut gate = Gate::capture()?;
    let temporary =
        PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or(ScalerError::Guard("runner temp"))?);
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    let frozen = tempfile::tempdir()?;
    let package = frozen.path().join("package");
    std::fs::create_dir(&package)?;
    let mut contract = Contract {
        status: ContractStatus::Failed,
        summary: format!("Worker setup did not complete: {setup}"),
        tests: vec![],
        risks: vec![],
    };
    let mut code = 1;
    let mut head = base.clone();
    let mut expected_tip = String::new();
    if setup == "success/success" {
        #[cfg(target_os = "linux")]
        // SAFETY: the dedicated driver must adopt and reap detached agent children.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // The account has no login, password, sudo rights or runner membership.
        sudo(&[
            "useradd",
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            AGENT_USER,
        ])?;
        let outer = tempfile::Builder::new()
            .prefix("carrick-dispatch-")
            .tempdir_in("/var/tmp")?;
        std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o711))?;
        let state = outer.path().join("agent");
        std::fs::create_dir(&state)?;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
        let bootstrap = crate::agent_runner::state()?;
        for name in ["home", "bin", "director"] {
            copy_tree(&bootstrap.join(name), &state.join(name), &mut 0)?;
        }
        let work = state.join("work");
        git(
            &state,
            &[
                "clone",
                "--no-local",
                "--no-checkout",
                "--no-hardlinks",
                root.to_str().ok_or(ScalerError::Guard("checkout path"))?,
                "work",
            ],
        )?;
        if dispatch.resume {
            git(
                &work,
                &[
                    "fetch",
                    "--no-tags",
                    "https://github.com/carrick-sh/carrick",
                    &format!("refs/heads/{}", dispatch.branch),
                ],
            )?;
            expected_tip = git(&work, &["rev-parse", "FETCH_HEAD"])?.trim().to_owned();
            git(&work, &["checkout", "-b", &dispatch.branch, "FETCH_HEAD"])?;
            git(&work, &["rebase", &base])?;
        } else {
            git(&work, &["checkout", "-b", &dispatch.branch, &base])?;
        }
        git(&work, &["config", "user.name", "carrick-workers[bot]"])?;
        git(
            &work,
            &[
                "config",
                "user.email",
                "carrick-workers[bot]@users.noreply.github.com",
            ],
        )?;
        let result = agent(&work, dispatch);
        // Retire the account before freezing source bytes, including on failure.
        cleanup_agent_user()?;
        sudo(&[
            "chmod",
            "700",
            state.to_str().ok_or(ScalerError::Guard("agent state"))?,
        ])?;
        sudo(&[
            "chown",
            "-hR",
            &unsafe { libc::geteuid() }.to_string(),
            state.to_str().ok_or(ScalerError::Guard("agent state"))?,
        ])?;
        code = result?;
        contract = read_contract(&state.join("result.json")).unwrap_or(Contract {
            status: ContractStatus::Failed,
            summary: "No valid worker contract".into(),
            tests: vec![],
            risks: vec!["Worker output is incomplete".into()],
        });
        gate.absorb_provider_home(&state.join("home"))?;
        contract.check(&gate)?;
        for name in ["agent.out", "agent.err"] {
            let bytes = regular_text(&state.join(name))?;
            std::fs::write(package.join(name), gate.diagnostic(bytes.as_bytes()))?;
        }
        let safe = frozen.path().join("snapshot");
        snapshot(&work, &safe, &dispatch.branch)?;
        if checkpoint(&safe, dispatch, &gate)? {
            contract.status = ContractStatus::Failed;
            contract
                .risks
                .push("Workflow checkpointed unfinished changes".into());
        }
        gate_work(&safe, &gate)?;
        head = git(&safe, &["rev-parse", "HEAD"])?.trim().to_owned();
        if head != base {
            git(&safe, &["update-ref", BUNDLE_REF, &head])?;
            let bundle = package.join("work.bundle");
            git(
                &safe,
                &[
                    "bundle",
                    "create",
                    bundle.to_str().ok_or(ScalerError::Guard("bundle path"))?,
                    BUNDLE_REF,
                    &format!("^{base}"),
                ],
            )?;
            if std::fs::metadata(&bundle)?.len() > MAX_BUNDLE_BYTES {
                return Err(ScalerError::Guard("bundle size cap exceeded"));
            }
        }
    }
    contract.check(&gate)?;
    std::fs::write(
        package.join("contract.json"),
        serde_json::to_vec_pretty(&contract)?,
    )?;
    let receipt = Receipt {
        base,
        head,
        issue: dispatch.issue,
        branch: dispatch.branch.clone(),
        exit_code: code,
        expected_tip,
        contract,
    };
    std::fs::write(
        package.join("result.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    if receipt.head != receipt.base {
        let validation = frozen.path().join("validation");
        std::fs::create_dir(&validation)?;
        git(&validation, &["init"])?;
        git(
            &validation,
            &[
                "fetch",
                "--no-tags",
                root.to_str().ok_or(ScalerError::Guard("root path"))?,
                &receipt.base,
            ],
        )?;
        validate_bundle(
            &validation,
            &package.join("work.bundle"),
            &receipt.base,
            &gate,
        )?;
    }
    gate.directory(&package)?;
    let target =
        PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or(ScalerError::Guard("runner temp"))?)
            .join("dispatch-output");
    copy_tree(&package, &target, &mut 0)?;
    Ok(())
}
fn publish(root: &Path, dispatch: &Dispatch, artifact: &Path) -> Result<(), ScalerError> {
    crate::agent_runner::check_token(root, crate::agent_runner::TokenScope::Worker)?;
    let gate = Gate::capture()?;
    gate.directory(artifact)?;
    let base =
        std::env::var("GITHUB_SHA").map_err(|_| ScalerError::Guard("missing admitted SHA"))?;
    let mut receipt: Option<Receipt> = None;
    for entry in std::fs::read_dir(artifact)? {
        let entry = entry?;
        if !matches!(
            entry.file_name().to_str(),
            Some("work.bundle" | "result.json" | "contract.json" | "agent.out" | "agent.err")
        ) {
            return Err(ScalerError::Guard("unexpected artifact member"));
        }
        if entry.file_name() == "result.json" {
            receipt = Some(serde_json::from_slice(&std::fs::read(entry.path())?)?);
        }
    }
    let receipt = receipt.ok_or(ScalerError::Guard("missing receipt"))?;
    if receipt.base != base
        || !sha(&base)
        || receipt.issue != dispatch.issue
        || receipt.branch != dispatch.branch
        || !sha(&receipt.head)
    {
        return Err(ScalerError::Guard("artifact admission mismatch"));
    }
    receipt.contract.check(&gate)?;
    let isolated = tempfile::tempdir()?;
    git(isolated.path(), &["init"])?;
    git(
        isolated.path(),
        &[
            "fetch",
            "--no-tags",
            root.to_str().ok_or(ScalerError::Guard("root path"))?,
            &base,
        ],
    )?;
    let bundle = artifact.join("work.bundle");
    let head = if receipt.head == base {
        if bundle.exists() {
            return Err(ScalerError::Guard("unexpected no-change bundle"));
        }
        base.clone()
    } else {
        validate_bundle(isolated.path(), &bundle, &base, &gate)?
    };
    if head != receipt.head {
        return Err(ScalerError::Guard("bundle head mismatch"));
    }
    git(isolated.path(), &["update-ref", "HEAD", &head])?;
    let existing = if dispatch.resume {
        Some(require_owned_pr(root, dispatch)?)
    } else {
        None
    };
    let template = include_str!("../../../.github/pull_request_template.md")
        .replace("Closes #\n", &format!("Closes #{}\n", dispatch.issue))
        .replace(
            "<!-- Approach and any candid divergence from Linux. -->",
            &receipt.contract.summary,
        )
        .replace("NEW: none / FIXED: none", "Not compared")
        .replace("NEW: / FIXED:", "Not compared")
        .replace("HEAD, SHA-256, CDHash", "Not collected");
    let body = format!(
        "{template}\nWorker contract (claims for review):\n\n```json\n{}\n```\n",
        serde_json::to_string_pretty(&receipt.contract)?
    );
    let comment = format!(
        "Dispatch run {}\n\n{}",
        run_id()?,
        serde_json::to_string_pretty(&receipt)?
    );
    // Validate everything before the first write, including static metadata.
    for text in [
        &body,
        &comment,
        &dispatch.branch,
        &marker(dispatch.issue, &dispatch.branch),
    ] {
        gate.check(text.as_bytes())?;
    }
    let body_path = isolated.path().join("body.md");
    let comment_path = isolated.path().join("comment.md");
    std::fs::write(&body_path, body)?;
    std::fs::write(&comment_path, comment)?;
    if head != base {
        // New branches must be absent, even if their name looks like ours.
        let expected = if dispatch.resume {
            git(
                isolated.path(),
                &[
                    "ls-remote",
                    "--heads",
                    "https://github.com/carrick-sh/carrick",
                    &format!("refs/heads/{}", dispatch.branch),
                ],
            )?
            .split_whitespace()
            .next()
            .ok_or(ScalerError::Guard("resume branch missing"))?
            .to_owned()
        } else {
            String::new()
        };
        if expected != receipt.expected_tip || (dispatch.resume && !sha(&expected)) {
            return Err(ScalerError::Guard("branch changed since preparation"));
        }
        // Git auth is scoped to this trusted process; never written to any home.
        let mut push = git_invocation(
            isolated.path(),
            &[
                "-c",
                "credential.helper=!gh auth git-credential",
                "push",
                "--no-follow-tags",
                &format!(
                    "--force-with-lease=refs/heads/{}:{expected}",
                    dispatch.branch
                ),
                "https://github.com/carrick-sh/carrick",
                &format!("HEAD:refs/heads/{}", dispatch.branch),
            ],
        );
        output(&mut push)?;
        if let Some(pr) = existing {
            gh(
                root,
                &[
                    "pr",
                    "comment",
                    &pr["number"].to_string(),
                    "--repo",
                    REPOSITORY,
                    "--body-file",
                    body_path.to_str().ok_or(ScalerError::Guard("body path"))?,
                ],
            )?;
        } else {
            let url = gh(
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
                    body_path.to_str().ok_or(ScalerError::Guard("body path"))?,
                ],
            )?;
            let marker_path = isolated.path().join("owner.md");
            std::fs::write(&marker_path, marker(dispatch.issue, &dispatch.branch))?;
            gh(
                root,
                &[
                    "pr",
                    "comment",
                    url.trim(),
                    "--repo",
                    REPOSITORY,
                    "--body-file",
                    marker_path
                        .to_str()
                        .ok_or(ScalerError::Guard("marker path"))?,
                ],
            )?;
        }
    }
    gh(
        root,
        &[
            "issue",
            "comment",
            &dispatch.issue.to_string(),
            "--repo",
            REPOSITORY,
            "--body-file",
            comment_path
                .to_str()
                .ok_or(ScalerError::Guard("comment path"))?,
        ],
    )?;
    if receipt.exit_code != 0 || receipt.contract.status != ContractStatus::Done {
        return Err(ScalerError::Guard(
            "dispatch incomplete; published contract describes failure",
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    #[test]
    fn safe_outputs_boundary() {
        let workflow = include_str!("../../../.github/workflows/dispatch-worker.yml");
        let worker = workflow
            .split("  worker:")
            .nth(1)
            .unwrap()
            .split("  publish:")
            .next()
            .unwrap();
        assert!(!worker.contains("AGENT_WORKER_TOKEN"));
        assert!(worker.contains("environment: agent-execution"));
        assert!(
            workflow
                .split("  publish:")
                .nth(1)
                .unwrap()
                .contains("environment: agent-dispatch")
        );
        assert!(!include_str!("agent_runner.rs").contains("helper = !gh auth git-credential"));
        assert!(workflow.contains("artifact-ids:"));
        assert!(workflow.contains("needs.worker.outputs.artifact_id"));
        assert!(!workflow.contains("steps.worker.outputs.artifact_path"));
        assert!(!worker.contains("ref: main"));
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
    fn publisher_refuses_unrelated_tag_oversize_and_credential_bundles() {
        let mut accepted = Vec::new();
        for case in [
            "unrelated",
            "tag",
            "oversize",
            "credential",
            "message",
            "merge-side",
            "clean",
        ] {
            let source = tempfile::tempdir().unwrap();
            fixture_repository(source.path());
            let base = git(source.path(), &["rev-parse", "HEAD"])
                .unwrap()
                .trim()
                .to_owned();
            if case == "unrelated" || case == "merge-side" {
                git(source.path(), &["checkout", "--orphan", "unrelated"]).unwrap();
            }
            let content = if case == "credential" {
                "ghs_plantedcredential"
            } else {
                "candidate"
            };
            std::fs::write(source.path().join("payload"), content).unwrap();
            git(source.path(), &["add", "payload"]).unwrap();
            git(
                source.path(),
                &[
                    "commit",
                    "-m",
                    if case == "message" {
                        "ghs_plantedcredential"
                    } else {
                        "candidate"
                    },
                ],
            )
            .unwrap();
            if case == "merge-side" {
                git(source.path(), &["checkout", "work/dispatch-634-pending"]).unwrap();
                git(
                    source.path(),
                    &[
                        "merge",
                        "--allow-unrelated-histories",
                        "--no-edit",
                        "unrelated",
                    ],
                )
                .unwrap();
            }
            let bundle = source.path().join("output.bundle");
            let bundle_path = bundle.to_str().unwrap();
            if case == "tag" {
                git(source.path(), &["tag", "extra"]).unwrap();
                git(
                    source.path(),
                    &["bundle", "create", bundle_path, "HEAD", "refs/tags/extra"],
                )
                .unwrap();
            } else if case == "oversize" {
                std::fs::File::create(&bundle)
                    .unwrap()
                    .set_len(MAX_BUNDLE_BYTES + 1)
                    .unwrap();
            } else if case == "unrelated" {
                git(source.path(), &["bundle", "create", bundle_path, "HEAD"]).unwrap();
            } else {
                git(source.path(), &["update-ref", BUNDLE_REF, "HEAD"]).unwrap();
                git(
                    source.path(),
                    &[
                        "bundle",
                        "create",
                        bundle_path,
                        BUNDLE_REF,
                        &format!("^{base}"),
                    ],
                )
                .unwrap();
            }
            let target = tempfile::tempdir().unwrap();
            git(target.path(), &["init"]).unwrap();
            git(
                target.path(),
                &["fetch", source.path().to_str().unwrap(), &base],
            )
            .unwrap();
            let result = validate_bundle(target.path(), &bundle, &base, &Gate::capture().unwrap());
            if case == "clean" {
                assert!(result.is_ok(), "{result:?}");
            } else if result.is_ok() {
                accepted.push(case);
            }
        }
        assert!(accepted.is_empty(), "accepted unsafe bundles: {accepted:?}");
    }
    #[test]
    fn branch_requires_app_pr_and_app_comment_marker() {
        let branch = "work/dispatch-634-old";
        let pr = json!({"number":12,"author":{"login":"app/carrick-workers","is_bot":true},
            "headRepositoryOwner":{"login":"carrick-sh"},"headRepository":{"name":"carrick"},
            "body":"Closes #634"});
        assert!(
            !owned_pr(&pr, &json!([]), 634, branch),
            "namespace or body is not ownership"
        );
        let mut comments =
            json!([{"user":{"login":"someone-else","type":"User"},"body":marker(634, branch)}]);
        assert!(!owned_pr(&pr, &comments, 634, branch));
        comments[0]["user"] = json!({"login":"carrick-workers[bot]","type":"Bot"});
        comments[0]["performed_via_github_app"] = json!({"slug":"carrick-workers"});
        assert!(owned_pr(&pr, &comments, 634, branch));
        assert!(!owned_pr(&pr, &comments, 635, branch));
        let mut unowned = pr;
        unowned["author"]["login"] = "someone-else".into();
        assert!(!owned_pr(&unowned, &comments, 634, branch));
    }
    #[test]
    fn agent_environment_has_no_github_token_or_config() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.env("GH_TOKEN", "planted")
            .env("GITHUB_TOKEN", "planted")
            .env("GITHUB_OUTPUT", "/runner/set_output")
            .env("GIT_CONFIG_GLOBAL", "/credential/helper");
        private_environment(&mut cmd);
        let output = cmd.output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "PATH=/usr/local/bin:/usr/bin:/bin\n"
        );
    }
    #[test]
    fn snapshot_drops_executable_git_configuration() {
        let source = tempfile::tempdir().unwrap();
        fixture_repository(source.path());
        let branch = "work/dispatch-634-pending";
        std::fs::write(source.path().join("payload"), "candidate").unwrap();
        git(source.path(), &["add", "payload"]).unwrap();
        git(source.path(), &["commit", "-m", "candidate"]).unwrap();
        std::fs::write(source.path().join(".gitattributes"), "* filter=evil").unwrap();
        std::fs::write(source.path().join(".git/config"),
            "[core]\nfsmonitor = touch /tmp/dispatch-must-not-execute\n[filter \"evil\"]\nclean = touch /tmp/dispatch-must-not-execute\n").unwrap();
        let frozen = tempfile::tempdir().unwrap();
        let target = frozen.path().join("snapshot");
        snapshot(source.path(), &target, branch).unwrap();
        let config = std::fs::read_to_string(target.join(".git/config")).unwrap();
        assert!(!config.contains("evil") && !config.contains("fsmonitor"));
        let gate = Gate::capture().unwrap();
        assert!(
            checkpoint(
                &target,
                &validate_event(&event(), TIERS, "tjfontaine").unwrap(),
                &gate
            )
            .unwrap()
        );
        assert!(!Path::new("/tmp/dispatch-must-not-execute").exists());
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
        let gate = Gate::capture().unwrap();
        assert!(checkpoint(root, &d, &gate).unwrap());
        let message = git(root, &["log", "-1", "--format=%B"]).unwrap();
        assert!(message.contains("Co-Authored-By: GPT-6.1 Sol <noreply@openai.com>"));
        assert_eq!(
            git(root, &["ls-tree", "--name-only", "HEAD"])
                .unwrap()
                .trim(),
            "new file"
        );
        assert!(!checkpoint(root, &d, &gate).unwrap());
    }
}
