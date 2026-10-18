//! Issue-label dispatch driver. Workflow input never becomes shell source.
use crate::ci_scaler::{REPOSITORY, ScalerError};
use crate::dispatch_redaction::{Gate, MAX_FILE_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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
    /// Foreground worker, bounded to 30 minutes plus publication/cleanup.
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

/// An explicit `Branch: work/...` line in the brief selects an existing branch.
/// All other invocations start at a freshly fetched GitHub main.
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
        let slug: String = title
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        let slug = slug
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-");
        let slug = slug.chars().take(60).collect::<String>();
        format!(
            "work/dispatch-{issue}-{}",
            if slug.is_empty() {
                "issue"
            } else {
                slug.trim_matches('-')
            }
        )
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
    for line in brief.lines() {
        let trimmed = line.trim();
        if let Some(marker @ ('`' | '~')) = trimmed.chars().next() {
            let count = trimmed.chars().take_while(|c| *c == marker).count();
            if count >= 3 {
                match fence {
                    None => fence = Some((marker, count)),
                    Some((open, length))
                        if open == marker
                            && count >= length
                            && trimmed[count..].trim().is_empty() =>
                    {
                        fence = None
                    }
                    _ => {}
                }
                continue;
            }
        }
        if fence.is_none() {
            if let Some(branch) = line.strip_prefix("Branch: ") {
                branches.push(branch);
            }
        }
    }
    branches
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
            "number,url,body,isDraft,headRepository,headRepositoryOwner",
        ],
    )?)?)
}
fn same_repository(pr: &Value) -> bool {
    pr["headRepositoryOwner"]["login"] == "carrick-sh" && pr["headRepository"]["name"] == "carrick"
}
fn references_issue(pr: &Value, issue: u64) -> bool {
    let needle = format!("#{issue}");
    let body = pr["body"].as_str().unwrap_or_default();
    body.match_indices(&needle).any(|(index, matched)| {
        let before = body[..index].chars().next_back();
        let after = body[index + matched.len()..].chars().next();
        before.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '/')
            && after.is_none_or(|c| !c.is_ascii_alphanumeric())
    })
}

pub fn brief_section(body: &str) -> Result<String, ScalerError> {
    let mut in_brief = false;
    let mut found = false;
    let mut lines = Vec::new();
    // Markdown fences may contain headings; they do not delimit sections.
    let mut fence: Option<char> = None;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            let marker = trimmed.chars().next();
            if fence == marker {
                fence = None;
            } else if fence.is_none() {
                fence = marker;
            }
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

fn command(root: &Path, program: &str, args: &[&str]) -> Result<String, ScalerError> {
    let remote =
        program == "gh" || (program == "git" && matches!(args.first(), Some(&"fetch" | &"push")));
    let mut limit = std::time::Duration::from_secs(120);
    if remote {
        limit = limit.min(crate::agent_runner::job_remaining(39)?);
    }
    let output = crate::ci_scaler::execute(
        Command::new(program).args(args).current_dir(root),
        &[],
        limit,
    );
    let bytes = match output {
        Err(error) if remote => {
            return Err(crate::agent_runner::check_token(
                root,
                crate::agent_runner::TokenScope::Worker,
            )
            .err()
            .unwrap_or(error));
        }
        result => result?,
    };
    String::from_utf8(bytes).map_err(|_| ScalerError::Guard("command output is not UTF-8"))
}
fn git(root: &Path, args: &[&str]) -> Result<String, ScalerError> {
    command(root, "git", args)
}
fn gh(root: &Path, args: &[&str]) -> Result<String, ScalerError> {
    command(root, "gh", args)
}

fn prepare(root: &Path, dispatch: &Dispatch, worktree: &Path) -> Result<(), ScalerError> {
    // Fix both git transport and gh to the App credential inherited from the
    // runner. actions/checkout deliberately leaves no installation token behind.
    gh(root, &["auth", "setup-git", "--hostname", "github.com"])?;
    git(
        root,
        &["config", "--local", "user.name", "carrick-workers[bot]"],
    )?;
    git(
        root,
        &[
            "config",
            "--local",
            "user.email",
            "carrick-workers[bot]@users.noreply.github.com",
        ],
    )?;
    git(
        root,
        &[
            "fetch",
            "https://github.com/carrick-sh/carrick",
            "+refs/heads/main:refs/remotes/origin/main",
        ],
    )?;
    let existing = dispatch.resume;
    if existing
        && !dispatch
            .branch
            .starts_with(&format!("work/dispatch-{}-", dispatch.issue))
    {
        let prs = open_prs(root, &dispatch.branch)?;
        if !prs.as_array().is_some_and(|prs| {
            prs.iter()
                .any(|pr| same_repository(pr) && references_issue(pr, dispatch.issue))
        }) {
            return Err(ScalerError::Guard(
                "branch is not owned by this issue dispatch",
            ));
        }
    }
    if !existing
        && git(
            root,
            &[
                "show-ref",
                "--verify",
                "--quiet",
                &format!("refs/remotes/origin/{}", dispatch.branch),
            ],
        )
        .is_ok()
    {
        return Err(ScalerError::Guard(
            "dispatch branch already exists; name it with Branch: to continue",
        ));
    }
    let start = if existing {
        let refspec = format!(
            "+refs/heads/{}:refs/remotes/origin/{}",
            dispatch.branch, dispatch.branch
        );
        git(
            root,
            &["fetch", "https://github.com/carrick-sh/carrick", &refspec],
        )?;
        format!("refs/remotes/origin/{}", dispatch.branch)
    } else {
        "refs/remotes/origin/main".to_owned()
    };
    let path = worktree
        .to_str()
        .ok_or(ScalerError::Guard("non-UTF8 worktree path"))?;
    git(
        root,
        &["worktree", "add", "-b", &dispatch.branch, path, &start],
    )?;
    if existing {
        git(worktree, &["rebase", "refs/remotes/origin/main"])?;
    }
    Ok(())
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
    if std::fs::metadata(result)?.len() > MAX_FILE_BYTES {
        return Err(ScalerError::Guard(
            "redaction gate refused oversized contract",
        ));
    }
    let value: Value = serde_json::from_slice(&std::fs::read(result)?)?;
    // Preserve a completed work contract even on transport failure. The
    // launcher exit code independently prevents a successful dispatch verdict.
    Ok(serde_json::from_value(value["structured_output"].clone())?)
}

fn wait_agent(command: &mut Command, limit: std::time::Duration) -> std::io::Result<i32> {
    use std::os::unix::process::CommandExt;
    let mut child = command.process_group(0).spawn()?;
    let pgid = i32::try_from(child.id()).map_err(std::io::Error::other)?;
    let deadline = std::time::Instant::now() + limit;
    let mut cancelled = None;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if cancelled.is_some() {
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                }
                return Ok(if cancelled.is_some() {
                    124
                } else {
                    status.code().unwrap_or(1)
                });
            }
            Ok(None) => {}
            Err(error) => {
                unsafe {
                    libc::kill(-pgid, libc::SIGKILL);
                }
                let _ = child.wait();
                return Err(error);
            }
        }
        let now = std::time::Instant::now();
        if now >= deadline && cancelled.is_none() {
            // The owned, unreaped lease supervisor receives TERM first so its
            // guardian can cancel descendants and retain custody through cleanup.
            unsafe {
                libc::kill(-pgid, libc::SIGTERM);
            }
            cancelled = Some(now);
        }
        if cancelled
            .is_some_and(|when| now.duration_since(when) >= std::time::Duration::from_secs(35))
        {
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
            child.wait()?;
            return Ok(124);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn agent(
    root: &Path,
    result_dir: &Path,
    dispatch: &Dispatch,
) -> Result<(i32, Contract), ScalerError> {
    let state = crate::agent_runner::state()?;
    let home = state.join("home");
    let schema_path = result_dir.join("schema.json");
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
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "host-lease",
            "--mode",
            "carrick",
            "--check-load",
            "--",
            "python3",
        ])
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
    crate::agent_runner::isolate_rust_homes(&mut command, &state)?;
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
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(state.join("agent.out"))?)
        .stderr(std::fs::File::create(state.join("agent.err"))?);
    let code = wait_agent(&mut command, crate::agent_runner::job_remaining(32)?)?;
    let contract = read_contract(&result).unwrap_or_else(|error| Contract {
        status: ContractStatus::Failed,
        summary: format!("No valid worker contract: {error}"),
        tests: vec![],
        risks: vec!["Worker output is incomplete".into()],
    });
    Ok((code, contract))
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
        let mut path = root.to_owned();
        for part in Path::new(file).components() {
            path.push(part);
            match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() => return Err(refusal()),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => return Err(e.into()),
            }
        }
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
                return Err(refusal());
            }
            total += gate.file(&path)?;
        }
    }
    let staged = git(root, &["diff", "--cached", "--name-only", "-z"])?;
    for file in staged.split('\0').filter(|s| !s.is_empty()) {
        if !admissible_file(file) {
            return Err(refusal());
        }
        gate.check(file.as_bytes())?;
        // Inspect staged blobs independently of the working file.
        if let Ok(id) = git(root, &["rev-parse", &format!(":{file}")]) {
            total += gate_object(root, gate, id.trim())?;
        }
    }
    let objects = git(
        root,
        &[
            "rev-list",
            "--objects",
            "--no-object-names",
            "HEAD",
            "^refs/remotes/origin/main",
        ],
    )?;
    if objects.lines().count() > 4096 {
        return Err(refusal());
    }
    for id in objects.lines() {
        total += gate_object(root, gate, id)?;
    }
    let commits = git(root, &["rev-list", "HEAD", "^refs/remotes/origin/main"])?;
    if commits.lines().count() > 256 {
        return Err(refusal());
    }
    for commit in commits.lines() {
        let paths = git(
            root,
            &[
                "diff-tree",
                "--no-commit-id",
                "--root",
                "-r",
                "--name-only",
                "-z",
                commit,
            ],
        )?;
        for path in paths.split('\0').filter(|s| !s.is_empty()) {
            if !admissible_file(path) {
                return Err(refusal());
            }
            gate.check(path.as_bytes())?;
        }
    }
    if total > 20 * MAX_FILE_BYTES {
        return Err(refusal());
    }
    Ok(())
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
        Command::new("git")
            .args(["cat-file", "-p", id])
            .current_dir(root),
        &[],
        std::time::Duration::from_secs(30),
    )?;
    gate.check(&bytes)?;
    Ok(size)
}
fn checkpoint(root: &Path, dispatch: &Dispatch, gate: &Gate) -> Result<bool, ScalerError> {
    gate_work(root, gate)?;
    if git(root, &["branch", "--show-current"])?.trim() != dispatch.branch {
        return Err(ScalerError::Guard("worker left its dispatched branch"));
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

/// Keep committed work recoverable even when App publication fails before
/// this one-job VM is destroyed. A failed commit hook leaves staged changes
/// in the binary patch; generated target paths were excluded by checkpoint.
fn preserve_work(
    root: &Path,
    result_dir: &Path,
    dispatch: &Dispatch,
    gate: &Gate,
) -> Result<(), ScalerError> {
    gate_work(root, gate)?;
    gate.directory(result_dir)?;
    let dispatched_ref = format!("refs/heads/{}", dispatch.branch);
    let commits = git(
        root,
        &[
            "rev-list",
            "--count",
            "HEAD",
            &dispatched_ref,
            "--not",
            "refs/remotes/origin/main",
        ],
    )?;
    if commits.trim() != "0" {
        let path = result_dir.join("work.bundle");
        git(
            root,
            &[
                "bundle",
                "create",
                path.to_str()
                    .ok_or(ScalerError::Guard("non-UTF8 bundle path"))?,
                "HEAD",
                &dispatched_ref,
                "^refs/remotes/origin/main",
            ],
        )?;
    }
    let patch = crate::ci_scaler::execute(
        Command::new("git")
            .args(["diff", "--binary", "HEAD"])
            .current_dir(root),
        &[],
        std::time::Duration::from_secs(120),
    )?;
    std::fs::write(result_dir.join("wip.patch"), patch)?;
    gate.directory(result_dir)?;
    Ok(())
}

fn publish(
    root: &Path,
    result_dir: &Path,
    dispatch: &Dispatch,
    contract: &Contract,
    gate: &Gate,
) -> Result<Option<String>, ScalerError> {
    gate_work(root, gate)?;
    gate.directory(result_dir)?;
    gate.check(&serde_json::to_vec(contract)?)?;
    gate.check(dispatch.title.as_bytes())?;
    gate.check(dispatch.branch.as_bytes())?;
    if git(root, &["branch", "--show-current"])?.trim() != dispatch.branch {
        return Err(ScalerError::Guard("refusing to publish another branch"));
    }
    let head = git(root, &["rev-parse", "HEAD"])?;
    let base = git(root, &["rev-parse", "refs/remotes/origin/main"])?;
    if head == base {
        return Ok(None);
    }
    // Explicit main rebases use force-with-lease with the exact fetched head;
    // a new branch must still be absent. Never overwrite a later worker push.
    let expected = if dispatch.resume {
        git(
            root,
            &[
                "rev-parse",
                &format!("refs/remotes/origin/{}", dispatch.branch),
            ],
        )?
    } else {
        String::new()
    };
    let lease = format!(
        "--force-with-lease=refs/heads/{}:{}",
        dispatch.branch,
        expected.trim()
    );
    let refspec = format!("HEAD:refs/heads/{}", dispatch.branch);
    git(
        root,
        &[
            "push",
            &lease,
            "https://github.com/carrick-sh/carrick",
            &refspec,
        ],
    )?;
    let prs = open_prs(root, &dispatch.branch)?;
    let template = include_str!("../../../.github/pull_request_template.md");
    let body = template
        .replace("Closes #\n", &format!("Closes #{}\n", dispatch.issue))
        .replace(
            "<!-- Root cause, Linux/host semantics, what broke for whom. -->",
            &format!("Issue #{}: {}.", dispatch.issue, dispatch.title),
        )
        .replace(
            "<!-- Approach and any candid divergence from Linux. -->",
            &contract.summary,
        )
        .replace("NEW: none / FIXED: none", "Not compared")
        .replace("NEW: / FIXED:", "Not compared")
        .replace("HEAD, SHA-256, CDHash", "Not collected");
    let body = format!(
        "{body}\nWorker contract (claims for review):\n\n```json\n{}\n```\n",
        serde_json::to_string_pretty(contract)?
    );
    gate.check(body.as_bytes())?;
    let path = result_dir.join("pr-body.md");
    std::fs::write(&path, body)?;
    let path = path
        .to_str()
        .ok_or(ScalerError::Guard("non-UTF8 result path"))?;
    if let Some(pr) = prs
        .as_array()
        .and_then(|prs| prs.iter().find(|pr| same_repository(pr)))
    {
        let number = pr["number"]
            .as_u64()
            .ok_or(ScalerError::Guard("PR number missing"))?
            .to_string();
        gh(
            root,
            &[
                "pr",
                "comment",
                &number,
                "--repo",
                REPOSITORY,
                "--body-file",
                path,
            ],
        )?;
        Ok(pr["url"].as_str().map(str::to_owned))
    } else {
        let title = format!("chore(ci): work issue {}", dispatch.issue);
        Ok(Some(
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
                    &title,
                    "--body-file",
                    path,
                ],
            )?
            .trim()
            .to_owned(),
        ))
    }
}

pub fn run(root: &Path, args: DispatchArgs) -> Result<(), ScalerError> {
    let (event, execute, setup_status) = match args.action {
        DispatchAction::Guard { event } => (event, false, String::new()),
        DispatchAction::Run {
            event,
            setup_status,
        } => (event, true, setup_status),
    };
    let event: Value = serde_json::from_slice(&std::fs::read(event)?)?;
    let actor = std::env::var("GITHUB_TRIGGERING_ACTOR")
        .map_err(|_| ScalerError::Guard("missing triggering actor"))?;
    let dispatch = validate_event(
        &event,
        include_str!("../../../.github/dispatch-tiers.toml"),
        &actor,
    )?;
    if !execute {
        println!("dispatch guard admitted issue {}", dispatch.issue);
        return Ok(());
    }
    if !std::env::var("GH_TOKEN").is_ok_and(|token| !token.is_empty()) {
        return Err(ScalerError::Guard(
            "host/infra: missing AGENT_WORKER_TOKEN supplied as GH_TOKEN",
        ));
    }
    let root = root.canonicalize()?;
    let mut gate = Gate::capture()?;
    let result_dir = root.join("dispatch-result");
    std::fs::create_dir(&result_dir)?;
    let worktree = root
        .parent()
        .ok_or(ScalerError::Guard("checkout has no parent"))?
        .join(format!(
            "dispatch-{}-{}-{}",
            dispatch.issue,
            std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".into()),
            std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "1".into())
        ));
    let mut contract = Contract {
        status: ContractStatus::Failed,
        summary: "Worker did not start".into(),
        tests: vec![],
        risks: vec![],
    };
    let mut exit = 1;
    let mut errors = Vec::new();
    let outcome = (|| -> Result<(), ScalerError> {
        crate::agent_runner::check_token(&root, crate::agent_runner::TokenScope::Worker)?;
        if setup_status != "success/success" {
            contract.summary = format!("Worker setup did not complete: {setup_status}");
            return Err(ScalerError::Guard(
                "bootstrap/auth failed; no agent was started",
            ));
        }
        prepare(&root, &dispatch, &worktree)?;
        (exit, contract) = agent(&worktree, &result_dir, &dispatch)?;
        Ok(())
    })();
    if let Err(error) = outcome {
        errors.push(error.to_string());
    }
    let mut pr = None;
    let checked = (|| -> Result<(), ScalerError> {
        gate.absorb_current()?;
        gate.check(dispatch.branch.as_bytes())?;
        gate.check(dispatch.title.as_bytes())?;
        gate.check(&serde_json::to_vec(&contract)?)?;
        gate.check(&serde_json::to_vec(&errors)?)?;
        gate.directory(&result_dir)?;
        if !worktree.join(".git").is_file() {
            return Ok(());
        }
        match checkpoint(&worktree, &dispatch, &gate) {
            Ok(true) => {
                contract.status = ContractStatus::Failed;
                contract
                    .risks
                    .push("Workflow committed unfinished changes as WIP".into());
            }
            Ok(false) => {}
            Err(error) if is_redaction(&error) => return Err(error),
            Err(error) => errors.push(format!("WIP checkpoint: {error}")),
        }
        if let Err(error) = preserve_work(&worktree, &result_dir, &dispatch, &gate) {
            if is_redaction(&error) {
                return Err(error);
            }
            errors.push(format!("Work preservation: {error}"));
        }
        match publish(&worktree, &result_dir, &dispatch, &contract, &gate) {
            Ok(url) => pr = url,
            Err(error) if is_redaction(&error) => return Err(error),
            Err(error) => errors.push(format!("PR publication: {error}")),
        }
        Ok(())
    })();
    let mut refused = checked.as_ref().is_err_and(is_redaction);
    if let Err(error) = checked {
        errors.push(error.to_string());
    }
    if gate.check(&serde_json::to_vec(&errors)?).is_err() {
        refused = true;
    }
    if refused {
        discard_outputs(&result_dir)?;
        contract = Contract {
            status: ContractStatus::Failed,
            summary: "redaction gate refused sensitive or unsafe output".into(),
            tests: vec![],
            risks: vec![],
        };
        errors = vec![
            "redaction gate refused publication; credential-bearing outputs discarded".to_owned(),
        ];
        pr = None;
        exit = 1;
    }
    let head = if refused {
        None
    } else {
        git(&worktree, &["rev-parse", "HEAD"])
            .ok()
            .map(|s| s.trim().to_owned())
    };
    let success =
        exit == 0 && errors.is_empty() && contract.status == ContractStatus::Done && pr.is_some();
    let receipt = json!({"issue":dispatch.issue,"branch":if refused { "[REDACTED]" } else { &dispatch.branch },"sha":head,"pr":pr,"exit_code":exit,
        "timeout":exit == 124,"killed_or_timeout":exit == 137,"success":success,"setup_status":setup_status,"errors":errors,"contract":contract});
    gate.check(&serde_json::to_vec(&receipt)?)?;
    std::fs::write(
        result_dir.join("result.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    let comment = format!(
        "Dispatch worker result (run {}, attempt {})\n\n```json\n{}\n```\n",
        std::env::var("GITHUB_RUN_ID").unwrap_or_default(),
        std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_default(),
        serde_json::to_string_pretty(&receipt)?
    );
    let comment_path = result_dir.join("issue-comment.md");
    std::fs::write(&comment_path, comment)?;
    gate.directory(&result_dir)?;
    seal_outputs(&gate, &result_dir)?;
    gh(
        &root,
        &[
            "issue",
            "comment",
            &dispatch.issue.to_string(),
            "--repo",
            REPOSITORY,
            "--body-file",
            comment_path
                .to_str()
                .ok_or(ScalerError::Guard("non-UTF8 result path"))?,
        ],
    )?;
    if success {
        Ok(())
    } else {
        Err(ScalerError::Guard(
            "dispatch incomplete; see issue comment and dispatch-result/result.json",
        ))
    }
}

fn is_redaction(error: &ScalerError) -> bool {
    matches!(error, ScalerError::Guard(message) if message.starts_with("redaction gate"))
}
fn discard_outputs(path: &Path) -> Result<(), ScalerError> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_dir() && !meta.file_type().is_symlink() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    std::fs::create_dir(path)?;
    Ok(())
}
/// Only this post-validation snapshot is an upload source. An interrupted run
/// never emits an artifact path; raw workspace files are not upload inputs.
fn seal_outputs(gate: &Gate, source: &Path) -> Result<(), ScalerError> {
    gate.directory(source)?;
    let temporary =
        std::env::var_os("RUNNER_TEMP").ok_or(ScalerError::Guard("RUNNER_TEMP required"))?;
    let sealed = tempfile::Builder::new()
        .prefix("dispatch-validated-")
        .tempdir_in(temporary)?;
    fn copy(source: &Path, target: &Path) -> std::io::Result<()> {
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let output = target.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                std::fs::create_dir(&output)?;
                copy(&entry.path(), &output)?;
            } else {
                std::fs::copy(entry.path(), output)?;
            }
        }
        Ok(())
    }
    copy(source, sealed.path())?;
    gate.directory(sealed.path())?;
    if let Some(output) = std::env::var_os("GITHUB_OUTPUT") {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().append(true).open(output)?;
        writeln!(file, "artifact_path={}", sealed.path().display())?;
        let _ = sealed.keep();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    #[test]
    fn startup_deadline_cancels_and_reaps_the_owned_child() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exec sleep 60"]);
        let start = std::time::Instant::now();
        assert_eq!(
            wait_agent(&mut command, std::time::Duration::from_millis(20)).unwrap(),
            124
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
    const TIERS: &str = include_str!("../../../.github/dispatch-tiers.toml");
    #[cfg(target_os = "linux")]
    #[test]
    fn agent_timeout_kills_a_grandchild_in_the_owned_group() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_file = tmp.path().join("grandchild.pid");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 60 & echo $! > \"$1\"; wait", "fixture"])
            .arg(&pid_file);
        assert_eq!(
            wait_agent(&mut command, std::time::Duration::from_millis(200)).unwrap(),
            124
        );
        let pid: i32 = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let alive = std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
            !stat
                .split(')')
                .nth(1)
                .unwrap()
                .trim_start()
                .starts_with('Z')
        });
        // Always clean up the red witness too.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        assert!(!alive, "agent timeout left a live grandchild");
    }
    fn event() -> Value {
        json!({"repository":{"full_name":REPOSITORY},"action":"labeled",
            "sender":{"login":"tjfontaine","type":"User"},"label":{"name":"dispatch:sol-high"},
            "issue":{"number":634,"user":{"login":"tjfontaine"},"title":"Dispatch workers!","body":"## Why\ncontext\n## Brief\nImplement it\n### Verify\nCheck it\n## Notes\nnot prompt"}})
    }
    #[test]
    fn labels_select_only_checked_in_tiers_and_extract_the_brief() {
        for (label, backend, model, effort) in [
            ("dispatch:sol-high", "codex", "gpt-6.1-sol", Some("high")),
            ("dispatch:argon-high", "agy", "argon-high", None),
            ("dispatch:opus", "agy", "opus", None),
        ] {
            let mut event = event();
            event["label"]["name"] = label.into();
            let d = validate_event(&event, TIERS, "tjfontaine").unwrap();
            assert_eq!(d.tier.backend, backend);
            assert_eq!(d.tier.model, model);
            assert_eq!(d.tier.effort.as_deref(), effort);
            assert_eq!(d.brief, "Implement it\n### Verify\nCheck it");
            assert_eq!(d.branch, "work/dispatch-634-dispatch-workers");
        }
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
    fn brief_headings_and_branch_names_are_data_not_commands() {
        assert!(brief_section("## Brief\n\n## Other\nx").is_err());
        assert!(brief_section("## Brief\nx\n## Brief\ny").is_err());
        assert_eq!(
            brief_section("## Brief\nx\n```sh\n## not a heading\necho hi\n```\n## Other\ny")
                .unwrap(),
            "x\n```sh\n## not a heading\necho hi\n```"
        );
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
        let mut value = event();
        value["issue"]["body"] = "## Brief\nBranch: work/existing-634\nRun it".into();
        assert_eq!(
            validate_event(&value, TIERS, "tjfontaine").unwrap().branch,
            "work/existing-634"
        );
    }
    #[test]
    fn structured_contract_keeps_work_status_independent_of_transport() {
        let tmp = tempfile::tempdir().unwrap();
        let result = tmp.path().join("result");
        assert!(read_contract(&result).is_err());
        for transport in ["SUCCESS", "ERROR"] {
            std::fs::write(
                &result,
                json!({"status":transport,"structured_output":{
                "status":"done","summary":"done","tests":[],"risks":[]}})
                .to_string(),
            )
            .unwrap();
            assert_eq!(read_contract(&result).unwrap().status, ContractStatus::Done);
        }
        std::fs::write(&result, r#"{"status":"ERROR","structured_output":null}"#).unwrap();
        assert!(read_contract(&result).is_err());
    }
    #[test]
    fn branch_directives_inside_fences_do_not_select_a_branch() {
        let mut value = event();
        value["issue"]["body"] =
            "## Brief\nImplement it\n```text\nBranch: work/foreign-799\n```".into();
        assert_eq!(
            validate_event(&value, TIERS, "tjfontaine").unwrap().branch,
            "work/dispatch-634-dispatch-workers"
        );
    }
    #[test]
    fn tracked_generated_files_cannot_escape_through_a_patch() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        git(root, &["init", "-b", "work/dispatch-634-dispatch-workers"]).unwrap();
        git(root, &["config", "user.name", "Fixture"]).unwrap();
        git(root, &["config", "user.email", "fixture@localhost"]).unwrap();
        git(root, &["config", "core.hooksPath", "/dev/null"]).unwrap();
        std::fs::create_dir(root.join("target")).unwrap();
        std::fs::write(root.join("target/file"), b"\0base").unwrap();
        git(root, &["add", "target/file"]).unwrap();
        git(root, &["commit", "-m", "fixture base"]).unwrap();
        git(root, &["update-ref", "refs/remotes/origin/main", "HEAD"]).unwrap();
        std::fs::write(
            root.join("target/file"),
            b"\0refresh_token=must-not-publish",
        )
        .unwrap();
        let gate = Gate::capture().unwrap();
        assert!(
            checkpoint(
                root,
                &validate_event(&event(), TIERS, "tjfontaine").unwrap(),
                &gate
            )
            .is_err()
        );
    }
    #[test]
    fn wip_checkpoint_preserves_trailer_and_excludes_target_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        git(root, &["init", "-b", "work/dispatch-634-dispatch-workers"]).unwrap();
        git(root, &["config", "user.name", "Dispatch test"]).unwrap();
        git(root, &["config", "user.email", "fixture@localhost"]).unwrap();
        // This is a standalone fixture repository, never the project's hooks.
        git(root, &["config", "core.hooksPath", "/dev/null"]).unwrap();
        std::fs::write(root.join("file"), "base").unwrap();
        git(root, &["add", "file"]).unwrap();
        git(root, &["commit", "-m", "fixture base"]).unwrap();
        git(root, &["update-ref", "refs/remotes/origin/main", "HEAD"]).unwrap();
        std::fs::remove_file(root.join("file")).unwrap();
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
