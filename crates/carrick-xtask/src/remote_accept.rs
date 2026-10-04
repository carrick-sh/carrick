use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use thiserror::Error;

use crate::accept::{self, AcceptPhase};
use crate::command::{self, CommandError};

pub const DEFAULT_HOST: &str = "rentamac@cloudmac";
pub const DEFAULT_REMOTE_ROOT: &str = "/Volumes/carrick/dev";
pub const MIN_FREE_DISK_KIB: u64 = 40 * 1024 * 1024; // 40 GiB in KiB
pub const POLL_INTERVAL: Duration = Duration::from_secs(30);
pub const MAX_CONSECUTIVE_SSH_FAILURES: u32 = 10;
pub const MAX_RECENT_GATE_RUNS: usize = 20;

pub const SUMMARY_HEADER: &str = "==================== ACCEPT GATE SUMMARY ====================";
pub const SUMMARY_FOOTER: &str = "=============================================================";

#[derive(clap::Args, Debug, Clone)]
pub struct RemoteAcceptArgs {
    #[arg(long = "ref", default_value = "HEAD", help = "Git ref to accept")]
    pub git_ref: String,

    #[arg(
        long,
        value_enum,
        default_value = "all",
        help = "Gate phase to run: host, signed, or all"
    )]
    pub phase: AcceptPhase,

    #[arg(
        long,
        help = "Remote SSH host [default: CARRICK_REMOTE_GATE_HOST or rentamac@cloudmac]"
    )]
    pub host: Option<String>,

    #[arg(
        long = "remote-root",
        help = "Remote root directory [default: CARRICK_REMOTE_GATE_ROOT or /Volumes/carrick/dev]"
    )]
    pub remote_root: Option<String>,

    #[arg(long, help = "Attach to an existing run-id and resume polling")]
    pub attach: Option<String>,

    #[arg(
        long,
        help = "Exact-SHA fixture manifest (default: unique local target/fixtures/bundles/<sha> bundle)"
    )]
    pub fixture_manifest: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub enum RemoteAcceptError {
    #[error("I/O error at '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("command error: {0}")]
    Command(#[from] CommandError),
    #[error("git error: {0}")]
    Git(String),
    #[error("working tree is dirty: {0}")]
    DirtyWorkingTree(String),
    #[error("remote SSH error on host '{host}': {details}")]
    Ssh { host: String, details: String },
    #[error("remote disk space error on host '{host}': {details}")]
    DiskSpace { host: String, details: String },
    #[error("remote worktree lock at '{lock_path}' on host '{host}' is held by run-id '{run_id}'")]
    LockHeld {
        host: String,
        run_id: String,
        lock_path: String,
    },
    #[error("invalid run-id '{0}': {1}")]
    InvalidRunId(String, String),
    #[error(
        "remote rsync path '{0}' contains characters unsupported by portable rsync argument handling"
    )]
    InvalidRsyncPath(String),
    #[error("signed fixture preparation: {0}")]
    Fixtures(#[from] crate::fixtures::FixturesError),
    #[error("signed/all remote acceptance requires an exact-SHA fixture bundle")]
    MissingFixtureBundle,
}

pub fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn resolve_host(host_opt: Option<&str>) -> String {
    if let Some(h) = host_opt {
        let trimmed = h.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(val) = std::env::var("CARRICK_REMOTE_GATE_HOST") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    DEFAULT_HOST.to_string()
}

pub fn resolve_remote_root(root_opt: Option<&str>) -> String {
    if let Some(r) = root_opt {
        let trimmed = r.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(val) = std::env::var("CARRICK_REMOTE_GATE_ROOT") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    DEFAULT_REMOTE_ROOT.to_string()
}

pub fn parse_df_available_kib(df_output: &str) -> Result<u64, String> {
    for line in df_output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Filesystem") || trimmed.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        // In POSIX `df -Pk`:
        // Filesystem 1024-blocks Used Available Capacity Mounted on
        // Available is token index 3.
        if let Some(avail) = tokens.get(3).and_then(|t| t.parse::<u64>().ok()) {
            return Ok(avail);
        }
    }
    Err(format!(
        "failed to parse available disk space from df output:\n{df_output}"
    ))
}

pub fn should_refuse_dirty(git_ref: &str, has_tracked_modifications: bool) -> bool {
    let trimmed = git_ref.trim();
    let is_head = trimmed.is_empty() || trimmed.eq_ignore_ascii_case("head") || trimmed == "@";
    is_head && has_tracked_modifications
}

pub fn generate_run_id(sha12: &str, timestamp: &str) -> String {
    format!("{sha12}-{timestamp}")
}

pub fn parse_run_id(run_id: &str) -> Result<(&str, &str), RemoteAcceptError> {
    if run_id.len() < 13 {
        return Err(RemoteAcceptError::InvalidRunId(
            run_id.to_string(),
            "run-id must be at least 13 characters (<sha12>-<timestamp>)".to_string(),
        ));
    }
    if !run_id.is_char_boundary(12) || run_id.as_bytes()[12] != b'-' {
        return Err(RemoteAcceptError::InvalidRunId(
            run_id.to_string(),
            "run-id missing '-' separator at index 12".to_string(),
        ));
    }
    let (sha12, rest) = run_id.split_at(12);
    if !sha12.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(RemoteAcceptError::InvalidRunId(
            run_id.to_string(),
            "sha12 prefix must contain only hex characters".to_string(),
        ));
    }
    let timestamp = &rest[1..];
    if timestamp.is_empty() {
        return Err(RemoteAcceptError::InvalidRunId(
            run_id.to_string(),
            "timestamp portion of run-id cannot be empty".to_string(),
        ));
    }
    Ok((sha12, timestamp))
}

pub fn local_run_dir(local_root: &Path, run_id: &str) -> PathBuf {
    local_root.join("target/remote-gate").join(run_id)
}

pub fn local_receipt_path(local_root: &Path, run_id: &str) -> PathBuf {
    local_run_dir(local_root, run_id).join("receipt.json")
}

pub fn remote_worktree_dir(remote_root: &Path) -> PathBuf {
    remote_root.join("gate-worktree")
}

pub fn remote_lock_dir(remote_root: &Path) -> PathBuf {
    remote_root.join("gate-worktree.lock")
}

pub fn remote_run_dir(remote_root: &Path, run_id: &str) -> PathBuf {
    remote_root.join("gate-runs").join(run_id)
}

pub fn remote_el1_gate_dir(worktree_dir: &Path, short_sha: &str) -> PathBuf {
    worktree_dir.join("target/el1-gate").join(short_sha)
}

pub fn build_lock_acquire_cmd(lock_dir: &str, run_id: &str) -> String {
    let q_lock = shell_quote(lock_dir);
    let q_run_id = shell_quote(run_id);
    format!(
        "if mkdir {q_lock} 2>/dev/null; then echo {q_run_id} > {q_lock}/run_id && echo LOCKED; else holder=$(cat {q_lock}/run_id 2>/dev/null || echo unknown); echo \"HELD:$holder\"; fi"
    )
}

pub fn build_lock_release_cmd(lock_dir: &str) -> String {
    let q_lock = shell_quote(lock_dir);
    format!("rm -rf {q_lock}")
}

pub fn extract_summary(log: &str) -> Option<String> {
    let start_idx = log.rfind(SUMMARY_HEADER)?;
    let slice = &log[start_idx..];
    let end_idx = slice.find(SUMMARY_FOOTER)?;
    let full_end = start_idx + end_idx + SUMMARY_FOOTER.len();
    Some(log[start_idx..full_end].to_string())
}

pub fn build_accept_job_script(
    worktree_dir: &str,
    phase: AcceptPhase,
    log_file: &str,
    exit_file: &str,
    lock_dir: &str,
    fixture_bundle: Option<&str>,
) -> Result<String, RemoteAcceptError> {
    let env_file = Path::new(worktree_dir)
        .parent()
        .unwrap_or(Path::new("."))
        .join("env.sh");
    let q_env = shell_quote(&env_file.to_string_lossy());
    let q_worktree = shell_quote(worktree_dir);
    let q_log = shell_quote(log_file);
    let q_exit = shell_quote(exit_file);
    let q_exit_tmp = shell_quote(&format!("{exit_file}.tmp"));
    let q_lock = shell_quote(lock_dir);
    let command = if phase == AcceptPhase::Host {
        format!("just accept --phase {phase}")
    } else {
        let bundle = fixture_bundle.ok_or(RemoteAcceptError::MissingFixtureBundle)?;
        // One gate lease spans restoration, accept and scoped guest cleanup.
        // The checkout lock is already held and remains held until job exit.
        let preparation = format!(
            "test -d {q_lock} && just fixtures-restore {} && just accept --phase {phase}",
            shell_quote(bundle)
        );
        format!("just lease gate sh -c {}", shell_quote(&preparation))
    };
    Ok(format!(
        "[ -f {q_env} ] && . {q_env}; cd {q_worktree} && {command} > {q_log} 2>&1; echo $? > {q_exit_tmp} && mv {q_exit_tmp} {q_exit}; rm -rf {q_lock}"
    ))
}

pub fn build_detached_start_cmd(
    worktree_dir: &str,
    phase: AcceptPhase,
    run_dir: &str,
    log_file: &str,
    exit_file: &str,
    lock_dir: &str,
    fixture_bundle: Option<&str>,
) -> Result<String, RemoteAcceptError> {
    let script = build_accept_job_script(
        worktree_dir,
        phase,
        log_file,
        exit_file,
        lock_dir,
        fixture_bundle,
    )?;
    Ok(format!(
        "mkdir -p {} && nohup sh -c {} >/dev/null 2>&1 </dev/null &",
        shell_quote(run_dir),
        shell_quote(&script)
    ))
}

pub fn build_worktree_setup_cmd(bare_repo: &str, worktree_dir: &str, full_sha: &str) -> String {
    build_worktree_setup(bare_repo, worktree_dir, full_sha, WorktreePolicy::Recreate)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorktreePolicy {
    Recreate,
    RequireClean,
}

fn build_worktree_setup(
    bare_repo: &str,
    worktree_dir: &str,
    full_sha: &str,
    policy: WorktreePolicy,
) -> String {
    let q_bare = shell_quote(bare_repo);
    let q_wt = shell_quote(worktree_dir);
    let q_sha = shell_quote(full_sha);

    let existing = match policy {
        WorktreePolicy::Recreate => format!(
            "git -C {q_wt} checkout --detach --force {q_sha} && git -C {q_wt} clean -fdx -e target -e conformance-probes/target"
        ),
        WorktreePolicy::RequireClean => format!("git -C {q_wt} checkout --detach {q_sha}"),
    };
    format!(
        "if [ ! -d {q_wt} ]; then git -C {q_bare} worktree add --detach {q_wt} {q_sha}; else {existing}; fi"
    )
}

pub fn build_prune_runs_cmd(gate_runs_dir: &str, keep_count: usize) -> String {
    let q_runs = shell_quote(gate_runs_dir);
    let skip_n = keep_count + 1;
    format!(
        "if [ -d {q_runs} ]; then ls -1dt {q_runs}/*/ 2>/dev/null | tail -n +{skip_n} | while read -r old_dir; do rm -rf \"$old_dir\"; done; fi"
    )
}

pub fn build_df_check_cmd(remote_root: &str) -> String {
    let q_root = shell_quote(remote_root);
    format!("df -Pk {q_root}")
}

pub fn build_du_worktrees_cmd(gate_worktrees_dir: &str) -> String {
    let q_wt = shell_quote(gate_worktrees_dir);
    format!("if [ -d {q_wt} ]; then du -sh {q_wt}/* 2>/dev/null | sort -hr | head -n 10; fi")
}

pub fn build_poll_cmd(exit_file: &str) -> String {
    let q_exit = shell_quote(exit_file);
    format!("if [ -f {q_exit} ]; then echo \"DONE:$(cat {q_exit})\"; else echo \"WAITING\"; fi")
}

pub fn run_ssh_command(host: &str, script: &str) -> Result<String, RemoteAcceptError> {
    let output = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            host,
            script,
        ])
        .output()
        .map_err(|e| RemoteAcceptError::Ssh {
            host: host.to_string(),
            details: format!("failed to spawn ssh: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(RemoteAcceptError::Ssh {
            host: host.to_string(),
            details: format!(
                "ssh command failed with exit {}:\nstdout:\n{stdout}\nstderr:\n{stderr}",
                output.status
            ),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn build_stale_lock_recovery_cmd(exit_file: &str, lock_dir: &str, new_run_id: &str) -> String {
    let q_exit = shell_quote(exit_file);
    let q_lock = shell_quote(lock_dir);
    let q_run_id = shell_quote(new_run_id);
    format!(
        "if [ -f {q_exit} ]; then rm -rf {q_lock} && if mkdir {q_lock} 2>/dev/null; then echo {q_run_id} > {q_lock}/run_id && echo RECOVERED; else echo RECOVERY_FAILED; fi; else echo ACTIVE; fi"
    )
}

pub fn acquire_remote_lock(
    host: &str,
    remote_root: &str,
    lock_dir: &str,
    run_id: &str,
) -> Result<(), RemoteAcceptError> {
    let cmd = build_lock_acquire_cmd(lock_dir, run_id);
    let output = run_ssh_command(host, &cmd)?;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed == "LOCKED" {
            return Ok(());
        }
        if let Some(holder) = trimmed.strip_prefix("HELD:") {
            let holder = holder.trim();
            let holder_str = if holder.is_empty() { "unknown" } else { holder };

            // Stale lock recovery: when acquisition finds the lock held, read its run_id.
            // If <remote_root>/gate-runs/<run_id>/exit exists, the holder finished without releasing,
            // so remove the lock and acquire it (print a notice). Otherwise fail with LockHeld as today.
            let holder_exit = format!("{remote_root}/gate-runs/{holder_str}/exit");
            let stale_cmd = build_stale_lock_recovery_cmd(&holder_exit, lock_dir, run_id);
            let recovery_out = run_ssh_command(host, &stale_cmd)?;
            if recovery_out.lines().any(|l| l.trim() == "RECOVERED") {
                println!(
                    "Notice: stale worktree lock held by finished run '{holder_str}' recovered (lock removed and re-acquired)"
                );
                return Ok(());
            }

            return Err(RemoteAcceptError::LockHeld {
                host: host.to_string(),
                run_id: holder_str.to_string(),
                lock_path: lock_dir.to_string(),
            });
        }
    }
    Err(RemoteAcceptError::Ssh {
        host: host.to_string(),
        details: format!("unexpected output when acquiring lock {lock_dir}: {output}"),
    })
}

pub struct RemoteLockGuard<'a> {
    host: &'a str,
    lock_dir: String,
    active: bool,
}

impl<'a> RemoteLockGuard<'a> {
    pub fn new(host: &'a str, lock_dir: String) -> Self {
        Self {
            host,
            lock_dir,
            active: true,
        }
    }

    pub fn disarm(&mut self) {
        self.active = false;
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn release(&mut self) {
        if self.active {
            let cmd = build_lock_release_cmd(&self.lock_dir);
            if let Err(e) = run_ssh_command(self.host, &cmd) {
                eprintln!(
                    "Warning: failed to release remote worktree lock {}: {e}",
                    self.lock_dir
                );
            }
            self.active = false;
        }
    }
}

impl<'a> Drop for RemoteLockGuard<'a> {
    fn drop(&mut self) {
        self.release();
    }
}

pub fn create_lock_guard_for_run<'a>(
    host: &'a str,
    lock_dir: String,
    attach: Option<&str>,
) -> Option<RemoteLockGuard<'a>> {
    if attach.is_some() {
        None
    } else {
        Some(RemoteLockGuard::new(host, lock_dir))
    }
}

pub fn resolve_short_sha_for_receipt(
    host: &str,
    worktree_dir: &str,
    sha12: &str,
    local_root: Option<&Path>,
) -> String {
    let remote_cmd = format!(
        "git -C {} rev-parse --short {}",
        shell_quote(worktree_dir),
        shell_quote(sha12)
    );
    if let Ok(out) = run_ssh_command(host, &remote_cmd) {
        let trimmed = out.trim();
        if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return trimmed.to_string();
        }
    }
    if let Some(out) = local_root.and_then(|root| {
        command::run_checked("git", ["rev-parse", "--short", sha12], Some(root)).ok()
    }) {
        let trimmed = out.stdout.trim();
        if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return trimmed.to_string();
        }
    }
    sha12[..9.min(sha12.len())].to_string()
}

fn rsync_remote_spec(host: &str, path: &str) -> Result<String, RemoteAcceptError> {
    // GNU rsync protects shell-active characters, but rsync 2.6.9/openrsync
    // splits remote arguments in the shell. Use their common safe subset;
    // embedded quoting would instead become literal filename bytes on GNU.
    if path.is_empty()
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-:@%+=,".contains(&b))
    {
        return Err(RemoteAcceptError::InvalidRsyncPath(path.to_string()));
    }
    Ok(format!("{host}:{path}"))
}

fn rsync_args(source: &str, destination: &str) -> [String; 6] {
    [
        "-avz".to_string(),
        "-e".to_string(),
        "ssh -o BatchMode=yes -o ConnectTimeout=10".to_string(),
        "--".to_string(),
        source.to_string(),
        destination.to_string(),
    ]
}

fn copy_fixture_bundle(
    local_root: &Path,
    host: &str,
    run_dir: &str,
    sha: &str,
    manifest: Option<&Path>,
) -> Result<String, RemoteAcceptError> {
    let manifest = crate::fixtures::resolve_bundle(local_root, sha, manifest)?;
    let artifact =
        crate::fixtures::archive::pack(&manifest, &local_root.join("target/fixtures/published"))?;
    crate::fixtures::archive::verify(&artifact, sha)?;
    let destination = format!("{run_dir}/fixtures");
    run_ssh_command(host, &format!("mkdir -p {}", shell_quote(&destination)))?;
    let filename = artifact
        .file_name()
        .ok_or(RemoteAcceptError::MissingFixtureBundle)?
        .to_string_lossy();
    let remote_artifact = format!("{destination}/{filename}");
    let remote_spec = rsync_remote_spec(host, &remote_artifact)?;
    command::run_checked(
        "rsync",
        rsync_args(&artifact.to_string_lossy(), &remote_spec),
        None,
    )?;
    Ok(remote_artifact)
}

pub(crate) fn check_remote_disk_space(
    host: &str,
    remote_root: &str,
) -> Result<(), RemoteAcceptError> {
    let df_cmd = build_df_check_cmd(remote_root);
    let df_output = run_ssh_command(host, &df_cmd)?;
    let avail_kib =
        parse_df_available_kib(&df_output).map_err(|e| RemoteAcceptError::DiskSpace {
            host: host.to_string(),
            details: e,
        })?;

    if avail_kib < MIN_FREE_DISK_KIB {
        let avail_gib = avail_kib as f64 / (1024.0 * 1024.0);
        let gate_worktrees_dir = format!("{remote_root}/gate-worktrees");
        let du_cmd = build_du_worktrees_cmd(&gate_worktrees_dir);
        let du_output = run_ssh_command(host, &du_cmd)
            .unwrap_or_else(|_| "<failed to query gate-worktrees directories>".to_string());

        let msg = format!(
            "remote free space ({avail_gib:.1} GiB) is below 40 GiB on {remote_root}\nLargest gate-worktrees directories:\n{du_output}"
        );
        eprintln!("{msg}");
        return Err(RemoteAcceptError::DiskSpace {
            host: host.to_string(),
            details: msg,
        });
    }

    Ok(())
}

/// Called only while holding the remote checkout lock. Both remote workflows
/// transport commits through the same gate ref namespace and persistent tree.
pub(crate) fn prepare_remote_worktree(
    local_root: &Path,
    host: &str,
    remote_root: &str,
    full_sha: &str,
    policy: WorktreePolicy,
) -> Result<String, RemoteAcceptError> {
    let worktree = remote_worktree_dir(Path::new(remote_root))
        .to_string_lossy()
        .into_owned();
    if policy == WorktreePolicy::RequireClean {
        let status = run_ssh_command(host, &build_worktree_clean_check_cmd(&worktree))?;
        if !status.trim().is_empty() {
            return Err(RemoteAcceptError::DirtyWorkingTree(status));
        }
    }
    let push_target = if host == DEFAULT_HOST && remote_root == DEFAULT_REMOTE_ROOT {
        let remotes = command::run_checked("git", ["remote"], Some(local_root))?;
        if remotes.stdout.lines().any(|l| l.trim() == "cloudmac") {
            "cloudmac".to_string()
        } else {
            format!("{host}:{remote_root}/carrick.git")
        }
    } else {
        format!("{host}:{remote_root}/carrick.git")
    };
    let refspec = format!("{full_sha}:refs/heads/gate/{}", &full_sha[..12]);
    println!("Pushing {full_sha} to {push_target} as {refspec}...");
    command::run_checked("git", ["push", &push_target, &refspec], Some(local_root))?;
    let setup = build_worktree_setup(
        &format!("{remote_root}/carrick.git"),
        &worktree,
        full_sha,
        policy,
    );
    run_ssh_command(host, &setup)?;
    let actual = run_ssh_command(
        host,
        &format!("git -C {} rev-parse HEAD", shell_quote(&worktree)),
    )?;
    if actual.trim() != full_sha {
        return Err(RemoteAcceptError::Git(format!(
            "remote HEAD {} does not match requested {full_sha}",
            actual.trim()
        )));
    }
    Ok(worktree)
}

pub(crate) fn build_worktree_clean_check_cmd(worktree: &str) -> String {
    let q_wt = shell_quote(worktree);
    format!("if [ -d {q_wt} ]; then git -C {q_wt} status --porcelain --untracked-files=all; fi")
}

pub fn run(root_opt: Option<&Path>, args: RemoteAcceptArgs) -> Result<i32, RemoteAcceptError> {
    let local_root = match root_opt {
        Some(r) => r.to_path_buf(),
        None => {
            let info = crate::cli::resolve_repo_info(None)
                .map_err(|e| RemoteAcceptError::Git(e.to_string()))?;
            info.repository_root
        }
    };

    let host = resolve_host(args.host.as_deref());
    let remote_root = resolve_remote_root(args.remote_root.as_deref());
    let remote_root_path = Path::new(&remote_root);
    let worktree_dir = remote_worktree_dir(remote_root_path)
        .to_string_lossy()
        .to_string();
    let lock_dir = remote_lock_dir(remote_root_path)
        .to_string_lossy()
        .to_string();

    let (run_id, sha12) = if let Some(existing_run_id) = &args.attach {
        let (parsed_sha, _) = parse_run_id(existing_run_id)?;
        println!("Attaching to remote run: {existing_run_id}");
        (existing_run_id.clone(), parsed_sha.to_string())
    } else {
        // Step 1: Resolve the ref to a full SHA locally. Refuse if local tracked tree is dirty AND ref is HEAD.
        let full_sha_out =
            command::run_checked("git", ["rev-parse", &args.git_ref], Some(&local_root))?;
        let full_sha = full_sha_out.stdout.trim().to_string();
        if full_sha.len() < 12 {
            return Err(RemoteAcceptError::Git(format!(
                "resolved SHA is too short: {full_sha}"
            )));
        }
        let sha12 = full_sha[..12].to_string();

        let status_out = command::run_checked("git", ["status", "--porcelain"], Some(&local_root))?;
        let (_clean, has_tracked) = accept::check_git_status(&status_out.stdout);
        if should_refuse_dirty(&args.git_ref, has_tracked) {
            return Err(RemoteAcceptError::DirtyWorkingTree(
                "local working tree has uncommitted tracked changes; accept receipt must belong to a commit"
                    .to_string(),
            ));
        }

        // Step 8: Check remote free space on remote volume (df). Refuse below 40 GiB free.
        check_remote_disk_space(&host, &remote_root)?;

        let timestamp = accept::generate_timestamp();
        let run_id = generate_run_id(&sha12, &timestamp);

        // Exclusive lock on remote worktree
        acquire_remote_lock(&host, &remote_root, &lock_dir, &run_id)?;
        let mut lock_guard = RemoteLockGuard::new(&host, lock_dir.clone());

        prepare_remote_worktree(
            &local_root,
            &host,
            &remote_root,
            &full_sha,
            WorktreePolicy::Recreate,
        )?;

        let run_dir = format!("{remote_root}/gate-runs/{run_id}");
        let bundle = if args.phase == AcceptPhase::Host {
            None
        } else {
            println!("Transferring exact-SHA fixture bundle...");
            Some(copy_fixture_bundle(
                &local_root,
                &host,
                &run_dir,
                &full_sha,
                args.fixture_manifest.as_deref(),
            )?)
        };

        // Step 4: Start detached accept gate on remote
        println!("run-id: {run_id}");

        let log_file = format!("{run_dir}/accept.log");
        let exit_file = format!("{run_dir}/exit");
        let start_cmd = build_detached_start_cmd(
            &worktree_dir,
            args.phase,
            &run_dir,
            &log_file,
            &exit_file,
            &lock_dir,
            bundle.as_deref(),
        )?;

        println!("Starting detached accept gate on {host}...");
        run_ssh_command(&host, &start_cmd)?;

        // The remote detached job now owns removing the lock when it finishes.
        // Disarm the local guard so it never removes the lock on drop.
        lock_guard.disarm();

        (run_id, sha12)
    };

    let gate_runs_dir = format!("{remote_root}/gate-runs");
    let remote_run_dir_path = format!("{gate_runs_dir}/{run_id}");
    let remote_exit_file = format!("{remote_run_dir_path}/exit");
    let poll_cmd = build_poll_cmd(&remote_exit_file);

    // Step 5: Poll every 30 s over short ssh calls until exit file exists
    println!("Polling remote accept execution (run-id: {run_id})...");
    let mut consecutive_ssh_failures = 0;
    let poll_start = Instant::now();

    let exit_code = loop {
        match run_ssh_command(&host, &poll_cmd) {
            Ok(output) => {
                consecutive_ssh_failures = 0;
                let trimmed = output.trim();
                if let Some(rest) = trimmed.strip_prefix("DONE:") {
                    let code_str = rest.trim();
                    let code = code_str.parse::<i32>().unwrap_or_else(|_| {
                        eprintln!(
                            "Warning: could not parse exit code '{code_str}', defaulting to 1"
                        );
                        1
                    });
                    println!(
                        "Remote accept finished with exit code {code} ({:.1}s)",
                        poll_start.elapsed().as_secs_f64()
                    );
                    break code;
                }
            }
            Err(err) => {
                consecutive_ssh_failures += 1;
                eprintln!(
                    "Warning: ssh poll error ({consecutive_ssh_failures}/{MAX_CONSECUTIVE_SSH_FAILURES}): {err}"
                );
                if consecutive_ssh_failures >= MAX_CONSECUTIVE_SSH_FAILURES {
                    return Err(RemoteAcceptError::Ssh {
                        host: host.clone(),
                        details: format!(
                            "failed after {MAX_CONSECUTIVE_SSH_FAILURES} consecutive ssh failures: {err}"
                        ),
                    });
                }
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    };

    // Step 6: Rsync receipt dir and accept.log back to local target/remote-gate/<run-id>/
    let local_dest = local_run_dir(&local_root, &run_id);
    fs::create_dir_all(&local_dest).map_err(|e| RemoteAcceptError::Io {
        path: local_dest.clone(),
        source: e,
    })?;

    // Copy only target/el1-gate/<short_sha>/ for THIS sha
    let short_sha = resolve_short_sha_for_receipt(&host, &worktree_dir, &sha12, Some(&local_root));
    let remote_receipt_src = format!("{worktree_dir}/target/el1-gate/{short_sha}/");
    let local_receipt_dest = format!("{}/", local_dest.display());
    let remote_receipt_spec = rsync_remote_spec(&host, &remote_receipt_src)?;
    let remote_log_src = format!("{remote_run_dir_path}/accept.log");
    let remote_log_spec = rsync_remote_spec(&host, &remote_log_src)?;
    let local_log_dest = local_dest.join("accept.log");

    // Attempt both transfers so a missing receipt still lets us fetch the log.
    // Report every failure before reading local files, which may be stale on attach.
    let mut fetch_errors = Vec::new();
    for (label, source, destination) in [
        ("receipt", remote_receipt_spec, local_receipt_dest),
        (
            "accept.log",
            remote_log_spec,
            local_log_dest.to_string_lossy().into_owned(),
        ),
    ] {
        if let Err(e) = command::run_checked("rsync", rsync_args(&source, &destination), None) {
            fetch_errors.push(format!("failed to fetch {label} from {source}: {e}"));
        }
    }
    if !fetch_errors.is_empty() {
        return Err(RemoteAcceptError::Ssh {
            host: host.clone(),
            details: fetch_errors.join("\n"),
        });
    }

    let mut exit_code = exit_code;
    if let Ok(log_content) = fs::read_to_string(&local_log_dest) {
        if let Some(summary) = extract_summary(&log_content) {
            println!("\n{summary}");
        } else {
            eprintln!("Warning: no ACCEPT GATE SUMMARY block found in accept.log");
            let lines: Vec<&str> = log_content.lines().collect();
            let start = lines.len().saturating_sub(40);
            for line in &lines[start..] {
                eprintln!("{line}");
            }
            if exit_code == 0 {
                exit_code = 1;
            }
        }
    } else {
        eprintln!(
            "Warning: could not read local accept.log at {}",
            local_log_dest.display()
        );
        if exit_code == 0 {
            exit_code = 1;
        }
    }

    let local_receipt = local_receipt_path(&local_root, &run_id);
    if local_receipt.is_file() {
        println!("Local receipt path: {}", local_receipt.display());
    } else {
        eprintln!("Warning: receipt missing at {}", local_receipt.display());
        exit_code = 1;
    }

    let prune_cmd = build_prune_runs_cmd(&gate_runs_dir, MAX_RECENT_GATE_RUNS);
    if let Err(e) = run_ssh_command(&host, &prune_cmd) {
        eprintln!("Warning: failed to prune old gate-runs: {e}");
    }

    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsync_fetch_argv_has_raw_remote_spec_and_option_terminator() {
        for (path, expected) in [
            (
                "/Volumes/carrick/dev/gate-worktree/target/el1-gate/012345678/",
                "rentamac@cloudmac:/Volumes/carrick/dev/gate-worktree/target/el1-gate/012345678/",
            ),
            (
                "/Volumes/carrick/dev/gate-runs/0123456789ab-20261004-120000/accept.log",
                "rentamac@cloudmac:/Volumes/carrick/dev/gate-runs/0123456789ab-20261004-120000/accept.log",
            ),
        ] {
            let spec = rsync_remote_spec("rentamac@cloudmac", path).expect("safe remote path");
            assert_eq!(spec, expected);
            assert_eq!(
                rsync_args(&spec, "/local workspace/result/").as_slice(),
                [
                    "-avz",
                    "-e",
                    "ssh -o BatchMode=yes -o ConnectTimeout=10",
                    "--",
                    expected,
                    "/local workspace/result/",
                ]
            );
        }
    }

    #[test]
    fn rsync_probe_upload_argv_preserves_trailing_slash() {
        let spec = rsync_remote_spec(
            "cloudmac",
            "/Volumes/carrick/dev/gate-worktree/conformance-probes/target/aarch64-unknown-linux-musl/release/",
        )
        .expect("safe remote path");
        assert_eq!(
            rsync_args("/local probes/release/", &spec).as_slice(),
            [
                "-avz",
                "-e",
                "ssh -o BatchMode=yes -o ConnectTimeout=10",
                "--",
                "/local probes/release/",
                "cloudmac:/Volumes/carrick/dev/gate-worktree/conformance-probes/target/aarch64-unknown-linux-musl/release/",
            ]
        );
    }

    #[test]
    fn rsync_remote_spec_refuses_shell_active_paths() {
        for path in [
            "",
            "/remote/with spaces/",
            "/remote/with\tseparator/",
            "/remote/with\nnewline/",
            "/remote/'quoted'/",
            "/remote/\"quoted\"/",
            "/remote/$variable/",
            "/remote/`command`/",
            "/remote/$(command)/",
            "/remote/semicolon;command/",
            "/remote/ampersand&command/",
            "/remote/pipe|command/",
            "/remote/glob*/",
            "/remote/question?/",
            "/remote/[pattern]/",
            "/remote/{a,b}/",
            "/remote/back\\slash/",
        ] {
            assert!(
                rsync_remote_spec("cloudmac", path).is_err(),
                "unsafe remote path accepted: {path:?}"
            );
        }
    }

    #[test]
    fn test_shell_quoting() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("simple"), "'simple'");
        assert_eq!(
            shell_quote("/Volumes/carrick/dev"),
            "'/Volumes/carrick/dev'"
        );
        assert_eq!(
            shell_quote("/Volumes/carrick/dev with spaces"),
            "'/Volumes/carrick/dev with spaces'"
        );
        assert_eq!(
            shell_quote("/Volumes/carrick/dev's test"),
            "'/Volumes/carrick/dev'\\''s test'"
        );
        assert_eq!(
            shell_quote("var=\"$FOO\" && rm -rf /"),
            "'var=\"$FOO\" && rm -rf /'"
        );
    }

    #[test]
    fn test_remote_command_construction() {
        let worktree = "/Volumes/carrick/work tree with spaces";
        let run_dir = "/Volumes/carrick/gate runs/123";
        let log_file = "/Volumes/carrick/gate runs/123/accept.log";
        let exit_file = "/Volumes/carrick/gate runs/123/exit";
        let lock_dir = "/Volumes/carrick/gate-worktree.lock";

        let start_cmd = build_detached_start_cmd(
            worktree,
            AcceptPhase::Host,
            run_dir,
            log_file,
            exit_file,
            lock_dir,
            None,
        )
        .unwrap();

        assert!(start_cmd.starts_with("mkdir -p '/Volumes/carrick/gate runs/123' && nohup sh -c "));
        assert!(start_cmd.ends_with(" >/dev/null 2>&1 </dev/null &"));
        let script = build_accept_job_script(
            worktree,
            AcceptPhase::Host,
            log_file,
            exit_file,
            lock_dir,
            None,
        )
        .unwrap();
        assert!(start_cmd.contains(&shell_quote(&script)));
        let start_cmd = script;
        assert!(start_cmd.contains("cd '/Volumes/carrick/work tree with spaces'"));
        assert!(start_cmd.contains("just accept --phase host"));
        assert!(!start_cmd.contains("--profile"));
        assert!(start_cmd.contains("> '/Volumes/carrick/gate runs/123/accept.log' 2>&1"));
        assert!(start_cmd.contains(
            "mv '/Volumes/carrick/gate runs/123/exit.tmp' '/Volumes/carrick/gate runs/123/exit'"
        ));
        assert!(start_cmd.contains("; rm -rf '/Volumes/carrick/gate-worktree.lock'"));
        let mv_idx = start_cmd
            .find("mv '/Volumes/carrick/gate runs/123/exit.tmp' '/Volumes/carrick/gate runs/123/exit'")
            .expect("mv in start_cmd");
        let rm_idx = start_cmd
            .find("rm -rf '/Volumes/carrick/gate-worktree.lock'")
            .expect("rm lock in start_cmd");
        assert!(
            mv_idx < rm_idx,
            "lock removal must occur after exit-file move"
        );

        let bare = "/Volumes/carrick/bare repo.git";
        let wt = "/Volumes/carrick/gate-worktree";
        let setup_cmd = build_worktree_setup_cmd(bare, wt, "abcdef1234567890");
        assert_eq!(
            setup_cmd,
            "if [ ! -d '/Volumes/carrick/gate-worktree' ]; then git -C '/Volumes/carrick/bare repo.git' worktree add --detach '/Volumes/carrick/gate-worktree' 'abcdef1234567890'; else git -C '/Volumes/carrick/gate-worktree' checkout --detach --force 'abcdef1234567890' && git -C '/Volumes/carrick/gate-worktree' clean -fdx -e target -e conformance-probes/target; fi"
        );

        let lock_cmd = build_lock_acquire_cmd("/Volumes/carrick/gate-worktree.lock", "run-123");
        assert!(lock_cmd.contains("mkdir '/Volumes/carrick/gate-worktree.lock'"));
        assert!(lock_cmd.contains("echo 'run-123' > '/Volumes/carrick/gate-worktree.lock'/run_id"));
        assert!(lock_cmd.contains("echo LOCKED"));
        assert!(lock_cmd.contains("echo \"HELD:$holder\""));

        let release_cmd = build_lock_release_cmd("/Volumes/carrick/gate-worktree.lock");
        assert_eq!(release_cmd, "rm -rf '/Volumes/carrick/gate-worktree.lock'");

        let prune_cmd = build_prune_runs_cmd("/Volumes/carrick/runs with spaces", 20);
        assert!(prune_cmd.contains("ls -1dt '/Volumes/carrick/runs with spaces'/*/"));
        assert!(prune_cmd.contains("tail -n +21"));

        let df_cmd = build_df_check_cmd("/Volumes/carrick/dev with spaces");
        assert_eq!(df_cmd, "df -Pk '/Volumes/carrick/dev with spaces'");

        let du_cmd = build_du_worktrees_cmd("/Volumes/carrick/worktrees with spaces");
        assert!(du_cmd.contains("du -sh '/Volumes/carrick/worktrees with spaces'/*"));

        let poll_cmd = build_poll_cmd("/Volumes/carrick/runs/exit with spaces");
        assert!(poll_cmd.contains("if [ -f '/Volumes/carrick/runs/exit with spaces' ]; then"));
    }

    #[test]
    fn test_run_id_format() {
        let sha12 = "a1b2c3d4e5f6";
        let timestamp = "20261003-120000";
        let run_id = generate_run_id(sha12, timestamp);
        assert_eq!(run_id, "a1b2c3d4e5f6-20261003-120000");

        let (parsed_sha, parsed_ts) = parse_run_id(&run_id).expect("valid run-id");
        assert_eq!(parsed_sha, sha12);
        assert_eq!(parsed_ts, timestamp);

        // Valid ISO timestamp variant
        let iso_run_id = "0123456789ab-20261003T120000Z";
        let (iso_sha, iso_ts) = parse_run_id(iso_run_id).expect("valid iso run-id");
        assert_eq!(iso_sha, "0123456789ab");
        assert_eq!(iso_ts, "20261003T120000Z");

        // Invalid: too short
        assert!(parse_run_id("short").is_err());
        // Invalid: missing separator
        assert!(parse_run_id("0123456789ab_20261003").is_err());
        // Invalid: non-hex sha
        assert!(parse_run_id("0123456789zz-20261003").is_err());
        // Invalid: empty timestamp
        assert!(parse_run_id("0123456789ab-").is_err());
    }

    #[test]
    fn test_receipt_path_mapping() {
        let local_root = Path::new("/workspace/carrick with spaces");
        let run_id = "0123456789ab-20261003-120000";

        let local_dir = local_run_dir(local_root, run_id);
        assert_eq!(
            local_dir,
            PathBuf::from(
                "/workspace/carrick with spaces/target/remote-gate/0123456789ab-20261003-120000"
            )
        );

        let local_receipt = local_receipt_path(local_root, run_id);
        assert_eq!(
            local_receipt,
            PathBuf::from(
                "/workspace/carrick with spaces/target/remote-gate/0123456789ab-20261003-120000/receipt.json"
            )
        );

        let remote_root = Path::new("/Volumes/carrick/dev with spaces");
        let remote_wt = remote_worktree_dir(remote_root);
        assert_eq!(
            remote_wt,
            PathBuf::from("/Volumes/carrick/dev with spaces/gate-worktree")
        );

        let remote_lock = remote_lock_dir(remote_root);
        assert_eq!(
            remote_lock,
            PathBuf::from("/Volumes/carrick/dev with spaces/gate-worktree.lock")
        );

        let remote_run = remote_run_dir(remote_root, run_id);
        assert_eq!(
            remote_run,
            PathBuf::from(
                "/Volumes/carrick/dev with spaces/gate-runs/0123456789ab-20261003-120000"
            )
        );

        let el1_gate = remote_el1_gate_dir(&remote_wt, "0123456789ab");
        assert_eq!(
            el1_gate,
            PathBuf::from(
                "/Volumes/carrick/dev with spaces/gate-worktree/target/el1-gate/0123456789ab"
            )
        );
    }

    #[test]
    fn test_lock_held_error() {
        let err = RemoteAcceptError::LockHeld {
            host: "rentamac@cloudmac".to_string(),
            run_id: "0123456789ab-20261003-120000".to_string(),
            lock_path: "/Volumes/carrick/dev/gate-worktree.lock".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("0123456789ab-20261003-120000"));
        assert!(msg.contains("rentamac@cloudmac"));
        assert!(msg.contains("/Volumes/carrick/dev/gate-worktree.lock"));
    }

    #[test]
    fn test_dirty_tree_refusal() {
        // Refuse if ref is HEAD and has tracked modifications
        assert!(should_refuse_dirty("HEAD", true));
        assert!(should_refuse_dirty("head", true));
        assert!(should_refuse_dirty("@", true));
        assert!(should_refuse_dirty("", true));

        // Allow if ref is HEAD and has clean tracked tree
        assert!(!should_refuse_dirty("HEAD", false));
        assert!(!should_refuse_dirty("head", false));
        assert!(!should_refuse_dirty("@", false));
        assert!(!should_refuse_dirty("", false));

        // Allow non-HEAD refs even if working tree has tracked modifications
        assert!(!should_refuse_dirty("main", true));
        assert!(!should_refuse_dirty("feature/test", true));
        assert!(!should_refuse_dirty("0123456789abcdef", true));
        assert!(!should_refuse_dirty("main", false));
    }

    #[test]
    fn test_summary_extraction() {
        let sample_log = r#"
Compiling something...
Running tests...
==================== ACCEPT GATE SUMMARY ====================
Phase:        host
Profile:      no-docker
Timestamp:    20261003-120000
Git HEAD:     0123456789abcdef
Working Tree: Clean
Overall:      PASS

Steps:
  [PASS] test-kernel (1.20s)
  [PASS] test (5.40s)

Receipt written to: target/el1-gate/0123456789ab/receipt.json
=============================================================
Done with exit 0.
"#;

        let extracted = extract_summary(sample_log).expect("summary extracted");
        assert!(extracted.starts_with(SUMMARY_HEADER));
        assert!(extracted.ends_with(SUMMARY_FOOTER));
        assert!(extracted.contains("Overall:      PASS"));
        assert!(
            extracted.contains("Receipt written to: target/el1-gate/0123456789ab/receipt.json")
        );

        let log_without_summary = "Compiling... done with error.";
        assert!(extract_summary(log_without_summary).is_none());

        // Test with multiple blocks: should extract the last block
        let multi_log = format!(
            "First block:\n{}\nMiddle\n{}",
            sample_log.replace("PASS", "FAIL"),
            sample_log
        );
        let extracted_multi = extract_summary(&multi_log).expect("summary extracted");
        assert!(extracted_multi.contains("Overall:      PASS"));
    }

    #[test]
    fn test_parse_df_output() {
        let sample_df = "\
Filesystem     1024-blocks    Used Available Capacity Mounted on
/dev/disk5s1     244234200 5745076 238489124       3% /Volumes/carrick
";
        let avail = parse_df_available_kib(sample_df).expect("parse df output");
        assert_eq!(avail, 238489124);

        // Too few columns
        let bad_df = "Filesystem\nfoo bar";
        assert!(parse_df_available_kib(bad_df).is_err());
    }

    #[test]
    fn test_host_and_remote_root_resolution() {
        assert_eq!(resolve_host(None), DEFAULT_HOST);
        assert_eq!(resolve_host(Some("custom@host")), "custom@host");
        assert_eq!(resolve_host(Some("   ")), DEFAULT_HOST);

        assert_eq!(resolve_remote_root(None), DEFAULT_REMOTE_ROOT);
        assert_eq!(resolve_remote_root(Some("/custom/root")), "/custom/root");
        assert_eq!(resolve_remote_root(Some("   ")), DEFAULT_REMOTE_ROOT);
    }

    #[test]
    fn test_attach_path_constructs_no_guard() {
        let guard_attach = create_lock_guard_for_run(
            "rentamac@cloudmac",
            "/Volumes/carrick/dev/gate-worktree.lock".to_string(),
            Some("0123456789ab-20261003-120000"),
        );
        assert!(
            guard_attach.is_none(),
            "attach path must construct no guard"
        );

        let guard_fresh = create_lock_guard_for_run(
            "rentamac@cloudmac",
            "/Volumes/carrick/dev/gate-worktree.lock".to_string(),
            None,
        );
        assert!(guard_fresh.is_some(), "fresh path must construct a guard");
        let mut g = guard_fresh.unwrap();
        assert!(g.is_active());
        g.disarm();
        assert!(!g.is_active());
    }

    #[test]
    fn test_stale_lock_branch_command_text() {
        let exit_file = "/Volumes/carrick/dev/gate-runs/0123456789ab-20261003-120000/exit";
        let lock_dir = "/Volumes/carrick/dev/gate-worktree.lock";
        let new_run_id = "cdef01234567-20261003-130000";

        let cmd = build_stale_lock_recovery_cmd(exit_file, lock_dir, new_run_id);
        assert!(cmd.starts_with(
            "if [ -f '/Volumes/carrick/dev/gate-runs/0123456789ab-20261003-120000/exit' ]; then"
        ));
        assert!(cmd.contains("rm -rf '/Volumes/carrick/dev/gate-worktree.lock'"));
        assert!(cmd.contains("mkdir '/Volumes/carrick/dev/gate-worktree.lock'"));
        assert!(cmd.contains(
            "echo 'cdef01234567-20261003-130000' > '/Volumes/carrick/dev/gate-worktree.lock'/run_id"
        ));
        assert!(cmd.contains("echo RECOVERED"));
        assert!(cmd.contains("echo ACTIVE"));
    }
}
