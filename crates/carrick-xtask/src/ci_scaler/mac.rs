//! cloudmac HVF JIT runners.
//!
//! `mac-jit` runs on the director's Mac, where `gh` holds the GitHub
//! credential. For each queued `kernel-runtime.yml` job with exactly
//! [`HVF_LABELS`] in a run [`Admission::Standing`] serves, it mints one JIT
//! config and feeds it over SSH stdin to `mac-run-once` on cloudmac. Only that
//! one-use JIT material crosses to cloudmac; nothing is written there by the
//! controller except through `mac-run-once`, which never stores the JIT.
//!
//! `mac-run-once` runs as root through one fixed sudoers entry. It verifies
//! the root-owned runner tree against a manifest pinned by the controller,
//! writes a root-owned policy bound to the one vetted run, and starts the
//! runner as the unprivileged runner user in a fresh session with the shared
//! job-start hook (`scripts/ci/admit-job.sh`). A rejected job kills that whole
//! session before any workflow step, exactly as on Willow clones. The JIT
//! config reaches the runner only through `ACTIONS_RUNNER_INPUT_JITCONFIG`.
use super::github::Github;
use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};

const NAME_PREFIX: &str = "carrick-hvf-";
/// Root-owned xtask on cloudmac; the only binary in the sudoers entry.
pub const REMOTE_XTASK: &str = "/Volumes/carrick-build/carrick-ci/bin/carrick-xtask";
/// Root-owned runner tree (`_work` and `_diag` belong to the runner user).
pub const RUNNER_DIR: &str = "/Volumes/carrick-build/actions-runner";
/// Root-owned per-runner state root.
pub const STATE_ROOT: &str = "/Volumes/carrick-build/carrick-ci/run";
/// Root-owned runner-tree manifest; its SHA-256 is pinned by the controller.
pub const MANIFEST: &str = "/Volumes/carrick-build/carrick-ci/runner-manifest.txt";
/// The unprivileged account jobs run as.
pub const RUN_USER: &str = "carrick-ci";
/// The job home, recreated from [`SKELETON`] before every job.
pub const JOB_HOME: &str = "/Volumes/carrick-build/carrick-ci/job-home";
/// Root-owned skeleton for [`JOB_HOME`] (dotfiles only; no toolchains).
pub const SKELETON: &str = "/Volumes/carrick-build/carrick-ci/skel";
/// Root-owned, read-only toolchain: `rustup/` (RUSTUP_HOME) and `cargo/bin`.
pub const TOOLCHAIN: &str = "/Volumes/carrick-build/carrick-ci/toolchain";
/// macOS cron and at deny lists; both must name [`RUN_USER`].
const SCHEDULER_DENY: [&str; 2] = ["/usr/lib/cron/cron.deny", "/usr/lib/cron/at.deny"];
/// Runner-tree entries the runner user writes; excluded from the manifest.
const RUNNER_WRITABLE: [&str; 2] = ["_work", "_diag"];
/// Literal hook command in `scripts/ci/admit-job.sh` (the Willow guest path).
const HOOK_COMMAND: &str = "/usr/local/bin/carrick-xtask ci-scaler admit-job";
/// A launched runner that has received no job by then is drained.
const UNASSIGNED_DRAIN_SECS: u64 = 900;
/// Upper bound for one SSH-held runner lifecycle (hvf-kernel times out at 180m).
const LAUNCH_LIMIT: Duration = Duration::from_secs(5 * 3600);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacState {
    /// Written before the JIT request; a crash here may leave a registration.
    Registering,
    /// JIT minted and handed to `mac-run-once`.
    Launched,
    /// Drained under the job-start hook's flock; no job can start any more.
    Draining,
    /// Registration removed; the ledger keeps the row for job deduplication.
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacRecord {
    pub key: JobKey,
    pub name: String,
    pub created: u64,
    pub state: MacState,
    pub runner: Option<RunnerId>,
    pub assigned: Option<JobId>,
}
impl RunnerRegistration for MacRecord {
    fn key(&self) -> JobKey {
        self.key
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn runner(&self) -> Option<RunnerId> {
        self.runner
    }
    fn set_runner(&mut self, runner: Option<RunnerId>) {
        self.runner = runner;
    }
    fn assigned(&self) -> Option<JobId> {
        self.assigned
    }
    fn set_assigned(&mut self, job: JobId) {
        self.assigned = Some(job);
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MacLedger {
    pub rows: Vec<MacRecord>,
}
impl MacLedger {
    /// One cloudmac runner at a time. A job key is re-served only when its
    /// earlier runners closed without running it (see [`Ledger::served`]).
    pub fn reserve(&mut self, key: JobKey, now: u64) -> Result<MacRecord, ScalerError> {
        if self.served(key) {
            return Err(ScalerError::Guard("job already reserved"));
        }
        if self.rows.iter().any(|r| r.state != MacState::Done) {
            return Err(ScalerError::Guard("cloudmac runner budget occupied"));
        }
        let row = MacRecord {
            key,
            name: format!(
                "{NAME_PREFIX}{}-{}-{}-{now}",
                key.run.0, key.attempt, key.job.0
            ),
            created: now,
            state: MacState::Registering,
            runner: None,
            assigned: None,
        };
        self.rows.push(row.clone());
        Ok(row)
    }
    pub fn served(&self, key: JobKey) -> bool {
        served(
            self.rows.iter().map(|r| {
                (
                    r.key,
                    r.state != MacState::Done,
                    r.assigned == Some(key.job),
                )
            }),
            key,
        )
    }
    pub fn load(path: &Path) -> Result<Self, ScalerError> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }
    pub fn save(&self, path: &Path) -> Result<(), ScalerError> {
        save_json(self, path)
    }
    fn update(&mut self, row: &MacRecord, path: &Path) -> Result<(), ScalerError> {
        let target = self
            .rows
            .iter_mut()
            .find(|r| r.name == row.name)
            .ok_or(ScalerError::Guard("missing ledger identity"))?;
        *target = row.clone();
        self.save(path)
    }
}

/// What the controller does next with the active cloudmac runner.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MacStep {
    Wait,
    /// Drain under the hook's flock, then remove the registration.
    Drain,
    /// Remove the registration and close the row.
    Remove,
}
/// `launch_done` is true once the SSH-held `mac-run-once` returned (or no
/// launch is owned by this controller process, e.g. after a restart).
pub fn mac_step(row: &MacRecord, assignment: Assignment, launch_done: bool, now: u64) -> MacStep {
    if row.state == MacState::Registering {
        // Interrupted before or during JIT delivery: never launched by us.
        return MacStep::Remove;
    }
    match assignment {
        Assignment::Busy => MacStep::Wait,
        // The runner exits after its one job; let it finish before removal.
        Assignment::Completed | Assignment::Unknown if launch_done => MacStep::Remove,
        Assignment::Completed | Assignment::Unknown => MacStep::Wait,
        // Exited without a job (rejected and killed, or failed to start).
        Assignment::Unassigned if launch_done => MacStep::Remove,
        Assignment::Unassigned
            if row.state == MacState::Draining
                || now.saturating_sub(row.created) >= UNASSIGNED_DRAIN_SECS =>
        {
            MacStep::Drain
        }
        Assignment::Unassigned => MacStep::Wait,
    }
}

fn valid_name(name: &str) -> bool {
    name.len() <= 96
        && name.strip_prefix(NAME_PREFIX).is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
        })
}
fn hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}
fn safe_word(text: &str, extra: &[u8]) -> bool {
    !text.is_empty()
        && !text.starts_with('-')
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

/// The cloudmac SSH destination, its root-owned xtask and the runner-tree pin.
#[derive(Debug, Clone)]
pub struct MacTarget {
    host: String,
    remote_xtask: String,
    manifest_sha256: String,
}
impl MacTarget {
    pub fn new(
        host: String,
        remote_xtask: String,
        manifest_sha256: String,
    ) -> Result<Self, ScalerError> {
        if !safe_word(&host, b"@._-") {
            return Err(ScalerError::Usage(format!(
                "unsafe SSH destination {host:?}"
            )));
        }
        if !remote_xtask.starts_with('/')
            || !safe_word(&remote_xtask, b"/._-")
            || remote_xtask.contains("..")
        {
            return Err(ScalerError::Usage(format!(
                "unsafe remote path {remote_xtask:?}"
            )));
        }
        if !hex64(&manifest_sha256) {
            return Err(ScalerError::Usage(
                "runner manifest pin must be a SHA-256 hex digest".into(),
            ));
        }
        Ok(Self {
            host,
            remote_xtask,
            manifest_sha256: manifest_sha256.to_ascii_lowercase(),
        })
    }
    fn ssh(&self, remote: &str) -> Command {
        let mut command = Command::new("ssh");
        command.args([
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "SendEnv=-*",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=4",
            &self.host,
            remote,
        ]);
        command
    }
    /// `sudo -n` the fixed xtask; the sudoers entry names only this binary
    /// and these two subcommands.
    pub fn run_once_command(&self, name: &str, binding: &RunBinding) -> String {
        use crate::remote_accept::shell_quote;
        format!(
            "sudo -n {} ci-scaler mac-run-once --name {} --run-id {} --run-attempt {} --sha {} --manifest-sha256 {}",
            shell_quote(&self.remote_xtask),
            shell_quote(name),
            binding.run.0,
            binding.attempt,
            shell_quote(&binding.sha),
            self.manifest_sha256
        )
    }
    pub fn quiesce_command(&self, name: &str) -> String {
        use crate::remote_accept::shell_quote;
        format!(
            "sudo -n {} ci-scaler mac-quiesce --name {}",
            shell_quote(&self.remote_xtask),
            shell_quote(name)
        )
    }
}

/// The shared job-start hook with the cloudmac xtask, policy and state paths
/// substituted for the Willow guest command. Everything else is unchanged.
pub fn mac_hook_script(exe: &Path, state: &Path) -> Result<String, ScalerError> {
    use crate::remote_accept::shell_quote;
    let source = include_str!("../../../../scripts/ci/admit-job.sh");
    if source.matches(HOOK_COMMAND).count() != 1 {
        return Err(ScalerError::Guard("job-start hook command is not unique"));
    }
    let text = |path: &Path| {
        path.to_str()
            .map(str::to_owned)
            .ok_or(ScalerError::Guard("non-UTF-8 hook path"))
    };
    Ok(source.replace(
        HOOK_COMMAND,
        &format!(
            "{} ci-scaler admit-job --policy-file {} --state-dir {}",
            shell_quote(&text(exe)?),
            shell_quote(&text(&state.join("policy"))?),
            shell_quote(&text(state)?)
        ),
    ))
}

fn drain(
    gh: &Github,
    target: &MacTarget,
    ledger: &mut MacLedger,
    row: &mut MacRecord,
    path: &Path,
) -> Result<bool, ScalerError> {
    // Same flock as the hook: after this, a job start is refused and killed.
    let quiet = execute(
        &mut target.ssh(&target.quiesce_command(&row.name)),
        &[],
        Duration::from_secs(30),
    )?;
    if String::from_utf8_lossy(&quiet).trim() != "Unassigned" {
        return Ok(false);
    }
    row.state = MacState::Draining;
    ledger.update(row, path)?;
    if matches!(gh.assignment(row)?, Assignment::Busy | Assignment::Unknown) {
        ledger.update(row, path)?;
        return Ok(false);
    }
    gh.remove_runner(row)?;
    Ok(true)
}

fn reconcile(
    gh: &Github,
    target: &MacTarget,
    ledger: &mut MacLedger,
    row: &mut MacRecord,
    path: &Path,
    launch_done: bool,
) -> Result<bool, ScalerError> {
    let assignment = if row.state == MacState::Registering {
        Assignment::Unknown
    } else {
        let assignment = gh.assignment(row)?;
        ledger.update(row, path)?;
        assignment
    };
    let removed = match mac_step(row, assignment, launch_done, now()?) {
        MacStep::Wait => false,
        MacStep::Remove => {
            gh.remove_runner(row)?;
            true
        }
        MacStep::Drain => drain(gh, target, ledger, row, path)?,
    };
    if removed {
        row.state = MacState::Done;
        ledger.update(row, path)?;
        println!("runner={} registration removed; ledger closed", row.name);
    }
    Ok(removed)
}

type Launch = (
    String,
    std::thread::JoinHandle<Result<Vec<u8>, ScalerError>>,
);

fn launch(
    gh: &Github,
    target: &MacTarget,
    ledger: &mut MacLedger,
    path: &Path,
    group: u64,
    key: JobKey,
) -> Result<Launch, ScalerError> {
    let mut row = ledger.reserve(key, now()?)?;
    ledger.save(path)?; // Registration intent is durable before the request.
    let JobPolicy::Bound(binding) = gh.vet(&Admission::Standing, key)? else {
        return Err(ScalerError::Guard("standing vet returned a pilot policy"));
    };
    let (runner, jit) = gh.generate_jit(&row.name, group, &HVF_LABELS)?;
    row.runner = Some(runner);
    row.state = MacState::Launched;
    ledger.update(&row, path)?;
    let mut input = jit.into_bytes();
    input.push(b'\n');
    let remote = target.run_once_command(&row.name, &binding);
    let target = target.clone();
    let handle =
        std::thread::spawn(move || execute(&mut target.ssh(&remote), &input, LAUNCH_LIMIT));
    println!(
        "runner={} job={} JIT delivered to cloudmac",
        row.name, key.job.0
    );
    Ok((row.name, handle))
}

pub(super) fn controller(
    target: &MacTarget,
    dir: &Path,
    group: u64,
    one_job: bool,
) -> Result<(), ScalerError> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(dir.join("controller.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(ScalerError::Guard("another controller owns this ledger"));
    }
    let gh = Github;
    let path = dir.join("mac-ledger.json");
    let mut ledger = MacLedger::load(&path)?;
    let mut launched: Option<Launch> = None;
    let mut backoff = super::live::Backoff::default();
    loop {
        let active = ledger
            .rows
            .iter()
            .find(|r| r.state != MacState::Done)
            .cloned();
        // Transient GitHub/SSH failures back off; they never end the loop.
        let pass: Result<(), ScalerError> = if let Some(mut row) = active {
            let launch_done = launched
                .as_ref()
                .is_none_or(|(name, handle)| name != &row.name || handle.is_finished());
            match reconcile(&gh, target, &mut ledger, &mut row, &path, launch_done) {
                Ok(true) => {
                    if let Some((_, handle)) = launched.take() {
                        // Output is mac-run-once's own status line; not logged.
                        let _ = handle.join();
                    }
                    if one_job {
                        return if row.assigned == Some(row.key.job) {
                            Ok(())
                        } else {
                            Err(ScalerError::External(
                                "runner finished without its job; cleanup completed",
                            ))
                        };
                    }
                    Ok(())
                }
                Ok(false) => Ok(()),
                Err(error) => Err(error),
            }
        } else {
            gh.demand(&Admission::Standing, &HVF_LABELS)
                .and_then(
                    |demand| match demand.into_iter().find(|job| !ledger.served(*job)) {
                        Some(job) => launch(&gh, target, &mut ledger, &path, group, job)
                            .map(|handle| launched = Some(handle)),
                        None => Ok(()),
                    },
                )
        };
        match pass {
            Ok(()) => backoff.reset(),
            Err(error) => {
                eprintln!("mac-jit pass failed: {error}; backing off");
                backoff.grow();
            }
        }
        std::thread::sleep(backoff.delay());
    }
}

fn owner_only(meta: &std::fs::Metadata, uid: u32) -> bool {
    meta.uid() == uid && meta.permissions().mode() & 0o022 == 0
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// Deterministic listing of a runner tree: every directory, regular file
/// (SHA-256 and permission bits) and symlink (target), except the runner
/// user's top-level `_work` and `_diag`. With `owner`, every entry must be
/// owned by that uid and not group/other writable.
pub fn runner_manifest_for(dir: &Path, owner: Option<u32>) -> Result<String, ScalerError> {
    fn walk(
        root: &Path,
        rel: &Path,
        owner: Option<u32>,
        lines: &mut Vec<String>,
    ) -> Result<(), ScalerError> {
        let mut entries: Vec<_> =
            std::fs::read_dir(root.join(rel))?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or(ScalerError::Guard("non-UTF-8 runner path"))?;
            if rel.as_os_str().is_empty() && RUNNER_WRITABLE.contains(&name) {
                continue;
            }
            let path = rel.join(name);
            let text = path
                .to_str()
                .ok_or(ScalerError::Guard("non-UTF-8 runner path"))?
                .to_owned();
            if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(ScalerError::Guard("runner path contains whitespace"));
            }
            let meta = std::fs::symlink_metadata(root.join(&path))?;
            if meta.file_type().is_symlink() {
                if owner.is_some_and(|uid| meta.uid() != uid) {
                    return Err(ScalerError::Guard("runner tree entry not root-owned"));
                }
                let target = std::fs::read_link(root.join(&path))?;
                let target = target
                    .to_str()
                    .ok_or(ScalerError::Guard("non-UTF-8 runner link"))?;
                lines.push(format!("link {target} {text}"));
                continue;
            }
            if owner.is_some_and(|uid| !owner_only(&meta, uid)) {
                return Err(ScalerError::Guard(
                    "runner tree entry not root-owned or group/other writable",
                ));
            }
            if meta.is_dir() {
                lines.push(format!("dir {text}"));
                walk(root, &path, owner, lines)?;
            } else if meta.is_file() {
                let digest = sha256_hex(&std::fs::read(root.join(&path))?);
                let mode = meta.permissions().mode() & 0o7777;
                lines.push(format!("file {digest} {mode:o} {text}"));
            } else {
                return Err(ScalerError::Guard("runner tree has a special file"));
            }
        }
        Ok(())
    }
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || owner.is_some_and(|uid| !owner_only(&meta, uid)) {
        return Err(ScalerError::Guard(
            "runner tree root not a root-owned directory",
        ));
    }
    let mut lines = Vec::new();
    walk(dir, Path::new(""), owner, &mut lines)?;
    let mut text = lines.join("\n");
    text.push('\n');
    Ok(text)
}
pub(super) fn runner_manifest(dir: &Path) -> Result<String, ScalerError> {
    runner_manifest_for(dir, Some(0))
}

/// The manifest file must be owner-only, match the controller's pin, and
/// equal a fresh listing of the tree (contents, modes, links, ownership).
pub fn verify_runner_tree(
    dir: &Path,
    manifest: &Path,
    pin: &str,
    owner: Option<u32>,
) -> Result<(), ScalerError> {
    let meta = std::fs::symlink_metadata(manifest)?;
    if !meta.is_file() || owner.is_some_and(|uid| !owner_only(&meta, uid)) {
        return Err(ScalerError::Guard("runner manifest must be root-owned"));
    }
    let pinned = std::fs::read(manifest)?;
    if !hex64(pin) || sha256_hex(&pinned) != pin.to_ascii_lowercase() {
        return Err(ScalerError::Guard("runner manifest does not match the pin"));
    }
    if runner_manifest_for(dir, owner)?.as_bytes() != pinned.as_slice() {
        return Err(ScalerError::Guard("runner tree differs from its manifest"));
    }
    Ok(())
}

fn read_jit(input: &mut impl Read) -> Result<String, ScalerError> {
    let mut bytes = Vec::new();
    input.take((1 << 20) + 1).read_to_end(&mut bytes)?;
    let line = bytes
        .strip_suffix(b"\n")
        .ok_or(ScalerError::Guard("JIT config must be one terminated line"))?;
    if line.is_empty()
        || line.len() >= 1 << 20
        || !line
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(b))
    {
        return Err(ScalerError::Guard("JIT config is not one base64 line"));
    }
    String::from_utf8(line.to_vec()).map_err(|_| ScalerError::Guard("JIT config encoding"))
}

/// Prepare the one-use runner state directory, owned by `owner` (root in
/// production): the bound policy and the hook are not writable by the
/// runner user; only the hook's flock file is (`run_uid`). `exe` is the
/// xtask the hook runs and must be owned by `owner`.
pub fn prepare_run_once(
    name: &str,
    exe: &Path,
    state_root: &Path,
    binding: &RunBinding,
    owner: u32,
    run_uid: u32,
) -> Result<PathBuf, ScalerError> {
    if !valid_name(name) {
        return Err(ScalerError::Guard("runner name is not a mac-jit name"));
    }
    let policy = JobPolicy::Bound(binding.clone());
    // Round-trip validates the binding before anything is written.
    JobPolicy::parse(&policy.render())?;
    let exe_meta = std::fs::symlink_metadata(exe)?;
    if !exe_meta.is_file() || !owner_only(&exe_meta, owner) {
        return Err(ScalerError::Guard(
            "hook xtask must be a root-owned file, not group/other writable",
        ));
    }
    let root_meta = std::fs::symlink_metadata(state_root)?;
    if !root_meta.is_dir() || !owner_only(&root_meta, owner) {
        return Err(ScalerError::Guard(
            "state root must be a root-owned directory, not group/other writable",
        ));
    }
    let state = state_root.join(name);
    // mkdir is the one-use admission: a replayed name loses here.
    std::fs::DirBuilder::new().mode(0o755).create(&state)?;
    let write = |file: &str, mode: u32, contents: &[u8]| -> Result<File, ScalerError> {
        let mut out = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(state.join(file))?;
        out.write_all(contents)?;
        out.sync_all()?;
        Ok(out)
    };
    write("policy", 0o644, format!("{}\n", policy.render()).as_bytes())?;
    write(
        "admit-job.sh",
        0o755,
        mac_hook_script(exe, &state)?.as_bytes(),
    )?;
    let lock = write("admission.lock", 0o600, b"")?;
    if unsafe { libc::fchown(lock.as_raw_fd(), run_uid, u32::MAX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    File::open(&state)?.sync_all()?;
    Ok(state)
}

struct RunUser {
    uid: u32,
    gid: u32,
    home: PathBuf,
}
fn run_user() -> Result<RunUser, ScalerError> {
    let name = std::ffi::CString::new(RUN_USER).map_err(|_| ScalerError::Guard("run user"))?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        )
    };
    if rc != 0 || out.is_null() {
        return Err(ScalerError::Guard("runner user account is missing"));
    }
    let home = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }
        .to_str()
        .map_err(|_| ScalerError::Guard("runner home"))?;
    if pwd.pw_uid == 0 || pwd.pw_gid == 0 {
        return Err(ScalerError::Guard("runner user must be unprivileged"));
    }
    Ok(RunUser {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home: PathBuf::from(home),
    })
}

/// launchd-managed Apple agents that launchd respawns for any uid with
/// processes, so they can never be killed away (observed live: a per-user
/// `distnoted agent`, ppid 1, under `carrick-ci`). Matched by the kernel's
/// real executable path, never argv. Add a path only when observed.
pub const EXEMPT_AGENTS: [&str; 1] = ["/usr/sbin/distnoted"];

/// Whether a surviving runner-account process is an exempt Apple agent: its
/// REAL executable path (from the kernel, not argv) is exactly on the
/// allowlist, launchd (pid 1) is its parent, and that binary is a root-owned
/// regular file nobody else can write. A job cannot qualify by rewriting its
/// argv (the path is the kernel's), by copying a binary elsewhere (exact
/// path), or by planting a binary at an allowlisted path (root-owned,
/// SIP-protected system directories).
pub fn exempt_agent(path: Option<&Path>, ppid: u32, allowlist: &[&str]) -> bool {
    let Some(path) = path else {
        return false;
    };
    ppid == 1
        && allowlist.iter().any(|agent| Path::new(agent) == path)
        && std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && owner_only(&meta, 0))
}

/// Kernel facts of one process: parent pid, effective and real uid, and the
/// real executable path (`proc_pidpath`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessFacts {
    pub ppid: u32,
    pub uid: u32,
    pub ruid: u32,
    pub path: Option<PathBuf>,
}

#[cfg(target_os = "macos")]
pub fn process_facts(pid: i32) -> Option<ProcessFacts> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if got != size {
        return None;
    }
    let mut buf = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let len = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    let path = (len > 0).then(|| {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len as usize]))
    });
    Some(ProcessFacts {
        ppid: info.pbi_ppid,
        uid: info.pbi_uid,
        ruid: info.pbi_ruid,
        path,
    })
}
#[cfg(not(target_os = "macos"))]
pub fn process_facts(_pid: i32) -> Option<ProcessFacts> {
    None
}

/// Every pid whose effective or real uid is `uid`, except `own` and the
/// exempt Apple agents.
#[cfg(target_os = "macos")]
fn reap_targets(uid: u32, own: i32) -> Vec<i32> {
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return Vec::new();
    }
    let mut pids = vec![0 as libc::pid_t; count as usize * 2 + 64];
    let bytes = (pids.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
    let listed = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    pids.truncate(listed.max(0) as usize);
    pids.into_iter()
        .filter(|pid| *pid > 0 && *pid != own)
        .filter(|pid| {
            process_facts(*pid).is_some_and(|facts| {
                (facts.uid == uid || facts.ruid == uid)
                    && !exempt_agent(facts.path.as_deref(), facts.ppid, &EXEMPT_AGENTS)
            })
        })
        .collect()
}
#[cfg(not(target_os = "macos"))]
fn reap_targets(_uid: u32, _own: i32) -> Vec<i32> {
    Vec::new()
}

/// Kill every non-exempt process of `user` repeatedly until none remains,
/// from a child that dropped to the account: `kill(pid)` then only reaches
/// that account's processes even if a pid is recycled, and reaping needs no
/// sudo target a job could write. Exempt Apple agents (see [`exempt_agent`])
/// are left to launchd. A fork loop or any other non-exempt process alive
/// past the ten-second bound fails the launch.
fn kill_all_as(user: &RunUser) -> Result<(), ScalerError> {
    if !cfg!(target_os = "macos") {
        return Err(ScalerError::Guard("mac-run-once reaping requires macOS"));
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            if libc::setgid(user.gid) != 0 || libc::setuid(user.uid) != 0 {
                libc::_exit(2);
            }
            let own = libc::getpid();
            for _ in 0..200 {
                let targets = reap_targets(user.uid, own);
                if targets.is_empty() {
                    libc::_exit(0);
                }
                for target in targets {
                    libc::kill(target, libc::SIGKILL);
                }
                libc::usleep(50_000);
            }
            libc::_exit(1);
        }
    }
    if pid < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid
        || !libc::WIFEXITED(status)
        || libc::WEXITSTATUS(status) != 0
    {
        return Err(ScalerError::Guard(
            "non-exempt runner-account processes survived ten seconds of SIGKILL; launch refused",
        ));
    }
    Ok(())
}

/// Whether a cron/at deny list names `user` on a line of its own.
pub fn denies_user(text: &str, user: &str) -> bool {
    text.lines().any(|line| line.trim() == user)
}

fn lchown(path: &Path, uid: u32, gid: u32) -> Result<(), ScalerError> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| ScalerError::Guard("path contains NUL"))?;
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Remove a job-writable directory without following symlinks into it.
fn wipe(path: &Path) -> Result<(), ScalerError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(std::fs::remove_dir_all(path)?),
        Ok(_) => Ok(std::fs::remove_file(path)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Copy the skeleton into a fresh tree. Directories are created with mkdir
/// and files with `create_new` + `O_NOFOLLOW`, so nothing is written through
/// a symlink; every created path is returned for the final ownership pass.
fn copy_tree(from: &Path, to: &Path, created: &mut Vec<PathBuf>) -> Result<(), ScalerError> {
    let mut entries: Vec<_> = std::fs::read_dir(from)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let source = entry.path();
        let target = to.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&source)?;
        if meta.file_type().is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(&source)?, &target)?;
        } else if meta.is_dir() {
            std::fs::DirBuilder::new()
                .mode(meta.permissions().mode() & 0o755)
                .create(&target)?;
            copy_tree(&source, &target, created)?;
        } else if meta.is_file() {
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(meta.permissions().mode() & 0o755)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&target)?;
            out.write_all(&std::fs::read(&source)?)?;
            out.sync_all()?;
        } else {
            return Err(ScalerError::Guard("skeleton has a special file"));
        }
        created.push(target);
    }
    Ok(())
}

/// Before every job (all runner-account processes already gone): build a
/// new job home entirely root-only under a fresh temporary name next to it,
/// hand it to the runner account at the very end (contents first, the home
/// itself last), then swap it into place by rename. The previous home is
/// moved aside and deleted without following symlinks; every runner-writable
/// work directory is emptied. Nothing a previous job wrote (caches, launch
/// agents, rc files, planted symlinks) survives or redirects a root write.
pub fn reset_job_area(
    skeleton: &Path,
    home: &Path,
    work: &[PathBuf],
    owner: u32,
    uid: u32,
    gid: u32,
) -> Result<(), ScalerError> {
    let meta = std::fs::symlink_metadata(skeleton)?;
    if !meta.is_dir() || !owner_only(&meta, owner) {
        return Err(ScalerError::Guard(
            "job-home skeleton must be a root-owned directory",
        ));
    }
    let (parent, name) = match (home.parent(), home.file_name().and_then(|n| n.to_str())) {
        (Some(parent), Some(name)) => (parent, name),
        _ => return Err(ScalerError::Guard("job home needs a parent directory")),
    };
    let parent_meta = std::fs::symlink_metadata(parent)?;
    if !parent_meta.is_dir() || !owner_only(&parent_meta, owner) {
        return Err(ScalerError::Guard(
            "job home's parent must be root-owned and not group/other writable",
        ));
    }
    let fresh = parent.join(format!(".{name}.new"));
    let stale = parent.join(format!(".{name}.old"));
    wipe(&fresh)?;
    wipe(&stale)?;
    std::fs::DirBuilder::new().mode(0o700).create(&fresh)?;
    let mut created = Vec::new();
    copy_tree(skeleton, &fresh, &mut created)?;
    // Children before parents, the new home itself last.
    for path in created.iter().rev() {
        lchown(path, uid, gid)?;
    }
    lchown(&fresh, uid, gid)?;
    if std::fs::symlink_metadata(home).is_ok() {
        std::fs::rename(home, &stale)?;
    }
    std::fs::rename(&fresh, home)?;
    wipe(&stale)?;
    for dir in work {
        wipe(dir)?;
        std::fs::DirBuilder::new().mode(0o700).create(dir)?;
        lchown(dir, uid, gid)?;
    }
    Ok(())
}

/// The read-only toolchain root and its rustup/cargo homes are owner-only.
pub fn verify_toolchain(dir: &Path, owner: u32) -> Result<(), ScalerError> {
    for path in [dir.to_path_buf(), dir.join("rustup"), dir.join("cargo/bin")] {
        let meta = std::fs::symlink_metadata(&path)?;
        if !meta.is_dir() || !owner_only(&meta, owner) {
            return Err(ScalerError::Guard(
                "toolchain must be root-owned and not group/other writable",
            ));
        }
    }
    Ok(())
}

pub(super) fn quiesce(name: &str) -> Result<(), ScalerError> {
    if unsafe { libc::geteuid() } != 0 || !valid_name(name) {
        return Err(ScalerError::Guard(
            "mac-quiesce runs as root for a mac-jit name",
        ));
    }
    println!("{:?}", quiesce_guest(&Path::new(STATE_ROOT).join(name))?);
    Ok(())
}

/// The runner is launched through `bin/Runner.Listener run`, not `run.sh`:
/// the stock `run.sh` copies `run-helper.sh.template` into the runner
/// directory, which is root-owned and read-only here. A one-job ephemeral JIT
/// runner needs no restart loop. The JIT config arrives via
/// `ACTIONS_RUNNER_INPUT_JITCONFIG`, never argv.
pub fn listener_command(runner_dir: &Path) -> Command {
    let mut command = Command::new(runner_dir.join("bin/Runner.Listener"));
    command.arg("run");
    command
}

pub(super) fn run_once(name: &str, binding: &RunBinding, pin: &str) -> Result<(), ScalerError> {
    use std::os::unix::process::CommandExt;
    if unsafe { libc::geteuid() } != 0 {
        return Err(ScalerError::Guard(
            "mac-run-once runs as root through its sudoers entry",
        ));
    }
    let runner_dir = Path::new(RUNNER_DIR);
    verify_runner_tree(runner_dir, Path::new(MANIFEST), pin, Some(0))?;
    for list in SCHEDULER_DENY {
        if !denies_user(&std::fs::read_to_string(list)?, RUN_USER) {
            return Err(ScalerError::Guard(
                "cron.deny and at.deny must both name the runner account",
            ));
        }
    }
    verify_toolchain(Path::new(TOOLCHAIN), 0)?;
    let user = run_user()?;
    if user.home != Path::new(JOB_HOME) {
        return Err(ScalerError::Guard(
            "runner account's home must be the wiped job home",
        ));
    }
    // Nothing from a previous job may still run, then nothing it wrote may
    // remain: kill every runner-account process and recreate its areas.
    kill_all_as(&user)?;
    reset_job_area(
        Path::new(SKELETON),
        Path::new(JOB_HOME),
        &RUNNER_WRITABLE.map(|dir| runner_dir.join(dir)),
        0,
        user.uid,
        user.gid,
    )?;
    let exe = std::env::current_exe()?;
    let state = prepare_run_once(name, &exe, Path::new(STATE_ROOT), binding, 0, user.uid)?;
    let jit = read_jit(&mut std::io::stdin().lock())?;
    let log = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(state.join("runner.log"))?;
    // Read-only rustup toolchain; per-job writable CARGO_HOME in the wiped
    // home. Jobs cannot install into, or persist anything through, PATH.
    let path = format!(
        "{JOB_HOME}/.cargo/bin:{TOOLCHAIN}/cargo/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    );
    let mut command = listener_command(runner_dir);
    command
        .current_dir(runner_dir)
        .env_clear()
        .env("PATH", path)
        .env("HOME", JOB_HOME)
        .env("RUSTUP_HOME", format!("{TOOLCHAIN}/rustup"))
        .env("CARGO_HOME", format!("{JOB_HOME}/.cargo"))
        .env("USER", RUN_USER)
        .env("LOGNAME", RUN_USER)
        .env("LANG", "en_US.UTF-8")
        .env(
            "ACTIONS_RUNNER_HOOK_JOB_STARTED",
            state.join("admit-job.sh"),
        )
        // Never argv: process arguments are visible to every local user.
        .env("ACTIONS_RUNNER_INPUT_JITCONFIG", &jit)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    let (uid, gid) = (user.uid, user.gid);
    // A fresh session (the hook's `kill -KILL 0` reaches listener, worker and
    // hook, never this launcher), then the unprivileged runner identity.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1
                || libc::setgroups(1, &gid) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    drop(jit);
    let group = i32::try_from(child.id()).map_err(|_| ScalerError::External("runner pid"))?;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if state.join("draining").exists() {
            // quiesce only drains a runner whose hook never admitted a job.
            unsafe {
                libc::kill(-group, libc::SIGKILL);
            }
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    if let Err(error) = kill_all_as(&user) {
        eprintln!("post-job reap: {error}");
    }
    std::fs::write(state.join("runner.exit"), format!("{status:?}\n"))?;
    println!("one-job runner exited");
    Ok(())
}
