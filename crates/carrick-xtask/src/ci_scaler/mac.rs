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

/// Kill every process of `user` as that user (`kill(-1)` from a child that
/// dropped to it): reaping needs no sudo target a job could write.
fn kill_all_as(user: &RunUser) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            if libc::setgid(user.gid) == 0 && libc::setuid(user.uid) == 0 {
                libc::kill(-1, libc::SIGKILL);
            }
            libc::_exit(0);
        }
    }
    if pid > 0 {
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
    }
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

pub(super) fn run_once(name: &str, binding: &RunBinding, pin: &str) -> Result<(), ScalerError> {
    use std::os::unix::process::CommandExt;
    if unsafe { libc::geteuid() } != 0 {
        return Err(ScalerError::Guard(
            "mac-run-once runs as root through its sudoers entry",
        ));
    }
    let runner_dir = Path::new(RUNNER_DIR);
    verify_runner_tree(runner_dir, Path::new(MANIFEST), pin, Some(0))?;
    let user = run_user()?;
    let exe = std::env::current_exe()?;
    let state = prepare_run_once(name, &exe, Path::new(STATE_ROOT), binding, 0, user.uid)?;
    let jit = read_jit(&mut std::io::stdin().lock())?;
    let log = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(state.join("runner.log"))?;
    let path = format!(
        "{}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        user.home.display()
    );
    let mut command = Command::new(runner_dir.join("run.sh"));
    command
        .current_dir(runner_dir)
        .env_clear()
        .env("PATH", path)
        .env("HOME", &user.home)
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
    kill_all_as(&user);
    std::fs::write(state.join("runner.exit"), format!("{status:?}\n"))?;
    println!("one-job runner exited");
    Ok(())
}
