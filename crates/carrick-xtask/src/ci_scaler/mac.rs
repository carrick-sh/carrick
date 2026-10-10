//! cloudmac HVF JIT runners.
//!
//! `mac-jit` runs on the director's Mac, where `gh` holds the GitHub
//! credential. For each queued `kernel-runtime.yml` job with exactly
//! [`HVF_LABELS`] in a run [`Admission::Standing`] serves, it mints one JIT
//! config and feeds it over SSH stdin to `mac-run-once` on cloudmac. Only that
//! one-use JIT material crosses to cloudmac; nothing is written there by the
//! controller except through `mac-run-once`, which never stores the JIT.
//!
//! `mac-run-once` starts the runner in a fresh session with the shared
//! job-start hook (`scripts/ci/admit-job.sh`). A rejected job kills that whole
//! session before any workflow step, exactly as on Willow clones.
use super::github::Github;
use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};

const NAME_PREFIX: &str = "carrick-hvf-";
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
    /// One cloudmac runner at a time; a job key is served at most once (a
    /// re-run is a new attempt and therefore a new key).
    pub fn reserve(&mut self, key: JobKey, now: u64) -> Result<MacRecord, ScalerError> {
        if self.rows.iter().any(|r| r.key == key) {
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

fn safe_word(text: &str, extra: &[u8]) -> bool {
    !text.is_empty()
        && !text.starts_with('-')
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}
fn valid_name(name: &str) -> bool {
    name.len() <= 96
        && name.strip_prefix(NAME_PREFIX).is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
        })
}

/// The cloudmac SSH destination and its installed paths.
#[derive(Debug, Clone)]
pub struct MacTarget {
    host: String,
    remote_xtask: String,
    remote_state_root: String,
}
impl MacTarget {
    pub fn new(
        host: String,
        remote_xtask: String,
        remote_state_root: String,
    ) -> Result<Self, ScalerError> {
        if !safe_word(&host, b"@._-") {
            return Err(ScalerError::Usage(format!(
                "unsafe SSH destination {host:?}"
            )));
        }
        for path in [&remote_xtask, &remote_state_root] {
            if !path.starts_with('/') || !safe_word(path, b"/._-") || path.contains("..") {
                return Err(ScalerError::Usage(format!("unsafe remote path {path:?}")));
            }
        }
        Ok(Self {
            host,
            remote_xtask,
            remote_state_root,
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
    fn run_once_command(&self, name: &str) -> String {
        use crate::remote_accept::shell_quote;
        format!(
            "{} ci-scaler mac-run-once --name {} --state-root {}",
            shell_quote(&self.remote_xtask),
            shell_quote(name),
            shell_quote(&self.remote_state_root)
        )
    }
    fn quiesce_command(&self, name: &str) -> String {
        use crate::remote_accept::shell_quote;
        format!(
            "{} ci-scaler quiesce --state-dir {}",
            shell_quote(&self.remote_xtask),
            shell_quote(&format!("{}/{name}", self.remote_state_root))
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
    let (runner, jit) = gh.generate_jit(&row.name, group, &HVF_LABELS)?;
    row.runner = Some(runner);
    row.state = MacState::Launched;
    ledger.update(&row, path)?;
    let mut input = jit.into_bytes();
    input.push(b'\n');
    let remote = target.run_once_command(&row.name);
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
    loop {
        let active = ledger
            .rows
            .iter()
            .find(|r| r.state != MacState::Done)
            .cloned();
        if let Some(mut row) = active {
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
                        return if row.assigned.is_some() {
                            Ok(())
                        } else {
                            Err(ScalerError::External(
                                "runner finished without an assigned job; cleanup completed",
                            ))
                        };
                    }
                }
                Ok(false) => {}
                Err(error) => eprintln!("reconcile failed: {error}; admission frozen"),
            }
        } else {
            let seen: Vec<JobKey> = ledger.rows.iter().map(|r| r.key).collect();
            if let Some(job) = gh
                .demand(&Admission::Standing, &HVF_LABELS)?
                .into_iter()
                .find(|job| !seen.contains(job))
            {
                match launch(&gh, target, &mut ledger, &path, group, job) {
                    Ok(handle) => launched = Some(handle),
                    Err(error) => eprintln!("launch failed: {error}; ledger kept for reconcile"),
                }
            }
        }
        std::thread::sleep(Duration::from_secs(30));
    }
}

fn owner_only(meta: &std::fs::Metadata, uid: u32) -> bool {
    meta.uid() == uid && meta.permissions().mode() & 0o022 == 0
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

/// Prepare the one-use runner state directory. `exe` is the xtask that the
/// hook will run; it must be root-owned so a job cannot replace admission.
pub fn prepare_run_once(
    name: &str,
    exe: &Path,
    state_root: &Path,
    uid: u32,
) -> Result<PathBuf, ScalerError> {
    if !valid_name(name) {
        return Err(ScalerError::Guard("runner name is not a mac-jit name"));
    }
    let exe_meta = std::fs::symlink_metadata(exe)?;
    if !exe_meta.is_file() || !owner_only(&exe_meta, 0) {
        return Err(ScalerError::Guard(
            "hook xtask must be a root-owned file, not group/other writable",
        ));
    }
    let root_meta = std::fs::symlink_metadata(state_root)?;
    if !root_meta.is_dir() || !owner_only(&root_meta, uid) {
        return Err(ScalerError::Guard(
            "state root must be a runner-owned directory, not group/other writable",
        ));
    }
    let state = state_root.join(name);
    // mkdir is the one-use admission: a replayed name loses here.
    std::fs::DirBuilder::new().mode(0o700).create(&state)?;
    let write = |file: &str, mode: u32, contents: &[u8]| -> Result<(), ScalerError> {
        let mut out = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(state.join(file))?;
        out.write_all(contents)?;
        out.sync_all()?;
        Ok(())
    };
    write(
        "policy",
        0o600,
        format!("{}\n", Admission::Standing.render()).as_bytes(),
    )?;
    write("admission.lock", 0o600, b"")?;
    write(
        "admit-job.sh",
        0o700,
        mac_hook_script(exe, &state)?.as_bytes(),
    )?;
    File::open(&state)?.sync_all()?;
    Ok(state)
}

pub(super) fn run_once(
    name: &str,
    runner_dir: &Path,
    state_root: &Path,
) -> Result<(), ScalerError> {
    use std::os::unix::process::CommandExt;
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return Err(ScalerError::Guard("runner must not run as root"));
    }
    let exe = std::env::current_exe()?;
    let state = prepare_run_once(name, &exe, state_root, uid)?;
    let jit = read_jit(&mut std::io::stdin().lock())?;
    let run = runner_dir.join("run.sh");
    if !std::fs::symlink_metadata(&run)?.is_file() {
        return Err(ScalerError::Guard("runner run.sh missing"));
    }
    let log = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(state.join("runner.log"))?;
    let mut command = Command::new(&run);
    command
        .arg("--jitconfig")
        .arg(&jit)
        .current_dir(runner_dir)
        .env(
            "ACTIONS_RUNNER_HOOK_JOB_STARTED",
            state.join("admit-job.sh"),
        )
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_CLIENT")
        .env_remove("SSH_TTY")
        .env_remove("SSH_AUTH_SOCK")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    // A fresh session and process group: the hook's `kill -KILL 0` reaches
    // listener, worker and hook, and never this SSH-held launcher.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
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
    std::fs::write(state.join("runner.exit"), format!("{status:?}\n"))?;
    println!("one-job runner exited");
    Ok(())
}
