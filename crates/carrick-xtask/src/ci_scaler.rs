//! Owner-approved JIT ephemeral runners: the Willow KVM clone controller
//! (one-job pilot or bounded standing mode) and the cloudmac HVF controller.
//! No general-purpose VM authority; every runner is one-use JIT material.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

mod assignment;
mod github;
mod live;
mod mac;
mod site;

pub use assignment::{
    admit_assigned, assigned_job_key, pending_assignment, publish_assignment, standing_hook_script,
};
pub use mac::{
    EXEMPT_AGENTS, JOB_HOME, MacLedger, MacRecord, MacState, MacStep, MacTarget, ProcessFacts,
    SCCACHE_CACHE_SIZE, SCCACHE_DIR, SCCACHE_SOCKET, apply_job_env, clone_runner_tree, denies_user,
    ensure_run_user_dir, exempt_agent, hand_clone_to_run_user, listener_command, mac_hook_script,
    mac_step, prepare_run_once, process_facts, remove_run_root, reset_job_area, run_root_path,
    runner_manifest_for, verify_runner_tree, verify_toolchain,
};

pub const POOL: &str = "carrick-ci";
pub const REPOSITORY: &str = "carrick-sh/carrick";
/// The one KVM runner label set: Willow clones register with exactly these,
/// and every workflow job they serve names exactly these in `runs-on`.
pub const LABELS: [&str; 4] = ["self-hosted", "Linux", "X64", "willow-kvm"];
/// The one HVF runner label set for cloudmac merge-queue JIT runners.
pub const HVF_LABELS: [&str; 4] = ["self-hosted", "macOS", "ARM64", "carrick-hvf"];
/// The 24-hour closure job's labels: never served by `mac-jit`, so it can
/// never occupy the merge-queue runner.
pub const HVF_CLOSURE_LABELS: [&str; 4] = ["self-hosted", "macOS", "ARM64", "carrick-hvf-closure"];
/// A job key whose runners repeatedly closed without running it is not
/// re-served beyond this many reservations; a re-run is a new attempt.
pub const MAX_SERVES_PER_JOB: usize = 3;
pub const KERNEL_RUNTIME_WORKFLOW: &str = ".github/workflows/kernel-runtime.yml";
pub const PILOT_WORKFLOW: &str = ".github/workflows/willow-pilot.yml";
const PILOT_BRANCH: &str = "work/willow-pilot";
const MERGE_QUEUE_PREFIX: &str = "gh-readonly-queue/main/";

#[derive(Debug, Error)]
pub enum ScalerError {
    #[error("host lease: {0}")]
    HostLease(#[from] crate::host_lease::HostLeaseError),
    #[error(
        "projected Willow CPU {projected:.1}% exceeds director's 80% ceiling; controller stopped"
    )]
    CpuCeiling { projected: f64 },
    #[error("KVM_GET_API_VERSION returned {version}, errno={errno}; expected 12")]
    Kvm { version: i32, errno: i32 },
    #[error("{0}")]
    Guard(&'static str),
    #[error("merge group is no longer queued")]
    StaleMergeGroup,
    #[error("merge group superseded by queued descendant {successor}")]
    SupersededMergeGroup { successor: String },
    #[error("{0}")]
    Usage(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    // Never include external output: API/runner responses may contain secrets.
    #[error("external operation failed: {0}")]
    External(&'static str),
    // Program name and exit status/signal or timeout only; never external output.
    #[error("external command failed: {0}")]
    CommandFailed(String),
    // Contains only a validated HTTP status and parameter names, never values.
    #[error("PVE rejected request: {0}")]
    PveRejected(String),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct CloneId(u16);
impl TryFrom<u16> for CloneId {
    type Error = ScalerError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if (308..=349).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ScalerError::Guard("VMID outside clone reservation"))
        }
    }
}
impl From<CloneId> for u16 {
    fn from(id: CloneId) -> Self {
        id.0
    }
}
impl CloneId {
    pub fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunId(pub u64);
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobId(pub u64);
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerId(pub u64);
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobKey {
    pub run: RunId,
    pub attempt: u32,
    pub job: JobId,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    Reserved,
    Cloning,
    Booting,
    Registered,
    Running,
    Reaping,
    Destroyed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub key: JobKey,
    pub vm: CloneId,
    pub name: String,
    pub created: u64,
    pub state: State,
    pub task: Option<String>,
    pub runner: Option<RunnerId>,
    pub assigned: Option<JobId>,
    pub ip: Option<std::net::Ipv4Addr>,
    pub failure: Option<String>,
    /// The true run/attempt/job a re-vetted hook request named; the
    /// reservation `key` remains demand provenance.
    #[serde(default)]
    pub assigned_key: Option<JobKey>,
}

#[derive(Debug, Clone)]
pub struct Vm {
    pub id: u16,
    pub name: String,
    pub pool: String,
    pub template: bool,
}
#[derive(Debug, Clone)]
pub struct PoolMember {
    pub id: u16,
    pub pool: String,
    pub template: bool,
}
impl Record {
    pub fn guard(&self, vm: &Vm) -> Result<(), ScalerError> {
        if vm.id != self.vm.get() || vm.pool != POOL || vm.name != self.name || vm.template {
            return Err(ScalerError::Guard("VM ownership mismatch; quarantined"));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Ledger {
    pub rows: Vec<Record>,
    /// Refused actual assignments survive restarts; a new attempt has a new key.
    #[serde(default)]
    refused: Vec<JobKey>,
    #[serde(skip)]
    publication: Option<assignment::Publication<Ledger>>,
}
impl Ledger {
    pub fn reserve(
        &mut self,
        key: JobKey,
        inventory: &[PoolMember],
        now: u64,
        limit: Concurrency,
    ) -> Result<Record, ScalerError> {
        if self.served(key) {
            return Err(ScalerError::Guard("job already reserved"));
        }
        let active: Vec<&Record> = self
            .rows
            .iter()
            .filter(|r| r.state != State::Destroyed)
            .collect();
        // Every non-template pool member must be an active ledger clone. An
        // unknown object occupies the whole budget: it is never adopted.
        let unknown = inventory.iter().any(|v| {
            v.pool == POOL
                && !(v.template && (300..=307).contains(&v.id))
                && !active.iter().any(|r| r.vm.get() == v.id)
        });
        if unknown {
            return Err(ScalerError::Guard(
                "clone budget occupied by an unknown pool object",
            ));
        }
        if active.len() >= usize::from(limit.get()) {
            return Err(ScalerError::Guard("clone concurrency budget occupied"));
        }
        let vm = (308..=349)
            .find(|id| {
                !inventory.iter().any(|v| v.id == *id) && !active.iter().any(|r| r.vm.get() == *id)
            })
            .ok_or(ScalerError::Guard("no free reserved VMID"))?;
        let row = Record {
            key,
            vm: CloneId::try_from(vm)?,
            name: format!(
                "carrick-ci-{}-{}-{}-{now}",
                key.run.0, key.attempt, key.job.0
            ),
            created: now,
            state: State::Reserved,
            task: None,
            runner: None,
            assigned: None,
            ip: None,
            failure: None,
            assigned_key: None,
        };
        self.rows.push(row.clone());
        Ok(row)
    }
    /// Whether `key` must not be reserved again: it was refused, a clone ran
    /// (or runs) it, a clone reserved for it is active and was not assigned
    /// another job, or it reached [`MAX_SERVES_PER_JOB`]. A clone that closed
    /// without a job (failed launch, drained) consumes one serve; a clone
    /// GitHub assigned another job neither holds nor consumes it.
    pub fn served(&self, key: JobKey) -> bool {
        self.refused.contains(&key)
            || served(
                self.rows
                    .iter()
                    .map(|r| (r.key, r.state != State::Destroyed, r.assigned)),
                key,
            )
    }
    pub fn load(path: &Path) -> Result<Self, ScalerError> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let mut ledger: Self = serde_json::from_slice(&bytes)?;
                assignment::bound_refusals(&mut ledger.refused);
                Ok(ledger)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }
    fn merge_assignments(&mut self, source: &Self) {
        assignment::merge_records(
            &mut self.rows,
            &source.rows,
            |row| row.name.clone(),
            |row, other| {
                if other.assigned_key.is_some() {
                    row.assigned = other.assigned;
                    row.assigned_key = other.assigned_key;
                }
            },
        );
        for key in &source.refused {
            if !self.refused.contains(key) {
                self.refused.push(*key);
            }
        }
        assignment::bound_refusals(&mut self.refused);
        // Runtime state must never recursively own the publication itself.
        self.publication = None;
    }
    fn refresh(&mut self) -> Result<(), ScalerError> {
        if let Some(publication) = self.publication.clone() {
            *self = publication.snapshot()?;
            self.publication = Some(publication);
        }
        Ok(())
    }
    pub fn save(&self, path: &Path) -> Result<(), ScalerError> {
        if let Some(publication) = &self.publication {
            publication.commit(self, path, Self::merge_assignments)
        } else {
            save_json(self, path)
        }
    }
}
impl assignment::Refusals for Ledger {
    fn served(&self, key: JobKey) -> bool {
        Ledger::served(self, key)
    }
    fn refused(&self) -> &[JobKey] {
        &self.refused
    }
    fn refused_mut(&mut self) -> &mut Vec<JobKey> {
        &mut self.refused
    }
    fn persist(&self, path: &Path) -> Result<(), ScalerError> {
        self.save(path)
    }
}
/// Shared re-serve rule over (reservation, active, actual job) ledger rows.
/// Job ids are unique across runs and attempts, so an actual assignment
/// anywhere in the ledger serves that job.
fn served(rows: impl Iterator<Item = (JobKey, bool, Option<JobId>)>, key: JobKey) -> bool {
    let mut count = 0;
    for (row_key, active, assigned) in rows {
        if assigned == Some(key.job) {
            return true;
        }
        if row_key == key && assigned.is_none() {
            if active {
                return true;
            }
            count += 1;
        }
    }
    count >= MAX_SERVES_PER_JOB
}
/// Durable owner-only ledger publication: fsynced file, rename, fsynced dir.
fn save_json(value: &impl Serialize, path: &Path) -> Result<(), ScalerError> {
    let parent = path
        .parent()
        .ok_or(ScalerError::Guard("ledger requires parent directory"))?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| ScalerError::Io(e.error))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Concurrent clone (or Mac runner) budget: 1 by default, never above 2.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Concurrency(u8);
impl Concurrency {
    pub const ONE: Self = Self(1);
    pub fn get(self) -> u8 {
        self.0
    }
}
impl TryFrom<u8> for Concurrency {
    type Error = ScalerError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if (1..=2).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ScalerError::Guard("max concurrency must be 1 or 2"))
        }
    }
}
impl std::str::FromStr for Concurrency {
    type Err = ScalerError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let value = text
            .parse::<u8>()
            .map_err(|_| ScalerError::Guard("max concurrency must be 1 or 2"))?;
        Self::try_from(value)
    }
}

/// Exact label-set equality against one of the label constants.
pub fn labels_match(expected: &[&str], labels: &[&str]) -> bool {
    labels.len() == expected.len() && expected.iter().all(|l| labels.contains(l))
}
pub fn eligible_labels(labels: &[&str]) -> bool {
    labels_match(&LABELS, labels)
}

/// Which workflow runs a controller serves and which jobs a runner's
/// job-start hook admits. The guest/runner reads it from a root- or
/// runner-owned policy file written by the controller, never from the job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The historical one-job pilot: `willow-pilot.yml`, dispatched from
    /// `work/willow-pilot` at one approved SHA.
    Pilot { sha: String },
    /// `kernel-runtime.yml` on this repository for a merge group into main,
    /// a push to main, or a workflow_dispatch on main. Never pull_request.
    Standing,
}
fn full_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|c| c.is_ascii_hexdigit())
}
impl Admission {
    pub fn pilot(sha: &str) -> Result<Self, ScalerError> {
        if !full_sha(sha) {
            return Err(ScalerError::Guard("approved SHA must be full commit hash"));
        }
        Ok(Self::Pilot {
            sha: sha.to_ascii_lowercase(),
        })
    }
    /// The workflow file (basename) whose runs this admission serves.
    pub fn workflow_file(&self) -> &'static str {
        let path = match self {
            Self::Pilot { .. } => PILOT_WORKFLOW,
            Self::Standing => KERNEL_RUNTIME_WORKFLOW,
        };
        path.rsplit('/').next().unwrap_or(path)
    }
    /// Demand side: may a controller create a runner for this workflow run?
    pub fn admits_run(&self, run: &serde_json::Value) -> bool {
        let branch = run["head_branch"].as_str().unwrap_or_default();
        let event = run["event"].as_str().unwrap_or_default();
        if run["repository"]["full_name"] != REPOSITORY {
            return false;
        }
        match self {
            Self::Pilot { sha } => {
                event == "workflow_dispatch"
                    && run["head_sha"] == sha.as_str()
                    && branch == PILOT_BRANCH
                    && run["path"] == PILOT_WORKFLOW
            }
            Self::Standing => {
                run["head_repository"]["full_name"] == REPOSITORY
                    && run["path"] == KERNEL_RUNTIME_WORKFLOW
                    && run["head_sha"].as_str().is_some_and(full_sha)
                    && standing_event_ref(event, branch)
            }
        }
    }
    /// Job-start side: runs in the hook before any workflow step.
    pub fn authorize(&self, context: &JobContext) -> Result<(), ScalerError> {
        let branch = context.git_ref.strip_prefix("refs/heads/").unwrap_or("");
        let admitted = full_sha(&context.sha)
            && context.repository == REPOSITORY
            && !context.git_ref.contains('@')
            && match self {
                Self::Pilot { sha } => {
                    context.sha == *sha
                        && context.event == "workflow_dispatch"
                        && branch == PILOT_BRANCH
                        && context.workflow_ref
                            == format!("{REPOSITORY}/{PILOT_WORKFLOW}@refs/heads/{PILOT_BRANCH}")
                }
                Self::Standing => {
                    standing_event_ref(&context.event, branch)
                        && context.workflow_ref
                            == format!("{REPOSITORY}/{KERNEL_RUNTIME_WORKFLOW}@{}", context.git_ref)
                }
            };
        if admitted {
            Ok(())
        } else {
            Err(ScalerError::Guard(
                "job-start authorization rejected workflow/repository/event/ref/SHA",
            ))
        }
    }
}
fn standing_event_ref(event: &str, branch: &str) -> bool {
    match event {
        "merge_group" => branch.strip_prefix(MERGE_QUEUE_PREFIX).is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        }),
        "push" | "workflow_dispatch" => branch == "main",
        _ => false,
    }
}

/// The GitHub runner registration a controller owns, shared by the Willow
/// clone ledger and the cloudmac ledger for assignment and removal.
pub trait RunnerRegistration {
    fn key(&self) -> JobKey;
    fn name(&self) -> &str;
    fn runner(&self) -> Option<RunnerId>;
    fn set_runner(&mut self, runner: Option<RunnerId>);
    fn assigned(&self) -> Option<JobId>;
    fn set_assigned(&mut self, job: JobId);
}
impl RunnerRegistration for Record {
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
pub fn admit_resources(cpu_busy: f64, threads: u32, available: u64) -> bool {
    cpu_busy.is_finite()
        && (0.0..=1.0).contains(&cpu_busy)
        && threads > 0
        && cpu_busy + 2.0 / f64::from(threads) <= 0.80
        && available >= 10 << 30 // 4 GiB clone + 6 GiB host reserve
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Assignment {
    Unassigned,
    Busy,
    Completed,
    Unknown,
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Reap {
    Keep,
    Destroy,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TaskState {
    Absent,
    Running,
    Succeeded,
    Failed,
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Recovery {
    Wait,
    ResumeClone,
    ResumeReaping,
    Inspect,
    FinishAbsent,
    Quarantine,
}
pub fn recovery_decision(row: &Record, present: bool, task: TaskState, now: u64) -> Recovery {
    if task == TaskState::Running {
        return Recovery::Wait;
    }
    if present {
        if row.state == State::Reaping {
            return Recovery::ResumeReaping;
        }
        if row.state == State::Cloning && task == TaskState::Succeeded {
            return Recovery::ResumeClone;
        }
        return Recovery::Inspect;
    }
    if task == TaskState::Failed
        || row.state == State::Destroyed
        || row.state == State::Reaping
        || (row.state == State::Reserved
            && task == TaskState::Absent
            && now.saturating_sub(row.created) >= 900)
    {
        Recovery::FinishAbsent
    } else {
        Recovery::Quarantine
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobContext {
    pub repository: String,
    pub event: String,
    pub workflow_ref: String,
    pub git_ref: String,
    pub sha: String,
    pub run_id: u64,
    pub run_attempt: u32,
}

/// The exact workflow run (and attempt, at one SHA) a runner was minted for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunBinding {
    pub run: RunId,
    pub attempt: u32,
    pub sha: String,
}

/// What a runner's job-start hook admits, written by the controller into a
/// root-owned policy file before the runner starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobPolicy {
    /// The historical pilot: [`Admission::Pilot`] for one approved SHA.
    Pilot { sha: String },
    /// [`Admission::Standing`] restricted to the one run the controller
    /// vetted (repository, workflow, event, ref, merge-group PR heads).
    Bound(RunBinding),
}
impl JobPolicy {
    pub fn parse(text: &str) -> Result<Self, ScalerError> {
        let words: Vec<&str> = text.split_whitespace().collect();
        let field = |word: &str, name: &str| word.strip_prefix(name).map(str::to_owned);
        match words.as_slice() {
            ["pilot", sha] => match Admission::pilot(sha)? {
                Admission::Pilot { sha } => Ok(Self::Pilot { sha }),
                Admission::Standing => Err(ScalerError::Guard("pilot policy")),
            },
            ["standing", run, attempt, sha] => {
                let run = field(run, "run=")
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or(ScalerError::Guard("policy run id"))?;
                let attempt = field(attempt, "attempt=")
                    .and_then(|v| v.parse::<u32>().ok())
                    .filter(|a| *a > 0)
                    .ok_or(ScalerError::Guard("policy run attempt"))?;
                let sha = field(sha, "sha=")
                    .filter(|s| full_sha(s))
                    .ok_or(ScalerError::Guard("policy sha"))?
                    .to_ascii_lowercase();
                Ok(Self::Bound(RunBinding {
                    run: RunId(run),
                    attempt,
                    sha,
                }))
            }
            _ => Err(ScalerError::Guard("unrecognized runner job policy")),
        }
    }
    pub fn render(&self) -> String {
        match self {
            Self::Pilot { sha } => format!("pilot {sha}"),
            Self::Bound(b) => format!(
                "standing run={} attempt={} sha={}",
                b.run.0, b.attempt, b.sha
            ),
        }
    }
    /// Job-start side: runs in the hook before any workflow step.
    pub fn authorize(&self, context: &JobContext) -> Result<(), ScalerError> {
        match self {
            Self::Pilot { sha } => Admission::Pilot { sha: sha.clone() }.authorize(context),
            Self::Bound(binding) => {
                Admission::Standing.authorize(context)?;
                if context.run_id == binding.run.0
                    && context.run_attempt == binding.attempt
                    && context.sha == binding.sha
                {
                    Ok(())
                } else {
                    Err(ScalerError::Guard(
                        "job-start authorization rejected a run other than the vetted one",
                    ))
                }
            }
        }
    }
}

/// Merge-queue trust: every pull request in the group ending at `sha`
/// (its own queue entry and every entry ahead of it) must have its head in
/// this repository. `response` is the GraphQL mergeQueue entries listing.
pub fn merge_group_heads_trusted(response: &serde_json::Value, sha: &str) -> bool {
    let Some(nodes) = response["data"]["repository"]["mergeQueue"]["entries"]["nodes"].as_array()
    else {
        return false;
    };
    let Some(position) = nodes
        .iter()
        .find(|n| n["headCommit"]["oid"] == sha)
        .and_then(|n| n["position"].as_u64())
    else {
        return false;
    };
    nodes
        .iter()
        .filter(|n| n["position"].as_u64().is_some_and(|p| p <= position))
        .all(|n| n["pullRequest"]["headRepository"]["nameWithOwner"] == REPOSITORY)
}
fn admission_lock(dir: &Path) -> Result<File, ScalerError> {
    use std::os::fd::AsRawFd;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join("admission.lock"))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}
pub fn quiesce_guest(dir: &Path) -> Result<Assignment, ScalerError> {
    let mut lock = admission_lock(dir)?;
    let mut marker = String::new();
    lock.read_to_string(&mut marker)?;
    if !marker.is_empty() {
        return Ok(Assignment::Busy);
    }
    let drain = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o644)
        .open(dir.join("draining"))?;
    drain.sync_all()?;
    File::open(dir)?.sync_all()?;
    Ok(Assignment::Unassigned)
}
pub fn mark_job_started(dir: &Path) -> Result<(), ScalerError> {
    let mut lock = admission_lock(dir)?;
    if dir.join("draining").exists() {
        return Err(ScalerError::Guard("runner is draining; job steps rejected"));
    }
    lock.write_all(b"job-started\n")?;
    lock.sync_all()?;
    Ok(())
}
pub fn reap_decision(row: &Record, now: u64, assignment: Assignment) -> Reap {
    if row.state == State::Reaping {
        return Reap::Destroy;
    }
    match assignment {
        Assignment::Completed => Reap::Destroy,
        Assignment::Unassigned if now.saturating_sub(row.created) >= 900 => Reap::Destroy,
        _ => Reap::Keep,
    }
}
pub trait ReaperApi {
    fn stop(&mut self, id: CloneId) -> Result<(), ScalerError>;
    fn destroy(&mut self, id: CloneId) -> Result<(), ScalerError>;
}
pub fn reap_owned(row: &Record, vm: &Vm, api: &mut impl ReaperApi) -> Result<(), ScalerError> {
    row.guard(vm)?;
    api.stop(row.vm)?;
    api.destroy(row.vm)
}

#[derive(clap::Args, Debug)]
pub struct ScalerArgs {
    #[command(subcommand)]
    pub action: ScalerAction,
}
#[derive(clap::Subcommand, Debug)]
pub enum ScalerAction {
    /// Run in the foreground ON Willow; the PVE secret never leaves the host.
    Pilot {
        #[arg(long)]
        approved_sha: String,
        #[arg(long, default_value = "/root/carrick-ci/state")]
        state_dir: PathBuf,
        #[arg(long, default_value_t = 1)]
        runner_group_id: u64,
        /// Exit after one completed or failed lifecycle has been cleaned up.
        #[arg(long)]
        one_job: bool,
    },
    /// Standing Willow mode ON Willow: serve kernel-runtime.yml KVM jobs for
    /// merge groups into main, pushes to main and dispatches on main.
    Standing {
        #[arg(long, default_value = "/root/carrick-ci/state")]
        state_dir: PathBuf,
        #[arg(long, default_value_t = 1)]
        runner_group_id: u64,
        /// Concurrent clones, 1 (default) or 2.
        #[arg(long, default_value = "1")]
        max_concurrency: Concurrency,
    },
    /// Director-Mac controller for cloudmac: mint one JIT config per queued
    /// carrick-hvf job and feed it to one runner over SSH stdin.
    MacJit {
        /// SSH destination of the gate Mac.
        #[arg(long, default_value = "rentamac@cloudmac")]
        host: String,
        /// Root-owned carrick-xtask on cloudmac, named in its sudoers entry.
        #[arg(long, default_value = mac::REMOTE_XTASK)]
        remote_xtask: String,
        /// SHA-256 of cloudmac's root-owned runner-tree manifest; every
        /// launch verifies the manifest and the tree against it.
        #[arg(long)]
        runner_manifest_sha256: String,
        /// Local ledger directory on the director's Mac.
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value_t = 1)]
        runner_group_id: u64,
        /// Exit after one runner lifecycle has been cleaned up.
        #[arg(long)]
        one_job: bool,
    },
    /// ON cloudmac as root (one fixed sudoers entry): verify the runner tree,
    /// write the bound root-owned policy, read one JIT config from stdin and
    /// run one ephemeral runner as the unprivileged runner user. All paths
    /// are fixed; only the run binding is an argument.
    MacRunOnce {
        /// Ledger-generated runner name (also the per-runner state directory).
        #[arg(long)]
        name: String,
        #[arg(long)]
        run_id: u64,
        #[arg(long)]
        run_attempt: u32,
        #[arg(long)]
        sha: String,
        #[arg(long)]
        manifest_sha256: String,
    },
    /// ON cloudmac as root: drain one named runner under its hook's flock.
    MacQuiesce {
        #[arg(long)]
        name: String,
        /// Read the pending hook request, or publish controller-vetted approval.
        #[arg(long)]
        assignment: bool,
        #[arg(long, requires = "assignment")]
        approve: Option<String>,
    },
    /// Print the runner-tree manifest (run once by the owner after a
    /// checksum-verified runner install; its SHA-256 is the controller pin).
    MacRunnerManifest {
        #[arg(long, default_value = mac::RUNNER_DIR)]
        runner_dir: PathBuf,
    },
    /// Print this host's KVM clone site as `SITE_*=value` lines for
    /// `build-template-debian.sh`; fails closed on an unknown host.
    Site,
    /// Print this host's PVE VM firewall file for template 300; fails on a
    /// site whose bridge needs no VM firewall.
    VmFirewall,
    /// Fail unless the calling (non-root runner) user can open KVM API 12.
    VerifyKvm,
    /// Runner job-start hook: authorize before any workflow step executes.
    AdmitJob {
        /// Ask the credential-holding controller to re-vet the assigned run.
        #[arg(long)]
        controller: bool,
        #[arg(long, default_value = "/etc/carrick-ci/policy")]
        policy_file: PathBuf,
        #[arg(long, default_value = "/run/carrick-ci")]
        state_dir: PathBuf,
    },
    /// Stale-runner boundary, serialized against job admission.
    Quiesce {
        #[arg(long, default_value = "/run/carrick-ci")]
        state_dir: PathBuf,
    },
}
/// The policy file is written by the controller before the runner starts.
/// A symlink or a group/other-writable file could be swapped by a job.
/// `owner` is the uid that must own it (root for every live runner).
pub fn read_policy(path: &Path, owner: Option<u32>) -> Result<JobPolicy, ScalerError> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file()
        || meta.permissions().mode() & 0o022 != 0
        || owner.is_some_and(|uid| meta.uid() != uid)
    {
        return Err(ScalerError::Guard(
            "runner policy must be a regular file owned by root, writable only by its owner",
        ));
    }
    JobPolicy::parse(&std::fs::read_to_string(path)?)
}
pub fn run(args: ScalerArgs) -> Result<(), ScalerError> {
    match args.action {
        ScalerAction::Site => {
            print!("{}", site::Site::local()?.shell_env()?);
            Ok(())
        }
        ScalerAction::VmFirewall => {
            let file = site::Site::local()?
                .vm_firewall_file(300)?
                .ok_or(ScalerError::Guard("this site uses no VM firewall"))?;
            print!("{file}");
            Ok(())
        }
        ScalerAction::VerifyKvm => verify_kvm(),
        ScalerAction::AdmitJob {
            policy_file,
            state_dir,
            controller,
        } => {
            let get = |name| {
                std::env::var(name).map_err(|_| ScalerError::Guard("missing GitHub job context"))
            };
            let number = |name| {
                get(name)?
                    .parse::<u64>()
                    .map_err(|_| ScalerError::Guard("malformed GitHub run context"))
            };
            let context = JobContext {
                repository: get("GITHUB_REPOSITORY")?,
                event: get("GITHUB_EVENT_NAME")?,
                workflow_ref: get("GITHUB_WORKFLOW_REF")?,
                git_ref: get("GITHUB_REF")?,
                sha: get("GITHUB_SHA")?,
                run_id: number("GITHUB_RUN_ID")?,
                run_attempt: u32::try_from(number("GITHUB_RUN_ATTEMPT")?)
                    .map_err(|_| ScalerError::Guard("malformed GitHub run context"))?,
            };
            if controller {
                admit_assigned(&state_dir, &context, 0, assignment::APPROVAL_LIMIT)?;
            } else {
                read_policy(&policy_file, Some(0))?.authorize(&context)?;
            }
            mark_job_started(&state_dir)?;
            println!("admitted workflow, event and ref");
            Ok(())
        }
        ScalerAction::Quiesce { state_dir } => {
            println!("{:?}", quiesce_guest(&state_dir)?);
            Ok(())
        }
        ScalerAction::Pilot {
            approved_sha,
            state_dir,
            runner_group_id,
            one_job,
        } => live::controller(
            &Admission::pilot(&approved_sha)?,
            &state_dir,
            runner_group_id,
            one_job,
            Concurrency::ONE,
        ),
        ScalerAction::Standing {
            state_dir,
            runner_group_id,
            max_concurrency,
        } => live::controller(
            &Admission::Standing,
            &state_dir,
            runner_group_id,
            false,
            max_concurrency,
        ),
        ScalerAction::MacJit {
            host,
            remote_xtask,
            runner_manifest_sha256,
            state_dir,
            runner_group_id,
            one_job,
        } => mac::controller(
            &mac::MacTarget::new(host, remote_xtask, runner_manifest_sha256)?,
            &state_dir,
            runner_group_id,
            one_job,
        ),
        ScalerAction::MacRunOnce {
            name,
            run_id,
            run_attempt,
            sha,
            manifest_sha256,
        } => mac::run_once(
            &name,
            &RunBinding {
                run: RunId(run_id),
                attempt: run_attempt,
                sha,
            },
            &manifest_sha256,
        ),
        ScalerAction::MacQuiesce {
            name,
            assignment,
            approve,
        } => {
            if assignment {
                mac::assignment_exchange(&name, approve.as_deref())
            } else {
                mac::quiesce(&name)
            }
        }
        ScalerAction::MacRunnerManifest { runner_dir } => {
            print!("{}", mac::runner_manifest(&runner_dir)?);
            Ok(())
        }
    }
}
fn verify_kvm() -> Result<(), ScalerError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let file = OpenOptions::new().read(true).write(true).open("/dev/kvm")?;
        // Linux KVM UAPI: KVM_GET_API_VERSION = _IO(0xAE, 0x00).
        // KVM rejects a nonzero argument even for this _IO request. Omitting
        // the variadic argument leaves register garbage (live EINVAL=22).
        let version = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                0xae00,
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if version != 12 {
            return Err(ScalerError::Kvm {
                version,
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        println!("KVM_GET_API_VERSION={version}");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    Err(ScalerError::Guard("KVM verification requires Linux"))
}

fn now() -> Result<u64, ScalerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ScalerError::Guard("system clock before epoch"))
}

// Capture output in memory, never in a command log or a tempfile. Bounds apply
// to every external command (including gh and ssh), not just guest readiness.
fn execute(command: &mut Command, input: &[u8], limit: Duration) -> Result<Vec<u8>, ScalerError> {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    let program = Path::new(command.get_program())
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("command")
        .to_owned();
    // External host tools (curl, gh, ssh, lvs, bash) must resolve shared
    // libraries via the system dynamic linker cache rather than scanning
    // Cargo's target/debug/deps directory when xtask or its test binary runs
    // under cargo.
    for var in [
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
    ] {
        command.env_remove(var);
    }
    let deadline = Instant::now() + limit;
    let has_input = !input.is_empty();
    let mut child = command
        .process_group(0)
        .stdin(if has_input {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let pgid = i32::try_from(child.id()).map_err(|_| ScalerError::External("process group ID"))?;
    let input_thread = if has_input {
        let mut stdin = child.stdin.take().ok_or(ScalerError::External("stdin"))?;
        let data = input.to_vec();
        Some(std::thread::spawn(move || stdin.write_all(&data)))
    } else {
        None
    };
    let stdout = child.stdout.take().ok_or(ScalerError::External("stdout"))?;
    let (output_tx, output_rx) = std::sync::mpsc::channel();
    let output_thread = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(20 * 1024 * 1024)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = output_tx.send(result);
    });
    let (wait_tx, wait_rx) = std::sync::mpsc::channel();
    let wait_thread = std::thread::spawn(move || {
        let _ = wait_tx.send(child.wait());
    });
    let status = wait_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    let output = output_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    if status.is_err() || output.is_err() {
        // This invocation owns a fresh process group, including pipe holders.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
    wait_thread
        .join()
        .map_err(|_| ScalerError::External("process waiter"))?;
    output_thread
        .join()
        .map_err(|_| ScalerError::External("output reader"))?;
    let write = match input_thread {
        Some(thread) => thread
            .join()
            .map_err(|_| ScalerError::External("input writer"))?,
        None => Ok(()),
    };
    match &status {
        Ok(Ok(s)) if s.success() => {}
        Ok(Ok(s)) => {
            let reason = if let Some(code) = s.code() {
                format!("{program} exited with code {code}")
            } else if let Some(sig) = s.signal() {
                format!("{program} killed by signal {sig}")
            } else {
                format!("{program} exited unsuccessfully")
            };
            return Err(ScalerError::CommandFailed(reason));
        }
        Ok(Err(err)) => {
            return Err(ScalerError::CommandFailed(format!(
                "{program} wait error: {err}"
            )));
        }
        Err(_) => {
            return Err(ScalerError::CommandFailed(format!(
                "{program} timed out after {}ms",
                limit.as_millis()
            )));
        }
    }
    write?;
    output
        .map_err(|_| {
            ScalerError::CommandFailed(format!(
                "{program} stdout timed out after {}ms",
                limit.as_millis()
            ))
        })?
        .map_err(ScalerError::Io)
}

#[cfg(test)]
mod timeout_tests {
    use super::*;
    #[test]
    fn timeout_is_bounded_when_descendants_hold_stdout_open() {
        let start = Instant::now();
        assert!(
            execute(
                Command::new("sh").args(["-c", "(sleep 2) & wait"]),
                &[],
                Duration::from_millis(100)
            )
            .is_err()
        );
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "descendant defeated timeout"
        );
    }
}
