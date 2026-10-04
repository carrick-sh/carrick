//! The owner-approved, one-clone Willow pilot. No general-purpose VM authority.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

mod live;

pub const POOL: &str = "carrick-ci";
pub const REPOSITORY: &str = "carrick-sh/carrick";
pub const LABELS: [&str; 4] = ["self-hosted", "Linux", "X64", "willow-kvm"];

#[derive(Debug, Error)]
pub enum ScalerError {
    #[error(
        "projected Willow CPU {projected:.1}% exceeds director's 80% ceiling; controller stopped"
    )]
    CpuCeiling { projected: f64 },
    #[error("KVM_GET_API_VERSION returned {version}, errno={errno}; expected 12")]
    Kvm { version: i32, errno: i32 },
    #[error("{0}")]
    Guard(&'static str),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    // Never include external output: API/runner responses may contain secrets.
    #[error("external operation failed: {0}")]
    External(&'static str),
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
}
impl Ledger {
    pub fn reserve(
        &mut self,
        key: JobKey,
        inventory: &[PoolMember],
        now: u64,
    ) -> Result<Record, ScalerError> {
        if self.rows.iter().any(|r| r.key == key) {
            return Err(ScalerError::Guard("job already reserved"));
        }
        if self.rows.iter().any(|r| r.state != State::Destroyed)
            || inventory
                .iter()
                .any(|v| v.pool == POOL && !(v.template && (300..=307).contains(&v.id)))
        {
            return Err(ScalerError::Guard(
                "one-clone budget occupied (including unknown objects)",
            ));
        }
        let vm = (308..=349)
            .find(|id| !inventory.iter().any(|v| v.id == *id))
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
        let parent = path
            .parent()
            .ok_or(ScalerError::Guard("ledger requires parent directory"))?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        serde_json::to_writer_pretty(&mut file, self)?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|e| ScalerError::Io(e.error))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

pub fn eligible_labels(labels: &[&str]) -> bool {
    labels.len() == LABELS.len() && LABELS.iter().all(|l| labels.contains(l))
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
    Inspect,
    FinishAbsent,
    Quarantine,
}
pub fn recovery_decision(row: &Record, present: bool, task: TaskState, now: u64) -> Recovery {
    if task == TaskState::Running {
        return Recovery::Wait;
    }
    if present {
        return Recovery::Inspect;
    }
    if task == TaskState::Failed
        || row.state == State::Destroyed
        || (row.state == State::Reaping && task == TaskState::Succeeded)
        || (row.state == State::Reserved
            && task == TaskState::Absent
            && now.saturating_sub(row.created) >= 900)
    {
        Recovery::FinishAbsent
    } else {
        Recovery::Quarantine
    }
}
pub struct JobContext {
    pub repository: String,
    pub event: String,
    pub workflow_ref: String,
    pub sha: String,
}
pub fn authorize_job(context: &JobContext, sha: &str) -> Result<(), ScalerError> {
    if sha.len() != 40
        || context.sha != sha
        || context.repository != REPOSITORY
        || context.event != "workflow_dispatch"
        || context.workflow_ref
            != "carrick-sh/carrick/.github/workflows/willow-pilot.yml@refs/heads/work/willow-pilot"
    {
        return Err(ScalerError::Guard(
            "job-start authorization rejected workflow/repository/event/SHA",
        ));
    }
    Ok(())
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
    /// Fail unless the calling (non-root runner) user can open KVM API 12.
    VerifyKvm,
    /// Runner job-start hook: authorize before any workflow step executes.
    AdmitJob,
    /// Guest-agent-only stale-runner boundary, serialized against job admission.
    Quiesce,
}
pub fn run(args: ScalerArgs) -> Result<(), ScalerError> {
    match args.action {
        ScalerAction::VerifyKvm => verify_kvm(),
        ScalerAction::AdmitJob => {
            let get = |name| {
                std::env::var(name).map_err(|_| ScalerError::Guard("missing GitHub job context"))
            };
            let context = JobContext {
                repository: get("GITHUB_REPOSITORY")?,
                event: get("GITHUB_EVENT_NAME")?,
                workflow_ref: get("GITHUB_WORKFLOW_REF")?,
                sha: get("GITHUB_SHA")?,
            };
            let sha = std::fs::read_to_string("/etc/carrick-ci/approved-sha")?;
            authorize_job(&context, sha.trim())?;
            mark_job_started(Path::new("/run/carrick-ci"))?;
            println!("approved pilot workflow and SHA admitted");
            Ok(())
        }
        ScalerAction::Quiesce => {
            println!("{:?}", quiesce_guest(Path::new("/run/carrick-ci"))?);
            Ok(())
        }
        ScalerAction::Pilot {
            approved_sha,
            state_dir,
            runner_group_id,
            one_job,
        } => live::pilot(&approved_sha, &state_dir, runner_group_id, one_job),
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
    use std::os::unix::process::CommandExt;
    let deadline = Instant::now() + limit;
    let mut child = command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let pgid = i32::try_from(child.id()).map_err(|_| ScalerError::External("process group ID"))?;
    let mut stdin = child.stdin.take().ok_or(ScalerError::External("stdin"))?;
    let data = input.to_vec();
    let input_thread = std::thread::spawn(move || stdin.write_all(&data));
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
    let write = input_thread
        .join()
        .map_err(|_| ScalerError::External("input writer"))?;
    if !matches!(&status, Ok(Ok(s)) if s.success()) {
        return Err(ScalerError::External(
            "command exit/timeout (output suppressed)",
        ));
    }
    write?;
    output
        .map_err(|_| ScalerError::External("command output timeout"))?
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
