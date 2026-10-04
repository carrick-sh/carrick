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
        inventory: &[Vm],
        now: u64,
    ) -> Result<Record, ScalerError> {
        if self.rows.iter().any(|r| r.key == key) {
            return Err(ScalerError::Guard("job already reserved"));
        }
        if self.rows.iter().any(|r| r.state != State::Destroyed)
            || inventory.iter().any(|v| v.pool == POOL && !v.template)
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
        && cpu_busy + 2.0 / f64::from(threads) < 0.85
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
}
pub fn run(args: ScalerArgs) -> Result<(), ScalerError> {
    match args.action {
        ScalerAction::VerifyKvm => verify_kvm(),
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
        let version = unsafe { libc::ioctl(file.as_raw_fd(), 0xae00) };
        if version != 12 {
            return Err(ScalerError::Guard("KVM API version is not 12"));
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
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or(ScalerError::External("stdin"))?;
    let data = input.to_vec();
    let input_thread = std::thread::spawn(move || stdin.write_all(&data));
    let stdout = child.stdout.take().ok_or(ScalerError::External("stdout"))?;
    let output_thread = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(20 * 1024 * 1024)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if start.elapsed() >= limit {
            child.kill()?;
            child.wait()?;
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let output = output_thread
        .join()
        .map_err(|_| ScalerError::External("output reader"))??;
    let write = input_thread
        .join()
        .map_err(|_| ScalerError::External("input writer"))?;
    if !status.is_some_and(|s| s.success()) {
        return Err(ScalerError::External(
            "command exit/timeout (output suppressed)",
        ));
    }
    write?;
    Ok(output)
}
