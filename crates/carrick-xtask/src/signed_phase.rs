//! Signed runs build under the shared `carrick` lease and execute under
//! `gate` (#2013). The driver runs one command twice: first as the build
//! phase under `carrick`, which lists the artifacts it produced, then, after
//! that lease is fully released, as the execution phase under `gate`.
//!
//! The artifact identity is captured inside the build lease and checked
//! again inside the gate lease before the execution phase starts. A changed
//! artifact is a broken invariant and refuses execution. There is no lock
//! upgrade: each phase is a separate supervised run, and the build lease is
//! closed before the gate lease is requested. Waiting for `gate` uses the
//! ordinary lease wait (`HOST_LEASE_WAIT_LIMIT`).
//!
//! Under an inherited lease both phases reuse it. An outer `gate` runs both
//! phases under that gate (no split); an outer `carrick` cannot grant the
//! execution phase, so the driver refuses before building anything.

use crate::host_lease::{HostLease, HostLeaseError, HostLeaseMode, extract_exit_code};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

/// Phase the driven command is asked to perform.
pub const PHASE_ENV: &str = "CARRICK_SIGNED_PHASE";
/// Directory the phases share; the build phase writes [`ARTIFACTS_FILE`] here.
pub const STATE_ENV: &str = "CARRICK_SIGNED_STATE";
/// Newline-separated absolute paths of every artifact the execution phase runs.
pub const ARTIFACTS_FILE: &str = "artifacts";
/// Identity captured at the end of the build phase, inside its lease.
pub const IDENTITY_FILE: &str = "identity.json";
/// Identity re-verified after gate admission, with both phases' lease modes.
pub const ADMISSION_FILE: &str = "admission.json";

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignedPhase {
    Build,
    Execute,
}

impl SignedPhase {
    pub fn lease_mode(self) -> HostLeaseMode {
        match self {
            Self::Build => HostLeaseMode::Carrick,
            Self::Execute => HostLeaseMode::Gate,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Execute => "execute",
        }
    }

    /// The phase this process was started in, if a driver started it.
    pub fn current() -> Result<Option<Self>, SignedPhaseError> {
        match std::env::var(PHASE_ENV) {
            Ok(value) => Self::from_str(&value, false)
                .map(Some)
                .map_err(|_| SignedPhaseError::Stage(format!("invalid {PHASE_ENV}={value}"))),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(SignedPhaseError::Stage(format!("{PHASE_ENV}: {error}"))),
        }
    }
}

#[derive(Debug, Error)]
pub enum SignedPhaseError {
    #[error(transparent)]
    Lease(#[from] HostLeaseError),
    #[error("signed phase state '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("signed phase identity: {0}")]
    Probe(String),
    #[error(
        "artifact identity changed between the build and execution phases; refusing to execute (built {built:?}, now {now:?})"
    )]
    IdentityChanged {
        built: Vec<AdmittedArtifact>,
        now: Vec<AdmittedArtifact>,
    },
    #[error("signed phase: {0}")]
    Stage(String),
}

/// Identity of one artifact the execution phase runs. CDHash and LC_UUID
/// are read where the host signs (macOS); SHA-256 is always present.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmittedArtifact {
    pub path: PathBuf,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdhash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lc_uuid: Option<String>,
}

/// One signed run's admission record: the lease each phase actually held
/// and the artifact identity carried from build to execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAdmission {
    pub build_lease: HostLeaseMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execute_lease: Option<HostLeaseMode>,
    pub artifacts: Vec<AdmittedArtifact>,
}

#[derive(clap::Args, Debug)]
pub struct SignedPhasesArgs {
    /// Directory shared by both phases (default: a fresh temporary directory).
    #[arg(long)]
    pub state: Option<PathBuf>,
    #[arg(long, help = "Refuse yes/stress/stress-ng unless CARRICK_ALLOW_LOAD=1")]
    pub check_load: bool,
    /// One phase inside its supervised lease; set only by the driver.
    #[arg(long, value_enum, hide = true)]
    pub stage: Option<SignedPhase>,
    #[arg(
        trailing_var_arg = true,
        required = true,
        allow_hyphen_values = true,
        help = "Command run once per phase with CARRICK_SIGNED_PHASE=build|execute"
    )]
    pub command: Vec<OsString>,
}

pub fn run_cli(args: SignedPhasesArgs) -> Result<i32, SignedPhaseError> {
    match (args.stage, args.state) {
        (Some(stage), Some(state)) => run_stage(stage, &state, &args.command, &host_identity),
        (Some(_), None) => Err(SignedPhaseError::Stage("--stage requires --state".into())),
        (None, Some(state)) => run(&state, args.check_load, &args.command),
        (None, None) => {
            let state = tempfile::Builder::new()
                .prefix("carrick-signed-phases-")
                .tempdir()
                .map_err(|source| SignedPhaseError::Io {
                    path: std::env::temp_dir(),
                    source,
                })?;
            run(state.path(), args.check_load, &args.command)
        }
    }
}

/// Build under `carrick`, then execute under `gate`, never holding both.
pub fn run(state: &Path, check_load: bool, command: &[OsString]) -> Result<i32, SignedPhaseError> {
    if command.is_empty() {
        return Err(HostLeaseError::EmptyCommand.into());
    }
    // An inherited shared lease can never become gate; refuse before the
    // build spends its time. An inherited gate serves both phases.
    if HostLease::inherited() {
        drop(HostLease::acquire(HostLeaseMode::Gate)?);
    }
    fs::create_dir_all(state).map_err(|source| SignedPhaseError::Io {
        path: state.to_path_buf(),
        source,
    })?;
    let state = fs::canonicalize(state).map_err(|source| SignedPhaseError::Io {
        path: state.to_path_buf(),
        source,
    })?;
    for stale in [ARTIFACTS_FILE, IDENTITY_FILE, ADMISSION_FILE] {
        match fs::remove_file(state.join(stale)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(SignedPhaseError::Io {
                    path: state.join(stale),
                    source: error,
                });
            }
            _ => {}
        }
    }
    let executable = std::env::current_exe().map_err(|source| SignedPhaseError::Io {
        path: PathBuf::from("current executable"),
        source,
    })?;
    for phase in [SignedPhase::Build, SignedPhase::Execute] {
        let mut staged: Vec<OsString> = vec![
            executable.clone().into_os_string(),
            "signed-phases".into(),
            "--stage".into(),
            phase.as_str().into(),
            "--state".into(),
            state.clone().into_os_string(),
            "--".into(),
        ];
        staged.extend(command.iter().cloned());
        // Each phase is one complete supervised run: its lease is released,
        // including cleanup, before the next phase requests its own.
        let code = crate::host_lease::run_command(phase.lease_mode(), check_load, &staged)?;
        if code != 0 {
            return Ok(code);
        }
    }
    Ok(0)
}

/// One phase, inside the lease its supervisor holds.
pub fn run_stage(
    phase: SignedPhase,
    state: &Path,
    command: &[OsString],
    probe: &dyn Fn(&Path) -> Result<AdmittedArtifact, String>,
) -> Result<i32, SignedPhaseError> {
    if !HostLease::inherited() {
        return Err(SignedPhaseError::Stage(
            "a phase runs only inside its supervised lease; use signed-phases without --stage"
                .into(),
        ));
    }
    let lease = HostLease::acquire(phase.lease_mode())?;
    match phase {
        SignedPhase::Build => {
            let code = run_phase_command(&lease, phase, state, command)?;
            if code != 0 {
                return Ok(code);
            }
            let paths = read_artifact_list(state)?;
            let identity = SignedAdmission {
                build_lease: lease.mode(),
                execute_lease: None,
                artifacts: capture(&paths, probe)?,
            };
            write_json(&state.join(IDENTITY_FILE), &identity)?;
            Ok(0)
        }
        SignedPhase::Execute => {
            let built: SignedAdmission = read_json(&state.join(IDENTITY_FILE))?;
            let paths: Vec<PathBuf> = built.artifacts.iter().map(|a| a.path.clone()).collect();
            let now = capture(&paths, probe)?;
            if now != built.artifacts {
                return Err(SignedPhaseError::IdentityChanged {
                    built: built.artifacts,
                    now,
                });
            }
            let admission = SignedAdmission {
                execute_lease: Some(lease.mode()),
                ..built
            };
            write_json(&state.join(ADMISSION_FILE), &admission)?;
            eprintln!(
                "signed-phases: {} artifact(s) unchanged since the build phase; executing under {}",
                admission.artifacts.len(),
                lease.mode()
            );
            run_phase_command(&lease, phase, state, command)
        }
    }
}

/// The admission record the execution phase wrote, for receipts.
pub fn read_admission(state: &Path) -> Result<SignedAdmission, SignedPhaseError> {
    read_json(&state.join(ADMISSION_FILE))
}

/// Record artifacts for admission. Paths must be absolute.
pub fn append_artifacts(state: &Path, paths: &[PathBuf]) -> Result<(), SignedPhaseError> {
    use std::io::Write;
    let path = state.join(ARTIFACTS_FILE);
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|source| SignedPhaseError::Io {
            path: path.clone(),
            source,
        })?;
    for artifact in paths {
        writeln!(file, "{}", artifact.display()).map_err(|source| SignedPhaseError::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(())
}

fn run_phase_command(
    lease: &HostLease,
    phase: SignedPhase,
    state: &Path,
    command: &[OsString],
) -> Result<i32, SignedPhaseError> {
    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    lease
        .configure_command(&mut child)
        .map_err(|source| SignedPhaseError::Io {
            path: lease.path().to_path_buf(),
            source,
        })?;
    child.env(PHASE_ENV, phase.as_str()).env(STATE_ENV, state);
    let status = child.status().map_err(|source| HostLeaseError::Spawn {
        cmd: command[0].to_string_lossy().into_owned(),
        source,
    })?;
    Ok(extract_exit_code(&status))
}

fn read_artifact_list(state: &Path) -> Result<Vec<PathBuf>, SignedPhaseError> {
    let path = state.join(ARTIFACTS_FILE);
    let text = fs::read_to_string(&path).map_err(|source| SignedPhaseError::Io {
        path: path.clone(),
        source,
    })?;
    let mut paths: Vec<PathBuf> = text
        .lines()
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect();
    if let Some(relative) = paths.iter().find(|path| !path.is_absolute()) {
        return Err(SignedPhaseError::Probe(format!(
            "artifact path '{}' is not absolute",
            relative.display()
        )));
    }
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Err(SignedPhaseError::Probe(
            "the build phase listed no artifacts to admit".into(),
        ));
    }
    Ok(paths)
}

fn capture(
    paths: &[PathBuf],
    probe: &dyn Fn(&Path) -> Result<AdmittedArtifact, String>,
) -> Result<Vec<AdmittedArtifact>, SignedPhaseError> {
    paths
        .iter()
        .map(|path| probe(path).map_err(SignedPhaseError::Probe))
        .collect()
}

/// SHA-256 everywhere; CDHash and LC_UUID from the signed Mach-O on macOS.
pub fn host_identity(path: &Path) -> Result<AdmittedArtifact, String> {
    if cfg!(target_os = "macos") {
        let identity = crate::accept::inspect_executable(path)?;
        return Ok(AdmittedArtifact {
            path: identity.path,
            sha256: identity.sha256,
            cdhash: Some(identity.cdhash),
            lc_uuid: Some(identity.lc_uuid),
        });
    }
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read '{}': {error}", path.display()))?;
    Ok(AdmittedArtifact {
        path: path.to_path_buf(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        cdhash: None,
        lc_uuid: None,
    })
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, SignedPhaseError> {
    let bytes = fs::read(path).map_err(|source| SignedPhaseError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|error| SignedPhaseError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, error),
    })
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), SignedPhaseError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| SignedPhaseError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, error),
    })?;
    crate::atomic_file::write(path, &bytes).map_err(|source| SignedPhaseError::Io {
        path: path.to_path_buf(),
        source,
    })
}
