use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, ExitStatus};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("failed to spawn '{program}': {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("command '{program}' failed with {status}:\nstdout:\n{stdout}\nstderr:\n{stderr}")]
    NonZeroExit {
        program: String,
        status: ExitStatus,
        stdout: String,
        stderr: String,
    },
}

impl CommandError {
    pub fn status(&self) -> Option<ExitStatus> {
        match self {
            Self::NonZeroExit { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn stdout(&self) -> Option<&str> {
        match self {
            Self::NonZeroExit { stdout, .. } => Some(stdout),
            _ => None,
        }
    }

    pub fn stderr(&self) -> Option<&str> {
        match self {
            Self::NonZeroExit { stderr, .. } => Some(stderr),
            _ => None,
        }
    }
}

pub fn run_checked<P, S, I>(
    program: P,
    argv: I,
    cwd: Option<&Path>,
) -> Result<CommandOutput, CommandError>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
    I: IntoIterator<Item = S>,
{
    let prog_display = program.as_ref().to_string_lossy().to_string();
    let mut cmd = Command::new(program.as_ref());
    cmd.args(argv);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    let output = cmd.output().map_err(|err| CommandError::Spawn {
        program: prog_display.clone(),
        source: err,
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if !output.status.success() {
        return Err(CommandError::NonZeroExit {
            program: prog_display,
            status: output.status,
            stdout,
            stderr,
        });
    }

    Ok(CommandOutput {
        status: output.status,
        stdout,
        stderr,
    })
}
