use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::command::{self, CommandError};

#[derive(Parser, Debug)]
#[command(name = "carrick-xtask", about = "Carrick xtask maintenance tool")]
pub struct Cli {
    #[arg(long, global = true, help = "Path to repository root or worktree")]
    pub root: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Display repository information as JSON")]
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoInfo {
    pub schema_version: u32,
    pub repository_root: PathBuf,
    pub head: String,
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Clap(#[from] clap::Error),

    #[error("command error: {0}")]
    Command(#[from] CommandError),

    #[error("git is unavailable: {0}")]
    GitUnavailable(std::io::Error),

    #[error("invalid git repository at '{}': {details}", path.display())]
    InvalidRepository { path: PathBuf, details: String },

    #[error("git rev-parse HEAD failed at '{}': {details}", path.display())]
    GitHeadFailed { path: PathBuf, details: String },

    #[error("I/O error at '{}': {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to serialize repository info to JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn resolve_repo_info(root: Option<&Path>) -> Result<RepoInfo, CliError> {
    let current_dir;
    let start_path = match root {
        Some(r) => r,
        None => {
            current_dir = std::env::current_dir().map_err(|e| CliError::Io {
                path: PathBuf::from("."),
                source: e,
            })?;
            &current_dir
        }
    };

    if !start_path.exists() {
        return Err(CliError::InvalidRepository {
            path: start_path.to_path_buf(),
            details: "path does not exist".to_string(),
        });
    }

    let toplevel_out =
        match command::run_checked("git", ["rev-parse", "--show-toplevel"], Some(start_path)) {
            Ok(out) => out,
            Err(CommandError::Spawn { source, .. }) => {
                return Err(CliError::GitUnavailable(source));
            }
            Err(CommandError::NonZeroExit { stderr, .. }) => {
                return Err(CliError::InvalidRepository {
                    path: start_path.to_path_buf(),
                    details: stderr.trim().to_string(),
                });
            }
        };

    let toplevel_str = toplevel_out.stdout.trim();
    let toplevel_path = Path::new(toplevel_str);
    let canonical_root = std::fs::canonicalize(toplevel_path).map_err(|e| CliError::Io {
        path: toplevel_path.to_path_buf(),
        source: e,
    })?;

    let head_out = match command::run_checked("git", ["rev-parse", "HEAD"], Some(&canonical_root)) {
        Ok(out) => out,
        Err(CommandError::Spawn { source, .. }) => return Err(CliError::GitUnavailable(source)),
        Err(CommandError::NonZeroExit { stderr, .. }) => {
            return Err(CliError::GitHeadFailed {
                path: canonical_root,
                details: stderr.trim().to_string(),
            });
        }
    };

    let head = head_out.stdout.trim().to_string();

    Ok(RepoInfo {
        schema_version: 1,
        repository_root: canonical_root,
        head,
    })
}

pub fn run<I, T>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    run_with_writer(args, &mut std::io::stdout())
}

pub fn run_with_writer<I, T, W>(args: I, writer: &mut W) -> Result<(), CliError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    W: Write,
{
    let cli = Cli::try_parse_from(args)?;
    match cli.command {
        Commands::Info => {
            let info = resolve_repo_info(cli.root.as_deref())?;
            let json = serde_json::to_string_pretty(&info)?;
            writeln!(writer, "{json}").map_err(|e| CliError::Io {
                path: PathBuf::from("stdout"),
                source: e,
            })?;
            Ok(())
        }
    }
}
