use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::command::{self, CommandError};
use crate::probe_coverage::{self, CoverageError};

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

    #[command(about = "Owner-approved, one-job Willow ephemeral runner pilot")]
    CiScaler(crate::ci_scaler::ScalerArgs),

    #[command(about = "Per-landing Carrick vs native Docker receipts")]
    Impact(crate::impact::ImpactArgs),

    #[command(about = "Three-way merge of schema-aware classification ledgers")]
    LedgerMerge {
        #[arg(long, help = "Repo-relative path of the ledger being merged")]
        path: PathBuf,
        #[arg(long, help = "Path to base file")]
        base: PathBuf,
        #[arg(long, help = "Path to ours file")]
        ours: PathBuf,
        #[arg(long, help = "Path to theirs file")]
        theirs: PathBuf,
        #[arg(long, help = "Path to output file")]
        output: PathBuf,
    },

    #[command(
        about = "Regenerate contract inventory using generate-inventory --root <root>, followed by --check"
    )]
    LedgerRegenerateContracts {
        #[arg(long, help = "Path to repository root")]
        root: Option<PathBuf>,
    },

    #[command(about = "Provision guest artifacts before signed execution")]
    Provision(crate::provision::ProvisionArgs),

    #[command(
        about = "Build, restore, or verify immutable signed-tier guest fixtures without Docker"
    )]
    Fixtures(crate::fixtures::FixturesArgs),

    #[command(
        name = "probe-coverage",
        about = "Validate probe inventory coverage against baseline"
    )]
    ProbeCoverage(ProbeCoverageArgs),

    #[command(
        name = "host-lease",
        about = "Run command under machine-global host lease flock (carrick shared, gate/docker exclusive)"
    )]
    HostLease(HostLeaseArgs),

    #[command(about = "Run the host and/or signed landing gate and output a JSON receipt")]
    Accept(crate::accept::AcceptArgs),

    #[command(
        name = "remote-accept",
        about = "Run accept gate on a remote Mac over ssh and fetch the receipt"
    )]
    RemoteAccept(crate::remote_accept::RemoteAcceptArgs),
    #[command(
        about = "Recapture moved host-authority positions on the gate Mac and return a patch"
    )]
    RemoteRecapture(crate::remote_recapture::RemoteRecaptureArgs),
}

#[derive(clap::Args, Debug, Clone)]
pub struct HostLeaseArgs {
    #[arg(
        long,
        value_enum,
        help = "Lock mode: carrick (shared), gate or docker (exclusive)"
    )]
    pub mode: crate::host_lease::HostLeaseMode,

    #[arg(long, help = "Refuse yes/stress/stress-ng unless CARRICK_ALLOW_LOAD=1")]
    pub check_load: bool,

    #[arg(
        trailing_var_arg = true,
        required = true,
        allow_hyphen_values = true,
        help = "Command and arguments to run under the host lease"
    )]
    pub command: Vec<OsString>,
}

#[derive(clap::Args, Debug, Clone)]
pub struct ProbeCoverageArgs {
    #[arg(long, help = "Base commit to validate coverage against")]
    pub base: Option<String>,

    #[arg(
        long,
        help = "Refresh conformance-probes/coverage-base.json to current HEAD and inventory"
    )]
    pub refresh_base: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoInfo {
    pub schema_version: u32,
    pub repository_root: PathBuf,
    pub head: String,
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("ci-scaler: {0}")]
    CiScaler(#[from] crate::ci_scaler::ScalerError),
    #[error("impact: {0}")]
    Impact(String),
    #[error("{0}")]
    Clap(#[from] clap::Error),

    #[error("command error: {0}")]
    Command(#[from] CommandError),

    #[error("coverage error: {0}")]
    Coverage(#[from] CoverageError),

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

    #[error("ledger merge conflict: {0}")]
    MergeConflict(#[from] crate::ledger_merge::MergeConflict),

    #[error("ledger contract regeneration error: {0}")]
    RegenerateContracts(#[from] crate::ledger_merge::RegenerateError),
    #[error("provision error: {0}")]
    Provision(#[from] crate::provision::ProvisionError),
    #[error("fixtures error: {0}")]
    Fixtures(#[from] crate::fixtures::FixturesError),
    #[error("host lease error: {0}")]
    HostLease(#[from] crate::host_lease::HostLeaseError),
    #[error("accept error: {0}")]
    Accept(#[from] crate::accept::AcceptError),
    #[error("remote accept error: {0}")]
    RemoteAccept(#[from] crate::remote_accept::RemoteAcceptError),
    #[error("remote recapture error: {0}")]
    RemoteRecapture(#[from] crate::remote_recapture::RecaptureError),
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
        Commands::CiScaler(args) => {
            crate::ci_scaler::run(args)?;
            Ok(())
        }
        Commands::Impact(args) => crate::impact::run(cli.root.as_deref(), args.action)
            .map_err(|e| CliError::Impact(e.to_string())),
        Commands::Info => {
            let info = resolve_repo_info(cli.root.as_deref())?;
            let json = serde_json::to_string_pretty(&info)?;
            writeln!(writer, "{json}").map_err(|e| CliError::Io {
                path: PathBuf::from("stdout"),
                source: e,
            })?;
            Ok(())
        }
        Commands::LedgerMerge {
            path,
            base,
            ours,
            theirs,
            output,
        } => {
            let base_str = std::fs::read_to_string(&base).map_err(|e| CliError::Io {
                path: base.clone(),
                source: e,
            })?;
            let ours_str = std::fs::read_to_string(&ours).map_err(|e| CliError::Io {
                path: ours.clone(),
                source: e,
            })?;
            let theirs_str = std::fs::read_to_string(&theirs).map_err(|e| CliError::Io {
                path: theirs.clone(),
                source: e,
            })?;

            let path_str = path.to_string_lossy();
            let merged =
                crate::ledger_merge::merge_ledger(&path_str, &base_str, &ours_str, &theirs_str)?;

            let parent_dir = output.parent().unwrap_or_else(|| Path::new("."));
            let file_name = output
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "output".to_string());
            let temp_path = parent_dir.join(format!(".{file_name}.tmp-{}", std::process::id()));

            let write_res = (|| -> Result<(), std::io::Error> {
                let mut f = std::fs::File::create(&temp_path)?;
                f.write_all(merged.to_json().as_bytes())?;
                f.sync_all()?;
                std::fs::rename(&temp_path, &output)?;
                Ok(())
            })();

            if let Err(e) = write_res {
                let _ = std::fs::remove_file(&temp_path);
                return Err(CliError::Io {
                    path: output.clone(),
                    source: e,
                });
            }

            writeln!(writer, "{}", merged.summary()).map_err(|e| CliError::Io {
                path: PathBuf::from("stdout"),
                source: e,
            })?;
            Ok(())
        }
        Commands::LedgerRegenerateContracts { root } => {
            let resolved_root = match root {
                Some(r) => r,
                None => match &cli.root {
                    Some(r) => r.clone(),
                    None => {
                        let info = resolve_repo_info(None)?;
                        info.repository_root
                    }
                },
            };
            crate::ledger_merge::regenerate_contracts(&resolved_root)?;
            writeln!(
                writer,
                "contract inventory regenerated and verified at {}",
                resolved_root.display()
            )
            .map_err(|e| CliError::Io {
                path: PathBuf::from("stdout"),
                source: e,
            })?;
            Ok(())
        }
        Commands::Provision(args) => {
            crate::provision::run(cli.root.as_deref(), args.action, writer)?;
            Ok(())
        }
        Commands::Fixtures(args) => {
            let info = resolve_repo_info(cli.root.as_deref())?;
            crate::fixtures::run(&info.repository_root, args.action, writer)?;
            Ok(())
        }
        Commands::ProbeCoverage(args) => {
            if args.refresh_base {
                probe_coverage::refresh_coverage_base(cli.root.as_deref())?;
                writeln!(writer, "probe-coverage: baseline refreshed").map_err(|e| {
                    CliError::Io {
                        path: PathBuf::from("stdout"),
                        source: e,
                    }
                })?;
            } else {
                probe_coverage::run_probe_coverage(cli.root.as_deref(), args.base.as_deref())?;
                writeln!(writer, "probe-coverage: ok").map_err(|e| CliError::Io {
                    path: PathBuf::from("stdout"),
                    source: e,
                })?;
            }
            Ok(())
        }
        Commands::HostLease(args) => {
            let exit_code =
                crate::host_lease::run_command(args.mode, args.check_load, &args.command)?;
            std::process::exit(exit_code);
        }
        Commands::Accept(args) => {
            crate::accept::run(cli.root.as_deref(), args)?;
            Ok(())
        }
        Commands::RemoteAccept(args) => {
            let exit_code = crate::remote_accept::run(cli.root.as_deref(), args)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }
        Commands::RemoteRecapture(args) => {
            crate::remote_recapture::run(cli.root.as_deref(), args)?;
            Ok(())
        }
    }
}
