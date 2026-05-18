use std::path::PathBuf;

use anyhow::{Context, bail};
use carrick::compat::{CompatReportFormat, CompatReporter, SyscallArgs};
use carrick::dispatch::{LinearMemory, SyscallDispatcher, SyscallRequest};
use carrick::elf::{inspect_elf, plan_elf_load};
use carrick::memory::AddressSpace;
use carrick::oci::{ImageReference, ImageStore, pull_image};
use carrick::rootfs::RootFs;
use carrick::runtime::{
    DEFAULT_MAX_TRAPS, run_static_elf_bytes_with_hvf_and_dispatcher,
    run_static_elf_with_hvf_and_dispatcher,
};
use carrick::syscall::{aarch64_table, lookup_aarch64};
use carrick::trap::hvf_capabilities;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[arg(long, env = "CARRICK_HOME", global = true)]
    store: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    InspectElf {
        path: PathBuf,
    },
    PlanElfLoad {
        path: PathBuf,
    },
    LoadElf {
        path: PathBuf,
        #[arg(long)]
        find_text: Option<String>,
    },
    RunElf {
        path: PathBuf,
        #[arg(long = "rootfs-layer")]
        rootfs_layers: Vec<PathBuf>,
        #[arg(long, default_value_t = DEFAULT_MAX_TRAPS)]
        max_traps: usize,
    },
    Pull {
        image: String,
    },
    Run {
        image: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    Shell {
        #[arg(default_value = "alpine:latest")]
        image: String,
    },
    Exec {
        context: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    CompatReport {
        #[arg(long, value_enum, default_value_t = CompatReportFormat::Json)]
        format: CompatReportFormat,
        #[arg(last = true)]
        command: Vec<String>,
    },
    DispatchSyscall {
        number: u64,
        #[arg(long, value_delimiter = ',')]
        args: Vec<u64>,
        #[arg(long, default_value_t = 0x4000)]
        memory_base: u64,
        #[arg(long, default_value = "")]
        memory_text: String,
    },
    Rootfs {
        #[arg(long = "layer", required = true)]
        layers: Vec<PathBuf>,
        #[command(subcommand)]
        command: RootfsCommand,
    },
    Syscalls {
        #[arg(long)]
        number: Option<u64>,
    },
    TrapCapabilities,
}

#[derive(Debug, Subcommand)]
enum RootfsCommand {
    Summary,
    Ls { path: PathBuf },
    Cat { path: PathBuf },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    register_dtrace_probes();

    let cli = Cli::parse();
    let store = cli
        .store
        .map(ImageStore::new)
        .unwrap_or_else(ImageStore::default_for_user);

    match cli.command {
        Commands::InspectElf { path } => {
            let metadata = inspect_elf(&path)
                .with_context(|| format!("failed to inspect {}", path.display()))?;
            println!("{}", serde_json::to_string_pretty(&metadata)?);
        }
        Commands::PlanElfLoad { path } => {
            let plan = plan_elf_load(&path)
                .with_context(|| format!("failed to plan ELF load for {}", path.display()))?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
        }
        Commands::LoadElf { path, find_text } => {
            let image = AddressSpace::load_elf(&path)
                .with_context(|| format!("failed to load ELF image for {}", path.display()))?;
            let found_address = find_text
                .as_ref()
                .and_then(|needle| image.find_bytes(needle.as_bytes()));
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "entry": image.entry(),
                    "region_count": image.regions().len(),
                    "regions": image.regions(),
                    "found_address": found_address,
                }))?
            );
        }
        Commands::RunElf {
            path,
            rootfs_layers,
            max_traps,
        } => {
            let dispatcher = if rootfs_layers.is_empty() {
                SyscallDispatcher::new()
            } else {
                SyscallDispatcher::with_rootfs(
                    RootFs::from_layer_paths(&rootfs_layers)
                        .context("failed to compose rootfs layers")?,
                )
            };
            let result = run_static_elf_with_hvf_and_dispatcher(&path, dispatcher, max_traps)
                .with_context(|| format!("failed to run static ELF {}", path.display()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "path": path,
                    "rootfs_layers": rootfs_layers,
                    "exit_code": result.exit_code,
                    "stdout": String::from_utf8_lossy(&result.stdout),
                    "stderr": String::from_utf8_lossy(&result.stderr),
                    "traps": result.traps,
                    "report": result.report,
                }))?
            );
        }
        Commands::Pull { image } => {
            let image = ImageReference::parse(&image)?;
            let summary = pull_image(&image, &store).await?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Commands::Run { image, command } => {
            let image = ImageReference::parse(&image)?;
            let command = if command.is_empty() {
                vec!["/bin/sh".to_owned()]
            } else {
                command
            };
            if command.len() != 1 {
                bail!(
                    "guest argv/env stack setup is not implemented yet; pass only the executable path"
                );
            }
            let summary = store.load_pull_summary(&image).await.with_context(|| {
                format!("image {} is not pulled into the store", image.canonical())
            })?;
            let rootfs_layers: Vec<PathBuf> = summary
                .layers
                .iter()
                .map(|layer| layer.path.clone())
                .collect();
            let rootfs = RootFs::from_layer_paths(&rootfs_layers)
                .context("failed to compose image rootfs layers")?;
            let executable_path = &command[0];
            let executable = rootfs.read(executable_path.as_str()).with_context(|| {
                format!("failed to read executable {executable_path} from rootfs")
            })?;
            let result = run_static_elf_bytes_with_hvf_and_dispatcher(
                &executable,
                SyscallDispatcher::with_rootfs(rootfs),
                DEFAULT_MAX_TRAPS,
            )
            .with_context(|| {
                format!(
                    "failed to run static ELF {} from image {}",
                    executable_path,
                    image.canonical()
                )
            })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "image": image.canonical(),
                    "command": command,
                    "store": store.root(),
                    "rootfs_layers": rootfs_layers,
                    "exit_code": result.exit_code,
                    "stdout": String::from_utf8_lossy(&result.stdout),
                    "stderr": String::from_utf8_lossy(&result.stderr),
                    "traps": result.traps,
                    "report": result.report,
                    "trap": hvf_capabilities(),
                }))?
            );
        }
        Commands::Shell { image } => {
            let image = ImageReference::parse(&image)?;
            println!(
                "{}",
                serde_json::json!({
                    "image": image.canonical(),
                    "command": ["/bin/sh"],
                    "store": store.root(),
                    "trap": hvf_capabilities(),
                })
            );
            bail!("interactive Linux shell execution is not implemented in this bootstrap yet");
        }
        Commands::Exec { context, command } => {
            println!(
                "{}",
                serde_json::json!({
                    "context": context,
                    "command": command,
                })
            );
            bail!("existing Carrick execution contexts are not implemented in this bootstrap yet");
        }
        Commands::CompatReport { format, command } => {
            if command.is_empty() {
                bail!("compat-report needs a command after --");
            }
            eprintln!(
                "compat-report runtime hooks are scaffolded; returning an empty report for {:?}",
                command
            );
            let report = CompatReporter::default().finish();
            println!("{}", report.render(format)?);
        }
        Commands::DispatchSyscall {
            number,
            args,
            memory_base,
            memory_text,
        } => {
            if args.len() != 6 {
                bail!("dispatch-syscall requires exactly six --args values");
            }
            let mut memory = LinearMemory::new(memory_base, memory_text.into_bytes());
            let mut dispatcher = SyscallDispatcher::new();
            let mut reporter = CompatReporter::default();
            let outcome = dispatcher.dispatch(
                SyscallRequest::new(
                    number,
                    SyscallArgs::from([args[0], args[1], args[2], args[3], args[4], args[5]]),
                ),
                &mut memory,
                &mut reporter,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "outcome": outcome,
                    "stdout": String::from_utf8_lossy(dispatcher.stdout()),
                    "stderr": String::from_utf8_lossy(dispatcher.stderr()),
                    "report": reporter.finish(),
                }))?
            );
        }
        Commands::Rootfs { layers, command } => {
            let rootfs = RootFs::from_layer_paths(&layers)?;
            match command {
                RootfsCommand::Summary => {
                    println!("{}", serde_json::to_string_pretty(&rootfs.summary())?);
                }
                RootfsCommand::Ls { path } => {
                    for name in rootfs.list_dir(path)? {
                        println!("{name}");
                    }
                }
                RootfsCommand::Cat { path } => {
                    print!("{}", rootfs.read_to_string(path)?);
                }
            }
        }
        Commands::Syscalls { number } => {
            if let Some(number) = number {
                let syscall = lookup_aarch64(number)
                    .with_context(|| format!("unknown Linux/aarch64 syscall {}", number))?;
                println!("{}", serde_json::to_string_pretty(syscall)?);
            } else {
                println!("{}", serde_json::to_string_pretty(aarch64_table())?);
            }
        }
        Commands::TrapCapabilities => {
            println!("{}", serde_json::to_string_pretty(&hvf_capabilities())?);
        }
    }

    Ok(())
}

fn register_dtrace_probes() {
    if let Err(err) = carrick::probes::register_dtrace_probes() {
        tracing::debug!("failed to register DTrace probes: {err}");
    }
}
