use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use carrick::compat::{CompatReportFormat, CompatReporter, SyscallArgs};
use carrick::dispatch::{LinearMemory, SyscallDispatcher, SyscallRequest};
use carrick::elf::{inspect_elf, plan_elf_load};
use carrick::fs_backend::{FsBackend, HostFsBackend, MemoryBackend};
use carrick::memory::AddressSpace;
use carrick::oci::{ImageReference, ImageStore, pull_image};
use carrick::rootfs::RootFs;
use carrick::runtime::{
    DEFAULT_MAX_TRAPS, DebugStateSnapshot, run_rootfs_elf_with_hvf_args_and_dispatcher_debug,
    run_static_elf_with_hvf_args_and_dispatcher_debug,
};
use carrick::syscall::{aarch64_table, lookup_aarch64};
use carrick::trap::hvf_capabilities;
use clap::{Parser, Subcommand};

/// Which writable-layer backend to install on the SyscallDispatcher.
/// See `src/fs_backend.rs` for the trait and both implementations.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum FsBackendKind {
    /// In-memory tmpfs. Fast, ephemeral, ideal for CI/tests/one-shots.
    Memory,
    /// Host APFS scratch directory, sandboxed via cap-std. Durable,
    /// reflink-seeded, the secure-by-default production option.
    Host,
}

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
        /// Write a JSON dump of the guest address-space layout (PIE base,
        /// interpreter base, HVF mappings, vector + trampoline pages) to
        /// this path BEFORE starting the vCPU. The dump is what the
        /// `carrick.lldb` Python plugin reads to translate guest addresses
        /// back to image / segment / file context.
        #[arg(long = "debug-state-path")]
        debug_state_path: Option<PathBuf>,
        /// Suppress the JSON compat-report envelope. The guest's stdout
        /// goes to the carrick process's stdout, stderr to stderr, and
        /// the host exit code matches the guest's exit_group code.
        /// Makes carrick feel like a normal command runner.
        #[arg(long)]
        raw: bool,
        /// Which writable-layer backend to use. Defaults to `host` on
        /// case-sensitive volumes (APFS scratch dir + cap-std sandbox)
        /// and `memory` elsewhere (in-memory tmpfs).
        #[arg(long, value_enum)]
        fs: Option<FsBackendKind>,
        #[arg(last = true)]
        args: Vec<String>,
    },
    Pull {
        image: String,
    },
    Run {
        image: String,
        #[arg(long, default_value_t = DEFAULT_MAX_TRAPS)]
        max_traps: usize,
        /// See `run-elf --debug-state-path`.
        #[arg(long = "debug-state-path")]
        debug_state_path: Option<PathBuf>,
        /// Suppress the JSON compat-report envelope.
        #[arg(long)]
        raw: bool,
        /// Which writable-layer backend to use. Defaults to `host` on
        /// case-sensitive volumes (APFS scratch dir + cap-std sandbox)
        /// and `memory` elsewhere (in-memory tmpfs).
        #[arg(long, value_enum)]
        fs: Option<FsBackendKind>,
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
    /// Tools for debugging Carrick under lldb. Pairs with the Python plugin
    /// at `scripts/carrick_lldb.py`.
    Debug {
        #[command(subcommand)]
        command: DebugCommand,
    },
    /// Run a carrick command under DTrace, in-process. Compiles the bundled
    /// D script via libdtrace, spawns the child carrick under
    /// `dtrace_proc_create`, and streams live per-syscall events + a
    /// frequency-sorted aggregation when the child exits. Requires root.
    Trace {
        /// Enable dtrace(1) `-F` style flow indentation. Each `entry/`
        /// or `return/` event in the live stream is indented by call
        /// depth, making it easier to follow nested syscall paths.
        #[arg(short = 'F', long = "flowindent")]
        flowindent: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Manage the dedicated APFS subvolume Carrick uses for its
    /// writable scratch space. The volume is case-sensitive (which
    /// Linux paths require) and lives at /Volumes/carrick. Internally
    /// this shells out to `diskutil(8)` — no Apple private framework
    /// dependency, no FFI surface.
    #[cfg(target_os = "macos")]
    Volume {
        #[command(subcommand)]
        command: VolumeCommand,
    },
}

#[cfg(target_os = "macos")]
#[derive(Debug, Subcommand)]
enum VolumeCommand {
    /// Create the carrick scratch volume if it doesn't exist. Adds a
    /// case-sensitive APFS subvolume (APFSX) to the boot container so
    /// it shares the boot disk's free space. Idempotent.
    Create {
        /// Optional quota in bytes. Without one the volume grows up
        /// to the container's free space.
        #[arg(long)]
        quota: Option<u64>,
    },
    /// Print the carrick scratch volume's device, mount point, and
    /// case-sensitivity flag. Nonzero exit if no volume exists yet.
    Info,
    /// Delete the carrick scratch volume. Destructive — anything on
    /// the volume is lost. Idempotent.
    Delete {
        /// Required confirmation; without `--yes` this is a no-op
        /// that prints the volume info and exits 0.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum DebugCommand {
    /// Decode an AArch64 ESR_EL1 value into its exception class, IL, ISS
    /// (with DFSC for data aborts) so the operator doesn't have to hand-
    /// parse syndromes during an interactive session.
    DecodeEsr {
        /// Syndrome value, hex (0xN) or decimal.
        syndrome: String,
    },
    /// Print the path to the `carrick_lldb.py` plugin so the operator can
    /// `command script import` it from their lldb session.
    LldbPlugin,
    /// Read the JSON dumped by `run --debug-state-path` and print it as a
    /// human-readable summary. Useful for one-shot inspection without lldb.
    InspectState {
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RootfsCommand {
    Summary,
    Ls { path: PathBuf },
    Cat { path: PathBuf },
}

/// We deliberately do NOT use `#[tokio::main]`: a multi-thread tokio
/// runtime initialised before the trap loop poisons every child of a
/// `fork(2)` we perform inside a syscall handler. The worker threads
/// don't exist in the child, the I/O driver's kqueue fd state is
/// out-of-sync, and panic-on-stdio-flush is the polite failure mode.
///
/// Async work (image pulls, summary reads) runs inside a short-lived
/// current-thread runtime that drops before the trap loop even begins,
/// so by the time fork can fire there is no tokio state to break.
fn main() -> anyhow::Result<()> {
    // Ignore SIGPIPE in the host so a guest writing to a closed
    // pipe end (eg `ls | head` after head exits) gets EPIPE from
    // libc::write instead of having the host carrick process killed
    // by SIGPIPE. The dispatcher then translates EPIPE into the
    // guest's errno; the guest sees Linux's standard EPIPE behavior.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    // Disable Apple's os_log activity tracing for this process tree.
    // Hypervisor.framework's `hv_vcpu_create` initializes an os_log
    // handle internally, and that handle is NOT fork-safe — a forked
    // child calling `hv_vcpu_create` crashes inside `_os_log_find`
    // with EXC_BAD_ACCESS ~14% of the time (verified via macOS
    // DiagnosticReports). Setting OS_ACTIVITY_MODE=disable before any
    // HVF call drops os_log out of the path entirely and makes
    // repeated fork() + hv_vcpu_create cycles deterministic.
    unsafe {
        let key = std::ffi::CString::new("OS_ACTIVITY_MODE").unwrap();
        let val = std::ffi::CString::new("disable").unwrap();
        libc::setenv(key.as_ptr(), val.as_ptr(), 1);
    }

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
            debug_state_path,
            raw,
            fs,
            args,
        } => {
            let mut dispatcher = if rootfs_layers.is_empty() {
                SyscallDispatcher::new()
            } else {
                SyscallDispatcher::with_rootfs(
                    RootFs::from_layer_paths(&rootfs_layers)
                        .context("failed to compose rootfs layers")?,
                )
            };
            install_fs_backend(&mut dispatcher, fs)?;
            if raw {
                dispatcher.set_stream_stdio(true);
            }
            let mut argv = vec![path.to_string_lossy().into_owned()];
            argv.extend(args);
            let result = run_static_elf_with_hvf_args_and_dispatcher_debug(
                &path,
                dispatcher,
                argv,
                std::iter::empty(),
                max_traps,
                debug_state_path.as_ref(),
            )
            .with_context(|| format!("failed to run static ELF {}", path.display()))?;
            if raw {
                emit_raw(&result);
                std::process::exit(if result.trap_limit_hit {
                    1
                } else {
                    result.exit_code
                });
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "path": path,
                    "rootfs_layers": rootfs_layers,
                    "exit_code": result.exit_code,
                    "stdout": String::from_utf8_lossy(&result.stdout),
                    "stderr": String::from_utf8_lossy(&result.stderr),
                    "traps": result.traps,
                    "trap_limit_hit": result.trap_limit_hit,
                    "report": result.report,
                }))?
            );
            if result.trap_limit_hit {
                bail!(
                    "guest did not exit after {} traps (compat report above)",
                    result.traps
                );
            }
        }
        Commands::Pull { image } => {
            let image = ImageReference::parse(&image)?;
            let summary = block_on_oci(pull_image(&image, &store))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Commands::Run {
            image,
            max_traps,
            debug_state_path,
            raw,
            fs,
            command,
        } => {
            let image = ImageReference::parse(&image)?;
            let command = if command.is_empty() {
                vec!["/bin/sh".to_owned()]
            } else {
                command
            };
            let summary = block_on_oci(store.load_pull_summary(&image)).with_context(|| {
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
            let mut dispatcher = SyscallDispatcher::with_rootfs_and_executable(
                rootfs.clone(),
                executable_path.clone(),
            );
            install_fs_backend(&mut dispatcher, fs)?;
            if raw {
                // Stream guest fd 1/2 straight to host fds 1/2 so
                // interactive prompts (`/ # `, ANSI cursor queries) reach
                // the user's terminal before the guest exits.
                dispatcher.set_stream_stdio(true);
            }
            // Provide a sane default Linux env. Without PATH glibc-based
            // tools like dpkg-query bail with "PATH is not set" and apt's
            // pre-fork helpers (apt-config, dpkg-query) can't locate their
            // siblings.
            let env: Vec<String> = vec![
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
                "HOME=/root".to_owned(),
                "TERM=xterm-256color".to_owned(),
                "LANG=C.UTF-8".to_owned(),
                "LC_ALL=C.UTF-8".to_owned(),
                "DEBIAN_FRONTEND=noninteractive".to_owned(),
                "PAGER=cat".to_owned(),
            ];
            let result = run_rootfs_elf_with_hvf_args_and_dispatcher_debug(
                executable_path.as_str(),
                &rootfs,
                dispatcher,
                command.clone(),
                env,
                max_traps,
                debug_state_path.as_ref(),
            )
            .with_context(|| {
                format!(
                    "failed to run ELF {} from image {}",
                    executable_path,
                    image.canonical()
                )
            })?;
            if raw {
                emit_raw(&result);
                std::process::exit(if result.trap_limit_hit {
                    1
                } else {
                    result.exit_code
                });
            }
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
                    "trap_limit_hit": result.trap_limit_hit,
                    "report": result.report,
                    "trap": hvf_capabilities(),
                }))?
            );
            if result.trap_limit_hit {
                bail!(
                    "guest did not exit after {} traps (compat report above)",
                    result.traps
                );
            }
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
                    use std::io::Write;
                    let bytes = rootfs.read(path)?;
                    std::io::stdout().write_all(&bytes)?;
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
        Commands::Debug { command } => match command {
            DebugCommand::DecodeEsr { syndrome } => {
                let stripped = syndrome.trim();
                let value = if let Some(hex) = stripped.strip_prefix("0x").or_else(|| stripped.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16)?
                } else {
                    stripped.parse::<u64>()?
                };
                println!("{}", serde_json::to_string_pretty(&decode_esr_el1(value))?);
            }
            DebugCommand::LldbPlugin => {
                let manifest_dir = env!("CARGO_MANIFEST_DIR");
                let path = std::path::Path::new(manifest_dir)
                    .join("scripts")
                    .join("carrick_lldb.py");
                if !path.exists() {
                    eprintln!(
                        "warning: lldb plugin not found at {} (CARGO_MANIFEST_DIR may not match runtime tree)",
                        path.display()
                    );
                }
                println!("{}", path.display());
            }
            DebugCommand::InspectState { path } => {
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                let state: DebugStateSnapshot = serde_json::from_slice(&bytes)
                    .with_context(|| format!("failed to parse {}", path.display()))?;
                println!("{}", serde_json::to_string_pretty(&state)?);
            }
        },
        Commands::Trace { flowindent, command } => {
            #[cfg(target_os = "macos")]
            {
                if command.is_empty() {
                    bail!(
                        "trace needs a carrick subcommand to forward (e.g. `carrick trace run alpine:latest /bin/busybox echo hi`)"
                    );
                }
                let me = std::env::current_exe()
                    .context("failed to resolve current carrick binary path")?;
                if unsafe { libc::geteuid() } != 0 {
                    eprintln!(
                        "carrick trace: not running as root; libdtrace will fail to open /dev/dtrace."
                    );
                    eprintln!(
                        "carrick trace: re-invoke as `sudo {} trace ...`",
                        me.display()
                    );
                }
                let opts = carrick::dtrace_consumer::TraceOptions { flowindent };
                carrick::dtrace_consumer::run_child_under_dtrace(&me, &command, &opts)
                    .map_err(|e| anyhow::anyhow!("trace failed: {}", e))?;
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (flowindent, command);
                bail!("carrick trace is only available on macOS (libdtrace).");
            }
        }
        #[cfg(target_os = "macos")]
        Commands::Volume { command } => match command {
            VolumeCommand::Create { quota } => {
                let v = carrick::apfs::create_carrick_volume(quota)
                    .context("failed to create carrick scratch volume")?;
                println!(
                    "{} {} {} case-sensitive={}",
                    v.device,
                    v.name,
                    v.mount_point
                        .as_deref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "Not Mounted".to_owned()),
                    v.case_sensitive,
                );
            }
            VolumeCommand::Info => {
                match carrick::apfs::find_carrick_volume()
                    .context("failed to query carrick scratch volume")?
                {
                    Some(v) => {
                        println!(
                            "{} {} {} case-sensitive={}",
                            v.device,
                            v.name,
                            v.mount_point
                                .as_deref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "Not Mounted".to_owned()),
                            v.case_sensitive,
                        );
                    }
                    None => {
                        bail!(
                            "no carrick scratch volume found; run `carrick volume create` to lay one down"
                        );
                    }
                }
            }
            VolumeCommand::Delete { yes } => {
                let Some(v) = carrick::apfs::find_carrick_volume()
                    .context("failed to query carrick scratch volume")?
                else {
                    println!("no carrick scratch volume to delete");
                    return Ok(());
                };
                if !yes {
                    println!(
                        "would delete {} ({}); pass --yes to confirm",
                        v.device,
                        v.name,
                    );
                    return Ok(());
                }
                carrick::apfs::delete_carrick_volume()
                    .context("failed to delete carrick scratch volume")?;
                println!("deleted {} ({})", v.device, v.name);
            }
        },
    }

    Ok(())
}


/// Resolve `--fs <memory|host>` into a concrete `Box<dyn FsBackend>`
/// and install it on the dispatcher. When the user did not pass an
/// explicit `--fs`, the default is `host` iff the scratch root sits
/// on a case-sensitive volume (the only place Linux semantics survive
/// intact) and `memory` otherwise, with a stderr warning.
///
/// If `--fs host` is requested but the cap-std scratch directory
/// cannot be constructed (e.g. `HOME` is unwritable) we fall back to
/// the in-memory backend with a warning rather than failing the run.
fn install_fs_backend(
    dispatcher: &mut SyscallDispatcher,
    fs: Option<FsBackendKind>,
) -> anyhow::Result<()> {
    let kind = fs.unwrap_or_else(default_fs_backend_kind);
    let backend: Box<dyn FsBackend> = match kind {
        FsBackendKind::Memory => Box::new(MemoryBackend::new()),
        FsBackendKind::Host => match HostFsBackend::new() {
            Ok(host) => Box::new(host),
            Err(err) => {
                eprintln!(
                    "carrick: --fs host failed ({err}); falling back to in-memory backend"
                );
                Box::new(MemoryBackend::new())
            }
        },
    };
    let _ = dispatcher.set_fs_backend(backend);
    Ok(())
}

/// Default backend choice: prefer `host` because that's the secure-
/// by-default option, but quietly fall back to `memory` when the
/// scratch root sits on a case-insensitive filesystem (a common
/// macOS default that breaks anything assuming Linux semantics).
fn default_fs_backend_kind() -> FsBackendKind {
    let probe = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".carrick").join("scratch"))
        .unwrap_or_else(|| std::env::temp_dir().join("carrick-scratch"));
    if std::fs::create_dir_all(&probe).is_err() {
        return FsBackendKind::Memory;
    }
    if probe_case_sensitive(&probe).unwrap_or(false) {
        FsBackendKind::Host
    } else {
        eprintln!(
            "carrick: {} is case-insensitive; defaulting --fs to memory. \
             Pass `--fs host` to force the cap-std backend (some Linux tools may misbehave).",
            probe.display()
        );
        FsBackendKind::Memory
    }
}

/// Detect whether `path` lives on a case-sensitive volume by creating
/// a sentinel file and trying to canonicalise the same path with the
/// case flipped. We do NOT trust statfs flags here because APFS
/// volumes routinely return MNT_NOATIME-style flags that say nothing
/// about case-sensitivity.
fn probe_case_sensitive(path: &Path) -> std::io::Result<bool> {
    let lower = path.join(".carrick-case-probe");
    let upper = path.join(".CARRICK-CASE-PROBE");
    std::fs::write(&lower, b"")?;
    let sensitive = if upper.exists() {
        // If the kernel can see the upper-case spelling, it's a
        // case-insensitive volume.
        std::fs::canonicalize(&upper).ok() != std::fs::canonicalize(&lower).ok()
    } else {
        true
    };
    let _ = std::fs::remove_file(&lower);
    Ok(sensitive)
}

/// When `--raw` is set, emit the guest's buffered stdout/stderr to the
/// carrick host process's fd 1 / fd 2 instead of wrapping them in JSON.
/// This makes carrick feel like a normal command runner: `carrick run
/// alpine /bin/busybox echo hi --raw` prints just `hi`.
fn emit_raw(result: &carrick::runtime::RunResult) {
    use std::io::Write;
    let _ = std::io::stdout().write_all(&result.stdout);
    let _ = std::io::stderr().write_all(&result.stderr);
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
}

/// Run a single OCI-related future on a short-lived current-thread tokio
/// runtime. The runtime is dropped before returning, so by the time the
/// guest issues `clone(2)` and we fork the host process there is no
/// async runtime alive in the parent to corrupt the child.
fn block_on_oci<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build current-thread tokio runtime")
        .block_on(fut)
}

/// Decode an `ESR_EL1` value into a human-readable struct. Mirrors the
/// fields documented in the ARMv8-A ARM and the lldb plugin's table so
/// CLI and lldb give the same answer for a given syndrome.
fn decode_esr_el1(value: u64) -> serde_json::Value {
    let ec = ((value >> 26) & 0x3f) as u8;
    let il = (value >> 25) & 1;
    let iss = value & 0x01_FF_FF_FF;
    let ec_name = match ec {
        0x00 => "Unknown",
        0x01 => "WFI/WFE trap",
        0x07 => "Trapped access to SVE/SIMD/FP (CPACR_EL1.FPEN)",
        0x15 => "SVC instruction (AArch64)",
        0x16 => "HVC instruction (AArch64)",
        0x18 => "MSR/MRS trapped",
        0x20 => "Instruction Abort from a lower EL",
        0x21 => "Instruction Abort from current EL",
        0x22 => "PC alignment fault",
        0x24 => "Data Abort from a lower EL",
        0x25 => "Data Abort from current EL",
        0x26 => "SP alignment fault",
        0x2c => "Trapped floating-point exception",
        0x2f => "SError interrupt",
        _ => "(other)",
    };

    let mut iss_detail = serde_json::Map::new();
    if matches!(ec, 0x20 | 0x21 | 0x24 | 0x25) {
        let dfsc = iss & 0x3f;
        let wnr = (iss >> 6) & 1;
        let s1ptw = (iss >> 7) & 1;
        let cm = (iss >> 8) & 1;
        let ea = (iss >> 9) & 1;
        let sf = (iss >> 15) & 1;
        let srt = (iss >> 16) & 0x1f;
        let isv = (iss >> 24) & 1;
        let dfsc_name = match dfsc {
            0x00 => "Address size fault, level 0",
            0x01 => "Address size fault, level 1",
            0x02 => "Address size fault, level 2",
            0x03 => "Address size fault, level 3",
            0x04 => "Translation fault, level 0",
            0x05 => "Translation fault, level 1",
            0x06 => "Translation fault, level 2",
            0x07 => "Translation fault, level 3",
            0x09 => "Access flag fault, level 1",
            0x0a => "Access flag fault, level 2",
            0x0b => "Access flag fault, level 3",
            0x0d => "Permission fault, level 1",
            0x0e => "Permission fault, level 2",
            0x0f => "Permission fault, level 3",
            0x10 => "Synchronous External abort, not on TT walk",
            0x21 => "Alignment fault",
            0x30 => "TLB conflict abort",
            0x31 => "Unsupported atomic hardware update fault",
            0x34 => "IMPLEMENTATION DEFINED fault (Lockdown)",
            0x35 => "External abort on translation table walk, level 1",
            0x36 => "External abort on translation table walk, level 2",
            0x37 => "External abort on translation table walk, level 3",
            _ => "(other)",
        };
        iss_detail.insert("dfsc".into(), serde_json::Value::from(dfsc));
        iss_detail.insert("dfsc_name".into(), serde_json::Value::from(dfsc_name));
        iss_detail.insert("wnr".into(), serde_json::Value::from(wnr == 1));
        iss_detail.insert("s1ptw".into(), serde_json::Value::from(s1ptw == 1));
        iss_detail.insert("cm".into(), serde_json::Value::from(cm == 1));
        iss_detail.insert("ea_external_abort".into(), serde_json::Value::from(ea == 1));
        iss_detail.insert("sf_64bit_reg".into(), serde_json::Value::from(sf == 1));
        iss_detail.insert("srt_register".into(), serde_json::Value::from(srt));
        iss_detail.insert("isv".into(), serde_json::Value::from(isv == 1));
    }

    serde_json::json!({
        "esr_el1": format!("0x{:x}", value),
        "ec": ec,
        "ec_hex": format!("0x{:02x}", ec),
        "ec_name": ec_name,
        "il": il == 1,
        "iss": format!("0x{:x}", iss),
        "iss_detail": iss_detail,
    })
}

#[cfg(test)]
mod tests {
    use super::decode_esr_el1;

    #[test]
    fn decodes_tier_b_data_abort_syndrome() {
        // Real syndrome captured from musl `ldaxr` failing at the Tier B wall.
        let json = decode_esr_el1(0x92000035);
        assert_eq!(json["ec_hex"], "0x24");
        assert_eq!(json["ec_name"], "Data Abort from a lower EL");
        assert_eq!(json["il"], true);
        assert_eq!(json["iss_detail"]["dfsc"], 53);
        assert_eq!(
            json["iss_detail"]["dfsc_name"],
            "External abort on translation table walk, level 1"
        );
        assert_eq!(json["iss_detail"]["wnr"], false);
        assert_eq!(json["iss_detail"]["isv"], false);
    }

    #[test]
    fn decodes_svc_from_lower_el() {
        // EC=0x15 (SVC AArch64), IL=1, ISS=0 (immediate)
        let json = decode_esr_el1(0x56000000);
        assert_eq!(json["ec_hex"], "0x15");
        assert_eq!(json["ec_name"], "SVC instruction (AArch64)");
        assert_eq!(json["il"], true);
    }

    #[test]
    fn decodes_hvc_from_el1() {
        let json = decode_esr_el1(0x5a000000);
        assert_eq!(json["ec_hex"], "0x16");
        assert_eq!(json["ec_name"], "HVC instruction (AArch64)");
    }
}

fn register_dtrace_probes() {
    match carrick::probes::register_dtrace_probes() {
        Ok(()) => {
            if std::env::var_os("CARRICK_DTRACE_DEBUG").is_some() {
                eprintln!("carrick: dtrace probes registered (pid={})", std::process::id());
            }
        }
        Err(err) => {
            // Always surface registration failures: silent failure here is
            // what makes the dtrace path feel broken.
            eprintln!("carrick: failed to register DTrace probes: {err}");
        }
    }
}
