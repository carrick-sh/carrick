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
    DEFAULT_MAX_TRAPS, DebugStateSnapshot, run_elf_from_dispatcher_debug,
    run_rootfs_elf_with_hvf_args_and_dispatcher_debug,
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
    /// byte-copied from the unpacked rootfs, the secure-by-default
    /// production option.
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
        /// Allocate a pseudo-terminal and run interactively, bridging the
        /// guest's stdin/stdout to this terminal (like `docker run -it`).
        /// Implies raw stdio.
        #[arg(short = 't', long = "tty")]
        tty: bool,
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
        /// Path to a custom D script to run instead of the bundled
        /// syscall tracer. Lets you write a targeted probe (e.g. fire
        /// only on a specific errno) without paying the full per-syscall
        /// stream cost. The script sees the same carrick USDT providers.
        #[arg(short = 's', long = "script")]
        script: Option<std::path::PathBuf>,
        /// Write DTrace events + aggregations to this file instead of stdout.
        /// Essential when tracing an interactive (`-t`) guest: without it the
        /// probe output intermixes with the guest's own terminal stream. The
        /// traced command's stdio is left untouched.
        #[arg(short = 'o', long = "trace-out", value_name = "FILE")]
        trace_out: Option<std::path::PathBuf>,
        /// Internal: `KEY=VAL` env vars to set in the traced child. Used by
        /// the sudo re-exec to carry CARRICK_* vars across `sudo`'s env_reset
        /// (which would otherwise strip them) without needing SETENV in
        /// sudoers — CLI args survive sudo where env vars don't.
        #[arg(long = "forward-env", value_name = "KEY=VAL")]
        forward_env: Vec<String>,
        /// Internal: original uid before auto-sudo. The trace parent keeps
        /// root for libdtrace, but the traced child drops to this uid.
        #[arg(long = "trace-uid", hide = true)]
        trace_uid: Option<u32>,
        /// Internal: original gid before auto-sudo.
        #[arg(long = "trace-gid", hide = true)]
        trace_gid: Option<u32>,
        /// Internal: original supplementary groups before auto-sudo.
        #[arg(long = "trace-groups", hide = true, value_delimiter = ',')]
        trace_groups: Vec<u32>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    #[command(name = "__trace-child", hide = true)]
    TraceChild {
        #[arg(long = "trace-uid")]
        trace_uid: u32,
        #[arg(long = "trace-gid")]
        trace_gid: u32,
        #[arg(long = "trace-groups", value_delimiter = ',')]
        trace_groups: Vec<u32>,
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
    InspectState { path: PathBuf },
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
/// Wire up guest stdio for a run.
///
/// For a non-interactive `--raw` run this just enables stdio streaming. For an
/// interactive `-t` run it forks a session-leader supervisor that owns the pty
/// and relay; the Carrick runtime continues only in the child process, in a
/// foreground process group under that supervisor. The parent returns an
/// `InteractiveParent` and must call `relay_and_wait()` instead of entering the
/// HVF runtime.
fn setup_interactive_stdio(
    dispatcher: &mut SyscallDispatcher,
    tty: bool,
    raw: bool,
) -> anyhow::Result<Option<carrick::interactive_supervisor::InteractiveParent>> {
    if !tty {
        if raw {
            dispatcher.set_stream_stdio(true);
        }
        return Ok(None);
    }
    match carrick::interactive_supervisor::fork_interactive_session()
        .context("failed to create interactive session supervisor")?
    {
        carrick::interactive_supervisor::SupervisorFork::Parent(parent) => Ok(Some(parent)),
        carrick::interactive_supervisor::SupervisorFork::Child(child) => {
            child
                .adopt_stdio(dispatcher)
                .context("failed to adopt interactive pty in runtime child")?;
            Ok(None)
        }
    }
}

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
    // INVARIANT: both are static string literals with no interior NUL byte, so
    // CString::new cannot fail.
    #[allow(clippy::unwrap_used)]
    unsafe {
        let key = std::ffi::CString::new("OS_ACTIVITY_MODE").unwrap();
        let val = std::ffi::CString::new("disable").unwrap();
        libc::setenv(key.as_ptr(), val.as_ptr(), 1);
    }

    // A guest process is one carrick (host) process; an unimplemented
    // syscall or invariant violation panics it. When that process is a
    // forked child (apt's http method, dpkg, gpgv…), the panic text
    // otherwise scrolls past buried in the guest program's own output and
    // the user only sees a downstream "dpkg returned 100". Print a loud,
    // attributed, greppable banner so the ROOT cause is unmissable.
    std::panic::set_hook(Box::new(|info| {
        let pid = unsafe { libc::getpid() };
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".to_owned());
        eprintln!(
            "\n\x1b[1;31m======== CARRICK GUEST ABORT [pid {pid}] ========\x1b[0m\n\
             {msg}\n  at {loc}\n\
             \x1b[1;31m=================================================\x1b[0m\n"
        );
    }));

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    register_dtrace_probes();

    run_cli(Cli::parse())
}

fn run_cli(cli: Cli) -> anyhow::Result<()> {
    let Cli { store, command } = cli;
    let store = store
        .map(ImageStore::new)
        .unwrap_or_else(ImageStore::default_for_user);

    // `carrick shell [image]` is a convenience for an interactive run of
    // /bin/sh: normalise it to `Run` with a pty when stdin is a terminal (raw
    // streaming otherwise, so piped input still works). This reuses the entire
    // run path (image pull, fs backend, pty relay) with zero duplication.
    let command = match command {
        Commands::Shell { image } => {
            // SAFETY: isatty on fd 0 is a simple syscall returning 0/1.
            let interactive = unsafe { libc::isatty(0) } == 1;
            Commands::Run {
                image,
                max_traps: DEFAULT_MAX_TRAPS,
                debug_state_path: None,
                raw: !interactive,
                tty: interactive,
                fs: None,
                command: vec!["/bin/sh".to_owned()],
            }
        }
        other => other,
    };

    match command {
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
            // Forward a small allowlist of runtime-tuning/diagnostic env vars from
            // the host when explicitly set (unset = absent, so this is a no-op in
            // normal use). Lets an operator pass e.g. GODEBUG=schedtrace=1000 to a
            // guest Go binary for differential debugging without rebuilding it.
            let mut elf_env: Vec<String> = Vec::new();
            for key in [
                "GODEBUG",
                "GOMAXPROCS",
                "GOTRACEBACK",
                "GOGC",
                "GODEBUGFLAGS",
            ] {
                if let Ok(val) = std::env::var(key) {
                    elf_env.push(format!("{key}={val}"));
                }
            }
            let result = run_static_elf_with_hvf_args_and_dispatcher_debug(
                &path,
                dispatcher,
                argv,
                elf_env.into_iter(),
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
            tty,
            fs,
            command,
        } => {
            let image = ImageReference::parse(&image)?;
            let command = if command.is_empty() {
                vec!["/bin/sh".to_owned()]
            } else {
                command
            };
            // docker-run semantics: use the locally-stored image if present,
            // otherwise pull it on demand. A bare name like `python:3.12-slim`
            // is already canonicalised to `docker.io/library/python:3.12-slim`
            // by the reference parser, so the pull and the store lookup agree.
            let summary = block_on_oci(async {
                match store.load_pull_summary(&image).await {
                    Ok(summary) => Ok(summary),
                    Err(_) => {
                        eprintln!(
                            "carrick: image {} not in store; pulling…",
                            image.canonical()
                        );
                        pull_image(&image, &store).await
                    }
                }
            })
            .with_context(|| format!("failed to obtain image {}", image.canonical()))?;
            let rootfs_layers: Vec<PathBuf> = summary
                .layers
                .iter()
                .map(|layer| layer.path.clone())
                .collect();
            let executable_path = &command[0];
            // Name the host process `carrick: <basename>` up front so
            // it's identifiable in ps/Activity Monitor even before the
            // guest sets its own comm via prctl.
            {
                let base = executable_path
                    .rsplit('/')
                    .next()
                    .unwrap_or(executable_path);
                carrick::dispatch::set_host_process_name(base.as_bytes());
            }

            // Resolve --fs (or the default) early so we can branch before
            // touching the in-memory rootfs. For --fs host we stream layers
            // straight onto the cap-std scratch Dir; for --fs memory we keep
            // the original in-memory RootFs path.
            let fs_kind = fs.unwrap_or_else(default_fs_backend_kind);

            // Standard Linux environment provided to every guest run.
            // Without PATH glibc-based tools like dpkg-query bail with
            // "PATH is not set" and apt's pre-fork helpers can't locate
            // their siblings.
            let mut env: Vec<String> = vec![
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
                "HOME=/root".to_owned(),
                "TERM=xterm-256color".to_owned(),
                "LANG=C.UTF-8".to_owned(),
                "LC_ALL=C.UTF-8".to_owned(),
                "DEBIAN_FRONTEND=noninteractive".to_owned(),
                "PAGER=cat".to_owned(),
            ];
            // Forward a small allowlist of runtime-tuning/diagnostic env vars from
            // the host when explicitly set. These are no-ops in normal use (unset)
            // but let an operator pass e.g. GODEBUG=schedtrace=1000 to a guest Go
            // binary, or GOMAXPROCS, without baking it into the image — invaluable
            // for differential debugging against Docker.
            for key in [
                "GODEBUG",
                "GOMAXPROCS",
                "GOTRACEBACK",
                "GOGC",
                "GODEBUGFLAGS",
            ] {
                if let Ok(val) = std::env::var(key) {
                    env.push(format!("{key}={val}"));
                }
            }

            let result = match fs_kind {
                FsBackendKind::Host => {
                    // Stream every OCI layer straight onto the cap-std scratch
                    // Dir.  No in-memory RootFs is built: the disk overlay is
                    // immediately authoritative for all fs syscalls AND for the
                    // initial ELF load (via read_exec_file / overlay-first).
                    let mut host = HostFsBackend::new()
                        .context("--fs host: failed to create scratch directory")?;
                    host.extract_layers(&rootfs_layers)
                        .context("--fs host: failed to stream OCI layers to scratch Dir")?;
                    let mut dispatcher = SyscallDispatcher::new();
                    dispatcher.set_executable_path(executable_path.clone());
                    seed_guest_baseline(&mut host);
                    let _ = dispatcher.set_fs_backend(Box::new(host));
                    // Interactive pty (or --raw stream): hand the guest the pty
                    // slave as fds 0/1/2 and relay master <-> the user's terminal.
                    let _supervisor_parent = setup_interactive_stdio(&mut dispatcher, tty, raw)?;
                    if let Some(parent) = _supervisor_parent {
                        let code = parent.relay_and_wait()?;
                        std::process::exit(code);
                    }
                    // Capture the run result WITHOUT `?` so contextual errors
                    // still include the selected fs backend and image.
                    let run_result = run_elf_from_dispatcher_debug(
                        executable_path.as_str(),
                        dispatcher,
                        command.clone(),
                        env,
                        max_traps,
                        debug_state_path.as_ref(),
                    );
                    run_result.with_context(|| {
                        format!(
                            "failed to run ELF {} from image {} (--fs host)",
                            executable_path,
                            image.canonical()
                        )
                    })?
                }
                FsBackendKind::Memory => {
                    // Classic in-memory path: unchanged behaviour.
                    let rootfs = RootFs::from_layer_paths(&rootfs_layers)
                        .context("failed to compose image rootfs layers")?;
                    let mut dispatcher = SyscallDispatcher::with_rootfs_and_executable(
                        rootfs.clone(),
                        executable_path.clone(),
                    );
                    install_fs_backend(&mut dispatcher, Some(FsBackendKind::Memory))?;
                    // Interactive pty (or --raw stream): hand the guest the pty
                    // slave as fds 0/1/2 and relay master <-> the user's terminal.
                    let _supervisor_parent = setup_interactive_stdio(&mut dispatcher, tty, raw)?;
                    if let Some(parent) = _supervisor_parent {
                        let code = parent.relay_and_wait()?;
                        std::process::exit(code);
                    }
                    // Capture the run result WITHOUT `?` so contextual errors
                    // still include the selected fs backend and image.
                    let run_result = run_rootfs_elf_with_hvf_args_and_dispatcher_debug(
                        executable_path.as_str(),
                        &rootfs,
                        dispatcher,
                        command.clone(),
                        env,
                        max_traps,
                        debug_state_path.as_ref(),
                    );
                    run_result.with_context(|| {
                        format!(
                            "failed to run ELF {} from image {} (--fs memory)",
                            executable_path,
                            image.canonical()
                        )
                    })?
                }
            };

            if tty {
                // Guest output already went to the terminal via the relay;
                // the stdout/stderr buffers are empty under stream_stdio.
                std::process::exit(if result.trap_limit_hit {
                    1
                } else {
                    result.exit_code
                });
            } else if raw {
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
        // `Shell` is normalised to `Run` (interactive /bin/sh) before this
        // match, so it is never reached here.
        Commands::Shell { .. } => unreachable!("Shell is normalised to Run above"),
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
            let reporter = CompatReporter::default();
            let outcome = dispatcher.dispatch(
                SyscallRequest::new(
                    number,
                    SyscallArgs::from([args[0], args[1], args[2], args[3], args[4], args[5]]),
                ),
                &mut memory,
                &reporter,
            )?;
            println!("{}", {
                let stdout = dispatcher.stdout();
                let stderr = dispatcher.stderr();
                serde_json::to_string_pretty(&serde_json::json!({
                    "outcome": outcome,
                    "stdout": String::from_utf8_lossy(&stdout),
                    "stderr": String::from_utf8_lossy(&stderr),
                    "report": reporter.finish(),
                }))?
            });
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
                let value = if let Some(hex) = stripped
                    .strip_prefix("0x")
                    .or_else(|| stripped.strip_prefix("0X"))
                {
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
        Commands::TraceChild {
            trace_uid,
            trace_gid,
            trace_groups,
            command,
        } => {
            #[cfg(target_os = "macos")]
            {
                exec_trace_child(trace_uid, trace_gid, &trace_groups, &command)?;
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (trace_uid, trace_gid, trace_groups, command);
                bail!("trace child execution is only available on macOS.");
            }
        }
        Commands::Trace {
            flowindent,
            script,
            trace_out,
            command,
            forward_env,
            trace_uid,
            trace_gid,
            trace_groups,
        } => {
            #[cfg(target_os = "macos")]
            {
                // Apply env vars carried across the sudo re-exec as CLI args.
                for kv in &forward_env {
                    if let Some((k, v)) = kv.split_once('=') {
                        // SAFETY: single-threaded at this point (pre-runtime).
                        unsafe { std::env::set_var(k, v) };
                    }
                }
                if command.is_empty() {
                    bail!(
                        "trace needs a carrick subcommand to forward (e.g. `carrick trace run alpine:latest /bin/busybox echo hi`)"
                    );
                }
                let me = std::env::current_exe()
                    .context("failed to resolve current carrick binary path")?;
                if unsafe { libc::geteuid() } != 0 {
                    // libdtrace needs root to open /dev/dtrace. Re-exec the
                    // whole `carrick trace ...` invocation under sudo so the
                    // caller doesn't have to remember the prefix.
                    use std::os::unix::process::CommandExt;
                    eprintln!("carrick trace: not root; re-executing under sudo…");
                    // Plain `sudo` resets the environment (env_reset), which
                    // would drop the CARRICK_* knobs the trace'd run needs
                    // (CARRICK_INSECURE_REGISTRIES, CARRICK_WATCH_ADDR,
                    // CARRICK_PULL_PLATFORM, CARRICK_HOME, …). Carry those and
                    // the user identity env (`HOME`, `USER`, `LOGNAME`, `SHELL`)
                    // across as `--forward-env KEY=VAL` CLI args (which survive
                    // sudo, unlike env vars, and don't need SETENV in sudoers);
                    // the re-exec'd carrick sets them before spawning the child.
                    let mut forwarded: Vec<std::ffi::OsString> =
                        vec![me.as_os_str().to_owned(), std::ffi::OsString::from("trace")];
                    if flowindent {
                        forwarded.push(std::ffi::OsString::from("--flowindent"));
                    }
                    if let Some(ref s) = script {
                        forwarded.push(std::ffi::OsString::from("--script"));
                        forwarded.push(s.as_os_str().to_owned());
                    }
                    if let Some(ref o) = trace_out {
                        forwarded.push(std::ffi::OsString::from("--trace-out"));
                        forwarded.push(o.as_os_str().to_owned());
                    }
                    forwarded.push(std::ffi::OsString::from("--trace-uid"));
                    forwarded.push(unsafe { libc::getuid() }.to_string().into());
                    forwarded.push(std::ffi::OsString::from("--trace-gid"));
                    forwarded.push(unsafe { libc::getgid() }.to_string().into());
                    let groups = current_supplementary_groups();
                    if !groups.is_empty() {
                        forwarded.push(std::ffi::OsString::from("--trace-groups"));
                        forwarded.push(join_ids(&groups).into());
                    }
                    for (k, v) in std::env::vars_os() {
                        let key = k.to_string_lossy();
                        if key.starts_with("CARRICK_")
                            || matches!(key.as_ref(), "HOME" | "USER" | "LOGNAME" | "SHELL")
                        {
                            forwarded.push(std::ffi::OsString::from("--forward-env"));
                            let mut kv = k;
                            kv.push("=");
                            kv.push(v);
                            forwarded.push(kv);
                        }
                    }
                    forwarded.push(std::ffi::OsString::from("--"));
                    forwarded.extend(command.iter().map(std::ffi::OsString::from));
                    let err = std::process::Command::new("sudo").args(&forwarded).exec();
                    bail!("carrick trace: failed to re-exec under sudo: {}", err);
                }
                let script_src =
                    match &script {
                        Some(path) => Some(std::fs::read_to_string(path).with_context(|| {
                            format!("failed to read D script {}", path.display())
                        })?),
                        None => None,
                    };
                let opts = carrick::dtrace_consumer::TraceOptions {
                    flowindent,
                    script: script_src,
                    out_path: trace_out.as_ref().map(|p| p.to_string_lossy().into_owned()),
                    drop_credentials: trace_drop_credentials(trace_uid, trace_gid, &trace_groups),
                };
                carrick::dtrace_consumer::run_child_under_dtrace(&me, &command, &opts)
                    .map_err(|e| anyhow::anyhow!("trace failed: {}", e))?;
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (
                    flowindent,
                    script,
                    trace_out,
                    command,
                    forward_env,
                    trace_uid,
                    trace_gid,
                    trace_groups,
                );
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
                        v.device, v.name,
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
    // Set once the host backend has materialised the COMPLETE rootfs onto
    // disk — after which the in-memory rootfs layer is redundant and gets
    // dropped (the disk overlay is authoritative for every read).
    let mut host_seeded = false;
    let mut backend: Box<dyn FsBackend> = match kind {
        FsBackendKind::Memory => Box::new(MemoryBackend::new()),
        FsBackendKind::Host => match HostFsBackend::new() {
            Ok(mut host) => {
                // SEED THE BACKEND WITH THE FULL ROOTFS.
                //
                // This is the "rootfs as APFS, throw away when done"
                // architecture: instead of layering the writable
                // overlay on top of the in-memory tar, materialise
                // every rootfs file/dir/symlink onto the cap-std-
                // sandboxed scratch directory. After this point, all
                // fs syscalls flow through real host syscalls
                // (openat/renameat/symlinkat/...) against a real
                // filesystem — which fixes apt's downstream chain
                // (symlinkat EROFS, SplitClearSignedFile, atomic
                // rename) by giving it real Linux fs semantics.
                if let Some(rootfs) = dispatcher.rootfs() {
                    if let Err(err) = host.seed_from_rootfs(rootfs) {
                        eprintln!(
                            "carrick: --fs host seed-from-rootfs failed ({err}); falling back to in-memory backend"
                        );
                        let mut mem: Box<dyn FsBackend> = Box::new(MemoryBackend::new());
                        seed_guest_baseline(&mut *mem);
                        let _ = dispatcher.set_fs_backend(mem);
                        return Ok(());
                    }
                    host_seeded = true;
                }
                Box::new(host)
            }
            Err(err) => {
                eprintln!("carrick: --fs host failed ({err}); falling back to in-memory backend");
                Box::new(MemoryBackend::new())
            }
        },
    };
    seed_guest_baseline(&mut *backend);
    let _ = dispatcher.set_fs_backend(backend);
    // The disk overlay now holds the entire filesystem; drop the redundant
    // in-memory rootfs layer so reads, execve and the ELF interpreter
    // loader all flow through the materialised host disk.
    if host_seeded {
        dispatcher.drop_rootfs_layer();
    }
    Ok(())
}

/// Pre-populate the writable overlay with a small Linux baseline plus
/// `/etc/hosts` entries resolved on the macOS host. Raw static binaries have
/// no OCI rootfs to supply `/tmp`, passwd/group databases, or resolver files;
/// enough real software assumes those paths exist that Carrick seeds them for
/// both memory and host backends.
fn seed_guest_baseline(backend: &mut dyn carrick::fs_backend::FsBackend) {
    use std::net::ToSocketAddrs;
    for dir in [
        "/tmp",
        "/var",
        "/var/tmp",
        "/root",
        "/etc",
        "/bin",
        "/sbin",
        "/usr",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/sbin",
    ] {
        let _ = backend.make_dir(dir);
    }
    let _ = backend.set_mode("/tmp", 0o1777);
    let _ = backend.set_mode("/var/tmp", 0o1777);
    let _ = backend.set_file_contents(
        "/etc/passwd",
        b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            .to_vec(),
    );
    let _ = backend.set_file_contents("/etc/group", b"root:x:0:\nnogroup:x:65534:\n".to_vec());
    let _ = backend.set_file_contents(
        "/etc/nsswitch.conf",
        b"passwd: files\ngroup: files\nhosts: files dns\n".to_vec(),
    );

    const HOSTNAMES: &[&str] = &[
        "deb.debian.org",
        "security.debian.org",
        "ftp.debian.org",
        "archive.ubuntu.com",
        "security.ubuntu.com",
        "ports.ubuntu.com",
    ];
    let mut hosts_content = String::from(
        "127.0.0.1\tlocalhost\n\
         ::1\tlocalhost ip6-localhost ip6-loopback\n\
         ff02::1\tip6-allnodes\n\
         ff02::2\tip6-allrouters\n",
    );
    for hostname in HOSTNAMES {
        if let Ok(addrs) = (*hostname, 80u16).to_socket_addrs() {
            for addr in addrs {
                match addr.ip() {
                    std::net::IpAddr::V4(v4) => {
                        hosts_content.push_str(&format!("{}\t{}\n", v4, hostname));
                        break; // one A record is enough; saves /etc/hosts noise
                    }
                    std::net::IpAddr::V6(_) => {}
                }
            }
        }
    }
    let _ = backend.set_file_contents("/etc/hosts", hosts_content.into_bytes());
}

/// Default backend choice: prefer `host` because that's the secure-
/// by-default option, but quietly fall back to `memory` when the
/// scratch root sits on a case-insensitive filesystem (a common
/// macOS default that breaks anything assuming Linux semantics).
fn default_fs_backend_kind() -> FsBackendKind {
    // Probe the SAME scratch root the host backend will actually use
    // (`preferred_scratch_root` prefers the dedicated case-sensitive
    // `/Volumes/carrick` volume), not a hardcoded `~/.carrick/scratch`.
    // Otherwise the decision and the real scratch location disagree: the
    // dedicated volume can be case-sensitive while `~/.carrick` is not, and we
    // would wrongly fall back to the in-memory backend.
    let probe = carrick::apfs::preferred_scratch_root()
        .unwrap_or_else(|_| std::env::temp_dir().join("carrick-scratch"));
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

#[cfg(target_os = "macos")]
fn current_supplementary_groups() -> Vec<u32> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return Vec::new();
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    let n = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if n <= 0 {
        return Vec::new();
    }
    groups.truncate(n as usize);
    groups.into_iter().map(|g| g as u32).collect()
}

#[cfg(target_os = "macos")]
fn join_ids(ids: &[u32]) -> String {
    ids.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
}

#[cfg(target_os = "macos")]
fn trace_drop_credentials(
    trace_uid: Option<u32>,
    trace_gid: Option<u32>,
    trace_groups: &[u32],
) -> Option<carrick::dtrace_consumer::TraceDropCredentials> {
    let (uid, gid) = match (trace_uid, trace_gid) {
        (Some(uid), Some(gid)) => (uid, gid),
        _ => {
            let uid = std::env::var("SUDO_UID").ok()?.parse().ok()?;
            let gid = std::env::var("SUDO_GID").ok()?.parse().ok()?;
            (uid, gid)
        }
    };

    Some(carrick::dtrace_consumer::TraceDropCredentials {
        uid,
        gid,
        groups: normalize_trace_groups(gid, trace_groups),
    })
}

#[cfg(target_os = "macos")]
fn normalize_trace_groups(primary_gid: u32, groups: &[u32]) -> Vec<u32> {
    let mut normalized = if groups.is_empty() {
        vec![primary_gid]
    } else {
        groups.to_vec()
    };
    if !normalized.contains(&primary_gid) {
        normalized.insert(0, primary_gid);
    }
    normalized
}

#[cfg(target_os = "macos")]
fn exec_trace_child(
    trace_uid: u32,
    trace_gid: u32,
    trace_groups: &[u32],
    command: &[String],
) -> anyhow::Result<()> {
    if command.is_empty() {
        bail!("trace child needs a carrick subcommand to dispatch");
    }

    let groups = normalize_trace_groups(trace_gid, trace_groups);
    let groups: Vec<libc::gid_t> = groups.into_iter().map(|g| g as libc::gid_t).collect();
    if unsafe { libc::setgroups(groups.len() as libc::c_int, groups.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("trace child failed to set supplementary groups");
    }
    if unsafe { libc::setgid(trace_gid as libc::gid_t) } != 0 {
        return Err(std::io::Error::last_os_error()).context("trace child failed to set gid");
    }
    if unsafe { libc::setuid(trace_uid as libc::uid_t) } != 0 {
        return Err(std::io::Error::last_os_error()).context("trace child failed to set uid");
    }

    let mut argv = Vec::with_capacity(command.len() + 1);
    argv.push("carrick".to_owned());
    argv.extend(command.iter().cloned());
    run_cli(Cli::parse_from(argv))
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
    // INVARIANT: fatal at startup — if the host cannot even build a
    // current-thread tokio runtime there is nothing to recover to; aborting
    // here (before any guest forks) is the correct, safe failure mode.
    #[allow(clippy::expect_used)]
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

fn register_dtrace_probes() {
    match carrick::probes::register_dtrace_probes() {
        Ok(()) => {
            if std::env::var_os("CARRICK_DTRACE_DEBUG").is_some() {
                eprintln!(
                    "carrick: dtrace probes registered (pid={})",
                    std::process::id()
                );
            }
        }
        Err(err) => {
            // Always surface registration failures: silent failure here is
            // what makes the dtrace path feel broken.
            eprintln!("carrick: failed to register DTrace probes: {err}");
        }
    }
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
