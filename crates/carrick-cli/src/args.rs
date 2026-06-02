//! Command-line argument model.

use std::path::PathBuf;

use carrick_runtime::compat::CompatReportFormat;
use carrick_runtime::runtime::DEFAULT_MAX_TRAPS;
use carrick_spec::{FsBackendKind, PidMode};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(author, version, about)]
pub(crate) struct Cli {
    #[arg(long, env = "CARRICK_HOME", global = true)]
    pub(crate) store: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
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
        /// Bind-mount a host directory/file into the guest:
        /// `HOST:GUEST[:ro]`. Needed under `--fs host` (a sandboxed scratch, not
        /// the real host FS) to expose host paths — e.g. a test's `testdata/`.
        #[arg(short = 'v', long = "volume", value_name = "HOST:GUEST[:ro]")]
        volume: Vec<String>,
        /// The guest's initial working directory. Defaults (under `--fs host`) to
        /// carrick's launch directory.
        #[arg(short = 'w', long = "workdir", value_name = "DIR")]
        workdir: Option<String>,
        /// `KEY=VAL` env vars to set in this process before the guest starts.
        /// Lets a `sudo`-launched run carry `CARRICK_*` tunables (e.g.
        /// `CARRICK_EXPOSED_CPUS`) across sudo's `env_reset` without needing
        /// SETENV in sudoers - CLI args survive sudo where env vars don't. Same
        /// idiom as `trace --forward-env`.
        #[arg(long = "forward-env", value_name = "KEY=VAL")]
        forward_env: Vec<String>,
        #[arg(last = true)]
        args: Vec<String>,
    },
    Pull {
        image: String,
        /// Target platform, e.g. `linux/amd64` or `linux/arm64`. Selects the
        /// OCI manifest entry for a multi-arch image. Defaults to arm64.
        #[arg(long, value_name = "OS/ARCH")]
        platform: Option<String>,
    },
    Run {
        image: String,
        /// Target platform, e.g. `linux/amd64` or `linux/arm64`. Selects the
        /// OCI manifest entry for multi-arch images and, for amd64, enables
        /// Rosetta 2 translation of the x86_64 guest. Defaults to the host
        /// architecture (arm64 on Apple Silicon).
        #[arg(long, value_name = "OS/ARCH")]
        platform: Option<String>,
        #[arg(long, default_value_t = DEFAULT_MAX_TRAPS)]
        max_traps: usize,
        /// See `run-elf --debug-state-path`.
        #[arg(long = "debug-state-path")]
        debug_state_path: Option<PathBuf>,
        /// Deprecated/no-op: the default `run` output is now docker-shaped
        /// (streamed stdio + the container's exit code). Kept so existing
        /// `--raw` invocations keep working; use `--json` for the old envelope.
        #[arg(long)]
        raw: bool,
        /// Emit the JSON compat-report envelope (exit code, traps, report) on
        /// stdout instead of behaving like `docker run`. Opt-in; off by default.
        #[arg(long)]
        json: bool,
        /// Allocate a pseudo-terminal and run interactively (like `docker run -it`).
        #[arg(short = 't', long = "tty")]
        tty: bool,
        /// Keep STDIN open even if not attached (like `docker run -it`).
        #[arg(short = 'i', long = "interactive")]
        interactive: bool,
        /// Run the container detached (like `docker run -d`): start it in the
        /// background, print its id, and return immediately. The container runs
        /// under its own NsSupervisor with stdout/stderr captured to a log;
        /// manage it with `carrick ps|stop|kill|rm`.
        #[arg(short = 'd', long = "detach", conflicts_with_all = ["tty", "interactive"])]
        detach: bool,
        /// Which writable-layer backend to use. Defaults to `host` on
        /// case-sensitive volumes and `memory` elsewhere.
        #[arg(long, value_enum)]
        fs: Option<FsBackendKind>,
        /// PID namespace mode (like `docker run --pid`). `private` (default)
        /// runs the container in its own PID namespace (init is pid 1); `host`
        /// shares the host PID namespace (no remap).
        #[arg(long, value_enum, default_value_t = PidMode::Private)]
        pid: PidMode,
        /// Set environment variables
        #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Read in a file of environment variables (may be repeated)
        #[arg(long = "env-file", value_name = "FILE")]
        env_file: Vec<PathBuf>,
        /// Working directory inside the container
        #[arg(short = 'w', long = "workdir", value_name = "DIR")]
        workdir: Option<String>,
        /// Username or UID
        #[arg(short = 'u', long = "user", value_name = "USER")]
        user: Option<String>,
        /// Overwrite the default ENTRYPOINT of the image
        #[arg(long = "entrypoint", value_name = "COMMAND")]
        entrypoint: Option<String>,
        /// Bind mount a volume
        #[arg(
            short = 'v',
            long = "volume",
            value_name = "host-src:container-dest[:ro|rw]"
        )]
        volume: Vec<String>,
        /// Attach a filesystem mount to the container
        #[arg(
            long = "mount",
            value_name = "type=bind,source=host-src,target=container-dest[,readonly]"
        )]
        mount: Vec<String>,
        /// Assign a name to the container
        #[arg(long = "name", value_name = "NAME")]
        name: Option<String>,
        /// Automatically remove the container when it exits
        #[arg(long = "rm")]
        rm: bool,
        /// Publish a container's port(s) to the host (no-op under host networking)
        #[arg(short = 'p', long = "publish", value_name = "hostPort:containerPort")]
        publish: Vec<String>,
        /// `KEY=VAL` env vars to set in this process before the guest starts.
        /// Carries `CARRICK_*` tunables across `sudo`'s env_reset without needing
        /// SETENV in sudoers (CLI args survive sudo where env vars don't). Same
        /// idiom as `run-elf`/`trace --forward-env`.
        #[arg(long = "forward-env", value_name = "KEY=VAL")]
        forward_env: Vec<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    Shell {
        #[arg(default_value = "alpine:latest")]
        image: String,
    },
    /// Fetch a container's logs (like `docker logs`). Replays the stdout/stderr
    /// captured from a detached (`run -d`) container.
    Logs {
        /// Follow log output (stream appended bytes until the container exits).
        #[arg(short = 'f', long = "follow")]
        follow: bool,
        /// Show only the last N lines.
        #[arg(short = 'n', long = "tail", value_name = "N")]
        tail: Option<usize>,
        /// Container id or name.
        container: String,
    },
    /// Block until one or more containers stop, then print each exit code
    /// (like `docker wait`).
    Wait {
        #[arg(required = true)]
        containers: Vec<String>,
    },
    /// Display detailed information on one or more containers (like
    /// `docker inspect`). Without `--format`, prints a JSON array.
    Inspect {
        /// Format the output with a Go-template-style expression, e.g.
        /// `{{.State.ExitCode}}` or `{{.State.Status}}` (`{{json .}}` for the
        /// whole object).
        #[arg(short = 'f', long = "format")]
        format: Option<String>,
        #[arg(required = true)]
        containers: Vec<String>,
    },
    /// List containers (like `docker ps`). Shows running containers; `--all`
    /// includes exited ones.
    Ps {
        /// Show all containers (default shows just running).
        #[arg(short = 'a', long = "all")]
        all: bool,
        /// Only display container ids.
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
    },
    /// Stop one or more running containers (SIGTERM, then SIGKILL after the
    /// grace period), like `docker stop`.
    Stop {
        /// Seconds to wait for graceful stop before SIGKILL.
        #[arg(short = 't', long = "time", default_value_t = 10)]
        time: u64,
        /// Container ids or names.
        #[arg(required = true)]
        containers: Vec<String>,
    },
    /// Send a signal to one or more running containers (like `docker kill`).
    Kill {
        /// Signal to send (name like `TERM`/`KILL` or number).
        #[arg(short = 's', long = "signal", default_value = "KILL")]
        signal: String,
        #[arg(required = true)]
        containers: Vec<String>,
    },
    /// Remove one or more containers (like `docker rm`). Refuses a running
    /// container unless `--force`.
    Rm {
        /// Force removal of a running container (SIGKILL it first).
        #[arg(short = 'f', long = "force")]
        force: bool,
        #[arg(required = true)]
        containers: Vec<String>,
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
        /// sudoers - CLI args survive sudo where env vars don't.
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
    /// this shells out to `diskutil(8)` - no Apple private framework
    /// dependency, no FFI surface.
    #[cfg(target_os = "macos")]
    Volume {
        #[command(subcommand)]
        command: VolumeCommand,
    },
}

#[cfg(target_os = "macos")]
#[derive(Debug, Subcommand)]
pub(crate) enum VolumeCommand {
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
    /// Delete the carrick scratch volume. Destructive - anything on
    /// the volume is lost. Idempotent.
    Delete {
        /// Required confirmation; without `--yes` this is a no-op
        /// that prints the volume info and exits 0.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum DebugCommand {
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
pub(crate) enum RootfsCommand {
    Summary,
    Ls { path: PathBuf },
    Cat { path: PathBuf },
}
