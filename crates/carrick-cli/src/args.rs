//! The clap command model — the docker-compatible surface plus the diagnostic
//! verbs.
//!
//! # Theory of operation
//!
//! This is the declarative spec of *what* `carrick` accepts; [`crate::commands`]
//! is *how* each one acts. The flag names, value shapes, and help text are
//! chosen for parity with the docker CLI (`-e`/`--env`, `-v`/`--volume`,
//! `--mount`, `-p`/`--publish`, `--entrypoint`, `--rm`, `--stop-signal`,
//! `--pid`, `--format`, …) so docker tooling and the bollard conformance harness
//! drive carrick unchanged. Where a flag has no faithful meaning under carrick's
//! host-only networking / no-daemon model it is still *accepted* and documented
//! as a no-op or a hard error (see `-p` in [`crate::runtime_util`]).
//!
//! A few argument conventions are load-bearing and easy to miss:
//!
//! - **`--forward-env KEY=VAL`** appears on `run`/`run-elf`/`trace` to carry
//!   `CARRICK_*` tunables across a `sudo` re-exec. CLI args survive `sudo`'s
//!   `env_reset` where bare env vars don't (and without needing `SETENV` in
//!   sudoers); the receiving command applies them with `set_var` before the
//!   guest starts.
//! - **`__trace-child` and the `--trace-uid/-gid/-groups` flags** are `hide`den
//!   internal plumbing for the trace privilege split (see [`crate::trace_cli`]),
//!   never typed by a user.
//! - **`--raw` vs `--json` on `run`** select the output envelope: `--raw` is now
//!   a no-op alias for the default docker-shaped streaming output, `--json` opts
//!   back into the legacy compat-report envelope.
//! - The **diagnostic/ELF-fixture verbs** (`run-elf`, `dispatch-syscall`,
//!   `inspect-elf`, `plan-elf-load`, `load-elf`, `rootfs`, `syscalls`,
//!   `trap-capabilities`, `debug`, `volume`) have no docker analogue; they exist
//!   for conformance fixtures and operator debugging.

use std::path::PathBuf;

// `compat-report --format` uses the HVF report renderer (`CompatReportFormat`),
// which is macOS-only; the subcommand is gated off on platform-linux.
#[cfg(feature = "platform-macos")]
use carrick_runtime::compat::CompatReportFormat;
use carrick_runtime::runtime::DEFAULT_MAX_TRAPS;
use carrick_spec::{
    ExecBackendRequest, FsBackendKind, NativeCodeModeRequest, NativePageProfileRequest, PidMode,
};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(author, version, about)]
pub(crate) struct Cli {
    #[arg(long, env = "CARRICK_HOME", global = true)]
    pub(crate) store: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Commands,
}

/// Docker `--pull` policy (`always`/`missing`/`never`). Local mirror of
/// [`carrick_image::PullPolicy`] so `carrick-image` need not depend on clap.
#[derive(Copy, Clone, Debug, clap::ValueEnum)]
pub(crate) enum PullArg {
    Always,
    Missing,
    Never,
}

impl From<PullArg> for carrick_image::PullPolicy {
    fn from(p: PullArg) -> Self {
        match p {
            PullArg::Always => carrick_image::PullPolicy::Always,
            PullArg::Missing => carrick_image::PullPolicy::Missing,
            PullArg::Never => carrick_image::PullPolicy::Never,
        }
    }
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
    /// `run-elf` drives a freestanding ELF straight through the HVF run loop
    /// (`run_static_elf_with_hvf_…`), macOS-only. On Linux use `carrick run
    /// <oci>`, or the `carrick-kvm run-elf` dev driver for a bare ELF.
    #[cfg(feature = "platform-macos")]
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
        /// Which writable-layer backend to use. Defaults to `host`. The
        /// in-memory backend (`memory`) is opt-in: build with
        /// `--features fs-memory`. It is incoherent across guest `fork`.
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
        /// Execution backend policy. `native` is experimental and trusted-code-only.
        #[arg(long = "exec-backend", value_enum, default_value_t = ExecBackendRequest::Auto, env = "CARRICK_EXEC_BACKEND")]
        exec_backend: ExecBackendRequest,
        /// Page profile for the native execution backend.
        #[arg(long = "native-page-profile", value_enum, default_value_t = NativePageProfileRequest::Auto, env = "CARRICK_NATIVE_PAGE_PROFILE")]
        native_page_profile: NativePageProfileRequest,
        /// Instruction execution mode for the Darwin-native backend.
        #[arg(long = "native-code-mode", value_enum, default_value_t = NativeCodeModeRequest::Brk, env = "CARRICK_NATIVE_CODE_MODE")]
        native_code_mode: NativeCodeModeRequest,
        /// Launch-time syscall policy. `run-elf` drives a bare host ELF and
        /// defaults to UNCONFINED (no policy); pass `seccomp=default` to opt
        /// into the container policy model `carrick run` applies by default
        /// (the shape the conformance Docker oracle runs under).
        #[arg(long = "security-opt", value_name = "OPTION")]
        security_opt: Vec<String>,
        #[arg(last = true)]
        args: Vec<String>,
    },
    Pull {
        image: String,
        /// Target platform, e.g. `linux/amd64` or `linux/arm64`. Selects the
        /// OCI manifest entry for a multi-arch image. Defaults to the host-native
        /// architecture.
        #[arg(long, value_name = "OS/ARCH")]
        platform: Option<String>,
    },
    /// Load an image from a docker-archive tarball into the local store (like
    /// `docker load`). Ingests a `docker save` / kaniko `--tar-path` archive so
    /// the tagged image resolves and runs locally without a registry pull.
    Load {
        /// Read the archive from a tar file instead of STDIN.
        #[arg(short = 'i', long = "input", value_name = "FILE")]
        input: PathBuf,
        /// Platform key to store the archive under, e.g. `linux/amd64`.
        /// Defaults to the host-native Carrick platform.
        #[arg(long, value_name = "OS/ARCH")]
        platform: Option<String>,
    },
    /// List images in the local store (like `docker images`).
    Images {
        /// Only show numeric image ids.
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
    },
    /// Remove one or more images from the local store (like `docker rmi`).
    /// Unreferenced layers are garbage-collected afterward.
    Rmi {
        #[arg(required = true)]
        images: Vec<String>,
    },
    /// Remove image layers no longer referenced by any image (like
    /// `docker image prune`), reclaiming disk space.
    Prune,
    /// Create a new reference to an existing stored image (like `docker tag`).
    /// Layers are shared, not copied.
    Tag {
        /// Existing image (id or name).
        source: String,
        /// New reference, e.g. `myapp:dev`.
        target: String,
    },
    /// Build an image from a Dockerfile (like `docker build`). Runs the real
    /// kaniko executor as a carrick guest (`carrick run --fs host`, traps
    /// effectively uncapped) over the build context, then ingests the result
    /// into the local store. By default kaniko writes a tar that carrick loads;
    /// with `--push` kaniko pushes straight to the registry.
    Build {
        /// Name and optionally a tag for the built image (`name:tag`). Defaults
        /// to `carrick-build:latest` — kaniko's `--destination` is required even
        /// for a `--no-push` build.
        #[arg(short = 't', long = "tag", value_name = "name:tag")]
        tag: Option<String>,
        /// Path to the Dockerfile, RELATIVE to the build context. Defaults to
        /// `Dockerfile`.
        #[arg(
            short = 'f',
            long = "file",
            value_name = "PATH",
            default_value = "Dockerfile"
        )]
        file: PathBuf,
        /// Set a build-time variable (`KEY=VALUE`), passed through to kaniko as
        /// `--build-arg KEY=VALUE`. May be repeated.
        #[arg(long = "build-arg", value_name = "KEY=VALUE")]
        build_arg: Vec<String>,
        /// Do not use cache when building the image (kaniko `--no-cache`).
        /// Takes precedence over `--cache` when both are given.
        #[arg(long = "no-cache")]
        no_cache: bool,
        /// Enable kaniko's layer cache (kaniko `--cache=true`). Layers are
        /// pulled from and pushed to the registry specified by `--cache-repo`.
        /// Ignored when `--no-cache` is also given.
        #[arg(long = "cache")]
        cache: bool,
        /// Registry repository kaniko uses to store and retrieve cached layers
        /// (kaniko `--cache-repo`). Only meaningful when `--cache` is set.
        #[arg(long = "cache-repo", value_name = "REF")]
        cache_repo: Option<String>,
        /// Target platform for the build, e.g. `linux/amd64` (kaniko
        /// `--customPlatform`).
        #[arg(long, value_name = "OS/ARCH")]
        platform: Option<String>,
        /// Push the built image to the registry instead of loading it into the
        /// local store. When set kaniko pushes to `--tag`'s registry; otherwise
        /// the image is built to a tar and ingested locally.
        #[arg(long = "push")]
        push: bool,
        /// The build context directory. Defaults to the current directory.
        #[arg(default_value = ".")]
        context: PathBuf,
    },
    /// Show carrick disk usage / clean it up (like `docker system`).
    System {
        #[command(subcommand)]
        command: SystemCommand,
    },
    /// Manage Docker-compatible network resources (like `docker network`).
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Log in to a container registry (like `docker login`). Stores the
    /// credential in carrick's own config; `~/.docker/config.json` is read
    /// read-only as a fallback and never modified.
    Login {
        /// Registry server (default: Docker Hub).
        registry: Option<String>,
        #[arg(short = 'u', long = "username")]
        username: Option<String>,
        #[arg(short = 'p', long = "password")]
        password: Option<String>,
        /// Read the password from stdin.
        #[arg(long = "password-stdin")]
        password_stdin: bool,
    },
    /// Log out of a registry (like `docker logout`) — remove its stored credential.
    Logout {
        /// Registry server (default: Docker Hub).
        registry: Option<String>,
    },
    Run {
        image: String,
        /// Target platform, e.g. `linux/amd64` or `linux/arm64`. Selects the
        /// OCI manifest entry for multi-arch images. Defaults to the host-native
        /// architecture, so it is not needed for a native run (arm64 on Apple
        /// Silicon, amd64 on the x86_64 lanes). On Apple Silicon, `linux/amd64`
        /// runs the x86_64 guest through Apple Rosetta 2 and requires it to be
        /// installed.
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
        /// Which writable-layer backend to use. Defaults to `host`. The
        /// in-memory backend (`memory`) is opt-in (`--features fs-memory`).
        #[arg(long, value_enum)]
        fs: Option<FsBackendKind>,
        /// Execution backend policy. `native` is experimental and trusted-code-only.
        #[arg(long = "exec-backend", value_enum, default_value_t = ExecBackendRequest::Auto, env = "CARRICK_EXEC_BACKEND")]
        exec_backend: ExecBackendRequest,
        /// Page profile for the native execution backend.
        #[arg(long = "native-page-profile", value_enum, default_value_t = NativePageProfileRequest::Auto, env = "CARRICK_NATIVE_PAGE_PROFILE")]
        native_page_profile: NativePageProfileRequest,
        /// Instruction execution mode for the Darwin-native backend.
        #[arg(long = "native-code-mode", value_enum, default_value_t = NativeCodeModeRequest::Brk, env = "CARRICK_NATIVE_CODE_MODE")]
        native_code_mode: NativeCodeModeRequest,
        /// PID namespace mode (like `docker run --pid`). `private` (default)
        /// runs the container in its own PID namespace (init is pid 1); `host`
        /// shares the host PID namespace (no remap).
        #[arg(long, value_enum, default_value_t = PidMode::Private)]
        pid: PidMode,
        /// Docker `--pull` policy: `always` re-checks the registry and re-pulls a
        /// moved tag, `missing` (default) pulls only when the image is absent,
        /// `never` uses only the local cache.
        #[arg(long, value_enum, default_value = "missing")]
        pull: PullArg,
        /// Container network mode: host, bridge, none, or container:<id|name>.
        #[arg(long = "net", alias = "network", default_value = "host")]
        network: String,
        /// Add a service alias on the bridge network.
        #[arg(long = "network-alias", value_name = "ALIAS")]
        network_alias: Vec<String>,
        /// Assign a static IPv4 address on the bridge network.
        #[arg(long = "ip", value_name = "IPv4")]
        ip: Option<String>,
        /// Add a custom host-to-IP mapping in the guest's /etc/hosts.
        #[arg(long = "add-host", value_name = "HOST:IP")]
        add_host: Vec<String>,
        /// Set a custom DNS nameserver.
        #[arg(long = "dns", value_name = "IP")]
        dns: Vec<String>,
        /// Set a custom DNS search domain.
        #[arg(long = "dns-search", value_name = "DOMAIN")]
        dns_search: Vec<String>,
        /// Set a custom DNS resolver option.
        #[arg(long = "dns-option", value_name = "OPTION")]
        dns_option: Vec<String>,
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
        /// Mount volumes from another container.
        #[arg(long = "volumes-from", value_name = "CONTAINER[:ro|:rw]")]
        volumes_from: Vec<String>,
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
        /// Signal to stop the container (name like `SIGQUIT`/`TERM` or number).
        /// Overrides the image's `STOPSIGNAL`; defaults to `SIGTERM`.
        #[arg(long = "stop-signal", value_name = "SIGNAL")]
        stop_signal: Option<String>,
        /// Seconds to wait for the container to stop before SIGKILL (used by
        /// `stop`/`restart` when `-t` is not given). Defaults to 10.
        #[arg(long = "stop-timeout", value_name = "SECONDS")]
        stop_timeout: Option<u64>,
        /// Publish a container's port(s) to the host (no-op under host networking)
        #[arg(short = 'p', long = "publish", value_name = "hostPort:containerPort")]
        publish: Vec<String>,
        /// Docker-compatible security options. Supported: `seccomp=unconfined`
        /// (disable the launch-time default syscall policy — carrick's model of
        /// Docker's builtin seccomp profile) and `seccomp=default`/
        /// `seccomp=builtin`. Custom profile files are not supported.
        #[arg(long = "security-opt", value_name = "OPTION")]
        security_opt: Vec<String>,
        /// `KEY=VAL` env vars to set in this process before the guest starts.
        /// Carries `CARRICK_*` tunables across `sudo`'s env_reset without needing
        /// SETENV in sudoers (CLI args survive sudo where env vars don't). Same
        /// idiom as `run-elf`/`trace --forward-env`.
        #[arg(long = "forward-env", value_name = "KEY=VAL")]
        forward_env: Vec<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Create a container without starting it (like `docker create`). Pulls the
    /// image and persists the config; launch it later with `carrick start`.
    Create {
        image: String,
        #[arg(long, value_name = "OS/ARCH")]
        platform: Option<String>,
        /// Which writable-layer backend to use. Defaults to `host`. The
        /// in-memory backend (`memory`) is opt-in (`--features fs-memory`).
        #[arg(long, value_enum)]
        fs: Option<FsBackendKind>,
        /// Execution backend policy. `native` is experimental and trusted-code-only.
        #[arg(long = "exec-backend", value_enum, default_value_t = ExecBackendRequest::Auto, env = "CARRICK_EXEC_BACKEND")]
        exec_backend: ExecBackendRequest,
        /// Page profile for the native execution backend.
        #[arg(long = "native-page-profile", value_enum, default_value_t = NativePageProfileRequest::Auto, env = "CARRICK_NATIVE_PAGE_PROFILE")]
        native_page_profile: NativePageProfileRequest,
        /// Instruction execution mode for the Darwin-native backend.
        #[arg(long = "native-code-mode", value_enum, default_value_t = NativeCodeModeRequest::Brk, env = "CARRICK_NATIVE_CODE_MODE")]
        native_code_mode: NativeCodeModeRequest,
        #[arg(long, value_enum, default_value_t = PidMode::Private)]
        pid: PidMode,
        /// Docker `--pull` policy: `always` re-checks the registry and re-pulls a
        /// moved tag, `missing` (default) pulls only when the image is absent,
        /// `never` uses only the local cache.
        #[arg(long, value_enum, default_value = "missing")]
        pull: PullArg,
        /// Container network mode: host, bridge, none, or container:<id|name>.
        #[arg(long = "net", alias = "network", default_value = "host")]
        network: String,
        /// Add a service alias on the bridge network.
        #[arg(long = "network-alias", value_name = "ALIAS")]
        network_alias: Vec<String>,
        /// Assign a static IPv4 address on the bridge network.
        #[arg(long = "ip", value_name = "IPv4")]
        ip: Option<String>,
        /// Add a custom host-to-IP mapping in the guest's /etc/hosts.
        #[arg(long = "add-host", value_name = "HOST:IP")]
        add_host: Vec<String>,
        /// Set a custom DNS nameserver.
        #[arg(long = "dns", value_name = "IP")]
        dns: Vec<String>,
        /// Set a custom DNS search domain.
        #[arg(long = "dns-search", value_name = "DOMAIN")]
        dns_search: Vec<String>,
        /// Set a custom DNS resolver option.
        #[arg(long = "dns-option", value_name = "OPTION")]
        dns_option: Vec<String>,
        #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        #[arg(long = "env-file", value_name = "FILE")]
        env_file: Vec<PathBuf>,
        #[arg(short = 'w', long = "workdir", value_name = "DIR")]
        workdir: Option<String>,
        #[arg(short = 'u', long = "user", value_name = "USER")]
        user: Option<String>,
        #[arg(long = "entrypoint", value_name = "COMMAND")]
        entrypoint: Option<String>,
        #[arg(
            short = 'v',
            long = "volume",
            value_name = "host-src:container-dest[:ro|rw]"
        )]
        volume: Vec<String>,
        /// Mount volumes from another container.
        #[arg(long = "volumes-from", value_name = "CONTAINER[:ro|:rw]")]
        volumes_from: Vec<String>,
        #[arg(long = "mount", value_name = "type=bind,source=...,target=...")]
        mount: Vec<String>,
        #[arg(long = "name", value_name = "NAME")]
        name: Option<String>,
        /// Automatically remove the container when it exits
        #[arg(long = "rm")]
        rm: bool,
        #[arg(short = 't', long = "tty")]
        tty: bool,
        #[arg(short = 'i', long = "interactive")]
        interactive: bool,
        /// Publish a container's port(s) to the host.
        #[arg(short = 'p', long = "publish", value_name = "hostPort:containerPort")]
        publish: Vec<String>,
        /// Signal to stop the container (overrides the image `STOPSIGNAL`).
        #[arg(long = "stop-signal", value_name = "SIGNAL")]
        stop_signal: Option<String>,
        /// Seconds to wait before SIGKILL when stopping. Defaults to 10.
        #[arg(long = "stop-timeout", value_name = "SECONDS")]
        stop_timeout: Option<u64>,
        /// Docker-compatible security options (see `run --security-opt`).
        #[arg(long = "security-opt", value_name = "OPTION")]
        security_opt: Vec<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Start one or more created or stopped containers (like `docker start`).
    Start {
        /// Attach STDOUT/STDERR (not yet implemented; prints the id).
        #[arg(short = 'a', long = "attach")]
        attach: bool,
        #[arg(required = true)]
        containers: Vec<String>,
    },
    /// Restart one or more containers (like `docker restart`).
    Restart {
        /// Seconds to wait for graceful stop before SIGKILL. When omitted, the
        /// container's `--stop-timeout` (else 10s) applies.
        #[arg(short = 't', long = "time")]
        time: Option<u64>,
        #[arg(required = true)]
        containers: Vec<String>,
    },
    /// Run an optional Docker Engine API server over a unix socket
    /// (`DOCKER_HOST=unix://<host>`). Daemonless: a translator over the on-disk
    /// container registry, not a resident owner of containers.
    Serve {
        /// Answer the Docker Engine HTTP API (required; reserved for future
        /// protocols).
        #[arg(long = "docker-api")]
        docker_api: bool,
        /// Unix socket path to listen on.
        #[arg(
            long = "host",
            value_name = "PATH",
            default_value = "/tmp/carrick.sock"
        )]
        host: String,
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
        /// Don't truncate the container id / command.
        #[arg(long = "no-trunc")]
        no_trunc: bool,
        /// Format each row with a Go-template-style expression, e.g.
        /// `{{.ID}} {{.Names}} {{.Status}}`.
        #[arg(long = "format")]
        format: Option<String>,
    },
    /// Stop one or more running containers (SIGTERM, then SIGKILL after the
    /// grace period), like `docker stop`.
    Stop {
        /// Seconds to wait for graceful stop before SIGKILL. When omitted, the
        /// container's `--stop-timeout` (else 10s) applies.
        #[arg(short = 't', long = "time")]
        time: Option<u64>,
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
    /// Run a command in a running container (like `docker exec`). The command
    /// shares the container's filesystem and PID namespace. Requires the
    /// container to have been started with `--fs host`.
    Exec {
        /// Keep STDIN open even if not attached.
        #[arg(short = 'i', long = "interactive")]
        interactive: bool,
        /// Allocate a pseudo-terminal.
        #[arg(short = 't', long = "tty")]
        tty: bool,
        /// Username or UID (`uid[:gid]`) to run the command as.
        #[arg(short = 'u', long = "user", value_name = "USER")]
        user: Option<String>,
        /// Working directory inside the container for the command.
        #[arg(short = 'w', long = "workdir", value_name = "DIR")]
        workdir: Option<String>,
        /// Set environment variables for the command (`KEY=VALUE`).
        #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Container id or name.
        container: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// `compat-report` renders the HVF syscall-coverage report; macOS-only.
    #[cfg(feature = "platform-macos")]
    CompatReport {
        // `CompatReportFormat` parses via `FromStr`/`Display` (not a clap
        // `ValueEnum` derive) so its home crate carrick-observability does not
        // pull `clap` into every backend's compile closure.
        #[arg(long, default_value_t = CompatReportFormat::Json)]
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
    /// Manage Docker-compatible named volumes. On macOS, `volume create`
    /// without a name keeps the legacy APFS scratch-volume setup behavior.
    Volume {
        #[command(subcommand)]
        command: VolumeCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum VolumeCommand {
    /// Create a Docker-compatible named volume. With no NAME on macOS, create
    /// Carrick's case-sensitive APFS scratch volume.
    Create {
        #[arg(short = 'd', long = "driver", default_value = "local")]
        driver: String,
        #[arg(long = "label", value_name = "KEY=VALUE")]
        label: Vec<String>,
        #[arg(short = 'o', long = "opt", value_name = "KEY=VALUE")]
        opt: Vec<String>,
        /// Optional quota in bytes for the legacy APFS scratch volume path.
        #[arg(long)]
        quota: Option<u64>,
        name: Option<String>,
    },
    /// List Docker-compatible named volumes.
    #[command(visible_alias = "list")]
    Ls {
        #[arg(short = 'f', long = "filter", value_name = "KEY=VALUE")]
        filter: Vec<String>,
        #[arg(long = "format", value_name = "FORMAT")]
        format: Option<String>,
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
    },
    /// Remove unused Docker-compatible named volumes.
    Prune {
        #[arg(short = 'a', long = "all")]
        all: bool,
        #[arg(short = 'f', long = "force")]
        force: bool,
        #[arg(long = "filter", value_name = "KEY=VALUE")]
        filter: Vec<String>,
    },
    /// Inspect a Docker-compatible named volume.
    Inspect {
        #[arg(required = true)]
        names: Vec<String>,
    },
    /// Remove one or more Docker-compatible named volumes.
    #[command(visible_alias = "remove")]
    Rm {
        #[arg(short = 'f', long = "force")]
        force: bool,
        #[arg(required = true)]
        names: Vec<String>,
    },
    /// Print the carrick scratch volume's device, mount point, and
    /// case-sensitivity flag. Nonzero exit if no volume exists yet.
    #[cfg(target_os = "macos")]
    Info,
    /// Delete the carrick scratch volume. Destructive - anything on
    /// the volume is lost. Idempotent.
    #[cfg(target_os = "macos")]
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
    /// Run `carrick run` with a deadline and dump lldb diagnostics before
    /// killing the scoped container when the deadline expires.
    LldbRun {
        /// Seconds to let the guest run before attaching lldb and saving cores.
        #[arg(long = "deadline-seconds", default_value_t = 30)]
        deadline_seconds: u64,
        /// Directory for the guest log, lldb transcript, ps snapshot, and cores.
        #[arg(long = "out-dir", default_value = "target/conformance/logs/lldb-runs")]
        out_dir: PathBuf,
        /// Stable container/run id. Defaults to `--name` when present, otherwise
        /// a generated id is injected as `run --name`.
        #[arg(long = "run-id")]
        run_id: Option<String>,
        /// Path to `scripts/carrick_lldb.py`. Defaults to the repo script when
        /// running from a checkout.
        #[arg(long = "lldb-plugin")]
        lldb_plugin: Option<PathBuf>,
        /// Skip `process save-core`; still records event rings and backtraces.
        #[arg(long = "no-core")]
        no_core: bool,
        /// Ask forked guest processes to SIGSTOP just before dying by this Linux
        /// signal, then dump lldb diagnostics when the stopped scoped process is
        /// observed. Diagnostic-only; normal runs are unaffected.
        #[arg(long = "stop-on-signal")]
        stop_on_signal: Option<i32>,
        /// Arguments for `carrick run` after `--`, excluding the `run` word.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum RootfsCommand {
    Summary,
    Ls { path: PathBuf },
    Cat { path: PathBuf },
}

#[derive(Debug, Subcommand)]
pub(crate) enum SystemCommand {
    /// Show carrick disk usage (images, containers), like `docker system df`.
    Df,
    /// Remove stopped containers and unreferenced image layers, like
    /// `docker system prune`.
    Prune {
        /// Do not prompt for confirmation (accepted for compatibility; carrick
        /// does not prompt).
        #[arg(short = 'f', long = "force")]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum NetworkCommand {
    /// Create a Docker-compatible network resource.
    Create {
        #[arg(short = 'd', long = "driver", default_value = "bridge")]
        driver: String,
        #[arg(long = "label", value_name = "KEY=VALUE")]
        label: Vec<String>,
        #[arg(long = "subnet", value_name = "CIDR")]
        subnet: Vec<String>,
        #[arg(long = "gateway", value_name = "IPv4")]
        gateway: Vec<String>,
        #[arg(long = "ip-range", value_name = "CIDR")]
        ip_range: Vec<String>,
        #[arg(long = "aux-address", value_name = "KEY=VALUE")]
        aux_address: Vec<String>,
        #[arg(long = "ipam-driver", default_value = "default")]
        ipam_driver: String,
        #[arg(long = "ipam-opt", value_name = "KEY=VALUE")]
        ipam_opt: Vec<String>,
        #[arg(long = "scope", value_name = "SCOPE")]
        scope: Option<String>,
        #[arg(long = "internal")]
        internal: bool,
        #[arg(long = "attachable")]
        attachable: bool,
        #[arg(long = "ingress")]
        ingress: bool,
        #[arg(long = "config-from", value_name = "NETWORK")]
        config_from: Option<String>,
        #[arg(long = "config-only")]
        config_only: bool,
        #[arg(long = "ipv4", value_name = "BOOL", num_args = 0..=1, default_missing_value = "true")]
        ipv4: Option<bool>,
        #[arg(long = "ipv6")]
        ipv6: bool,
        #[arg(short = 'o', long = "opt", value_name = "KEY=VALUE")]
        opt: Vec<String>,
        name: String,
    },
    /// Connect a container to a Docker-compatible network resource.
    Connect {
        #[arg(long = "alias", value_name = "ALIAS")]
        alias: Vec<String>,
        #[arg(long = "link", value_name = "LINK")]
        link: Vec<String>,
        #[arg(long = "ip", value_name = "IPv4")]
        ip: Option<String>,
        #[arg(long = "ip6", value_name = "IPv6")]
        ip6: Option<String>,
        #[arg(long = "link-local-ip", value_name = "IP")]
        link_local_ip: Vec<String>,
        #[arg(long = "driver-opt", value_name = "KEY=VALUE")]
        driver_opt: Vec<String>,
        #[arg(long = "gw-priority", value_name = "INT")]
        gw_priority: Option<i64>,
        network: String,
        container: String,
    },
    /// Disconnect a container from a Docker-compatible network resource.
    Disconnect {
        #[arg(short = 'f', long = "force")]
        force: bool,
        network: String,
        container: String,
    },
    /// List Docker-compatible network resources.
    #[command(visible_alias = "list")]
    Ls,
    /// Remove unused Docker-compatible network resources.
    Prune {
        #[arg(short = 'f', long = "force")]
        force: bool,
        #[arg(long = "filter", value_name = "KEY=VALUE")]
        filter: Vec<String>,
    },
    /// Inspect a Docker-compatible network resource.
    Inspect {
        #[arg(required = true)]
        names: Vec<String>,
    },
    /// Remove one or more Docker-compatible network resources.
    #[command(visible_alias = "remove")]
    Rm {
        #[arg(required = true)]
        names: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands};
    #[cfg(feature = "platform-macos")]
    use carrick_spec::NativeCodeModeRequest;
    use clap::Parser;

    #[test]
    fn network_inspect_accepts_multiple_names_like_docker() {
        assert!(
            Cli::try_parse_from(["carrick", "network", "inspect", "net1", "net2"]).is_ok(),
            "network inspect should accept multiple names"
        );
    }

    #[test]
    fn volume_inspect_accepts_multiple_names_like_docker() {
        assert!(
            Cli::try_parse_from(["carrick", "volume", "inspect", "vol1", "vol2"]).is_ok(),
            "volume inspect should accept multiple names"
        );
    }

    #[test]
    #[cfg(feature = "platform-macos")]
    fn run_elf_accepts_explicit_dsr_code_mode() {
        let cli = Cli::try_parse_from([
            "carrick",
            "run-elf",
            "/tmp/probe",
            "--exec-backend",
            "native",
            "--native-page-profile",
            "native16k",
            "--native-code-mode",
            "dsr",
        ])
        .expect("parse DSR mode");
        assert!(matches!(
            cli.command,
            Commands::RunElf {
                native_code_mode: NativeCodeModeRequest::Dsr,
                ..
            }
        ));
    }
}
