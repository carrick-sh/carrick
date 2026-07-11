//! Runtime execution entry points that bridge shared run specs to
//! dispatcher-backed guest execution.

use crate::dispatch::SyscallDispatcher;
#[cfg(feature = "fs-memory")]
use crate::fs_backend::MemoryBackend;
use crate::fs_backend::{FsBackend, HostFsBackend};
use crate::network::NetworkHostsEntry;
use crate::rootfs::RootFs;
#[cfg(feature = "fs-memory")]
use crate::runtime::run_rootfs_elf_with_hvf_args_and_dispatcher_debug;
use crate::runtime::{RunResult, RuntimeError, run_elf_from_dispatcher_debug};
use crate::vfs::BindVfs;
use anyhow::{Context, Result};
use carrick_spec::{FsBackendKind, NetworkNamespaceSpec, PidMode, Platform, RunSpec};
use std::borrow::Cow;
use std::path::PathBuf;

/// True when a runtime error means the ENTRYPOINT executable (or its loader)
/// could not be found/read. The runc/shell convention is to exit 127 for that —
/// `docker run img /nope` and `sh -c nope` both yield 127 — not the generic 1 a
/// propagated error would produce.
fn is_entrypoint_not_found(e: &RuntimeError) -> bool {
    matches!(
        e,
        RuntimeError::AddressSpace(crate::memory::AddressSpaceError::Io(io))
            if io.kind() == std::io::ErrorKind::NotFound
    )
}

/// A 127 ("command not found") result for a failed entrypoint load.
fn entrypoint_not_found_result() -> RunResult {
    RunResult {
        exit_code: 127,
        stdout: Vec::new(),
        stderr: Vec::new(),
        traps: 0,
        report: crate::compat::CompatReport::default(),
        trap_limit_hit: false,
    }
}

/// True when the entrypoint EXISTS but cannot be executed as a program: a
/// non-ELF / malformed image (goblin parse failure → "exec format error") or a
/// permission denial (EACCES). The runc/shell convention is to exit 126 for
/// that — `docker run img /etc/hostname` yields 126 — distinct from 127 (not
/// found) and the generic 1 a propagated error would produce.
fn is_entrypoint_not_executable(e: &RuntimeError) -> bool {
    match e {
        // A file that isn't a loadable AArch64 ELF (wrong magic, truncated,
        // wrong machine, parse error): docker's "exec format error".
        RuntimeError::AddressSpace(crate::memory::AddressSpaceError::Elf(_)) => true,
        // The file exists but we lack execute/read permission: "permission denied".
        RuntimeError::AddressSpace(crate::memory::AddressSpaceError::Io(io)) => {
            io.kind() == std::io::ErrorKind::PermissionDenied
        }
        _ => false,
    }
}

/// A 126 ("command found but not executable") result for an entrypoint that
/// exists but cannot be loaded/exec'd.
fn entrypoint_not_executable_result() -> RunResult {
    RunResult {
        exit_code: 126,
        stdout: Vec::new(),
        stderr: Vec::new(),
        traps: 0,
        report: crate::compat::CompatReport::default(),
        trap_limit_hit: false,
    }
}

/// For a detached container (`CARRICK_CONTAINER_ID` set), the stable on-disk
/// overlay path `<registry>/<id>/scratch`, recording it into the registry so
/// `carrick exec` can attach the same filesystem. `None` for a foreground run
/// (which uses an ephemeral per-run scratch). Best-effort registry write — a
/// failure just means `exec` can't find the overlay later, not a run failure.
fn detached_stable_scratch() -> Option<PathBuf> {
    let id = std::env::var("CARRICK_CONTAINER_ID").ok()?;
    if !crate::container::is_safe_id(&id) {
        return None;
    }
    let scratch = crate::container::container_dir(&id).join("scratch");
    if let Ok(mut state) = crate::container::ContainerState::load(&id) {
        state.config.scratch_path = Some(scratch.to_string_lossy().into_owned());
        let _ = state.persist();
    }
    Some(scratch)
}

/// For an `amd64` (Rosetta-translated) container, expose the host's Rosetta
/// runtime files inside the guest VFS at the same paths. Rosetta opens these at
/// startup to load its support libraries and (optionally) its AOT translation
/// cache; they do not exist in the OCI image. The `oah` runtime dir is mapped
/// read-only; the per-user cache dir is writable (best-effort — it is
/// SIP-protected and may be inaccessible, in which case Rosetta JITs without a
/// persistent cache).
/// Environment variable by which the operator acknowledges responsibility for
/// complying with Apple's macOS Software License Agreement when running amd64
/// containers through Rosetta 2. Setting it (to any value) accepts that risk
/// and suppresses the per-run reminder.
pub const ROSETTA_ACCEPT_ENV: &str = "CARRICK_ACCEPT_ROSETTA_TERMS";

/// Print a one-time (per process) reminder that amd64 support drives Apple's
/// Rosetta 2 — which carrick does not bundle or redistribute — and that its use
/// is governed by Apple's macOS Software License Agreement. Suppressed once the
/// operator accepts the terms via [`ROSETTA_ACCEPT_ENV`] (or the legacy
/// `CARRICK_NO_ROSETTA_NOTICE`). Goes to stderr so it never corrupts a `--raw`
/// guest's stdout.
fn rosetta_license_notice() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static SHOWN: AtomicBool = AtomicBool::new(false);
    if std::env::var_os(ROSETTA_ACCEPT_ENV).is_some()
        || std::env::var_os("CARRICK_NO_ROSETTA_NOTICE").is_some()
    {
        return;
    }
    if SHOWN.swap(true, Ordering::Relaxed) {
        return;
    }
    eprintln!(
        "carrick: running an amd64 container via Apple Rosetta 2 (translation \
         provided by your macOS install; carrick bundles none of it). Use is \
         subject to Apple's macOS Software License Agreement. Set {ROSETTA_ACCEPT_ENV}=1 \
         to accept and silence this notice."
    );
}

fn install_rosetta_mounts(dispatcher: &mut SyscallDispatcher) {
    const ROSETTA_RUNTIME_DIR: &str = "/Library/Apple/usr/libexec/oah";
    const ROSETTA_CACHE_DIR: &str = "/var/db/oah";
    for (path, readonly) in [(ROSETTA_RUNTIME_DIR, true), (ROSETTA_CACHE_DIR, false)] {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        let bind = BindVfs::new(path, PathBuf::from(path), readonly);
        dispatcher.register_mount(PathBuf::from(path), Box::new(bind));
    }
}

pub struct Runtime;

impl Runtime {
    pub fn execute(spec: &RunSpec) -> Result<RunResult, RuntimeError> {
        // Guardrail: execute() forks (PID-namespace NsSupervisor, interactive
        // session, and guest fork(2)). A live tokio runtime must NOT survive into
        // here — its blocking-pool threads don't survive fork, so a forked child
        // deadlocks in BlockingPool::shutdown. Callers resolve the image under
        // tokio, DROP the runtime, then call execute.
        debug_assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "tokio runtime must not be live when Runtime::execute is called \
             (tokio-fork-isolation invariant)"
        );
        if spec.platform == Platform::Amd64 {
            rosetta_license_notice();
        }
        let execution_plan = crate::page_profile::resolve_execution_plan(spec)?;
        crate::page_profile::validate_native_code_mode(spec.native_code_mode, &execution_plan)?;
        if execution_plan.backend != crate::page_profile::ExecutionBackend::NativeDarwin {
            debug_assert_eq!(
                execution_plan.page_geometry.linux_page_size,
                crate::page_profile::DEFAULT_LINUX_PAGE_SIZE
            );
        }
        // Container launch (`carrick run <image>`) places the root guest in a
        // fresh PID namespace so its init sees getpid()==1, ns-local child
        // pids, and an ns-filtered /proc — the headline docker-run behavior
        // (docs/namespaces-design.md §1.0, §5.2). `run-elf` bypasses
        // Runtime::execute entirely, so it stays in the identity namespace.
        // `--pid=host` opts out (shares the host pid ns, like docker), leaving
        // the guest with host pids and no supervisor.
        //
        // The forking NsSupervisor (orphan reaping + teardown) is enabled only
        // for STREAMING output paths (raw / tty), where the guest writes to
        // inherited fds: the supervisor becomes the fork parent and returns the
        // run result, which carries no buffered stdout/stderr. The default
        // buffered JSON-envelope path keeps the guest in-process (translation
        // still works) so its captured output is returned as before.
        match spec.pid {
            PidMode::Host => {} // share the host pid ns — no placement.
            PidMode::Private => {
                if let Ok(region) = std::env::var("CARRICK_JOIN_REGION") {
                    // `carrick exec`: join the running container's namespace as a
                    // member — do NOT fork our own supervisor (it already has one).
                    if !crate::namespace::pid::join_existing(std::path::Path::new(&region)) {
                        return Err(RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to join container namespace at {region}"
                        )));
                    }
                } else if spec.raw || spec.tty {
                    crate::namespace::pid::request_supervisor();
                } else {
                    crate::namespace::pid::request();
                }
            }
        }
        // Name the host process `carrick: <argv>` up front so
        // it's identifiable in ps/Activity Monitor even before the
        // guest sets its own comm via prctl.
        {
            let cmdline = spec.argv.join(" ");
            crate::dispatch::set_host_process_name(cmdline.as_bytes());
        }

        // The environment is already fully resolved by the engine layer
        // (image ENV + baseline defaults for missing keys + CLI overrides, in
        // docker precedence). Pass it through verbatim — injecting a second
        // baseline here would place duplicate keys *before* spec.envp, and
        // glibc's getenv returns the first match, silently overriding the
        // image's own ENV (e.g. PATH). The engine is the single source of env.
        let env: Vec<String> = spec.envp.clone();
        let runtime_network = std::sync::Arc::new(
            crate::network::RuntimeNetwork::create(&spec.network)
                .map_err(|e| RuntimeError::Unsupported(format!("network setup failed: {e}")))?,
        );

        let result = match spec.fs_backend {
            FsBackendKind::Host => {
                // Stream every OCI layer straight onto the cap-std scratch Dir.
                // `carrick exec` ATTACHES the running container's existing overlay
                // (already holds the full rootfs + the container's writes) and
                // skips extraction. A DETACHED container gets a STABLE overlay
                // under its registry dir (persisted + shared with `exec`, cleaned
                // up by `rm`); a foreground run gets an ephemeral per-run TempDir.
                let exec_overlay = std::env::var("CARRICK_EXEC_OVERLAY").ok();
                let mut host = if let Some(scratch) = &exec_overlay {
                    HostFsBackend::attach(std::path::Path::new(scratch)).map_err(|e| {
                        RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to attach container overlay {scratch}: {e}"
                        ))
                    })?
                } else if let Some(scratch) = detached_stable_scratch() {
                    HostFsBackend::attach_or_create(&scratch).map_err(|e| {
                        RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to create container overlay: {}",
                            e
                        ))
                    })?
                } else {
                    HostFsBackend::new().map_err(|e| {
                        RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to create scratch directory: {}",
                            e
                        ))
                    })?
                };

                // Convert layers to Vec<PathBuf>
                let layer_paths: Vec<PathBuf> = spec
                    .rootfs_layers
                    .iter()
                    .map(|p| PathBuf::from(p.as_std_path()))
                    .collect();

                // `exec` reuses the container's overlay, which already holds the
                // extracted rootfs — re-extracting would clobber the container's
                // runtime writes. Only a fresh run extracts.
                if exec_overlay.is_none() {
                    host.extract_layers(&layer_paths).map_err(|e| {
                        RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to stream OCI layers: {}",
                            e
                        ))
                    })?;
                }

                let mut dispatcher = SyscallDispatcher::with_network(runtime_network.clone());
                dispatcher.set_page_geometry(execution_plan.page_geometry);
                let guest_hostname = effective_guest_hostname(spec);
                dispatcher.set_guest_hostname(guest_hostname.as_ref());
                // Sandboxed container fs (extracted OCI layers on a cap-std
                // overlay): forbid the execve host-fs fallback so a target
                // absent from the container ENOENTs instead of escaping to the
                // matching host binary.
                dispatcher.sandbox_exec_to_container();
                dispatcher.set_executable_path(spec.executable.clone());
                if let Some(cwd) = &spec.cwd {
                    dispatcher.set_cwd(cwd.as_str());
                }
                dispatcher.set_credentials(spec.uid, spec.gid);
                // Launch-time container syscall policy (the Docker default-
                // seccomp model, or unconfined) — before boot, inherited by the
                // whole guest process tree. See crate::container_policy.
                dispatcher.apply_seccomp_policy(spec.seccomp_policy);

                let hosts_entries = runtime_network.guest_hosts_entries().map_err(|e| {
                    RuntimeError::Unsupported(format!("network hosts setup failed: {e}"))
                })?;
                seed_guest_baseline(
                    &mut host,
                    None,
                    &spec.network,
                    &hosts_entries,
                    &spec.extra_hosts,
                    guest_hostname.as_ref(),
                );

                // Install custom bind mounts on dispatcher
                for mount in &spec.mounts {
                    let host_path = PathBuf::from(mount.source.as_std_path());
                    let target_path = PathBuf::from(mount.target.as_std_path());
                    let bind_vfs = BindVfs::new(mount.target.as_str(), host_path, mount.readonly);
                    dispatcher.register_mount(target_path, Box::new(bind_vfs));
                }
                if spec.platform == Platform::Amd64 {
                    install_rosetta_mounts(&mut dispatcher);
                }

                let _ = dispatcher.set_fs_backend(Box::new(host));

                // Interactive pty or raw stream
                let _supervisor_parent =
                    setup_interactive_stdio(&mut dispatcher, spec.tty, spec.raw).map_err(|e| {
                        RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to setup interactive stdio: {}",
                            e
                        ))
                    })?;
                if let Some(parent) = _supervisor_parent {
                    let code = parent.relay_and_wait().map_err(|e| {
                        RuntimeError::FsBackend(anyhow::anyhow!(
                            "interactive supervisor failed: {}",
                            e
                        ))
                    })?;
                    return Ok(RunResult {
                        exit_code: code,
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        traps: 0,
                        report: crate::compat::CompatReport::default(),
                        trap_limit_hit: false,
                    });
                }

                let debug_path = spec
                    .debug_state_path
                    .as_ref()
                    .map(|p| PathBuf::from(p.as_std_path()));
                let run_result = if execution_plan.backend
                    == crate::page_profile::ExecutionBackend::NativeDarwin
                {
                    crate::native_darwin::run_elf_from_dispatcher_debug(
                        &spec.executable,
                        dispatcher,
                        spec.argv.clone(),
                        env,
                        spec.max_traps,
                        debug_path.as_ref(),
                        spec.native_code_mode,
                        &execution_plan,
                    )
                } else {
                    run_elf_from_dispatcher_debug(
                        &spec.executable,
                        dispatcher,
                        spec.argv.clone(),
                        env,
                        spec.max_traps,
                        debug_path.as_ref(),
                    )
                };
                match run_result {
                    Ok(r) => r,
                    Err(e) if is_entrypoint_not_found(&e) => {
                        return Ok(entrypoint_not_found_result());
                    }
                    Err(e) if is_entrypoint_not_executable(&e) => {
                        return Ok(entrypoint_not_executable_result());
                    }
                    Err(e) => {
                        return Err(RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to run ELF from dispatcher: {}",
                            e
                        )));
                    }
                }
            }
            #[cfg(feature = "fs-memory")]
            FsBackendKind::Memory => {
                let layer_paths: Vec<PathBuf> = spec
                    .rootfs_layers
                    .iter()
                    .map(|p| PathBuf::from(p.as_std_path()))
                    .collect();

                let rootfs = RootFs::from_layer_paths(&layer_paths).map_err(|e| {
                    RuntimeError::FsBackend(anyhow::anyhow!("failed to compose rootfs: {}", e))
                })?;

                let mut dispatcher = SyscallDispatcher::with_rootfs_and_executable(
                    rootfs.clone(),
                    spec.executable.clone(),
                );
                dispatcher.set_page_geometry(execution_plan.page_geometry);
                let guest_hostname = effective_guest_hostname(spec);
                dispatcher.set_guest_hostname(guest_hostname.as_ref());
                if let Some(cwd) = &spec.cwd {
                    dispatcher.set_cwd(cwd.as_str());
                }
                dispatcher.set_credentials(spec.uid, spec.gid);
                // Same launch-time policy application as the Host branch.
                dispatcher.apply_seccomp_policy(spec.seccomp_policy);

                install_fs_backend(
                    &mut dispatcher,
                    FsBackendKind::Memory,
                    guest_hostname.as_ref(),
                )
                .map_err(|e| {
                    RuntimeError::FsBackend(anyhow::anyhow!("failed to install fs backend: {}", e))
                })?;

                // Install custom bind mounts on dispatcher
                for mount in &spec.mounts {
                    let host_path = PathBuf::from(mount.source.as_std_path());
                    let target_path = PathBuf::from(mount.target.as_std_path());
                    let bind_vfs = BindVfs::new(mount.target.as_str(), host_path, mount.readonly);
                    dispatcher.register_mount(target_path, Box::new(bind_vfs));
                }
                if spec.platform == Platform::Amd64 {
                    install_rosetta_mounts(&mut dispatcher);
                }

                // Interactive pty or raw stream
                let _supervisor_parent =
                    setup_interactive_stdio(&mut dispatcher, spec.tty, spec.raw).map_err(|e| {
                        RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to setup interactive stdio: {}",
                            e
                        ))
                    })?;
                if let Some(parent) = _supervisor_parent {
                    let code = parent.relay_and_wait().map_err(|e| {
                        RuntimeError::FsBackend(anyhow::anyhow!(
                            "interactive supervisor failed: {}",
                            e
                        ))
                    })?;
                    return Ok(RunResult {
                        exit_code: code,
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        traps: 0,
                        report: crate::compat::CompatReport::default(),
                        trap_limit_hit: false,
                    });
                }

                let debug_path = spec
                    .debug_state_path
                    .as_ref()
                    .map(|p| PathBuf::from(p.as_std_path()));
                let run_result = if execution_plan.backend
                    == crate::page_profile::ExecutionBackend::NativeDarwin
                {
                    crate::native_darwin::run_elf_from_dispatcher_debug(
                        &spec.executable,
                        dispatcher,
                        spec.argv.clone(),
                        env,
                        spec.max_traps,
                        debug_path.as_ref(),
                        spec.native_code_mode,
                        &execution_plan,
                    )
                } else {
                    run_rootfs_elf_with_hvf_args_and_dispatcher_debug(
                        &spec.executable,
                        &rootfs,
                        dispatcher,
                        spec.argv.clone(),
                        env,
                        spec.max_traps,
                        debug_path.as_ref(),
                    )
                };
                match run_result {
                    Ok(r) => r,
                    Err(e) if is_entrypoint_not_found(&e) => {
                        return Ok(entrypoint_not_found_result());
                    }
                    Err(e) if is_entrypoint_not_executable(&e) => {
                        return Ok(entrypoint_not_executable_result());
                    }
                    Err(e) => {
                        return Err(RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to run rootfs ELF: {}",
                            e
                        )));
                    }
                }
            }
        };

        Ok(result)
    }
}

/// On a `--fs host` failure, fall back to the in-memory backend. Only compiled
/// with the `fs-memory` feature, because `install_fs_backend` (its only caller)
/// is reachable solely through the feature-gated `FsBackendKind::Memory` arm.
#[cfg(feature = "fs-memory")]
fn host_failure_fallback(reason: &str) -> anyhow::Result<Box<dyn FsBackend>> {
    eprintln!("carrick: {reason}; falling back to in-memory backend");
    Ok(Box::new(MemoryBackend::new()))
}

/// Build and install a fs backend for the `run-elf`/memory fixture path. Only
/// reachable from the `fs-memory`-gated `FsBackendKind::Memory` arm above, so it
/// is compiled only when that feature is on.
#[cfg(feature = "fs-memory")]
fn install_fs_backend(
    dispatcher: &mut SyscallDispatcher,
    kind: FsBackendKind,
    guest_hostname: &str,
) -> anyhow::Result<()> {
    let mut host_seeded = false;
    let mut backend: Box<dyn FsBackend> = match kind {
        #[cfg(feature = "fs-memory")]
        FsBackendKind::Memory => Box::new(MemoryBackend::new()),
        FsBackendKind::Host => match HostFsBackend::new() {
            Ok(mut host) => {
                if let Some(rootfs) = dispatcher.rootfs() {
                    host.seed_from_rootfs(rootfs)?;
                    host_seeded = true;
                }
                Box::new(host)
            }
            Err(err) => host_failure_fallback(&format!("--fs host failed ({err})"))?,
        },
    };
    let default_network = NetworkNamespaceSpec::default();
    seed_guest_baseline(
        &mut *backend,
        dispatcher.rootfs(),
        &default_network,
        &[],
        &[],
        guest_hostname,
    );
    let _ = dispatcher.set_fs_backend(backend);
    if host_seeded {
        dispatcher.drop_rootfs_layer();
    }
    Ok(())
}

/// The guest's hostname under the current `--net=host` contract: the macOS
/// host's short hostname (so the guest shares the host's network identity), or
/// the `carrick` fallback when the host name is unavailable/empty. SINGLE
/// accessor for `uname(2)` nodename, `/proc/sys/kernel/hostname`, and the
/// `/etc/hosts` self-mapping — keeping them in lockstep and giving a future UTS
/// namespace one place to override per-namespace instead of scattered literals.
pub fn guest_hostname() -> &'static str {
    carrick_host::host_facts::host_short_hostname().unwrap_or(crate::linux_abi::CARRICK_HOSTNAME)
}

fn effective_guest_hostname(spec: &RunSpec) -> Cow<'_, str> {
    spec.hostname
        .as_deref()
        .filter(|hostname| !hostname.is_empty())
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Borrowed(guest_hostname()))
}

fn seed_guest_baseline(
    backend: &mut dyn FsBackend,
    rootfs: Option<&RootFs>,
    network: &NetworkNamespaceSpec,
    network_hosts_entries: &[NetworkHostsEntry],
    extra_hosts: &[String],
    guest_hostname: &str,
) {
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
    set_baseline_file_if_missing(
        backend,
        rootfs,
        "/etc/passwd",
        b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            .to_vec(),
    );
    set_baseline_file_if_missing(
        backend,
        rootfs,
        "/etc/group",
        b"root:x:0:\nnogroup:x:65534:\n".to_vec(),
    );
    set_baseline_file_if_missing(
        backend,
        rootfs,
        "/etc/nsswitch.conf",
        b"passwd: files\ngroup: files\nhosts: files dns\n".to_vec(),
    );

    // /etc/hosts is RUNTIME-managed under the --net=host contract: like Docker,
    // carrick regenerates it on every start (NOT an if-missing seed) so the guest
    // always resolves `localhost` AND its own hostname
    // (`gethostbyname(gethostname())`) — apps routinely look up their own name to
    // find their IP. Docker images typically ship an EMPTY /etc/hosts and rely on
    // the runtime to populate it, so an existence guard here would (wrongly) leave
    // the guest unable to resolve itself (Go os Test...; CPython test_socket).
    let network_model = crate::network::model::LinuxNetworkModel::from_spec(network);
    let mut hosts_content = network_model
        .hosts_config(
            network,
            network_hosts_entries
                .iter()
                .map(|entry| (entry.addr, entry.names.clone())),
            extra_hosts,
            guest_hostname,
        )
        .render();
    // Pre-resolving the Debian/Ubuntu apt mirrors here was ~8 blocking
    // getaddrinfo() calls (~80 ms via mDNSResponder) on EVERY startup — a profile
    // showed it was the #2 cost after diskutil. It predates carrick synthesizing
    // /etc/resolv.conf from the host resolver, so the guest now resolves these
    // mirrors itself; the static seed is redundant. Keep it available behind an
    // opt-in env for offline/locked-down apt runs, but off the default hot path.
    if std::env::var_os("CARRICK_SEED_APT_MIRRORS").is_some() {
        const HOSTNAMES: &[&str] = &[
            "deb.debian.org",
            "security.debian.org",
            "ftp.debian.org",
            "archive.ubuntu.com",
            "security.ubuntu.com",
            "ports.ubuntu.com",
        ];
        for hostname in HOSTNAMES {
            if let Ok(addrs) = (*hostname, 80u16).to_socket_addrs() {
                for addr in addrs {
                    if let std::net::IpAddr::V4(v4) = addr.ip() {
                        hosts_content.push_str(&format!("{}\t{}\n", v4, hostname));
                        break;
                    }
                }
            }
        }
    }
    // Preserve any NON-loopback entries the image baked into /etc/hosts (rare —
    // most ship it empty — but a custom alias shouldn't silently vanish). carrick
    // owns the loopback + self lines above, so skip those to avoid duplicates.
    let existing = backend
        .file_contents("/etc/hosts")
        .or_else(|| rootfs.and_then(|r| r.read("/etc/hosts").ok()))
        .unwrap_or_default();
    for line in String::from_utf8_lossy(&existing).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let first = trimmed.split_whitespace().next().unwrap_or("");
        let carrick_managed = matches!(
            first,
            "127.0.0.1" | "127.0.1.1" | "::1" | "ff02::1" | "ff02::2"
        );
        if !carrick_managed {
            hosts_content.push_str(trimmed);
            hosts_content.push('\n');
        }
    }
    let _ = backend.set_file_contents("/etc/hosts", hosts_content.into_bytes());
    // /etc/hostname must agree with uname(2)/gethostname()/proc — overwrite any
    // build-time value from the image with the runtime guest hostname (Docker
    // likewise writes the container hostname here at create). Unconditional: a
    // stale image hostname is exactly the bug.
    let _ = backend.set_file_contents(
        "/etc/hostname",
        format!("{}\n", guest_hostname).into_bytes(),
    );
}

fn set_baseline_file_if_missing(
    backend: &mut dyn FsBackend,
    rootfs: Option<&RootFs>,
    path: &str,
    contents: Vec<u8>,
) {
    if backend.metadata(path).is_some()
        || rootfs
            .and_then(|rootfs| rootfs.metadata(path).ok())
            .is_some()
    {
        return;
    }
    let _ = backend.set_file_contents(path, contents);
}

fn setup_interactive_stdio(
    dispatcher: &mut SyscallDispatcher,
    tty: bool,
    raw: bool,
) -> anyhow::Result<Option<crate::interactive_supervisor::InteractiveParent>> {
    if !tty {
        if raw {
            dispatcher.set_stream_stdio(true);
        }
        return Ok(None);
    }
    // Guardrail: forking with a live tokio runtime deadlocks the child in
    // BlockingPool::shutdown (the blocking-pool worker threads don't survive
    // fork). The CLI must resolve the image under tokio, drop the runtime, then
    // call execute — so no tokio runtime is current here.
    debug_assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "tokio runtime must not be live across the interactive-session fork \
         (tokio-fork-isolation invariant)"
    );
    match crate::interactive_supervisor::fork_interactive_session()
        .context("failed to create interactive session supervisor")?
    {
        crate::interactive_supervisor::SupervisorFork::Parent(parent) => Ok(Some(parent)),
        crate::interactive_supervisor::SupervisorFork::Child(child) => {
            child
                .adopt_stdio(dispatcher)
                .context("failed to adopt interactive pty in runtime child")?;
            Ok(None)
        }
    }
}

#[cfg(test)]
mod exit_code_tests {
    use super::{Runtime, is_entrypoint_not_executable, is_entrypoint_not_found};
    use crate::elf::ElfInspectError;
    use crate::fs_backend::{FsBackend, MemoryBackend};
    use crate::memory::AddressSpaceError;
    use crate::runtime::RuntimeError;
    use camino::Utf8PathBuf;
    use carrick_spec::{
        ExecBackendRequest, FsBackendKind, NativePageProfileRequest, NetworkNamespaceSpec, PidMode,
        Platform, RunSpec,
    };
    use std::io::{Error as IoError, ErrorKind};

    fn rt_io(kind: ErrorKind) -> RuntimeError {
        RuntimeError::AddressSpace(AddressSpaceError::Io(IoError::from(kind)))
    }
    fn rt_not_elf() -> RuntimeError {
        RuntimeError::AddressSpace(AddressSpaceError::Elf(ElfInspectError::NotElf))
    }

    fn native_run_spec(page_profile: NativePageProfileRequest) -> RunSpec {
        RunSpec {
            executable: "/bin/sh".to_string(),
            argv: vec!["/bin/sh".to_string()],
            envp: Vec::new(),
            cwd: Some(Utf8PathBuf::from("/")),
            rootfs_layers: Vec::new(),
            fs_backend: FsBackendKind::Host,
            mounts: Vec::new(),
            tty: false,
            raw: true,
            interactive: false,
            max_traps: 100,
            debug_state_path: None,
            platform: Platform::Aarch64,
            exec_backend: ExecBackendRequest::Native,
            native_page_profile: page_profile,
            native_code_mode: carrick_spec::NativeCodeModeRequest::Brk,
            pid: PidMode::Host,
            hostname: None,
            network: NetworkNamespaceSpec::default(),
            extra_hosts: Vec::new(),
            uid: 0,
            gid: 0,
            seccomp_policy: carrick_spec::SeccompPolicy::ContainerDefault,
        }
    }

    #[test]
    fn not_found_maps_to_127_class_only() {
        // docker/runc/shell: a missing entrypoint is 127.
        assert!(is_entrypoint_not_found(&rt_io(ErrorKind::NotFound)));
        assert!(!is_entrypoint_not_found(&rt_io(
            ErrorKind::PermissionDenied
        )));
        assert!(!is_entrypoint_not_found(&rt_not_elf()));
    }

    #[test]
    fn not_executable_maps_to_126_class_only() {
        // docker/runc: an entrypoint that exists but cannot exec (non-ELF
        // "exec format error", or EACCES "permission denied") is 126 — not 127,
        // not the generic 1.
        assert!(is_entrypoint_not_executable(&rt_not_elf()));
        assert!(is_entrypoint_not_executable(&rt_io(
            ErrorKind::PermissionDenied
        )));
        assert!(!is_entrypoint_not_executable(&rt_io(ErrorKind::NotFound)));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn explicit_native_linux4k_uses_container_entrypoint_resolution() {
        let result = Runtime::execute(&native_run_spec(NativePageProfileRequest::Linux4k))
            .expect("native container setup should classify a missing entrypoint");

        assert_eq!(result.exit_code, 127);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn seed_guest_baseline_writes_extra_hosts_entries() {
        let mut backend = MemoryBackend::new();
        let network = NetworkNamespaceSpec::default();
        super::seed_guest_baseline(
            &mut backend,
            None,
            &network,
            &[],
            &["db.local:10.12.0.7".to_string()],
            "api-host",
        );

        let hosts = String::from_utf8(backend.file_contents("/etc/hosts").unwrap()).unwrap();
        assert!(
            hosts.contains("10.12.0.7\tdb.local\n"),
            "extra host entry missing from /etc/hosts:\n{hosts}"
        );
    }

    #[test]
    fn seed_guest_baseline_adds_bridge_host_gateway_names() {
        let mut backend = MemoryBackend::new();
        let network =
            NetworkNamespaceSpec::bridge_default(Some("web".to_string()), Vec::new(), Vec::new());
        super::seed_guest_baseline(&mut backend, None, &network, &[], &[], "api-host");

        let hosts = String::from_utf8(backend.file_contents("/etc/hosts").unwrap()).unwrap();
        assert!(
            hosts.contains("172.31.0.1\thost.docker.internal gateway.docker.internal\n"),
            "bridge /etc/hosts should include Docker Desktop host gateway names:\n{hosts}"
        );
    }

    #[test]
    fn seed_guest_baseline_expands_extra_host_gateway_token() {
        let mut backend = MemoryBackend::new();
        let network =
            NetworkNamespaceSpec::bridge_default(Some("web".to_string()), Vec::new(), Vec::new());
        super::seed_guest_baseline(
            &mut backend,
            None,
            &network,
            &[],
            &["host.docker.internal:host-gateway".to_string()],
            "api-host",
        );

        let hosts = String::from_utf8(backend.file_contents("/etc/hosts").unwrap()).unwrap();
        assert!(
            hosts.contains("172.31.0.1\thost.docker.internal\n"),
            "host-gateway token should expand to the bridge gateway:\n{hosts}"
        );
    }

    #[test]
    fn seed_guest_baseline_extra_hosts_override_generated_gateway_name() {
        let mut backend = MemoryBackend::new();
        let network =
            NetworkNamespaceSpec::bridge_default(Some("web".to_string()), Vec::new(), Vec::new());
        super::seed_guest_baseline(
            &mut backend,
            None,
            &network,
            &[],
            &["host.docker.internal:10.12.0.7".to_string()],
            "api-host",
        );

        let hosts = String::from_utf8(backend.file_contents("/etc/hosts").unwrap()).unwrap();
        assert!(
            hosts.contains("10.12.0.7\thost.docker.internal\n"),
            "explicit host entry should be preserved:\n{hosts}"
        );
        assert!(
            !hosts.contains("172.31.0.1\thost.docker.internal"),
            "explicit host.docker.internal should override the generated gateway entry:\n{hosts}"
        );
        assert!(
            hosts.contains("172.31.0.1\tgateway.docker.internal\n"),
            "unoverridden gateway.docker.internal should still be generated:\n{hosts}"
        );
    }

    #[test]
    fn seed_guest_baseline_writes_requested_hostname_surfaces() {
        let mut backend = MemoryBackend::new();
        let network = NetworkNamespaceSpec::default();
        super::seed_guest_baseline(&mut backend, None, &network, &[], &[], "api-host");

        let hosts = String::from_utf8(backend.file_contents("/etc/hosts").unwrap()).unwrap();
        assert!(
            hosts.contains("127.0.1.1\tapi-host\n"),
            "requested hostname missing from /etc/hosts:\n{hosts}"
        );
        assert_eq!(
            backend.file_contents("/etc/hostname").unwrap(),
            b"api-host\n"
        );
    }
}
