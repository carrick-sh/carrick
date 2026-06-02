//! Runtime execution entry points that bridge shared run specs to
//! dispatcher-backed guest execution.

use crate::dispatch::SyscallDispatcher;
use crate::fs_backend::{FsBackend, HostFsBackend, MemoryBackend};
use crate::rootfs::RootFs;
use crate::runtime::{
    RunResult, RuntimeError, run_elf_from_dispatcher_debug,
    run_rootfs_elf_with_hvf_args_and_dispatcher_debug,
};
use crate::vfs::BindVfs;
use anyhow::{Context, Result};
use carrick_spec::{FsBackendKind, PidMode, Platform, RunSpec};
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
        if spec.platform == Platform::Amd64 {
            rosetta_license_notice();
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
                if spec.raw || spec.tty {
                    crate::namespace::pid::request_supervisor();
                } else {
                    crate::namespace::pid::request();
                }
            }
        }
        // Name the host process `carrick: <basename>` up front so
        // it's identifiable in ps/Activity Monitor even before the
        // guest sets its own comm via prctl.
        {
            let exec_path = &spec.executable;
            let base = exec_path.rsplit('/').next().unwrap_or(exec_path);
            crate::dispatch::set_host_process_name(base.as_bytes());
        }

        // The environment is already fully resolved by the engine layer
        // (image ENV + baseline defaults for missing keys + CLI overrides, in
        // docker precedence). Pass it through verbatim — injecting a second
        // baseline here would place duplicate keys *before* spec.envp, and
        // glibc's getenv returns the first match, silently overriding the
        // image's own ENV (e.g. PATH). The engine is the single source of env.
        let env: Vec<String> = spec.envp.clone();

        let result = match spec.fs_backend {
            FsBackendKind::Host => {
                // Stream every OCI layer straight onto the cap-std scratch Dir.
                // A DETACHED container gets a STABLE overlay under its registry
                // dir (persisted + shared with `exec`, cleaned up by `rm`); a
                // foreground run gets an ephemeral per-run TempDir.
                let mut host = match detached_stable_scratch() {
                    Some(scratch) => HostFsBackend::attach_or_create(&scratch).map_err(|e| {
                        RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to create container overlay: {}",
                            e
                        ))
                    })?,
                    None => HostFsBackend::new().map_err(|e| {
                        RuntimeError::FsBackend(anyhow::anyhow!(
                            "failed to create scratch directory: {}",
                            e
                        ))
                    })?,
                };

                // Convert layers to Vec<PathBuf>
                let layer_paths: Vec<PathBuf> = spec
                    .rootfs_layers
                    .iter()
                    .map(|p| PathBuf::from(p.as_std_path()))
                    .collect();

                host.extract_layers(&layer_paths).map_err(|e| {
                    RuntimeError::FsBackend(anyhow::anyhow!("failed to stream OCI layers: {}", e))
                })?;

                let mut dispatcher = SyscallDispatcher::new();
                dispatcher.set_executable_path(spec.executable.clone());
                if let Some(cwd) = &spec.cwd {
                    dispatcher.set_cwd(cwd.as_str());
                }
                dispatcher.set_credentials(spec.uid, spec.gid);

                seed_guest_baseline(&mut host, None);

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
                let run_result = run_elf_from_dispatcher_debug(
                    &spec.executable,
                    dispatcher,
                    spec.argv.clone(),
                    env,
                    spec.max_traps,
                    debug_path.as_ref(),
                );
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
                if let Some(cwd) = &spec.cwd {
                    dispatcher.set_cwd(cwd.as_str());
                }
                dispatcher.set_credentials(spec.uid, spec.gid);

                install_fs_backend(&mut dispatcher, FsBackendKind::Memory).map_err(|e| {
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
                let run_result = run_rootfs_elf_with_hvf_args_and_dispatcher_debug(
                    &spec.executable,
                    &rootfs,
                    dispatcher,
                    spec.argv.clone(),
                    env,
                    spec.max_traps,
                    debug_path.as_ref(),
                );
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

fn install_fs_backend(
    dispatcher: &mut SyscallDispatcher,
    kind: FsBackendKind,
) -> anyhow::Result<()> {
    let mut host_seeded = false;
    let mut backend: Box<dyn FsBackend> = match kind {
        FsBackendKind::Memory => Box::new(MemoryBackend::new()),
        FsBackendKind::Host => match HostFsBackend::new() {
            Ok(mut host) => {
                if let Some(rootfs) = dispatcher.rootfs() {
                    host.seed_from_rootfs(rootfs)?;
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
    seed_guest_baseline(&mut *backend, dispatcher.rootfs());
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

fn seed_guest_baseline(backend: &mut dyn FsBackend, rootfs: Option<&RootFs>) {
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
    let mut hosts_content = String::from(
        "127.0.0.1\tlocalhost\n\
         ::1\tlocalhost ip6-localhost ip6-loopback\n\
         ff02::1\tip6-allnodes\n\
         ff02::2\tip6-allrouters\n",
    );
    // Self-mapping: Debian convention puts the configured hostname on a dedicated
    // 127.0.1.1, distinct from 127.0.0.1 localhost. The name is the canonical UTS
    // nodename so it stays in lockstep with uname(2), /etc/hostname, and
    // /proc/sys/kernel/hostname. --net=host: one global hostname on loopback.
    hosts_content.push_str(&format!("127.0.1.1\t{}\n", guest_hostname()));
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
        format!("{}\n", guest_hostname()).into_bytes(),
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
    use super::{is_entrypoint_not_executable, is_entrypoint_not_found};
    use crate::elf::ElfInspectError;
    use crate::memory::AddressSpaceError;
    use crate::runtime::RuntimeError;
    use std::io::{Error as IoError, ErrorKind};

    fn rt_io(kind: ErrorKind) -> RuntimeError {
        RuntimeError::AddressSpace(AddressSpaceError::Io(IoError::from(kind)))
    }
    fn rt_not_elf() -> RuntimeError {
        RuntimeError::AddressSpace(AddressSpaceError::Elf(ElfInspectError::NotElf))
    }

    #[test]
    fn not_found_maps_to_127_class_only() {
        // docker/runc/shell: a missing entrypoint is 127.
        assert!(is_entrypoint_not_found(&rt_io(ErrorKind::NotFound)));
        assert!(!is_entrypoint_not_found(&rt_io(ErrorKind::PermissionDenied)));
        assert!(!is_entrypoint_not_found(&rt_not_elf()));
    }

    #[test]
    fn not_executable_maps_to_126_class_only() {
        // docker/runc: an entrypoint that exists but cannot exec (non-ELF
        // "exec format error", or EACCES "permission denied") is 126 — not 127,
        // not the generic 1.
        assert!(is_entrypoint_not_executable(&rt_not_elf()));
        assert!(is_entrypoint_not_executable(&rt_io(ErrorKind::PermissionDenied)));
        assert!(!is_entrypoint_not_executable(&rt_io(ErrorKind::NotFound)));
    }
}
