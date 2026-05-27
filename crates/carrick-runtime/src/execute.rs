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
use carrick_spec::{FsBackendKind, Platform, RunSpec};
use std::path::PathBuf;

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
                let mut host = HostFsBackend::new().map_err(|e| {
                    RuntimeError::FsBackend(anyhow::anyhow!(
                        "failed to create scratch directory: {}",
                        e
                    ))
                })?;

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
                run_result.map_err(|e| {
                    RuntimeError::FsBackend(anyhow::anyhow!(
                        "failed to run ELF from dispatcher: {}",
                        e
                    ))
                })?
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
                run_result.map_err(|e| {
                    RuntimeError::FsBackend(anyhow::anyhow!("failed to run rootfs ELF: {}", e))
                })?
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

    // /etc/hosts. Check existence FIRST so we never resolve (below) only to
    // discard the result when the guest already has a hosts file.
    let have_hosts = backend.metadata("/etc/hosts").is_some()
        || rootfs
            .and_then(|rootfs| rootfs.metadata("/etc/hosts").ok())
            .is_some();
    if !have_hosts {
        let mut hosts_content = String::from(
            "127.0.0.1\tlocalhost\n\
             ::1\tlocalhost ip6-localhost ip6-loopback\n\
             ff02::1\tip6-allnodes\n\
             ff02::2\tip6-allrouters\n",
        );
        // Pre-resolving the Debian/Ubuntu apt mirrors here was ~8 blocking
        // getaddrinfo() calls (~80 ms via mDNSResponder) on EVERY startup — a
        // profile showed it was the #2 cost after diskutil. It predates carrick
        // synthesizing /etc/resolv.conf from the host resolver, so the guest now
        // resolves these mirrors itself; the static seed is redundant. Keep it
        // available behind an opt-in env for offline/locked-down apt runs, but
        // off the default hot path.
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
        let _ = backend.set_file_contents("/etc/hosts", hosts_content.into_bytes());
    }
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
