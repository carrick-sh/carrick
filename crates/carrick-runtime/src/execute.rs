//! Runtime execution entry points that bridge shared run specs to
//! dispatcher-backed guest execution.

use crate::dispatch::SyscallDispatcher;
#[cfg(feature = "fs-memory")]
use crate::fs_backend::MemoryBackend;
use crate::fs_backend::{FsBackend, HostFsBackend};
use crate::network::NetworkHostsEntry;
use crate::rootfs::RootFs;
use crate::runtime::{RunResult, RuntimeError};
use crate::vfs::BindVfs;
#[cfg(feature = "fs-memory")]
use carrick_spec::FsBackendKind;
use carrick_spec::{NetworkNamespaceSpec, RunSpec};
use std::borrow::Cow;
use std::path::PathBuf;

/// True when a runtime error means the ENTRYPOINT executable (or its loader)
/// could not be found/read. The runc/shell convention is to exit 127 for that —
/// `docker run img /nope` and `sh -c nope` both yield 127 — not the generic 1 a
/// propagated error would produce.
pub(crate) fn is_entrypoint_not_found(e: &RuntimeError) -> bool {
    matches!(
        e,
        RuntimeError::AddressSpace(crate::memory::AddressSpaceError::Io(io))
            if io.kind() == std::io::ErrorKind::NotFound
    )
}

/// A 127 ("command not found") result for a failed entrypoint load.
pub(crate) fn entrypoint_not_found_result() -> RunResult {
    RunResult {
        exit_code: 127,
        terminating_signal: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        traps: 0,
        report: crate::compat::CompatReport::default(),
        trap_limit_hit: false,
        terminal_reason: None,
    }
}

/// True when the entrypoint EXISTS but cannot be executed as a program: a
/// non-ELF / malformed image (goblin parse failure → "exec format error") or a
/// permission denial (EACCES). The runc/shell convention is to exit 126 for
/// that — `docker run img /etc/hostname` yields 126 — distinct from 127 (not
/// found) and the generic 1 a propagated error would produce.
pub(crate) fn is_entrypoint_not_executable(e: &RuntimeError) -> bool {
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
pub(crate) fn entrypoint_not_executable_result() -> RunResult {
    RunResult {
        exit_code: 126,
        terminating_signal: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        traps: 0,
        report: crate::compat::CompatReport::default(),
        trap_limit_hit: false,
        terminal_reason: None,
    }
}

/// For a managed (detached) container, the stable on-disk overlay path
/// `<registry>/<id>/scratch`. `None` for an id that is not a safe registry
/// key. A foreground run never calls this (it uses an ephemeral per-run
/// scratch).
pub(crate) fn detached_stable_scratch_path(id: &str) -> Option<PathBuf> {
    if !crate::container::is_safe_id(id) {
        return None;
    }
    Some(crate::container::container_dir(id).join("scratch"))
}

/// Record a managed container's overlay path into its registry record so
/// `carrick exec`/`rm` find the same filesystem. Called only once the overlay
/// has been attached and its root prepared: a preparation that fails earlier
/// publishes nothing. Best-effort — a failed write means `exec` cannot find
/// the overlay later, not a run failure.
pub(crate) fn record_detached_scratch(id: &str, scratch: &std::path::Path) {
    if let Ok(mut state) = crate::container::ContainerState::load(id) {
        state.config.scratch_path = Some(scratch.to_string_lossy().into_owned());
        let _ = state.persist();
    }
}

#[derive(Debug)]
pub(crate) enum HostRootLayout {
    /// Historical path: the writable host root contains the complete image.
    Materialized,
    /// Sparse writable upper paired with the shared immutable cache lower.
    CachedLower(RootFs),
}

pub(crate) fn prepare_host_root(
    host: &mut HostFsBackend,
    layer_paths: &[PathBuf],
    existing_overlay: bool,
    use_cached_lower: bool,
    cache_root: &std::path::Path,
) -> std::io::Result<HostRootLayout> {
    if use_cached_lower
        && let Some(entry) = crate::layer_cache::acquire_immutable_entry(layer_paths, cache_root)?
    {
        if !existing_overlay {
            host.enable_sparse_upper_fast_miss();
        }
        return RootFs::from_immutable_host_dir(&entry)
            .map(HostRootLayout::CachedLower)
            .map_err(|error| std::io::Error::other(error.to_string()));
    }
    if !existing_overlay {
        host.extract_layers(layer_paths)?;
    }
    Ok(HostRootLayout::Materialized)
}

pub(crate) fn cached_lower_enabled(execution_plan: &crate::page_profile::ExecutionPlan) -> bool {
    #[cfg(target_os = "macos")]
    {
        let _ = execution_plan;
        std::env::var_os("CARRICK_FS_CACHED_LOWER").as_deref() != Some(std::ffi::OsStr::new("0"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = execution_plan;
        false
    }
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
/// `CARRICK_NO_ROSETTA_NOTICE`). Goes to stderr so it never corrupts a streaming
/// guest's stdout.
pub(crate) fn rosetta_license_notice() {
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

pub(crate) fn install_rosetta_mounts(dispatcher: &mut SyscallDispatcher) {
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
pub(crate) fn install_fs_backend(
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

/// The nodename of the ROOT UTS namespace — what `uname(2)`,
/// `/proc/sys/kernel/hostname` and the `/etc/hosts` self-mapping report.
///
/// It used to BE the host fact: a direct `gethostname(3)` on every call, which
/// is a machine answer to a namespace question. The host's short hostname now
/// only SEEDS the root namespace (see [`crate::kernel::netns`]) under the
/// `--net host` contract, and every reader goes to the namespace, so a name set
/// after startup is the name every reader sees.
pub fn guest_hostname() -> String {
    crate::kernel::root_uts_ns().nodename()
}

pub(crate) fn effective_guest_hostname(spec: &RunSpec) -> Cow<'_, str> {
    spec.hostname
        .as_deref()
        .filter(|hostname| !hostname.is_empty())
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Owned(guest_hostname()))
}

pub(crate) fn seed_guest_baseline(
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

#[cfg(test)]
mod exit_code_tests {
    use super::{
        HostRootLayout, is_entrypoint_not_executable, is_entrypoint_not_found, prepare_host_root,
        seed_guest_baseline,
    };
    use crate::elf::ElfInspectError;
    use crate::fs_backend::{FsBackend, HostFsBackend, MemoryBackend};
    use crate::memory::AddressSpaceError;
    use crate::runtime::RuntimeError;
    use carrick_spec::NetworkNamespaceSpec;
    use std::io::{Error as IoError, ErrorKind};

    fn rt_io(kind: ErrorKind) -> RuntimeError {
        RuntimeError::AddressSpace(AddressSpaceError::Io(IoError::from(kind)))
    }
    fn rt_not_elf() -> RuntimeError {
        RuntimeError::AddressSpace(AddressSpaceError::Elf(ElfInspectError::NotElf))
    }

    #[cfg(target_os = "macos")]
    fn write_host_root_test_layer(path: &std::path::Path) {
        let file = std::fs::File::create(path).unwrap();
        let mut tar = tar::Builder::new(file);
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_mode(0o755);
        dir.set_size(0);
        dir.set_cksum();
        tar.append_data(&mut dir, "etc/", std::io::empty()).unwrap();
        let body = b"cached-lower\n";
        let mut file = tar::Header::new_gnu();
        file.set_mode(0o644);
        file.set_size(body.len() as u64);
        file.set_cksum();
        tar.append_data(&mut file, "etc/motd", &body[..]).unwrap();
        tar.finish().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cached_lower_setup_leaves_the_per_run_upper_sparse() {
        let temp = tempfile::TempDir::new().unwrap();
        let upper_root = temp.path().join("uppers");
        let cache_root = temp.path().join("cache-root");
        std::fs::create_dir(&upper_root).unwrap();
        std::fs::create_dir(&cache_root).unwrap();
        let layer = temp.path().join("sha256-layer");
        write_host_root_test_layer(&layer);
        let mut host = HostFsBackend::new_in(&upper_root).unwrap();

        let layout = prepare_host_root(&mut host, &[layer], false, true, &cache_root).unwrap();
        let HostRootLayout::CachedLower(rootfs) = layout else {
            panic!("default setup should select an immutable cached lower");
        };
        assert_eq!(rootfs.read("/etc/motd").unwrap(), b"cached-lower\n");
        assert!(
            host.file_contents("/etc/motd").is_none(),
            "the per-run upper must not contain a cloned image namespace"
        );
        assert!(
            host.fast_nofollow_absent("/etc/motd"),
            "a newly-created sparse upper must authorize the one-lookup miss path"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cached_lower_existing_overlay_stays_conservative() {
        let temp = tempfile::TempDir::new().unwrap();
        let upper_root = temp.path().join("uppers");
        let cache_root = temp.path().join("cache-root");
        std::fs::create_dir(&upper_root).unwrap();
        std::fs::create_dir(&cache_root).unwrap();
        let layer = temp.path().join("sha256-layer");
        write_host_root_test_layer(&layer);
        let mut host = HostFsBackend::new_in(&upper_root).unwrap();

        let layout = prepare_host_root(&mut host, &[layer], true, true, &cache_root).unwrap();
        assert!(matches!(layout, HostRootLayout::CachedLower(_)));
        assert!(
            !host.fast_nofollow_absent("/etc/motd"),
            "an attached or previously-used upper must never infer sparse authority"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cached_lower_hatch_preserves_materialized_root_setup() {
        let temp = tempfile::TempDir::new().unwrap();
        let upper_root = temp.path().join("uppers");
        let cache_root = temp.path().join("cache-root");
        std::fs::create_dir(&upper_root).unwrap();
        std::fs::create_dir(&cache_root).unwrap();
        let layer = temp.path().join("sha256-layer");
        write_host_root_test_layer(&layer);
        let mut host = HostFsBackend::new_in(&upper_root).unwrap();

        let layout = prepare_host_root(&mut host, &[layer], false, false, &cache_root).unwrap();
        assert!(matches!(layout, HostRootLayout::Materialized));
        assert_eq!(host.file_contents("/etc/motd").unwrap(), b"cached-lower\n");
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

    #[test]
    fn seed_guest_baseline_writes_extra_hosts_entries() {
        let mut backend = MemoryBackend::new();
        let network = NetworkNamespaceSpec::default();
        seed_guest_baseline(
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
        seed_guest_baseline(&mut backend, None, &network, &[], &[], "api-host");

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
        seed_guest_baseline(
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
        seed_guest_baseline(
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
        seed_guest_baseline(&mut backend, None, &network, &[], &[], "api-host");

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
