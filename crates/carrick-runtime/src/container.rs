//! Container lifecycle registry — the on-disk state that backs `carrick run
//! -d`, `ps`, `stop`, `kill`, and `rm`.
//!
//! Carrick is **daemonless**: there is no `carrickd`. Each detached container
//! is owned by its one VM carrier. This module is just a filesystem registry:
//! one directory per container under a shared root, holding a JSON state file
//! plus the captured stdout/stderr log.
//! `ps`/`stop`/`kill`/`rm` are CLI operations over this directory plus the
//! authenticated control endpoint owned by each carrier. Guest-semantic
//! signals address the persisted logical init identity, never a host pid.
//!
//! This mirrors the podman model (per-container conmon + on-disk state), not
//! the docker model (one always-on daemon owning every container).

use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Lifecycle status of a container in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerStatus {
    /// Registry entry written, container not yet running.
    Created,
    /// The init (pid 1) is live.
    Running,
    /// The init exited; `exit_code` is set.
    Exited,
}

/// Fail-closed status used when the sole carrier disappeared without writing a
/// terminal receipt (for example after SIGKILL, abort, or host failure). With no
/// daemon or helper process there is no surviving `waitpid(2)` authority that
/// can recover the exact signal; fabricating exit 0 would be materially wrong.
pub const UNKNOWN_CARRIER_EXIT_CODE: i32 = 255;

/// One container's persisted state. Written by the detached carrier and read by
/// the lifecycle CLI subcommands. Field set is intentionally small and
/// host-meaningful (the compatibility pids identify the carrier, but are not
/// guest-signal targets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerState {
    /// Full 64-hex container id.
    pub id: String,
    /// Optional `--name`.
    pub name: Option<String>,
    /// The image reference run.
    pub image: String,
    /// argv of the container command (for `ps` display).
    pub command: Vec<String>,
    pub status: ContainerStatus,
    /// Compatibility alias for the carrier host pid. New carrier-only launches
    /// write the same pid to this and `init_pid`; 0 until known.
    pub supervisor_pid: i32,
    /// Host pid of the carrier that owns logical guest-init (ns-pid 1).
    /// Lifecycle signal delivery uses `control`, not this compatibility hint.
    pub init_pid: i32,
    /// Unix epoch seconds when the container was created (stamped by the
    /// caller, since the runtime forbids `SystemTime::now` in some contexts).
    pub created_secs: u64,
    /// Exit code once `status == Exited`.
    pub exit_code: Option<i32>,
    /// `--rm`: remove the registry entry when the container exits.
    pub auto_remove: bool,
    /// Docker API `HostConfig.AutoRemove`: the API server owns delayed cleanup so
    /// attach can drain logs before the registry directory disappears.
    #[serde(default)]
    pub api_auto_remove: bool,
    /// Docker/API-facing labels used for container discovery and filtering.
    #[serde(default)]
    pub labels: std::collections::HashMap<String, String>,
    /// Exact mutating-control incarnation for this carrier.
    #[serde(default)]
    pub control: Option<CarrierControlState>,
    /// Exact carrier incarnation that published this terminal state. A bare
    /// `Exited` status is not sufficient authority for lifecycle mutation.
    #[serde(default)]
    pub terminal_control: Option<CarrierControlState>,
    /// One-shot 128-bit authorization for the exact re-exec allowed to become
    /// this container's carrier. Cleared by the winning carrier before boot.
    #[serde(default)]
    pub launch_ticket: Option<String>,
    /// Run configuration needed to `exec` into (and later restart) this
    /// container. Additive: `#[serde(default)]` so registry entries written
    /// before this field existed still load.
    #[serde(default)]
    pub config: RunConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierControlState {
    pub schema: String,
    pub owner_nonce: crate::kernel::control::ControlNonce,
    pub init: crate::kernel::control::ControlTaskKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierTerminalReceipt {
    pub control: CarrierControlState,
    pub exit_code: i32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StopSignalAbi {
    /// Pre-carrier-control state. A non-default value is ambiguous because the
    /// old CLI persisted Darwin numbers and did not preserve its source text.
    LegacyHost,
    /// Linux signal numbering delivered to the logical kernel task.
    #[default]
    Linux,
}

fn legacy_stop_signal_abi() -> StopSignalAbi {
    StopSignalAbi::LegacyHost
}

/// The subset of a container's run inputs persisted so `exec` (and later
/// `start`/`restart`) can reconstruct a compatible run. `exec` re-resolves the
/// image layers from the store via [`ContainerState::image`] and re-applies
/// these, overriding with its own flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RunConfig {
    /// Raw `--platform` string (`None` = host default).
    pub platform: Option<String>,
    /// Execution backend request preserved across start/restart/exec.
    #[serde(default)]
    pub exec_backend: carrick_spec::ExecBackendRequest,
    /// Container env overrides (`-e`/`--env-file`), re-applied over the image env.
    pub env: Vec<String>,
    /// `-w/--workdir`.
    pub workdir: Option<String>,
    /// `-u/--user` (numeric `uid[:gid]` or a name).
    pub user: Option<String>,
    /// Docker-compatible container hostname / UTS identity. `None` preserves
    /// the runtime's historical host-derived fallback.
    #[serde(default)]
    pub hostname: Option<String>,
    /// PID namespace mode — `exec` joins the same region.
    pub pid: carrick_spec::PidMode,
    /// Container network mode.
    #[serde(default)]
    pub network: carrick_spec::NetworkMode,
    /// Docker API-facing HostConfig.NetworkMode. This can outlive the effective
    /// endpoint set after `docker network disconnect`, so keep it separate from
    /// the runtime network mode.
    #[serde(default)]
    pub api_network_mode: Option<String>,
    /// Bridge-network service aliases.
    #[serde(default)]
    pub network_aliases: Vec<String>,
    /// Docker/API-facing network attachment names and per-network aliases. The
    /// runtime still has one bridge namespace today; this preserves the Engine
    /// API resource names Compose clients reconcile against.
    #[serde(default)]
    pub network_attachments: Vec<NetworkAttachment>,
    /// Docker-compatible `--network container:<id>` target. Today the runtime
    /// lowers this to the target's effective host/bridge/none mode, while this
    /// field preserves the shared-network relationship for API presentation and
    /// a future true namespace join.
    #[serde(default)]
    pub network_container: Option<String>,
    /// Docker-compatible extra `/etc/hosts` entries (`--add-host` /
    /// HostConfig.ExtraHosts), preserved across start and exec.
    #[serde(default)]
    pub extra_hosts: Vec<String>,
    /// Docker-compatible resolver overrides, preserved across start and exec.
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub dns_search: Vec<String>,
    #[serde(default)]
    pub dns_options: Vec<String>,
    /// Docker-compatible `--volumes-from` / HostConfig.VolumesFrom entries,
    /// preserved for inspect. The inherited mounts themselves are materialized
    /// into `mounts` at create time so start/restart do not depend on mutable
    /// source-container state.
    #[serde(default)]
    pub volumes_from: Vec<String>,
    /// Published ports requested at create/run time.
    #[serde(default)]
    pub published_ports: Vec<carrick_spec::PortMapping>,
    /// On-disk writable overlay path (`--fs host`), shared with `exec`. `None`
    /// means the container used the in-process memory fs, so `exec` (which needs
    /// a shareable overlay) is unsupported for it.
    pub scratch_path: Option<String>,
    /// `--entrypoint` override (`None` = the image ENTRYPOINT). Persisted as the
    /// SPLIT inputs — `command` holds only the cmd args — so `start` re-merges
    /// entrypoint+cmd through the engine instead of double-applying the image
    /// entrypoint.
    pub entrypoint: Option<Vec<String>>,
    /// Bind/volume mounts (`-v`/`--mount`), re-applied at `start`.
    pub mounts: Vec<carrick_spec::Mount>,
    /// Resolved fs backend; only `Host` is startable (a memory overlay can't be
    /// relaunched). `None` for legacy entries.
    pub fs: Option<carrick_spec::FsBackendKind>,
    /// `-t`: allocate a pty (for `start --attach` fidelity).
    pub tty: bool,
    /// `-i`: keep stdin open.
    pub interactive: bool,
    /// Max guest traps before the run aborts. A NAMED default is required: a bare
    /// default would deserialize legacy entries to 0 and trip the trap limit
    /// immediately.
    #[serde(default = "default_max_traps")]
    pub max_traps: usize,
    /// Linux stop signum (`docker run --stop-signal` / image `STOPSIGNAL`).
    /// `None` falls back to `SIGTERM` at stop time.
    pub stop_signal: Option<i32>,
    /// Numbering authority for `stop_signal`. Missing fields deserialize as the
    /// retired host ABI; newly-created states explicitly persist Linux.
    #[serde(default = "legacy_stop_signal_abi")]
    pub stop_signal_abi: StopSignalAbi,
    /// Grace seconds before `SIGKILL` (`--stop-timeout`). `None` falls back to
    /// `stop -t`, else 10.
    pub stop_timeout: Option<u64>,
    /// Raw `--security-opt` values (docker syntax), preserved so start/restart
    /// and `exec` run under the same launch-time syscall policy the container
    /// was created with (empty = docker's default profile model).
    #[serde(default)]
    pub security_opts: Vec<String>,
    /// Docker-compatible `--cap-add` grants, preserved across
    /// start/restart/exec exactly like `security_opts` (docker keeps the
    /// container's capability set for its whole lifetime).
    #[serde(default)]
    pub cap_add: Vec<String>,
}

fn default_max_traps() -> usize {
    crate::runtime::DEFAULT_MAX_TRAPS
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkAttachment {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub links: Vec<String>,
    #[serde(default)]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub gw_priority: i64,
    #[serde(default)]
    pub ipv4_address: Option<String>,
    #[serde(default)]
    pub ipv6_address: Option<String>,
    #[serde(default)]
    pub link_local_ips: Vec<String>,
    #[serde(default)]
    pub driver_opts: std::collections::HashMap<String, String>,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            platform: None,
            exec_backend: carrick_spec::ExecBackendRequest::HvPatch,
            env: Vec::new(),
            workdir: None,
            user: None,
            hostname: None,
            pid: carrick_spec::PidMode::default(),
            network: carrick_spec::NetworkMode::Host,
            api_network_mode: None,
            network_aliases: Vec::new(),
            network_attachments: Vec::new(),
            network_container: None,
            extra_hosts: Vec::new(),
            dns_servers: Vec::new(),
            dns_search: Vec::new(),
            dns_options: Vec::new(),
            volumes_from: Vec::new(),
            published_ports: Vec::new(),
            scratch_path: None,
            entrypoint: None,
            mounts: Vec::new(),
            fs: None,
            tty: false,
            interactive: false,
            // Both the struct Default (legacy entries with NO config object) and
            // the field serde default (config present, max_traps missing) must
            // yield the real default — 0 would trip the trap limit immediately.
            max_traps: default_max_traps(),
            stop_signal: None,
            stop_signal_abi: StopSignalAbi::Linux,
            stop_timeout: None,
            security_opts: Vec::new(),
            cap_add: Vec::new(),
        }
    }
}

/// The registry root: `<scratch>/containers` (per-user, case-sensitive). Each
/// container lives in `<root>/<id>/`.
pub fn registry_root() -> PathBuf {
    // The APFS scratch root (a case-sensitive, fast-clone volume) is a macOS
    // host concept; on Linux fall back to a tempdir-based root.
    #[cfg(target_os = "macos")]
    let base = crate::apfs::preferred_scratch_root()
        .unwrap_or_else(|_| std::env::temp_dir().join("carrick"));
    #[cfg(not(target_os = "macos"))]
    let base = std::env::temp_dir().join("carrick");
    base.join("containers")
}

/// A container id is a safe single path component iff it is non-empty and
/// contains only `[0-9a-zA-Z_-]`. Ids we generate are 64-hex; this guard
/// rejects anything that could traverse out of the registry root (`/`, `..`,
/// NUL, etc.) before it is ever joined into a filesystem path — defense against
/// a crafted `carrick rm '../../etc'` style argument (CWE-22).
pub fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The directory for one container id, or `None` if `id` is not a safe single
/// path component (CWE-22 guard — see [`is_safe_id`]). The path is built only
/// after the id is proven to be a bare `[0-9A-Za-z_-]+` token, so it can never
/// contain a separator or `..` and thus cannot escape [`registry_root`].
pub fn container_dir_checked(id: &str) -> Option<PathBuf> {
    if !is_safe_id(id) {
        return None;
    }
    // `id` is validated as a single safe path component above; joining it onto
    // the registry root stays within the root by construction.
    Some(registry_root().join(id)) // nosemgrep: path is an allowlisted [0-9A-Za-z_-]+ token, not a traversable path
}

/// The directory for one container id. Convenience wrapper that falls back to
/// the registry root for an unsafe id (so a subsequent open/create fails as a
/// directory rather than escaping). Prefer [`container_dir_checked`] where an
/// explicit error is wanted.
pub fn container_dir(id: &str) -> PathBuf {
    container_dir_checked(id).unwrap_or_else(registry_root)
}

/// An "id rejected as unsafe" io error (CWE-22 guard). Surfaced by the path
/// builders so a crafted id fails closed instead of escaping the registry.
/// (Every container id carrick generates is 64-hex, so this only triggers on a
/// hand-crafted CLI argument.)
fn unsafe_id_err() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "container id is not a safe path component",
    )
}

/// The state-file path for one container id, validated against [`is_safe_id`].
pub fn state_path(id: &str) -> std::io::Result<PathBuf> {
    Ok(container_dir_checked(id)
        .ok_or_else(unsafe_id_err)?
        .join("state.json"))
}

/// The stdout/stderr log path for one container id (detached runs redirect the
/// guest's inherited stdio here so `carrick logs` can replay it later).
pub fn log_path(id: &str) -> std::io::Result<PathBuf> {
    Ok(container_dir_checked(id)
        .ok_or_else(unsafe_id_err)?
        .join("output.log"))
}

fn receipt_path(id: &str) -> std::io::Result<PathBuf> {
    if !is_safe_id(id) {
        return Err(unsafe_id_err());
    }
    Ok(registry_root()
        .join(".terminal-receipts")
        .join(format!("{id}.json")))
}

fn launch_ticket_path(id: &str, ticket: &str) -> std::io::Result<PathBuf> {
    if !is_safe_id(id) || ticket.len() != 32 || !ticket.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(unsafe_id_err());
    }
    Ok(container_dir_checked(id)
        .ok_or_else(unsafe_id_err)?
        .join(format!(".launch-ticket-{ticket}")))
}

pub fn prepare_launch_ticket(state: &mut ContainerState) -> std::io::Result<String> {
    if state.status != ContainerStatus::Created
        || state.control.is_some()
        || state.launch_ticket.is_some()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "container already has a carrier launch in progress",
        ));
    }
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| std::io::Error::other(format!("generate launch ticket: {error:?}")))?;
    let ticket = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path = launch_ticket_path(&state.id, &ticket)?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    state.launch_ticket = Some(ticket.clone());
    if let Err(error) = state.persist() {
        let _ = std::fs::remove_file(path);
        state.launch_ticket = None;
        return Err(error);
    }
    Ok(ticket)
}

fn bound_launch_authorization(ticket: &str, pid: libc::pid_t) -> String {
    format!("{ticket}:{pid}")
}

/// Bind the prepared bearer to the exact pid returned by `posix_spawn` before
/// the parent releases the child-side grant pipe.
pub fn bind_launch_ticket_to_pid(
    id: &str,
    ticket: &str,
    pid: libc::pid_t,
) -> std::io::Result<String> {
    if pid <= 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "carrier launch pid must be positive",
        ));
    }
    let mut state = ContainerState::load(id)?;
    if state.status != ContainerStatus::Created
        || state.control.is_some()
        || state.launch_ticket.as_deref() != Some(ticket)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "carrier launch ticket no longer owns the Created state",
        ));
    }
    let authorization = bound_launch_authorization(ticket, pid);
    state.launch_ticket = Some(authorization.clone());
    state.persist()?;
    Ok(authorization)
}

/// Atomically consume the exact parent's one-shot ticket. The ticket is first
/// authenticated against the current process id, then unlink is used as the
/// one-shot primitive. The bound authorization remains in state until managed
/// carrier control atomically publishes Running.
pub fn consume_launch_ticket(id: &str, ticket: &str, pid: libc::pid_t) -> std::io::Result<String> {
    let path = launch_ticket_path(id, ticket)?;
    let state = ContainerState::load(id)?;
    let authorization = bound_launch_authorization(ticket, pid);
    if state.status != ContainerStatus::Created
        || state.control.is_some()
        || state.launch_ticket.as_deref() != Some(authorization.as_str())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "carrier launch ticket does not own the Created state",
        ));
    }
    std::fs::remove_file(path)?;
    Ok(authorization)
}

pub fn cancel_launch_ticket(id: &str, ticket: &str) {
    if let Ok(path) = launch_ticket_path(id, ticket) {
        let _ = std::fs::remove_file(path);
    }
    if let Ok(mut state) = ContainerState::load(id)
        && state.launch_ticket.as_deref().is_some_and(|authorization| {
            authorization == ticket || authorization.starts_with(&format!("{ticket}:"))
        })
    {
        state.launch_ticket = None;
        let _ = state.persist();
    }
}

/// Exclusive lifecycle transaction for one container. POSIX record locks are
/// process-owned and are not inherited across `fork`, so a detached carrier
/// cannot accidentally retain the CLI parent's start/remove transaction.
#[derive(Debug)]
pub struct ContainerLifecycleLock {
    file: std::fs::File,
    _process_guard: parking_lot::MutexGuard<'static, ()>,
}

const LIFECYCLE_LOCK_STRIPES: usize = 64;
const NAME_REGISTRY_LOCK_SLOT: usize = LIFECYCLE_LOCK_STRIPES;
const LIFECYCLE_LOCK_SLOTS: usize = LIFECYCLE_LOCK_STRIPES + 1;

fn lifecycle_lock_stripe(key: &str) -> &'static parking_lot::Mutex<()> {
    static STRIPES: std::sync::OnceLock<[parking_lot::Mutex<()>; LIFECYCLE_LOCK_SLOTS]> =
        std::sync::OnceLock::new();
    let stripes = STRIPES.get_or_init(|| std::array::from_fn(|_| parking_lot::Mutex::new(())));
    // Rename holds one per-container lifecycle lock before taking the global
    // name-registry lock. Keep the latter outside the striped container set so
    // a hash collision can never turn that intentional nesting into a
    // same-thread, non-reentrant mutex deadlock.
    if key == ".container-names" {
        return &stripes[NAME_REGISTRY_LOCK_SLOT];
    }
    let hash = key.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    &stripes[hash as usize % LIFECYCLE_LOCK_STRIPES]
}

impl Drop for ContainerLifecycleLock {
    fn drop(&mut self) {
        // SAFETY: zero is a valid starting representation for `libc::flock`;
        // the fields used by F_SETLK are initialized immediately below.
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = libc::F_UNLCK as _;
        lock.l_whence = libc::SEEK_SET as _;
        // SAFETY: fd is owned by `self.file`; `lock` points to a live flock.
        let _ = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETLK, &lock) };
    }
}

pub fn lock_lifecycle(id: &str) -> std::io::Result<ContainerLifecycleLock> {
    if !is_safe_id(id) {
        return Err(unsafe_id_err());
    }
    lock_registry_record(id, &format!("{id}.lock"))
}

/// Serialize the registry-wide name uniqueness check with initial state
/// publication. This lock is intentionally separate from per-container
/// lifecycle locks and is held only across the short name claim transaction.
pub fn lock_name_registry() -> std::io::Result<ContainerLifecycleLock> {
    lock_registry_record(".container-names", ".container-names.lock")
}

fn lock_registry_record(key: &str, filename: &str) -> std::io::Result<ContainerLifecycleLock> {
    let process_guard = lifecycle_lock_stripe(key).lock();
    let directory = registry_root().join(".lifecycle-locks");
    ensure_private_aux_directory(&directory)?;
    let path = directory.join(filename);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "container lifecycle lock is not an owned regular file",
        ));
    }
    // SAFETY: zero is a valid starting representation for `libc::flock`;
    // the fields used by F_SETLKW are initialized immediately below.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    // SAFETY: fd is owned by `file`; `lock` points to a live flock.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLKW, &lock) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ContainerLifecycleLock {
        file,
        _process_guard: process_guard,
    })
}

pub fn terminal_receipt(id: &str) -> std::io::Result<Option<CarrierTerminalReceipt>> {
    let path = receipt_path(id)?;
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn persist_terminal_receipt(id: &str, receipt: &CarrierTerminalReceipt) -> std::io::Result<()> {
    let path = receipt_path(id)?;
    let directory = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "terminal receipt path has no parent",
        )
    })?;
    ensure_private_aux_directory(directory)?;
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(
        &temporary,
        serde_json::to_vec(receipt).map_err(std::io::Error::other)?,
    )?;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(temporary, path)
}

fn ensure_private_aux_directory(directory: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(registry_root())?;
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) => {
            // SAFETY: geteuid has no preconditions.
            let uid = unsafe { libc::geteuid() };
            if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != uid {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{} is not an owned directory", directory.display()),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(directory)?;
        }
        Err(error) => return Err(error),
    }
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
}

pub fn clear_terminal_receipt(id: &str) -> std::io::Result<()> {
    match std::fs::remove_file(receipt_path(id)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

impl ContainerState {
    /// Create the container directory and write the initial state atomically
    /// (write to a temp file + rename, like `cred_ipc`). The id is one carrick
    /// generated (64-hex), so it always passes the safe-id guard.
    pub fn create(&self) -> std::io::Result<()> {
        let dir = container_dir_checked(&self.id).ok_or_else(unsafe_id_err)?;
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        clear_terminal_receipt(&self.id)?;
        self.persist()
    }

    /// Persist the current state to `state.json` atomically.
    pub fn persist(&self) -> std::io::Result<()> {
        let directory = container_dir_checked(&self.id).ok_or_else(unsafe_id_err)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let path = state_path(&self.id)?;
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // `path`/`tmp` are under the registry root by construction (id is an
        // allowlisted token; see container_dir_checked).
        std::fs::write(&tmp, &bytes)?; // nosemgrep
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, &path) // nosemgrep
    }

    /// Load a container's state by id.
    pub fn load(id: &str) -> std::io::Result<Self> {
        let path = state_path(id)?;
        let bytes = std::fs::read(&path)?; // nosemgrep
        serde_json::from_slice(&bytes).map_err(|error| {
            let detail = error.to_string();
            let action = if detail.contains("execution backend") {
                "; recreate the container with --exec-backend vmm if it requires virtualized execution"
            } else {
                ""
            };
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "failed to load container state '{}' for '{id}': {detail}{action}",
                    path.display()
                ),
            )
        })
    }

    /// Remove this container's registry directory.
    pub fn remove(id: &str) -> std::io::Result<()> {
        let dir = container_dir_checked(id).ok_or_else(unsafe_id_err)?;
        std::fs::remove_dir_all(&dir) // nosemgrep
    }

    /// Whether the recorded init pid is still alive (host `kill(pid, 0)`).
    /// A `Running` entry whose init is gone is stale (the supervisor crashed
    /// before updating it) — callers reconcile such entries to `Exited`.
    pub fn init_alive(&self) -> bool {
        pid_alive(self.init_pid)
    }
}

/// Whether `pid` is a *live* process (not a zombie). A pid <= 0 is never alive.
/// `kill(pid, 0)` alone is insufficient: a terminated-but-unreaped process is a
/// zombie that still answers `kill(0)` with success, which would make a stopped
/// container's exited init look "running" until launchd reaps it. So we also
/// check the host process state and treat `Z` (zombie) as dead.
pub fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: kill with signal 0 only probes existence/permission; it delivers
    // nothing.
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    // Exists in the process table — but a zombie is not running. If we can read
    // its state and it is a zombie, report dead; if state is unreadable, fall
    // back to the kill(0) result (better to over-report alive than miss a
    // genuinely-running process).
    match crate::host_proc::pid_info(pid as u32) {
        Some(info) => info.state != 'Z',
        None => true,
    }
}

/// List all container states in the registry (best-effort; unreadable or
/// malformed entries are skipped). Stale `Running` entries whose init has died
/// are reported with their recorded state — the CLI reconciles them.
pub fn list() -> Vec<ContainerState> {
    let mut out = list_unreconciled();
    for state in &mut out {
        if reconciled_status(state) == ContainerStatus::Exited {
            state.status = ContainerStatus::Exited;
            state.exit_code.get_or_insert(UNKNOWN_CARRIER_EXIT_CODE);
        }
    }
    out
}

/// Registry lookup input without host-PID reconciliation. Mutating lifecycle
/// commands authenticate the persisted control incarnation themselves; a PID
/// liveness hint must never erase that authority before they acquire its lock.
fn list_unreconciled() -> Vec<ContainerState> {
    let root = registry_root();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return out;
    };
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        if let Some(id) = entry.file_name().to_str()
            && let Ok(state) = ContainerState::load(id)
        {
            out.push(state);
        }
    }
    out
}

/// Resolve a user-supplied id-or-name (and unambiguous id prefix) to a full
/// container id. Returns `Err` with a human message on no-match / ambiguity.
pub fn resolve(id_or_name: &str) -> Result<String, String> {
    let all = list_unreconciled();
    // Exact id.
    if all.iter().any(|c| c.id == id_or_name) {
        return Ok(id_or_name.to_string());
    }
    // Exact name.
    let by_name: Vec<&ContainerState> = all
        .iter()
        .filter(|c| c.name.as_deref() == Some(id_or_name))
        .collect();
    if by_name.len() == 1 {
        return Ok(by_name[0].id.clone());
    }
    if by_name.len() > 1 {
        return Err(format!("name {id_or_name:?} is ambiguous"));
    }
    // Unambiguous id prefix (docker allows this).
    let by_prefix: Vec<&ContainerState> = all
        .iter()
        .filter(|c| c.id.starts_with(id_or_name))
        .collect();
    match by_prefix.len() {
        1 => Ok(by_prefix[0].id.clone()),
        0 => Err(format!("no such container: {id_or_name}")),
        _ => Err(format!("id prefix {id_or_name:?} is ambiguous")),
    }
}

/// Render a 12-hex short id (docker's default `ps` width).
pub fn short_id(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

/// Generate a 64-hex container id from a seed (the supervisor pid + a creation
/// timestamp + a per-call counter). The runtime forbids `Math.random`-style
/// nondeterminism in some paths, so the CLI passes in the entropy; this just
/// formats it. Collision probability across a single host's containers is
/// negligible (pid+secs+counter is unique per launch).
pub fn make_id(seed_hi: u64, seed_lo: u64) -> String {
    // Four 64-bit words → 64 hex chars, LOOKING like a docker sha256 id without
    // implying content addressing. BOTH seeds avalanche into EVERY word — in
    // particular the first word `a`, whose top 48 bits are the 12-hex SHORT id
    // (`carrick ps` width / `short_id`). An earlier version set `a = seed_hi
    // .rotate_left(17) ^ CONST`, so for a small `seed_hi` (a pid) the short id
    // was constant-dominated (every id began `9e3779b9…`) with the real entropy
    // buried in `b`, past the short-id cutoff — colliding short ids and an
    // ugly default. Mixing both seeds first fixes the distribution.
    let mix = seed_hi.rotate_left(17).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ seed_lo.wrapping_mul(0xc2b2_ae3d_27d4_eb4f);
    let a = mix ^ 0xff51_afd7_ed55_8ccd;
    let b = (seed_lo ^ mix.rotate_right(29)).wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    let c = (seed_hi ^ seed_lo)
        .wrapping_add(0x1656_67b1_9e37_79f9)
        .rotate_left(31);
    let d = mix.wrapping_add(seed_lo).rotate_right(23) ^ seed_hi;
    format!("{a:016x}{b:016x}{c:016x}{d:016x}")
}

/// Update an existing container's state to Exited (or remove it if auto_remove),
/// recording the exit code. Best-effort: a missing entry is not an error.
pub fn mark_exited(id: &str, exit_code: i32) {
    if let Ok(mut state) = ContainerState::load(id) {
        // Managed carrier control already published the authoritative exact
        // receipt. The outer runtime compatibility hook must not erase its
        // provenance after `complete()` returns.
        if state.status == ContainerStatus::Exited && state.terminal_control.is_some() {
            return;
        }
        // A managed carrier owns Running state. A losing duplicate entry or
        // compatibility finalizer must never overwrite that exact owner.
        if state.control.is_some() {
            return;
        }
        if state.auto_remove {
            let _ = ContainerState::remove(id);
        } else {
            state.status = ContainerStatus::Exited;
            state.exit_code = Some(exit_code);
            state.control = None;
            state.terminal_control = None;
            state.launch_ticket = None;
            let _ = state.persist();
        }
    }
}

/// Publish terminal state only when `expected` still owns this exact carrier
/// incarnation. A stale drop/rollback must never overwrite a replacement run.
pub fn mark_control_owner_exited(
    id: &str,
    expected: &CarrierControlState,
    exit_code: i32,
) -> std::io::Result<bool> {
    let mut state = ContainerState::load(id)?;
    if state.control.as_ref() != Some(expected) {
        return Ok(false);
    }
    let receipt = CarrierTerminalReceipt {
        control: expected.clone(),
        exit_code,
    };
    persist_terminal_receipt(id, &receipt)?;
    if state.auto_remove {
        ContainerState::remove(id)?;
    } else {
        state.status = ContainerStatus::Exited;
        state.exit_code = Some(exit_code);
        state.control = None;
        state.terminal_control = Some(expected.clone());
        state.launch_ticket = None;
        state.persist()?;
    }
    Ok(true)
}

/// Reconcile a loaded state against reality: a `Running` entry whose init is
/// dead is reported as `Exited` (the supervisor died without updating it).
pub fn reconciled_status(state: &ContainerState) -> ContainerStatus {
    if state.status == ContainerStatus::Running && !pid_alive(state.init_pid) {
        ContainerStatus::Exited
    } else {
        state.status
    }
}

/// Persist the fail-closed terminal transition for a carrier that disappeared
/// before it could write its own exact receipt. Exact normal exits are still
/// published by the carrier through [`mark_exited`]. An uncatchable death has no
/// surviving status owner in the one-carrier design, so it is recorded as 255
/// rather than the old supervisor-era false success. Auto-remove entries are
/// removed during the same reconciliation.
pub fn reconcile_terminal_state(state: &mut ContainerState) -> ContainerStatus {
    if state.status != ContainerStatus::Running || pid_alive(state.init_pid) {
        return state.status;
    }
    state.status = ContainerStatus::Exited;
    state.exit_code.get_or_insert(UNKNOWN_CARRIER_EXIT_CODE);
    state.control = None;
    state.terminal_control = None;
    state.launch_ticket = None;
    if state.auto_remove {
        let _ = ContainerState::remove(&state.id);
    } else {
        let _ = state.persist();
    }
    state.status
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn make_id_is_64_hex_and_stable() {
        let id = make_id(1234, 5678);
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // Deterministic for a given seed.
        assert_eq!(id, make_id(1234, 5678));
        // Different seeds → different ids.
        assert_ne!(id, make_id(1234, 5679));
    }

    #[test]
    fn short_id_is_well_distributed() {
        // The SHORT id (the proctitle/ps id space) must carry both seeds — the
        // entropy must reach the first 12 hex, not be buried past the cutoff.
        // lo-only change must move the short id:
        assert_ne!(
            short_id(&make_id(1234, 5678)),
            short_id(&make_id(1234, 5679))
        );
        // small, close pids (seed_hi) must not collapse to the same short id:
        let ids: Vec<String> = (1000u64..1010)
            .map(|pid| short_id(&make_id(pid, 42)).to_string())
            .collect();
        let distinct: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(distinct.len(), ids.len(), "short ids collide: {ids:?}");
        // and they must NOT all share the old constant prefix (the regression).
        assert!(
            !ids.iter().all(|s| s.starts_with("9e3779b9")),
            "short ids still constant-dominated: {ids:?}"
        );
    }

    #[test]
    fn short_id_is_12_chars() {
        let id = make_id(1, 2);
        assert_eq!(short_id(&id).len(), 12);
        assert!(id.starts_with(short_id(&id)));
    }

    #[test]
    fn pid_alive_rejects_nonpositive() {
        assert!(!pid_alive(0));
        assert!(!pid_alive(-1));
        // Our own pid is alive.
        assert!(pid_alive(std::process::id() as i32));
    }

    #[test]
    fn reconciled_status_marks_dead_running_as_exited() {
        let mut s = ContainerState {
            id: "x".into(),
            name: None,
            image: "img".into(),
            command: vec![],
            status: ContainerStatus::Running,
            supervisor_pid: 0,
            init_pid: 999_999_999, // not a live pid
            created_secs: 0,
            exit_code: None,
            auto_remove: false,
            api_auto_remove: false,
            labels: std::collections::HashMap::new(),
            control: None,
            terminal_control: None,
            launch_ticket: None,
            config: RunConfig::default(),
        };
        assert_eq!(reconciled_status(&s), ContainerStatus::Exited);
        assert_eq!(reconcile_terminal_state(&mut s), ContainerStatus::Exited);
        assert_eq!(s.exit_code, Some(UNKNOWN_CARRIER_EXIT_CODE));
        s.status = ContainerStatus::Created;
        assert_eq!(reconciled_status(&s), ContainerStatus::Created);
    }

    #[test]
    fn run_config_round_trips_and_defaults_when_missing() {
        // A registry entry written before `config` existed must still load
        // (additive #[serde(default)]).
        let legacy = r#"{"id":"x","name":null,"image":"img","command":[],
            "status":"created","supervisor_pid":0,"init_pid":0,"created_secs":0,
            "exit_code":null,"auto_remove":false}"#;
        let s: ContainerState = serde_json::from_str(legacy).expect("legacy state loads");
        assert!(s.config.scratch_path.is_none());
        assert_eq!(
            s.config.exec_backend,
            carrick_spec::ExecBackendRequest::HvPatch
        );
        // Load-bearing: a legacy entry with NO config object must default
        // max_traps to DEFAULT_MAX_TRAPS, not 0 (0 trips the trap limit at once).
        assert_eq!(s.config.max_traps, crate::runtime::DEFAULT_MAX_TRAPS);
        assert_eq!(s.config.stop_signal_abi, StopSignalAbi::Linux);

        // A config object present but WITHOUT max_traps also defaults correctly
        // (the named field serde default).
        let no_traps = r#"{"id":"y","name":null,"image":"img","command":[],
            "status":"created","supervisor_pid":0,"init_pid":0,"created_secs":0,
            "exit_code":null,"auto_remove":false,"config":{"env":["A=1"]}}"#;
        let s_nt: ContainerState = serde_json::from_str(no_traps).expect("loads");
        assert_eq!(s_nt.config.max_traps, crate::runtime::DEFAULT_MAX_TRAPS);
        assert_eq!(s_nt.config.stop_signal_abi, StopSignalAbi::LegacyHost);
        assert_eq!(
            s_nt.config.exec_backend,
            carrick_spec::ExecBackendRequest::HvPatch
        );

        // A fully-populated config round-trips (all P5 relaunch fields).
        let mut s2 = s.clone();
        s2.config.scratch_path = Some("/p/scratch".into());
        s2.config.env = vec!["A=1".into()];
        s2.config.entrypoint = Some(vec!["/bin/sh".into()]);
        s2.config.mounts = vec![carrick_spec::Mount {
            source: "/h".into(),
            target: "/g".into(),
            readonly: true,
        }];
        s2.config.fs = Some(carrick_spec::FsBackendKind::Host);
        s2.config.tty = true;
        s2.config.max_traps = 4242;
        s2.config.stop_signal = Some(3);
        s2.config.stop_timeout = Some(7);
        s2.config.exec_backend = carrick_spec::ExecBackendRequest::HvPatch;
        let json = serde_json::to_string(&s2).expect("serialize");
        let round: ContainerState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round.config.scratch_path.as_deref(), Some("/p/scratch"));
        assert_eq!(round.config.env, vec!["A=1".to_string()]);
        assert_eq!(round.config.entrypoint, Some(vec!["/bin/sh".to_string()]));
        assert_eq!(round.config.mounts.len(), 1);
        assert!(round.config.mounts[0].readonly);
        assert_eq!(round.config.fs, Some(carrick_spec::FsBackendKind::Host));
        assert!(round.config.tty);
        assert_eq!(round.config.max_traps, 4242);
        assert_eq!(round.config.stop_signal, Some(3));
        assert_eq!(round.config.stop_signal_abi, StopSignalAbi::Linux);
        assert_eq!(round.config.stop_timeout, Some(7));
        assert_eq!(
            round.config.exec_backend,
            carrick_spec::ExecBackendRequest::HvPatch
        );

        for (legacy_backend, guidance) in [
            ("native", "retired"),
            ("vmm", "retired"),
            ("hvf", "retired"),
        ] {
            let incompatible = no_traps.replace(
                r#""config":{"env":["A=1"]}"#,
                &format!(r#""config":{{"env":["A=1"],"exec_backend":"{legacy_backend}"}}"#),
            );
            let error = serde_json::from_str::<ContainerState>(&incompatible)
                .expect_err("explicit legacy backend must fail")
                .to_string();
            assert!(error.contains(guidance), "unexpected error: {error}");
        }
    }

    #[test]
    fn managed_terminal_state_is_bound_to_the_exact_control_incarnation() {
        let id = format!("terminal-receipt-{}", std::process::id());
        let _ = ContainerState::remove(&id);
        let _ = clear_terminal_receipt(&id);
        let control = CarrierControlState {
            schema: crate::kernel::control::CARRIER_CONTROL_STATE_SCHEMA.to_owned(),
            owner_nonce: crate::kernel::control::ControlNonce::fresh().expect("nonce"),
            init: crate::kernel::control::ControlTaskKey { pid: 1, serial: 7 },
        };
        let state = ContainerState {
            id: id.clone(),
            name: None,
            image: "test".to_owned(),
            command: vec!["/bin/true".to_owned()],
            status: ContainerStatus::Running,
            supervisor_pid: std::process::id() as i32,
            init_pid: std::process::id() as i32,
            created_secs: 0,
            exit_code: None,
            auto_remove: false,
            api_auto_remove: false,
            labels: std::collections::HashMap::new(),
            control: Some(control.clone()),
            terminal_control: None,
            launch_ticket: None,
            config: RunConfig::default(),
        };
        state.create().expect("create state");

        assert!(mark_control_owner_exited(&id, &control, 23).expect("mark terminal"));
        mark_exited(&id, 23);
        let terminal = ContainerState::load(&id).expect("terminal state");
        assert_eq!(terminal.status, ContainerStatus::Exited);
        assert_eq!(terminal.exit_code, Some(23));
        assert_eq!(terminal.control, None);
        assert_eq!(terminal.terminal_control, Some(control.clone()));
        assert_eq!(
            terminal_receipt(&id).expect("receipt"),
            Some(CarrierTerminalReceipt {
                control: control.clone(),
                exit_code: 23,
            })
        );

        let _ = ContainerState::remove(&id);
        let _ = clear_terminal_receipt(&id);

        let auto_id = format!("terminal-receipt-auto-{}", std::process::id());
        let _ = ContainerState::remove(&auto_id);
        let _ = clear_terminal_receipt(&auto_id);
        let mut auto = terminal;
        auto.id = auto_id.clone();
        auto.status = ContainerStatus::Running;
        auto.exit_code = None;
        auto.auto_remove = true;
        auto.control = Some(control.clone());
        auto.terminal_control = None;
        auto.create().expect("create auto-remove state");

        assert!(mark_control_owner_exited(&auto_id, &control, 9).expect("auto-remove terminal"));
        assert_eq!(
            ContainerState::load(&auto_id)
                .expect_err("auto-remove state removed")
                .kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(
            terminal_receipt(&auto_id).expect("auto-remove receipt"),
            Some(CarrierTerminalReceipt {
                control,
                exit_code: 9,
            })
        );
        let _ = clear_terminal_receipt(&auto_id);
    }

    #[test]
    fn lifecycle_lock_refuses_a_symlink_file() {
        let id = format!("lifecycle-lock-symlink-{}", std::process::id());
        let directory = registry_root().join(".lifecycle-locks");
        ensure_private_aux_directory(&directory).expect("private lock directory");
        let path = directory.join(format!("{id}.lock"));
        let _ = std::fs::remove_file(&path);
        std::os::unix::fs::symlink("/tmp", &path).expect("symlink fixture");

        let error = lock_lifecycle(&id).expect_err("O_NOFOLLOW must reject symlink lock");
        assert!(
            matches!(
                error.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::EACCES) | Some(libc::EPERM)
            ),
            "unexpected error: {error}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn lifecycle_lock_serializes_threads_in_the_same_process() {
        let id = format!("lifecycle-lock-thread-{}", std::process::id());
        let first = lock_lifecycle(&id).expect("first lifecycle lock");
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let thread_id = id.clone();
        let contender = std::thread::spawn(move || {
            let _second = lock_lifecycle(&thread_id).expect("second lifecycle lock");
            acquired_tx.send(()).expect("report acquisition");
        });

        assert_eq!(
            acquired_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "same-process lifecycle contender bypassed the first transaction"
        );
        drop(first);
        acquired_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("contender acquires after release");
        contender.join().expect("contender thread");
    }

    #[test]
    fn name_registry_lock_serializes_concurrent_creators() {
        let first = lock_name_registry().expect("first name registry lock");
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            let _second = lock_name_registry().expect("second name registry lock");
            acquired_tx.send(()).expect("report acquisition");
        });
        assert_eq!(
            acquired_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        );
        drop(first);
        acquired_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("creator acquires after release");
        contender.join().expect("creator thread");
    }

    #[test]
    fn name_registry_lock_never_aliases_a_container_lifecycle_stripe() {
        let registry = lifecycle_lock_stripe(".container-names");
        for index in 0..(LIFECYCLE_LOCK_STRIPES * 4) {
            let id = format!("container-lock-collision-check-{index}");
            assert!(
                !std::ptr::eq(registry, lifecycle_lock_stripe(&id)),
                "global name lock aliased the lifecycle stripe for {id}"
            );
        }
    }

    #[test]
    fn launch_ticket_is_one_shot_and_losing_entry_cannot_overwrite_winner() {
        let id = format!("launch-ticket-{}", std::process::id());
        let _ = ContainerState::remove(&id);
        let mut state: ContainerState = serde_json::from_str(
            r#"{"id":"placeholder","name":null,"image":"img","command":[],
                "status":"created","supervisor_pid":0,"init_pid":0,"created_secs":0,
                "exit_code":null,"auto_remove":false}"#,
        )
        .expect("state fixture");
        state.id = id.clone();
        state.create().expect("create state");

        let ticket = prepare_launch_ticket(&mut state).expect("prepare ticket");
        assert_eq!(ticket.len(), 32);
        bind_launch_ticket_to_pid(&id, &ticket, 77).expect("bind exact spawned pid");
        assert_eq!(
            consume_launch_ticket(&id, &ticket, 78)
                .expect_err("wrong pid must not consume ticket")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let authorization =
            consume_launch_ticket(&id, &ticket, 77).expect("exact entry consumes ticket");
        assert_eq!(
            ContainerState::load(&id)
                .expect("authorized state")
                .launch_ticket
                .as_deref(),
            Some(authorization.as_str())
        );
        assert_eq!(
            consume_launch_ticket(&id, &ticket, 77)
                .expect_err("duplicate entry must lose")
                .kind(),
            std::io::ErrorKind::NotFound
        );

        let control = CarrierControlState {
            schema: crate::kernel::control::CARRIER_CONTROL_STATE_SCHEMA.to_owned(),
            owner_nonce: crate::kernel::control::ControlNonce::fresh().expect("nonce"),
            init: crate::kernel::control::ControlTaskKey { pid: 1, serial: 11 },
        };
        let mut winner = ContainerState::load(&id).expect("consumed state");
        winner.status = ContainerStatus::Running;
        winner.control = Some(control.clone());
        winner.persist().expect("publish winner");

        mark_exited(&id, 125);
        let preserved = ContainerState::load(&id).expect("winner preserved");
        assert_eq!(preserved.status, ContainerStatus::Running);
        assert_eq!(preserved.control, Some(control));
        assert_eq!(preserved.exit_code, None);

        let _ = ContainerState::remove(&id);
    }

    #[test]
    fn load_reports_path_and_recreate_action_for_incompatible_backend() {
        let id = format!("legacy-backend-{}", std::process::id());
        let dir = container_dir_checked(&id).expect("safe test id");
        std::fs::create_dir_all(&dir).expect("create test registry directory"); // nosemgrep
        let path = state_path(&id).expect("state path");
        let incompatible = format!(
            r#"{{"id":"{id}","name":null,"image":"img","command":[],
                "status":"created","supervisor_pid":0,"init_pid":0,"created_secs":0,
                "exit_code":null,"auto_remove":false,
                "config":{{"exec_backend":"hvf"}}}}"#
        );
        std::fs::write(&path, incompatible).expect("write incompatible state"); // nosemgrep

        let error = ContainerState::load(&id).expect_err("legacy backend state must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let message = error.to_string();
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(
            message.contains(
                "native and legacy vmm backends were retired; only 'hvpatch' is supported"
            ),
            "{message}"
        );
        let _ = ContainerState::remove(&id);
    }

    #[test]
    fn persisted_container_state_is_private() {
        let mut state: ContainerState = serde_json::from_str(
            r#"{"id":"private-state-test","name":null,"image":"img","command":[],
                "status":"created","supervisor_pid":0,"init_pid":0,"created_secs":0,
                "exit_code":null,"auto_remove":false}"#,
        )
        .expect("state fixture");
        state.id = format!("private-state-{}", std::process::id());
        let _ = ContainerState::remove(&state.id);

        state.create().expect("create private state");

        let directory_mode = std::fs::metadata(container_dir(&state.id))
            .expect("container directory")
            .permissions()
            .mode()
            & 0o777;
        let state_mode = std::fs::metadata(state_path(&state.id).expect("state path"))
            .expect("state file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(state_mode, 0o600);

        let _ = ContainerState::remove(&state.id);
    }

    #[test]
    fn persisting_a_legacy_container_tightens_its_directory() {
        let mut state: ContainerState = serde_json::from_str(
            r#"{"id":"legacy-private-state","name":null,"image":"img","command":[],
                "status":"created","supervisor_pid":0,"init_pid":0,"created_secs":0,
                "exit_code":null,"auto_remove":false}"#,
        )
        .expect("state fixture");
        state.id = format!("legacy-private-state-{}", std::process::id());
        let directory = container_dir(&state.id);
        let _ = ContainerState::remove(&state.id);
        std::fs::create_dir_all(&directory).expect("legacy directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("legacy mode");

        state.persist().expect("persist legacy state");

        assert_eq!(
            std::fs::metadata(&directory)
                .expect("directory")
                .permissions()
                .mode()
                & 0o777,
            0o700,
        );
        let _ = ContainerState::remove(&state.id);
    }
}
