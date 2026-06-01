//! Container lifecycle registry — the on-disk state that backs `carrick run
//! -d`, `ps`, `stop`, `kill`, and `rm`.
//!
//! Carrick is **daemonless**: there is no `carrickd`. Each detached container
//! is its own process tree rooted at a per-container NsSupervisor (the parent
//! half of the runtime fork — see [`crate::namespace::supervisor`]). This
//! module is just a filesystem registry: one directory per container under a
//! shared root, holding a JSON state file plus the captured stdout/stderr log.
//! `ps`/`stop`/`kill`/`rm` are pure CLI operations over this directory — they
//! read state, send signals to the recorded pids, and unlink. Nothing needs to
//! be running for them to work; if no container is detached, nothing is alive.
//!
//! This mirrors the podman model (per-container conmon + on-disk state), not
//! the docker model (one always-on daemon owning every container).

use std::path::{Path, PathBuf};

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

/// One container's persisted state. Written by the detached supervisor and read
/// by the lifecycle CLI subcommands. Field set is intentionally small and
/// host-meaningful (the pids are HOST pids — what the CLI signals).
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
    /// Host pid of the NsSupervisor (the detached process the CLI waits on /
    /// signals for whole-container control). 0 until known.
    pub supervisor_pid: i32,
    /// Host pid of the guest-init (ns-pid 1) — the target of `stop`/`kill`. 0
    /// until known.
    pub init_pid: i32,
    /// Unix epoch seconds when the container was created (stamped by the
    /// caller, since the runtime forbids `SystemTime::now` in some contexts).
    pub created_secs: u64,
    /// Exit code once `status == Exited`.
    pub exit_code: Option<i32>,
    /// `--rm`: remove the registry entry when the container exits.
    pub auto_remove: bool,
}

/// The registry root: `<scratch>/containers` (per-user, case-sensitive). Each
/// container lives in `<root>/<id>/`.
pub fn registry_root() -> PathBuf {
    crate::apfs::preferred_scratch_root()
        .unwrap_or_else(|_| std::env::temp_dir().join("carrick"))
        .join("containers")
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

impl ContainerState {
    /// Create the container directory and write the initial state atomically
    /// (write to a temp file + rename, like `cred_ipc`). The id is one carrick
    /// generated (64-hex), so it always passes the safe-id guard.
    pub fn create(&self) -> std::io::Result<()> {
        let dir = container_dir_checked(&self.id).ok_or_else(unsafe_id_err)?;
        std::fs::create_dir_all(&dir)?;
        self.persist()
    }

    /// Persist the current state to `state.json` atomically.
    pub fn persist(&self) -> std::io::Result<()> {
        let path = state_path(&self.id)?;
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // `path`/`tmp` are under the registry root by construction (id is an
        // allowlisted token; see container_dir_checked).
        std::fs::write(&tmp, &bytes)?; // nosemgrep
        std::fs::rename(&tmp, &path) // nosemgrep
    }

    /// Load a container's state by id.
    pub fn load(id: &str) -> std::io::Result<Self> {
        let path = state_path(id)?;
        let bytes = std::fs::read(&path)?; // nosemgrep
        serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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

/// `kill(pid, 0) == 0` — the process exists and we may signal it. A pid <= 0 is
/// never alive.
pub fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: kill with signal 0 only probes existence/permission; it delivers
    // nothing.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// List all container states in the registry (best-effort; unreadable or
/// malformed entries are skipped). Stale `Running` entries whose init has died
/// are reported with their recorded state — the CLI reconciles them.
pub fn list() -> Vec<ContainerState> {
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
    let all = list();
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
    // Two 64-bit words → 32 hex chars; pad to 64 with a mix so it LOOKS like a
    // docker sha256 id without implying content addressing.
    let a = seed_hi.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15;
    let b = seed_lo.wrapping_mul(0xc2b2_ae3d_27d4_eb4f);
    let c = (seed_hi ^ seed_lo).wrapping_add(0x1656_67b1_9e37_79f9);
    let d = (seed_hi.wrapping_add(seed_lo)).rotate_right(23);
    format!("{a:016x}{b:016x}{c:016x}{d:016x}")
}

/// Update an existing container's state to Exited (or remove it if auto_remove),
/// recording the exit code. Best-effort: a missing entry is not an error.
pub fn mark_exited(id: &str, exit_code: i32) {
    if let Ok(mut state) = ContainerState::load(id) {
        if state.auto_remove {
            let _ = ContainerState::remove(id);
        } else {
            state.status = ContainerStatus::Exited;
            state.exit_code = Some(exit_code);
            let _ = state.persist();
        }
    }
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

#[cfg(test)]
mod tests {
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
        };
        assert_eq!(reconciled_status(&s), ContainerStatus::Exited);
        s.status = ContainerStatus::Created;
        assert_eq!(reconciled_status(&s), ContainerStatus::Created);
    }
}
