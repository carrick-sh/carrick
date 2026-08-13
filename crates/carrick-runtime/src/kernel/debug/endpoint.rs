//! Socket location, permissions, and stale-owner rules for the kernel debug
//! endpoint.
//!
//! The path is `/tmp/carrick-kernel/<uid>/<token>/snapshot.sock`, where
//! `token` is the first 128 bits of `sha256(CARRICK_RUN_ID)` in hex. The run
//! ID is hashed, never embedded: a run ID may carry a branch name, a ticket,
//! or a host name, and a world-readable listing must not leak it. Parent
//! directories are 0700 and the socket is 0600, so the filesystem agrees with
//! the peer-uid check rather than relying on it alone.
//!
//! **Correction to the K1 spec's `$TMPDIR` + full-digest layout.** That layout
//! is not bindable on the reference platform. macOS `sun_path` holds 104 bytes
//! including the NUL, while a per-user `$TMPDIR`
//! (`/var/folders/8f/dl9bkkyn1zs5ycl864wv184h0000gn/T/`, 49 bytes) plus
//! `carrick-kernel/<uid>/` plus a 64-hex digest plus `snapshot.sock` is 146
//! bytes — every bind would fail `EINVAL`. Two changes make it fit with room
//! to spare (70 bytes): a fixed `/tmp` base instead of `$TMPDIR`, and a
//! 32-hex-character token.
//!
//! The fixed base is also the more correct choice for a *rendezvous* path: the
//! runtime and the `carrick debug` client are separate processes, and
//! `$TMPDIR` is not guaranteed identical between them (it differs under
//! `sudo`, under a different launch context, and inside a test harness). A
//! rendezvous both sides must compute independently cannot depend on ambient
//! per-process environment. Isolation is unchanged: the per-uid parent is
//! 0700, the socket is 0600, and the peer uid is checked on every connection.
//! 128 bits of digest is far past any collision concern for a directory name
//! and is equally irreversible.
//!
//! A leftover socket from a crashed run must not permanently poison the run
//! ID, and a *live* run's socket must never be stolen by a second server. The
//! owner record next to the socket carries the owning host PID and a per-server
//! nonce; reclamation requires proof that the recorded owner is gone AND that
//! the record is not our own.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const DIRECTORY_MODE: u32 = 0o700;
const SOCKET_MODE: u32 = 0o600;
const OWNER_RECORD: &str = "owner.json";
const SOCKET_NAME: &str = "snapshot.sock";
/// Hex characters of the run digest kept in the path. 32 hex = 128 bits.
const RUN_TOKEN_HEX: usize = 32;

/// Capacity of `sockaddr_un.sun_path`, derived from the platform's own struct
/// rather than written down. The value differs per platform (macOS and the
/// BSDs give 104, Linux 108), and a hardcoded number here would silently
/// become wrong on a host whose ABI disagrees — the failure mode being a
/// `bind` that returns a bare `EINVAL`.
const SUN_PATH_CAPACITY: usize =
    size_of::<libc::sockaddr_un>() - std::mem::offset_of!(libc::sockaddr_un, sun_path);

/// Usable path bytes, reserving the terminating NUL.
const MAX_SUN_PATH: usize = SUN_PATH_CAPACITY - 1;

/// Override for the rendezvous base. Both the runtime and the client read it,
/// so a caller that sets it must set it for both.
const BASE_DIR_ENV: &str = "CARRICK_KERNEL_DEBUG_DIR";

#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("kernel debug endpoint needs a non-empty CARRICK_RUN_ID")]
    MissingRunId,
    #[error("kernel debug endpoint path is already owned by live pid {pid}")]
    OwnedByLiveProcess { pid: u32 },
    #[error("kernel debug endpoint owner record is unreadable: {0}")]
    UnreadableOwner(String),
    #[error(
        "kernel debug socket path is {length} bytes, over the {MAX_SUN_PATH}-byte AF_UNIX limit: {path}"
    )]
    PathTooLong { length: usize, path: String },
    #[error("kernel debug endpoint filesystem operation failed: {0}")]
    Io(#[from] io::Error),
}

/// A resolved endpoint location. Constructing one performs no I/O, so a client
/// can compute the path of a run that is not running.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebugEndpoint {
    base: PathBuf,
    directory: PathBuf,
    socket: PathBuf,
}

impl DebugEndpoint {
    /// Resolve the endpoint for an exact external run identity under the
    /// ambient `$TMPDIR`.
    pub fn for_run_id(run_id: &str) -> Result<Self, EndpointError> {
        Self::in_base(base_directory(), run_id)
    }

    /// Resolve under an explicit base directory.
    ///
    /// Tests use this instead of mutating `TMPDIR`: process-global env
    /// mutation is racy across parallel tests and makes one test's temp dir
    /// the parent of the next one's.
    pub fn in_base(base: PathBuf, run_id: &str) -> Result<Self, EndpointError> {
        if run_id.is_empty() {
            return Err(EndpointError::MissingRunId);
        }
        let token = run_token(run_id);
        let directory = base.join(uid_component()).join(token);
        let socket = directory.join(SOCKET_NAME);
        // Fail here, by name, rather than letting `bind` return a bare
        // `EINVAL` that no operator can act on.
        let length = socket.as_os_str().len();
        if length > MAX_SUN_PATH {
            return Err(EndpointError::PathTooLong {
                length,
                path: socket.display().to_string(),
            });
        }
        Ok(Self {
            base,
            directory,
            socket,
        })
    }

    /// Resolve from the ambient `CARRICK_RUN_ID`, which every gated run sets.
    pub fn for_current_run() -> Result<Self, EndpointError> {
        let run_id = std::env::var("CARRICK_RUN_ID").unwrap_or_default();
        Self::for_run_id(&run_id)
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn owner_record_path(&self) -> PathBuf {
        self.directory.join(OWNER_RECORD)
    }

    /// Create the directory chain with 0700 and claim the socket path.
    ///
    /// Fails closed when a live server already owns it. Reclaims only when the
    /// recorded owner PID is dead and the record is not this server's own.
    pub fn claim(&self, nonce: u64) -> Result<(), EndpointError> {
        create_private_dir(&self.base, &self.directory)?;

        if let Some(owner) = self.read_owner()? {
            if owner.nonce == nonce {
                // Our own record. Nothing to reclaim, nothing to steal.
                return Ok(());
            }
            if process_is_alive(owner.pid) {
                return Err(EndpointError::OwnedByLiveProcess { pid: owner.pid });
            }
            // Recorded owner is gone and is not us: reclaim.
            remove_if_present(&self.socket)?;
            remove_if_present(&self.owner_record_path())?;
        } else {
            // No record at all. A bare socket with no owner record cannot be
            // proven dead, so refuse rather than steal it.
            if fs::symlink_metadata(&self.socket).is_ok() {
                return Err(EndpointError::UnreadableOwner(format!(
                    "{} exists with no owner record",
                    self.socket.display()
                )));
            }
        }
        Ok(())
    }

    /// Record this server as the owner. Written after a successful bind so a
    /// record never advertises a socket that does not exist.
    pub fn write_owner(&self, nonce: u64) -> Result<(), EndpointError> {
        let record = OwnerRecord {
            pid: std::process::id(),
            nonce,
        };
        let encoded = serde_json::to_vec(&record)
            .map_err(|error| EndpointError::UnreadableOwner(error.to_string()))?;
        let path = self.owner_record_path();
        fs::write(&path, encoded)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(SOCKET_MODE))?;
        Ok(())
    }

    /// Tighten the bound socket to 0600.
    pub fn secure_socket(&self) -> Result<(), EndpointError> {
        fs::set_permissions(&self.socket, fs::Permissions::from_mode(SOCKET_MODE))?;
        Ok(())
    }

    /// Best-effort teardown. A failure here must not mask a run's real result.
    pub fn release(&self) {
        let _ = remove_if_present(&self.socket);
        let _ = remove_if_present(&self.owner_record_path());
    }

    fn read_owner(&self) -> Result<Option<OwnerRecord>, EndpointError> {
        let path = self.owner_record_path();
        match fs::read(&path) {
            Ok(bytes) => {
                let record: OwnerRecord = serde_json::from_slice(&bytes)
                    .map_err(|error| EndpointError::UnreadableOwner(error.to_string()))?;
                Ok(Some(record))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(EndpointError::Io(error)),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct OwnerRecord {
    pid: u32,
    nonce: u64,
}

/// Hash the run ID so the path carries a token, never the identity itself.
fn run_token(run_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(run_id.as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .chars()
        .take(RUN_TOKEN_HEX)
        .collect()
}

/// Fixed rendezvous base. Deliberately not `$TMPDIR` — see the module docs.
fn base_directory() -> PathBuf {
    std::env::var_os(BASE_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/carrick-kernel"))
}

fn uid_component() -> String {
    // SAFETY: `getuid` is always safe and cannot fail.
    let uid = unsafe { libc::getuid() };
    uid.to_string()
}

fn create_private_dir(base: &Path, path: &Path) -> Result<(), EndpointError> {
    fs::create_dir_all(path)?;
    // Re-apply the mode: `create_dir_all` honours the umask, so a permissive
    // umask would otherwise leave an 0755 directory behind. Walk up only as
    // far as the base — the base's own parents are not ours to tighten.
    let mut current = Some(path);
    while let Some(directory) = current {
        fs::set_permissions(directory, fs::Permissions::from_mode(DIRECTORY_MODE))?;
        if directory == base {
            break;
        }
        current = directory.parent();
    }
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<(), EndpointError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(EndpointError::Io(error)),
    }
}

/// `kill(pid, 0)` distinguishes "gone" from "alive but not ours". `EPERM`
/// means the process exists under another uid, which is still alive.
fn process_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: signal 0 performs permission/existence checks only.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A SHORT base: the whole point of the layout correction is that the
    /// socket path fits `sun_path`, and a test rooted in the deep macOS
    /// `$TMPDIR` would not exercise a bindable path.
    pub(in crate::kernel::debug) fn scoped_endpoint(
        run_id: &str,
    ) -> (tempfile::TempDir, DebugEndpoint) {
        let temp = tempfile::Builder::new()
            .prefix("ck")
            .tempdir_in("/tmp")
            .expect("temp dir");
        let endpoint = DebugEndpoint::in_base(temp.path().to_path_buf(), run_id).expect("endpoint");
        (temp, endpoint)
    }

    #[test]
    fn the_path_hashes_the_run_id_and_never_embeds_it() {
        let (_temp, endpoint) = scoped_endpoint("branch/feature-secret-ticket-1234");
        let rendered = endpoint.socket_path().display().to_string();
        assert!(
            !rendered.contains("secret") && !rendered.contains("ticket"),
            "run id leaked into {rendered}"
        );
        assert!(
            rendered.ends_with(SOCKET_NAME),
            "unexpected socket name in {rendered}"
        );
        let token = run_token("branch/feature-secret-ticket-1234");
        assert_eq!(token.len(), RUN_TOKEN_HEX, "token must be a 128-bit prefix");
        assert!(rendered.contains(&token), "token missing from {rendered}");
    }

    #[test]
    fn distinct_run_ids_get_distinct_endpoints() {
        let temp = tempfile::Builder::new()
            .prefix("ck")
            .tempdir_in("/tmp")
            .expect("temp dir");
        let base = temp.path().to_path_buf();
        let first = DebugEndpoint::in_base(base.clone(), "run-a").expect("endpoint");
        let second = DebugEndpoint::in_base(base, "run-b").expect("endpoint");
        assert_ne!(first.socket_path(), second.socket_path());
    }

    /// The default production layout must be bindable on this host. This is
    /// the regression test for the `$TMPDIR` + 64-hex layout that produced a
    /// 146-byte path and an unconditional `EINVAL` from `bind`.
    #[test]
    fn the_default_layout_fits_the_af_unix_path_limit() {
        let endpoint = DebugEndpoint::for_run_id(
            "a-deliberately-long-external-run-identity-with-branch-and-ticket-detail",
        )
        .expect("the default layout must resolve");
        let length = endpoint.socket_path().as_os_str().len();
        assert!(
            length <= MAX_SUN_PATH,
            "default socket path is {length} bytes: {}",
            endpoint.socket_path().display()
        );
    }

    /// An over-long base is refused by name rather than deferred to `bind`.
    #[test]
    fn an_unbindable_path_is_refused_by_name() {
        let base = PathBuf::from(format!("/tmp/{}", "x".repeat(MAX_SUN_PATH)));
        let error = DebugEndpoint::in_base(base, "run-too-long")
            .expect_err("an over-long path must be refused");
        assert!(
            matches!(error, EndpointError::PathTooLong { .. }),
            "expected a named path-length refusal, got {error:?}"
        );
    }

    #[test]
    fn an_empty_run_id_is_refused() {
        assert!(matches!(
            DebugEndpoint::for_run_id(""),
            Err(EndpointError::MissingRunId)
        ));
    }

    #[test]
    fn claim_creates_private_directories() {
        let (_temp, endpoint) = scoped_endpoint("run-private");
        endpoint.claim(7).expect("claim");
        let mode = fs::metadata(endpoint.directory())
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, DIRECTORY_MODE, "endpoint directory must be 0700");
    }

    #[test]
    fn a_live_owner_is_never_stolen() {
        let (_temp, endpoint) = scoped_endpoint("run-live-owner");
        endpoint.claim(1).expect("claim");
        // The current process is unambiguously alive.
        endpoint.write_owner(1).expect("write owner");
        let error = endpoint
            .claim(2)
            .expect_err("a second server must not steal a live endpoint");
        assert!(
            matches!(error, EndpointError::OwnedByLiveProcess { .. }),
            "expected live-owner refusal, got {error:?}"
        );
    }

    #[test]
    fn a_dead_owner_is_reclaimed() {
        let (_temp, endpoint) = scoped_endpoint("run-dead-owner");
        endpoint.claim(1).expect("claim");
        // pid 0 is never a live process for this purpose.
        let record = OwnerRecord { pid: 0, nonce: 1 };
        fs::write(
            endpoint.owner_record_path(),
            serde_json::to_vec(&record).expect("encode"),
        )
        .expect("seed stale owner");
        fs::write(endpoint.socket_path(), b"stale").expect("seed stale socket");

        endpoint.claim(2).expect("a dead owner must be reclaimable");
        assert!(
            !endpoint.socket_path().exists(),
            "reclaim must remove the stale socket"
        );
    }

    #[test]
    fn a_socket_with_no_owner_record_is_refused_rather_than_stolen() {
        let (_temp, endpoint) = scoped_endpoint("run-orphan-socket");
        endpoint.claim(1).expect("claim");
        fs::write(endpoint.socket_path(), b"orphan").expect("seed orphan socket");
        let error = endpoint
            .claim(2)
            .expect_err("an unprovable owner must not be reclaimed");
        assert!(
            matches!(error, EndpointError::UnreadableOwner(_)),
            "expected unreadable-owner refusal, got {error:?}"
        );
    }

    #[test]
    fn reclaiming_our_own_record_is_idempotent() {
        let (_temp, endpoint) = scoped_endpoint("run-self-claim");
        endpoint.claim(42).expect("claim");
        endpoint.write_owner(42).expect("write owner");
        endpoint
            .claim(42)
            .expect("a server must be able to re-claim its own endpoint");
    }
}
