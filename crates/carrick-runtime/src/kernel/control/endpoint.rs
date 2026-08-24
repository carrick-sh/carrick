use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::ControlNonce;

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const SOCKET_NAME: &str = "control.sock";
const OWNER_NAME: &str = "owner.json";
const MAX_SUN_PATH: usize =
    size_of::<libc::sockaddr_un>() - std::mem::offset_of!(libc::sockaddr_un, sun_path) - 1;

#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("carrier control needs a safe non-empty container id")]
    InvalidContainerId,
    #[error("carrier control endpoint is owned by live pid {pid}")]
    OwnedByLiveProcess { pid: u32 },
    #[error("carrier control endpoint owner record is invalid: {0}")]
    InvalidOwner(String),
    #[error("carrier control endpoint belongs to a different incarnation")]
    StaleOwnerNonce,
    #[error("carrier control socket path is too long: {0}")]
    PathTooLong(String),
    #[error("carrier control endpoint I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Clone, Debug)]
pub struct ControlEndpoint {
    base: PathBuf,
    directory: PathBuf,
    socket: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CurrentOwner {
    pub pid: u32,
    pub nonce: ControlNonce,
}

impl ControlEndpoint {
    pub fn for_container_id(container_id: &str) -> Result<Self, EndpointError> {
        // The endpoint is created and authenticated by the effective
        // credential.  Using the real uid here makes a sudo-launched carrier
        // create a root-owned directory under a non-root uid's pathname, which
        // the later ownership check correctly rejects.
        let uid = unsafe { libc::geteuid() };
        let base = std::env::var_os("CARRICK_CONTROL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("/tmp/carrick-control-{uid}")));
        Self::in_base(base, container_id)
    }

    pub fn in_base(base: PathBuf, container_id: &str) -> Result<Self, EndpointError> {
        if !crate::container::is_safe_id(container_id) {
            return Err(EndpointError::InvalidContainerId);
        }
        let digest = Sha256::digest(container_id.as_bytes());
        let token = digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let directory = base.join(token);
        let socket = directory.join(SOCKET_NAME);
        if socket.as_os_str().len() > MAX_SUN_PATH {
            return Err(EndpointError::PathTooLong(socket.display().to_string()));
        }
        Ok(Self {
            base,
            directory,
            socket,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn owner_path(&self) -> PathBuf {
        self.directory.join(OWNER_NAME)
    }

    pub fn claim(&self, nonce: ControlNonce) -> Result<(), EndpointError> {
        ensure_owned_private_directory(&self.base)?;
        ensure_owned_private_directory(&self.directory)?;
        match fs::read(self.owner_path()) {
            Ok(bytes) => {
                let owner: OwnerRecord = serde_json::from_slice(&bytes)
                    .map_err(|error| EndpointError::InvalidOwner(error.to_string()))?;
                if owner.nonce == nonce {
                    return Ok(());
                }
                if process_is_alive(owner.pid) {
                    return Err(EndpointError::OwnedByLiveProcess { pid: owner.pid });
                }
                remove_file(&self.socket)?;
                remove_file(&self.owner_path())?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if fs::symlink_metadata(&self.socket).is_ok() {
                    return Err(EndpointError::InvalidOwner(format!(
                        "{} exists without an owner record",
                        self.socket.display()
                    )));
                }
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    pub fn publish_bound_owner(&self, nonce: ControlNonce) -> Result<(), EndpointError> {
        fs::set_permissions(&self.socket, fs::Permissions::from_mode(FILE_MODE))?;
        let owner = OwnerRecord {
            pid: std::process::id(),
            nonce,
        };
        let path = self.owner_path();
        let temporary = self.directory.join(format!("owner.{}.tmp", nonce.hex()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(FILE_MODE))?;
        file.write_all(&serde_json::to_vec(&owner).map_err(io::Error::other)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        // `sync_all` above makes the record bytes durable; syncing the parent
        // makes the atomic name replacement durable as well.
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    pub(super) fn current_owner(&self, nonce: ControlNonce) -> Result<CurrentOwner, EndpointError> {
        let owner = self
            .read_owner()?
            .ok_or_else(|| EndpointError::InvalidOwner("owner record is missing".to_owned()))?;
        if owner.nonce != nonce {
            return Err(EndpointError::StaleOwnerNonce);
        }
        if !process_is_alive(owner.pid) {
            return Err(EndpointError::InvalidOwner(
                "owner process is no longer live".to_owned(),
            ));
        }
        Ok(CurrentOwner {
            pid: owner.pid,
            nonce: owner.nonce,
        })
    }

    pub fn release_if_owner(&self, nonce: ControlNonce) {
        if self
            .read_owner()
            .ok()
            .flatten()
            .is_some_and(|owner| owner.pid == std::process::id() && owner.nonce == nonce)
        {
            let _ = remove_file(&self.socket);
            let _ = remove_file(&self.owner_path());
        }
    }

    pub(super) fn rollback_unpublished_socket(&self) {
        if self.read_owner().ok().flatten().is_none() {
            let _ = remove_file(&self.socket);
        }
    }

    fn read_owner(&self) -> Result<Option<OwnerRecord>, EndpointError> {
        match fs::read(self.owner_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| EndpointError::InvalidOwner(error.to_string())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

fn ensure_owned_private_directory(path: &Path) -> Result<(), EndpointError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_owned_private_directory(path, &metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))?;
            let metadata = fs::symlink_metadata(path)?;
            validate_owned_private_directory(path, &metadata)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_owned_private_directory(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), EndpointError> {
    let uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != uid {
        return Err(EndpointError::InvalidOwner(format!(
            "{} is not an owned directory",
            path.display()
        )));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))?;
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRecord {
    pid: u32,
    nonce: ControlNonce,
}

fn remove_file(path: &Path) -> Result<(), EndpointError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn process_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(test)]
pub(super) fn test_endpoint(container_id: &str) -> (tempfile::TempDir, ControlEndpoint) {
    let temp = tempfile::Builder::new()
        .prefix("cc")
        .tempdir_in("/tmp")
        .expect("tempdir");
    let endpoint =
        ControlEndpoint::in_base(temp.path().to_path_buf(), container_id).expect("endpoint");
    (temp, endpoint)
}
