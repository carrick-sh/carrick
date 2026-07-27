//! Container-lifetime authority for portable native AArch64 translations.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const AUTHORITY_MARKER: &str = ".carrick-authority";
const AUTHORITY_NONCE_LEN: usize = 16;

static CONTAINER_CACHE: Mutex<Option<ContainerCacheAuthority>> = Mutex::new(None);

/// Identity required to adopt one container's cache directory after host
/// self-reexec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerCacheReexecConfig {
    pub host_fd: i32,
    pub original_host_fd_flags: i32,
    pub host_device: u64,
    pub host_inode: u64,
    pub path: PathBuf,
    pub creator_pid: i32,
    pub authority_nonce: [u8; AUTHORITY_NONCE_LEN],
    pub translator_abi: u32,
}

/// The open-directory capability behind a container-private cache.
#[derive(Debug)]
pub struct ContainerCacheAuthority {
    directory: File,
    path: PathBuf,
    creator_pid: i32,
    authority_nonce: [u8; AUTHORITY_NONCE_LEN],
    cleanup_owner: bool,
}

impl ContainerCacheAuthority {
    fn create() -> std::io::Result<Self> {
        let tempdir = tempfile::Builder::new()
            .prefix("carrick-native-aot-")
            .tempdir()?;
        let path = tempdir.path().to_path_buf();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;

        let mut authority_nonce = [0_u8; AUTHORITY_NONCE_LEN];
        getrandom::fill(&mut authority_nonce)
            .map_err(|error| invalid_data(format!("generate cache authority nonce: {error}")))?;
        let marker_path = path.join(AUTHORITY_MARKER);
        let mut marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&marker_path)?;
        marker.write_all(&authority_nonce)?;
        marker.sync_all()?;

        let directory = open_directory(&path)?;
        let kept_path = tempdir.keep();
        debug_assert_eq!(kept_path, path);
        Ok(Self {
            directory,
            path,
            creator_pid: unsafe { libc::getpid() },
            authority_nonce,
            cleanup_owner: true,
        })
    }

    fn adopt(config: &ContainerCacheReexecConfig) -> std::io::Result<Self> {
        if config.host_fd < 0
            || !config.path.is_absolute()
            || config.translator_abi != carrick_dsr_aarch64::shared_cache::TRANSLATOR_ABI_V1
        {
            return Err(invalid_data("invalid inherited cache authority"));
        }

        // The reexec transport transfers ownership of this descriptor. Take
        // it before validation so every rejection closes the inherited fd.
        let directory = unsafe { File::from_raw_fd(config.host_fd) };
        let fd_identity = directory.metadata()?;
        let path_identity = std::fs::symlink_metadata(&config.path)?;
        if !path_identity.is_dir()
            || path_identity.file_type().is_symlink()
            || fd_identity.dev() != config.host_device
            || fd_identity.ino() != config.host_inode
            || path_identity.dev() != config.host_device
            || path_identity.ino() != config.host_inode
            || path_identity.uid() != unsafe { libc::geteuid() }
            || path_identity.mode() & 0o777 != 0o700
        {
            return Err(invalid_data("inherited cache authority identity mismatch"));
        }

        let marker_name = CString::new(AUTHORITY_MARKER)
            .map_err(|_| invalid_data("cache authority marker contains NUL"))?;
        let marker_fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                marker_name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if marker_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut marker = unsafe { File::from_raw_fd(marker_fd) };
        let mut authority_nonce = [0_u8; AUTHORITY_NONCE_LEN];
        marker.read_exact(&mut authority_nonce)?;
        let mut trailing = [0_u8; 1];
        if marker.read(&mut trailing)? != 0 || authority_nonce != config.authority_nonce {
            return Err(invalid_data("inherited cache authority nonce mismatch"));
        }

        if unsafe {
            libc::fcntl(
                directory.as_raw_fd(),
                libc::F_SETFD,
                config.original_host_fd_flags,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            directory,
            path: config.path.clone(),
            creator_pid: config.creator_pid,
            authority_nonce,
            // Only the process that created the directory may remove it. An
            // adopted authority is always a descendant's capability.
            cleanup_owner: false,
        })
    }

    pub fn snapshot(&self) -> std::io::Result<ContainerCacheReexecConfig> {
        let host_fd = self.directory.as_raw_fd();
        let original_host_fd_flags = unsafe { libc::fcntl(host_fd, libc::F_GETFD) };
        if original_host_fd_flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let identity = self.directory.metadata()?;
        Ok(ContainerCacheReexecConfig {
            host_fd,
            original_host_fd_flags,
            host_device: identity.dev(),
            host_inode: identity.ino(),
            path: self.path.clone(),
            creator_pid: self.creator_pid,
            authority_nonce: self.authority_nonce,
            translator_abi: carrick_dsr_aarch64::shared_cache::TRANSLATOR_ABI_V1,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    fn directory(&self) -> &File {
        &self.directory
    }
}

impl Drop for ContainerCacheAuthority {
    fn drop(&mut self) {
        if self.cleanup_owner && owns_cleanup(self.creator_pid, unsafe { libc::getpid() }) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Scope guard owned by the parent process that launched one native
/// container. Dropping it after the root guest exits removes the cache.
#[derive(Debug)]
pub struct ContainerCacheSession {
    creator_pid: i32,
}

impl Drop for ContainerCacheSession {
    fn drop(&mut self) {
        if !owns_cleanup(self.creator_pid, unsafe { libc::getpid() }) {
            return;
        }
        if let Ok(mut authority) = CONTAINER_CACHE.lock()
            && authority
                .as_ref()
                .is_some_and(|cache| cache.creator_pid == self.creator_pid)
        {
            let _ = authority.take();
        }
    }
}

pub fn begin_container_cache() -> std::io::Result<ContainerCacheSession> {
    let authority = ContainerCacheAuthority::create()?;
    let creator_pid = authority.creator_pid;
    let mut active = CONTAINER_CACHE
        .lock()
        .map_err(|_| invalid_data("container cache authority lock poisoned"))?;
    if active.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "a native container cache is already active",
        ));
    }
    *active = Some(authority);
    Ok(ContainerCacheSession { creator_pid })
}

pub fn container_cache_snapshot() -> std::io::Result<Option<ContainerCacheReexecConfig>> {
    CONTAINER_CACHE
        .lock()
        .map_err(|_| invalid_data("container cache authority lock poisoned"))?
        .as_ref()
        .map(ContainerCacheAuthority::snapshot)
        .transpose()
}

pub fn adopt_container_cache(config: &ContainerCacheReexecConfig) -> std::io::Result<()> {
    let authority = ContainerCacheAuthority::adopt(config)?;
    let mut active = CONTAINER_CACHE
        .lock()
        .map_err(|_| invalid_data("container cache authority lock poisoned"))?;
    if active.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "native container cache authority was already initialized",
        ));
    }
    *active = Some(authority);
    Ok(())
}

fn open_directory(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn owns_cleanup(creator_pid: i32, current_pid: i32) -> bool {
    creator_pid == current_pid
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::PermissionsExt;

    fn duplicated_snapshot(authority: &ContainerCacheAuthority) -> ContainerCacheReexecConfig {
        let mut snapshot = authority.snapshot().expect("snapshot cache authority");
        let duplicate =
            unsafe { libc::fcntl(authority.directory().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        assert!(duplicate >= 0, "duplicate directory fd");
        snapshot.host_fd = duplicate;
        snapshot
    }

    #[test]
    fn authority_is_private_and_survives_validated_reexec_adoption() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let snapshot = duplicated_snapshot(&authority);
        let adopted = ContainerCacheAuthority::adopt(&snapshot).expect("adopt cache authority");

        assert_eq!(adopted.path(), authority.path());
        assert_eq!(
            adopted.snapshot().expect("snapshot adopted authority"),
            snapshot
        );
        assert_eq!(
            std::fs::metadata(authority.path())
                .expect("stat cache directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn authority_rejects_substituted_directory_fd() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let substitute = ContainerCacheAuthority::create().expect("create substitute authority");
        let mut snapshot = duplicated_snapshot(&substitute);
        let expected = authority.snapshot().expect("snapshot expected authority");
        snapshot.host_device = expected.host_device;
        snapshot.host_inode = expected.host_inode;

        let error = ContainerCacheAuthority::adopt(&snapshot)
            .expect_err("substituted directory must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn authority_rejects_substituted_directory_path() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let substitute = ContainerCacheAuthority::create().expect("create substitute authority");
        let mut snapshot = duplicated_snapshot(&authority);
        snapshot.path = substitute.path().to_path_buf();

        let error = ContainerCacheAuthority::adopt(&snapshot)
            .expect_err("substituted path must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn only_the_creator_pid_owns_cleanup() {
        let pid = unsafe { libc::getpid() };
        assert!(owns_cleanup(pid, pid));
        assert!(!owns_cleanup(pid, pid.saturating_add(1)));
    }

    #[test]
    fn creator_session_removes_cache_after_container_exit() {
        let session = begin_container_cache().expect("begin container cache");
        let path = container_cache_snapshot()
            .expect("snapshot container cache")
            .expect("active container cache")
            .path;
        assert!(path.is_dir());

        drop(session);

        assert!(!path.exists());
        assert!(
            container_cache_snapshot()
                .expect("snapshot inactive cache")
                .is_none()
        );
    }

    #[test]
    fn inherited_process_cannot_remove_creator_cache() {
        let mut authority = ContainerCacheAuthority::create().expect("create cache authority");
        let path = authority.path().to_path_buf();
        authority.creator_pid = unsafe { libc::getpid() }.saturating_add(1);

        drop(authority);

        assert!(path.is_dir());
        std::fs::remove_dir_all(path).expect("remove test cache");
    }

    #[test]
    fn adoption_takes_ownership_of_the_inherited_fd() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let snapshot = duplicated_snapshot(&authority);
        let inherited_fd = snapshot.host_fd;
        let adopted = ContainerCacheAuthority::adopt(&snapshot).expect("adopt cache authority");
        drop(adopted);

        let borrowed = unsafe { std::fs::File::from_raw_fd(inherited_fd) };
        let result = unsafe { libc::fcntl(borrowed.as_raw_fd(), libc::F_GETFD) };
        std::mem::forget(borrowed);
        assert_eq!(result, -1);
    }
}
