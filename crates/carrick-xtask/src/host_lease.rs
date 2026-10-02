use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::ffi::{CString, OsString};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use thiserror::Error;

pub const DEFAULT_LOCK_PATH: &str = "/tmp/carrick-host-lease.lock";

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostLeaseMode {
    Carrick,
    Docker,
}

impl fmt::Display for HostLeaseMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Carrick => write!(f, "carrick"),
            Self::Docker => write!(f, "docker"),
        }
    }
}

#[derive(Debug, Error)]
pub enum HostLeaseError {
    #[error("I/O error on host lease at '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to spawn child process '{cmd}': {source}")]
    Spawn {
        cmd: String,
        #[source]
        source: io::Error,
    },
    #[error("child process error: {0}")]
    ChildWait(#[source] io::Error),
    #[error("no command specified to run under host-lease")]
    EmptyCommand,
}

pub struct HostLease {
    fd: libc::c_int,
    path: PathBuf,
    mode: HostLeaseMode,
}

impl HostLease {
    pub fn acquire(mode: HostLeaseMode) -> Result<Self, HostLeaseError> {
        Self::acquire_path(Path::new(DEFAULT_LOCK_PATH), mode)
    }

    pub fn acquire_path(path: &Path, mode: HostLeaseMode) -> Result<Self, HostLeaseError> {
        let path_str = path.to_str().ok_or_else(|| HostLeaseError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "path is not valid UTF-8"),
        })?;
        let c_path = CString::new(path_str).map_err(|e| HostLeaseError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, e),
        })?;

        // Open or create the lock file with mode 0666.
        // SAFETY: c_path is a valid null-terminated C string.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o666) };
        if fd < 0 {
            return Err(HostLeaseError::Io {
                path: path.to_path_buf(),
                source: io::Error::last_os_error(),
            });
        }

        // Try setting 0666 permissions in case the creator had a restrictive umask.
        // If the file was created by another user, fchmod may return EPERM; ignore it.
        // SAFETY: fd is an open file descriptor.
        unsafe {
            libc::fchmod(fd, 0o666);
        }

        let op = match mode {
            HostLeaseMode::Carrick => libc::LOCK_SH,
            HostLeaseMode::Docker => libc::LOCK_EX,
        };

        let mut waited = false;
        loop {
            // SAFETY: fd is a valid open file descriptor.
            let ret = unsafe { libc::flock(fd, op | libc::LOCK_NB) };
            if ret == 0 {
                break;
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                waited = true;
                eprintln!("host-lease: waiting for {mode} ...");
                break;
            }
            // SAFETY: fd is valid and must be closed on error.
            unsafe { libc::close(fd) };
            return Err(HostLeaseError::Io {
                path: path.to_path_buf(),
                source: err,
            });
        }

        if waited {
            loop {
                // SAFETY: fd is a valid open file descriptor.
                let ret = unsafe { libc::flock(fd, op) };
                if ret == 0 {
                    break;
                }
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                // SAFETY: fd is valid and must be closed on error.
                unsafe { libc::close(fd) };
                return Err(HostLeaseError::Io {
                    path: path.to_path_buf(),
                    source: err,
                });
            }
            eprintln!("host-lease: acquired {mode}");
        }

        Ok(Self {
            fd,
            path: path.to_path_buf(),
            mode,
        })
    }

    pub fn mode(&self) -> HostLeaseMode {
        self.mode
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for HostLease {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: self.fd is a valid file descriptor owned by HostLease.
            unsafe {
                libc::flock(self.fd, libc::LOCK_UN);
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

pub fn run_command(mode: HostLeaseMode, cmd_args: &[OsString]) -> Result<i32, HostLeaseError> {
    if cmd_args.is_empty() {
        return Err(HostLeaseError::EmptyCommand);
    }

    let lease = HostLease::acquire(mode)?;

    let prog = &cmd_args[0];
    let args = &cmd_args[1..];

    let mut command = std::process::Command::new(prog);
    command.args(args);

    let mut child = command.spawn().map_err(|e| HostLeaseError::Spawn {
        cmd: prog.to_string_lossy().to_string(),
        source: e,
    })?;

    let status = child.wait().map_err(HostLeaseError::ChildWait)?;

    let exit_code = extract_exit_code(&status);

    drop(lease);
    Ok(exit_code)
}

pub fn extract_exit_code(status: &ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        code
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(sig) = status.signal() {
                128 + sig
            } else {
                1
            }
        }
        #[cfg(not(unix))]
        {
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn shared_and_shared_coexist() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let lease1 =
            HostLease::acquire_path(path, HostLeaseMode::Carrick).expect("acquire lease 1");
        let lease2 =
            HostLease::acquire_path(path, HostLeaseMode::Carrick).expect("acquire lease 2");

        assert!(lease1.fd >= 0);
        assert!(lease2.fd >= 0);

        drop(lease1);
        drop(lease2);
    }

    #[test]
    fn exclusive_blocks_while_shared_held() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let shared_lease =
            HostLease::acquire_path(path, HostLeaseMode::Carrick).expect("acquire shared lease");

        // Open a second file description to the same file
        let path_str = path.to_str().unwrap();
        let c_path = CString::new(path_str).unwrap();
        // SAFETY: c_path is a valid null-terminated string.
        let fd2 = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
        assert!(fd2 >= 0, "open fd2 failed");

        // Non-blocking exclusive lock attempt must fail with EWOULDBLOCK
        // SAFETY: fd2 is an open file descriptor.
        let ret = unsafe { libc::flock(fd2, libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(ret, -1);
        let err = io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::EWOULDBLOCK));

        // Drop the shared lease, releasing the lock
        drop(shared_lease);

        // Now non-blocking exclusive lock must succeed immediately
        // SAFETY: fd2 is an open file descriptor.
        let ret = unsafe { libc::flock(fd2, libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(ret, 0, "exclusive lock should succeed after shared dropped");

        // SAFETY: fd2 is an open file descriptor.
        unsafe {
            libc::flock(fd2, libc::LOCK_UN);
            libc::close(fd2);
        }
    }

    #[test]
    fn shared_blocks_while_exclusive_held() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let exclusive_lease =
            HostLease::acquire_path(path, HostLeaseMode::Docker).expect("acquire exclusive lease");

        // Open a second file description to the same file
        let path_str = path.to_str().unwrap();
        let c_path = CString::new(path_str).unwrap();
        // SAFETY: c_path is a valid null-terminated string.
        let fd2 = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
        assert!(fd2 >= 0, "open fd2 failed");

        // Non-blocking shared lock attempt must fail with EWOULDBLOCK
        // SAFETY: fd2 is an open file descriptor.
        let ret = unsafe { libc::flock(fd2, libc::LOCK_SH | libc::LOCK_NB) };
        assert_eq!(ret, -1);
        let err = io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::EWOULDBLOCK));

        // Drop the exclusive lease, releasing the lock
        drop(exclusive_lease);

        // Now non-blocking shared lock must succeed immediately
        // SAFETY: fd2 is an open file descriptor.
        let ret = unsafe { libc::flock(fd2, libc::LOCK_SH | libc::LOCK_NB) };
        assert_eq!(ret, 0, "shared lock should succeed after exclusive dropped");

        // SAFETY: fd2 is an open file descriptor.
        unsafe {
            libc::flock(fd2, libc::LOCK_UN);
            libc::close(fd2);
        }
    }
}
