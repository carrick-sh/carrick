use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::ffi::{CString, OsString};
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

pub const DEFAULT_LOCK_PATH: &str = "/tmp/carrick-host-lease.lock";
/// A contended machine may be running a full acceptance gate. Failure, never skip.
pub const HOST_LEASE_WAIT_LIMIT: Duration = Duration::from_secs(60 * 60);
const INHERITED_SOCKET: &str = "CARRICK_HOST_LEASE_SOCKET";
pub(crate) const SCOPE_FD: &str = "CARRICK_HOST_LEASE_SCOPE_FD";
const VALIDATION_LIMIT: Duration = Duration::from_secs(5);

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostLeaseMode {
    Carrick,
    Docker,
    Gate,
}

impl fmt::Display for HostLeaseMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Carrick => write!(f, "carrick"),
            Self::Docker => write!(f, "docker"),
            Self::Gate => write!(f, "gate"),
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
    #[error(
        "host-lease: failed waiting for {mode} at '{path}' after {limit:?} (HOST_LEASE_WAIT_LIMIT); no command was run"
    )]
    Timeout {
        path: PathBuf,
        mode: HostLeaseMode,
        limit: Duration,
    },
    #[error("invalid inherited host lease: {0}")]
    Inherited(String),
    #[error("host load check failed: {0}")]
    Load(#[from] crate::host_load::HostLoadError),
}

pub struct HostLease {
    // Production workloads run below lease_supervisor, which alone owns this
    // holder and retains it through cancellation, descendant exit and reaping.
    _holder: Option<LeaseHolder>,
    _scope: Option<OwnedFd>,
    socket: PathBuf,
    path: PathBuf,
    mode: HostLeaseMode,
}

#[derive(Serialize, Deserialize)]
struct LeaseIdentity {
    dev: u64,
    ino: u64,
    mode: HostLeaseMode,
    scope: Option<ScopeIdentity>,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ScopeIdentity {
    dev: u64,
    ino: u64,
}

impl ScopeIdentity {
    pub(crate) fn writer(fd: &OwnedFd) -> io::Result<Self> {
        // SAFETY: the caller owns this scope descriptor; verify its direction.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFIFO || flags & libc::O_ACCMODE != libc::O_WRONLY
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "lease scope is not a pipe writer",
            ));
        }
        Ok(Self {
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
        })
    }
}

struct LeaseHolder {
    _fd: std::fs::File,
    directory: tempfile::TempDir,
    stopping: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
}

impl Drop for LeaseHolder {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        // Wake blocking accept; no polling and no lifetime granted to clients.
        let _ = UnixStream::connect(self.directory.path().join("lease.sock"));
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
        // The owned fd closes after the server stops. Clients never owned it.
    }
}

impl HostLease {
    /// Claim an idle host directly, without waiting or inherited admission.
    pub fn try_exclusive(path: &Path) -> Result<Option<Self>, HostLeaseError> {
        match Self::acquire_path_with_limit(path, HostLeaseMode::Gate, Duration::ZERO) {
            Ok(lease) => Ok(Some(lease)),
            Err(HostLeaseError::Timeout { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn acquire(mode: HostLeaseMode) -> Result<Self, HostLeaseError> {
        let path = std::env::var_os("CARRICK_HOST_LEASE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOCK_PATH));
        if let Some(socket) = std::env::var_os(INHERITED_SOCKET) {
            return Self::inherit(&path, mode, Path::new(&socket));
        }
        if std::env::var_os("CARRICK_HOST_LEASE_FD").is_some() {
            return Err(HostLeaseError::Inherited(
                "obsolete fd handoff; restart the outer lease runner".into(),
            ));
        }
        Self::acquire_path(&path, mode)
    }

    pub fn acquire_path(path: &Path, mode: HostLeaseMode) -> Result<Self, HostLeaseError> {
        Self::acquire_path_with_limit(path, mode, HOST_LEASE_WAIT_LIMIT)
    }

    fn acquire_path_with_limit(
        path: &Path,
        mode: HostLeaseMode,
        limit: Duration,
    ) -> Result<Self, HostLeaseError> {
        Self::acquire_path_with_wait(path, mode, limit, None, |duration| {
            std::thread::sleep(duration);
            Ok(false)
        })
    }

    pub(crate) fn acquire_supervised(
        mode: HostLeaseMode,
        scope: ScopeIdentity,
        wait: impl FnMut(Duration) -> io::Result<bool>,
    ) -> Result<Self, HostLeaseError> {
        let path = std::env::var_os("CARRICK_HOST_LEASE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOCK_PATH));
        Self::acquire_path_with_wait(&path, mode, HOST_LEASE_WAIT_LIMIT, Some(scope), wait)
    }

    fn acquire_path_with_wait(
        path: &Path,
        mode: HostLeaseMode,
        limit: Duration,
        scope: Option<ScopeIdentity>,
        mut wait: impl FnMut(Duration) -> io::Result<bool>,
    ) -> Result<Self, HostLeaseError> {
        let path_str = path.to_str().ok_or_else(|| HostLeaseError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "path is not valid UTF-8"),
        })?;
        let c_path = CString::new(path_str).map_err(|e| HostLeaseError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, e),
        })?;

        // Open or create the lock file with mode 0666; inherit only explicitly.
        // SAFETY: c_path is a valid null-terminated C string.
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
                0o666,
            )
        };
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
            HostLeaseMode::Docker | HostLeaseMode::Gate => libc::LOCK_EX,
        };

        let start = Instant::now();
        let mut waited = false;
        loop {
            // SAFETY: fd is a valid open file descriptor.
            if unsafe { libc::flock(fd, op | libc::LOCK_NB) } == 0 {
                break;
            }
            let err = io::Error::last_os_error();
            if !matches!(
                err.raw_os_error(),
                Some(libc::EINTR) | Some(libc::EWOULDBLOCK)
            ) {
                // SAFETY: close our owned descriptor on error.
                unsafe { libc::close(fd) };
                return Err(HostLeaseError::Io {
                    path: path.to_path_buf(),
                    source: err,
                });
            }
            if !waited {
                eprintln!(
                    "host-lease: waiting for {mode} at {} (HOST_LEASE_WAIT_LIMIT: {limit:?})",
                    path.display()
                );
                waited = true;
            }
            if start.elapsed() >= limit {
                // SAFETY: close our owned descriptor on timeout.
                unsafe { libc::close(fd) };
                return Err(HostLeaseError::Timeout {
                    path: path.to_path_buf(),
                    mode,
                    limit,
                });
            }
            let interrupted =
                wait(Duration::from_millis(100).min(limit.saturating_sub(start.elapsed())));
            if !matches!(interrupted, Ok(false)) {
                // SAFETY: uniquely owned lock attempt, no work admitted yet.
                unsafe {
                    libc::close(fd);
                }
                return Err(HostLeaseError::Io {
                    path: path.to_path_buf(),
                    source: match interrupted {
                        Err(error) => error,
                        _ => io::Error::new(
                            io::ErrorKind::Interrupted,
                            "lease runner died before admission",
                        ),
                    },
                });
            }
        }
        eprintln!("host-lease: acquired {mode} at {}", path.display());

        // SAFETY: fd is uniquely owned after successful acquisition.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Self::serve(path, mode, fd, scope).map_err(|source| HostLeaseError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    fn serve(
        path: &Path,
        mode: HostLeaseMode,
        fd: OwnedFd,
        scope: Option<ScopeIdentity>,
    ) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        // Keep AF_UNIX names short even when the checkout/TMPDIR is long.
        // TempDir creates a private 0700 directory; its random path is the
        // validation capability. It contains no transferable lock descriptor.
        let directory = tempfile::Builder::new()
            .prefix("carrick-lease-")
            .tempdir_in("/tmp")?;
        let socket = directory.path().join("lease.sock");
        let listener = UnixListener::bind(&socket)?;
        let fd = std::fs::File::from(fd);
        let metadata = fd.metadata()?;
        let identity = serde_json::to_vec(&LeaseIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode,
            scope,
        })?;
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopping);
        let server = std::thread::Builder::new()
            .name("host-lease-validation".into())
            .spawn(move || {
                for connection in listener.incoming() {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    match connection {
                        Ok(mut stream) => {
                            if stream.set_write_timeout(Some(VALIDATION_LIMIT)).is_ok() {
                                let _ = stream.write_all(&identity);
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            })?;
        Ok(Self {
            _holder: Some(LeaseHolder {
                _fd: fd,
                directory,
                stopping,
                server: Some(server),
            }),
            _scope: None,
            socket,
            path: path.to_path_buf(),
            mode,
        })
    }

    /// Nested commands stay inside the supervisor's workload lifetime. The
    /// scope pipe (never a lock description) also covers fork without exec.
    pub fn configure_command(&self, command: &mut Command) -> io::Result<()> {
        command
            .env_remove("CARRICK_HOST_LEASE_FD")
            .env_remove("CARRICK_HOST_LEASE_MODE")
            .env(INHERITED_SOCKET, &self.socket)
            .env("CARRICK_HOST_LEASE_PATH", &self.path);
        if let Some(scope) = &self._scope {
            let scope = scope.try_clone()?;
            command.env(SCOPE_FD, scope.as_raw_fd().to_string());
            // SAFETY: explicit scope-pipe handoff, only async-signal-safe fcntl.
            unsafe {
                command.pre_exec(move || {
                    if libc::fcntl(scope.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        Ok(())
    }

    fn inherit(
        path: &Path,
        requested: HostLeaseMode,
        socket: &Path,
    ) -> Result<Self, HostLeaseError> {
        use std::os::unix::fs::MetadataExt;
        let validate = || -> io::Result<LeaseIdentity> {
            let stream = UnixStream::connect(socket)?;
            stream.set_read_timeout(Some(VALIDATION_LIMIT))?;
            let mut bytes = Vec::new();
            stream.take(4096).read_to_end(&mut bytes)?;
            Ok(serde_json::from_slice(&bytes)?)
        };
        let identity = validate().map_err(|e| HostLeaseError::Inherited(e.to_string()))?;
        if identity.mode != requested && identity.mode != HostLeaseMode::Gate {
            return Err(HostLeaseError::Inherited(format!(
                "cannot nest {requested} under {}; no lock upgrades",
                identity.mode
            )));
        }
        let expected =
            std::fs::metadata(path).map_err(|e| HostLeaseError::Inherited(e.to_string()))?;
        if identity.dev != expected.dev() || identity.ino != expected.ino() {
            return Err(HostLeaseError::Inherited(
                "holder does not lease the configured lock file".into(),
            ));
        }
        let scope = if let Some(expected_scope) = identity.scope {
            let duplicate_scope = || -> io::Result<OwnedFd> {
                let fd: libc::c_int = std::env::var(SCOPE_FD)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
                    .parse()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                // SAFETY: duplicate only an inherited descriptor; the owned
                // duplicate pins the identity while authenticating its scope.
                let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
                if duplicate < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: newly returned, uniquely owned duplicate scope writer.
                let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
                if ScopeIdentity::writer(&duplicate)? != expected_scope {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "descriptor is not this lease's scope",
                    ));
                }
                Ok(duplicate)
            };
            Some(duplicate_scope().map_err(|e| HostLeaseError::Inherited(e.to_string()))?)
        } else {
            None
        };
        Ok(Self {
            _holder: None,
            _scope: scope,
            socket: socket.to_path_buf(),
            path: path.to_path_buf(),
            mode: identity.mode,
        })
    }

    pub fn mode(&self) -> HostLeaseMode {
        self.mode
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn run_command(
    mode: HostLeaseMode,
    check_load: bool,
    cmd_args: &[OsString],
) -> Result<i32, HostLeaseError> {
    if cmd_args.is_empty() {
        return Err(HostLeaseError::EmptyCommand);
    }
    if std::env::var_os("CARRICK_HOST_LEASE_FD").is_some() {
        return Err(HostLeaseError::Inherited(
            "obsolete fd handoff; restart the outer lease runner".into(),
        ));
    }

    if check_load {
        crate::host_load::check()?;
    }
    if std::env::var_os(INHERITED_SOCKET).is_none() {
        return crate::lease_supervisor::launch(mode, check_load, cmd_args);
    }
    let lease = HostLease::acquire(mode)?;
    if check_load {
        crate::host_load::check()?;
    }

    let prog = &cmd_args[0];
    let args = &cmd_args[1..];

    let mut command = std::process::Command::new(prog);
    command.args(args);
    lease
        .configure_command(&mut command)
        .map_err(|source| HostLeaseError::Io {
            path: lease.path().to_path_buf(),
            source,
        })?;

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

    // An unrelated parallel fork can briefly retain even CLOEXEC descriptions
    // until it execs. Exclusion is immediate; release waits for that exec boundary.
    const TEST_LEASE_RELEASE_LIMIT: Duration = Duration::from_secs(30);

    #[test]
    fn gate_and_docker_exclude_all_other_modes() {
        for holder in [
            HostLeaseMode::Gate,
            HostLeaseMode::Docker,
            HostLeaseMode::Carrick,
        ] {
            for contender in [
                HostLeaseMode::Gate,
                HostLeaseMode::Docker,
                HostLeaseMode::Carrick,
            ] {
                if holder == HostLeaseMode::Carrick && contender == HostLeaseMode::Carrick {
                    continue;
                }
                let temp = NamedTempFile::new().unwrap();
                let held = HostLease::acquire_path(temp.path(), holder).unwrap();
                let blocked =
                    HostLease::acquire_path_with_limit(temp.path(), contender, Duration::ZERO);
                assert!(
                    matches!(blocked, Err(HostLeaseError::Timeout { .. })),
                    "{holder} must exclude {contender}"
                );
                drop(held);
                HostLease::acquire_path_with_limit(
                    temp.path(),
                    contender,
                    TEST_LEASE_RELEASE_LIMIT,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn nested_validation_never_owns_or_downgrades_gate() {
        let temp = NamedTempFile::new().unwrap();
        let gate = HostLease::acquire_path(temp.path(), HostLeaseMode::Gate).unwrap();
        let nested = HostLease::inherit(temp.path(), HostLeaseMode::Carrick, &gate.socket).unwrap();
        assert_eq!(nested.mode(), HostLeaseMode::Gate);
        assert!(nested._holder.is_none());
        assert!(matches!(
            HostLease::acquire_path_with_limit(temp.path(), HostLeaseMode::Carrick, Duration::ZERO),
            Err(HostLeaseError::Timeout { .. })
        ));
        drop(gate);
        HostLease::acquire_path_with_limit(
            temp.path(),
            HostLeaseMode::Gate,
            TEST_LEASE_RELEASE_LIMIT,
        )
        .unwrap();
        assert!(
            HostLease::inherit(temp.path(), HostLeaseMode::Carrick, &nested.socket).is_err(),
            "stale capability must fail closed"
        );
    }

    #[test]
    fn nested_validation_rejects_upgrades_wrong_path_and_stale_socket() {
        let temp = NamedTempFile::new().unwrap();
        let other = NamedTempFile::new().unwrap();
        let shared = HostLease::acquire_path(temp.path(), HostLeaseMode::Carrick).unwrap();
        assert!(HostLease::inherit(temp.path(), HostLeaseMode::Gate, &shared.socket).is_err());
        assert!(HostLease::inherit(other.path(), HostLeaseMode::Carrick, &shared.socket).is_err());
        assert!(HostLease::inherit(temp.path(), HostLeaseMode::Carrick, other.path()).is_err());
    }

    #[test]
    fn shared_and_shared_coexist() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let lease1 =
            HostLease::acquire_path(path, HostLeaseMode::Carrick).expect("acquire lease 1");
        let lease2 =
            HostLease::acquire_path(path, HostLeaseMode::Carrick).expect("acquire lease 2");

        assert!(lease1._holder.is_some());
        assert!(lease2._holder.is_some());

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
        let fd2 = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        assert!(fd2 >= 0, "open fd2 failed");

        // Non-blocking exclusive lock attempt must fail with EWOULDBLOCK
        // SAFETY: fd2 is an open file descriptor.
        let ret = unsafe { libc::flock(fd2, libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(ret, -1);
        let err = io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::EWOULDBLOCK));

        // Drop the shared lease, releasing the lock
        drop(shared_lease);

        // Release can cross a concurrent fork's exec boundary.
        let _exclusive = HostLease::acquire_path_with_limit(
            path,
            HostLeaseMode::Docker,
            TEST_LEASE_RELEASE_LIMIT,
        )
        .expect("exclusive lock should succeed after shared dropped");

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
        let fd2 = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        assert!(fd2 >= 0, "open fd2 failed");

        // Non-blocking shared lock attempt must fail with EWOULDBLOCK
        // SAFETY: fd2 is an open file descriptor.
        let ret = unsafe { libc::flock(fd2, libc::LOCK_SH | libc::LOCK_NB) };
        assert_eq!(ret, -1);
        let err = io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::EWOULDBLOCK));

        // Drop the exclusive lease, releasing the lock
        drop(exclusive_lease);

        // Release can cross a concurrent fork's exec boundary.
        let _shared = HostLease::acquire_path_with_limit(
            path,
            HostLeaseMode::Carrick,
            TEST_LEASE_RELEASE_LIMIT,
        )
        .expect("shared lock should succeed after exclusive dropped");

        // SAFETY: fd2 is an open file descriptor.
        unsafe {
            libc::flock(fd2, libc::LOCK_UN);
            libc::close(fd2);
        }
    }
}
