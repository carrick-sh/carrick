use crate::lock_file::OwnedFileLock;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::ffi::{CString, OsString};
use std::fmt;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

pub const DEFAULT_LOCK_PATH: &str = "/tmp/carrick-host-lease.lock";
/// A contended machine may be running a full acceptance gate. Failure, never skip.
pub const HOST_LEASE_WAIT_LIMIT: Duration = Duration::from_secs(60 * 60);
const INHERITED_SOCKET: &str = "CARRICK_HOST_LEASE_SOCKET";
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
    #[error("host-lease cleanup incomplete during {operation}: {source}; run failed")]
    Cleanup {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
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
    // Commands never own this holder. macOS supervisor/guardian custody
    // retains the shared description across either custodian's death.
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

// Send only a scope writer, never the flock description. The aligned control
// storage holds one SCM_RIGHTS record; UnixStream supplies SIGPIPE protection.
fn send_scope_reply(
    mut stream: &UnixStream,
    bytes: &[u8],
    scope: Option<&OwnedFd>,
) -> io::Result<()> {
    let mut control = [0usize; 8];
    let mut vector = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: all pointers below refer to live, aligned storage for this call.
    let sent = unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        if let Some(scope) = scope {
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _) as _;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _) as _;
            libc::CMSG_DATA(header)
                .cast::<libc::c_int>()
                .write_unaligned(scope.as_raw_fd());
        }
        loop {
            let sent = libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL);
            if sent >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break sent;
            }
        }
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    stream.write_all(&bytes[sent as usize..])
}

fn receive_scope_reply(
    stream: &UnixStream,
    bytes: &mut [u8],
    scopes: &mut Vec<OwnedFd>,
) -> io::Result<usize> {
    let mut control = [0usize; 8];
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: the kernel writes bounded data and aligned ancillary records.
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control) as _;
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = libc::MSG_DONTWAIT;
        let count = libc::recvmsg(stream.as_raw_fd(), &mut message, flags);
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let length = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                for offset in 0..length / std::mem::size_of::<libc::c_int>() {
                    let fd = libc::CMSG_DATA(header)
                        .cast::<libc::c_int>()
                        .add(offset)
                        .read_unaligned();
                    scopes.push(OwnedFd::from_raw_fd(fd));
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
        // Own every received fd before rejecting malformed/truncated input.
        if message.msg_flags & libc::MSG_CTRUNC != 0 || scopes.len() > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid lease scope descriptors",
            ));
        }
        for scope in scopes.iter() {
            if libc::fcntl(scope.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(count as usize)
    }
}

fn lease_request(
    socket: &Path,
    delegate: Option<libc::uid_t>,
) -> io::Result<(LeaseIdentity, Option<OwnedFd>)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let mut stream = UnixStream::connect(socket)?;
    let metadata = std::fs::symlink_metadata(socket)?;
    if !metadata.file_type().is_socket()
        || carrick_portable::peer_credentials(stream.as_raw_fd())?.uid != metadata.uid()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "lease server identity mismatch",
        ));
    }
    let mut request = [0; 5];
    if let Some(uid) = delegate {
        request[0] = 1;
        request[1..].copy_from_slice(&uid.to_le_bytes());
    }
    stream.write_all(&request)?;
    read_validation_identity(stream)
}

fn serve_lease_request(
    mut stream: &UnixStream,
    owner: libc::uid_t,
    allowed: &mut std::collections::BTreeSet<libc::uid_t>,
    identity: &[u8],
    scope: Option<&OwnedFd>,
) -> io::Result<()> {
    use std::io::Read;
    let uid = carrick_portable::peer_credentials(stream.as_raw_fd())?.uid;
    if uid != owner && !allowed.contains(&uid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "lease client uid not admitted",
        ));
    }
    stream.set_read_timeout(Some(VALIDATION_LIMIT))?;
    stream.set_write_timeout(Some(VALIDATION_LIMIT))?;
    let mut request = [0; 5];
    stream.read_exact(&mut request)?;
    match request[0] {
        0 if request[1..] == [0; 4] => {}
        1 if uid == owner => {
            allowed.insert(libc::uid_t::from_le_bytes(
                request[1..].try_into().map_err(io::Error::other)?,
            ));
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "lease delegation requires its owner",
            ));
        }
    }
    send_scope_reply(stream, identity, scope)
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
    _custody: OwnedFileLock,
    directory: tempfile::TempDir,
    stopping: Arc<AtomicBool>,
    active: Arc<Mutex<Option<UnixStream>>>,
    server: Option<std::thread::JoinHandle<()>>,
}

impl LeaseHolder {
    fn close_admission(&mut self) {
        if self.server.is_none() {
            return;
        }
        self.stopping.store(true, Ordering::Release);
        if let Some(stream) = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        // Wake blocking accept; joining drops the server-owned scope writer.
        let _ = UnixStream::connect(self.directory.path().join("lease.sock"));
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
        // Direct guards unlock here; supervised macOS custody releases only
        // when the supervisor and guardian have both closed their copies.
        // Unrelated fork copies cannot extend this lease; clients never own it.
    }
}

impl Drop for LeaseHolder {
    fn drop(&mut self) {
        self.close_admission();
    }
}

fn read_validation_identity(stream: UnixStream) -> io::Result<(LeaseIdentity, Option<OwnedFd>)> {
    read_validation_identity_until(&stream, Instant::now() + VALIDATION_LIMIT)
}

fn read_validation_identity_until(
    stream: &UnixStream,
    deadline: Instant,
) -> io::Result<(LeaseIdentity, Option<OwnedFd>)> {
    // Darwin rejects setsockopt after the peer has closed, even with a complete
    // reply queued. Bound reads without changing socket options. One deadline
    // covers the entire reply, including EOF; partial progress cannot extend it.
    let mut bytes = [0; 4097];
    let mut length = 0;
    let mut scopes = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "lease validation expired"))?;
        let mut event = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one owned, live socket descriptor, bounded by the deadline.
        let ready = unsafe {
            libc::poll(
                &mut event,
                1,
                remaining.as_millis().max(1).min(i32::MAX as u128) as i32,
            )
        };
        if ready == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "lease validation expired",
            ));
        }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if event.revents & libc::POLLNVAL != 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        // HUP/ERR may accompany readable final bytes. Receive before deciding
        // whether EOF completes the identity; never discard a queued reply.
        // SAFETY: the live socket and writable buffer tail are valid. Per-call
        // nonblocking I/O prevents a readiness race from blocking past deadline.
        let count = match receive_scope_reply(stream, &mut bytes[length..], &mut scopes) {
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if count == 0 {
            return Ok((serde_json::from_slice(&bytes[..length])?, scopes.pop()));
        }
        length += count;
        if length == bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "lease validation reply exceeds 4096 bytes",
            ));
        }
    }
}

impl HostLease {
    /// Claim an idle host directly, without waiting or inherited admission.
    pub fn try_exclusive(path: &Path) -> Result<Option<Self>, HostLeaseError> {
        match Self::acquire_path_with_wait(path, HostLeaseMode::Gate, Duration::ZERO, None, |_| {
            Ok(false)
        }) {
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
        Self::acquire_path_with_wait(&path, mode, HOST_LEASE_WAIT_LIMIT, None, |duration| {
            std::thread::sleep(duration);
            Ok(false)
        })
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

    #[cfg(target_os = "macos")]
    pub(crate) fn guardian_custody(&mut self) -> io::Result<OwnedFd> {
        let holder = self
            ._holder
            .as_mut()
            .ok_or_else(|| io::Error::other("supervisor must own lease"))?;
        let fd = &mut holder._custody;
        let duplicate = fd.try_clone()?;
        // Neither cooperating holder may explicitly unlock the shared file
        // description: release is the last close after workload cleanup.
        fd.retain_until_last_close();
        Ok(duplicate.into())
    }

    pub(crate) fn acquire_supervised(
        mode: HostLeaseMode,
        scope: &OwnedFd,
        wait: impl FnMut(Duration) -> io::Result<bool>,
    ) -> Result<Self, HostLeaseError> {
        let path = std::env::var_os("CARRICK_HOST_LEASE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOCK_PATH));
        Self::acquire_path_with_wait(
            &path,
            mode,
            HOST_LEASE_WAIT_LIMIT,
            Some(scope.try_clone().map_err(HostLeaseError::ChildWait)?),
            wait,
        )
    }

    fn acquire_path_with_wait(
        path: &Path,
        mode: HostLeaseMode,
        limit: Duration,
        scope: Option<OwnedFd>,
        wait: impl FnMut(Duration) -> io::Result<bool>,
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
        // SAFETY: uniquely owned CLOEXEC descriptor, including error paths.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Self::acquire_fd_with_wait(path, mode, limit, scope, wait, fd)
    }

    fn acquire_fd_with_wait(
        path: &Path,
        mode: HostLeaseMode,
        limit: Duration,
        scope: Option<OwnedFd>,
        mut wait: impl FnMut(Duration) -> io::Result<bool>,
        fd: OwnedFd,
    ) -> Result<Self, HostLeaseError> {
        let op = match mode {
            HostLeaseMode::Carrick => libc::LOCK_SH,
            HostLeaseMode::Docker | HostLeaseMode::Gate => libc::LOCK_EX,
        };

        let start = Instant::now();
        let mut waited = false;
        loop {
            // SAFETY: fd is a valid open file descriptor.
            if unsafe { libc::flock(fd.as_raw_fd(), op | libc::LOCK_NB) } == 0 {
                break;
            }
            let err = io::Error::last_os_error();
            if !matches!(
                err.raw_os_error(),
                Some(libc::EINTR) | Some(libc::EWOULDBLOCK)
            ) {
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
                return Err(HostLeaseError::Timeout {
                    path: path.to_path_buf(),
                    mode,
                    limit,
                });
            }
            let interrupted =
                wait(Duration::from_millis(100).min(limit.saturating_sub(start.elapsed())));
            if !matches!(interrupted, Ok(false)) {
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

        let fd = OwnedFileLock::from_locked(std::fs::File::from(fd));
        Self::serve(path, mode, fd, scope).map_err(|source| HostLeaseError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    fn serve(
        path: &Path,
        mode: HostLeaseMode,
        fd: OwnedFileLock,
        scope: Option<OwnedFd>,
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
        let metadata = fd.metadata()?;
        let (dev, ino) = (metadata.dev(), metadata.ino());
        let identity = serde_json::to_vec(&LeaseIdentity {
            dev,
            ino,
            mode,
            scope: scope.as_ref().map(ScopeIdentity::writer).transpose()?,
        })?;
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopping);
        let active = Arc::new(Mutex::new(None::<UnixStream>));
        let serving = Arc::clone(&active);
        // SAFETY: geteuid has no preconditions; delegation is owner-only.
        let owner = unsafe { libc::geteuid() };
        let server = std::thread::Builder::new()
            .name("host-lease-validation".into())
            .spawn(move || {
                let mut allowed = std::collections::BTreeSet::new();
                for connection in listener.incoming() {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    match connection {
                        Ok(stream) => {
                            {
                                let mut current = serving
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                if stop.load(Ordering::Acquire) {
                                    break;
                                }
                                let Ok(handle) = stream.try_clone() else {
                                    continue;
                                };
                                *current = Some(handle);
                            }
                            let _ = serve_lease_request(
                                &stream,
                                owner,
                                &mut allowed,
                                &identity,
                                scope.as_ref(),
                            );
                            serving
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .take();
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            })?;
        Ok(Self {
            _holder: Some(LeaseHolder {
                _custody: fd,
                directory,
                stopping,
                active,
                server: Some(server),
            }),
            _scope: None,
            socket,
            path: path.to_path_buf(),
            mode,
        })
    }

    /// Stop admitting scope writers while retaining flock through cleanup.
    pub(crate) fn close_admission(&mut self) {
        if let Some(holder) = &mut self._holder {
            holder.close_admission();
        }
    }

    /// Nested commands stay inside the supervisor's workload lifetime. The
    /// scope pipe (never a lock description) also covers fork without exec.
    pub fn configure_command(&self, command: &mut Command) -> io::Result<()> {
        crate::command::sanitize_cargo_package_env(command);
        command
            .env_remove("CARRICK_HOST_LEASE_FD")
            .env_remove("CARRICK_HOST_LEASE_MODE")
            .env_remove("CARRICK_HOST_LEASE_SCOPE_FD")
            .env(INHERITED_SOCKET, &self.socket)
            .env("CARRICK_HOST_LEASE_PATH", &self.path);
        if let Some(scope) = &self._scope {
            let scope = scope.try_clone()?;
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
        let (identity, scope) =
            lease_request(socket, None).map_err(|e| HostLeaseError::Inherited(e.to_string()))?;
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
        match (identity.scope, scope.as_ref()) {
            (Some(expected), Some(writer))
                if ScopeIdentity::writer(writer)
                    .map_err(|e| HostLeaseError::Inherited(e.to_string()))?
                    == expected => {}
            (None, None) => {}
            _ => {
                return Err(HostLeaseError::Inherited(
                    "holder returned the wrong scope writer".into(),
                ));
            }
        }
        Ok(Self {
            _holder: None,
            _scope: scope,
            socket: socket.to_path_buf(),
            path: path.to_path_buf(),
            mode: identity.mode,
        })
    }

    /// The lease this process inherited from an outer runner, if any. Never
    /// takes a fresh lock: without a handoff there is nothing to pass on.
    pub(crate) fn inherited(mode: HostLeaseMode) -> Result<Option<Self>, HostLeaseError> {
        if std::env::var_os(INHERITED_SOCKET).is_none() {
            return Ok(None);
        }
        Self::acquire(mode).map(Some)
    }

    /// Hand this lease to a command that runs as another account (sudo).
    /// The admitted account uid may validate and join the scope; it never
    /// receives the locked description, so its death cannot release or change
    /// the holder's lock, and nested acquires still refuse upgrades.
    pub(crate) fn account_handoff(
        &self,
        uid: libc::uid_t,
        group: libc::gid_t,
    ) -> io::Result<AccountHandoff> {
        use std::os::unix::fs::PermissionsExt;
        if !self.socket.is_absolute() || !self.path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "account lease handoff needs absolute socket and lock paths",
            ));
        }
        let directory = self.socket.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "lease socket has no directory")
        })?;
        // The socket owner alone can admit another uid. Peer credentials,
        // not group membership or a caller-supplied uid, authorize requests.
        lease_request(&self.socket, Some(uid))?;
        // Group traverse and connect only; the directory stays unlistable and
        // closed to every other account.
        for (path, mode) in [(directory, 0o710), (self.socket.as_path(), 0o660)] {
            std::os::unix::fs::chown(path, None, Some(group))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
        Ok(AccountHandoff {
            socket: self.socket.clone(),
            path: self.path.clone(),
        })
    }

    pub fn mode(&self) -> HostLeaseMode {
        self.mode
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Only the socket and lock path cross the cleared account environment.
/// Scope custody is recovered from the authenticated socket after exec.
pub(crate) struct AccountHandoff {
    socket: PathBuf,
    path: PathBuf,
}

impl AccountHandoff {
    pub(crate) fn assignments(&self) -> Vec<OsString> {
        [
            (INHERITED_SOCKET, &self.socket),
            ("CARRICK_HOST_LEASE_PATH", &self.path),
        ]
        .into_iter()
        .map(|(key, path)| {
            let mut assignment = OsString::from(key);
            assignment.push("=");
            assignment.push(path);
            assignment
        })
        .collect()
    }

    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self {
            socket: "/tmp/carrick-lease-fixture/lease.sock".into(),
            path: DEFAULT_LOCK_PATH.into(),
        }
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

    #[test]
    fn validation_reads_identity_after_peer_closed() {
        // Run the Linux syscall model in its own process. No process-global
        // injection or serialization affects the ordinary parallel test suite.
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "host_lease::tests::closed_validation_peer_fixture",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "closed-peer validation failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    #[ignore = "isolated closed-peer fixture invoked by its parent regression"]
    fn closed_validation_peer_fixture() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let reply = LeaseIdentity {
            dev: 1,
            ino: 2,
            mode: HostLeaseMode::Gate,
            scope: None,
        };
        server
            .write_all(&serde_json::to_vec(&reply).unwrap())
            .unwrap();
        drop(server); // Happens before ANY client read or socket configuration.
        #[cfg(target_os = "linux")]
        reject_closed_peer_timeout_option(client.as_raw_fd());
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert_eq!(
            client
                .set_read_timeout(Some(VALIDATION_LIMIT))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL),
            "Darwin closed-peer failure must be active before testing validation",
        );
        let (identity, scope) = read_validation_identity(client).unwrap();
        assert!(scope.is_none());
        assert_eq!(identity.dev, reply.dev);
        assert_eq!(identity.ino, reply.ino);
        assert_eq!(identity.mode, HostLeaseMode::Gate);
        assert!(identity.scope.is_none());
    }

    #[cfg(target_os = "linux")]
    fn reject_closed_peer_timeout_option(fd: libc::c_int) {
        // Darwin's sosetoptlock rejects options after AF_UNIX peer teardown.
        // Linux permits SO_RCVTIMEO then, so model ONLY that operation on this
        // already-disconnected fd. This is a syscall witness, not a sandbox.
        let arg_low = std::mem::offset_of!(libc::seccomp_data, args) as u32
            + if cfg!(target_endian = "big") { 4 } else { 0 };
        let mut filter = [
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
            (
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                0,
                5,
                libc::SYS_setsockopt as u32,
            ),
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, arg_low),
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 3, fd as u32),
            (
                libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                0,
                0,
                arg_low + 16,
            ),
            (
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                0,
                1,
                libc::SO_RCVTIMEO as u32,
            ),
            (
                libc::BPF_RET | libc::BPF_K,
                0,
                0,
                libc::SECCOMP_RET_ERRNO | libc::EINVAL as u32,
            ),
            (libc::BPF_RET | libc::BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW),
        ]
        .map(|(code, jt, jf, k)| libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        });
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: this isolated test thread owns the filter storage; prctl
        // copies it synchronously. All other syscalls remain permitted.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                0
            );
        }
    }

    #[test]
    fn validation_requires_eof_within_one_deadline() {
        let (client, mut server) = UnixStream::pair().unwrap();
        server
            .write_all(br#"{"dev":1,"ino":2,"mode":"gate","scope":null}"#)
            .unwrap();
        // Keep the peer open with an otherwise complete identity. Validation
        // must await EOF within the supplied budget, not accept partial framing.
        let error =
            read_validation_identity_until(&client, Instant::now() + Duration::from_millis(10))
                .err()
                .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn validation_rejects_incomplete_and_oversized_closed_replies() {
        for reply in [b"{".to_vec(), vec![b' '; 4097]] {
            let (client, mut server) = UnixStream::pair().unwrap();
            server.write_all(&reply).unwrap();
            drop(server);
            let error = read_validation_identity(client).err().unwrap();
            if reply.len() > 4096 {
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(error.to_string().contains("exceeds 4096 bytes"));
            } else {
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            }
        }
    }

    #[test]
    fn unrelated_fork_exec_cannot_extend_host_lease() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let lease = HostLease::acquire_path(file.path(), HostLeaseMode::Gate).unwrap();
        let immediate = crate::lock_file::tests::with_unrelated_fork_exec(
            || {
                drop(lease);
                HostLease::try_exclusive(file.path()).unwrap().is_some()
            },
            || assert!(HostLease::try_exclusive(file.path()).unwrap().is_some()),
        );
        assert!(
            immediate,
            "unrelated pre-exec child retained dropped host lease despite CLOEXEC"
        );
    }

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
                HostLease::acquire_path_with_limit(temp.path(), contender, Duration::ZERO).unwrap();
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
        HostLease::acquire_path_with_limit(temp.path(), HostLeaseMode::Gate, Duration::ZERO)
            .unwrap();
        assert!(
            HostLease::inherit(temp.path(), HostLeaseMode::Carrick, &nested.socket).is_err(),
            "stale capability must fail closed"
        );
    }

    #[test]
    fn account_handoff_lets_a_stripped_process_reuse_the_holders_lease() {
        for mode in [HostLeaseMode::Carrick, HostLeaseMode::Gate] {
            account_handoff_reuses_mode(mode);
        }
    }

    fn account_handoff_reuses_mode(mode: HostLeaseMode) {
        // The dispatch loop inherits a supervised lease; its agent runs as
        // another account through sudo, which resets env and closes fds >= 3.
        let lock = NamedTempFile::new().unwrap();
        let (_lifetime, writer) = std::io::pipe().unwrap();
        let writer: OwnedFd = writer.into();
        let holder = HostLease::acquire_path_with_wait(
            lock.path(),
            mode,
            Duration::ZERO,
            Some(writer.try_clone().unwrap()),
            |_| Ok(false),
        )
        .unwrap();
        let inherited = HostLease {
            _holder: None,
            _scope: Some(writer),
            socket: holder.socket.clone(),
            path: lock.path().to_path_buf(),
            mode,
        };
        // SAFETY: getgid has no preconditions.
        let handoff = inherited
            .account_handoff(unsafe { libc::geteuid() }, unsafe { libc::getgid() })
            .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(holder.socket.parent().unwrap()), 0o710);
            assert_eq!(mode(&holder.socket), 0o660);
        }
        let elsewhere = tempfile::tempdir().unwrap();
        let mut account = Command::new("/usr/bin/env");
        account
            .arg("-i")
            .args(handoff.assignments())
            .arg(format!("EXPECTED_HANDOFF_MODE={mode}"))
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "host_lease::tests::account_handoff_child_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .current_dir(elsewhere.path())
            .stdin(std::process::Stdio::null());
        // SAFETY: async-signal-safe close only; models sudo's closefrom(3).
        unsafe {
            account.pre_exec(|| {
                for fd in 3..1024 {
                    libc::close(fd);
                }
                Ok(())
            });
        }
        let output = account.output().unwrap();
        assert!(
            output.status.success(),
            "account-side nested acquire failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        // The child's exit never released or changed the holder's lock.
        assert!(matches!(
            HostLease::acquire_path_with_limit(lock.path(), HostLeaseMode::Gate, Duration::ZERO),
            Err(HostLeaseError::Timeout { .. })
        ));
        if mode == HostLeaseMode::Gate {
            assert!(matches!(
                HostLease::acquire_path_with_limit(
                    lock.path(),
                    HostLeaseMode::Carrick,
                    Duration::ZERO
                ),
                Err(HostLeaseError::Timeout { .. })
            ));
        }
        drop(inherited);
        drop(holder);
    }

    #[test]
    #[ignore = "account-side fixture invoked by its parent handoff regression"]
    fn account_handoff_child_fixture() {
        assert!(
            std::env::var_os(INHERITED_SOCKET).is_some(),
            "no lease handoff reached the account"
        );
        // Model tool runners close inherited descriptors before spawning a tool.
        unsafe {
            libc::close(3);
        }
        let lease = HostLease::acquire(HostLeaseMode::Carrick).unwrap();
        assert!(lease._holder.is_none(), "took a lock instead of inheriting");
        assert!(lease._scope.is_some(), "scope writer did not cross");
        let expected = std::env::var("EXPECTED_HANDOFF_MODE").unwrap();
        assert_eq!(lease.mode().to_string(), expected);
        if expected == "gate" {
            let nested = HostLease::acquire(HostLeaseMode::Gate).unwrap();
            assert_eq!(nested.mode(), HostLeaseMode::Gate);
            assert_eq!(nested.path(), lease.path());
            assert!(nested._holder.is_none(), "nested gate reacquired the lock");
            assert!(nested._scope.is_some());
        } else {
            assert!(
                HostLease::acquire(HostLeaseMode::Gate).is_err(),
                "nested acquire must not upgrade"
            );
        }
        // stdin is back to /dev/null, not the scope pipe.
        // SAFETY: fstat on stdin into owned storage.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        assert_eq!(unsafe { libc::fstat(0, &mut stat) }, 0);
        assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFCHR);
    }

    #[test]
    fn socket_refuses_unadmitted_uid_and_forged_delegation() {
        // Real peer credentials come from the connected socket, never the
        // request's uid. Exercise the exact production request handler.
        let uid = unsafe { libc::geteuid() };
        let owner = uid.checked_add(1).unwrap();
        for admitted in [false, true] {
            let (mut client, server) = UnixStream::pair().unwrap();
            let mut request = [1; 5];
            request[1..].copy_from_slice(&owner.to_le_bytes());
            client.write_all(&request).unwrap();
            let mut allowed = std::collections::BTreeSet::new();
            if admitted {
                allowed.insert(uid);
            }
            let error = serve_lease_request(&server, owner, &mut allowed, b"{}", None).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(!allowed.contains(&owner));
        }
    }

    #[test]
    fn closing_socket_admission_releases_server_scope_but_keeps_flock() {
        use std::io::Read;
        let lock = NamedTempFile::new().unwrap();
        let (mut reader, writer) = std::io::pipe().unwrap();
        let mut holder = HostLease::acquire_path_with_wait(
            lock.path(),
            HostLeaseMode::Gate,
            Duration::ZERO,
            Some(writer.into()),
            |_| Ok(false),
        )
        .unwrap();
        // An idle authenticated connection cannot delay cancellation.
        let _idle = UnixStream::connect(&holder.socket).unwrap();
        holder.close_admission();
        let mut event = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut event, 1, 1000) }, 1);
        assert_eq!(
            reader.read(&mut [0]).unwrap(),
            0,
            "server kept a scope writer"
        );
        assert!(matches!(
            HostLease::acquire_path_with_limit(lock.path(), HostLeaseMode::Carrick, Duration::ZERO),
            Err(HostLeaseError::Timeout { .. })
        ));
        assert!(HostLease::inherit(lock.path(), HostLeaseMode::Carrick, &holder.socket).is_err());
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

        // Release is immediate even if an unrelated fork has not executed yet.
        let _exclusive =
            HostLease::acquire_path_with_limit(path, HostLeaseMode::Docker, Duration::ZERO)
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

        // Release is immediate even if an unrelated fork has not executed yet.
        let _shared =
            HostLease::acquire_path_with_limit(path, HostLeaseMode::Carrick, Duration::ZERO)
                .expect("shared lock should succeed after exclusive dropped");

        // SAFETY: fd2 is an open file descriptor.
        unsafe {
            libc::flock(fd2, libc::LOCK_UN);
            libc::close(fd2);
        }
    }
}
