use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::ffi::{CString, OsString};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};
use thiserror::Error;

pub const DEFAULT_LOCK_PATH: &str = "/tmp/carrick-host-lease.lock";
/// A contended machine may be running a full acceptance gate. Failure, never skip.
pub const HOST_LEASE_WAIT_LIMIT: Duration = Duration::from_secs(60 * 60);
const INHERITED_FD: &str = "CARRICK_HOST_LEASE_FD";
const INHERITED_MODE: &str = "CARRICK_HOST_LEASE_MODE";

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
    fd: libc::c_int,
    path: PathBuf,
    mode: HostLeaseMode,
}

impl HostLease {
    pub fn acquire(mode: HostLeaseMode) -> Result<Self, HostLeaseError> {
        let path = std::env::var_os("CARRICK_HOST_LEASE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOCK_PATH));
        if let Some(fd) = std::env::var_os(INHERITED_FD) {
            return Self::inherit(
                &path,
                mode,
                &fd.to_string_lossy(),
                &std::env::var(INHERITED_MODE).unwrap_or_default(),
            );
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
            std::thread::sleep(
                Duration::from_millis(100).min(limit.saturating_sub(start.elapsed())),
            );
        }
        eprintln!("host-lease: acquired {mode} at {}", path.display());

        Ok(Self {
            fd,
            path: path.to_path_buf(),
            mode,
        })
    }

    /// Descendants reuse the same open file description: never acquire a
    /// second shared lock under an exclusive gate, or downgrade the gate lock.
    pub fn configure_command(&self, command: &mut Command) -> io::Result<()> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::process::CommandExt;
        // Give the command its own lifetime authority, even if this handle is
        // dropped before spawn. CLOEXEC prevents leaks to unrelated children.
        // SAFETY: fcntl duplicates our live owned descriptor.
        let copy = unsafe { libc::fcntl(self.fd, libc::F_DUPFD_CLOEXEC, 3) };
        if copy < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: copy is a new owned descriptor.
        let inherited = unsafe { std::fs::File::from_raw_fd(copy) };
        command
            .env(INHERITED_FD, inherited.as_raw_fd().to_string())
            .env(INHERITED_MODE, self.mode.to_string())
            .env("CARRICK_HOST_LEASE_PATH", &self.path);
        // SAFETY: the child uses only async-signal-safe fcntl calls after fork.
        // Only this command inherits the lease, never unrelated subprocesses.
        unsafe {
            command.pre_exec(move || {
                let fd = inherited.as_raw_fd();
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }

    fn inherit(
        path: &Path,
        requested: HostLeaseMode,
        fd: &str,
        mode: &str,
    ) -> Result<Self, HostLeaseError> {
        use std::os::unix::fs::MetadataExt;
        let mode = match mode {
            "carrick" => HostLeaseMode::Carrick,
            "docker" => HostLeaseMode::Docker,
            "gate" => HostLeaseMode::Gate,
            _ => return Err(HostLeaseError::Inherited("missing or invalid mode".into())),
        };
        if mode != requested && mode != HostLeaseMode::Gate {
            return Err(HostLeaseError::Inherited(format!(
                "cannot nest {requested} under {mode}; no lock upgrades"
            )));
        }
        let fd: libc::c_int = fd
            .parse()
            .map_err(|_| HostLeaseError::Inherited("invalid descriptor".into()))?;
        if fd < 3 {
            return Err(HostLeaseError::Inherited(
                "descriptor must not be stdin/stdout/stderr".into(),
            ));
        }
        // SAFETY: fcntl validates the descriptor and returns a new owned fd.
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if copy < 0 {
            return Err(HostLeaseError::Inherited(
                io::Error::last_os_error().to_string(),
            ));
        }
        // SAFETY: copy is newly owned; File closes it on every error path.
        let file = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(copy) };
        let actual = file
            .metadata()
            .map_err(|e| HostLeaseError::Inherited(e.to_string()))?;
        let expected =
            std::fs::metadata(path).map_err(|e| HostLeaseError::Inherited(e.to_string()))?;
        if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
            return Err(HostLeaseError::Inherited(
                "descriptor does not name the configured lock file".into(),
            ));
        }
        // Check that the inode is actually leased, without touching the inherited
        // description (flock on that description could downgrade its exclusive lock).
        let probe =
            std::fs::File::open(path).map_err(|e| HostLeaseError::Inherited(e.to_string()))?;
        use std::os::fd::{AsRawFd, IntoRawFd};
        // SAFETY: probe owns a valid fd; LOCK_NB cannot wait.
        if unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Err(HostLeaseError::Inherited(
                "descriptor has no active lease".into(),
            ));
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(HostLeaseError::Inherited(
                "cannot verify active lease".into(),
            ));
        }
        // Adoption ends the exec handoff. The original descriptor is also
        // still open in this process; a CLOEXEC duplicate alone would leave it
        // leaking into every unrelated command spawned after adoption.
        // SAFETY: fd was validated above and still names the incoming lease.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        // SAFETY: descriptor flags are process-local, not shared with the parent.
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(HostLeaseError::Inherited(
                io::Error::last_os_error().to_string(),
            ));
        }
        Ok(Self {
            fd: file.into_raw_fd(),
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
            // Closing releases only our reference. LOCK_UN would also unlock
            // surviving descendants that share the same open description.
            // SAFETY: self.fd is a valid file descriptor owned by HostLease.
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
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

    if check_load {
        crate::host_load::check()?;
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

    // Run only in a dedicated subprocess, where a handed-off descriptor is
    // genuinely non-CLOEXEC at entry and no test mutates another test's state.
    #[test]
    #[ignore = "subprocess fixture for unrelated-child descriptor regression"]
    fn inherited_lease_child_fixture() {
        use std::io::Read;
        use std::os::fd::FromRawFd;
        struct ChildCleanup(std::process::Child);
        impl Drop for ChildCleanup {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let fresh = std::env::var("CARRICK_LEASE_FIXTURE_FRESH").as_deref() == Ok("1");
        let lease = HostLease::acquire(HostLeaseMode::Gate).unwrap();
        let incoming = if fresh {
            None
        } else {
            let fd = std::env::var(INHERITED_FD).unwrap().parse().unwrap();
            // SAFETY: this fixture owns the original descriptor handed to it
            // at exec; acquire owns a separate duplicate, not this descriptor.
            Some(unsafe { std::fs::File::from_raw_fd(fd) })
        };
        let mut child = ChildCleanup(
            Command::new("/bin/sleep")
                .arg("60")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let path = lease.path().to_path_buf();
        drop(lease);
        drop(incoming);
        assert!(child.0.try_wait().unwrap().is_none());
        if fresh {
            HostLease::acquire_path_with_limit(&path, HostLeaseMode::Gate, Duration::ZERO)
                .expect("unrelated live child must not retain fresh lease");
        } else {
            std::fs::write(
                std::env::var_os("CARRICK_LEASE_CHILD_PID_FILE").unwrap(),
                child.0.id().to_string(),
            )
            .unwrap();
            // The parent checks release while sleep is alive, then closes this
            // pipe. Keep the fixture alive to reap sleep on both pass and failure.
            let mut stdin = libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: stdin points to one live pollfd; the timeout is bounded.
            assert!(
                unsafe {
                    libc::poll(
                        &mut stdin,
                        1,
                        TEST_LEASE_RELEASE_LIMIT.as_millis() as libc::c_int,
                    )
                } > 0,
                "parent must finish its release assertion within TEST_LEASE_RELEASE_LIMIT"
            );
            let _ = std::io::stdin().read(&mut [0u8; 1]).unwrap();
        }
    }

    #[test]
    fn inherited_lease_does_not_leak_to_unrelated_child() {
        struct FixtureCleanup(std::process::Child);
        impl Drop for FixtureCleanup {
            fn drop(&mut self) {
                // EOF releases the fixture's bounded wait and reaps its sleep
                // child even when the parent assertion fails red-first.
                drop(self.0.stdin.take());
                let _ = self.0.wait();
            }
        }
        let temp = NamedTempFile::new().unwrap();
        let pid_file = NamedTempFile::new().unwrap();
        let gate = HostLease::acquire_path(temp.path(), HostLeaseMode::Gate).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "host_lease::tests::inherited_lease_child_fixture",
            ])
            .stdin(std::process::Stdio::piped())
            .env("CARRICK_LEASE_CHILD_PID_FILE", pid_file.path());
        gate.configure_command(&mut command).unwrap();
        let mut fixture = FixtureCleanup(command.spawn().unwrap());
        drop(command);
        drop(gate);
        let deadline = Instant::now() + TEST_LEASE_RELEASE_LIMIT;
        let pid: libc::pid_t = loop {
            if let Ok(pid) = std::fs::read_to_string(pid_file.path()).unwrap().parse() {
                break pid;
            }
            assert!(
                fixture.0.try_wait().unwrap().is_none(),
                "fixture exited before ready"
            );
            assert!(
                Instant::now() < deadline,
                "fixture exceeded TEST_LEASE_RELEASE_LIMIT"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        // SAFETY: signal zero checks existence without changing the child.
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            0,
            "unrelated child must still be alive"
        );
        HostLease::acquire_path_with_limit(temp.path(), HostLeaseMode::Gate, Duration::ZERO)
            .expect(
                "unrelated child must not retain adopted lease after source descriptions close",
            );
        drop(fixture.0.stdin.take());
        assert!(fixture.0.wait().unwrap().success());
    }

    #[test]
    fn fresh_lease_does_not_leak_to_unrelated_child() {
        let temp = NamedTempFile::new().unwrap();
        // Isolate the zero-limit assertion from other tests' fork-before-exec
        // windows. The helper runs concurrently with the rest of the suite.
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "host_lease::tests::inherited_lease_child_fixture",
            ])
            .env_remove(INHERITED_FD)
            .env_remove(INHERITED_MODE)
            .env("CARRICK_HOST_LEASE_PATH", temp.path())
            .env("CARRICK_LEASE_FIXTURE_FRESH", "1")
            .status()
            .unwrap();
        assert!(status.success());
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
    fn inherited_gate_remains_exclusive_after_nested_carrick_returns() {
        let temp = NamedTempFile::new().unwrap();
        let gate = HostLease::acquire_path(temp.path(), HostLeaseMode::Gate).unwrap();
        let nested = HostLease::inherit(
            temp.path(),
            HostLeaseMode::Carrick,
            &gate.fd.to_string(),
            "gate",
        )
        .unwrap();
        assert_eq!(nested.mode(), HostLeaseMode::Gate);
        drop(nested);
        assert!(matches!(
            HostLease::acquire_path_with_limit(temp.path(), HostLeaseMode::Carrick, Duration::ZERO),
            Err(HostLeaseError::Timeout { .. })
        ));
        // Closing the parent's handle must leave a surviving child's lease held.
        let child = HostLease::inherit(
            temp.path(),
            HostLeaseMode::Carrick,
            &gate.fd.to_string(),
            "gate",
        )
        .unwrap();
        drop(gate);
        assert!(matches!(
            HostLease::acquire_path_with_limit(temp.path(), HostLeaseMode::Carrick, Duration::ZERO),
            Err(HostLeaseError::Timeout { .. })
        ));
        drop(child);
        HostLease::acquire_path_with_limit(
            temp.path(),
            HostLeaseMode::Gate,
            TEST_LEASE_RELEASE_LIMIT,
        )
        .unwrap();
    }

    #[test]
    fn configured_command_owns_lease_until_command_dropped() {
        let temp = NamedTempFile::new().unwrap();
        let gate = HostLease::acquire_path(temp.path(), HostLeaseMode::Gate).unwrap();
        let mut command = Command::new("true");
        gate.configure_command(&mut command).unwrap();
        drop(gate);
        assert!(matches!(
            HostLease::acquire_path_with_limit(temp.path(), HostLeaseMode::Carrick, Duration::ZERO),
            Err(HostLeaseError::Timeout { .. })
        ));
        assert!(command.status().unwrap().success());
        drop(command);
        HostLease::acquire_path_with_limit(
            temp.path(),
            HostLeaseMode::Gate,
            TEST_LEASE_RELEASE_LIMIT,
        )
        .unwrap();
    }

    #[test]
    fn inherited_lease_rejects_upgrade_invalid_fd_and_wrong_path() {
        let temp = NamedTempFile::new().unwrap();
        let other = NamedTempFile::new().unwrap();
        let shared = HostLease::acquire_path(temp.path(), HostLeaseMode::Carrick).unwrap();
        assert!(
            HostLease::inherit(
                temp.path(),
                HostLeaseMode::Gate,
                &shared.fd.to_string(),
                "carrick"
            )
            .is_err()
        );
        assert!(
            HostLease::inherit(
                other.path(),
                HostLeaseMode::Carrick,
                &shared.fd.to_string(),
                "carrick"
            )
            .is_err()
        );
        assert!(HostLease::inherit(temp.path(), HostLeaseMode::Carrick, "-1", "carrick").is_err());
        assert!(HostLease::inherit(temp.path(), HostLeaseMode::Carrick, "0", "carrick").is_err());
        assert!(
            HostLease::inherit(temp.path(), HostLeaseMode::Carrick, "invalid", "carrick").is_err()
        );
        drop(shared);
        use std::os::fd::AsRawFd;
        // This inode has never been leased. The just-dropped inode may still
        // be held by another test's child between fork and exec.
        assert!(
            HostLease::inherit(
                other.path(),
                HostLeaseMode::Carrick,
                &other.as_raw_fd().to_string(),
                "carrick"
            )
            .is_err()
        );
    }

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
