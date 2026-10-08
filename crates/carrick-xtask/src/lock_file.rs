//! Process-owned flock release, independent of incidental forked fd copies.
use std::fs::File;
use std::ops::{Deref, DerefMut};

pub(crate) struct OwnedFileLock {
    file: File,
    release: ReleaseAuthority,
}

enum ReleaseAuthority {
    AcquiringProcess(u32),
    #[cfg(target_os = "macos")]
    LastCustodian,
}

impl OwnedFileLock {
    /// The caller has successfully locked this CLOEXEC file description.
    pub(crate) fn from_locked(file: File) -> Self {
        Self {
            file,
            release: ReleaseAuthority::AcquiringProcess(std::process::id()),
        }
    }
}

impl OwnedFileLock {
    #[cfg(target_os = "macos")]
    pub(crate) fn retain_until_last_close(&mut self) {
        self.release = ReleaseAuthority::LastCustodian;
    }
}

impl Deref for OwnedFileLock {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}

impl DerefMut for OwnedFileLock {
    fn deref_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl Drop for OwnedFileLock {
    fn drop(&mut self) {
        // close alone leaves flock held by an unrelated pre-exec fork's copy.
        // Only the acquiring process may unlock the shared description: a
        // fork child dropping its inherited guard must not revoke the parent.
        if matches!(self.release, ReleaseAuthority::AcquiringProcess(owner) if std::process::id() == owner)
        {
            let _ = self.file.unlock();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn fork_child_dropping_guard_cannot_unlock_parent() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let locked = File::open(file.path()).unwrap();
        locked.lock().unwrap();
        let guard = super::OwnedFileLock::from_locked(locked);
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // SAFETY: child only closes its inherited guard, writes the handshake,
        // and _exits. The parent waits exactly this PID, never process-wide -1.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            drop(guard);
            unsafe {
                let written = libc::write(child.as_raw_fd(), b"c".as_ptr().cast(), 1);
                libc::_exit(if written == 1 { 0 } else { 1 });
            }
        }
        parent.read_exact(&mut [0]).unwrap();
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert!(
            matches!(
                file.as_file().try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ),
            "fork child revoked its parent's live authority"
        );
        drop(guard);
        file.as_file().try_lock().unwrap();
    }

    /// Keep an unrelated fork alive on both sides of exec. No global state or
    /// serialization: each actor owns a private socket/stdio control channel.
    pub(crate) fn with_unrelated_fork_exec<T>(
        before_exec: impl FnOnce() -> T,
        after_exec: impl FnOnce(),
    ) -> T {
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        child
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let spawning = std::thread::spawn(move || {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "read finish || :"])
                .stdin(Stdio::piped());
            // SAFETY: after fork, only async-signal-safe socket I/O occurs.
            // Command::spawn's exec-error channel acknowledges successful exec.
            unsafe {
                command.pre_exec(move || {
                    let fd = child.as_raw_fd();
                    if libc::write(fd, b"r".as_ptr().cast(), 1) != 1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let mut proceed = 0u8;
                    if libc::read(fd, (&mut proceed as *mut u8).cast(), 1) != 1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            command.spawn().unwrap()
        });
        parent.read_exact(&mut [0]).unwrap();
        let result = before_exec();
        parent.write_all(b"e").unwrap();
        let mut child = spawning.join().unwrap();
        // The unrelated child is still alive, but has crossed the exec boundary.
        assert!(child.try_wait().unwrap().is_none());
        after_exec();
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        result
    }
}
