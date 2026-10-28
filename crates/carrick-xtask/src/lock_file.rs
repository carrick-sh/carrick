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

    /// Write an executable file in a forked child with an unshared descriptor
    /// table so no concurrent `fork()` on a sibling test thread can inherit a
    /// writable file description (`inode->i_writecount > 0`) and trigger
    /// `ETXTBSY` (`os error 26`) when the test immediately `execve`s it.
    pub(crate) fn write_test_executable(
        path: impl AsRef<std::path::Path>,
        contents: impl AsRef<[u8]>,
        permissions: std::fs::Permissions,
    ) {
        write_test_executable_with_hook(path.as_ref(), contents.as_ref(), permissions, || {});
    }

    fn write_test_executable_with_hook(
        path: &std::path::Path,
        contents: &[u8],
        permissions: std::fs::Permissions,
        while_open: impl FnOnce(),
    ) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;

        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let mode = permissions.mode();
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        child
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // SAFETY: `fork()` gives the child an unshared file-descriptor table.
        // The child performs only async-signal-safe syscalls (`open`, `write`,
        // `fchmod`, `read`, `close`, `_exit`) and exits without running
        // destructors. The parent waits for this exact `pid`.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                let sock = child.as_raw_fd();
                let fd = libc::open(
                    c_path.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
                    0o600 as libc::c_uint,
                );
                if fd < 0 {
                    libc::_exit(1);
                }
                let mut offset = 0usize;
                while offset < contents.len() {
                    let written = libc::write(
                        fd,
                        contents[offset..].as_ptr().cast(),
                        contents.len() - offset,
                    );
                    if written < 0 {
                        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                            continue;
                        }
                        let _ = libc::close(fd);
                        libc::_exit(2);
                    }
                    offset += written as usize;
                }
                if libc::fchmod(fd, mode as libc::mode_t) != 0 {
                    let _ = libc::close(fd);
                    libc::_exit(3);
                }
                if libc::write(sock, b"o".as_ptr().cast(), 1) != 1 {
                    let _ = libc::close(fd);
                    libc::_exit(4);
                }
                let mut ack = 0u8;
                if libc::read(sock, (&mut ack as *mut u8).cast(), 1) != 1 {
                    let _ = libc::close(fd);
                    libc::_exit(5);
                }
                if libc::close(fd) != 0 {
                    libc::_exit(6);
                }
                libc::_exit(0);
            }
        }
        drop(child);
        parent.read_exact(&mut [0]).unwrap();
        while_open();
        parent.write_all(b"c").unwrap();
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "fork-safe executable writer failed for {} with status {status:#x}",
            path.display()
        );
    }

    #[test]
    fn unrelated_fork_exec_cannot_hold_test_executable_busy() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("witness.sh");
        let (mut fork_ready_parent, mut fork_ready_child) = UnixStream::pair().unwrap();
        let (mut closed_parent, mut closed_child) = UnixStream::pair().unwrap();
        fork_ready_parent
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        closed_child
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let script_for_writer = script.clone();
        let writer = std::thread::spawn(move || {
            write_test_executable_with_hook(
                &script_for_writer,
                b"#!/bin/sh\nexit 0\n",
                std::fs::Permissions::from_mode(0o700),
                || {
                    fork_ready_child.write_all(b"o").unwrap();
                    fork_ready_child.read_exact(&mut [0]).unwrap();
                },
            );
            closed_parent.write_all(b"c").unwrap();
        });
        fork_ready_parent.read_exact(&mut [0]).unwrap();
        let status = with_unrelated_fork_exec(
            || {
                fork_ready_parent.write_all(b"f").unwrap();
                closed_child.read_exact(&mut [0]).unwrap();
                Command::new(&script).status()
            },
            || {
                assert!(Command::new(&script).status().unwrap().success());
            },
        );
        writer.join().unwrap();
        assert!(
            status
                .expect("unrelated pre-exec fork held executable open for write (ETXTBSY)")
                .success()
        );
    }
}
