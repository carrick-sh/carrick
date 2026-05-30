//! fd-table accessors and installers split out of dispatch/fs.rs (WS-F3):
//! the free-slot finder, the install_fd* helpers, and the typed fd-kind
//! accessors (host file/socket/pipe, inotify, splice). Pure `impl
//! SyscallDispatcher` move — `self.…` resolution is type-based.
use super::*;

impl SyscallDispatcher {
    fn first_free_fd(
        table: &HashMap<i32, OpenFile>,
        min_fd: i32,
        reserved: Option<i32>,
        closed_stdio: &[bool; 3],
    ) -> Option<i32> {
        // Cap at the soft RLIMIT_NOFILE (1024, matching getrlimit/prlimit and
        // /proc/self/limits): descriptors run 0..1024, so the first free slot
        // at or above the limit means the table is full. `None` => the caller
        // returns EMFILE, matching Linux fd exhaustion.
        const RLIMIT_NOFILE_CUR: i32 = 1024;
        let mut fd = min_fd.max(0);
        loop {
            // A bare stdio number (0/1/2) is reserved (not allocatable) UNLESS the
            // guest explicitly closed it — then POSIX lets the lowest-free open/dup
            // land there. A caller wanting "anything but stdio" passes min_fd = 3.
            let reserved_stdio = (0..3).contains(&fd) && !closed_stdio[fd as usize];
            if Some(fd) != reserved && !table.contains_key(&fd) && !reserved_stdio {
                break;
            }
            fd = fd.checked_add(1)?;
        }
        if fd >= RLIMIT_NOFILE_CUR {
            None
        } else {
            Some(fd)
        }
    }

    /// Clear the "closed" flag for a reused stdio fd (it is open again).
    fn clear_closed_stdio(&self, fd: i32) {
        if (0..3).contains(&fd) {
            self.io.closed_stdio.lock()[fd as usize] = false;
        }
    }

    pub(in crate::dispatch) fn install_fd_at_or_above(
        &self,
        min_fd: i32,
        open_file: OpenFile,
    ) -> Result<i32, OpenFile> {
        let mut table = self.io.open_files.write();
        // Lock order: open_files → closed_stdio (the close path never holds both).
        let fd = {
            let closed = self.io.closed_stdio.lock();
            match Self::first_free_fd(&table, min_fd, None, &closed) {
                Some(fd) => fd,
                None => return Err(open_file),
            }
        };
        retain_open_file(&open_file.description);
        table.insert(fd, open_file);
        self.clear_closed_stdio(fd);
        let mut next_fd = self.io.next_fd.lock();
        *next_fd = (*next_fd).max(fd.saturating_add(1));
        Ok(fd)
    }

    pub(in crate::dispatch) fn install_fd_pair_at_or_above(
        &self,
        min_fd: i32,
        first: OpenFile,
        second: OpenFile,
    ) -> Result<(i32, i32), (OpenFile, OpenFile)> {
        let mut table = self.io.open_files.write();
        let (first_fd, second_fd) = {
            let closed = self.io.closed_stdio.lock();
            let Some(first_fd) = Self::first_free_fd(&table, min_fd, None, &closed) else {
                return Err((first, second));
            };
            let Some(second_fd) =
                Self::first_free_fd(&table, first_fd.saturating_add(1), Some(first_fd), &closed)
            else {
                return Err((first, second));
            };
            (first_fd, second_fd)
        };
        retain_open_file(&first.description);
        retain_open_file(&second.description);
        table.insert(first_fd, first);
        table.insert(second_fd, second);
        self.clear_closed_stdio(first_fd);
        self.clear_closed_stdio(second_fd);
        let mut next_fd = self.io.next_fd.lock();
        *next_fd = (*next_fd).max(second_fd.saturating_add(1));
        Ok((first_fd, second_fd))
    }

    pub(in crate::dispatch) fn install_fd(
        &self,
        description: OpenDescription,
        fd_flags: u64,
    ) -> DispatchOutcome {
        let open_file = OpenFile::new(Arc::new(RwLock::new(description)), fd_flags);
        // POSIX lowest-free-descriptor (min_fd = 0): reuses a stdio number the
        // guest explicitly closed — busybox ash's background-job forkchild does
        // `close(0); open("/dev/null")` and treats anything but fd 0 as an error
        // ("can't open /dev/null") — else the lowest fd >= 3.
        match self.install_fd_at_or_above(0, open_file) {
            Ok(fd) => DispatchOutcome::Returned { value: fd as i64 },
            Err(_) => DispatchOutcome::errno(linux_errno::EMFILE),
        }
    }

    pub(in crate::dispatch) fn open_file(&self, fd: i32) -> Option<OpenFile> {
        self.io.open_files.read().get(&fd).cloned()
    }

    pub(in crate::dispatch) fn fd_table_contains(&self, fd: i32) -> bool {
        self.io.open_files.read().contains_key(&fd)
    }

    /// Host fd of `fd` iff it is a real regular file (HostFile) — the source
    /// macOS `sendfile(2)` can stream.
    pub(in crate::dispatch) fn regular_host_file_fd(&self, fd: i32) -> Option<i32> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::HostFile { host_fd, .. } => Some(*host_fd),
            _ => None,
        }
    }

    /// Writable host fd of `fd` iff it is a guest-writable HostFile. The host
    /// fd may be broader than guest access mode for HVF mmap max-protection, so
    /// write-side callers must use this helper rather than `regular_host_file_fd`.
    pub(in crate::dispatch) fn regular_host_file_write_fd(&self, fd: i32) -> Option<i32> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::HostFile {
                host_fd,
                writable: true,
                ..
            } => Some(*host_fd),
            _ => None,
        }
    }

    /// Host fd of `fd` iff it is a host socket — the destination macOS
    /// `sendfile(2)` streams to.
    pub(in crate::dispatch) fn host_socket_fd(&self, fd: i32) -> Option<i32> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::HostSocket { host_fd, .. } => Some(*host_fd),
            _ => None,
        }
    }

    /// The [`InotifyState`] behind `fd` iff it is an inotify instance.
    pub(in crate::dispatch) fn inotify_state(
        &self,
        fd: i32,
    ) -> Option<Arc<crate::inotify::InotifyState>> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::Inotify { state, .. } => Some(Arc::clone(state)),
            _ => None,
        }
    }

    pub(in crate::dispatch) fn pipe_reader(&self, fd: i32) -> Option<(PipeRef, u64)> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::PipeReader { base, pipe } => {
                Some((Arc::clone(pipe), base.status_flags()))
            }
            _ => None,
        }
    }

    pub(in crate::dispatch) fn fd_is_pipe_writer(&self, fd: i32) -> Result<bool, i32> {
        let Some(open_file) = self.open_file(fd) else {
            return if is_stdio_fd(fd) {
                Ok(false)
            } else {
                Err(LINUX_EBADF)
            };
        };
        let open = open_file.description.read();
        Ok(match &*open {
            OpenDescription::PipeWriter { .. } => true,
            // Real host pipe write end (fork-safe pipe model). A pty end is
            // bidirectional, so it's a valid splice target regardless of
            // is_read_end.
            OpenDescription::HostPipe {
                is_read_end, pty, ..
            } => pty.is_some() || !*is_read_end,
            _ => false,
        })
    }

    /// The raw host fd backing `fd` if it is a [`OpenDescription::HostPipe`]
    /// read end, else `None`. Lets `splice` drain a real host pipe.
    pub(in crate::dispatch) fn host_pipe_read_fd(&self, fd: i32) -> Option<i32> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::HostPipe {
                host_fd,
                is_read_end: true,
                ..
            } => Some(*host_fd),
            _ => None,
        }
    }

    pub(in crate::dispatch) fn splice_output_errno(&self, fd: i32) -> Option<i32> {
        if is_stdio_fd(fd) {
            return None;
        }
        let Some(open_file) = self.open_file(fd) else {
            return Some(LINUX_EBADF);
        };
        let open = open_file.description.read();
        match &*open {
            OpenDescription::PipeWriter { pipe, .. } => {
                if pipe.lock().readers == 0 {
                    Some(LINUX_EPIPE)
                } else {
                    None
                }
            }
            // Real host pipe write end: the kernel enforces EPIPE itself on
            // write, so we just accept the destination here.
            OpenDescription::HostPipe {
                is_read_end: false, ..
            } => None,
            // A host socket is a valid splice destination (pipe->socket, the
            // io.Copy(conn, pipe) direction); the host send enforces its own
            // errors. Without this the `_` arm below rejected it with EINVAL.
            OpenDescription::HostSocket { .. } => None,
            // Splicing FROM a pipe INTO a regular file is valid on Linux (only
            // ONE end must be a pipe). The write + offset advance is handled by
            // write_output_fd. A read-only fd is EBADF.
            OpenDescription::HostFile { writable: true, .. }
            | OpenDescription::File { writable: true, .. } => None,
            OpenDescription::HostFile { .. } | OpenDescription::File { .. } => Some(LINUX_EBADF),
            _ => Some(LINUX_EINVAL),
        }
    }
}
