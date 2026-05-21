//! fs syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

/// Owned filesystem-subsystem state. Split out of `SyscallDispatcher` so
/// the fs handlers borrow only the VFS state they touch instead of the
/// whole dispatcher. Field semantics are unchanged from the former loose
/// fields (`vfs_mounts`/`rootfs_vfs`).
pub(super) struct FsState {
    /// Unified VFS mount table. Holds DevVfs at /dev, ProcVfs at
    /// /proc, SysVfs at /sys. The dispatcher consults it first; any
    /// path no mount claims (or that a mount returns ENOSYS for)
    /// falls through to the legacy code path, which reads the rootfs +
    /// overlay from [`Self::rootfs_vfs`].
    pub vfs_mounts: crate::vfs::VfsMounts,

    /// The `/` mount: immutable OCI rootfs + writable overlay
    /// ([`FsBackend`]). Held as a typed field rather than mounted in
    /// `vfs_mounts` because the dispatcher's existing fs syscalls reach
    /// into the overlay/rootfs state through ~50 call sites today.
    pub rootfs_vfs: crate::vfs::RootFsVfs,
}

/// Owned I/O-subsystem state. Split out of `SyscallDispatcher` so the I/O
/// handlers borrow only the fd/stdio state they touch. Field semantics are
/// unchanged from the former loose fields (`stdout`/`stderr`/`stream_stdio`/
/// `open_files`/`next_fd`/`cwd`).
pub(super) struct IoState {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// When true, writes to fd 1/2 stream directly to host fds 1/2
    /// instead of buffering into `stdout`/`stderr`. Set by `--raw`/the
    /// interactive runtime so the user sees the guest's prompt and
    /// output in real time, instead of after exit.
    pub stream_stdio: bool,
    pub open_files: HashMap<i32, OpenFile>,
    pub next_fd: i32,
    pub cwd: String,
}

impl IoState {
    pub(super) fn new() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            stream_stdio: false,
            open_files: HashMap::new(),
            next_fd: 3,
            cwd: "/".to_owned(),
        }
    }
}

impl FsState {
    pub(super) fn new() -> Self {
        Self {
            vfs_mounts: {
                let mut m = crate::vfs::VfsMounts::new();
                m.mount("/dev", Box::new(crate::vfs::DevVfs::new()));
                m.mount("/proc", Box::new(crate::vfs::ProcVfs::new()));
                m.mount("/sys", Box::new(crate::vfs::SysVfs::new()));
                m
            },
            rootfs_vfs: crate::vfs::RootFsVfs::new(),
        }
    }
}

impl SyscallDispatcher {
    pub(super) fn getcwd<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let size = usize::try_from(ctx.arg(1))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(1)))?;
        let mut bytes = self.io.cwd.as_bytes().to_vec();
        bytes.push(0);
        if bytes.len() > size {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ERANGE,
            });
        }
        if ctx.memory.write_bytes(address, &bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        // Linux getcwd(2) returns the LENGTH of the buffer filled (including
        // the terminating NUL), not the buffer address. glibc tolerates a
        // positive non-length, but tools that use the return value as a
        // length (and the kernel ABI) require the real count.
        Ok(DispatchOutcome::Returned {
            value: bytes.len() as i64,
        })
    }

    pub(super) fn faccessat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Linux's `faccessat` (syscall 48) takes only (dirfd, pathname, mode).
        // The 4-arg form with flags is `faccessat2` (syscall 439). We were
        // erroneously reading x3 as flags here, which is whatever uninit
        // register state the caller had — making glibc see EINVAL for normal
        // access(F_OK)-style calls and abort with "stack smashing detected".
        self.access_at(ctx.arg(0), ctx.arg(1), ctx.arg(2), 0, &*ctx.memory)
    }

    pub(super) fn faccessat2<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.access_at(
            ctx.arg(0),
            ctx.arg(1),
            ctx.arg(2),
            ctx.arg(3),
            &*ctx.memory,
        )
    }

    fn access_at(
        &self,
        dirfd: u64,
        pathname: u64,
        mode: u64,
        flags: u64,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        if mode & !(LINUX_R_OK | LINUX_W_OK | LINUX_X_OK) != 0
            || !linux_access_flags_are_supported(flags)
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            if flags & LINUX_AT_EMPTY_PATH == 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOENT,
                });
            }
            if dirfd == LINUX_AT_FDCWD {
                return Ok(self.access_resolved_path(&self.io.cwd, mode, flags));
            }
            return Ok(self.fd_access(dirfd as i32, mode));
        }

        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        Ok(self.access_resolved_path(&path, mode, flags))
    }

    fn access_resolved_path(&self, path: &str, mode: u64, flags: u64) -> DispatchOutcome {
        // Synthetic /proc /sys paths bypass the rootfs/overlay
        // layered view: they have their own permission model.
        if let Some(outcome) = self.synthetic_access(path, mode) {
            return outcome;
        }
        // Layered overlay+rootfs lookup via RootFsVfs. AT_SYMLINK_NOFOLLOW
        // doesn't change the access mask (no chmod-on-link semantics
        // exposed in our compat layer), so we use the default lookup.
        let _ = flags; // AT_SYMLINK_NOFOLLOW is currently a no-op here
        use crate::vfs::Vfs as _;
        match self.fs.rootfs_vfs.lookup(path) {
            Ok(md) => access_metadata(&vfs_md_to_rootfs_md(path, &md), mode),
            Err(errno) => DispatchOutcome::Errno { errno },
        }
    }

    fn fd_access(&self, fd: i32, mode: u64) -> DispatchOutcome {
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let open = open_file.description.borrow();
        match &*open {
            OpenDescription::File { metadata, .. }
            | OpenDescription::HostFile { metadata, .. }
            | OpenDescription::Directory { metadata, .. } => access_metadata(metadata, mode),
            OpenDescription::SyntheticFile { path, .. } => self
                .synthetic_access(path, mode)
                .unwrap_or(DispatchOutcome::Errno {
                    errno: LINUX_ENOENT,
                }),
            OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Netlink { .. } => synthetic_readonly_access(mode),
        }
    }

    pub(super) fn chdir<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pathname = ctx.arg(0);
        let path = match read_guest_c_string(&*ctx.memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(LINUX_AT_FDCWD, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // Use the LAYERED lookup (overlay/host backend first, then rootfs),
        // not just the immutable rootfs — otherwise a freshly mkdir'd
        // directory is invisible and chdir into it fails ENOENT (dpkg-deb
        // mkdir's its extraction dir then chdir's there).
        let metadata = match self.layered_metadata(&path) {
            Ok(metadata) => metadata,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if metadata.kind != RootFsEntryKind::Directory {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOTDIR,
            });
        }
        self.io.cwd = display_rootfs_path(&metadata.path);
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn fchdir<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        Ok(match &*open {
            OpenDescription::Directory { metadata, .. } => {
                self.io.cwd = display_rootfs_path(&metadata.path);
                DispatchOutcome::Returned { value: 0 }
            }
            OpenDescription::File { .. }
            | OpenDescription::HostFile { .. }
            | OpenDescription::SyntheticFile { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Netlink { .. } => DispatchOutcome::Errno {
                errno: LINUX_ENOTDIR,
            },
        })
    }

    fn synthetic_access(&self, path: &str, mode: u64) -> Option<DispatchOutcome> {
        if !is_synthetic_virtual_file(path, &self.synthetic_proc_context()) {
            return None;
        }
        Some(synthetic_readonly_access(mode))
    }

    fn record_unimplemented_virtual_file(
        reporter: &mut CompatReporter,
        path: &str,
    ) -> Option<DispatchOutcome> {
        if path.starts_with("/proc/") {
            reporter.record(CompatEvent::proc_read_unimplemented(path.to_owned()));
            Some(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            })
        } else if path.starts_with("/sys/") {
            // /sys paths that are synthesized must not be recorded as unimplemented;
            // they are handled by the synthetic open path before reaching ENOENT.
            if synthetic_sys_file(path).is_some() {
                return None;
            }
            reporter.record(CompatEvent::sys_read_unimplemented(path.to_owned()));
            Some(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            })
        } else {
            None
        }
    }

    pub(super) fn pipe2<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let flags = ctx.arg(1);
        let memory = &mut *ctx.memory;
        if flags & !(LINUX_O_CLOEXEC | LINUX_O_NONBLOCK) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        // Allocate a real host pipe so the two ends share state via the
        // kernel and survive `libc::fork(2)` natively. macOS's `pipe(2)`
        // returns two fds: [0] read end, [1] write end.
        let mut host_fds = [0i32; 2];
        let r = unsafe { libc::pipe(host_fds.as_mut_ptr()) };
        if r != 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }

        let host_read = host_fds[0];
        let host_write = host_fds[1];

        let Some(read_fd) = self.allocate_fd(3) else {
            unsafe {
                libc::close(host_read);
                libc::close(host_write);
            }
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        let Some(write_fd) = self.allocate_fd(read_fd.saturating_add(1)) else {
            unsafe {
                libc::close(host_read);
                libc::close(host_write);
            }
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        let pair = LinuxFdPair { read_fd, write_fd };
        if write_kernel_struct_raw(memory, address, &pair).is_err() {
            unsafe {
                libc::close(host_read);
                libc::close(host_write);
            }
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }

        // The access mode must be encoded per end so fcntl(F_GETFL) reports
        // it: the read end is O_RDONLY (0), the write end O_WRONLY. Without
        // this, glibc's fdopen(write_end, "w") sees O_RDONLY via F_GETFL and
        // fails with EINVAL ("Failed to open new FD - fdopen") — apt's dpkg
        // status pipe hit exactly that.
        let nonblock = flags & LINUX_O_NONBLOCK;
        // pipe2(2)'s O_NONBLOCK must take effect on the actual pipe ends.
        // The read/write path does a raw libc::read/write on the host fd and
        // relies on its blocking mode — `status_flags` is only bookkeeping
        // for F_GETFL. Without applying it here a nonblocking read on an
        // empty pipe blocks the supervisor forever (matches what
        // fcntl(F_SETFL) already does for the apt http-method path).
        if nonblock != 0 {
            for hfd in [host_read, host_write] {
                unsafe {
                    let cur = libc::fcntl(hfd, libc::F_GETFL, 0);
                    if cur >= 0 {
                        libc::fcntl(hfd, libc::F_SETFL, cur | libc::O_NONBLOCK);
                    }
                }
            }
        }
        let fd_flags = linux_fd_flags_from_open_flags(flags);
        self.insert_open_file(
            read_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostPipe {
                    host_fd: host_read,
                    is_read_end: true,
                    status_flags: LINUX_O_RDONLY | nonblock,
                })),
                fd_flags,
            },
        );
        self.insert_open_file(
            write_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostPipe {
                    host_fd: host_write,
                    is_read_end: false,
                    status_flags: LINUX_O_WRONLY | nonblock,
                })),
                fd_flags,
            },
        );

        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn dup<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let old_fd = ctx.arg(0) as i32;
        Ok(self.duplicate_fd(old_fd, 3, 0))
    }

    pub(super) fn dup3<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let old_fd = ctx.arg(0) as i32;
        let new_fd = ctx.arg(1) as i32;
        let flags = ctx.arg(2);
        // Linux dup3 requires old_fd != new_fd and only honours
        // O_CLOEXEC in `flags`. It explicitly allows new_fd to be 0/1/2
        // — that's how shells redirect stdin/stdout/stderr.
        if old_fd == new_fd || flags & !LINUX_O_CLOEXEC != 0 || new_fd < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let description = match self.io.open_files.get(&old_fd) {
            Some(open_file) => Rc::clone(&open_file.description),
            None if is_stdio_fd(old_fd) => {
                // Shell `2>&1` style redirects: the source fd is the
                // process's real host fd 0/1/2 (no OpenDescription was
                // ever created for them — writes go straight through
                // stream_stdio). dup3 onto a different fd needs to
                // capture that host fd so future writes/reads also
                // reach the same host endpoint. Duplicate the host fd
                // and wrap it as a HostPipe so the write path picks it
                // up before the bare-stdio fallback.
                let duped = unsafe { libc::dup(old_fd) };
                if duped < 0 {
                    return Ok(DispatchOutcome::Errno {
                        errno: host_errno(),
                    });
                }
                Rc::new(RefCell::new(OpenDescription::HostPipe {
                    host_fd: duped,
                    is_read_end: old_fd == 0,
                    status_flags: 0,
                }))
            }
            None => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
        };
        if let Some(replaced) = self.io.open_files.remove(&new_fd) {
            close_open_file(&replaced);
        }
        retain_open_file(&description);
        self.io.open_files.insert(
            new_fd,
            OpenFile {
                description,
                fd_flags: linux_fd_flags_from_open_flags(flags),
            },
        );
        Ok(DispatchOutcome::Returned {
            value: new_fd as i64,
        })
    }

    pub(super) fn fcntl<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let command = ctx.arg(1);
        let arg = ctx.arg(2);
        Ok(match command {
            LINUX_F_DUPFD => match linux_min_fd(arg) {
                Ok(min_fd) => self.duplicate_fd(fd, min_fd, 0),
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_F_DUPFD_CLOEXEC => match linux_min_fd(arg) {
                Ok(min_fd) => self.duplicate_fd(fd, min_fd, LINUX_FD_CLOEXEC),
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_F_GETPIPE_SZ => {
                let Some(open_file) = self.io.open_files.get(&fd) else {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                };
                match &*open_file.description.borrow() {
                    OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
                        DispatchOutcome::Returned {
                            value: LINUX_PIPE_BUF_SIZE,
                        }
                    }
                    OpenDescription::HostSocket { .. } => {
                        DispatchOutcome::Errno { errno: LINUX_EBADF }
                    }
                    _ => DispatchOutcome::Errno { errno: LINUX_EBADF },
                }
            }
            LINUX_F_GETFD => {
                if let Some(open_file) = self.io.open_files.get(&fd) {
                    return Ok(DispatchOutcome::Returned {
                        value: open_file.fd_flags as i64,
                    });
                }
                // stdio without an OpenDescription: not CLOEXEC by default
                // (Linux semantics: stdio survives exec). Return 0.
                if is_stdio_fd(fd) {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                DispatchOutcome::Errno { errno: LINUX_EBADF }
            }
            LINUX_F_SETFD => {
                if let Some(open_file) = self.io.open_files.get_mut(&fd) {
                    open_file.fd_flags = arg & LINUX_FD_CLOEXEC;
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                // apt's http method fcntl(fd, F_SETFD, FD_CLOEXEC)s its
                // inherited stdio fds on startup. Returning EBADF here
                // makes apt abort with "Could not set close on exec".
                // Carrick's exec inherits stdio via the host fd directly;
                // CLOEXEC is meaningless for our model (we don't exec
                // anything host-side after the syscall returns) but we
                // accept the call so the guest's bookkeeping succeeds.
                if is_stdio_fd(fd) {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                DispatchOutcome::Errno { errno: LINUX_EBADF }
            }
            LINUX_F_GETFL => {
                if let Some(open_file) = self.io.open_files.get(&fd) {
                    let open = open_file.description.borrow();
                    return Ok(DispatchOutcome::Returned {
                        value: open.status_flags() as i64,
                    });
                }
                // stdio without an OpenDescription: glibc cat/head/etc
                // probe `fcntl(1, F_GETFL)` on startup to decide whether
                // stdout is append-only. Returning O_RDWR (with the
                // appropriate direction for fd 0 vs 1/2) keeps them happy
                // instead of bailing with "Bad file descriptor".
                if is_stdio_fd(fd) {
                    let flags: u64 = if fd == 0 {
                        LINUX_O_RDONLY
                    } else {
                        LINUX_O_WRONLY
                    };
                    return Ok(DispatchOutcome::Returned { value: flags as i64 });
                }
                DispatchOutcome::Errno { errno: LINUX_EBADF }
            }
            LINUX_F_SETFL => {
                let Some(open_file) = self.io.open_files.get(&fd) else {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                };
                let next_flags = arg & !LINUX_O_CLOEXEC;
                // Propagate O_NONBLOCK to the underlying host fd when one
                // exists. Without this, our libc::read still blocks even
                // after the guest set O_NONBLOCK — apt's http method
                // depends on this for the pselect6 wait pattern.
                let open = open_file.description.borrow();
                if let Some(host_fd) = match &*open {
                    OpenDescription::HostPipe { host_fd, .. }
                    | OpenDescription::HostSocket { host_fd, .. } => Some(*host_fd),
                    _ => None,
                } {
                    let want_nonblock = next_flags & LINUX_O_NONBLOCK != 0;
                    unsafe {
                        let cur = libc::fcntl(host_fd, libc::F_GETFL, 0);
                        if cur >= 0 {
                            let next = if want_nonblock {
                                cur | libc::O_NONBLOCK
                            } else {
                                cur & !libc::O_NONBLOCK
                            };
                            if next != cur {
                                libc::fcntl(host_fd, libc::F_SETFL, next);
                            }
                        }
                    }
                }
                drop(open);
                open_file
                    .description
                    .borrow_mut()
                    .set_status_flags(next_flags);
                DispatchOutcome::Returned { value: 0 }
            }
            // Advisory record locks: apt uses fcntl(F_SETLK) on
            // /var/lib/apt/lists/lock as its inter-process lock. Carrick
            // runs the guest as a single-tenant VM (no real concurrent
            // apt invocations against the same overlay), so we treat the
            // whole F_*LK family as no-op success. Without this apt
            // reports "Could not get lock ... open (22: Invalid argument)"
            // because the F_SETLK that follows the openat is what
            // actually fails — apt's error message just blames open.
            LINUX_F_SETLK
            | LINUX_F_SETLKW
            | LINUX_F_OFD_SETLK
            | LINUX_F_OFD_SETLKW => {
                if !self.fd_is_valid(fd) {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                }
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_F_GETLK | LINUX_F_OFD_GETLK => {
                // Indicate "no lock present" by leaving the caller's
                // struct flock untouched and returning 0. apt only ever
                // probes after a successful SETLK so it doesn't
                // re-inspect the buffer.
                if !self.fd_is_valid(fd) {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                }
                DispatchOutcome::Returned { value: 0 }
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
        })
    }

    pub(super) fn ioctl<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let ioctl_request = ctx.arg(1);
        let arg = ctx.arg(2);
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }

        Ok(match ioctl_request {
            LINUX_TIOCGWINSZ if fd_is_tty(&self.io.open_files, fd) => {
                // Prefer the live host window size when stdin/stdout/stderr
                // is a real macOS terminal; fall back to the 80x24 stub so
                // headless invocations (CI, redirected pipes that we still
                // synthesize a TTY for in tests) keep prior behaviour.
                let winsize = if crate::host_tty::host_isatty(fd) {
                    crate::host_tty::get_host_winsize(fd)
                        .unwrap_or_else(LinuxWinsize::terminal_80x24)
                } else {
                    LinuxWinsize::terminal_80x24()
                };
                write_kernel_struct(&mut *ctx.memory, arg, &winsize)
            }
            LINUX_TIOCGWINSZ => DispatchOutcome::Errno {
                errno: LINUX_ENOTTY,
            },
            LINUX_TCGETS if fd_is_tty(&self.io.open_files, fd) => {
                // Mirror the live host terminal modes when available so
                // `less`, `vi`, and an interactive shell see the actual
                // ICANON/ECHO state the user has configured.
                let termios = if crate::host_tty::host_isatty(fd) {
                    crate::host_tty::get_host_termios(fd)
                        .unwrap_or_else(LinuxTermios::default_cooked)
                } else {
                    LinuxTermios::default_cooked()
                };
                // KernelAbi for LinuxTermios pins this at 36 bytes —
                // the kernel-ABI termios size, NOT our 44-byte Rust
                // struct (which includes the termios2-only ispeed/ospeed
                // tail). Going past 36 here is what blew glibc's
                // tcgetattr canary and crashed ls/dpkg.
                write_kernel_struct(&mut *ctx.memory, arg, &termios)
            }
            LINUX_TCGETS => DispatchOutcome::Errno {
                errno: LINUX_ENOTTY,
            },
            LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF if fd_is_tty(&self.io.open_files, fd) => {
                // Read 36 bytes (kernel termios), then pad to the
                // 44-byte zerocopy struct so we can parse it. The guest
                // only provided a 36-byte buffer; reading 44 would
                // EFAULT at the boundary of a stack-page allocation.
                match ctx.memory.read_bytes(arg, LINUX_TERMIOS_KERNEL_SIZE) {
                    Ok(bytes) => {
                        if crate::host_tty::host_isatty(fd) {
                            let mut padded =
                                [0u8; core::mem::size_of::<LinuxTermios>()];
                            padded[..LINUX_TERMIOS_KERNEL_SIZE]
                                .copy_from_slice(&bytes);
                            if let Ok(t) = LinuxTermios::read_from_bytes(&padded) {
                                let _ = crate::host_tty::set_host_termios_tracking(fd, &t);
                            }
                        }
                        DispatchOutcome::Returned { value: 0 }
                    }
                    Err(_) => DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    },
                }
            }
            LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF => DispatchOutcome::Errno {
                errno: LINUX_ENOTTY,
            },
            LINUX_TIOCSCTTY => match self.tty_ioctl_fd_kind(fd) {
                Ok(TtyFdKind::Stdio) => DispatchOutcome::Returned { value: 0 },
                Ok(TtyFdKind::Other) => DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                },
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_TIOCGPGRP => match self.tty_ioctl_fd_kind(fd) {
                Ok(TtyFdKind::Stdio) => {
                    write_packed(&mut *ctx.memory, arg, &LINUX_BOOTSTRAP_PGID.to_le_bytes())
                }
                Ok(TtyFdKind::Other) => DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                },
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_TIOCSPGRP => match self.tty_ioctl_fd_kind(fd) {
                Ok(TtyFdKind::Stdio) => {
                    let mut buf = [0u8; 4];
                    match ctx.memory.read_bytes(arg, 4) {
                        Ok(bytes) => buf.copy_from_slice(&bytes),
                        Err(_) => {
                            return Ok(DispatchOutcome::Errno {
                                errno: LINUX_EFAULT,
                            });
                        }
                    }
                    let pgid = i32::from_le_bytes(buf);
                    if pgid == LINUX_BOOTSTRAP_PGID {
                        DispatchOutcome::Returned { value: 0 }
                    } else {
                        DispatchOutcome::Errno { errno: LINUX_EPERM }
                    }
                }
                Ok(TtyFdKind::Other) => DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                },
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_FIONREAD => {
                // Stdio, eventfd, timerfd, epoll, pipe writer, directory, regular file,
                // synthetic file: writing 0 ("nothing pending") is benign. Pipe reader
                // gets the actual buffered byte count.
                let available: i32 = match self.io.open_files.get(&fd) {
                    Some(open_file) => match &*open_file.description.borrow() {
                        OpenDescription::PipeReader { pipe, .. } => {
                            let len = pipe.borrow().buffer.len();
                            i32::try_from(len).unwrap_or(i32::MAX)
                        }
                        _ => 0,
                    },
                    // stdio fd (already validated above) or any other valid fd: 0.
                    None => 0,
                };
                write_packed(&mut *ctx.memory, arg, &available.to_le_bytes())
            }
            LINUX_FIONBIO => {
                if ctx.memory.read_bytes(arg, 4).is_err() {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
                // Bootstrap: accept and ignore — we don't persist nonblocking
                // state for most fd kinds. Real fcntl(F_SETFL) is the durable path.
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_TIOCNOTTY => match self.tty_ioctl_fd_kind(fd) {
                Ok(TtyFdKind::Stdio) => DispatchOutcome::Returned { value: 0 },
                Ok(TtyFdKind::Other) => DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                },
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_TIOCGSID => match self.tty_ioctl_fd_kind(fd) {
                Ok(TtyFdKind::Stdio) => {
                    write_packed(&mut *ctx.memory, arg, &LINUX_BOOTSTRAP_SID.to_le_bytes())
                }
                Ok(TtyFdKind::Other) => DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                },
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            _ => {
                ctx.reporter
                    .record(CompatEvent::unhandled_ioctl(fd, ioctl_request, arg));
                DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                }
            }
        })
    }

    fn tty_ioctl_fd_kind(&self, fd: i32) -> Result<TtyFdKind, i32> {
        if is_stdio_fd(fd) {
            Ok(TtyFdKind::Stdio)
        } else if self.io.open_files.contains_key(&fd) {
            Ok(TtyFdKind::Other)
        } else {
            Err(LINUX_EBADF)
        }
    }

    pub(super) fn fd_is_valid(&self, fd: i32) -> bool {
        is_stdio_fd(fd) || self.io.open_files.contains_key(&fd)
    }

    pub(super) fn flock<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let operation = ctx.arg(1);
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }

        let lock_operation = operation & !LINUX_LOCK_NB;
        Ok(match lock_operation {
            LINUX_LOCK_SH | LINUX_LOCK_EX | LINUX_LOCK_UN => DispatchOutcome::Returned { value: 0 },
            _ => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
        })
    }

    fn statfs(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pathname = request.arg(0);
        let buffer = request.arg(1);
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(LINUX_AT_FDCWD, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // Consult the layered view (overlay/disk first, then rootfs) so
        // that files the guest created in the overlay are visible here
        // too — a rootfs-direct lookup would miss them.
        if let Err(errno) = self.layered_metadata(&path) {
            return Ok(DispatchOutcome::Errno { errno });
        }
        Ok(write_statfs(memory, buffer))
    }

    fn fstatfs(&self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        if !self.io.open_files.contains_key(&fd) {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        }
        write_statfs(memory, request.arg(1))
    }

    fn truncate(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pathname = request.arg(0);
        let length = i64::from_ne_bytes(request.arg(1).to_ne_bytes());
        if length < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved = match self.resolve_at_path(LINUX_AT_FDCWD, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        }
        // Layered metadata (overlay/disk first, then rootfs) — not rootfs-only,
        // so guest-created files are seen too.
        let kind = match self.layered_metadata(&resolved) {
            Ok(md) => md.kind,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if kind == RootFsEntryKind::Directory {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EISDIR });
        }
        // Disk-backed: open the real file and ftruncate it. The whole rootfs
        // is materialised on the cap-std scratch under --fs host, so this
        // works for both rootfs and guest-created files. MemoryBackend has no
        // raw fd → EROFS (path-based truncate stays unsupported in-memory).
        match self.fs.rootfs_vfs.overlay.open_raw_fd(&resolved, true, false, false) {
            Some(host_fd) => {
                let rc = unsafe { libc::ftruncate(host_fd, length as libc::off_t) };
                let err = if rc < 0 { host_errno() } else { 0 };
                unsafe { libc::close(host_fd) };
                if err != 0 {
                    Ok(DispatchOutcome::Errno { errno: err })
                } else {
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
            }
            None => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
        }
    }

    pub(super) fn fallocate<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let mode = ctx.arg(1);
        let offset = i64::from_ne_bytes(ctx.arg(2).to_ne_bytes());
        let length = i64::from_ne_bytes(ctx.arg(3).to_ne_bytes());
        if mode & !LINUX_FALLOC_FL_SUPPORTED != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if length <= 0 || offset < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if is_stdio_fd(fd) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ESPIPE,
            });
        }
        let Some(open_file) = self.io.open_files.get(&fd).cloned() else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        // Only mode-0 (default allocation) is implemented as a real grow;
        // FALLOC_FL_KEEP_SIZE preallocates without changing the apparent
        // size, which on a tmpfs/host-backed file is a no-op success.
        let grow = mode & LINUX_FALLOC_FL_KEEP_SIZE == 0;
        let new_size = (offset as u64).saturating_add(length as u64);
        // Snapshot the writeback path/contents in a scope so the borrow
        // drops before we touch self.fs.rootfs_vfs.overlay (mirrors ftruncate).
        let writeback: Option<(String, Vec<u8>)>;
        let outcome: DispatchOutcome;
        {
            let mut open = open_file.description.borrow_mut();
            match &mut *open {
                OpenDescription::File {
                    contents, metadata, ..
                } if grow => {
                    // In-memory model (--fs memory): grow the cached bytes.
                    if new_size as usize > contents.len() {
                        contents.resize(new_size as usize, 0);
                        metadata.size = contents.len();
                    }
                    writeback = None;
                    outcome = DispatchOutcome::Returned { value: 0 };
                }
                OpenDescription::File { .. } => {
                    // KEEP_SIZE: don't change apparent size.
                    writeback = None;
                    outcome = DispatchOutcome::Returned { value: 0 };
                }
                OpenDescription::HostFile { host_fd, .. } => {
                    // Real fd into the cap-std scratch: grow with ftruncate
                    // (the change is visible across fork). KEEP_SIZE → no-op.
                    if grow {
                        let mut st: libc::stat = unsafe { core::mem::zeroed() };
                        if unsafe { libc::fstat(*host_fd, &mut st) } < 0 {
                            return Ok(DispatchOutcome::Errno { errno: host_errno() });
                        }
                        if new_size > st.st_size as u64 {
                            let r =
                                unsafe { libc::ftruncate(*host_fd, new_size as libc::off_t) };
                            if r < 0 {
                                return Ok(DispatchOutcome::Errno { errno: host_errno() });
                            }
                        }
                    }
                    writeback = None;
                    outcome = DispatchOutcome::Returned { value: 0 };
                }
                OpenDescription::SyntheticFile { .. } => {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
                }
                OpenDescription::Directory { .. } => {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EISDIR });
                }
                _ => return Ok(DispatchOutcome::Errno { errno: LINUX_ESPIPE }),
            }
        }
        if let Some((path, contents)) = writeback {
            let _ = self.fs.rootfs_vfs.overlay.set_file_contents(&path, contents);
        }
        Ok(outcome)
    }

    pub(super) fn ftruncate<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let length = i64::from_ne_bytes(ctx.arg(1).to_ne_bytes());
        if length < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if is_stdio_fd(fd) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let Some(open_file) = self.io.open_files.get(&fd).cloned() else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        // Snapshot the path + new contents in a scope so the borrow drops
        // before we touch self.fs.rootfs_vfs.overlay.
        let writeback: Option<(String, Vec<u8>)>;
        let outcome: DispatchOutcome;
        {
            let mut open = open_file.description.borrow_mut();
            match &mut *open {
                OpenDescription::File {
                    path,
                    contents,
                    offset,
                    writable,
                    metadata,
                    ..
                } => {
                    if !*writable {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                    }
                    let new_len = length as usize;
                    if new_len > contents.len() {
                        contents.resize(new_len, 0);
                    } else {
                        contents.truncate(new_len);
                        if *offset > new_len {
                            *offset = new_len;
                        }
                    }
                    metadata.size = contents.len();
                    writeback = Some((path.clone(), contents.clone()));
                    outcome = DispatchOutcome::Returned { value: 0 };
                }
                OpenDescription::HostFile {
                    host_fd, writable, ..
                } => {
                    if !*writable {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                    }
                    // Real fd: ftruncate the kernel file directly (the
                    // change is visible across fork).
                    let r = unsafe { libc::ftruncate(*host_fd, length as libc::off_t) };
                    if r < 0 {
                        return Ok(DispatchOutcome::Errno { errno: host_errno() });
                    }
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                OpenDescription::SyntheticFile { .. } => {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                }
                OpenDescription::Directory { .. } => {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EISDIR });
                }
                _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL }),
            }
        }
        if let Some((path, contents)) = writeback {
            let _ = self.fs.rootfs_vfs.overlay.set_file_contents(&path, contents);
        }
        Ok(outcome)
    }

    pub(super) fn openat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let flags = ctx.arg(2);
        self.open_at_path(dirfd, pathname, flags, &*ctx.memory, ctx.reporter)
    }

    pub(super) fn openat2<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let how_address = ctx.arg(2);
        let size = ctx.arg(3);
        let arg0 = ctx.arg(0);
        let arg1 = ctx.arg(1);
        if size != LINUX_OPEN_HOW_SIZE {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let how = match read_open_how(&*ctx.memory, how_address) {
            Ok(how) => how,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if how.mode != 0
            || how.resolve != 0
            || how.flags & !(LINUX_O_CLOEXEC | LINUX_O_NONBLOCK) != 0
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        self.open_at_path(arg0, arg1, how.flags, &*ctx.memory, ctx.reporter)
    }

    fn open_at_path(
        &mut self,
        dirfd: u64,
        pathname: u64,
        flags: u64,
        memory: &impl GuestMemory,
        reporter: &mut CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        let access = flags & LINUX_O_ACCMODE;
        if access != LINUX_O_RDONLY && access != LINUX_O_WRONLY && access != LINUX_O_RDWR {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let writable_request = access == LINUX_O_WRONLY || access == LINUX_O_RDWR;
        let want_create = flags & LINUX_O_CREAT != 0;
        let want_excl = flags & LINUX_O_EXCL != 0;
        let want_trunc = flags & LINUX_O_TRUNC != 0;

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        // VFS-mount routing. DevVfs serves /dev/*, ProcVfs serves
        // /proc/*, SysVfs serves /sys/*. The dispatcher converts each
        // VfsHandle variant into the matching OpenDescription, then
        // falls back to the legacy synthetic-then-overlay-then-rootfs
        // chain for any path no mount claims (or that the mount
        // returns ENOSYS for).
        let vfs_outcome = self.try_vfs_open(&path, access, flags);
        match vfs_outcome {
            VfsOpenAttempt::Installed(fd) => {
                return Ok(DispatchOutcome::Returned { value: fd as i64 });
            }
            VfsOpenAttempt::Errno(errno) => {
                return Ok(DispatchOutcome::Errno { errno });
            }
            VfsOpenAttempt::FallThrough => {}
        }

        // /proc/* and /sys/* synthetic file opens now flow through
        // ProcVfs / SysVfs (mounted in `SyscallDispatcher::new`). Any
        // unknown /proc or /sys path returns ENOSYS from the mount
        // and falls through to the overlay+rootfs lookup below, which
        // handles directory entries like /proc itself.

        if let Some(outcome) = Self::record_unimplemented_virtual_file(reporter, &path) {
            return Ok(outcome);
        }
        // Layered overlay+rootfs lookup with full openat semantics
        // (O_CREAT/O_EXCL/O_TRUNC, write-promotion of rootfs-only
        // files) lives in RootFsVfs::open_for_dispatch.
        let dispatch_result = self.fs.rootfs_vfs.open_for_dispatch(
            &path,
            want_create,
            want_excl,
            want_trunc,
            writable_request,
        );
        // USDT probe: every guest path-level open, with the resolved
        // path string and resulting size/errno. Lets dtrace operators
        // see exactly what bytes each forked carrick process is
        // serving for paths like /etc/hosts during the apt-resolver
        // run.
        match &dispatch_result {
            Ok(crate::vfs::rootfs::OpenDispatchResult::File { contents, .. }) => {
                crate::probes::path_open(&path, contents.len() as u64, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile { metadata, .. }) => {
                crate::probes::path_open(&path, metadata.size as u64, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::Directory { .. }) => {
                crate::probes::path_open(&path, 0, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::NotFoundCreate) => {
                crate::probes::path_open(&path, 0, 0);
            }
            Err(errno) => {
                crate::probes::path_open(&path, 0, *errno);
            }
        }
        let description = match dispatch_result {
            Ok(crate::vfs::rootfs::OpenDispatchResult::File {
                metadata,
                contents,
                writable,
            }) => OpenDescription::File {
                path,
                metadata,
                contents,
                offset: 0,
                status_flags: flags & !LINUX_O_CLOEXEC,
                writable,
            },
            Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile {
                host_fd,
                metadata,
                writable,
            }) => OpenDescription::HostFile {
                host_fd,
                metadata,
                status_flags: flags & !LINUX_O_CLOEXEC,
                writable,
            },
            Ok(crate::vfs::rootfs::OpenDispatchResult::Directory { metadata, entries }) => {
                if writable_request {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EISDIR });
                }
                OpenDescription::Directory {
                    path,
                    metadata,
                    entries,
                    offset: 0,
                    status_flags: flags & !LINUX_O_CLOEXEC,
                }
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::NotFoundCreate) => {
                // O_CREAT path: validate the parent directory exists,
                // create the empty overlay entry, return a writable
                // File description.
                if let Some(parent) = Path::new(&path).parent() {
                    let parent_str = display_rootfs_path(parent);
                    if !self.path_is_directory(&parent_str) {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_ENOENT });
                    }
                }
                let metadata = RootFsMetadata {
                    path: Path::new(&path).to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: 0o644,
                    size: 0,
                };
                // Disk-backed overlay (--fs host): create + open a real
                // host fd so the new file is fork-shareable. Falls back
                // to the in-memory File for MemoryBackend.
                if let Some(host_fd) =
                    self.fs.rootfs_vfs.overlay.open_raw_fd(&path, true, true, want_trunc)
                {
                    OpenDescription::HostFile {
                        host_fd,
                        metadata,
                        status_flags: flags & !LINUX_O_CLOEXEC,
                        writable: true,
                    }
                } else {
                    if self.fs.rootfs_vfs.overlay.create_file(&path).is_err() {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL });
                    }
                    OpenDescription::File {
                        path,
                        metadata,
                        contents: Vec::new(),
                        offset: 0,
                        status_flags: flags & !LINUX_O_CLOEXEC,
                        writable: writable_request || want_create,
                    }
                }
            }
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        let Some(fd) = self.allocate_fd(3) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        self.insert_open_file(
            fd,
            OpenFile {
                description: Rc::new(RefCell::new(description)),
                fd_flags: linux_fd_flags_from_open_flags(flags),
            },
        );
        Ok(DispatchOutcome::Returned { value: fd as i64 })
    }

    /// Layered "is this a directory?" probe used by mkdirat / openat
    /// (O_CREAT) parent-existence checks. The synthetic /proc and
    /// /sys roots count as directories so that
    /// `mkdir("/proc/.tmp-XYZ")` can be detected as EEXIST rather
    /// than the wrong errno.
    fn path_is_directory(&self, path: &str) -> bool {
        if path == "/" || path.is_empty() {
            return true;
        }
        match self.fs.rootfs_vfs.overlay.lookup(path) {
            Some(OverlayEntry::Dir) => return true,
            Some(OverlayEntry::Deleted) | Some(OverlayEntry::File(_)) => return false,
            None => {}
        }
        if let Some(rootfs) = &self.fs.rootfs_vfs.rootfs {
            if let Ok(metadata) = rootfs.metadata(path) {
                return metadata.kind == RootFsEntryKind::Directory;
            }
        }
        false
    }

    /// Layered metadata probe. Mirrors the rootfs-or-synthetic chain
    /// used by stat / faccessat sites, but consults the overlay first
    /// and respects deletions.
    fn layered_metadata(&self, path: &str) -> Result<RootFsMetadata, i32> {
        use crate::vfs::Vfs as _;
        self.fs.rootfs_vfs
            .lookup(path)
            .map(|md| vfs_md_to_rootfs_md(path, &md))
    }

    pub(super) fn close<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        Ok(if let Some(open_file) = self.io.open_files.remove(&fd) {
            close_open_file(&open_file);
            DispatchOutcome::Returned { value: 0 }
        } else if is_stdio_fd(fd) {
            // Guest closing its own stdio at exit: there's nothing for
            // us to do (host fd stays open under stream_stdio so
            // sibling processes keep working), but reporting EBADF
            // here makes glibc print "write error: Bad file descriptor"
            // after the program's real output. Return success.
            DispatchOutcome::Returned { value: 0 }
        } else {
            DispatchOutcome::Errno { errno: LINUX_EBADF }
        })
    }

    /// `close_range(first, last, flags)` — close every fd in `[first, last]`
    /// (inclusive). Used by glibc's posix_spawn / apt's pre-fork cleanup
    /// to drop inherited fds in O(1) syscalls instead of an O(N) fcntl
    /// or close loop. Without this, apt walks fd 3..NR_OPEN issuing a
    /// fcntl per fd and burns 100k+ traps before exec.
    pub(super) fn close_range<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let first = ctx.arg(0);
        let last = ctx.arg(1);
        let flags = ctx.arg(2);
        // CLOSE_RANGE_UNSHARE=2 is a no-op for us (single fd table);
        // CLOSE_RANGE_CLOEXEC=4 would mark fds CLOEXEC instead of
        // closing — accept the bit and apply CLOEXEC.
        const CLOSE_RANGE_UNSHARE: u64 = 2;
        const CLOSE_RANGE_CLOEXEC: u64 = 4;
        if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 || first > last {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL });
        }
        let cloexec_only = flags & CLOSE_RANGE_CLOEXEC != 0;
        // Drain matching fds out of the table so we don't iterate a
        // gigantic [first, last] (callers commonly pass last=u32::MAX).
        let fds: Vec<i32> = self.io
            .open_files
            .keys()
            .copied()
            .filter(|fd| (*fd as u64) >= first && (*fd as u64) <= last)
            .collect();
        for fd in fds {
            if cloexec_only {
                if let Some(open_file) = self.io.open_files.get_mut(&fd) {
                    open_file.fd_flags |= LINUX_FD_CLOEXEC;
                }
            } else if let Some(open_file) = self.io.open_files.remove(&fd) {
                close_open_file(&open_file);
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn duplicate_fd(&mut self, old_fd: i32, min_fd: i32, fd_flags: u64) -> DispatchOutcome {
        let description = match self.io.open_files.get(&old_fd) {
            Some(open_file) => Rc::clone(&open_file.description),
            None if is_stdio_fd(old_fd) => {
                // dup/fcntl(F_DUPFD) of the process's bare stdio fds:
                // mirror what dup3 does and grab the host fd into a
                // HostPipe so future reads/writes still hit the right
                // host endpoint (this is what dpkg-query needs at
                // startup to redirect its diagnostic fd, and what most
                // glibc fork+exec helpers expect to succeed).
                let duped = unsafe { libc::dup(old_fd) };
                if duped < 0 {
                    return DispatchOutcome::Errno {
                        errno: host_errno(),
                    };
                }
                Rc::new(RefCell::new(OpenDescription::HostPipe {
                    host_fd: duped,
                    is_read_end: old_fd == 0,
                    status_flags: 0,
                }))
            }
            None => return DispatchOutcome::Errno { errno: LINUX_EBADF },
        };
        let Some(new_fd) = self.allocate_fd(min_fd) else {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        retain_open_file(&description);
        self.io.open_files.insert(
            new_fd,
            OpenFile {
                description,
                fd_flags,
            },
        );
        DispatchOutcome::Returned {
            value: new_fd as i64,
        }
    }

    /// Try to satisfy an open via the VFS mount table. Returns
    /// `Installed(fd)` when a mount handled it, `Errno(e)` when a
    /// mount explicitly failed, and `FallThrough` when no mount
    /// claimed the path (or the claiming mount returned ENOSYS). The
    /// caller wraps the legacy lookup chain inside `FallThrough`.
    fn try_vfs_open(&mut self, path: &str, access: u64, flags: u64) -> VfsOpenAttempt {
        // Build the OpenContext from owned/copy data so the mut
        // borrow of `vfs_mounts` doesn't conflict with reads from
        // sibling fields.
        let exec_path = self.proc.executable_path.clone();
        let addr_regions = self.mem.address_space_regions.clone();
        let brk = self.mem.brk_current;
        let mmap = self.mem.mmap_next;
        let ctx = crate::vfs::OpenContext {
            executable_path: Some(exec_path.as_str()),
            address_space_regions: addr_regions.as_deref(),
            brk_current: brk,
            mmap_next: mmap,
        };
        let vfs_flags = crate::vfs::OpenFlags {
            read: matches!(access, LINUX_O_RDONLY | LINUX_O_RDWR),
            write: matches!(access, LINUX_O_WRONLY | LINUX_O_RDWR),
            nonblock: flags & LINUX_O_NONBLOCK != 0,
            cloexec: flags & LINUX_O_CLOEXEC != 0,
            append: flags & LINUX_O_APPEND != 0,
            trunc: flags & LINUX_O_TRUNC != 0,
            create: flags & LINUX_O_CREAT != 0,
            excl: flags & LINUX_O_EXCL != 0,
            directory: flags & LINUX_O_DIRECTORY != 0,
            nofollow: flags & 0o400000 != 0,
            mode: 0,
        };
        let handle = {
            let Some(m) = self.fs.vfs_mounts.resolve_mut(path) else {
                return VfsOpenAttempt::FallThrough;
            };
            match m.vfs.open(&m.full_path, vfs_flags, &ctx) {
                Ok(h) => h,
                Err(errno) if errno == LINUX_ENOSYS => {
                    return VfsOpenAttempt::FallThrough;
                }
                Err(errno) => {
                    return VfsOpenAttempt::Errno(errno);
                }
            }
        };
        match handle {
            crate::vfs::VfsHandle::HostFd {
                host_fd,
                is_read_end,
                status_flags,
            } => {
                let new_fd = match self.allocate_fd(3) {
                    Some(fd) => fd,
                    None => {
                        unsafe { libc::close(host_fd) };
                        return VfsOpenAttempt::Errno(linux_errno::EMFILE);
                    }
                };
                self.insert_open_file(
                    new_fd,
                    OpenFile {
                        description: Rc::new(RefCell::new(OpenDescription::HostPipe {
                            host_fd,
                            is_read_end,
                            status_flags: status_flags as u64,
                        })),
                        fd_flags: linux_fd_flags_from_open_flags(flags),
                    },
                );
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::Bytes {
                path,
                contents,
                status_flags,
            } => {
                let new_fd = match self.allocate_fd(3) {
                    Some(fd) => fd,
                    None => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                self.insert_open_file(
                    new_fd,
                    OpenFile {
                        description: Rc::new(RefCell::new(OpenDescription::SyntheticFile {
                            path,
                            contents,
                            offset: 0,
                            status_flags: ((status_flags as u64) | flags) & !LINUX_O_CLOEXEC,
                        })),
                        fd_flags: linux_fd_flags_from_open_flags(flags),
                    },
                );
                VfsOpenAttempt::Installed(new_fd)
            }
        }
    }

    pub(super) fn allocate_fd(&mut self, min_fd: i32) -> Option<i32> {
        let mut fd = min_fd.max(3);
        while self.io.open_files.contains_key(&fd) {
            fd = fd.checked_add(1)?;
        }
        self.io.next_fd = self.io.next_fd.max(fd.saturating_add(1));
        Some(fd)
    }

    pub(super) fn insert_open_file(&mut self, fd: i32, open_file: OpenFile) {
        retain_open_file(&open_file.description);
        if let Some(replaced) = self.io.open_files.insert(fd, open_file) {
            close_open_file(&replaced);
        }
    }

    pub(super) fn install_fd(&mut self, description: OpenDescription, fd_flags: u64) -> DispatchOutcome {
        let Some(fd) = self.allocate_fd(3) else {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        self.insert_open_file(
            fd,
            OpenFile {
                description: Rc::new(RefCell::new(description)),
                fd_flags,
            },
        );
        DispatchOutcome::Returned { value: fd as i64 }
    }

    pub(super) fn getdents64<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let address = ctx.arg(1);
        let length = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let memory = &mut *ctx.memory;
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let mut open = open_file.description.borrow_mut();
        let OpenDescription::Directory {
            entries, offset, ..
        } = &mut *open
        else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };

        let mut out = Vec::new();
        while *offset < entries.len() {
            let record = dirent64_record(&entries[*offset], *offset + 1);
            if record.len() > length {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            if out.len() + record.len() > length {
                break;
            }
            out.extend_from_slice(&record);
            *offset += 1;
        }

        if memory.write_bytes(address, &out).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }

        Ok(DispatchOutcome::Returned {
            value: out.len() as i64,
        })
    }

    pub(super) fn lseek<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let offset = ctx.arg(1) as i64;
        let whence = ctx.arg(2);
        let Some(open_file) = self.io.open_files.get(&fd) else {
            // lseek on stdio with no OpenDescription is, on Linux, a
            // valid call on an unseekable pipe/tty — kernel returns
            // ESPIPE, not EBADF. Returning EBADF confuses glibc's
            // ftell/fclose path into reporting "write error: Bad
            // file descriptor" after every successful write.
            if is_stdio_fd(fd) {
                return Ok(DispatchOutcome::Errno { errno: LINUX_ESPIPE });
            }
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let mut open = open_file.description.borrow_mut();

        // HostFile: the kernel owns the offset — delegate straight to
        // libc::lseek on the real fd.
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            let host_whence = match whence {
                LINUX_SEEK_SET => libc::SEEK_SET,
                LINUX_SEEK_CUR => libc::SEEK_CUR,
                LINUX_SEEK_END => libc::SEEK_END,
                _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL }),
            };
            let r = unsafe { libc::lseek(*host_fd, offset as libc::off_t, host_whence) };
            if r < 0 {
                return Ok(DispatchOutcome::Errno { errno: host_errno() });
            }
            return Ok(DispatchOutcome::Returned { value: r as i64 });
        }

        let (current, end) = match &*open {
            OpenDescription::File {
                contents, offset, ..
            }
            | OpenDescription::SyntheticFile {
                contents, offset, ..
            } => (*offset as i64, contents.len() as i64),
            OpenDescription::Directory {
                entries, offset, ..
            } => (*offset as i64, entries.len() as i64),
            // Linux returns ESPIPE for lseek on a pipe / socket / tty
            // (the kernel's POSIX answer for "unseekable stream") and
            // EINVAL only for nonsensical arg combinations. Returning
            // EINVAL here made dpkg-query's ftell() retry-loop spin
            // forever because POSIX says "EINVAL is recoverable" while
            // ESPIPE means "give up, it's a stream".
            OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Netlink { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ESPIPE,
                });
            }
            // HostFile is handled by the early libc::lseek above.
            OpenDescription::HostFile { .. } => unreachable!("HostFile lseek handled above"),
            OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        };
        let next = match whence {
            LINUX_SEEK_SET => offset,
            LINUX_SEEK_CUR => current.saturating_add(offset),
            LINUX_SEEK_END => end.saturating_add(offset),
            _ => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        };
        if next < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        match &mut *open {
            OpenDescription::File { offset, .. }
            | OpenDescription::Directory { offset, .. }
            | OpenDescription::SyntheticFile { offset, .. } => *offset = next as usize,
            OpenDescription::HostFile { .. } => unreachable!("HostFile lseek handled above"),
            OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Netlink { .. } => {}
        }
        Ok(DispatchOutcome::Returned { value: next })
    }

    pub(super) fn read<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let address = ctx.arg(1);
        let length = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let memory = &mut *ctx.memory;
        // fd 0 with no explicit OpenDescription: read from host stdin.
        // This is what makes `read` against the guest's stdin pick up
        // input from the user's terminal (or whatever the carrick host
        // process's stdin is — file, pipe, or terminal).
        if fd == 0 && !self.io.open_files.contains_key(&0) {
            return Ok(read_host_pipe(memory, address, length, 0));
        }
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let mut open = open_file.description.borrow_mut();
        let (contents, offset) = match &mut *open {
            OpenDescription::File {
                contents, offset, ..
            }
            | OpenDescription::SyntheticFile {
                contents, offset, ..
            } => (contents, offset),
            OpenDescription::EventFd {
                counter, semaphore, ..
            } => return Ok(read_eventfd(memory, address, length, counter, *semaphore)),
            OpenDescription::TimerFd {
                clock_id,
                interval,
                deadline,
                expirations,
                status_flags,
            } => {
                let nonblocking = *status_flags & LINUX_TFD_NONBLOCK != 0;
                return Ok(read_timerfd(
                    memory,
                    address,
                    length,
                    *clock_id,
                    interval,
                    deadline,
                    expirations,
                    nonblocking,
                ));
            }
            OpenDescription::PipeReader { pipe, status_flags } => {
                return Ok(read_pipe(memory, address, length, pipe, *status_flags));
            }
            OpenDescription::HostPipe {
                host_fd,
                is_read_end,
                ..
            } => {
                if !*is_read_end {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                }
                return Ok(read_host_pipe(memory, address, length, *host_fd));
            }
            OpenDescription::Directory { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EISDIR,
                });
            }
            OpenDescription::Epoll { .. } | OpenDescription::PipeWriter { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            OpenDescription::HostSocket { host_fd, .. } => {
                return Ok(read_host_pipe(memory, address, length, *host_fd));
            }
            // Netlink: drain whatever a prior dump request queued. A bare
            // read(2) is rare on netlink sockets (recvmsg is the norm), but
            // model it as draining the synthetic response so it doesn't
            // wedge a caller.
            OpenDescription::Netlink { recv_queue, .. } => {
                return Ok(net::drain_netlink_queue(memory, address, length, recv_queue));
            }
            // Real host file: libc::read advances the kernel offset
            // (shared across fork). read_host_pipe is just a
            // memory-into-guest read(2) wrapper.
            OpenDescription::HostFile { host_fd, .. } => {
                return Ok(read_host_pipe(memory, address, length, *host_fd));
            }
        };
        let remaining = &contents[*offset..];
        let read_len = remaining.len().min(length);
        let bytes = &remaining[..read_len];
        if memory.write_bytes(address, bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        *offset += read_len;
        Ok(DispatchOutcome::Returned {
            value: read_len as i64,
        })
    }

    pub(super) fn readv<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let iov = ctx.arg(1);
        let iovcnt = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let memory = &mut *ctx.memory;
        let iovecs = match read_iovecs(memory, iov, iovcnt) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let mut open = open_file.description.borrow_mut();
        // Real host file: readv via the kernel fd (advances the shared
        // offset). Fill each iovec sequentially.
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            let hfd = *host_fd;
            let mut total = 0i64;
            for iov in &iovecs {
                let len = usize::try_from(iov.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                if len == 0 {
                    continue;
                }
                match read_host_pipe(memory, iov.iov_base, len, hfd) {
                    DispatchOutcome::Returned { value } => {
                        total += value;
                        if (value as usize) < len {
                            break;
                        }
                    }
                    other => return Ok(other),
                }
            }
            return Ok(DispatchOutcome::Returned { value: total });
        }
        let (contents, offset) = match &mut *open {
            OpenDescription::File {
                contents, offset, ..
            }
            | OpenDescription::SyntheticFile {
                contents, offset, ..
            } => (contents, offset),
            OpenDescription::HostFile { .. } => unreachable!("HostFile readv handled above"),
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Netlink { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        };
        let read_len = read_from_contents_at(memory, contents, *offset, &iovecs)?;
        *offset += read_len;
        Ok(DispatchOutcome::Returned {
            value: read_len as i64,
        })
    }

    pub(super) fn pread64<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let buffer = ctx.arg(1);
        let length = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let offset = usize::try_from(ctx.arg(3))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(3)))?;
        let memory = &mut *ctx.memory;
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        // Real host file: positional read via libc::pread (doesn't
        // disturb the shared kernel offset).
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            let mut buf = vec![0u8; length];
            let n = unsafe {
                libc::pread(*host_fd, buf.as_mut_ptr() as *mut _, length, offset as libc::off_t)
            };
            if n < 0 {
                return Ok(DispatchOutcome::Errno { errno: host_errno() });
            }
            let n = n as usize;
            if n > 0 && memory.write_bytes(buffer, &buf[..n]).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
            return Ok(DispatchOutcome::Returned { value: n as i64 });
        }
        let contents = match &*open {
            OpenDescription::File { contents, .. }
            | OpenDescription::SyntheticFile { contents, .. } => contents,
            OpenDescription::HostFile { .. } => unreachable!("HostFile pread handled above"),
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Netlink { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        };

        let read_len = if offset < contents.len() {
            let bytes = &contents[offset..][..contents[offset..].len().min(length)];
            if memory.write_bytes(buffer, bytes).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
            bytes.len()
        } else {
            0
        };
        Ok(DispatchOutcome::Returned {
            value: read_len as i64,
        })
    }

    pub(super) fn preadv<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let iov = ctx.arg(1);
        let iovcnt = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let offset = usize::try_from(ctx.arg(3))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(3)))?;
        let memory = &mut *ctx.memory;
        let iovecs = match read_iovecs(memory, iov, iovcnt) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        // Real host file: positional readv via libc::pread per iovec
        // (kernel offset untouched).
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            let hfd = *host_fd;
            let mut total = 0i64;
            let mut cur = offset;
            for iov in &iovecs {
                let len = usize::try_from(iov.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                if len == 0 {
                    continue;
                }
                let mut buf = vec![0u8; len];
                let n = unsafe {
                    libc::pread(hfd, buf.as_mut_ptr() as *mut _, len, cur as libc::off_t)
                };
                if n < 0 {
                    return Ok(DispatchOutcome::Errno { errno: host_errno() });
                }
                let n = n as usize;
                if n > 0 && memory.write_bytes(iov.iov_base, &buf[..n]).is_err() {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
                }
                total += n as i64;
                cur += n;
                if n < len {
                    break;
                }
            }
            return Ok(DispatchOutcome::Returned { value: total });
        }
        let contents = match &*open {
            OpenDescription::File { contents, .. }
            | OpenDescription::SyntheticFile { contents, .. } => contents,
            OpenDescription::HostFile { .. } => unreachable!("HostFile preadv handled above"),
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Netlink { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        };
        let read_len = read_from_contents_at(memory, contents, offset, &iovecs)?;
        Ok(DispatchOutcome::Returned {
            value: read_len as i64,
        })
    }

    pub(super) fn pwrite64<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let address = ctx.arg(1);
        let length = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let offset = i64::from_ne_bytes(ctx.arg(3).to_ne_bytes());
        if offset < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let bytes = match (&*ctx.memory).read_bytes(address, length) {
            Ok(b) => b,
            Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
        };
        if is_stdio_fd(fd) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ESPIPE,
            });
        }
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        // Real host file: positional write via libc::pwrite (visible
        // across fork; kernel offset untouched).
        if let OpenDescription::HostFile { host_fd, writable, .. } = &*open {
            if !*writable {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            let n = unsafe {
                libc::pwrite(*host_fd, bytes.as_ptr() as *const _, length, offset as libc::off_t)
            };
            if n < 0 {
                return Ok(DispatchOutcome::Errno { errno: host_errno() });
            }
            return Ok(DispatchOutcome::Returned { value: n as i64 });
        }
        let errno = match &*open {
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
            OpenDescription::HostFile { .. } => unreachable!("handled above"),
            OpenDescription::Directory { .. } => LINUX_EISDIR,
            OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Netlink { .. }
            | OpenDescription::Epoll { .. } => LINUX_ESPIPE,
        };
        Ok(DispatchOutcome::Errno { errno })
    }

    pub(super) fn pwritev<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let iov = ctx.arg(1);
        let iovcnt = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let offset = i64::from_ne_bytes(ctx.arg(3).to_ne_bytes());
        let memory = &*ctx.memory;
        let iovecs = match read_iovecs(memory, iov, iovcnt) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if offset < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        for iovec in &iovecs {
            let iov_len = usize::try_from(iovec.iov_len)
                .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
            if memory.read_bytes(iovec.iov_base, iov_len).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }
        if is_stdio_fd(fd) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ESPIPE,
            });
        }
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        // Real host file: positional writev via libc::pwrite per iovec.
        if let OpenDescription::HostFile { host_fd, writable, .. } = &*open {
            if !*writable {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            let hfd = *host_fd;
            let mut total = 0i64;
            let mut cur = offset;
            for iov in &iovecs {
                let len = usize::try_from(iov.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                if len == 0 {
                    continue;
                }
                let buf = match memory.read_bytes(iov.iov_base, len) {
                    Ok(b) => b,
                    Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
                };
                let n = unsafe {
                    libc::pwrite(hfd, buf.as_ptr() as *const _, len, cur as libc::off_t)
                };
                if n < 0 {
                    return Ok(DispatchOutcome::Errno { errno: host_errno() });
                }
                total += n as i64;
                cur += n as i64;
                if (n as usize) < len {
                    break;
                }
            }
            return Ok(DispatchOutcome::Returned { value: total });
        }
        let errno = match &*open {
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
            OpenDescription::HostFile { .. } => unreachable!("handled above"),
            OpenDescription::Directory { .. } => LINUX_EISDIR,
            OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Netlink { .. }
            | OpenDescription::Epoll { .. } => LINUX_ESPIPE,
        };
        Ok(DispatchOutcome::Errno { errno })
    }

    pub(super) fn sendfile<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let out_fd = ctx.arg(0) as i32;
        let in_fd = ctx.arg(1) as i32;
        let offset_address = ctx.arg(2);
        let count = usize::try_from(ctx.arg(3))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(3)))?;
        let memory = &mut *ctx.memory;
        if count == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        let mut offset = match self.sendfile_offset(in_fd, offset_address, memory)? {
            Ok(offset) => offset,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let bytes = match self.sendfile_bytes(in_fd, offset, count) {
            Ok(bytes) => bytes,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let outcome = self.write_output_fd(out_fd, &bytes);
        let DispatchOutcome::Returned { value } = outcome else {
            return Ok(outcome);
        };
        let written = usize::try_from(value).unwrap_or(0);
        offset = offset.saturating_add(written);
        if offset_address == 0 {
            if let Some(open_file) = self.io.open_files.get(&in_fd) {
                let mut open = open_file.description.borrow_mut();
                match &mut *open {
                    OpenDescription::File {
                        offset: current, ..
                    }
                    | OpenDescription::SyntheticFile {
                        offset: current, ..
                    } => *current = offset,
                    _ => {}
                }
            }
        } else if memory
            .write_bytes(offset_address, &(offset as u64).to_ne_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }

        Ok(DispatchOutcome::Returned { value })
    }

    /// copy_file_range(2): like sendfile but file-to-file with independent
    /// in/out offset pointers. coreutils `cat`/`cp` and apt/dpkg use it for
    /// efficient copies; it was unimplemented and the panic-on-unknown guard
    /// turned that into a hard abort. We read from in_fd at its (pointer or
    /// current) offset and write to out_fd, reusing the sendfile machinery.
    pub(super) fn copy_file_range<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let in_fd = ctx.arg(0) as i32;
        let off_in_addr = ctx.arg(1);
        let out_fd = ctx.arg(2) as i32;
        let off_out_addr = ctx.arg(3);
        // Callers (coreutils `cat`) pass len = SSIZE_MAX and loop until EOF,
        // so cap each call to a bounded chunk rather than trying to allocate
        // a multi-exabyte buffer. A short return is legal for copy_file_range.
        let requested = usize::try_from(ctx.arg(4)).unwrap_or(usize::MAX);
        let memory = &mut *ctx.memory;
        let count = requested.min(8 * 1024 * 1024);
        if count == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        let in_offset = match self.sendfile_offset(in_fd, off_in_addr, memory)? {
            Ok(o) => o,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let bytes = match self.sendfile_bytes(in_fd, in_offset, count) {
            Ok(b) => b,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if bytes.is_empty() {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        // Write side. off_out == NULL → write at out_fd's current position
        // (the common case: cat to a pipe/stdout). Non-NULL → pwrite at the
        // given offset on a real host fd and advance *off_out.
        let written = if off_out_addr == 0 {
            let outcome = self.write_output_fd(out_fd, &bytes);
            let DispatchOutcome::Returned { value } = outcome else {
                return Ok(outcome);
            };
            usize::try_from(value).unwrap_or(0)
        } else {
            let out_off = match read_u64(memory, off_out_addr) {
                Ok(v) => v,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            let host_fd = match self.io.open_files.get(&out_fd) {
                Some(of) => match &*of.description.borrow() {
                    OpenDescription::HostFile { host_fd, writable: true, .. } => *host_fd,
                    OpenDescription::HostFile { .. } => {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF })
                    }
                    _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL }),
                },
                None => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
            };
            let n = unsafe {
                libc::pwrite(
                    host_fd,
                    bytes.as_ptr() as *const _,
                    bytes.len(),
                    out_off as libc::off_t,
                )
            };
            if n < 0 {
                return Ok(DispatchOutcome::Errno { errno: host_errno() });
            }
            let n = n as usize;
            if memory
                .write_bytes(off_out_addr, &(out_off + n as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
            n
        };

        // Advance the input offset (pointer or the fd's own position).
        let new_in = in_offset.saturating_add(written);
        if off_in_addr == 0 {
            if let Some(of) = self.io.open_files.get(&in_fd) {
                let mut open = of.description.borrow_mut();
                match &mut *open {
                    OpenDescription::File { offset, .. }
                    | OpenDescription::SyntheticFile { offset, .. } => *offset = new_in,
                    OpenDescription::HostFile { host_fd, .. } => {
                        unsafe { libc::lseek(*host_fd, new_in as libc::off_t, libc::SEEK_SET) };
                    }
                    _ => {}
                }
            }
        } else if memory
            .write_bytes(off_in_addr, &(new_in as u64).to_ne_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }

        Ok(DispatchOutcome::Returned {
            value: written as i64,
        })
    }

    fn sendfile_offset(
        &self,
        in_fd: i32,
        offset_address: u64,
        memory: &impl GuestMemory,
    ) -> Result<Result<usize, i32>, DispatchError> {
        if offset_address != 0 {
            return match read_u64(memory, offset_address) {
                Ok(offset) => {
                    Ok(Ok(usize::try_from(offset)
                        .map_err(|_| DispatchError::LengthTooLarge(offset))?))
                }
                Err(errno) => Ok(Err(errno)),
            };
        }
        let Some(in_file) = self.io.open_files.get(&in_fd) else {
            return Ok(Err(LINUX_EBADF));
        };
        let open = in_file.description.borrow();
        match &*open {
            OpenDescription::File { offset, .. }
            | OpenDescription::SyntheticFile { offset, .. } => Ok(Ok(*offset)),
            // HostFile: current offset is the kernel's; query via lseek.
            OpenDescription::HostFile { host_fd, .. } => {
                let cur = unsafe { libc::lseek(*host_fd, 0, libc::SEEK_CUR) };
                if cur < 0 {
                    Ok(Err(host_errno()))
                } else {
                    Ok(Ok(cur as usize))
                }
            }
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Netlink { .. } => Ok(Err(LINUX_EINVAL)),
        }
    }

    fn sendfile_bytes(&self, in_fd: i32, offset: usize, count: usize) -> Result<Vec<u8>, i32> {
        let Some(in_file) = self.io.open_files.get(&in_fd) else {
            return Err(LINUX_EBADF);
        };
        let open = in_file.description.borrow();
        // HostFile: pread the requested window from the real fd.
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            let mut buf = vec![0u8; count];
            let n = unsafe {
                libc::pread(*host_fd, buf.as_mut_ptr() as *mut _, count, offset as libc::off_t)
            };
            if n < 0 {
                return Err(host_errno());
            }
            buf.truncate(n as usize);
            return Ok(buf);
        }
        let contents = match &*open {
            OpenDescription::File { contents, .. }
            | OpenDescription::SyntheticFile { contents, .. } => contents,
            OpenDescription::HostFile { .. } => unreachable!("HostFile sendfile handled above"),
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Netlink { .. } => return Err(LINUX_EINVAL),
        };
        let available = contents.get(offset..).unwrap_or_default();
        let write_len = available.len().min(count);
        Ok(available[..write_len].to_vec())
    }

    pub(super) fn splice<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let in_fd = ctx.arg(0) as i32;
        let off_in_address = ctx.arg(1);
        let out_fd = ctx.arg(2) as i32;
        let off_out_address = ctx.arg(3);
        let count = usize::try_from(ctx.arg(4))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(4)))?;
        let flags = ctx.arg(5);
        let memory = &mut *ctx.memory;
        if flags & !LINUX_SPLICE_SUPPORTED_FLAGS != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if count == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        if let Some((pipe, status_flags)) = self.pipe_reader(in_fd) {
            if off_in_address != 0 || off_out_address != 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            if let Some(errno) = self.splice_output_errno(out_fd) {
                return Ok(DispatchOutcome::Errno { errno });
            }
            let bytes = match take_pipe_bytes(&pipe, count, status_flags) {
                Ok(bytes) => bytes,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            let outcome = self.write_output_fd(out_fd, &bytes);
            return Ok(outcome);
        }

        // Splice OUT of a real host pipe's read end (the fork-safe pipe model;
        // `pipe2`/`fcntl` now hand back HostPipe descriptions, so splice must
        // recognise them just like the legacy in-memory PipeReader above).
        if let Some(host_fd) = self.host_pipe_read_fd(in_fd) {
            if off_in_address != 0 || off_out_address != 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            if let Some(errno) = self.splice_output_errno(out_fd) {
                return Ok(DispatchOutcome::Errno { errno });
            }
            let mut buf = vec![0u8; count];
            let n = unsafe { libc::read(host_fd, buf.as_mut_ptr() as *mut _, count) };
            if n < 0 {
                return Ok(DispatchOutcome::Errno { errno: host_errno() });
            }
            buf.truncate(n as usize);
            let outcome = self.write_output_fd(out_fd, &buf);
            return Ok(outcome);
        }

        if off_out_address != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        match self.fd_is_pipe_writer(out_fd) {
            Ok(true) => {}
            Ok(false) => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        }

        let mut offset = match self.sendfile_offset(in_fd, off_in_address, memory)? {
            Ok(offset) => offset,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let bytes = match self.sendfile_bytes(in_fd, offset, count) {
            Ok(bytes) => bytes,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let outcome = self.write_output_fd(out_fd, &bytes);
        let DispatchOutcome::Returned { value } = outcome else {
            return Ok(outcome);
        };
        let written = usize::try_from(value).unwrap_or(0);
        offset = offset.saturating_add(written);
        if off_in_address == 0 {
            if let Some(open_file) = self.io.open_files.get(&in_fd) {
                let mut open = open_file.description.borrow_mut();
                match &mut *open {
                    OpenDescription::File {
                        offset: current, ..
                    }
                    | OpenDescription::SyntheticFile {
                        offset: current, ..
                    } => *current = offset,
                    _ => {}
                }
            }
        } else if memory
            .write_bytes(off_in_address, &(offset as u64).to_ne_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }

        Ok(DispatchOutcome::Returned { value })
    }

    fn pipe_reader(&self, fd: i32) -> Option<(Rc<RefCell<PipeState>>, u64)> {
        let open_file = self.io.open_files.get(&fd)?;
        let open = open_file.description.borrow();
        match &*open {
            OpenDescription::PipeReader { pipe, status_flags } => {
                Some((Rc::clone(pipe), *status_flags))
            }
            _ => None,
        }
    }

    fn fd_is_pipe_writer(&self, fd: i32) -> Result<bool, i32> {
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return if is_stdio_fd(fd) {
                Ok(false)
            } else {
                Err(LINUX_EBADF)
            };
        };
        let open = open_file.description.borrow();
        Ok(match &*open {
            OpenDescription::PipeWriter { .. } => true,
            // Real host pipe write end (fork-safe pipe model).
            OpenDescription::HostPipe { is_read_end, .. } => !*is_read_end,
            _ => false,
        })
    }

    /// The raw host fd backing `fd` if it is a [`OpenDescription::HostPipe`]
    /// read end, else `None`. Lets `splice` drain a real host pipe.
    fn host_pipe_read_fd(&self, fd: i32) -> Option<i32> {
        let open_file = self.io.open_files.get(&fd)?;
        let open = open_file.description.borrow();
        match &*open {
            OpenDescription::HostPipe {
                host_fd,
                is_read_end: true,
                ..
            } => Some(*host_fd),
            _ => None,
        }
    }

    fn splice_output_errno(&self, fd: i32) -> Option<i32> {
        if is_stdio_fd(fd) {
            return None;
        }
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return Some(LINUX_EBADF);
        };
        let open = open_file.description.borrow();
        match &*open {
            OpenDescription::PipeWriter { pipe, .. } => {
                if pipe.borrow().readers == 0 {
                    Some(LINUX_EPIPE)
                } else {
                    None
                }
            }
            // Real host pipe write end: the kernel enforces EPIPE itself on
            // write, so we just accept the destination here.
            OpenDescription::HostPipe {
                is_read_end: false,
                ..
            } => None,
            // Splicing FROM a pipe INTO a regular file is valid on Linux (only
            // ONE end must be a pipe). The write + offset advance is handled by
            // write_output_fd. A read-only fd is EBADF.
            OpenDescription::HostFile { writable: true, .. }
            | OpenDescription::File { writable: true, .. } => None,
            OpenDescription::HostFile { .. } | OpenDescription::File { .. } => {
                Some(LINUX_EBADF)
            }
            _ => Some(LINUX_EINVAL),
        }
    }

    pub(super) fn sync<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn syncfs<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }
        // Like sync/fdatasync: we don't model durable disk state, so a
        // successful flush is a no-op that returns 0.
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn xattr_unsupported(&self) -> DispatchOutcome {
        DispatchOutcome::Errno {
            errno: LINUX_ENOTSUP,
        }
    }

    /// Resolve the first argument of an xattr syscall to the rootfs path it
    /// names: a path string (path/lpath variants) or the path of the file an
    /// fd refers to (f-variant). Returns `Err(errno)` on a bad path or an fd
    /// that has no backing host file (e.g. the in-memory backend).
    fn xattr_target_path(
        &self,
        request: &SyscallRequest,
        memory: &impl GuestMemory,
        target: XattrTarget,
    ) -> Result<String, i32> {
        match target {
            XattrTarget::Path => {
                let path = read_guest_c_string(memory, request.arg(0))?;
                if path.is_empty() {
                    return Err(LINUX_ENOENT);
                }
                self.resolve_at_path(LINUX_AT_FDCWD, &path)
            }
            XattrTarget::Fd => {
                let fd = request.arg(0) as i32;
                let open_file = self.io.open_files.get(&fd).ok_or(LINUX_EBADF)?;
                let open = open_file.description.borrow();
                match &*open {
                    OpenDescription::File { path, .. }
                    | OpenDescription::Directory { path, .. } => Ok(path.clone()),
                    // HostFile caches no path; xattr on a raw host fd that has
                    // no recoverable rootfs path is unsupported. The probe and
                    // the common case use the path variants.
                    _ => Err(LINUX_ENOTSUP),
                }
            }
        }
    }

    fn setxattr(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        target: XattrTarget,
    ) -> Result<DispatchOutcome, DispatchError> {
        // setxattr(path/fd, name, value, size, flags)
        let resolved = match self.xattr_target_path(&request, memory, target) {
            Ok(p) => p,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let name = match read_guest_c_string(memory, request.arg(1)) {
            Ok(name) => name,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let size = request.arg(3) as usize;
        let flags = request.arg(4) as i32;
        let value = match memory.read_bytes(request.arg(2), size) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                })
            }
        };
        match self.fs
            .rootfs_vfs
            .overlay
            .set_xattr(&resolved, &name, &value, flags)
        {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => Ok(DispatchOutcome::Errno { errno }),
        }
    }

    fn getxattr(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        target: XattrTarget,
    ) -> Result<DispatchOutcome, DispatchError> {
        // getxattr(path/fd, name, value, size)
        let resolved = match self.xattr_target_path(&request, memory, target) {
            Ok(p) => p,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let name = match read_guest_c_string(memory, request.arg(1)) {
            Ok(name) => name,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let buf_addr = request.arg(2);
        let size = request.arg(3) as usize;
        let value = match self.fs.rootfs_vfs.overlay.get_xattr(&resolved, &name) {
            Ok(value) => value,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // size == 0 is the "tell me how big" probe: return the length without
        // copying anything.
        if size == 0 {
            return Ok(DispatchOutcome::Returned {
                value: value.len() as i64,
            });
        }
        if value.len() > size {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ERANGE,
            });
        }
        if memory.write_bytes(buf_addr, &value).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: value.len() as i64,
        })
    }

    fn listxattr(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        target: XattrTarget,
    ) -> Result<DispatchOutcome, DispatchError> {
        // listxattr(path/fd, list, size)
        let resolved = match self.xattr_target_path(&request, memory, target) {
            Ok(p) => p,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let buf_addr = request.arg(1);
        let size = request.arg(2) as usize;
        let names = match self.fs.rootfs_vfs.overlay.list_xattr(&resolved) {
            Ok(names) => names,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // Assemble the NUL-separated, NUL-terminated name list Linux returns.
        let mut list = Vec::new();
        for n in &names {
            list.extend_from_slice(n.as_bytes());
            list.push(0);
        }
        if size == 0 {
            return Ok(DispatchOutcome::Returned {
                value: list.len() as i64,
            });
        }
        if list.len() > size {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ERANGE,
            });
        }
        if memory.write_bytes(buf_addr, &list).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: list.len() as i64,
        })
    }

    fn bootstrap_enosys(&self) -> DispatchOutcome {
        DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        }
    }

    // === Normalized shim-wrappers ===
    // Thin adapters giving each remaining legacy handler the uniform
    // SyscallCtx<M> contract so it can live in the `normalized_dispatch!`
    // table. The inner fns are unchanged (already tested); these forward
    // `ctx.request` (Copy) and `ctx.memory`. Once every syscall has a
    // wrapper the legacy match in `dispatch()` is deleted and the macro
    // table becomes the single authoritative syscall registry.
    pub(super) fn sys_setxattr_path<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.setxattr(ctx.request, ctx.memory, XattrTarget::Path)
    }

    pub(super) fn sys_setxattr_fd<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.setxattr(ctx.request, ctx.memory, XattrTarget::Fd)
    }

    pub(super) fn sys_getxattr_path<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.getxattr(ctx.request, ctx.memory, XattrTarget::Path)
    }

    pub(super) fn sys_getxattr_fd<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.getxattr(ctx.request, ctx.memory, XattrTarget::Fd)
    }

    pub(super) fn sys_listxattr_path<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.listxattr(ctx.request, ctx.memory, XattrTarget::Path)
    }

    pub(super) fn sys_listxattr_fd<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.listxattr(ctx.request, ctx.memory, XattrTarget::Fd)
    }

    pub(super) fn sys_xattr_unsupported<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.xattr_unsupported())
    }

    pub(super) fn sys_statfs<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.statfs(ctx.request, ctx.memory)
    }

    pub(super) fn sys_fstatfs<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.fstatfs(ctx.request, ctx.memory))
    }

    pub(super) fn sys_truncate<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.truncate(ctx.request, &*ctx.memory)
    }

    pub(super) fn sys_bootstrap_enosys<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.bootstrap_enosys())
    }

    pub(super) fn fsync<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn fdatasync<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn write<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0);
        let address = ctx.arg(1);
        let length = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let bytes = match (&*ctx.memory).read_bytes(address, length) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        };

        // Check open_files FIRST: dup3 may have redirected fd 1/2 to
        // a pipe, an eventfd, or some other resource. Only after we've
        // confirmed there's no open description do we fall back to the
        // dispatcher's built-in stdout/stderr buffers.
        if let Some(open_file) = self.io.open_files.get(&(fd as i32)).cloned() {
            // Take an inner scope so the borrow on the description ends
            // before we touch self.fs.rootfs_vfs.overlay (writable File path below).
            #[allow(dead_code)]
            enum FileWriteback {
                None,
                Update { path: String, contents: Vec<u8> },
            }
            let outcome: DispatchOutcome;
            let writeback: FileWriteback;
            {
                let mut open = open_file.description.borrow_mut();
                match &mut *open {
                    OpenDescription::EventFd { counter, .. } => {
                        return Ok(write_eventfd(&bytes, counter));
                    }
                    OpenDescription::PipeWriter { pipe, .. } => {
                        return Ok(write_pipe(&bytes, pipe));
                    }
                    OpenDescription::HostPipe {
                        host_fd,
                        is_read_end,
                        ..
                    } => {
                        if *is_read_end {
                            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                        }
                        return Ok(write_host_pipe(&bytes, *host_fd));
                    }
                    OpenDescription::HostSocket { host_fd, .. } => {
                        // write(2) on a connected socket maps directly to a
                        // host write(2). Unconnected sockets will surface
                        // their own ENOTCONN via the host.
                        return Ok(write_host_pipe(&bytes, *host_fd));
                    }
                    OpenDescription::HostFile {
                        host_fd,
                        writable,
                        status_flags,
                        ..
                    } => {
                        if !*writable {
                            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                        }
                        // O_APPEND: seek to EOF before writing so `>>` and
                        // log appends don't overwrite from offset 0. (The
                        // host fd isn't opened O_APPEND, so we emulate the
                        // seek-then-write; single-writer, which covers the
                        // shell/dpkg append cases.)
                        if *status_flags & LINUX_O_APPEND != 0 {
                            unsafe { libc::lseek(*host_fd, 0, libc::SEEK_END) };
                        }
                        // libc::write to the real fd: advances the
                        // kernel offset and is visible across fork.
                        return Ok(write_host_pipe(&bytes, *host_fd));
                    }
                    OpenDescription::File {
                        path,
                        contents,
                        offset,
                        writable,
                        metadata,
                        ..
                    } => {
                        if !*writable {
                            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                        }
                        write_into_file_contents(contents, offset, &bytes);
                        metadata.size = contents.len();
                        outcome = DispatchOutcome::Returned {
                            value: bytes.len() as i64,
                        };
                        writeback = FileWriteback::Update {
                            path: path.clone(),
                            contents: contents.clone(),
                        };
                    }
                    _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
                }
            }
            if let FileWriteback::Update { path, contents } = writeback {
                let _ = self.fs.rootfs_vfs.overlay.set_file_contents(&path, contents);
            }
            return Ok(outcome);
        }
        match fd {
            1 => self.io.stdout.extend_from_slice(&bytes),
            2 => self.io.stderr.extend_from_slice(&bytes),
            _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
        }

        Ok(DispatchOutcome::Returned {
            value: length as i64,
        })
    }

    fn write_output_fd(&mut self, fd: i32, bytes: &[u8]) -> DispatchOutcome {
        // Mirror `write`/`writev`: any fd present in `open_files` (e.g.
        // after a dup3 over stdio) takes precedence over the built-in
        // stdout/stderr buffers. Without this, `busybox cat`'s
        // `sendfile(1, infile, ...)` writes the file contents to the
        // dispatcher's internal stdout instead of the pipe write end.
        if let Some(open_file) = self.io.open_files.get(&fd).cloned() {
            // Regular-file destinations need the overlay writeback to happen
            // AFTER the description borrow is dropped, so use the same
            // collect-then-write pattern as `write`. Non-file arms return
            // directly. This is what makes splice/copy_file_range/sendfile to a
            // regular file (off_out at the fd's current position) work, matching
            // real Linux (splice pipe->file).
            let outcome: DispatchOutcome;
            let writeback: Option<(String, Vec<u8>)>;
            {
                let mut open = open_file.description.borrow_mut();
                match &mut *open {
                    OpenDescription::PipeWriter { pipe, .. } => return write_pipe(bytes, pipe),
                    OpenDescription::HostPipe {
                        host_fd,
                        is_read_end,
                        ..
                    } => {
                        return if *is_read_end {
                            DispatchOutcome::Errno { errno: LINUX_EBADF }
                        } else {
                            write_host_pipe(bytes, *host_fd)
                        };
                    }
                    OpenDescription::HostSocket { host_fd, .. } => {
                        return write_host_pipe(bytes, *host_fd);
                    }
                    OpenDescription::HostFile {
                        host_fd,
                        writable,
                        status_flags,
                        ..
                    } => {
                        if !*writable {
                            return DispatchOutcome::Errno { errno: LINUX_EBADF };
                        }
                        if *status_flags & LINUX_O_APPEND != 0 {
                            unsafe { libc::lseek(*host_fd, 0, libc::SEEK_END) };
                        }
                        return write_host_pipe(bytes, *host_fd);
                    }
                    OpenDescription::File {
                        path,
                        contents,
                        offset,
                        writable,
                        metadata,
                        ..
                    } => {
                        if !*writable {
                            return DispatchOutcome::Errno { errno: LINUX_EBADF };
                        }
                        write_into_file_contents(contents, offset, bytes);
                        metadata.size = contents.len();
                        outcome = DispatchOutcome::Returned {
                            value: bytes.len() as i64,
                        };
                        writeback = Some((path.clone(), contents.clone()));
                    }
                    _ => return DispatchOutcome::Errno { errno: LINUX_EBADF },
                }
            }
            if let Some((path, contents)) = writeback {
                let _ = self.fs.rootfs_vfs.overlay.set_file_contents(&path, contents);
            }
            return outcome;
        }
        if self.io.stream_stdio && (fd == 1 || fd == 2) {
            let n = unsafe {
                libc::write(fd, bytes.as_ptr() as *const _, bytes.len())
            };
            if n < 0 {
                let errno = unsafe { *libc::__error() };
                return DispatchOutcome::Errno {
                    errno: errno as i32,
                };
            }
            return DispatchOutcome::Returned { value: n as i64 };
        }
        match fd {
            1 => self.io.stdout.extend_from_slice(bytes),
            2 => self.io.stderr.extend_from_slice(bytes),
            _ => return DispatchOutcome::Errno { errno: LINUX_EBADF },
        }
        DispatchOutcome::Returned {
            value: bytes.len() as i64,
        }
    }

    pub(super) fn writev<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0);
        let iov = ctx.arg(1);
        let iovcnt = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let memory = &*ctx.memory;
        let iovecs = match read_iovecs(memory, iov, iovcnt) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        let mut total = 0usize;
        for iovec in iovecs {
            let iov_base = iovec.iov_base;
            let iov_len = usize::try_from(iovec.iov_len)
                .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
            let bytes = match memory.read_bytes(iov_base, iov_len) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            };
            // Mirror `write`: check open_files FIRST so post-dup3
            // redirects (eg `dup3(pipe_write, 1)`) actually plumb
            // through the redirected description rather than the
            // built-in stdout buffer.
            if let Some(open_file) = self.io.open_files.get(&(fd as i32)).cloned() {
                enum FileWriteback {
                    None,
                    Update { path: String, contents: Vec<u8> },
                }
                let outcome: DispatchOutcome;
                let writeback: FileWriteback;
                {
                    let mut open = open_file.description.borrow_mut();
                    match &mut *open {
                        OpenDescription::PipeWriter { pipe, .. } => {
                            outcome = write_pipe(&bytes, pipe);
                            writeback = FileWriteback::None;
                        }
                        OpenDescription::HostPipe {
                            host_fd,
                            is_read_end,
                            ..
                        } => {
                            if *is_read_end {
                                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                            }
                            outcome = write_host_pipe(&bytes, *host_fd);
                            writeback = FileWriteback::None;
                        }
                        OpenDescription::HostSocket { host_fd, .. } => {
                            outcome = write_host_pipe(&bytes, *host_fd);
                            writeback = FileWriteback::None;
                        }
                        OpenDescription::HostFile {
                            host_fd,
                            writable,
                            status_flags,
                            ..
                        } => {
                            if !*writable {
                                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                            }
                            // Mirror `write`(64): O_APPEND seeks to EOF, then
                            // libc::write to the real fd advances the shared
                            // kernel offset (visible across fork and to the
                            // readv that follows).
                            if *status_flags & LINUX_O_APPEND != 0 {
                                unsafe { libc::lseek(*host_fd, 0, libc::SEEK_END) };
                            }
                            outcome = write_host_pipe(&bytes, *host_fd);
                            writeback = FileWriteback::None;
                        }
                        OpenDescription::File {
                            path,
                            contents,
                            offset,
                            writable,
                            metadata,
                            ..
                        } => {
                            if !*writable {
                                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                            }
                            write_into_file_contents(contents, offset, &bytes);
                            metadata.size = contents.len();
                            outcome = DispatchOutcome::Returned {
                                value: bytes.len() as i64,
                            };
                            writeback = FileWriteback::Update {
                                path: path.clone(),
                                contents: contents.clone(),
                            };
                        }
                        _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
                    }
                }
                if let FileWriteback::Update { path, contents } = writeback {
                    let _ = self.fs.rootfs_vfs.overlay.set_file_contents(&path, contents);
                }
                let DispatchOutcome::Returned { value } = outcome else {
                    return Ok(outcome);
                };
                total = total
                    .checked_add(value as usize)
                    .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                continue;
            }
            if self.io.stream_stdio && (fd == 1 || fd == 2) {
                let n = unsafe {
                    libc::write(fd as i32, bytes.as_ptr() as *const _, bytes.len())
                };
                if n < 0 {
                    return Ok(DispatchOutcome::Errno {
                        errno: host_errno(),
                    });
                }
                total = total
                    .checked_add(n as usize)
                    .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                continue;
            }
            match fd {
                1 => self.io.stdout.extend_from_slice(&bytes),
                2 => self.io.stderr.extend_from_slice(&bytes),
                _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
            }
            total = total
                .checked_add(bytes.len())
                .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
        }

        Ok(DispatchOutcome::Returned {
            value: total as i64,
        })
    }

    pub(super) fn readlinkat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let buffer = ctx.arg(2);
        let buffer_size = usize::try_from(ctx.arg(3))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(3)))?;
        if buffer_size == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let path = match read_guest_c_string(&*ctx.memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        let target = if path == "/proc/self/exe" || path == "/proc/curproc/exe" {
            self.proc.executable_path.clone()
        } else if let Some(t) = self.fs.rootfs_vfs.overlay.read_link(&path) {
            // Symlink created in the writable backend (cap-std on --fs host).
            t
        } else {
            use crate::vfs::Vfs as _;
            match self.fs.rootfs_vfs.readlink(&path) {
                Ok(p) => p.to_string_lossy().into_owned(),
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            }
        };

        let bytes = target.as_bytes();
        let written = bytes.len().min(buffer_size);
        if ctx.memory.write_bytes(buffer, &bytes[..written]).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: written as i64,
        })
    }

    pub(super) fn mknodat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let mode = ctx.arg(2) as u32;
        let path = match read_guest_c_string(&*ctx.memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved = match self.resolve_at_path(dirfd, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EEXIST,
            });
        }
        // Existence check must consult the layered view (overlay/disk
        // first, then rootfs) — a rootfs-direct lookup would miss a file
        // the guest already created in the overlay and wrongly report
        // EROFS instead of EEXIST. Mirrors the linkat EEXIST check.
        if self.layered_metadata(&resolved).is_ok() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EEXIST,
            });
        }
        // Linux mknod(2): a zero type field means S_IFREG. Only regular
        // files are materialised on the host backend (like open O_CREAT);
        // device/fifo/socket nodes can't be backed by the cap-std scratch,
        // so they report EPERM (matching the unprivileged-mknod errno).
        let type_bits = mode & LINUX_S_IFMT;
        if type_bits != 0 && type_bits != LINUX_S_IFREG {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EPERM });
        }
        // Create an empty regular file in the writable backend (cap-std).
        // MemoryBackend's create_file works in-memory too. After this the
        // path exists in the layered view.
        match self.fs.rootfs_vfs.overlay.create_file(&resolved) {
            Ok(()) => {
                if mode & 0o7777 != 0 {
                    let _ = self.fs.rootfs_vfs.overlay.set_mode(&resolved, mode & 0o7777);
                }
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            Err(crate::fs_backend::BackendError::Unsupported) => {
                Ok(DispatchOutcome::Errno { errno: LINUX_EROFS })
            }
            Err(_) => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
        }
    }

    pub(super) fn mkdirat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let path = match read_guest_c_string(&*ctx.memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved = match self.resolve_at_path(dirfd, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EEXIST,
            });
        }
        // Layered existence + parent-exists checks live inside
        // RootFsVfs::mkdir; the dispatcher only handles synthetic
        // path shadowing.
        use crate::vfs::Vfs as _;
        match self.fs.rootfs_vfs.mkdir(&resolved, 0) {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => Ok(DispatchOutcome::Errno { errno }),
        }
    }

    pub(super) fn fchmod<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }
        // The overlay is a tmpfs that doesn't track owner/mode; accept
        // the call as a no-op so apt's chmod-the-directory-I-just-made
        // helpers don't fail with EROFS.
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn fchown<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }
        // See `fchmod` above: tmpfs semantics, no-op success.
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn fchownat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let flags = ctx.arg(4);
        if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let path = match read_guest_c_string(&*ctx.memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            if flags & LINUX_AT_EMPTY_PATH == 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOENT,
                });
            }
            if dirfd == LINUX_AT_FDCWD {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !self.fd_is_valid(dirfd as i32) {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        let resolved = match self.resolve_at_path(dirfd, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // Layered presence check: overlay first (tombstones become ENOENT),
        // synthetic /proc and /sys are no-op success, rootfs is no-op
        // success (tmpfs semantics).
        match self.layered_metadata(&resolved) {
            Ok(_) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => {
                if is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
                    Ok(DispatchOutcome::Returned { value: 0 })
                } else {
                    Ok(DispatchOutcome::Errno { errno })
                }
            }
        }
    }

    pub(super) fn fchmodat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let flags = ctx.arg(3);
        if flags & !LINUX_AT_SYMLINK_NOFOLLOW != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let path = match read_guest_c_string(&*ctx.memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved = match self.resolve_at_path(dirfd, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // Apply the mode to the writable backend (cap-std set_permissions on
        // --fs host). Synthetic /proc /sys paths and the in-memory backend
        // (Unsupported) accept it as a no-op as long as the path exists.
        if is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if let Err(errno) = self.layered_metadata(&resolved) {
            return Ok(DispatchOutcome::Errno { errno });
        }
        let mode = (ctx.arg(2) & 0o7777) as u32;
        match self.fs.rootfs_vfs.overlay.set_mode(&resolved, mode) {
            Ok(()) | Err(crate::fs_backend::BackendError::Unsupported) => {
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            Err(_) => Ok(DispatchOutcome::Returned { value: 0 }),
        }
    }

    pub(super) fn linkat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let olddirfd = ctx.arg(0);
        let oldpath = ctx.arg(1);
        let newdirfd = ctx.arg(2);
        let newpath = ctx.arg(3);
        let flags = ctx.arg(4);
        if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let old = match read_guest_c_string(&*ctx.memory, oldpath) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let new_path = match read_guest_c_string(&*ctx.memory, newpath) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if new_path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        if old.is_empty() && flags & LINUX_AT_EMPTY_PATH == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved_old = if old.is_empty() {
            if !self.fd_is_valid(olddirfd as i32) {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            None
        } else {
            let resolved = match self.resolve_at_path(olddirfd, &old) {
                Ok(resolved) => resolved,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            let exists = is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context())
                || self.layered_metadata(&resolved).is_ok();
            if !exists {
                return Ok(DispatchOutcome::Errno { errno: LINUX_ENOENT });
            }
            Some(resolved)
        };
        let resolved_new = match self.resolve_at_path(newdirfd, &new_path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved_new, &self.synthetic_proc_context())
            || self.layered_metadata(&resolved_new).is_ok()
        {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EEXIST });
        }
        // Create a real hard link in the writable backend (cap-std
        // hard_link). dpkg link()s e.g. /var/lib/dpkg/status -> status-old.
        // AT_EMPTY_PATH (link by fd) isn't supported. MemoryBackend can't
        // hard-link an in-memory file, so it falls back to a content copy.
        let Some(src) = resolved_old else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        };
        match self.fs.rootfs_vfs.overlay.hard_link(&src, &resolved_new) {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(crate::fs_backend::BackendError::Unsupported) => {
                // In-memory backend: emulate with a content copy (callers
                // like dpkg only need the data, not shared inodes).
                let contents = self.fs
                    .rootfs_vfs
                    .overlay
                    .file_contents(&src)
                    .or_else(|| self.fs.rootfs_vfs.rootfs.as_ref().and_then(|r| r.read(&src).ok()))
                    .unwrap_or_default();
                match self.fs.rootfs_vfs.overlay.set_file_contents(&resolved_new, contents) {
                    Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                    Err(_) => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
                }
            }
            Err(_) => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
        }
    }

    pub(super) fn symlinkat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let target = ctx.arg(0);
        let newdirfd = ctx.arg(1);
        let linkpath = ctx.arg(2);
        let target_path = match read_guest_c_string(&*ctx.memory, target) {
            Ok(target) => target,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if target_path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let link = match read_guest_c_string(&*ctx.memory, linkpath) {
            Ok(link) => link,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if link.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved_link = match self.resolve_at_path(newdirfd, &link) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved_link, &self.synthetic_proc_context()) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EEXIST,
            });
        }
        // If the link path already exists (anywhere in the layered
        // view), report EEXIST. Otherwise the overlay can't create
        // symlinks today, so we return EROFS.
        if self.layered_metadata(&resolved_link).is_ok() {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EEXIST });
        }
        // Create a real symlink in the writable backend (cap-std). The
        // target is stored verbatim, matching symlinkat(2). MemoryBackend
        // returns Unsupported → EROFS.
        match self.fs.rootfs_vfs.overlay.symlink(&target_path, &resolved_link) {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(crate::fs_backend::BackendError::Unsupported) => {
                Ok(DispatchOutcome::Errno { errno: LINUX_EROFS })
            }
            Err(_) => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
        }
    }

    pub(super) fn renameat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.do_renameat(
            ctx.arg(0),
            ctx.arg(1),
            ctx.arg(2),
            ctx.arg(3),
            0,
            &*ctx.memory,
        )
    }

    pub(super) fn renameat2<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // RENAME_NOREPLACE=1, RENAME_EXCHANGE=2, RENAME_WHITEOUT=4. We
        // implement the common subset (no flags or NOREPLACE). EXCHANGE
        // and WHITEOUT are not supported by overlayfs in our limited
        // mode either, so reject them.
        const RENAME_NOREPLACE: u64 = 1;
        const RENAME_EXCHANGE: u64 = 2;
        let flags = ctx.arg(4);
        if flags & !RENAME_NOREPLACE != 0 {
            if flags & RENAME_EXCHANGE != 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        self.do_renameat(
            ctx.arg(0),
            ctx.arg(1),
            ctx.arg(2),
            ctx.arg(3),
            flags,
            &*ctx.memory,
        )
    }

    fn do_renameat(
        &mut self,
        olddirfd: u64,
        oldpath: u64,
        newdirfd: u64,
        newpath: u64,
        flags: u64,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        const RENAME_NOREPLACE: u64 = 1;
        let old = match read_guest_c_string(memory, oldpath) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let new_path = match read_guest_c_string(memory, newpath) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if old.is_empty() || new_path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved_old = match self.resolve_at_path(olddirfd, &old) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let resolved_new = match self.resolve_at_path(newdirfd, &new_path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved_old, &self.synthetic_proc_context())
            || is_synthetic_virtual_file(&resolved_new, &self.synthetic_proc_context())
        {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        }
        let no_replace = flags & RENAME_NOREPLACE != 0;
        match self.fs
            .rootfs_vfs
            .rename_with_flags(&resolved_old, &resolved_new, no_replace)
        {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => Ok(DispatchOutcome::Errno { errno }),
        }
    }

    pub(super) fn unlinkat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let flags = ctx.arg(2);
        if flags & !LINUX_AT_REMOVEDIR != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let path = match read_guest_c_string(&*ctx.memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved = match self.resolve_at_path(dirfd, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let remove_dir = flags & LINUX_AT_REMOVEDIR != 0;
        // Synthetic /proc /sys paths can't be unlinked.
        if is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        }
        use crate::vfs::Vfs as _;
        let result = if remove_dir {
            self.fs.rootfs_vfs.rmdir(&resolved)
        } else {
            self.fs.rootfs_vfs.unlink(&resolved)
        };
        match result {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => Ok(DispatchOutcome::Errno { errno }),
        }
    }

    pub(super) fn utimensat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let times = ctx.arg(2);
        let flags = ctx.arg(3);
        let memory = &*ctx.memory;
        if flags & !LINUX_AT_SYMLINK_NOFOLLOW != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // `times == NULL` means "set both to now"; otherwise read the two
        // timespecs and resolve UTIME_NOW/UTIME_OMIT into concrete
        // (sec, nsec) pairs or `None` (omit) for the backend.
        let (atime_set, mtime_set): (Option<(i64, i64)>, Option<(i64, i64)>);
        if times != 0 {
            let atime = match read_timespec(memory, times) {
                Ok(timespec) => timespec,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            let mtime_address = times
                .checked_add(core::mem::size_of::<LinuxTimespec>() as u64)
                .ok_or(DispatchError::LengthTooLarge(times))?;
            let mtime = match read_timespec(memory, mtime_address) {
                Ok(timespec) => timespec,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            if !linux_utimensat_timespec_is_valid(atime)
                || !linux_utimensat_timespec_is_valid(mtime)
            {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            atime_set = resolve_utimensat_timespec(atime);
            mtime_set = resolve_utimensat_timespec(mtime);
        } else {
            // NULL → set both to the current wall-clock time.
            let now = now_realtime_timespec();
            atime_set = Some(now);
            mtime_set = Some(now);
        }

        if pathname == 0 {
            if dirfd == LINUX_AT_FDCWD {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
            if !self.fd_is_valid(dirfd as i32) {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // The path must exist in the layered view, else NotFound (or a
        // no-op success for synthetic /proc paths whose times we can't
        // back).
        match self.layered_metadata(&path) {
            Ok(_) => {}
            Err(errno) => {
                if is_synthetic_virtual_file(&path, &self.synthetic_proc_context()) {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                return Ok(DispatchOutcome::Errno { errno });
            }
        }
        if atime_set.is_none() && mtime_set.is_none() {
            // Both UTIME_OMIT: nothing to persist.
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        // Persist atime/mtime to the materialised host file (disk-backed
        // overlay). A subsequent stat reads real disk metadata via
        // real_stat and will report the set mtime. MemoryBackend returns
        // Unsupported; accept as a no-op so in-memory guests don't fail.
        match self.fs.rootfs_vfs.overlay.set_times(&path, atime_set, mtime_set) {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(crate::fs_backend::BackendError::Unsupported) => {
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            Err(_) => Ok(DispatchOutcome::Errno {
                errno: LINUX_EROFS,
            }),
        }
    }

    pub(super) fn newfstatat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let statbuf = ctx.arg(2);
        let flags = ctx.arg(3);
        let memory = &mut *ctx.memory;
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        if path.is_empty() && flags & LINUX_AT_EMPTY_PATH != 0 {
            return Ok(self.write_fd_stat(dirfd as i32, statbuf, memory));
        }

        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // Synthetic /proc /sys paths first.
        if let Some(contents) = synthetic_proc_file(&path, &self.synthetic_proc_context()) {
            return Ok(write_synthetic_stat(
                memory,
                statbuf,
                &path,
                contents.len(),
                LINUX_S_IFREG | 0o444,
            ));
        }
        if let Some(contents) = synthetic_sys_file(&path) {
            return Ok(write_synthetic_stat(
                memory,
                statbuf,
                &path,
                contents.len(),
                LINUX_S_IFREG | 0o444,
            ));
        }
        // Disk-backed overlay (--fs host): prefer the REAL on-disk stat
        // so the type bits (S_IFLNK for a symlink) and st_nlink (a true
        // hard link reports >1) reflect what the kernel would report.
        // `AT_SYMLINK_NOFOLLOW` selects lstat (report the link) vs stat
        // (report the target) semantics.
        let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0;
        if let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&path, follow) {
            return Ok(write_stat_real(memory, statbuf, &path, &real));
        }
        // Layered overlay+rootfs lookup via RootFsVfs. Honour
        // AT_SYMLINK_NOFOLLOW (lstat) on backends without real_stat.
        use crate::vfs::Vfs as _;
        let lookup = if follow {
            self.fs.rootfs_vfs.lookup(&path)
        } else {
            self.fs.rootfs_vfs.lookup_nofollow(&path)
        };
        match lookup {
            Ok(md) => Ok(write_stat(memory, statbuf, &vfs_md_to_rootfs_md(&path, &md))),
            Err(errno) => Ok(DispatchOutcome::Errno { errno }),
        }
    }

    pub(super) fn statx<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let flags = ctx.arg(2);
        let mask = ctx.arg(3);
        let statxbuf = ctx.arg(4);
        let memory = &mut *ctx.memory;

        if !linux_statx_flags_are_supported(flags) || mask & LINUX_STATX_RESERVED != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        if path.is_empty() {
            if flags & LINUX_AT_EMPTY_PATH == 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOENT,
                });
            }
            return Ok(self.write_fd_statx(dirfd as i32, statxbuf, memory));
        }

        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if let Some(contents) = synthetic_proc_file(&path, &self.synthetic_proc_context()) {
            return Ok(write_synthetic_statx(memory, statxbuf, &path, contents.len()));
        }
        if let Some(contents) = synthetic_sys_file(&path) {
            return Ok(write_synthetic_statx(memory, statxbuf, &path, contents.len()));
        }
        // Disk-backed overlay (--fs host): prefer the REAL on-disk stat
        // (S_IFLNK + true st_nlink). `AT_SYMLINK_NOFOLLOW` selects lstat
        // (the link) vs stat (the target).
        let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0;
        if let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&path, follow) {
            return Ok(write_statx_real(memory, statxbuf, &path, &real));
        }
        // Fallback for backends without real_stat (e.g. the in-memory
        // overlay): honour AT_SYMLINK_NOFOLLOW by reporting the link itself
        // rather than its target.
        use crate::vfs::Vfs as _;
        let lookup = if follow {
            self.fs.rootfs_vfs.lookup(&path)
        } else {
            self.fs.rootfs_vfs.lookup_nofollow(&path)
        };
        match lookup {
            Ok(md) => Ok(write_statx(memory, statxbuf, &vfs_md_to_rootfs_md(&path, &md))),
            Err(errno) => Ok(DispatchOutcome::Errno { errno }),
        }
    }

    pub(super) fn fstat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let statbuf = ctx.arg(1);
        Ok(self.write_fd_stat(fd, statbuf, &mut *ctx.memory))
    }

    fn write_fd_stat(
        &self,
        fd: i32,
        statbuf: u64,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let Some(open_file) = self.io.open_files.get(&fd) else {
            if is_stdio_fd(fd) {
                // Glibc cat/head/etc fstat stdout on startup to decide
                // whether they're talking to a regular file (use POSIX
                // sendfile fast path) or a TTY/pipe (default cooked
                // path). Synthesize a character-device stat so they
                // pick the right branch instead of bailing EBADF.
                let label = match fd {
                    0 => "/dev/stdin",
                    1 => "/dev/stdout",
                    _ => "/dev/stderr",
                };
                // Report the REAL type of whatever is wired to the guest's
                // stdio. Under `--fs host`/`--raw` (stream_stdio) the guest's
                // 0/1/2 are carrick's own host fds, so fstat the host fd and
                // carry its type bits: a pipe → S_IFIFO, a tty → S_IFCHR, a
                // file redirect → S_IFREG. The S_IF* type values are identical
                // on macOS and Linux, so they transfer directly. This matches
                // real Linux (e.g. a piped stdin reports FIFO, not CHR) and
                // keeps tools off the regular-file seek fast path for pipes.
                let mut host_st: libc::stat = unsafe { std::mem::zeroed() };
                let mode = if unsafe { libc::fstat(fd, &mut host_st) } == 0 {
                    (host_st.st_mode as u32 & LINUX_S_IFMT) | 0o620
                } else {
                    // Fall back to a character device if the host fstat fails.
                    LINUX_S_IFCHR | 0o620
                };
                return write_synthetic_stat(memory, statbuf, label, 0, mode);
            }
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let open = open_file.description.borrow();
        let metadata = match &*open {
            OpenDescription::File { metadata, .. }
            | OpenDescription::Directory { metadata, .. } => metadata,
            // Real host file: fstat the live fd for the REAL size AND times
            // (atime/mtime/ctime). Using the live inode keeps fstat-by-fd
            // consistent with statx/newfstatat-by-path (both go through real
            // on-disk times) — required so apt's pkgcache mtime cross-check
            // passes. Falling back to the stored metadata (which carries
            // mtime=0) made `apt install` abort with "Cache is out of sync,
            // can't x-ref a package file". See `real_stat_from_libc`.
            OpenDescription::HostFile { host_fd, metadata, .. } => {
                let path = metadata.path.to_string_lossy().into_owned();
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(*host_fd, &mut st) } == 0 {
                    let real = super::real_stat_from_libc(&st);
                    return write_stat_real(memory, statbuf, &path, &real);
                }
                // fstat failed: fall back to the stored metadata (size only).
                return write_stat(memory, statbuf, metadata);
            }
            OpenDescription::SyntheticFile { path, contents, .. } => {
                return write_synthetic_stat(
                    memory,
                    statbuf,
                    path,
                    contents.len(),
                    LINUX_S_IFREG | 0o444,
                );
            }
            // anon_inode fds (eventfd/timerfd/epoll) carry NO S_IFMT type
            // bits on Linux — fstat reports st_mode with the type field 0,
            // not S_IFREG. Match that so type-introspecting tools agree.
            OpenDescription::EventFd { .. } => {
                return write_synthetic_stat(memory, statbuf, "anon_inode:[eventfd]", 0, 0o600);
            }
            OpenDescription::TimerFd { .. } => {
                return write_synthetic_stat(memory, statbuf, "anon_inode:[timerfd]", 0, 0o600);
            }
            OpenDescription::Epoll { .. } => {
                return write_synthetic_stat(memory, statbuf, "anon_inode:[eventpoll]", 0, 0o600);
            }
            // Pipes are FIFOs and sockets are sockets — NOT regular files.
            // Reporting S_IFREG made every pipe share one inode + look like
            // a regular file, so `grep` in a pipeline aborted with "input
            // file is also the output". The distinct type bits fix that.
            OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
                return write_synthetic_stat(
                    memory,
                    statbuf,
                    "pipe:[carrick]",
                    0,
                    LINUX_S_IFIFO | 0o600,
                );
            }
            OpenDescription::HostSocket { .. } | OpenDescription::Netlink { .. } => {
                return write_synthetic_stat(
                    memory,
                    statbuf,
                    "socket:[carrick]",
                    0,
                    LINUX_S_IFSOCK | 0o600,
                );
            }
        };
        write_stat(memory, statbuf, metadata)
    }

    fn write_fd_statx(
        &self,
        fd: i32,
        statxbuf: u64,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let open = open_file.description.borrow();
        let metadata = match &*open {
            OpenDescription::File { metadata, .. }
            | OpenDescription::Directory { metadata, .. } => metadata,
            OpenDescription::HostFile { host_fd, metadata, .. } => {
                let mut md = metadata.clone();
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(*host_fd, &mut st) } == 0 {
                    md.size = st.st_size as usize;
                }
                return write_statx(memory, statxbuf, &md);
            }
            OpenDescription::SyntheticFile { path, contents, .. } => {
                return write_synthetic_statx(memory, statxbuf, path, contents.len());
            }
            OpenDescription::EventFd { .. } => {
                return write_synthetic_statx(memory, statxbuf, "anon_inode:[eventfd]", 0);
            }
            OpenDescription::TimerFd { .. } => {
                return write_synthetic_statx(memory, statxbuf, "anon_inode:[timerfd]", 0);
            }
            OpenDescription::Epoll { .. } => {
                return write_synthetic_statx(memory, statxbuf, "anon_inode:[eventpoll]", 0);
            }
            OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
                return write_synthetic_statx(memory, statxbuf, "pipe:[carrick]", 0);
            }
            OpenDescription::HostSocket { .. } | OpenDescription::Netlink { .. } => {
                return write_synthetic_statx(memory, statxbuf, "socket:[carrick]", 0);
            }
        };
        write_statx(memory, statxbuf, metadata)
    }

    fn resolve_at_path(&self, dirfd: u64, path: &str) -> Result<String, i32> {
        // dirfd is an `int` in the kernel ABI: only the low 32 bits are
        // meaningful, and AT_FDCWD (-100) may arrive zero-extended (0xFFFFFF9C)
        // or sign-extended (0xFFFF..FF9C) depending on how the guest libc
        // widened it. Canonicalise via i32 so AT_FDCWD is recognised either
        // way (coreutils `ln` passed the zero-extended form → symlinkat/linkat
        // wrongly treated it as a real fd → EBADF).
        let dirfd = (dirfd as i32) as i64 as u64;
        if path.is_empty() || Path::new(path).is_absolute() {
            return Ok(path.to_owned());
        }
        if dirfd == LINUX_AT_FDCWD {
            return Ok(join_rootfs_path(&self.io.cwd, path));
        }

        match self.io.open_files.get(&(dirfd as i32)) {
            Some(open_file) => match &*open_file.description.borrow() {
                OpenDescription::Directory { path: dir, .. } => Ok(join_rootfs_path(dir, path)),
                OpenDescription::File { .. }
                | OpenDescription::HostFile { .. }
                | OpenDescription::SyntheticFile { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Netlink { .. } => Err(LINUX_ENOTDIR),
            },
            None => Err(LINUX_EBADF),
        }
    }
}
