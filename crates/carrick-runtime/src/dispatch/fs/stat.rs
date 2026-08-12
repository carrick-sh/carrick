//! fd stat/statx record assembly split out of dispatch/fs.rs (WS-F3):
//! the synthetic stdio (label, st_mode) probe and the fstat/statx
//! buffer writers + StatRecord builder. Pure `impl SyscallDispatcher` move.
use super::*;
use crate::linux_abi::LinuxErrno;

impl SyscallDispatcher {
    /// The synthetic `(label, st_mode)` for a bare stdio fd (0/1/2) with no
    /// OpenDescription. Glibc fstat()s stdio on startup to pick its tty/file/
    /// pipe code path, so report the REAL host type (a pty → S_IFCHR, a pipe →
    /// S_IFIFO, a redirect → S_IFREG; the S_IF* values match Linux). When the
    /// fd is the `carrick run -t` controlling tty, label it `/dev/pts/N` so the
    /// synthetic st_ino matches `stat("/dev/pts/N")` — the equality `ttyname(3)`
    /// checks between `fstat(fd)` and the `/proc/self/fd/N` readlink target.
    /// Shared by `write_fd_stat` (fstat) and `write_fd_statx` (statx).
    pub(super) fn stdio_synthetic_label_mode(&self, fd: i32) -> (String, u32) {
        let label = if crate::host_tty::host_isatty(fd)
            && let Some(n) = self.pty_table().lock().controlling()
        {
            format!("/dev/pts/{n}")
        } else {
            match fd {
                0 => "/dev/stdin",
                1 => "/dev/stdout",
                _ => "/dev/stderr",
            }
            .to_string()
        };
        let mut host_st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fd is a stdio fd; &host_st is a valid stat out-param.
        let mode = if unsafe { libc::fstat(fd, &mut host_st) } == 0 {
            (host_st.st_mode as u32 & LINUX_S_IFMT) | 0o620
        } else {
            LINUX_S_IFCHR | 0o620
        };
        (label, mode)
    }

    pub(super) fn write_fd_stat(
        &self,
        fd: i32,
        statbuf: u64,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        match self.fd_stat_record(fd) {
            Ok(record) => write_stat_record(memory, statbuf, &record),
            Err(errno) => DispatchOutcome::errno(errno),
        }
    }

    pub(super) fn write_fd_statx(
        &self,
        fd: i32,
        statxbuf: u64,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        match self.fd_stat_record(fd) {
            Ok(record) => write_statx_record(memory, statxbuf, &record),
            Err(errno) => DispatchOutcome::errno(errno),
        }
    }

    pub(super) fn fd_stat_record(&self, fd: i32) -> Result<StatRecord, LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            // A stdio fd the guest explicitly closed (and did not reopen) is
            // genuinely closed: report EBADF, not our still-open host stream.
            if is_stdio_fd(fd) && !self.stdio_is_closed(fd) {
                let (label, mode) = self.stdio_synthetic_label_mode(fd);
                return Ok(StatRecord::synthetic(&label, 0, mode));
            }
            return Err(LINUX_EBADF);
        };
        if open_file
            .description
            .concrete_backing::<crate::dispatch::ioring::IoUringBacking>()
            .is_some()
        {
            return Ok(StatRecord::synthetic("anon_inode:[io_uring]", 0, 0o600));
        }
        let open = open_file.description.read();
        // A named FIFO opened by path is modelled as a `HostPipe` (no pty),
        // whose `stat_source` hands back a SYNTHETIC record (hashed inode,
        // mode 0o600). But a path-stat (lstat) of the same FIFO reports the
        // REAL on-disk inode/mode, so `os.path.samestat(lstat(fifo),
        // fstat(open(fifo)))` was False — shutil.rmtree's safe-fd walk then
        // mis-classified the pipe as a symlink ("Cannot call rmtree on a
        // symbolic link") instead of raising NotADirectoryError
        // (test_rmtree_on_named_pipe). Anonymous pipe2() ends are also
        // `HostPipe` but carry no recorded path, so they keep the synthetic
        // record. Recover the real FIFO stat from the fd's recorded path.
        let is_named_pipe = matches!(&*open, OpenDescription::HostPipe { pty: None, .. });
        drop(open);
        if is_named_pipe
            && let Some(path) = self.lookup_recorded_fd_open_path(fd)
            && let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&path, false)
            && real.kind == RootFsEntryKind::Fifo
        {
            return Ok(StatRecord::from_real(&path, &real));
        }
        let open = open_file.description.read();
        let source = open.stat_source();
        drop(open);
        match source {
            OpenStatSource::Record(record) => Ok(record),
            OpenStatSource::HostStream {
                host_fd,
                identity,
                fallback_mode,
            } => {
                // fstat the real host fd to recover the Linux file type: a host
                // character device (/dev/null, /dev/zero, …) reports S_IFCHR
                // (mode 0o666, like Linux), a host pipe end reports S_IFIFO
                // (mode 0o600). The S_IF* type bits match between macOS and
                // Linux. Falls back to `fallback_mode` if the host fstat fails.
                let mut host_st: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: host_fd is a live host fd; &host_st is a valid out-param.
                let mode = if unsafe { libc::fstat(host_fd.get(), &mut host_st) } == 0 {
                    let type_bits = host_st.st_mode as u32 & LINUX_S_IFMT;
                    let perms = if type_bits == LINUX_S_IFCHR {
                        0o666
                    } else {
                        0o600
                    };
                    type_bits | perms
                } else {
                    fallback_mode
                };
                // Preserve open-description identity in guest stat records.
                // A constant label made every HostPipe-backed object share one
                // synthetic inode: after `2>&1 >/dev/null`, GNU m4 therefore
                // mistook stderr's pipe for stdout's /dev/null and discarded
                // `dumpdef`, leaving autom4te with an empty builtin table.
                // Include the Linux file type because host inode numbers can
                // collide across devices; use `pipe_id` for identity because
                // BSD gives the two ends of one pipe different host inodes.
                let label = host_stream_stat_label(identity, mode & LINUX_S_IFMT);
                Ok(StatRecord::synthetic(&label, 0, mode))
            }
            // An open Directory or in-memory File: its fd-stat must report the
            // SAME st_ino/st_dev as a path-stat of the same path. Under
            // `--fs host` the path-stat (newfstatat/statx) uses the REAL host
            // inode via `overlay.real_stat`; mirror it here so
            // `os.path.samestat(lstat(dir), fstat(open(dir)))` is True (the
            // synthetic `fallback` hashes the path to a DIFFERENT inode). When
            // no host stat exists (MemoryBackend), the path-stat is ALSO the
            // synthetic record, so the `fallback` already matches.
            OpenStatSource::PathRecord { path, fallback } => {
                if let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&path, true) {
                    Ok(StatRecord::from_real(&path, &real))
                } else if let Some(real) = self
                    .fs
                    .vfs_mounts
                    .resolve(&path)
                    .and_then(|m| m.vfs.real_stat(&m.full_path, true))
                {
                    // The path-stat (newfstatat) falls through to the VFS mount
                    // table when the overlay misses — a bind mount (`-v`), /proc,
                    // /dev. Mirror it so a bind-mounted DIRECTORY's fstat reports
                    // the SAME (real host) inode as its path-stat; otherwise
                    // SameFile(fstat(open(dir)), stat(dir)) is false (Go os
                    // TestFileChdir; Python os.path.samestat). Without this the
                    // fd fell back to the path-HASH inode while the path-stat
                    // returned the real host inode.
                    Ok(StatRecord::from_real(&path, &real))
                } else {
                    Ok(fallback)
                }
            }
            OpenStatSource::HostFile { host_fd, metadata } => {
                let path = metadata.path.to_string_lossy().into_owned();
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(host_fd.get(), &mut st) } == 0 {
                    let mut real = super::real_stat_from_libc(&st);
                    // The real file's mode was forced owner-accessible; the
                    // guest-visible mode + owner live in xattrs on the same fd.
                    // For a mknod(2) device-node MARKER the mode xattr carries the
                    // FULL guest mode (S_IFCHR/S_IFBLK type bits); RealStat.mode is
                    // perms-only, so keep just the perms here and recover the
                    // device TYPE + st_rdev below via apply_device_node.
                    let device = match crate::fs_backend::fget_mode_xattr(host_fd.get()) {
                        Some(m) => {
                            real.mode = m & 0o7777;
                            let type_bits = m & LINUX_S_IFMT;
                            if type_bits == LINUX_S_IFCHR || type_bits == LINUX_S_IFBLK {
                                Some((
                                    type_bits,
                                    crate::fs_backend::fget_rdev_xattr(host_fd.get()).unwrap_or(0),
                                ))
                            } else {
                                None
                            }
                        }
                        None => None,
                    };
                    let (uid, gid) = crate::fs_backend::fget_owner_xattr(host_fd.get());
                    real.uid = uid.unwrap_or(0);
                    real.gid = gid.unwrap_or(0);
                    let mut record = StatRecord::from_real(&path, &real);
                    record.apply_device_node(device);
                    return Ok(record);
                }
                Ok(StatRecord::from_metadata(&metadata))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_stream_file(
        host_fd: i32,
        pipe_id: u64,
        is_read_end: bool,
        write_kind: HostWriteKind,
    ) -> OpenFile {
        OpenFile::from_open_description(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                base: OpenDescriptionBase::new(if is_read_end {
                    LINUX_O_RDONLY
                } else {
                    LINUX_O_WRONLY
                }),
                host_fd: HostFdRef::new(host_fd),
                is_read_end,
                pipe_id,
                pty: None,
                bidirectional: false,
                write_kind,
            })),
            0,
        )
    }

    #[test]
    fn host_stream_stats_distinguish_devices_and_preserve_pipe_identity() {
        let dispatcher = SyscallDispatcher::new();
        let mut pipe_fds = [-1; 2];
        // SAFETY: `pipe_fds` has space for both output descriptors.
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        // SAFETY: static NUL-terminated path; returned fd is owned below.
        let null_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
        assert!(null_fd >= 0);

        let pipe_identity = host_inode_pipe_id(pipe_fds[0]);
        let null_identity = host_inode_pipe_id(null_fd);
        assert_ne!(pipe_identity, 0);
        assert_ne!(null_identity, 0);
        {
            let file_table = dispatcher.captured_file_table();
            let mut files = file_table.write_open_files();
            files.insert(
                20,
                host_stream_file(pipe_fds[0], pipe_identity, true, HostWriteKind::PipeLike),
            );
            files.insert(
                21,
                host_stream_file(pipe_fds[1], pipe_identity, false, HostWriteKind::PipeLike),
            );
            files.insert(
                22,
                host_stream_file(null_fd, null_identity, false, HostWriteKind::RegularFile),
            );
        }

        let pipe_read = dispatcher.fd_stat_record(20).expect("pipe read stat");
        let pipe_write = dispatcher.fd_stat_record(21).expect("pipe write stat");
        let null = dispatcher.fd_stat_record(22).expect("null stat");
        assert_eq!(pipe_read.ino, pipe_write.ino);
        assert_ne!(pipe_read.ino, null.ino);
        assert_eq!(pipe_read.mode & LINUX_S_IFMT, LINUX_S_IFIFO);
        assert_eq!(null.mode & LINUX_S_IFMT, LINUX_S_IFCHR);

        let pipe_link = dispatcher
            .open_file(20)
            .and_then(|file| file.description.read().readlink_target())
            .expect("pipe readlink target");
        assert_eq!(pipe_link, format!("pipe:[{}]", pipe_read.ino));
    }
}
