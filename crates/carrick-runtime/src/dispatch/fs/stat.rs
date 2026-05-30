//! fd stat/statx record assembly split out of dispatch/fs.rs (WS-F3):
//! the synthetic stdio (label, st_mode) probe and the fstat/statx
//! buffer writers + StatRecord builder. Pure `impl SyscallDispatcher` move.
use super::*;

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

    pub(super) fn fd_stat_record(&self, fd: i32) -> Result<StatRecord, i32> {
        let Some(open_file) = self.open_file(fd) else {
            if is_stdio_fd(fd) {
                let (label, mode) = self.stdio_synthetic_label_mode(fd);
                return Ok(StatRecord::synthetic(&label, 0, mode));
            }
            return Err(LINUX_EBADF);
        };
        let open = open_file.description.read();
        let source = open.stat_source();
        drop(open);
        match source {
            OpenStatSource::Record(record) => Ok(record),
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
                } else {
                    Ok(fallback)
                }
            }
            OpenStatSource::HostFile { host_fd, metadata } => {
                let path = metadata.path.to_string_lossy().into_owned();
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(host_fd, &mut st) } == 0 {
                    let mut real = super::real_stat_from_libc(&st);
                    // The real file's mode was forced owner-accessible; the
                    // guest-visible mode + owner live in xattrs on the same fd.
                    if let Some(m) = crate::fs_backend::fget_mode_xattr(host_fd) {
                        real.mode = m;
                    }
                    let (uid, gid) = crate::fs_backend::fget_owner_xattr(host_fd);
                    real.uid = uid.unwrap_or(0);
                    real.gid = gid.unwrap_or(0);
                    return Ok(StatRecord::from_real(&path, &real));
                }
                Ok(StatRecord::from_metadata(&metadata))
            }
        }
    }
}
