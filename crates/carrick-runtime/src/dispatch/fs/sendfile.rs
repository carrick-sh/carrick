//! `sendfile`/`copy_file_range` data-movement helpers: the offset resolver,
//! the in-memory/HostFile byte reader, and the Darwin `copyfile`/`fclonefileat`
//! fast path. Split out of `dispatch/fs.rs` (WS-F3) as `impl SyscallDispatcher`
//! methods; the move is type-transparent to `self.…` callers.
use super::*;
use crate::linux_abi::LinuxErrno;

/// `CARRICK_DARWIN_COPYFILE_FAST_PATH=0` disables the whole-file
/// `copyfile`/`fclonefileat` fast path in `copy_file_range`, falling back to
/// the ordinary read-then-write body. Default ON; the hatch exists so the
/// fast path can be ablated when attributing a data-corruption bug.
#[cfg(target_os = "macos")]
fn darwin_copyfile_fast_path_disabled() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISABLED.get_or_init(|| {
        std::env::var_os("CARRICK_DARWIN_COPYFILE_FAST_PATH").is_some_and(|value| value == "0")
    })
}

impl SyscallDispatcher {
    /// copy_file_range(2): like sendfile but file-to-file with independent
    /// in/out offset pointers. coreutils `cat`/`cp` and apt/dpkg use it for
    /// efficient copies; it was unimplemented and the panic-on-unknown guard
    /// turned that into a hard abort. We read from in_fd at its (pointer or
    /// current) offset and write to out_fd, reusing the sendfile machinery.
    #[cfg(target_os = "macos")]
    pub(super) fn try_darwin_copyfile_range_fast_path(
        &self,
        in_fd: i32,
        in_offset: usize,
        off_in_addr: u64,
        out_fd: i32,
        off_out_addr: u64,
        count: usize,
    ) -> Result<Option<DispatchOutcome>, DispatchError> {
        if off_in_addr != 0 || off_out_addr != 0 || in_offset != 0 {
            return Ok(None);
        }
        // Exact ablation hatch. This fast path validates its preconditions by
        // reading both HOST fd offsets, which forked guest processes share, so
        // it is the leading suspect for the 1-in-10 corrupt Go build-cache
        // archive. Shipping ON, with `=0` to bisect it, is the rule; a fast
        // path with no way to turn it off cannot be attributed.
        if darwin_copyfile_fast_path_disabled() {
            return Ok(None);
        }

        let Some(input) = self.host_file_copy_info(in_fd) else {
            return Ok(None);
        };
        let Some(output) = self.host_file_copy_info(out_fd) else {
            return Ok(None);
        };
        if !output.writable {
            return Ok(Some(DispatchOutcome::errno(LINUX_EBADF)));
        }
        if input.size == 0
            || output.size != 0
            || count
                < usize::try_from(input.size)
                    .map_err(|_| DispatchError::LengthTooLarge(input.size))?
        {
            return Ok(None);
        }
        let (Some(input_offset), Some(output_offset)) = (
            host_fd_offset(HostFd(input.host_fd)),
            host_fd_offset(HostFd(output.host_fd)),
        ) else {
            return Ok(None);
        };
        if input_offset != 0 || output_offset != 0 {
            return Ok(None);
        }

        match crate::darwin_fs::copyfile_clone_or_data(input.host_fd, output.host_fd, input.size) {
            Ok(Some(result)) => {
                let copied = result.bytes();
                if !set_host_fd_offset(HostFd(input.host_fd), copied)
                    || !set_host_fd_offset(HostFd(output.host_fd), copied)
                {
                    return Ok(None);
                }
                Ok(Some(DispatchOutcome::Returned {
                    value: i64::try_from(copied)
                        .map_err(|_| DispatchError::LengthTooLarge(copied))?,
                }))
            }
            Ok(None) => Ok(None),
            Err(errno) => Ok(Some(DispatchOutcome::errno(errno))),
        }
    }

    /// True iff `a` and `b` refer to the SAME underlying file — the same fd, or
    /// two host fds on the same `(st_dev, st_ino)`. Used by `copy_file_range` to
    /// reject an overlapping copy onto the same file (Linux returns EINVAL). A
    /// non-host description, or a host `fstat` failure, is treated as "cannot
    /// prove same file" (false) so a legitimate distinct-file copy is never
    /// rejected.
    pub(super) fn copy_same_file(&self, a: i32, b: i32) -> bool {
        if a == b {
            return true;
        }
        match (self.host_fd_dev_ino(a), self.host_fd_dev_ino(b)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        }
    }

    fn host_fd_dev_ino(&self, fd: i32) -> Option<(i64, u64)> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        let OpenDescription::HostFile { host_fd, .. } = &*open else {
            return None;
        };
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(host_fd.raw(), st.as_mut_ptr()) } != 0 {
            return None;
        }
        let st = unsafe { st.assume_init() };
        Some((st.st_dev as i64, st.st_ino))
    }

    // Only the Darwin copyfile/fclonefileat fast path (above, macOS-gated) uses
    // this; HostFileCopyInfo is itself macOS-only. On Linux copy_file_range
    // falls through to the portable buffer-copy path.
    #[cfg(target_os = "macos")]
    fn host_file_copy_info(&self, fd: i32) -> Option<HostFileCopyInfo> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        let OpenDescription::HostFile {
            host_fd, writable, ..
        } = &*open
        else {
            return None;
        };
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(host_fd.raw(), st.as_mut_ptr()) } != 0 {
            return None;
        }
        let st = unsafe { st.assume_init() };
        if st.st_size < 0 {
            return None;
        }
        Some(HostFileCopyInfo {
            host_fd: host_fd.raw(),
            size: st.st_size as u64,
            writable: *writable,
        })
    }

    pub(super) fn sendfile_offset(
        &self,
        in_fd: i32,
        offset_address: u64,
        memory: &impl GuestMemory,
    ) -> Result<Result<usize, LinuxErrno>, DispatchError> {
        if offset_address != 0 {
            return match read_u64(memory, offset_address) {
                Ok(offset) => {
                    Ok(Ok(usize::try_from(offset)
                        .map_err(|_| DispatchError::LengthTooLarge(offset))?))
                }
                Err(errno) => Ok(Err(errno)),
            };
        }
        let Some(in_file) = self.open_file(in_fd) else {
            return Ok(Err(LINUX_EBADF));
        };
        let open = in_file.description.read();
        match &*open {
            OpenDescription::Closed { .. } => Ok(Err(LINUX_EBADF)),
            OpenDescription::File { offset, .. }
            | OpenDescription::SyntheticFile { offset, .. } => Ok(Ok(*offset)),
            // HostFile: current offset is the kernel's; query via lseek.
            OpenDescription::HostFile { host_fd, .. } => {
                match (unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR) })
                    .host_syscall_errno()
                {
                    Ok(cur) => Ok(Ok(cur as usize)),
                    Err(errno) => Ok(Err(errno)),
                }
            }
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::Pidfd { .. }
            | OpenDescription::Inotify { .. }
            | OpenDescription::Fanotify { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::SignalFd { .. }
            | OpenDescription::FsContext { .. }
            | OpenDescription::Mqueue { .. }
            | OpenDescription::BpfMap { .. }
            | OpenDescription::BpfProg { .. }
            | OpenDescription::Netlink { .. } => Ok(Err(LINUX_EINVAL)),
        }
    }

    pub(super) fn sendfile_bytes(
        &self,
        in_fd: i32,
        offset: usize,
        count: usize,
    ) -> Result<Vec<u8>, LinuxErrno> {
        let Some(in_file) = self.open_file(in_fd) else {
            return Err(LINUX_EBADF);
        };
        let open = in_file.description.read();
        // HostFile: pread the requested window from the real fd. Cap the buffer:
        // callers (Go's poll.SendFile) pass count = INT_MAX, and a naive
        // `vec![0u8; count]` would zero-fill 2 GiB per call. Linux sendfile is
        // free to transfer fewer than `count` bytes (the caller loops), so read
        // at most one chunk; pread then truncates to what the file holds.
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            const SENDFILE_CHUNK: usize = 1 << 24; // 16 MiB
            let want = count.min(SENDFILE_CHUNK);
            let mut buf = vec![0u8; want];
            let n = unsafe {
                libc::pread(
                    host_fd.raw(),
                    buf.as_mut_ptr() as *mut _,
                    want,
                    offset as libc::off_t,
                )
            };
            let n = n.host_syscall_errno()?;
            buf.truncate(n as usize);
            return Ok(buf);
        }
        let bytes = match &*open {
            OpenDescription::Closed { .. } => return Err(LINUX_EBADF),
            OpenDescription::File { contents, .. } => contents.read_at(offset, count),
            OpenDescription::SyntheticFile { contents, .. } => {
                let available = contents.get(offset..).unwrap_or_default();
                let write_len = available.len().min(count);
                available[..write_len].to_vec()
            }
            OpenDescription::HostFile { .. } => return Err(LINUX_EINVAL),
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::Pidfd { .. }
            | OpenDescription::Inotify { .. }
            | OpenDescription::Fanotify { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::SignalFd { .. }
            | OpenDescription::FsContext { .. }
            | OpenDescription::Mqueue { .. }
            | OpenDescription::BpfMap { .. }
            | OpenDescription::BpfProg { .. }
            | OpenDescription::Netlink { .. } => return Err(LINUX_EINVAL),
        };
        Ok(bytes)
    }
}
