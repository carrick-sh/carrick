//! Filesystem and I/O state owned by the syscall dispatcher.

use super::super::*;

/// Owned filesystem-subsystem state. Split out of `SyscallDispatcher` so
/// the fs handlers borrow only the VFS state they touch instead of the
/// whole dispatcher. Field semantics are unchanged from the former loose
/// fields (`vfs_mounts`/`rootfs_vfs`).
pub(in crate::dispatch) struct FsState {
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

    /// Shared pseudo-terminal table, also cloned into the /dev (ptmx) and
    /// /dev/pts mounts. The ioctl (TIOCSPTLCK) and close (free-on-master-
    /// close) paths reach it through the dispatcher.
    pub(in crate::dispatch) pty_table: std::sync::Arc<parking_lot::Mutex<crate::vfs::PtyTable>>,
}

/// Owned I/O-subsystem state. Split out of `SyscallDispatcher` so the I/O
/// handlers borrow only the fd/stdio state they touch. Field semantics are
/// unchanged from the former loose fields (`stdout`/`stderr`/`stream_stdio`/
/// `open_files`/`next_fd`/`cwd`).
pub(in crate::dispatch) struct IoState {
    pub stdout: Mutex<Vec<u8>>,
    pub stderr: Mutex<Vec<u8>>,
    /// When true, writes to fd 1/2 stream directly to host fds 1/2
    /// instead of buffering into `stdout`/`stderr`. Set by `--raw`/the
    /// interactive runtime so the user sees the guest's prompt and
    /// output in real time, instead of after exit.
    pub stream_stdio: Mutex<bool>,
    pub open_files: RwLock<HashMap<i32, OpenFile>>,
    pub next_fd: Mutex<i32>,
    pub cwd: RwLock<String>,
    /// FD_CLOEXEC state for bare stdio fds (0/1/2) that have no
    /// `OpenDescription` in `open_files`. Linux lets `fcntl(F_SETFD,
    /// FD_CLOEXEC)` on stdio and a subsequent `F_GETFD` reflects the bit;
    /// without persisting it here, F_GETFD always read back 0 (diverging
    /// from real Linux on the fcntlstdio conformance probe).
    pub stdio_cloexec: Mutex<[bool; 3]>,
    /// Guest path each open fd was opened at, regardless of backend (host-fd
    /// backed `OpenDescription`s carry no path of their own). Serves
    /// `readlink(/proc/self/fd/N)` — Apple Rosetta readlinks its main-binary fd
    /// to recover the binary path. Best-effort: populated on open, cleared on
    /// close (a stale entry for a recycled fd is overwritten by the next open).
    pub fd_open_paths: RwLock<HashMap<i32, String>>,
}

impl IoState {
    pub(in crate::dispatch) fn new() -> Self {
        Self {
            stdout: Mutex::new(Vec::new()),
            stderr: Mutex::new(Vec::new()),
            stream_stdio: Mutex::new(false),
            open_files: RwLock::new(HashMap::new()),
            next_fd: Mutex::new(3),
            cwd: RwLock::new("/".to_owned()),
            stdio_cloexec: Mutex::new([false; 3]),
            fd_open_paths: RwLock::new(HashMap::new()),
        }
    }
}

pub(super) fn flush_host_fd(host_fd: i32) -> Result<(), i32> {
    unsafe { libc::fsync(host_fd) }.host_syscall_errno()?;
    #[cfg(target_os = "macos")]
    if strict_durability_enabled() {
        unsafe { libc::fcntl(host_fd, libc::F_FULLFSYNC) }.host_syscall_errno()?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn strict_durability_enabled() -> bool {
    std::env::var_os("CARRICK_STRICT_DURABILITY").is_some_and(|value| value != "0")
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy)]
pub(super) struct HostFileCopyInfo {
    pub(super) host_fd: i32,
    pub(super) size: u64,
    pub(super) writable: bool,
}

#[cfg(target_os = "macos")]
pub(super) fn host_fd_offset(host_fd: i32) -> Option<u64> {
    let offset = unsafe { libc::lseek(host_fd, 0, libc::SEEK_CUR) };
    if offset < 0 {
        return None;
    }
    Some(offset as u64)
}

#[cfg(target_os = "macos")]
pub(super) fn set_host_fd_offset(host_fd: i32, offset: u64) -> bool {
    let Ok(offset) = libc::off_t::try_from(offset) else {
        return false;
    };
    (unsafe { libc::lseek(host_fd, offset, libc::SEEK_SET) }) >= 0
}

impl FsState {
    pub(in crate::dispatch) fn new() -> Self {
        let pty_table = std::sync::Arc::new(parking_lot::Mutex::new(crate::vfs::PtyTable::new()));
        Self {
            vfs_mounts: {
                let mut m = crate::vfs::VfsMounts::new();
                m.mount(
                    "/dev",
                    Box::new(crate::vfs::DevVfs::new(std::sync::Arc::clone(&pty_table))),
                );
                m.mount(
                    "/dev/pts",
                    Box::new(crate::vfs::DevptsVfs::new(std::sync::Arc::clone(
                        &pty_table,
                    ))),
                );
                m.mount("/proc", Box::new(crate::vfs::ProcVfs::new()));
                m.mount("/sys", Box::new(crate::vfs::SysVfs::new()));
                // Inject a working /etc/resolv.conf synthesized from the macOS
                // host DNS config (the `--net host` / docker contract), so the
                // guest resolver gets real nameservers instead of ENOENT →
                // `[::1]:53` fallback. A single-file mount, so it shadows only
                // this exact path; the rest of /etc comes from the rootfs.
                m.mount(
                    "/etc/resolv.conf",
                    Box::new(crate::vfs::ResolvConfVfs::new()),
                );
                // /etc/services from the macOS host (format-identical to Linux),
                // so the guest's getservbyname/port lookups work under --fs host
                // (the scratch has no /etc/services). Single-file mount.
                m.mount(
                    "/etc/services",
                    Box::new(crate::vfs::EtcServicesVfs::new()),
                );
                m
            },
            rootfs_vfs: crate::vfs::RootFsVfs::new(),
            pty_table,
        }
    }
}
