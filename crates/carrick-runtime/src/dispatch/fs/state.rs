//! Filesystem and I/O state owned by the syscall dispatcher.

use super::super::*;
use crate::linux_abi::{LinuxDnotifyMask, LinuxErrno};
use std::sync::atomic::AtomicU64;

/// Guest-visible fd allocation pressure caused by host-backed path opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::dispatch) struct PathOpenFdPressure(usize);

impl PathOpenFdPressure {
    pub(in crate::dispatch) const fn new(limit: usize) -> Self {
        Self(limit)
    }

    pub(in crate::dispatch) fn is_exhausted_by(self, open_fd_count: usize) -> bool {
        open_fd_count >= self.0
    }
}

/// Path opens are much slower under HVF than Docker Linux. Keep the guest's
/// visible RLIMIT_NOFILE at Docker's 1M default, but stop path-open fd-fill
/// loops early enough that LTP reaches the same post-open assertions instead of
/// spending the whole per-test timeout opening host paths.
pub(in crate::dispatch) const PATH_OPEN_FD_PRESSURE: PathOpenFdPressure =
    PathOpenFdPressure::new(4 * 1024);

#[derive(Debug, Clone)]
pub(in crate::dispatch) struct DnotifyRegistration {
    pub(in crate::dispatch) fd: i32,
    pub(in crate::dispatch) tid: crate::thread::ThreadId,
    pub(in crate::dispatch) path: String,
    pub(in crate::dispatch) mask: LinuxDnotifyMask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::dispatch) struct LegacyAioContextId(u64);

impl LegacyAioContextId {
    pub(in crate::dispatch) fn from_guest(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    pub(in crate::dispatch) fn allocated_from(raw: u64) -> Self {
        Self(raw)
    }

    pub(in crate::dispatch) fn get(self) -> u64 {
        self.0
    }
}

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

    /// Dispatch-layer inotify watch table, keyed by guest path. Populated by
    /// `inotify_add_watch`, drained by the fs handlers, which synthesize the
    /// precise `IN_OPEN`/`IN_ACCESS`/`IN_MODIFY`/`IN_CLOSE_*`/`IN_CREATE`/
    /// `IN_DELETE`/`IN_MOVED_*` events the coarse kqueue `NOTE_*` set cannot
    /// express for same-process operations. Empty (the common case) → the
    /// handlers' notify calls are a single `is_empty` read and return.
    pub(in crate::dispatch) inotify_registry: crate::inotify::InotifyRegistry,

    /// Dnotify (`F_NOTIFY`) directory watches. Linux delivers `SIGIO` to the
    /// fd's async owner on matching directory changes. Carrick implements the
    /// same-process create/delete/rename cases exercised by LTP by piggybacking
    /// on the existing dispatch-layer mutation hooks.
    pub(in crate::dispatch) dnotify_registry: parking_lot::Mutex<Vec<DnotifyRegistration>>,

    /// Fork-coherent cache of `resolve_at_path` results (guest AT_FDCWD
    /// absolute path -> canonical host-side path). Under `--fs host` a resolve
    /// re-walks the path on the host (one-to-many `openat`s); a syscall-bound
    /// loop on ONE stable path (LTP `tst_fuzzy_sync` `inotify_add_watch`) pays
    /// it every iteration. Validated against a `MAP_SHARED` generation bumped
    /// on structural fs mutations, so a sibling's mkdir/rename/unlink correctly
    /// invalidates it. See [`crate::fs_resolve_cache`].
    pub(in crate::dispatch) resolve_cache: crate::fs_resolve_cache::ResolveCache,
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
    /// Which bare stdio fds (0/1/2) the guest has explicitly `close`d. A closed
    /// stdio number becomes free for reuse by the lowest-free-descriptor
    /// allocator (POSIX): busybox ash's background-job `forkchild` does
    /// `close(0); open("/dev/null")` and treats a non-zero return as an error.
    /// Without honoring this, the open got fd 3 and ash printed "can't open
    /// /dev/null". Cleared when a fd is installed at that number again.
    pub closed_stdio: Mutex<[bool; 3]>,
    /// Guest path each open fd was opened at, regardless of backend (host-fd
    /// backed `OpenDescription`s carry no path of their own). Serves
    /// `readlink(/proc/self/fd/N)` — Apple Rosetta readlinks its main-binary fd
    /// to recover the binary path. Best-effort: populated on open, cleared on
    /// close (a stale entry for a recycled fd is overwritten by the next open).
    pub fd_open_paths: RwLock<HashMap<i32, String>>,
    /// Bytes pulled from a host pipe by splice but not accepted by the
    /// destination yet. Linux does not consume pipe bytes when splice returns
    /// EAGAIN on the output side; host pipes have no peek API, so Carrick stages
    /// the bytes here and retries them before reading more from the host pipe.
    pub splice_pushback: Mutex<HashMap<i32, VecDeque<u8>>>,
    /// Live io_uring instances keyed by ring fd (WS-H4-B1). Side table rather
    /// than an `OpenDescription` variant so io_uring needs no new arm across the
    /// ~24 fd match sites; `mmap`/`io_uring_enter` look the ring up here.
    pub io_uring_instances: RwLock<HashMap<i32, crate::dispatch::ioring::IoUringState>>,
    /// Minimal legacy Linux AIO contexts (`io_setup`/`io_destroy`/`io_submit`).
    /// Carrick services the currently covered AIO contract synchronously, but
    /// still needs a real context namespace so invalid-context checks match
    /// Linux instead of degrading to ENOSYS/TCONF.
    pub legacy_aio_contexts: RwLock<std::collections::BTreeSet<LegacyAioContextId>>,
    /// Raw allocation counter. It is wrapped into `LegacyAioContextId` before
    /// entering the guest-visible context namespace.
    pub next_legacy_aio_context: AtomicU64,
    /// Guest soft RLIMIT_NOFILE: the highest fd the allocator hands out
    /// (`fd < nofile_soft`). The default mirrors Docker's LTP oracle and
    /// carrick's exposed `nr_open` ceiling; a guest may lower/raise it via
    /// setrlimit/prlimit64 (libuv's TEST_FILE_LIMIT does). Lock-free so the fd
    /// allocator can read it while holding open_files (never the proc lock).
    pub nofile_soft: AtomicU64,
    /// Guest fds that have hosted an epoll interest set (recorded at
    /// `epoll_ctl`). Lets the Linux lane's consumption-based EPOLLET re-arm
    /// ([`crate::dispatch::SyscallDispatcher::epoll_rearm_after_io`]) find the
    /// epoll instances possibly watching an fd without scanning the whole fd
    /// table on every guest read/write. Entries are pruned lazily: a stale fd
    /// (closed / recycled as a non-epoll) is removed when the re-arm next
    /// visits it.
    pub epoll_fds: RwLock<std::collections::BTreeSet<i32>>,
}

/// Default soft RLIMIT_NOFILE. Docker's LTP oracle starts processes with the
/// soft cap raised to the Linux `nr_open` ceiling; matching that avoids a
/// guest-visible split between `getrlimit(RLIMIT_NOFILE)`,
/// `/proc/sys/fs/nr_open`, and fd allocation.
pub(in crate::dispatch) const DEFAULT_NOFILE_SOFT: u64 = 1024 * 1024;

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
            closed_stdio: Mutex::new([false; 3]),
            fd_open_paths: RwLock::new(HashMap::new()),
            splice_pushback: Mutex::new(HashMap::new()),
            io_uring_instances: RwLock::new(HashMap::new()),
            legacy_aio_contexts: RwLock::new(std::collections::BTreeSet::new()),
            next_legacy_aio_context: AtomicU64::new(1),
            nofile_soft: AtomicU64::new(DEFAULT_NOFILE_SOFT),
            epoll_fds: RwLock::new(std::collections::BTreeSet::new()),
        }
    }
}

pub(super) fn flush_host_fd(host_fd: i32) -> Result<(), LinuxErrno> {
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

pub(super) fn host_fd_offset(host_fd: crate::dispatch::HostFd) -> Option<u64> {
    let offset = unsafe { libc::lseek(host_fd.get(), 0, libc::SEEK_CUR) };
    if offset < 0 {
        return None;
    }
    Some(offset as u64)
}

#[cfg(target_os = "macos")]
pub(super) fn set_host_fd_offset(host_fd: crate::dispatch::HostFd, offset: u64) -> bool {
    let Ok(offset) = libc::off_t::try_from(offset) else {
        return false;
    };
    (unsafe { libc::lseek(host_fd.get(), offset, libc::SEEK_SET) }) >= 0
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
                m.mount("/etc/services", Box::new(crate::vfs::EtcServicesVfs::new()));
                // POSIX shared-memory: Linux apps (and LTP's `tst_test` —
                // ~10 SIGNALS-area tests TBROKed without it) expect /dev/shm
                // to be a writable tmpfs-style directory where MAP_SHARED
                // files live. Bind-mount a per-process host directory under
                // <tempdir>/carrick-shm-<pid>/ so the kernel-backed file is a
                // real host file (which the existing mmap MAP_SHARED alias
                // machinery already handles fork-coherently). The
                // longest-prefix-wins mount table takes precedence over the
                // /dev DevVfs mount for /dev/shm/*.
                //
                // Use the host's TEMP DIR (`std::env::temp_dir()`) rather than a
                // hardcoded macOS path: `/private/tmp` is the real path `/tmp`
                // resolves to on macOS, but it does not exist on Linux (and an
                // unprivileged user cannot create `/private`), so the old
                // hardcoded path left the backing dir absent on the KVM/Linux
                // host — `/dev/shm` then `lookup`ed to a missing host dir and
                // the guest saw ENOENT ("No such file or directory"). The temp
                // dir resolves to `/var/folders/...` (macOS), `/tmp` (Linux),
                // honoring `$TMPDIR`, so this is portable across HVF and KVM.
                let shm_host =
                    std::env::temp_dir().join(format!("carrick-shm-{}", std::process::id()));
                let _ = std::fs::create_dir_all(&shm_host);
                // POSIX `/dev/shm` is a `rwxrwxrwt` (sticky, world-writable)
                // tmpfs — `shm_open(3)`/`sem_open(3)` create world-accessible
                // nodes there. Stamp the standard 0o1777 so the mount point
                // itself reports drwxrwxrwt (the BindVfs `lookup` reflects the
                // host dir's real mode) and so multi-process SHM works.
                use std::os::unix::fs::PermissionsExt as _;
                let _ =
                    std::fs::set_permissions(&shm_host, std::fs::Permissions::from_mode(0o1777));
                m.mount(
                    "/dev/shm",
                    Box::new(crate::vfs::BindVfs::new("/dev/shm", shm_host, false)),
                );
                m
            },
            rootfs_vfs: crate::vfs::RootFsVfs::new(),
            pty_table,
            inotify_registry: crate::inotify::InotifyRegistry::default(),
            dnotify_registry: parking_lot::Mutex::new(Vec::new()),
            resolve_cache: crate::fs_resolve_cache::ResolveCache::new(),
        }
    }
}
