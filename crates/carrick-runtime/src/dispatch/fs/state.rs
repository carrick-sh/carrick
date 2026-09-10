//! Filesystem and I/O state owned by the syscall dispatcher.

use super::super::*;
use crate::linux_abi::{LinuxDnotifyMask, LinuxErrno};
use carrick_fatal::carrick_fatal;

#[derive(Debug, Clone)]
pub(in crate::dispatch) struct DnotifyRegistration {
    pub(in crate::dispatch) fd: i32,
    pub(in crate::dispatch) tid: crate::thread::ThreadId,
    pub(in crate::dispatch) path: String,
    pub(in crate::dispatch) mask: LinuxDnotifyMask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LegacyAioContextId(u64);

impl LegacyAioContextId {
    pub(in crate::dispatch) fn from_guest(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    pub(crate) fn allocated_from(raw: u64) -> Self {
        Self(raw)
    }

    pub(in crate::dispatch) fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SplicePushback {
    chunks: VecDeque<SplicePushbackChunk>,
    len: usize,
}

#[derive(Clone, Debug)]
struct SplicePushbackChunk {
    bytes: Vec<u8>,
    offset: usize,
}

impl SplicePushback {
    pub(in crate::dispatch) fn len(&self) -> usize {
        self.len
    }

    pub(in crate::dispatch) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(in crate::dispatch) fn push_back_owned(&mut self, bytes: Vec<u8>) {
        self.push_owned(bytes, PushbackEnd::Back);
    }

    pub(in crate::dispatch) fn push_front(&mut self, bytes: &[u8]) {
        self.push_owned(bytes.to_vec(), PushbackEnd::Front);
    }

    pub(in crate::dispatch) fn take_vec(&mut self, count: usize) -> Vec<u8> {
        let Some(chunk) = self.chunks.front() else {
            return Vec::new();
        };
        let available = chunk.bytes.len().saturating_sub(chunk.offset);
        if chunk.offset == 0 && available == count {
            if let Some(chunk) = self.chunks.pop_front() {
                self.len -= count;
                return chunk.bytes;
            }
        }

        let mut out = Vec::with_capacity(count.min(self.len));
        self.take_into(count, &mut out);
        out
    }

    pub(in crate::dispatch) fn take_into(&mut self, count: usize, out: &mut Vec<u8>) {
        let mut remaining = count;
        while remaining > 0 {
            let Some(chunk) = self.chunks.front_mut() else {
                break;
            };
            let available = chunk.bytes.len().saturating_sub(chunk.offset);
            if available == 0 {
                self.chunks.pop_front();
                continue;
            }
            let take = remaining.min(available);
            out.extend_from_slice(&chunk.bytes[chunk.offset..chunk.offset + take]);
            chunk.offset += take;
            self.len -= take;
            remaining -= take;
            if chunk.offset == chunk.bytes.len() {
                self.chunks.pop_front();
            }
        }
    }

    #[cfg(test)]
    pub(in crate::dispatch) fn chunk_count_for_tests(&self) -> usize {
        self.chunks.len()
    }

    fn push_owned(&mut self, bytes: Vec<u8>, end: PushbackEnd) {
        if bytes.is_empty() {
            return;
        }
        let len = bytes.len();
        let chunk = SplicePushbackChunk { bytes, offset: 0 };
        self.len += len;
        match end {
            PushbackEnd::Front => self.chunks.push_front(chunk),
            PushbackEnd::Back => self.chunks.push_back(chunk),
        }
    }
}

enum PushbackEnd {
    Front,
    Back,
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
    pub vfs_mounts: std::sync::Arc<crate::vfs::VfsMounts>,

    /// The `/` mount: immutable OCI rootfs + writable overlay
    /// ([`FsBackend`]). Held as a typed field rather than mounted in
    /// `vfs_mounts` because the dispatcher's existing fs syscalls reach
    /// into the overlay/rootfs state through ~50 call sites today.
    pub rootfs_vfs: std::sync::Arc<crate::vfs::RootFsVfs>,

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

    /// Dispatch-layer fanotify mark table. Same seam as `inotify_registry`, but
    /// SHARED by `Arc` across guest fork rather than deep-copied: a fanotify
    /// mark lives on the inode and its group outlives any one fd, so a forked
    /// child must keep generating events into the group its parent reads even
    /// after the child closes its own inherited fd (LTP `fanotify12`). Empty in
    /// the common case → the fs hooks cost one uncontended read lock.
    pub(in crate::dispatch) fanotify_registry: crate::fanotify::FanotifyRegistry,

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

    /// Fully prepared, stack-independent HvPatch exec images keyed by real
    /// host-file identity and mutation timestamps. Shared by every in-process
    /// child: repeatedly starting the Go compiler must not re-read, re-parse,
    /// and re-patch the same ELF. Non-host-backed targets bypass this cache.
    pub(in crate::dispatch) hvpatch_exec_cache:
        std::sync::Arc<parking_lot::Mutex<HashMap<String, crate::memory::AddressSpace>>>,

    /// Classic POSIX record locks for backends that multiplex multiple Linux
    /// processes inside one host process. HVPatch task generations are the
    /// owners; host-process-backed lanes continue using the host fcntl table.
    pub(in crate::dispatch) classic_record_locks: std::sync::Arc<super::LogicalRecordLocks>,
}

/// Exclusive terminal ownership of one container's immutable mount-routing
/// table. Capturing this token seals mount configuration: every dispatcher
/// fork and archive endpoint keeps an `Arc` alias while it can still perform a
/// lookup, and retirement succeeds only after all of those aliases have been
/// joined and dropped. This preserves the lock-free `entries` read path.
pub(crate) struct MountRetirement {
    container: crate::kernel::ContainerId,
    mounts: Option<std::sync::Arc<crate::vfs::VfsMounts>>,
    prepared: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum MountRetirementError {
    #[error("mount retirement belongs to container {actual:?}, not {expected:?}")]
    WrongContainer {
        expected: crate::kernel::ContainerId,
        actual: crate::kernel::ContainerId,
    },
    #[error("container {container:?} still has {owners} live mount-table owners")]
    LiveOwners {
        container: crate::kernel::ContainerId,
        owners: usize,
    },
    #[error("container mount table was already retired")]
    AlreadyRetired,
}

impl MountRetirement {
    pub(crate) fn new(
        container: crate::kernel::ContainerId,
        mounts: std::sync::Arc<crate::vfs::VfsMounts>,
    ) -> Self {
        Self {
            container,
            mounts: Some(mounts),
            prepared: false,
        }
    }

    pub(crate) fn mount_count(&self) -> usize {
        self.mounts.as_ref().map_or(0, |mounts| mounts.len())
    }

    /// Prove that the run loop, every forked dispatcher and archive control
    /// endpoint have relinquished this exact table. Once this succeeds no
    /// actor remains that could create a new `Arc` alias.
    pub(crate) fn prepare(&mut self) -> Result<(), MountRetirementError> {
        let mounts = self
            .mounts
            .as_ref()
            .ok_or(MountRetirementError::AlreadyRetired)?;
        let owners = std::sync::Arc::strong_count(mounts);
        if owners != 1 {
            return Err(MountRetirementError::LiveOwners {
                container: self.container,
                owners,
            });
        }
        self.prepared = true;
        Ok(())
    }

    pub(crate) fn prepare_for(
        &mut self,
        container: crate::kernel::ContainerId,
    ) -> Result<(), MountRetirementError> {
        if self.container != container {
            return Err(MountRetirementError::WrongContainer {
                expected: container,
                actual: self.container,
            });
        }
        self.prepare()
    }

    /// Drain and drop every mount before the teardown receipt is returned.
    /// `prepare` made the `try_unwrap` invariant stable; failure here means an
    /// impossible post-quiesce ownership change, so continuing would fabricate
    /// cleanup evidence.
    pub(crate) fn clear(&mut self) -> usize {
        if !self.prepared {
            carrick_fatal!(
                "dispatch::mount_retirement",
                "mount destruction requested without first proving sole ownership"
            );
        }
        let mounts = self.mounts.take().unwrap_or_else(|| {
            carrick_fatal!(
                "dispatch::mount_retirement",
                "prepared mount-retirement token lost its mount table before destruction"
            );
        });
        let mut mounts = std::sync::Arc::try_unwrap(mounts).unwrap_or_else(|shared| {
            carrick_fatal!(
                "dispatch::mount_retirement",
                "a new mount-table owner appeared after sole ownership was proven: strong={}",
                std::sync::Arc::strong_count(&shared)
            );
        });
        let count = mounts.clear_all();
        self.prepared = false;
        count
    }
}

/// Where a guest's bare fd 1/2 bytes go for the whole run. Chosen at
/// `Runtime::prepare`, sealed at boot, inherited by every logical child.
pub enum StdioSink {
    /// Buffer into `RunResult::{stdout,stderr}`; nothing reaches the host fds.
    Captured,
    /// Write through to the carrier's own host fds 1/2 — `docker run` shape,
    /// the CLI default (`StdioMode::Inherit`).
    Inherit,
    /// The caller's writers. Each guest write(2)/writev(2) to fd 1/2 runs the
    /// matching writer on the guest's own vCPU thread under a mutex: a writer
    /// that blocks blocks THAT guest write (and any sibling writing the same
    /// stream), exactly as a full pipe would. Writer errors come back to the
    /// guest as the host errno translated to Linux (EPIPE stays EPIPE).
    Piped {
        stdout: Box<dyn std::io::Write + Send>,
        stderr: Box<dyn std::io::Write + Send>,
    },
}

/// Shared writer for one piped stream: the same `Arc` is cloned into every
/// logical child so the whole process tree drains into one caller writer.
pub(in crate::dispatch) type SharedWriter = Arc<Mutex<Box<dyn std::io::Write + Send>>>;

/// The dispatcher-side form of [`StdioSink`]: cheap to clone (only `Arc`s), so
/// a write reads the route once and drops the lock BEFORE the possibly
/// blocking host/caller write.
#[derive(Clone)]
pub(in crate::dispatch) enum StdioRoute {
    Captured,
    Inherit,
    Piped {
        stdout: SharedWriter,
        stderr: SharedWriter,
    },
}

impl From<StdioSink> for StdioRoute {
    fn from(sink: StdioSink) -> Self {
        match sink {
            StdioSink::Captured => StdioRoute::Captured,
            StdioSink::Inherit => StdioRoute::Inherit,
            StdioSink::Piped { stdout, stderr } => StdioRoute::Piped {
                stdout: Arc::new(Mutex::new(stdout)),
                stderr: Arc::new(Mutex::new(stderr)),
            },
        }
    }
}

/// Process-local output transport. Linux fd-table authority lives exclusively
/// in the captured Kernel [`crate::kernel::FileTable`].
pub(in crate::dispatch) struct RuntimeIo {
    pub stdout: Arc<Mutex<Vec<u8>>>,
    pub stderr: Arc<Mutex<Vec<u8>>>,
    /// Where bare fd 1/2 writes go. `Captured` (the default) appends to
    /// `stdout`/`stderr` above.
    route: Mutex<StdioRoute>,
}

impl RuntimeIo {
    pub(in crate::dispatch) fn new() -> Self {
        Self {
            stdout: Arc::new(Mutex::new(Vec::new())),
            stderr: Arc::new(Mutex::new(Vec::new())),
            route: Mutex::new(StdioRoute::Captured),
        }
    }

    pub(in crate::dispatch) fn set_sink(&self, sink: StdioSink) {
        *self.route.lock() = StdioRoute::from(sink);
    }

    /// A snapshot of the route; the lock is released before the caller writes.
    pub(in crate::dispatch) fn route(&self) -> StdioRoute {
        self.route.lock().clone()
    }

    /// Whether fd 1/2 are the carrier's real host fds (the only mode in which
    /// a guest `F_SETFL` on stdio must reach the host descriptor).
    pub(in crate::dispatch) fn inherits_host_stdio(&self) -> bool {
        matches!(*self.route.lock(), StdioRoute::Inherit)
    }

    pub(in crate::dispatch) fn fork_clone(&self) -> Self {
        Self {
            // A guest fork's children write into the same output buffers as their
            // parent, streaming each write into the shared destination as it happens.
            stdout: Arc::clone(&self.stdout),
            stderr: Arc::clone(&self.stderr),
            // Same route object: a piped tree shares ONE caller writer.
            route: Mutex::new(self.route()),
        }
    }
}

#[cfg(test)]
mod forked_descendants_capture_tests {
    use super::*;

    #[test]
    fn forked_descendants_share_one_capture_sink() {
        let root = RuntimeIo::new();
        let child = root.fork_clone();
        child.stdout.lock().extend_from_slice(b"child");
        child.stderr.lock().extend_from_slice(b"error");
        assert_eq!(&*root.stdout.lock(), b"child");
        assert_eq!(&*root.stderr.lock(), b"error");
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

pub(in crate::dispatch) fn host_fd_offset(host_fd: crate::dispatch::HostFd) -> Option<u64> {
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
    pub(in crate::dispatch) fn vfs_mounts_mut(&mut self) -> &mut crate::vfs::VfsMounts {
        let strong = std::sync::Arc::strong_count(&self.vfs_mounts);
        let Some(mounts) = std::sync::Arc::get_mut(&mut self.vfs_mounts) else {
            carrick_fatal!(
                "dispatch::fs_mounts",
                "VFS mounts cannot be reconfigured after guest fork: strong={strong}"
            );
        };
        mounts
    }

    pub(in crate::dispatch) fn rootfs_vfs_mut(&mut self) -> &mut crate::vfs::RootFsVfs {
        let strong = std::sync::Arc::strong_count(&self.rootfs_vfs);
        let Some(rootfs) = std::sync::Arc::get_mut(&mut self.rootfs_vfs) else {
            carrick_fatal!(
                "dispatch::fs_mounts",
                "rootfs cannot be reconfigured after guest fork: strong={strong}"
            );
        };
        rootfs
    }

    pub(in crate::dispatch) fn new_with_host_resolver(
        snapshot: Option<&crate::vfs::HostResolverSnapshot>,
    ) -> Self {
        let pty_table = std::sync::Arc::new(parking_lot::Mutex::new(crate::vfs::PtyTable::new()));
        Self {
            vfs_mounts: std::sync::Arc::new({
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
                    Box::new(
                        snapshot.map_or_else(crate::vfs::ResolvConfVfs::new, |snapshot| {
                            crate::vfs::ResolvConfVfs::from_host_snapshot(snapshot)
                        }),
                    ),
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
            }),
            rootfs_vfs: std::sync::Arc::new(crate::vfs::RootFsVfs::new()),
            pty_table,
            inotify_registry: crate::inotify::InotifyRegistry::default(),
            fanotify_registry: crate::fanotify::FanotifyRegistry::default(),
            dnotify_registry: parking_lot::Mutex::new(Vec::new()),
            resolve_cache: crate::fs_resolve_cache::ResolveCache::new(),
            hvpatch_exec_cache: std::sync::Arc::new(parking_lot::Mutex::new(HashMap::new())),
            classic_record_locks: std::sync::Arc::new(super::LogicalRecordLocks::default()),
        }
    }

    pub(in crate::dispatch) fn fork_clone(&self) -> Self {
        Self {
            vfs_mounts: std::sync::Arc::clone(&self.vfs_mounts),
            rootfs_vfs: std::sync::Arc::clone(&self.rootfs_vfs),
            pty_table: std::sync::Arc::clone(&self.pty_table),
            inotify_registry: self.inotify_registry.clone(),
            // Arc clone: the SAME table, not a copy. See the field docs.
            fanotify_registry: self.fanotify_registry.clone(),
            dnotify_registry: parking_lot::Mutex::new(self.dnotify_registry.lock().clone()),
            resolve_cache: crate::fs_resolve_cache::ResolveCache::new(),
            hvpatch_exec_cache: std::sync::Arc::clone(&self.hvpatch_exec_cache),
            classic_record_locks: std::sync::Arc::clone(&self.classic_record_locks),
        }
    }
}

#[cfg(test)]
mod fork_clone_tests {
    use super::*;

    #[test]
    fn forked_runtime_io_shares_output_buffers_and_preserves_sink() {
        let parent = RuntimeIo::new();
        parent.stdout.lock().extend_from_slice(b"parent");
        parent.set_sink(StdioSink::Inherit);

        let child = parent.fork_clone();

        assert_eq!(&*child.stdout.lock(), b"parent");
        assert!(child.stderr.lock().is_empty());
        assert!(matches!(child.route(), StdioRoute::Inherit));
        assert_eq!(&*parent.stdout.lock(), b"parent");
    }
}

#[cfg(test)]
mod stdio_sink_tests {
    use super::*;
    use crate::compat::{CompatReporter, SyscallArgs};
    use std::sync::Arc;

    /// A `Write` that records into a shared buffer so the test can read back
    /// what the guest's write(2) delivered.
    struct Recorder(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Recorder {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn write_fd(dispatcher: &mut SyscallDispatcher, fd: u64, bytes: &[u8]) -> DispatchOutcome {
        const BUF: u64 = 0x4000;
        let mut memory = LinearMemory::new(BUF, vec![0u8; 0x1000]);
        memory.write_bytes(BUF, bytes).unwrap();
        let reporter = CompatReporter::default();
        // Same two-phase-borrow idiom as tests/integration/address_space.rs:236.
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    64,
                    SyscallArgs::from([fd, BUF, bytes.len() as u64, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap()
    }

    #[test]
    fn write_to_fd1_and_fd2_lands_in_the_piped_sink_not_the_capture_buffer() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let err = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_stdio_sink(StdioSink::Piped {
            stdout: Box::new(Recorder(Arc::clone(&out))),
            stderr: Box::new(Recorder(Arc::clone(&err))),
        });

        assert_eq!(
            write_fd(&mut dispatcher, 1, b"hello"),
            DispatchOutcome::Returned { value: 5 }
        );
        assert_eq!(
            write_fd(&mut dispatcher, 2, b"oops\n"),
            DispatchOutcome::Returned { value: 5 }
        );

        assert_eq!(&*out.lock(), b"hello");
        assert_eq!(&*err.lock(), b"oops\n");
        assert!(
            dispatcher.stdout().is_empty(),
            "piped bytes must not also be captured"
        );
        assert!(dispatcher.stderr().is_empty());
    }

    #[test]
    fn captured_sink_fills_the_run_result_buffers() {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_stdio_sink(StdioSink::Captured);
        assert_eq!(
            write_fd(&mut dispatcher, 1, b"kept"),
            DispatchOutcome::Returned { value: 4 }
        );
        assert_eq!(dispatcher.stdout(), b"kept");
    }

    #[test]
    fn piped_writer_errors_surface_as_the_guest_write_errno() {
        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from_raw_os_error(libc::EPIPE))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_stdio_sink(StdioSink::Piped {
            stdout: Box::new(Broken),
            stderr: Box::new(std::io::sink()),
        });
        assert_eq!(
            write_fd(&mut dispatcher, 1, b"x"),
            DispatchOutcome::errno(crate::linux_abi::LINUX_EPIPE)
        );
    }

    #[test]
    fn forked_runtime_io_shares_the_piped_writer() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let parent = RuntimeIo::new();
        parent.set_sink(StdioSink::Piped {
            stdout: Box::new(Recorder(Arc::clone(&out))),
            stderr: Box::new(std::io::sink()),
        });
        let child = parent.fork_clone();
        let StdioRoute::Piped { stdout, .. } = child.route() else {
            panic!("a forked child must inherit the parent's piped route");
        };
        // UFCS: `std::io::Write` is not in scope in this module (nor via the
        // `dispatch` glob), and a trait import just for one call is noise.
        std::io::Write::write_all(&mut *stdout.lock(), b"child").unwrap();
        assert_eq!(&*out.lock(), b"child");
    }

    #[test]
    fn forked_child_output_captured_into_parent_buffers() {
        let parent = SyscallDispatcher::new();
        parent.set_stdio_sink(StdioSink::Captured);
        let parent_context = parent.capture_one_task_context().unwrap();
        let parent_tid = parent_context.thread().registry_id();
        let child_tid = crate::thread::ThreadId::from_guest_supplied_tid(2);
        let mut child = parent.fork_clone_in_process(parent_tid, child_tid, 10, 11);
        *child.kernel_binding.write() = parent_context.task_binding();

        assert_eq!(
            write_fd(&mut child, 1, b"hello\n"),
            DispatchOutcome::Returned { value: 6 }
        );
        assert_eq!(parent.stdout(), b"hello\n");
    }

    #[test]
    fn forked_child_output_streamed_to_piped_sink() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let err = Arc::new(Mutex::new(Vec::new()));
        let parent = SyscallDispatcher::new();
        parent.set_stdio_sink(StdioSink::Piped {
            stdout: Box::new(Recorder(Arc::clone(&out))),
            stderr: Box::new(Recorder(Arc::clone(&err))),
        });
        let parent_context = parent.capture_one_task_context().unwrap();
        let parent_tid = parent_context.thread().registry_id();
        let child_tid = crate::thread::ThreadId::from_guest_supplied_tid(2);
        let mut child = parent.fork_clone_in_process(parent_tid, child_tid, 10, 11);
        *child.kernel_binding.write() = parent_context.task_binding();

        assert_eq!(
            write_fd(&mut child, 1, b"hello from child\n"),
            DispatchOutcome::Returned { value: 17 }
        );
        assert_eq!(&*out.lock(), b"hello from child\n");
        assert!(parent.stdout().is_empty());
    }

    #[test]
    fn interleaved_parent_and_child_writes_preserve_pipeline_order() {
        let mut parent = SyscallDispatcher::new();
        parent.set_stdio_sink(StdioSink::Captured);
        let parent_context = parent.capture_one_task_context().unwrap();
        let parent_tid = parent_context.thread().registry_id();
        let child_tid = crate::thread::ThreadId::from_guest_supplied_tid(2);
        let mut child = parent.fork_clone_in_process(parent_tid, child_tid, 10, 11);
        *child.kernel_binding.write() = parent_context.task_binding();

        assert_eq!(
            write_fd(&mut parent, 1, b"parent first\n"),
            DispatchOutcome::Returned { value: 13 }
        );
        assert_eq!(
            write_fd(&mut child, 1, b"child second\n"),
            DispatchOutcome::Returned { value: 13 }
        );
        assert_eq!(
            write_fd(&mut parent, 1, b"parent third\n"),
            DispatchOutcome::Returned { value: 13 }
        );
        assert_eq!(
            write_fd(&mut child, 1, b"child fourth\n"),
            DispatchOutcome::Returned { value: 13 }
        );

        assert_eq!(
            parent.stdout(),
            b"parent first\nchild second\nparent third\nchild fourth\n"
        );
    }

    #[test]
    fn stderr_kept_separate_from_stdout_across_fork() {
        let mut parent = SyscallDispatcher::new();
        parent.set_stdio_sink(StdioSink::Captured);
        let parent_context = parent.capture_one_task_context().unwrap();
        let parent_tid = parent_context.thread().registry_id();
        let child_tid = crate::thread::ThreadId::from_guest_supplied_tid(2);
        let mut child = parent.fork_clone_in_process(parent_tid, child_tid, 10, 11);
        *child.kernel_binding.write() = parent_context.task_binding();

        assert_eq!(
            write_fd(&mut parent, 1, b"parent out\n"),
            DispatchOutcome::Returned { value: 11 }
        );
        assert_eq!(
            write_fd(&mut child, 2, b"child err\n"),
            DispatchOutcome::Returned { value: 10 }
        );
        assert_eq!(
            write_fd(&mut child, 1, b"child out\n"),
            DispatchOutcome::Returned { value: 10 }
        );
        assert_eq!(
            write_fd(&mut parent, 2, b"parent err\n"),
            DispatchOutcome::Returned { value: 11 }
        );

        assert_eq!(parent.stdout(), b"parent out\nchild out\n");
        assert_eq!(parent.stderr(), b"child err\nparent err\n");
    }

    fn dup_fd(dispatcher: &mut SyscallDispatcher, oldfd: u64) -> DispatchOutcome {
        let mut memory = LinearMemory::new(0, vec![]);
        let reporter = CompatReporter::default();
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(23, SyscallArgs::from([oldfd, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap()
    }

    fn dup3_fd(
        dispatcher: &mut SyscallDispatcher,
        oldfd: u64,
        newfd: u64,
        flags: u64,
    ) -> DispatchOutcome {
        let mut memory = LinearMemory::new(0, vec![]);
        let reporter = CompatReporter::default();
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(24, SyscallArgs::from([oldfd, newfd, flags, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap()
    }

    fn close_fd(dispatcher: &mut SyscallDispatcher, fd: u64) -> DispatchOutcome {
        let mut memory = LinearMemory::new(0, vec![]);
        let reporter = CompatReporter::default();
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(57, SyscallArgs::from([fd, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap()
    }

    #[test]
    fn inherit_dup_redirection_sequence_returns_success() {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_stdio_sink(StdioSink::Inherit);

        // exec 3>&1
        assert_eq!(
            dup3_fd(&mut dispatcher, 1, 3, 0),
            DispatchOutcome::Returned { value: 3 }
        );
        // echo via3 >&3 (direct write to 3)
        assert_eq!(
            write_fd(&mut dispatcher, 3, b"via3\n"),
            DispatchOutcome::Returned { value: 5 }
        );
        // echo via3 >&3 (shell redirection dance: save 1 to 10, dup 3 to 1, write 1, restore 1, close 10)
        assert_eq!(
            dup3_fd(&mut dispatcher, 1, 10, 0),
            DispatchOutcome::Returned { value: 10 }
        );
        assert_eq!(
            dup3_fd(&mut dispatcher, 3, 1, 0),
            DispatchOutcome::Returned { value: 1 }
        );
        assert_eq!(
            write_fd(&mut dispatcher, 1, b"via3\n"),
            DispatchOutcome::Returned { value: 5 }
        );
        assert_eq!(
            dup3_fd(&mut dispatcher, 10, 1, 0),
            DispatchOutcome::Returned { value: 1 }
        );
        assert_eq!(
            close_fd(&mut dispatcher, 10),
            DispatchOutcome::Returned { value: 0 }
        );
    }

    #[test]
    fn captured_dup_redirection_captures_to_stdout() {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_stdio_sink(StdioSink::Captured);

        // exec 3>&1
        assert_eq!(
            dup3_fd(&mut dispatcher, 1, 3, 0),
            DispatchOutcome::Returned { value: 3 }
        );
        // write to fd 3
        assert_eq!(
            write_fd(&mut dispatcher, 3, b"via3\n"),
            DispatchOutcome::Returned { value: 5 }
        );
        // shell redirection dance
        assert_eq!(
            dup3_fd(&mut dispatcher, 1, 10, 0),
            DispatchOutcome::Returned { value: 10 }
        );
        assert_eq!(
            dup3_fd(&mut dispatcher, 3, 1, 0),
            DispatchOutcome::Returned { value: 1 }
        );
        assert_eq!(
            write_fd(&mut dispatcher, 1, b"via1\n"),
            DispatchOutcome::Returned { value: 5 }
        );
        assert_eq!(
            dup3_fd(&mut dispatcher, 10, 1, 0),
            DispatchOutcome::Returned { value: 1 }
        );
        assert_eq!(
            close_fd(&mut dispatcher, 10),
            DispatchOutcome::Returned { value: 0 }
        );

        assert_eq!(dispatcher.stdout(), b"via3\nvia1\n");
    }

    #[test]
    fn captured_stream_separation_with_dup2() {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_stdio_sink(StdioSink::Captured);

        assert_eq!(
            write_fd(&mut dispatcher, 1, b"OUT\n"),
            DispatchOutcome::Returned { value: 4 }
        );
        // 1>&2: redirect stdout to stderr
        assert_eq!(
            dup3_fd(&mut dispatcher, 2, 1, 0),
            DispatchOutcome::Returned { value: 1 }
        );
        assert_eq!(
            write_fd(&mut dispatcher, 1, b"ERR\n"),
            DispatchOutcome::Returned { value: 4 }
        );
        assert_eq!(dispatcher.stdout(), b"OUT\n");
        assert_eq!(dispatcher.stderr(), b"ERR\n");
    }

    #[test]
    fn child_writes_to_duped_stdio_after_fork_captured() {
        let mut parent = SyscallDispatcher::new();
        parent.set_stdio_sink(StdioSink::Captured);

        // dup 1 to 3
        assert_eq!(
            dup_fd(&mut parent, 1),
            DispatchOutcome::Returned { value: 3 }
        );

        let parent_context = parent.capture_one_task_context().unwrap();
        let parent_tid = parent_context.thread().registry_id();
        let child_tid = crate::thread::ThreadId::from_guest_supplied_tid(2);
        let mut child = parent.fork_clone_in_process(parent_tid, child_tid, 10, 11);
        *child.kernel_binding.write() = parent_context.task_binding();

        assert_eq!(
            write_fd(&mut child, 3, b"child via 3\n"),
            DispatchOutcome::Returned { value: 12 }
        );
        assert_eq!(parent.stdout(), b"child via 3\n");
    }

    #[test]
    fn piped_dup_and_stream_separation() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let err = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_stdio_sink(StdioSink::Piped {
            stdout: Box::new(Recorder(Arc::clone(&out))),
            stderr: Box::new(Recorder(Arc::clone(&err))),
        });

        // exec 3>&1
        assert_eq!(
            dup3_fd(&mut dispatcher, 1, 3, 0),
            DispatchOutcome::Returned { value: 3 }
        );
        assert_eq!(
            write_fd(&mut dispatcher, 3, b"piped 3\n"),
            DispatchOutcome::Returned { value: 8 }
        );
        assert_eq!(&*out.lock(), b"piped 3\n");

        // 1>&2
        assert_eq!(
            dup3_fd(&mut dispatcher, 2, 1, 0),
            DispatchOutcome::Returned { value: 1 }
        );
        assert_eq!(
            write_fd(&mut dispatcher, 1, b"piped err\n"),
            DispatchOutcome::Returned { value: 10 }
        );
        assert_eq!(&*err.lock(), b"piped err\n");
    }
}
