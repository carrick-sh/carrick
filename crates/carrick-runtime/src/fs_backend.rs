//! Swappable filesystem-write backend behind a single trait.
//!
//! Carrick's OCI rootfs is read-only by construction (the layers come
//! out of an OCI image and are immutable). To let the guest do useful
//! work - `apt update` mkdirs `/var/lib/apt/lists/partial`, `dpkg`
//! rewrites status files, build tools touch `/tmp` - the dispatcher
//! needs a writable layer that sits on top.
//!
//! There are two reasonable places to put that layer:
//!
//! * `MemoryBackend`: pure in-memory `HashMap<PathBuf, Vec<u8>>`,
//!   fast, ephemeral, ideal for CI / tests / one-shot runs.
//! * `HostFsBackend`: a real APFS scratch directory, sandboxed via
//!   `root_fd` + `namei_leaf` with `O_NOFOLLOW` / `AT_SYMLINK_NOFOLLOW`
//!   (kernel-rooted, syscall-level escape-proof),
//!   byte-copied from the unpacked rootfs (a future clonefile(2) seed
//!   would be O(1) on APFS). This is the production / durable option.
//!
//! Both implement the same [`FsBackend`] trait. The dispatcher holds
//! a `Box<dyn FsBackend>` and is otherwise agnostic to which one is
//! in use. The CLI `--fs <memory|host>` flag selects at runtime.
//!
//! API choice: the trait methods mirror the high-level operations the
//! dispatcher already performs (`lookup`, `make_dir`, `set_file_contents`,
//! `mark_deleted`, ...). They are intentionally layer-aware rather
//! than POSIX-shaped: the dispatcher already does its own overlay-first
//! plus rootfs-fallback merging, so the backend's job is to be the
//! "upper" layer. A POSIX-shaped open/read/write trait was considered
//! but would have required either duplicating the layering logic in
//! each backend or rewriting every fs-touching syscall site; the
//! current shape is the minimum-risk version that still lets the host
//! backend live behind the same trait.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::linux_abi::LinuxErrno;
use crate::rootfs::{RootFsDirEntry, RootFsEntryKind, RootFsMetadata};
use carrick_abi::{NsGid, NsUid};

/// What an [`FsBackend`] knows about a path. `Dir` and `File` are
/// positive entries; `Deleted` is the tombstone the upper layer uses
/// to shadow a path that exists in the read-only rootfs underneath.
///
/// `File` owns its bytes so the trait can be implemented by both an
/// in-memory backend (cheap clone of an existing Vec) and a host-fs
/// backend (read-back from disk). Callers that only need to know the
/// *kind* of the entry should match on the enum and ignore the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayEntry {
    Dir,
    File(Vec<u8>),
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendError {
    Invalid,
    Io,
    Unsupported,
    /// The host refused a resource the guest is entitled to (its own
    /// descriptor, disk space, quota), already translated into the guest's
    /// errno by [`host_open_refusal`]. Authoritative: the dispatcher returns
    /// it as-is instead of the generic `EINVAL`/`EIO` it lowers `Io` to.
    Host(LinuxErrno),
}

/// Outcome of a backend handing the dispatcher a host fd for a guest open
/// ([`FsBackend::open_raw_fd`], [`FsBackend::create_raw_fd`],
/// [`FsBackend::open_raw_fd_with_metadata`]).
///
/// Two different "no fd" answers used to share one `Option::None`: "this
/// backend cannot serve the path from here, keep lowering" and "the host
/// refused the open outright". The dispatcher lowers the first to the next
/// backend, then to a create, then to `EINVAL` — so a host `EMFILE` on the
/// guest's own open reached the guest as `EINVAL` (LTP `fork09` breaks its
/// fill loop only on `EMFILE` and TBROKs on anything else). The two are now
/// distinct variants and a refusal carries the guest's errno.
#[must_use]
#[derive(Debug)]
pub enum HostFdOpen<T> {
    /// The fd IS the guest's open (caller owns it, must close it).
    Served(T),
    /// Not servable from this backend: the caller keeps its exact next
    /// lowering (another layer, the layered resolver, `ENOENT`, a create).
    /// Deliberately carries no host errno — the fast-path errno rule
    /// (`docs/fs-host-capstd-amplification.md`) makes only `ENOENT`
    /// authoritative below the layered view, and every other path-semantic
    /// host errno is a fact about the HOST's resolution, not the guest's.
    Unavailable,
    /// The host refused a resource the guest is entitled to, already
    /// translated into the guest's errno by [`host_open_refusal`].
    /// Authoritative: no further lowering may hide it.
    Refused(LinuxErrno),
}

impl<T> HostFdOpen<T> {
    /// The served value, dropping the distinction between `Unavailable` and
    /// `Refused`. For callers that own no guest-visible errno of their own
    /// (internal reopen helpers, tests); a dispatcher path must match.
    pub fn served(self) -> Option<T> {
        match self {
            Self::Served(value) => Some(value),
            Self::Unavailable | Self::Refused(_) => None,
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> HostFdOpen<U> {
        match self {
            Self::Served(value) => HostFdOpen::Served(f(value)),
            Self::Unavailable => HostFdOpen::Unavailable,
            Self::Refused(errno) => HostFdOpen::Refused(errno),
        }
    }

    /// Lower to the next lowering only when this one was `Unavailable`; a
    /// refusal is final.
    pub fn or_else(self, f: impl FnOnce() -> HostFdOpen<T>) -> HostFdOpen<T> {
        match self {
            Self::Unavailable => f(),
            served_or_refused => served_or_refused,
        }
    }

    /// For a caller that lowers `Unavailable` to its next lowering but must
    /// stop on a refusal: `Ok(Some)` served, `Ok(None)` lower further,
    /// `Err` the guest's final answer.
    pub fn lowerable(self) -> Result<Option<T>, LinuxErrno> {
        match self {
            Self::Served(value) => Ok(Some(value)),
            Self::Unavailable => Ok(None),
            Self::Refused(refused) => Err(refused),
        }
    }

    /// As a guest errno: `Unavailable` is the caller's own `unavailable`
    /// errno, a refusal keeps its own.
    pub fn into_errno(self, unavailable: LinuxErrno) -> Result<T, LinuxErrno> {
        match self {
            Self::Served(value) => Ok(value),
            Self::Unavailable => Err(unavailable),
            Self::Refused(refused) => Err(refused),
        }
    }

    /// As a backend result: `Unavailable` is the backend's own `Io`, a
    /// refusal keeps its errno.
    pub fn into_backend_result(self) -> Result<T, BackendError> {
        match self {
            Self::Served(value) => Ok(value),
            Self::Unavailable => Err(BackendError::Io),
            Self::Refused(refused) => Err(BackendError::Host(refused)),
        }
    }
}

/// Classify a host open failure for the guest's own open: is this a
/// resource the guest was entitled to (its answer), or a fact about the
/// host's path resolution (the layered resolver's)?
///
/// `EMFILE`/`ENFILE`: the guest is BELOW its own `RLIMIT_NOFILE` — the fd
/// table enforced that before the host was asked — so what is full is the
/// system's table, which Linux reports as `ENFILE`. `ENOSPC`/`EDQUOT`/
/// `ENOMEM`/`EIO`: the host storage is the authority for real I/O and its
/// refusal is exact. Everything else (`ENOENT`, `ENOTDIR`, `ELOOP`,
/// `EACCES`, `EISDIR`, `EEXIST`, …) describes the host's view of the path,
/// which the guest's layered view may legitimately differ from: `None`,
/// and the caller stays `Unavailable`.
pub(crate) fn host_open_refusal(host_errno: i32) -> Option<LinuxErrno> {
    match host_errno {
        libc::EMFILE | libc::ENFILE => Some(crate::linux_abi::LINUX_ENFILE),
        libc::ENOSPC | libc::EDQUOT | libc::ENOMEM | libc::EIO => {
            Some(crate::host_to_linux_errno(host_errno))
        }
        _ => None,
    }
}

/// [`host_open_refusal`] of an `io::Error` (a cap-std/`std` failure).
pub(crate) fn io_open_refusal(error: &std::io::Error) -> Option<LinuxErrno> {
    error.raw_os_error().and_then(host_open_refusal)
}

/// Durable authority needed to reopen the exact host-filesystem overlay after
/// a PID-preserving host exec. The path locates the already-populated scratch;
/// device/inode identity prevents a substituted path from granting a different
/// filesystem root.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostFsReexecAuthority {
    pub root_path: Vec<u8>,
    pub device: u64,
    pub inode: u64,
    pub cleanup_on_drop: bool,
    /// This root was created as the sparse writable upper of an immutable
    /// cached lower. Historical/materialized authorities default false.
    #[serde(default)]
    pub sparse_upper_fast_miss: bool,
}

/// Real on-disk stat values for a path, read straight from the backing
/// filesystem. Carries the bits a synthesized [`RootFsMetadata`] can't
/// represent faithfully: the true file *type* (so a symlink reports as
/// a symlink, not whatever it points at) and the real hard-link count.
/// Only disk-backed backends can produce this; the in-memory backend
/// returns `None` and the dispatcher falls back to its synthesized stat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealStat {
    pub kind: RootFsEntryKind,
    /// Real inode number for disk-backed entries. Host-backed path and fd
    /// stats use this so identity checks such as Go's PWD-vs-dot comparison
    /// see a followed symlink as the same directory as its target.
    pub ino: u64,
    /// Hard-link count (`st_nlink`).
    pub nlink: u32,
    /// Permission bits only (low 0o7777); the type bits are derived
    /// from `kind`.
    pub mode: u32,
    /// Guest-visible owner uid/gid (`st_uid`/`st_gid`). Tracked in xattrs
    /// because carrick can't really chown the scratch as a non-root macOS
    /// process; defaults to 0 (root) when unset.
    pub uid: NsUid,
    pub gid: NsGid,
    pub size: u64,
    /// Allocated 512-byte blocks from the host inode (`st_blocks`), if available.
    pub blocks: Option<u64>,
    /// Last-access time `(sec, nsec)` from the real on-disk inode.
    pub atime: (i64, i64),
    /// Last-modification time `(sec, nsec)` from the real on-disk inode.
    pub mtime: (i64, i64),
    /// Inode-change time `(sec, nsec)` from the real on-disk inode.
    pub ctime: (i64, i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFileContents {
    pub base: Arc<[u8]>,
    pub dirty: BTreeMap<usize, Vec<u8>>,
    pub len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFileEntry {
    pub metadata: RootFsMetadata,
    pub contents: SharedFileContents,
}

thread_local! {
    static EXCLUSIVE_ARCHIVE_GATES: std::cell::RefCell<Vec<usize>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

/// Per-overlay exclusion between a multi-path archive transaction and ordinary
/// guest mutations. Ordinary mutations take a recursive shared guard, retaining
/// concurrency; archive validation/apply/rollback takes the exclusive guard.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct ArchiveMutationGate {
    lock: RwLock<()>,
}

pub(crate) struct ArchiveTransactionGuard<'a> {
    gate_id: usize,
    _guard: RwLockWriteGuard<'a, ()>,
}

enum MutationGuard<'a> {
    Shared { _guard: RwLockReadGuard<'a, ()> },
    ArchiveOwner,
}

impl ArchiveMutationGate {
    fn id(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }

    pub(crate) fn archive_transaction(&self) -> ArchiveTransactionGuard<'_> {
        let guard = self.lock.write();
        let gate_id = self.id();
        EXCLUSIVE_ARCHIVE_GATES.with(|held| held.borrow_mut().push(gate_id));
        ArchiveTransactionGuard {
            gate_id,
            _guard: guard,
        }
    }

    fn mutation(&self) -> MutationGuard<'_> {
        let gate_id = self.id();
        if EXCLUSIVE_ARCHIVE_GATES.with(|held| held.borrow().contains(&gate_id)) {
            MutationGuard::ArchiveOwner
        } else {
            MutationGuard::Shared {
                _guard: self.lock.read_recursive(),
            }
        }
    }
}

impl Drop for ArchiveTransactionGuard<'_> {
    fn drop(&mut self) {
        EXCLUSIVE_ARCHIVE_GATES.with(|held| {
            let mut held = held.borrow_mut();
            if let Some(index) = held.iter().rposition(|gate| *gate == self.gate_id) {
                held.remove(index);
            }
        });
    }
}

/// Trait every writable-layer backend implements. Methods are layer-
/// aware (see module docs); the dispatcher does its own overlay-first
/// merging with the read-only rootfs underneath.
pub trait FsBackend: Send + Sync {
    /// Return the backend's mutation exclusion only when all namespace-changing
    /// methods participate. Unknown backends fail closed for archive import.
    #[doc(hidden)]
    fn archive_mutation_gate(&self) -> Option<&ArchiveMutationGate> {
        None
    }
    /// Snapshot the durable root authority needed by native host self-reexec.
    /// Memory and synthetic backends reject this boundary explicitly.
    fn native_reexec_authority(&self) -> Result<HostFsReexecAuthority, BackendError> {
        Err(BackendError::Unsupported)
    }

    /// Look up `path`. Returns `Some(OverlayEntry::Deleted)` for a
    /// tombstoned path, `Some(File)` / `Some(Dir)` for entries the
    /// backend owns, and `None` when the backend has nothing to say
    /// (caller falls through to the rootfs).
    fn lookup(&self, path: &str) -> Option<OverlayEntry>;

    /// Cheap accessor: just the kind of `path`, with no byte fetch.
    /// Default impl forwards to `lookup`; backends may override for
    /// performance (the host backend doesn't have to read the file
    /// contents off disk).
    fn lookup_kind(&self, path: &str) -> Option<OverlayEntryKind> {
        self.lookup(path).map(|e| match e {
            OverlayEntry::Dir => OverlayEntryKind::Dir,
            OverlayEntry::File(_) => OverlayEntryKind::File,
            OverlayEntry::Deleted => OverlayEntryKind::Deleted,
        })
    }

    /// Metadata for an entry the backend owns. `None` falls through.
    fn metadata(&self, path: &str) -> Option<RootFsMetadata>;

    /// One-pass `(lookup_kind, metadata)` for callers that need both answers
    /// for the same path (the layered `Vfs::lookup`). The default preserves
    /// the historical two-call pattern exactly — `metadata` is consulted only
    /// when the kind probe says the backend owns the path — so counting/
    /// wrapping backends observe identical call sequences. Disk backends
    /// override this to derive both answers from ONE contained open instead
    /// of two full path walks.
    fn lookup_kind_and_metadata(
        &self,
        path: &str,
    ) -> (Option<OverlayEntryKind>, Option<RootFsMetadata>) {
        match self.lookup_kind(path) {
            None => (None, None),
            kind => (kind, self.metadata(path)),
        }
    }

    /// Read the file bytes for `path`. `None` if the backend doesn't
    /// have a file at that path.
    fn file_contents(&self, path: &str) -> Option<Vec<u8>>;

    /// Read at most `max` leading bytes of the file at `path`. `None` exactly
    /// when [`FsBackend::file_contents`] would return `None`; an existing empty
    /// file yields `Some(vec![])`. The default materializes the whole file and
    /// truncates — disk backends override it with a bounded read so existence
    /// and shebang probes on a multi-MB executable stop paying a full read.
    fn file_head(&self, path: &str, max: usize) -> Option<Vec<u8>> {
        self.file_contents(path).map(|mut bytes| {
            bytes.truncate(max);
            bytes
        })
    }

    /// Open the regular file at `path` read-only as a REAL host fd, using
    /// exactly the resolution `file_contents` uses (so the accept set and the
    /// followed symlinks are identical). `None` for backends without host
    /// files, for missing paths, or for non-file entries. The execve path
    /// maps guest images MAP_PRIVATE straight from this fd instead of
    /// materializing their bytes per exec.
    fn open_file_readonly(&self, _path: &str) -> Option<std::fs::File> {
        None
    }

    /// Return a cheap shared snapshot for an in-memory file when the backend
    /// can expose one without materializing the whole payload.
    fn shared_file_contents(&self, _path: &str) -> Option<SharedFileContents> {
        None
    }

    /// Return metadata plus a cheap shared contents snapshot for a file when the
    /// backend can answer both in one pass. `trunc` applies O_TRUNC before the
    /// snapshot is returned.
    fn shared_file_entry(&self, _path: &str, _trunc: bool) -> Option<SharedFileEntry> {
        None
    }

    /// Return no-follow metadata in one cheap backend pass when the backend can
    /// prove the path is not a symlink. The default is conservative because host
    /// backends may need real lstat/readlink behavior.
    fn fast_nofollow_metadata(&self, _path: &str) -> Option<RootFsMetadata> {
        None
    }

    /// Prove that `path` is absent from a sparse writable upper without a
    /// cap-std component walk. `false` means "unknown", never "present".
    /// The default is conservative for every non-host backend.
    fn fast_nofollow_absent(&self, _path: &str) -> bool {
        false
    }

    /// `True` iff `path` is currently tombstoned.
    /// Whether the final component of `rel` exists on the host under exactly
    /// these bytes. A normalizing host filesystem (APFS) resolves an NFD
    /// spelling to an NFC entry that Linux would report ENOENT for; a
    /// resolver that stats through a parent fd must ask this before
    /// believing a hit. Default: byte-exact (in-memory backends).
    fn name_matches_on_disk(&self, _rel: &Path) -> bool {
        true
    }

    /// Whether this backend's entries can be resolved and filled by the
    /// rootfs dentry cache. The cache fills from host directory fds and
    /// `real_stat`, which only a disk-backed backend answers; an in-memory
    /// backend must stay on the layered path or its own entries are
    /// invisible to the cache (`mkdirat_creates_overlay_dir_and_fstatat_sees_it`).
    fn serves_dentry_cache(&self) -> bool {
        false
    }

    fn is_deleted(&self, path: &str) -> bool {
        matches!(self.lookup_kind(path), Some(OverlayEntryKind::Deleted))
    }

    /// Cheaply check if `name` is whiteouted in the directory referred to by `parent_fd`.
    fn has_whiteout_in_dir(&self, _parent_fd: i32, _name: &str) -> bool {
        false
    }

    /// `True` iff the backend can answer "what's at this path" — i.e.
    /// `lookup(...).is_some()`.
    fn shadows(&self, path: &str) -> bool {
        self.lookup_kind(path).is_some()
    }

    /// Create a directory at `path`. Idempotent.
    fn make_dir(&self, path: &str) -> Result<(), BackendError>;

    /// Create a directory using an already-held parent directory fd and leaf name
    /// resolved by Carrick's dentry layer, avoiding whole-path walks.
    fn make_dir_at(
        &self,
        parent_fd: Option<&std::os::fd::OwnedFd>,
        leaf_c: Option<&std::ffi::CStr>,
        rel: &NormalizedRelPath,
    ) -> Result<(), BackendError> {
        let _ = (parent_fd, leaf_c);
        self.make_dir(rel.as_path().to_str().ok_or(BackendError::Invalid)?)
    }

    /// Materialise an empty file at `path`. Used by `openat(..., O_CREAT)`
    /// when the file did not previously exist.
    fn create_file(&self, path: &str) -> Result<(), BackendError>;

    /// Materialise a writable overlay entry backed by immutable rootfs bytes.
    /// The default preserves the historical full-copy behavior; in-memory
    /// backends can override this with a copy-on-write entry that stores only
    /// dirty ranges.
    fn create_file_from_rootfs(
        &self,
        path: &str,
        contents: Arc<[u8]>,
        _mode: u32,
    ) -> Result<(), BackendError> {
        self.set_file_contents(path, contents.as_ref().to_vec())
    }

    /// Create a named pipe (FIFO) at `path` with permission bits `mode`
    /// (low 0o7777). Used by `mknod(2)`/`mkfifo(3)` for `S_IFIFO`. The host
    /// backend makes a real `mkfifoat(2)` node on the cap-std scratch (so the
    /// FIFO is fork-shareable and stats as `S_IFIFO`); the in-memory backend
    /// can't back a real pipe and returns `Unsupported` (→ guest `EPERM`,
    /// matching unprivileged mknod). Default: unsupported.
    fn create_fifo(&self, _path: &str, _mode: u32) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }

    /// Whether this backend can contain named FIFO nodes that need special
    /// `open(2)` handling. The dispatcher runs a per-open FIFO metadata probe
    /// only when this answers `true`, so a precise `false` removes a full
    /// path walk from every ordinary open. The memory backend can never hold
    /// one (`create_fifo` is unsupported there); the host backend answers
    /// from a durable marker stamped by `create_fifo` (layer extraction skips
    /// special tar entries, so guest `mknod` is the only FIFO source). The
    /// conservative default is `true`.
    fn may_have_fifo_nodes(&self) -> bool {
        true
    }

    /// Materialise an `AF_UNIX` socket node at the guest `path` with permission
    /// bits `mode` (low 0o7777). Called by `bind(2)` for a pathname socket so a
    /// subsequent `stat`/`os.path.exists`/`chmod`/`unlink` of the bound path
    /// matches Linux (a real `S_IFSOCK` node). macOS can't `mknod(S_IFSOCK)` as
    /// non-root and the real host socket lives at a hashed scratch path, so the
    /// node is a *marker*: the host backend writes a regular file tagged with
    /// the `user.carrick.socket` xattr (fork-coherent, recognised by
    /// `real_stat`/`metadata`); the in-memory backend records it in a `sockets`
    /// map. Reports `RootFsEntryKind::Socket` → `S_IFSOCK`. Default: unsupported.
    fn create_socket(&self, _path: &str, _mode: u32) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }

    /// Materialise a CHARACTER or BLOCK device node at the guest `path`.
    /// `full_mode` carries the `S_IFCHR`/`S_IFBLK` type bits plus permission bits
    /// (already umask-applied); `dev` is the raw guest `dev_t` (stored verbatim —
    /// the Linux major/minor encoding round-trips). macOS/cap-std can't
    /// `mknod(S_IFCHR|S_IFBLK)` as a non-root process, so the host backend writes
    /// a MARKER regular file tagged with the device xattrs (see
    /// `CARRICK_RDEV_XATTR`); `real_stat`/the stat reconstruction then report the
    /// device type + `st_rdev`. The in-memory backend has no host inode to tag
    /// and returns `Unsupported` (→ guest `EPERM`, matching unprivileged mknod
    /// and the FIFO/socket degradation). Default: unsupported.
    fn create_device(&self, _path: &str, _full_mode: u32, _dev: u64) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }

    /// If `path` is a device-node marker created by `create_device`, return its
    /// `(type_bits, dev)` — `type_bits` being `S_IFCHR` or `S_IFBLK` from the
    /// stored full mode, and `dev` the raw `dev_t`. `None` for every other path
    /// (a plain regular file, a directory, anything with no device xattr), so the
    /// stat reconstruction leaves normal files completely unaffected. Default:
    /// none (backends with no host inode can't carry the marker).
    fn device_node(&self, _path: &str) -> Option<(u32, u64)> {
        None
    }

    /// Replace the contents of `path`. Used by write/writev/pwrite/
    /// ftruncate writeback and by rename-into-overlay.
    fn set_file_contents(&self, path: &str, contents: Vec<u8>) -> Result<(), BackendError>;

    /// Apply a dirty byte range to `path`, growing the file to `final_size`
    /// when needed. Backends with mutable storage should override this to avoid
    /// whole-file replacement; the default preserves the old behavior.
    fn write_file_range(
        &self,
        path: &str,
        offset: usize,
        bytes: &[u8],
        final_size: usize,
    ) -> Result<(), BackendError> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or(BackendError::Invalid)?;
        if final_size < end {
            return Err(BackendError::Invalid);
        }
        let mut contents = self.file_contents(path).ok_or(BackendError::Unsupported)?;
        if final_size > contents.len() {
            contents.resize(final_size, 0);
        }
        contents[offset..end].copy_from_slice(bytes);
        self.set_file_contents(path, contents)
    }

    /// Drop the backend's entry for `path` entirely. Returns true iff
    /// the backend was holding something there. Does NOT tombstone —
    /// caller pairs this with `mark_deleted` when the path also lives
    /// in the rootfs.
    fn remove_entry(&self, path: &str) -> bool;

    /// Checked form of [`FsBackend::remove_entry`] for transactional cleanup.
    /// `Ok(false)` means the entry was already absent; an actual backend/path
    /// failure must remain distinguishable from absence.
    fn remove_entry_checked(&self, path: &str) -> Result<bool, BackendError> {
        Ok(self.remove_entry(path))
    }

    /// Remove an entry using an already-held parent directory fd and leaf name
    /// resolved by Carrick's dentry layer, avoiding whole-path walks.
    fn remove_entry_at(
        &self,
        parent_fd: Option<&std::os::fd::OwnedFd>,
        leaf_c: Option<&std::ffi::CStr>,
        rel: &NormalizedRelPath,
        is_dir: bool,
    ) -> Result<bool, BackendError> {
        let _ = (parent_fd, leaf_c, is_dir);
        self.remove_entry_checked(rel.as_path().to_str().ok_or(BackendError::Invalid)?)
    }

    /// Tombstone `path` so that subsequent layered lookups treat it as
    /// absent, even if the rootfs still has it underneath.
    fn mark_deleted(&self, path: &str) -> Result<(), BackendError>;

    /// Immediate children of `dir` that the backend owns. Names only
    /// (the dispatcher pairs each with metadata via `metadata`).
    /// Directory children with, when the enumeration already learned it, the
    /// child's size. The host backend's FIFO probe stats every non-directory
    /// child anyway; carrying `st_size` out of that same stat lets directory
    /// materialization skip a full contained open per file (measured: five
    /// host syscalls per child on the fs-walk workload).
    fn child_names(&self, dir: &str) -> Vec<(String, RootFsEntryKind, Option<u64>)>;

    /// Optional exact dirent-only listing. Mode and size are not populated;
    /// callers may consume only name, kind and inode. A backend that cannot
    /// classify marker nodes or directory records exactly returns None.
    fn stream_dirents(&self, _dir: &str) -> Option<Vec<RootFsDirEntry>> {
        None
    }

    /// Archive-only bounded directory enumeration. Implementations must stop
    /// after producing `limit + 1` visible candidates and must never delegate
    /// to the unbounded [`FsBackend::child_names`] default. The extra entry is
    /// the caller's exact overflow sentinel.
    fn child_names_bounded(
        &self,
        _dir: &str,
        _limit: usize,
    ) -> Result<Vec<(String, RootFsEntryKind, Option<u64>)>, BackendError> {
        Err(BackendError::Unsupported)
    }

    /// Immediate children of `dir` that are tombstoned. The dispatcher
    /// uses this to filter rootfs-supplied entries.
    fn deleted_child_names(&self, dir: &str) -> Vec<String>;

    /// Bounded counterpart to [`FsBackend::deleted_child_names`] for archive
    /// overlay merges. Unknown backends fail closed rather than allocating an
    /// unbounded tombstone set.
    fn deleted_child_names_bounded(
        &self,
        _dir: &str,
        _limit: usize,
    ) -> Result<Vec<String>, BackendError> {
        Err(BackendError::Unsupported)
    }

    /// Rename an entry the backend owns. Returns `Ok(true)` iff the
    /// source was present in the backend; `Ok(false)` means the
    /// caller has to materialise the rootfs-backed source into the
    /// backend first.
    fn rename_overlay_entry(&self, from: &str, to: &str) -> Result<bool, BackendError>;

    /// Rename an entry using already-held parent directory fds and leaf names
    /// resolved by Carrick's dentry layer, avoiding whole-path walks.
    fn rename_overlay_entry_at(
        &self,
        src_parent_fd: Option<&std::os::fd::OwnedFd>,
        src_leaf_c: Option<&std::ffi::CStr>,
        src_rel: &NormalizedRelPath,
        dst_parent_fd: Option<&std::os::fd::OwnedFd>,
        dst_leaf_c: Option<&std::ffi::CStr>,
        dst_rel: &NormalizedRelPath,
    ) -> Result<bool, BackendError> {
        let _ = (src_parent_fd, src_leaf_c, dst_parent_fd, dst_leaf_c);
        self.rename_overlay_entry(
            src_rel.as_path().to_str().ok_or(BackendError::Invalid)?,
            dst_rel.as_path().to_str().ok_or(BackendError::Invalid)?,
        )
    }

    /// Atomically EXCHANGE the two entries `a` and `b` (`renameat2(2)`
    /// `RENAME_EXCHANGE`): each path ends up referring to what the other named,
    /// with all metadata (mode/owner/inode/contents) following the entry, not
    /// the name. BOTH paths must already exist in the backend (the dispatcher
    /// has verified existence and materialised any rootfs-only source first);
    /// `Ok(false)` means a path was not backend-owned and the caller must
    /// materialise it before retrying. Default: unsupported.
    fn exchange_overlay_entries(&self, _a: &str, _b: &str) -> Result<bool, BackendError> {
        Err(BackendError::Unsupported)
    }

    /// Open a REAL host file descriptor for `path`. For a disk-backed
    /// backend this is a normal kernel file: shared offset, and —
    /// crucially — it survives `libc::fork(2)`, so a forked child's
    /// writes are visible to the parent and vice versa. This is what
    /// makes apt's "child writes a temp file / pipe, parent reads it"
    /// verification patterns work under `--fs host`.
    ///
    /// `write` -> guest requested write access; `create` -> +O_CREAT;
    /// `trunc` -> +O_TRUNC. Returns the raw fd (caller owns it, must
    /// close it). The host fd carries the guest's own access mode; the
    /// dispatcher separately tracks guest-visible writability, and a
    /// consumer needing broader host access asks for it explicitly through
    /// [`Self::upgrade_host_fd_for_shared_map`]. `MemoryBackend` returns
    /// `Unavailable`: an in-memory HashMap has no kernel fd and cannot be
    /// shared across a real fork, so the dispatcher keeps its in-memory File
    /// model there. A host resource refusal (`EMFILE`, `ENOSPC`, …) is
    /// `Refused` with the guest's errno — see [`HostFdOpen`].
    ///
    /// CONTRACT: every host fd a backend hands out — here, from
    /// [`Self::open_raw_fd_with_metadata`], [`Self::create_raw_fd`],
    /// [`Self::open_file_readonly`] and `ImmutableHostFileOpen::Served` — is
    /// already `O_NONBLOCK`. The dispatcher keeps every host-backed fd
    /// non-blocking (`dispatch::net::set_host_nonblocking`) and emulates
    /// guest blocking itself, so the backend opens with the flag instead of
    /// the dispatcher paying an `F_GETFL`+`F_SETFL` round trip per open; the
    /// install sites only `debug_assert` it.
    fn open_raw_fd(&self, path: &str, write: bool, create: bool, trunc: bool) -> HostFdOpen<i32>;

    /// Re-open the regular file behind `fd` (a host fd this backend handed
    /// out, currently `O_RDONLY`) `O_RDWR` and install the new open IN PLACE
    /// with `dup2`, so every holder of the fd NUMBER — the shared
    /// `OpenDescription::HostFile`, its `HostFdRef` views, the dispatcher's
    /// bookkeeping — sees a writable host fd without a description swap. The
    /// file offset carries over. Returns `false`, leaving `fd` untouched,
    /// when the backend cannot vouch for the file: it is not a regular file
    /// under the backend's writable root (the immutable layer store is
    /// deliberately outside it — a guest must never hold a writable host
    /// view of content shared across runs), or the host refuses the write
    /// open.
    ///
    /// The one consumer is the dispatcher's live `MAP_SHARED` alias of a
    /// guest-read-only description: Darwin caps a shared file mapping's
    /// max-protection at the fd's access mode and HVF refuses a read-capped
    /// region, so the alias needs a writable host fd even though the guest's
    /// own view stays read-only (the guest's `PROT_WRITE`/`mprotect` refusals
    /// are decided from its status flags, never from this fd). Upgrading at
    /// map time — rare — keeps every ordinary read-only open at the cheaper
    /// host `O_RDONLY`. Default: `false` (fall back to the snapshot path).
    fn upgrade_host_fd_for_shared_map(&self, _fd: i32) -> bool {
        false
    }

    /// Create-open a NEW regular file with the guest's (umask-applied) `mode`
    /// and return the raw fd plus whether that mode is already the file's
    /// guest-visible mode. `false` means the caller must still `set_mode`
    /// (the mode is not owner-representable on the host, or the backend
    /// created with its default mode). Default: the plain create-open,
    /// mode not applied.
    fn create_raw_fd(&self, path: &str, _mode: u32, trunc: bool) -> HostFdOpen<(i32, bool)> {
        self.open_raw_fd(path, true, true, trunc)
            .map(|fd| (fd, false))
    }

    /// Reopen an already-written artifact so the caller can issue `fsync(2)`.
    /// `Ok(None)` means this backend has no host descriptor (for example the
    /// in-memory overlay); disk-backed implementations must return `Err` when
    /// the reopen itself fails so durability cannot silently degrade.
    fn reopen_for_durability(&self, _path: &str) -> Result<Option<i32>, BackendError> {
        Ok(None)
    }

    /// Open a REAL host file descriptor and return the metadata needed by the
    /// dispatcher from the same open file. Backends that can answer this avoid a
    /// separate metadata lookup before opening the fd.
    fn open_raw_fd_with_metadata(
        &self,
        _path: &str,
        _write: bool,
        _create: bool,
        _trunc: bool,
    ) -> HostFdOpen<(i32, RootFsMetadata)> {
        HostFdOpen::Unavailable
    }

    /// Open host vnode descriptors for inotify-style watches. Directory
    /// watches may include a host path so the inotify shim can snapshot/diff
    /// child names after a kqueue directory-write wakeup. Default:
    /// unsupported for backends with no real host namespace.
    fn watch_fds(&self, _path: &str) -> Result<Vec<crate::vfs::WatchFd>, LinuxErrno> {
        Err(crate::linux_abi::LINUX_ENOSYS)
    }

    /// Open a REAL host fd for an UNNAMED file (`O_TMPFILE` semantics): a
    /// regular file that exists nowhere in any namespace, so it's never
    /// linked, never visible to `lookup`/getdents, and is reaped when the
    /// last fd closes. A disk-backed backend creates a uniquely-named file in
    /// its scratch dir, opens it `O_RDWR`, immediately `unlink(2)`s it (the
    /// open fd keeps the unnamed inode alive), and `fchmod`s it to the guest
    /// `mode` (low 0o7777). Because the result is a real kernel fd, it is
    /// shared across `libc::fork(2)` AND inherited across `exec(2)` — so a
    /// forked+exec'd child's writes are visible to the parent's reads, which
    /// is what `tempfile.TemporaryFile()` + a faulthandler subprocess rely on.
    /// Returns the raw fd (caller owns it, must close it). `MemoryBackend`
    /// returns `None` (no kernel fd → the dispatcher keeps the in-memory
    /// anonymous `File` model). Default: unsupported.
    fn open_anon_fd(&self, _mode: u32) -> Option<i32> {
        None
    }

    /// Open a real host fd on the FIFO at `path` in NON-BLOCKING mode for the
    /// given guest access (`0`=RDONLY, `1`=WRONLY, `2`=RDWR). Always
    /// `O_NONBLOCK` so a writer-less `O_RDONLY` open returns immediately instead
    /// of blocking the dispatcher; the dispatcher then services guest blocking
    /// semantics via the kqueue `WaitOnFds` path (see `open_at_path`). Returns
    /// `None` if the backend can't (no real node) or the open failed (e.g.
    /// `O_WRONLY|O_NONBLOCK` with no reader → ENXIO). Default: unsupported.
    fn open_fifo_nonblock(&self, _path: &str, _access: u32) -> Option<i32> {
        None
    }

    /// Return the host identity `(st_dev, st_ino)` of the FIFO at `path` by stating
    /// the resolved host node, without opening an fd. Default: unsupported (returns None).
    fn fifo_identity(&self, _path: &str) -> Option<(u64, u64)> {
        None
    }

    /// Create a symlink at `linkpath` pointing at `target` (the target is
    /// stored verbatim, not resolved). Default: unsupported.
    fn symlink(&self, _target: &str, _linkpath: &str) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }

    /// Create a hard link `linkpath` referring to the same data as `src`.
    /// Default: unsupported.
    fn hard_link(&self, _src: &str, _linkpath: &str) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }

    /// Set the permission bits (low 0o7777) of `path`. Default: unsupported.
    fn set_mode(&self, _path: &str, _mode: u32) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }

    /// Set the guest-visible owner of `path`. Pass `None` to leave unchanged.
    /// Default: no-op success (tmpfs-like). The host backend records it durably
    /// in xattrs since it can't really chown.
    fn set_owner(
        &self,
        _path: &str,
        _uid: Option<NsUid>,
        _gid: Option<NsGid>,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    /// Read the guest-visible (uid, gid) of `path`, or `None` if unknown.
    /// Defaults to root (0,0) on backends that don't track ownership.
    fn get_owner(&self, _path: &str) -> Option<(NsUid, NsGid)> {
        None
    }

    /// Set the access/modification times of `path`. Each component is
    /// `Some((sec, nsec))` to set an explicit time, or `None` to leave it
    /// unchanged (UTIME_OMIT). The caller is responsible for resolving
    /// UTIME_NOW to a concrete timestamp before calling. Default:
    /// unsupported (the in-memory backend has no persistent timestamps).
    fn set_times(
        &self,
        _path: &str,
        _atime: Option<(i64, i64)>,
        _mtime: Option<(i64, i64)>,
        // AT_SYMLINK_NOFOLLOW: set the SYMLINK's own times rather than its
        // target's (lutimes). Backends that follow by default must honour it.
        _nofollow: bool,
    ) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }

    /// Grow `path` so its size is at least `size` bytes (mode-0 fallocate /
    /// posix_fallocate semantics: never shrinks). Default: unsupported.
    fn allocate(&self, _path: &str, _size: u64) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
    }

    /// Read the target of a symlink at `path`. Default: not a symlink.
    fn read_link(&self, _path: &str) -> Option<String> {
        None
    }

    /// Set an extended attribute `name` to `value` on `path`. `flags` is the
    /// Linux XATTR_CREATE/XATTR_REPLACE mask. Only the `user.*` namespace is
    /// supported (the conformance-relevant namespace); other namespaces and
    /// the in-memory backend return `Err(LINUX_ENOTSUP)` via the default.
    fn set_xattr(
        &self,
        _path: &str,
        _name: &str,
        _value: &[u8],
        _flags: i32,
        _follow: bool,
    ) -> Result<(), LinuxErrno> {
        Err(crate::linux_abi::LINUX_ENOTSUP)
    }

    /// Read the extended attribute `name` on `path`. Returns the raw value
    /// bytes. `Err(LINUX_ENODATA)` if absent. Default: unsupported.
    fn get_xattr(&self, _path: &str, _name: &str, _follow: bool) -> Result<Vec<u8>, LinuxErrno> {
        Err(crate::linux_abi::LINUX_ENOTSUP)
    }

    /// List the `user.*` extended attribute names on `path` (names only, no
    /// trailing NUL — the caller assembles the NUL-separated list). Default:
    /// unsupported.
    fn list_xattr(&self, _path: &str, _follow: bool) -> Result<Vec<String>, LinuxErrno> {
        Err(crate::linux_abi::LINUX_ENOTSUP)
    }

    /// Remove the `user.*` extended attribute `name` from `path`.
    /// `Err(LINUX_ENODATA)` if the attribute is absent. Default: unsupported.
    fn remove_xattr(&self, _path: &str, _name: &str, _follow: bool) -> Result<(), LinuxErrno> {
        Err(crate::linux_abi::LINUX_ENOTSUP)
    }

    /// Read the REAL on-disk stat for `path` (type + hard-link count +
    /// mode + size), the way a kernel `newfstatat`/`statx` would see it.
    ///
    /// `follow` selects symlink semantics: `false` is lstat (report the
    /// link itself — `RootFsEntryKind::Symlink`), `true` is stat (report
    /// the link target). Only disk-backed backends can answer this; the
    /// default returns `None` so the dispatcher falls back to its
    /// synthesized [`RootFsMetadata`]-based stat.
    fn real_stat(&self, _path: &str, _follow: bool) -> Option<RealStat> {
        None
    }

    /// Dispatch-level fast stat: serve `path`'s `RealStat` straight from the
    /// stat cache (one revalidating `fstatat` through a cached contained parent
    /// fd), letting the `newfstatat`/`statx` handlers skip `resolve_at_path`'s
    /// parent-containment `openat` entirely on a hit. Returns `None` whenever the
    /// cache is disabled or the path is not a plain cached regular file/dir
    /// (symlinks, escapes, cross-mount, /proc, errors) — the caller then takes
    /// the full resolve-and-stat path. Default: `None`. See
    /// [`HostFsBackend::stat_cache`].
    fn stat_cache_lookup(&self, _path: &str) -> Option<RealStat> {
        None
    }

    /// Fast intermediate-path validation for the resolver's hot path: validate
    /// the PARENT chain of a lexically-joined guest absolute `abs` with the
    /// kernel in ~one syscall (openat the parent + F_GETPATH byte-exact),
    /// replacing the per-component O(K²) slow walk for the common case. See
    /// [`ParentResolve`]. Default: `Slow` (no kernel path to fast-walk).
    fn validate_parents_fast(&self, _abs: &str) -> ParentResolve {
        ParentResolve::Slow
    }

    /// Open a TRUSTED host dirfd on the directory at guest `path`, for the
    /// dispatcher's dirfd-relative fast lane. `Some` ONLY when the backend can
    /// prove, byte-exactly, that the opened inode's real host path equals
    /// `sandbox_root + path` — i.e. no symlink, Unicode alias, or sandbox
    /// escape anywhere in the chain — so that a later single-component
    /// `openat(fd, name, O_NOFOLLOW)` is structurally contained with NO
    /// per-op containment check. The returned fd is `O_CLOEXEC|O_DIRECTORY`
    /// and owned by the caller. Default: `None` (no kernel namespace to
    /// anchor trust in — the memory backend can never take this lane).
    fn open_trusted_dir_fd(&self, _path: &str) -> Option<std::os::fd::OwnedFd> {
        None
    }

    /// Return an open, contained host dirfd for `dir` if supported.
    fn dir_fd_for(&self, _dir: &Path) -> Option<std::sync::Arc<std::os::fd::OwnedFd>> {
        None
    }

    /// Whether this backend is shared with the host (not private to container).
    fn is_shared(&self) -> bool {
        false
    }

    /// `true` when the overlay's own bookkeeping could make a RAW host
    /// directory stream lie about the guest view of `dir` — i.e. `getdents`
    /// must take the layered (per-child classified) path instead of streaming
    /// `d_type`/`d_ino` straight off the host dirfd. For the host backend the
    /// scratch tree IS the merged truth (the rootfs is materialized, deletions
    /// are real unlinks), so the only interference is MARKER nodes whose
    /// guest-visible type differs from their on-disk type: AF_UNIX socket
    /// nodes (`create_socket`) and mknod device nodes (`create_device`), both
    /// regular files on disk. Sidecar files are name-filtered by the stream
    /// itself and are not interference. Default: `true` (fail closed — a
    /// backend that cannot prove otherwise keeps today's layered path).
    fn dir_has_overlay_interference(&self, _dir: &str) -> bool {
        true
    }

    /// True iff a host stat of a plain entry is the complete guest-visible
    /// answer (no chmod/chown metadata xattrs, no marker nodes anywhere), so
    /// dispatch fast lanes may skip their per-entry xattr probe. Fail-closed
    /// default: only backends that track the markers may say true.
    fn serves_plain_metadata(&self) -> bool {
        false
    }

    /// Notify the backend that a metadata xattr (chmod/chown) was written.
    fn note_meta_xattr_written(&self) {}

    /// Monotonic per-backend structural generation. Bumped on any mutation
    /// that adds, removes, or renames entries in this backend's namespace.
    fn structural_generation(&self) -> u64 {
        0
    }

    /// Human-readable backend name for `--fs` reporting. Default is
    /// the impl's `type_name`-style identifier.
    fn name(&self) -> &'static str {
        "unknown"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayEntryKind {
    Dir,
    File,
    Deleted,
}

/// Result of [`FsBackend::validate_parents_fast`] — a one-syscall kernel-walked
/// check of a path's intermediate (parent) chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentResolve {
    /// Every intermediate exists, is a directory, has NO symlink/Unicode-alias
    /// redirection, and stays in the sandbox — the resolver can skip BOTH the
    /// intermediate-dir ENOTDIR validation and the intermediate-symlink rewrite.
    AllDirsNoSymlink,
    /// An intermediate component is a non-directory → ENOTDIR.
    NotDir,
    /// Anything else (a missing component, an intermediate symlink, a
    /// Unicode-aliased name, a sandbox escape, or a non-host backend): the
    /// caller must run the exact per-component slow path.
    Slow,
}
pub mod path;
pub use self::path::*;

pub mod memory;
pub use self::memory::MemoryBackend;

pub mod host;
pub use self::host::*;

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests;
