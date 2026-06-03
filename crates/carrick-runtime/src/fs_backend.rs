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
//!   `cap_std::fs::Dir` (kernel-rooted, syscall-level escape-proof),
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

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use parking_lot::RwLock;

use crate::dispatch::HostSyscallResult;
use crate::rootfs::{RootFs, RootFsDirEntry, RootFsEntryKind, RootFsError, RootFsMetadata};

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
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// Last-access time `(sec, nsec)` from the real on-disk inode.
    pub atime: (i64, i64),
    /// Last-modification time `(sec, nsec)` from the real on-disk inode.
    pub mtime: (i64, i64),
    /// Inode-change time `(sec, nsec)` from the real on-disk inode.
    pub ctime: (i64, i64),
}

/// Trait every writable-layer backend implements. Methods are layer-
/// aware (see module docs); the dispatcher does its own overlay-first
/// merging with the read-only rootfs underneath.
pub trait FsBackend: Send + Sync {
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

    /// Read the file bytes for `path`. `None` if the backend doesn't
    /// have a file at that path.
    fn file_contents(&self, path: &str) -> Option<Vec<u8>>;

    /// `True` iff `path` is currently tombstoned.
    fn is_deleted(&self, path: &str) -> bool {
        matches!(self.lookup_kind(path), Some(OverlayEntryKind::Deleted))
    }

    /// `True` iff the backend can answer "what's at this path" — i.e.
    /// `lookup(...).is_some()`.
    fn shadows(&self, path: &str) -> bool {
        self.lookup_kind(path).is_some()
    }

    /// Create a directory at `path`. Idempotent.
    fn make_dir(&self, path: &str) -> Result<(), BackendError>;

    /// Materialise an empty file at `path`. Used by `openat(..., O_CREAT)`
    /// when the file did not previously exist.
    fn create_file(&self, path: &str) -> Result<(), BackendError>;

    /// Create a named pipe (FIFO) at `path` with permission bits `mode`
    /// (low 0o7777). Used by `mknod(2)`/`mkfifo(3)` for `S_IFIFO`. The host
    /// backend makes a real `mkfifoat(2)` node on the cap-std scratch (so the
    /// FIFO is fork-shareable and stats as `S_IFIFO`); the in-memory backend
    /// can't back a real pipe and returns `Unsupported` (→ guest `EPERM`,
    /// matching unprivileged mknod). Default: unsupported.
    fn create_fifo(&self, _path: &str, _mode: u32) -> Result<(), BackendError> {
        Err(BackendError::Unsupported)
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

    /// Replace the contents of `path`. Used by write/writev/pwrite/
    /// ftruncate writeback and by rename-into-overlay.
    fn set_file_contents(&self, path: &str, contents: Vec<u8>) -> Result<(), BackendError>;

    /// Drop the backend's entry for `path` entirely. Returns true iff
    /// the backend was holding something there. Does NOT tombstone —
    /// caller pairs this with `mark_deleted` when the path also lives
    /// in the rootfs.
    fn remove_entry(&self, path: &str) -> bool;

    /// Tombstone `path` so that subsequent layered lookups treat it as
    /// absent, even if the rootfs still has it underneath.
    fn mark_deleted(&self, path: &str) -> Result<(), BackendError>;

    /// Immediate children of `dir` that the backend owns. Names only
    /// (the dispatcher pairs each with metadata via `metadata`).
    fn child_names(&self, dir: &str) -> Vec<(String, RootFsEntryKind)>;

    /// Immediate children of `dir` that are tombstoned. The dispatcher
    /// uses this to filter rootfs-supplied entries.
    fn deleted_child_names(&self, dir: &str) -> Vec<String>;

    /// Rename an entry the backend owns. Returns `Ok(true)` iff the
    /// source was present in the backend; `Ok(false)` means the
    /// caller has to materialise the rootfs-backed source into the
    /// backend first.
    fn rename_overlay_entry(&self, from: &str, to: &str) -> Result<bool, BackendError>;

    /// Open a REAL host file descriptor for `path`. For a disk-backed
    /// backend this is a normal kernel file: shared offset, and —
    /// crucially — it survives `libc::fork(2)`, so a forked child's
    /// writes are visible to the parent and vice versa. This is what
    /// makes apt's "child writes a temp file / pipe, parent reads it"
    /// verification patterns work under `--fs host`.
    ///
    /// `write` -> guest requested write access; `create` -> +O_CREAT;
    /// `trunc` -> +O_TRUNC. Returns the raw fd (caller owns it, must
    /// close it). A disk backend may internally open read-only guest fds
    /// with broader host access when safe; the dispatcher separately tracks
    /// guest-visible writability. `MemoryBackend` returns None: an in-memory
    /// HashMap has no kernel fd and cannot be shared across a real fork, so
    /// the dispatcher keeps its in-memory File model there.
    fn open_raw_fd(&self, path: &str, write: bool, create: bool, trunc: bool) -> Option<i32>;

    /// Open host vnode descriptors for inotify-style watches. Directory
    /// watches may include a host path so the inotify shim can snapshot/diff
    /// child names after a kqueue directory-write wakeup. Default:
    /// unsupported for backends with no real host namespace.
    fn watch_fds(&self, _path: &str) -> Result<Vec<crate::vfs::WatchFd>, i32> {
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

    /// Set the guest-visible owner of `path` (`u32::MAX` = leave unchanged, the
    /// `chown(-1)` sentinel). Default: no-op success (tmpfs-like). The host
    /// backend records it durably in xattrs since it can't really chown.
    fn set_owner(&self, _path: &str, _uid: u32, _gid: u32) -> Result<(), BackendError> {
        Ok(())
    }

    /// Read the guest-visible (uid, gid) of `path`, or `None` if unknown.
    /// Defaults to root (0,0) on backends that don't track ownership.
    fn get_owner(&self, _path: &str) -> Option<(u32, u32)> {
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
    fn set_xattr(&self, _path: &str, _name: &str, _value: &[u8], _flags: i32) -> Result<(), i32> {
        Err(crate::linux_abi::LINUX_ENOTSUP)
    }

    /// Read the extended attribute `name` on `path`. Returns the raw value
    /// bytes. `Err(LINUX_ENODATA)` if absent. Default: unsupported.
    fn get_xattr(&self, _path: &str, _name: &str) -> Result<Vec<u8>, i32> {
        Err(crate::linux_abi::LINUX_ENOTSUP)
    }

    /// List the `user.*` extended attribute names on `path` (names only, no
    /// trailing NUL — the caller assembles the NUL-separated list). Default:
    /// unsupported.
    fn list_xattr(&self, _path: &str) -> Result<Vec<String>, i32> {
        Err(crate::linux_abi::LINUX_ENOTSUP)
    }

    /// Remove the `user.*` extended attribute `name` from `path`.
    /// `Err(LINUX_ENODATA)` if the attribute is absent. Default: unsupported.
    fn remove_xattr(&self, _path: &str, _name: &str) -> Result<(), i32> {
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

    /// Fast intermediate-path validation for the resolver's hot path: validate
    /// the PARENT chain of a lexically-joined guest absolute `abs` with the
    /// kernel in ~one syscall (openat the parent + F_GETPATH byte-exact),
    /// replacing the per-component O(K²) slow walk for the common case. See
    /// [`ParentResolve`]. Default: `Slow` (no kernel path to fast-walk).
    fn validate_parents_fast(&self, _abs: &str) -> ParentResolve {
        ParentResolve::Slow
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

/// Strip a leading `/` and collapse `.` / `..` so the backend's
/// internal keys match what `RootFs::normalize_rootfs_path` would
/// produce. Returns `None` for paths that would escape the rootfs
/// (`/../something`).
pub fn normalize(path: &str) -> Option<PathBuf> {
    // `path` arrives in the VFS layer's reversible escape form (see
    // `crate::pathcodec`): undecodable guest path bytes are carried as PUA
    // scalars so the `&str`-based layer can hold them. We KEEP that encoded form
    // as the on-disk host name — macOS APFS rejects a raw non-UTF-8 filename
    // with EILSEQ (errno 92), so a guest's opaque `b"\xff"` cannot be stored
    // byte-for-byte. The PUA escape is valid UTF-8 (APFS-storable) AND
    // reversible, so it's our durable host representation of an undecodable
    // name. The escape is decoded back to the raw guest bytes only at the
    // GUEST-facing read-back boundaries (getdents/readlink/getcwd), so the
    // guest still sees `b"\xff"` and a re-open by those bytes round-trips.
    // Valid-UTF-8 paths encode to themselves (fast path, allocation-free).
    normalize_raw(Path::new(path))
}

/// Component-normalize a path whose components are already in the host's
/// canonical on-disk form (the VFS escape encoding, or plain UTF-8). Used for a
/// path that must NOT be re-encoded (e.g. a symlink target read back from the
/// host, which is already in the encoded form).
pub fn normalize_raw(raw: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Prefix(_) => return None,
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Normal(name) => out.push(name),
        }
    }
    Some(out)
}

/// Build a NUL-terminated C path from a raw host `OsStr` *by its bytes* —
/// unlike `CString::new(os.to_str()?)`, this does not reject a legitimate
/// non-UTF-8 (undecodable) filename that Linux lets the guest create. Returns
/// `None` only if the bytes contain an interior NUL (impossible for a real
/// path component).
#[cfg(unix)]
fn cstring_from_osstr(os: &std::ffi::OsStr) -> Option<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(os.as_bytes()).ok()
}

fn io_error_to_linux_errno(error: std::io::Error) -> i32 {
    crate::dispatch::macos_to_linux_errno(error.raw_os_error().unwrap_or(libc::EIO))
}

fn open_host_watch_fd(path: &Path) -> Result<i32, i32> {
    let cpath = cstring_from_osstr(path.as_os_str()).ok_or(crate::linux_abi::LINUX_EINVAL)?;
    #[cfg(target_os = "macos")]
    let host_flags = libc::O_EVTONLY;
    #[cfg(not(target_os = "macos"))]
    let host_flags = libc::O_RDONLY;
    // SAFETY: `cpath` is NUL-terminated and points at a real host path.
    let fd = unsafe { libc::open(cpath.as_ptr(), host_flags) };
    if fd < 0 {
        let raw = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        return Err(crate::dispatch::macos_to_linux_errno(raw));
    }
    Ok(fd)
}

fn child_name(prefix: &Path, candidate: &Path) -> Option<String> {
    let stripped = candidate.strip_prefix(prefix).ok()?;
    let mut components = stripped.components();
    let first = components.next()?;
    if components.next().is_some() {
        return None;
    }
    let Component::Normal(name) = first else {
        return None;
    };
    // The on-disk name is already in the host's canonical form (the VFS escape
    // encoding for an undecodable name, else plain UTF-8) — both are valid
    // UTF-8. Carry it through unchanged; the guest-facing getdents decodes it.
    Some(name.to_string_lossy().into_owned())
}

// ---------------------------------------------------------------------
// MemoryBackend: pure in-memory tmpfs-style upper layer.
// ---------------------------------------------------------------------

/// In-memory FsBackend: directories and file contents live in maps,
/// deletions are a tombstone set. Cheap, ephemeral, exactly what CI
/// or `cargo test` wants.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct MemoryBackendState {
    dirs: HashSet<PathBuf>,
    files: HashMap<PathBuf, Vec<u8>>,
    deletions: HashSet<PathBuf>,
    /// AF_UNIX socket nodes materialised by `bind(2)` (path → permission bits).
    /// Reported as `RootFsEntryKind::Socket` (S_IFSOCK) by `metadata`; present
    /// (existing, empty) to `lookup`/`lookup_kind`. Bind + chmod + unlink all
    /// happen in the same process, so no cross-fork coherence is required here.
    sockets: HashMap<PathBuf, u32>,
}

/// In-memory FsBackend: directories and file contents live in maps,
/// deletions are a tombstone set. Cheap, ephemeral, exactly what CI
/// or `cargo test` wants.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    inner: RwLock<MemoryBackendState>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Clone for MemoryBackend {
    fn clone(&self) -> Self {
        Self {
            inner: RwLock::new(self.inner.read().clone()),
        }
    }
}

impl PartialEq for MemoryBackend {
    fn eq(&self, other: &Self) -> bool {
        *self.inner.read() == *other.inner.read()
    }
}

impl Eq for MemoryBackend {}

impl FsBackend for MemoryBackend {
    fn lookup(&self, path: &str) -> Option<OverlayEntry> {
        let normalized = normalize(path)?;
        let inner = self.inner.read();
        if inner.deletions.contains(&normalized) {
            return Some(OverlayEntry::Deleted);
        }
        if inner.dirs.contains(&normalized) {
            return Some(OverlayEntry::Dir);
        }
        if let Some(bytes) = inner.files.get(&normalized) {
            return Some(OverlayEntry::File(bytes.clone()));
        }
        // An AF_UNIX socket node: present, but has no readable bytes. Report it
        // as an empty File-shaped entry so the layered lookup treats the path as
        // existing (the true Socket kind is carried by `metadata`).
        if inner.sockets.contains_key(&normalized) {
            return Some(OverlayEntry::File(Vec::new()));
        }
        None
    }

    fn lookup_kind(&self, path: &str) -> Option<OverlayEntryKind> {
        let normalized = normalize(path)?;
        let inner = self.inner.read();
        if inner.deletions.contains(&normalized) {
            return Some(OverlayEntryKind::Deleted);
        }
        if inner.dirs.contains(&normalized) {
            return Some(OverlayEntryKind::Dir);
        }
        if inner.files.contains_key(&normalized) || inner.sockets.contains_key(&normalized) {
            return Some(OverlayEntryKind::File);
        }
        None
    }

    fn metadata(&self, path: &str) -> Option<RootFsMetadata> {
        let normalized = normalize(path)?;
        let inner = self.inner.read();
        if let Some(&mode) = inner.sockets.get(&normalized) {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::Socket,
                mode: mode & 0o7777,
                size: 0,
            });
        }
        if let Some(contents) = inner.files.get(&normalized) {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::File,
                mode: 0o644,
                size: contents.len(),
            });
        }
        if inner.dirs.contains(&normalized) {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::Directory,
                mode: 0o755,
                size: 0,
            });
        }
        None
    }

    fn file_contents(&self, path: &str) -> Option<Vec<u8>> {
        let normalized = normalize(path)?;
        self.inner.read().files.get(&normalized).cloned()
    }

    fn make_dir(&self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        inner.deletions.remove(&normalized);
        inner.dirs.insert(normalized);
        Ok(())
    }

    fn create_file(&self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        inner.deletions.remove(&normalized);
        inner.files.entry(normalized).or_default();
        Ok(())
    }

    fn create_socket(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        inner.deletions.remove(&normalized);
        // A bind to an existing path normally fails (EADDRINUSE) — the caller
        // (net.rs bind) only reaches create_socket after a successful host
        // bind, so just record/overwrite the node.
        inner.files.remove(&normalized);
        inner.sockets.insert(normalized, mode & 0o7777);
        Ok(())
    }

    fn set_mode(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        // Only socket nodes track a mode in-memory (regular files/dirs report a
        // fixed mode); chmod on those stays tmpfs-no-op success (default trait).
        if let Some(slot) = inner.sockets.get_mut(&normalized) {
            *slot = mode & 0o7777;
            return Ok(());
        }
        Err(BackendError::Unsupported)
    }

    fn set_file_contents(&self, path: &str, contents: Vec<u8>) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        inner.deletions.remove(&normalized);
        inner.files.insert(normalized, contents);
        Ok(())
    }

    fn remove_entry(&self, path: &str) -> bool {
        let Some(normalized) = normalize(path) else {
            return false;
        };
        let mut inner = self.inner.write();
        let had_file = inner.files.remove(&normalized).is_some();
        let had_dir = inner.dirs.remove(&normalized);
        let had_socket = inner.sockets.remove(&normalized).is_some();
        had_file || had_dir || had_socket
    }

    fn mark_deleted(&self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        inner.files.remove(&normalized);
        inner.dirs.remove(&normalized);
        inner.sockets.remove(&normalized);
        inner.deletions.insert(normalized);
        Ok(())
    }

    fn child_names(&self, dir: &str) -> Vec<(String, RootFsEntryKind)> {
        let Some(prefix) = normalize(dir) else {
            return Vec::new();
        };
        let inner = self.inner.read();
        let mut out = Vec::new();
        for path in inner.files.keys() {
            if let Some(name) = child_name(&prefix, path) {
                out.push((name, RootFsEntryKind::File));
            }
        }
        for path in inner.sockets.keys() {
            if let Some(name) = child_name(&prefix, path) {
                out.push((name, RootFsEntryKind::Socket));
            }
        }
        for path in inner.dirs.iter() {
            if let Some(name) = child_name(&prefix, path) {
                out.push((name, RootFsEntryKind::Directory));
            }
        }
        out
    }

    fn deleted_child_names(&self, dir: &str) -> Vec<String> {
        let Some(prefix) = normalize(dir) else {
            return Vec::new();
        };
        self.inner
            .read()
            .deletions
            .iter()
            .filter_map(|path| child_name(&prefix, path))
            .collect()
    }

    fn rename_overlay_entry(&self, from: &str, to: &str) -> Result<bool, BackendError> {
        let src = normalize(from).ok_or(BackendError::Invalid)?;
        let dst = normalize(to).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        if let Some(contents) = inner.files.remove(&src) {
            inner.deletions.remove(&dst);
            inner.files.insert(dst.clone(), contents);
            inner.deletions.insert(src);
            return Ok(true);
        }
        if inner.dirs.remove(&src) {
            inner.deletions.remove(&dst);
            inner.dirs.insert(dst);
            inner.deletions.insert(src);
            return Ok(true);
        }
        Ok(false)
    }

    fn open_raw_fd(&self, _path: &str, _write: bool, _create: bool, _trunc: bool) -> Option<i32> {
        // No kernel fd backs an in-memory HashMap, and a real
        // libc::fork can't share it. The dispatcher uses its in-memory
        // File model for this backend.
        None
    }

    fn name(&self) -> &'static str {
        "memory"
    }
}

// ---------------------------------------------------------------------
// HostFsBackend: sandboxed real-filesystem upper layer.
// ---------------------------------------------------------------------

/// Monotonic counter feeding the transient (pre-unlink) name of an
/// `open_anon_fd` O_TMPFILE inode, so concurrent guest threads/processes
/// never collide on the scratch name between create and unlink.
static ANON_FD_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Real-filesystem FsBackend rooted at a scratch directory on disk.
///
/// All host syscalls go through a [`cap_std::fs::Dir`] handle that
/// the kernel opened at construction time. cap-std makes path-escape
/// syscall-level impossible: absolute paths, `..` components and
/// pre-existing symlinks pointing outside the scratch root all fail
/// at the open(2)/openat(2) layer, not as a Rust-level check.
///
/// The backend is purely disk-backed: the cap-std `dir` handle is the
/// single source of truth for what exists. Reads (`lookup`, `metadata`,
/// `file_contents`, `child_names`, ...) go straight to the live scratch
/// tree, and writes land directly there (cap-std `dir.create_dir`/
/// `dir.open_with` + std `Write`).
///
/// The one piece of in-memory state we keep is `tombstones`: paths the
/// guest deleted that still exist in the read-only rootfs layer
/// underneath. The dispatcher's layered lookup consults this to shadow
/// the rootfs, just like for the memory backend.
pub struct HostFsBackend {
    /// The kernel-rooted sandbox handle. ALL fs operations on the
    /// scratch dir go through this. Holding it directly (rather than
    /// the underlying `PathBuf`) is what enforces the sandbox.
    dir: cap_std::fs::Dir,
    /// Backing `TempDir` so the scratch root is removed when the
    /// backend drops. `Some` for the normal case; `None` if the
    /// caller already owns the lifetime (e.g. tests with a custom
    /// `tempfile::TempDir`).
    _scratch: Option<tempfile::TempDir>,
    /// Per-run advisory flock so a startup sweeper can `rm -rf`
    /// orphaned scratch directories left behind by crashed runs.
    /// Held for the lifetime of the backend.
    _lock: Option<fd_lock::RwLock<std::fs::File>>,
    /// PID of the process that created this backend (and thus owns the
    /// `TempDir` lifetime). carrick forks real processes for guest
    /// `clone(2)`; every forked child inherits this struct via COW and
    /// shares the SAME on-disk scratch directory. If a forked child's
    /// `HostFsBackend` ran `TempDir::drop` it would `remove_dir_all`
    /// the scratch out from under its still-running siblings (the cause
    /// of the `--fs host` apt-resolver regression: a worker exiting
    /// deleted /etc/hosts mid-resolution). The Drop impl leaks the
    /// `TempDir` in any process other than the creator, so only the
    /// original `carrick run` process reaps the scratch.
    owner_pid: u32,
    /// F_GETPATH of the sandbox root dir fd, cached for the fast-stat
    /// containment check (an opened entry's F_GETPATH must live under this).
    /// `None` disables the fast path (treated as not-enabled).
    root_prefix: Option<String>,
    /// `--fs host` fast stat path (openat+F_GETPATH instead of cap-std's
    /// per-component walk; see docs/fs-host-capstd-amplification.md) enabled.
    /// Default ON. It was briefly default-off because its extra openat/close
    /// churn per stat AGGRAVATED a fork-quiesce wedge (test_fork1 hung); that
    /// wedge — the forking thread's `others` sibling count going stale-high as
    /// vCPUs exited mid-quiesce — is fixed (runtime.rs recomputes it live), so
    /// the win (test_glob 140s→48s) is on by default.
    fast_fs: bool,
}

/// F_GETPATH of a cap-std dir fd → its absolute host path (macOS), used as the
/// containment prefix for the fast-stat path. `None` on failure/non-macOS.
fn host_root_prefix(dir: &cap_std::fs::Dir) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let mut buf = [0u8; libc::PATH_MAX as usize];
        let rc = unsafe {
            libc::fcntl(
                dir.as_raw_fd(),
                libc::F_GETPATH,
                buf.as_mut_ptr() as *mut libc::c_char,
            )
        };
        if rc < 0 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        std::str::from_utf8(&buf[..end]).ok().map(|s| s.to_owned())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = dir;
        None
    }
}

/// `--fs host` fast stat path enabled. Default ON (`CARRICK_FAST_FS=0` opts out).
/// It was briefly default-off because it aggravated a fork-quiesce wedge; that
/// wedge (stale `others` count — see runtime.rs fork loop) is now fixed, so the
/// perf win is on by default. See docs/fs-host-capstd-amplification.md.
fn fast_fs_enabled() -> bool {
    !matches!(
        std::env::var("CARRICK_FAST_FS").as_deref(),
        Ok("0") | Ok("false")
    )
}

impl Drop for HostFsBackend {
    fn drop(&mut self) {
        let current = unsafe { libc::getpid() as u32 };
        if current != self.owner_pid {
            // Forked descendant: leak the TempDir so its Drop does NOT
            // delete the shared scratch directory. `into_path` consumes
            // the TempDir without scheduling removal.
            if let Some(scratch) = self._scratch.take() {
                let _ = scratch.keep();
            }
        }
    }
}

impl std::fmt::Debug for HostFsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostFsBackend").finish()
    }
}

impl HostFsBackend {
    /// Construct a backend rooted at a fresh per-run scratch directory
    /// under `scratch_root` (default `~/.carrick/scratch/<pid>`).
    /// Sweeps orphans (directories whose lockfile is no longer
    /// flock'd) before allocating a new one.
    pub fn new() -> std::io::Result<Self> {
        let scratch_root = default_scratch_root()?;
        Self::new_in(&scratch_root)
    }

    pub fn new_in(scratch_root: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(scratch_root)?;
        sweep_orphans(scratch_root);

        let scratch = tempfile::TempDir::new_in(scratch_root)?;
        let lock = acquire_lockfile(scratch.path())?;
        let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority())?;
        let root_prefix = host_root_prefix(&dir);
        let fast_fs = fast_fs_enabled();
        Ok(Self {
            dir,
            _scratch: Some(scratch),
            _lock: Some(lock),
            owner_pid: unsafe { libc::getpid() as u32 },
            root_prefix,
            fast_fs,
        })
    }

    /// Walk a `RootFs` and write every file/dir/symlink into the
    /// scratch root, then register every path as "known" so the
    /// backend's lookup returns it. After this call, the backend
    /// IS the rootfs — the dispatcher's read-side fallback to the
    /// in-memory `RootFs` becomes redundant (every path the rootfs
    /// would have served is now on disk under the cap-std `Dir`).
    ///
    /// This is the architectural shift from "overlay on top of read-
    /// only rootfs" to "host APFS owns everything, throw away on
    /// exit." cap-std's rooted `Dir` keeps the sandbox guarantee:
    /// guest paths are still confined to the scratch root.
    pub fn seed_from_rootfs(&mut self, rootfs: &crate::rootfs::RootFs) -> std::io::Result<()> {
        rootfs
            .extract_to_dir(&self.dir)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        // Everything is on the cap-std disk now, which is the single
        // source of truth for lookups — no bookkeeping to record.
        Ok(())
    }

    /// Construct against an already-allocated scratch dir without
    /// taking ownership of its lifetime. Used by tests.
    pub fn from_existing_dir(dir: cap_std::fs::Dir) -> Self {
        let root_prefix = host_root_prefix(&dir);
        let fast_fs = fast_fs_enabled();
        Self {
            dir,
            _scratch: None,
            _lock: None,
            owner_pid: unsafe { libc::getpid() as u32 },
            root_prefix,
            fast_fs,
        }
    }

    /// Open an EXISTING scratch directory as the writable overlay WITHOUT owning
    /// its lifetime (no `TempDir` auto-delete, no lockfile). Because the
    /// `--fs host` path extracts the whole rootfs onto the scratch, that
    /// directory IS the container's full filesystem — so this backs a detached
    /// container's stable overlay at `<registry>/<id>/scratch` (cleaned up by
    /// `carrick rm`) and lets `exec` share the exact same filesystem.
    pub fn attach(path: &Path) -> std::io::Result<Self> {
        let dir = cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority())?;
        Ok(Self::from_existing_dir(dir))
    }

    /// Like [`HostFsBackend::attach`], but creates `path` first if it is absent.
    /// Used to lay down a detached container's stable overlay before extracting
    /// the image layers into it.
    pub fn attach_or_create(path: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(path)?;
        Self::attach(path)
    }

    /// Fast `real_stat` for the common regular-file / directory case on
    /// `--fs host`: one `fstatat` (kernel resolves the whole path) instead of
    /// cap-std's per-component walk, with an `openat`+`F_GETPATH` containment
    /// check that an intermediate symlink didn't escape the sandbox root. Returns
    /// `None` (→ the cap-std path handles it) for symlink leaves (owner on the
    /// link), FIFOs/sockets/devices (open would block or differ), escapes (cap-std
    /// re-roots absolute-symlink targets), or any error. See
    /// docs/fs-host-capstd-amplification.md.
    /// Core of the fast path: `fstatat` (one syscall, kernel-resolved) + an
    /// `openat`+`F_GETPATH` containment check, returning the raw `stat` and the
    /// carrick entry kind for the common regular-file / directory case. `None`
    /// (→ cap-std handles it) for symlink leaves, FIFOs/sockets/devices, escapes
    /// (an intermediate symlink the kernel followed out of the sandbox root), or
    /// any error. See docs/fs-host-capstd-amplification.md.
    #[cfg(target_os = "macos")]
    fn fast_lstat_contained(
        &self,
        rel: &Path,
        follow: bool,
    ) -> Option<(libc::stat, RootFsEntryKind)> {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        if !self.fast_fs {
            return None;
        }
        let root_prefix = self.root_prefix.as_deref()?;
        let rel_c = std::ffi::CString::new(rel.as_os_str().as_bytes()).ok()?;
        let dir_fd = self.dir.as_raw_fd();

        // 1. lstat/stat in ONE syscall (kernel resolves the whole path).
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        let at_flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
        if unsafe { libc::fstatat(dir_fd, rel_c.as_ptr(), &mut st, at_flags) } != 0 {
            return None;
        }
        let typ = st.st_mode as u32 & libc::S_IFMT as u32;
        let kind = if typ == libc::S_IFDIR as u32 {
            RootFsEntryKind::Directory
        } else if typ == libc::S_IFREG as u32 {
            if read_socket_xattr(&self.dir, rel) {
                RootFsEntryKind::Socket
            } else {
                RootFsEntryKind::File
            }
        } else {
            return None; // symlink/FIFO/socket-node/device → cap-std path
        };

        // 2. Containment: open the entry and verify its real host path (F_GETPATH)
        //    is under the sandbox root. O_NONBLOCK so a (racing) FIFO can't block
        //    us; O_NOFOLLOW on lstat so a leaf-symlink swap can't redirect. An
        //    intermediate symlink the kernel followed out of the root is caught.
        let mut oflags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;
        if kind == RootFsEntryKind::Directory {
            oflags |= libc::O_DIRECTORY;
        }
        if !follow {
            oflags |= libc::O_NOFOLLOW;
        }
        let fd = unsafe { libc::openat(dir_fd, rel_c.as_ptr(), oflags, 0) };
        if fd < 0 {
            return None;
        }
        let mut buf = [0u8; libc::PATH_MAX as usize];
        let getpath_ok =
            unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr() as *mut libc::c_char) } >= 0;
        unsafe { libc::close(fd) };
        if !getpath_ok {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let got = std::str::from_utf8(&buf[..end]).ok()?;
        let contained = got == root_prefix
            || (got.len() > root_prefix.len()
                && got.starts_with(root_prefix)
                && got.as_bytes()[root_prefix.len()] == b'/');
        if !contained {
            return None;
        }
        Some((st, kind))
    }

    #[cfg(target_os = "macos")]
    fn fast_real_stat(&self, normalized: &Path, follow: bool) -> Option<RealStat> {
        let rel = Self::rel_path(normalized)?; // None == root dir: let cap-std handle
        let (st, kind) = self.fast_lstat_contained(rel, follow)?;

        // Build RealStat (mode/owner via the fast path-based xattr helpers).
        let is_dir = kind == RootFsEntryKind::Directory;
        let override_mode = read_mode_xattr(&self.dir, rel, is_dir);
        let owner = read_owner_xattr(&self.dir, rel, is_dir, false);
        let on_disk_mode = st.st_mode as u32 & 0o7777;
        let default_mode = if is_dir { 0o755 } else { 0o644 };
        Some(RealStat {
            kind,
            ino: st.st_ino,
            nlink: st.st_nlink as u32,
            mode: override_mode.unwrap_or(if on_disk_mode == 0 {
                default_mode
            } else {
                on_disk_mode
            }),
            uid: owner.0.unwrap_or(0),
            gid: owner.1.unwrap_or(0),
            size: st.st_size as u64,
            atime: (st.st_atime, st.st_atime_nsec),
            mtime: (st.st_mtime, st.st_mtime_nsec),
            ctime: (st.st_ctime, st.st_ctime_nsec),
        })
    }

    #[cfg(not(target_os = "macos"))]
    fn fast_real_stat(&self, _normalized: &Path, _follow: bool) -> Option<RealStat> {
        None
    }

    #[cfg(not(target_os = "macos"))]
    fn fast_lstat_contained(
        &self,
        _rel: &Path,
        _follow: bool,
    ) -> Option<(libc::stat, RootFsEntryKind)> {
        None
    }

    /// Stream OCI layer blobs directly into the scratch Dir (the on-demand
    /// rootfs path for `--fs host`). Replaces build-RootFs-then-seed: never
    /// materializes the in-memory tree. The Dir is authoritative afterward.
    pub fn extract_layers(
        &mut self,
        paths: &[std::path::PathBuf],
    ) -> std::io::Result<crate::rootfs::ExtractStats> {
        // Fast path: seed the scratch from the digest-keyed clonefile cache (an
        // O(1) COW clone of a once-extracted layer stack) instead of re-doing a
        // full byte-copy extraction. Only when we own a real scratch TempDir
        // (the production path); tests using `from_existing_dir` have no path to
        // anchor the cache against and fall straight through.
        if let Some(scratch) = self._scratch.as_ref().map(|t| t.path().to_path_buf())
            && matches!(
                crate::layer_cache::try_seed_scratch(paths, &scratch),
                Ok(true)
            )
        {
            // The clone reproduces the same on-disk tree a direct extraction
            // would; per-file ExtractStats aren't recovered for a cache hit.
            return Ok(crate::rootfs::ExtractStats::default());
        }
        crate::rootfs::extract_layer_paths_to_dir(paths, &self.dir)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn rel_path(normalized: &Path) -> Option<&Path> {
        if normalized.as_os_str().is_empty() {
            // cap-std doesn't have an "open this dir itself" path; the
            // empty path normalises to the scratch root, which the
            // dispatcher treats as the rootfs's `/`. We never want to
            // operate on the scratch root as a file, so reject here.
            None
        } else {
            Some(normalized)
        }
    }

    /// Resolve `path` to its final non-symlink target, following symlinks
    /// MANUALLY (40-hop ELOOP guard). cap-std follows a *relative* symlink
    /// target within the sandbox but refuses an *absolute* one as an escape —
    /// so `cat /a` where `/a -> /b` (absolute) would otherwise read the link's
    /// own target string instead of `/b`'s contents. Resolving by hand
    /// interprets an absolute target relative to the guest root. Returns the
    /// normalized (scratch-root-relative) path; if the final component doesn't
    /// exist (e.g. open-for-create) the path is returned unchanged so the
    /// caller can create it.
    fn resolve_following(&self, path: &str) -> Option<PathBuf> {
        let mut normalized = normalize(path)?;
        let mut hops = 0u32;
        loop {
            let Some(rel) = Self::rel_path(&normalized) else {
                return Some(normalized);
            };
            let Ok(meta) = self.dir.symlink_metadata(rel) else {
                // Doesn't exist (or unreadable) — hand back the path as-is.
                return Some(normalized);
            };
            if !meta.is_symlink() {
                return Some(normalized);
            }
            if hops >= 40 {
                return None; // ELOOP
            }
            hops += 1;
            let target = self.dir.read_link_contents(rel).ok()?;
            // `target` is raw host bytes; normalize it WITHOUT a String round-
            // trip so an undecodable symlink target isn't corrupted.
            normalized = if target.is_absolute() {
                normalize_raw(&target)?
            } else {
                let parent = normalized.parent().unwrap_or_else(|| Path::new(""));
                normalize_raw(&parent.join(&target))?
            };
        }
    }

    /// Byte-exact existence guard against macOS's normalizing VFS.
    ///
    /// macOS APFS/HFS+ normalize filenames at the syscall boundary: a
    /// `stat`/`open` of an NFD byte sequence resolves the NFC-named inode
    /// (and vice-versa), and compatibility forms (NFKC/NFKD) collapse too.
    /// Linux does NOT — a filename is an opaque byte string, so two
    /// differently-normalized names are two DIFFERENT files. carrick must
    /// present the Linux view: a guest `open("Grü̈ß")` (NFD) where only the
    /// NFC file exists has to fail with ENOENT, exactly as on Linux.
    ///
    /// cap-std's `symlink_metadata(rel)` goes through the normalizing host
    /// VFS, so it cannot see the difference. We re-check the FINAL component
    /// against the parent directory's `read_dir` listing, which returns each
    /// entry's true on-disk bytes; if the guest's requested bytes are not
    /// present verbatim, the host merely aliased a differently-normalized
    /// name and we report "not present" (`false`).
    ///
    /// Hot-path cheap: ASCII-only names can never be Unicode-normalized, so
    /// we skip the readdir entirely unless the final component carries a
    /// non-ASCII byte. (Intermediate path components are not re-checked: a
    /// normalized directory in the middle of the path is already an
    /// established on-disk entry, and re-walking every ancestor on every
    /// stat would be quadratic; the leaf is where guest-supplied freshly-
    /// normalized names actually bite — the unicode-filename tests.)
    fn name_matches_on_disk(&self, rel: &Path) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let Some(file_name) = rel.file_name() else {
            // No final component (the scratch root) — nothing to alias.
            return true;
        };
        let want = file_name.as_bytes();
        if want.is_ascii() {
            // ASCII bytes are never altered by Unicode normalization, so the
            // host VFS could not have aliased; trust the metadata lookup.
            return true;
        }
        let parent = rel.parent().unwrap_or_else(|| Path::new(""));
        let read = if parent.as_os_str().is_empty() {
            self.dir.entries()
        } else {
            self.dir.read_dir(parent)
        };
        let Ok(read) = read else {
            // Parent unreadable: don't manufacture a phantom mismatch.
            return true;
        };
        for entry in read.flatten() {
            if entry.file_name().as_bytes() == want {
                return true;
            }
        }
        false
    }
}

/// Extended attribute that carries the guest-intended file mode. carrick runs
/// as a non-root macOS user but presents the guest as root, so it must not
/// chmod a scratch file to a mode that locks itself out (e.g. `creat(f, 0)`
/// under umask 0777). The real file is kept owner-accessible; the true
/// guest mode lives in this xattr ON the file. Storing it on the file (rather
/// than in process memory) makes it coherent across carrick's real `fork`s
/// and frees us from lifecycle bookkeeping — it moves with rename and dies
/// with unlink. `user.`-prefixed so it's valid on Linux too (macOS accepts
/// any name). Reported by `metadata`/`fstat`; root semantics mean carrick
/// never enforces these bits against the guest, so the real mode can differ.
const CARRICK_MODE_XATTR: &[u8] = b"user.carrick.mode\0";

/// Same name as a `&str` (no trailing NUL). It lives in the `user.*` namespace
/// for Linux validity, so the guest-facing xattr syscalls (get/set/list) must
/// explicitly hide it — otherwise it leaks into the guest's `listxattr`.
#[allow(dead_code)]
pub(crate) const CARRICK_MODE_XATTR_NAME: &str = "user.carrick.mode";

/// Guest owner uid/gid xattrs. carrick runs the guest as root but as a
/// non-root macOS process it can't `chown` the scratch file to an arbitrary
/// uid, so the guest-visible owner is tracked here (same durable, fork-coherent
/// scheme as the mode). Hidden from the guest's get/set/listxattr like the
/// mode (they live in `user.*` for Linux validity).
const CARRICK_UID_XATTR: &[u8] = b"user.carrick.uid\0";
const CARRICK_GID_XATTR: &[u8] = b"user.carrick.gid\0";

/// Marker xattr that flags a regular scratch file as an `AF_UNIX` socket node
/// materialised by `bind(2)` (see `FsBackend::create_socket`). macOS can't
/// `mknod(S_IFSOCK)` as non-root, so the guest-facing node is a regular file;
/// this xattr makes `real_stat`/`metadata` report `S_IFSOCK` instead of
/// `S_IFREG`. Value is the marker byte `1`. Fork-coherent (lives on the real
/// on-disk file) and hidden from the guest's get/set/listxattr like the others.
const CARRICK_SOCKET_XATTR: &[u8] = b"user.carrick.socket\0";
#[allow(dead_code)]
pub(crate) const CARRICK_SOCKET_XATTR_NAME: &str = "user.carrick.socket";
#[allow(dead_code)]
pub(crate) const CARRICK_UID_XATTR_NAME: &str = "user.carrick.uid";
#[allow(dead_code)]
pub(crate) const CARRICK_GID_XATTR_NAME: &str = "user.carrick.gid";

fn is_internal_carrick_xattr(name: &str) -> bool {
    name.starts_with("user.carrick.")
}

/// Linux VFS xattr namespaces a guest may use. macOS xattrs are namespace-
/// agnostic, so we store the Linux name verbatim as a host xattr (carrick's own
/// `user.carrick.*` are still hidden via `is_internal_carrick_xattr`). The guest
/// runs as root by default, so it may use `trusted.*` (CAP_SYS_ADMIN) just like
/// the Docker-as-root oracle (CPython test_os's xattr-support probe sets
/// `trusted.foo`). `system.*`/`security.*` are likewise accepted and round-trip.
fn is_guest_xattr_namespace(name: &str) -> bool {
    name.starts_with("user.")
        || name.starts_with("trusted.")
        || name.starts_with("security.")
        || name.starts_with("system.")
}

#[cfg(target_os = "macos")]
fn fset_u32_xattr(fd: std::os::fd::RawFd, name: &[u8], val: u32) {
    let v = val.to_le_bytes();
    // macOS: fsetxattr(fd, name, value, size, position, options)
    unsafe {
        libc::fsetxattr(
            fd,
            name.as_ptr() as *const libc::c_char,
            v.as_ptr() as *const libc::c_void,
            v.len(),
            0,
            0,
        );
    }
}

#[cfg(target_os = "macos")]
fn fget_u32_xattr(fd: std::os::fd::RawFd, name: &[u8]) -> Option<u32> {
    let mut v = [0u8; 4];
    let n = unsafe {
        libc::fgetxattr(
            fd,
            name.as_ptr() as *const libc::c_char,
            v.as_mut_ptr() as *mut libc::c_void,
            v.len(),
            0,
            0,
        )
    };
    (n == 4).then(|| u32::from_le_bytes(v))
}

#[cfg(not(target_os = "macos"))]
fn fset_u32_xattr(fd: std::os::fd::RawFd, name: &[u8], val: u32) {
    let v = val.to_le_bytes();
    // Linux: fsetxattr(fd, name, value, size, flags)
    unsafe {
        libc::fsetxattr(
            fd,
            name.as_ptr() as *const libc::c_char,
            v.as_ptr() as *const libc::c_void,
            v.len(),
            0,
        );
    }
}

#[cfg(not(target_os = "macos"))]
fn fget_u32_xattr(fd: std::os::fd::RawFd, name: &[u8]) -> Option<u32> {
    let mut v = [0u8; 4];
    let n = unsafe {
        libc::fgetxattr(
            fd,
            name.as_ptr() as *const libc::c_char,
            v.as_mut_ptr() as *mut libc::c_void,
            v.len(),
        )
    };
    (n == 4).then(|| u32::from_le_bytes(v))
}

pub(crate) fn fget_mode_xattr(fd: std::os::fd::RawFd) -> Option<u32> {
    fget_u32_xattr(fd, CARRICK_MODE_XATTR)
}

/// Read the (uid, gid) owner xattrs from a fd. `None` for either if unset.
pub(crate) fn fget_owner_xattr(fd: std::os::fd::RawFd) -> (Option<u32>, Option<u32>) {
    (
        fget_u32_xattr(fd, CARRICK_UID_XATTR),
        fget_u32_xattr(fd, CARRICK_GID_XATTR),
    )
}

/// Open a short-lived fd for `rel` (file or dir) and run `f` on it.
fn with_entry_fd<R>(
    dir: &cap_std::fs::Dir,
    rel: &Path,
    is_dir: bool,
    writable: bool,
    f: impl FnOnce(std::os::fd::RawFd) -> R,
) -> Option<R> {
    use cap_std::fs::OpenOptionsExt;
    use std::os::fd::AsRawFd;
    if is_dir {
        let d = dir.open_dir(rel).ok()?;
        Some(f(d.as_raw_fd()))
    } else if writable {
        let file = dir
            .open_with(rel, cap_std::fs::OpenOptions::new().read(true).write(true))
            .ok()?;
        Some(f(file.as_raw_fd()))
    } else {
        // Read-only xattr peek (mode/owner). A plain read open() would bump
        // the file's access time to "now" on a strict-atime APFS volume —
        // and the mode xattr is read on EVERY stat of a regular file, so a
        // guest's `os.utime(path, (past_atime, ...))` was silently undone by
        // the very next stat. macOS `O_EVTONLY` opens the file "for event
        // monitoring only": fgetxattr still works, but the kernel does NOT
        // record an access, so atime is preserved exactly as the guest set
        // it (mailbox.Maildir.clean's getatime-cutoff sweep then matches
        // Linux). fall back to a plain open if O_EVTONLY isn't honored.
        const O_EVTONLY: i32 = 0x8000;
        let file = dir
            .open_with(
                rel,
                cap_std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(O_EVTONLY),
            )
            .or_else(|_| dir.open(rel))
            .ok()?;
        Some(f(file.as_raw_fd()))
    }
}

/// Read the guest-mode xattr for `rel` under `dir`. `None` => fall back to the
/// real mode.
fn read_mode_xattr(dir: &cap_std::fs::Dir, rel: &Path, is_dir: bool) -> Option<u32> {
    #[cfg(target_os = "macos")]
    {
        let _ = is_dir;
        path_get_u32_xattr(dir, rel, CARRICK_MODE_XATTR, false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        with_entry_fd(dir, rel, is_dir, false, |fd| {
            fget_u32_xattr(fd, CARRICK_MODE_XATTR)
        })
        .flatten()
    }
}

/// Write the guest-mode xattr for `rel` under `dir`. Best-effort.
pub(crate) fn write_mode_xattr(dir: &cap_std::fs::Dir, rel: &Path, is_dir: bool, mode: u32) {
    let _ = with_entry_fd(dir, rel, is_dir, true, |fd| {
        fset_u32_xattr(fd, CARRICK_MODE_XATTR, mode)
    });
}

/// `true` iff `rel` carries the `AF_UNIX`-socket marker xattr (see
/// `CARRICK_SOCKET_XATTR`). A read-only `O_EVTONLY` peek that preserves atime,
/// just like `read_mode_xattr`.
fn read_socket_xattr(dir: &cap_std::fs::Dir, rel: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        path_get_u32_xattr(dir, rel, CARRICK_SOCKET_XATTR, false).is_some()
    }
    #[cfg(not(target_os = "macos"))]
    {
        with_entry_fd(dir, rel, false, false, |fd| {
            fget_u32_xattr(fd, CARRICK_SOCKET_XATTR).is_some()
        })
        .unwrap_or(false)
    }
}

/// Read the guest owner (uid, gid) xattrs for `rel`. Either may be `None`.
/// Absolute host path of `rel` under the cap-std sandbox `dir` (macOS F_GETPATH
/// on the dir fd). Symlink xattr ops need it: cap-std can't open a symlink (its
/// O_NOFOLLOW conflicts with O_SYMLINK), so the link's own xattrs are reached by
/// a path-based setxattr/getxattr with XATTR_NOFOLLOW. `rel` is sandbox-validated.
#[cfg(target_os = "macos")]
fn sandbox_abs_path(dir: &cap_std::fs::Dir, rel: &Path) -> Option<std::path::PathBuf> {
    use std::os::fd::AsRawFd;
    let mut buf = [0u8; libc::PATH_MAX as usize];
    let rc = unsafe {
        libc::fcntl(
            dir.as_raw_fd(),
            libc::F_GETPATH,
            buf.as_mut_ptr() as *mut libc::c_char,
        )
    };
    if rc < 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(std::path::Path::new(std::str::from_utf8(&buf[..end]).ok()?).join(rel))
}

#[cfg(target_os = "macos")]
const XATTR_NOFOLLOW: i32 = 0x0001;

/// Path-based u32 xattr read (macOS). Unlike `with_entry_fd` + `fget_u32_xattr`,
/// this issues NO open() — so it avoids cap-std's per-component path walk (the
/// dominant cost of every stat on `--fs host`; ~291 host opens per guest open,
/// see docs/fs-host-capstd-amplification.md) and never bumps atime (getxattr is
/// a metadata op, like the O_EVTONLY open it replaces). `nofollow` reads a
/// symlink's OWN xattr (XATTR_NOFOLLOW); callers resolve real files first, so for
/// those the leaf is not a symlink and the flag is moot.
#[cfg(target_os = "macos")]
fn path_get_u32_xattr(
    dir: &cap_std::fs::Dir,
    rel: &Path,
    name: &[u8],
    nofollow: bool,
) -> Option<u32> {
    use std::os::unix::ffi::OsStrExt;
    let abs = sandbox_abs_path(dir, rel)?;
    let cpath = std::ffi::CString::new(abs.as_os_str().as_bytes()).ok()?;
    let mut v = [0u8; 4];
    let n = unsafe {
        libc::getxattr(
            cpath.as_ptr(),
            name.as_ptr() as *const libc::c_char,
            v.as_mut_ptr() as *mut libc::c_void,
            v.len(),
            0,
            if nofollow { XATTR_NOFOLLOW } else { 0 },
        )
    };
    (n == 4).then(|| u32::from_le_bytes(v))
}

#[cfg(target_os = "macos")]
fn symlink_get_u32_xattr(dir: &cap_std::fs::Dir, rel: &Path, name: &[u8]) -> Option<u32> {
    path_get_u32_xattr(dir, rel, name, true)
}

#[cfg(target_os = "macos")]
fn symlink_set_u32_xattr(dir: &cap_std::fs::Dir, rel: &Path, name: &[u8], val: u32) {
    use std::os::unix::ffi::OsStrExt;
    let Some(abs) = sandbox_abs_path(dir, rel) else {
        return;
    };
    let Ok(cpath) = std::ffi::CString::new(abs.as_os_str().as_bytes()) else {
        return;
    };
    let v = val.to_le_bytes();
    unsafe {
        libc::setxattr(
            cpath.as_ptr(),
            name.as_ptr() as *const libc::c_char,
            v.as_ptr() as *const libc::c_void,
            v.len(),
            0,
            XATTR_NOFOLLOW,
        );
    }
}

#[cfg(not(target_os = "macos"))]
fn symlink_get_u32_xattr(_d: &cap_std::fs::Dir, _r: &Path, _n: &[u8]) -> Option<u32> {
    None
}
#[cfg(not(target_os = "macos"))]
fn symlink_set_u32_xattr(_d: &cap_std::fs::Dir, _r: &Path, _n: &[u8], _v: u32) {}

fn read_owner_xattr(
    dir: &cap_std::fs::Dir,
    rel: &Path,
    is_dir: bool,
    symlink: bool,
) -> (Option<u32>, Option<u32>) {
    if symlink {
        return (
            symlink_get_u32_xattr(dir, rel, CARRICK_UID_XATTR),
            symlink_get_u32_xattr(dir, rel, CARRICK_GID_XATTR),
        );
    }
    #[cfg(target_os = "macos")]
    {
        let _ = is_dir;
        (
            path_get_u32_xattr(dir, rel, CARRICK_UID_XATTR, false),
            path_get_u32_xattr(dir, rel, CARRICK_GID_XATTR, false),
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        with_entry_fd(dir, rel, is_dir, false, |fd| {
            (
                fget_u32_xattr(fd, CARRICK_UID_XATTR),
                fget_u32_xattr(fd, CARRICK_GID_XATTR),
            )
        })
        .unwrap_or((None, None))
    }
}

/// Write the guest owner uid/gid xattrs for `rel`. A value of `u32::MAX`
/// (the `chown(-1)` sentinel) leaves that field unchanged. Best-effort.
pub(crate) fn write_owner_xattr(
    dir: &cap_std::fs::Dir,
    rel: &Path,
    is_dir: bool,
    symlink: bool,
    uid: u32,
    gid: u32,
) {
    if symlink {
        // lchown: the owner lives on the LINK itself (XATTR_NOFOLLOW).
        if uid != u32::MAX {
            symlink_set_u32_xattr(dir, rel, CARRICK_UID_XATTR, uid);
        }
        if gid != u32::MAX {
            symlink_set_u32_xattr(dir, rel, CARRICK_GID_XATTR, gid);
        }
        return;
    }
    let _ = with_entry_fd(dir, rel, is_dir, !is_dir, |fd| {
        if uid != u32::MAX {
            fset_u32_xattr(fd, CARRICK_UID_XATTR, uid);
        }
        if gid != u32::MAX {
            fset_u32_xattr(fd, CARRICK_GID_XATTR, gid);
        }
    });
}

impl FsBackend for HostFsBackend {
    fn lookup(&self, path: &str) -> Option<OverlayEntry> {
        let normalized = normalize(path)?;
        if normalized.as_os_str().is_empty() {
            // The sandbox root is always a directory.
            return Some(OverlayEntry::Dir);
        }
        let rel = Self::rel_path(&normalized)?;
        // Fast contained dir stat (no cap-std per-component walk) — the glob
        // hot path. Non-dirs fall through to the cap-std logic below.
        if let Some((_, RootFsEntryKind::Directory)) = self.fast_lstat_contained(rel, false) {
            return if self.name_matches_on_disk(rel) {
                Some(OverlayEntry::Dir)
            } else {
                None
            };
        }
        let meta = self.dir.symlink_metadata(rel).ok()?;
        // Reject a host-aliased (Unicode-normalized) name: present the Linux
        // byte-exact view, where a differently-normalized name is a different
        // (non-existent) file. See `name_matches_on_disk`.
        if !self.name_matches_on_disk(rel) {
            return None;
        }
        // After seed_from_rootfs the whole rootfs lives on disk under
        // the cap-std root. Every file/dir present in the sandbox is
        // authoritative — that's the "rootfs on host APFS" architecture.
        if meta.is_dir() {
            return Some(OverlayEntry::Dir);
        }
        if meta.is_file() {
            let mut buf = Vec::with_capacity(meta.len() as usize);
            let mut file = self.dir.open(rel).ok()?;
            file.read_to_end(&mut buf).ok()?;
            return Some(OverlayEntry::File(buf));
        }
        // A symlink: `OverlayEntry` has no Symlink variant, but the path
        // DOES exist, so report it as present rather than `None` (which
        // would make the layered lookup fall through and lose the entry).
        // Hand back the link target bytes so a content read is sensible;
        // `metadata`/`real_stat` carry the true `Symlink` kind for stat.
        if meta.is_symlink() {
            let target = self.dir.read_link_contents(rel).ok()?;
            // The stored target is already in the host's canonical (escape-
            // encoded or plain-UTF-8) form; hand back those bytes. readlink
            // goes through `read_link` (above) + a guest-facing decode.
            return Some(OverlayEntry::File(
                target.to_string_lossy().into_owned().into_bytes(),
            ));
        }
        // A FIFO is present but unreadable as bytes (opening it would block).
        // Report it as a (empty) File-shaped entry so the layered lookup
        // treats the path as existing; `metadata`/`RootFsVfs::lookup` carry
        // the true `Fifo` kind. Crucially, do NOT open the node here.
        {
            use cap_std::fs::MetadataExt;
            if meta.mode() & (libc::S_IFMT as u32) == libc::S_IFIFO as u32 {
                return Some(OverlayEntry::File(Vec::new()));
            }
        }
        None
    }

    fn lookup_kind(&self, path: &str) -> Option<OverlayEntryKind> {
        let normalized = normalize(path)?;
        if normalized.as_os_str().is_empty() {
            return Some(OverlayEntryKind::Dir);
        }
        let rel = Self::rel_path(&normalized)?;
        let meta = self.dir.symlink_metadata(rel).ok()?;
        // Reject a host-aliased (Unicode-normalized) name (see `lookup`).
        if !self.name_matches_on_disk(rel) {
            return None;
        }
        if meta.is_dir() {
            return Some(OverlayEntryKind::Dir);
        }
        if meta.is_file() {
            return Some(OverlayEntryKind::File);
        }
        // Symlink: present (treated as a File-shaped entry in the
        // `OverlayEntryKind` vocabulary, which has no Symlink variant).
        if meta.is_symlink() {
            return Some(OverlayEntryKind::File);
        }
        // FIFO: present (File-shaped in the kind vocabulary; the true `Fifo`
        // kind is carried by `metadata`). Never opens the node.
        {
            use cap_std::fs::MetadataExt;
            if meta.mode() & (libc::S_IFMT as u32) == libc::S_IFIFO as u32 {
                return Some(OverlayEntryKind::File);
            }
        }
        None
    }

    fn metadata(&self, path: &str) -> Option<RootFsMetadata> {
        let normalized = normalize(path)?;
        // The sandbox root ("/") is always a directory. rel_path refuses
        // to yield a relative path for it, so report it directly — once
        // the rootfs layer is dropped (--fs host) this is the only source
        // of truth for root metadata (statfs/open/mkdir-parent checks).
        if normalized.as_os_str().is_empty() {
            return Some(RootFsMetadata {
                path: std::path::Path::new("/").to_path_buf(),
                kind: RootFsEntryKind::Directory,
                mode: 0o755,
                size: 0,
            });
        }
        let rel = Self::rel_path(&normalized)?;
        // Fast contained dir/file stat (no cap-std per-component walk) — the
        // bulk of glob/stat cost. Symlinks/FIFOs fall through to cap-std below.
        if let Some((st, kind)) = self.fast_lstat_contained(rel, false) {
            if !self.name_matches_on_disk(rel) {
                return None;
            }
            let is_dir = kind == RootFsEntryKind::Directory;
            let override_mode = read_mode_xattr(&self.dir, rel, is_dir);
            let on_disk = st.st_mode as u32 & 0o7777;
            let default = if is_dir { 0o755 } else { 0o644 };
            return Some(RootFsMetadata {
                path: normalized,
                kind,
                mode: override_mode.unwrap_or(if on_disk == 0 { default } else { on_disk }),
                size: if is_dir { 0 } else { st.st_size as usize },
            });
        }
        let meta = self.dir.symlink_metadata(rel).ok()?;
        // Reject a host-aliased (Unicode-normalized) name (see `lookup`).
        if !self.name_matches_on_disk(rel) {
            return None;
        }
        // FIFO (named pipe): symlink_metadata reports neither dir/file/symlink.
        // Detect it from the raw type bits and report S_IFIFO. The mode lives on
        // the real node (create_fifo set it exactly), NOT in an xattr — reading
        // the xattr would open() the FIFO and an O_RDONLY open of a writer-less
        // FIFO blocks, wedging the dispatcher. `symlink_metadata` is fstatat,
        // so this never opens the node.
        {
            use cap_std::fs::MetadataExt;
            if meta.mode() & (libc::S_IFMT as u32) == libc::S_IFIFO as u32 {
                let mode = meta.mode() & 0o7777;
                return Some(RootFsMetadata {
                    path: normalized,
                    kind: RootFsEntryKind::Fifo,
                    mode: if mode == 0 { 0o644 } else { mode },
                    size: 0,
                });
            }
        }
        // A guest-mode xattr is the guest-visible mode (see CARRICK_MODE_XATTR);
        // the real file's mode was forced owner-accessible and isn't faithful.
        // Symlinks always report 0777, so skip the (link-following) xattr read.
        let override_mode = if meta.is_symlink() {
            None
        } else {
            read_mode_xattr(&self.dir, rel, meta.is_dir())
        };
        let mode = override_mode.unwrap_or_else(|| {
            use cap_std::fs::MetadataExt;
            meta.mode() & 0o7777
        });
        if meta.is_dir() {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::Directory,
                mode: if override_mode.is_none() && mode == 0 {
                    0o755
                } else {
                    mode
                },
                size: 0,
            });
        }
        if meta.is_file() {
            // An AF_UNIX socket node materialised by `create_socket` is a
            // regular file flagged with the socket-marker xattr → report
            // S_IFSOCK so getdents/stat see DT_SOCK/S_IFSOCK, not a plain file.
            let kind = if read_socket_xattr(&self.dir, rel) {
                RootFsEntryKind::Socket
            } else {
                RootFsEntryKind::File
            };
            return Some(RootFsMetadata {
                path: normalized,
                kind,
                mode: if override_mode.is_none() && mode == 0 {
                    0o644
                } else {
                    mode
                },
                size: meta.len() as usize,
            });
        }
        // Symlink: report `kind: Symlink` so callers that build a stat
        // from this metadata emit S_IFLNK. `symlink_metadata` did NOT
        // follow the link, so this is the link's own metadata.
        if meta.is_symlink() {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::Symlink,
                mode: if mode == 0 { 0o777 } else { mode },
                size: meta.len() as usize,
            });
        }
        None
    }

    fn file_contents(&self, path: &str) -> Option<Vec<u8>> {
        // Follow symlinks by hand so an absolute target resolves under the
        // guest root (cap-std won't traverse it). See `resolve_following`.
        let normalized = self.resolve_following(path)?;
        let rel = Self::rel_path(&normalized)?;
        let mut buf = Vec::new();
        let mut file = self.dir.open(rel).ok()?;
        file.read_to_end(&mut buf).ok()?;
        Some(buf)
    }

    fn make_dir(&self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        // Create all parent dirs in the scratch tree so the guest's
        // mkdir-deep paths "just work" (apt does
        // mkdir(/var/lib/apt/lists/partial) without checking parents).
        if let Some(parent) = rel.parent()
            && !parent.as_os_str().is_empty()
        {
            self.dir
                .create_dir_all(parent)
                .map_err(|_| BackendError::Io)?;
        }
        match self.dir.create_dir(rel) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(BackendError::Io),
        }
        Ok(())
    }

    fn create_file(&self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        if let Some(parent) = rel.parent()
            && !parent.as_os_str().is_empty()
        {
            self.dir
                .create_dir_all(parent)
                .map_err(|_| BackendError::Io)?;
        }
        let mut opts = cap_std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(false);
        self.dir
            .open_with(rel, &opts)
            .map_err(|_| BackendError::Io)?;
        Ok(())
    }

    fn create_fifo(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        use std::os::fd::AsRawFd;
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        // mknod(2) does NOT create intermediate directories (unlike the
        // overlay's create_file). A missing parent must surface as ENOENT —
        // mkfifoat below reports it; the dispatcher maps the failure.
        //
        // Operate on a CONFINED parent handle + slash-free leaf so the raw
        // *at primitives cannot resolve any symlink against the HOST root and
        // cannot escape the sandbox. cap_std::fs::Dir::open_dir follows only
        // in-sandbox symlink components and returns Err on an absolute or
        // net-`..` escape. The fchmodat below is still PATH-BASED (it never
        // opens the FIFO node), preserving the no-open property below.
        let parent_rel = rel.parent();
        let file_name = rel.file_name().ok_or(BackendError::Invalid)?;
        // Build the C name from the raw OsStr bytes — `to_str()` would reject a
        // legitimate non-UTF-8 (undecodable) filename that the guest is allowed
        // to create on Linux.
        let c_name = cstring_from_osstr(file_name).ok_or(BackendError::Invalid)?;
        // For a non-empty parent, open it through cap-std (confined); for a
        // top-level FIFO (empty parent), the sandbox root self.dir is the parent.
        let parent_dir = match parent_rel {
            Some(p) if !p.as_os_str().is_empty() => {
                Some(self.dir.open_dir(p).map_err(|_| BackendError::Io)?)
            }
            _ => None,
        };
        let dirfd = match &parent_dir {
            Some(pdir) => pdir.as_raw_fd(),
            None => self.dir.as_raw_fd(),
        };
        // Real named pipe on the cap-std scratch (fork-shareable, stats as
        // S_IFIFO). mkfifoat applies the host process umask; override it below
        // with the exact guest-requested mode so stat reports it faithfully.
        let rc = unsafe { libc::mkfifoat(dirfd, c_name.as_ptr(), (mode & 0o7777) as libc::mode_t) };
        if rc != 0 {
            return Err(BackendError::Io);
        }
        // Force the exact mode via PATH-BASED fchmodat — NOT cap-std's
        // set_permissions, which opens the node first: an O_RDONLY open of a
        // writer-less FIFO blocks and would wedge the single dispatcher thread.
        // Likewise the guest-mode xattr (CARRICK_MODE_XATTR) is skipped for
        // FIFOs because reading it back would also have to open the node;
        // `symlink_metadata` reads the on-disk mode without opening it.
        unsafe {
            libc::fchmodat(dirfd, c_name.as_ptr(), (mode & 0o7777) as libc::mode_t, 0);
        }
        Ok(())
    }

    fn create_socket(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        // macOS can't `mknod(S_IFSOCK)` as a non-root process, and the real
        // host socket the guest bound lives at a HASHED scratch path (so its
        // sun_path fits macOS's 104-byte limit, see net::support). To give the
        // guest a stat-able node at its OWN path, materialise a regular file on
        // the scratch and flag it with the socket-marker xattr — `real_stat`/
        // `metadata` then report `S_IFSOCK` (not `S_IFREG`). The real file is
        // fork-coherent (lives on the cap-std scratch shared across fork), so a
        // forkserver child that re-stats the path sees the same node.
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        if let Some(parent) = rel.parent()
            && !parent.as_os_str().is_empty()
        {
            self.dir
                .create_dir_all(parent)
                .map_err(|_| BackendError::Io)?;
        }
        let mut opts = cap_std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        self.dir
            .open_with(rel, &opts)
            .map_err(|_| BackendError::Io)?;
        // Mark it as a socket and stamp the guest-visible mode (bind applied the
        // umask; net.rs passes the resulting bits) so stat reports it faithfully.
        let _ = with_entry_fd(&self.dir, rel, false, true, |fd| {
            fset_u32_xattr(fd, CARRICK_SOCKET_XATTR, 1);
            fset_u32_xattr(fd, CARRICK_MODE_XATTR, mode & 0o7777);
        });
        Ok(())
    }

    fn set_file_contents(&self, path: &str, contents: Vec<u8>) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        if let Some(parent) = rel.parent()
            && !parent.as_os_str().is_empty()
        {
            self.dir
                .create_dir_all(parent)
                .map_err(|_| BackendError::Io)?;
        }
        let mut opts = cap_std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        let mut file = self
            .dir
            .open_with(rel, &opts)
            .map_err(|_| BackendError::Io)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| BackendError::Io)?;
        file.write_all(&contents).map_err(|_| BackendError::Io)?;
        Ok(())
    }

    fn remove_entry(&self, path: &str) -> bool {
        let Some(normalized) = normalize(path) else {
            return false;
        };
        let Some(rel) = Self::rel_path(&normalized) else {
            return false;
        };
        // The cap-std scratch is the source of truth (readdir/lookup hit
        // it), so remove from disk unconditionally.
        self.dir.remove_file(rel).is_ok() || self.dir.remove_dir(rel).is_ok()
    }

    fn mark_deleted(&self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        // Also evict any in-scratch entry so the scratch tree matches
        // the tombstoned view.
        if let Some(rel) = Self::rel_path(&normalized) {
            let _ = self.dir.remove_file(rel);
            let _ = self.dir.remove_dir(rel);
        }
        Ok(())
    }

    fn child_names(&self, dir: &str) -> Vec<(String, RootFsEntryKind)> {
        let Some(normalized) = normalize(dir) else {
            return Vec::new();
        };
        // Read the LIVE cap-std directory. Files created via open_raw_fd
        // (which hands back a raw fd) and directories created via mkdir
        // both land on the scratch disk, and the whole rootfs is
        // materialised there too. The disk is the single source of truth,
        // so readdir/glob see everything that exists by path — including
        // apt's downloaded .deb that dpkg later needs to find.
        let read = match Self::rel_path(&normalized) {
            Some(rel) => self.dir.read_dir(rel),
            None => self.dir.entries(), // scratch root == guest "/"
        };
        let Ok(read) = read else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in read.flatten() {
            // The on-disk name is already the host's canonical (escape-encoded
            // or plain-UTF-8) form; carry it through unchanged. The guest-facing
            // getdents decodes the escape back to the raw opaque bytes.
            let name = entry.file_name().to_string_lossy().into_owned();
            let kind = match entry.file_type() {
                Ok(ft) if ft.is_dir() => RootFsEntryKind::Directory,
                Ok(ft) if ft.is_symlink() => RootFsEntryKind::Symlink,
                _ => {
                    // cap-std's FileType only distinguishes dir/symlink, so a
                    // FIFO falls here. It MUST be classified as Fifo (via the
                    // raw mode — fstatat, no open): downstream readdir size
                    // lookup reads File contents, and opening a writer-less
                    // FIFO O_RDONLY blocks the dispatcher forever (the tst_test
                    // framework-hang). S_IFIFO check keeps it path-based.
                    use cap_std::fs::MetadataExt;
                    let is_fifo = entry
                        .metadata()
                        .ok()
                        .map(|m| m.mode() & (libc::S_IFMT as u32) == libc::S_IFIFO as u32)
                        .unwrap_or(false);
                    if is_fifo {
                        RootFsEntryKind::Fifo
                    } else {
                        RootFsEntryKind::File
                    }
                }
            };
            out.push((name, kind));
        }
        out
    }

    fn deleted_child_names(&self, dir: &str) -> Vec<String> {
        let _ = dir;
        // Host backend is disk-authoritative: deletions are real unlinks,
        // so there are no tombstoned children to surface.
        Vec::new()
    }

    fn rename_overlay_entry(&self, from: &str, to: &str) -> Result<bool, BackendError> {
        let src = normalize(from).ok_or(BackendError::Invalid)?;
        let dst = normalize(to).ok_or(BackendError::Invalid)?;
        let src_rel = Self::rel_path(&src)
            .ok_or(BackendError::Invalid)?
            .to_path_buf();
        let dst_rel = Self::rel_path(&dst)
            .ok_or(BackendError::Invalid)?
            .to_path_buf();
        // The cap-std scratch is the source of truth: an entry is
        // renameable iff it actually exists on disk. (open_raw_fd
        // creations and seeded rootfs entries are all on disk.)
        if self.dir.symlink_metadata(&src_rel).is_err() {
            return Ok(false);
        }
        if let Some(parent) = dst_rel.parent()
            && !parent.as_os_str().is_empty()
        {
            self.dir
                .create_dir_all(parent)
                .map_err(|_| BackendError::Io)?;
        }
        self.dir
            .rename(&src_rel, &self.dir, &dst_rel)
            .map_err(|_| BackendError::Io)?;
        Ok(true)
    }

    fn open_raw_fd(&self, path: &str, write: bool, create: bool, trunc: bool) -> Option<i32> {
        use std::os::fd::IntoRawFd;
        // Follow symlinks by hand first so an absolute symlink target (which
        // cap-std refuses to traverse) resolves to the file under the guest
        // root rather than opening the link itself.
        let normalized = self.resolve_following(path)?;
        // A tombstoned path is "deleted" in the layered view; don't
        // resurrect it via a raw open.
        let rel = Self::rel_path(&normalized)?;
        if create
            && let Some(parent) = rel.parent()
            && !parent.as_os_str().is_empty()
        {
            self.dir.create_dir_all(parent).ok()?;
        }
        let mut opts = cap_std::fs::OpenOptions::new();
        opts.read(true);
        if write {
            opts.write(true);
        }
        opts.create(create).truncate(trunc);
        let file = if !write && !trunc && !create {
            // HVF rejects hv_vm_map of a MAP_SHARED file VMA whose backing fd
            // only allows read max-protection. Prefer an O_RDWR host fd for
            // Carrick-owned scratch files, while still recording guest
            // writability separately in OpenDescription::HostFile.
            let mut rw_opts = cap_std::fs::OpenOptions::new();
            rw_opts.read(true).write(true);
            self.dir
                .open_with(rel, &rw_opts)
                .or_else(|_| self.dir.open_with(rel, &opts))
                .ok()?
        } else {
            self.dir.open_with(rel, &opts).ok()?
        };
        // Hand the kernel fd to the caller. `into_raw_fd` consumes the
        // cap-std File without closing it, so the dispatcher owns the
        // fd lifetime (it closes it on guest close()).
        Some(file.into_std().into_raw_fd())
    }

    fn watch_fds(&self, path: &str) -> Result<Vec<crate::vfs::WatchFd>, i32> {
        use std::os::unix::ffi::OsStrExt;

        let scratch = self
            ._scratch
            .as_ref()
            .ok_or(crate::linux_abi::LINUX_ENOSYS)?;
        let kind = self
            .lookup_kind(path)
            .ok_or(crate::linux_abi::LINUX_ENOENT)?;
        if matches!(kind, OverlayEntryKind::Deleted) {
            return Err(crate::linux_abi::LINUX_ENOENT);
        }
        let normalized = self
            .resolve_following(path)
            .ok_or(crate::linux_abi::LINUX_EINVAL)?;
        let host_path = scratch.path().join(&normalized);
        let root_fd = open_host_watch_fd(&host_path)?;
        let metadata = std::fs::symlink_metadata(&host_path).map_err(io_error_to_linux_errno)?;
        if !metadata.is_dir() {
            return Ok(vec![crate::vfs::WatchFd::unnamed(root_fd)]);
        }

        let mut fds = vec![crate::vfs::WatchFd::scanning_directory(
            root_fd,
            host_path.clone(),
        )];
        for entry in std::fs::read_dir(&host_path).map_err(io_error_to_linux_errno)? {
            let entry = entry.map_err(io_error_to_linux_errno)?;
            if let Ok(host_fd) = open_host_watch_fd(&entry.path()) {
                fds.push(crate::vfs::WatchFd::named(
                    host_fd,
                    entry.file_name().as_bytes().to_vec(),
                ));
            }
        }
        Ok(fds)
    }

    fn open_anon_fd(&self, mode: u32) -> Option<i32> {
        use std::os::fd::IntoRawFd;
        // O_TMPFILE = an unnamed regular file. macOS has no O_TMPFILE flag, so
        // synthesize the same semantics: create a uniquely-named file in the
        // scratch root, open it O_RDWR, then unlink the name immediately. The
        // open fd keeps the now-nameless inode alive (POSIX), and because it is
        // a real kernel fd it is inherited across fork(2) AND exec(2) — exactly
        // what makes a forked+exec'd child's write visible to the parent's read
        // (tempfile.TemporaryFile + faulthandler subprocess). The transient
        // name is never visible to the guest: it lives only between create and
        // unlink, and the guest namespace lookup never sees it.
        //
        // Build a per-(pid, counter, nanos) unique name so concurrent guest
        // threads/processes don't collide. O_RDWR (not the guest access mode)
        // so HVF can mmap the result with write max-protection if needed; the
        // dispatcher records the guest-visible writability separately in
        // OpenDescription::HostFile.
        let pid = unsafe { libc::getpid() } as u64;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = ANON_FD_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!(".carrick_o_tmpfile.{pid}.{seq}.{nanos}");
        let rel = Path::new(&name);

        let mut opts = cap_std::fs::OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        let file = self.dir.open_with(rel, &opts).ok()?;
        let raw_fd = file.into_std().into_raw_fd();

        // Force the guest-requested mode (the create above used the host umask)
        // via fchmod on the now-open fd. Best-effort: O_TMPFILE files are
        // unnamed, so the mode only matters for a later linkat(AT_EMPTY_PATH)
        // materialization and for fstat. fchmod operates on the inode directly,
        // so it still works after the unlink below.
        unsafe {
            libc::fchmod(raw_fd, (mode & 0o7777) as libc::mode_t);
        }

        // Unlink the name NOW so the file is anonymous; the open fd keeps the
        // inode alive. If the unlink fails we still proceed — the file would
        // just leak a name in scratch (cleaned on run teardown), not a
        // correctness bug, but it should not normally fail (we just created the
        // name with O_EXCL).
        let _ = self.dir.remove_file(rel);

        Some(raw_fd)
    }

    fn open_fifo_nonblock(&self, path: &str, access: u32) -> Option<i32> {
        use std::os::fd::AsRawFd;
        // resolve_following won't open the node; it just resolves the path.
        let normalized = self.resolve_following(path)?;
        let rel = Self::rel_path(&normalized)?;
        let c_rel = cstring_from_osstr(rel.as_os_str())?;
        let host_access = match access {
            0 => libc::O_RDONLY,
            1 => libc::O_WRONLY,
            _ => libc::O_RDWR,
        };
        // O_NONBLOCK is the whole point: an O_RDONLY open of a writer-less FIFO
        // returns immediately instead of blocking the dispatcher thread. The
        // resulting fd stays non-blocking; read_host_pipe/write_host_pipe route
        // EAGAIN to the kqueue WaitOnFds park for guest blocking semantics.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                c_rel.as_ptr(),
                host_access | libc::O_NONBLOCK,
            )
        };
        if fd < 0 { None } else { Some(fd) }
    }

    fn symlink(&self, target: &str, linkpath: &str) -> Result<(), BackendError> {
        let normalized = normalize(linkpath).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        if let Some(parent) = rel.parent()
            && !parent.as_os_str().is_empty()
        {
            self.dir
                .create_dir_all(parent)
                .map_err(|_| BackendError::Io)?;
        }
        // symlink_contents stores `target` verbatim (it may be absolute or
        // dangling), which is the Linux symlinkat(2) semantic.
        self.dir
            .symlink_contents(target, rel)
            .map_err(|_| BackendError::Io)
    }

    fn hard_link(&self, src: &str, linkpath: &str) -> Result<(), BackendError> {
        let src_norm = normalize(src).ok_or(BackendError::Invalid)?;
        let dst_norm = normalize(linkpath).ok_or(BackendError::Invalid)?;
        let src_rel = Self::rel_path(&src_norm)
            .ok_or(BackendError::Invalid)?
            .to_path_buf();
        let dst_rel = Self::rel_path(&dst_norm)
            .ok_or(BackendError::Invalid)?
            .to_path_buf();
        if let Some(parent) = dst_rel.parent()
            && !parent.as_os_str().is_empty()
        {
            self.dir
                .create_dir_all(parent)
                .map_err(|_| BackendError::Io)?;
        }
        self.dir
            .hard_link(&src_rel, &self.dir, &dst_rel)
            .map_err(|_| BackendError::Io)
    }

    fn set_mode(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        use cap_std::fs::MetadataExt;
        use cap_std::fs::Permissions;
        use cap_std::fs::PermissionsExt;
        use std::os::fd::AsRawFd;
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        let mode = mode & 0o7777;
        let meta = self.dir.symlink_metadata(rel);
        // A FIFO's mode lives on the real node (not an xattr); set it via
        // PATH-BASED fchmodat — neither set_permissions nor the xattr write may
        // open the node, since an O_RDONLY open of a writer-less FIFO blocks.
        // Operate on a CONFINED parent handle + slash-free leaf so the raw
        // fchmodat cannot resolve a symlink component against the HOST root and
        // cannot escape the sandbox (same guard as create_fifo). fchmodat stays
        // PATH-BASED, so it never opens the FIFO node.
        if let Ok(m) = &meta
            && m.mode() & (libc::S_IFMT as u32) == libc::S_IFIFO as u32
            && let Some(file_name) = rel.file_name()
            && let Some(c_name) = cstring_from_osstr(file_name)
        {
            let parent_dir = match rel.parent() {
                Some(p) if !p.as_os_str().is_empty() => self.dir.open_dir(p).ok(),
                _ => None,
            };
            let dirfd = match &parent_dir {
                Some(pdir) => pdir.as_raw_fd(),
                None => self.dir.as_raw_fd(),
            };
            unsafe {
                libc::fchmodat(dirfd, c_name.as_ptr(), mode as libc::mode_t, 0);
            }
            return Ok(());
        }
        // Force owner rwx on the REAL file so carrick (a non-root macOS
        // process) can always still open/stat/unlink it, then record the
        // guest-visible mode in an xattr ON the file (see CARRICK_MODE_XATTR).
        let is_dir = meta.map(|m| m.is_dir()).unwrap_or(false);
        let _ = self
            .dir
            .set_permissions(rel, Permissions::from_mode(mode | 0o700));
        write_mode_xattr(&self.dir, rel, is_dir, mode);
        Ok(())
    }

    fn set_owner(&self, path: &str, uid: u32, gid: u32) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        // carrick is not root on macOS, so it can't chown(2) the scratch file
        // to an arbitrary uid — record the guest-visible owner in xattrs ON the
        // file (durable, fork-coherent) and report it from stat.
        let m = self.dir.symlink_metadata(rel).ok();
        let is_dir = m.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let symlink = m.as_ref().map(|m| m.is_symlink()).unwrap_or(false);
        write_owner_xattr(&self.dir, rel, is_dir, symlink, uid, gid);
        Ok(())
    }

    fn get_owner(&self, path: &str) -> Option<(u32, u32)> {
        use cap_std::fs::MetadataExt;
        let normalized = normalize(path)?;
        let rel = Self::rel_path(&normalized)?;
        let meta = self.dir.symlink_metadata(rel).ok()?;
        // A FIFO has no owner xattr and reading one would open() the node
        // (O_RDONLY blocks a writer-less FIFO) — report root (0,0) directly.
        if meta.mode() & (libc::S_IFMT as u32) == libc::S_IFIFO as u32 {
            return Some((0, 0));
        }
        let (uid, gid) = read_owner_xattr(&self.dir, rel, meta.is_dir(), meta.is_symlink());
        Some((uid.unwrap_or(0), gid.unwrap_or(0)))
    }

    fn set_times(
        &self,
        path: &str,
        atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
        nofollow: bool,
    ) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        // `None` (UTIME_OMIT) leaves the component untouched.
        let to_ts = |t: Option<(i64, i64)>| match t {
            Some((sec, nsec)) => libc::timespec {
                tv_sec: sec as libc::time_t,
                tv_nsec: nsec as libc::c_long,
            },
            None => libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
        };
        let times = [to_ts(atime), to_ts(mtime)];
        if nofollow {
            // AT_SYMLINK_NOFOLLOW (lutimes): set the SYMLINK's OWN times, not
            // the target's. open()+futimens follows the link, so issue a
            // path-based utimensat RELATIVE to the scratch dir fd — the kernel
            // leaves the final component unfollowed and the dirfd keeps us
            // sandboxed within the cap-std root. (libuv fs_lutime.)
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
            let c = std::ffi::CString::new(rel.as_os_str().as_bytes())
                .map_err(|_| BackendError::Invalid)?;
            let rc = unsafe {
                libc::utimensat(
                    self.dir.as_raw_fd(),
                    c.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            return if rc < 0 {
                crate::probes::fs_op("set_times:lutimensat_err", path, 30);
                Err(BackendError::Io)
            } else {
                Ok(())
            };
        }
        // Follow path: open a real kernel fd for the materialised file and
        // drive `futimens(2)`. cap-std has no set-times API, but the whole
        // rootfs lives on the cap-std scratch, so a raw fd lets us persist
        // atime/mtime where a later stat (real_stat) will see them. Open
        // O_RDONLY (write=false): futimens needs only the fd + ownership, not
        // write mode, and O_RDWR would EISDIR on a DIRECTORY (test_os
        // test_utime_directory) and EACCES on a read-only file the guest owns.
        let host_fd = match self.open_raw_fd(path, false, false, false) {
            Some(fd) => fd,
            None => {
                crate::probes::fs_op("set_times:open_none", path, 30);
                return Err(BackendError::Io);
            }
        };
        let rc = unsafe { libc::futimens(host_fd, times.as_ptr()) };
        let err = if rc < 0 {
            crate::probes::fs_op("set_times:futimens_err", path, 30);
            Err(BackendError::Io)
        } else {
            Ok(())
        };
        unsafe { libc::close(host_fd) };
        err
    }

    fn allocate(&self, path: &str, size: u64) -> Result<(), BackendError> {
        let _normalized = normalize(path).ok_or(BackendError::Invalid)?;
        // mode-0 fallocate only ever grows the file. Open the real fd and
        // `ftruncate` up to `size` if the file is currently smaller; never
        // shrink (posix_fallocate semantics).
        let host_fd = self
            .open_raw_fd(path, true, false, false)
            .ok_or(BackendError::Io)?;
        let cur = {
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            if unsafe { libc::fstat(host_fd, &mut st) } < 0 {
                unsafe { libc::close(host_fd) };
                return Err(BackendError::Io);
            }
            st.st_size as u64
        };
        let err = if size > cur {
            let rc = unsafe { libc::ftruncate(host_fd, size as libc::off_t) };
            if rc < 0 {
                Err(BackendError::Io)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        };
        unsafe { libc::close(host_fd) };
        err
    }

    fn read_link(&self, path: &str) -> Option<String> {
        let normalized = normalize(path)?;
        let rel = Self::rel_path(&normalized)?;
        let target = self.dir.read_link_contents(rel).ok()?;
        // The stored target is already in the host's canonical (escape-encoded
        // or plain-UTF-8) form — both valid UTF-8. Return it unchanged; the
        // guest-facing readlinkat decodes the escape back to the raw bytes.
        Some(target.to_string_lossy().into_owned())
    }

    fn set_xattr(&self, path: &str, name: &str, value: &[u8], flags: i32) -> Result<(), i32> {
        // Accept the Linux VFS xattr namespaces (user./trusted./security./
        // system.); the guest is root so trusted.* is allowed, matching the
        // Docker-as-root oracle. Other prefixes report unsupported.
        if !is_guest_xattr_namespace(name) {
            return Err(crate::linux_abi::LINUX_ENOTSUP);
        }
        // Hide carrick's internal metadata xattrs: a guest must not be able to
        // read or clobber them (they live in user.* only for Linux validity).
        if is_internal_carrick_xattr(name) {
            return Err(crate::linux_abi::LINUX_ENOTSUP);
        }
        // Open a real kernel fd for the materialised file (same approach as
        // `set_times`/`allocate`) and drive macOS `fsetxattr(2)` on it. The
        // attribute name is stored verbatim ("user.foo"), so a later
        // list/get round-trips the exact Linux name.
        let host_fd = self
            .open_raw_fd(path, true, false, false)
            .ok_or(crate::linux_abi::LINUX_ENODATA)?;
        let cname = match std::ffi::CString::new(name) {
            Ok(c) => c,
            Err(_) => {
                unsafe { libc::close(host_fd) };
                return Err(crate::linux_abi::LINUX_EINVAL);
            }
        };
        // Translate Linux XATTR_CREATE/XATTR_REPLACE to the macOS options
        // (same semantics, different numeric values).
        let mut opts: libc::c_int = 0;
        if flags & crate::linux_abi::LINUX_XATTR_CREATE != 0 {
            opts |= libc::XATTR_CREATE;
        }
        if flags & crate::linux_abi::LINUX_XATTR_REPLACE != 0 {
            opts |= libc::XATTR_REPLACE;
        }
        let rc = unsafe {
            libc::fsetxattr(
                host_fd,
                cname.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len() as libc::size_t,
                0,
                opts,
            )
        };
        let err = rc.host_syscall_errno().map(|_| ());
        unsafe { libc::close(host_fd) };
        err
    }

    fn get_xattr(&self, path: &str, name: &str) -> Result<Vec<u8>, i32> {
        if !is_guest_xattr_namespace(name) || is_internal_carrick_xattr(name) {
            return Err(crate::linux_abi::LINUX_ENODATA);
        }
        let host_fd = self
            .open_raw_fd(path, false, false, false)
            .ok_or(crate::linux_abi::LINUX_ENODATA)?;
        let cname = match std::ffi::CString::new(name) {
            Ok(c) => c,
            Err(_) => {
                unsafe { libc::close(host_fd) };
                return Err(crate::linux_abi::LINUX_EINVAL);
            }
        };
        // First call with size 0 to learn the value length.
        let needed =
            unsafe { libc::fgetxattr(host_fd, cname.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
        let needed = match needed.host_syscall_errno() {
            Ok(needed) => needed,
            Err(err) => {
                unsafe { libc::close(host_fd) };
                return Err(err);
            }
        };
        let mut buf = vec![0u8; needed as usize];
        let n = unsafe {
            libc::fgetxattr(
                host_fd,
                cname.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
                0,
                0,
            )
        };
        let result = n.host_syscall_errno().map(|n| {
            buf.truncate(n as usize);
            buf
        });
        unsafe { libc::close(host_fd) };
        result
    }

    fn list_xattr(&self, path: &str) -> Result<Vec<String>, i32> {
        fn list_xattr_fd(host_fd: std::os::fd::RawFd) -> Result<Vec<String>, i32> {
            // macOS may surface its own attribute names (e.g. resource forks);
            // we read the full NUL-separated list then filter to `user.*` so the
            // result is exactly the Linux-conformant namespace the guest set.
            let needed = unsafe { libc::flistxattr(host_fd, std::ptr::null_mut(), 0, 0) };
            let needed = match needed.host_syscall_errno() {
                Ok(needed) => needed,
                Err(crate::linux_abi::LINUX_ENODATA) => return Ok(Vec::new()),
                Err(err) => return Err(err),
            };
            let mut buf = vec![0u8; needed as usize];
            let n = unsafe {
                libc::flistxattr(
                    host_fd,
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len() as libc::size_t,
                    0,
                )
            };
            let n = match n.host_syscall_errno() {
                Ok(n) => n,
                Err(crate::linux_abi::LINUX_ENODATA) => return Ok(Vec::new()),
                Err(err) => return Err(err),
            };
            buf.truncate(n as usize);
            let names = buf
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .filter_map(|s| std::str::from_utf8(s).ok())
                .filter(|s| is_guest_xattr_namespace(s) && !is_internal_carrick_xattr(s))
                .map(|s| s.to_owned())
                .collect();
            Ok(names)
        }

        let normalized = self
            .resolve_following(path)
            .ok_or(crate::linux_abi::LINUX_ENODATA)?;
        let Some(rel) = Self::rel_path(&normalized) else {
            use std::os::fd::AsRawFd;
            let root = self
                .dir
                .open_dir(".")
                .map_err(|_| crate::linux_abi::LINUX_ENODATA)?;
            return list_xattr_fd(root.as_raw_fd());
        };
        let meta = self
            .dir
            .symlink_metadata(rel)
            .map_err(|_| crate::linux_abi::LINUX_ENODATA)?;
        with_entry_fd(&self.dir, rel, meta.is_dir(), false, list_xattr_fd)
            .ok_or(crate::linux_abi::LINUX_ENODATA)?
    }

    fn remove_xattr(&self, path: &str, name: &str) -> Result<(), i32> {
        // Mirror get_xattr: a non-`user.*` or carrick-internal name has no
        // guest-visible attribute to remove → ENODATA.
        if !is_guest_xattr_namespace(name) || is_internal_carrick_xattr(name) {
            return Err(crate::linux_abi::LINUX_ENODATA);
        }
        let host_fd = self
            .open_raw_fd(path, true, false, false)
            .ok_or(crate::linux_abi::LINUX_ENODATA)?;
        let cname = match std::ffi::CString::new(name) {
            Ok(c) => c,
            Err(_) => {
                unsafe { libc::close(host_fd) };
                return Err(crate::linux_abi::LINUX_EINVAL);
            }
        };
        // macOS fremovexattr; ENOATTR (absent attribute) maps to Linux ENODATA
        // via host_syscall_errno (commit d9b1822).
        let rc = unsafe { libc::fremovexattr(host_fd, cname.as_ptr(), 0) };
        let err = rc.host_syscall_errno().map(|_| ());
        unsafe { libc::close(host_fd) };
        err
    }

    fn validate_parents_fast(&self, abs: &str) -> ParentResolve {
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            if !self.fast_fs {
                return ParentResolve::Slow;
            }
            let Some(root_prefix) = self.root_prefix.as_deref() else {
                return ParentResolve::Slow;
            };
            let Some(normalized) = normalize(abs) else {
                return ParentResolve::Slow;
            };
            // Parent = all but the final component; an empty parent is the
            // sandbox root, which is always a directory (no intermediates).
            let parent = match normalized.parent() {
                Some(p) if !p.as_os_str().is_empty() => p,
                _ => return ParentResolve::AllDirsNoSymlink,
            };
            let Ok(parent_c) = std::ffi::CString::new(parent.as_os_str().as_bytes()) else {
                return ParentResolve::Slow;
            };
            let dir_fd = self.dir.as_raw_fd();
            // ONE openat: the kernel walks every intermediate. O_DIRECTORY makes a
            // non-directory parent (or any non-dir intermediate) fail ENOTDIR.
            // Symlinks ARE followed; F_GETPATH below reveals any redirection.
            let oflags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NONBLOCK;
            let fd = unsafe { libc::openat(dir_fd, parent_c.as_ptr(), oflags, 0) };
            if fd < 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                // ENOTDIR ⇒ an intermediate is a non-dir. Anything else (ENOENT
                // missing, ELOOP, EACCES, …) ⇒ let the exact slow path decide.
                return if e == libc::ENOTDIR {
                    ParentResolve::NotDir
                } else {
                    ParentResolve::Slow
                };
            }
            let mut buf = [0u8; libc::PATH_MAX as usize];
            let getpath_ok = unsafe {
                libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr() as *mut libc::c_char)
            } >= 0;
            unsafe { libc::close(fd) };
            if !getpath_ok {
                return ParentResolve::Slow;
            }
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let got = &buf[..end];
            // Byte-exact: the real on-disk path must equal sandbox_root + "/" +
            // parent. ANY difference (an intermediate symlink the kernel followed,
            // a Unicode-normalized alias, a sandbox escape) ⇒ the slow path, which
            // resolves symlinks and rejects aliases exactly.
            let mut expected =
                Vec::with_capacity(root_prefix.len() + 1 + parent.as_os_str().len());
            expected.extend_from_slice(root_prefix.as_bytes());
            expected.push(b'/');
            expected.extend_from_slice(parent.as_os_str().as_bytes());
            if got == expected.as_slice() {
                ParentResolve::AllDirsNoSymlink
            } else {
                ParentResolve::Slow
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = abs;
            ParentResolve::Slow
        }
    }

    fn real_stat(&self, path: &str, follow: bool) -> Option<RealStat> {
        use cap_std::fs::MetadataExt;
        let mut normalized = normalize(path)?;
        // Reject a host-aliased (Unicode-normalized) leaf: stat/lstat of a
        // differently-normalized name must report ENOENT, exactly as on Linux
        // (see `name_matches_on_disk`). Checked on the guest-typed leaf BEFORE
        // any symlink following — that final component is where a freshly
        // normalized guest name aliases an on-disk entry.
        if let Some(rel) = Self::rel_path(&normalized)
            && !self.name_matches_on_disk(rel)
        {
            return None;
        }
        // Fast path (--fs host): a single fstatat + openat/F_GETPATH containment
        // for the common regular-file/dir case, skipping cap-std's per-component
        // walk. Falls through to cap-std for symlinks/FIFOs/escapes/errors.
        if let Some(rs) = self.fast_real_stat(&normalized, follow) {
            return Some(rs);
        }
        // lstat (`follow == false`) reports the link itself; stat
        // (`follow == true`) reports the target. We follow symlinks
        // MANUALLY rather than via cap-std's `metadata`, because cap-std
        // refuses to traverse an ABSOLUTE symlink target (it treats it as
        // a sandbox escape). Resolving by hand lets an absolute target
        // like `/tmp/dd` be interpreted relative to the guest root.
        let meta = if follow {
            let mut hops = 0u32;
            loop {
                let Some(rel) = Self::rel_path(&normalized) else {
                    break self.dir.dir_metadata().ok()?;
                };
                let m = self.dir.symlink_metadata(rel).ok()?;
                if !m.is_symlink() {
                    break m;
                }
                if hops >= 40 {
                    // ELOOP guard.
                    return None;
                }
                hops += 1;
                let target = self.dir.read_link_contents(rel).ok()?;
                // `target` is raw host bytes; normalize WITHOUT a String round-
                // trip so an undecodable symlink target isn't corrupted.
                normalized = if target.is_absolute() {
                    // Absolute target → relative to the guest root.
                    normalize_raw(&target)?
                } else {
                    // Relative target → relative to the link's parent dir.
                    let parent = normalized.parent().unwrap_or_else(|| Path::new(""));
                    normalize_raw(&parent.join(&target))?
                };
            }
        } else {
            match Self::rel_path(&normalized) {
                Some(rel) => self.dir.symlink_metadata(rel).ok()?,
                None => self.dir.dir_metadata().ok()?,
            }
        };
        let kind = if meta.is_dir() {
            RootFsEntryKind::Directory
        } else if meta.is_symlink() {
            RootFsEntryKind::Symlink
        } else if meta.mode() & (libc::S_IFMT as u32) == libc::S_IFIFO as u32 {
            RootFsEntryKind::Fifo
        } else if matches!(Self::rel_path(&normalized), Some(rel) if read_socket_xattr(&self.dir, rel))
        {
            // A regular scratch file flagged as an AF_UNIX socket node by
            // `create_socket` (see CARRICK_SOCKET_XATTR) → report S_IFSOCK.
            RootFsEntryKind::Socket
        } else {
            RootFsEntryKind::File
        };
        let mode = meta.mode() & 0o7777;
        let default_mode = match kind {
            RootFsEntryKind::Directory => 0o755,
            RootFsEntryKind::Symlink => 0o777,
            RootFsEntryKind::File
            | RootFsEntryKind::CharDevice
            | RootFsEntryKind::Fifo
            | RootFsEntryKind::Socket => 0o644,
        };
        // The real file's mode was forced owner-accessible; the guest-visible
        // mode lives in an xattr on the (symlink-resolved) target. Symlinks
        // report 0777, and a FIFO's xattr read would have to open() the node
        // (O_RDONLY blocks a writer-less FIFO and wedges the dispatcher) — its
        // mode lives on the real node (set by create_fifo). Skip the xattr for
        // both; use the real on-disk mode.
        let (override_mode, owner) = if kind == RootFsEntryKind::Fifo {
            // A FIFO's owner xattr can't be read (open() of a writer-less
            // FIFO blocks); report none.
            (None, (None, None))
        } else if kind == RootFsEntryKind::Symlink {
            // A symlink's mode is always 0o777; its owner lives on the link
            // itself (XATTR_NOFOLLOW), so lchown round-trips through lstat.
            match Self::rel_path(&normalized) {
                Some(rel) => (
                    None,
                    (
                        symlink_get_u32_xattr(&self.dir, rel, CARRICK_UID_XATTR),
                        symlink_get_u32_xattr(&self.dir, rel, CARRICK_GID_XATTR),
                    ),
                ),
                None => (None, (None, None)),
            }
        } else {
            match Self::rel_path(&normalized) {
                Some(rel) => {
                    let is_dir = matches!(kind, RootFsEntryKind::Directory);
                    (
                        read_mode_xattr(&self.dir, rel, is_dir),
                        read_owner_xattr(&self.dir, rel, is_dir, false),
                    )
                }
                None => (None, (None, None)),
            }
        };
        Some(RealStat {
            kind,
            ino: meta.ino(),
            nlink: meta.nlink() as u32,
            mode: override_mode.unwrap_or(if mode == 0 { default_mode } else { mode }),
            uid: owner.0.unwrap_or(0),
            gid: owner.1.unwrap_or(0),
            size: meta.len(),
            atime: (meta.atime(), meta.atime_nsec()),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        })
    }

    fn name(&self) -> &'static str {
        "host"
    }
}

fn default_scratch_root() -> std::io::Result<PathBuf> {
    // Prefer the dedicated carrick APFS volume (case-sensitive, isolated,
    // throw-away-able via `carrick volume delete`) when it exists. The
    // user lays it down once via `carrick volume create`; without it we
    // fall back to `~/.carrick/scratch`, which on a standard macOS
    // install is on the case-INSENSITIVE boot volume and will cause the
    // dispatcher's case-sensitivity probe to demote us to MemoryBackend.
    #[cfg(target_os = "macos")]
    {
        return crate::apfs::preferred_scratch_root();
    }
    #[allow(unreachable_code)]
    {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("TMPDIR").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let mut path = home;
        path.push(".carrick");
        path.push("scratch");
        Ok(path)
    }
}

fn acquire_lockfile(scratch_dir: &Path) -> std::io::Result<fd_lock::RwLock<std::fs::File>> {
    let lock_path = scratch_dir.join(".carrick.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    let mut lock = fd_lock::RwLock::new(file);
    // Best-effort try_write to take an advisory exclusive lock. We
    // don't hold the guard explicitly — the lock is released when the
    // file (and so the RwLock) drops.
    {
        let _guard = lock
            .try_write()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::WouldBlock, e))?;
        // Re-leak by leaving the scope; the underlying file fd retains
        // the flock per-process until the fd is closed.
        std::mem::forget(_guard);
    }
    Ok(lock)
}

fn sweep_orphans(scratch_root: &Path) {
    let Ok(entries) = std::fs::read_dir(scratch_root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let lock_path = path.join(".carrick.lock");
        if !lock_path.exists() {
            // No lockfile — either a brand-new dir or pre-lock era.
            // Don't touch it.
            continue;
        }
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
        else {
            continue;
        };
        let mut lock = fd_lock::RwLock::new(file);
        if lock.try_write().is_ok() {
            // No other process holds the lock; orphan from a prior
            // crashed run. Reap it.
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

// ---------------------------------------------------------------------
// Layered directory merge (overlay + rootfs - tombstones)
// ---------------------------------------------------------------------

/// Helper used by `getdents64` and `list_dir`-style call sites: merge
/// overlay child entries with rootfs entries while honouring the
/// overlay's tombstones. Returns entries in stable insertion order
/// (rootfs first, overlay's additions next).
pub fn layered_directory_entries(
    overlay: &dyn FsBackend,
    rootfs: Option<&RootFs>,
    dir: &str,
) -> Result<Vec<RootFsDirEntry>, RootFsError> {
    let mut out: Vec<RootFsDirEntry> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let deleted: HashSet<String> = overlay.deleted_child_names(dir).into_iter().collect();

    if let Some(rootfs) = rootfs {
        match rootfs.directory_entries(dir) {
            Ok(entries) => {
                for entry in entries {
                    if deleted.contains(&entry.name) {
                        continue;
                    }
                    if overlay.shadows(&joined(dir, &entry.name)) {
                        continue;
                    }
                    seen.insert(entry.name.clone());
                    out.push(entry);
                }
            }
            Err(RootFsError::NotFound(_)) => {
                // Will succeed only if the overlay covers this dir.
            }
            Err(other) => return Err(other),
        }
    }

    for (name, kind) in overlay.child_names(dir) {
        if seen.contains(&name) || deleted.contains(&name) {
            continue;
        }
        let path = joined(dir, &name);
        let normalized = normalize(&path).unwrap_or_default();
        let metadata = match kind {
            // A FIFO must NEVER be read here: `file_contents` opens the node
            // O_RDONLY and a writer-less FIFO open BLOCKS the dispatcher thread
            // forever. This is the tst_test framework-hang — a test that
            // mknod()s a FIFO in its tmpdir, then the framework openat()s the
            // tmpdir (O_DIRECTORY) and enumerates it, wedging on the FIFO's
            // size lookup. A FIFO's stat size is 0, so just report that.
            RootFsEntryKind::Fifo => RootFsMetadata {
                path: normalized,
                kind,
                mode: 0o644,
                size: 0,
            },
            // CharDevice never appears in the writable overlay (it only comes
            // from the /dev VFS mounts), but the match must be exhaustive.
            RootFsEntryKind::File | RootFsEntryKind::CharDevice => {
                // Use the backend's `metadata` (fstatat / HashMap len) for the
                // size — NOT `file_contents`, which open()s and reads the whole
                // file. On a strict-atime APFS scratch that read bumped the
                // file's access time to "now", so a guest's
                // `os.utime(path, (past_atime, ...))` was silently undone by the
                // very next directory enumeration (os.listdir → getdents). That
                // broke mailbox.Maildir.clean()'s getatime-cutoff sweep. A pure
                // stat preserves atime and avoids slurping every file just to
                // learn its length.
                let size = overlay.metadata(&path).map(|m| m.size).unwrap_or(0);
                RootFsMetadata {
                    path: normalized,
                    kind,
                    mode: 0o644,
                    size,
                }
            }
            RootFsEntryKind::Directory => RootFsMetadata {
                path: normalized,
                kind,
                mode: 0o755,
                size: 0,
            },
            RootFsEntryKind::Symlink => RootFsMetadata {
                path: normalized,
                kind,
                mode: 0o777,
                size: 0,
            },
            // AF_UNIX socket node (bind). Pull the stored permission bits from
            // the backend's `metadata` (the in-memory map / host marker xattr);
            // size is 0 like Linux. Never reads contents.
            RootFsEntryKind::Socket => {
                let mode = overlay.metadata(&path).map(|m| m.mode).unwrap_or(0o755);
                RootFsMetadata {
                    path: normalized,
                    kind,
                    mode,
                    size: 0,
                }
            }
        };
        seen.insert(name.clone());
        // Real host inode so getdents64 d_ino == a later stat's st_ino (scandir
        // DirEntry.inode()). lstat (follow=false) names the entry itself. 0 if
        // unavailable (in-memory backend) → getdents64 hashes the path instead.
        let ino = overlay.real_stat(&path, false).map(|s| s.ino).unwrap_or(0);
        out.push(RootFsDirEntry {
            name,
            metadata,
            ino,
        });
    }
    // NOTE: `.`/`..` are intentionally NOT added here — this helper also backs
    // the directory-EMPTINESS check (rmdir/unlinkat AT_REMOVEDIR), where two
    // synthetic dot entries would make every empty dir look non-empty
    // (ENOTEMPTY → broke `rm -rf`). The dot entries are synthesized only on the
    // getdents64 read path (see the getdents64 handler).
    Ok(out)
}

fn joined(base: &str, name: &str) -> String {
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", base.trim_end_matches('/'))
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- shared scenarios, run against both backends -----------------

    fn scenario_mkdir_then_stat<B: FsBackend>(b: &mut B) {
        b.make_dir("/var/lib/apt/lists/partial").unwrap();
        let entry = b.lookup("/var/lib/apt/lists/partial");
        assert!(matches!(entry, Some(OverlayEntry::Dir)), "got {entry:?}");
        let meta = b.metadata("/var/lib/apt/lists/partial").unwrap();
        assert_eq!(meta.kind, RootFsEntryKind::Directory);
    }

    fn scenario_open_create_write_read<B: FsBackend>(b: &mut B) {
        b.create_file("/tmp/example").unwrap();
        b.set_file_contents("/tmp/example", b"abcd".to_vec())
            .unwrap();
        let bytes = b.file_contents("/tmp/example").unwrap();
        assert_eq!(bytes, b"abcd");
    }

    fn scenario_unlink_hides_rootfs_path<B: FsBackend>(b: &mut B) {
        // Simulate a rootfs-backed path by tombstoning it; the
        // dispatcher does this in `unlinkat` for files that live in
        // the rootfs.
        b.mark_deleted("/etc/motd").unwrap();
        // Backend-agnostic observable: the path is no longer a readable file.
        // MemoryBackend records a tombstone (lookup -> Deleted); the
        // disk-authoritative HostFsBackend really removes it (lookup -> None).
        assert!(b.file_contents("/etc/motd").is_none());
        assert!(!matches!(
            b.lookup("/etc/motd"),
            Some(OverlayEntry::File(_))
        ));
    }

    fn scenario_rename_overlay_file<B: FsBackend>(b: &mut B) {
        b.create_file("/tmp/src").unwrap();
        b.set_file_contents("/tmp/src", b"hello".to_vec()).unwrap();
        let moved = b.rename_overlay_entry("/tmp/src", "/tmp/dst").unwrap();
        assert!(moved);
        assert_eq!(b.file_contents("/tmp/dst").as_deref(), Some(&b"hello"[..]));
        // Source no longer readable: MemoryBackend tombstones it, the
        // disk-authoritative HostFsBackend really renamed it away.
        assert!(b.file_contents("/tmp/src").is_none());
    }

    fn scenario_child_names_only_immediate<B: FsBackend>(b: &mut B) {
        b.make_dir("/var/lib/apt").unwrap();
        b.make_dir("/var/lib/apt/lists").unwrap();
        b.set_file_contents("/var/lib/apt/lists/lock", Vec::new())
            .unwrap();
        let mut names: Vec<String> = b
            .child_names("/var/lib/apt")
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        names.sort();
        assert_eq!(names, vec!["lists".to_owned()]);
    }

    // -- MemoryBackend ------------------------------------------------

    #[test]
    fn memory_mkdir_then_stat() {
        scenario_mkdir_then_stat(&mut MemoryBackend::new());
    }

    #[test]
    fn memory_open_create_write_read() {
        scenario_open_create_write_read(&mut MemoryBackend::new());
    }

    #[test]
    fn memory_unlink_hides_rootfs_path() {
        scenario_unlink_hides_rootfs_path(&mut MemoryBackend::new());
    }

    #[test]
    fn memory_rename_overlay_file() {
        scenario_rename_overlay_file(&mut MemoryBackend::new());
    }

    #[test]
    fn memory_child_names_only_immediate() {
        scenario_child_names_only_immediate(&mut MemoryBackend::new());
    }

    #[test]
    fn memory_normalize_strips_root_and_collapses_dots() {
        assert_eq!(
            normalize("/var/lib/apt/lists/partial"),
            Some(PathBuf::from("var/lib/apt/lists/partial"))
        );
        assert_eq!(
            normalize("/var/./lib/../lib/apt"),
            Some(PathBuf::from("var/lib/apt"))
        );
        assert_eq!(normalize("/../escape"), None);
    }

    // -- HostFsBackend ------------------------------------------------

    #[cfg(target_os = "macos")]
    fn host_backend() -> (HostFsBackend, tempfile::TempDir) {
        let scratch = tempfile::TempDir::new().unwrap();
        let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority())
            .unwrap();
        (HostFsBackend::from_existing_dir(dir), scratch)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_mkdir_then_stat() {
        let (mut b, _scratch) = host_backend();
        scenario_mkdir_then_stat(&mut b);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_open_create_write_read() {
        let (mut b, _scratch) = host_backend();
        scenario_open_create_write_read(&mut b);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn attach_shares_an_existing_scratch_across_handles() {
        // exec relies on this: a second backend attached to the same on-disk
        // scratch sees the first's writes (the shared container overlay).
        let scratch = tempfile::TempDir::new().unwrap();
        let a = HostFsBackend::attach(scratch.path()).unwrap();
        a.set_file_contents("/hello", b"world".to_vec()).unwrap();
        let b = HostFsBackend::attach(scratch.path()).unwrap();
        assert_eq!(b.file_contents("/hello").as_deref(), Some(&b"world"[..]));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_seed_from_rootfs_materializes_through_cap_dir() {
        let mut tar = tar::Builder::new(Vec::new());
        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_mode(0o755);
        dir_header.set_size(0);
        tar.append_data(&mut dir_header, "etc/", std::io::empty())
            .unwrap();

        let data = b"seeded\n";
        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_mode(0o640);
        file_header.set_size(data.len() as u64);
        tar.append_data(&mut file_header, "etc/motd", &data[..])
            .unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Symlink);
        link_header.set_mode(0o777);
        link_header.set_size(0);
        link_header.set_link_name("motd").unwrap();
        tar.append_data(&mut link_header, "etc/current", std::io::empty())
            .unwrap();

        let rootfs =
            RootFs::from_layers([crate::rootfs::LayerSource::Tar(tar.into_inner().unwrap())])
                .unwrap();
        let (mut backend, _scratch) = host_backend();
        backend.seed_from_rootfs(&rootfs).unwrap();

        assert!(matches!(backend.lookup("/etc"), Some(OverlayEntry::Dir)));
        assert!(
            matches!(backend.lookup("/etc/motd"), Some(OverlayEntry::File(ref b)) if b == b"seeded\n")
        );
        let link = backend.read_link("/etc/current").unwrap();
        assert_eq!(link, "motd");
        assert_eq!(
            backend.metadata("/etc/current").unwrap().kind,
            RootFsEntryKind::Symlink
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_unlink_hides_rootfs_path() {
        let (mut b, _scratch) = host_backend();
        scenario_unlink_hides_rootfs_path(&mut b);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_rename_overlay_file() {
        let (mut b, _scratch) = host_backend();
        scenario_rename_overlay_file(&mut b);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_child_names_only_immediate() {
        let (mut b, _scratch) = host_backend();
        scenario_child_names_only_immediate(&mut b);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_open_raw_fd_then_set_mode_visible_via_fget_xattr() {
        // Mirrors the openat(O_CREAT)+fstat path: create+open a real fd, set
        // the guest mode, then read it back from THAT fd (what fstat does).
        let (b, _scratch) = host_backend();
        let fd = b.open_raw_fd("/g", true, true, true).expect("open_raw_fd");
        b.set_mode("/g", 0o041).unwrap();
        assert_eq!(fget_mode_xattr(fd), Some(0o041), "fstat-side xattr read");
        unsafe { libc::close(fd) };
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_readonly_open_prefers_writable_host_fd() {
        let (b, _scratch) = host_backend();
        b.set_file_contents("/g", b"hvf maxprot\n".to_vec())
            .unwrap();
        let fd = b
            .open_raw_fd("/g", false, false, false)
            .expect("open_raw_fd");
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_eq!(flags & libc::O_ACCMODE, libc::O_RDWR);
        unsafe { libc::close(fd) };
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_set_mode_roundtrips_via_xattr_even_when_inaccessible() {
        let (b, _scratch) = host_backend();
        b.create_file("/f").unwrap();
        // A mode with no owner-read would lock carrick out if applied
        // literally; the xattr must still report it faithfully.
        b.set_mode("/f", 0o041).unwrap();
        assert_eq!(b.metadata("/f").unwrap().mode, 0o041);
        b.set_mode("/f", 0).unwrap();
        assert_eq!(b.metadata("/f").unwrap().mode, 0);
        b.set_mode("/f", 0o755).unwrap();
        assert_eq!(b.metadata("/f").unwrap().mode, 0o755);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_guest_xattr_api_hides_all_internal_carrick_names() {
        let (b, _scratch) = host_backend();
        assert_eq!(b.list_xattr("/").unwrap(), Vec::<String>::new());
        b.set_file_contents("/plain", b"x".to_vec()).unwrap();
        assert_eq!(b.list_xattr("/plain").unwrap(), Vec::<String>::new());

        b.set_file_contents("/f", b"x".to_vec()).unwrap();
        b.set_mode("/f", 0o600).unwrap();
        b.set_owner("/f", 123, 456).unwrap();

        for name in [
            CARRICK_MODE_XATTR_NAME,
            CARRICK_UID_XATTR_NAME,
            CARRICK_GID_XATTR_NAME,
            "user.carrick.future",
        ] {
            assert_eq!(
                b.get_xattr("/f", name),
                Err(crate::linux_abi::LINUX_ENODATA),
                "{name} must not be guest-readable",
            );
            assert_eq!(
                b.set_xattr("/f", name, b"guest", 0),
                Err(crate::linux_abi::LINUX_ENOTSUP),
                "{name} must not be guest-writable",
            );
        }

        b.set_xattr("/f", "user.visible", b"ok", 0).unwrap();
        let names = b.list_xattr("/f").unwrap();
        assert_eq!(names, vec!["user.visible".to_string()]);
    }

    /// Cap-std enforces sandboxing at the syscall layer: trying to
    /// reach outside the rooted dir via `..` or via a symlink that
    /// points outside the scratch root must fail at open time, NOT
    /// silently leak through. This is the sandboxing invariant the
    /// task called out as load-bearing for the host backend.
    #[cfg(target_os = "macos")]
    #[test]
    fn host_rejects_path_escape() {
        let outer = tempfile::TempDir::new().unwrap();
        // Create a victim file outside the scratch tree.
        let victim = outer.path().join("victim");
        std::fs::write(&victim, b"secret").unwrap();

        let scratch = outer.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let dir =
            cap_std::fs::Dir::open_ambient_dir(&scratch, cap_std::ambient_authority()).unwrap();
        let b = HostFsBackend::from_existing_dir(dir);
        // Try to escape via `..`. cap-std rejects this at the path-
        // walking layer, not via a Rust-level check, which is exactly
        // the secure-by-default guarantee we wanted.
        let result = b.set_file_contents("/../victim", b"pwned".to_vec());
        assert!(
            result.is_err(),
            "host backend must reject paths that escape its sandbox root"
        );

        // And via a symlink that points outside the scratch root: lay
        // down the symlink directly with std::os::unix::fs::symlink so
        // it pre-exists in the scratch tree, then try to write through
        // it. cap-std's open(2) must refuse to follow it past the
        // root.
        std::os::unix::fs::symlink(outer.path().join("victim"), scratch.join("escape")).unwrap();
        let result = b.set_file_contents("/escape", b"pwned".to_vec());
        assert!(
            result.is_err(),
            "host backend must reject writes through a symlink that escapes the sandbox"
        );
        // The victim file must be untouched.
        assert_eq!(std::fs::read(&victim).unwrap(), b"secret");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_resolve_following_enforces_symlink_hop_limit() {
        let scratch = tempfile::TempDir::new().unwrap();
        std::os::unix::fs::symlink("b", scratch.path().join("a")).unwrap();
        std::os::unix::fs::symlink("a", scratch.path().join("b")).unwrap();
        let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority())
            .unwrap();
        let b = HostFsBackend::from_existing_dir(dir);

        assert_eq!(b.file_contents("/a"), None);
    }

    /// HostFsBackend must survive `libc::fork(2)`: the apt-resolver
    /// regression under `--fs host` had the symptom of a forked
    /// child carrick process reading /etc/hosts via the inherited
    /// cap-std Dir fd and somehow not seeing the seeded content.
    /// This test reproduces the exact pattern (seed in parent, read
    /// in `libc::fork` child) to nail down whether cap-std's openat
    /// against an inherited dir fd returns the right bytes.
    #[cfg(target_os = "macos")]
    #[test]
    fn host_backend_survives_libc_fork_for_etc_hosts() {
        let (b, scratch) = host_backend();
        b.make_dir("/etc").unwrap();
        b.set_file_contents("/etc/hosts", b"151.101.194.132\tdeb.debian.org\n".to_vec())
            .unwrap();

        // Pipe the child carrick's read result back to the parent
        // so we can assert on it. The child must see the SAME bytes
        // the parent wrote.
        let mut pipefd: [i32; 2] = [0, 0];
        assert_eq!(unsafe { libc::pipe(pipefd.as_mut_ptr()) }, 0);
        let (read_end, write_end) = (pipefd[0], pipefd[1]);

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Child: read /etc/hosts via the inherited backend, write
            // the result to the pipe, then _exit so we bypass Rust
            // destructors that might race with the parent's view.
            unsafe { libc::close(read_end) };
            let buf = b.file_contents("/etc/hosts").unwrap_or_default();
            unsafe {
                libc::write(write_end, buf.as_ptr() as *const _, buf.len());
                libc::close(write_end);
                libc::_exit(0);
            }
        }
        // Parent: read what the child saw.
        unsafe { libc::close(write_end) };
        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(read_end, chunk.as_mut_ptr() as *mut _, chunk.len()) };
            if n <= 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n as usize]);
        }
        unsafe { libc::close(read_end) };
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };

        assert_eq!(
            String::from_utf8_lossy(&got),
            "151.101.194.132\tdeb.debian.org\n",
            "forked child read different bytes from /etc/hosts than the parent wrote"
        );
        drop(scratch);
    }

    /// Build a minimal tar layer on disk and verify that
    /// `HostFsBackend::extract_layers` streams it into the scratch Dir
    /// so that subsequent `lookup` / `metadata` calls return correct
    /// results — without ever seeding via `RootFs`.
    #[cfg(target_os = "macos")]
    #[test]
    fn host_extract_layers_streams_into_scratch() {
        use std::io::Write as _;

        // Helper: write a tar archive to disk and return its path.
        fn write_layer(
            dir: &std::path::Path,
            name: &str,
            build: impl FnOnce(&mut tar::Builder<Vec<u8>>),
        ) -> std::path::PathBuf {
            let mut b = tar::Builder::new(Vec::new());
            build(&mut b);
            let bytes = b.into_inner().unwrap();
            let p = dir.join(name);
            std::fs::File::create(&p)
                .unwrap()
                .write_all(&bytes)
                .unwrap();
            p
        }

        let tmp = tempfile::TempDir::new().unwrap();
        let layer = write_layer(tmp.path(), "layer0.tar", |b| {
            // etc/ directory
            let mut h_dir = tar::Header::new_gnu();
            h_dir.set_entry_type(tar::EntryType::Directory);
            h_dir.set_mode(0o755);
            h_dir.set_size(0);
            b.append_data(&mut h_dir, "etc/", std::io::empty()).unwrap();
            // etc/motd file
            let data = b"hi\n";
            let mut h_file = tar::Header::new_gnu();
            h_file.set_entry_type(tar::EntryType::Regular);
            h_file.set_mode(0o644);
            h_file.set_size(data.len() as u64);
            b.append_data(&mut h_file, "etc/motd", &data[..]).unwrap();
        });

        let (mut backend, _scratch) = host_backend();
        let stats = backend.extract_layers(&[layer]).unwrap();

        // Stats sanity
        assert_eq!(stats.dirs, 1, "expected 1 directory");
        assert_eq!(stats.files, 1, "expected 1 file");

        // /etc must be a Dir
        assert!(
            matches!(backend.lookup("/etc"), Some(OverlayEntry::Dir)),
            "lookup('/etc') should be Dir, got {:?}",
            backend.lookup("/etc")
        );

        // /etc/motd must be a File with the right bytes
        assert!(
            matches!(backend.lookup("/etc/motd"), Some(OverlayEntry::File(ref b)) if b == b"hi\n"),
            "lookup('/etc/motd') should be File(b\"hi\\n\"), got {:?}",
            backend.lookup("/etc/motd")
        );

        // metadata must report File kind
        let meta = backend
            .metadata("/etc/motd")
            .expect("metadata('/etc/motd') must be Some");
        assert_eq!(
            meta.kind,
            RootFsEntryKind::File,
            "metadata kind should be File, got {:?}",
            meta.kind
        );
    }
}
