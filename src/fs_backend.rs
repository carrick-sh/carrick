// Swappable filesystem-write backend behind a single trait.
//
// Carrick's OCI rootfs is read-only by construction (the layers come
// out of an OCI image and are immutable). To let the guest do useful
// work — `apt update` mkdir's `/var/lib/apt/lists/partial`, `dpkg`
// rewrites status files, build tools touch `/tmp` — the dispatcher
// needs a writable layer that sits on top.
//
// There are two reasonable places to put that layer:
//
//   * `MemoryBackend`: pure in-memory `HashMap<PathBuf, Vec<u8>>`,
//     fast, ephemeral, ideal for CI / tests / one-shot runs.
//   * `HostFsBackend`: a real APFS scratch directory, sandboxed via
//     `cap_std::fs::Dir` (kernel-rooted, syscall-level escape-proof),
//     reflink-seeded from the unpacked rootfs (clonefile is O(1) on
//     APFS). This is the production / durable option.
//
// Both implement the same [`FsBackend`] trait. The dispatcher holds
// a `Box<dyn FsBackend>` and is otherwise agnostic to which one is
// in use. The CLI `--fs <memory|host>` flag selects at runtime.
//
// API choice: the trait methods mirror the high-level operations the
// dispatcher already performs (`lookup`, `make_dir`, `set_file_contents`,
// `mark_deleted`, ...). They are intentionally *layer-aware* rather
// than POSIX-shaped — the dispatcher already does its own overlay-
// first + rootfs-fallback merging, so the backend's job is to be the
// "upper" layer. A POSIX-shaped open/read/write trait was considered
// but would have required either duplicating the layering logic in
// each backend or rewriting every fs-touching syscall site; the
// current shape is the minimum-risk version that still lets the host
// backend live behind the same trait.

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
    /// `write` -> O_RDWR (else O_RDONLY); `create` -> +O_CREAT;
    /// `trunc` -> +O_TRUNC. Returns the raw fd (caller owns it, must
    /// close it). `MemoryBackend` returns None: an in-memory HashMap
    /// has no kernel fd and cannot be shared across a real fork, so
    /// the dispatcher keeps its in-memory File model there.
    fn open_raw_fd(&self, path: &str, write: bool, create: bool, trunc: bool) -> Option<i32>;

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

/// Strip a leading `/` and collapse `.` / `..` so the backend's
/// internal keys match what `RootFs::normalize_rootfs_path` would
/// produce. Returns `None` for paths that would escape the rootfs
/// (`/../something`).
pub fn normalize(path: &str) -> Option<PathBuf> {
    let raw = Path::new(path);
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
        if inner.files.contains_key(&normalized) {
            return Some(OverlayEntryKind::File);
        }
        None
    }

    fn metadata(&self, path: &str) -> Option<RootFsMetadata> {
        let normalized = normalize(path)?;
        let inner = self.inner.read();
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
        had_file || had_dir
    }

    fn mark_deleted(&self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        inner.files.remove(&normalized);
        inner.dirs.remove(&normalized);
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
        Ok(Self {
            dir,
            _scratch: Some(scratch),
            _lock: Some(lock),
            owner_pid: unsafe { libc::getpid() as u32 },
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
        Self {
            dir,
            _scratch: None,
            _lock: None,
            owner_pid: unsafe { libc::getpid() as u32 },
        }
    }

    /// Stream OCI layer blobs directly into the scratch Dir (the on-demand
    /// rootfs path for `--fs host`). Replaces build-RootFs-then-seed: never
    /// materializes the in-memory tree. The Dir is authoritative afterward.
    pub fn extract_layers(
        &mut self,
        paths: &[std::path::PathBuf],
    ) -> std::io::Result<crate::rootfs::ExtractStats> {
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
            normalized = if target.is_absolute() {
                normalize(&target.to_string_lossy())?
            } else {
                let parent = normalized.parent().unwrap_or_else(|| Path::new(""));
                normalize(&parent.join(&target).to_string_lossy())?
            };
        }
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
pub(crate) const CARRICK_MODE_XATTR_NAME: &str = "user.carrick.mode";

/// Guest owner uid/gid xattrs. carrick runs the guest as root but as a
/// non-root macOS process it can't `chown` the scratch file to an arbitrary
/// uid, so the guest-visible owner is tracked here (same durable, fork-coherent
/// scheme as the mode). Hidden from the guest's get/set/listxattr like the
/// mode (they live in `user.*` for Linux validity).
const CARRICK_UID_XATTR: &[u8] = b"user.carrick.uid\0";
const CARRICK_GID_XATTR: &[u8] = b"user.carrick.gid\0";
#[allow(dead_code)]
pub(crate) const CARRICK_UID_XATTR_NAME: &str = "user.carrick.uid";
#[allow(dead_code)]
pub(crate) const CARRICK_GID_XATTR_NAME: &str = "user.carrick.gid";

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
        let file = dir.open(rel).ok()?;
        Some(f(file.as_raw_fd()))
    }
}

/// Read the guest-mode xattr for `rel` under `dir`. `None` => fall back to the
/// real mode.
fn read_mode_xattr(dir: &cap_std::fs::Dir, rel: &Path, is_dir: bool) -> Option<u32> {
    with_entry_fd(dir, rel, is_dir, false, |fd| {
        fget_u32_xattr(fd, CARRICK_MODE_XATTR)
    })
    .flatten()
}

/// Write the guest-mode xattr for `rel` under `dir`. Best-effort.
pub(crate) fn write_mode_xattr(dir: &cap_std::fs::Dir, rel: &Path, is_dir: bool, mode: u32) {
    let _ = with_entry_fd(dir, rel, is_dir, true, |fd| {
        fset_u32_xattr(fd, CARRICK_MODE_XATTR, mode)
    });
}

/// Read the guest owner (uid, gid) xattrs for `rel`. Either may be `None`.
fn read_owner_xattr(
    dir: &cap_std::fs::Dir,
    rel: &Path,
    is_dir: bool,
) -> (Option<u32>, Option<u32>) {
    with_entry_fd(dir, rel, is_dir, false, |fd| {
        (
            fget_u32_xattr(fd, CARRICK_UID_XATTR),
            fget_u32_xattr(fd, CARRICK_GID_XATTR),
        )
    })
    .unwrap_or((None, None))
}

/// Write the guest owner uid/gid xattrs for `rel`. A value of `u32::MAX`
/// (the `chown(-1)` sentinel) leaves that field unchanged. Best-effort.
pub(crate) fn write_owner_xattr(
    dir: &cap_std::fs::Dir,
    rel: &Path,
    is_dir: bool,
    uid: u32,
    gid: u32,
) {
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
        let meta = self.dir.symlink_metadata(rel).ok()?;
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
            return Some(OverlayEntry::File(
                target.to_string_lossy().into_owned().into_bytes(),
            ));
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
        let meta = self.dir.symlink_metadata(rel).ok()?;
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
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::File,
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
            let name = entry.file_name().to_string_lossy().into_owned();
            let kind = match entry.file_type() {
                Ok(ft) if ft.is_dir() => RootFsEntryKind::Directory,
                Ok(ft) if ft.is_symlink() => RootFsEntryKind::Symlink,
                _ => RootFsEntryKind::File,
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
        if write {
            opts.read(true).write(true);
        } else {
            opts.read(true);
        }
        opts.create(create).truncate(trunc);
        let file = self.dir.open_with(rel, &opts).ok()?;
        // Hand the kernel fd to the caller. `into_raw_fd` consumes the
        // cap-std File without closing it, so the dispatcher owns the
        // fd lifetime (it closes it on guest close()).
        Some(file.into_std().into_raw_fd())
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
        use cap_std::fs::Permissions;
        use cap_std::fs::PermissionsExt;
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        let mode = mode & 0o7777;
        // Force owner rwx on the REAL file so carrick (a non-root macOS
        // process) can always still open/stat/unlink it, then record the
        // guest-visible mode in an xattr ON the file (see CARRICK_MODE_XATTR).
        let is_dir = self
            .dir
            .symlink_metadata(rel)
            .map(|m| m.is_dir())
            .unwrap_or(false);
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
        let is_dir = self
            .dir
            .symlink_metadata(rel)
            .map(|m| m.is_dir())
            .unwrap_or(false);
        write_owner_xattr(&self.dir, rel, is_dir, uid, gid);
        Ok(())
    }

    fn set_times(
        &self,
        path: &str,
        atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
    ) -> Result<(), BackendError> {
        let _normalized = normalize(path).ok_or(BackendError::Invalid)?;
        // Open a real kernel fd for the materialised file and drive
        // `futimens(2)` directly. cap-std has no set-times API, but the
        // whole rootfs lives on the cap-std scratch, so a raw fd lets us
        // persist atime/mtime where a later stat (which reads real disk
        // metadata via real_stat) will see them.
        let host_fd = match self.open_raw_fd(path, true, false, false) {
            Some(fd) => fd,
            None => {
                crate::probes::fs_op("set_times:open_none", path, 30);
                return Err(BackendError::Io);
            }
        };
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
        Some(target.to_string_lossy().into_owned())
    }

    fn set_xattr(&self, path: &str, name: &str, value: &[u8], flags: i32) -> Result<(), i32> {
        // Only the Linux `user.*` namespace is modelled. Anything else
        // (security.*, trusted.*, system.*) reports unsupported, matching
        // what an unprivileged guest typically sees and keeping the host's
        // own attribute namespaces out of the picture.
        if !name.starts_with("user.") {
            return Err(crate::linux_abi::LINUX_ENOTSUP);
        }
        // Hide carrick's internal mode xattr: a guest must not be able to read
        // or clobber it (it lives in user.* only for Linux validity).
        if name == CARRICK_MODE_XATTR_NAME {
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
        if !name.starts_with("user.") || name == CARRICK_MODE_XATTR_NAME {
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
        let host_fd = self
            .open_raw_fd(path, false, false, false)
            .ok_or(crate::linux_abi::LINUX_ENODATA)?;
        // macOS may surface its own attribute names (e.g. resource forks);
        // we read the full NUL-separated list then filter to `user.*` so the
        // result is exactly the Linux-conformant namespace the guest set.
        let needed = unsafe { libc::flistxattr(host_fd, std::ptr::null_mut(), 0, 0) };
        let needed = match needed.host_syscall_errno() {
            Ok(needed) => needed,
            Err(err) => {
                unsafe { libc::close(host_fd) };
                return Err(err);
            }
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
        unsafe { libc::close(host_fd) };
        let n = n.host_syscall_errno()?;
        buf.truncate(n as usize);
        let names = buf
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .filter_map(|s| std::str::from_utf8(s).ok())
            .filter(|s| s.starts_with("user.") && *s != CARRICK_MODE_XATTR_NAME)
            .map(|s| s.to_owned())
            .collect();
        Ok(names)
    }

    fn real_stat(&self, path: &str, follow: bool) -> Option<RealStat> {
        use cap_std::fs::MetadataExt;
        let mut normalized = normalize(path)?;
        // lstat (`follow == false`) reports the link itself; stat
        // (`follow == true`) reports the target. We follow symlinks
        // MANUALLY rather than via cap-std's `metadata`, because cap-std
        // refuses to traverse an ABSOLUTE symlink target (it treats it as
        // a sandbox escape). Resolving by hand lets an absolute target
        // like `/tmp/dd` be interpreted relative to the guest root.
        let meta = if follow {
            let mut hops = 0u32;
            loop {
                let rel = Self::rel_path(&normalized)?;
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
                normalized = if target.is_absolute() {
                    // Absolute target → relative to the guest root.
                    normalize(&target.to_string_lossy())?
                } else {
                    // Relative target → relative to the link's parent dir.
                    let parent = normalized.parent().unwrap_or_else(|| Path::new(""));
                    normalize(&parent.join(&target).to_string_lossy())?
                };
            }
        } else {
            let rel = Self::rel_path(&normalized)?;
            self.dir.symlink_metadata(rel).ok()?
        };
        let kind = if meta.is_dir() {
            RootFsEntryKind::Directory
        } else if meta.is_symlink() {
            RootFsEntryKind::Symlink
        } else {
            RootFsEntryKind::File
        };
        let mode = meta.mode() & 0o7777;
        let default_mode = match kind {
            RootFsEntryKind::Directory => 0o755,
            RootFsEntryKind::Symlink => 0o777,
            RootFsEntryKind::File | RootFsEntryKind::CharDevice => 0o644,
        };
        // The real file's mode was forced owner-accessible; the guest-visible
        // mode lives in an xattr on the (symlink-resolved) target. Symlinks
        // always report 0777, so skip the link-following xattr read for them.
        let (override_mode, owner) = if matches!(kind, RootFsEntryKind::Symlink) {
            (None, (None, None))
        } else {
            match Self::rel_path(&normalized) {
                Some(rel) => {
                    let is_dir = matches!(kind, RootFsEntryKind::Directory);
                    (
                        read_mode_xattr(&self.dir, rel, is_dir),
                        read_owner_xattr(&self.dir, rel, is_dir),
                    )
                }
                None => (None, (None, None)),
            }
        };
        Some(RealStat {
            kind,
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
            // CharDevice never appears in the writable overlay (it only comes
            // from the /dev VFS mounts), but the match must be exhaustive.
            RootFsEntryKind::File | RootFsEntryKind::CharDevice => {
                let size = overlay.file_contents(&path).map(|b| b.len()).unwrap_or(0);
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
        };
        seen.insert(name.clone());
        out.push(RootFsDirEntry { name, metadata });
    }
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
        let (mut b, _scratch) = host_backend();
        let fd = b.open_raw_fd("/g", true, true, true).expect("open_raw_fd");
        b.set_mode("/g", 0o041).unwrap();
        assert_eq!(fget_mode_xattr(fd), Some(0o041), "fstat-side xattr read");
        unsafe { libc::close(fd) };
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_set_mode_roundtrips_via_xattr_even_when_inaccessible() {
        let (mut b, _scratch) = host_backend();
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
        let mut b = HostFsBackend::from_existing_dir(dir);
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
        let (mut b, scratch) = host_backend();
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
