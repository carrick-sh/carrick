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
}

/// Trait every writable-layer backend implements. Methods are layer-
/// aware (see module docs); the dispatcher does its own overlay-first
/// merging with the read-only rootfs underneath.
pub trait FsBackend: Send {
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
    fn make_dir(&mut self, path: &str) -> Result<(), BackendError>;

    /// Materialise an empty file at `path`. Used by `openat(..., O_CREAT)`
    /// when the file did not previously exist.
    fn create_file(&mut self, path: &str) -> Result<(), BackendError>;

    /// Replace the contents of `path`. Used by write/writev/pwrite/
    /// ftruncate writeback and by rename-into-overlay.
    fn set_file_contents(&mut self, path: &str, contents: Vec<u8>)
        -> Result<(), BackendError>;

    /// Drop the backend's entry for `path` entirely. Returns true iff
    /// the backend was holding something there. Does NOT tombstone —
    /// caller pairs this with `mark_deleted` when the path also lives
    /// in the rootfs.
    fn remove_entry(&mut self, path: &str) -> bool;

    /// Tombstone `path` so that subsequent layered lookups treat it as
    /// absent, even if the rootfs still has it underneath.
    fn mark_deleted(&mut self, path: &str) -> Result<(), BackendError>;

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
    fn rename_overlay_entry(
        &mut self,
        from: &str,
        to: &str,
    ) -> Result<bool, BackendError>;

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
pub struct MemoryBackend {
    dirs: HashSet<PathBuf>,
    files: HashMap<PathBuf, Vec<u8>>,
    deletions: HashSet<PathBuf>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl FsBackend for MemoryBackend {
    fn lookup(&self, path: &str) -> Option<OverlayEntry> {
        let normalized = normalize(path)?;
        if self.deletions.contains(&normalized) {
            return Some(OverlayEntry::Deleted);
        }
        if self.dirs.contains(&normalized) {
            return Some(OverlayEntry::Dir);
        }
        if let Some(bytes) = self.files.get(&normalized) {
            return Some(OverlayEntry::File(bytes.clone()));
        }
        None
    }

    fn lookup_kind(&self, path: &str) -> Option<OverlayEntryKind> {
        let normalized = normalize(path)?;
        if self.deletions.contains(&normalized) {
            return Some(OverlayEntryKind::Deleted);
        }
        if self.dirs.contains(&normalized) {
            return Some(OverlayEntryKind::Dir);
        }
        if self.files.contains_key(&normalized) {
            return Some(OverlayEntryKind::File);
        }
        None
    }

    fn metadata(&self, path: &str) -> Option<RootFsMetadata> {
        let normalized = normalize(path)?;
        if let Some(contents) = self.files.get(&normalized) {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::File,
                mode: 0o644,
                size: contents.len(),
            });
        }
        if self.dirs.contains(&normalized) {
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
        self.files.get(&normalized).cloned()
    }

    fn make_dir(&mut self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        self.deletions.remove(&normalized);
        self.dirs.insert(normalized);
        Ok(())
    }

    fn create_file(&mut self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        self.deletions.remove(&normalized);
        self.files.entry(normalized).or_insert_with(Vec::new);
        Ok(())
    }

    fn set_file_contents(
        &mut self,
        path: &str,
        contents: Vec<u8>,
    ) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        self.deletions.remove(&normalized);
        self.files.insert(normalized, contents);
        Ok(())
    }

    fn remove_entry(&mut self, path: &str) -> bool {
        let Some(normalized) = normalize(path) else {
            return false;
        };
        let had_file = self.files.remove(&normalized).is_some();
        let had_dir = self.dirs.remove(&normalized);
        had_file || had_dir
    }

    fn mark_deleted(&mut self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        self.files.remove(&normalized);
        self.dirs.remove(&normalized);
        self.deletions.insert(normalized);
        Ok(())
    }

    fn child_names(&self, dir: &str) -> Vec<(String, RootFsEntryKind)> {
        let Some(prefix) = normalize(dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for path in self.files.keys() {
            if let Some(name) = child_name(&prefix, path) {
                out.push((name, RootFsEntryKind::File));
            }
        }
        for path in self.dirs.iter() {
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
        self.deletions
            .iter()
            .filter_map(|path| child_name(&prefix, path))
            .collect()
    }

    fn rename_overlay_entry(
        &mut self,
        from: &str,
        to: &str,
    ) -> Result<bool, BackendError> {
        let src = normalize(from).ok_or(BackendError::Invalid)?;
        let dst = normalize(to).ok_or(BackendError::Invalid)?;
        if let Some(contents) = self.files.remove(&src) {
            self.deletions.remove(&dst);
            self.files.insert(dst.clone(), contents);
            self.deletions.insert(src);
            return Ok(true);
        }
        if self.dirs.remove(&src) {
            self.deletions.remove(&dst);
            self.dirs.insert(dst);
            self.deletions.insert(src);
            return Ok(true);
        }
        Ok(false)
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
/// We *also* keep a small in-memory bookkeeping table mirroring the
/// in-memory backend:
///
///   * `dirs_created`: directories the guest created via mkdirat. Used
///     so `lookup` can tell "guest-created dir" from "happens to exist
///     in the scratch root from a prior reflink seed".
///   * `tombstones`: paths the guest deleted that still exist in the
///     read-only rootfs underneath. The dispatcher's layered lookup
///     consults this just like for the memory backend.
///
/// Plain file mutations land directly in the scratch tree (cap-std
/// `dir.create`/`dir.open_with` + std `Write`). Reads go back through
/// the same handle.
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
    dirs_created: HashSet<PathBuf>,
    tombstones: HashSet<PathBuf>,
    /// Paths the backend "knows about" — i.e. anything ever created,
    /// touched or recorded. Used by `lookup` so we can tell whether a
    /// scratch-disk file came from the guest (overlay-owned) vs from
    /// a leftover reflink seed we should ignore here.
    known_files: HashSet<PathBuf>,
}

impl std::fmt::Debug for HostFsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostFsBackend")
            .field("dirs_created", &self.dirs_created.len())
            .field("tombstones", &self.tombstones.len())
            .field("known_files", &self.known_files.len())
            .finish()
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
        let dir = cap_std::fs::Dir::open_ambient_dir(
            scratch.path(),
            cap_std::ambient_authority(),
        )?;
        Ok(Self {
            dir,
            _scratch: Some(scratch),
            _lock: Some(lock),
            dirs_created: HashSet::new(),
            tombstones: HashSet::new(),
            known_files: HashSet::new(),
        })
    }

    /// Construct against an already-allocated scratch dir without
    /// taking ownership of its lifetime. Used by tests.
    pub fn from_existing_dir(dir: cap_std::fs::Dir) -> Self {
        Self {
            dir,
            _scratch: None,
            _lock: None,
            dirs_created: HashSet::new(),
            tombstones: HashSet::new(),
            known_files: HashSet::new(),
        }
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
}

impl FsBackend for HostFsBackend {
    fn lookup(&self, path: &str) -> Option<OverlayEntry> {
        let normalized = normalize(path)?;
        if self.tombstones.contains(&normalized) {
            return Some(OverlayEntry::Deleted);
        }
        let rel = Self::rel_path(&normalized)?;
        let meta = self.dir.symlink_metadata(rel).ok()?;
        if meta.is_dir() {
            // Only report as overlay-owned if the guest created it.
            if self.dirs_created.contains(&normalized) {
                return Some(OverlayEntry::Dir);
            }
            return None;
        }
        if meta.is_file() {
            if self.known_files.contains(&normalized) {
                let mut buf = Vec::with_capacity(meta.len() as usize);
                let mut file = self.dir.open(rel).ok()?;
                file.read_to_end(&mut buf).ok()?;
                return Some(OverlayEntry::File(buf));
            }
        }
        None
    }

    fn lookup_kind(&self, path: &str) -> Option<OverlayEntryKind> {
        let normalized = normalize(path)?;
        if self.tombstones.contains(&normalized) {
            return Some(OverlayEntryKind::Deleted);
        }
        let rel = Self::rel_path(&normalized)?;
        let meta = self.dir.symlink_metadata(rel).ok()?;
        if meta.is_dir() && self.dirs_created.contains(&normalized) {
            return Some(OverlayEntryKind::Dir);
        }
        if meta.is_file() && self.known_files.contains(&normalized) {
            return Some(OverlayEntryKind::File);
        }
        None
    }

    fn metadata(&self, path: &str) -> Option<RootFsMetadata> {
        let normalized = normalize(path)?;
        let rel = Self::rel_path(&normalized)?;
        let meta = self.dir.symlink_metadata(rel).ok()?;
        if meta.is_dir() && self.dirs_created.contains(&normalized) {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::Directory,
                mode: 0o755,
                size: 0,
            });
        }
        if meta.is_file() && self.known_files.contains(&normalized) {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::File,
                mode: 0o644,
                size: meta.len() as usize,
            });
        }
        None
    }

    fn file_contents(&self, path: &str) -> Option<Vec<u8>> {
        let normalized = normalize(path)?;
        if !self.known_files.contains(&normalized) {
            return None;
        }
        let rel = Self::rel_path(&normalized)?;
        let mut buf = Vec::new();
        let mut file = self.dir.open(rel).ok()?;
        file.read_to_end(&mut buf).ok()?;
        Some(buf)
    }

    fn make_dir(&mut self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        // Create all parent dirs in the scratch tree so the guest's
        // mkdir-deep paths "just work" (apt does
        // mkdir(/var/lib/apt/lists/partial) without checking parents).
        if let Some(parent) = rel.parent() {
            if !parent.as_os_str().is_empty() {
                self.dir
                    .create_dir_all(parent)
                    .map_err(|_| BackendError::Io)?;
            }
        }
        match self.dir.create_dir(rel) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(BackendError::Io),
        }
        self.tombstones.remove(&normalized);
        // Record every ancestor so /var, /var/lib, /var/lib/apt all
        // show up as overlay-dirs after a deep mkdir.
        let mut ancestor = PathBuf::new();
        for component in normalized.components() {
            ancestor.push(component);
            self.dirs_created.insert(ancestor.clone());
        }
        Ok(())
    }

    fn create_file(&mut self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        if let Some(parent) = rel.parent() {
            if !parent.as_os_str().is_empty() {
                self.dir
                    .create_dir_all(parent)
                    .map_err(|_| BackendError::Io)?;
            }
        }
        let mut opts = cap_std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(false);
        self.dir
            .open_with(rel, &opts)
            .map_err(|_| BackendError::Io)?;
        self.tombstones.remove(&normalized);
        self.known_files.insert(normalized);
        Ok(())
    }

    fn set_file_contents(
        &mut self,
        path: &str,
        contents: Vec<u8>,
    ) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        if let Some(parent) = rel.parent() {
            if !parent.as_os_str().is_empty() {
                self.dir
                    .create_dir_all(parent)
                    .map_err(|_| BackendError::Io)?;
            }
        }
        let mut opts = cap_std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        let mut file = self
            .dir
            .open_with(rel, &opts)
            .map_err(|_| BackendError::Io)?;
        file.seek(SeekFrom::Start(0)).map_err(|_| BackendError::Io)?;
        file.write_all(&contents).map_err(|_| BackendError::Io)?;
        self.tombstones.remove(&normalized);
        self.known_files.insert(normalized);
        Ok(())
    }

    fn remove_entry(&mut self, path: &str) -> bool {
        let Some(normalized) = normalize(path) else {
            return false;
        };
        let Some(rel) = Self::rel_path(&normalized) else {
            return false;
        };
        let mut removed = false;
        if self.known_files.remove(&normalized) {
            let _ = self.dir.remove_file(rel);
            removed = true;
        }
        if self.dirs_created.remove(&normalized) {
            let _ = self.dir.remove_dir(rel);
            removed = true;
        }
        removed
    }

    fn mark_deleted(&mut self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        // Also evict any in-scratch entry so the scratch tree matches
        // the tombstoned view.
        if let Some(rel) = Self::rel_path(&normalized) {
            let _ = self.dir.remove_file(rel);
            let _ = self.dir.remove_dir(rel);
        }
        self.known_files.remove(&normalized);
        self.dirs_created.remove(&normalized);
        self.tombstones.insert(normalized);
        Ok(())
    }

    fn child_names(&self, dir: &str) -> Vec<(String, RootFsEntryKind)> {
        let Some(prefix) = normalize(dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for path in self.known_files.iter() {
            if let Some(name) = child_name(&prefix, path) {
                out.push((name, RootFsEntryKind::File));
            }
        }
        for path in self.dirs_created.iter() {
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
        self.tombstones
            .iter()
            .filter_map(|path| child_name(&prefix, path))
            .collect()
    }

    fn rename_overlay_entry(
        &mut self,
        from: &str,
        to: &str,
    ) -> Result<bool, BackendError> {
        let src = normalize(from).ok_or(BackendError::Invalid)?;
        let dst = normalize(to).ok_or(BackendError::Invalid)?;
        let src_rel = Self::rel_path(&src).ok_or(BackendError::Invalid)?.to_path_buf();
        let dst_rel = Self::rel_path(&dst).ok_or(BackendError::Invalid)?.to_path_buf();
        if self.known_files.contains(&src) {
            if let Some(parent) = dst_rel.parent() {
                if !parent.as_os_str().is_empty() {
                    self.dir
                        .create_dir_all(parent)
                        .map_err(|_| BackendError::Io)?;
                }
            }
            self.dir
                .rename(&src_rel, &self.dir, &dst_rel)
                .map_err(|_| BackendError::Io)?;
            self.known_files.remove(&src);
            self.known_files.insert(dst.clone());
            self.tombstones.remove(&dst);
            self.tombstones.insert(src);
            return Ok(true);
        }
        if self.dirs_created.contains(&src) {
            if let Some(parent) = dst_rel.parent() {
                if !parent.as_os_str().is_empty() {
                    self.dir
                        .create_dir_all(parent)
                        .map_err(|_| BackendError::Io)?;
                }
            }
            self.dir
                .rename(&src_rel, &self.dir, &dst_rel)
                .map_err(|_| BackendError::Io)?;
            self.dirs_created.remove(&src);
            self.dirs_created.insert(dst.clone());
            self.tombstones.remove(&dst);
            self.tombstones.insert(src);
            return Ok(true);
        }
        Ok(false)
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
    let deleted: HashSet<String> = overlay
        .deleted_child_names(dir)
        .into_iter()
        .collect();

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
            RootFsEntryKind::File => {
                let size = overlay
                    .file_contents(&path)
                    .map(|b| b.len())
                    .unwrap_or(0);
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
        b.set_file_contents("/tmp/example", b"abcd".to_vec()).unwrap();
        let bytes = b.file_contents("/tmp/example").unwrap();
        assert_eq!(bytes, b"abcd");
    }

    fn scenario_unlink_hides_rootfs_path<B: FsBackend>(b: &mut B) {
        // Simulate a rootfs-backed path by tombstoning it; the
        // dispatcher does this in `unlinkat` for files that live in
        // the rootfs.
        b.mark_deleted("/etc/motd").unwrap();
        assert!(b.is_deleted("/etc/motd"));
        let entry = b.lookup("/etc/motd");
        assert!(matches!(entry, Some(OverlayEntry::Deleted)));
    }

    fn scenario_rename_overlay_file<B: FsBackend>(b: &mut B) {
        b.create_file("/tmp/src").unwrap();
        b.set_file_contents("/tmp/src", b"hello".to_vec()).unwrap();
        let moved = b.rename_overlay_entry("/tmp/src", "/tmp/dst").unwrap();
        assert!(moved);
        assert_eq!(
            b.file_contents("/tmp/dst").as_deref(),
            Some(&b"hello"[..])
        );
        // Source is tombstoned now.
        assert!(b.is_deleted("/tmp/src"));
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
        let dir = cap_std::fs::Dir::open_ambient_dir(
            scratch.path(),
            cap_std::ambient_authority(),
        )
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
        let dir = cap_std::fs::Dir::open_ambient_dir(
            &scratch,
            cap_std::ambient_authority(),
        )
        .unwrap();
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
        std::os::unix::fs::symlink(outer.path().join("victim"), scratch.join("escape"))
            .unwrap();
        let result = b.set_file_contents("/escape", b"pwned".to_vec());
        assert!(
            result.is_err(),
            "host backend must reject writes through a symlink that escapes the sandbox"
        );
        // The victim file must be untouched.
        assert_eq!(std::fs::read(&victim).unwrap(), b"secret");
    }
}
