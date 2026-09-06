//! OCI rootfs composition: merging container image layers into a single
//! filesystem view.
//!
//! # Theory of operation
//!
//! A container image is an *ordered stack* of tar layers. The bottom layer is
//! the base; each layer above adds, replaces, or deletes entries from the
//! layers below it. Composing them into one coherent tree is the same job an
//! overlay filesystem does at mount time — except carrick has no Linux kernel
//! and no `overlayfs`, so this module does the merge itself, in userspace,
//! at guest setup. The output is the immutable lower layer the VFS serves `/`
//! from (with a writable overlay stacked on top by `fs_backend`; see
//! [`crate::vfs::RootFsVfs`]).
//!
//! ## The merge rules (OCI whiteout conventions)
//!
//! Layers are applied first-to-last. Within each layer:
//!
//! * A regular entry (file / dir / symlink / hardlink) is materialised at its
//!   path, **replacing** whatever a lower layer put there.
//! * A `.wh.<name>` entry is a *whiteout*: it deletes `<name>` (and, if it was
//!   a directory, its whole subtree) from the accumulated lower layers. The
//!   whiteout marker itself never appears in the result.
//! * A `.wh..wh..opq` entry is an *opaque whiteout*: it hides *all* lower-layer
//!   contents of its parent directory, so only entries from this layer and
//!   above show through. Implemented by clearing the directory and recreating
//!   it empty.
//!
//! `WHITEOUT_PREFIX` / `OPAQUE_WHITEOUT` name these markers. Both the in-memory
//! and the on-disk paths apply the *same* rules; the on-disk path's whiteout
//! handling is written to replicate `RootFs::apply_layer` exactly.
//!
//! ## Two materialisation strategies
//!
//! There are two ways carrick turns a layer stack into a usable rootfs, and
//! they exist because the project moved between two backends:
//!
//! 1. **In-memory** ([`RootFs::from_layers`] / `apply_layer`). The merge result
//!    lives in three maps — `files`, `directories`, `symlinks` — keyed by
//!    *root-relative* normalised paths. File contents are buffered in
//!    `Vec<u8>`. Nothing touches the host filesystem; lookups
//!    ([`RootFs::read`], [`RootFs::metadata`], [`RootFs::list_dir`]) are served
//!    straight out of the maps. This backs `--fs memory`.
//! 2. **Streaming-to-disk** ([`extract_layer_paths_to_dir`] / `apply_tar_to_dir`,
//!    plus [`RootFs::extract_to_dir`] for an
//!    already-merged in-memory tree). Layer blobs are streamed
//!    (`std::io::copy`, never the whole file buffered) into a real
//!    scratch directory on disk, applying the same
//!    overlay+whiteout semantics as they land. This backs `--fs host`, where
//!    apt's downstream operations (`symlinkat`, atomic `rename`, the `gpgv`
//!    subprocess, hardlink-heavy dpkg unpacks, …) need real kernel filesystem
//!    semantics rather than bespoke overlay logic.
//!
//! ## Path safety is load-bearing
//!
//! Layer tarballs are untrusted input. Every path is run through
//! `normalize_path`, which collapses `.`/`..`, rejects any `..` that would
//! escape the root, and rejects Windows-style prefixes. Symlink *targets* are
//! normalised relative to the link's own directory and likewise rejected if
//! they escape root (`normalize_symlink_target`). Without this a malicious
//! image could write outside the rootfs (`../../etc/...`) or point a symlink at
//! the host's real `/etc/passwd`. The unit tests at the bottom of this file are
//! the executable spec for these escape cases.
//!
//! ## Symlink resolution walks every component
//!
//! `RootFs::resolve_symlink` resolves symlinks along **every** path component,
//! not just the leaf. Debian's usrmerge makes `/lib` itself a symlink
//! (`/lib -> usr/lib`), so the dynamic linker's request for
//! `/lib/ld-linux-aarch64.so.1` only succeeds if the *parent* component is
//! followed before the final lookup. Recursion is capped at 40 (Linux's
//! `SYMLOOP_MAX`) to bound pathological chains.
//!
//! ## Mode-preservation invariant (on-disk path)
//!
//! carrick is a non-root macOS process serving its own scratch. An image entry
//! the *owner* cannot read/search (a file with no owner-read bit, a directory
//! without owner `r-x`) would lock carrick out of serving it. So the on-disk
//! materialiser stores the *true* image mode in the `user.carrick.mode` xattr
//! (via `fs_backend`) and forces the minimum owner bits on the real node; the
//! VFS's `real_stat` reports the xattr mode back to the guest, so the guest
//! still sees the image's permissions. Special nodes the tar may carry
//! (char/block/fifo) are skipped on the on-disk path and accounted in
//! [`ExtractStats::skipped_special`].

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use flate2::read::GzDecoder;
use serde::Serialize;
use thiserror::Error;

use crate::fs_backend::{FsBackend, HostFsBackend, ImmutableHostFileOpen, RealStat};

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerSource {
    Tar(Vec<u8>),
    TarGz(Vec<u8>),
}

#[derive(Debug, Clone, Serialize)]
pub struct RootFs {
    files: HashMap<PathBuf, FileEntry>,
    directories: HashSet<PathBuf>,
    symlinks: HashMap<PathBuf, SymlinkEntry>,
    /// Optional immutable on-disk lower. Skipped from the historical summary
    /// serialization: native reexec carries the explicit identity-checked
    /// authority below, never a lossy serialized `RootFs` snapshot.
    #[serde(skip)]
    immutable_host: Option<ImmutableHostRoot>,
}

/// Lower-layer lookup memo keyed by `(path, follow)`; `None` records that
/// the lower has no such path.
type LowerDcache = HashMap<(PathBuf, bool), Option<LowerEntry>>;

#[derive(Debug, Clone)]
struct ImmutableHostRoot {
    backend: Arc<HostFsBackend>,
    /// The lower's dcache: every `(path, follow)` the layered view has ever
    /// asked this lower about, positive AND negative, answered once.
    ///
    /// The published cache entry is never mutated for the lifetime of the
    /// container, so an entry here never goes stale and needs no generation
    /// stamp — this is the one place in the fs where a negative lookup can
    /// be memoised outright. Without it every `unlink`/`creat` of an
    /// upper-only file paid a host `openat`+`fstat`+`close` of the lower to
    /// re-learn that the lower has no such path, which was one third of the
    /// host opens per guest `unlink` of a freshly created file. Bounded by
    /// [`LOWER_DCACHE_MAX_ENTRIES`]; on overflow the whole map is dropped
    /// rather than evicted, since a refill is one lookup each.
    dcache: Arc<parking_lot::Mutex<LowerDcache>>,
    /// Per-directory child listings of the lower, filled ADAPTIVELY: a
    /// directory is listed once it has answered "absent" twice, because a
    /// second miss in the same directory is the signature of a workload
    /// creating its own files there (a build tree, `/tmp`), where every
    /// further creat/unlink would otherwise pay a host probe of the lower per
    /// name. A single miss never lists, so a positive-heavy walk of the image
    /// (`find /usr`) keeps its one-stat-per-path cost instead of paying a
    /// directory read per directory it touches. Membership is byte-exact,
    /// which is both Linux's rule and the host's own (the lower lives on a
    /// case-sensitive volume, [`crate::apfs`] refuses `--fs host` otherwise).
    listings: Arc<parking_lot::Mutex<HashMap<PathBuf, LowerListing>>>,
}

/// What the lower knows about one directory's children.
#[derive(Debug, Clone)]
enum LowerListing {
    /// Probed `misses` absent names here so far; not yet worth a listing.
    Misses(u8),
    /// The complete, immutable child-name set: absence is answered from it.
    Names(Arc<HashSet<std::ffi::OsString>>),
    /// Not a plain directory of the lower (a symlink, a file, unreadable):
    /// every lookup under it keeps taking the exact per-path probe.
    Opaque,
    /// The directory itself is absent from the lower, so is everything
    /// beneath it — an upper-only tree (the guest's own `mkdir /tmp/x`),
    /// where every fresh name would otherwise re-walk the lower per lookup.
    Absent,
}

/// Second miss in one directory ⇒ list it (see [`ImmutableHostRoot::listings`]).
const LOWER_LISTING_MISS_THRESHOLD: u8 = 2;

/// Cap on [`ImmutableHostRoot::dcache`] — generous for a build tree, small
/// against the extraction it describes.
const LOWER_DCACHE_MAX_ENTRIES: usize = 1 << 16;

/// The immutable facts [`host_metadata`] reports about one lower entry:
/// exactly the [`RootFsMetadata`] fields, minus the path the key carries.
#[derive(Debug, Clone, Copy)]
struct LowerEntry {
    kind: RootFsEntryKind,
    mode: u32,
    size: usize,
}

impl PartialEq for RootFs {
    fn eq(&self, other: &Self) -> bool {
        self.files == other.files
            && self.directories == other.directories
            && self.symlinks == other.symlinks
            && match (&self.immutable_host, &other.immutable_host) {
                (Some(a), Some(b)) => Arc::ptr_eq(&a.backend, &b.backend),
                (None, None) => true,
                _ => false,
            }
    }
}

impl Eq for RootFs {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub mode: u32,
    pub size: usize,
    #[serde(skip)]
    contents: Arc<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SymlinkEntry {
    path: PathBuf,
    target: PathBuf,
    target_text: String,
}

impl FileEntry {
    pub fn contents(&self) -> &[u8] {
        self.contents.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootFsSummary {
    pub file_count: usize,
    pub directory_count: usize,
    pub symlink_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootFsEntryKind {
    File,
    Directory,
    Symlink,
    /// Character device (e.g. the `/dev/*` and `/dev/pts/N` nodes served by the
    /// VFS mounts). Reports `S_IFCHR` from stat and `DT_CHR` from getdents.
    CharDevice,
    /// Named pipe (FIFO), created via `mknod`/`mkfifo`. On `--fs host` it is a
    /// real `mkfifoat(2)` node on the cap-std scratch; stat reports `S_IFIFO`
    /// and getdents `DT_FIFO`. Opened as a non-blocking `HostPipe` so a guest
    /// open/read/write of a writer-less FIFO parks on kqueue instead of wedging
    /// the dispatcher (see `open_at_path`).
    Fifo,
    /// AF_UNIX socket node, materialised at the guest path by a successful
    /// `bind(2)` of a pathname `AF_UNIX` socket. macOS can't `mknod(S_IFSOCK)`
    /// as non-root and the real host socket lives at a hashed scratch path, so
    /// the guest-facing node is a marker entry (host backend: a regular file
    /// flagged via the `user.carrick.socket` xattr → fork-coherent; in-memory
    /// backend: a `sockets` map). Reports `S_IFSOCK` from stat and `DT_SOCK`
    /// from getdents so `os.path.exists`/`stat.S_ISSOCK`/`chmod`/`unlink` on the
    /// bound path match Linux (multiprocessing forkserver).
    Socket,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootFsMetadata {
    pub path: PathBuf,
    pub kind: RootFsEntryKind,
    pub mode: u32,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootFsDirEntry {
    pub name: String,
    pub metadata: RootFsMetadata,
    /// Real host inode for this entry, so getdents64's `d_ino` matches a later
    /// `stat()` (CPython scandir DirEntry.inode() == os.stat().st_ino). 0 means
    /// unknown (in-memory/synthetic entries) → getdents64 falls back to a
    /// path-derived synthetic ino.
    pub ino: u64,
}

#[derive(Debug, Error)]
pub enum RootFsError {
    #[error("failed to decode OCI layer: {0}")]
    Io(#[from] std::io::Error),
    #[error("layer contains a path outside the rootfs: {0}")]
    UnsafePath(String),
    #[error("rootfs path does not exist: {0}")]
    NotFound(String),
    #[error("rootfs path is not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("too many symlinks while resolving rootfs path: {0}")]
    TooManySymlinks(String),
    #[error("rootfs directory exceeds the caller's entry bound: {0}")]
    DirectoryTooLarge(String),
}

/// Statistics returned by [`extract_layer_paths_to_dir`].
#[derive(Debug, Clone, Default)]
pub struct ExtractStats {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub skipped_special: u64,
    /// Entries whose tar mode was owner-unreadable and therefore had to be
    /// preserved in a `user.carrick.mode` xattr (rare). Non-zero means the
    /// backend must stamp its metadata-xattr root marker so the fast stat
    /// lanes keep probing per entry.
    pub mode_xattrs: u64,
}

/// Stream OCI layer blobs (gzip or raw tar) directly into `dir`, applying
/// overlay + whiteout semantics. Never materializes the file tree in memory.
///
/// Layers are applied in order (first to last). Each layer can add, replace,
/// or delete entries from prior layers using standard OCI whiteout conventions.
pub fn extract_layer_paths_to_dir(
    paths: &[PathBuf],
    dest: &Path,
) -> Result<ExtractStats, RootFsError> {
    let mut stats = ExtractStats::default();
    for path in paths {
        let file = fs::File::open(path)?;
        let mut buf = BufReader::new(file);
        // Sniff first 2 bytes for gzip magic without consuming the stream.
        let magic = buf.fill_buf()?;
        let is_gz = magic.len() >= 2 && magic[0] == 0x1f && magic[1] == 0x8b;
        if is_gz {
            let decoder = GzDecoder::new(buf);
            let mut archive = tar::Archive::new(decoder);
            apply_tar_to_dir(&mut archive, dest, &mut stats)?;
        } else {
            let mut archive = tar::Archive::new(buf);
            apply_tar_to_dir(&mut archive, dest, &mut stats)?;
        }
    }
    Ok(stats)
}

fn apply_tar_to_dir<R: Read>(
    archive: &mut tar::Archive<R>,
    dest: &Path,
    stats: &mut ExtractStats,
) -> Result<(), RootFsError> {
    use std::io::ErrorKind;
    use std::os::unix::fs::PermissionsExt as _;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.into_owned();
        let path = normalize_layer_path(&raw_path)?;
        if path.as_os_str().is_empty() {
            // A layer entry for the rootfs root itself (`/` or `./`) — nothing
            // to create; the root already exists. (kaniko emits such an entry.)
            continue;
        }

        // Whiteout detection — replicates apply_layer exactly.
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            if file_name == OPAQUE_WHITEOUT {
                // Opaque whiteout: clear the parent directory then recreate it.
                if let Some(parent) = path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    let parent_abs = dest.join(parent);
                    match std::fs::remove_dir_all(&parent_abs) {
                        Ok(()) | Err(_) => {}
                    }
                    std::fs::create_dir_all(&parent_abs)?;
                }
                continue;
            }

            if let Some(hidden_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
                if let Some(parent) = path.parent() {
                    let target = if parent.as_os_str().is_empty() {
                        PathBuf::from(hidden_name)
                    } else {
                        parent.join(hidden_name)
                    };
                    let target_abs = dest.join(&target);
                    // Try removing as a file first, then as a directory tree.
                    match std::fs::remove_file(&target_abs) {
                        Ok(()) => {}
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(_) => match std::fs::remove_dir_all(&target_abs) {
                            Ok(()) | Err(_) => {}
                        },
                    }
                }
                continue;
            }
        }

        let entry_type = entry.header().entry_type();
        let mode = entry.header().mode().unwrap_or(0o644);

        // Ensure parent directory exists for all non-root entries.
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dest.join(parent))?;
        }

        let dest_path = dest.join(&path);
        if entry_type.is_dir() {
            std::fs::create_dir_all(&dest_path)?;
            // A directory the owner can't read+search (r-x) would lock carrick
            // (a non-root macOS process) out of its own scratch. Preserve the
            // true mode in the carrick xattr and force owner r-x on the real
            // dir; otherwise apply the image mode directly. (See HostFsBackend
            // / CARRICK_MODE_XATTR.)
            if mode & 0o500 != 0o500 {
                let _ = std::fs::set_permissions(
                    &dest_path,
                    std::fs::Permissions::from_mode(mode | 0o700),
                );
                crate::fs_backend::write_mode_xattr(dest, &path, true, mode);
                stats.mode_xattrs += 1;
            } else {
                let _ = std::fs::set_permissions(&dest_path, std::fs::Permissions::from_mode(mode));
            }
            stats.dirs += 1;
        } else if entry_type.is_symlink() {
            let link_name = entry
                .link_name()?
                .ok_or_else(|| RootFsError::UnsafePath(path.display().to_string()))?
                .into_owned();
            // Remove any existing entry at path before creating the symlink.
            let _ = std::fs::remove_file(&dest_path);
            let _ = std::fs::remove_dir_all(&dest_path);
            // Store the raw link target verbatim (Linux symlinkat(2) semantics).
            std::os::unix::fs::symlink(link_name, &dest_path)?;
            stats.symlinks += 1;
        } else if entry_type.is_file() {
            // Streaming copy — never buffers the whole file.
            let mut f = std::fs::File::create(&dest_path)?;
            std::io::copy(&mut entry, &mut f)?;
            drop(f);
            // A file the owner can't read would lock carrick (non-root) out of
            // serving its content. Preserve the true mode in the carrick xattr
            // and force owner rw on the real file; otherwise apply the image
            // mode directly (real_stat reports it faithfully).
            if mode & 0o400 == 0 {
                let _ = std::fs::set_permissions(
                    &dest_path,
                    std::fs::Permissions::from_mode(mode | 0o600),
                );
                crate::fs_backend::write_mode_xattr(dest, &path, false, mode);
                stats.mode_xattrs += 1;
            } else {
                let _ = std::fs::set_permissions(&dest_path, std::fs::Permissions::from_mode(mode));
            }
            stats.files += 1;
        } else if entry_type.is_hard_link() {
            let link_name = entry
                .link_name()?
                .ok_or_else(|| RootFsError::UnsafePath(path.display().to_string()))?
                .into_owned();
            let target = normalize_layer_path(&link_name)?;
            if target == path {
                return Err(RootFsError::UnsafePath(path.display().to_string()));
            }
            // A new-layer hardlink replaces the path from lower layers. Remove
            // that destination before linking: falling back to `create(path)`
            // while it is already a hardlink to `target` truncates BOTH names.
            match std::fs::remove_file(&dest_path) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(_) => match std::fs::remove_dir_all(&dest_path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                },
            }
            let target_abs = dest.join(&target);
            match std::fs::hard_link(&target_abs, &dest_path) {
                Ok(()) => {}
                Err(_) => {
                    // Fall back to copying target's bytes if hard_link fails.
                    let mut src = std::fs::File::open(&target_abs)?;
                    let mut dst = std::fs::File::create(&dest_path)?;
                    std::io::copy(&mut src, &mut dst)?;
                }
            }
            stats.files += 1;
        } else {
            // char/block/fifo/other special — skip.
            stats.skipped_special += 1;
        }
    }
    Ok(())
}

impl RootFs {
    pub fn from_layers<I>(layers: I) -> Result<Self, RootFsError>
    where
        I: IntoIterator<Item = LayerSource>,
    {
        let mut rootfs = Self {
            files: HashMap::new(),
            directories: HashSet::from([PathBuf::new()]),
            symlinks: HashMap::new(),
            immutable_host: None,
        };

        for layer in layers {
            rootfs.apply_layer(layer)?;
        }

        Ok(rootfs)
    }

    pub fn from_layer_paths<I, P>(paths: I) -> Result<Self, RootFsError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let layers = paths
            .into_iter()
            .map(|path| LayerSource::from_path(path.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_layers(layers)
    }

    /// Bind an already-published cache directory as the immutable lower.
    /// Reads are capability-rooted through [`HostFsBackend`], while this type
    /// deliberately exposes no mutation methods for the lower.
    pub(crate) fn from_immutable_host_dir(path: &Path) -> Result<Self, RootFsError> {
        let backend = HostFsBackend::attach(path)?;
        // The cache entry root carries no metadata-xattr root marker (the
        // extraction wrote per-entry xattrs directly); its CLEAN sentinel file
        // is the only proof that none exist. Absent sentinel = assume xattrs,
        // so the lower's stat lanes keep probing per entry.
        if !path.join(crate::layer_cache::CLEAN_META_MARKER).exists() {
            backend.assume_meta_xattrs();
        }
        let authority = backend.native_reexec_authority()?;
        if authority.cleanup_on_drop {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "immutable host lower unexpectedly owns cleanup",
            )
            .into());
        }
        Ok(Self {
            files: HashMap::new(),
            directories: HashSet::new(),
            symlinks: HashMap::new(),
            immutable_host: Some(ImmutableHostRoot {
                backend: Arc::new(backend),
                dcache: Arc::new(parking_lot::Mutex::new(HashMap::new())),
                listings: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            }),
        })
    }

    pub fn summary(&self) -> RootFsSummary {
        if let Some(host) = self.immutable_host.as_ref() {
            let mut summary = RootFsSummary {
                file_count: 0,
                directory_count: 1,
                symlink_count: 0,
            };
            let mut pending = vec![String::from("/")];
            while let Some(dir) = pending.pop() {
                for (name, kind, _) in host.backend.child_names(&dir) {
                    let path = if dir == "/" {
                        format!("/{name}")
                    } else {
                        format!("{dir}/{name}")
                    };
                    match kind {
                        RootFsEntryKind::Directory => {
                            summary.directory_count += 1;
                            pending.push(path);
                        }
                        RootFsEntryKind::Symlink => summary.symlink_count += 1,
                        _ => summary.file_count += 1,
                    }
                }
            }
            return summary;
        }
        RootFsSummary {
            file_count: self.files.len(),
            directory_count: self.directories.len(),
            symlink_count: self.symlinks.len(),
        }
    }

    /// Materialise the in-memory rootfs onto a real on-disk directory.
    /// This is what gets carrick out of "overlay on top of read-only
    /// in-memory tar" and onto "real filesystem owns everything" — the
    /// architectural shift the project moved to when apt's downstream
    /// fs ops (symlinkat, atomic rename, gpgv subprocess, ...) needed
    /// real kernel semantics instead of bespoke overlay logic.
    ///
    /// Directories are created first (sorted by depth so parents land before
    /// children), then regular files, then symlinks. The destination dir must
    /// exist and be empty (caller's job). This is the capability-rooted
    /// materializer used by HostFsBackend so rootfs seeding stays inside the
    /// already-open scratch dir.
    pub fn extract_to_dir(&self, dest: &Path) -> Result<(), RootFsError> {
        use std::os::unix::fs::PermissionsExt as _;

        // Directories: process shallowest first.
        let mut dirs: Vec<&PathBuf> = self.directories.iter().collect();
        dirs.sort_by_key(|p| p.components().count());
        for d in dirs {
            std::fs::create_dir_all(dest.join(d))?;
        }
        // Files.
        for (path, entry) in &self.files {
            let dest_path = dest.join(path);
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = std::fs::File::create(&dest_path)?;
            file.write_all(entry.contents.as_ref())?;
            drop(file);
            let _ =
                std::fs::set_permissions(&dest_path, std::fs::Permissions::from_mode(entry.mode));
        }
        // Symlinks last (target paths might point at files we just wrote).
        for (link_path, entry) in &self.symlinks {
            let dest_path = dest.join(link_path);
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // If the link path already exists (e.g. parent created it as a dir),
            // remove first.
            let _ = std::fs::remove_file(&dest_path);
            let _ = std::fs::remove_dir_all(&dest_path);
            std::os::unix::fs::symlink(&entry.target_text, &dest_path)?;
        }
        Ok(())
    }

    /// Path-based extraction.
    pub fn extract_to_disk(&self, dest: &Path) -> Result<(), RootFsError> {
        self.extract_to_dir(dest)
    }

    /// Every path the rootfs holds, regardless of kind. Used by
    /// HostFsBackend's seed step to register the materialised view so
    /// dispatcher lookups stop falling through to the in-memory RootFs.
    pub fn all_paths(&self) -> Vec<PathBuf> {
        let mut out =
            Vec::with_capacity(self.files.len() + self.directories.len() + self.symlinks.len());
        out.extend(self.files.keys().cloned());
        out.extend(self.directories.iter().cloned());
        out.extend(self.symlinks.keys().cloned());
        out
    }

    pub fn read(&self, path: impl AsRef<Path>) -> Result<Vec<u8>, RootFsError> {
        if let Some(host) = self.immutable_host.as_ref() {
            return host
                .backend
                .file_contents(path.as_ref().to_string_lossy().as_ref())
                .ok_or_else(|| RootFsError::NotFound(display_rootfs_path(path.as_ref())));
        }
        Ok(self.read_shared(path)?.as_ref().to_vec())
    }

    pub fn read_shared(&self, path: impl AsRef<Path>) -> Result<Arc<[u8]>, RootFsError> {
        if let Some(host) = self.immutable_host.as_ref() {
            return host
                .backend
                .file_contents(path.as_ref().to_string_lossy().as_ref())
                .map(Arc::from)
                .ok_or_else(|| RootFsError::NotFound(display_rootfs_path(path.as_ref())));
        }
        let path = normalize_rootfs_path(path.as_ref())?;
        let path = self.resolve_symlink(&path, 0)?;
        self.files
            .get(&path)
            .map(|entry| entry.contents.clone())
            .ok_or_else(|| RootFsError::NotFound(display_rootfs_path(&path)))
    }

    /// Read at most `max` leading bytes without materializing the whole host
    /// file when this root is backed by an immutable cache directory.
    pub fn read_head(&self, path: impl AsRef<Path>, max: usize) -> Result<Vec<u8>, RootFsError> {
        if let Some(host) = self.immutable_host.as_ref() {
            return host
                .backend
                .file_head(path.as_ref().to_string_lossy().as_ref(), max)
                .ok_or_else(|| RootFsError::NotFound(display_rootfs_path(path.as_ref())));
        }
        let mut bytes = self.read(path)?;
        bytes.truncate(max);
        Ok(bytes)
    }

    pub fn open_file_readonly(&self, path: impl AsRef<Path>) -> Option<std::fs::File> {
        self.immutable_host
            .as_ref()?
            .backend
            .open_file_readonly(path.as_ref().to_string_lossy().as_ref())
    }

    /// Open or authoritatively miss a regular file in the immutable host root.
    /// On Darwin this reaches the contained fd-centric backend lane instead of
    /// separately walking the path for metadata and the readable fd.
    pub(crate) fn open_immutable_file_readonly(
        &self,
        path: impl AsRef<Path>,
    ) -> ImmutableHostFileOpen {
        let Some(host) = self.immutable_host.as_ref() else {
            return ImmutableHostFileOpen::Fallback;
        };
        host.backend
            .open_immutable_file_readonly(path.as_ref().to_string_lossy().as_ref())
    }

    /// Open a byte-exact directory anchor in the immutable host lower.
    /// Callers must separately prove that the writable overlay cannot affect
    /// the path and invalidate that proof on every structural generation.
    pub(crate) fn open_trusted_dir_fd(
        &self,
        path: impl AsRef<Path>,
    ) -> Option<std::os::fd::OwnedFd> {
        self.immutable_host
            .as_ref()?
            .backend
            .open_trusted_dir_fd(path.as_ref().to_string_lossy().as_ref())
    }

    pub fn read_to_string(&self, path: impl AsRef<Path>) -> Result<String, RootFsError> {
        Ok(String::from_utf8(self.read(path)?)?)
    }

    pub fn read_link(&self, path: impl AsRef<Path>) -> Result<String, RootFsError> {
        if let Some(host) = self.immutable_host.as_ref() {
            return host
                .backend
                .read_link(path.as_ref().to_string_lossy().as_ref())
                .ok_or_else(|| RootFsError::NotFound(display_rootfs_path(path.as_ref())));
        }
        let path = normalize_rootfs_path(path.as_ref())?;
        self.symlinks
            .get(&path)
            .map(|entry| entry.target_text.clone())
            .ok_or_else(|| RootFsError::NotFound(display_rootfs_path(&path)))
    }

    pub fn list_dir(&self, path: impl AsRef<Path>) -> Result<Vec<String>, RootFsError> {
        if let Some(host) = self.immutable_host.as_ref() {
            let path_text = path.as_ref().to_string_lossy();
            if !matches!(
                host.backend.real_stat(path_text.as_ref(), true),
                Some(RealStat {
                    kind: RootFsEntryKind::Directory,
                    ..
                })
            ) {
                return Err(RootFsError::NotFound(display_rootfs_path(path.as_ref())));
            }
            let names = host
                .backend
                .child_names(path_text.as_ref())
                .into_iter()
                .map(|(name, _, _)| name)
                .collect::<BTreeSet<_>>();
            return Ok(names.into_iter().collect());
        }
        let dir = normalize_rootfs_path(path.as_ref())?;
        if !self.directories.contains(&dir) {
            return Err(RootFsError::NotFound(display_rootfs_path(&dir)));
        }

        let mut names = BTreeSet::new();
        for child in self.files.keys().chain(self.directories.iter()) {
            insert_child_name(&mut names, &dir, child);
        }
        for child in self.symlinks.keys() {
            insert_child_name(&mut names, &dir, child);
        }

        Ok(names.into_iter().collect())
    }

    pub fn metadata(&self, path: impl AsRef<Path>) -> Result<RootFsMetadata, RootFsError> {
        if let Some(host) = self.immutable_host.as_ref() {
            return host_metadata(host, path.as_ref(), true);
        }
        let path = normalize_rootfs_path(path.as_ref())?;
        let path = self.resolve_symlink(&path, 0)?;
        self.metadata_for_normalized(&path)
    }

    /// The REAL host stat of an entry the immutable cache lower holds.
    ///
    /// The lower is a real host directory, so an entry only it holds is
    /// `open`ed as a real host fd whose `fstat` reports that host inode — and
    /// `directory_entries` already publishes the same inode as `d_ino`. This
    /// is the identity the path lane must report too; [`RootFsMetadata`]
    /// carries only kind/mode/size and cannot. Returns `None` for an
    /// in-memory rootfs, which has no host inode at all.
    pub fn immutable_real_stat(&self, path: impl AsRef<Path>, follow: bool) -> Option<RealStat> {
        let host = self.immutable_host.as_ref()?;
        host_real_stat(host, path.as_ref(), follow)
    }

    pub fn immutable_backend(&self) -> Option<&HostFsBackend> {
        self.immutable_host.as_ref().map(|h| &*h.backend)
    }

    pub fn symlink_metadata(&self, path: impl AsRef<Path>) -> Result<RootFsMetadata, RootFsError> {
        if let Some(host) = self.immutable_host.as_ref() {
            return host_metadata(host, path.as_ref(), false);
        }
        let path = normalize_rootfs_path(path.as_ref())?;
        self.metadata_for_normalized(&path)
    }

    pub fn directory_entries(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<Vec<RootFsDirEntry>, RootFsError> {
        if let Some(host) = self.immutable_host.as_ref() {
            let dir = normalize_rootfs_path(path.as_ref())?;
            let dir_text = display_rootfs_path(&dir);
            if !matches!(
                host.backend.real_stat(&dir_text, true),
                Some(RealStat {
                    kind: RootFsEntryKind::Directory,
                    ..
                })
            ) {
                return Err(RootFsError::NotFound(dir_text));
            }
            return host
                .backend
                .child_names(&display_rootfs_path(&dir))
                .into_iter()
                .map(|(name, kind, known_size)| {
                    let child = dir.join(&name);
                    let child_text = display_rootfs_path(&child);
                    let stat = host.backend.real_stat(&child_text, false);
                    Ok(RootFsDirEntry {
                        name,
                        metadata: RootFsMetadata {
                            path: child,
                            kind: stat.map(|value| value.kind).unwrap_or(kind),
                            mode: stat.map(|value| value.mode).unwrap_or(
                                if kind == RootFsEntryKind::Directory {
                                    0o755
                                } else {
                                    0o644
                                },
                            ),
                            size: stat
                                .and_then(|value| usize::try_from(value.size).ok())
                                .or_else(|| known_size.and_then(|size| usize::try_from(size).ok()))
                                .unwrap_or(0),
                        },
                        ino: stat.map(|value| value.ino).unwrap_or(0),
                    })
                })
                .collect();
        }
        let dir = normalize_rootfs_path(path.as_ref())?;
        if !self.directories.contains(&dir) {
            return Err(RootFsError::NotFound(display_rootfs_path(&dir)));
        }

        self.list_dir(&dir)?
            .into_iter()
            .map(|name| {
                let metadata = self.metadata_for_normalized(&dir.join(&name))?;
                // In-memory rootfs has no host inode; getdents64 will hash the path.
                Ok(RootFsDirEntry {
                    name,
                    metadata,
                    ino: 0,
                })
            })
            .collect()
    }

    /// Archive-only bounded directory enumeration. At most `limit + 1`
    /// entries are ever retained; the extra entry is used solely to prove the
    /// caller's cumulative archive budget was exceeded.
    pub(crate) fn directory_entries_bounded(
        &self,
        path: impl AsRef<Path>,
        limit: usize,
    ) -> Result<Vec<RootFsDirEntry>, RootFsError> {
        if let Some(host) = self.immutable_host.as_ref() {
            let dir = normalize_rootfs_path(path.as_ref())?;
            let dir_text = display_rootfs_path(&dir);
            if !matches!(
                host.backend.real_stat(&dir_text, true),
                Some(RealStat {
                    kind: RootFsEntryKind::Directory,
                    ..
                })
            ) {
                return Err(RootFsError::NotFound(dir_text));
            }
            let children = host
                .backend
                .child_names_bounded(&display_rootfs_path(&dir), limit)
                .map_err(|_| RootFsError::NotFound(display_rootfs_path(&dir)))?;
            if children.len() > limit {
                return Err(RootFsError::DirectoryTooLarge(display_rootfs_path(&dir)));
            }
            return children
                .into_iter()
                .map(|(name, kind, known_size)| {
                    let child = dir.join(&name);
                    let child_text = display_rootfs_path(&child);
                    let stat = host.backend.real_stat(&child_text, false);
                    Ok(RootFsDirEntry {
                        name,
                        metadata: RootFsMetadata {
                            path: child,
                            kind: stat.map(|value| value.kind).unwrap_or(kind),
                            mode: stat.map(|value| value.mode).unwrap_or(
                                if kind == RootFsEntryKind::Directory {
                                    0o755
                                } else {
                                    0o644
                                },
                            ),
                            size: stat
                                .and_then(|value| usize::try_from(value.size).ok())
                                .or_else(|| known_size.and_then(|size| usize::try_from(size).ok()))
                                .unwrap_or(0),
                        },
                        ino: stat.map(|value| value.ino).unwrap_or(0),
                    })
                })
                .collect();
        }

        let dir = normalize_rootfs_path(path.as_ref())?;
        if !self.directories.contains(&dir) {
            return Err(RootFsError::NotFound(display_rootfs_path(&dir)));
        }
        let mut names = BTreeSet::new();
        for child in self.files.keys().chain(self.directories.iter()) {
            insert_child_name(&mut names, &dir, child);
            if names.len() > limit {
                return Err(RootFsError::DirectoryTooLarge(display_rootfs_path(&dir)));
            }
        }
        for child in self.symlinks.keys() {
            insert_child_name(&mut names, &dir, child);
            if names.len() > limit {
                return Err(RootFsError::DirectoryTooLarge(display_rootfs_path(&dir)));
            }
        }
        names
            .into_iter()
            .map(|name| {
                let metadata = self.metadata_for_normalized(&dir.join(&name))?;
                Ok(RootFsDirEntry {
                    name,
                    metadata,
                    ino: 0,
                })
            })
            .collect()
    }

    pub fn contains(&self, path: impl AsRef<Path>) -> Result<bool, RootFsError> {
        if let Some(host) = self.immutable_host.as_ref() {
            return Ok(host
                .backend
                .real_stat(path.as_ref().to_string_lossy().as_ref(), false)
                .is_some());
        }
        let path = normalize_rootfs_path(path.as_ref())?;
        Ok(self.files.contains_key(&path)
            || self.directories.contains(&path)
            || self.symlinks.contains_key(&path))
    }

    fn apply_layer(&mut self, layer: LayerSource) -> Result<(), RootFsError> {
        let bytes = match layer {
            LayerSource::Tar(bytes) => bytes,
            LayerSource::TarGz(bytes) => {
                let mut decoder = GzDecoder::new(Cursor::new(bytes));
                let mut decoded = Vec::new();
                decoder.read_to_end(&mut decoded)?;
                decoded
            }
        };

        let mut archive = tar::Archive::new(Cursor::new(bytes));
        for entry in archive.entries()? {
            let mut entry = entry?;
            let raw_path = entry.path()?.into_owned();
            let path = normalize_layer_path(&raw_path)?;
            if path.as_os_str().is_empty() {
                // Root entry (`/` or `./`) — the rootfs root already exists.
                continue;
            }

            if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
                if file_name == OPAQUE_WHITEOUT {
                    if let Some(parent) = path.parent() {
                        self.apply_opaque_whiteout(parent);
                    }
                    continue;
                }

                if let Some(hidden_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
                    if let Some(parent) = path.parent() {
                        self.remove_path(&parent.join(hidden_name));
                    }
                    continue;
                }
            }

            if let Some(parent) = path.parent() {
                self.ensure_directories(parent);
            }

            let entry_type = entry.header().entry_type();
            let mode = entry.header().mode().unwrap_or(0o644);
            if entry_type.is_dir() {
                self.ensure_directories(&path);
                continue;
            }

            if entry_type.is_symlink() {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| RootFsError::UnsafePath(path.display().to_string()))?
                    .into_owned();
                let target_text = target
                    .to_str()
                    .ok_or_else(|| RootFsError::UnsafePath(path.display().to_string()))?
                    .to_owned();
                let target = normalize_symlink_target(&path, &target)?;
                self.symlinks.insert(
                    path.clone(),
                    SymlinkEntry {
                        path,
                        target,
                        target_text,
                    },
                );
                continue;
            }

            if entry_type.is_hard_link() {
                // A tar hardlink entry is another name for an already-archived
                // regular file (Ubuntu 26.04 uutils-coreutils: ~115 applets are
                // hardlinks to one multi-call ELF). The in-memory store has no
                // inode aliasing, so point the new path at the target's bytes —
                // `contents` is an Arc, so this shares the (10 MB) body, not copies
                // it. Mirrors the host backend's `dir.hard_link` (see
                // `apply_tar_to_dir`). Well-formed layers emit the target first; a
                // dangling target (out-of-order / cross-kind) is left unresolved
                // rather than aborting the whole rootfs.
                let link_name = entry
                    .link_name()?
                    .ok_or_else(|| RootFsError::UnsafePath(path.display().to_string()))?
                    .into_owned();
                let target = normalize_layer_path(&link_name)?;
                if let Some(src) = self.files.get(&target) {
                    let entry = FileEntry {
                        path: path.clone(),
                        mode: src.mode,
                        size: src.size,
                        contents: Arc::clone(&src.contents),
                    };
                    self.files.insert(path, entry);
                }
                continue;
            }

            if entry_type.is_file() {
                let mut contents = Vec::new();
                entry.read_to_end(&mut contents)?;
                self.files.insert(
                    path.clone(),
                    FileEntry {
                        path,
                        mode,
                        size: contents.len(),
                        contents: Arc::from(contents),
                    },
                );
            }
        }

        Ok(())
    }

    fn ensure_directories(&mut self, path: &Path) {
        let mut current = PathBuf::new();
        for component in path.components() {
            if let Component::Normal(name) = component {
                current.push(name);
                self.directories.insert(current.clone());
            }
        }
    }

    fn remove_path(&mut self, path: &Path) {
        self.files.remove(path);
        self.symlinks.remove(path);
        self.files
            .retain(|candidate, _| !candidate.starts_with(path));
        self.symlinks
            .retain(|candidate, _| !candidate.starts_with(path));
        self.directories
            .retain(|candidate| candidate == Path::new("") || !candidate.starts_with(path));
    }

    fn apply_opaque_whiteout(&mut self, path: &Path) {
        self.files
            .retain(|candidate, _| !candidate.starts_with(path));
        self.symlinks
            .retain(|candidate, _| !candidate.starts_with(path));
        self.directories.retain(|candidate| {
            candidate == Path::new("") || candidate == path || !candidate.starts_with(path)
        });
        self.ensure_directories(path);
    }

    /// Resolve symlinks along EVERY component of `path`, not just the
    /// leaf — Debian's `/lib -> usr/lib` makes the parent component a
    /// symlink, and the dynamic linker request for
    /// `/lib/ld-linux-aarch64.so.1` has to walk it before the final
    /// `ld-linux-aarch64.so.1` lookup succeeds. Cap recursion at 40
    /// (Linux's SYMLOOP_MAX) to bound pathological chains.
    fn resolve_symlink(&self, path: &Path, depth: usize) -> Result<PathBuf, RootFsError> {
        if depth > 40 {
            return Err(RootFsError::TooManySymlinks(display_rootfs_path(path)));
        }
        let mut acc = PathBuf::new();
        let components: Vec<_> = path.components().collect();
        for (i, component) in components.iter().enumerate() {
            acc.push(component.as_os_str());
            if let Some(entry) = self.symlinks.get(&acc) {
                let target_resolved = self.resolve_symlink(&entry.target, depth + 1)?;
                // The remaining components after the symlink we just
                // resolved get re-appended; they may themselves contain
                // further symlinks, hence the recursive call below.
                let mut rebuilt = target_resolved;
                for tail in &components[i + 1..] {
                    rebuilt.push(tail.as_os_str());
                }
                return self.resolve_symlink(&rebuilt, depth + 1);
            }
        }
        Ok(path.to_path_buf())
    }

    fn metadata_for_normalized(&self, path: &Path) -> Result<RootFsMetadata, RootFsError> {
        if let Some(entry) = self.files.get(path) {
            return Ok(RootFsMetadata {
                path: path.to_path_buf(),
                kind: RootFsEntryKind::File,
                mode: entry.mode,
                size: entry.size,
            });
        }

        if self.directories.contains(path) {
            return Ok(RootFsMetadata {
                path: path.to_path_buf(),
                kind: RootFsEntryKind::Directory,
                mode: 0o755,
                size: 0,
            });
        }

        if let Some(target) = self.symlinks.get(path) {
            return Ok(RootFsMetadata {
                path: path.to_path_buf(),
                kind: RootFsEntryKind::Symlink,
                mode: 0o777,
                size: target.target_text.len(),
            });
        }

        Err(RootFsError::NotFound(display_rootfs_path(path)))
    }
}

/// The lower's own view of a path — the single place the immutable host root
/// is stat'd, so `host_metadata` and [`RootFs::immutable_real_stat`] can never
/// answer from different reads.
fn host_real_stat(host: &ImmutableHostRoot, path: &Path, follow: bool) -> Option<RealStat> {
    let normalized = normalize_rootfs_path(path).ok()?;
    host.backend
        .real_stat(&display_rootfs_path(&normalized), follow)
}

/// Whether the lower's memoised listing of `normalized`'s parent proves the
/// name absent — the zero-host-call answer. A name that IS listed, or a
/// parent that has no listing yet, says nothing and the caller probes.
fn lower_listing_says_absent(host: &ImmutableHostRoot, normalized: &Path) -> bool {
    let (Some(parent), Some(leaf)) = (normalized.parent(), normalized.file_name()) else {
        return false;
    };
    let listings = host.listings.lock();
    match listings.get(parent) {
        Some(LowerListing::Names(names)) => !names.contains(leaf),
        Some(LowerListing::Absent) => true,
        _ => false,
    }
}

/// Record one exact "absent" answer for a child of `normalized`'s parent and,
/// at the threshold, list that directory. The listing is taken only for a
/// plain directory of the lower (`follow = false` kind `Directory`, itself
/// memoised): a symlinked parent (merged-usr `/bin -> usr/bin`) resolves per
/// path instead, so listing and probe can never disagree. A parent the lower
/// has no entry for at all is [`LowerListing::Absent`]: its `NotFound` came
/// through this same memoised resolution, and the lower never changes, so
/// every name beneath it is provably absent without a further probe.
fn note_lower_miss(host: &ImmutableHostRoot, normalized: &Path) {
    let Some(parent) = normalized.parent() else {
        return;
    };
    // A parent already proven absent — by its own memoised negative lookup
    // or by ITS parent's listing — needs no miss count: the first name
    // beneath it settles the whole directory.
    let parent_known_absent = matches!(
        host.dcache.lock().get(&(parent.to_path_buf(), false)),
        Some(None)
    ) || lower_listing_says_absent(host, parent);
    {
        let mut listings = host.listings.lock();
        match listings.get_mut(parent) {
            None if parent_known_absent => {
                listings.insert(parent.to_path_buf(), LowerListing::Absent);
                return;
            }
            None => {
                listings.insert(parent.to_path_buf(), LowerListing::Misses(1));
                return;
            }
            Some(LowerListing::Misses(n)) => {
                *n = n.saturating_add(1);
                if *n < LOWER_LISTING_MISS_THRESHOLD {
                    return;
                }
            }
            Some(_) => return,
        }
    }
    let listing = match host_metadata(host, parent, false) {
        Ok(RootFsMetadata {
            kind: RootFsEntryKind::Directory,
            ..
        }) => host
            .backend
            .child_name_set(&display_rootfs_path(parent))
            .map_or(LowerListing::Opaque, |names| {
                LowerListing::Names(Arc::new(names))
            }),
        Err(RootFsError::NotFound(_)) => LowerListing::Absent,
        Ok(_) | Err(_) => LowerListing::Opaque,
    };
    host.listings.lock().insert(parent.to_path_buf(), listing);
}

fn host_metadata(
    host: &ImmutableHostRoot,
    path: &Path,
    follow: bool,
) -> Result<RootFsMetadata, RootFsError> {
    let normalized = normalize_rootfs_path(path)?;
    let key = (normalized, follow);
    let cached = host.dcache.lock().get(&key).copied();
    let entry = match cached {
        Some(entry) => entry,
        None if lower_listing_says_absent(host, &key.0) => None,
        None => {
            let entry = host_real_stat(host, path, follow).map(|stat| LowerEntry {
                kind: stat.kind,
                mode: stat.mode,
                size: usize::try_from(stat.size).unwrap_or(usize::MAX),
            });
            if entry.is_none() {
                note_lower_miss(host, &key.0);
            }
            let mut dcache = host.dcache.lock();
            if dcache.len() >= LOWER_DCACHE_MAX_ENTRIES {
                dcache.clear();
            }
            dcache.insert(key.clone(), entry);
            entry
        }
    };
    let (normalized, _) = key;
    let entry = entry.ok_or_else(|| RootFsError::NotFound(display_rootfs_path(&normalized)))?;
    Ok(RootFsMetadata {
        path: normalized,
        kind: entry.kind,
        mode: entry.mode,
        size: entry.size,
    })
}

impl LayerSource {
    pub fn from_path(path: &Path) -> Result<Self, RootFsError> {
        let bytes = fs::read(path)?;
        if bytes.starts_with(&[0x1f, 0x8b]) {
            Ok(Self::TarGz(bytes))
        } else {
            Ok(Self::Tar(bytes))
        }
    }
}

fn normalize_layer_path(path: &Path) -> Result<PathBuf, RootFsError> {
    // Layer tar entries are conventionally relative (`./etc/foo`), but some
    // tools (e.g. kaniko) emit absolute entries (`/etc/foo`) and a bare root
    // entry (`/` or `./`). Treat a leading `/` as rootfs-relative; a `..` that
    // escapes the root is still rejected by `normalize_path`. A root entry
    // normalizes to the empty path, which the apply loops skip (the rootfs root
    // already exists).
    normalize_path(path, true)
}

fn normalize_rootfs_path(path: &Path) -> Result<PathBuf, RootFsError> {
    normalize_path(path, true)
}

fn normalize_symlink_target(link_path: &Path, target: &Path) -> Result<PathBuf, RootFsError> {
    if target.is_absolute() {
        return normalize_rootfs_path(target);
    }

    let parent = link_path.parent().unwrap_or_else(|| Path::new(""));
    normalize_path(&parent.join(target), false)
}

fn normalize_path(path: &Path, allow_absolute: bool) -> Result<PathBuf, RootFsError> {
    let mut out = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(_) => {
                return Err(RootFsError::UnsafePath(path.display().to_string()));
            }
            Component::RootDir => {
                if !allow_absolute {
                    return Err(RootFsError::UnsafePath(path.display().to_string()));
                }
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return Err(RootFsError::UnsafePath(path.display().to_string()));
                }
            }
            Component::Normal(component) => out.push(component),
        }
    }

    Ok(out)
}

fn display_rootfs_path(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", path.display())
    }
}

fn insert_child_name(names: &mut BTreeSet<String>, dir: &Path, child: &Path) {
    if child == dir {
        return;
    }
    if let Ok(stripped) = child.strip_prefix(dir)
        && let Some(component) = stripped.components().next()
    {
        names.insert(component.as_os_str().to_string_lossy().into_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    fn lower_listing_state(rootfs: &RootFs, dir: &str) -> Option<&'static str> {
        let host = rootfs.immutable_host.as_ref().unwrap();
        let listings = host.listings.lock();
        listings.get(Path::new(dir)).map(|state| match state {
            LowerListing::Misses(_) => "misses",
            LowerListing::Names(_) => "names",
            LowerListing::Opaque => "opaque",
            LowerListing::Absent => "absent",
        })
    }

    /// The immutable lower answers a directory's absences from ONE listing
    /// once that directory has missed twice, stays exact for present names,
    /// and never lists through a symlinked parent.
    #[cfg(target_os = "macos")]
    #[test]
    fn immutable_lower_lists_a_directory_after_two_misses() {
        let lower = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("usr/bin")).unwrap();
        std::fs::create_dir_all(lower.path().join("tmp")).unwrap();
        std::fs::write(lower.path().join("tmp/kept"), b"k").unwrap();
        std::fs::write(lower.path().join("usr/bin/sh"), b"#!").unwrap();
        std::os::unix::fs::symlink("usr/bin", lower.path().join("bin")).unwrap();
        let rootfs = RootFs::from_immutable_host_dir(lower.path()).unwrap();

        assert!(rootfs.symlink_metadata("/tmp/fs_new_0").is_err());
        assert_eq!(lower_listing_state(&rootfs, "tmp"), Some("misses"));
        assert!(rootfs.symlink_metadata("/tmp/fs_new_1").is_err());
        assert_eq!(lower_listing_state(&rootfs, "tmp"), Some("names"));

        // Now planted on the host AFTER the listing: the lower is immutable
        // by contract, so the memo — not the disk — is the authority.
        std::fs::write(lower.path().join("tmp/planted"), b"p").unwrap();
        assert!(rootfs.symlink_metadata("/tmp/planted").is_err());
        // Present names are still answered exactly (kind, size, mode).
        let kept = rootfs.symlink_metadata("/tmp/kept").unwrap();
        assert_eq!(kept.kind, RootFsEntryKind::File);
        assert_eq!(kept.size, 1);
        // Byte-exact: a case variant of a present name is absent, as on Linux.
        assert!(rootfs.symlink_metadata("/tmp/KEPT").is_err());

        // A symlinked parent resolves per path and is never listed.
        assert!(rootfs.symlink_metadata("/bin/nope0").is_err());
        assert!(rootfs.symlink_metadata("/bin/nope1").is_err());
        assert_eq!(lower_listing_state(&rootfs, "bin"), Some("opaque"));
        assert_eq!(
            rootfs.symlink_metadata("/bin/sh").unwrap().kind,
            RootFsEntryKind::File
        );
        assert!(rootfs.symlink_metadata("/bin/nope2").is_err());
    }

    /// A directory the lower LACKS (the guest's own `mkdir -p /tmp/LTP_x`,
    /// which exists only in the upper) proves every child absent: once its
    /// absence is known no lookup beneath it may probe the host again.
    /// `ltp-creat05` ran 8x the oracle because this parent was memoised as
    /// `Opaque`, so each of its 4,096 fresh `creat05_N` names re-walked the
    /// lower three times per guest `open`.
    #[cfg(target_os = "macos")]
    #[test]
    fn immutable_lower_absent_parent_proves_every_child_absent() {
        let lower = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(lower.path().join("tmp")).unwrap();
        let rootfs = RootFs::from_immutable_host_dir(lower.path()).unwrap();

        assert!(rootfs.symlink_metadata("/tmp/ltp_x/creat_0").is_err());
        assert!(rootfs.symlink_metadata("/tmp/ltp_x/creat_1").is_err());
        assert_eq!(lower_listing_state(&rootfs, "tmp/ltp_x"), Some("absent"));

        // Planted on the host AFTER the answer: the lower is immutable by
        // contract, so a probe here would be both wasted and wrong.
        std::fs::create_dir_all(lower.path().join("tmp/ltp_x")).unwrap();
        std::fs::write(lower.path().join("tmp/ltp_x/creat_2"), b"p").unwrap();
        assert!(rootfs.symlink_metadata("/tmp/ltp_x/creat_2").is_err());
        assert!(rootfs.metadata("/tmp/ltp_x/creat_2").is_err());
        assert!(rootfs.symlink_metadata("/tmp/ltp_x").is_err());
        // The absent parent proves its whole subtree absent, not one level.
        assert!(
            rootfs
                .symlink_metadata("/tmp/ltp_x/deeper/creat_3")
                .is_err()
        );
        assert_eq!(
            lower_listing_state(&rootfs, "tmp/ltp_x/deeper"),
            Some("absent")
        );
    }

    #[test]
    fn symlink_target_with_parent_dir_resolves_within_root() {
        // etc/mtab -> ../proc/mounts should resolve to /proc/mounts
        let resolved =
            normalize_symlink_target(Path::new("etc/mtab"), Path::new("../proc/mounts")).unwrap();
        assert_eq!(resolved, PathBuf::from("proc/mounts"));
    }

    #[test]
    fn symlink_target_with_multiple_parent_dirs_resolves_within_root() {
        // a/b/c -> ../../x: resolution starts in the symlink's parent dir (a/b),
        // .. -> a, .. -> "" (root), then x -> /x.
        let resolved = normalize_symlink_target(Path::new("a/b/c"), Path::new("../../x")).unwrap();
        assert_eq!(resolved, PathBuf::from("x"));
    }

    #[test]
    fn symlink_target_one_parent_dir_pops_one_segment() {
        // a/b/c -> ../x: from a/b, .. -> a, x -> a/x.
        let resolved = normalize_symlink_target(Path::new("a/b/c"), Path::new("../x")).unwrap();
        assert_eq!(resolved, PathBuf::from("a/x"));
    }

    #[test]
    fn symlink_target_escaping_root_from_shallow_path_is_rejected() {
        // a -> ../../../etc/passwd (one level deep) MUST still be unsafe.
        let err =
            normalize_symlink_target(Path::new("a"), Path::new("../../../etc/passwd")).unwrap_err();
        assert!(matches!(err, RootFsError::UnsafePath(_)));
    }

    #[test]
    fn symlink_target_escaping_root_via_second_parent_dir_is_rejected() {
        // etc/foo -> ../../etc/passwd
        // First .. from /etc lands at /; second .. from / is the escape.
        let err = normalize_symlink_target(Path::new("etc/foo"), Path::new("../../etc/passwd"))
            .unwrap_err();
        assert!(matches!(err, RootFsError::UnsafePath(_)));
    }

    #[test]
    fn symlink_target_with_curdir_resolves() {
        // bin/sh -> ./busybox should resolve to /bin/busybox
        let resolved =
            normalize_symlink_target(Path::new("bin/sh"), Path::new("./busybox")).unwrap();
        assert_eq!(resolved, PathBuf::from("bin/busybox"));
    }

    #[test]
    fn layer_path_with_parent_dir_collapses() {
        // foo/../bar inside a layer path should collapse to bar
        let normalized = normalize_layer_path(Path::new("foo/../bar")).unwrap();
        assert_eq!(normalized, PathBuf::from("bar"));
    }

    #[test]
    fn layer_path_escaping_root_is_rejected() {
        let err = normalize_layer_path(Path::new("../escape")).unwrap_err();
        assert!(matches!(err, RootFsError::UnsafePath(_)));
    }

    #[test]
    fn layer_root_and_absolute_paths_normalize() {
        // A layer entry for the rootfs root itself ("/" or "./") normalizes to
        // the empty path (the apply loops skip it). kaniko emits such an entry.
        assert!(
            normalize_layer_path(Path::new("/"))
                .unwrap()
                .as_os_str()
                .is_empty()
        );
        assert!(
            normalize_layer_path(Path::new("./"))
                .unwrap()
                .as_os_str()
                .is_empty()
        );
        // An absolute layer entry is treated as rootfs-relative (leading `/`
        // stripped), not rejected.
        assert_eq!(
            normalize_layer_path(Path::new("/etc/services")).unwrap(),
            PathBuf::from("etc/services")
        );
        // A `..` escape is still rejected even with a leading `/`.
        assert!(matches!(
            normalize_layer_path(Path::new("/../escape")).unwrap_err(),
            RootFsError::UnsafePath(_)
        ));
    }

    #[test]
    fn rootfs_path_escaping_via_root_then_parent_is_rejected() {
        // "/../safe.txt" — / then .. on empty stack escapes.
        let err = normalize_rootfs_path(Path::new("/../safe.txt")).unwrap_err();
        assert!(matches!(err, RootFsError::UnsafePath(_)));
    }

    /// Build a tar in memory and load it as a RootFs. Mirrors what the
    /// OCI loader does, so the assertions exercise the same resolution
    /// path as `carrick run`.
    fn make_rootfs(files: &[(&str, &[u8])], dirs: &[&str], symlinks: &[(&str, &str)]) -> RootFs {
        use tar::{Builder, EntryType, Header};
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut builder = Builder::new(&mut buf);
            for path in dirs {
                let mut h = Header::new_gnu();
                h.set_path(format!("{}/", path)).unwrap();
                h.set_entry_type(EntryType::Directory);
                h.set_size(0);
                h.set_mode(0o755);
                h.set_cksum();
                builder.append(&h, std::io::empty()).unwrap();
            }
            for (path, bytes) in files {
                let mut h = Header::new_gnu();
                h.set_path(path).unwrap();
                h.set_size(bytes.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                builder.append(&h, *bytes).unwrap();
            }
            for (link, target) in symlinks {
                let mut h = Header::new_gnu();
                h.set_path(link).unwrap();
                h.set_entry_type(EntryType::Symlink);
                h.set_size(0);
                h.set_mode(0o777);
                h.set_link_name(target).unwrap();
                h.set_cksum();
                builder.append(&h, std::io::empty()).unwrap();
            }
            builder.finish().unwrap();
        }
        RootFs::from_layers(std::iter::once(LayerSource::Tar(buf))).unwrap()
    }

    #[test]
    fn resolve_walks_through_directory_symlinks() {
        // Debian usrmerge: /lib -> usr/lib, then
        // /usr/lib/ld-linux-aarch64.so.1 -> aarch64-linux-gnu/ld-linux-aarch64.so.1
        let fs = make_rootfs(
            &[(
                "usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
                b"FAKE-LD",
            )],
            &["usr", "usr/lib", "usr/lib/aarch64-linux-gnu"],
            &[
                ("lib", "usr/lib"),
                (
                    "usr/lib/ld-linux-aarch64.so.1",
                    "aarch64-linux-gnu/ld-linux-aarch64.so.1",
                ),
            ],
        );
        let bytes = fs
            .read("/lib/ld-linux-aarch64.so.1")
            .expect("walk parent symlink");
        assert_eq!(bytes, b"FAKE-LD");
    }

    #[test]
    fn later_layer_hardlink_replaces_existing_alias_without_truncating_target() {
        use tar::{Builder, EntryType, Header};

        fn hardlink_layer(include_target: bool) -> Vec<u8> {
            let mut bytes = Vec::new();
            {
                let mut builder = Builder::new(&mut bytes);
                if include_target {
                    let body: &[u8] = b"ELF-perl-interpreter";
                    let mut header = Header::new_gnu();
                    header.set_path("usr/bin/perl").unwrap();
                    header.set_size(body.len() as u64);
                    header.set_mode(0o755);
                    header.set_cksum();
                    builder.append(&header, body).unwrap();
                }
                let mut header = Header::new_gnu();
                header.set_path("usr/bin/perl5.38.2").unwrap();
                header.set_entry_type(EntryType::Link);
                header.set_size(0);
                header.set_mode(0o755);
                header.set_link_name("/usr/bin/perl").unwrap();
                header.set_cksum();
                builder.append(&header, std::io::empty()).unwrap();
                builder.finish().unwrap();
            }
            bytes
        }

        let scratch = tempfile::tempdir().unwrap();
        let mut stats = ExtractStats::default();
        let mut base = tar::Archive::new(std::io::Cursor::new(hardlink_layer(true)));
        apply_tar_to_dir(&mut base, scratch.path(), &mut stats).unwrap();
        let mut update = tar::Archive::new(std::io::Cursor::new(hardlink_layer(false)));
        apply_tar_to_dir(&mut update, scratch.path(), &mut stats).unwrap();

        assert_eq!(
            std::fs::read(scratch.path().join("usr/bin/perl")).unwrap(),
            b"ELF-perl-interpreter"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("usr/bin/perl5.38.2")).unwrap(),
            b"ELF-perl-interpreter"
        );
    }

    #[test]
    fn resolve_reads_hardlinked_applet() {
        // Ubuntu 26.04 uutils-coreutils: /usr/bin/uname -> symlink ->
        // ../lib/cargo/bin/coreutils/uname, and that applet is a HARDLINK to the
        // one multi-call binary (the first applet is the regular-file entry; the
        // other ~114 applets are tar hardlink entries pointing at it). The
        // in-memory backend must materialize hardlinks or every non-first applet
        // is dropped -> NotFound at boot ("failed to run rootfs ELF").
        use tar::{Builder, EntryType, Header};
        let body: &[u8] = b"\x7fELF-coreutils-multicall-binary";
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut b = Builder::new(&mut buf);
            // The regular file (first applet, alphabetically `arch`).
            let mut h = Header::new_gnu();
            h.set_path("usr/lib/cargo/bin/coreutils/arch").unwrap();
            h.set_size(body.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            b.append(&h, body).unwrap();
            // The `uname` applet: a hardlink to the regular file above.
            let mut h = Header::new_gnu();
            h.set_path("usr/lib/cargo/bin/coreutils/uname").unwrap();
            h.set_entry_type(EntryType::Link);
            h.set_size(0);
            h.set_link_name("usr/lib/cargo/bin/coreutils/arch").unwrap();
            h.set_cksum();
            b.append(&h, std::io::empty()).unwrap();
            // /usr/bin/uname -> ../lib/cargo/bin/coreutils/uname (relative symlink).
            let mut h = Header::new_gnu();
            h.set_path("usr/bin/uname").unwrap();
            h.set_entry_type(EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            h.set_link_name("../lib/cargo/bin/coreutils/uname").unwrap();
            h.set_cksum();
            b.append(&h, std::io::empty()).unwrap();
            b.finish().unwrap();
        }
        let fs = RootFs::from_layers(std::iter::once(LayerSource::Tar(buf))).unwrap();
        // The hardlinked applet itself reads as the multi-call binary.
        assert_eq!(
            fs.read("/usr/lib/cargo/bin/coreutils/uname").unwrap(),
            body,
            "hardlink applet must materialize"
        );
        // And the full chain a bare `uname` entrypoint walks: symlink -> hardlink.
        assert_eq!(
            fs.read("/usr/bin/uname").unwrap(),
            body,
            "symlink -> hardlink chain must resolve"
        );
    }

    #[test]
    fn layer_extraction_rejects_parent_escape() {
        use tar::{Builder, Header};

        let sandbox = tempfile::tempdir().unwrap();
        let scratch = sandbox.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();

        let mut buf = Vec::new();
        {
            let mut b = Builder::new(&mut buf);
            let mut h = Header::new_gnu();
            let bytes = h.as_mut_bytes();
            let name = b"../escape";
            bytes[..name.len()].copy_from_slice(name);
            h.set_size(4);
            h.set_mode(0o644);
            h.set_cksum();
            b.append(&h, b"fail".as_slice()).unwrap();
            b.finish().unwrap();
        }
        let mut archive = tar::Archive::new(std::io::Cursor::new(buf));
        let mut stats = ExtractStats::default();
        let res = apply_tar_to_dir(&mut archive, &scratch, &mut stats);
        assert!(
            matches!(res, Err(RootFsError::UnsafePath(_))),
            "entry named ../escape must be refused with UnsafePath, got: {:?}",
            res
        );
        assert!(
            !sandbox.path().join("escape").exists(),
            "escape file must not exist outside scratch root"
        );
    }

    #[test]
    fn layer_extraction_rejects_relative_symlink_escape() {
        use tar::{Builder, EntryType, Header};

        let sandbox = tempfile::tempdir().unwrap();
        let scratch = sandbox.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();

        let mut buf = Vec::new();
        {
            let mut b = Builder::new(&mut buf);
            let mut h = Header::new_gnu();
            h.set_path("sub/link_escape").unwrap();
            h.set_entry_type(EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            h.set_link_name("../../outside").unwrap();
            h.set_cksum();
            b.append(&h, std::io::empty()).unwrap();
            b.finish().unwrap();
        }
        let mut archive = tar::Archive::new(std::io::Cursor::new(buf));
        let mut stats = ExtractStats::default();
        let res = apply_tar_to_dir(&mut archive, &scratch, &mut stats);
        assert!(
            matches!(res, Err(RootFsError::UnsafePath(_))),
            "relative symlink escaping root must be refused with UnsafePath, got: {:?}",
            res
        );
        assert!(
            !sandbox.path().join("outside").exists(),
            "outside path must not exist"
        );
    }

    #[test]
    fn layer_extraction_refuses_absolute_symlink_escape() {
        use tar::{Builder, EntryType, Header};

        let sandbox = tempfile::tempdir().unwrap();
        let scratch = sandbox.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();

        let outside_target = sandbox.path().join("outside_target");
        std::fs::create_dir_all(&outside_target).unwrap();
        let mut buf = Vec::new();
        {
            let mut b = Builder::new(&mut buf);
            let mut h = Header::new_gnu();
            h.set_path("link_abs").unwrap();
            h.set_entry_type(EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            // Absolute target pointing to outside_target
            h.set_link_name(outside_target.to_str().unwrap()).unwrap();
            h.set_cksum();
            b.append(&h, std::io::empty()).unwrap();

            let data = b"payload";
            let mut h2 = Header::new_gnu();
            h2.set_path("link_abs/owned_file").unwrap();
            h2.set_size(data.len() as u64);
            h2.set_mode(0o644);
            h2.set_cksum();
            b.append(&h2, data.as_slice()).unwrap();
            b.finish().unwrap();
        }
        let mut archive = tar::Archive::new(std::io::Cursor::new(buf));
        let mut stats = ExtractStats::default();
        let _ = apply_tar_to_dir(&mut archive, &scratch, &mut stats);
        assert!(
            !outside_target.join("owned_file").exists(),
            "file must NEVER be written to absolute host target outside scratch root"
        );
    }

    #[test]
    fn layer_extraction_directory_symlink_traversal() {
        use tar::{Builder, EntryType, Header};

        let sandbox = tempfile::tempdir().unwrap();
        let scratch_c = sandbox.path().join("scratch_c");
        std::fs::create_dir_all(&scratch_c).unwrap();
        let mut buf = Vec::new();
        {
            let mut b = Builder::new(&mut buf);
            // Directory usr/bin
            let mut h0 = Header::new_gnu();
            h0.set_path("usr/bin").unwrap();
            h0.set_entry_type(EntryType::Directory);
            h0.set_mode(0o755);
            h0.set_size(0);
            h0.set_cksum();
            b.append(&h0, std::io::empty()).unwrap();

            // Symlink bin -> usr/bin
            let mut h1 = Header::new_gnu();
            h1.set_path("bin").unwrap();
            h1.set_entry_type(EntryType::Symlink);
            h1.set_size(0);
            h1.set_mode(0o777);
            h1.set_link_name("usr/bin").unwrap();
            h1.set_cksum();
            b.append(&h1, std::io::empty()).unwrap();

            // Regular file bin/true
            let data = b"binary-content";
            let mut h2 = Header::new_gnu();
            h2.set_path("bin/true").unwrap();
            h2.set_size(data.len() as u64);
            h2.set_mode(0o755);
            h2.set_cksum();
            b.append(&h2, data.as_slice()).unwrap();
            b.finish().unwrap();
        }
        let mut archive = tar::Archive::new(std::io::Cursor::new(buf));
        let mut stats = ExtractStats::default();
        apply_tar_to_dir(&mut archive, &scratch_c, &mut stats).unwrap();

        let bin_path = scratch_c.join("bin");
        let bin_meta = std::fs::symlink_metadata(&bin_path).unwrap();
        assert!(
            bin_meta.file_type().is_symlink(),
            "bin must be a symlink, not a directory"
        );
        assert_eq!(
            std::fs::read_link(&bin_path).unwrap(),
            std::path::Path::new("usr/bin")
        );
        let target_file = scratch_c.join("usr/bin/true");
        assert!(
            target_file.exists(),
            "bin/true must be written at usr/bin/true through the contained directory symlink"
        );
        assert_eq!(std::fs::read(&target_file).unwrap(), b"binary-content");
    }

    #[test]
    fn rootfs_extract_to_dir_directory_symlink_traversal() {
        use tar::{Builder, EntryType, Header};
        let mut buf = Vec::new();
        {
            let mut b = Builder::new(&mut buf);
            let mut h0 = Header::new_gnu();
            h0.set_path("usr/bin").unwrap();
            h0.set_entry_type(EntryType::Directory);
            h0.set_mode(0o755);
            h0.set_size(0);
            h0.set_cksum();
            b.append(&h0, std::io::empty()).unwrap();

            let mut h1 = Header::new_gnu();
            h1.set_path("bin").unwrap();
            h1.set_entry_type(EntryType::Symlink);
            h1.set_size(0);
            h1.set_mode(0o777);
            h1.set_link_name("usr/bin").unwrap();
            h1.set_cksum();
            b.append(&h1, std::io::empty()).unwrap();

            let data = b"true-binary";
            let mut h2 = Header::new_gnu();
            h2.set_path("bin/true").unwrap();
            h2.set_size(data.len() as u64);
            h2.set_mode(0o755);
            h2.set_cksum();
            b.append(&h2, data.as_slice()).unwrap();
            b.finish().unwrap();
        }
        let rootfs = RootFs::from_layers([LayerSource::Tar(buf)]).unwrap();
        let sandbox = tempfile::tempdir().unwrap();
        let scratch = sandbox.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        rootfs.extract_to_dir(&scratch).unwrap();

        let bin_path = scratch.join("bin");
        assert!(
            std::fs::symlink_metadata(&bin_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "bin must be a symlink"
        );
        let true_path = scratch.join("usr/bin/true");
        assert!(
            true_path.exists(),
            "usr/bin/true must exist when extracted through rootfs.extract_to_dir"
        );
    }
}
