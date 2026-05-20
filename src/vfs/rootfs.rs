//! `/` mount: the OCI rootfs (immutable, read-only) plus a writable
//! overlay (`FsBackend`) on top.
//!
//! This is the deepest of the four migration steps because the
//! dispatcher's existing fs syscalls (openat, stat, statx, unlinkat,
//! mkdirat, renameat2, symlinkat, linkat, readlinkat, fchmodat,
//! utimensat...) all touch the overlay+rootfs pair. Step 4 lands
//! `RootFsVfs` as the canonical owner of that state and provides the
//! full `Vfs` trait surface; routing every dispatcher fs syscall
//! through the trait is the mechanical follow-up.
//!
//! For now the dispatcher reaches into `self.rootfs_vfs.rootfs` and
//! `self.rootfs_vfs.overlay` directly (preserving every existing
//! lookup path). `RootFsVfs::open` etc. are exercised by their own
//! unit tests, where they consult exactly the same overlay+rootfs
//! data the dispatcher uses, so when the dispatcher does flip
//! through the trait the result is byte-identical to what it
//! produced via direct access.

use crate::linux_abi::{
    LINUX_EACCES, LINUX_EEXIST, LINUX_EINVAL, LINUX_EISDIR, LINUX_ENOENT, LINUX_ENOTDIR,
    LINUX_ENOTEMPTY, LINUX_EROFS,
};
use crate::fs_backend::{FsBackend, MemoryBackend, OverlayEntry};
use crate::rootfs::{RootFs, RootFsDirEntry, RootFsEntryKind, RootFsError, RootFsMetadata};

use super::{
    DirEnt, EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle,
};

/// The `/` mount. Owns the immutable OCI rootfs (`rootfs`) and the
/// writable overlay (`overlay`). Direct field access by the
/// dispatcher is intentional for step 4 of the migration — the
/// dispatcher's existing fs syscalls each touch one or both of these
/// state pieces directly, and rewriting them all at once is the
/// follow-up step.
pub struct RootFsVfs {
    pub rootfs: Option<RootFs>,
    pub overlay: Box<dyn FsBackend>,
}

/// Richer result from [`RootFsVfs::open_for_dispatch`]. Carries the
/// rootfs-shaped types the dispatcher's existing `OpenDescription`
/// variants consume, plus a `NotFoundCreate` variant signalling that
/// the caller should perform the O_CREAT path.
pub enum OpenDispatchResult {
    File {
        metadata: RootFsMetadata,
        contents: Vec<u8>,
        writable: bool,
    },
    /// A regular file backed by a REAL host fd (disk-backed overlay,
    /// i.e. `--fs host`). The dispatcher wraps this as
    /// `OpenDescription::HostFile`, so reads/writes go to the shared
    /// kernel file and survive `libc::fork`.
    HostFile {
        host_fd: i32,
        metadata: RootFsMetadata,
        writable: bool,
    },
    Directory {
        metadata: RootFsMetadata,
        entries: Vec<RootFsDirEntry>,
    },
    /// Returned only when `want_create` was true and the path
    /// doesn't exist. The dispatcher creates the entry in the
    /// overlay itself (it knows the right initial contents / mode).
    NotFoundCreate,
}

impl RootFsVfs {
    pub fn new() -> Self {
        Self {
            rootfs: None,
            overlay: Box::new(MemoryBackend::new()),
        }
    }

    pub fn with_rootfs(rootfs: RootFs) -> Self {
        Self {
            rootfs: Some(rootfs),
            overlay: Box::new(MemoryBackend::new()),
        }
    }

    /// Swap the writable overlay. Returns the previously-installed
    /// backend so the caller can decide what to do with it.
    pub fn set_overlay(&mut self, backend: Box<dyn FsBackend>) -> Box<dyn FsBackend> {
        std::mem::replace(&mut self.overlay, backend)
    }

    /// Non-following metadata lookup (the `lstat`/`AT_SYMLINK_NOFOLLOW`
    /// counterpart to the symlink-following [`Vfs::lookup`]). If the final
    /// path component is a symlink, this reports the link itself
    /// (`EntryKind::Symlink`, size = byte length of the target string) rather
    /// than resolving it. Used by `statx`/`newfstatat` when the guest passes
    /// `AT_SYMLINK_NOFOLLOW` and the writable backend can't answer a
    /// `real_stat` (e.g. the in-memory backend).
    pub fn lookup_nofollow(&self, path: &str) -> Result<Metadata, VfsError> {
        // A symlink materialised in the writable overlay.
        if let Some(target) = self.overlay.read_link(path) {
            return Ok(Metadata {
                kind: EntryKind::Symlink,
                mode: 0o777,
                size: target.len() as u64,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        // A symlink in the immutable rootfs layer: report the link, not its
        // target. Non-symlink entries fall through to the regular (following)
        // lookup, which is identical for them.
        if let Some(rootfs) = self.rootfs.as_ref() {
            if let Ok(md) = rootfs.symlink_metadata(path) {
                if matches!(md.kind, RootFsEntryKind::Symlink) {
                    return Ok(Metadata {
                        kind: EntryKind::Symlink,
                        mode: md.mode,
                        size: md.size as u64,
                        uid: 0,
                        gid: 0,
                        mtime_secs: 0,
                        mtime_nanos: 0,
                    });
                }
            }
        }
        self.lookup(path)
    }

    /// Richer open variant the dispatcher uses for the openat
    /// fallback after VFS-mount routing (/dev /proc /sys). Returns
    /// the full rootfs-shaped metadata + entries / contents that the
    /// dispatcher's `OpenDescription::File` / `Directory` variants
    /// need, including the writable-overlay-promotion semantics for
    /// rootfs files opened with O_WRONLY/O_RDWR.
    ///
    /// The Vfs-trait `open` method returns `VfsHandle::Bytes` for
    /// reads only; this method covers the writable + directory
    /// cases that don't fit neatly into the trait surface yet.
    pub fn open_for_dispatch(
        &mut self,
        path: &str,
        want_create: bool,
        want_excl: bool,
        want_trunc: bool,
        writable_request: bool,
    ) -> Result<OpenDispatchResult, i32> {
        // Overlay-first: tombstone short-circuits to ENOENT for the
        // non-create case (with O_CREAT we treat it as "no file in
        // the way" and let the caller create).
        let overlay_view = self.overlay.lookup(path);
        let overlay_deleted = matches!(overlay_view, Some(OverlayEntry::Deleted));
        match overlay_view {
            Some(OverlayEntry::File(mut contents)) => {
                if want_create && want_excl {
                    return Err(LINUX_EEXIST);
                }
                let mode = self.overlay.metadata(path).map(|m| m.mode).unwrap_or(0o644);
                // Disk-backed overlay (--fs host): hand back a REAL host
                // fd so reads/writes share the kernel file across fork.
                if let Some(host_fd) =
                    self.overlay.open_raw_fd(path, writable_request, false, want_trunc)
                {
                    let size = self.overlay.metadata(path).map(|m| m.size).unwrap_or(0);
                    let metadata = RootFsMetadata {
                        path: std::path::Path::new(path).to_path_buf(),
                        kind: RootFsEntryKind::File,
                        mode,
                        size,
                    };
                    return Ok(OpenDispatchResult::HostFile {
                        host_fd,
                        metadata,
                        writable: writable_request,
                    });
                }
                // In-memory overlay (MemoryBackend): cached-bytes File.
                if want_trunc {
                    contents.clear();
                    self.overlay
                        .set_file_contents(path, contents.clone())
                        .map_err(|_| LINUX_EINVAL)?;
                }
                let metadata = RootFsMetadata {
                    path: std::path::Path::new(path).to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode,
                    size: contents.len(),
                };
                return Ok(OpenDispatchResult::File {
                    metadata,
                    contents,
                    writable: writable_request,
                });
            }
            Some(OverlayEntry::Dir) => {
                if writable_request {
                    return Err(LINUX_EISDIR);
                }
                let entries = crate::overlay::layered_directory_entries(
                    self.overlay.as_ref(),
                    self.rootfs.as_ref(),
                    path,
                )
                .map_err(|e| crate::dispatch::rootfs_errno(e))?;
                let metadata = RootFsMetadata {
                    path: std::path::Path::new(path).to_path_buf(),
                    kind: RootFsEntryKind::Directory,
                    mode: 0o755,
                    size: 0,
                };
                return Ok(OpenDispatchResult::Directory { metadata, entries });
            }
            _ => {}
        }
        // Rootfs lookup. Tombstoned paths are treated as not-found
        // so O_CREAT can fall through cleanly.
        let rootfs_metadata: Option<RootFsMetadata> = if overlay_deleted {
            None
        } else if let Some(rootfs) = self.rootfs.as_ref() {
            match rootfs.metadata(path) {
                Ok(metadata) => Some(metadata),
                Err(RootFsError::NotFound(_)) => None,
                Err(e) => return Err(crate::dispatch::rootfs_errno(e)),
            }
        } else {
            None
        };
        match rootfs_metadata {
            Some(metadata) => match metadata.kind {
                RootFsEntryKind::File => {
                    if want_create && want_excl {
                        return Err(LINUX_EEXIST);
                    }
                    // Disk-backed overlay (--fs host): the whole rootfs is
                    // materialised on the cap-std scratch, so a writable open
                    // of a rootfs file gets a REAL host fd — writes land on
                    // disk and share across fork. Without this, writes went to
                    // an in-memory copy (invisible to forked children and
                    // never persisted), and renames of rootfs files hit EROFS
                    // (dpkg's status/status-old rewrite failed).
                    if let Some(host_fd) =
                        self.overlay.open_raw_fd(path, writable_request, false, want_trunc)
                    {
                        let size = if want_trunc { 0 } else { metadata.size };
                        let md = RootFsMetadata {
                            path: std::path::Path::new(path).to_path_buf(),
                            kind: RootFsEntryKind::File,
                            mode: metadata.mode,
                            size,
                        };
                        return Ok(OpenDispatchResult::HostFile {
                            host_fd,
                            metadata: md,
                            writable: writable_request,
                        });
                    }
                    // INVARIANT: reaching this branch required reading metadata
                    // from self.rootfs above, so it is necessarily Some here.
                    #[allow(clippy::expect_used)]
                    let mut contents = self
                        .rootfs
                        .as_ref()
                        .expect("rootfs metadata implies rootfs")
                        .read(path)
                        .map_err(|e| crate::dispatch::rootfs_errno(e))?;
                    // Write-promotion: if the caller asked for write
                    // access, copy the rootfs file into the overlay so
                    // subsequent writes land in mutable storage.
                    let writable = if writable_request {
                        if want_trunc {
                            contents.clear();
                        }
                        self.overlay
                            .set_file_contents(path, contents.clone())
                            .map_err(|_| LINUX_EINVAL)?;
                        true
                    } else {
                        false
                    };
                    Ok(OpenDispatchResult::File {
                        metadata,
                        contents,
                        writable,
                    })
                }
                RootFsEntryKind::Directory => {
                    let entries = crate::overlay::layered_directory_entries(
                        self.overlay.as_ref(),
                        self.rootfs.as_ref(),
                        path,
                    )
                    .map_err(|e| crate::dispatch::rootfs_errno(e))?;
                    Ok(OpenDispatchResult::Directory { metadata, entries })
                }
                RootFsEntryKind::Symlink => Err(LINUX_EINVAL),
            },
            None => {
                if want_create {
                    Ok(OpenDispatchResult::NotFoundCreate)
                } else {
                    Err(LINUX_ENOENT)
                }
            }
        }
    }

    /// Layered rename with optional `RENAME_NOREPLACE` semantics.
    /// Walks the overlay-then-rootfs view to find the source,
    /// materialises the destination in the overlay (copying bytes
    /// from the rootfs if needed), then tombstones the source so the
    /// layered view shows it as gone.
    pub fn rename_with_flags(
        &mut self,
        from: &str,
        to: &str,
        no_replace: bool,
    ) -> Result<(), VfsError> {
        let (src_kind, src_contents, src_in_overlay) = match self.overlay.lookup(from) {
            Some(OverlayEntry::Deleted) => return Err(LINUX_ENOENT),
            Some(OverlayEntry::Dir) => (RootFsEntryKind::Directory, None, true),
            Some(OverlayEntry::File(b)) => (RootFsEntryKind::File, Some(b), true),
            None => match self.rootfs.as_ref().and_then(|r| r.symlink_metadata(from).ok()) {
                Some(md) => match md.kind {
                    RootFsEntryKind::File | RootFsEntryKind::Symlink => {
                        // INVARIANT: this arm is reached only via the
                        // `self.rootfs.as_ref().and_then(..symlink_metadata..)`
                        // match above, which already proved rootfs is Some.
                        #[allow(clippy::expect_used)]
                        let bytes = self
                            .rootfs
                            .as_ref()
                            .expect("rootfs metadata implies rootfs")
                            .read(from)
                            .map_err(|e| crate::dispatch::rootfs_errno(e))?;
                        (RootFsEntryKind::File, Some(bytes), false)
                    }
                    RootFsEntryKind::Directory => (RootFsEntryKind::Directory, None, false),
                },
                None => return Err(LINUX_ENOENT),
            },
        };
        let dst_exists = match self.overlay.lookup(to) {
            Some(OverlayEntry::Deleted) => false,
            Some(OverlayEntry::Dir) | Some(OverlayEntry::File(_)) => true,
            None => self
                .rootfs
                .as_ref()
                .map(|r| r.symlink_metadata(to).is_ok())
                .unwrap_or(false),
        };
        if dst_exists && no_replace {
            return Err(LINUX_EEXIST);
        }
        // Prefer the backend's real rename first. For a writable
        // backend (host: cap-std `dir.rename`; memory: in-place map
        // move) this atomically relocates the WHOLE entry — including a
        // directory's entire subtree/contents — and reports Ok(true)
        // when the source actually lived in the backend. A real
        // directory rename on disk also removes the source, which is
        // exactly the Linux semantics the conformance probe checks
        // (source gone, contents moved). Only fall back to the
        // copy/materialise + tombstone path when the source was NOT in
        // the writable backend (Ok(false)) — e.g. a pure-rootfs entry
        // under --fs memory.
        match self.overlay.rename_overlay_entry(from, to) {
            Ok(true) => {
                // Backend moved the entry (contents included). If the
                // rootfs ALSO has the source path, leave a tombstone so
                // the layered view doesn't resurrect the rootfs copy.
                let rootfs_has_src = self
                    .rootfs
                    .as_ref()
                    .map(|r| r.symlink_metadata(from).is_ok())
                    .unwrap_or(false);
                if rootfs_has_src {
                    self.overlay.mark_deleted(from).map_err(|_| LINUX_EINVAL)?;
                }
                return Ok(());
            }
            Ok(false) => {}
            Err(_) => return Err(LINUX_EINVAL),
        }

        // Fallback: source is not owned by the writable backend
        // (rootfs-only entry). Materialise the destination, then
        // tombstone the rootfs source.
        match src_kind {
            RootFsEntryKind::File | RootFsEntryKind::Symlink => {
                self.overlay
                    .set_file_contents(to, src_contents.unwrap_or_default())
                    .map_err(|_| LINUX_EINVAL)?;
            }
            RootFsEntryKind::Directory => {
                self.overlay.make_dir(to).map_err(|_| LINUX_EINVAL)?;
            }
        }
        if src_in_overlay {
            self.overlay.remove_entry(from);
        }
        let rootfs_has_src = self
            .rootfs
            .as_ref()
            .map(|r| r.symlink_metadata(from).is_ok())
            .unwrap_or(false);
        if rootfs_has_src {
            self.overlay
                .mark_deleted(from)
                .map_err(|_| LINUX_EINVAL)?;
        }
        Ok(())
    }

    /// Layered "is this path a directory" check. Used by the
    /// dispatcher to validate mkdir/rename parent paths.
    pub fn is_directory(&self, path: &str) -> bool {
        match self.overlay.lookup(path) {
            Some(OverlayEntry::Dir) => return true,
            Some(OverlayEntry::File(_)) => return false,
            Some(OverlayEntry::Deleted) => return false,
            None => {}
        }
        self.rootfs
            .as_ref()
            .and_then(|r| r.metadata(path).ok())
            .map(|m| m.kind == RootFsEntryKind::Directory)
            .unwrap_or(false)
    }
}

impl Default for RootFsVfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs for RootFsVfs {
    /// Overlay-first lookup. The writable overlay shadows the
    /// rootfs for tombstoned paths and overlay-owned entries; if
    /// neither layer has the path, return ENOENT.
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        // The filesystem root always exists as a directory. Resolve it
        // here so root-relative metadata (statfs("/"), open("/"),
        // mkdir parent checks) works regardless of whether the rootfs
        // layer is present — under `--fs host` it is dropped after the
        // disk is seeded, and the host backend deliberately refuses to
        // treat its sandbox root as a lookupable entry.
        if path.is_empty() || path == "/" {
            return Ok(Metadata {
                kind: EntryKind::Directory,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        if let Some(entry) = self.overlay.lookup(path) {
            // Prefer the backend's own metadata (the host backend
            // reads real on-disk mode bits, so executables keep their
            // 0o111). Fall back to defaults only if the backend can't
            // produce metadata for an entry it just reported.
            let backend_md = self.overlay.metadata(path);
            match entry {
                OverlayEntry::Deleted => return Err(LINUX_ENOENT),
                OverlayEntry::Dir => {
                    return Ok(Metadata {
                        kind: EntryKind::Directory,
                        mode: backend_md.map(|m| m.mode).unwrap_or(0o755),
                        size: 0,
                        uid: 0,
                        gid: 0,
                        mtime_secs: 0,
                        mtime_nanos: 0,
                    });
                }
                OverlayEntry::File(bytes) => {
                    return Ok(Metadata {
                        kind: EntryKind::File,
                        mode: backend_md.map(|m| m.mode).unwrap_or(0o644),
                        size: bytes.len() as u64,
                        uid: 0,
                        gid: 0,
                        mtime_secs: 0,
                        mtime_nanos: 0,
                    });
                }
            }
        }
        let rootfs = self.rootfs.as_ref().ok_or(LINUX_ENOENT)?;
        let md = rootfs.metadata(path).map_err(|_| LINUX_ENOENT)?;
        Ok(Metadata {
            kind: match md.kind {
                RootFsEntryKind::File => EntryKind::File,
                RootFsEntryKind::Directory => EntryKind::Directory,
                RootFsEntryKind::Symlink => EntryKind::Symlink,
            },
            mode: md.mode,
            size: md.size as u64,
            uid: 0,
            gid: 0,
            mtime_secs: 0,
            mtime_nanos: 0,
        })
    }

    fn readlink(&self, path: &str) -> Result<std::path::PathBuf, VfsError> {
        // A symlink materialised in the writable overlay (cap-std on
        // --fs host, where the rootfs layer is dropped after seeding).
        if let Some(target) = self.overlay.read_link(path) {
            return Ok(std::path::PathBuf::from(target));
        }
        // A symlink in the immutable rootfs layer (present for --fs memory).
        if let Some(rootfs) = self.rootfs.as_ref() {
            match rootfs.read_link(path) {
                Ok(target) => return Ok(std::path::PathBuf::from(target)),
                Err(crate::rootfs::RootFsError::NotFound(_)) => {}
                Err(_) => return Err(LINUX_ENOENT),
            }
        }
        // Not a symlink in either layer. Linux readlink(2) distinguishes
        // EINVAL (the path EXISTS but isn't a symlink) from ENOENT (no
        // such path) — apt's realpath()/flAbsPath relies on this. Consult
        // the layered view so an existing regular file/dir on the disk
        // overlay yields EINVAL even with the rootfs layer dropped.
        if self.lookup(path).is_ok() {
            Err(crate::linux_abi::LINUX_EINVAL)
        } else {
            Err(LINUX_ENOENT)
        }
    }

    fn open(
        &mut self,
        path: &str,
        flags: OpenFlags,
        _ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        // Overlay-first: bytes-backed File entries.
        if let Some(entry) = self.overlay.lookup(path) {
            match entry {
                OverlayEntry::Deleted => return Err(LINUX_ENOENT),
                OverlayEntry::Dir => return Err(LINUX_EISDIR),
                OverlayEntry::File(contents) => {
                    if flags.excl && flags.create {
                        return Err(LINUX_EEXIST);
                    }
                    let mut contents = contents;
                    if flags.trunc {
                        contents.clear();
                        if self
                            .overlay
                            .set_file_contents(path, contents.clone())
                            .is_err()
                        {
                            return Err(crate::linux_abi::LINUX_EINVAL);
                        }
                    }
                    return Ok(VfsHandle::Bytes {
                        path: path.to_string(),
                        contents,
                        status_flags: 0,
                    });
                }
            }
        }
        // Rootfs fallthrough — read-only for now.
        if flags.write {
            return Err(LINUX_EROFS);
        }
        let rootfs = self.rootfs.as_ref().ok_or(LINUX_ENOENT)?;
        let bytes = rootfs.read(path).map_err(|_| LINUX_ENOENT)?;
        Ok(VfsHandle::Bytes {
            path: path.to_string(),
            contents: bytes,
            status_flags: 0,
        })
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEnt>, VfsError> {
        // Layered readdir: rootfs entries minus overlay tombstones,
        // plus overlay-owned entries. Reuse the existing helper.
        match crate::overlay::layered_directory_entries(
            self.overlay.as_ref(),
            self.rootfs.as_ref(),
            path,
        ) {
            Ok(entries) => Ok(entries
                .into_iter()
                .map(|e| DirEnt {
                    name: e.name,
                    kind: match e.metadata.kind {
                        RootFsEntryKind::File => EntryKind::File,
                        RootFsEntryKind::Directory => EntryKind::Directory,
                        RootFsEntryKind::Symlink => EntryKind::Symlink,
                    },
                })
                .collect()),
            Err(_) => Err(LINUX_ENOTDIR),
        }
    }

    fn mkdir(&mut self, path: &str, _mode: u32) -> Result<(), VfsError> {
        // Layered EEXIST: an existing overlay or rootfs entry (file
        // or dir) at `path` blocks mkdir. A tombstone clears the
        // rootfs view so a re-create is allowed.
        match self.overlay.lookup(path) {
            Some(OverlayEntry::Dir) | Some(OverlayEntry::File(_)) => {
                return Err(LINUX_EEXIST);
            }
            Some(OverlayEntry::Deleted) => {}
            None => {
                if let Some(rootfs) = self.rootfs.as_ref() {
                    if rootfs.metadata(path).is_ok() {
                        return Err(LINUX_EEXIST);
                    }
                }
            }
        }
        // Parent must exist as a directory in the layered view.
        if let Some(parent) = std::path::Path::new(path).parent() {
            let parent_str = parent.to_string_lossy();
            let parent_str: &str = if parent_str.is_empty() {
                "/"
            } else {
                parent_str.as_ref()
            };
            if !self.is_directory(parent_str) {
                return Err(LINUX_ENOENT);
            }
        }
        self.overlay
            .make_dir(path)
            .map_err(|_| crate::linux_abi::LINUX_EINVAL)
    }

    fn unlink(&mut self, path: &str) -> Result<(), VfsError> {
        // Layered: overlay first (a tombstone short-circuits to
        // ENOENT). Then rootfs via symlink_metadata so symlinks are
        // identified as such (not followed).
        let (kind, in_overlay, in_rootfs) = match self.overlay.lookup(path) {
            Some(OverlayEntry::Deleted) => return Err(LINUX_ENOENT),
            Some(OverlayEntry::Dir) => (RootFsEntryKind::Directory, true, false),
            Some(OverlayEntry::File(_)) => (RootFsEntryKind::File, true, false),
            None => match self.rootfs.as_ref().and_then(|r| r.symlink_metadata(path).ok()) {
                Some(md) => (md.kind, false, true),
                None => return Err(LINUX_ENOENT),
            },
        };
        if matches!(kind, RootFsEntryKind::Directory) {
            return Err(LINUX_EISDIR);
        }
        if in_overlay {
            self.overlay.remove_entry(path);
            // Tombstone only if the rootfs also has this path, so a
            // re-create still works.
            let rootfs_has_it = self
                .rootfs
                .as_ref()
                .map(|r| r.symlink_metadata(path).is_ok())
                .unwrap_or(false);
            if rootfs_has_it {
                self.overlay
                    .mark_deleted(path)
                    .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
            }
        } else if in_rootfs {
            self.overlay
                .mark_deleted(path)
                .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
        }
        Ok(())
    }

    fn rmdir(&mut self, path: &str) -> Result<(), VfsError> {
        let (kind, in_overlay, in_rootfs) = match self.overlay.lookup(path) {
            Some(OverlayEntry::Deleted) => return Err(LINUX_ENOENT),
            Some(OverlayEntry::Dir) => (RootFsEntryKind::Directory, true, false),
            Some(OverlayEntry::File(_)) => (RootFsEntryKind::File, true, false),
            None => match self.rootfs.as_ref().and_then(|r| r.symlink_metadata(path).ok()) {
                Some(md) => (md.kind, false, true),
                None => return Err(LINUX_ENOENT),
            },
        };
        if !matches!(kind, RootFsEntryKind::Directory) {
            return Err(LINUX_ENOTDIR);
        }
        // Linux rmdir(2) requires the directory to be empty (ENOTEMPTY
        // otherwise). The layered view must show no surviving children:
        // overlay-owned entries plus rootfs entries that aren't tombstoned.
        if let Ok(entries) = crate::overlay::layered_directory_entries(
            self.overlay.as_ref(),
            self.rootfs.as_ref(),
            path,
        ) {
            if !entries.is_empty() {
                return Err(LINUX_ENOTEMPTY);
            }
        }
        if in_overlay {
            self.overlay.remove_entry(path);
            let rootfs_has_it = self
                .rootfs
                .as_ref()
                .map(|r| r.symlink_metadata(path).is_ok())
                .unwrap_or(false);
            if rootfs_has_it {
                self.overlay
                    .mark_deleted(path)
                    .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
            }
        } else if in_rootfs {
            self.overlay
                .mark_deleted(path)
                .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
        }
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), VfsError> {
        self.rename_with_flags(from, to, false)
    }

    fn truncate(&mut self, path: &str, len: u64) -> Result<(), VfsError> {
        // Materialise the file into the overlay (if it's only in
        // rootfs), then truncate.
        let mut contents = match self.overlay.lookup(path) {
            Some(OverlayEntry::Deleted) => return Err(LINUX_ENOENT),
            Some(OverlayEntry::Dir) => return Err(LINUX_EISDIR),
            Some(OverlayEntry::File(b)) => b,
            None => self
                .rootfs
                .as_ref()
                .ok_or(LINUX_ENOENT)?
                .read(path)
                .map_err(|_| LINUX_ENOENT)?,
        };
        contents.truncate(len as usize);
        contents.resize(len as usize, 0);
        self.overlay
            .set_file_contents(path, contents)
            .map_err(|_| LINUX_EACCES)
    }

    fn name(&self) -> &'static str {
        "rootfs"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rootfs::LayerSource;
    use tar::{Builder, EntryType, Header};

    fn rootfs_with_files() -> RootFs {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut builder = Builder::new(&mut buf);
            for dir in ["etc", "usr", "usr/bin"] {
                let mut h = Header::new_gnu();
                h.set_path(format!("{}/", dir)).unwrap();
                h.set_entry_type(EntryType::Directory);
                h.set_size(0);
                h.set_mode(0o755);
                h.set_cksum();
                builder.append(&h, std::io::empty()).unwrap();
            }
            let entries: &[(&str, &[u8], u32)] = &[
                ("etc/hosts", b"127.0.0.1\tlocalhost\n", 0o644),
                ("usr/bin/true", b"#!/bin/sh\n", 0o755),
            ];
            for (path, body, mode) in entries {
                let mut h = Header::new_gnu();
                h.set_path(path).unwrap();
                h.set_size(body.len() as u64);
                h.set_mode(*mode);
                h.set_cksum();
                builder.append(&h, *body).unwrap();
            }
            builder.finish().unwrap();
        }
        RootFs::from_layers(std::iter::once(LayerSource::Tar(buf))).unwrap()
    }

    #[test]
    fn lookup_rootfs_file() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        let md = v.lookup("/etc/hosts").unwrap();
        assert_eq!(md.kind, EntryKind::File);
        assert!(md.size > 0);
    }

    #[test]
    fn lookup_rootfs_dir() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        let md = v.lookup("/etc").unwrap();
        assert_eq!(md.kind, EntryKind::Directory);
    }

    #[test]
    fn lookup_missing_is_enoent() {
        let v = RootFsVfs::with_rootfs(rootfs_with_files());
        assert_eq!(v.lookup("/no-such"), Err(LINUX_ENOENT));
    }

    #[test]
    fn open_rootfs_file_returns_bytes() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        let h = v
            .open(
                "/etc/hosts",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { contents, .. } => {
                assert!(String::from_utf8_lossy(&contents).contains("localhost"));
            }
            other => panic!("expected Bytes, got {:?}", other),
        }
    }

    #[test]
    fn open_write_to_rootfs_only_is_erofs() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        let result = v.open(
            "/etc/hosts",
            OpenFlags {
                write: true,
                ..Default::default()
            },
            &OpenContext::default(),
        );
        assert_eq!(result, Err(LINUX_EROFS));
    }

    #[test]
    fn overlay_shadows_rootfs() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay
            .set_file_contents("/etc/hosts", b"10.0.0.1 myhost\n".to_vec())
            .unwrap();
        let h = v
            .open(
                "/etc/hosts",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { contents, .. } => {
                let s = String::from_utf8_lossy(&contents);
                assert!(s.contains("myhost"), "got: {:?}", s);
                assert!(!s.contains("localhost"), "rootfs leaked through overlay: {:?}", s);
            }
            other => panic!("expected Bytes, got {:?}", other),
        }
    }

    #[test]
    fn tombstone_shadows_rootfs() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay.mark_deleted("/etc/hosts").unwrap();
        assert_eq!(v.lookup("/etc/hosts"), Err(LINUX_ENOENT));
    }

    #[test]
    fn unlink_tombstones_rootfs_path() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.unlink("/etc/hosts").unwrap();
        assert_eq!(v.lookup("/etc/hosts"), Err(LINUX_ENOENT));
    }

    #[test]
    fn unlink_dir_returns_eisdir() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        assert_eq!(v.unlink("/etc"), Err(LINUX_EISDIR));
    }

    #[test]
    fn unlink_missing_returns_enoent() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        assert_eq!(v.unlink("/no-such"), Err(LINUX_ENOENT));
    }

    #[test]
    fn mkdir_then_lookup() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.mkdir("/tmp", 0o755).unwrap();
        let md = v.lookup("/tmp").unwrap();
        assert_eq!(md.kind, EntryKind::Directory);
    }

    #[test]
    fn readdir_layered() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        // Add an overlay-owned file.
        v.mkdir("/etc/extras", 0o755).unwrap();
        let entries = v.readdir("/etc").unwrap();
        let names: std::collections::BTreeSet<_> =
            entries.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains("hosts"));
        assert!(names.contains("extras"));
    }

    #[test]
    fn rename_overlay_file_to_new_path() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay
            .set_file_contents("/etc/source", b"hello\n".to_vec())
            .unwrap();
        v.rename_with_flags("/etc/source", "/etc/dest", false).unwrap();
        assert_eq!(v.lookup("/etc/source"), Err(LINUX_ENOENT));
        let md = v.lookup("/etc/dest").unwrap();
        assert_eq!(md.kind, EntryKind::File);
        assert_eq!(md.size, 6);
    }

    #[test]
    fn rename_rootfs_file_promotes_into_overlay() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.rename_with_flags("/etc/hosts", "/etc/renamed_hosts", false)
            .unwrap();
        // Source tombstoned in overlay.
        assert_eq!(v.lookup("/etc/hosts"), Err(LINUX_ENOENT));
        // Destination has the same content as the original rootfs file.
        let md = v.lookup("/etc/renamed_hosts").unwrap();
        assert_eq!(md.kind, EntryKind::File);
        assert!(md.size > 0);
    }

    #[test]
    fn rename_with_no_replace_rejects_existing() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay
            .set_file_contents("/etc/source", b"x".to_vec())
            .unwrap();
        // /etc/hosts already exists in the rootfs.
        let result = v.rename_with_flags("/etc/source", "/etc/hosts", true);
        assert_eq!(result, Err(LINUX_EEXIST));
    }

    #[test]
    fn rename_missing_source_is_enoent() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        let result = v.rename_with_flags("/etc/no-such", "/etc/dest", false);
        assert_eq!(result, Err(LINUX_ENOENT));
    }

    #[test]
    fn open_for_dispatch_overlay_file() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay
            .set_file_contents("/etc/scratch", b"overlay\n".to_vec())
            .unwrap();
        let result = v
            .open_for_dispatch("/etc/scratch", false, false, false, true)
            .unwrap();
        match result {
            OpenDispatchResult::File { contents, writable, .. } => {
                assert_eq!(String::from_utf8_lossy(&contents), "overlay\n");
                assert!(writable);
            }
            _ => panic!("expected File"),
        }
    }

    #[test]
    fn open_for_dispatch_rootfs_file_with_writable_promotes() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        let result = v
            .open_for_dispatch("/etc/hosts", false, false, false, true)
            .unwrap();
        match result {
            OpenDispatchResult::File { writable, .. } => assert!(writable),
            _ => panic!("expected File"),
        }
        // Promotion happened: the overlay now has /etc/hosts.
        assert!(matches!(
            v.overlay.lookup("/etc/hosts"),
            Some(OverlayEntry::File(_))
        ));
    }

    #[test]
    fn open_for_dispatch_directory_returns_layered_entries() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.mkdir("/etc/extras", 0o755).unwrap();
        let result = v
            .open_for_dispatch("/etc", false, false, false, false)
            .unwrap();
        match result {
            OpenDispatchResult::Directory { entries, .. } => {
                let names: std::collections::BTreeSet<_> =
                    entries.iter().map(|e| e.name.clone()).collect();
                assert!(names.contains("hosts"));
                assert!(names.contains("extras"));
            }
            _ => panic!("expected Directory"),
        }
    }

    #[test]
    fn open_for_dispatch_not_found_create_signals_caller() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        let result = v
            .open_for_dispatch("/etc/new", true, false, false, true)
            .unwrap();
        assert!(matches!(result, OpenDispatchResult::NotFoundCreate));
    }

    #[test]
    fn open_for_dispatch_excl_on_existing_is_eexist() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        let result = v.open_for_dispatch("/etc/hosts", true, true, false, true);
        assert_eq!(result.err(), Some(LINUX_EEXIST));
    }

    #[test]
    fn mkdir_layered_eexist() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        // Rootfs has /etc; mkdir of an existing path is EEXIST.
        assert_eq!(v.mkdir("/etc", 0o755), Err(LINUX_EEXIST));
    }

    #[test]
    fn mkdir_no_parent_is_enoent() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        assert_eq!(v.mkdir("/no-such-parent/sub", 0o755), Err(LINUX_ENOENT));
    }

    #[test]
    fn is_directory_layered() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        assert!(v.is_directory("/etc"));
        assert!(!v.is_directory("/etc/hosts"));
        assert!(!v.is_directory("/no-such"));
        v.mkdir("/var/tmp", 0o755).unwrap_or_default();
    }

    #[test]
    fn open_overlay_trunc_clears_bytes() {
        let mut v = RootFsVfs::with_rootfs(rootfs_with_files());
        v.overlay
            .set_file_contents("/etc/hosts", b"original\n".to_vec())
            .unwrap();
        let h = v
            .open(
                "/etc/hosts",
                OpenFlags {
                    write: true,
                    trunc: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { contents, .. } => assert!(contents.is_empty()),
            other => panic!("expected Bytes, got {:?}", other),
        }
        // Confirm the overlay was also truncated.
        let md = v.lookup("/etc/hosts").unwrap();
        assert_eq!(md.size, 0);
    }
}
