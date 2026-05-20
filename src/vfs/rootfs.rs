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

use crate::dispatch::{LINUX_EACCES, LINUX_EEXIST, LINUX_EISDIR, LINUX_ENOENT, LINUX_ENOTDIR, LINUX_EROFS};
use crate::fs_backend::{FsBackend, MemoryBackend, OverlayEntry};
use crate::rootfs::{RootFs, RootFsEntryKind};

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
        if let Some(entry) = self.overlay.lookup(path) {
            match entry {
                OverlayEntry::Deleted => return Err(LINUX_ENOENT),
                OverlayEntry::Dir => {
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
                OverlayEntry::File(bytes) => {
                    return Ok(Metadata {
                        kind: EntryKind::File,
                        mode: 0o644,
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
        let rootfs = self.rootfs.as_ref().ok_or(LINUX_ENOENT)?;
        rootfs
            .read_link(path)
            .map(std::path::PathBuf::from)
            .map_err(|_| LINUX_ENOENT)
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
                            return Err(crate::dispatch::LINUX_EINVAL);
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
        self.overlay
            .make_dir(path)
            .map_err(|_| crate::dispatch::LINUX_EINVAL)
    }

    fn unlink(&mut self, path: &str) -> Result<(), VfsError> {
        // Tombstone in overlay; if rootfs had the path it's now
        // shadow-deleted. Returns ENOENT only if neither layer ever
        // had the path.
        match self.lookup(path) {
            Ok(md) if md.kind == EntryKind::Directory => return Err(LINUX_EISDIR),
            Ok(_) => {}
            Err(_) => return Err(LINUX_ENOENT),
        }
        self.overlay.remove_entry(path);
        self.overlay
            .mark_deleted(path)
            .map_err(|_| crate::dispatch::LINUX_EINVAL)
    }

    fn rmdir(&mut self, path: &str) -> Result<(), VfsError> {
        match self.lookup(path) {
            Ok(md) if md.kind != EntryKind::Directory => return Err(LINUX_ENOTDIR),
            Ok(_) => {}
            Err(_) => return Err(LINUX_ENOENT),
        }
        self.overlay.remove_entry(path);
        self.overlay
            .mark_deleted(path)
            .map_err(|_| crate::dispatch::LINUX_EINVAL)
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
