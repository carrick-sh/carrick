//! Layered path resolution helpers split out of dispatch/fs.rs (WS-F3):
//! directory probing, overlay metadata/lstat, symlink readlink, and
//! symlink-following canonicalization across the rootfs layers. Pure
//! `impl SyscallDispatcher` move.
use super::*;

impl SyscallDispatcher {
    /// Layered "is this a directory?" probe used by mkdirat / openat
    /// (O_CREAT) parent-existence checks. The synthetic /proc and
    /// /sys roots count as directories so that
    /// `mkdir("/proc/.tmp-XYZ")` can be detected as EEXIST rather
    /// than the wrong errno.
    pub(super) fn path_is_directory(&self, path: &str) -> bool {
        if path == "/" || path.is_empty() {
            return true;
        }
        match self.fs.rootfs_vfs.overlay.lookup(path) {
            Some(OverlayEntry::Dir) => return true,
            Some(OverlayEntry::Deleted) | Some(OverlayEntry::File(_)) => return false,
            None => {}
        }
        if let Some(rootfs) = &self.fs.rootfs_vfs.rootfs
            && let Ok(metadata) = rootfs.metadata(path)
        {
            return metadata.kind == RootFsEntryKind::Directory;
        }
        false
    }

    /// Layered metadata probe. Mirrors the rootfs-or-synthetic chain
    /// used by stat / faccessat sites, but consults the overlay first
    /// and respects deletions.
    pub(crate) fn layered_metadata(&self, path: &str) -> Result<RootFsMetadata, i32> {
        use crate::vfs::Vfs as _;
        // Consult the VFS mounts (/dev, /dev/pts, /proc, /sys) FIRST so stat of
        // /dev/ptmx, /dev/pts/N, /dev/tty, and synthetic /proc /sys paths
        // resolves — mirroring the open path (`try_vfs_open`). Previously stat
        // only saw the rootfs, so these mount paths returned ENOENT even though
        // they appeared in readdir and could be opened (which broke e.g.
        // `ttyname(3)` → `tty(1)`, and `ls -l /dev`). A mount miss falls back to
        // the rootfs so image-provided entries still resolve.
        if let Some(m) = self.fs.vfs_mounts.resolve(path)
            && let Ok(md) = m.vfs.lookup(&m.full_path)
        {
            return Ok(vfs_md_to_rootfs_md(path, &md));
        }
        self.fs
            .rootfs_vfs
            .lookup(path)
            .map(|md| vfs_md_to_rootfs_md(path, &md))
    }

    /// Read a symlink's target string through the layered view (writable overlay
    /// first, then rootfs/mounts) — mirrors `readlinkat`. `None` if `path` isn't
    /// a symlink any backend can read.
    pub(super) fn readlink_layered(&self, path: &str) -> Option<String> {
        if let Some(target) = self.fs.rootfs_vfs.overlay.read_link(path) {
            return Some(target);
        }
        use crate::vfs::Vfs as _;
        if let Some(m) = self.fs.vfs_mounts.resolve(path)
            && let Ok(target) = m.vfs.readlink(&m.full_path)
        {
            return Some(target.to_string_lossy().into_owned());
        }
        self.fs
            .rootfs_vfs
            .readlink(path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// Resolve `path` following a trailing symlink chain THROUGH the full VFS
    /// (overlay + mount table), returning the final non-symlink absolute guest
    /// path. The per-backend `real_stat`/`lookup` only follow symlinks within a
    /// single backend, so a symlink in one mount (e.g. a `/tmp` host-scratch
    /// link) whose target lands in another (e.g. a `/run` bind mount) doesn't
    /// resolve — the cause of `chdir`-to-such-a-symlink returning ENOTDIR and
    /// `stat`'s dev/ino mismatching across the boundary (Go os/exec
    /// TestExplicitPWD). We re-resolve each target against the whole VFS.
    /// Bounded by `LINUX_ELOOP`. Follows only the FINAL component; an
    /// intermediate cross-mount symlink is a known, separate limitation.
    /// Layered LSTAT: like `layered_metadata` but does NOT follow a trailing
    /// symlink — reports `Symlink` for a symlink so `canonicalize_following` can
    /// read its target. (`layered_metadata`/`Vfs::lookup` follow, and a
    /// cross-mount symlink they can't follow gets misclassified as a plain
    /// File.) Mounts answer for their subtree; otherwise the overlay-aware
    /// `lookup_nofollow` does.
    pub(crate) fn layered_lstat(&self, path: &str) -> Result<RootFsMetadata, i32> {
        if let Some(m) = self.fs.vfs_mounts.resolve(path)
            && let Ok(md) = m.vfs.lookup_nofollow(&m.full_path)
        {
            return Ok(vfs_md_to_rootfs_md(path, &md));
        }
        self.fs
            .rootfs_vfs
            .lookup_nofollow(path)
            .map(|md| vfs_md_to_rootfs_md(path, &md))
    }

    pub(super) fn canonicalize_following(&self, path: &str) -> Result<String, i32> {
        let mut cur = path.to_string();
        for _ in 0..40 {
            let md = self.layered_lstat(&cur)?;
            if md.kind != RootFsEntryKind::Symlink {
                return Ok(cur);
            }
            let target = self
                .readlink_layered(&cur)
                .ok_or(crate::linux_abi::LINUX_ENOENT)?;
            cur = if target.starts_with('/') {
                join_rootfs_path("/", &target)
            } else {
                let parent = Path::new(&cur)
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "/".to_string());
                join_rootfs_path(&parent, &target)
            };
        }
        Err(crate::linux_abi::LINUX_ELOOP)
    }
}
