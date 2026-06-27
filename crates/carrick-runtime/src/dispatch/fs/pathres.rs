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

    /// Like `canonicalize_following`, but a final component that resolves to a
    /// MISSING path returns that resolved path (Ok) instead of ENOENT — for the
    /// `open(O_CREAT)` case. Linux follows a trailing (even DANGLING) symlink and
    /// creates the TARGET: `open(broken_symlink, O_CREAT|O_WRONLY)` makes the
    /// link's target file, leaving the link resolving to it (zipfile/tarfile
    /// overwrite of a broken symlink as a file). Only the O_CREAT path uses this;
    /// a plain open still gets ENOENT for a broken symlink via
    /// `canonicalize_following`.
    pub(super) fn canonicalize_following_allow_missing(&self, path: &str) -> Result<String, i32> {
        let mut cur = path.to_string();
        for _ in 0..40 {
            let md = match self.layered_lstat(&cur) {
                Ok(md) => md,
                // Resolved to a not-yet-existent path (the link's missing target,
                // or a brand-new file): O_CREAT will create it HERE.
                Err(e) if e == crate::linux_abi::LINUX_ENOENT => return Ok(cur),
                Err(e) => return Err(e),
            };
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

    /// Linux caps the TOTAL symlinks followed in a SINGLE pathname resolution at
    /// MAXSYMLINKS (40); exceeding it is ELOOP. carrick resolves each intermediate
    /// symlink with its OWN 40-hop cap (`canonicalize_following` /
    /// `resolve_intermediate_symlinks` run per component), so a path that STACKS
    /// many shallow intermediate symlinks never accumulates to the cap and wrongly
    /// resolves. LTP's ELOOP cases (stat03/lstat02/truncate03/readlink03/open13)
    /// build exactly that: a `test_eloop` directory holding `test_eloop ->
    /// ../test_eloop`, with the path repeating `test_eloop` ~43 times — each hop is
    /// a single follow that the per-component resolvers reset. Walk the path once,
    /// following each component's symlink chain against a SHARED budget, and report
    /// a cumulative overflow. Only the slow (symlink-bearing) resolution path calls
    /// this, so symlink-free lookups pay nothing. Resolves entirely through the
    /// layered view (not the host), so it isn't bounded by the host's own
    /// MAXSYMLINKS (FreeBSD's 32 < Linux's 40).
    pub(super) fn symlink_follow_budget_exceeded(&self, abs: &str) -> bool {
        // Only INTERMEDIATE components are followed here — the FINAL component's
        // symlink is the caller's to interpret (lstat/readlink READ it; stat
        // follows it via canonicalize_following). Following the final here would
        // wrongly ELOOP an lstat/readlink of a self-referential link (lstat02,
        // readlink03, truncate03's cases that pass a trailing self-link).
        let comps: Vec<&str> = abs
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .collect();
        if comps.len() < 2 {
            return false;
        }
        let mut follows = 0usize;
        let mut base = String::new();
        for comp in &comps[..comps.len() - 1] {
            if *comp == ".." {
                if let Some(i) = base.rfind('/') {
                    base.truncate(i);
                }
                continue;
            }
            let mut cur = format!("{base}/{comp}");
            // Follow this component's symlink chain; every hop counts against the
            // SHARED budget. A self-referential link keeps `cur` fixed, so the
            // budget — not a position change — is what terminates the walk.
            while let Ok(md) = self.layered_lstat(&cur) {
                if md.kind != RootFsEntryKind::Symlink {
                    break;
                }
                follows += 1;
                if follows > 40 {
                    return true;
                }
                let Some(target) = self.readlink_layered(&cur) else {
                    return false;
                };
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
            base = cur;
        }
        false
    }
}
