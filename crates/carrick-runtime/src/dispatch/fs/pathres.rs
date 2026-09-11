//! Layered path resolution helpers split out of dispatch/fs.rs (WS-F3):
//! directory probing, overlay metadata/lstat, symlink readlink, and
//! symlink-following canonicalization across the rootfs layers. Pure
//! `impl SyscallDispatcher` move.
use super::*;
use crate::linux_abi::LinuxErrno;
use std::path::Path;

/// Recursion budget shared by `canonicalize_following` and the symlink-aware
/// `..` walk it calls.
///
/// The two are mutually recursive: expanding a symlink whose target contains
/// `..` needs a symlink-aware walk, and that walk canonicalizes each symlink
/// intermediate it meets. A cycle like `a -> b/..`, `b -> a/..` would otherwise
/// recurse until the stack died — and LTP's ELOOP cases stack ~43 links on
/// purpose (`stat03`, `lstat02`, `truncate03`). Past Linux's MAXSYMLINKS the
/// answer is ELOOP, which is also what Linux reports.
const DOTDOT_RESOLVE_MAX_DEPTH: u32 = 40;

thread_local! {
    static DOTDOT_RESOLVE_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

struct DotdotDepthGuard;

impl DotdotDepthGuard {
    /// Enter one level, or `None` once the budget is spent.
    fn enter() -> Option<Self> {
        DOTDOT_RESOLVE_DEPTH.with(|depth| {
            if depth.get() >= DOTDOT_RESOLVE_MAX_DEPTH {
                return None;
            }
            depth.set(depth.get() + 1);
            Some(Self)
        })
    }
}

impl Drop for DotdotDepthGuard {
    fn drop(&mut self) {
        DOTDOT_RESOLVE_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

#[cfg(test)]
pub(crate) struct ExecutorBoundaryPathTestGuard(DotdotDepthGuard);

impl SyscallDispatcher {
    /// True only after every recursive path-resolution guard on the current
    /// executor pthread has unwound.
    pub(crate) fn executor_boundary_path_resolution_is_clear() -> bool {
        DOTDOT_RESOLVE_DEPTH.with(|depth| depth.get() == 0)
    }

    #[cfg(test)]
    pub(crate) fn with_dirty_executor_boundary_path_resolution_for_test<R>(
        operation: impl FnOnce() -> R,
    ) -> R {
        let _guard = DotdotDepthGuard::enter().expect("enter test path-resolution depth");
        operation()
    }

    #[cfg(test)]
    pub(crate) fn dirty_executor_boundary_path_guard_for_test() -> ExecutorBoundaryPathTestGuard {
        ExecutorBoundaryPathTestGuard(
            DotdotDepthGuard::enter().expect("enter persistent test path-resolution depth"),
        )
    }

    /// Layered "is this a directory?" probe used by mkdirat / openat
    /// (O_CREAT) parent-existence checks. The synthetic /proc and
    /// /sys roots count as directories so that
    /// `mkdir("/proc/.tmp-XYZ")` can be detected as EEXIST rather
    /// than the wrong errno.
    pub(super) fn path_is_directory(&self, path: &str) -> bool {
        if path == "/" || path.is_empty() {
            return true;
        }
        if let Some(m) = self.fs.vfs_mounts.resolve(path)
            && let Ok(md) = m.vfs.lookup(&m.full_path)
        {
            return md.kind == crate::vfs::EntryKind::Directory;
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
    pub(crate) fn layered_metadata(&self, path: &str) -> Result<RootFsMetadata, LinuxErrno> {
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
    pub(crate) fn layered_lstat(&self, path: &str) -> Result<RootFsMetadata, LinuxErrno> {
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

    /// Join a relative symlink TARGET onto the directory holding the link.
    ///
    /// A `..` inside the target must be applied AFTER resolving what precedes
    /// it: for `parent -> current/..` with `current -> .`, Linux resolves
    /// `current` to the directory holding it and then climbs, landing in that
    /// directory's PARENT. `join_rootfs_path` collapses `..` LEXICALLY, cancelling
    /// it against `current` and landing back where it started — which sent
    /// CPython's `test_tarfile.test_parent_symlink` extraction to
    /// `outerdir/dest/evil` where Linux writes `outerdir/evil`. (The same
    /// lexical-collapse bug is already called out at the `..` guard in
    /// `resolve_at_path`, but that guard only fires when the INPUT path contains
    /// `..`; here it is inside the link's target.)
    ///
    /// Targets without `..` keep the cheap lexical join, which is almost all of
    /// them.
    fn join_symlink_target(&self, parent: &str, target: &str) -> Result<String, LinuxErrno> {
        if !target.split('/').any(|c| c == "..") {
            return Ok(join_rootfs_path(parent, target));
        }
        match DotdotDepthGuard::enter() {
            Some(_guard) => self.resolve_dotdot_symlink_aware(parent, target),
            None => Err(crate::linux_abi::LINUX_ELOOP),
        }
    }

    pub(crate) fn canonicalize_following(&self, path: &str) -> Result<String, LinuxErrno> {
        let mut cur = path.to_string();
        for _ in 0..40 {
            let md = self.layered_lstat(&cur)?;
            if md.kind != RootFsEntryKind::Symlink {
                return Ok(cur);
            }
            let target = self
                .readlink_layered(&cur)
                .ok_or(crate::linux_abi::LINUX_ENOENT)?;
            let source = cur;
            let next = if target.starts_with('/') {
                join_rootfs_path("/", &target)
            } else {
                let parent = Path::new(&source)
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "/".to_string());
                self.join_symlink_target(&parent, &target)?
            };
            // A final symlink can expand to itself or below itself
            // (`link -> link/inside`). The next host lstat then sees the link as
            // an intermediate component and may collapse the cycle to ENOENT.
            // Reject the recursive prefix before crossing that host boundary.
            if next == source
                || next
                    .strip_prefix(&source)
                    .is_some_and(|suffix| suffix.starts_with('/'))
            {
                return Err(crate::linux_abi::LINUX_ELOOP);
            }
            cur = next;
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
    pub(super) fn canonicalize_following_allow_missing(
        &self,
        path: &str,
    ) -> Result<String, LinuxErrno> {
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
                self.join_symlink_target(&parent, &target)?
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

    pub(in crate::dispatch) fn resolve_at_path(
        &self,
        dirfd: u64,
        path: &str,
    ) -> Result<String, LinuxErrno> {
        // Cache only AT_FDCWD absolute paths: their resolution is independent of
        // the cwd and of any dirfd, so the guest path string alone is a complete
        // key. (Relative / dirfd-anchored paths would need those in the key; they
        // are rare in the syscall-bound hot loops this targets.) The cache is
        // validated against a fork-coherent generation bumped on structural fs
        // mutations, so a create/delete/rename/symlink correctly invalidates it.
        // Only successful resolutions are cached; errors re-resolve.
        // Build a cache key when the resolution is fully determined by the
        // guest path plus (for a relative path) the cwd:
        //   - absolute path      -> the path itself (cwd/dirfd irrelevant)
        //   - AT_FDCWD + relative -> cwd + '\0' + path, so a later chdir keys a
        //     different entry rather than serving a stale one (LTP fuzzy-sync
        //     tests chdir into their tmpdir and pass a relative name).
        // A relative path through a REAL dirfd depends on that fd's directory,
        // so it is not keyed here.
        let is_atfdcwd = (dirfd as i32) as i64 as u64 == LINUX_AT_FDCWD;
        let fs_context = self.captured_fs_context();
        let cache_key: Option<String> = if std::path::Path::new(path).is_absolute() {
            match fs_context.chroot_root().as_deref() {
                Some(root) if root != "/" => Some(format!("{root}\u{0}{path}")),
                _ => Some(path.to_owned()),
            }
        } else if is_atfdcwd {
            Some(format!("{}\u{0}{}", fs_context.cwd(), path))
        } else {
            None
        };
        // Sample the generation at ENTRY, before reading any fs state: a new
        // entry is stamped with this, so a mutation racing our resolve (which
        // bumps to a higher generation) leaves the entry born stale.
        let gen_at_entry = crate::fs_resolve_cache::current_generation();
        if let Some(ref key) = cache_key {
            // Validate the lookup against the FRESH current generation (read
            // now, not `gen_at_entry`) so a mutation between entry and here also
            // invalidates.
            if let Some(hit) = self
                .fs
                .resolve_cache
                .get(key, crate::fs_resolve_cache::current_generation())
            {
                // Still enforce DAC search permission per call — it depends on
                // live creds, not the path structure (a no-op for root, the hot
                // case). The resolution itself is what the cache elides.
                self.check_search_access(&hit)?;
                return Ok(hit);
            }
        }
        let resolved = match self.resolve_at_path_inner(dirfd, path) {
            Ok(resolved) => resolved,
            Err(errno) => {
                // Linux checks search (x) permission on EACH directory as it
                // descends, so a no-search-permission prefix reports EACCES
                // BEFORE a deeper ENOTDIR/ENOENT is discovered. carrick resolves
                // the whole path as host-root first (finding the deeper error),
                // so re-run the guest DAC search check on the input's directory
                // prefix and let an EACCES there take precedence (pathconf02:
                // abs_path = <mode-0 tmpdir>/testfile/testfile_1). No-op for root.
                if (errno == LINUX_ENOTDIR || errno == LINUX_ENOENT)
                    && let Some(abs) = self.absolute_input_path(dirfd, path)
                {
                    self.check_search_access(&abs)?;
                }
                return Err(errno);
            }
        };
        self.check_search_access(&resolved)?;
        if let Some(key) = cache_key {
            self.fs
                .resolve_cache
                .put(key, resolved.clone(), gen_at_entry);
        }
        Ok(resolved)
    }

    /// The lexical absolute form of a guest input path (anchor + path, ".."
    /// collapsed), WITHOUT existence/symlink resolution — used to run the DAC
    /// search-permission walk on a path whose full resolution already failed.
    /// `None` when the dirfd anchor can't be determined (not a directory fd).
    fn absolute_input_path(&self, dirfd: u64, path: &str) -> Option<String> {
        let dirfd = (dirfd as i32) as i64 as u64;
        let fs_context = self.captured_fs_context();
        let (anchor, path) = if Path::new(path).is_absolute() {
            match fs_context.chroot_root().as_deref() {
                Some(root) if root != "/" => (root.to_owned(), path.trim_start_matches('/')),
                _ => ("/".to_string(), path),
            }
        } else if dirfd == LINUX_AT_FDCWD {
            (fs_context.cwd(), path)
        } else {
            match self.open_file(dirfd as i32)?.description.read().as_deref() {
                Some(OpenDescription::Directory { path: dir, .. }) => (dir.clone(), path),
                _ => return None,
            }
        };
        Some(join_rootfs_path(&anchor, path))
    }

    /// Linux DAC search-permission check: resolving a path requires search
    /// (execute) permission on EVERY directory component leading to the final
    /// name. carrick runs every guest op as host-root, so the host kernel never
    /// enforces this — but when the guest has dropped to a non-root euid we
    /// must, or a no-search-permission component wrongly succeeds (lstat02,
    /// stat03, truncate03, readlink03, … all assert EACCES here). Root (euid 0)
    /// holds CAP_DAC_OVERRIDE and is exempt, which is also the hot path: the
    /// overwhelming majority of guests run as root, so this returns immediately.
    pub(super) fn check_search_access(&self, abs: &str) -> Result<(), LinuxErrno> {
        let creds = self.cred_snapshot();
        // fsuid, not euid: setfsuid(2) moves every file-access check onto the
        // fsuid, and capabilities(7) drops CAP_DAC_READ_SEARCH on an fsuid
        // 0 -> nonzero transition. This function already selected its
        // permission class from `creds.fsuid` below while bypassing on
        // `creds.euid` — two identities in one check, so a process that had
        // dropped only its fsuid searched as root.
        if creds.fsuid.is_root() {
            return Ok(());
        }
        let trimmed = abs.trim_end_matches('/');
        let parent = match trimmed.rsplit_once('/') {
            Some((p, _)) if !p.is_empty() => p,
            _ => return Ok(()),
        };
        let mut prefix = String::new();
        for comp in parent.split('/').filter(|c| !c.is_empty()) {
            prefix.push('/');
            prefix.push_str(comp);
            // A missing or non-directory component is ENOENT/ENOTDIR, surfaced
            // by the existence checks elsewhere — not our concern here.
            let Ok(md) = self.layered_metadata(&prefix) else {
                return Ok(());
            };
            if md.kind != RootFsEntryKind::Directory {
                return Ok(());
            }
            let (uid, gid) = self
                .fs
                .rootfs_vfs
                .overlay
                .get_owner(&prefix)
                .unwrap_or((carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT));
            // Pick the permission class: owner, then group, else other. (carrick
            // tracks the primary fsgid, not the full supplementary set — a close
            // approximation that the LTP search-permission cases exercise.)
            let x_bit = if creds.fsuid == uid {
                0o100
            } else if creds.fsgid == gid {
                0o010
            } else {
                0o001
            };
            if md.mode & x_bit == 0 {
                return Err(LINUX_EACCES);
            }
        }
        Ok(())
    }

    pub(super) fn check_directory_search_access(&self, abs: &str) -> Result<(), LinuxErrno> {
        let creds = self.cred_snapshot();
        // fsuid — same rule as `check_search_access`.
        if creds.fsuid.is_root() {
            return Ok(());
        }
        let md = self.layered_metadata(abs)?;
        if md.kind != RootFsEntryKind::Directory {
            return Ok(());
        }
        let (uid, gid) = self
            .fs
            .rootfs_vfs
            .overlay
            .get_owner(abs)
            .unwrap_or((carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT));
        let x_bit = if creds.fsuid == uid {
            0o100
        } else if creds.fsgid == gid {
            0o010
        } else {
            0o001
        };
        if md.mode & x_bit == 0 {
            return Err(LINUX_EACCES);
        }
        Ok(())
    }

    fn resolve_at_path_inner(&self, dirfd: u64, path: &str) -> Result<String, LinuxErrno> {
        // dirfd is an `int` in the kernel ABI: only the low 32 bits are
        // meaningful, and AT_FDCWD (-100) may arrive zero-extended (0xFFFFFF9C)
        // or sign-extended (0xFFFF..FF9C) depending on how the guest libc
        // widened it. Canonicalise via i32 so AT_FDCWD is recognised either
        // way (coreutils `ln` passed the zero-extended form → symlinkat/linkat
        // wrongly treated it as a real fd → EBADF).
        let dirfd = (dirfd as i32) as i64 as u64;
        if path.is_empty() {
            return Ok(path.to_owned());
        }
        // `/dev/fd/N` and `/dev/std{in,out,err}` are Linux symlinks into
        // `/proc/self/fd`; rewrite to that so the magic-fd machinery (open → dup
        // N) serves them. The rewritten path is absolute, so it re-resolves
        // independently of `dirfd`. (Fixes bash process substitution `<(...)`.)
        if let Some(rewritten) = rewrite_dev_fd_alias(path) {
            return self.resolve_at_path(dirfd, &rewritten);
        }
        // ENAMETOOLONG: Linux rejects any single component > NAME_MAX (255) and
        // any total path > PATH_MAX (4096) at resolution time. carrick lacked
        // these limits, so a too-long path SUCCEEDED instead of failing
        // (LTP lstat02/stat03/truncate03/open13/… "returned 0, expected -1").
        check_path_length(path)?;
        // The anchor directory a relative path resolves against (already a real,
        // symlink-free path): "/" for an absolute path, the cwd for AT_FDCWD, else
        // the dirfd's directory.
        let fs_context = self.captured_fs_context();
        let (anchor, path) = if Path::new(path).is_absolute() {
            match fs_context.chroot_root().as_deref() {
                Some(root) if root != "/" => (root.to_owned(), path.trim_start_matches('/')),
                _ => ("/".to_string(), path),
            }
        } else if dirfd == LINUX_AT_FDCWD {
            (fs_context.cwd(), path)
        } else {
            match self.open_file(dirfd as i32).as_ref() {
                Some(open_file) => match open_file.description.read().as_deref() {
                    Some(OpenDescription::Directory { path: dir, .. }) => {
                        // A relative *at op through a dirfd whose directory has
                        // since been removed (rmdir) resolves to ENOENT on Linux:
                        // the open fd persists but its path no longer exists.
                        // carrick keeps the Directory description cached, so
                        // re-verify the anchor still exists in the layered view
                        // (symlinkat01/linkat01 deldirfd cases → ENOENT).
                        if self.layered_metadata(dir).is_err() {
                            return Err(LINUX_ENOENT);
                        }
                        (dir.clone(), path)
                    }
                    _ => return Err(LINUX_ENOTDIR),
                },
                // A valid fd that isn't in the table (e.g. a stdio fd) is still a
                // non-directory, so a relative path can't be anchored to it →
                // ENOTDIR; only a genuinely-invalid fd is EBADF (statx03 uses
                // dfd=1 → ENOTDIR, dfd=-1 → EBADF).
                None if self.fd_is_valid(dirfd as i32) => return Err(LINUX_ENOTDIR),
                None => return Err(LINUX_EBADF),
            }
        };
        // A ".." component must be applied AFTER following any preceding symlink
        // (Linux: "a/.." with a -> b/c lands in b, not lexically at the parent of
        // a). join_rootfs_path collapses ".." LEXICALLY, before symlink
        // resolution, so it gets this wrong. Take a symlink-aware walk only when a
        // ".." is present; the (overwhelmingly common) no-".." path keeps the
        // cheap lexical join + the existing intermediate-symlink rewrite, so the
        // hot path is unchanged. (Go os TestRootConsistency*/dotdot_in_path_after_symlink.)
        if path.split('/').any(|c| c == "..") || anchor.split('/').any(|c| c == "..") {
            return self.resolve_dotdot_symlink_aware(&anchor, path);
        }
        let abs = join_rootfs_path(&anchor, path);
        // Fast path: ONE kernel-walked openat+F_GETPATH of the PARENT chain
        // replaces both per-component O(K²) passes below (validate_intermediate_
        // dirs + resolve_intermediate_symlinks) for the common case — every
        // intermediate exists, is a directory, and involves no symlink or
        // Unicode-alias redirection. Anything non-trivial → the exact slow path.
        match self.fs.rootfs_vfs.overlay.validate_parents_fast(&abs) {
            crate::fs_backend::ParentResolve::AllDirsNoSymlink => return Ok(abs),
            crate::fs_backend::ParentResolve::NotDir => return Err(LINUX_ENOTDIR),
            crate::fs_backend::ParentResolve::Slow => {}
        }
        // ELOOP: Linux caps the CUMULATIVE symlinks followed across the whole path
        // at MAXSYMLINKS (40). carrick's per-component resolvers each cap at 40 but
        // don't share a budget, so a path stacking many shallow intermediate
        // symlinks (LTP stat03/lstat02/truncate03 build `test_eloop -> ../test_eloop`
        // repeated ~43×) would otherwise resolve to a directory instead of failing.
        // Surface the overflow here, on the slow (symlink-bearing) path only.
        if self.symlink_follow_budget_exceeded(&abs) {
            return Err(crate::linux_abi::LINUX_ELOOP);
        }
        // ENOTDIR: an existing intermediate component that is not a directory
        // can't be traversed. carrick previously let the final lookup return
        // ENOENT (or leniently resolved through it). Synthesize ENOTDIR here so
        // `stat("/etc/passwd/foo")` & co match Linux (lstat02/stat03/…).
        self.validate_intermediate_dirs(&abs)?;
        // Collapse intermediate (non-final) directory symlinks so the returned
        // path is symlink-free in its parent chain. Downstream consumers
        // (real_stat via cap-std, layered_metadata, canonicalize_following's
        // final-component follow) cannot traverse an intermediate symlink whose
        // target is absolute (cap-std treats an absolute target as a sandbox
        // escape), so `stat("/link/f")` where `/link -> /realdir` would wrongly
        // return ENOENT. Rewriting to `/realdir/f` matches Linux path
        // resolution. The final component is intentionally NOT followed here —
        // each caller decides lstat-vs-stat semantics (AT_SYMLINK_NOFOLLOW).
        Ok(self.resolve_intermediate_symlinks(&abs))
    }

    /// Resolve a path containing ".." components symlink-AWARE: walk left to
    /// right, FOLLOWING each intermediate symlink before applying "..", so
    /// "a/../c" with `a -> b/c` lands in `b` (then `b/c`), matching Linux — not
    /// the lexical `/c` that `join_rootfs_path` would produce. The FINAL component
    /// is NOT followed (the caller decides lstat-vs-stat). A non-directory
    /// intermediate is ENOTDIR; a symlink cycle propagates ELOOP; a missing
    /// intermediate propagates ENOENT before any later `..` can collapse it.
    /// Only invoked when a ".." is actually present.
    pub(super) fn resolve_dotdot_symlink_aware(
        &self,
        anchor: &str,
        path: &str,
    ) -> Result<String, LinuxErrno> {
        let mut all: Vec<&str> = Vec::new();
        if !Path::new(path).is_absolute() {
            all.extend(anchor.split('/').filter(|c| !c.is_empty() && *c != "."));
        }
        all.extend(path.split('/').filter(|c| !c.is_empty() && *c != "."));

        // `base` is the resolved, symlink-free prefix so far (no trailing slash;
        // empty string == root).
        let mut base = String::new();
        let last = all.len().saturating_sub(1);
        for (i, comp) in all.iter().enumerate() {
            if *comp == ".." {
                // Climb one resolved component (never above root).
                match base.rfind('/') {
                    Some(pos) => base.truncate(pos),
                    None => base.clear(),
                }
                continue;
            }
            let mut candidate = base.clone();
            candidate.push('/');
            candidate.push_str(comp);
            if i == last {
                // Final component: leave it unfollowed for the caller.
                base = candidate;
                break;
            }
            match self.layered_lstat(&candidate) {
                Ok(md) if md.kind == RootFsEntryKind::Symlink => {
                    match self.canonicalize_following(&candidate) {
                        Ok(target) if self.path_is_directory(&target) => {
                            base = target.trim_end_matches('/').to_owned();
                        }
                        // Symlink to a non-directory can't be traversed as an
                        // intermediate; ELOOP/other errors propagate.
                        Ok(_) => return Err(LINUX_ENOTDIR),
                        Err(e) => return Err(e),
                    }
                }
                // A real directory intermediate: descend.
                Ok(md) if md.kind == RootFsEntryKind::Directory => base = candidate,
                // An existing non-directory intermediate (regular file, device,
                // FIFO) can't be traversed → ENOTDIR.
                Ok(_) => return Err(LINUX_ENOTDIR),
                // A missing or otherwise inaccessible intermediate stops path
                // resolution immediately. In particular, `missing/..` is ENOENT
                // on Linux; it must not collapse back to the parent.
                Err(errno) => return Err(errno),
            }
        }
        Ok(if base.is_empty() {
            "/".to_owned()
        } else {
            base
        })
    }

    /// Rewrite `abs` so every intermediate (non-final) directory-symlink
    /// component is replaced by its resolved target, leaving the final
    /// component untouched. Best-effort: a component that doesn't resolve to a
    /// directory (dangling/non-dir symlink, ELOOP) leaves the path from that
    /// point unchanged, so the downstream lookup surfaces the correct
    /// ENOENT/ENOTDIR. Bounded by `canonicalize_following`'s own ELOOP guard.
    pub(super) fn resolve_intermediate_symlinks(&self, abs: &str) -> String {
        let comps: Vec<&str> = abs.split('/').filter(|c| !c.is_empty()).collect();
        if comps.len() < 2 {
            return abs.to_owned();
        }
        let mut base = String::new();
        for comp in &comps[..comps.len() - 1] {
            let mut candidate = base.clone();
            candidate.push('/');
            candidate.push_str(comp);
            match self.layered_lstat(&candidate) {
                Ok(md) if md.kind == RootFsEntryKind::Symlink => {
                    match self.canonicalize_following(&candidate) {
                        Ok(target) if self.path_is_directory(&target) => {
                            base = target.trim_end_matches('/').to_owned();
                        }
                        // Unresolvable/non-dir symlink intermediate: stop
                        // rewriting; leave the rest for the downstream lookup.
                        _ => return abs.to_owned(),
                    }
                }
                // Plain directory (or not-yet-statable): keep walking.
                _ => {
                    base = candidate;
                }
            }
        }
        if let Some(name) = comps.last() {
            base.push('/');
            base.push_str(name);
        }
        if base.is_empty() {
            "/".to_owned()
        } else {
            base
        }
    }

    /// Walk the intermediate (non-final) components of an already-joined
    /// absolute guest path; if any EXISTING intermediate is a non-directory
    /// (regular file / char device), traversing it is ENOTDIR. A missing
    /// intermediate is left alone — the final lookup surfaces ENOENT, which is
    /// correct. Symlink intermediates are followed by the downstream resolver,
    /// so they're not flagged here. Cheap: short-circuits at the first missing
    /// component (so a fresh deep path costs one lookup).
    fn validate_intermediate_dirs(&self, abs: &str) -> Result<(), LinuxErrno> {
        let comps: Vec<&str> = abs.split('/').filter(|c| !c.is_empty()).collect();
        if comps.len() < 2 {
            return Ok(()); // no intermediates
        }
        let mut prefix = String::new();
        for comp in &comps[..comps.len() - 1] {
            prefix.push('/');
            prefix.push_str(comp);
            match self.layered_lstat(&prefix) {
                Ok(md) => match md.kind {
                    RootFsEntryKind::Directory => {}
                    // A symlink intermediate is traversable IFF it resolves to a
                    // directory (Linux follows it). Resolve through the layered
                    // VFS — this handles an absolute in-rootfs target (e.g.
                    // `/tmp/sm_link -> /tmp/sm_real`) that a single-backend
                    // cap-std follow can't (it treats absolute as a sandbox
                    // escape). A symlink to a non-directory (or a dangling one)
                    // is ENOTDIR, matching Linux.
                    RootFsEntryKind::Symlink => match self.canonicalize_following(&prefix) {
                        Ok(target) if self.path_is_directory(&target) => {}
                        // A self-referential / over-deep intermediate symlink is
                        // a CYCLE → ELOOP, not ENOTDIR. canonicalize_following
                        // caps at 40 hops and returns ELOOP; propagate it rather
                        // than collapsing to the non-dir ENOTDIR below
                        // (lstat02/stat03/truncate03/readlink03 assert ELOOP on
                        // an intermediate self-linking component).
                        Err(e) if e == crate::linux_abi::LINUX_ELOOP => return Err(e),
                        _ => return Err(LINUX_ENOTDIR),
                    },
                    // A regular file / char device can't be a path component.
                    _ => return Err(LINUX_ENOTDIR),
                },
                // Intermediate doesn't exist (or isn't statable) → stop; the
                // final resolution returns ENOENT as Linux does.
                Err(_) => return Ok(()),
            }
        }
        Ok(())
    }
}
