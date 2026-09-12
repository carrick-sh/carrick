//! Sandboxed real-filesystem upper layer.
//!
//! [`HostFsBackend`] is a directory-backed filesystem backend rooted in an APFS
//! scratch directory.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::dispatch::HostSyscallResult;
use crate::linux_abi::LinuxErrno;
use crate::rootfs::{RootFs, RootFsDirEntry, RootFsEntryKind, RootFsError, RootFsMetadata};
use carrick_abi::{NsGid, NsUid};

use crate::fs_backend::path::{
    NormalizedRelPath, cstring_from_osstr, dup_host_watch_fd, io_error_to_linux_errno, normalize,
    normalize_raw, open_host_watch_fd,
};
use crate::fs_backend::{
    ArchiveMutationGate, BackendError, FsBackend, HostFdOpen, HostFsReexecAuthority, OverlayEntry,
    OverlayEntryKind, ParentResolve, RealStat, host_open_refusal, io_open_refusal,
};

// ---------------------------------------------------------------------
// HostFsBackend: sandboxed real-filesystem upper layer.
// ---------------------------------------------------------------------

/// Monotonic counter feeding the transient (pre-unlink) name of an
/// `open_anon_fd` O_TMPFILE inode, so concurrent guest threads/processes
/// never collide on the scratch name between create and unlink.
static ANON_FD_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Monotonic suffix for scratch trees retired from the live run namespace.
/// Time and pid make names legible in crash forensics; this counter is the
/// collision authority when two backends retire within the same clock tick.
static SCRATCH_TRASH_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) const SCRATCH_TRASH_PREFIX: &str = ".carrick-trash-";
const LEGACY_SCRATCH_TRASH_PREFIX: &str = ".carrick-reap-";
pub(crate) const SCRATCH_TRASH_DIRECTORY: &str = ".carrick-trash";
const SCRATCH_CLEANUP_QUEUE_DEPTH: usize = 8;
const SCRATCH_SYNC_CLEANUP_LIMIT: usize = 256;

/// Real-filesystem FsBackend rooted at a scratch directory on disk.
///
/// All host syscalls go through a [`std::os::fd::OwnedFd`] root handle and
/// `namei_leaf` resolution that produces `(parent_dir_fd, leaf_name)` pairs.
/// Operations are performed using single host `*at` calls with `O_NOFOLLOW`
/// and `AT_SYMLINK_NOFOLLOW`. Absolute paths, `..` components and symlinks
/// are resolved within Carrick's Linux-rooted namei resolver.
///
/// The backend is purely disk-backed: the `root_fd` handle and live on-disk
/// entries are the single source of truth for what exists. Reads (`lookup`,
/// `metadata`, `file_contents`, `child_names`, ...) go straight to the live
/// scratch tree, and writes land directly there.
///
/// The one piece of in-memory state we keep is `tombstones`: paths the
/// guest deleted that still exist in the read-only rootfs layer
/// underneath. The dispatcher's layered lookup consults this to shadow
/// the rootfs, just like for the memory backend.
// `root_prefix`/`fast_fs`/`cache_pid` drive the macOS `--fs host` fast-stat
// path only; on non-macOS those fields are populated but never read.
#[allow(dead_code)]
pub struct HostFsBackend {
    /// The kernel-rooted sandbox handle. ALL fs operations on the
    /// scratch dir go through this.
    pub(crate) root_fd: std::sync::Arc<std::os::fd::OwnedFd>,
    pub(crate) root_path: PathBuf,
    archive_mutation_gate: ArchiveMutationGate,
    /// Backing `TempDir` so the scratch root is removed when the
    /// backend drops. `Some` for the normal case; `None` if the
    /// caller already owns the lifetime (e.g. tests with a custom
    /// `tempfile::TempDir`).
    _scratch: Option<tempfile::TempDir>,
    /// Cleanup ownership adopted after a native host self-reexec. A TempDir
    /// cannot be reconstructed from a path, so the resumed owner removes this
    /// exact verified scratch explicitly on final process exit.
    _attached_cleanup_path: Option<PathBuf>,
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
    pub(crate) root_prefix: Option<String>,
    /// `--fs host` fast stat path (openat+F_GETPATH instead of cap-std's
    /// per-component walk; see docs/fs-host-capstd-amplification.md) enabled.
    /// Default ON. It was briefly default-off because its extra openat/close
    /// churn per stat AGGRAVATED a fork-quiesce wedge (test_fork1 hung); that
    /// wedge — the forking thread's `others` sibling count going stale-high as
    /// vCPUs exited mid-quiesce — is fixed (runtime.rs recomputes it live), so
    /// the win (test_glob 140s→48s) is on by default.
    pub(crate) fast_fs: bool,
    /// This backend is a freshly-created sparse upper paired with an immutable
    /// lower, so an ENOENT proved while the upper has never contained a symlink
    /// is authoritative. Explicitly carried through native self-reexec; never
    /// inferred from an arbitrary attached directory.
    sparse_upper_fast_miss: bool,
    /// Dir-fd-anchored stat cache. Default ON (`CARRICK_FS_STATCACHE=0` opts out).
    /// Maps a leaf path → a cached `RealStat` + the leaf's identity snapshot
    /// (ino/ctime/mtime/size) + an `OwnedFd` of its CONTAINED parent dir. A
    /// repeat stat revalidates with ONE `fstatat(parent_fd, name, AT_NOFOLLOW)`
    /// (≈1µs) and reuses the cached kind/mode/owner when the identity is
    /// unchanged — replacing the 2 containment `openat`s + the xattr reads, so a
    /// hot path approaches the HVF trap floor (~1.8µs ≈ native; ~55× → ~2.5×
    /// native on perf_disk_meta). The per-hit revalidation catches every
    /// in-place mutation (chmod/chown/write/unlink → re-fill or ENOENT);
    /// clear-on-fork and clear-on-rename cover the in-process structural cases.
    /// RESIDUAL coherence window (the reason it is opt-out, not unconditional):
    /// another carrick process concurrently RENAMING a directory this process has
    /// cached as a parent — that single case can briefly serve a stale path until
    /// eviction. Validated regression-free across the full conformance matrix.
    /// See docs/fs-host-capstd-amplification.md.
    pub(crate) stat_cache: parking_lot::Mutex<std::collections::BTreeMap<PathBuf, StatCacheEntry>>,
    /// **The kernel directory cache** — carrick's own `dcache`, keyed by the
    /// sandbox-relative directory path and holding a CONTAINMENT-PROVEN host
    /// dirfd for each.
    ///
    /// This is the state behind [`Self::dir_fd_for`] and [`Self::namei_leaf`].
    /// Its purpose is that a guest path operation costs ONE host `*at` call on
    /// an already-open parent instead of a resolution of the whole path. The
    /// walk it replaces was the single largest host-syscall source in the
    /// kernel lane: cap-std's `manually::open` opens every component of every
    /// path on every call with no reuse between calls, and on the cold
    /// `go build` that was 47.5% of all host opens
    /// (`docs/perf-results/2026-08-13-hvpatch-build-amplification-ledger.md`).
    ///
    /// **Why an entry may be trusted.** Containment is structural, not audited:
    /// every entry is reached by opening ONE component at a time with
    /// `O_NOFOLLOW | O_DIRECTORY`, starting at the sandbox root, so no symlink
    /// is ever traversed and no resolution can leave the root. Given such a
    /// parent, `openat(parent, leaf, O_NOFOLLOW)` is contained by the same
    /// argument, which is why the hot path issues no `F_GETPATH` at all — that
    /// check exists to audit a traversal, and there is none to audit.
    ///
    /// Strong `Arc`s, not `Weak`: the cache owns the fds and is bounded
    /// explicitly (`DIR_CACHE_MAX_ENTRIES`), so a directory's fd survives
    /// between the operations that share it rather than dying with whichever
    /// stat entry happened to hold it.
    ///
    /// Benign race: two threads may both miss on one directory and both open
    /// it; the later `insert` replaces the earlier. Both are valid, contained
    /// and independently owned, so the only effect is a transient second fd.
    pub(crate) dir_cache: parking_lot::Mutex<std::collections::BTreeMap<PathBuf, DirCacheEntry>>,
    /// Per-directory generation cells referenced by entries. An entry is stale
    /// if its parent directory's generation moved.
    dir_generations: parking_lot::Mutex<
        std::collections::BTreeMap<PathBuf, std::sync::Arc<std::sync::atomic::AtomicU64>>,
    >,
    /// Instrument cache eviction visits for testing: visits <= (evicted entries + log n).
    cache_eviction_visited_keys: std::sync::atomic::AtomicU64,
    /// Host `openat` calls spent WALKING a path to a directory fd
    /// ([`Self::dir_fd_for_hops`] and its post-reclaim retry) — the exact cost
    /// that `namei_leaf` -> `dir_fd_for(parent)` pays on every guest
    /// `mkdirat`/`unlinkat`/`openat`. It is the amplification this cache
    /// exists to remove, so it is counted rather than described: a warm
    /// `dir_cache` must answer with ZERO walk opens, and
    /// `warm_dir_cache_bounds_path_walk_opens_per_guest_op` fails if it does
    /// not. Diagnostic only; nothing branches on it.
    path_walk_host_opens: std::sync::atomic::AtomicU64,
    /// The process generation that owns the current [`Self::dir_cache`] fds.
    /// Changed on host fork so a child drops inherited entries and adopts
    /// the cache for this process. Replaces per-call `libc::getpid()`.
    dir_cache_proc_gen: std::sync::atomic::AtomicU64,
    /// The process generation that owns the current `stat_cache` contents.
    /// Changed on host fork so each process caches its own view.
    /// Replaces per-call `libc::getpid()`.
    cache_proc_gen: std::sync::atomic::AtomicU64,
    /// `CARRICK_FS_STATCACHE` enabled (default ON — see `stat_cache`).
    use_stat_cache: bool,
    /// `Some(merged)` when this scratch is composed as an overlayfs mount
    /// (lowerdir = the shared cached extraction, upperdir = this run's writes)
    /// instead of a byte-copy — the `dir` is opened on `merged`, and `Drop`
    /// `umount2(MNT_DETACH)`s it before the `TempDir` removes the scratch.
    /// Linux-only; always `None` on macOS (clonefile is already O(1)).
    overlay_mount: Option<std::path::PathBuf>,
    /// Fork-coherent cache for `watch_fds`: resolved host-relative path plus,
    /// for non-directories, one source fd for the watched vnode. LTP
    /// `tst_fuzzy_sync` tests re-run `inotify_add_watch`/`inotify_rm_watch` on
    /// the SAME path hundreds of thousands of times; caching the resolved path
    /// elides the cap-std walk, and duping the source fd elides the hot host
    /// `open(2)`. Each entry is stamped with the shared fs generation
    /// ([`crate::fs_resolve_cache`]) and served only while it still matches, so a
    /// structural mutation in ANY carrick process invalidates it. Because fds are
    /// cached, a host fork adopts this cache by clearing inherited parent entries
    /// before first use in the child.
    pub(crate) watch_res_cache:
        parking_lot::Mutex<std::collections::HashMap<String, WatchResCacheEntry>>,
    /// The process generation that owns current `watch_res_cache` fd entries.
    watch_cache_proc_gen: std::sync::atomic::AtomicU64,
    /// Sticky fast answer for [`FsBackend::may_have_fifo_nodes`]: once ANY
    /// process is known to have created a FIFO under this scratch root the
    /// answer is `true` forever with no syscall. `false` only means "consult
    /// the durable root marker" — the in-process bool alone is NOT
    /// fork-coherent (`mkfifo f` runs in one guest process, `cat f` in a
    /// sibling), so the truth lives in [`CARRICK_HAS_FIFO_XATTR`] on the
    /// scratch root and this is only a cache of a `true` reading.
    fifo_seen: std::sync::atomic::AtomicBool,
    /// The shared root-MARKER generation
    /// ([`crate::fs_resolve_cache::current_marker_generation`]) at which this
    /// process last read the root marker as ABSENT. `stamp_root_marker` bumps
    /// it after every stamp, so "marker generation unchanged since the last
    /// absent reading" proves no FIFO appeared anywhere — the per-open
    /// `may_have_fifo_nodes` check is then one shared-atomic load, zero
    /// syscalls. `0` = never checked (generation starts at 1).
    fifo_absent_gen: std::sync::atomic::AtomicU64,
    /// Sticky fast answer for [`FsBackend::dir_has_overlay_interference`]:
    /// once ANY process is known to have created a MARKER node (AF_UNIX
    /// socket / mknod device — regular files whose guest-visible type lives
    /// in xattrs) the raw getdents stream would lie about `d_type`, so the
    /// answer is `true` forever with no syscall. Mirrors `fifo_seen`: the
    /// durable truth is [`CARRICK_HAS_MARKER_NODES_XATTR`] on the scratch
    /// root; this bool caches only a `true` reading.
    marker_seen: std::sync::atomic::AtomicBool,
    /// Shared root-marker generation at which this process last read the
    /// marker-node root xattr as ABSENT; mirrors `fifo_absent_gen`
    /// (`create_socket`/`create_device` stamp the marker BEFORE creating the
    /// node).
    marker_absent_gen: std::sync::atomic::AtomicU64,
    /// Sticky fast answer for "does any entry carry guest metadata xattrs"
    /// (mode/uid/gid): mirrors `marker_seen`/`marker_absent_gen` over
    /// [`CARRICK_HAS_META_XATTRS_XATTR`], stamped by `set_mode`/`set_owner`
    /// BEFORE the first xattr write.
    meta_xattr_seen: std::sync::atomic::AtomicBool,
    meta_xattr_absent_gen: std::sync::atomic::AtomicU64,
    /// Sticky cache of the durable host-upper whiteout marker. The marker and
    /// adjacent sidecars make sparse-upper deletions visible across real host
    /// forks and native self-reexecs; the shared root-marker generation
    /// makes an absent reading safe to cache in each process.
    whiteout_seen: std::sync::atomic::AtomicBool,
    whiteout_absent_gen: std::sync::atomic::AtomicU64,
    /// Durable upper-symlink marker cache. Any symlink permanently disables
    /// authoritative sparse-upper misses because an intermediate link needs
    /// the layered resolver's Linux-rooted semantics.
    symlink_seen: std::sync::atomic::AtomicBool,
    symlink_absent_gen: std::sync::atomic::AtomicU64,
}

/// A cached `RealStat` plus the snapshot needed to revalidate it cheaply. The
/// `parent_fd` is a CONTAINED directory fd (verified via F_GETPATH when the
/// entry was filled) used as a trusted anchor: `fstatat(parent_fd, name)` of a
/// single component cannot escape it. See [`HostFsBackend::stat_cache`].
#[cfg(target_os = "macos")]
pub(crate) struct StatCacheEntry {
    pub(crate) parent_fd: std::sync::Arc<std::os::fd::OwnedFd>,
    /// Generation cell of the parent directory. An entry is stale if its parent's
    /// generation moved.
    parent_gen: std::sync::Arc<std::sync::atomic::AtomicU64>,
    stamped_parent_gen: u64,
    /// Shared directory-topology generation this entry's parent dirfd was proven at.
    dir_generation: u64,
    /// Guest-metadata generation the xattr-derived fields (`mode_override`,
    /// `real.uid`/`gid`, the socket kind) were read at. While it still equals
    /// [`crate::fs_resolve_cache::current_meta_generation`], no carrick writer
    /// has touched ANY metadata xattr since the fill, so an inode whose
    /// timestamps moved for other reasons (child churn, an append) is served
    /// with those fields intact and only the volatile ones refreshed.
    meta_generation: u64,
    /// The `user.carrick.mode` override at fill time; `None` means the guest
    /// mode IS the on-disk mode and is re-read from the fresh `fstatat`.
    mode_override: Option<u32>,
    ino: u64,
    /// `st_birthtime` at fill time. APFS never reuses an inode number, but the
    /// pair (ino, birthtime) identifies the inode on any host filesystem, so
    /// a name re-created over a recycled number is a miss, not a stale hit.
    birth: (i64, i64),
    real: RealStat,
}

#[cfg(target_os = "macos")]
impl StatCacheEntry {
    fn is_valid(&self, current_dir_gen: u64) -> bool {
        self.dir_generation == current_dir_gen
            && self.parent_gen.load(std::sync::atomic::Ordering::Relaxed) == self.stamped_parent_gen
    }
}

/// One directory in [`HostFsBackend::dir_cache`]: a containment-proven host
/// dirfd plus its parent directory's generation cell.
pub(crate) struct DirCacheEntry {
    fd: std::sync::Arc<std::os::fd::OwnedFd>,
    parent_gen: std::sync::Arc<std::sync::atomic::AtomicU64>,
    stamped_parent_gen: u64,
    dir_generation: u64,
}

impl DirCacheEntry {
    fn is_valid(&self, current_dir_gen: u64) -> bool {
        self.dir_generation == current_dir_gen
            && self.parent_gen.load(std::sync::atomic::Ordering::Relaxed) == self.stamped_parent_gen
    }
}

/// Non-macOS placeholder so the `stat_cache` field type is well-formed; the
/// cache is only populated/consulted on macOS (the only `--fs host` fast path).
// `real` is never read off-macOS (the cache is never consulted there), but the
// field keeps the type identical to the macOS variant's payload.
#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub(crate) struct StatCacheEntry {
    real: RealStat,
}

#[cfg(not(target_os = "macos"))]
impl StatCacheEntry {
    fn is_valid(&self, _current_dir_gen: u64) -> bool {
        true
    }
}

pub(crate) struct WatchResCacheEntry {
    generation: u64,
    normalized: PathBuf,
    pub(crate) source_fd: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
}

/// F_GETPATH of a root dir fd → its absolute host path (macOS), used as the
/// containment prefix for the fast-stat path. `None` on failure/non-macOS.
fn host_root_prefix(root_fd: &std::os::fd::OwnedFd) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let mut buf = [0u8; libc::PATH_MAX as usize];
        let rc = unsafe {
            libc::fcntl(
                root_fd.as_raw_fd(),
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
        let _ = root_fd;
        None
    }
}

pub(crate) fn host_dir_identity(fd: i32) -> std::io::Result<(u64, u64)> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    Ok((stat.st_dev as u64, stat.st_ino))
}

/// `true` iff the open fd's real host path (`F_GETPATH`) lives at or under
/// `root_prefix` — the sandbox-containment check for the fast paths. An
/// intermediate (or followed-leaf) symlink the kernel resolved out of the root
/// shows an outside path here and is rejected. `F_GETPATH` on an open fd is a
/// cheap (no-path-walk) read of the vnode's cached path.
#[cfg(target_os = "macos")]
fn fd_contained_under(fd: std::os::fd::RawFd, root_prefix: &str) -> bool {
    let mut buf = [0u8; libc::PATH_MAX as usize];
    if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr() as *mut libc::c_char) } < 0 {
        return false;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    match std::str::from_utf8(&buf[..end]) {
        Ok(got) => {
            got == root_prefix
                || (got.len() > root_prefix.len()
                    && got.starts_with(root_prefix)
                    && got.as_bytes()[root_prefix.len()] == b'/')
        }
        Err(_) => false,
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

/// `--fs host` stat cache enabled. Default ON (`CARRICK_FS_STATCACHE=0` opts
/// out). See [`HostFsBackend::stat_cache`] for the speed/coherence trade-off.
fn stat_cache_enabled() -> bool {
    !matches!(
        std::env::var("CARRICK_FS_STATCACHE").as_deref(),
        Ok("0") | Ok("false")
    )
}

/// `--fs host` overlayfs rootfs composition (Linux). OPT-IN
/// (`CARRICK_FS_OVERLAY=1`): each per-run scratch becomes an overlay over the
/// shared cached extraction instead of a full byte-copy — the per-run latency
/// floor on a no-reflink filesystem (ext4, or ZFS in an unprivileged container
/// where FICLONE is denied). Off by default until the conformance gate has
/// A/B-validated byte-identical verdicts against the blessed baseline.
#[cfg(target_os = "linux")]
fn overlay_enabled() -> bool {
    matches!(
        std::env::var("CARRICK_FS_OVERLAY").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Outcome of [`HostFsBackend::fast_open_for_guest`] — the fd-centric fast
/// path for a guest's own (non-creating, non-truncating) file open.
#[cfg(target_os = "macos")]
pub(crate) enum FastGuestOpen {
    /// The open fd IS the guest's open: real access mode, containment- and
    /// Unicode-alias-checked, `O_NONBLOCK` already cleared. `stat` is the
    /// `fstat` of the same fd, so the caller derives every piece of metadata
    /// it needs without another path walk.
    Served {
        fd: std::os::fd::OwnedFd,
        stat: libc::stat,
        kind: RootFsEntryKind,
    },
    /// The leaf is a symlink (`O_NOFOLLOW` → `ELOOP`). The caller must run
    /// the `resolve_following` + cap-std path: an absolute symlink target has
    /// to be re-rooted under the GUEST root, which the host kernel's own
    /// resolution cannot do.
    SymlinkLeaf,
    /// The (contained) leaf is a FIFO. The caller must route to the
    /// `open_fifo_nonblock` handling — NEVER to the cap-std slow path, whose
    /// blocking `open(2)` of a writer-less FIFO would wedge the dispatcher.
    Fifo,
    /// The kernel reported ENOENT before any fd existed. Immutable-lower
    /// callers may turn this into an authoritative guest miss only after
    /// proving that the nearest existing ancestor is a contained directory;
    /// ordinary mutable-backend callers retain their exact fallback.
    Missing,
    /// Anything else (miss, escape, alias, exotic type, error): run the exact
    /// cap-std slow path. A fast-path failure proves nothing about the guest
    /// view — e.g. an intermediate ABSOLUTE symlink resolves against the host
    /// root here but under the guest root on the slow path.
    Fallback,
    /// The host refused a resource the guest is entitled to (see
    /// [`host_open_refusal`]) even after carrick reclaimed its own descriptor
    /// caches. Final: the slow path would only re-ask the same kernel.
    Refused(LinuxErrno),
}

/// Result of an immutable host lower's read-only regular-file fast path.
/// `Missing` is stronger than an `Option::None`: the backend has proved the
/// failed path lies below a contained existing directory and crosses no
/// symlink whose Linux-rooted semantics require the layered resolver.
pub(crate) enum ImmutableHostFileOpen {
    Served {
        file: std::fs::File,
        metadata: RootFsMetadata,
    },
    Missing,
    Fallback,
}

impl Drop for HostFsBackend {
    fn drop(&mut self) {
        let current = unsafe { libc::getpid() as u32 };
        if current != self.owner_pid {
            // Forked descendant: leak the TempDir so its Drop does NOT
            // delete the shared scratch directory. `keep` consumes the
            // TempDir without scheduling removal. Don't touch the overlay
            // mount either — the OWNER unmounts it.
            if let Some(scratch) = self._scratch.take() {
                let _ = scratch.keep();
            }
        } else {
            // Owner: detach an overlayfs scratch mount (if any) BEFORE the
            // `TempDir` Drop removes the scratch tree. MNT_DETACH (lazy) so the
            // still-open cap-std `dir` fd — a field dropped right after this
            // `drop` returns — doesn't cause EBUSY; the mount finalizes when
            // that fd closes, leaving an empty `merged/` for the TempDir to
            // remove.
            #[cfg(target_os = "linux")]
            if let Some(mp) = self.overlay_mount.take() {
                use std::os::unix::ffi::OsStrExt;
                if let Ok(c) = std::ffi::CString::new(mp.as_os_str().as_bytes()) {
                    // SAFETY: `c` is a valid NUL-terminated path; MNT_DETACH
                    // never blocks on open fds.
                    unsafe {
                        libc::umount2(c.as_ptr(), libc::MNT_DETACH);
                    }
                }
            }

            // Reclaim the run's scratch OFF the exit path. Measured: a no-op
            // container spends 1,310 ms of its 1,772 ms after the guest has
            // exited, almost all of it unlinking the image's ~26k files
            // (docs/perf-results/container-lifecycle-split.jsonl) - pure wall
            // the user waits through for a tree nobody will read again.
            if let Some(scratch) = self._scratch.take() {
                defer_remove_tree(scratch.keep());
            }
            if let Some(path) = self._attached_cleanup_path.take() {
                defer_remove_tree(path);
            }
        }
    }
}

/// Retire a scratch tree without paying recursive unlink wall on the exit
/// owner. The same-directory rename removes the live name in O(1), after which
/// one bounded in-process worker may reclaim it while the carrier remains
/// alive. The worker deliberately has no shutdown join: process exit is the
/// latency boundary, and the next startup sweep is the durable fallback for a
/// partly removed or merely queued tree.
pub(crate) fn defer_remove_tree(path: PathBuf) {
    let Some(parent) = path.parent().map(Path::to_path_buf) else {
        return;
    };
    let retired = rename_scratch_to_trash(&path);
    cleanup_oldest_trash_checkpoint(&parent);
    if let Some(retired) = retired {
        enqueue_scratch_cleanup(retired);
    }
}

fn rename_scratch_to_trash(path: &Path) -> Option<PathBuf> {
    let parent = path.parent()?;
    let trash = parent.join(SCRATCH_TRASH_DIRECTORY);
    if std::fs::create_dir_all(&trash).is_err() {
        return None;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();

    for _ in 0..4 {
        let sequence = SCRATCH_TRASH_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let retired = trash.join(format!("{SCRATCH_TRASH_PREFIX}{pid}-{stamp}-{sequence}"));
        match std::fs::rename(path, &retired) {
            Ok(()) => return Some(retired),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            // Missing means another owner already retired or reclaimed this
            // exact tree. Any other failure leaves the lock-bearing original
            // in place for the next startup sweep; never recurse on this exit
            // path merely because the optimization could not arm.
            Err(_) => return None,
        }
    }
    None
}

/// Make durable cleanup progress without handing recursive deletion latency to
/// startup or guest exit. The filesystem tree is the cursor: each invocation
/// removes at most [`SCRATCH_SYNC_CLEANUP_LIMIT`] entries from the oldest
/// retired tree, preserving that tree's age until it is fully gone.
pub(crate) fn cleanup_oldest_trash_checkpoint(scratch_root: &Path) -> usize {
    let dedicated = scratch_root.join(SCRATCH_TRASH_DIRECTORY);
    let search_root = if dedicated.is_dir() {
        dedicated.as_path()
    } else {
        scratch_root
    };
    let mut budget = CleanupBudget::new(SCRATCH_SYNC_CLEANUP_LIMIT);
    let Some(Ok(entries)) = budget.attempt(|| std::fs::read_dir(search_root)) else {
        return 0;
    };
    let mut oldest: Option<(PathBuf, (std::time::SystemTime, std::ffi::OsString))> = None;
    for entry in entries {
        if !budget.charge() {
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let Some(Ok(file_type)) = budget.attempt(|| entry.file_type()) else {
            continue;
        };
        let path = entry.path();
        if !file_type.is_dir() || !is_retired_scratch(&path) {
            continue;
        }
        let modified = match budget.attempt(|| entry.metadata().and_then(|meta| meta.modified())) {
            Some(Ok(modified)) => modified,
            Some(Err(_)) => std::time::UNIX_EPOCH,
            None => break,
        };
        let order = (
            modified,
            path.file_name().unwrap_or_default().to_os_string(),
        );
        if oldest.as_ref().is_none_or(|(_, current)| order < *current) {
            oldest = Some((path, order));
        }
    }
    let Some((oldest, (original_modified, _))) = oldest else {
        return 0;
    };
    cleanup_tree_entries_with_budget(&oldest, search_root, &mut budget);
    if let Some(Ok(directory)) = budget.attempt(|| std::fs::File::open(&oldest)) {
        let _ = budget.attempt(|| {
            directory.set_times(std::fs::FileTimes::new().set_modified(original_modified))
        });
    }
    debug_assert_eq!(
        budget.attempts + budget.remaining,
        SCRATCH_SYNC_CLEANUP_LIMIT
    );
    budget.removed
}

#[cfg(test)]
pub(crate) fn cleanup_tree_entries_bounded(path: &Path, remaining: &mut usize) -> usize {
    let limit = *remaining;
    let mut budget = CleanupBudget::new(*remaining);
    let work_root = path.parent().unwrap_or(path);
    cleanup_tree_entries_with_budget(path, work_root, &mut budget);
    *remaining = budget.remaining;
    debug_assert_eq!(budget.attempts + budget.remaining, limit);
    budget.removed
}

#[derive(Debug)]
struct CleanupBudget {
    remaining: usize,
    attempts: usize,
    removed: usize,
}

impl CleanupBudget {
    fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            attempts: 0,
            removed: 0,
        }
    }

    fn charge(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        self.attempts += 1;
        true
    }

    fn attempt<T>(
        &mut self,
        operation: impl FnOnce() -> std::io::Result<T>,
    ) -> Option<std::io::Result<T>> {
        self.charge().then(operation)
    }

    fn removed_one(&mut self) {
        self.removed += 1;
    }
}

fn cleanup_tree_entries_with_budget(path: &Path, work_root: &Path, budget: &mut CleanupBudget) {
    let Some(Ok(metadata)) = budget.attempt(|| std::fs::symlink_metadata(path)) else {
        return;
    };
    if !metadata.file_type().is_dir() {
        if let Some(Ok(())) = budget.attempt(|| std::fs::remove_file(path)) {
            budget.removed_one();
        }
        return;
    }

    let _ =
        budget.attempt(|| std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)));

    let Some(Ok(entries)) = budget.attempt(|| std::fs::read_dir(path)) else {
        return;
    };
    let failures = cleanup_failure_root(work_root);
    let mut blocked = false;
    for entry in entries {
        if !budget.charge() {
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let entry_path = entry.path();
        let Some(Ok(file_type)) = budget.attempt(|| entry.file_type()) else {
            continue;
        };
        // Preserve one attempt to quarantine the whole retired root if this
        // mutation fails. A permanently immutable prefix must not monopolize
        // every later checkpoint.
        if budget.remaining < 3 {
            break;
        }
        if file_type.is_dir() {
            let sequence = SCRATCH_TRASH_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let promoted = work_root.join(format!(
                "{SCRATCH_TRASH_PREFIX}promoted-{}-{sequence}",
                std::process::id()
            ));
            if !matches!(
                budget.attempt(|| std::fs::rename(&entry_path, promoted)),
                Some(Ok(()))
            ) {
                blocked = true;
                break;
            }
        } else {
            match budget.attempt(|| std::fs::remove_file(&entry_path)) {
                Some(Ok(())) => budget.removed_one(),
                Some(Err(_)) => {
                    blocked = true;
                    break;
                }
                None => break,
            }
        }
    }
    if blocked {
        let sequence = SCRATCH_TRASH_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let target = failures.join(format!("{}-{sequence}", std::process::id()));
        if matches!(
            budget.attempt(|| std::fs::create_dir_all(&failures)),
            Some(Ok(()))
        ) {
            let _ = budget.attempt(|| std::fs::rename(path, target));
        }
        return;
    }
    if let Some(Ok(())) = budget.attempt(|| std::fs::remove_dir(path)) {
        budget.removed_one();
    }
}

fn cleanup_failure_root(work_root: &Path) -> PathBuf {
    let scratch_root = if work_root
        .file_name()
        .is_some_and(|name| name == SCRATCH_TRASH_DIRECTORY)
    {
        work_root.parent().unwrap_or(work_root)
    } else {
        work_root
    };
    scratch_root.join(".carrick-cleanup-failures")
}

fn is_retired_scratch(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.starts_with(SCRATCH_TRASH_PREFIX) || name.starts_with(LEGACY_SCRATCH_TRASH_PREFIX)
        })
}

enum ScratchCleanupWork {
    Remove(PathBuf),
    Discover {
        root: PathBuf,
        #[cfg(test)]
        observer: Option<ScratchDiscoveryObserver>,
    },
}

#[cfg(test)]
pub(crate) struct ScratchDiscoveryObserver {
    pub(crate) before_root_lock: std::sync::Arc<std::sync::Barrier>,
    pub(crate) cleanup_complete: std::sync::Arc<std::sync::Barrier>,
}

fn scratch_cleanup_sender() -> &'static Option<std::sync::mpsc::SyncSender<ScratchCleanupWork>> {
    static SENDER: std::sync::OnceLock<Option<std::sync::mpsc::SyncSender<ScratchCleanupWork>>> =
        std::sync::OnceLock::new();
    SENDER.get_or_init(|| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(SCRATCH_CLEANUP_QUEUE_DEPTH);
        std::thread::Builder::new()
            .name("carrick-fs-cleanup".to_string())
            .spawn(move || {
                while let Ok(work) = receiver.recv() {
                    match work {
                        ScratchCleanupWork::Remove(path) => {
                            let _ = std::fs::remove_dir_all(path);
                        }
                        ScratchCleanupWork::Discover {
                            root,
                            #[cfg(test)]
                            observer,
                        } => {
                            for retired in discover_orphans_after_root_lock(
                                &root,
                                #[cfg(test)]
                                observer.as_ref(),
                            ) {
                                let _ = std::fs::remove_dir_all(retired);
                            }
                            #[cfg(test)]
                            if let Some(observer) = observer {
                                observer.cleanup_complete.wait();
                            }
                        }
                    }
                }
            })
            .ok()
            .map(|_| sender)
    })
}

fn enqueue_scratch_cleanup(path: PathBuf) {
    if let Some(sender) = scratch_cleanup_sender() {
        // Never let a saturated cleanup queue become guest exit latency. A
        // dropped enqueue is still durable because the retired name is one the
        // next startup sweep owns unconditionally.
        let _ = sender.try_send(ScratchCleanupWork::Remove(path));
    }
}

fn enqueue_orphan_discovery(root: PathBuf) {
    if let Some(sender) = scratch_cleanup_sender() {
        let _ = sender.try_send(ScratchCleanupWork::Discover {
            root,
            #[cfg(test)]
            observer: None,
        });
    }
}

#[cfg(test)]
pub(crate) fn enqueue_orphan_discovery_observed(root: PathBuf, observer: ScratchDiscoveryObserver) {
    scratch_cleanup_sender()
        .as_ref()
        .expect("scratch cleanup worker")
        .send(ScratchCleanupWork::Discover {
            root,
            observer: Some(observer),
        })
        .expect("enqueue observed scratch discovery");
}

fn discover_orphans_after_root_lock(
    scratch_root: &Path,
    #[cfg(test)] observer: Option<&ScratchDiscoveryObserver>,
) -> Vec<PathBuf> {
    let root_lock_path = scratch_root.join(".carrick.sweep.lock");
    let Ok(root_lock_file) = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&root_lock_path)
    else {
        return Vec::new();
    };
    let mut root_lock = fd_lock::RwLock::new(root_lock_file);
    #[cfg(test)]
    if let Some(observer) = observer {
        observer.before_root_lock.wait();
    }
    let Ok(_root_guard) = root_lock.write() else {
        return Vec::new();
    };
    discover_orphans(scratch_root, None)
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
        let root_lock_path = scratch_root.join(".carrick.sweep.lock");
        let root_lock_file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&root_lock_path)?;
        let mut root_lock = fd_lock::RwLock::new(root_lock_file);
        let root_guard = root_lock.write()?;
        sweep_orphans(scratch_root);

        let scratch = tempfile::TempDir::new_in(scratch_root)?;
        let lock = acquire_lockfile(scratch.path())?;
        drop(root_guard);
        let scratch_c = std::ffi::CString::new(scratch.path().as_os_str().as_encoded_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let raw = unsafe {
            libc::open(
                scratch_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let root_fd = std::sync::Arc::new(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) });
        let root_prefix = host_root_prefix(&root_fd);
        let fast_fs = fast_fs_enabled();
        let root_path = scratch.path().to_path_buf();
        let proc_gen = crate::fs_resolve_cache::current_process_generation();
        Ok(Self {
            root_fd,
            root_path,
            archive_mutation_gate: ArchiveMutationGate::default(),
            _scratch: Some(scratch),
            _attached_cleanup_path: None,
            _lock: Some(lock),
            owner_pid: unsafe { libc::getpid() as u32 },
            root_prefix,
            fast_fs,
            sparse_upper_fast_miss: false,
            stat_cache: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            dir_cache: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            dir_generations: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            cache_eviction_visited_keys: std::sync::atomic::AtomicU64::new(0),
            path_walk_host_opens: std::sync::atomic::AtomicU64::new(0),
            dir_cache_proc_gen: std::sync::atomic::AtomicU64::new(proc_gen),
            cache_proc_gen: std::sync::atomic::AtomicU64::new(proc_gen),
            use_stat_cache: stat_cache_enabled(),
            overlay_mount: None,
            watch_res_cache: parking_lot::Mutex::new(std::collections::HashMap::new()),
            watch_cache_proc_gen: std::sync::atomic::AtomicU64::new(proc_gen),
            fifo_seen: std::sync::atomic::AtomicBool::new(false),
            fifo_absent_gen: std::sync::atomic::AtomicU64::new(0),
            marker_seen: std::sync::atomic::AtomicBool::new(false),
            marker_absent_gen: std::sync::atomic::AtomicU64::new(0),
            meta_xattr_seen: std::sync::atomic::AtomicBool::new(false),
            meta_xattr_absent_gen: std::sync::atomic::AtomicU64::new(0),
            whiteout_seen: std::sync::atomic::AtomicBool::new(false),
            whiteout_absent_gen: std::sync::atomic::AtomicU64::new(0),
            symlink_seen: std::sync::atomic::AtomicBool::new(false),
            symlink_absent_gen: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Authorize the fail-closed sparse-upper miss proof. Callers may do this
    /// only for a newly-created writable upper that is paired with an
    /// immutable lower; arbitrary attached/materialized roots stay disabled.
    pub(crate) fn enable_sparse_upper_fast_miss(&mut self) {
        self.sparse_upper_fast_miss = true;
    }

    /// Walk a `RootFs` and write every file/dir/symlink into the
    /// scratch root, then register every path as "known" so the
    /// backend's lookup returns it.
    pub fn seed_from_rootfs(&mut self, rootfs: &crate::rootfs::RootFs) -> std::io::Result<()> {
        rootfs
            .extract_to_dir(&self.root_path)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(())
    }

    /// Construct against an already-allocated root fd without
    /// taking ownership of its lifetime. Used by tests.
    pub fn from_existing_root_fd(
        root_fd: std::sync::Arc<std::os::fd::OwnedFd>,
        root_path: PathBuf,
    ) -> Self {
        let root_prefix = host_root_prefix(&root_fd);
        let fast_fs = fast_fs_enabled();
        let proc_gen = crate::fs_resolve_cache::current_process_generation();
        Self {
            root_fd,
            root_path,
            archive_mutation_gate: ArchiveMutationGate::default(),
            _scratch: None,
            _attached_cleanup_path: None,
            _lock: None,
            owner_pid: unsafe { libc::getpid() as u32 },
            root_prefix,
            fast_fs,
            sparse_upper_fast_miss: false,
            stat_cache: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            dir_cache: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            dir_generations: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            cache_eviction_visited_keys: std::sync::atomic::AtomicU64::new(0),
            path_walk_host_opens: std::sync::atomic::AtomicU64::new(0),
            dir_cache_proc_gen: std::sync::atomic::AtomicU64::new(proc_gen),
            cache_proc_gen: std::sync::atomic::AtomicU64::new(proc_gen),
            use_stat_cache: stat_cache_enabled(),
            overlay_mount: None,
            watch_res_cache: parking_lot::Mutex::new(std::collections::HashMap::new()),
            watch_cache_proc_gen: std::sync::atomic::AtomicU64::new(proc_gen),
            fifo_seen: std::sync::atomic::AtomicBool::new(false),
            fifo_absent_gen: std::sync::atomic::AtomicU64::new(0),
            marker_seen: std::sync::atomic::AtomicBool::new(false),
            marker_absent_gen: std::sync::atomic::AtomicU64::new(0),
            meta_xattr_seen: std::sync::atomic::AtomicBool::new(false),
            meta_xattr_absent_gen: std::sync::atomic::AtomicU64::new(0),
            whiteout_seen: std::sync::atomic::AtomicBool::new(false),
            whiteout_absent_gen: std::sync::atomic::AtomicU64::new(0),
            symlink_seen: std::sync::atomic::AtomicBool::new(false),
            symlink_absent_gen: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Construct against an already-allocated scratch dir fd without
    /// taking ownership of its lifetime. Used by tests.
    pub fn from_existing_dir(dir: std::os::fd::OwnedFd) -> Self {
        use std::os::fd::AsRawFd;
        let root_path =
            carrick_portable::fd_abs_path(dir.as_raw_fd()).unwrap_or_else(|| PathBuf::from("/"));
        let root_fd = std::sync::Arc::new(dir);
        Self::from_existing_root_fd(root_fd, root_path)
    }

    /// Construct against an already-allocated scratch path.
    pub fn from_path(path: &Path) -> std::io::Result<Self> {
        let path_c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let raw = unsafe {
            libc::open(
                path_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let root_fd = std::sync::Arc::new(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) });
        Ok(Self::from_existing_root_fd(root_fd, path.to_path_buf()))
    }

    /// Open an EXISTING scratch directory as the writable overlay WITHOUT owning
    /// its lifetime (no `TempDir` auto-delete, no lockfile).
    pub fn attach(path: &Path) -> std::io::Result<Self> {
        Self::from_path(path)
    }

    /// Like [`HostFsBackend::attach`], but creates `path` first if it is absent.
    pub fn attach_or_create(path: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(path)?;
        Self::attach(path)
    }

    /// Snapshot the current contained root for native host self-reexec.
    pub fn native_reexec_authority(&self) -> std::io::Result<HostFsReexecAuthority> {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;

        let root_path = &self.root_path;
        let (device, inode) = host_dir_identity(self.root_fd.as_raw_fd())?;
        let current_pid = unsafe { libc::getpid() as u32 };
        Ok(HostFsReexecAuthority {
            root_path: root_path.as_os_str().as_bytes().to_vec(),
            device,
            inode,
            cleanup_on_drop: native_reexec_transfers_cleanup(
                self.owner_pid,
                current_pid,
                self._scratch.is_some() || self._attached_cleanup_path.is_some(),
            ),
            sparse_upper_fast_miss: self.sparse_upper_fast_miss,
        })
    }

    /// Reopen the exact overlay described by a validated reexec authority.
    pub fn attach_for_reexec(authority: &HostFsReexecAuthority) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(std::ffi::OsString::from_vec(authority.root_path.clone()));
        let mut backend = Self::from_path(&path)?;
        let identity = host_dir_identity(backend.root_fd.as_raw_fd())?;
        if identity != (authority.device, authority.inode) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "native reexec host filesystem root identity changed",
            ));
        }
        if authority.cleanup_on_drop {
            backend._attached_cleanup_path = Some(path);
        }
        backend.owner_pid = unsafe { libc::getpid() as u32 };
        backend.sparse_upper_fast_miss = authority.sparse_upper_fast_miss;
        Ok(backend)
    }

    /// Serve `dir`'s containment-proven host dirfd from the kernel directory
    /// cache, opening and proving it on a miss. `dir` must be a NORMALIZED,
    /// sandbox-relative directory path — [`normalize`] has already collapsed
    /// `.` and resolved `..` lexically, and returns `None` rather than a path
    /// that climbs out of the root, so no component here can be `..`.
    ///
    /// This is the lower half of carrick's namei. See [`Self::dir_cache`] for
    /// why an entry may be trusted and what invalidates it.
    ///
    /// Cost: zero host syscalls on a hit; otherwise ONE `openat` per component
    /// not already cached — so a sequential walk into a tree pays one call per
    /// NEW directory and nothing thereafter.
    ///
    /// **Containment is structural and total.** The descent starts at the
    /// sandbox root and opens exactly one component at a time with
    /// `O_NOFOLLOW | O_DIRECTORY`, so no symlink is ever traversed and no
    /// resolution can leave the root. That is precisely the property cap-std's
    /// manual walk provides — this keeps it and caches the result, which is the
    /// whole difference. Nothing here calls `F_GETPATH`: there is no traversal
    /// to audit after the fact.
    ///
    /// It also means a cached entry can never have been reached THROUGH a
    /// symlink, so re-pointing a symlink cannot invalidate one — which is why
    /// the invalidation set is only rename, exchange and directory removal. A
    /// genuinely symlinked directory simply fails here (`ELOOP`) and the caller
    /// keeps its exact existing fallback, which re-roots absolute targets under
    /// the guest root.
    pub(super) fn dir_fd_for(
        &self,
        dir: &Path,
    ) -> Result<std::sync::Arc<std::os::fd::OwnedFd>, i32> {
        self.dir_fd_for_hops(dir, 0)
    }

    fn dir_fd_for_hops(
        &self,
        dir: &Path,
        hops: u32,
    ) -> Result<std::sync::Arc<std::os::fd::OwnedFd>, i32> {
        use std::os::fd::AsRawFd;
        use std::sync::atomic::Ordering::Relaxed;

        if hops >= 40 {
            return Err(libc::ELOOP);
        }

        if !self.fast_fs {
            return self.dir_fd_for_after_reclaim(
                dir,
                crate::fs_resolve_cache::current_dir_generation(),
                hops,
            );
        }
        let generation = crate::fs_resolve_cache::current_dir_generation();
        let proc_gen = crate::fs_resolve_cache::current_process_generation();

        // Adopt-and-clear if we crossed a host fork: a child must not trust
        // dirfds it inherited from a parent that may since have moved them.
        {
            let mut cache = self.dir_cache.lock();
            if self.dir_cache_proc_gen.load(Relaxed) != proc_gen {
                cache.clear();
                self.dir_cache_proc_gen.store(proc_gen, Relaxed);
            }
            if let Some(entry) = cache.get(dir)
                && entry.is_valid(generation)
            {
                return Ok(entry.fd.clone());
            }
        }

        // The sandbox root itself is contained by definition. It is already an
        // Arc<OwnedFd>, so cloning it avoids any descriptor table allocation.
        let root = {
            let cached = {
                let cache = self.dir_cache.lock();
                cache
                    .get(Path::new(""))
                    .filter(|entry| entry.is_valid(generation))
                    .map(|entry| entry.fd.clone())
            };
            match cached {
                Some(fd) => fd,
                None => {
                    let fd = self.root_fd.clone();
                    self.publish_dir_fd(Path::new(""), &fd, generation);
                    fd
                }
            }
        };
        if dir.as_os_str().is_empty() {
            return Ok(root);
        }

        // Start from the deepest cached ancestor. `ancestors()` yields
        // longest-first, so the first hit is the deepest.
        let mut current = root;
        let mut walked = PathBuf::new();
        let mut remaining: Vec<&std::ffi::OsStr> = Vec::new();
        {
            let cache = self.dir_cache.lock();
            let mut found = false;
            for ancestor in dir.ancestors().skip(1) {
                if let Some(entry) = cache.get(ancestor)
                    && entry.is_valid(generation)
                    && let Ok(rest) = dir.strip_prefix(ancestor)
                {
                    current = entry.fd.clone();
                    walked = ancestor.to_path_buf();
                    remaining = rest.iter().collect();
                    found = true;
                    break;
                }
            }
            if !found {
                remaining = dir.iter().collect();
            }
        }

        let flags = libc::O_RDONLY
            | libc::O_DIRECTORY
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | libc::O_NOFOLLOW;
        for component in remaining {
            walked.push(component);
            let Some(component_c) = cstring_from_osstr(component) else {
                return Err(libc::EINVAL);
            };
            self.path_walk_host_opens
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let raw = unsafe { libc::openat(current.as_raw_fd(), component_c.as_ptr(), flags, 0) };
            if raw < 0 {
                let err = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                let out_of_fds = matches!(err, libc::EMFILE | libc::ENFILE);
                if out_of_fds {
                    self.drop_dir_cache();
                    return self.dir_fd_for_after_reclaim(dir, generation, hops);
                }
                let mut st: libc::stat = unsafe { core::mem::zeroed() };
                let is_symlink = unsafe {
                    libc::fstatat(
                        current.as_raw_fd(),
                        component_c.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    ) == 0
                        && (st.st_mode as u32 & libc::S_IFMT as u32 == libc::S_IFLNK as u32)
                };
                if is_symlink {
                    let mut buf = [0u8; libc::PATH_MAX as usize];
                    let n = unsafe {
                        libc::readlinkat(
                            current.as_raw_fd(),
                            component_c.as_ptr(),
                            buf.as_mut_ptr() as *mut libc::c_char,
                            buf.len(),
                        )
                    };
                    if n <= 0 || n as usize >= buf.len() {
                        return Err(err);
                    }
                    use std::os::unix::ffi::OsStrExt as _;
                    let target = std::ffi::OsStr::from_bytes(&buf[..n as usize]);
                    let target_path = Path::new(target);
                    let resolved_target = if target_path.is_absolute() {
                        normalize_raw(target_path).ok_or(libc::EACCES)?
                    } else {
                        let parent = walked.parent().unwrap_or_else(|| Path::new(""));
                        normalize_raw(&parent.join(target_path)).ok_or(libc::EACCES)?
                    };
                    let target_fd = self.dir_fd_for_hops(&resolved_target, hops + 1)?;
                    self.publish_dir_fd(&walked, &target_fd, generation);
                    current = target_fd;
                    continue;
                }
                return Err(err);
            }
            // SAFETY: `raw` is a freshly-opened owned dir fd.
            let fd = std::sync::Arc::new(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) });
            self.publish_dir_fd(&walked, &fd, generation);
            current = fd;
        }
        Ok(current)
    }

    /// One non-recursing retry of [`Self::dir_fd_for`] after an fd reclaim.
    /// Separated so the reclaim path cannot loop: this walk opens fds into a
    /// just-emptied cache, and if it still cannot get one there is nothing left
    /// to reclaim and the caller must fall back.
    fn dir_fd_for_after_reclaim(
        &self,
        dir: &Path,
        generation: u64,
        hops: u32,
    ) -> Result<std::sync::Arc<std::os::fd::OwnedFd>, i32> {
        use std::os::fd::AsRawFd;

        if hops >= 40 {
            return Err(libc::ELOOP);
        }

        let mut current = self.root_fd.clone();
        self.publish_dir_fd(Path::new(""), &current, generation);
        let flags = libc::O_RDONLY
            | libc::O_DIRECTORY
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | libc::O_NOFOLLOW;
        let mut walked = PathBuf::new();
        for component in dir.iter() {
            walked.push(component);
            let Some(component_c) = cstring_from_osstr(component) else {
                return Err(libc::EINVAL);
            };
            self.path_walk_host_opens
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let raw = unsafe { libc::openat(current.as_raw_fd(), component_c.as_ptr(), flags, 0) };
            if raw < 0 {
                let err = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                let mut st: libc::stat = unsafe { core::mem::zeroed() };
                let is_symlink = unsafe {
                    libc::fstatat(
                        current.as_raw_fd(),
                        component_c.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    ) == 0
                        && (st.st_mode as u32 & libc::S_IFMT as u32 == libc::S_IFLNK as u32)
                };
                if is_symlink {
                    let mut buf = [0u8; libc::PATH_MAX as usize];
                    let n = unsafe {
                        libc::readlinkat(
                            current.as_raw_fd(),
                            component_c.as_ptr(),
                            buf.as_mut_ptr() as *mut libc::c_char,
                            buf.len(),
                        )
                    };
                    if n <= 0 || n as usize >= buf.len() {
                        return Err(err);
                    }
                    use std::os::unix::ffi::OsStrExt as _;
                    let target = std::ffi::OsStr::from_bytes(&buf[..n as usize]);
                    let target_path = Path::new(target);
                    let resolved_target = if target_path.is_absolute() {
                        normalize_raw(target_path).ok_or(libc::EACCES)?
                    } else {
                        let parent = walked.parent().unwrap_or_else(|| Path::new(""));
                        normalize_raw(&parent.join(target_path)).ok_or(libc::EACCES)?
                    };
                    let target_fd = self.dir_fd_for_hops(&resolved_target, hops + 1)?;
                    self.publish_dir_fd(&walked, &target_fd, generation);
                    current = target_fd;
                    continue;
                }
                return Err(err);
            }
            // SAFETY: `raw` is a freshly-opened owned dir fd.
            let fd = std::sync::Arc::new(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) });
            self.publish_dir_fd(&walked, &fd, generation);
            current = fd;
        }
        Ok(current)
    }

    /// Publish a proven dirfd. Bounded: a path-diverse workload just resets the
    /// cache, which costs re-opens and never correctness — every served entry
    /// is independently generation-checked.
    fn publish_dir_fd(
        &self,
        dir: &Path,
        fd: &std::sync::Arc<std::os::fd::OwnedFd>,
        dir_generation: u64,
    ) {
        if !self.fast_fs {
            return;
        }
        const DIR_CACHE_MAX_ENTRIES: usize = 4096;
        let mut cache = self.dir_cache.lock();
        if cache.len() >= DIR_CACHE_MAX_ENTRIES {
            cache.clear();
        }
        let parent = dir.parent().unwrap_or_else(|| Path::new(""));
        let parent_gen = self.dir_gen_for(parent);
        let stamped_parent_gen = parent_gen.load(std::sync::atomic::Ordering::Relaxed);
        cache.insert(
            dir.to_path_buf(),
            DirCacheEntry {
                fd: fd.clone(),
                parent_gen,
                stamped_parent_gen,
                dir_generation,
            },
        );
    }

    /// The upper half of carrick's namei: turn a normalized sandbox-relative
    /// path into the two things a host `*at` syscall needs — a
    /// containment-proven parent dirfd and the leaf's NUL-terminated name.
    ///
    /// Every path-taking operation that reaches the host should go through
    /// here, so that resolution is paid once per directory instead of once per
    /// call. `None` means "this path is not servable from the cache" (an
    /// intermediate symlink, an escape, a missing parent, a non-UTF-8-safe
    /// name, or the fast path disabled).
    pub(crate) fn namei_leaf(
        &self,
        rel: &Path,
    ) -> Option<(std::sync::Arc<std::os::fd::OwnedFd>, std::ffi::CString)> {
        self.namei_leaf_res(rel).ok()
    }

    fn namei_leaf_res(
        &self,
        rel: &Path,
    ) -> Result<(std::sync::Arc<std::os::fd::OwnedFd>, std::ffi::CString), i32> {
        let name = rel.file_name().ok_or(libc::EINVAL)?;
        let name_c = cstring_from_osstr(name).ok_or(libc::EINVAL)?;
        let parent = rel.parent().unwrap_or_else(|| Path::new(""));
        let parent_fd = self.dir_fd_for(parent)?;
        Ok((parent_fd, name_c))
    }

    /// Open the exact metadata inode without a second ambient path walk.
    /// O_NONBLOCK is mandatory for writerless FIFOs. macOS O_SYMLINK binds
    /// the link itself; other hosts refuse a link instead of following it.
    fn metadata_fd(&self, rel: &Path, follow: bool) -> Result<Arc<std::os::fd::OwnedFd>, i32> {
        let resolved;
        let rel = if follow {
            resolved = self
                .resolve_following(rel.to_str().ok_or(libc::EINVAL)?)
                .ok_or(libc::ELOOP)?;
            resolved.as_path()
        } else {
            rel
        };
        if rel.as_os_str().is_empty() {
            return Ok(self.root_fd.clone());
        }
        let (parent, leaf) = self.namei_leaf_res(rel)?;
        #[cfg(target_os = "macos")]
        let nofollow = libc::O_SYMLINK;
        #[cfg(not(target_os = "macos"))]
        let nofollow = libc::O_NOFOLLOW;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | nofollow,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }
        Ok(Arc::new(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) }))
    }

    /// Ensure all intermediate parent directories for `rel` exist beneath the
    /// contained sandbox root, creating them on demand (similar to `mkdir -p`),
    /// and return the parent directory fd.
    fn ensure_parent_dirs(&self, rel: &Path) -> Result<std::sync::Arc<std::os::fd::OwnedFd>, i32> {
        let parent = rel.parent().unwrap_or_else(|| Path::new(""));
        if parent.as_os_str().is_empty() {
            return self.dir_fd_for(parent);
        }
        if let Ok(fd) = self.dir_fd_for(parent) {
            return Ok(fd);
        }
        let generation = crate::fs_resolve_cache::current_dir_generation();
        let mut current = self.dir_fd_for(Path::new(""))?;
        let mut walked = PathBuf::new();
        let flags = libc::O_RDONLY
            | libc::O_DIRECTORY
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | libc::O_NOFOLLOW;
        for component in parent.iter() {
            walked.push(component);
            let Some(comp_c) = cstring_from_osstr(component) else {
                return Err(libc::EINVAL);
            };
            let rc = unsafe { libc::mkdirat(current.as_raw_fd(), comp_c.as_ptr(), 0o755) };
            if rc != 0 {
                let err = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                if err != libc::EEXIST {
                    return Err(err);
                }
            }
            let raw = unsafe { libc::openat(current.as_raw_fd(), comp_c.as_ptr(), flags, 0) };
            if raw < 0 {
                let err = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                return Err(err);
            }
            let fd = std::sync::Arc::new(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) });
            self.publish_dir_fd(&walked, &fd, generation);
            current = fd;
        }
        Ok(current)
    }

    /// Drop every cached dirfd. Used where this process has just changed
    /// directory topology and must not serve its own stale view before the
    /// shared generation is observed.
    pub(crate) fn drop_dir_cache(&self) {
        self.dir_cache.lock().clear();
    }

    /// Host `openat` calls spent walking paths since the last
    /// [`Self::reset_path_walk_host_opens`]. See [`Self::path_walk_host_opens`].
    pub fn path_walk_host_opens(&self) -> u64 {
        self.path_walk_host_opens
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Zero the path-walk host-open counter so a caller can measure one
    /// guest operation's amplification.
    pub fn reset_path_walk_host_opens(&self) {
        self.path_walk_host_opens
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn cache_eviction_visited_keys(&self) -> u64 {
        self.cache_eviction_visited_keys
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn reset_cache_eviction_visited_keys(&self) {
        self.cache_eviction_visited_keys
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn dir_gen_for(&self, dir: &Path) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        let mut gens = self.dir_generations.lock();
        gens.entry(dir.to_path_buf())
            .or_insert_with(|| std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)))
            .clone()
    }

    /// Evict `dir` and all its descendants from [`Self::dir_cache`] using
    /// ordered BTreeMap range removal.
    fn evict_dir_cache_subtree(&self, dir: &Path) {
        let mut cache = self.dir_cache.lock();
        let mut visited = 0u64;
        let mut to_remove = Vec::new();
        for (k, _) in cache.range(dir.to_path_buf()..) {
            visited += 1;
            if k.as_path() == dir || k.starts_with(dir) {
                to_remove.push(k.clone());
            } else {
                break;
            }
        }
        self.cache_eviction_visited_keys
            .fetch_add(visited, std::sync::atomic::Ordering::Relaxed);
        for k in to_remove {
            cache.remove(&k);
        }
    }

    /// Evict `dir` and all its descendants from [`Self::stat_cache`] using
    /// ordered BTreeMap range removal.
    fn evict_stat_cache_subtree(&self, dir: &Path) {
        if !self.use_stat_cache {
            return;
        }
        let mut stats = self.stat_cache.lock();
        let mut visited = 0u64;
        let mut to_remove = Vec::new();
        for (k, _) in stats.range(dir.to_path_buf()..) {
            visited += 1;
            if k.as_path() == dir || k.starts_with(dir) {
                to_remove.push(k.clone());
            } else {
                break;
            }
        }
        self.cache_eviction_visited_keys
            .fetch_add(visited, std::sync::atomic::Ordering::Relaxed);
        for k in to_remove {
            stats.remove(&k);
        }
    }

    /// The guest's own host open failed with `host_errno`. If that is
    /// descriptor exhaustion and carrick's own directory cache (up to 4096
    /// held dirfds) may be why, reclaim it and report `true`: the caller
    /// retries ONCE — the move a kernel makes when a cache exhausts its
    /// resource, and the same one `dir_fd_for` makes for its own opens. A
    /// second failure is then the guest's answer.
    fn reclaim_for_host_refusal(&self, host_errno: i32) -> bool {
        if !matches!(host_errno, libc::EMFILE | libc::ENFILE) {
            return false;
        }
        let mut cache = self.dir_cache.lock();
        let held = !cache.is_empty();
        cache.clear();
        held
    }

    /// `openat` for the guest's own open, with the one reclaim-and-retry
    /// [`Self::reclaim_for_host_refusal`] allows. `Err` carries the host
    /// errno of the final attempt.
    fn openat_for_guest(
        &self,
        dir_fd: i32,
        name: &std::ffi::CStr,
        flags: i32,
        mode: libc::c_uint,
    ) -> Result<i32, i32> {
        let raw = unsafe { libc::openat(dir_fd, name.as_ptr(), flags, mode) };
        if raw >= 0 {
            return Ok(raw);
        }
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if !self.reclaim_for_host_refusal(errno) {
            return Err(errno);
        }
        let raw = unsafe { libc::openat(dir_fd, name.as_ptr(), flags, mode) };
        if raw >= 0 {
            return Ok(raw);
        }
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
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
    /// Open `rel` ONCE under the sandbox root and resolve everything a stat
    /// needs from the resulting fd: type (`fstat`), sandbox containment
    /// (`F_GETPATH`), and the guest mode/owner/socket xattrs (`fgetxattr`). A
    /// single in-kernel path walk replaces the old `fstatat` + separate
    /// containment `openat` + one `getxattr` PER attribute (each its own full
    /// re-walk of the path; ~7 walks of a deep path per guest stat, see
    /// docs/fs-host-capstd-amplification.md). `O_EVTONLY` opens "for event
    /// monitoring only": `fstat`/`F_GETPATH`/`fgetxattr` all work, but the kernel
    /// records NO access, so atime is preserved exactly as the guest set it (the
    /// property the path-based xattr peeks were introduced for). Returns the
    /// still-open fd (auto-closed on drop, including every early return) so the
    /// caller can read fd-relative xattrs with no further walk. `None` (→ the
    /// cap-std slow path) for symlink leaves, FIFOs/sockets/devices, sandbox
    /// escapes, or any error.
    #[cfg(target_os = "macos")]
    fn fast_open_contained(
        &self,
        rel: &Path,
        follow: bool,
    ) -> Option<(std::os::fd::OwnedFd, libc::stat, RootFsEntryKind)> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        if !self.fast_fs {
            return None;
        }
        let root_prefix = self.root_prefix.as_deref()?;

        // ONE open. O_EVTONLY: event-monitoring open — fstat/F_GETPATH/fgetxattr
        // all work but the kernel records no access, so atime is untouched (this
        // is what made the per-attr path getxattrs necessary; folding them onto
        // one O_EVTONLY fd keeps the atime guarantee AND collapses the walks).
        // O_NONBLOCK so a (racing) FIFO can't wedge the open. O_NOFOLLOW on lstat
        // (`!follow`) so a leaf symlink isn't traversed; on stat (`follow`) it IS
        // traversed and the F_GETPATH containment below proves the *target* is
        // in-sandbox.
        const O_EVTONLY: libc::c_int = 0x8000;
        let mut oflags = O_EVTONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;
        if !follow {
            oflags |= libc::O_NOFOLLOW;
        }

        // Resolve the parent through the kernel directory cache and open the
        // LEAF against it. Two things follow, and both are the point of the
        // cache:
        //
        //  - the directory chain is resolved once per directory instead of once
        //    per call, so the kernel walks one component here, not the path;
        //  - on the `!follow` arm the open is a single component `O_NOFOLLOW`
        //    beneath an already-proven dirfd, which cannot traverse a symlink
        //    and therefore cannot leave the sandbox. Containment is structural
        //    and the `F_GETPATH` is not issued at all — it was 6.43 host
        //    `fcntl`s per guest `openat` on the cold build.
        //
        // The `follow` arm still proves containment explicitly: the leaf symlink
        // IS traversed there and its target may be anywhere.
        let (raw, proven) = match self.namei_leaf(rel) {
            Some((parent_fd, name_c)) => {
                let raw =
                    unsafe { libc::openat(parent_fd.as_raw_fd(), name_c.as_ptr(), oflags, 0) };
                (raw, !follow)
            }
            None => {
                // No cached resolution (an intermediate symlink, a missing
                // parent, the cache disabled): fall back to letting the kernel
                // resolve the whole path from the sandbox root, which must then
                // be proven contained.
                let rel_c = std::ffi::CString::new(rel.as_os_str().as_bytes()).ok()?;
                let raw =
                    unsafe { libc::openat(self.root_fd.as_raw_fd(), rel_c.as_ptr(), oflags, 0) };
                (raw, false)
            }
        };
        if raw < 0 {
            return None; // symlink leaf (O_NOFOLLOW→ELOOP), ENOENT, …
        }
        // SAFETY: `raw` is a freshly-opened owned fd; OwnedFd closes it on drop,
        // covering every `?`/`return None` below as well as the caller's drop.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // Type via fstat on the open fd — no extra path walk.
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(raw, &mut st) } != 0 {
            return None;
        }
        let typ = st.st_mode as u32 & libc::S_IFMT as u32;
        // Regular files report File here; the AF_UNIX-socket-marker check (rare)
        // is folded into the single fd_carrick_meta xattr pass the metadata/stat
        // callers do, so the glob lookup hot path pays no socket read at all.
        let kind = if typ == libc::S_IFDIR as u32 {
            RootFsEntryKind::Directory
        } else if typ == libc::S_IFREG as u32 {
            RootFsEntryKind::File
        } else {
            return None; // symlink/FIFO/socket-node/device
        };

        // Containment: structural containment guarantees that child paths
        // resolved under parent dirfds cannot escape the root. Preserve debug
        // assertions only.
        let _ = (&root_prefix, &proven);
        #[cfg(debug_assertions)]
        if !proven && !fd_contained_under(raw, root_prefix) {
            return None;
        }
        Some((fd, st, kind))
    }

    /// [`HostFsBackend::fast_open_contained`] for callers that only need
    /// `(stat, kind)`, with the same acceptance set (a plain regular file or
    /// directory; everything else is `None` for the exact slow path).
    ///
    /// On the `!follow` arm with a cached parent this is ONE
    /// `fstatat(parent, leaf, AT_SYMLINK_NOFOLLOW)`: a single component that
    /// cannot traverse a symlink beneath an already-contained dirfd is
    /// contained by the same structural argument the open lane relies on, and
    /// a stat records no access, so nothing the `O_EVTONLY` open provided is
    /// lost. That open was `openat`+`fstat`+`close` for a KIND — three host
    /// calls per `lookup_kind`, which is the first probe of every ordinary
    /// guest `open`, `unlink` and `mkdir`. The follow arm keeps the open: a
    /// followed leaf symlink can land anywhere and its target must be proven
    /// contained on the fd.
    #[cfg(target_os = "macos")]
    fn fast_lstat_contained(
        &self,
        rel: &Path,
        follow: bool,
    ) -> Option<(libc::stat, RootFsEntryKind)> {
        use std::os::fd::AsRawFd;
        if !follow
            && self.fast_fs
            && self.root_prefix.is_some()
            && let Some((parent_fd, name_c)) = self.namei_leaf(rel)
        {
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            let rc = unsafe {
                libc::fstatat(
                    parent_fd.as_raw_fd(),
                    name_c.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                return None;
            }
            let typ = st.st_mode as u32 & libc::S_IFMT as u32;
            let kind = if typ == libc::S_IFDIR as u32 {
                RootFsEntryKind::Directory
            } else if typ == libc::S_IFREG as u32 {
                RootFsEntryKind::File
            } else {
                return None;
            };
            return Some((st, kind));
        }
        self.fast_open_contained(rel, follow)
            .map(|(_fd, st, kind)| (st, kind))
    }

    /// Build guest-facing metadata from the already-contained fd fast path.
    ///
    /// This is deliberately limited to the regular-file/directory shapes
    /// accepted by `fast_open_contained`. A symlink, non-regular host file
    /// type, Unicode alias, or escape returns `None` so callers retain the
    /// exact cap-std fallback instead of broadening the fast path's semantics.
    #[cfg(target_os = "macos")]
    fn fast_metadata_contained(&self, normalized: &Path, rel: &Path) -> Option<RootFsMetadata> {
        use std::os::fd::AsRawFd;

        // A repeat lookup of a plain file/directory is ONE revalidating
        // `fstatat` through the cached contained parent (see `stat_cache`),
        // not an open+fstat+xattr pass: `open(2)` of an existing file looked
        // its leaf up this way before opening it, so the probe cost as much
        // as the open. Symlink leaves and exotic types return None from the
        // cache and take the contained-open path below unchanged.
        if self.stat_cache_active()
            && let Some(real) = self.stat_cache_get_or_fill(rel)
        {
            if !self.name_matches_on_disk(rel) {
                return None;
            }
            let is_dir = real.kind == RootFsEntryKind::Directory;
            return Some(RootFsMetadata {
                path: normalized.to_path_buf(),
                kind: real.kind,
                mode: real.mode,
                size: if is_dir {
                    0
                } else {
                    usize::try_from(real.size).unwrap_or(usize::MAX)
                },
            });
        }

        let (fd, st, kind) = self.fast_open_contained(rel, false)?;
        if !self.name_matches_on_disk(rel) {
            return None;
        }
        let is_dir = kind == RootFsEntryKind::Directory;
        let (override_mode, _uid, _gid, is_socket) = fd_carrick_meta(fd.as_raw_fd());
        let kind = if !is_dir && is_socket {
            RootFsEntryKind::Socket
        } else {
            kind
        };
        let on_disk = st.st_mode as u32 & 0o7777;
        let default = if is_dir { 0o755 } else { 0o644 };
        Some(RootFsMetadata {
            path: normalized.to_path_buf(),
            kind,
            mode: override_mode.unwrap_or(if on_disk == 0 { default } else { on_disk }),
            size: if is_dir { 0 } else { st.st_size as usize },
        })
    }

    /// Fd-centric fast path for the guest's own file open (`open_raw_fd`),
    /// sibling of [`HostFsBackend::fast_open_contained`]: ONE `openat` with
    /// the REAL access mode replaces the probe stack (resolve_following's
    /// per-component `symlink_metadata` walk plus the RW-then-RO double
    /// cap-std walk) for the common regular-file case, and the returned fd is
    /// the fd actually served to the guest. Restricted by the callers to
    /// non-creating, non-truncating opens — creating opens keep the full
    /// cap-std path per the sandbox rationale in
    /// docs/fs-host-capstd-amplification.md.
    ///
    /// Unlike the `O_EVTONLY` probes, this IS the guest's open: a regular
    /// file's atime advances exactly as a real `open(2)`+read would, which is
    /// the faithful behavior for a served open.
    #[cfg(target_os = "macos")]
    pub(crate) fn fast_open_for_guest(&self, rel: &Path, write: bool) -> FastGuestOpen {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        if !self.fast_fs {
            return FastGuestOpen::Fallback;
        }
        let Some(root_prefix) = self.root_prefix.as_deref() else {
            return FastGuestOpen::Fallback;
        };
        let Ok(rel_c) = std::ffi::CString::new(rel.as_os_str().as_bytes()) else {
            return FastGuestOpen::Fallback;
        };
        // Resolve the parent through the kernel directory cache and open the
        // leaf against it. Every open on this path is `O_NOFOLLOW`, so a single
        // component beneath an already-proven dirfd cannot traverse a symlink
        // and containment is structural — the `F_GETPATH` below is then not
        // issued at all. Without a cached parent, the kernel resolves the whole
        // path from the sandbox root and containment must be proven explicitly.
        let namei = self.namei_leaf_res(rel);
        let (dir_fd, rel_c, proven) = match &namei {
            Ok((parent_fd, name_c)) => (parent_fd.as_raw_fd(), name_c, true),
            Err(errno) => {
                if let Some(refused) = host_open_refusal(*errno) {
                    return FastGuestOpen::Refused(refused);
                }
                (self.root_fd.as_raw_fd(), &rel_c, false)
            }
        };
        // O_NONBLOCK: a racing FIFO at the leaf must never block this open
        // (the FIFO-never-blocks-the-dispatcher rule); cleared again below
        // before the fd is served. O_NOFOLLOW: a symlink leaf is the typed
        // `SymlinkLeaf` outcome (ELOOP), not a host-side traversal — its
        // absolute target must be re-rooted under the guest root by the slow
        // path. O_NOCTTY: purely defensive — an intermediate absolute symlink
        // can briefly land this open on an arbitrary host node before the
        // containment check rejects it, and that probe must never acquire a
        // controlling terminal.
        let base = libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NOCTTY;
        // The host open carries the guest's OWN access mode. An O_RDWR open of
        // an APFS file costs ~1.7x an O_RDONLY one (10.8 vs 6.3 us measured
        // 2026-09-01), and the majority of guest opens are read-only, so a
        // read request is exactly one O_RDONLY openat — no RW probe. The one
        // consumer that needs a writable host fd behind a guest O_RDONLY
        // description, a live MAP_SHARED alias (HVF caps the alias at the
        // fd's max-protection), upgrades the fd in place at map time through
        // `FsBackend::upgrade_host_fd_for_shared_map` instead of taxing every
        // open for it. A write request failing with its real access mode lets
        // the slow path produce the exact error/None it does today.
        let accmode = if write { libc::O_RDWR } else { libc::O_RDONLY };
        let raw = match self.openat_for_guest(dir_fd, rel_c, accmode | base, 0) {
            Ok(raw) => raw,
            Err(libc::ELOOP) => return FastGuestOpen::SymlinkLeaf,
            Err(libc::ENOENT) if !write => return FastGuestOpen::Missing,
            Err(errno) => {
                return match host_open_refusal(errno) {
                    Some(refused) => FastGuestOpen::Refused(refused),
                    None => FastGuestOpen::Fallback,
                };
            }
        };
        // SAFETY: `raw` is a freshly-opened owned fd; OwnedFd closes it on
        // drop, covering every early return below.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(raw, &mut st) } != 0 {
            return FastGuestOpen::Fallback;
        }
        // Containment: structural containment guarantees that child paths
        // resolved under parent dirfds cannot escape the root. Preserve debug
        // assertions only.
        let _ = (&root_prefix, &proven);
        #[cfg(debug_assertions)]
        if !proven && !fd_contained_under(raw, root_prefix) {
            return FastGuestOpen::Fallback;
        }
        // Byte-exact leaf-name guard against macOS's normalizing VFS, exactly
        // as `lookup`/`metadata` do; ASCII names exit for free.
        if !self.name_matches_on_disk(rel) {
            return FastGuestOpen::Fallback;
        }
        let typ = st.st_mode as u32 & libc::S_IFMT as u32;
        let kind = if typ == libc::S_IFDIR as u32 {
            RootFsEntryKind::Directory
        } else if typ == libc::S_IFREG as u32 {
            RootFsEntryKind::File
        } else if typ == libc::S_IFIFO as u32 {
            // Contained FIFO (a create race — the dispatcher normally
            // intercepts FIFOs before the file-open path): the probe fd
            // drops/closes and the caller routes to open_fifo_nonblock.
            return FastGuestOpen::Fifo;
        } else {
            // Socket-marker files stat as S_IFREG (served above); a real
            // socket/device node here means an escape-shaped oddity → the
            // exact slow path.
            return FastGuestOpen::Fallback;
        };
        // The fd stays O_NONBLOCK: that is the dispatcher's invariant for
        // every host-backed fd (see the `open_raw_fd` contract), and the
        // guest's OWN requested flags (its O_NONBLOCK, the O_APPEND
        // emulation) live in the OpenDescription, never on the host fd.
        FastGuestOpen::Served { fd, stat: st, kind }
    }

    /// Create-open of a NEW regular file as ONE `openat(O_CREAT)` against the
    /// cached, containment-proven parent dirfd, sibling of
    /// [`Self::fast_open_for_guest`] for the creating case.
    ///
    /// The `O_CREAT` sandbox finding in docs/fs-host-capstd-amplification.md
    /// is about a MULTI-component `openat(root_fd, "link/file", O_CREAT)`:
    /// `O_NOFOLLOW` guards only the leaf, so an intermediate symlink creates
    /// the file outside the root before any containment check can run. That
    /// shape cannot occur here: the parent comes from the kernel directory
    /// cache, which walked it one `O_NOFOLLOW|O_DIRECTORY` component at a
    /// time and proved it under the root, and the leaf is a single slash-free
    /// component opened `O_NOFOLLOW` — the create lands in exactly that
    /// directory. Without a cached parent there is no proven anchor and the
    /// caller keeps the cap-std path (which also materialises missing
    /// ancestors).
    ///
    /// The guest's umask-applied `mode` is applied on the held fd (`fchmod`
    /// only when the host umask would have masked a requested bit), so the
    /// file needs no path-based `set_mode` afterwards — that was a stat, an
    /// open+fchmod and an open+fremovexattr per `creat(2)`. A mode carrick
    /// cannot represent natively (no owner rw) is created owner-rw and
    /// reported `mode_applied = false` so the caller records it via the
    /// xattr override exactly as before.
    #[cfg(target_os = "macos")]
    fn fast_create_for_guest(&self, rel: &Path, mode: u32, trunc: bool) -> HostFdOpen<(i32, bool)> {
        use std::os::fd::AsRawFd;
        if !self.fast_fs || self.root_prefix.is_none() {
            return HostFdOpen::Unavailable;
        }
        let (parent_fd, name_c) = match self.namei_leaf_res(rel) {
            Ok(pair) => pair,
            Err(errno) => {
                return match host_open_refusal(errno) {
                    Some(refused) => HostFdOpen::Refused(refused),
                    None => HostFdOpen::Unavailable,
                };
            }
        };
        let mode = mode & 0o7777;
        let representable = mode & 0o600 == 0o600;
        let host_mode = if representable { mode } else { mode | 0o600 };
        // O_EXCL: the layered view proved the path absent, so a host entry
        // there is a shape this lane does not describe (EEXIST → the exact
        // cap-std path, which opens it as before). It also makes "created
        // now" a kernel fact rather than an inference, so the mode fix-up
        // below can never touch a pre-existing file's mode.
        let mut flags = libc::O_RDWR
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NOCTTY
            | libc::O_NONBLOCK;
        if trunc {
            flags |= libc::O_TRUNC;
        }
        let raw = match self.openat_for_guest(
            parent_fd.as_raw_fd(),
            &name_c,
            flags,
            host_mode as libc::c_uint,
        ) {
            Ok(raw) => raw,
            Err(errno) => {
                return match host_open_refusal(errno) {
                    Some(refused) => HostFdOpen::Refused(refused),
                    None => HostFdOpen::Unavailable,
                };
            }
        };
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(raw, &mut st) } != 0
            || st.st_mode as u32 & libc::S_IFMT as u32 != libc::S_IFREG as u32
        {
            // A raced-in FIFO/device/socket at the leaf: not the regular file
            // this lane promises; the exact cap-std path decides.
            unsafe {
                libc::close(raw);
            }
            return HostFdOpen::Unavailable;
        }
        if !self.name_matches_on_disk(rel) {
            unsafe {
                libc::close(raw);
            }
            return HostFdOpen::Unavailable;
        }
        // The kernel applied the host umask to `host_mode` and may drop a
        // setuid/setgid/sticky bit at creation; only a requested bit in
        // those classes needs the fchmod.
        if representable && mode & (host_umask() | 0o7000) != 0 {
            unsafe {
                libc::fchmod(raw, mode as libc::mode_t);
            }
        }
        HostFdOpen::Served((raw, representable))
    }

    /// Prove that an ENOENT from `fast_open_for_guest` is a real miss in this
    /// immutable tree. Walk upward only across ENOENT ancestors until an
    /// existing directory can be opened and containment-checked. Encountering
    /// a symlink leaf (ELOOP), non-directory, escape, Unicode alias, or any
    /// unexpected host error fails closed to the layered resolver.
    #[cfg(target_os = "macos")]
    fn missing_below_contained_ancestor(&self, rel: &Path) -> bool {
        use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
        use std::os::unix::ffi::OsStrExt as _;

        let Some(root_prefix) = self.root_prefix.as_deref() else {
            return false;
        };
        let mut candidate = rel.parent();
        loop {
            let Some(parent) = candidate else {
                return true;
            };
            if parent.as_os_str().is_empty() {
                // `self.root_fd` is the already-open immutable root authority.
                return true;
            }
            let Ok(parent_c) = std::ffi::CString::new(parent.as_os_str().as_bytes()) else {
                return false;
            };
            const O_EVTONLY: libc::c_int = 0x8000;
            let raw = unsafe {
                libc::openat(
                    self.root_fd.as_raw_fd(),
                    parent_c.as_ptr(),
                    O_EVTONLY
                        | libc::O_NONBLOCK
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW
                        | libc::O_NOCTTY,
                    0,
                )
            };
            if raw < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                    candidate = parent.parent();
                    continue;
                }
                return false;
            }
            // SAFETY: `raw` is a freshly-opened owned descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut stat: libc::stat = unsafe { core::mem::zeroed() };
            if unsafe { libc::fstat(raw, &mut stat) } != 0
                || stat.st_mode as u32 & libc::S_IFMT as u32 != libc::S_IFDIR as u32
                || !fd_contained_under(raw, root_prefix)
                || !self.name_matches_on_disk(parent)
            {
                return false;
            }
            drop(fd);
            return true;
        }
    }

    /// Immutable-lower sibling of `open_raw_fd_with_metadata`: successful
    /// files and authoritative contained misses are typed separately from the
    /// semantic fallback cases.
    pub(crate) fn open_immutable_file_readonly(&self, path: &str) -> ImmutableHostFileOpen {
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd as _;

            let Some(normalized) = normalize(path) else {
                return ImmutableHostFileOpen::Fallback;
            };
            let Some(rel) = Self::rel_path(&normalized) else {
                return ImmutableHostFileOpen::Fallback;
            };
            match self.fast_open_for_guest(rel, false) {
                FastGuestOpen::Served {
                    fd,
                    stat,
                    kind: RootFsEntryKind::File,
                } => {
                    let (override_mode, _uid, _gid, is_socket) = fd_carrick_meta(fd.as_raw_fd());
                    if is_socket {
                        return ImmutableHostFileOpen::Fallback;
                    }
                    let on_disk_mode = stat.st_mode as u32 & 0o7777;
                    let mode = override_mode.unwrap_or(if on_disk_mode == 0 {
                        0o644
                    } else {
                        on_disk_mode
                    });
                    ImmutableHostFileOpen::Served {
                        file: std::fs::File::from(fd),
                        metadata: RootFsMetadata {
                            // GUEST-ABSOLUTE, not the sandbox-relative form
                            // `normalize` produces (it drops `RootDir`). This
                            // metadata becomes an `OpenDescription::HostFile`,
                            // whose `path` IS the guest path the fd was opened
                            // at — `open_path()` serves it to `execveat`
                            // AT_EMPTY_PATH (fexecve) and to `fchown`/`futimens`
                            // path resolution. Every sibling producer of a
                            // served `HostFile` stores the absolute path; this
                            // lane storing `usr/local/bin/python3.12` made
                            // `fexecve` re-resolve against the caller's cwd, so
                            // it only worked while the cwd was `/`.
                            path: Path::new("/").join(&normalized),
                            kind: RootFsEntryKind::File,
                            mode,
                            size: stat.st_size as usize,
                        },
                    }
                }
                FastGuestOpen::Missing if self.missing_below_contained_ancestor(rel) => {
                    ImmutableHostFileOpen::Missing
                }
                // A host refusal is reported by the exact open the fallback
                // performs (`open_raw_fd_with_metadata` → `Refused`), where
                // the dispatcher owns the errno.
                FastGuestOpen::Served { .. }
                | FastGuestOpen::SymlinkLeaf
                | FastGuestOpen::Fifo
                | FastGuestOpen::Missing
                | FastGuestOpen::Fallback
                | FastGuestOpen::Refused(_) => ImmutableHostFileOpen::Fallback,
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = path;
            ImmutableHostFileOpen::Fallback
        }
    }

    /// A plain `O_RDONLY` fd on the sandbox root itself, for root-directory
    /// xattr reads/writes. cap-std's dir handle is `O_PATH` on Linux and
    /// `f*xattr` on an `O_PATH` fd is `EBADF` (see `with_entry_fd`), so
    /// re-open `.` relative to it — valid on every host OS.
    fn root_meta_fd(&self) -> Option<std::os::fd::OwnedFd> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let raw = unsafe {
            libc::openat(
                self.root_fd.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return None;
        }
        // SAFETY: freshly-opened owned fd.
        Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) })
    }

    /// Durable sandbox-root marker read (tri-state; see [`RootMarker`]). Backs
    /// both [`FsBackend::may_have_fifo_nodes`] ([`CARRICK_HAS_FIFO_XATTR`]) and
    /// [`FsBackend::dir_has_overlay_interference`]
    /// ([`CARRICK_HAS_MARKER_NODES_XATTR`]).
    fn root_marker_xattr(&self, name: &[u8]) -> RootMarker {
        use std::os::fd::AsRawFd;
        let Some(fd) = self.root_meta_fd() else {
            return RootMarker::Unknown;
        };
        let mut v = [0u8; 4];
        // SAFETY: valid fd, NUL-terminated name, in-bounds buffer.
        let n = unsafe {
            carrick_portable::fgetxattr(
                fd.as_raw_fd(),
                name.as_ptr() as *const libc::c_char,
                v.as_mut_ptr() as *mut libc::c_void,
                v.len(),
            )
        };
        if n >= 0 {
            return RootMarker::Present;
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(XATTR_ABSENT_ERRNO) {
            RootMarker::Absent
        } else {
            RootMarker::Unknown
        }
    }

    /// Stamp a durable marker xattr on the sandbox root. Called BEFORE the
    /// node that motivates it exists, so no process can ever observe the node
    /// while the corresponding query still answers "none".
    fn stamp_root_marker(&self, name: &[u8], seen: &std::sync::atomic::AtomicBool) {
        use std::os::fd::AsRawFd;
        if let Some(fd) = self.root_meta_fd() {
            fset_u32_xattr(fd.as_raw_fd(), name, 1);
        }
        seen.store(true, std::sync::atomic::Ordering::Relaxed);
        // After the xattr is durable: every process's cached ABSENT reading of
        // any root marker is now stale (see `current_marker_generation`).
        crate::fs_resolve_cache::bump_marker_generation();
    }

    /// Record that entries under this root MAY carry guest metadata xattrs
    /// without the root itself carrying the durable marker. A published
    /// layer-cache entry is such a root: its per-entry mode xattrs were
    /// written by the extraction, not by `set_mode`, and only its
    /// `CLEAN_META_MARKER` file (absent = conservative) says whether any
    /// exist. This backend never mutates, so the sticky in-process reading is
    /// the complete truth for it and `serves_plain_metadata` fails closed.
    pub(crate) fn assume_meta_xattrs(&self) {
        self.meta_xattr_seen
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Stamp the durable FIFO marker on the sandbox root. Called by
    /// `create_fifo` BEFORE the node exists, so no process can ever observe a
    /// FIFO while `may_have_fifo_nodes` still answers false.
    fn stamp_fifo_marker(&self) {
        self.stamp_root_marker(CARRICK_HAS_FIFO_XATTR, &self.fifo_seen);
    }

    /// Stamp the durable marker-node marker (socket/device marker files whose
    /// guest type lives in xattrs) on the sandbox root. Called by
    /// `create_socket`/`create_device` BEFORE the node exists, so no process
    /// can stream a directory while a marker node is observable in it.
    fn stamp_marker_node_marker(&self) {
        self.stamp_root_marker(CARRICK_HAS_MARKER_NODES_XATTR, &self.marker_seen);
    }

    fn may_have_whiteouts(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        if self.whiteout_seen.load(Relaxed) {
            return true;
        }
        let now = crate::fs_resolve_cache::current_marker_generation();
        if self.whiteout_absent_gen.load(Relaxed) == now {
            return false;
        }
        match self.root_marker_xattr(CARRICK_HAS_WHITEOUTS_XATTR) {
            RootMarker::Present => {
                self.whiteout_seen.store(true, Relaxed);
                true
            }
            RootMarker::Absent => {
                self.whiteout_absent_gen.store(now, Relaxed);
                false
            }
            // Fail closed: checking for a sidecar is safe on a filesystem that
            // cannot carry the root xattr; incorrectly skipping one is not.
            RootMarker::Unknown => true,
        }
    }

    fn may_have_upper_symlinks(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        if self.symlink_seen.load(Relaxed) {
            return true;
        }
        let now = crate::fs_resolve_cache::current_marker_generation();
        if self.symlink_absent_gen.load(Relaxed) == now {
            return false;
        }
        match self.root_marker_xattr(CARRICK_HAS_SYMLINKS_XATTR) {
            RootMarker::Present => {
                self.symlink_seen.store(true, Relaxed);
                true
            }
            RootMarker::Absent => {
                self.symlink_absent_gen.store(now, Relaxed);
                false
            }
            RootMarker::Unknown => true,
        }
    }

    /// One kernel lookup proves an entry absent from a sparse upper. The proof
    /// is valid only while the upper has never contained a symlink: otherwise
    /// an intermediate absolute/relative link requires Carrick's Linux-rooted
    /// layered resolver rather than Darwin's host-rooted path walk.
    #[cfg(target_os = "macos")]
    fn sparse_upper_nofollow_absent(&self, path: &str) -> bool {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::ffi::OsStrExt as _;

        if !self.sparse_upper_fast_miss || !self.fast_fs {
            return false;
        }
        let generation = self.structural_generation();
        // Whiteouts can hide an entire lower directory, so checking only the
        // queried leaf cannot prove the layered path. Keep the fast miss
        // armed only while the sparse upper has never published any
        // whiteout; workloads without lower deletions retain the one-call
        // proof, and the first deletion fails closed globally.
        if self.may_have_upper_symlinks() || self.may_have_whiteouts() {
            return false;
        }
        let Some(normalized) = normalize(path) else {
            return false;
        };
        let Some(rel) = Self::rel_path(&normalized) else {
            return false;
        };
        let Ok(path) = std::ffi::CString::new(rel.as_os_str().as_bytes()) else {
            return false;
        };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let rc = unsafe {
            libc::fstatat(
                self.root_fd.as_raw_fd(),
                path.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        rc < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
            // A symlink creator stamps its durable marker and bumps BEFORE
            // publishing the link. Any concurrent structural change therefore
            // invalidates the proof instead of racing it into a false miss.
            && self.structural_generation() == generation
    }

    #[cfg(not(target_os = "macos"))]
    fn sparse_upper_nofollow_absent(&self, _path: &str) -> bool {
        false
    }

    fn is_whiteouted_normalized(&self, normalized: &Path) -> bool {
        use std::os::unix::ffi::OsStrExt as _;
        if !self.may_have_whiteouts() {
            return false;
        }
        let Some(marker) = host_whiteout_sidecar_rel(normalized) else {
            return false;
        };
        let Some(leaf) = normalized.file_name() else {
            return false;
        };
        let Some((parent_fd, leaf_c)) = self.namei_leaf(&marker) else {
            return false;
        };
        use std::os::fd::AsRawFd as _;
        let raw = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            )
        };
        if raw < 0 {
            return false;
        }
        use std::io::Read as _;
        use std::os::fd::FromRawFd as _;
        let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
        let mut stored = Vec::new();
        if file.read_to_end(&mut stored).is_err() {
            return false;
        }
        stored == leaf.as_bytes()
    }

    fn clear_whiteout_normalized(&self, normalized: &Path) {
        if !self.may_have_whiteouts() {
            return;
        }
        let Some(marker) = host_whiteout_sidecar_rel(normalized) else {
            return;
        };
        if let Some((parent_fd, leaf_c)) = self.namei_leaf(&marker) {
            use std::os::fd::AsRawFd as _;
            unsafe {
                libc::unlinkat(parent_fd.as_raw_fd(), leaf_c.as_ptr(), 0);
            }
        }
    }

    fn write_whiteout_normalized(&self, normalized: &Path) -> Result<(), BackendError> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::ffi::OsStrExt as _;
        let marker = host_whiteout_sidecar_rel(normalized).ok_or(BackendError::Invalid)?;
        let leaf = normalized.file_name().ok_or(BackendError::Invalid)?;
        self.stamp_root_marker(CARRICK_HAS_WHITEOUTS_XATTR, &self.whiteout_seen);
        let parent_fd = self
            .ensure_parent_dirs(&marker)
            .map_err(|_| BackendError::Io)?;
        let leaf_c = cstring_from_osstr(marker.file_name().ok_or(BackendError::Invalid)?)
            .ok_or(BackendError::Invalid)?;
        unsafe {
            libc::unlinkat(parent_fd.as_raw_fd(), leaf_c.as_ptr(), 0);
        }
        let raw = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o644,
            )
        };
        if raw < 0 {
            return Err(BackendError::Io);
        }
        use std::io::Write as _;
        use std::os::fd::FromRawFd as _;
        let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
        file.write_all(leaf.as_bytes())
            .map_err(|_| BackendError::Io)?;
        // This is the deletion's cross-process linearization point: the
        // sidecar is durable before every forked process's cached-absent
        // generation becomes stale.
        crate::fs_resolve_cache::bump_generation();
        Ok(())
    }

    /// Single host `openat` implementation for [`FsBackend::open_raw_fd`]:
    /// manual leaf symlink resolution (absolute targets re-rooted under the guest root)
    /// followed by single `openat` under the contained parent.
    fn open_raw_fd_impl(
        &self,
        path: &str,
        write: bool,
        create: bool,
        trunc: bool,
    ) -> HostFdOpen<i32> {
        let Some(normalized) = self.resolve_following(path) else {
            return HostFdOpen::Unavailable;
        };
        let Some(rel) = Self::rel_path(&normalized) else {
            return HostFdOpen::Unavailable;
        };
        let (parent_fd, leaf_c) = if create {
            match self.ensure_parent_dirs(rel) {
                Ok(parent) => match rel.file_name().and_then(cstring_from_osstr) {
                    Some(leaf) => (parent, leaf),
                    None => return HostFdOpen::Unavailable,
                },
                Err(errno) => {
                    return match host_open_refusal(errno) {
                        Some(refused) => HostFdOpen::Refused(refused),
                        None => HostFdOpen::Unavailable,
                    };
                }
            }
        } else {
            match self.namei_leaf_res(rel) {
                Ok(pair) => pair,
                Err(errno) => {
                    return match host_open_refusal(errno) {
                        Some(refused) => HostFdOpen::Refused(refused),
                        None => HostFdOpen::Unavailable,
                    };
                }
            }
        };
        let mut flags = if write { libc::O_RDWR } else { libc::O_RDONLY };
        flags |= libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        if create {
            flags |= libc::O_CREAT;
        }
        if trunc {
            flags |= libc::O_TRUNC;
        }
        use std::os::fd::AsRawFd as _;
        match self.openat_for_guest(parent_fd.as_raw_fd(), &leaf_c, flags, 0o666) {
            Ok(fd) => HostFdOpen::Served(fd),
            Err(errno) => match host_open_refusal(errno) {
                Some(refused) => HostFdOpen::Refused(refused),
                None => HostFdOpen::Unavailable,
            },
        }
    }

    #[cfg(target_os = "macos")]
    fn fast_real_stat(&self, normalized: &Path, follow: bool) -> Option<RealStat> {
        use std::os::fd::AsRawFd;
        let rel = Self::rel_path(normalized)?; // None == root dir: let cap-std handle

        // Opt-in stat cache: a repeat stat of a non-symlink leaf is served by one
        // revalidating fstatat through the cached contained parent fd, skipping
        // both containment opens and the xattr reads. Returns None for symlink
        // leaves / misses-that-aren't-cacheable, which fall through to the
        // (uncached) fd-centric path below. See `stat_cache`.
        if self.stat_cache_active()
            && let Some(rs) = self.stat_cache_get_or_fill(rel)
        {
            return Some(rs);
        }

        let (fd, st, kind) = self.fast_open_contained(rel, follow)?;
        let raw = fd.as_raw_fd();

        // mode/owner/socket via ONE flistxattr-gated pass on the ALREADY-OPEN fd
        // — no path walk, no atime bump. Symlink leaves never reach here
        // (fast_open_contained returns None for them), so the link-following
        // owner reads (XATTR_NOFOLLOW) stay on the cap-std slow path.
        let is_dir = kind == RootFsEntryKind::Directory;
        let (override_mode, uid, gid, is_socket) = fd_carrick_meta(raw);
        // A regular file carrying the socket marker reports S_IFSOCK.
        let kind = if !is_dir && is_socket {
            RootFsEntryKind::Socket
        } else {
            kind
        };
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
            uid: uid.unwrap_or(NsUid::ROOT),
            gid: gid.unwrap_or(NsGid::ROOT),
            size: st.st_size as u64,
            blocks: Some(st.st_blocks.max(0) as u64),
            atime: (st.st_atime, carrick_portable::stat_atime_nsec(&st)),
            mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(&st)),
            ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(&st)),
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

    /// Drop this process's cached stat entries and dirfds after a rename or
    /// exchange it performed itself.
    ///
    /// The DURABLE invalidation is the shared directory-topology generation
    /// (`fs_resolve_cache::bump_dir_generation`), which every process observes
    /// and which the caller bumps. This clear is the local half: it stops this
    /// process from serving its own in-flight entries between the mutation and
    /// its next generation read, and it releases the dirfds immediately rather
    /// than leaving them to be evicted lazily.
    ///
    /// LOCK ORDER `stat_cache` -> `dir_cache`; `dir_cache` is never taken
    /// first, so [`Self::dir_fd_for`] must never be called while holding
    /// `stat_cache`.
    fn drop_stat_cache_after_rename(&self) {
        let mut map = self.stat_cache.lock();
        map.clear();
        self.drop_dir_cache();
    }

    /// The stat cache may be consulted: enabled (default ON) and the `--fs host`
    /// fast path is live. Cross-process coherence is handled inside `stat_cache_get_or_fill`
    /// (clear-on-fork + per-hit revalidation), not by gating on a pid. See
    /// `stat_cache`.
    #[cfg(target_os = "macos")]
    pub(crate) fn stat_cache_active(&self) -> bool {
        self.use_stat_cache && self.fast_fs && self.root_prefix.is_some()
    }

    /// Serve `rel`'s `RealStat` from the cache, revalidating with one
    /// `fstatat(parent_fd, name, AT_NOFOLLOW)`; on a miss, open the CONTAINED
    /// parent, lstat the leaf, read its xattr metadata, and cache the result
    /// keyed on the leaf path. Returns `None` (→ the uncached fd-centric path /
    /// cap-std handles it) for symlink leaves, FIFOs/devices, escapes, or errors
    /// — i.e. anything not a plain contained regular file or directory.
    #[cfg(target_os = "macos")]
    pub(crate) fn stat_cache_get_or_fill(&self, rel: &Path) -> Option<RealStat> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        const O_EVTONLY: libc::c_int = 0x8000;

        let name = rel.file_name()?; // leaf is always a single component here
        let name_c = std::ffi::CString::new(name.as_bytes()).ok()?;

        // --- Revalidate an existing entry: ONE fstatat through the cached,
        //     already-contained parent fd (no path walk, no openat). Clone the
        //     needed bits out from under the lock so the syscall runs unlocked.
        //     Under the same lock, adopt-and-clear if we crossed a fork (a child
        //     must not trust the parent's inherited fds).
        //
        //     An entry whose parent dirfd was proven at an older directory
        //     generation is NOT served: a rename in this or any other process
        //     may have moved the directory the fd names, and identity
        //     revalidation cannot see that — the inode, ctime and size are all
        //     unchanged at the new location.
        let proc_gen = crate::fs_resolve_cache::current_process_generation();
        let meta_generation = crate::fs_resolve_cache::current_meta_generation();
        let dir_generation = crate::fs_resolve_cache::current_dir_generation();
        let cached = {
            use std::sync::atomic::Ordering::Relaxed;
            let mut map = self.stat_cache.lock();
            if self.cache_proc_gen.load(Relaxed) != proc_gen {
                map.clear();
                // LOCK ORDER `stat_cache` -> `dir_cache`; this is the only site
                // that holds both, and `dir_cache` is never taken first.
                self.drop_dir_cache();
                self.cache_proc_gen.store(proc_gen, Relaxed);
            }
            map.get(rel)
                .filter(|e| e.is_valid(dir_generation))
                .map(|e| {
                    (
                        e.parent_fd.clone(),
                        e.ino,
                        e.birth,
                        e.meta_generation,
                        e.mode_override,
                        e.real,
                    )
                })
        };
        if let Some((parent_fd, ino, birth, entry_meta_generation, mode_override, real)) = cached {
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            let ok = unsafe {
                libc::fstatat(
                    parent_fd.as_raw_fd(),
                    name_c.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0;
            let typ = st.st_mode as u32 & libc::S_IFMT as u32;
            let is_dir = real.kind == RootFsEntryKind::Directory;
            let same_type = if is_dir {
                typ == libc::S_IFDIR as u32
            } else {
                typ == libc::S_IFREG as u32
            };
            // The same inode, still the same type, and no carrick metadata
            // writer since the fill ⇒ the xattr-derived fields (mode override,
            // owner, socket marker) still hold. Everything else the guest can
            // observe — size, times, nlink, an on-disk (override-less) mode —
            // is answered by the fresh `fstatat` itself. This is deliberately
            // NOT a timestamp comparison: a directory's ctime/mtime/size move
            // on every child create/unlink and a file's on every append, and
            // treating that as stale re-ran the whole xattr pass per lookup.
            if ok
                && st.st_ino == ino
                && (st.st_birthtime, st.st_birthtime_nsec) == birth
                && same_type
                && entry_meta_generation == meta_generation
            {
                let on_disk_mode = st.st_mode as u32 & 0o7777;
                let default_mode = if is_dir { 0o755 } else { 0o644 };
                return Some(RealStat {
                    ino: st.st_ino,
                    nlink: st.st_nlink as u32,
                    mode: mode_override.unwrap_or(if on_disk_mode == 0 {
                        default_mode
                    } else {
                        on_disk_mode
                    }),
                    size: st.st_size as u64,
                    blocks: Some(st.st_blocks.max(0) as u64),
                    atime: (st.st_atime, carrick_portable::stat_atime_nsec(&st)),
                    mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(&st)),
                    ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(&st)),
                    ..real
                });
            }
            // Stale (replaced / removed / now a symlink / metadata rewritten):
            // drop and re-fill.
            self.stat_cache.lock().remove(rel);
        }

        // --- Fill: resolve the parent through the kernel directory cache (zero
        //     host syscalls once that directory is known), lstat the leaf, read
        //     its metadata, then cache. Sibling leaves of one directory are the
        //     overwhelming case — a package dir, a `bin/` — so this is where the
        //     per-directory resolution is amortised away.
        //
        //     Called with NO lock held: LOCK ORDER is `stat_cache` ->
        //     `dir_cache`, and `dir_fd_for` takes `dir_cache`.
        let parent = rel.parent().unwrap_or_else(|| Path::new(""));
        let parent_fd = self.dir_fd_for(parent).ok()?;

        // lstat the leaf relative to the contained parent — a single component
        // under a trusted anchor cannot escape it (AT_SYMLINK_NOFOLLOW: a symlink
        // leaf is reported, not traversed).
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                name_c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return None;
        }
        let typ = st.st_mode as u32 & libc::S_IFMT as u32;
        let is_dir = typ == libc::S_IFDIR as u32;
        if !is_dir && typ != libc::S_IFREG as u32 {
            return None; // symlink/FIFO/device → existing path / cap-std
        }

        // Metadata via one flistxattr-gated fd pass (O_NOFOLLOW: confirmed
        // non-symlink; O_EVTONLY: no atime bump). Skipped outright while the
        // root markers prove no entry anywhere carries a mode/owner xattr or
        // a socket/device marker: the inode alone is then the complete guest
        // answer, and a cold file costs one fstatat instead of fstatat +
        // openat + flistxattr + close. The first `set_mode`/`set_owner`
        // that needs an xattr stamps the marker BEFORE writing it, and the
        // write itself bumps the inode's ctime, so an entry cached under the
        // plain reading revalidates stale and refills through the xattr pass.
        // Sampled BEFORE the xattr read: a writer landing between the read
        // and the insert bumps past this value, so the entry is born stale
        // and refills on its first hit instead of serving the pre-write bytes.
        let meta_generation = crate::fs_resolve_cache::current_meta_generation();
        let dir_generation = crate::fs_resolve_cache::current_dir_generation();
        let (override_mode, uid, gid, is_socket) = if self.serves_plain_metadata() {
            (None, None, None, false)
        } else {
            let leaf_flags = O_EVTONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
            let leaf_raw =
                unsafe { libc::openat(parent_fd.as_raw_fd(), name_c.as_ptr(), leaf_flags, 0) };
            if leaf_raw < 0 {
                return None;
            }
            let leaf_fd = unsafe { OwnedFd::from_raw_fd(leaf_raw) };
            fd_carrick_meta(leaf_fd.as_raw_fd())
        };
        let kind = if is_dir {
            RootFsEntryKind::Directory
        } else if is_socket {
            RootFsEntryKind::Socket
        } else {
            RootFsEntryKind::File
        };
        let on_disk_mode = st.st_mode as u32 & 0o7777;
        let default_mode = if is_dir { 0o755 } else { 0o644 };
        let real = RealStat {
            kind,
            ino: st.st_ino,
            nlink: st.st_nlink as u32,
            mode: override_mode.unwrap_or(if on_disk_mode == 0 {
                default_mode
            } else {
                on_disk_mode
            }),
            uid: uid.unwrap_or(NsUid::ROOT),
            gid: gid.unwrap_or(NsGid::ROOT),
            size: st.st_size as u64,
            blocks: Some(st.st_blocks.max(0) as u64),
            atime: (st.st_atime, carrick_portable::stat_atime_nsec(&st)),
            mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(&st)),
            ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(&st)),
        };
        let mut map = self.stat_cache.lock();
        // Bounded: a pathological working set just resets the cache (correctness
        // is unaffected — every entry is independently revalidated on hit).
        if map.len() >= 4096 {
            map.clear();
        }
        let parent = rel.parent().unwrap_or_else(|| Path::new(""));
        let parent_gen = self.dir_gen_for(parent);
        let stamped_parent_gen = parent_gen.load(std::sync::atomic::Ordering::Relaxed);
        map.insert(
            rel.to_path_buf(),
            StatCacheEntry {
                parent_fd,
                parent_gen,
                stamped_parent_gen,
                dir_generation,
                meta_generation,
                mode_override: override_mode,
                ino: st.st_ino,
                birth: (st.st_birthtime, st.st_birthtime_nsec),
                real,
            },
        );
        Some(real)
    }

    #[cfg(not(target_os = "macos"))]
    pub(crate) fn stat_cache_active(&self) -> bool {
        false
    }

    #[cfg(not(target_os = "macos"))]
    pub(crate) fn stat_cache_get_or_fill(&self, _rel: &Path) -> Option<RealStat> {
        None
    }

    /// Stream OCI layer blobs directly into the scratch Dir (the on-demand
    /// rootfs path for `--fs host`). Replaces build-RootFs-then-seed: never
    /// materializes the in-memory tree. The Dir is authoritative afterward.
    pub fn extract_layers(
        &mut self,
        paths: &[std::path::PathBuf],
    ) -> std::io::Result<crate::rootfs::ExtractStats> {
        // Fastest path (Linux, opt-in via CARRICK_FS_OVERLAY): compose the rootfs
        // as an overlayfs mount — lowerdir = the shared digest-keyed cached
        // extraction (read-only, never copied), upperdir = this run's writes —
        // instead of cloning/copying the whole tree per run. On a filesystem
        // without reflink (e.g. ext4, or ZFS in an unprivileged container where
        // FICLONE is denied) the clone path degrades to a full byte-copy, which
        // dominates per-run latency; an overlay mount is O(1) and keeps per-run
        // isolation (each run's writes land in its own upperdir).
        #[cfg(target_os = "linux")]
        if overlay_enabled()
            && let Some(scratch) = self._scratch.as_ref().map(|t| t.path().to_path_buf())
        {
            if let Ok(Some(merged)) = crate::layer_cache::overlay_seed_scratch(paths, &scratch) {
                let merged_c = std::ffi::CString::new(merged.as_os_str().as_encoded_bytes())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                let raw = unsafe {
                    libc::open(
                        merged_c.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                };
                if raw < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let root_fd =
                    std::sync::Arc::new(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) });
                self.root_prefix = host_root_prefix(&root_fd);
                self.root_path = merged.clone();
                self.root_fd = root_fd;
                self.overlay_mount = Some(merged);
                return Ok(crate::rootfs::ExtractStats::default());
            }
            // overlay unavailable/failed → fall through to the clone/copy path.
        }
        // Fast path: seed the scratch from the digest-keyed clonefile cache (an
        // O(1) COW clone of a once-extracted layer stack) instead of re-doing a
        // full byte-copy extraction. Only when we own a real scratch TempDir
        // (the production path); tests using `from_existing_dir` have no path to
        // anchor the cache against and fall straight through.
        if let Some(scratch) = self._scratch.as_ref().map(|t| t.path().to_path_buf())
            && let Ok(seed) = crate::layer_cache::try_seed_scratch(paths, &scratch)
            && seed.cloned
        {
            // The clone reproduces the same on-disk tree a direct extraction
            // would; per-file ExtractStats aren't recovered for a cache hit.
            // Entry xattrs cloned with the tree; the cache's sentinel says
            // whether any exist, re-arming the metadata-xattr root marker the
            // scratch-root clone cannot carry.
            if seed.cache_has_mode_xattrs {
                self.stamp_root_marker(CARRICK_HAS_META_XATTRS_XATTR, &self.meta_xattr_seen);
            }
            return Ok(crate::rootfs::ExtractStats::default());
        }
        let stats = crate::rootfs::extract_layer_paths_to_dir(paths, &self.root_path)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        if stats.mode_xattrs > 0 {
            self.stamp_root_marker(CARRICK_HAS_META_XATTRS_XATTR, &self.meta_xattr_seen);
        }
        Ok(stats)
    }

    fn rel_path(normalized: &Path) -> Option<&Path> {
        if normalized.as_os_str().is_empty() {
            None
        } else {
            Some(normalized)
        }
    }

    pub(crate) fn read_dir_entries<T>(
        &self,
        dir: &Path,
        mut f: impl FnMut(&std::ffi::CStr, u8, Option<u64>) -> Option<T>,
    ) -> std::io::Result<Vec<T>> {
        use std::os::fd::AsRawFd as _;
        let parent_fd = self
            .dir_fd_for(dir)
            .map_err(std::io::Error::from_raw_os_error)?;
        // A new open description gives each enumeration its own seek offset.
        let dup_raw = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if dup_raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let dirp = unsafe { libc::fdopendir(dup_raw) };
        if dirp.is_null() {
            unsafe { libc::close(dup_raw) };
            return Err(std::io::Error::last_os_error());
        }
        let mut results = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(dirp) };
            if entry.is_null() {
                break;
            }
            let d_name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            let bytes = d_name.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let d_type = unsafe { (*entry).d_type };
            let size = if d_type == libc::DT_REG {
                let mut st: libc::stat = unsafe { core::mem::zeroed() };
                if unsafe {
                    libc::fstatat(
                        parent_fd.as_raw_fd(),
                        d_name.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } == 0
                {
                    Some(st.st_size as u64)
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(item) = f(d_name, d_type, size) {
                results.push(item);
            }
        }
        unsafe { libc::closedir(dirp) };
        Ok(results)
    }

    /// Resolve `path` to its final non-symlink target, following symlinks
    /// MANUALLY (40-hop ELOOP guard).
    pub(crate) fn resolve_following(&self, path: &str) -> Option<PathBuf> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::ffi::OsStrExt as _;
        let mut normalized = normalize(path)?;
        let mut hops = 0u32;
        loop {
            let Some(rel) = Self::rel_path(&normalized) else {
                return Some(normalized);
            };
            let Some((parent_fd, leaf_c)) = self.namei_leaf(rel) else {
                return Some(normalized);
            };
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    parent_fd.as_raw_fd(),
                    leaf_c.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Some(normalized);
            }
            if st.st_mode as u32 & libc::S_IFMT as u32 != libc::S_IFLNK as u32 {
                return Some(normalized);
            }
            if hops >= 40 {
                return None; // ELOOP
            }
            hops += 1;
            let mut buf = [0u8; libc::PATH_MAX as usize];
            let n = unsafe {
                libc::readlinkat(
                    parent_fd.as_raw_fd(),
                    leaf_c.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            };
            if n <= 0 {
                return None;
            }
            let target = std::ffi::OsStr::from_bytes(&buf[..n as usize]);
            let target = Path::new(target);
            normalized = if target.is_absolute() {
                normalize_raw(target)?
            } else {
                let parent = normalized.parent().unwrap_or_else(|| Path::new(""));
                normalize_raw(&parent.join(target))?
            };
        }
    }

    pub(crate) fn child_name_set(&self, dir: &str) -> Option<HashSet<std::ffi::OsString>> {
        use std::os::unix::ffi::OsStrExt as _;
        let normalized = normalize(dir)?;
        let rel = Self::rel_path(&normalized).unwrap_or_else(|| Path::new(""));
        let entries = self
            .read_dir_entries(rel, |d_name, _, _| {
                Some(std::ffi::OsStr::from_bytes(d_name.to_bytes()).to_os_string())
            })
            .ok()?;
        let mut out = HashSet::new();
        for name in entries {
            if is_internal_sidecar_name(&name.to_string_lossy()) {
                continue;
            }
            out.insert(name);
        }
        Some(out)
    }

    fn name_matches_on_disk_impl(&self, rel: &Path) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let Some(file_name) = rel.file_name() else {
            return true;
        };
        let want = file_name.as_bytes();
        if want.is_ascii() {
            return true;
        }
        let parent = rel.parent().unwrap_or_else(|| Path::new(""));
        let Ok(entries) =
            self.read_dir_entries(parent, |d_name, _, _| Some(d_name.to_bytes() == want))
        else {
            return true;
        };
        entries.into_iter().any(|matched| matched)
    }
}

pub(crate) fn native_reexec_transfers_cleanup(
    owner_pid: u32,
    current_pid: u32,
    owns_root: bool,
) -> bool {
    owns_root && owner_pid == current_pid
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
pub(crate) const CARRICK_MODE_XATTR: &[u8] = b"user.carrick.mode\0";

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

/// Device-node id xattr (`st_rdev`). macOS/cap-std can't `mknod(S_IFCHR|S_IFBLK)`
/// as a non-root process, so a guest device node created by `mknod(2)` is a
/// MARKER regular file: its full guest mode (type + perms) lives in
/// `CARRICK_MODE_XATTR` and the raw guest `dev_t` is stored VERBATIM here (the
/// Linux dev_t major/minor encoding round-trips as an opaque u64 — no decode
/// needed). `real_stat`/`metadata` and the stat reconstruction read these two
/// together to report `S_IFCHR`/`S_IFBLK` with the right `st_rdev`. Fork-coherent
/// (lives on the real on-disk file) and hidden from the guest's xattr syscalls
/// like the others.
const CARRICK_RDEV_XATTR: &[u8] = b"user.carrick.rdev\0";
#[allow(dead_code)]
pub(crate) const CARRICK_RDEV_XATTR_NAME: &str = "user.carrick.rdev";

/// Marker xattr that flags a regular scratch file as an `AF_UNIX` socket node
/// materialised by `bind(2)` (see `FsBackend::create_socket`). macOS can't
/// `mknod(S_IFSOCK)` as non-root, so the guest-facing node is a regular file;
/// this xattr makes `real_stat`/`metadata` report `S_IFSOCK` instead of
/// `S_IFREG`. Value is the marker byte `1`. Fork-coherent (lives on the real
/// on-disk file) and hidden from the guest's get/set/listxattr like the others.
const CARRICK_SOCKET_XATTR: &[u8] = b"user.carrick.socket\0";
#[allow(dead_code)]
pub(crate) const CARRICK_SOCKET_XATTR_NAME: &str = "user.carrick.socket";

/// Marker xattr on the sandbox ROOT directory recording that a FIFO node has
/// (at some point) been created under it — the durable truth behind
/// [`FsBackend::may_have_fifo_nodes`]. It must be durable host state, not an
/// in-process flag: carrick forks real host processes, so `mkfifo f` in one
/// guest process followed by `cat f` in a SIBLING must still trigger the
/// dispatcher's FIFO open interception (a plain open of a writer-less FIFO
/// blocks and would wedge that sibling's dispatcher). It also survives
/// `exec`-style re-attach of a detached container's scratch. Never removed
/// (a deleted FIFO leaves the conservative `true` behind — a per-open probe
/// resumes, which is the pre-marker behavior). Hidden from the guest's
/// get/set/listxattr like every `user.carrick.*` name.
const CARRICK_HAS_FIFO_XATTR: &[u8] = b"user.carrick.has_fifo\0";

/// Marker xattr on the sandbox ROOT directory recording that a MARKER node —
/// an AF_UNIX socket node (`create_socket`) or a mknod device node
/// (`create_device`), both regular files whose guest-visible TYPE lives in
/// xattrs — has (at some point) been created under it. The durable truth
/// behind [`FsBackend::dir_has_overlay_interference`]: while absent, a raw
/// host directory stream's `d_type` is guest-faithful for every entry, so
/// `getdents64` may stream straight off a trusted host dirfd. Same durability
/// rationale and never-removed conservatism as [`CARRICK_HAS_FIFO_XATTR`]
/// (carrick forks real host processes; `bind()` in one process must disable
/// streaming in every sibling). Hidden from the guest's xattr syscalls like
/// every `user.carrick.*` name.
const CARRICK_HAS_MARKER_NODES_XATTR: &[u8] = b"user.carrick.has_marker_nodes\0";
/// Root marker: some entry carries per-file guest METADATA xattrs (mode from
/// chmod, uid/gid from chown). While ABSENT, a host stat of a plain entry IS
/// the guest-visible answer, so the trusted dispatch lanes may skip their
/// per-entry xattr probe entirely. Device/socket marker nodes stamp their own
/// mode xattrs but are covered by [`CARRICK_HAS_MARKER_NODES_XATTR`].
const CARRICK_HAS_META_XATTRS_XATTR: &[u8] = b"user.carrick.has_meta_xattrs\0";
/// Durable root marker asserting that adjacent sparse-upper whiteout sidecars
/// may exist. Stamped before the first sidecar and never removed; absence may
/// be cached against the shared filesystem generation.
const CARRICK_HAS_WHITEOUTS_XATTR: &[u8] = b"user.carrick.has_whiteouts\0";
/// Durable root marker asserting that the sparse upper may contain a symlink.
/// Stamped and generation-published before the first link itself is visible,
/// so an absent marker is a fail-closed prerequisite for the one-lookup sparse
/// upper miss path.
const CARRICK_HAS_SYMLINKS_XATTR: &[u8] = b"user.carrick.has_symlinks\0";

/// The errno that means "xattr not present" (as opposed to "this filesystem
/// cannot do xattrs", which must fail CLOSED — see `root_fifo_marker`).
#[cfg(target_os = "linux")]
const XATTR_ABSENT_ERRNO: i32 = libc::ENODATA;
#[cfg(not(target_os = "linux"))]
const XATTR_ABSENT_ERRNO: i32 = libc::ENOATTR;

/// Tri-state reading of a sandbox-root marker xattr ([`CARRICK_HAS_FIFO_XATTR`]
/// / [`CARRICK_HAS_MARKER_NODES_XATTR`]). `Unknown` (the marker mechanism
/// itself failed, e.g. a host filesystem without `user.*` xattr support) is
/// distinct from `Absent` so the consumers can fail closed (per-open FIFO
/// probe resumes; getdents streaming stays off) instead of wrongly answering
/// "none" forever.
enum RootMarker {
    Present,
    Absent,
    Unknown,
}
#[allow(dead_code)]
pub(crate) const CARRICK_UID_XATTR_NAME: &str = "user.carrick.uid";
#[allow(dead_code)]
pub(crate) const CARRICK_GID_XATTR_NAME: &str = "user.carrick.gid";

pub(crate) fn is_internal_carrick_xattr(name: &str) -> bool {
    name.starts_with("user.carrick.")
}

/// Linux VFS xattr namespaces a guest may use. macOS xattrs are namespace-
/// agnostic, so we store the Linux name verbatim as a host xattr (carrick's own
/// `user.carrick.*` are still hidden via `is_internal_carrick_xattr`). The guest
/// runs as root by default, so it may use `trusted.*` (CAP_SYS_ADMIN) just like
/// the Docker-as-root oracle (CPython test_os's xattr-support probe sets
/// `trusted.foo`). `system.*`/`security.*` are likewise accepted and round-trip.
pub(crate) fn is_guest_xattr_namespace(name: &str) -> bool {
    name.starts_with("user.")
        || name.starts_with("trusted.")
        || name.starts_with("security.")
        || name.starts_with("system.")
}

#[allow(dead_code)]
fn fremove_xattr(fd: std::os::fd::RawFd, name: &[u8]) {
    // Best-effort: a missing stale override is the common case on every host.
    unsafe {
        carrick_portable::fremovexattr(fd, name.as_ptr().cast());
    }
    crate::fs_resolve_cache::bump_meta_generation();
}

#[cfg(test)]
pub static HOST_XATTR_READS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub fn host_xattr_read_count() -> usize {
    HOST_XATTR_READS.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
pub fn reset_host_xattr_read_count() -> usize {
    HOST_XATTR_READS.swap(0, std::sync::atomic::Ordering::SeqCst)
}

#[cfg(target_os = "macos")]
fn fget_u32_xattr(fd: std::os::fd::RawFd, name: &[u8]) -> Option<u32> {
    #[cfg(test)]
    HOST_XATTR_READS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut v = [0u8; 4];
    let n = unsafe {
        carrick_portable::fgetxattr(
            fd,
            name.as_ptr() as *const libc::c_char,
            v.as_mut_ptr() as *mut libc::c_void,
            v.len(),
        )
    };
    (n == 4).then(|| u32::from_le_bytes(v))
}

pub(crate) fn fset_u32_xattr(fd: std::os::fd::RawFd, name: &[u8], val: u32) {
    let v = val.to_le_bytes();
    // Portable fd-xattr (Linux fsetxattr / macOS f*xattr+position / FreeBSD extattr_set_fd).
    unsafe {
        carrick_portable::fsetxattr(
            fd,
            name.as_ptr() as *const libc::c_char,
            v.as_ptr() as *const libc::c_void,
            v.len(),
            0,
        );
    }
    crate::fs_resolve_cache::bump_meta_generation();
}

#[cfg(not(target_os = "macos"))]
fn fget_u32_xattr(fd: std::os::fd::RawFd, name: &[u8]) -> Option<u32> {
    #[cfg(test)]
    HOST_XATTR_READS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut v = [0u8; 4];
    let n = unsafe {
        carrick_portable::fgetxattr(
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

pub(crate) fn fset_mode_xattr(fd: std::os::fd::RawFd, mode: u32) {
    fset_u32_xattr(fd, CARRICK_MODE_XATTR, mode);
}

pub(crate) fn fset_mode(fd: std::os::fd::RawFd, mode: u32) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc == 0 {
        let kind = st.st_mode as u32 & libc::S_IFMT as u32;
        let owner_ok = if kind == libc::S_IFDIR as u32 {
            mode & 0o700 == 0o700
        } else {
            mode & 0o600 == 0o600
        };
        if kind != libc::S_IFLNK as u32 {
            let native_mode = if owner_ok { mode } else { mode | 0o700 };
            let _ = unsafe { libc::fchmod(fd, native_mode as libc::mode_t) };
            if owner_ok {
                fremove_xattr(fd, CARRICK_MODE_XATTR);
                return;
            }
        }
    }
    fset_mode_xattr(fd, mode);
}

/// 8-byte little-endian xattr write/read, mirroring the u32 helpers above. Used
/// for the device-node `st_rdev` (a 64-bit `dev_t`).
#[allow(dead_code)]
fn fset_u64_xattr(fd: std::os::fd::RawFd, name: &[u8], val: u64) {
    let v = val.to_le_bytes();
    // Portable fd-xattr (carrick-portable maps the per-OS position/options args).
    unsafe {
        carrick_portable::fsetxattr(
            fd,
            name.as_ptr() as *const libc::c_char,
            v.as_ptr() as *const libc::c_void,
            v.len(),
            0,
        );
    }
    crate::fs_resolve_cache::bump_meta_generation();
}

fn fget_u64_xattr(fd: std::os::fd::RawFd, name: &[u8]) -> Option<u64> {
    #[cfg(test)]
    HOST_XATTR_READS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut v = [0u8; 8];
    let n = unsafe {
        carrick_portable::fgetxattr(
            fd,
            name.as_ptr() as *const libc::c_char,
            v.as_mut_ptr() as *mut libc::c_void,
            v.len(),
        )
    };
    (n == 8).then(|| u64::from_le_bytes(v))
}

/// Read carrick's device-node id (`st_rdev`) xattr for an open fd. `None` when
/// the file is not a device-node marker (so callers leave `st_rdev` at 0).
pub(crate) fn fget_rdev_xattr(fd: std::os::fd::RawFd) -> Option<u64> {
    fget_u64_xattr(fd, CARRICK_RDEV_XATTR)
}

/// Read carrick's guest metadata (mode / owner uid+gid / AF_UNIX-socket marker)
/// for an open fd in ONE `flistxattr` plus a targeted `fgetxattr` for only the
/// attributes actually present — instead of an unconditional read per attribute
/// (each ~5 µs on APFS; see docs/fs-host-capstd-amplification.md). The
/// overwhelmingly common scratch file carries at most the mode xattr (uid/gid
/// appear only after a guest `chown`, the socket marker only on a bound AF_UNIX
/// node), so this collapses the typical 3–4 reads to one list + one read; a
/// file with no carrick xattrs costs just the list. Falls back to direct reads
/// if the name buffer is too small (a file with unusually many xattrs).
pub(crate) fn fd_carrick_meta(
    fd: std::os::fd::RawFd,
) -> (Option<u32>, Option<NsUid>, Option<NsGid>, bool) {
    let mut names = [0u8; 1024];
    let n = unsafe {
        carrick_portable::flistxattr(fd, names.as_mut_ptr() as *mut libc::c_char, names.len())
    };
    if n < 0 || n as usize > names.len() {
        // flistxattr error, or more names than the probe buffer holds: read each
        // attribute directly (correct, just not collapsed). Rare on scratch.
        return (
            fget_u32_xattr(fd, CARRICK_MODE_XATTR),
            fget_u32_xattr(fd, CARRICK_UID_XATTR).map(NsUid::new),
            fget_u32_xattr(fd, CARRICK_GID_XATTR).map(NsGid::new),
            fget_u32_xattr(fd, CARRICK_SOCKET_XATTR).is_some(),
        );
    }
    // Each listed name is NUL-terminated; the CARRICK_*_XATTR constants carry a
    // trailing NUL, so the NUL-inclusive slices compare equal byte-for-byte.
    let listed = &names[..n as usize];
    let has = |name: &[u8]| listed.split_inclusive(|&b| b == 0).any(|s| s == name);
    let read_if = |present: bool, name| present.then(|| fget_u32_xattr(fd, name)).flatten();
    (
        read_if(has(CARRICK_MODE_XATTR), CARRICK_MODE_XATTR),
        read_if(has(CARRICK_UID_XATTR), CARRICK_UID_XATTR).map(NsUid::new),
        read_if(has(CARRICK_GID_XATTR), CARRICK_GID_XATTR).map(NsGid::new),
        has(CARRICK_SOCKET_XATTR),
    )
}

/// Read the (uid, gid) owner xattrs from a fd. `None` for either if unset.
pub(crate) fn fget_owner_xattr(fd: std::os::fd::RawFd) -> (Option<NsUid>, Option<NsGid>) {
    (
        fget_u32_xattr(fd, CARRICK_UID_XATTR).map(NsUid::new),
        fget_u32_xattr(fd, CARRICK_GID_XATTR).map(NsGid::new),
    )
}

/// Set the (uid, gid) owner xattrs on an open fd.
pub(crate) fn fset_owner_xattr(
    fd: std::os::fd::RawFd,
    uid: Option<carrick_abi::NsUid>,
    gid: Option<carrick_abi::NsGid>,
) {
    if let Some(u) = uid {
        fset_u32_xattr(fd, CARRICK_UID_XATTR, u.raw());
    }
    if let Some(g) = gid {
        fset_u32_xattr(fd, CARRICK_GID_XATTR, g.raw());
    }
}

/// Open a short-lived fd for `rel` (file or dir) and run `f` on it.
fn with_entry_fd<R>(
    backend: &HostFsBackend,
    rel: &Path,
    is_dir: bool,
    writable: bool,
    f: impl FnOnce(std::os::fd::RawFd) -> R,
) -> Option<R> {
    let _ = (is_dir, writable);
    let fd = backend.metadata_fd(rel, false).ok()?;
    Some(f(fd.as_raw_fd()))
}

/// Read the guest-mode xattr for `rel` under `root_path`. `None` => fall back to the
/// real mode.
fn read_mode_xattr(backend: &HostFsBackend, rel: &Path, is_dir: bool) -> Option<u32> {
    #[cfg(target_os = "macos")]
    {
        let _ = is_dir;
        path_get_u32_xattr(backend, rel, CARRICK_MODE_XATTR, false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        with_entry_fd(backend, rel, is_dir, false, |fd| {
            fget_u32_xattr(fd, CARRICK_MODE_XATTR)
        })
        .flatten()
    }
}

/// Read the device-node id (`st_rdev`) xattr for the regular `rel` under `root_path`.
/// `None` => the file is not a device-node marker. Mirrors `read_mode_xattr`
/// (read-only, atime-preserving on macOS).
fn read_rdev_xattr(backend: &HostFsBackend, rel: &Path) -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        path_get_u64_xattr(backend, rel, CARRICK_RDEV_XATTR, false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Devices are never directories, so a plain (non-dir) read-only fd peek.
        with_entry_fd(backend, rel, false, false, |fd| {
            fget_u64_xattr(fd, CARRICK_RDEV_XATTR)
        })
        .flatten()
    }
}

/// Stamp a regular `rel` under `root_path` as a guest DEVICE NODE: persist the FULL
/// guest mode (type + perms) in `CARRICK_MODE_XATTR` and the raw guest `dev_t`
/// in `CARRICK_RDEV_XATTR`. Used by `create_device`. Best-effort, like the other
/// xattr writers (a failed write leaves the file looking like a plain regular
/// file). `full_mode` carries the `S_IFCHR`/`S_IFBLK` type bits so the stat
/// reconstruction can recover the device type.
fn write_device_xattrs(backend: &HostFsBackend, rel: &Path, full_mode: u32, dev: u64) {
    #[cfg(target_os = "macos")]
    {
        path_set_u32_xattr(backend, rel, CARRICK_MODE_XATTR, full_mode);
        path_set_u64_xattr(backend, rel, CARRICK_RDEV_XATTR, dev);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = with_entry_fd(backend, rel, false, true, |fd| {
            fset_u32_xattr(fd, CARRICK_MODE_XATTR, full_mode);
            fset_u64_xattr(fd, CARRICK_RDEV_XATTR, dev);
        });
    }
}

/// `true` iff the contained inode carries the `AF_UNIX` socket marker xattr.
fn read_socket_xattr(backend: &HostFsBackend, rel: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        path_get_u32_xattr(backend, rel, CARRICK_SOCKET_XATTR, false).is_some()
    }
    #[cfg(not(target_os = "macos"))]
    {
        with_entry_fd(backend, rel, false, false, |fd| {
            fget_u32_xattr(fd, CARRICK_SOCKET_XATTR).is_some()
        })
        .unwrap_or(false)
    }
}

/// Read a u32 xattr through a contained metadata fd (macOS).
#[cfg(target_os = "macos")]
fn path_get_u32_xattr(
    backend: &HostFsBackend,
    rel: &Path,
    name: &[u8],
    nofollow: bool,
) -> Option<u32> {
    let fd = backend.metadata_fd(rel, !nofollow).ok()?;
    fget_u32_xattr(fd.as_raw_fd(), name)
}

/// Read an 8-byte LE xattr through a contained metadata fd (macOS).
#[cfg(target_os = "macos")]
fn path_get_u64_xattr(
    backend: &HostFsBackend,
    rel: &Path,
    name: &[u8],
    nofollow: bool,
) -> Option<u64> {
    let fd = backend.metadata_fd(rel, !nofollow).ok()?;
    fget_u64_xattr(fd.as_raw_fd(), name)
}

#[cfg(target_os = "macos")]
fn symlink_get_u32_xattr(backend: &HostFsBackend, rel: &Path, name: &[u8]) -> Option<u32> {
    path_get_u32_xattr(backend, rel, name, true)
}

#[cfg(target_os = "macos")]
fn symlink_set_u32_xattr(backend: &HostFsBackend, rel: &Path, name: &[u8], val: u32) {
    if let Ok(fd) = backend.metadata_fd(rel, false) {
        fset_u32_xattr(fd.as_raw_fd(), name, val);
    }
}

#[cfg(target_os = "macos")]
fn path_set_u32_xattr(backend: &HostFsBackend, rel: &Path, name: &[u8], val: u32) {
    if let Ok(fd) = backend.metadata_fd(rel, false) {
        fset_u32_xattr(fd.as_raw_fd(), name, val);
    }
}

#[cfg(target_os = "macos")]
fn path_set_u64_xattr(backend: &HostFsBackend, rel: &Path, name: &[u8], val: u64) {
    if let Ok(fd) = backend.metadata_fd(rel, false) {
        fset_u64_xattr(fd.as_raw_fd(), name, val);
    }
}

/// Prefix for a per-symlink xattr SIDECAR file (non-macOS). Linux (and every
/// Linux filesystem) forbids `user.*`/`trusted.*` xattrs ON A SYMLINK at the VFS
/// layer, so a symlink's carrick-owned uid/gid (`lchown`) cannot be stored in an
/// xattr the way a regular file's is. We persist it instead in a tiny sidecar
/// file placed ADJACENT to the link (`<dir>/.carrick-lnkxattr.<name>.<key>`),
/// which is fork-coherent (a real on-disk file under the rootfs, inherited
/// across `libc::fork`, not an in-process map) and resolved through the same
/// contained parent fd as the link itself. macOS uses an O_SYMLINK fd.
const LINK_OWNER_SIDECAR_PREFIX: &str = ".carrick-lnkown.";
const LINK_XATTR_SIDECAR_PREFIX: &str = ".carrick-lnkxattr.";
/// Adjacent sparse-upper whiteout. The suffix is SHA-256 of the host-encoded
/// leaf, keeping the internal name below `NAME_MAX`; the marker body stores the
/// exact leaf so directory merging can recover it and reject corruption.
const HOST_WHITEOUT_SIDECAR_PREFIX: &str = ".carrick-whiteout.";

/// The carrier's file-creation mask, read once. `umask(2)` is get-and-set,
/// so the read briefly sets 0 and restores; carrick's own scratch creations
/// pass explicit modes, so a creation racing that window gets exactly the
/// mode it asked for.
#[cfg(target_os = "macos")]
fn host_umask() -> u32 {
    static HOST_UMASK: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *HOST_UMASK.get_or_init(|| {
        let previous = unsafe { libc::umask(0) };
        unsafe {
            libc::umask(previous);
        }
        u32::from(previous) & 0o777
    })
}

/// True iff `name` is one of carrick's internal per-symlink sidecar files.
/// Directory enumeration must hide these regardless of backend: they are
/// metadata storage, not guest-visible files.
pub(crate) fn is_internal_sidecar_name(name: &str) -> bool {
    name.starts_with(LINK_OWNER_SIDECAR_PREFIX)
        || name.starts_with(LINK_XATTR_SIDECAR_PREFIX)
        || name.starts_with(HOST_WHITEOUT_SIDECAR_PREFIX)
        // The layer cache's clean-metadata marker rides into the per-run
        // scratch with the COW clone; it is carrick bookkeeping, never a
        // guest-visible entry.
        || name == crate::layer_cache::CLEAN_META_MARKER
}

fn host_whiteout_sidecar_rel(normalized: &Path) -> Option<PathBuf> {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::ffi::OsStrExt as _;

    let leaf = normalized.file_name()?;
    let digest = Sha256::digest(leaf.as_bytes());
    let marker = format!("{HOST_WHITEOUT_SIDECAR_PREFIX}{digest:x}");
    Some(match normalized.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(marker),
        _ => PathBuf::from(marker),
    })
}

/// Map a carrick xattr name (`b"user.carrick.uid\0"`) to its short sidecar key
/// (`uid`). Returns `None` for an unrecognised name (defensive; only the three
/// carrick `user.carrick.*` owner/socket names are ever passed here).
#[cfg(not(target_os = "macos"))]
fn link_xattr_sidecar_key(name: &[u8]) -> Option<&'static str> {
    let trimmed = name.strip_suffix(b"\0").unwrap_or(name);
    match trimmed {
        b"user.carrick.uid" => Some("uid"),
        b"user.carrick.gid" => Some("gid"),
        b"user.carrick.socket" => Some("socket"),
        _ => None,
    }
}

/// The sidecar relative path for the symlink `rel`, attr `key`: same parent dir,
/// name `.carrick-lnkxattr.<linkname>.<key>`. `None` if `rel` has no file name.
#[cfg(not(target_os = "macos"))]
fn link_xattr_sidecar_rel(rel: &Path, key: &str) -> Option<std::path::PathBuf> {
    let name = rel.file_name()?.to_str()?;
    let file = format!("{LINK_XATTR_SIDECAR_PREFIX}{name}.{key}");
    Some(match rel.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(file),
        _ => std::path::PathBuf::from(file),
    })
}

#[cfg(not(target_os = "macos"))]
fn symlink_get_u32_xattr(backend: &HostFsBackend, rel: &Path, name: &[u8]) -> Option<u32> {
    let key = link_xattr_sidecar_key(name)?;
    let sidecar = link_xattr_sidecar_rel(rel, key)?;
    let fd = backend.metadata_fd(&sidecar, false).ok()?;
    let mut bytes = [0u8; 4];
    let n = unsafe { libc::pread(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if n != 4 {
        return None;
    }
    (bytes.len() == 4).then(|| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(not(target_os = "macos"))]
fn symlink_set_u32_xattr(backend: &HostFsBackend, rel: &Path, name: &[u8], val: u32) {
    let Some(key) = link_xattr_sidecar_key(name) else {
        return;
    };
    let Some(sidecar) = link_xattr_sidecar_rel(rel, key) else {
        return;
    };
    let Some((parent, leaf)) = backend.namei_leaf(&sidecar) else {
        return;
    };
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_TRUNC
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if raw >= 0 {
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        let bytes = val.to_le_bytes();
        unsafe {
            libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len());
        }
    }
    crate::fs_resolve_cache::bump_meta_generation();
}

/// Remove any xattr sidecars belonging to the symlink `rel` (called from the
/// backend's unlink so a reused name does not inherit a stale owner). Best-effort.
#[cfg(not(target_os = "macos"))]
pub(crate) fn remove_link_xattr_sidecars(backend: &HostFsBackend, rel: &Path) {
    for key in ["uid", "gid", "socket"] {
        if let Some(sidecar) = link_xattr_sidecar_rel(rel, key) {
            if let Some((parent, leaf)) = backend.namei_leaf(&sidecar) {
                unsafe {
                    libc::unlinkat(parent.as_raw_fd(), leaf.as_ptr(), 0);
                }
            }
        }
    }
}

fn read_owner_xattr(
    backend: &HostFsBackend,
    rel: &Path,
    is_dir: bool,
    symlink: bool,
) -> (Option<NsUid>, Option<NsGid>) {
    let (uid, gid) = if symlink {
        (
            symlink_get_u32_xattr(backend, rel, CARRICK_UID_XATTR),
            symlink_get_u32_xattr(backend, rel, CARRICK_GID_XATTR),
        )
    } else {
        #[cfg(target_os = "macos")]
        {
            let _ = is_dir;
            (
                path_get_u32_xattr(backend, rel, CARRICK_UID_XATTR, false),
                path_get_u32_xattr(backend, rel, CARRICK_GID_XATTR, false),
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            with_entry_fd(backend, rel, is_dir, false, |fd| {
                (
                    fget_u32_xattr(fd, CARRICK_UID_XATTR),
                    fget_u32_xattr(fd, CARRICK_GID_XATTR),
                )
            })
            .unwrap_or((None, None))
        }
    };
    (uid.map(NsUid::new), gid.map(NsGid::new))
}

/// Write the guest owner uid/gid xattrs for `rel`. Pass `None` to leave unchanged.
/// Best-effort.
pub(crate) fn write_owner_xattr(
    backend: &HostFsBackend,
    rel: &Path,
    is_dir: bool,
    symlink: bool,
    uid: Option<NsUid>,
    gid: Option<NsGid>,
) {
    if symlink {
        // lchown: the owner lives on the LINK itself (XATTR_NOFOLLOW).
        if let Some(uid) = uid {
            symlink_set_u32_xattr(backend, rel, CARRICK_UID_XATTR, uid.raw());
        }
        if let Some(gid) = gid {
            symlink_set_u32_xattr(backend, rel, CARRICK_GID_XATTR, gid.raw());
        }
        return;
    }
    let _ = with_entry_fd(backend, rel, is_dir, !is_dir, |fd| {
        if let Some(uid) = uid {
            fset_u32_xattr(fd, CARRICK_UID_XATTR, uid.raw());
        }
        if let Some(gid) = gid {
            fset_u32_xattr(fd, CARRICK_GID_XATTR, gid.raw());
        }
    });
}

impl FsBackend for HostFsBackend {
    fn serves_dentry_cache(&self) -> bool {
        true
    }

    fn name_matches_on_disk(&self, rel: &Path) -> bool {
        self.name_matches_on_disk_impl(rel)
    }

    fn archive_mutation_gate(&self) -> Option<&ArchiveMutationGate> {
        Some(&self.archive_mutation_gate)
    }

    /// Answer "is this path whiteed out" without resolving the path when the
    /// sandbox holds NO whiteouts at all.
    ///
    /// The trait default goes straight to `lookup_kind`, which resolves the
    /// whole path through cap-std's component-by-component walk. On a cold
    /// `go build` that cost 3,472 host `openat`s — a deletion check walking
    /// every path that the caller is about to walk again to do the real work,
    /// on a rootfs where nothing had been deleted.
    ///
    /// `may_have_whiteouts` is the existing durable answer to the prior
    /// question: it reads the root's whiteout xattr, caches the negative
    /// against the resolve-cache generation so a deletion elsewhere
    /// invalidates it, and FAILS CLOSED (`RootMarker::Unknown` → `true`) on a
    /// filesystem that cannot carry the marker. So a `false` here means no
    /// whiteout exists to find, and skipping the walk cannot change the
    /// answer — this removes work, it does not weaken the check.
    fn is_deleted(&self, path: &str) -> bool {
        if !self.may_have_whiteouts() {
            return false;
        }
        matches!(self.lookup_kind(path), Some(OverlayEntryKind::Deleted))
    }

    fn has_whiteout_in_dir(&self, parent_fd: i32, name: &str) -> bool {
        use sha2::{Digest as _, Sha256};
        if !self.may_have_whiteouts() {
            return false;
        }
        let digest = Sha256::digest(name.as_bytes());
        let marker = format!("{HOST_WHITEOUT_SIDECAR_PREFIX}{digest:x}\0");
        let raw = unsafe {
            libc::openat(
                parent_fd,
                marker.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            )
        };
        if raw < 0 {
            return false;
        }
        let mut buf = [0u8; 256];
        let n = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        unsafe {
            libc::close(raw);
        }
        if n <= 0 {
            return false;
        }
        &buf[..n as usize] == name.as_bytes()
    }

    fn native_reexec_authority(&self) -> Result<HostFsReexecAuthority, BackendError> {
        #[cfg(target_os = "macos")]
        {
            HostFsBackend::native_reexec_authority(self).map_err(|_| BackendError::Io)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(BackendError::Unsupported)
        }
    }

    fn lookup(&self, path: &str) -> Option<OverlayEntry> {
        let normalized = normalize(path)?;
        if self.is_whiteouted_normalized(&normalized) {
            return Some(OverlayEntry::Deleted);
        }
        if normalized.as_os_str().is_empty() {
            // The sandbox root is always a directory.
            return Some(OverlayEntry::Dir);
        }
        let rel = Self::rel_path(&normalized)?;
        // Fast contained dir stat (no per-component walk) — the glob hot path.
        if let Some((_, RootFsEntryKind::Directory)) = self.fast_lstat_contained(rel, false) {
            return if self.name_matches_on_disk(rel) {
                Some(OverlayEntry::Dir)
            } else {
                None
            };
        }
        let (parent_fd, leaf_c) = self.namei_leaf(rel)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 || !self.name_matches_on_disk(rel) {
            return None;
        }
        let mode = st.st_mode as u32;
        let file_type = mode & (libc::S_IFMT as u32);
        if file_type == libc::S_IFDIR as u32 {
            return Some(OverlayEntry::Dir);
        }
        if file_type == libc::S_IFREG as u32 {
            let raw_fd = unsafe {
                libc::openat(
                    parent_fd.as_raw_fd(),
                    leaf_c.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if raw_fd < 0 {
                return None;
            }
            let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
            let mut buf = Vec::with_capacity(st.st_size.max(0) as usize);
            file.read_to_end(&mut buf).ok()?;
            return Some(OverlayEntry::File(buf));
        }
        if file_type == libc::S_IFLNK as u32 {
            let mut buf = vec![0u8; 1024];
            let len = unsafe {
                libc::readlinkat(
                    parent_fd.as_raw_fd(),
                    leaf_c.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            };
            if len < 0 {
                return None;
            }
            buf.truncate(len as usize);
            return Some(OverlayEntry::File(buf));
        }
        if file_type == libc::S_IFIFO as u32 {
            return Some(OverlayEntry::File(Vec::new()));
        }
        None
    }

    fn lookup_kind(&self, path: &str) -> Option<OverlayEntryKind> {
        let normalized = normalize(path)?;
        if self.is_whiteouted_normalized(&normalized) {
            return Some(OverlayEntryKind::Deleted);
        }
        if normalized.as_os_str().is_empty() {
            return Some(OverlayEntryKind::Dir);
        }
        let rel = Self::rel_path(&normalized)?;
        #[cfg(target_os = "macos")]
        if let Some((_, kind)) = self.fast_lstat_contained(rel, false) {
            if !self.name_matches_on_disk(rel) {
                return None;
            }
            return match kind {
                RootFsEntryKind::Directory => Some(OverlayEntryKind::Dir),
                RootFsEntryKind::File => Some(OverlayEntryKind::File),
                _ => None,
            };
        }
        if self.sparse_upper_nofollow_absent(path) {
            return None;
        }
        let (parent_fd, leaf_c) = self.namei_leaf(rel)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 || !self.name_matches_on_disk(rel) {
            return None;
        }
        let mode = st.st_mode as u32;
        let file_type = mode & (libc::S_IFMT as u32);
        if file_type == libc::S_IFDIR as u32 {
            return Some(OverlayEntryKind::Dir);
        }
        if file_type == libc::S_IFREG as u32
            || file_type == libc::S_IFLNK as u32
            || file_type == libc::S_IFIFO as u32
        {
            return Some(OverlayEntryKind::File);
        }
        None
    }

    fn fast_nofollow_metadata(&self, path: &str) -> Option<RootFsMetadata> {
        let normalized = normalize(path)?;
        if normalized.as_os_str().is_empty() {
            return Some(RootFsMetadata {
                path: std::path::Path::new("/").to_path_buf(),
                kind: RootFsEntryKind::Directory,
                mode: 0o755,
                size: 0,
            });
        }
        let rel = Self::rel_path(&normalized)?;
        #[cfg(target_os = "macos")]
        {
            self.fast_metadata_contained(&normalized, rel)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = rel;
            None
        }
    }

    fn fast_nofollow_absent(&self, path: &str) -> bool {
        self.sparse_upper_nofollow_absent(path)
    }

    fn metadata(&self, path: &str) -> Option<RootFsMetadata> {
        let normalized = normalize(path)?;
        if self.is_whiteouted_normalized(&normalized) {
            return None;
        }
        if normalized.as_os_str().is_empty() {
            return Some(RootFsMetadata {
                path: std::path::Path::new("/").to_path_buf(),
                kind: RootFsEntryKind::Directory,
                mode: 0o755,
                size: 0,
            });
        }
        let rel = Self::rel_path(&normalized)?;
        #[cfg(target_os = "macos")]
        if let Some(metadata) = self.fast_metadata_contained(&normalized, rel) {
            return Some(metadata);
        }
        if self.sparse_upper_nofollow_absent(path) {
            return None;
        }
        let (parent_fd, leaf_c) = self.namei_leaf(rel)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 || !self.name_matches_on_disk(rel) {
            return None;
        }
        let mode = st.st_mode as u32;
        let file_type = mode & (libc::S_IFMT as u32);
        if file_type == libc::S_IFIFO as u32 {
            let m = mode & 0o7777;
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::Fifo,
                mode: if m == 0 { 0o644 } else { m },
                size: 0,
            });
        }
        let is_symlink = file_type == libc::S_IFLNK as u32;
        let is_dir = file_type == libc::S_IFDIR as u32;
        let is_file = file_type == libc::S_IFREG as u32;
        let override_mode = if is_symlink {
            None
        } else {
            read_mode_xattr(self, rel, is_dir)
        };
        let m = override_mode.unwrap_or(mode & 0o7777);
        if is_dir {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::Directory,
                mode: if override_mode.is_none() && m == 0 {
                    0o755
                } else {
                    m
                },
                size: 0,
            });
        }
        if is_file {
            let kind = if read_socket_xattr(self, rel) {
                RootFsEntryKind::Socket
            } else {
                RootFsEntryKind::File
            };
            return Some(RootFsMetadata {
                path: normalized,
                kind,
                mode: if override_mode.is_none() && m == 0 {
                    0o644
                } else {
                    m
                },
                size: st.st_size.max(0) as usize,
            });
        }
        if is_symlink {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::Symlink,
                mode: if m == 0 { 0o777 } else { m },
                size: st.st_size.max(0) as usize,
            });
        }
        None
    }

    fn lookup_kind_and_metadata(
        &self,
        path: &str,
    ) -> (Option<OverlayEntryKind>, Option<RootFsMetadata>) {
        if let Some(normalized) = normalize(path)
            && self.is_whiteouted_normalized(&normalized)
        {
            return (Some(OverlayEntryKind::Deleted), None);
        }
        // The layered `Vfs::lookup` needs BOTH the overlay kind and the
        // backend metadata; answered separately (`lookup_kind` then
        // `metadata`) each ran its own contained open — two kernel walks for
        // one question. Derive both from ONE `fast_open_contained` fd for the
        // common regular-file/directory shapes (mirroring
        // `fast_metadata_contained`); symlinks, FIFOs, aliases and misses
        // keep the exact historical two-call pattern below.
        #[cfg(target_os = "macos")]
        if let Some(normalized) = normalize(path)
            && let Some(rel) = Self::rel_path(&normalized)
        {
            // `fast_metadata_contained` answers a plain file/directory from
            // the stat cache (one revalidating fstatat) or one contained fd;
            // a Unicode-aliased name is None there too, which is exactly the
            // "no such entry" the Linux view reports.
            if let Some(metadata) = self.fast_metadata_contained(&normalized, rel) {
                let entry_kind = if metadata.kind == RootFsEntryKind::Directory {
                    OverlayEntryKind::Dir
                } else {
                    OverlayEntryKind::File
                };
                return (Some(entry_kind), Some(metadata));
            }
        }
        match self.lookup_kind(path) {
            None => (None, None),
            kind => (kind, self.metadata(path)),
        }
    }

    fn may_have_fifo_nodes(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        if self.fifo_seen.load(Relaxed) {
            return true;
        }
        // Layer extraction never materialises FIFOs (special tar entries are
        // skipped — see `extract_layer_entries`/`extract_to_dir`), so the only
        // way a FIFO appears under this root is `create_fifo`, which stamps
        // the durable root marker BEFORE creating the node; the stamp bumps
        // the shared marker generation. Reading the generation first and the
        // marker second makes the absent-stamp sound: a stamp taken at
        // generation G proves the marker was absent at some point ≥ the G
        // bump, and any later FIFO creation bumps past G.
        let now = crate::fs_resolve_cache::current_marker_generation();
        if self.fifo_absent_gen.load(Relaxed) == now {
            return false;
        }
        match self.root_marker_xattr(CARRICK_HAS_FIFO_XATTR) {
            RootMarker::Present => {
                self.fifo_seen.store(true, Relaxed);
                true
            }
            RootMarker::Absent => {
                self.fifo_absent_gen.store(now, Relaxed);
                false
            }
            // The marker mechanism is unavailable (host fs without user
            // xattrs): fail CLOSED to the historical per-open FIFO probe —
            // a wrong `false` would send a FIFO open down the blocking path.
            RootMarker::Unknown => true,
        }
    }

    fn serves_plain_metadata(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        // Plain iff NEITHER marker is set: no chmod/chown metadata xattrs AND
        // no socket/device marker nodes (whose own mode xattrs ride the
        // marker-nodes flag). Fail CLOSED (false) when markers are unknown.
        if self.meta_xattr_seen.load(Relaxed) {
            return false;
        }
        let now = crate::fs_resolve_cache::current_marker_generation();
        let meta_absent = self.meta_xattr_absent_gen.load(Relaxed) == now
            || match self.root_marker_xattr(CARRICK_HAS_META_XATTRS_XATTR) {
                RootMarker::Present => {
                    self.meta_xattr_seen.store(true, Relaxed);
                    return false;
                }
                RootMarker::Absent => {
                    self.meta_xattr_absent_gen.store(now, Relaxed);
                    true
                }
                RootMarker::Unknown => false,
            };
        meta_absent && !self.dir_has_overlay_interference("/")
    }

    fn note_meta_xattr_written(&self) {
        self.stamp_root_marker(CARRICK_HAS_META_XATTRS_XATTR, &self.meta_xattr_seen);
    }

    fn dir_has_overlay_interference(&self, _dir: &str) -> bool {
        // The scratch tree is the merged truth for the host backend (rootfs
        // materialized, deletions are real unlinks), so the only thing that
        // can make a raw host directory stream lie is a MARKER node (socket/
        // device — a regular file whose guest type lives in xattrs). Tracked
        // root-level like the FIFO marker: `create_socket`/`create_device`
        // stamp the durable root xattr (bumping the shared marker generation)
        // BEFORE creating the node, so "marker generation unchanged since the
        // last absent reading" proves no marker node appeared anywhere. Coarse (any
        // marker node anywhere disables streaming everywhere) but exact —
        // and walk workloads do not bind sockets or mknod devices.
        use std::sync::atomic::Ordering::Relaxed;
        if self.marker_seen.load(Relaxed) {
            return true;
        }
        let now = crate::fs_resolve_cache::current_marker_generation();
        if self.marker_absent_gen.load(Relaxed) == now {
            return false;
        }
        match self.root_marker_xattr(CARRICK_HAS_MARKER_NODES_XATTR) {
            RootMarker::Present => {
                self.marker_seen.store(true, Relaxed);
                true
            }
            RootMarker::Absent => {
                self.marker_absent_gen.store(now, Relaxed);
                false
            }
            // Marker mechanism unavailable: fail CLOSED (no streaming).
            RootMarker::Unknown => true,
        }
    }

    fn file_contents(&self, path: &str) -> Option<Vec<u8>> {
        let typed = normalize(path)?;
        if self.is_whiteouted_normalized(&typed) {
            return None;
        }
        let normalized = self.resolve_following(path)?;
        let rel = Self::rel_path(&normalized)?;
        let (parent_fd, leaf_c) = self.namei_leaf(rel)?;
        let fd = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return None;
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).ok()?;
        Some(buf)
    }

    fn file_head(&self, path: &str, max: usize) -> Option<Vec<u8>> {
        let typed = normalize(path)?;
        if self.is_whiteouted_normalized(&typed) {
            return None;
        }
        let normalized = self.resolve_following(path)?;
        let rel = Self::rel_path(&normalized)?;
        let (parent_fd, leaf_c) = self.namei_leaf(rel)?;
        let fd = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return None;
        }
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut buf = Vec::new();
        let mut bounded = std::io::Read::take(file, max as u64);
        bounded.read_to_end(&mut buf).ok()?;
        Some(buf)
    }

    fn open_file_readonly(&self, path: &str) -> Option<std::fs::File> {
        let typed = normalize(path)?;
        if self.is_whiteouted_normalized(&typed) {
            return None;
        }
        let normalized = self.resolve_following(path)?;
        let rel = Self::rel_path(&normalized)?;
        let (parent_fd, leaf_c) = self.namei_leaf(rel)?;
        let fd = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return None;
        }
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let metadata = file.metadata().ok()?;
        metadata.is_file().then_some(file)
    }

    fn make_dir(&self, path: &str) -> Result<(), BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = NormalizedRelPath::from_normalized_relative(normalized);
        self.make_dir_at(None, None, &rel)
    }

    fn make_dir_at(
        &self,
        parent_fd: Option<&std::os::fd::OwnedFd>,
        leaf_c: Option<&std::ffi::CStr>,
        rel: &NormalizedRelPath,
    ) -> Result<(), BackendError> {
        use std::os::fd::AsRawFd;
        let _mutation = self.archive_mutation_gate.mutation();
        let (pfd, name_c) = match (parent_fd, leaf_c) {
            (Some(fd), Some(name)) => (fd.as_raw_fd(), name),
            _ => {
                let parent_fd = match self.ensure_parent_dirs(rel.as_path()) {
                    Ok(fd) => fd,
                    Err(errno) => {
                        return match host_open_refusal(errno) {
                            Some(refused) => Err(BackendError::Host(refused)),
                            None => Err(BackendError::Io),
                        };
                    }
                };
                let leaf_name = rel
                    .file_name()
                    .and_then(cstring_from_osstr)
                    .ok_or(BackendError::Invalid)?;
                let rc = unsafe { libc::mkdirat(parent_fd.as_raw_fd(), leaf_name.as_ptr(), 0o755) };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::AlreadyExists {
                        return match io_open_refusal(&err) {
                            Some(refused) => Err(BackendError::Host(refused)),
                            None => Err(BackendError::Io),
                        };
                    }
                } else {
                    let flags = libc::O_RDONLY
                        | libc::O_DIRECTORY
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK
                        | libc::O_NOFOLLOW;
                    let raw = unsafe {
                        libc::openat(parent_fd.as_raw_fd(), leaf_name.as_ptr(), flags, 0)
                    };
                    if raw >= 0 {
                        let fd =
                            std::sync::Arc::new(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) });
                        let generation = crate::fs_resolve_cache::current_dir_generation();
                        self.publish_dir_fd(rel.as_path(), &fd, generation);
                    }
                }
                self.clear_whiteout_normalized(rel.as_path());
                crate::fs_resolve_cache::bump_generation();
                return Ok(());
            }
        };
        let rc = unsafe { libc::mkdirat(pfd, name_c.as_ptr(), 0o755) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::AlreadyExists {
                return match io_open_refusal(&err) {
                    Some(refused) => Err(BackendError::Host(refused)),
                    None => Err(BackendError::Io),
                };
            }
        }
        self.clear_whiteout_normalized(rel.as_path());
        crate::fs_resolve_cache::bump_generation();
        Ok(())
    }

    fn create_file(&self, path: &str) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        let parent_fd = match self.ensure_parent_dirs(rel) {
            Ok(fd) => fd,
            Err(errno) => {
                return match host_open_refusal(errno) {
                    Some(refused) => Err(BackendError::Host(refused)),
                    None => Err(BackendError::Io),
                };
            }
        };
        let leaf_name = rel
            .file_name()
            .and_then(cstring_from_osstr)
            .ok_or(BackendError::Invalid)?;
        let flags = libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let fd = unsafe { libc::openat(parent_fd.as_raw_fd(), leaf_name.as_ptr(), flags, 0o644) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return match io_open_refusal(&err) {
                Some(refused) => Err(BackendError::Host(refused)),
                None => Err(BackendError::Io),
            };
        }
        unsafe { libc::close(fd) };
        self.clear_whiteout_normalized(&normalized);
        crate::fs_resolve_cache::bump_generation();
        Ok(())
    }

    fn create_fifo(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        let parent_fd = match self.ensure_parent_dirs(rel) {
            Ok(fd) => fd,
            Err(errno) => {
                return match host_open_refusal(errno) {
                    Some(refused) => Err(BackendError::Host(refused)),
                    None => Err(BackendError::Invalid),
                };
            }
        };
        let leaf_c = rel
            .file_name()
            .and_then(cstring_from_osstr)
            .ok_or(BackendError::Invalid)?;
        self.stamp_fifo_marker();
        crate::fs_resolve_cache::bump_generation();
        let rc = unsafe {
            libc::mkfifoat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                (mode & 0o7777) as libc::mode_t,
            )
        };
        if rc != 0 {
            return Err(BackendError::Io);
        }
        unsafe {
            libc::fchmodat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                (mode & 0o7777) as libc::mode_t,
                0,
            );
        }
        Ok(())
    }

    fn create_socket(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        let parent_fd = match self.ensure_parent_dirs(rel) {
            Ok(fd) => fd,
            Err(errno) => {
                return match host_open_refusal(errno) {
                    Some(refused) => Err(BackendError::Host(refused)),
                    None => Err(BackendError::Io),
                };
            }
        };
        let leaf_name = rel
            .file_name()
            .and_then(cstring_from_osstr)
            .ok_or(BackendError::Invalid)?;
        self.stamp_marker_node_marker();
        crate::fs_resolve_cache::bump_generation();
        let flags =
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let fd = unsafe { libc::openat(parent_fd.as_raw_fd(), leaf_name.as_ptr(), flags, 0o600) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return match io_open_refusal(&err) {
                Some(refused) => Err(BackendError::Host(refused)),
                None => Err(BackendError::Io),
            };
        }
        fset_u32_xattr(fd, CARRICK_SOCKET_XATTR, 1);
        fset_u32_xattr(fd, CARRICK_MODE_XATTR, mode & 0o7777);
        unsafe { libc::close(fd) };
        Ok(())
    }

    fn create_device(&self, path: &str, full_mode: u32, dev: u64) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        let (parent_fd, leaf_c) = match self.namei_leaf_res(rel) {
            Ok(pair) => pair,
            Err(errno) => {
                return match host_open_refusal(errno) {
                    Some(refused) => Err(BackendError::Host(refused)),
                    None => Err(BackendError::Invalid),
                };
            }
        };
        self.stamp_marker_node_marker();
        crate::fs_resolve_cache::bump_generation();
        let flags =
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let fd = unsafe { libc::openat(parent_fd.as_raw_fd(), leaf_c.as_ptr(), flags, 0o600) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return match io_open_refusal(&err) {
                Some(refused) => Err(BackendError::Host(refused)),
                None => Err(BackendError::Io),
            };
        }
        write_device_xattrs(self, rel, full_mode, dev);
        unsafe { libc::close(fd) };
        Ok(())
    }

    fn device_node(&self, path: &str) -> Option<(u32, u64)> {
        let normalized = normalize(path)?;
        let rel = Self::rel_path(&normalized)?;
        let (parent_fd, leaf_c) = self.namei_leaf(rel)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return None;
        }
        let mode = st.st_mode as u32;
        if (mode & (libc::S_IFMT as u32)) != libc::S_IFREG as u32 {
            return None;
        }
        let full_mode = read_mode_xattr(self, rel, false)?;
        let type_bits = full_mode & crate::linux_abi::LINUX_S_IFMT;
        if type_bits != crate::linux_abi::LINUX_S_IFCHR
            && type_bits != crate::linux_abi::LINUX_S_IFBLK
        {
            return None;
        }
        let dev = read_rdev_xattr(self, rel).unwrap_or(0);
        Some((type_bits, dev))
    }

    fn set_file_contents(&self, path: &str, contents: Vec<u8>) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        let (parent_fd, leaf_c) = match self.namei_leaf(rel) {
            Some(pair) => pair,
            None => {
                let p = self.ensure_parent_dirs(rel).map_err(|_| BackendError::Io)?;
                let l = rel
                    .file_name()
                    .and_then(cstring_from_osstr)
                    .ok_or(BackendError::Invalid)?;
                (p, l)
            }
        };
        let flags =
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let fd = unsafe { libc::openat(parent_fd.as_raw_fd(), leaf_c.as_ptr(), flags, 0o666) };
        if fd < 0 {
            return Err(BackendError::Io);
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(&contents).map_err(|_| BackendError::Io)?;
        self.clear_whiteout_normalized(&normalized);
        crate::fs_resolve_cache::bump_generation();
        Ok(())
    }

    fn create_file_from_rootfs(
        &self,
        path: &str,
        contents: Arc<[u8]>,
        mode: u32,
    ) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        self.set_file_contents(path, contents.as_ref().to_vec())?;
        self.set_mode(path, mode)
    }

    fn write_file_range(
        &self,
        path: &str,
        offset: usize,
        bytes: &[u8],
        final_size: usize,
    ) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let end = offset
            .checked_add(bytes.len())
            .ok_or(BackendError::Invalid)?;
        if final_size < end {
            return Err(BackendError::Invalid);
        }
        let host_fd = self
            .open_raw_fd(path, true, false, false)
            .into_backend_result()?;
        let result = (|| {
            let mut written = 0usize;
            while written < bytes.len() {
                let write_offset = offset.checked_add(written).ok_or(BackendError::Invalid)?;
                let write_offset =
                    i64::try_from(write_offset).map_err(|_| BackendError::Invalid)?;
                let n = unsafe {
                    libc::pwrite(
                        host_fd,
                        bytes[written..].as_ptr() as *const libc::c_void,
                        bytes.len() - written,
                        write_offset as libc::off_t,
                    )
                }
                .host_syscall_errno()
                .map_err(|_| BackendError::Io)?;
                if n == 0 {
                    return Err(BackendError::Io);
                }
                written = written
                    .checked_add(n as usize)
                    .ok_or(BackendError::Invalid)?;
            }

            let final_size_i64 = i64::try_from(final_size).map_err(|_| BackendError::Invalid)?;
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            unsafe { libc::fstat(host_fd, &mut st) }
                .host_syscall_errno()
                .map_err(|_| BackendError::Io)?;
            if final_size_i64 > st.st_size {
                unsafe { libc::ftruncate(host_fd, final_size_i64 as libc::off_t) }
                    .host_syscall_errno()
                    .map_err(|_| BackendError::Io)?;
            }
            Ok(())
        })();
        unsafe {
            libc::close(host_fd);
        }
        result
    }

    fn remove_entry(&self, path: &str) -> bool {
        self.remove_entry_checked(path).unwrap_or(false)
    }

    fn remove_entry_checked(&self, path: &str) -> Result<bool, BackendError> {
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        let rel_norm = NormalizedRelPath::from_normalized_relative(rel.to_path_buf());
        self.remove_entry_at(None, None, &rel_norm, false)
    }

    fn remove_entry_at(
        &self,
        parent_fd: Option<&std::os::fd::OwnedFd>,
        leaf_c: Option<&std::ffi::CStr>,
        rel: &NormalizedRelPath,
        is_dir: bool,
    ) -> Result<bool, BackendError> {
        use std::os::fd::AsRawFd;
        let _mutation = self.archive_mutation_gate.mutation();
        let fallback_pair;
        let (pfd, name_c) = if let (Some(fd), Some(name)) = (parent_fd, leaf_c) {
            (fd.as_raw_fd(), name)
        } else {
            fallback_pair = match self.namei_leaf(rel.as_path()) {
                Some(pair) => pair,
                None => return Ok(false),
            };
            (fallback_pair.0.as_raw_fd(), fallback_pair.1.as_c_str())
        };

        let mut rc = if is_dir {
            unsafe { libc::unlinkat(pfd, name_c.as_ptr(), libc::AT_REMOVEDIR) }
        } else {
            unsafe { libc::unlinkat(pfd, name_c.as_ptr(), 0) }
        };
        let mut removed_dir = is_dir;
        if rc != 0 && !is_dir {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err == libc::EISDIR || err == libc::EPERM {
                rc = unsafe { libc::unlinkat(pfd, name_c.as_ptr(), libc::AT_REMOVEDIR) };
                if rc == 0 {
                    removed_dir = true;
                }
            }
        }
        if rc == 0 {
            crate::fs_resolve_cache::bump_generation();
            if removed_dir {
                let parent = rel.parent().unwrap_or_else(|| Path::new(""));
                self.dir_gen_for(parent)
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.dir_gen_for(rel.as_path())
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.evict_dir_cache_subtree(rel.as_path());
                self.evict_stat_cache_subtree(rel.as_path());
            } else {
                self.evict_dir_cache_subtree(rel.as_path());
                if self.use_stat_cache {
                    self.stat_cache.lock().remove(rel.as_path());
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                remove_link_xattr_sidecars(self, rel.as_path());
            }
            return Ok(true);
        }
        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == libc::ENOENT {
            Ok(false)
        } else {
            Err(BackendError::Io)
        }
    }

    fn mark_deleted(&self, path: &str) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let _ = self.remove_entry_checked(path);
        let res = self.write_whiteout_normalized(&normalized);
        if res.is_ok() {
            crate::fs_resolve_cache::bump_generation();
        }
        res
    }

    fn child_names(&self, dir: &str) -> Vec<(String, RootFsEntryKind, Option<u64>)> {
        self.child_names_bounded(dir, usize::MAX)
            .unwrap_or_default()
    }

    #[cfg(target_os = "macos")]
    fn stream_dirents(&self, dir: &str) -> Option<Vec<RootFsDirEntry>> {
        use std::os::fd::AsRawFd;
        if self.dir_has_overlay_interference(dir) {
            return None;
        }
        let normalized = normalize(dir)?;
        let rel = Self::rel_path(&normalized).unwrap_or_else(|| Path::new(""));
        let parent = self.dir_fd_for(rel).ok()?;
        // The cached capability fd's seek offset must not be touched by a
        // concurrent enumeration. Give the stream its own open description.
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return None;
        }
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        read_host_dir_entries(owned.as_raw_fd(), dir)
    }

    fn child_names_bounded(
        &self,
        dir: &str,
        limit: usize,
    ) -> Result<Vec<(String, RootFsEntryKind, Option<u64>)>, BackendError> {
        let Some(normalized) = normalize(dir) else {
            return Ok(Vec::new());
        };
        let rel = Self::rel_path(&normalized).unwrap_or_else(|| Path::new(""));
        let entries = self
            .read_dir_entries(rel, |d_name, d_type, size| {
                let name = d_name.to_string_lossy().into_owned();
                if is_internal_sidecar_name(&name) {
                    return None;
                }
                let kind = match d_type {
                    libc::DT_DIR => RootFsEntryKind::Directory,
                    libc::DT_LNK => RootFsEntryKind::Symlink,
                    libc::DT_FIFO => RootFsEntryKind::Fifo,
                    _ => RootFsEntryKind::File,
                };
                Some((name, kind, size))
            })
            .map_err(|_| BackendError::Io)?;
        let bound = limit.saturating_add(1);
        let mut out = entries;
        if out.len() > bound {
            out.truncate(bound);
        }
        out.shrink_to_fit();
        Ok(out)
    }

    fn deleted_child_names(&self, dir: &str) -> Vec<String> {
        self.deleted_child_names_bounded(dir, usize::MAX)
            .unwrap_or_default()
    }

    fn deleted_child_names_bounded(
        &self,
        dir: &str,
        limit: usize,
    ) -> Result<Vec<String>, BackendError> {
        use std::os::unix::ffi::OsStringExt as _;
        if !self.may_have_whiteouts() {
            return Ok(Vec::new());
        }
        let Some(normalized) = normalize(dir) else {
            return Ok(Vec::new());
        };
        let rel = Self::rel_path(&normalized).unwrap_or_else(|| Path::new(""));
        let Ok(entries) = self.read_dir_entries(rel, |d_name, _, _| {
            let name = d_name.to_string_lossy();
            if !name.starts_with(HOST_WHITEOUT_SIDECAR_PREFIX) {
                return None;
            }
            Some(d_name.to_bytes().to_vec())
        }) else {
            return Ok(Vec::new());
        };
        let parent_fd = match self.dir_fd_for(rel) {
            Ok(fd) => fd,
            Err(_) => return Ok(Vec::new()),
        };
        let bound = limit.saturating_add(1);
        let mut deleted = Vec::with_capacity(entries.len().min(bound));
        for marker_bytes in entries {
            let Ok(marker_c) = std::ffi::CString::new(marker_bytes) else {
                continue;
            };
            let fd = unsafe {
                libc::openat(
                    parent_fd.as_raw_fd(),
                    marker_c.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 {
                continue;
            }
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            let mut leaf = Vec::new();
            if file.read_to_end(&mut leaf).is_err() {
                continue;
            }
            let leaf_path = PathBuf::from(std::ffi::OsString::from_vec(leaf));
            if leaf_path.components().count() == 1
                && matches!(leaf_path.components().next(), Some(Component::Normal(_)))
                && host_whiteout_sidecar_rel(&normalized.join(&leaf_path))
                    .and_then(|path| path.file_name().map(ToOwned::to_owned))
                    .is_some_and(|expected| {
                        use std::os::unix::ffi::OsStrExt as _;
                        expected.as_os_str().as_bytes() == marker_c.as_bytes()
                    })
            {
                deleted.push(leaf_path.to_string_lossy().into_owned());
                if deleted.len() >= bound {
                    break;
                }
            }
        }
        deleted.shrink_to_fit();
        Ok(deleted)
    }

    fn rename_overlay_entry(&self, from: &str, to: &str) -> Result<bool, BackendError> {
        let src = normalize(from).ok_or(BackendError::Invalid)?;
        let dst = normalize(to).ok_or(BackendError::Invalid)?;
        let src_rel = NormalizedRelPath::from_normalized_relative(src);
        let dst_rel = NormalizedRelPath::from_normalized_relative(dst);
        self.rename_overlay_entry_at(None, None, &src_rel, None, None, &dst_rel)
    }

    fn rename_overlay_entry_at(
        &self,
        src_parent_fd: Option<&std::os::fd::OwnedFd>,
        src_leaf_c: Option<&std::ffi::CStr>,
        src_rel: &NormalizedRelPath,
        dst_parent_fd: Option<&std::os::fd::OwnedFd>,
        dst_leaf_c: Option<&std::ffi::CStr>,
        dst_rel: &NormalizedRelPath,
    ) -> Result<bool, BackendError> {
        use std::os::fd::AsRawFd;
        let _mutation = self.archive_mutation_gate.mutation();

        let src_fallback;
        let (src_pfd, src_name_c) = if let (Some(fd), Some(name)) = (src_parent_fd, src_leaf_c) {
            (fd.as_raw_fd(), name)
        } else {
            src_fallback = match self.namei_leaf(src_rel.as_path()) {
                Some(pair) => pair,
                None => return Ok(false),
            };
            (src_fallback.0.as_raw_fd(), src_fallback.1.as_c_str())
        };

        let dst_fallback_fd;
        let dst_fallback_name;
        let (dst_pfd, dst_name_c) = if let (Some(fd), Some(name)) = (dst_parent_fd, dst_leaf_c) {
            (fd.as_raw_fd(), name)
        } else {
            dst_fallback_fd = self
                .ensure_parent_dirs(dst_rel.as_path())
                .map_err(|_| BackendError::Io)?;
            dst_fallback_name = dst_rel
                .file_name()
                .and_then(cstring_from_osstr)
                .ok_or(BackendError::Invalid)?;
            (dst_fallback_fd.as_raw_fd(), dst_fallback_name.as_c_str())
        };

        let rc =
            unsafe { libc::renameat(src_pfd, src_name_c.as_ptr(), dst_pfd, dst_name_c.as_ptr()) };
        if rc != 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err == libc::ENOENT {
                return Ok(false);
            }
            return Err(BackendError::Io);
        }

        #[cfg(not(target_os = "macos"))]
        {
            remove_link_xattr_sidecars(self, dst_rel.as_path());
            for key in ["uid", "gid", "socket"] {
                if let (Some(s), Some(d)) = (
                    link_xattr_sidecar_rel(src_rel.as_path(), key),
                    link_xattr_sidecar_rel(dst_rel.as_path(), key),
                ) {
                    if let (Some((sp, sl)), Some(dp)) =
                        (self.namei_leaf(&s), self.ensure_parent_dirs(&d))
                    {
                        if let Some(dl) = d.file_name().and_then(cstring_from_osstr) {
                            unsafe {
                                libc::renameat(
                                    sp.as_raw_fd(),
                                    sl.as_ptr(),
                                    dp.as_raw_fd(),
                                    dl.as_ptr(),
                                );
                            }
                        }
                    }
                }
            }
        }

        crate::fs_resolve_cache::bump_generation();
        crate::fs_resolve_cache::bump_dir_generation();
        let src_parent = src_rel.parent().unwrap_or_else(|| Path::new(""));
        let dst_parent = dst_rel.parent().unwrap_or_else(|| Path::new(""));
        self.dir_gen_for(src_parent)
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.dir_gen_for(dst_parent)
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.dir_gen_for(src_rel.as_path())
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.dir_gen_for(dst_rel.as_path())
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.evict_dir_cache_subtree(src_rel.as_path());
        self.evict_dir_cache_subtree(dst_rel.as_path());
        self.evict_stat_cache_subtree(src_rel.as_path());
        self.evict_stat_cache_subtree(dst_rel.as_path());
        Ok(true)
    }

    fn exchange_overlay_entries(&self, a: &str, b: &str) -> Result<bool, BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let a_norm = normalize(a).ok_or(BackendError::Invalid)?;
        let b_norm = normalize(b).ok_or(BackendError::Invalid)?;
        let a_rel = Self::rel_path(&a_norm).ok_or(BackendError::Invalid)?;
        let b_rel = Self::rel_path(&b_norm).ok_or(BackendError::Invalid)?;
        let (a_parent_fd, a_leaf) = match self.namei_leaf(a_rel) {
            Some(pair) => pair,
            None => return Ok(false),
        };
        let (b_parent_fd, b_leaf) = match self.namei_leaf(b_rel) {
            Some(pair) => pair,
            None => return Ok(false),
        };
        #[cfg(target_os = "macos")]
        {
            let rc = unsafe {
                libc::renameatx_np(
                    a_parent_fd.as_raw_fd(),
                    a_leaf.as_ptr(),
                    b_parent_fd.as_raw_fd(),
                    b_leaf.as_ptr(),
                    libc::RENAME_SWAP,
                )
            };
            if rc != 0 {
                return Err(BackendError::Io);
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let seq = ANON_FD_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let pid = unsafe { libc::getpid() } as u64;
            let tmp_name = format!(".carrick_exchange.{pid}.{seq}");
            let tmp_c = std::ffi::CString::new(tmp_name).map_err(|_| BackendError::Invalid)?;
            let rc1 = unsafe {
                libc::renameat(
                    a_parent_fd.as_raw_fd(),
                    a_leaf.as_ptr(),
                    a_parent_fd.as_raw_fd(),
                    tmp_c.as_ptr(),
                )
            };
            if rc1 != 0 {
                return Err(BackendError::Io);
            }
            let rc2 = unsafe {
                libc::renameat(
                    b_parent_fd.as_raw_fd(),
                    b_leaf.as_ptr(),
                    a_parent_fd.as_raw_fd(),
                    a_leaf.as_ptr(),
                )
            };
            if rc2 != 0 {
                unsafe {
                    libc::renameat(
                        a_parent_fd.as_raw_fd(),
                        tmp_c.as_ptr(),
                        a_parent_fd.as_raw_fd(),
                        a_leaf.as_ptr(),
                    );
                }
                return Err(BackendError::Io);
            }
            let rc3 = unsafe {
                libc::renameat(
                    a_parent_fd.as_raw_fd(),
                    tmp_c.as_ptr(),
                    b_parent_fd.as_raw_fd(),
                    b_leaf.as_ptr(),
                )
            };
            if rc3 != 0 {
                unsafe {
                    libc::renameat(
                        a_parent_fd.as_raw_fd(),
                        a_leaf.as_ptr(),
                        b_parent_fd.as_raw_fd(),
                        b_leaf.as_ptr(),
                    );
                    libc::renameat(
                        a_parent_fd.as_raw_fd(),
                        tmp_c.as_ptr(),
                        a_parent_fd.as_raw_fd(),
                        a_leaf.as_ptr(),
                    );
                }
                return Err(BackendError::Io);
            }
        }
        crate::fs_resolve_cache::bump_generation();
        crate::fs_resolve_cache::bump_dir_generation();
        self.drop_dir_cache();
        if self.use_stat_cache {
            self.drop_stat_cache_after_rename();
        }
        Ok(true)
    }

    fn open_raw_fd(&self, path: &str, write: bool, create: bool, trunc: bool) -> HostFdOpen<i32> {
        // Fd-centric fast path for the common non-creating, non-truncating
        // open: ONE kernel-resolved openat with the real access mode replaces
        // the resolve_following walk + double cap-std open. Creating and
        // truncating opens keep the full cap-std path (sandboxed parent
        // creation, exact O_TRUNC semantics).
        #[cfg(target_os = "macos")]
        if !create
            && !trunc
            && let Some(normalized) = normalize(path)
            && let Some(rel) = Self::rel_path(&normalized)
        {
            match self.fast_open_for_guest(rel, write) {
                FastGuestOpen::Served { fd, .. } => {
                    use std::os::fd::IntoRawFd;
                    return HostFdOpen::Served(fd.into_raw_fd());
                }
                // A FIFO discovered at open time (create race — the
                // dispatcher normally intercepts FIFOs before this path):
                // NEVER hand it to the cap-std slow path, whose blocking
                // open of a writer-less FIFO would wedge the dispatcher.
                // O_RDWR for a write request so the open can't ENXIO/block
                // regardless of reader presence.
                FastGuestOpen::Fifo => {
                    return match self.open_fifo_nonblock(path, if write { 2 } else { 0 }) {
                        Some(fd) => HostFdOpen::Served(fd),
                        None => HostFdOpen::Unavailable,
                    };
                }
                FastGuestOpen::Refused(refused) => return HostFdOpen::Refused(refused),
                FastGuestOpen::SymlinkLeaf | FastGuestOpen::Missing | FastGuestOpen::Fallback => {}
            }
        }
        self.open_raw_fd_impl(path, write, create, trunc)
    }

    #[cfg(target_os = "macos")]
    fn upgrade_host_fd_for_shared_map(&self, fd: i32) -> bool {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let Some(root_prefix) = self.root_prefix.as_deref() else {
            return false;
        };
        let mut buf = [0u8; libc::PATH_MAX as usize];
        if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr() as *mut libc::c_char) } < 0 {
            return false;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let Ok(path) = std::ffi::CString::new(&buf[..end]) else {
            return false;
        };
        // Containment is checked on the fd ALREADY held (its vnode's cached
        // path), and the re-open is pinned to that same inode below, so the
        // path is only a handle for the kernel to reach the vnode again —
        // a rename or replacement between the two steps is caught by the
        // identity comparison, never served.
        if !fd_contained_under(fd, root_prefix) {
            return false;
        }
        let Ok(old_identity) = host_dir_identity(fd) else {
            return false;
        };
        let raw = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NOCTTY,
            )
        };
        if raw < 0 {
            return false;
        }
        // SAFETY: freshly-opened owned fd; drop closes it on every early
        // return and after the dup2 below has copied it onto `fd`.
        let new = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(new.as_raw_fd(), &mut st) } != 0
            || st.st_mode as u32 & libc::S_IFMT as u32 != libc::S_IFREG as u32
            || (st.st_dev as u64, st.st_ino) != old_identity
        {
            return false;
        }
        let offset = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
        if offset < 0 || unsafe { libc::lseek(new.as_raw_fd(), offset, libc::SEEK_SET) } < 0 {
            return false;
        }
        // dup2 atomically replaces the open behind the number; the caller
        // holds the description's write guard, so no read/write can move the
        // offset between the copy above and the swap.
        if unsafe { libc::dup2(new.as_raw_fd(), fd) } < 0 {
            return false;
        }
        // dup2 clears FD_CLOEXEC on the target; restore the dispatcher's
        // host-fd invariant.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        true
    }

    fn create_raw_fd(&self, path: &str, mode: u32, trunc: bool) -> HostFdOpen<(i32, bool)> {
        #[cfg(target_os = "macos")]
        if let Some(normalized) = normalize(path)
            && let Some(rel) = Self::rel_path(&normalized)
        {
            match self.fast_create_for_guest(rel, mode, trunc) {
                HostFdOpen::Served(created) => return HostFdOpen::Served(created),
                HostFdOpen::Refused(refused) => return HostFdOpen::Refused(refused),
                HostFdOpen::Unavailable => {}
            }
        }
        self.open_raw_fd_impl(path, true, true, trunc)
            .map(|fd| (fd, false))
    }

    fn reopen_for_durability(&self, path: &str) -> Result<Option<i32>, BackendError> {
        self.open_raw_fd(path, true, false, false)
            .into_backend_result()
            .map(Some)
    }

    fn open_raw_fd_with_metadata(
        &self,
        path: &str,
        write: bool,
        create: bool,
        trunc: bool,
    ) -> HostFdOpen<(i32, RootFsMetadata)> {
        // Same fast path as `open_raw_fd`, deriving the dispatch metadata
        // from the SAME fd (fstat + one flistxattr-gated xattr pass) so the
        // served open needs no separate lookup/metadata walk at all.
        #[cfg(target_os = "macos")]
        if !create
            && !trunc
            && let Some(normalized) = normalize(path)
            && let Some(rel) = Self::rel_path(&normalized)
        {
            match self.fast_open_for_guest(rel, write) {
                FastGuestOpen::Served { fd, stat, kind } => {
                    if kind != RootFsEntryKind::File {
                        // This API serves regular files only (the dispatcher
                        // routes directories through the Directory arm); the
                        // fd drops (closes) and the caller's `open_raw_fd`
                        // fallback reproduces the historical behavior.
                        return HostFdOpen::Unavailable;
                    }
                    use std::os::fd::{AsRawFd, IntoRawFd};
                    let override_mode = if self.serves_plain_metadata() {
                        None
                    } else {
                        fd_carrick_meta(fd.as_raw_fd()).0
                    };
                    let on_disk_mode = stat.st_mode as u32 & 0o7777;
                    let mode = override_mode.unwrap_or(if on_disk_mode == 0 {
                        0o644
                    } else {
                        on_disk_mode
                    });
                    return HostFdOpen::Served((
                        fd.into_raw_fd(),
                        RootFsMetadata {
                            path: std::path::Path::new(path).to_path_buf(),
                            kind: RootFsEntryKind::File,
                            mode,
                            size: stat.st_size as usize,
                        },
                    ));
                }
                // Not a regular file: let the caller fall back to its
                // metadata + `open_raw_fd` sequence (whose own Fifo route
                // stays non-blocking).
                FastGuestOpen::Fifo => return HostFdOpen::Unavailable,
                FastGuestOpen::Refused(refused) => return HostFdOpen::Refused(refused),
                FastGuestOpen::SymlinkLeaf | FastGuestOpen::Missing | FastGuestOpen::Fallback => {}
            }
        }
        let fd = match self.open_raw_fd_impl(path, write, create, trunc) {
            HostFdOpen::Served(fd) => fd,
            HostFdOpen::Unavailable => return HostFdOpen::Unavailable,
            HostFdOpen::Refused(refused) => return HostFdOpen::Refused(refused),
        };
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            unsafe { libc::close(fd) };
            return HostFdOpen::Unavailable;
        }
        let typ = st.st_mode as u32 & libc::S_IFMT as u32;
        if typ != libc::S_IFREG as u32 {
            unsafe { libc::close(fd) };
            return HostFdOpen::Unavailable;
        }
        let override_mode = if self.serves_plain_metadata() {
            None
        } else {
            fd_carrick_meta(fd).0
        };
        let on_disk_mode = st.st_mode as u32 & 0o7777;
        let mode = override_mode.unwrap_or(if on_disk_mode == 0 {
            0o644
        } else {
            on_disk_mode
        });
        HostFdOpen::Served((
            fd,
            RootFsMetadata {
                path: std::path::Path::new(path).to_path_buf(),
                kind: RootFsEntryKind::File,
                mode,
                size: if trunc { 0 } else { st.st_size as usize },
            },
        ))
    }

    fn watch_fds(&self, path: &str) -> Result<Vec<crate::vfs::WatchFd>, LinuxErrno> {
        use std::os::fd::FromRawFd;
        use std::os::unix::ffi::OsStrExt;
        use std::sync::atomic::Ordering::Relaxed;

        let scratch = self
            ._scratch
            .as_ref()
            .ok_or(crate::linux_abi::LINUX_ENOSYS)?;
        // Resolution cache: `inotify_add_watch` re-resolves the SAME path every
        // iteration in the LTP fuzzy-sync loop, and `lookup_kind` +
        // `resolve_following` each do a cap-std openat-per-component walk. Serve
        // a cached resolved path while the shared fs generation is unchanged (a
        // structural mutation in ANY process bumps it); the kqueue watch fd
        // itself still opens fresh below. Sample the generation at entry for the
        // store stamp, but validate a hit against the FRESH current generation
        // so a mutation between entry and lookup also invalidates.
        let gen_at_entry = crate::fs_resolve_cache::current_generation();
        let cached = {
            let now = crate::fs_resolve_cache::current_generation();
            let proc_gen = crate::fs_resolve_cache::current_process_generation();
            let mut guard = self.watch_res_cache.lock();
            if self.watch_cache_proc_gen.load(Relaxed) != proc_gen {
                guard.clear();
                self.watch_cache_proc_gen.store(proc_gen, Relaxed);
            }
            guard.get(path).and_then(|entry| {
                (entry.generation == now)
                    .then(|| (entry.normalized.clone(), entry.source_fd.clone()))
            })
        };
        let (normalized, cached_source_fd) = match cached {
            // A cached hit is never a tombstone — we don't store those.
            Some(entry) => entry,
            None => {
                let kind = self
                    .lookup_kind(path)
                    .ok_or(crate::linux_abi::LINUX_ENOENT)?;
                if matches!(kind, OverlayEntryKind::Deleted) {
                    // Don't cache the tombstone — a re-create bumps the
                    // generation and this re-resolves anyway.
                    return Err(crate::linux_abi::LINUX_ENOENT);
                }
                let normalized = self
                    .resolve_following(path)
                    .ok_or(crate::linux_abi::LINUX_EINVAL)?;
                (normalized, None)
            }
        };
        let host_path = scratch.path().join(&normalized);
        let root_fd = match cached_source_fd {
            Some(ref source_fd) => {
                dup_host_watch_fd(std::os::fd::AsRawFd::as_raw_fd(&**source_fd))?
            }
            None => open_host_watch_fd(&host_path)?,
        };
        let metadata = std::fs::symlink_metadata(&host_path).map_err(io_error_to_linux_errno)?;
        if !metadata.is_dir() {
            if cached_source_fd.is_none() {
                let source_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(root_fd) };
                let watch_fd = dup_host_watch_fd(std::os::fd::AsRawFd::as_raw_fd(&source_fd))?;
                let mut guard = self.watch_res_cache.lock();
                // Bound it: distinct watched paths are normally few, but a
                // path-diverse guest must not grow this without limit.
                if guard.len() >= 8192 && !guard.contains_key(path) {
                    guard.clear();
                }
                guard.insert(
                    path.to_owned(),
                    WatchResCacheEntry {
                        generation: gen_at_entry,
                        normalized,
                        source_fd: Some(std::sync::Arc::new(source_fd)),
                    },
                );
                return Ok(vec![crate::vfs::WatchFd::unnamed(watch_fd)]);
            }
            return Ok(vec![crate::vfs::WatchFd::unnamed(root_fd)]);
        }

        if cached_source_fd.is_none() {
            let mut guard = self.watch_res_cache.lock();
            if guard.len() >= 8192 && !guard.contains_key(path) {
                guard.clear();
            }
            guard.insert(
                path.to_owned(),
                WatchResCacheEntry {
                    generation: gen_at_entry,
                    normalized: normalized.clone(),
                    source_fd: None,
                },
            );
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
        let pid = unsafe { libc::getpid() } as u64;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = ANON_FD_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!(".carrick_o_tmpfile.{pid}.{seq}.{nanos}");
        let c_name = std::ffi::CString::new(name).ok()?;
        // O_RDWR (not the guest access mode) so HVF can mmap the result with
        // write max-protection if needed; the dispatcher records writability.
        let raw_fd = unsafe {
            libc::openat(
                self.root_fd.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw_fd < 0 {
            return None;
        }
        unsafe {
            libc::fchmod(raw_fd, (mode & 0o7777) as libc::mode_t);
            libc::unlinkat(self.root_fd.as_raw_fd(), c_name.as_ptr(), 0);
        }
        Some(raw_fd)
    }

    fn open_fifo_nonblock(&self, path: &str, access: u32) -> Option<i32> {
        let normalized = self.resolve_following(path)?;
        let rel = Self::rel_path(&normalized)?;
        let (parent_fd, leaf_c) = self.namei_leaf(rel)?;
        let host_access = match access {
            0 => libc::O_RDONLY,
            1 => libc::O_WRONLY,
            _ => libc::O_RDWR,
        };
        let fd = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                host_access | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 { None } else { Some(fd) }
    }

    fn fifo_identity(&self, path: &str) -> Option<(u64, u64)> {
        let normalized = self.resolve_following(path)?;
        let rel = Self::rel_path(&normalized)?;
        let (parent_fd, leaf_c) = self.namei_leaf(rel)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return None;
        }
        Some((st.st_dev as u64, st.st_ino as u64))
    }

    fn symlink(&self, target: &str, linkpath: &str) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(linkpath).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        let parent_fd = self.ensure_parent_dirs(rel).map_err(|_| BackendError::Io)?;
        let leaf_name = rel
            .file_name()
            .and_then(cstring_from_osstr)
            .ok_or(BackendError::Invalid)?;
        let target_c = std::ffi::CString::new(target).map_err(|_| BackendError::Invalid)?;
        self.stamp_root_marker(CARRICK_HAS_SYMLINKS_XATTR, &self.symlink_seen);
        crate::fs_resolve_cache::bump_generation();
        let rc = unsafe {
            libc::symlinkat(target_c.as_ptr(), parent_fd.as_raw_fd(), leaf_name.as_ptr())
        };
        if rc != 0 {
            return Err(BackendError::Io);
        }
        self.evict_dir_cache_subtree(rel);
        if self.use_stat_cache {
            self.stat_cache.lock().remove(rel);
        }
        Ok(())
    }

    fn hard_link(&self, src: &str, linkpath: &str) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let src_norm = normalize(src).ok_or(BackendError::Invalid)?;
        let dst_norm = normalize(linkpath).ok_or(BackendError::Invalid)?;
        let src_rel = Self::rel_path(&src_norm).ok_or(BackendError::Invalid)?;
        let dst_rel = Self::rel_path(&dst_norm).ok_or(BackendError::Invalid)?;
        let (src_parent_fd, src_leaf) = self.namei_leaf(src_rel).ok_or(BackendError::Invalid)?;
        let dst_parent_fd = self
            .ensure_parent_dirs(dst_rel)
            .map_err(|_| BackendError::Io)?;
        let dst_leaf = dst_rel
            .file_name()
            .and_then(cstring_from_osstr)
            .ok_or(BackendError::Invalid)?;
        let rc = unsafe {
            libc::linkat(
                src_parent_fd.as_raw_fd(),
                src_leaf.as_ptr(),
                dst_parent_fd.as_raw_fd(),
                dst_leaf.as_ptr(),
                0,
            )
        };
        if rc != 0 {
            return Err(BackendError::Io);
        }
        crate::fs_resolve_cache::bump_generation();
        Ok(())
    }

    fn set_mode(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let fd = self
            .metadata_fd(&normalized, false)
            .map_err(|_| BackendError::Io)?;
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return Err(BackendError::Io);
        }
        let mode = mode & 0o7777;
        let kind = st.st_mode as u32 & libc::S_IFMT as u32;
        if kind == libc::S_IFIFO as u32 {
            return unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) }
                .host_syscall_errno()
                .map(|_| ())
                .map_err(BackendError::Host);
        }
        let owner_ok = if kind == libc::S_IFDIR as u32 {
            mode & 0o700 == 0o700
        } else {
            mode & 0o600 == 0o600
        };
        if kind != libc::S_IFLNK as u32 {
            let native_mode = if owner_ok { mode } else { mode | 0o700 };
            unsafe { libc::fchmod(fd.as_raw_fd(), native_mode as libc::mode_t) }
                .host_syscall_errno()
                .map_err(BackendError::Host)?;
            if owner_ok {
                fremove_xattr(fd.as_raw_fd(), CARRICK_MODE_XATTR);
                return Ok(());
            }
        }
        self.stamp_root_marker(CARRICK_HAS_META_XATTRS_XATTR, &self.meta_xattr_seen);
        fset_mode_xattr(fd.as_raw_fd(), mode);
        Ok(())
    }

    fn set_owner(
        &self,
        path: &str,
        uid: Option<NsUid>,
        gid: Option<NsGid>,
    ) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        self.stamp_root_marker(CARRICK_HAS_META_XATTRS_XATTR, &self.meta_xattr_seen);
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
        let (parent_fd, leaf_c) = self.namei_leaf(rel).ok_or(BackendError::Invalid)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(BackendError::Io);
        }
        let raw_type = (st.st_mode as u32) & (libc::S_IFMT as u32);
        let is_dir = raw_type == libc::S_IFDIR as u32;
        let is_symlink = raw_type == libc::S_IFLNK as u32;
        #[cfg(target_os = "macos")]
        {
            if !is_symlink && raw_type == libc::S_IFIFO as u32 {
                if let Some(uid) = uid {
                    path_set_u32_xattr(self, rel, CARRICK_UID_XATTR, uid.raw());
                }
                if let Some(gid) = gid {
                    path_set_u32_xattr(self, rel, CARRICK_GID_XATTR, gid.raw());
                }
                return Ok(());
            }
        }
        write_owner_xattr(self, rel, is_dir, is_symlink, uid, gid);
        Ok(())
    }

    fn get_owner(&self, path: &str) -> Option<(NsUid, NsGid)> {
        let normalized = normalize(path)?;
        let rel = Self::rel_path(&normalized)?;
        let (parent_fd, leaf_c) = self.namei_leaf(rel)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return None;
        }
        let raw_type = (st.st_mode as u32) & (libc::S_IFMT as u32);
        if raw_type == libc::S_IFIFO as u32 {
            #[cfg(target_os = "macos")]
            {
                let uid = path_get_u32_xattr(self, rel, CARRICK_UID_XATTR, false);
                let gid = path_get_u32_xattr(self, rel, CARRICK_GID_XATTR, false);
                return Some((
                    uid.map(NsUid::new).unwrap_or(NsUid::ROOT),
                    gid.map(NsGid::new).unwrap_or(NsGid::ROOT),
                ));
            }
            #[cfg(not(target_os = "macos"))]
            return Some((NsUid::ROOT, NsGid::ROOT));
        }
        let is_dir = raw_type == libc::S_IFDIR as u32;
        let is_symlink = raw_type == libc::S_IFLNK as u32;
        let (uid, gid) = read_owner_xattr(self, rel, is_dir, is_symlink);
        Some((uid.unwrap_or(NsUid::ROOT), gid.unwrap_or(NsGid::ROOT)))
    }

    fn set_times(
        &self,
        path: &str,
        atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
        nofollow: bool,
    ) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
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
            let rel = Self::rel_path(&normalized).ok_or(BackendError::Invalid)?;
            let (parent_fd, leaf_c) = self.namei_leaf(rel).ok_or(BackendError::Invalid)?;
            let rc = unsafe {
                libc::utimensat(
                    parent_fd.as_raw_fd(),
                    leaf_c.as_ptr(),
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
        let host_fd = match self.open_raw_fd(path, false, false, false) {
            HostFdOpen::Served(fd) => fd,
            HostFdOpen::Refused(refused) => return Err(BackendError::Host(refused)),
            HostFdOpen::Unavailable => {
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
        let _mutation = self.archive_mutation_gate.mutation();
        let _normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let host_fd = self
            .open_raw_fd(path, true, false, false)
            .into_backend_result()?;
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
        if self.sparse_upper_nofollow_absent(path) {
            return None;
        }
        let (parent_fd, leaf_c) = self.namei_leaf(rel)?;
        use std::os::fd::AsRawFd as _;
        let mut buf = vec![0u8; 1024];
        let len = unsafe {
            libc::readlinkat(
                parent_fd.as_raw_fd(),
                leaf_c.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if len < 0 {
            return None;
        }
        buf.truncate(len as usize);
        String::from_utf8(buf).ok()
    }

    fn set_xattr(
        &self,
        path: &str,
        name: &str,
        value: &[u8],
        flags: i32,
        follow: bool,
    ) -> Result<(), LinuxErrno> {
        let _mutation = self.archive_mutation_gate.mutation();
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
        // list/get round-trips the exact Linux name. A DIRECTORY can't be
        // opened O_RDWR (EISDIR), so fall back to a read-only handle — xattr is
        // metadata and macOS `fsetxattr` accepts an O_RDONLY dir fd (setxattr02
        // case 01: `user.*` on a directory must succeed, not fail ENODATA).
        let cname = match std::ffi::CString::new(name) {
            Ok(c) => c,
            Err(_) => return Err(crate::linux_abi::LINUX_EINVAL),
        };
        // Translate Linux XATTR_CREATE/XATTR_REPLACE to the macOS options
        // (same semantics, different numeric values).
        let mut opts: libc::c_int = 0;
        let xflags = carrick_abi::LinuxXattrFlags::from_bits_truncate(flags);
        if xflags.contains(carrick_abi::LinuxXattrFlags::CREATE) {
            opts |= carrick_portable::XATTR_CREATE;
        }
        if xflags.contains(carrick_abi::LinuxXattrFlags::REPLACE) {
            opts |= carrick_portable::XATTR_REPLACE;
        }

        let normalized = normalize(path).ok_or(crate::linux_abi::LINUX_EINVAL)?;
        let owned_fd = self
            .metadata_fd(&normalized, follow)
            .map_err(crate::host_to_linux_errno)?;
        let host_fd = owned_fd.as_raw_fd();
        let rc = unsafe {
            carrick_portable::fsetxattr(
                host_fd,
                cname.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len() as libc::size_t,
                opts,
            )
        };
        rc.host_syscall_errno().map(|_| ())
    }

    fn get_xattr(&self, path: &str, name: &str, follow: bool) -> Result<Vec<u8>, LinuxErrno> {
        if !is_guest_xattr_namespace(name) || is_internal_carrick_xattr(name) {
            return Err(crate::linux_abi::LINUX_ENODATA);
        }
        let cname = match std::ffi::CString::new(name) {
            Ok(c) => c,
            Err(_) => return Err(crate::linux_abi::LINUX_EINVAL),
        };

        let normalized = normalize(path).ok_or(crate::linux_abi::LINUX_EINVAL)?;
        let owned_fd = self
            .metadata_fd(&normalized, follow)
            .map_err(crate::host_to_linux_errno)?;
        let host_fd = owned_fd.as_raw_fd();
        // First call with size 0 to learn the value length.
        let needed = unsafe {
            carrick_portable::fgetxattr(host_fd, cname.as_ptr(), std::ptr::null_mut(), 0)
        };
        let needed = match needed.host_syscall_errno() {
            Ok(needed) => needed,
            Err(err) => {
                return Err(err);
            }
        };
        let mut buf = vec![0u8; needed as usize];
        let n = unsafe {
            carrick_portable::fgetxattr(
                host_fd,
                cname.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
            )
        };
        n.host_syscall_errno().map(|n| {
            buf.truncate(n as usize);
            buf
        })
    }

    fn list_xattr(&self, path: &str, follow: bool) -> Result<Vec<String>, LinuxErrno> {
        fn collect_names(
            needed: isize,
            mut read: impl FnMut(&mut [u8]) -> isize,
        ) -> Result<Vec<String>, LinuxErrno> {
            let needed = match needed.host_syscall_errno() {
                Ok(needed) => needed,
                Err(crate::linux_abi::LINUX_ENODATA) => return Ok(Vec::new()),
                Err(err) => return Err(err),
            };
            let mut buf = vec![0u8; needed as usize];
            let n = match read(&mut buf).host_syscall_errno() {
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

        fn list_xattr_fd(host_fd: std::os::fd::RawFd) -> Result<Vec<String>, LinuxErrno> {
            // macOS may surface its own attribute names (e.g. resource forks);
            // we read the full NUL-separated list then filter to `user.*` so the
            // result is exactly the Linux-conformant namespace the guest set.
            let needed = unsafe { carrick_portable::flistxattr(host_fd, std::ptr::null_mut(), 0) };
            collect_names(needed, |buf| unsafe {
                carrick_portable::flistxattr(
                    host_fd,
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len() as libc::size_t,
                )
            })
        }

        let normalized = normalize(path).ok_or(crate::linux_abi::LINUX_EINVAL)?;
        let fd = self
            .metadata_fd(&normalized, follow)
            .map_err(crate::host_to_linux_errno)?;
        list_xattr_fd(fd.as_raw_fd())
    }

    fn remove_xattr(&self, path: &str, name: &str, follow: bool) -> Result<(), LinuxErrno> {
        let _mutation = self.archive_mutation_gate.mutation();
        // Mirror get_xattr: a non-`user.*` or carrick-internal name has no
        // guest-visible attribute to remove → ENODATA.
        if !is_guest_xattr_namespace(name) || is_internal_carrick_xattr(name) {
            return Err(crate::linux_abi::LINUX_ENODATA);
        }
        // A directory can't be opened O_RDWR; fall back to a read-only handle so
        // its xattrs can be removed too (setxattr02 removes the `user.*` key it
        // set on a directory between iterations).
        let cname = match std::ffi::CString::new(name) {
            Ok(c) => c,
            Err(_) => return Err(crate::linux_abi::LINUX_EINVAL),
        };

        let normalized = normalize(path).ok_or(crate::linux_abi::LINUX_EINVAL)?;
        let owned_fd = self
            .metadata_fd(&normalized, follow)
            .map_err(crate::host_to_linux_errno)?;
        let host_fd = owned_fd.as_raw_fd();
        // macOS fremovexattr; ENOATTR (absent attribute) maps to Linux ENODATA
        // via host_syscall_errno.
        let rc = unsafe { carrick_portable::fremovexattr(host_fd, cname.as_ptr()) };
        rc.host_syscall_errno().map(|_| ())
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
            let dir_fd = self.root_fd.as_raw_fd();
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
            let getpath_ok =
                unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr() as *mut libc::c_char) }
                    >= 0;
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
            let mut expected = Vec::with_capacity(root_prefix.len() + 1 + parent.as_os_str().len());
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

    fn open_trusted_dir_fd(&self, path: &str) -> Option<std::os::fd::OwnedFd> {
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
            use std::os::unix::ffi::OsStrExt;
            if !self.fast_fs {
                return None;
            }
            let root_prefix = self.root_prefix.as_deref()?;
            let normalized = normalize(path)?;
            let dir_fd = self.root_fd.as_raw_fd();
            // O_NOFOLLOW: the dispatcher hands us an already symlink-resolved
            // path, so a symlink leaf here is unexpected — reject rather than
            // traverse. O_NONBLOCK is moot for a directory but harmless.
            let oflags = libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK;
            let (raw, expected) = if normalized.as_os_str().is_empty() {
                // The sandbox root itself (guest "/"): trivially contained.
                let raw = unsafe { libc::openat(dir_fd, c".".as_ptr(), oflags, 0) };
                (raw, root_prefix.as_bytes().to_vec())
            } else {
                let rel_c = std::ffi::CString::new(normalized.as_os_str().as_bytes()).ok()?;
                let raw = unsafe { libc::openat(dir_fd, rel_c.as_ptr(), oflags, 0) };
                let mut expected =
                    Vec::with_capacity(root_prefix.len() + 1 + normalized.as_os_str().len());
                expected.extend_from_slice(root_prefix.as_bytes());
                expected.push(b'/');
                expected.extend_from_slice(normalized.as_os_str().as_bytes());
                (raw, expected)
            };
            if raw < 0 {
                return None;
            }
            // SAFETY: freshly-opened owned fd; closes on every early return.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            // Trust needs the BYTE-EXACT identity check (`F_GETPATH` equals
            // sandbox_root + path), not mere prefix containment: an in-sandbox
            // intermediate symlink or a Unicode-aliased component would leave
            // the fd contained but anchored at a DIFFERENT directory than the
            // recorded guest path, and every later single-component op would
            // silently resolve there. Any difference ⇒ untrusted.
            let mut buf = [0u8; libc::PATH_MAX as usize];
            if unsafe {
                libc::fcntl(
                    fd.as_raw_fd(),
                    libc::F_GETPATH,
                    buf.as_mut_ptr() as *mut libc::c_char,
                )
            } < 0
            {
                return None;
            }
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if &buf[..end] != expected.as_slice() {
                return None;
            }
            Some(fd)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = path;
            None
        }
    }

    fn dir_fd_for(&self, dir: &Path) -> Option<std::sync::Arc<std::os::fd::OwnedFd>> {
        Self::dir_fd_for(self, dir).ok()
    }

    fn is_shared(&self) -> bool {
        false
    }

    fn stat_cache_lookup(&self, path: &str) -> Option<RealStat> {
        // Disabled / non-macOS short-circuits via stat_cache_active() == false.
        if !self.stat_cache_active() {
            return None;
        }
        let normalized = normalize(path)?;
        let rel = Self::rel_path(&normalized)?;
        // Same Unicode-alias guard real_stat applies before its fast path: a
        // differently-normalized leaf the host VFS would alias must miss (the
        // caller then resolves it the slow way → ENOENT). ASCII leaves (the hot
        // case) short-circuit this with no syscall.
        if !self.name_matches_on_disk(rel) {
            return None;
        }
        self.stat_cache_get_or_fill(rel)
    }

    fn real_stat(&self, path: &str, follow: bool) -> Option<RealStat> {
        let normalized = if follow {
            self.resolve_following(path)?
        } else {
            normalize(path)?
        };

        if let Some(rel) = Self::rel_path(&normalized)
            && !self.name_matches_on_disk(rel)
        {
            return None;
        }

        if let Some(rs) = self.fast_real_stat(&normalized, follow) {
            return Some(rs);
        }

        use std::os::fd::AsRawFd as _;
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        let rel = Self::rel_path(&normalized);
        let rc = match rel {
            Some(r) => {
                let (parent_fd, leaf_c) = self.namei_leaf(r)?;
                unsafe {
                    libc::fstatat(
                        parent_fd.as_raw_fd(),
                        leaf_c.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                }
            }
            None => unsafe { libc::fstat(self.root_fd.as_raw_fd(), &mut st) },
        };
        if rc != 0 {
            return None;
        }

        let typ = st.st_mode as u32 & libc::S_IFMT as u32;
        let is_dir = typ == libc::S_IFDIR as u32;
        let is_symlink = typ == libc::S_IFLNK as u32;
        let is_fifo = typ == libc::S_IFIFO as u32;

        let kind = if is_dir {
            RootFsEntryKind::Directory
        } else if is_symlink {
            RootFsEntryKind::Symlink
        } else if is_fifo {
            RootFsEntryKind::Fifo
        } else if rel.is_some_and(|r| read_socket_xattr(self, r)) {
            RootFsEntryKind::Socket
        } else {
            RootFsEntryKind::File
        };

        let mode = st.st_mode as u32 & 0o7777;
        let default_mode = match kind {
            RootFsEntryKind::Directory => 0o755,
            RootFsEntryKind::Symlink => 0o777,
            RootFsEntryKind::File
            | RootFsEntryKind::CharDevice
            | RootFsEntryKind::Fifo
            | RootFsEntryKind::Socket => 0o644,
        };

        let (override_mode, owner) = if kind == RootFsEntryKind::Fifo {
            #[cfg(target_os = "macos")]
            {
                match rel {
                    Some(r) => (
                        None,
                        (
                            path_get_u32_xattr(self, r, CARRICK_UID_XATTR, false).map(NsUid::new),
                            path_get_u32_xattr(self, r, CARRICK_GID_XATTR, false).map(NsGid::new),
                        ),
                    ),
                    None => (None, (None, None)),
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                (None, (None, None))
            }
        } else if kind == RootFsEntryKind::Symlink {
            match rel {
                Some(r) => (
                    None,
                    (
                        symlink_get_u32_xattr(self, r, CARRICK_UID_XATTR).map(NsUid::new),
                        symlink_get_u32_xattr(self, r, CARRICK_GID_XATTR).map(NsGid::new),
                    ),
                ),
                None => (None, (None, None)),
            }
        } else {
            match rel {
                Some(r) => (
                    read_mode_xattr(self, r, is_dir),
                    read_owner_xattr(self, r, is_dir, false),
                ),
                None => (None, (None, None)),
            }
        };

        Some(RealStat {
            kind,
            ino: st.st_ino,
            nlink: st.st_nlink as u32,
            mode: override_mode.unwrap_or(if mode == 0 { default_mode } else { mode }),
            uid: owner.0.unwrap_or(NsUid::ROOT),
            gid: owner.1.unwrap_or(NsGid::ROOT),
            size: st.st_size as u64,
            blocks: Some(st.st_blocks.max(0) as u64),
            atime: (st.st_atime, carrick_portable::stat_atime_nsec(&st)),
            mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(&st)),
            ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(&st)),
        })
    }

    fn structural_generation(&self) -> u64 {
        crate::fs_resolve_cache::current_generation()
    }

    fn name(&self) -> &'static str {
        "host"
    }
}

pub(crate) fn default_scratch_root() -> std::io::Result<PathBuf> {
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

pub(crate) fn acquire_lockfile(
    scratch_dir: &Path,
) -> std::io::Result<fd_lock::RwLock<std::fs::File>> {
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

pub(crate) fn sweep_orphans(scratch_root: &Path) {
    const STARTUP_DISCOVERY_LIMIT: usize = 64;
    let retired_scratch = discover_orphans(scratch_root, Some(STARTUP_DISCOVERY_LIMIT));
    cleanup_oldest_trash_checkpoint(scratch_root);
    for retired in retired_scratch {
        if retired.exists() {
            enqueue_scratch_cleanup(retired);
        }
    }

    // Complete discovery away from the startup critical path. The dedicated
    // trash namespace makes normal retirement immediately discoverable; this
    // background pass is only for crashed live-name trees and legacy trash.
    enqueue_orphan_discovery(scratch_root.to_path_buf());
}

fn discover_orphans(scratch_root: &Path, limit: Option<usize>) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(scratch_root) else {
        return Vec::new();
    };
    let mut retired_scratch = Vec::new();
    for entry in entries.take(limit.unwrap_or(usize::MAX)).flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        // A tree retired by `defer_remove_tree` is never live again. Reclaim it
        // even if an interrupted in-process cleanup already removed the lock
        // file. Keep recognizing the pre-kernel-retirement name so upgrades do
        // not strand old scratch trees.
        if is_retired_scratch(&path) {
            if let Some(retired) = rename_scratch_to_trash(&path) {
                retired_scratch.push(retired);
            }
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
            // No other process holds the lock; orphan from a prior crashed run
            // OR a run that exited via process::exit (which skips Drop, so an
            // overlay-composed scratch left its `merged` overlay mounted). Detach
            // that mount before retiring the name, or the cleanup worker could
            // descend into the live overlay. Best-effort: umount2 of a non-mount
            // is a harmless EINVAL.
            #[cfg(target_os = "linux")]
            unmount_overlay_at(&path.join("merged"));
            drop(lock);
            if let Some(retired) = rename_scratch_to_trash(&path) {
                retired_scratch.push(retired);
            }
        }
    }
    retired_scratch
}

/// Best-effort lazy unmount of an overlay left at `merged` (see `sweep_orphans`
/// and `HostFsBackend`'s `overlay_mount`). MNT_DETACH never blocks on open fds.
#[cfg(target_os = "linux")]
fn unmount_overlay_at(merged: &Path) {
    use std::os::unix::ffi::OsStrExt;
    if let Ok(c) = std::ffi::CString::new(merged.as_os_str().as_bytes()) {
        // SAFETY: `c` is a valid NUL-terminated path; MNT_DETACH is non-blocking.
        unsafe {
            libc::umount2(c.as_ptr(), libc::MNT_DETACH);
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
    let deleted: HashSet<String> = overlay.deleted_child_names(dir).into_iter().collect();
    // The upper's contribution to THIS directory, read ONCE. `child_names`
    // is the same enumeration the additions pass below already performed, and
    // it answers the shadowing question for every lower entry by NAME: the
    // upper can only shadow `dir/x` by holding `x` as a child of `dir`, so
    // membership in this set is exactly `shadows(joined(dir, x))` — byte
    // exact on both sides (`lookup_kind` applies the same on-disk name check
    // the enumeration reads through) — for one directory read instead of one
    // full path lookup per lower entry.
    //
    // That per-entry lookup was the dominant term behind a guest `getdents64`
    // on an image directory: listing `/usr/local/lib/python3.12` (201 entries)
    // under `python:3.12-slim` issued 384 host `fstatat64`, and half of them
    // came from `shadows`. The sparse upper very often holds a directory as
    // an EMPTY SHELL (an ancestor materialized for something below it), which
    // is why the cheaper "the upper has nothing at this path at all" proof
    // does not fire on the hot directories and this one does.
    let upper_children = overlay.child_names(dir);
    let upper_names: HashSet<&str> = upper_children
        .iter()
        .map(|(name, _, _)| name.as_str())
        .collect();
    let mut seen: HashSet<String> = HashSet::new();

    if let Some(rootfs) = rootfs {
        match rootfs.directory_entries(dir) {
            Ok(entries) => {
                for entry in entries {
                    if is_internal_sidecar_name(&entry.name) {
                        continue;
                    }
                    if deleted.contains(&entry.name) {
                        continue;
                    }
                    if upper_names.contains(entry.name.as_str()) {
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
    drop(upper_names);

    for (name, kind, known_size) in upper_children {
        if is_internal_sidecar_name(&name) {
            continue;
        }
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
                let size = known_size
                    .and_then(|size| usize::try_from(size).ok())
                    .or_else(|| overlay.metadata(&path).map(|m| m.size))
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

/// One streamed readdir batch of a TRUSTED host dirfd, translated to the
/// `RootFsDirEntry` shape `getdents64`'s `dirent64_record` encoder consumes —
/// `d_name`/`d_type`/`d_ino` straight off the kernel, zero per-child stats.
/// `dup` + `fdopendir` gives `DIR*` ownership of a separate descriptor, but
/// shares its open-description offset. Callers must supply a private stream
/// description or serialize its offset. Skips "."/".." (the getdents
/// handler synthesizes deterministic dot entries) and carrick's internal
/// sidecar names. `None` on any surprise (`DT_UNKNOWN`, an unmappable type,
/// `fdopendir` failure) ⇒ the caller takes the exact layered path.
#[cfg(target_os = "macos")]
pub(crate) fn read_host_dir_entries(
    host_dir_fd: i32,
    dir_path: &str,
) -> Option<Vec<RootFsDirEntry>> {
    struct Dirp(*mut libc::DIR);
    impl Drop for Dirp {
        fn drop(&mut self) {
            // SAFETY: closes the DIR* (and its adopted dup'd fd) exactly once.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    // SAFETY: dup a descriptor for DIR* to adopt without closing the caller's
    // descriptor. The open-description seek offset remains shared.
    let dup = unsafe { libc::dup(host_dir_fd) };
    if dup < 0 {
        return None;
    }
    let raw_dirp = unsafe { libc::fdopendir(dup) };
    if raw_dirp.is_null() {
        // SAFETY: fdopendir did not adopt the fd, so it is still ours.
        unsafe {
            libc::close(dup);
        }
        return None;
    }
    let dirp = Dirp(raw_dirp);
    // fdopendir adopts the fd's CURRENT offset; the dup shares the
    // original's, so rewind to read the whole directory.
    unsafe { libc::rewinddir(dirp.0) };
    let mut out = Vec::new();
    loop {
        // SAFETY: dirp.0 is a live DIR*; readdir returns null at end.
        let ent = unsafe { libc::readdir(dirp.0) };
        if ent.is_null() {
            break;
        }
        // SAFETY: `ent` points at the DIR*'s current record; d_name is
        // NUL-terminated within the struct.
        let (d_type, d_ino, name_bytes) = unsafe {
            let e = &*ent;
            (
                e.d_type,
                e.d_ino,
                std::ffi::CStr::from_ptr(e.d_name.as_ptr()).to_bytes(),
            )
        };
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        // On-disk names are valid UTF-8 by construction (APFS rejects raw
        // non-UTF-8; undecodable guest names live in the reversible escape
        // form — see `fs_backend::normalize`), so this lossy read matches
        // `child_names` byte-for-byte.
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        if crate::fs_backend::is_internal_sidecar_name(&name) {
            continue;
        }
        let kind = match d_type {
            libc::DT_DIR => RootFsEntryKind::Directory,
            libc::DT_REG => RootFsEntryKind::File,
            libc::DT_LNK => RootFsEntryKind::Symlink,
            libc::DT_FIFO => RootFsEntryKind::Fifo,
            libc::DT_SOCK => RootFsEntryKind::Socket,
            libc::DT_CHR => RootFsEntryKind::CharDevice,
            // DT_UNKNOWN / DT_BLK / anything else: the stream cannot answer
            // d_type faithfully — layered path for the WHOLE directory.
            _ => return None,
        };
        let path = if dir_path == "/" {
            format!("/{name}")
        } else {
            format!("{dir_path}/{name}")
        };
        out.push(RootFsDirEntry {
            name,
            metadata: RootFsMetadata {
                path: std::path::PathBuf::from(path),
                kind,
                // getdents64 consumes only `kind` (→ d_type), the name and
                // the ino; mode/size mirror the layered merge's defaults for
                // entries it does not open.
                mode: if kind == RootFsEntryKind::Directory {
                    0o755
                } else {
                    0o644
                },
                size: 0,
            },
            ino: d_ino,
        });
    }
    Some(out)
}

/// Trusted host dirfds are only ever minted by the macOS `--fs host` fast
/// path; the streaming reader is unreachable elsewhere.
#[cfg(not(target_os = "macos"))]
pub(crate) fn read_host_dir_entries(
    _host_dir_fd: i32,
    _dir_path: &str,
) -> Option<Vec<RootFsDirEntry>> {
    None
}

/// Dirent-only layered merge, with the same upper shadowing and whiteout
/// precedence as layered_directory_entries. None requests its exact fallback.
/// Returned mode/size fields are placeholders, never stat metadata.
pub(crate) fn try_layered_stream_dirents(
    overlay: &dyn FsBackend,
    rootfs: Option<&RootFs>,
    dir: &str,
) -> Option<Vec<RootFsDirEntry>> {
    let upper = overlay.stream_dirents(dir)?;
    let lower = match rootfs {
        Some(rootfs) => rootfs.stream_dirents(dir)?,
        None => Vec::new(),
    };
    let deleted: HashSet<String> = overlay.deleted_child_names(dir).into_iter().collect();
    let upper_names: HashSet<&str> = upper.iter().map(|row| row.name.as_str()).collect();
    let mut out: Vec<_> = lower
        .into_iter()
        .filter(|row| {
            !is_internal_sidecar_name(&row.name)
                && !deleted.contains(&row.name)
                && !upper_names.contains(row.name.as_str())
        })
        .collect();
    drop(upper_names);
    out.extend(
        upper
            .into_iter()
            .filter(|row| !is_internal_sidecar_name(&row.name) && !deleted.contains(&row.name)),
    );
    Some(out)
}

fn joined(base: &str, name: &str) -> String {
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", base.trim_end_matches('/'))
    }
}
