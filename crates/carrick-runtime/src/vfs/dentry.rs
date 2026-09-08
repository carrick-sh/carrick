//! Directory entry (dentry) cache for the host-backed rootfs.
//!
//! Provides fast, in-memory resolution of guest paths on the host-backed
//! rootfs (`--fs host`). The rootfs scratch is private to the container run
//! (COW seed; only Carrick mutates it), so positive and negative dentry lookups
//! are authoritative and served with zero host syscalls on hit.
//!
//! Shared mounts (e.g. bind mounts) revalidate via `fstatat` through the
//! cached parent dirfd and are never negative-cached.
//!
//! # Inode Coherence Model
//!
//! The cache separates directory topology (dentries) from file metadata (inodes):
//! - **Dentries** map `(parent_dentry_id, name) -> PositiveDentry / NegativeDentry`.
//!   A positive dentry records the entry's identity `(dev, ino, kind, symlink_target)`.
//!   Multiple dentries can point to the same `(dev, ino)` (hard links).
//! - **Inodes** map `(dev, ino) -> InodeRecord { mode, uid, gid, size, atime, mtime, ctime, nlink }`.
//!
//! Mutations update or invalidate the cache as follows:
//! - **Update in place**:
//!   - Directory generation bumps (`bump_dir_generation`): updates `dir_gen` in place to
//!     invalidate negative lookups in that directory without evicting positive dentries.
//!   - Directory renames: updates `dirs` path table and bumps child directory generation.
//!   - In-memory file mutations (`update_inode`): Carrick owns the in-memory buffer, so
//!     stat attributes (size, mode) can be updated in place in `inodes`.
//! - **Invalidate**:
//!   - Host file descriptor mutations (`write`, `pwrite`, `writev`, `pwritev`, `ftruncate`,
//!     `fallocate`, `futimens`, `fchmod`, `fchown`): invalidate `(dev, ino)` in `inodes` and
//!     clear fast-path stat entries. The next `stat` performs a single `fstatat` to reload
//!     authoritative host metadata (exact APFS nanosecond timestamps, sizes, mode).
//!   - Hard link creation (`link`, `linkat`): creates the new dentry and invalidates the
//!     source `(dev, ino)` in `inodes`, so both the source and the new link observe the
//!     updated `st_nlink` and content.
//!   - Unlink / Rmdir (`unlink`, `unlinkat`, `rmdir`): evicts the dentry (recording a negative
//!     dentry for private rootfs) and invalidates `(dev, ino)` in `inodes` so remaining hard
//!     link aliases observe decremented `st_nlink`.
//!   - Path mutations (`truncate`, `chmod`, `chown`, `utimes`): invalidate the target path's
//!     dentry and inode record.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use parking_lot::{Mutex, RwLock};

use crate::fs_backend::{FsBackend, RealStat};
use crate::linux_abi::{
    LINUX_EAGAIN, LINUX_EINVAL, LINUX_EISDIR, LINUX_ELOOP, LINUX_ENAMETOOLONG, LINUX_ENOENT,
    LINUX_ENOSYS, LINUX_ENOTDIR, LINUX_EXDEV, LinuxErrno,
};
use crate::rootfs::{RootFs, RootFsEntryKind};
use carrick_abi::{NsGid, NsUid};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DentryId(pub u64);

impl DentryId {
    pub const ROOT: DentryId = DentryId(0);
}

#[derive(Clone, Debug)]
pub struct PositiveDentry {
    pub id: Option<DentryId>,
    pub kind: RootFsEntryKind,
    pub ino: u64,
    pub dev: u64,
    pub symlink_target: Option<String>,
    pub parent_gen: u64,
    pub dir_gen: Option<Arc<AtomicU64>>,
    pub is_lower: bool,
    pub accessed: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InodeIdentity {
    pub dev: u64,
    pub ino: u64,
}

impl InodeIdentity {
    pub const fn new(dev: u64, ino: u64) -> Self {
        Self { dev, ino }
    }
}

impl From<(u64, u64)> for InodeIdentity {
    fn from((dev, ino): (u64, u64)) -> Self {
        Self { dev, ino }
    }
}

impl From<InodeIdentity> for (u64, u64) {
    fn from(id: InodeIdentity) -> Self {
        (id.dev, id.ino)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InodeRecord {
    pub mode: u32,
    pub uid: NsUid,
    pub gid: NsGid,
    pub size: u64,
    pub atime: (i64, i64),
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
    pub nlink: u32,
    pub rdev: u64,
    pub dev_type: u32,
}

impl PositiveDentry {
    pub fn to_real_stat(&self, record: &InodeRecord) -> RealStat {
        RealStat {
            kind: self.kind,
            ino: self.ino,
            nlink: record.nlink,
            mode: record.mode,
            uid: record.uid,
            gid: record.gid,
            size: record.size,
            atime: record.atime,
            mtime: record.mtime,
            ctime: record.ctime,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NegativeDentry {
    pub parent_gen: u64,
    pub accessed: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
pub enum DentryNode {
    Positive(PositiveDentry),
    Negative(NegativeDentry),
}

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub id: DentryId,
    pub dir_gen: Arc<AtomicU64>,
    pub upper_dir_fd: Option<Arc<OwnedFd>>,
    pub lower_dir_fd: Option<Arc<OwnedFd>>,
    pub lower_probed: bool,
    pub upper_probed_gen: u64,
    pub parent: Option<(DentryId, String)>,
    pub path: String,
    pub dev: u64,
    pub ino: u64,
    pub child_dir_count: usize,
    pub accessed: Arc<AtomicBool>,
    pub pin_count: Arc<AtomicUsize>,
    pub lower_negatives: Arc<parking_lot::RwLock<HashSet<String>>>,
}

fn entry_node_approx_bytes(name: &str, node: &DentryNode) -> usize {
    let name_cost = name.len() + 48;
    let node_cost = match node {
        DentryNode::Positive(pos) => {
            std::mem::size_of::<PositiveDentry>()
                + pos.symlink_target.as_ref().map_or(0, |s| s.len())
        }
        DentryNode::Negative(_) => std::mem::size_of::<NegativeDentry>(),
    };
    name_cost + node_cost
}

fn dir_entry_approx_bytes(dir: &DirEntry) -> usize {
    std::mem::size_of::<DirEntry>() + dir.path.len() * 2 + 80
}

fn inode_approx_bytes() -> usize {
    std::mem::size_of::<InodeRecord>() + 48
}

#[derive(Clone, Debug)]
pub struct ResolvedDentry {
    pub dentry: PositiveDentry,
    pub canonical_path: String,
    pub parent_dir_fd: Option<Arc<OwnedFd>>,
    pub leaf_name: String,
    pub leaf_name_c: CString,
}

const FAST_PATH_CAP: usize = 16384;

#[derive(Default)]
struct FastPathCache {
    stat_follow: HashMap<String, Result<RealStat, LinuxErrno>>,
    stat_nofollow: HashMap<String, Result<RealStat, LinuxErrno>>,
    lookup_follow: HashMap<String, Result<ResolvedDentry, LinuxErrno>>,
    lookup_nofollow: HashMap<String, Result<ResolvedDentry, LinuxErrno>>,
}

pub struct DentryCache {
    proc_gen: AtomicU64,
    mutation_gen: AtomicU64,
    next_dentry_id: AtomicU64,
    is_shared: bool,
    host_opens: AtomicU64,
    capacity_bytes: usize,
    eviction_enabled: bool,
    approx_bytes: AtomicUsize,
    dir_eviction_queue: Mutex<VecDeque<DentryId>>,
    fast_path: RwLock<FastPathCache>,
    entries: RwLock<HashMap<(DentryId, String), DentryNode>>,
    inodes: RwLock<HashMap<(u64, u64), InodeRecord>>,
    dirs: RwLock<HashMap<DentryId, DirEntry>>,
    path_to_dir_id: RwLock<HashMap<String, DentryId>>,
}

impl Default for DentryCache {
    fn default() -> Self {
        Self::new(false)
    }
}

impl DentryCache {
    pub fn new(is_shared: bool) -> Self {
        let eviction_enabled = std::env::var("CARRICK_DENTRY_EVICT")
            .ok()
            .is_none_or(|v| v != "0");

        let capacity_bytes = std::env::var("CARRICK_DENTRY_CACHE_CAPACITY_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(32 * 1024 * 1024);

        Self::new_with_capacity(is_shared, capacity_bytes, eviction_enabled)
    }

    pub fn new_with_capacity(
        is_shared: bool,
        capacity_bytes: usize,
        eviction_enabled: bool,
    ) -> Self {
        let root_gen = Arc::new(AtomicU64::new(1));
        let root_dir = DirEntry {
            id: DentryId::ROOT,
            dir_gen: root_gen,
            upper_dir_fd: None,
            lower_dir_fd: None,
            lower_probed: false,
            upper_probed_gen: 0,
            parent: None,
            path: "/".to_string(),
            dev: 0,
            ino: 1,
            child_dir_count: 0,
            accessed: Arc::new(AtomicBool::new(true)),
            pin_count: Arc::new(AtomicUsize::new(0)),
            lower_negatives: Arc::new(parking_lot::RwLock::new(HashSet::new())),
        };
        let initial_bytes = dir_entry_approx_bytes(&root_dir);

        let mut dirs = HashMap::new();
        dirs.insert(DentryId::ROOT, root_dir);
        let mut path_to_dir_id = HashMap::new();
        path_to_dir_id.insert("/".to_string(), DentryId::ROOT);
        path_to_dir_id.insert("".to_string(), DentryId::ROOT);

        Self {
            proc_gen: AtomicU64::new(crate::fs_resolve_cache::current_process_generation()),
            mutation_gen: AtomicU64::new(1),
            next_dentry_id: AtomicU64::new(1),
            is_shared,
            host_opens: AtomicU64::new(0),
            capacity_bytes,
            eviction_enabled,
            approx_bytes: AtomicUsize::new(initial_bytes),
            dir_eviction_queue: Mutex::new(VecDeque::new()),
            fast_path: RwLock::new(FastPathCache::default()),
            entries: RwLock::new(HashMap::new()),
            inodes: RwLock::new(HashMap::new()),
            dirs: RwLock::new(dirs),
            path_to_dir_id: RwLock::new(path_to_dir_id),
        }
    }

    pub fn approx_memory_bytes(&self) -> usize {
        self.approx_bytes.load(Ordering::Relaxed)
    }

    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    fn add_approx_bytes(&self, bytes: usize) {
        self.approx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn sub_approx_bytes(&self, bytes: usize) {
        self.approx_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                Some(cur.saturating_sub(bytes))
            })
            .ok();
    }

    pub fn host_open_count(&self) -> u64 {
        self.host_opens.load(Ordering::Relaxed)
    }

    pub fn reset_host_open_count(&self) {
        self.host_opens.store(0, Ordering::Relaxed);
    }

    pub fn is_shared(&self) -> bool {
        self.is_shared
    }

    fn combined_generation(&self) -> u64 {
        self.mutation_gen
            .load(Ordering::Relaxed)
            .wrapping_add(crate::fs_resolve_cache::current_generation())
    }

    fn bump_mutation(&self) {
        self.mutation_gen.fetch_add(1, Ordering::SeqCst);
        let mut fp = self.fast_path.write();
        fp.stat_follow.clear();
        fp.stat_nofollow.clear();
        fp.lookup_follow.clear();
        fp.lookup_nofollow.clear();
    }

    /// Clear the cache if we crossed a host fork.
    fn check_fork(&self) {
        let cur_gen = crate::fs_resolve_cache::current_process_generation();
        if self.proc_gen.load(Ordering::Relaxed) != cur_gen {
            let mut entries = self.entries.write();
            let mut dirs = self.dirs.write();
            let mut path_to_dir_id = self.path_to_dir_id.write();
            entries.clear();
            self.inodes.write().clear();
            dirs.clear();
            path_to_dir_id.clear();
            self.dir_eviction_queue.lock().clear();
            let root_gen = Arc::new(AtomicU64::new(1));
            let root_dir = DirEntry {
                id: DentryId::ROOT,
                dir_gen: root_gen,
                upper_dir_fd: None,
                lower_dir_fd: None,
                lower_probed: false,
                lower_negatives: Arc::new(parking_lot::RwLock::new(HashSet::new())),
                upper_probed_gen: 0,
                parent: None,
                path: "/".to_string(),
                dev: 0,
                ino: 1,
                child_dir_count: 0,
                accessed: Arc::new(AtomicBool::new(true)),
                pin_count: Arc::new(AtomicUsize::new(0)),
            };
            self.approx_bytes
                .store(dir_entry_approx_bytes(&root_dir), Ordering::Relaxed);
            dirs.insert(DentryId::ROOT, root_dir);
            path_to_dir_id.insert("/".to_string(), DentryId::ROOT);
            path_to_dir_id.insert("".to_string(), DentryId::ROOT);
            self.proc_gen.store(cur_gen, Ordering::Relaxed);
            self.bump_mutation();
        }
    }

    /// Lookup `path` through the dentry cache, resolving symlink chains (up to 40 hops).
    pub fn lookup_path(
        &self,
        path: &str,
        follow_trailing: bool,
        backend: &dyn FsBackend,
        rootfs: Option<&RootFs>,
    ) -> Result<ResolvedDentry, LinuxErrno> {
        self.check_fork();

        let requires_dir = path.ends_with('/') || path.ends_with("/.");
        let effective_follow = follow_trailing || requires_dir;

        let mut norm_path = path.trim_end_matches('/');
        while norm_path.ends_with("/.") {
            norm_path = &norm_path[..norm_path.len() - 2];
        }
        let norm_path = if norm_path.is_empty() { "/" } else { norm_path };

        if !self.is_shared {
            let fp = self.fast_path.read();
            let map = if effective_follow {
                &fp.lookup_follow
            } else {
                &fp.lookup_nofollow
            };
            if let Some(res) = map.get(norm_path) {
                if requires_dir
                    && let Ok(r) = res
                    && r.dentry.kind != RootFsEntryKind::Directory
                {
                    return Err(LINUX_ENOTDIR);
                }
                return res.clone();
            }
        }

        let start_gen = self.mutation_gen.load(Ordering::SeqCst);
        let res = self.lookup_path_slow(norm_path, effective_follow, backend, rootfs);

        if !self.is_shared && (res.is_ok() || matches!(res, Err(LINUX_ENOENT))) {
            if self.mutation_gen.load(Ordering::SeqCst) == start_gen {
                let mut fp = self.fast_path.write();
                if self.mutation_gen.load(Ordering::SeqCst) == start_gen {
                    let lookup_map = if effective_follow {
                        &mut fp.lookup_follow
                    } else {
                        &mut fp.lookup_nofollow
                    };
                    if lookup_map.len() >= FAST_PATH_CAP {
                        lookup_map.clear();
                    }
                    lookup_map.insert(norm_path.to_string(), res.clone());

                    let stat_map = if effective_follow {
                        &mut fp.stat_follow
                    } else {
                        &mut fp.stat_nofollow
                    };
                    if stat_map.len() >= FAST_PATH_CAP {
                        stat_map.clear();
                    }
                    match &res {
                        Ok(r) => {
                            if let Some(record) = self
                                .inodes
                                .read()
                                .get(&(r.dentry.dev, r.dentry.ino))
                                .copied()
                            {
                                stat_map.insert(
                                    norm_path.to_string(),
                                    Ok(r.dentry.to_real_stat(&record)),
                                );
                            }
                        }
                        Err(e) => {
                            stat_map.insert(norm_path.to_string(), Err(*e));
                        }
                    }
                }
            }
        }

        if requires_dir
            && let Ok(r) = &res
            && r.dentry.kind != RootFsEntryKind::Directory
        {
            return Err(LINUX_ENOTDIR);
        }

        res
    }

    fn resolve_dir_id(
        &self,
        dir_id: DentryId,
        backend: &dyn FsBackend,
        rootfs: Option<&RootFs>,
    ) -> Result<ResolvedDentry, LinuxErrno> {
        if dir_id == DentryId::ROOT {
            let (root_gen, upper_fd, lower_fd) = {
                let mut dirs = self.dirs.write();
                let r = dirs.get_mut(&DentryId::ROOT).ok_or(LINUX_ENOENT)?;
                if r.upper_dir_fd.is_none() {
                    r.upper_dir_fd = backend.dir_fd_for(Path::new(""));
                }
                if r.lower_dir_fd.is_none() {
                    r.lower_dir_fd = rootfs
                        .and_then(|rf| rf.immutable_backend())
                        .and_then(|b| b.dir_fd_for(Path::new("")));
                }
                (
                    r.dir_gen.clone(),
                    r.upper_dir_fd.clone(),
                    r.lower_dir_fd.clone(),
                )
            };
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            let fd_ref = upper_fd.as_ref().or(lower_fd.as_ref());
            let (dev, ino, mode) = if let Some(fd) = fd_ref {
                unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
                (st.st_dev as u64, st.st_ino, st.st_mode as u32 & 0o7777)
            } else {
                (0, 1, 0o755)
            };
            {
                let mut dirs = self.dirs.write();
                if let Some(r) = dirs.get_mut(&DentryId::ROOT) {
                    r.dev = dev;
                    r.ino = ino;
                }
            }
            let record = InodeRecord {
                mode: if mode == 0 { 0o755 } else { mode },
                uid: NsUid::ROOT,
                gid: NsGid::ROOT,
                size: 4096,
                atime: (0, 0),
                mtime: (0, 0),
                ctime: (0, 0),
                nlink: 2,
                rdev: 0,
                dev_type: 0,
            };
            self.insert_inode_record(dev, ino, record);

            return Ok(ResolvedDentry {
                dentry: PositiveDentry {
                    id: Some(DentryId::ROOT),
                    kind: RootFsEntryKind::Directory,
                    ino,
                    dev,
                    symlink_target: None,
                    parent_gen: 1,
                    dir_gen: Some(root_gen),
                    is_lower: false,
                    accessed: Arc::new(AtomicBool::new(true)),
                },
                canonical_path: "/".to_string(),
                parent_dir_fd: None,
                leaf_name: "/".to_string(),
                leaf_name_c: CString::new("/").map_err(|_| LINUX_ENOENT)?,
            });
        }

        let (parent_id, leaf_name, path) = {
            let dirs = self.dirs.read();
            let d = match dirs.get(&dir_id) {
                Some(d) => {
                    d.accessed.store(true, Ordering::Relaxed);
                    d
                }
                None => return Err(LINUX_EAGAIN),
            };
            let (parent_id, leaf_name) = d.parent.as_ref().ok_or(LINUX_ENOENT)?;
            (*parent_id, leaf_name.clone(), d.path.clone())
        };

        let leaf_parent_fd = {
            let dirs = self.dirs.read();
            dirs.get(&parent_id)
                .and_then(|p| p.upper_dir_fd.clone().or_else(|| p.lower_dir_fd.clone()))
        };

        let node = {
            let entries = self.entries.read();
            match entries.get(&(parent_id, leaf_name.clone())) {
                Some(DentryNode::Positive(pos)) => pos.clone(),
                _ => return Err(LINUX_ENOENT),
            }
        };

        let leaf_name_c = CString::new(leaf_name.as_bytes()).map_err(|_| LINUX_ENOENT)?;
        Ok(ResolvedDentry {
            dentry: node,
            canonical_path: path,
            parent_dir_fd: leaf_parent_fd,
            leaf_name,
            leaf_name_c,
        })
    }

    fn lookup_path_slow(
        &self,
        norm_path: &str,
        follow_trailing: bool,
        backend: &dyn FsBackend,
        rootfs: Option<&RootFs>,
    ) -> Result<ResolvedDentry, LinuxErrno> {
        if norm_path == "/" {
            return self.resolve_dir_id(DentryId::ROOT, backend, rootfs);
        }

        if norm_path.starts_with("/proc")
            || norm_path.starts_with("/sys")
            || norm_path.starts_with("/dev")
        {
            return Err(LINUX_EXDEV);
        }

        let raw_components: Vec<String> = norm_path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(|s| s.to_string())
            .collect();

        let mut current_id = DentryId::ROOT;
        let mut symlinks_followed = 0;
        let mut components = raw_components;
        let mut comp_idx = 0;

        while comp_idx < components.len() {
            let name = &components[comp_idx];
            let is_last = comp_idx + 1 == components.len();

            if current_id == DentryId::ROOT && (name == "proc" || name == "sys" || name == "dev") {
                return Err(LINUX_EXDEV);
            }

            if name == "." {
                if is_last {
                    match self.resolve_dir_id(current_id, backend, rootfs) {
                        Ok(r) => return Ok(r),
                        Err(LINUX_EAGAIN) => {
                            current_id = DentryId::ROOT;
                            comp_idx = 0;
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                comp_idx += 1;
                continue;
            }
            if name == ".." {
                let parent_id = {
                    let dirs = self.dirs.read();
                    dirs.get(&current_id)
                        .and_then(|d| d.parent.as_ref().map(|p| p.0))
                        .unwrap_or(DentryId::ROOT)
                };
                current_id = parent_id;
                if is_last {
                    match self.resolve_dir_id(current_id, backend, rootfs) {
                        Ok(r) => return Ok(r),
                        Err(LINUX_EAGAIN) => {
                            current_id = DentryId::ROOT;
                            comp_idx = 0;
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                comp_idx += 1;
                continue;
            }

            let (parent_dir_gen, upper_fd, lower_fd, current_dir_path) = {
                let mut dirs = self.dirs.write();
                let current_generation = self.combined_generation();
                let parent_probe_info = if current_id != DentryId::ROOT {
                    dirs.get(&current_id).and_then(|d| {
                        if d.upper_dir_fd.is_none() && d.upper_probed_gen != current_generation {
                            let (pid, name) = d.parent.clone()?;
                            let pfd = dirs.get(&pid).and_then(|p| p.upper_dir_fd.clone());
                            Some((pfd, name))
                        } else {
                            None
                        }
                    })
                } else {
                    None
                };

                let probed_fd = if let Some((Some(ref pfd), ref leaf_name)) = parent_probe_info {
                    if let Ok(name_c) = CString::new(leaf_name.as_bytes()) {
                        let raw = unsafe {
                            libc::openat(
                                pfd.as_raw_fd(),
                                name_c.as_ptr(),
                                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                            )
                        };
                        if raw >= 0 {
                            self.host_opens.fetch_add(1, Ordering::Relaxed);
                            Some(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                match dirs.get_mut(&current_id) {
                    Some(d) => {
                        d.accessed.store(true, Ordering::Relaxed);
                        let current_gen = d.dir_gen.load(Ordering::SeqCst);
                        let path = d.path.clone();
                        if current_id == DentryId::ROOT {
                            if d.upper_dir_fd.is_none() {
                                d.upper_dir_fd = backend.dir_fd_for(Path::new(""));
                            }
                            if d.lower_dir_fd.is_none() {
                                d.lower_dir_fd = rootfs
                                    .and_then(|rf| rf.immutable_backend())
                                    .and_then(|b| b.dir_fd_for(Path::new("")));
                            }
                        } else if parent_probe_info.is_some() {
                            if let Some(fd) = probed_fd {
                                d.upper_dir_fd = Some(fd);
                                d.upper_probed_gen = u64::MAX;
                            } else {
                                d.upper_probed_gen = current_generation;
                            }
                        }
                        (
                            current_gen,
                            d.upper_dir_fd.clone(),
                            d.lower_dir_fd.clone(),
                            path,
                        )
                    }
                    None => {
                        current_id = DentryId::ROOT;
                        comp_idx = 0;
                        continue;
                    }
                }
            };

            let cached_node = {
                let entries = self.entries.read();
                entries.get(&(current_id, name.clone())).cloned()
            };

            let dentry_node = match cached_node {
                Some(DentryNode::Negative(neg)) => {
                    if neg.parent_gen == parent_dir_gen {
                        if self.is_shared {
                            let parent_fd = upper_fd.as_ref().or(lower_fd.as_ref());
                            if let Some(pfd) = parent_fd {
                                if let Ok(name_c) = CString::new(name.as_bytes()) {
                                    let mut st: libc::stat = unsafe { core::mem::zeroed() };
                                    let rc = unsafe {
                                        libc::fstatat(
                                            pfd.as_raw_fd(),
                                            name_c.as_ptr(),
                                            &mut st,
                                            libc::AT_SYMLINK_NOFOLLOW,
                                        )
                                    };
                                    if rc == 0 {
                                        let mut entries = self.entries.write();
                                        if let Some(removed) =
                                            entries.remove(&(current_id, name.clone()))
                                        {
                                            let b = entry_node_approx_bytes(name, &removed);
                                            self.sub_approx_bytes(b);
                                        }
                                        None
                                    } else {
                                        neg.accessed.store(true, Ordering::Relaxed);
                                        return Err(LINUX_ENOENT);
                                    }
                                } else {
                                    neg.accessed.store(true, Ordering::Relaxed);
                                    return Err(LINUX_ENOENT);
                                }
                            } else {
                                neg.accessed.store(true, Ordering::Relaxed);
                                return Err(LINUX_ENOENT);
                            }
                        } else {
                            neg.accessed.store(true, Ordering::Relaxed);
                            return Err(LINUX_ENOENT);
                        }
                    } else {
                        None
                    }
                }
                Some(DentryNode::Positive(pos)) => {
                    pos.accessed.store(true, Ordering::Relaxed);
                    if pos.parent_gen == parent_dir_gen {
                        if self.is_shared {
                            let parent_fd = if pos.is_lower { &lower_fd } else { &upper_fd };
                            if let Some(parent_fd) = parent_fd {
                                let name_c =
                                    CString::new(name.as_bytes()).map_err(|_| LINUX_ENOENT)?;
                                let mut st: libc::stat = unsafe { core::mem::zeroed() };
                                let ok = unsafe {
                                    libc::fstatat(
                                        parent_fd.as_raw_fd(),
                                        name_c.as_ptr(),
                                        &mut st,
                                        libc::AT_SYMLINK_NOFOLLOW,
                                    )
                                } == 0;
                                if ok && st.st_ino == pos.ino {
                                    let child_path = if current_dir_path == "/" {
                                        format!("/{}", name)
                                    } else {
                                        format!(
                                            "{}/{}",
                                            current_dir_path.trim_end_matches('/'),
                                            name
                                        )
                                    };
                                    let (mode, uid, gid) = if pos.is_lower {
                                        let rs = rootfs
                                            .and_then(|rf| rf.immutable_backend())
                                            .and_then(|b| {
                                                if !b.serves_plain_metadata() {
                                                    b.real_stat(&child_path, false)
                                                } else {
                                                    None
                                                }
                                            });
                                        if let Some(rs) = rs {
                                            (rs.mode, rs.uid, rs.gid)
                                        } else {
                                            (st.st_mode as u32 & 0o7777, NsUid::ROOT, NsGid::ROOT)
                                        }
                                    } else if !backend.serves_plain_metadata() {
                                        if let Some(rs) = backend.real_stat(&child_path, false) {
                                            (rs.mode, rs.uid, rs.gid)
                                        } else {
                                            (st.st_mode as u32 & 0o7777, NsUid::ROOT, NsGid::ROOT)
                                        }
                                    } else {
                                        (st.st_mode as u32 & 0o7777, NsUid::ROOT, NsGid::ROOT)
                                    };
                                    let record = InodeRecord {
                                        mode,
                                        uid,
                                        gid,
                                        size: st.st_size as u64,
                                        atime: (
                                            st.st_atime,
                                            carrick_portable::stat_atime_nsec(&st),
                                        ),
                                        mtime: (
                                            st.st_mtime,
                                            carrick_portable::stat_mtime_nsec(&st),
                                        ),
                                        ctime: (
                                            st.st_ctime,
                                            carrick_portable::stat_ctime_nsec(&st),
                                        ),
                                        nlink: st.st_nlink as u32,
                                        rdev: 0,
                                        dev_type: 0,
                                    };
                                    self.insert_inode_record(st.st_dev as u64, st.st_ino, record);
                                    Some(pos)
                                } else {
                                    if let Some(removed) =
                                        self.entries.write().remove(&(current_id, name.clone()))
                                    {
                                        self.sub_approx_bytes(entry_node_approx_bytes(
                                            name, &removed,
                                        ));
                                    }
                                    None
                                }
                            } else {
                                Some(pos)
                            }
                        } else {
                            Some(pos)
                        }
                    } else {
                        if let Some(removed) =
                            self.entries.write().remove(&(current_id, name.clone()))
                        {
                            self.sub_approx_bytes(entry_node_approx_bytes(name, &removed));
                        }
                        None
                    }
                }
                None => None,
            };

            let node = match dentry_node {
                Some(pos) => pos,
                None => self.fill_component(
                    current_id,
                    name,
                    parent_dir_gen,
                    upper_fd.as_ref(),
                    lower_fd.as_ref(),
                    &current_dir_path,
                    backend,
                    rootfs,
                )?,
            };

            let leaf_parent_fd = if node.is_lower {
                lower_fd.clone()
            } else {
                upper_fd.clone()
            };

            if node.kind == RootFsEntryKind::Symlink {
                if is_last && !follow_trailing {
                    let leaf_path = format!("{}/{}", current_dir_path.trim_end_matches('/'), name);
                    let leaf_name_c = CString::new(name.as_bytes()).map_err(|_| LINUX_ENOENT)?;
                    return Ok(ResolvedDentry {
                        dentry: node,
                        canonical_path: leaf_path,
                        parent_dir_fd: leaf_parent_fd,
                        leaf_name: name.clone(),
                        leaf_name_c,
                    });
                }
                symlinks_followed += 1;
                if symlinks_followed > 40 {
                    return Err(LINUX_ELOOP);
                }
                let target = node.symlink_target.as_deref().ok_or(LINUX_ENOENT)?;
                let target_components: Vec<String> = target
                    .split('/')
                    .filter(|c| !c.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                let remaining_components = &components[comp_idx + 1..];

                let mut new_components =
                    Vec::with_capacity(target_components.len() + remaining_components.len());
                new_components.extend(target_components);
                new_components.extend_from_slice(remaining_components);

                if target.starts_with('/') {
                    if target.starts_with("/proc")
                        || target.starts_with("/sys")
                        || target.starts_with("/dev")
                    {
                        return Err(LINUX_EXDEV);
                    }
                    current_id = DentryId::ROOT;
                }
                components = new_components;
                comp_idx = 0;
                continue;
            }

            if node.kind == RootFsEntryKind::Directory {
                current_id = node.id.ok_or(LINUX_ENOENT)?;
                comp_idx += 1;
                if is_last {
                    let dirs = self.dirs.read();
                    let dir = match dirs.get(&current_id) {
                        Some(d) => {
                            d.accessed.store(true, Ordering::Relaxed);
                            d
                        }
                        None => {
                            current_id = DentryId::ROOT;
                            comp_idx = 0;
                            continue;
                        }
                    };
                    let leaf_name_c = CString::new(name.as_bytes()).map_err(|_| LINUX_ENOENT)?;
                    return Ok(ResolvedDentry {
                        dentry: node,
                        canonical_path: dir.path.clone(),
                        parent_dir_fd: leaf_parent_fd,
                        leaf_name: name.clone(),
                        leaf_name_c,
                    });
                }
                continue;
            }

            // Regular file or other non-dir leaf
            if is_last {
                let leaf_path = format!("{}/{}", current_dir_path.trim_end_matches('/'), name);
                let leaf_name_c = CString::new(name.as_bytes()).map_err(|_| LINUX_ENOENT)?;
                return Ok(ResolvedDentry {
                    dentry: node,
                    canonical_path: leaf_path,
                    parent_dir_fd: leaf_parent_fd,
                    leaf_name: name.clone(),
                    leaf_name_c,
                });
            } else {
                return Err(LINUX_ENOTDIR);
            }
        }

        Err(LINUX_ENOENT)
    }

    fn insert_positive(&self, parent_id: DentryId, name: &str, pos: PositiveDentry) {
        let node = DentryNode::Positive(pos);
        let added_bytes = entry_node_approx_bytes(name, &node);
        self.add_approx_bytes(added_bytes);

        {
            let mut entries = self.entries.write();
            if !self.eviction_enabled && entries.len() >= 16384 {
                entries.clear();
            }
            entries.insert((parent_id, name.to_string()), node);
        }

        if self.approx_bytes.load(Ordering::Relaxed) > self.capacity_bytes {
            self.evict_if_needed();
        }
    }

    fn insert_negative(&self, parent_id: DentryId, name: &str, parent_gen: u64) {
        let node = DentryNode::Negative(NegativeDentry {
            parent_gen,
            accessed: Arc::new(AtomicBool::new(true)),
        });
        let added_bytes = entry_node_approx_bytes(name, &node);
        self.add_approx_bytes(added_bytes);

        {
            let mut entries = self.entries.write();
            if !self.eviction_enabled && entries.len() >= 16384 {
                entries.clear();
            }
            entries.insert((parent_id, name.to_string()), node);
        }

        if self.approx_bytes.load(Ordering::Relaxed) > self.capacity_bytes {
            self.evict_if_needed();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_dir(
        &self,
        id: DentryId,
        dir_gen: Arc<AtomicU64>,
        upper_dir_fd: Option<Arc<OwnedFd>>,
        lower_dir_fd: Option<Arc<OwnedFd>>,
        parent_id: DentryId,
        name: &str,
        path: &str,
        dev: u64,
        ino: u64,
    ) {
        if !self.eviction_enabled {
            if self.dirs.read().len() >= 4096 {
                let mut entries = self.entries.write();
                let mut inodes = self.inodes.write();
                let mut dirs = self.dirs.write();
                let mut path_map = self.path_to_dir_id.write();
                if dirs.len() >= 4096 {
                    entries.clear();
                    inodes.clear();
                    dirs.clear();
                    path_map.clear();
                    let root_dir = DirEntry {
                        id: DentryId::ROOT,
                        dir_gen: Arc::new(AtomicU64::new(1)),
                        upper_dir_fd: None,
                        lower_dir_fd: None,
                        lower_probed: false,
                        upper_probed_gen: 0,
                        parent: None,
                        path: "/".to_string(),
                        dev: 0,
                        ino: 1,
                        child_dir_count: 0,
                        accessed: Arc::new(AtomicBool::new(true)),
                        pin_count: Arc::new(AtomicUsize::new(0)),
                        lower_negatives: Arc::new(parking_lot::RwLock::new(HashSet::new())),
                    };
                    dirs.insert(DentryId::ROOT, root_dir);
                    path_map.insert("/".to_string(), DentryId::ROOT);
                    path_map.insert("".to_string(), DentryId::ROOT);
                    self.bump_mutation();
                }
            }
        }

        let lower_probed = lower_dir_fd.is_some()
            || (parent_id != DentryId::ROOT
                && self
                    .dirs
                    .read()
                    .get(&parent_id)
                    .is_some_and(|p| p.lower_probed && p.lower_dir_fd.is_none()));
        let upper_probed_gen = if upper_dir_fd.is_some() {
            u64::MAX
        } else {
            self.combined_generation()
        };
        let dir_entry = DirEntry {
            id,
            dir_gen,
            upper_dir_fd,
            lower_dir_fd,
            lower_probed,
            upper_probed_gen,
            parent: Some((parent_id, name.to_string())),
            path: path.to_string(),
            dev,
            ino,
            child_dir_count: 0,
            accessed: Arc::new(AtomicBool::new(true)),
            pin_count: Arc::new(AtomicUsize::new(0)),
            lower_negatives: Arc::new(parking_lot::RwLock::new(HashSet::new())),
        };

        let dir_bytes = dir_entry_approx_bytes(&dir_entry);
        self.add_approx_bytes(dir_bytes);

        {
            let mut dirs = self.dirs.write();
            let mut path_map = self.path_to_dir_id.write();

            if let Some(parent) = dirs.get_mut(&parent_id) {
                parent.child_dir_count += 1;
            }

            dirs.insert(id, dir_entry);
            path_map.insert(path.to_string(), id);
        }

        self.dir_eviction_queue.lock().push_back(id);
        if self.approx_bytes.load(Ordering::Relaxed) > self.capacity_bytes {
            self.evict_if_needed();
        }
    }

    fn evict_if_needed(&self) {
        if !self.eviction_enabled {
            return;
        }
        if self.approx_bytes.load(Ordering::Relaxed) <= self.capacity_bytes {
            return;
        }

        let target_bytes = (self.capacity_bytes * 7) / 8;

        let mut entries = self.entries.write();
        let mut inodes = self.inodes.write();
        let mut dirs = self.dirs.write();
        let mut path_map = self.path_to_dir_id.write();

        let mut bumped = false;

        // 1. Evict leaf directories first
        {
            let mut dir_q = self.dir_eviction_queue.lock();
            let mut attempts = 0;
            let max_attempts = dir_q.len() + 32;

            while self.approx_bytes.load(Ordering::Relaxed) > target_bytes
                && attempts < max_attempts
                && !dir_q.is_empty()
            {
                attempts += 1;
                let dir_id = match dir_q.pop_front() {
                    Some(id) => id,
                    None => break,
                };

                if dir_id == DentryId::ROOT {
                    continue;
                }

                let dir = match dirs.get(&dir_id) {
                    Some(d) => d,
                    None => continue,
                };

                // Non-leaf directories cannot be evicted
                if dir.child_dir_count > 0 {
                    dir_q.push_back(dir_id);
                    continue;
                }

                // Evict only unpinned directories (pinned by open fds)
                if dir.pin_count.load(Ordering::Relaxed) > 0 {
                    dir_q.push_back(dir_id);
                    continue;
                }

                // Second-chance clock
                if dir.accessed.swap(false, Ordering::Relaxed) {
                    dir_q.push_back(dir_id);
                    continue;
                }

                // Evict this leaf directory
                let Some(dir) = dirs.remove(&dir_id) else {
                    continue;
                };
                let dir_bytes = dir_entry_approx_bytes(&dir);
                self.sub_approx_bytes(dir_bytes);

                path_map.remove(&dir.path);
                if inodes.remove(&(dir.dev, dir.ino)).is_some() {
                    self.sub_approx_bytes(inode_approx_bytes());
                }

                // Remove all entries cached under this directory
                entries.retain(|&(p_id, ref child_name), node| {
                    if p_id == dir_id {
                        let node_bytes = entry_node_approx_bytes(child_name, node);
                        self.sub_approx_bytes(node_bytes);
                        if let DentryNode::Positive(pos) = node {
                            if inodes.remove(&(pos.dev, pos.ino)).is_some() {
                                self.sub_approx_bytes(inode_approx_bytes());
                            }
                        }
                        false
                    } else {
                        true
                    }
                });

                // Unlink from parent
                if let Some((parent_id, ref leaf_name)) = dir.parent {
                    if let Some(node) = entries.remove(&(parent_id, leaf_name.clone())) {
                        let node_bytes = entry_node_approx_bytes(leaf_name, &node);
                        self.sub_approx_bytes(node_bytes);
                    }
                    if let Some(parent) = dirs.get_mut(&parent_id) {
                        parent.child_dir_count = parent.child_dir_count.saturating_sub(1);
                    }
                }

                bumped = true;
            }
        }

        // 2. If still over capacity, evict standalone entries
        if self.approx_bytes.load(Ordering::Relaxed) > target_bytes {
            let mut to_remove = Vec::new();
            for ((p_id, child_name), node) in entries.iter() {
                if *p_id == DentryId::ROOT {
                    continue;
                }
                match node {
                    DentryNode::Positive(pos) => {
                        if pos.id.is_some() {
                            continue;
                        }
                        if pos.accessed.swap(false, Ordering::Relaxed) {
                            continue;
                        }
                        to_remove.push((*p_id, child_name.clone()));
                    }
                    DentryNode::Negative(neg) => {
                        if neg.accessed.swap(false, Ordering::Relaxed) {
                            continue;
                        }
                        to_remove.push((*p_id, child_name.clone()));
                    }
                }
                if to_remove.len() >= 256 {
                    break;
                }
            }
            for (p_id, child_name) in to_remove {
                if let Some(node) = entries.remove(&(p_id, child_name.clone())) {
                    self.sub_approx_bytes(entry_node_approx_bytes(&child_name, &node));
                    if let DentryNode::Positive(pos) = node {
                        if inodes.remove(&(pos.dev, pos.ino)).is_some() {
                            self.sub_approx_bytes(inode_approx_bytes());
                        }
                    }
                    bumped = true;
                }
            }
        }

        if bumped {
            self.bump_mutation();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn construct_positive_from_stat(
        &self,
        parent_id: DentryId,
        name: &str,
        parent_dir_gen: u64,
        parent_fd: &Arc<OwnedFd>,
        name_c: &CString,
        st: &libc::stat,
        full_path: &str,
        rel_full: &str,
        is_lower: bool,
        backend: &dyn FsBackend,
        rootfs: Option<&RootFs>,
    ) -> Result<PositiveDentry, LinuxErrno> {
        let mode_type = st.st_mode as u32 & libc::S_IFMT as u32;
        let real_stat = if is_lower {
            rootfs.and_then(|rf| rf.immutable_backend()).and_then(|b| {
                if !b.serves_plain_metadata() {
                    b.real_stat(full_path, false)
                } else {
                    None
                }
            })
        } else if !backend.serves_plain_metadata() {
            backend.real_stat(full_path, false)
        } else {
            None
        };

        if mode_type == libc::S_IFLNK as u32 {
            let mut buf = [0u8; libc::PATH_MAX as usize];
            let n = unsafe {
                libc::readlinkat(
                    parent_fd.as_raw_fd(),
                    name_c.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            };
            if n <= 0 || n as usize >= buf.len() {
                return Err(LINUX_ENOENT);
            }
            let target = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
            let (uid, gid) = if let Some(ref rs) = real_stat {
                (rs.uid, rs.gid)
            } else {
                (NsUid::ROOT, NsGid::ROOT)
            };
            let record = InodeRecord {
                mode: st.st_mode as u32 & 0o7777,
                uid,
                gid,
                size: n as u64,
                atime: (st.st_atime, carrick_portable::stat_atime_nsec(st)),
                mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(st)),
                ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(st)),
                nlink: st.st_nlink as u32,
                rdev: 0,
                dev_type: 0,
            };
            self.insert_inode_record(st.st_dev as u64, st.st_ino, record);
            let pos = PositiveDentry {
                id: None,
                kind: RootFsEntryKind::Symlink,
                ino: st.st_ino,
                dev: st.st_dev as u64,
                symlink_target: Some(target),
                parent_gen: parent_dir_gen,
                dir_gen: None,
                is_lower,
                accessed: Arc::new(AtomicBool::new(true)),
            };
            self.insert_positive(parent_id, name, pos.clone());
            return Ok(pos);
        }

        if mode_type == libc::S_IFDIR as u32 {
            let child_upper_dir_fd = if !is_lower {
                let raw = unsafe {
                    libc::openat(
                        parent_fd.as_raw_fd(),
                        name_c.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                };
                if raw >= 0 {
                    self.host_opens.fetch_add(1, Ordering::Relaxed);
                    Some(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
                } else {
                    backend.dir_fd_for(Path::new(rel_full))
                }
            } else {
                let parent_upper_fd = self
                    .dirs
                    .read()
                    .get(&parent_id)
                    .and_then(|d| d.upper_dir_fd.clone());
                match parent_upper_fd {
                    Some(pfd) => {
                        let raw = unsafe {
                            libc::openat(
                                pfd.as_raw_fd(),
                                name_c.as_ptr(),
                                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                            )
                        };
                        if raw >= 0 {
                            self.host_opens.fetch_add(1, Ordering::Relaxed);
                            Some(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
                        } else {
                            None
                        }
                    }
                    None => None,
                }
            };
            let child_lower_dir_fd = if is_lower {
                let raw = unsafe {
                    libc::openat(
                        parent_fd.as_raw_fd(),
                        name_c.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                };
                if raw >= 0 {
                    self.host_opens.fetch_add(1, Ordering::Relaxed);
                    Some(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
                } else {
                    None
                }
            } else {
                let parent_lower_fd = self
                    .dirs
                    .read()
                    .get(&parent_id)
                    .and_then(|d| d.lower_dir_fd.clone());
                match parent_lower_fd {
                    Some(pfd) => {
                        let raw = unsafe {
                            libc::openat(
                                pfd.as_raw_fd(),
                                name_c.as_ptr(),
                                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                            )
                        };
                        if raw >= 0 {
                            self.host_opens.fetch_add(1, Ordering::Relaxed);
                            Some(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
                        } else {
                            None
                        }
                    }
                    None => None,
                }
            };
            let new_dir_id = DentryId(self.next_dentry_id.fetch_add(1, Ordering::Relaxed));
            let child_dir_gen = Arc::new(AtomicU64::new(1));
            self.insert_dir(
                new_dir_id,
                child_dir_gen.clone(),
                child_upper_dir_fd,
                child_lower_dir_fd,
                parent_id,
                name,
                full_path,
                st.st_dev as u64,
                st.st_ino,
            );
            let on_disk_mode = st.st_mode as u32 & 0o7777;
            let (mode, uid, gid) = if let Some(ref rs) = real_stat {
                (rs.mode, rs.uid, rs.gid)
            } else {
                (
                    if on_disk_mode == 0 {
                        0o755
                    } else {
                        on_disk_mode
                    },
                    NsUid::ROOT,
                    NsGid::ROOT,
                )
            };
            let record = InodeRecord {
                mode,
                uid,
                gid,
                size: st.st_size as u64,
                atime: (st.st_atime, carrick_portable::stat_atime_nsec(st)),
                mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(st)),
                ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(st)),
                nlink: st.st_nlink as u32,
                rdev: 0,
                dev_type: 0,
            };
            self.insert_inode_record(st.st_dev as u64, st.st_ino, record);
            let pos = PositiveDentry {
                id: Some(new_dir_id),
                kind: RootFsEntryKind::Directory,
                ino: st.st_ino,
                dev: st.st_dev as u64,
                symlink_target: None,
                parent_gen: parent_dir_gen,
                dir_gen: Some(child_dir_gen),
                is_lower,
                accessed: Arc::new(AtomicBool::new(true)),
            };
            self.insert_positive(parent_id, name, pos.clone());
            return Ok(pos);
        }

        // File / Socket / Fifo / CharDevice
        let (kind, mode, uid, gid) = if let Some(ref rs) = real_stat {
            (rs.kind, rs.mode, rs.uid, rs.gid)
        } else {
            let is_socket = mode_type == libc::S_IFSOCK as u32;
            let is_fifo = mode_type == libc::S_IFIFO as u32;
            let is_chr = mode_type == libc::S_IFCHR as u32;
            let kind = if is_socket {
                RootFsEntryKind::Socket
            } else if is_fifo {
                RootFsEntryKind::Fifo
            } else if is_chr {
                RootFsEntryKind::CharDevice
            } else {
                RootFsEntryKind::File
            };
            let on_disk_mode = st.st_mode as u32 & 0o7777;
            let default_mode = if kind == RootFsEntryKind::Directory {
                0o755
            } else {
                0o644
            };
            let mode = if on_disk_mode == 0 {
                default_mode
            } else {
                on_disk_mode
            };
            (kind, mode, NsUid::ROOT, NsGid::ROOT)
        };
        let record = InodeRecord {
            mode,
            uid,
            gid,
            size: st.st_size as u64,
            atime: (st.st_atime, carrick_portable::stat_atime_nsec(st)),
            mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(st)),
            ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(st)),
            nlink: st.st_nlink as u32,
            rdev: 0,
            dev_type: 0,
        };
        self.insert_inode_record(st.st_dev as u64, st.st_ino, record);
        let pos = PositiveDentry {
            id: None,
            kind,
            ino: st.st_ino,
            dev: st.st_dev as u64,
            symlink_target: None,
            parent_gen: parent_dir_gen,
            dir_gen: None,
            is_lower,
            accessed: Arc::new(AtomicBool::new(true)),
        };
        self.insert_positive(parent_id, name, pos.clone());
        Ok(pos)
    }

    /// Helper to fill a missing component using the backend and rootfs.
    #[allow(clippy::too_many_arguments)]
    fn fill_component(
        &self,
        parent_id: DentryId,
        name: &str,
        parent_dir_gen: u64,
        upper_parent_fd: Option<&Arc<OwnedFd>>,
        lower_parent_fd: Option<&Arc<OwnedFd>>,
        current_dir_path: &str,
        backend: &dyn FsBackend,
        rootfs: Option<&RootFs>,
    ) -> Result<PositiveDentry, LinuxErrno> {
        let full_path = if current_dir_path == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", current_dir_path.trim_end_matches('/'), name)
        };
        let rel_full = full_path.trim_start_matches('/');

        let is_whiteout = match upper_parent_fd {
            Some(pfd) => backend.has_whiteout_in_dir(pfd.as_raw_fd(), name),
            None => false,
        };
        if is_whiteout {
            if !self.is_shared {
                self.insert_negative(parent_id, name, parent_dir_gen);
            }
            return Err(LINUX_ENOENT);
        }

        // Linux NAME_MAX: a component longer than 255 bytes is ENAMETOOLONG
        // before any lookup, and is never a negative entry (`patherrno`).
        if name.len() > 255 {
            return Err(LINUX_ENAMETOOLONG);
        }
        let name_c = CString::new(name.as_bytes()).map_err(|_| LINUX_ENOENT)?;

        // 1. Check Upper Overlay
        if let Some(parent_fd) = upper_parent_fd {
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            let rc = unsafe {
                libc::fstatat(
                    parent_fd.as_raw_fd(),
                    name_c.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            // A normalizing host (APFS) answers an NFD spelling with the NFC
            // entry; Linux says ENOENT. Ask the backend for the byte-exact
            // name before trusting the hit (`unicodenorm`).
            if rc == 0 && !backend.name_matches_on_disk(Path::new(rel_full)) {
                if !self.is_shared {
                    self.insert_negative(parent_id, name, parent_dir_gen);
                }
                return Err(LINUX_ENOENT);
            }
            if rc == 0 {
                return self.construct_positive_from_stat(
                    parent_id,
                    name,
                    parent_dir_gen,
                    parent_fd,
                    &name_c,
                    &st,
                    &full_path,
                    rel_full,
                    /* is_lower = */ false,
                    backend,
                    rootfs,
                );
            }
        } else if let Some(rs) = backend.real_stat(&full_path, false) {
            let symlink_target = if rs.kind == RootFsEntryKind::Symlink {
                backend.read_link(&full_path)
            } else {
                None
            };
            let (dir_id, child_dir_gen) = if rs.kind == RootFsEntryKind::Directory {
                let new_dir_id = DentryId(self.next_dentry_id.fetch_add(1, Ordering::Relaxed));
                let child_dir_gen = Arc::new(AtomicU64::new(1));
                let (parent_upper_fd, parent_lower_fd) = {
                    let dirs = self.dirs.read();
                    let d = dirs.get(&parent_id);
                    (
                        d.and_then(|d| d.upper_dir_fd.clone()),
                        d.and_then(|d| d.lower_dir_fd.clone()),
                    )
                };
                let child_upper_dir_fd = match parent_upper_fd {
                    Some(pfd) => {
                        let raw = unsafe {
                            libc::openat(
                                pfd.as_raw_fd(),
                                name_c.as_ptr(),
                                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                            )
                        };
                        if raw >= 0 {
                            self.host_opens.fetch_add(1, Ordering::Relaxed);
                            Some(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
                        } else {
                            None
                        }
                    }
                    None => None,
                };
                let child_lower_dir_fd = match parent_lower_fd {
                    Some(pfd) => {
                        let raw = unsafe {
                            libc::openat(
                                pfd.as_raw_fd(),
                                name_c.as_ptr(),
                                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                            )
                        };
                        if raw >= 0 {
                            self.host_opens.fetch_add(1, Ordering::Relaxed);
                            Some(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
                        } else {
                            None
                        }
                    }
                    None => None,
                };
                self.insert_dir(
                    new_dir_id,
                    child_dir_gen.clone(),
                    child_upper_dir_fd,
                    child_lower_dir_fd,
                    parent_id,
                    name,
                    &full_path,
                    0,
                    rs.ino,
                );
                (Some(new_dir_id), Some(child_dir_gen))
            } else {
                (None, None)
            };
            let record = InodeRecord {
                mode: rs.mode,
                uid: rs.uid,
                gid: rs.gid,
                size: rs.size,
                atime: rs.atime,
                mtime: rs.mtime,
                ctime: rs.ctime,
                nlink: rs.nlink,
                rdev: 0,
                dev_type: 0,
            };
            self.insert_inode_record(0, rs.ino, record);
            let pos = PositiveDentry {
                id: dir_id,
                kind: rs.kind,
                ino: rs.ino,
                dev: 0,
                symlink_target,
                parent_gen: parent_dir_gen,
                dir_gen: child_dir_gen,
                is_lower: false,
                accessed: Arc::new(AtomicBool::new(true)),
            };
            self.insert_positive(parent_id, name, pos.clone());
            return Ok(pos);
        } else if let Some(md) = backend.fast_nofollow_metadata(&full_path) {
            let symlink_target = if md.kind == RootFsEntryKind::Symlink {
                backend.read_link(&full_path)
            } else {
                None
            };
            let (uid, gid) = backend
                .get_owner(&full_path)
                .unwrap_or((NsUid::ROOT, NsGid::ROOT));
            let (dir_id, child_dir_gen) = if md.kind == RootFsEntryKind::Directory {
                let new_dir_id = DentryId(self.next_dentry_id.fetch_add(1, Ordering::Relaxed));
                let child_dir_gen = Arc::new(AtomicU64::new(1));
                let (parent_upper_fd, parent_lower_fd) = {
                    let dirs = self.dirs.read();
                    let d = dirs.get(&parent_id);
                    (
                        d.and_then(|d| d.upper_dir_fd.clone()),
                        d.and_then(|d| d.lower_dir_fd.clone()),
                    )
                };
                let child_upper_dir_fd = match parent_upper_fd {
                    Some(pfd) => {
                        let raw = unsafe {
                            libc::openat(
                                pfd.as_raw_fd(),
                                name_c.as_ptr(),
                                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                            )
                        };
                        if raw >= 0 {
                            self.host_opens.fetch_add(1, Ordering::Relaxed);
                            Some(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
                        } else {
                            None
                        }
                    }
                    None => None,
                };
                let child_lower_dir_fd = match parent_lower_fd {
                    Some(pfd) => {
                        let raw = unsafe {
                            libc::openat(
                                pfd.as_raw_fd(),
                                name_c.as_ptr(),
                                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                            )
                        };
                        if raw >= 0 {
                            self.host_opens.fetch_add(1, Ordering::Relaxed);
                            Some(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
                        } else {
                            None
                        }
                    }
                    None => None,
                };
                self.insert_dir(
                    new_dir_id,
                    child_dir_gen.clone(),
                    child_upper_dir_fd,
                    child_lower_dir_fd,
                    parent_id,
                    name,
                    &full_path,
                    0,
                    1,
                );
                (Some(new_dir_id), Some(child_dir_gen))
            } else {
                (None, None)
            };
            let ino = 1;
            let record = InodeRecord {
                mode: md.mode,
                uid,
                gid,
                size: md.size as u64,
                atime: (0, 0),
                mtime: (0, 0),
                ctime: (0, 0),
                nlink: if md.kind == RootFsEntryKind::Directory {
                    2
                } else {
                    1
                },
                rdev: 0,
                dev_type: 0,
            };
            self.insert_inode_record(0, ino, record);
            let pos = PositiveDentry {
                id: dir_id,
                kind: md.kind,
                ino,
                dev: 0,
                symlink_target,
                parent_gen: parent_dir_gen,
                dir_gen: child_dir_gen,
                is_lower: false,
                accessed: Arc::new(AtomicBool::new(true)),
            };
            self.insert_positive(parent_id, name, pos.clone());
            return Ok(pos);
        }

        // 2. Check Lower RootFs (if available)
        if let Some(rf) = rootfs {
            let lower_neg = {
                let dirs = self.dirs.read();
                dirs.get(&parent_id)
                    .is_some_and(|d| d.lower_negatives.read().contains(name))
            };
            if lower_neg {
                if !self.is_shared {
                    self.insert_negative(parent_id, name, parent_dir_gen);
                }
                return Err(LINUX_ENOENT);
            }

            if let Some(lower_fd) = lower_parent_fd {
                let mut st: libc::stat = unsafe { core::mem::zeroed() };
                let rc = unsafe {
                    libc::fstatat(
                        lower_fd.as_raw_fd(),
                        name_c.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if rc == 0 {
                    return self.construct_positive_from_stat(
                        parent_id,
                        name,
                        parent_dir_gen,
                        lower_fd,
                        &name_c,
                        &st,
                        &full_path,
                        rel_full,
                        /* is_lower = */ true,
                        backend,
                        rootfs,
                    );
                } else {
                    let dirs = self.dirs.read();
                    if let Some(d) = dirs.get(&parent_id) {
                        d.lower_negatives.write().insert(name.to_string());
                    }
                }
            } else if let Ok(md) = rf.symlink_metadata(&full_path) {
                // Fallback for when lower_parent_fd is not available (e.g. in-memory rootfs)
                let (mode, uid, gid, dev, ino, nlink, atime, mtime, ctime) = if let Some(rs) =
                    rf.immutable_real_stat(&full_path, false)
                {
                    (
                        rs.mode, rs.uid, rs.gid, 0, rs.ino, rs.nlink, rs.atime, rs.mtime, rs.ctime,
                    )
                } else {
                    (
                        md.mode,
                        NsUid::ROOT,
                        NsGid::ROOT,
                        0,
                        1,
                        1,
                        (0, 0),
                        (0, 0),
                        (0, 0),
                    )
                };
                let symlink_target = if md.kind == RootFsEntryKind::Symlink {
                    rf.read_link(&full_path).ok()
                } else {
                    None
                };
                let (dir_id, child_dir_gen) = if md.kind == RootFsEntryKind::Directory {
                    let new_dir_id = DentryId(self.next_dentry_id.fetch_add(1, Ordering::Relaxed));
                    let child_dir_gen = Arc::new(AtomicU64::new(1));
                    let (parent_upper_fd, parent_lower_fd) = {
                        let dirs = self.dirs.read();
                        let d = dirs.get(&parent_id);
                        (
                            d.and_then(|d| d.upper_dir_fd.clone()),
                            d.and_then(|d| d.lower_dir_fd.clone()),
                        )
                    };
                    let child_upper_dir_fd = match parent_upper_fd {
                        Some(pfd) => {
                            let raw = unsafe {
                                libc::openat(
                                    pfd.as_raw_fd(),
                                    name_c.as_ptr(),
                                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                                )
                            };
                            if raw >= 0 {
                                self.host_opens.fetch_add(1, Ordering::Relaxed);
                                Some(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
                            } else {
                                None
                            }
                        }
                        None => None,
                    };
                    let child_lower_dir_fd = match parent_lower_fd {
                        Some(pfd) => {
                            let raw = unsafe {
                                libc::openat(
                                    pfd.as_raw_fd(),
                                    name_c.as_ptr(),
                                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                                )
                            };
                            if raw >= 0 {
                                self.host_opens.fetch_add(1, Ordering::Relaxed);
                                Some(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
                            } else {
                                None
                            }
                        }
                        None => None,
                    };
                    self.insert_dir(
                        new_dir_id,
                        child_dir_gen.clone(),
                        child_upper_dir_fd,
                        child_lower_dir_fd,
                        parent_id,
                        name,
                        &full_path,
                        dev,
                        ino,
                    );
                    (Some(new_dir_id), Some(child_dir_gen))
                } else {
                    (None, None)
                };
                let record = InodeRecord {
                    mode,
                    uid,
                    gid,
                    size: md.size as u64,
                    atime,
                    mtime,
                    ctime,
                    nlink,
                    rdev: 0,
                    dev_type: 0,
                };
                self.insert_inode_record(dev, ino, record);
                let pos = PositiveDentry {
                    id: dir_id,
                    kind: md.kind,
                    ino,
                    dev,
                    symlink_target,
                    parent_gen: parent_dir_gen,
                    dir_gen: child_dir_gen,
                    is_lower: true,
                    accessed: Arc::new(AtomicBool::new(true)),
                };
                self.insert_positive(parent_id, name, pos.clone());
                return Ok(pos);
            }
        }

        // 3. Absent in both Upper and Lower
        if rootfs.is_some() {
            let dirs = self.dirs.read();
            if let Some(d) = dirs.get(&parent_id) {
                d.lower_negatives.write().insert(name.to_string());
            }
        }
        if !self.is_shared {
            self.insert_negative(parent_id, name, parent_dir_gen);
        }
        Err(LINUX_ENOENT)
    }

    /// Read stat for `path` via the dentry cache.
    pub fn stat(
        &self,
        path: &str,
        follow: bool,
        backend: &dyn FsBackend,
        rootfs: Option<&RootFs>,
    ) -> Result<RealStat, LinuxErrno> {
        self.check_fork();

        let requires_dir = path.ends_with('/') || path.ends_with("/.");
        let effective_follow = follow || requires_dir;
        let mut norm_path = path.trim_end_matches('/');
        while norm_path.ends_with("/.") {
            norm_path = &norm_path[..norm_path.len() - 2];
        }
        let norm_path = if norm_path.is_empty() { "/" } else { norm_path };

        if !self.is_shared {
            let fp = self.fast_path.read();
            let map = if effective_follow {
                &fp.stat_follow
            } else {
                &fp.stat_nofollow
            };
            if let Some(res) = map.get(norm_path) {
                let stat_res = *res;
                if requires_dir
                    && let Ok(st) = stat_res
                    && st.kind != RootFsEntryKind::Directory
                {
                    return Err(LINUX_ENOTDIR);
                }
                return stat_res;
            }
        }

        let resolved = match self.lookup_path(path, effective_follow, backend, rootfs) {
            Ok(r) => r,
            Err(e) => {
                if !self.is_shared && matches!(e, LINUX_ENOENT) {
                    let mut fp = self.fast_path.write();
                    let map = if effective_follow {
                        &mut fp.stat_follow
                    } else {
                        &mut fp.stat_nofollow
                    };
                    if map.len() < FAST_PATH_CAP {
                        map.insert(norm_path.to_string(), Err(LINUX_ENOENT));
                    }
                }
                return Err(e);
            }
        };
        if requires_dir && resolved.dentry.kind != RootFsEntryKind::Directory {
            return Err(LINUX_ENOTDIR);
        }
        let record = self.get_or_refresh_inode(&resolved, backend, rootfs)?;
        let st = resolved.dentry.to_real_stat(&record);
        if !self.is_shared {
            let mut fp = self.fast_path.write();
            let map = if effective_follow {
                &mut fp.stat_follow
            } else {
                &mut fp.stat_nofollow
            };
            if map.len() < FAST_PATH_CAP {
                map.insert(norm_path.to_string(), Ok(st));
            }
        }
        Ok(st)
    }

    /// Readlink for `path` via the dentry cache.
    pub fn readlink(
        &self,
        path: &str,
        backend: &dyn FsBackend,
        rootfs: Option<&RootFs>,
    ) -> Result<String, LinuxErrno> {
        let resolved = self.lookup_path(path, false, backend, rootfs)?;
        resolved.dentry.symlink_target.ok_or(LINUX_EINVAL)
    }

    /// Fast non-creating open for a regular file.
    pub fn fast_open(
        &self,
        path: &str,
        write: bool,
        backend: &dyn FsBackend,
        rootfs: Option<&RootFs>,
    ) -> Result<
        (
            std::os::fd::OwnedFd,
            RealStat,
            String,
            carrick_guest_mem::PrivateFileSource,
        ),
        LinuxErrno,
    > {
        let resolved = self.lookup_path(path, true, backend, rootfs)?;
        if resolved.dentry.kind == RootFsEntryKind::Directory {
            return Err(LINUX_EISDIR);
        }
        if resolved.dentry.kind != RootFsEntryKind::File {
            return Err(LINUX_ENOSYS);
        }
        // Lower files must not be directly opened for writing without copy-up.
        if write && resolved.dentry.is_lower {
            return Err(LINUX_EXDEV);
        }
        let parent_fd = resolved.parent_dir_fd.as_ref().ok_or(LINUX_ENOENT)?;
        let accmode = if write { libc::O_RDWR } else { libc::O_RDONLY };
        let base = libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NOCTTY;
        let raw = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                resolved.leaf_name_c.as_ptr(),
                accmode | base,
                0,
            )
        };
        if raw < 0 {
            let err = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ENOENT);
            return Err(crate::host_to_linux_errno(err));
        }
        self.host_opens.fetch_add(1, Ordering::Relaxed);
        let record = self.get_or_refresh_inode(&resolved, backend, rootfs)?;
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        Ok((
            fd,
            resolved.dentry.to_real_stat(&record),
            resolved.canonical_path,
            if resolved.dentry.is_lower {
                carrick_guest_mem::PrivateFileSource::ImmutableLower
            } else {
                carrick_guest_mem::PrivateFileSource::Mutable
            },
        ))
    }

    /// Open a metadata file descriptor for `path`, resolving through the dentry cache
    /// across both upper and lower layers.
    pub fn open_metadata_fd(
        &self,
        path: &str,
        follow: bool,
        backend: &dyn FsBackend,
        rootfs: Option<&RootFs>,
    ) -> Result<Arc<OwnedFd>, LinuxErrno> {
        self.check_fork();
        let resolved = self.lookup_path(path, follow, backend, rootfs)?;
        if resolved.dentry.id == Some(DentryId::ROOT) {
            let fd = {
                let mut dirs = self.dirs.write();
                let d = dirs.get_mut(&DentryId::ROOT).ok_or(LINUX_ENOENT)?;
                if d.upper_dir_fd.is_none() {
                    d.upper_dir_fd = backend.dir_fd_for(Path::new(""));
                }
                if d.lower_dir_fd.is_none() {
                    d.lower_dir_fd = rootfs
                        .and_then(|rf| rf.immutable_backend())
                        .and_then(|b| b.dir_fd_for(Path::new("")));
                }
                d.upper_dir_fd.as_ref().or(d.lower_dir_fd.as_ref()).cloned()
            }
            .ok_or(LINUX_ENOENT)?;
            let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if raw < 0 {
                return Err(crate::host_to_linux_errno(
                    std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EIO),
                ));
            }
            return Ok(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }));
        }

        let parent_fd = resolved.parent_dir_fd.ok_or(LINUX_ENOENT)?;
        #[cfg(target_os = "macos")]
        let nofollow = if follow { 0 } else { libc::O_SYMLINK };
        #[cfg(not(target_os = "macos"))]
        let nofollow = if follow { 0 } else { libc::O_NOFOLLOW };
        let raw = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                resolved.leaf_name_c.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | nofollow,
            )
        };
        if raw < 0 {
            return Err(crate::host_to_linux_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            ));
        }
        Ok(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
    }

    /// Get cached inode record for `(dev, ino)`.
    pub fn get_inode_record(&self, dev: u64, ino: u64) -> Option<InodeRecord> {
        self.check_fork();
        self.inodes.read().get(&(dev, ino)).copied()
    }

    /// Insert or update inode record for `(dev, ino)`.
    pub fn insert_inode_record(&self, dev: u64, ino: u64, record: InodeRecord) {
        self.check_fork();
        self.inodes.write().insert((dev, ino), record);
    }

    /// Get cached inode record or refresh it from disk/backend.
    pub fn get_or_refresh_inode(
        &self,
        resolved: &ResolvedDentry,
        backend: &dyn FsBackend,
        rootfs: Option<&RootFs>,
    ) -> Result<InodeRecord, LinuxErrno> {
        let key = (resolved.dentry.dev, resolved.dentry.ino);
        if let Some(record) = self.inodes.read().get(&key).copied() {
            return Ok(record);
        }
        self.refresh_inode(resolved, backend, rootfs)
    }

    fn refresh_inode(
        &self,
        resolved: &ResolvedDentry,
        backend: &dyn FsBackend,
        rootfs: Option<&RootFs>,
    ) -> Result<InodeRecord, LinuxErrno> {
        let key = (resolved.dentry.dev, resolved.dentry.ino);

        // 1. Try fstatat via parent_dir_fd if available
        if let Some(parent_fd) = &resolved.parent_dir_fd {
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            let rc = unsafe {
                libc::fstatat(
                    parent_fd.as_raw_fd(),
                    resolved.leaf_name_c.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc == 0 {
                let (mode, uid, gid) = if resolved.dentry.is_lower {
                    let rs = rootfs.and_then(|rf| rf.immutable_backend()).and_then(|b| {
                        if !b.serves_plain_metadata() {
                            b.real_stat(&resolved.canonical_path, false)
                        } else {
                            None
                        }
                    });
                    if let Some(rs) = rs {
                        (rs.mode, rs.uid, rs.gid)
                    } else {
                        (st.st_mode as u32 & 0o7777, NsUid::ROOT, NsGid::ROOT)
                    }
                } else if !backend.serves_plain_metadata() {
                    if let Some(rs) = backend.real_stat(&resolved.canonical_path, false) {
                        (rs.mode, rs.uid, rs.gid)
                    } else {
                        (st.st_mode as u32 & 0o7777, NsUid::ROOT, NsGid::ROOT)
                    }
                } else {
                    (st.st_mode as u32 & 0o7777, NsUid::ROOT, NsGid::ROOT)
                };
                let record = InodeRecord {
                    mode,
                    uid,
                    gid,
                    size: st.st_size as u64,
                    atime: (st.st_atime, carrick_portable::stat_atime_nsec(&st)),
                    mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(&st)),
                    ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(&st)),
                    nlink: st.st_nlink as u32,
                    rdev: 0,
                    dev_type: 0,
                };
                self.inodes.write().insert(key, record);
                return Ok(record);
            }
        }

        // 2. Try backend real_stat
        let rs = if resolved.dentry.is_lower {
            rootfs.and_then(|rf| rf.immutable_backend()).and_then(|b| {
                if !b.serves_plain_metadata() {
                    b.real_stat(&resolved.canonical_path, false)
                } else {
                    None
                }
            })
        } else if !backend.serves_plain_metadata() {
            backend.real_stat(&resolved.canonical_path, false)
        } else {
            None
        };
        if let Some(rs) = rs {
            let record = InodeRecord {
                mode: rs.mode,
                uid: rs.uid,
                gid: rs.gid,
                size: rs.size,
                atime: rs.atime,
                mtime: rs.mtime,
                ctime: rs.ctime,
                nlink: rs.nlink,
                rdev: 0,
                dev_type: 0,
            };
            self.inodes.write().insert(key, record);
            return Ok(record);
        }

        // 3. Try rootfs
        if let Some(rf) = rootfs {
            if let Some(rs) = rf.immutable_real_stat(&resolved.canonical_path, false) {
                let record = InodeRecord {
                    mode: rs.mode,
                    uid: rs.uid,
                    gid: rs.gid,
                    size: rs.size,
                    atime: rs.atime,
                    mtime: rs.mtime,
                    ctime: rs.ctime,
                    nlink: rs.nlink,
                    rdev: 0,
                    dev_type: 0,
                };
                self.inodes.write().insert(key, record);
                return Ok(record);
            }
        }

        Err(LINUX_ENOENT)
    }

    fn split_parent_and_name(path: &str) -> Option<(&str, &str)> {
        let norm = path.trim_end_matches('/');
        if norm.is_empty() {
            return None;
        }
        let idx = norm.rfind('/')?;
        let parent = if idx == 0 { "/" } else { &norm[..idx] };
        let name = &norm[idx + 1..];
        if name.is_empty() {
            None
        } else {
            Some((parent, name))
        }
    }

    fn find_parent_dir_id(&self, parent_path: &str) -> Option<DentryId> {
        let map = self.path_to_dir_id.read();
        map.get(parent_path)
            .or_else(|| map.get(parent_path.trim_end_matches('/')))
            .copied()
    }

    /// Notify that an entry was created at `path`.
    pub fn entry_created(&self, path: &str, inode: Option<InodeIdentity>) {
        self.bump_mutation();
        let norm = path.trim_end_matches('/');
        let norm = if norm.is_empty() { "/" } else { norm };
        if let Some((parent_path, name)) = Self::split_parent_and_name(norm)
            && let Some(parent_id) = self.find_parent_dir_id(parent_path)
        {
            let mut entries = self.entries.write();
            if let Some(node) = entries.remove(&(parent_id, name.to_string())) {
                self.sub_approx_bytes(entry_node_approx_bytes(name, &node));
            }
            let dirs = self.dirs.read();
            if let Some(d) = dirs.get(&parent_id) {
                if self.inodes.write().remove(&(d.dev, d.ino)).is_some() {
                    self.sub_approx_bytes(inode_approx_bytes());
                }
            }
        }
        if let Some(dir_id) = self.path_to_dir_id.read().get(norm) {
            let dirs = self.dirs.read();
            if let Some(d) = dirs.get(dir_id) {
                d.dir_gen.fetch_add(1, Ordering::SeqCst);
            }
        }
        if let Some(id) = inode {
            if self.inodes.write().remove(&(id.dev, id.ino)).is_some() {
                self.sub_approx_bytes(inode_approx_bytes());
            }
        }
    }

    /// Notify that an entry at `path` was removed (unlinked or rmdir'd).
    pub fn entry_removed(&self, path: &str, inode: Option<InodeIdentity>) {
        self.bump_mutation();
        let norm = path.trim_end_matches('/');
        let norm = if norm.is_empty() { "/" } else { norm };
        let removed_dir = {
            let mut dirs = self.dirs.write();
            let mut path_map = self.path_to_dir_id.write();
            if let Some(dir_id) = path_map.remove(norm) {
                dirs.remove(&dir_id)
            } else {
                None
            }
        };
        if let Some(ref d) = removed_dir {
            self.sub_approx_bytes(dir_entry_approx_bytes(d));
            d.dir_gen.fetch_add(1, Ordering::SeqCst);
            if let Some((parent_id, _)) = d.parent {
                let mut dirs = self.dirs.write();
                if let Some(parent) = dirs.get_mut(&parent_id) {
                    parent.child_dir_count = parent.child_dir_count.saturating_sub(1);
                }
            }
        }
        if let Some((parent_path, name)) = Self::split_parent_and_name(norm)
            && let Some(parent_id) = self.find_parent_dir_id(parent_path)
        {
            let mut entries = self.entries.write();
            if let Some(node) = entries.remove(&(parent_id, name.to_string())) {
                self.sub_approx_bytes(entry_node_approx_bytes(name, &node));
                if let DentryNode::Positive(pos) = node {
                    if self.inodes.write().remove(&(pos.dev, pos.ino)).is_some() {
                        self.sub_approx_bytes(inode_approx_bytes());
                    }
                }
            }
            drop(entries);

            let parent_gen = {
                let dirs = self.dirs.read();
                if let Some(d) = dirs.get(&parent_id) {
                    if self.inodes.write().remove(&(d.dev, d.ino)).is_some() {
                        self.sub_approx_bytes(inode_approx_bytes());
                    }
                    Some(d.dir_gen.load(Ordering::SeqCst))
                } else {
                    None
                }
            };
            if let Some(generation) = parent_gen {
                if !self.is_shared {
                    self.insert_negative(parent_id, name, generation);
                }
            }
        }
        if let Some(id) = inode {
            if self.inodes.write().remove(&(id.dev, id.ino)).is_some() {
                self.sub_approx_bytes(inode_approx_bytes());
            }
        }
    }

    /// Notify that an entry was moved from `old_path` to `new_path`.
    pub fn entry_moved(&self, old_path: &str, new_path: &str, inode: Option<InodeIdentity>) {
        self.bump_mutation();
        let norm_old = old_path.trim_end_matches('/');
        let norm_new = new_path.trim_end_matches('/');

        // 1. If old path was a cached directory, bump its generation and update path map
        let renamed_dir_id = {
            let mut path_map = self.path_to_dir_id.write();
            let id = path_map.remove(norm_old);
            if let Some(id) = id {
                path_map.insert(norm_new.to_string(), id);
            }
            id
        };
        if let Some(dir_id) = renamed_dir_id {
            let mut dirs = self.dirs.write();
            if let Some(d) = dirs.get_mut(&dir_id) {
                d.dir_gen.fetch_add(1, Ordering::SeqCst);
                d.path = norm_new.to_string();
            }
        }

        // 2. Old location becomes Negative
        if let Some((old_parent_path, old_name)) = Self::split_parent_and_name(norm_old)
            && let Some(old_parent_id) = self.find_parent_dir_id(old_parent_path)
        {
            let mut entries = self.entries.write();
            if let Some(node) = entries.remove(&(old_parent_id, old_name.to_string())) {
                self.sub_approx_bytes(entry_node_approx_bytes(old_name, &node));
            }
            drop(entries);

            let old_parent_gen = {
                let dirs = self.dirs.read();
                if let Some(d) = dirs.get(&old_parent_id) {
                    if self.inodes.write().remove(&(d.dev, d.ino)).is_some() {
                        self.sub_approx_bytes(inode_approx_bytes());
                    }
                    Some(d.dir_gen.load(Ordering::SeqCst))
                } else {
                    None
                }
            };
            if let Some(generation) = old_parent_gen {
                if !self.is_shared {
                    self.insert_negative(old_parent_id, old_name, generation);
                }
            }
        }

        // 3. Invalidate new location so it fills fresh
        if let Some((new_parent_path, new_name)) = Self::split_parent_and_name(norm_new)
            && let Some(new_parent_id) = self.find_parent_dir_id(new_parent_path)
        {
            let mut entries = self.entries.write();
            if let Some(node) = entries.remove(&(new_parent_id, new_name.to_string())) {
                self.sub_approx_bytes(entry_node_approx_bytes(new_name, &node));
                if let DentryNode::Positive(pos) = node {
                    if self.inodes.write().remove(&(pos.dev, pos.ino)).is_some() {
                        self.sub_approx_bytes(inode_approx_bytes());
                    }
                }
            }
            let dirs = self.dirs.read();
            if let Some(d) = dirs.get(&new_parent_id) {
                if self.inodes.write().remove(&(d.dev, d.ino)).is_some() {
                    self.sub_approx_bytes(inode_approx_bytes());
                }
            }
        }
        if let Some(id) = inode {
            if self.inodes.write().remove(&(id.dev, id.ino)).is_some() {
                self.sub_approx_bytes(inode_approx_bytes());
            }
        }
    }

    /// Notify that entries at `a` and `b` were exchanged (e.g. renameat2 RENAME_EXCHANGE).
    pub fn entry_exchanged(
        &self,
        a: &str,
        b: &str,
        inode_a: Option<InodeIdentity>,
        inode_b: Option<InodeIdentity>,
    ) {
        self.bump_mutation();
        let norm_a = a.trim_end_matches('/');
        let norm_b = b.trim_end_matches('/');

        // Invalidate directory path cache for both if present
        {
            let mut path_map = self.path_to_dir_id.write();
            let mut dirs = self.dirs.write();
            if let Some(id_a) = path_map.remove(norm_a) {
                if let Some(d) = dirs.remove(&id_a) {
                    self.sub_approx_bytes(dir_entry_approx_bytes(&d));
                }
            }
            if let Some(id_b) = path_map.remove(norm_b) {
                if let Some(d) = dirs.remove(&id_b) {
                    self.sub_approx_bytes(dir_entry_approx_bytes(&d));
                }
            }
        }

        // Invalidate entry a in its parent
        if let Some((parent_path_a, name_a)) = Self::split_parent_and_name(norm_a)
            && let Some(parent_id_a) = self.find_parent_dir_id(parent_path_a)
        {
            let mut entries = self.entries.write();
            if let Some(node) = entries.remove(&(parent_id_a, name_a.to_string())) {
                self.sub_approx_bytes(entry_node_approx_bytes(name_a, &node));
                if let DentryNode::Positive(pos) = node {
                    if self.inodes.write().remove(&(pos.dev, pos.ino)).is_some() {
                        self.sub_approx_bytes(inode_approx_bytes());
                    }
                }
            }
            let dirs = self.dirs.read();
            if let Some(d) = dirs.get(&parent_id_a) {
                d.dir_gen.fetch_add(1, Ordering::SeqCst);
                if self.inodes.write().remove(&(d.dev, d.ino)).is_some() {
                    self.sub_approx_bytes(inode_approx_bytes());
                }
            }
        }

        // Invalidate entry b in its parent
        if let Some((parent_path_b, name_b)) = Self::split_parent_and_name(norm_b)
            && let Some(parent_id_b) = self.find_parent_dir_id(parent_path_b)
        {
            let mut entries = self.entries.write();
            if let Some(node) = entries.remove(&(parent_id_b, name_b.to_string())) {
                self.sub_approx_bytes(entry_node_approx_bytes(name_b, &node));
                if let DentryNode::Positive(pos) = node {
                    if self.inodes.write().remove(&(pos.dev, pos.ino)).is_some() {
                        self.sub_approx_bytes(inode_approx_bytes());
                    }
                }
            }
            let dirs = self.dirs.read();
            if let Some(d) = dirs.get(&parent_id_b) {
                d.dir_gen.fetch_add(1, Ordering::SeqCst);
                if self.inodes.write().remove(&(d.dev, d.ino)).is_some() {
                    self.sub_approx_bytes(inode_approx_bytes());
                }
            }
        }

        if let Some(id) = inode_a {
            if self.inodes.write().remove(&(id.dev, id.ino)).is_some() {
                self.sub_approx_bytes(inode_approx_bytes());
            }
        }
        if let Some(id) = inode_b {
            if self.inodes.write().remove(&(id.dev, id.ino)).is_some() {
                self.sub_approx_bytes(inode_approx_bytes());
            }
        }
    }

    /// Invalidate cached inode or path metadata when file attributes/contents changed.
    pub fn inode_changed(&self, path: &str, inode: Option<InodeIdentity>) {
        self.bump_mutation();
        let norm = path.trim_end_matches('/');
        let norm = if norm.is_empty() { "/" } else { norm };
        if let Some((parent_path, name)) = Self::split_parent_and_name(norm)
            && let Some(parent_id) = self.find_parent_dir_id(parent_path)
        {
            let mut entries = self.entries.write();
            if let Some(node) = entries.remove(&(parent_id, name.to_string())) {
                self.sub_approx_bytes(entry_node_approx_bytes(name, &node));
                if let DentryNode::Positive(pos) = node {
                    if self.inodes.write().remove(&(pos.dev, pos.ino)).is_some() {
                        self.sub_approx_bytes(inode_approx_bytes());
                    }
                }
            }
        }
        if let Some(id) = inode {
            if self.inodes.write().remove(&(id.dev, id.ino)).is_some() {
                self.sub_approx_bytes(inode_approx_bytes());
            }
        }
    }

    /// Invalidate cached inode record for `id`.
    pub fn invalidate_inode(&self, id: InodeIdentity) {
        self.bump_mutation();
        if self.inodes.write().remove(&(id.dev, id.ino)).is_some() {
            self.sub_approx_bytes(inode_approx_bytes());
        }
    }

    /// Bump the generation of a directory, invalidating negative lookups within it.
    pub fn bump_dir_generation(&self, path: &str) {
        self.bump_mutation();
        let norm = path.trim_end_matches('/');
        let norm = if norm.is_empty() { "/" } else { norm };
        if let Some(dir_id) = self.path_to_dir_id.read().get(norm) {
            let dirs = self.dirs.read();
            if let Some(d) = dirs.get(dir_id) {
                d.dir_gen.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// Pin a cached directory by path to prevent eviction while an open fd exists on it.
    pub fn pin_dir(&self, path: &str) {
        let norm = path.trim_end_matches('/');
        let norm = if norm.is_empty() { "/" } else { norm };
        let dir_id = self.path_to_dir_id.read().get(norm).copied();
        if let Some(dir_id) = dir_id {
            self.pin_dir_id(dir_id);
        }
    }

    /// Unpin a cached directory by path when an open fd on it is closed.
    pub fn unpin_dir(&self, path: &str) {
        let norm = path.trim_end_matches('/');
        let norm = if norm.is_empty() { "/" } else { norm };
        let dir_id = self.path_to_dir_id.read().get(norm).copied();
        if let Some(dir_id) = dir_id {
            self.unpin_dir_id(dir_id);
        }
    }

    /// Pin a cached directory by DentryId.
    pub fn pin_dir_id(&self, dir_id: DentryId) {
        let dirs = self.dirs.read();
        if let Some(dir) = dirs.get(&dir_id) {
            dir.pin_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Unpin a cached directory by DentryId.
    pub fn unpin_dir_id(&self, dir_id: DentryId) {
        let dirs = self.dirs.read();
        if let Some(dir) = dirs.get(&dir_id) {
            dir.pin_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Check whether a directory is currently pinned.
    pub fn is_dir_pinned(&self, dir_id: DentryId) -> bool {
        let dirs = self.dirs.read();
        dirs.get(&dir_id)
            .is_some_and(|d| d.pin_count.load(Ordering::Relaxed) > 0)
    }

    /// Check whether a directory is currently cached.
    pub fn has_dir(&self, path: &str) -> bool {
        let norm = path.trim_end_matches('/');
        let norm = if norm.is_empty() { "/" } else { norm };
        self.path_to_dir_id.read().contains_key(norm)
    }

    /// Check whether an entry is currently cached under a directory.
    pub fn has_entry(&self, dir_path: &str, child_name: &str) -> bool {
        let norm = dir_path.trim_end_matches('/');
        let norm = if norm.is_empty() { "/" } else { norm };
        let dir_id = match self.path_to_dir_id.read().get(norm).copied() {
            Some(id) => id,
            None => return false,
        };
        self.entries
            .read()
            .contains_key(&(dir_id, child_name.to_string()))
    }

    /// Check whether the parent of `path` is proven to have no lower-layer backing.
    /// Returns false only if the parent is cached and has lower_probed with no lower_dir_fd.
    pub fn parent_has_lower_dir(&self, path: &str) -> bool {
        let norm = path.trim_end_matches('/');
        let norm = if norm.is_empty() { "/" } else { norm };
        if let Some((parent_path, _)) = Self::split_parent_and_name(norm)
            && let Some(parent_id) = self.find_parent_dir_id(parent_path)
        {
            let dirs = self.dirs.read();
            if let Some(dir) = dirs.get(&parent_id) {
                if dir.lower_probed && dir.lower_dir_fd.is_none() {
                    return false;
                }
            }
        }
        true
    }

    /// Check whether a directory is proven to have no lower-layer backing.
    /// Returns false only if the directory is cached and has lower_probed with no lower_dir_fd.
    pub fn has_lower_dir(&self, path: &str) -> bool {
        let norm = path.trim_end_matches('/');
        let norm = if norm.is_empty() { "/" } else { norm };
        let map = self.path_to_dir_id.read();
        if let Some(dir_id) = map
            .get(norm)
            .or_else(|| map.get(norm.trim_end_matches('/')))
        {
            let dirs = self.dirs.read();
            if let Some(dir) = dirs.get(dir_id) {
                if dir.lower_probed && dir.lower_dir_fd.is_none() {
                    return false;
                }
            }
        }
        true
    }

    /// Check whether an entry exists in the lower layer.
    /// Returns false with 0 host calls if the parent is a pure-upper directory
    /// or if the entry is recorded in `lower_negatives`.
    /// Otherwise probes lower with 1 host call and caches the negative on ENOENT.
    pub fn lower_has_entry(&self, path: &str, rootfs: Option<&RootFs>) -> bool {
        let norm = path.trim_end_matches('/');
        let norm = if norm.is_empty() { "/" } else { norm };
        let Some((parent_path, name)) = Self::split_parent_and_name(norm) else {
            return rootfs.and_then(|r| r.symlink_metadata(norm).ok()).is_some();
        };
        let Some(parent_id) = self.find_parent_dir_id(parent_path) else {
            return rootfs.and_then(|r| r.symlink_metadata(norm).ok()).is_some();
        };
        let dirs = self.dirs.read();
        let Some(dir) = dirs.get(&parent_id) else {
            return rootfs.and_then(|r| r.symlink_metadata(norm).ok()).is_some();
        };
        if dir.lower_probed && dir.lower_dir_fd.is_none() {
            return false;
        }
        if dir.lower_negatives.read().contains(name) {
            return false;
        }
        let lower_fd = dir.lower_dir_fd.clone();
        drop(dirs);

        if let Some(lfd) = lower_fd {
            if let Ok(name_c) = CString::new(name.as_bytes()) {
                let mut st: libc::stat = unsafe { core::mem::zeroed() };
                let rc = unsafe {
                    libc::fstatat(
                        lfd.as_raw_fd(),
                        name_c.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if rc == 0 {
                    return true;
                }
            }
        } else if let Some(rf) = rootfs {
            if rf.symlink_metadata(norm).is_ok() {
                return true;
            }
        } else {
            return false;
        }

        // Probed and absent in lower: record in lower_negatives!
        let dirs = self.dirs.read();
        if let Some(dir) = dirs.get(&parent_id) {
            dir.lower_negatives.write().insert(name.to_string());
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_backend::HostFsBackend;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_dentry_cache_positive_and_negative() {
        let tmp = tempdir().unwrap();
        let backend = HostFsBackend::from_path(tmp.path()).unwrap();
        let cache = DentryCache::new(false);

        // Create a file
        let file_path = tmp.path().join("foo.txt");
        fs::write(&file_path, b"hello").unwrap();

        // 1. Positive lookup
        let stat1 = cache
            .stat("/foo.txt", true, &backend, None)
            .expect("stat foo.txt");
        assert_eq!(stat1.size, 5);

        // Subsequent lookup hits cache
        let stat2 = cache
            .stat("/foo.txt", true, &backend, None)
            .expect("stat foo.txt cached");
        assert_eq!(stat2.size, 5);

        // 2. Negative lookup
        let err1 = cache.stat("/bar.txt", true, &backend, None).unwrap_err();
        assert_eq!(err1, LINUX_ENOENT);

        let err2 = cache.stat("/bar.txt", true, &backend, None).unwrap_err();
        assert_eq!(err2, LINUX_ENOENT);

        // 3. Create after negative lookup invalidates negative dentry
        cache.entry_created("/bar.txt", None);
        fs::write(tmp.path().join("bar.txt"), b"bar content").unwrap();
        let stat_bar = cache
            .stat("/bar.txt", true, &backend, None)
            .expect("stat bar.txt after create");
        assert_eq!(stat_bar.size, 11);

        // 4. Unlink
        cache.entry_removed("/foo.txt", None);
        fs::remove_file(&file_path).unwrap();
        let err3 = cache.stat("/foo.txt", true, &backend, None).unwrap_err();
        assert_eq!(err3, LINUX_ENOENT);
    }

    #[test]
    fn test_dentry_cache_symlink() {
        let tmp = tempdir().unwrap();
        let backend = HostFsBackend::from_path(tmp.path()).unwrap();
        let cache = DentryCache::new(false);

        let target_path = tmp.path().join("target.txt");
        fs::write(&target_path, b"symlink target").unwrap();
        std::os::unix::fs::symlink("target.txt", tmp.path().join("link1.txt")).unwrap();
        std::os::unix::fs::symlink("link1.txt", tmp.path().join("link2.txt")).unwrap();

        // Multi-hop resolution
        let stat = cache
            .stat("/link2.txt", true, &backend, None)
            .expect("stat link2.txt");
        assert_eq!(stat.size, 14);

        // Readlink
        let target = cache
            .readlink("/link1.txt", &backend, None)
            .expect("readlink link1.txt");
        assert_eq!(target, "target.txt");
    }

    #[test]
    fn test_dentry_cache_dir_generation() {
        let tmp = tempdir().unwrap();
        let backend = HostFsBackend::from_path(tmp.path()).unwrap();
        let cache = DentryCache::new(false);

        let subdir = tmp.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        let stat_dir = cache
            .stat("/subdir", true, &backend, None)
            .expect("stat subdir");
        assert_eq!(stat_dir.kind, RootFsEntryKind::Directory);

        // Query negative child
        let err = cache
            .stat("/subdir/missing", true, &backend, None)
            .unwrap_err();
        assert_eq!(err, LINUX_ENOENT);

        // Bump dir generation on subdir
        cache.bump_dir_generation("/subdir");
        fs::write(subdir.join("missing"), b"found now").unwrap();
        let stat_child = cache
            .stat("/subdir/missing", true, &backend, None)
            .expect("stat child after bump");
        assert_eq!(stat_child.size, 9);
    }

    #[test]
    fn test_dentry_cache_with_lower_rootfs() {
        let lower_tmp = tempdir().unwrap();
        fs::create_dir_all(lower_tmp.path().join("usr/bin")).unwrap();
        fs::write(lower_tmp.path().join("usr/bin/python3.12"), b"binary").unwrap();
        std::os::unix::fs::symlink("python3.12", lower_tmp.path().join("usr/bin/python3")).unwrap();

        let rootfs = RootFs::from_immutable_host_dir(lower_tmp.path()).unwrap();

        let upper_tmp = tempdir().unwrap();
        let backend = HostFsBackend::from_path(upper_tmp.path()).unwrap();
        let cache = DentryCache::new(false);

        // 1. Stat symlink in lower
        let st = cache
            .stat("/usr/bin/python3", true, &backend, Some(&rootfs))
            .expect("stat lower symlink");
        assert_eq!(st.size, 6);

        // 2. Readlink in lower
        let target = cache
            .readlink("/usr/bin/python3", &backend, Some(&rootfs))
            .expect("readlink lower symlink");
        assert_eq!(target, "python3.12");

        // 3. Fast open read-only in lower
        let (fd, st_open, path, source) = cache
            .fast_open("/usr/bin/python3", false, &backend, Some(&rootfs))
            .expect("fast open lower readonly");
        assert_eq!(path, "/usr/bin/python3.12");
        assert_eq!(st_open.size, 6);
        assert_eq!(source, carrick_guest_mem::PrivateFileSource::ImmutableLower);
        drop(fd);

        // 4. Fast open writable on lower must return LINUX_EXDEV (to trigger copy-up)
        let err_open_write = cache
            .fast_open("/usr/bin/python3", true, &backend, Some(&rootfs))
            .unwrap_err();
        assert_eq!(err_open_write, LINUX_EXDEV);

        // 5. Negative lookup in lower
        let err = cache
            .stat("/usr/lib/nonexistent", true, &backend, Some(&rootfs))
            .unwrap_err();
        assert_eq!(err, LINUX_ENOENT);

        // 6. Deep path with symlink: /usr/local/bin/python3 -> python3.12
        fs::create_dir_all(lower_tmp.path().join("usr/local/bin")).unwrap();
        fs::write(
            lower_tmp.path().join("usr/local/bin/python3.12"),
            b"python312",
        )
        .unwrap();
        std::os::unix::fs::symlink("python3.12", lower_tmp.path().join("usr/local/bin/python3"))
            .unwrap();
        let (fd_deep, st_deep, path_deep, source_deep) = cache
            .fast_open("/usr/local/bin/python3", false, &backend, Some(&rootfs))
            .expect("fast open lower /usr/local/bin/python3");
        assert_eq!(path_deep, "/usr/local/bin/python3.12");
        assert_eq!(st_deep.size, 9);
        assert_eq!(
            source_deep,
            carrick_guest_mem::PrivateFileSource::ImmutableLower
        );
        drop(fd_deep);
    }

    #[test]
    fn test_dentry_cache_inode_invalidation_and_hard_links() {
        let tmp = tempdir().unwrap();
        let backend = HostFsBackend::from_path(tmp.path()).unwrap();
        let cache = DentryCache::new(false);

        // 1. Create file with 5 bytes
        let file_path = tmp.path().join("foo.txt");
        fs::write(&file_path, b"hello").unwrap();

        let st1 = cache
            .stat("/foo.txt", true, &backend, None)
            .expect("stat foo.txt");
        assert_eq!(st1.size, 5);
        assert_eq!(st1.nlink, 1);

        use std::os::unix::fs::MetadataExt;
        let meta1 = fs::metadata(&file_path).unwrap();
        let ino_ident = Some(InodeIdentity::new(meta1.dev(), meta1.ino()));

        // 2. Invalidate inode, simulate fd-based write of 6 more bytes (total 11)
        cache.inode_changed("/foo.txt", ino_ident);
        fs::write(&file_path, b"hello world").unwrap();

        let st2 = cache
            .stat("/foo.txt", true, &backend, None)
            .expect("stat foo.txt after fd write");
        assert_eq!(st2.size, 11);
        assert_eq!(st2.ino, st1.ino);

        // 3. Hard link: link /foo.txt -> /ln.txt
        let link_path = tmp.path().join("ln.txt");
        fs::hard_link(&file_path, &link_path).unwrap();
        cache.entry_created("/ln.txt", ino_ident);
        cache.inode_changed("/foo.txt", ino_ident);

        // Both /foo.txt and /ln.txt must observe nlink == 2 and size == 11
        let st_foo = cache
            .stat("/foo.txt", true, &backend, None)
            .expect("stat foo after link");
        assert_eq!(st_foo.nlink, 2);
        assert_eq!(st_foo.size, 11);

        let st_ln = cache
            .stat("/ln.txt", true, &backend, None)
            .expect("stat ln after link");
        assert_eq!(st_ln.nlink, 2);
        assert_eq!(st_ln.size, 11);
        assert_eq!(st_ln.ino, st_foo.ino);

        // 4. Invalidate inode, write 3 bytes to file via hard link
        cache.inode_changed("/ln.txt", ino_ident);
        fs::write(&link_path, b"abc").unwrap();

        // Both aliases must observe the updated size 3
        let st_ln2 = cache
            .stat("/ln.txt", true, &backend, None)
            .expect("stat ln after write");
        assert_eq!(st_ln2.size, 3);

        let st_foo2 = cache
            .stat("/foo.txt", true, &backend, None)
            .expect("stat foo after write to ln");
        assert_eq!(st_foo2.size, 3);
    }

    #[test]
    fn test_dentry_cache_repeated_mkdir_rmdir_cycles() {
        let tmp = tempdir().unwrap();
        let backend = HostFsBackend::from_path(tmp.path()).unwrap();
        let cache = DentryCache::new(false);

        // Pre-create parent directory /tmp
        fs::create_dir_all(tmp.path().join("tmp")).unwrap();
        cache.entry_created("/tmp", None);
        assert!(cache.stat("/tmp", true, &backend, None).is_ok());

        // Repeatedly create and remove subdirectories under /tmp
        for i in 0..500 {
            let dir_name = format!("cycle_{i}");
            let disk_dir = tmp.path().join("tmp").join(&dir_name);
            fs::create_dir_all(&disk_dir).unwrap();
            let guest_path = format!("/tmp/{dir_name}");
            cache.entry_created(&guest_path, None);

            // Lookup and stat should succeed
            assert!(cache.stat(&guest_path, true, &backend, None).is_ok());

            // Remove directory
            fs::remove_dir(&disk_dir).unwrap();
            cache.entry_removed(&guest_path, None);
            assert!(cache.stat(&guest_path, true, &backend, None).is_err());
        }

        // After 500 cycles, /tmp must still be stat-able and dirs must not have leaked 500 entries
        assert!(cache.stat("/tmp", true, &backend, None).is_ok());
        assert!(cache.dirs.read().len() < 50);
    }

    #[test]
    fn test_dentry_cache_5000_dirs_preserves_earlier_entry() {
        let tmp = tempdir().unwrap();
        let backend = HostFsBackend::from_path(tmp.path()).unwrap();
        let cache = DentryCache::new(false);

        for i in 0..5000 {
            let dir_name = format!("dir_{i}");
            let disk_dir = tmp.path().join(&dir_name);
            fs::create_dir_all(&disk_dir).unwrap();
            let file_name = "file.txt";
            fs::write(disk_dir.join(file_name), b"test").unwrap();

            let guest_dir = format!("/dir_{i}");
            let guest_file = format!("/dir_{i}/file.txt");
            cache.entry_created(&guest_dir, None);
            cache.entry_created(&guest_file, None);
            assert!(cache.stat(&guest_file, true, &backend, None).is_ok());
        }

        // Target file right before the 4096th directory (i = 4094)
        let target_file = "/dir_4094/file.txt";
        let target_dir = "/dir_4094";
        // Check if it's cached in path_to_dir_id and entries
        let dir_id = cache.path_to_dir_id.read().get(target_dir).copied();
        assert!(
            dir_id.is_some(),
            "dir_4094 should still be cached in path_to_dir_id"
        );
        assert!(cache.stat(target_file, true, &backend, None).is_ok());
    }

    #[test]
    fn test_dentry_cache_memory_bounded_eviction_leaf_first() {
        let tmp = tempdir().unwrap();
        let backend = HostFsBackend::from_path(tmp.path()).unwrap();
        // Capacity of 64 KiB
        let cache = DentryCache::new_with_capacity(false, 64 * 1024, true);

        // 1. Create a parent directory with 2 leaf subdirectories
        fs::create_dir_all(tmp.path().join("parent").join("leaf1")).unwrap();
        fs::create_dir_all(tmp.path().join("parent").join("leaf2")).unwrap();
        fs::write(tmp.path().join("parent").join("leaf1").join("f1.txt"), b"1").unwrap();
        fs::write(tmp.path().join("parent").join("leaf2").join("f2.txt"), b"2").unwrap();

        cache.entry_created("/parent", None);
        cache.entry_created("/parent/leaf1", None);
        cache.entry_created("/parent/leaf2", None);
        cache.entry_created("/parent/leaf1/f1.txt", None);
        cache.entry_created("/parent/leaf2/f2.txt", None);

        assert!(
            cache
                .stat("/parent/leaf1/f1.txt", true, &backend, None)
                .is_ok()
        );
        assert!(
            cache
                .stat("/parent/leaf2/f2.txt", true, &backend, None)
                .is_ok()
        );

        // Both /parent and leaves are cached
        assert!(cache.path_to_dir_id.read().get("/parent").is_some());
        assert!(cache.path_to_dir_id.read().get("/parent/leaf1").is_some());

        // 2. Churn with many other directories to exceed capacity and trigger eviction
        for i in 0..1000 {
            let dname = format!("churn_{i}");
            let disk = tmp.path().join(&dname);
            fs::create_dir_all(&disk).unwrap();
            fs::write(disk.join("f.txt"), b"x").unwrap();
            let gdir = format!("/churn_{i}");
            let gfile = format!("/churn_{i}/f.txt");
            cache.entry_created(&gdir, None);
            cache.entry_created(&gfile, None);
            let _ = cache.stat(&gfile, true, &backend, None);
        }

        // Eviction happened: memory is bounded
        let approx = cache.approx_memory_bytes();
        assert!(
            approx <= cache.capacity_bytes() * 3,
            "Memory should be bounded, got {approx}"
        );

        // Root is NEVER evicted
        assert!(cache.dirs.read().contains_key(&DentryId::ROOT));

        // Re-stat /parent/leaf1/f1.txt must succeed cleanly (re-walks backend if evicted)
        assert!(
            cache
                .stat("/parent/leaf1/f1.txt", true, &backend, None)
                .is_ok()
        );
    }

    #[test]
    fn test_dentry_cache_exchange_preserves_both_entries() {
        let tmp = tempdir().unwrap();
        let backend = HostFsBackend::from_path(tmp.path()).unwrap();
        let cache = DentryCache::new(false);

        let path_a = tmp.path().join("file_a.txt");
        let path_b = tmp.path().join("file_b.txt");
        fs::write(&path_a, b"aaa").unwrap();
        fs::write(&path_b, b"bbbbbb").unwrap();

        cache.entry_created("/file_a.txt", None);
        cache.entry_created("/file_b.txt", None);

        let st_a = cache.stat("/file_a.txt", true, &backend, None).unwrap();
        let st_b = cache.stat("/file_b.txt", true, &backend, None).unwrap();
        assert_eq!(st_a.size, 3);
        assert_eq!(st_b.size, 6);

        // Perform swap on disk
        let tmp_swap = tmp.path().join("file_swap.tmp");
        fs::rename(&path_a, &tmp_swap).unwrap();
        fs::rename(&path_b, &path_a).unwrap();
        fs::rename(&tmp_swap, &path_b).unwrap();

        // Notify exchange
        cache.entry_exchanged("/file_a.txt", "/file_b.txt", None, None);

        // Both must stat successfully with swapped sizes, neither is negative
        let st_a_new = cache.stat("/file_a.txt", true, &backend, None).unwrap();
        let st_b_new = cache.stat("/file_b.txt", true, &backend, None).unwrap();
        assert_eq!(st_a_new.size, 6);
        assert_eq!(st_b_new.size, 3);
    }

    #[test]
    fn test_dentry_cache_pinned_directory_survives_eviction() {
        let tmp = tempdir().unwrap();
        let backend = HostFsBackend::from_path(tmp.path()).unwrap();
        // 64 KiB capacity so eviction triggers quickly
        let cache = DentryCache::new_with_capacity(false, 64 * 1024, true);

        // 1. Create a pinned directory with an entry
        let pinned_dir = tmp.path().join("pinned_dir");
        fs::create_dir_all(&pinned_dir).unwrap();
        fs::write(pinned_dir.join("inside.txt"), b"data").unwrap();

        cache.entry_created("/pinned_dir", None);
        cache.entry_created("/pinned_dir/inside.txt", None);
        assert!(
            cache
                .lookup_path("/pinned_dir/inside.txt", false, &backend, None)
                .is_ok()
        );

        // Open directory fd -> pin directory through cache mutator
        cache.pin_dir("/pinned_dir");

        // Churn past capacity with many other directories
        for i in 0..500 {
            let dname = format!("churn_pin_{i}");
            let disk = tmp.path().join(&dname);
            fs::create_dir_all(&disk).unwrap();
            fs::write(disk.join("f.txt"), b"x").unwrap();
            let gdir = format!("/churn_pin_{i}");
            let gfile = format!("/churn_pin_{i}/f.txt");
            cache.entry_created(&gdir, None);
            cache.entry_created(&gfile, None);
            let _ = cache.stat(&gfile, true, &backend, None);
        }

        // The pinned directory and its cached entries MUST survive
        assert!(
            cache.has_dir("/pinned_dir"),
            "pinned directory must survive eviction"
        );
        assert!(
            cache.has_entry("/pinned_dir", "inside.txt"),
            "entries in pinned directory must survive eviction"
        );

        // Close directory fd -> unpin directory through cache mutator
        cache.unpin_dir("/pinned_dir");

        // Churn past capacity again
        for i in 500..1000 {
            let dname = format!("churn_pin_{i}");
            let disk = tmp.path().join(&dname);
            fs::create_dir_all(&disk).unwrap();
            fs::write(disk.join("f.txt"), b"x").unwrap();
            let gdir = format!("/churn_pin_{i}");
            let gfile = format!("/churn_pin_{i}/f.txt");
            cache.entry_created(&gdir, None);
            cache.entry_created(&gfile, None);
            let _ = cache.stat(&gfile, true, &backend, None);
        }

        // Now that it is unpinned, it is evicted
        assert!(
            !cache.has_dir("/pinned_dir"),
            "unpinned directory must be evicted after churn past capacity"
        );
    }

    #[test]
    fn test_dentry_concurrent_eviction_lookup_fallback_no_enoent() {
        use std::sync::atomic::AtomicBool;
        use std::thread;

        let tmp = tempdir().unwrap();
        let cache = Arc::new(DentryCache::new_with_capacity(false, 64 * 1024, true));
        let stop = Arc::new(AtomicBool::new(false));

        let target_dir = tmp.path().join("target");
        fs::create_dir_all(&target_dir).unwrap();

        // Thread 1: churns and triggers eviction continuously
        let cache_clone1 = Arc::clone(&cache);
        let stop_clone1 = Arc::clone(&stop);
        let tmp_path = tmp.path().to_path_buf();
        let churn_handle = thread::spawn(move || {
            let mut idx = 0;
            let b = HostFsBackend::from_path(&tmp_path).unwrap();
            while !stop_clone1.load(Ordering::Relaxed) {
                let dir_name = format!("churn_race_{}", idx % 50);
                let p = tmp_path.join(&dir_name);
                let _ = fs::create_dir_all(&p);
                let file_p = p.join("test.txt");
                let _ = fs::write(&file_p, b"data");
                let lookup_path = format!("/{}/test.txt", dir_name);
                let _ = cache_clone1.lookup_path(&lookup_path, false, &b, None);
                idx += 1;
            }
        });

        // Thread 2: creates files in target_dir and looks them up concurrently with eviction
        let b2 = HostFsBackend::from_path(tmp.path()).unwrap();
        for i in 0..150 {
            let file_name = format!("file_{i}.txt");
            let file_p = target_dir.join(&file_name);
            fs::write(&file_p, b"hello").unwrap();

            let lookup_path = format!("/target/{file_name}");
            let res = cache.lookup_path(&lookup_path, false, &b2, None);
            assert!(
                res.is_ok(),
                "lookup of existing file {lookup_path} must not fail with ENOENT during concurrent eviction, got: {:?}",
                res.err()
            );
        }

        stop.store(true, Ordering::Relaxed);
        churn_handle.join().unwrap();
    }

    #[test]
    fn test_warm_cache_per_entry_invalidation() {
        let tmp = tempdir().unwrap();
        let backend = HostFsBackend::from_path(tmp.path()).unwrap();
        let cache = DentryCache::new(false);

        let test_dir = tmp.path().join("test_dir");
        fs::create_dir(&test_dir).unwrap();
        fs::write(test_dir.join("file_a.txt"), b"aaa").unwrap();
        fs::write(test_dir.join("file_b.txt"), b"bbb").unwrap();

        // 1. Initial lookups to populate the cache
        cache.reset_host_open_count();
        let st_a1 = cache
            .stat("/test_dir/file_a.txt", false, &backend, None)
            .unwrap();
        let st_b1 = cache
            .stat("/test_dir/file_b.txt", false, &backend, None)
            .unwrap();
        assert_eq!(st_a1.size, 3);
        assert_eq!(st_b1.size, 3);

        // 2. Create file_c.txt in the same directory
        fs::write(test_dir.join("file_c.txt"), b"ccc").unwrap();
        cache.entry_created("/test_dir/file_c.txt", None);

        // Warm lookup of file_a.txt and file_b.txt must NOT be evicted by file_c creation!
        cache.reset_host_open_count();
        let st_a2 = cache
            .stat("/test_dir/file_a.txt", false, &backend, None)
            .unwrap();
        let st_b2 = cache
            .stat("/test_dir/file_b.txt", false, &backend, None)
            .unwrap();
        assert_eq!(st_a2.size, 3);
        assert_eq!(st_b2.size, 3);
        // On a warm dentry cache, stat requires 0 host opens
        assert_eq!(
            cache.host_open_count(),
            0,
            "sibling positive dentries must remain cached after entry_created"
        );

        // 3. Unlink file_a.txt
        fs::remove_file(test_dir.join("file_a.txt")).unwrap();
        cache.entry_removed("/test_dir/file_a.txt", None);

        // file_b.txt must STILL remain cached!
        cache.reset_host_open_count();
        let st_b3 = cache
            .stat("/test_dir/file_b.txt", false, &backend, None)
            .unwrap();
        assert_eq!(st_b3.size, 3);
        assert_eq!(
            cache.host_open_count(),
            0,
            "sibling positive dentries must remain cached after entry_removed"
        );

        // file_a.txt must be negative
        let err_a = cache
            .stat("/test_dir/file_a.txt", false, &backend, None)
            .unwrap_err();
        assert_eq!(err_a, LINUX_ENOENT);
    }

    #[test]
    fn test_lower_negative_cached_after_one_probe() {
        let lower_tmp = tempdir().unwrap();
        fs::create_dir_all(lower_tmp.path().join("tmp")).unwrap();
        let rootfs = RootFs::from_immutable_host_dir(lower_tmp.path()).unwrap();

        let upper_tmp = tempdir().unwrap();
        let backend = HostFsBackend::from_path(upper_tmp.path()).unwrap();
        let cache = DentryCache::new(false);

        // Warm /tmp
        let _ = cache.stat("/tmp", false, &backend, Some(&rootfs)).unwrap();

        // 1. Probe nonexistent entry under lower-backed /tmp
        cache.reset_host_open_count();
        let err1 = cache
            .stat("/tmp/nonexistent_file", false, &backend, Some(&rootfs))
            .unwrap_err();
        assert_eq!(err1, LINUX_ENOENT);
        let first_opens = cache.host_open_count();

        // 2. Second lookup must use cached lower-negative, requiring 0 host opens
        cache.reset_host_open_count();
        let err2 = cache
            .stat("/tmp/nonexistent_file", false, &backend, Some(&rootfs))
            .unwrap_err();
        assert_eq!(err2, LINUX_ENOENT);
        assert_eq!(
            cache.host_open_count(),
            0,
            "second lookup of lower-negative path must issue 0 host opens"
        );
        let _ = first_opens;
    }
}
