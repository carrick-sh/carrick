//! VFS decorators and custom filesystem injection for `carrick-embed`.
//!
//! Provides in-memory file systems, multi-layer composition, access/path/content
//! filtering, and bounded execution tracing for embedded container runs.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use carrick_abi::{
    LINUX_EBUSY, LINUX_EEXIST, LINUX_EFBIG, LINUX_EINVAL, LINUX_EISDIR, LINUX_ELOOP, LINUX_ENOENT,
    LINUX_ENOSYS, LINUX_ENOTDIR, LINUX_ENOTEMPTY, LINUX_EROFS, LinuxErrno, NsGid, NsUid,
};
pub use carrick_runtime::vfs::{
    DirEnt, EntryKind, MAX_IN_MEMORY_FILE_SIZE, Metadata, OpenContext, OpenFlags, Vfs, VfsError,
    VfsHandle,
};
use parking_lot::{Mutex, RwLock};

/// Normalize a guest path to an absolute, clean path starting with `/`.
pub(crate) fn normalize_path(path: &str) -> String {
    let mut components = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            components.pop();
        } else {
            components.push(part);
        }
    }
    if components.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", components.join("/"))
    }
}

// ============================================================================
// InMemoryFileVfs
// ============================================================================

#[derive(Clone)]
enum InMemNode {
    File {
        contents: Arc<RwLock<Vec<u8>>>,
        mode: u32,
        uid: NsUid,
        gid: NsGid,
        mtime_secs: i64,
    },
    Directory {
        mode: u32,
        uid: NsUid,
        gid: NsGid,
        mtime_secs: i64,
    },
    Symlink {
        target: PathBuf,
        mode: u32,
        uid: NsUid,
        gid: NsGid,
        mtime_secs: i64,
    },
}

impl InMemNode {
    fn metadata(&self) -> Metadata {
        match self {
            Self::File {
                contents,
                mode,
                uid,
                gid,
                mtime_secs,
            } => Metadata {
                kind: EntryKind::File,
                mode: *mode,
                size: contents.read().len() as u64,
                mtime_secs: *mtime_secs,
                mtime_nanos: 0,
                uid: uid.raw(),
                gid: gid.raw(),
            },
            Self::Directory {
                mode,
                uid,
                gid,
                mtime_secs,
            } => Metadata {
                kind: EntryKind::Directory,
                mode: *mode,
                size: 0,
                mtime_secs: *mtime_secs,
                mtime_nanos: 0,
                uid: uid.raw(),
                gid: gid.raw(),
            },
            Self::Symlink {
                target,
                mode,
                uid,
                gid,
                mtime_secs,
            } => Metadata {
                kind: EntryKind::Symlink,
                mode: *mode,
                size: target.as_os_str().len() as u64,
                mtime_secs: *mtime_secs,
                mtime_nanos: 0,
                uid: uid.raw(),
                gid: gid.raw(),
            },
        }
    }
}

/// An in-memory filesystem with explicit metadata, deterministic storage,
/// configurable read-only / bounded capacity, and real write capture.
pub struct InMemoryFileVfs {
    nodes: Arc<RwLock<BTreeMap<String, InMemNode>>>,
    readonly: bool,
    max_file_size: usize,
}

impl InMemoryFileVfs {
    /// Create a new, empty in-memory filesystem containing a root directory (`/`).
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            "/".to_string(),
            InMemNode::Directory {
                mode: 0o755,
                uid: NsUid::ROOT,
                gid: NsGid::ROOT,
                mtime_secs: 0,
            },
        );
        Self {
            nodes: Arc::new(RwLock::new(nodes)),
            readonly: false,
            max_file_size: MAX_IN_MEMORY_FILE_SIZE as usize,
        }
    }

    /// Set read-only mode on this in-memory filesystem.
    pub fn readonly(mut self, ro: bool) -> Self {
        self.readonly = ro;
        self
    }

    /// Set maximum allowed file size in bytes for created and truncated files.
    pub fn max_file_size(mut self, max: usize) -> Self {
        self.max_file_size = max;
        self
    }

    /// Add a regular file with default permissions (`0o644`, owned by root).
    pub fn add_file(
        &self,
        path: impl AsRef<Path>,
        data: impl Into<Vec<u8>>,
    ) -> Result<(), VfsError> {
        self.add_file_with_metadata(path, data, 0o644, NsUid::ROOT, NsGid::ROOT, 0)
    }

    fn ensure_dirs_locked(
        nodes: &mut BTreeMap<String, InMemNode>,
        dir_path: &str,
    ) -> Result<(), LinuxErrno> {
        let norm = normalize_path(dir_path);
        if norm == "/" {
            return Ok(());
        }
        let mut current = String::new();
        for part in norm.split('/').filter(|p| !p.is_empty()) {
            current.push('/');
            current.push_str(part);
            match nodes.get(&current) {
                Some(InMemNode::Directory { .. }) => {}
                Some(_) => return Err(LINUX_ENOTDIR),
                None => {
                    nodes.insert(
                        current.clone(),
                        InMemNode::Directory {
                            mode: 0o755,
                            uid: NsUid::ROOT,
                            gid: NsGid::ROOT,
                            mtime_secs: 0,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    /// Add a regular file with explicit mode, ownership, and mtime.
    pub fn add_file_with_metadata(
        &self,
        path: impl AsRef<Path>,
        data: impl Into<Vec<u8>>,
        mode: u32,
        uid: NsUid,
        gid: NsGid,
        mtime_secs: i64,
    ) -> Result<(), VfsError> {
        let path_str = normalize_path(&path.as_ref().to_string_lossy());
        if path_str == "/" {
            return Err(LINUX_EISDIR);
        }
        let data = data.into();
        if data.len() > self.max_file_size {
            return Err(LINUX_EFBIG);
        }
        let mut nodes = self.nodes.write();
        let parent = parent_path(&path_str);
        Self::ensure_dirs_locked(&mut nodes, &parent)?;
        nodes.insert(
            path_str,
            InMemNode::File {
                contents: Arc::new(RwLock::new(data)),
                mode,
                uid,
                gid,
                mtime_secs,
            },
        );
        Ok(())
    }

    /// Add a directory with default permissions (`0o755`, owned by root).
    pub fn add_dir(&self, path: impl AsRef<Path>) -> Result<(), VfsError> {
        self.add_dir_with_metadata(path, 0o755, NsUid::ROOT, NsGid::ROOT, 0)
    }

    /// Add a directory with explicit mode, ownership, and mtime.
    pub fn add_dir_with_metadata(
        &self,
        path: impl AsRef<Path>,
        mode: u32,
        uid: NsUid,
        gid: NsGid,
        mtime_secs: i64,
    ) -> Result<(), VfsError> {
        let path_str = normalize_path(&path.as_ref().to_string_lossy());
        if path_str == "/" {
            return Ok(());
        }
        let mut nodes = self.nodes.write();
        let parent = parent_path(&path_str);
        Self::ensure_dirs_locked(&mut nodes, &parent)?;
        nodes.insert(
            path_str,
            InMemNode::Directory {
                mode,
                uid,
                gid,
                mtime_secs,
            },
        );
        Ok(())
    }

    /// Add a symlink pointing to `target`.
    pub fn add_symlink(
        &self,
        link_path: impl AsRef<Path>,
        target: impl AsRef<Path>,
    ) -> Result<(), VfsError> {
        let path_str = normalize_path(&link_path.as_ref().to_string_lossy());
        if path_str == "/" {
            return Err(LINUX_EINVAL);
        }
        let mut nodes = self.nodes.write();
        let parent = parent_path(&path_str);
        Self::ensure_dirs_locked(&mut nodes, &parent)?;
        nodes.insert(
            path_str,
            InMemNode::Symlink {
                target: target.as_ref().to_path_buf(),
                mode: 0o777,
                uid: NsUid::ROOT,
                gid: NsGid::ROOT,
                mtime_secs: 0,
            },
        );
        Ok(())
    }

    /// Read the full byte contents of a file in the in-memory filesystem.
    pub fn read_file_bytes(&self, path: &str) -> Result<Vec<u8>, VfsError> {
        let nodes = self.nodes.read();
        let target_path = Self::resolve_symlinks_locked(&nodes, path, 32)?;
        match nodes.get(&target_path) {
            Some(InMemNode::File { contents, .. }) => Ok(contents.read().clone()),
            Some(InMemNode::Directory { .. }) => Err(LINUX_EISDIR),
            Some(InMemNode::Symlink { .. }) => unreachable!(),
            None => Err(LINUX_ENOENT),
        }
    }

    /// Read the string contents of a file in UTF-8 format.
    pub fn read_file_string(&self, path: &str) -> Result<String, VfsError> {
        let bytes = self.read_file_bytes(path)?;
        String::from_utf8(bytes).map_err(|_| LINUX_EINVAL)
    }

    /// Return a snapshot of all regular files and their live byte contents.
    pub fn written_files(&self) -> Vec<(String, Vec<u8>)> {
        let nodes = self.nodes.read();
        nodes
            .iter()
            .filter_map(|(path, node)| match node {
                InMemNode::File { contents, .. } => Some((path.clone(), contents.read().clone())),
                _ => None,
            })
            .collect()
    }

    fn resolve_symlinks_locked(
        nodes: &BTreeMap<String, InMemNode>,
        path: &str,
        max_hops: usize,
    ) -> Result<String, LinuxErrno> {
        let mut current = normalize_path(path);
        for _ in 0..max_hops {
            match nodes.get(&current) {
                Some(InMemNode::Symlink { target, .. }) => {
                    let target_str = target.to_string_lossy();
                    if target_str.starts_with('/') {
                        current = normalize_path(&target_str);
                    } else {
                        let parent = parent_path(&current);
                        let joined = format!("{parent}/{target_str}");
                        current = normalize_path(&joined);
                    }
                }
                _ => return Ok(current),
            }
        }
        Err(LINUX_ELOOP)
    }
}

impl Default for InMemoryFileVfs {
    fn default() -> Self {
        Self::new()
    }
}

fn parent_path(path: &str) -> String {
    if path == "/" {
        return "/".to_string();
    }
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(idx) => path[..idx].to_string(),
        None => "/".to_string(),
    }
}

impl Vfs for InMemoryFileVfs {
    fn name(&self) -> &'static str {
        "in-memory-vfs"
    }

    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        let nodes = self.nodes.read();
        let target_path = Self::resolve_symlinks_locked(&nodes, path, 32)?;
        nodes
            .get(&target_path)
            .map(|node| node.metadata())
            .ok_or(LINUX_ENOENT)
    }

    fn lookup_nofollow(&self, path: &str) -> Result<Metadata, VfsError> {
        let norm = normalize_path(path);
        let nodes = self.nodes.read();
        nodes
            .get(&norm)
            .map(|node| node.metadata())
            .ok_or(LINUX_ENOENT)
    }

    fn readlink(&self, path: &str) -> Result<PathBuf, VfsError> {
        let norm = normalize_path(path);
        let nodes = self.nodes.read();
        match nodes.get(&norm) {
            Some(InMemNode::Symlink { target, .. }) => Ok(target.clone()),
            Some(_) => Err(LINUX_EINVAL),
            None => Err(LINUX_ENOENT),
        }
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEnt>, VfsError> {
        let norm = normalize_path(path);
        let nodes = self.nodes.read();
        match nodes.get(&norm) {
            Some(InMemNode::Directory { .. }) => {}
            Some(_) => return Err(LINUX_ENOTDIR),
            None => return Err(LINUX_ENOENT),
        }

        let prefix = if norm == "/" {
            "/".to_string()
        } else {
            format!("{norm}/")
        };

        let mut entries = Vec::new();
        entries.push(DirEnt {
            name: ".".to_string(),
            kind: EntryKind::Directory,
        });
        entries.push(DirEnt {
            name: "..".to_string(),
            kind: EntryKind::Directory,
        });

        for (node_path, node) in nodes.iter() {
            if node_path == &norm || !node_path.starts_with(&prefix) {
                continue;
            }
            let sub = &node_path[prefix.len()..];
            if !sub.contains('/') {
                entries.push(DirEnt {
                    name: sub.to_string(),
                    kind: node.metadata().kind,
                });
            }
        }
        Ok(entries)
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        _ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        if self.readonly && flags.write {
            return Err(LINUX_EROFS);
        }

        let norm = normalize_path(path);
        let mut nodes = self.nodes.write();

        let resolved_path = if flags.nofollow {
            norm.clone()
        } else {
            Self::resolve_symlinks_locked(&nodes, &norm, 32)?
        };

        if let Some(node) = nodes.get(&resolved_path) {
            if flags.create && flags.excl {
                return Err(LINUX_EEXIST);
            }
            match node {
                InMemNode::Directory { .. } => {
                    if flags.write {
                        return Err(LINUX_EISDIR);
                    }
                    drop(nodes);
                    let entries = self.readdir(&resolved_path)?;
                    return Ok(VfsHandle::Directory {
                        path: resolved_path,
                        entries,
                        status_flags: 0,
                    });
                }
                InMemNode::Symlink { .. } if flags.nofollow => {
                    return Err(LINUX_ELOOP);
                }
                InMemNode::Symlink { .. } => unreachable!(),
                InMemNode::File { contents, .. } => {
                    if flags.directory {
                        return Err(LINUX_ENOTDIR);
                    }
                    if flags.trunc && flags.write {
                        contents.write().clear();
                    }
                    return Ok(VfsHandle::InMemoryFile {
                        path: resolved_path,
                        contents: Arc::clone(contents),
                        status_flags: 0,
                        writable: flags.write && !self.readonly,
                        max_size: self.max_file_size,
                    });
                }
            }
        }

        if !flags.create {
            return Err(LINUX_ENOENT);
        }

        if self.readonly {
            return Err(LINUX_EROFS);
        }

        let parent = parent_path(&resolved_path);
        match nodes.get(&parent) {
            Some(InMemNode::Directory { .. }) => {}
            Some(_) => return Err(LINUX_ENOTDIR),
            None => return Err(LINUX_ENOENT),
        }

        let contents = Arc::new(RwLock::new(Vec::new()));
        nodes.insert(
            resolved_path.clone(),
            InMemNode::File {
                contents: Arc::clone(&contents),
                mode: flags.mode,
                uid: NsUid::ROOT,
                gid: NsGid::ROOT,
                mtime_secs: 0,
            },
        );

        Ok(VfsHandle::InMemoryFile {
            path: resolved_path,
            contents,
            status_flags: 0,
            writable: flags.write && !self.readonly,
            max_size: self.max_file_size,
        })
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let norm = normalize_path(path);
        let mut nodes = self.nodes.write();
        if nodes.contains_key(&norm) {
            return Err(LINUX_EEXIST);
        }
        let parent = parent_path(&norm);
        match nodes.get(&parent) {
            Some(InMemNode::Directory { .. }) => {}
            Some(_) => return Err(LINUX_ENOTDIR),
            None => return Err(LINUX_ENOENT),
        }
        nodes.insert(
            norm,
            InMemNode::Directory {
                mode,
                uid: NsUid::ROOT,
                gid: NsGid::ROOT,
                mtime_secs: 0,
            },
        );
        Ok(())
    }

    fn unlink(&self, path: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let norm = normalize_path(path);
        let mut nodes = self.nodes.write();
        match nodes.get(&norm) {
            Some(InMemNode::Directory { .. }) => Err(LINUX_EISDIR),
            Some(_) => {
                nodes.remove(&norm);
                Ok(())
            }
            None => Err(LINUX_ENOENT),
        }
    }

    fn rmdir(&self, path: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let norm = normalize_path(path);
        if norm == "/" {
            return Err(LINUX_EBUSY);
        }
        let mut nodes = self.nodes.write();
        match nodes.get(&norm) {
            Some(InMemNode::Directory { .. }) => {}
            Some(_) => return Err(LINUX_ENOTDIR),
            None => return Err(LINUX_ENOENT),
        }

        let prefix = format!("{norm}/");
        if nodes.keys().any(|k| k.starts_with(&prefix)) {
            return Err(LINUX_ENOTEMPTY);
        }
        nodes.remove(&norm);
        Ok(())
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let from_norm = normalize_path(from);
        let to_norm = normalize_path(to);
        if from_norm == to_norm {
            return Ok(());
        }
        let mut nodes = self.nodes.write();
        let from_node = nodes.get(&from_norm).cloned().ok_or(LINUX_ENOENT)?;

        let to_parent = parent_path(&to_norm);
        match nodes.get(&to_parent) {
            Some(InMemNode::Directory { .. }) => {}
            Some(_) => return Err(LINUX_ENOTDIR),
            None => return Err(LINUX_ENOENT),
        }

        if let Some(target) = nodes.get(&to_norm) {
            match (&from_node, target) {
                (InMemNode::Directory { .. }, InMemNode::Directory { .. }) => {
                    let prefix = format!("{to_norm}/");
                    if nodes.keys().any(|k| k.starts_with(&prefix)) {
                        return Err(LINUX_ENOTEMPTY);
                    }
                }
                (InMemNode::Directory { .. }, _) => return Err(LINUX_ENOTDIR),
                (_, InMemNode::Directory { .. }) => return Err(LINUX_EISDIR),
                _ => {}
            }
        }

        if matches!(from_node, InMemNode::Directory { .. }) {
            let from_prefix = format!("{from_norm}/");
            let mut descendants = Vec::new();
            for (k, v) in nodes.iter() {
                if k.starts_with(&from_prefix) {
                    descendants.push((k.clone(), v.clone()));
                }
            }
            for (k, _) in &descendants {
                nodes.remove(k);
            }
            nodes.remove(&from_norm);
            nodes.insert(to_norm.clone(), from_node);
            for (k, v) in descendants {
                let sub = &k[from_prefix.len()..];
                nodes.insert(format!("{to_norm}/{sub}"), v);
            }
        } else {
            nodes.remove(&from_norm);
            nodes.insert(to_norm, from_node);
        }
        Ok(())
    }

    fn symlink(&self, target: &str, link: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        self.add_symlink(link, target)
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let norm = normalize_path(path);
        let mut nodes = self.nodes.write();
        let node = nodes.get_mut(&norm).ok_or(LINUX_ENOENT)?;
        match node {
            InMemNode::File { mode: m, .. }
            | InMemNode::Directory { mode: m, .. }
            | InMemNode::Symlink { mode: m, .. } => *m = mode,
        }
        Ok(())
    }

    fn chown(
        &self,
        path: &str,
        uid: Option<NsUid>,
        gid: Option<NsGid>,
        _nofollow: bool,
    ) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let norm = normalize_path(path);
        let mut nodes = self.nodes.write();
        let node = nodes.get_mut(&norm).ok_or(LINUX_ENOENT)?;
        match node {
            InMemNode::File { uid: u, gid: g, .. }
            | InMemNode::Directory { uid: u, gid: g, .. }
            | InMemNode::Symlink { uid: u, gid: g, .. } => {
                if let Some(uid) = uid {
                    *u = uid;
                }
                if let Some(gid) = gid {
                    *g = gid;
                }
            }
        }
        Ok(())
    }

    fn set_times(
        &self,
        path: &str,
        _atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
        _nofollow: bool,
    ) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let norm = normalize_path(path);
        let mut nodes = self.nodes.write();
        let node = nodes.get_mut(&norm).ok_or(LINUX_ENOENT)?;
        if let Some((secs, _)) = mtime {
            match node {
                InMemNode::File { mtime_secs: m, .. }
                | InMemNode::Directory { mtime_secs: m, .. }
                | InMemNode::Symlink { mtime_secs: m, .. } => *m = secs,
            }
        }
        Ok(())
    }

    fn truncate(&mut self, path: &str, len: u64) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        if len as usize > self.max_file_size {
            return Err(LINUX_EFBIG);
        }
        let norm = normalize_path(path);
        let nodes = self.nodes.read();
        match nodes.get(&norm) {
            Some(InMemNode::File { contents, .. }) => {
                let mut data = contents.write();
                let len = len as usize;
                if len > data.len() {
                    data.resize(len, 0);
                } else {
                    data.truncate(len);
                }
                Ok(())
            }
            Some(InMemNode::Directory { .. }) => Err(LINUX_EISDIR),
            Some(InMemNode::Symlink { .. }) => Err(LINUX_EINVAL),
            None => Err(LINUX_ENOENT),
        }
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>, VfsError> {
        self.read_file_bytes(path)
    }
}

// ============================================================================
// LayeredVfs
// ============================================================================

/// Multi-layer VFS composition.
///
/// # Explicit Per-Operation Fall-Through Policy
///
/// * **`lookup` / `lookup_nofollow` / `real_stat`**:
///   Queries layers in top-to-bottom order (index 0 down to `layers.len() - 1`).
///   Returns the first `Ok(metadata)`.
///   Falls through on `ENOENT` or `ENOSYS`.
///   Any other error (e.g. `EACCES`, `ENOTDIR`) halts traversal and is returned immediately.
///   If all layers report `ENOENT`/`ENOSYS`, returns `ENOENT`.
///
/// * **`readlink`**:
///   Queries layers top-to-bottom.
///   Returns the first `Ok(target)`.
///   Falls through on `ENOENT`, `ENOSYS`, or `EINVAL` (path is not a symlink on that layer).
///   Returns `ENOENT` if no layer contains a symlink at the path.
///
/// * **`readdir` / `readdir_bounded`**:
///   Scans ALL layers that recognize `path` as a directory and merges their entries.
///   Entries from upper layers take precedence over lower layers for identical entry names.
///   If at least one layer yields directory entries, returns the merged set.
///   If all layers return `ENOENT` or `ENOSYS`, returns `ENOENT`.
///   If any layer returns `ENOTDIR` when upper layers found nothing, returns `ENOTDIR`.
///
/// * **`open`**:
///   - **Read-only opens** (neither `write`, `create`, nor `trunc` requested):
///     Queries layers top-to-bottom. Returns the first `Ok(handle)`.
///     Falls through on `ENOENT` or `ENOSYS`. Any other error halts and returns.
///   - **Mutating / write opens** (`write`, `create`, or `trunc` requested):
///     Targets the top layer (layer 0) exclusively.
///     If the top layer is read-only (`EROFS`), returns `EROFS` without falling through
///     to lower layers (avoiding silent corruption/divergence).
///     If `create` is requested, invokes `open` on the top layer.
///
/// * **Mutating operations** (`mkdir`, `unlink`, `rmdir`, `rename`, `symlink`, `link`,
///   `chmod`, `chown`, `set_times`, `truncate`, `create_socket`):
///   All mutations are dispatched strictly to the top layer (`layers[0]`).
///   If the top layer is read-only, returns `EROFS`.
///   Cross-layer rename/link across different underlying filesystems returns `EXDEV`.
///
/// * **`read_file`**:
///   Queries layers top-to-bottom and returns the first `Ok(bytes)`.
///
/// # Whiteout Handling & Deletion Semantics
///
/// `LayeredVfs` does **not** implement whiteout markers (such as `.wh.` files or `0/0` character
/// devices) upon unlinking or removing entries that exist in lower layers. An `unlink` or `rmdir`
/// operation is dispatched directly to the uppermost layer (`layers[0]`). If the path existed on
/// layer 0, it is removed from layer 0; any entry at the same path in an underlying layer (layer 1..N)
/// will remain intact and will become visible to subsequent `lookup` and `readdir` calls.
///
/// # Metadata Ownership
///
/// Attribute metadata (permissions, UID, GID, timestamps, size) is **non-coalesced**.
/// Lookups return the exact metadata reported by the first layer containing the target entry,
/// without attribute inheritance or merging from lower layers.
pub struct LayeredVfs {
    layers: Vec<Box<dyn Vfs>>,
}

impl LayeredVfs {
    /// Create a new layered filesystem with layers ordered top-to-bottom.
    /// Layer index 0 is the upper-most / highest priority layer.
    pub fn new(layers: Vec<Box<dyn Vfs>>) -> Self {
        Self { layers }
    }
}

impl Vfs for LayeredVfs {
    fn name(&self) -> &'static str {
        "layered-vfs"
    }

    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        let mut last_err = LINUX_ENOENT;
        for layer in &self.layers {
            match layer.lookup(path) {
                Ok(meta) => return Ok(meta),
                Err(e) if e == LINUX_ENOENT || e == LINUX_ENOSYS => {
                    last_err = e;
                }
                Err(e) => return Err(e),
            }
        }
        Err(if last_err == LINUX_ENOSYS {
            LINUX_ENOENT
        } else {
            last_err
        })
    }

    fn lookup_nofollow(&self, path: &str) -> Result<Metadata, VfsError> {
        let mut last_err = LINUX_ENOENT;
        for layer in &self.layers {
            match layer.lookup_nofollow(path) {
                Ok(meta) => return Ok(meta),
                Err(e) if e == LINUX_ENOENT || e == LINUX_ENOSYS => {
                    last_err = e;
                }
                Err(e) => return Err(e),
            }
        }
        Err(if last_err == LINUX_ENOSYS {
            LINUX_ENOENT
        } else {
            last_err
        })
    }

    fn real_stat(&self, path: &str, follow: bool) -> Option<carrick_runtime::fs_backend::RealStat> {
        for layer in &self.layers {
            if let Some(stat) = layer.real_stat(path, follow) {
                return Some(stat);
            }
        }
        None
    }

    fn readlink(&self, path: &str) -> Result<PathBuf, VfsError> {
        for layer in &self.layers {
            match layer.readlink(path) {
                Ok(target) => return Ok(target),
                Err(e) if e == LINUX_ENOENT || e == LINUX_ENOSYS || e == LINUX_EINVAL => {}
                Err(e) => return Err(e),
            }
        }
        Err(LINUX_ENOENT)
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEnt>, VfsError> {
        let mut merged = BTreeMap::new();
        let mut found_dir = false;
        let mut last_err = LINUX_ENOENT;

        for layer in &self.layers {
            match layer.readdir(path) {
                Ok(entries) => {
                    found_dir = true;
                    for ent in entries {
                        merged.entry(ent.name.clone()).or_insert(ent);
                    }
                }
                Err(e) if e == LINUX_ENOENT || e == LINUX_ENOSYS => {
                    last_err = e;
                }
                Err(e) => {
                    if !found_dir {
                        return Err(e);
                    }
                }
            }
        }

        if found_dir {
            Ok(merged.into_values().collect())
        } else {
            Err(if last_err == LINUX_ENOSYS {
                LINUX_ENOENT
            } else {
                last_err
            })
        }
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        if self.layers.is_empty() {
            return Err(LINUX_ENOENT);
        }

        // Mutation/write opens target the top-most layer exclusively.
        if flags.write || flags.create || flags.trunc {
            return self.layers[0].open(path, flags, ctx);
        }

        // Read-only opens fall through from top to bottom.
        let mut last_err = LINUX_ENOENT;
        for layer in &self.layers {
            match layer.open(path, flags, ctx) {
                Ok(handle) => return Ok(handle),
                Err(e) if e == LINUX_ENOENT || e == LINUX_ENOSYS => {
                    last_err = e;
                }
                Err(e) => return Err(e),
            }
        }
        Err(if last_err == LINUX_ENOSYS {
            LINUX_ENOENT
        } else {
            last_err
        })
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        if self.layers.is_empty() {
            return Err(LINUX_EROFS);
        }
        self.layers[0].mkdir(path, mode)
    }

    fn unlink(&self, path: &str) -> Result<(), VfsError> {
        if self.layers.is_empty() {
            return Err(LINUX_EROFS);
        }
        self.layers[0].unlink(path)
    }

    fn rmdir(&self, path: &str) -> Result<(), VfsError> {
        if self.layers.is_empty() {
            return Err(LINUX_EROFS);
        }
        self.layers[0].rmdir(path)
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), VfsError> {
        if self.layers.is_empty() {
            return Err(LINUX_EROFS);
        }
        self.layers[0].rename(from, to)
    }

    fn symlink(&self, target: &str, link: &str) -> Result<(), VfsError> {
        if self.layers.is_empty() {
            return Err(LINUX_EROFS);
        }
        self.layers[0].symlink(target, link)
    }

    fn link(&self, from: &str, to: &str) -> Result<(), VfsError> {
        if self.layers.is_empty() {
            return Err(LINUX_EROFS);
        }
        self.layers[0].link(from, to)
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        if self.layers.is_empty() {
            return Err(LINUX_EROFS);
        }
        self.layers[0].chmod(path, mode)
    }

    fn chown(
        &self,
        path: &str,
        uid: Option<NsUid>,
        gid: Option<NsGid>,
        nofollow: bool,
    ) -> Result<(), VfsError> {
        if self.layers.is_empty() {
            return Err(LINUX_EROFS);
        }
        self.layers[0].chown(path, uid, gid, nofollow)
    }

    fn set_times(
        &self,
        path: &str,
        atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
        nofollow: bool,
    ) -> Result<(), VfsError> {
        if self.layers.is_empty() {
            return Err(LINUX_EROFS);
        }
        self.layers[0].set_times(path, atime, mtime, nofollow)
    }

    fn truncate(&mut self, path: &str, len: u64) -> Result<(), VfsError> {
        if self.layers.is_empty() {
            return Err(LINUX_EROFS);
        }
        self.layers[0].truncate(path, len)
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>, VfsError> {
        for layer in &self.layers {
            match layer.read_file(path) {
                Ok(bytes) => return Ok(bytes),
                Err(e) if e == LINUX_ENOENT || e == LINUX_ENOSYS => {}
                Err(e) => return Err(e),
            }
        }
        Err(LINUX_ENOENT)
    }
}

// ============================================================================
// FilterVfs
// ============================================================================

pub type PathRewriteFn = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;
pub type AccessFilterFn = Box<dyn Fn(&str, &OpenFlags) -> Result<(), LinuxErrno> + Send + Sync>;
pub type ContentFilterFn = Box<dyn Fn(&str, Vec<u8>) -> Vec<u8> + Send + Sync>;
pub type MetadataFilterFn = Box<dyn Fn(&str, Metadata) -> Metadata + Send + Sync>;

/// VFS decorator that filters and transforms path resolution, access control,
/// file metadata, and file content.
pub struct FilterVfs {
    inner: Box<dyn Vfs>,
    readonly: bool,
    path_rewriter: Option<PathRewriteFn>,
    access_filter: Option<AccessFilterFn>,
    content_filter: Option<ContentFilterFn>,
    metadata_filter: Option<MetadataFilterFn>,
}

impl FilterVfs {
    /// Wrap an inner VFS with a filter.
    pub fn new(inner: Box<dyn Vfs>) -> Self {
        Self {
            inner,
            readonly: false,
            path_rewriter: None,
            access_filter: None,
            content_filter: None,
            metadata_filter: None,
        }
    }

    /// Enforce read-only access on the filtered filesystem.
    pub fn readonly(mut self, ro: bool) -> Self {
        self.readonly = ro;
        self
    }

    /// Rewrite paths before handing them to the inner VFS.
    /// If the closure returns `None`, access to that path is blocked (`ENOENT`).
    pub fn with_path_rewrite<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Option<String> + Send + Sync + 'static,
    {
        self.path_rewriter = Some(Box::new(f));
        self
    }

    /// Filter open access based on path and open flags.
    pub fn with_access_filter<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, &OpenFlags) -> Result<(), LinuxErrno> + Send + Sync + 'static,
    {
        self.access_filter = Some(Box::new(f));
        self
    }

    /// Transform bytes returned from `read_file` or `VfsHandle::Bytes`.
    pub fn with_content_filter<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, Vec<u8>) -> Vec<u8> + Send + Sync + 'static,
    {
        self.content_filter = Some(Box::new(f));
        self
    }

    /// Modify file/directory metadata returned from `lookup` / `lookup_nofollow`.
    pub fn with_metadata_filter<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, Metadata) -> Metadata + Send + Sync + 'static,
    {
        self.metadata_filter = Some(Box::new(f));
        self
    }

    fn map_path<'a>(&'a self, path: &'a str) -> Result<std::borrow::Cow<'a, str>, LinuxErrno> {
        if let Some(rewriter) = &self.path_rewriter {
            match (rewriter)(path) {
                Some(mapped) => Ok(std::borrow::Cow::Owned(mapped)),
                None => Err(LINUX_ENOENT),
            }
        } else {
            Ok(std::borrow::Cow::Borrowed(path))
        }
    }
}

impl Vfs for FilterVfs {
    fn name(&self) -> &'static str {
        "filter-vfs"
    }

    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        let mapped = self.map_path(path)?;
        let mut meta = self.inner.lookup(&mapped)?;
        if let Some(filter) = &self.metadata_filter {
            meta = (filter)(path, meta);
        }
        Ok(meta)
    }

    fn lookup_nofollow(&self, path: &str) -> Result<Metadata, VfsError> {
        let mapped = self.map_path(path)?;
        let mut meta = self.inner.lookup_nofollow(&mapped)?;
        if let Some(filter) = &self.metadata_filter {
            meta = (filter)(path, meta);
        }
        Ok(meta)
    }

    fn real_stat(&self, path: &str, follow: bool) -> Option<carrick_runtime::fs_backend::RealStat> {
        let mapped = self.map_path(path).ok()?;
        self.inner.real_stat(&mapped, follow)
    }

    fn readlink(&self, path: &str) -> Result<PathBuf, VfsError> {
        let mapped = self.map_path(path)?;
        self.inner.readlink(&mapped)
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEnt>, VfsError> {
        let mapped = self.map_path(path)?;
        self.inner.readdir(&mapped)
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        if self.readonly && flags.write {
            return Err(LINUX_EROFS);
        }
        if let Some(access) = &self.access_filter {
            (access)(path, &flags)?;
        }
        let mapped = self.map_path(path)?;
        let mut handle = self.inner.open(&mapped, flags, ctx)?;
        if let Some(filter) = &self.content_filter
            && let VfsHandle::Bytes {
                path: p,
                contents,
                status_flags,
            } = handle
        {
            let transformed = (filter)(&p, contents);
            handle = VfsHandle::Bytes {
                path: p,
                contents: transformed,
                status_flags,
            };
        }
        Ok(handle)
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let mapped = self.map_path(path)?;
        self.inner.mkdir(&mapped, mode)
    }

    fn unlink(&self, path: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let mapped = self.map_path(path)?;
        self.inner.unlink(&mapped)
    }

    fn rmdir(&self, path: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let mapped = self.map_path(path)?;
        self.inner.rmdir(&mapped)
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let mapped_from = self.map_path(from)?;
        let mapped_to = self.map_path(to)?;
        self.inner.rename(&mapped_from, &mapped_to)
    }

    fn symlink(&self, target: &str, link: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let mapped_link = self.map_path(link)?;
        self.inner.symlink(target, &mapped_link)
    }

    fn link(&self, from: &str, to: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let mapped_from = self.map_path(from)?;
        let mapped_to = self.map_path(to)?;
        self.inner.link(&mapped_from, &mapped_to)
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let mapped = self.map_path(path)?;
        self.inner.chmod(&mapped, mode)
    }

    fn chown(
        &self,
        path: &str,
        uid: Option<NsUid>,
        gid: Option<NsGid>,
        nofollow: bool,
    ) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let mapped = self.map_path(path)?;
        self.inner.chown(&mapped, uid, gid, nofollow)
    }

    fn set_times(
        &self,
        path: &str,
        atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
        nofollow: bool,
    ) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let mapped = self.map_path(path)?;
        self.inner.set_times(&mapped, atime, mtime, nofollow)
    }

    fn truncate(&mut self, path: &str, len: u64) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let mapped = self.map_path(path)?.into_owned();
        self.inner.truncate(&mapped, len)
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>, VfsError> {
        let mapped = self.map_path(path)?;
        let mut bytes = self.inner.read_file(&mapped)?;
        if let Some(filter) = &self.content_filter {
            bytes = (filter)(path, bytes);
        }
        Ok(bytes)
    }
}

// ============================================================================
// RecordingVfs
// ============================================================================

/// Operation kind for a recorded VFS call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VfsOp {
    Lookup,
    LookupNofollow,
    Readlink,
    Readdir,
    Open { flags: OpenFlags },
    WatchFd,
    Mkdir { mode: u32 },
    Unlink,
    Rmdir,
    Rename { to: String },
    Symlink { target: String },
    Link { to: String },
    Chmod { mode: u32 },
    Chown,
    SetTimes,
    Truncate { len: u64 },
    ReadFile,
}

/// A recorded event summarizing a VFS call and its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfsEvent {
    pub op: VfsOp,
    pub path: String,
    pub result: Result<VfsOpOutcome, LinuxErrno>,
}

/// Summary outcome of a recorded VFS call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VfsOpOutcome {
    Lookup(Metadata),
    Readlink(PathBuf),
    Readdir(usize),
    Open(VfsHandleKind),
    ReadFile(usize),
    Unit,
}

/// Discriminant of a returned `VfsHandle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsHandleKind {
    HostFd,
    SyntheticDevice,
    Bytes,
    Pty,
    Directory,
    InMemoryFile,
}

impl From<&VfsHandle> for VfsHandleKind {
    fn from(h: &VfsHandle) -> Self {
        match h {
            VfsHandle::HostFd { .. } => Self::HostFd,
            VfsHandle::SyntheticDevice { .. } => Self::SyntheticDevice,
            VfsHandle::Bytes { .. } => Self::Bytes,
            VfsHandle::Pty { .. } => Self::Pty,
            VfsHandle::Directory { .. } => Self::Directory,
            VfsHandle::InMemoryFile { .. } => Self::InMemoryFile,
        }
    }
}

struct RecordingState {
    events: VecDeque<VfsEvent>,
    capacity: usize,
    dropped: usize,
}

/// Transparent recording decorator for any `Vfs` instance.
///
/// Captures a bounded log of operations with drop counters.
/// **Strictly errno-transparent**: wrapping an inner VFS does not alter any
/// returned errno or mutation behavior.
pub struct RecordingVfs {
    inner: Box<dyn Vfs>,
    state: Arc<Mutex<RecordingState>>,
}

impl RecordingVfs {
    /// Wrap `inner` with a recording log capped at `capacity` events.
    pub fn new(inner: Box<dyn Vfs>, capacity: usize) -> Self {
        Self {
            inner,
            state: Arc::new(Mutex::new(RecordingState {
                events: VecDeque::with_capacity(capacity.min(1024)),
                capacity,
                dropped: 0,
            })),
        }
    }

    /// Retrieve all recorded events currently in the buffer.
    pub fn events(&self) -> Vec<VfsEvent> {
        self.state.lock().events.iter().cloned().collect()
    }

    /// Count of events dropped due to capacity exhaustion.
    pub fn dropped_count(&self) -> usize {
        self.state.lock().dropped
    }

    /// Clear recorded events and reset drop count.
    pub fn clear(&self) {
        let mut state = self.state.lock();
        state.events.clear();
        state.dropped = 0;
    }

    /// Capacity limit of the event buffer.
    pub fn capacity(&self) -> usize {
        self.state.lock().capacity
    }

    fn record(&self, event: VfsEvent) {
        let mut state = self.state.lock();
        if state.events.len() >= state.capacity {
            state.events.pop_front();
            state.dropped += 1;
        }
        state.events.push_back(event);
    }
}

impl Vfs for RecordingVfs {
    fn name(&self) -> &'static str {
        "recording-vfs"
    }

    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        let res = self.inner.lookup(path);
        self.record(VfsEvent {
            op: VfsOp::Lookup,
            path: path.to_string(),
            result: res.clone().map(VfsOpOutcome::Lookup),
        });
        res
    }

    fn lookup_nofollow(&self, path: &str) -> Result<Metadata, VfsError> {
        let res = self.inner.lookup_nofollow(path);
        self.record(VfsEvent {
            op: VfsOp::LookupNofollow,
            path: path.to_string(),
            result: res.clone().map(VfsOpOutcome::Lookup),
        });
        res
    }

    fn real_stat(&self, path: &str, follow: bool) -> Option<carrick_runtime::fs_backend::RealStat> {
        self.inner.real_stat(path, follow)
    }

    fn readlink(&self, path: &str) -> Result<PathBuf, VfsError> {
        let res = self.inner.readlink(path);
        self.record(VfsEvent {
            op: VfsOp::Readlink,
            path: path.to_string(),
            result: res.clone().map(VfsOpOutcome::Readlink),
        });
        res
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEnt>, VfsError> {
        let res = self.inner.readdir(path);
        self.record(VfsEvent {
            op: VfsOp::Readdir,
            path: path.to_string(),
            result: res
                .as_ref()
                .map(|v| VfsOpOutcome::Readdir(v.len()))
                .map_err(|e| *e),
        });
        res
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        let res = self.inner.open(path, flags, ctx);
        self.record(VfsEvent {
            op: VfsOp::Open { flags },
            path: path.to_string(),
            result: res
                .as_ref()
                .map(|h| VfsOpOutcome::Open(VfsHandleKind::from(h)))
                .map_err(|e| *e),
        });
        res
    }

    fn watch_fd(&self, path: &str) -> Result<i32, VfsError> {
        let res = self.inner.watch_fd(path);
        self.record(VfsEvent {
            op: VfsOp::WatchFd,
            path: path.to_string(),
            result: res.map(|_| VfsOpOutcome::Unit),
        });
        res
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        let res = self.inner.mkdir(path, mode);
        self.record(VfsEvent {
            op: VfsOp::Mkdir { mode },
            path: path.to_string(),
            result: res.map(|_| VfsOpOutcome::Unit),
        });
        res
    }

    fn unlink(&self, path: &str) -> Result<(), VfsError> {
        let res = self.inner.unlink(path);
        self.record(VfsEvent {
            op: VfsOp::Unlink,
            path: path.to_string(),
            result: res.map(|_| VfsOpOutcome::Unit),
        });
        res
    }

    fn rmdir(&self, path: &str) -> Result<(), VfsError> {
        let res = self.inner.rmdir(path);
        self.record(VfsEvent {
            op: VfsOp::Rmdir,
            path: path.to_string(),
            result: res.map(|_| VfsOpOutcome::Unit),
        });
        res
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), VfsError> {
        let res = self.inner.rename(from, to);
        self.record(VfsEvent {
            op: VfsOp::Rename { to: to.to_string() },
            path: from.to_string(),
            result: res.map(|_| VfsOpOutcome::Unit),
        });
        res
    }

    fn symlink(&self, target: &str, link: &str) -> Result<(), VfsError> {
        let res = self.inner.symlink(target, link);
        self.record(VfsEvent {
            op: VfsOp::Symlink {
                target: target.to_string(),
            },
            path: link.to_string(),
            result: res.map(|_| VfsOpOutcome::Unit),
        });
        res
    }

    fn link(&self, from: &str, to: &str) -> Result<(), VfsError> {
        let res = self.inner.link(from, to);
        self.record(VfsEvent {
            op: VfsOp::Link { to: to.to_string() },
            path: from.to_string(),
            result: res.map(|_| VfsOpOutcome::Unit),
        });
        res
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        let res = self.inner.chmod(path, mode);
        self.record(VfsEvent {
            op: VfsOp::Chmod { mode },
            path: path.to_string(),
            result: res.map(|_| VfsOpOutcome::Unit),
        });
        res
    }

    fn chown(
        &self,
        path: &str,
        uid: Option<NsUid>,
        gid: Option<NsGid>,
        nofollow: bool,
    ) -> Result<(), VfsError> {
        let res = self.inner.chown(path, uid, gid, nofollow);
        self.record(VfsEvent {
            op: VfsOp::Chown,
            path: path.to_string(),
            result: res.map(|_| VfsOpOutcome::Unit),
        });
        res
    }

    fn set_times(
        &self,
        path: &str,
        atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
        nofollow: bool,
    ) -> Result<(), VfsError> {
        let res = self.inner.set_times(path, atime, mtime, nofollow);
        self.record(VfsEvent {
            op: VfsOp::SetTimes,
            path: path.to_string(),
            result: res.map(|_| VfsOpOutcome::Unit),
        });
        res
    }

    fn truncate(&mut self, path: &str, len: u64) -> Result<(), VfsError> {
        let res = self.inner.truncate(path, len);
        self.record(VfsEvent {
            op: VfsOp::Truncate { len },
            path: path.to_string(),
            result: res.map(|_| VfsOpOutcome::Unit),
        });
        res
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>, VfsError> {
        let res = self.inner.read_file(path);
        self.record(VfsEvent {
            op: VfsOp::ReadFile,
            path: path.to_string(),
            result: res
                .as_ref()
                .map(|v| VfsOpOutcome::ReadFile(v.len()))
                .map_err(|e| *e),
        });
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_abi::LINUX_EACCES;

    #[test]
    fn in_memory_file_vfs_basic_crud() {
        let vfs = InMemoryFileVfs::new();
        vfs.add_dir("/test").unwrap();
        vfs.add_file("/test/hello.txt", b"hello world").unwrap();

        let meta = vfs.lookup("/test/hello.txt").unwrap();
        assert_eq!(meta.kind, EntryKind::File);
        assert_eq!(meta.size, 11);

        let bytes = vfs.read_file_bytes("/test/hello.txt").unwrap();
        assert_eq!(bytes, b"hello world");

        let text = vfs.read_file_string("/test/hello.txt").unwrap();
        assert_eq!(text, "hello world");

        let entries = vfs.readdir("/test").unwrap();
        assert!(entries.iter().any(|e| e.name == "hello.txt"));

        // Open and mutate
        let open_flags = OpenFlags {
            read: true,
            write: true,
            create: false,
            excl: false,
            trunc: false,
            append: false,
            directory: false,
            nofollow: false,
            nonblock: false,
            cloexec: false,
            mode: 0o644,
        };
        let ctx = OpenContext::default();
        let handle = vfs.open("/test/hello.txt", open_flags, &ctx).unwrap();
        match handle {
            VfsHandle::InMemoryFile {
                contents, writable, ..
            } => {
                assert!(writable);
                contents.write().extend_from_slice(b" extra");
            }
            other => panic!("expected InMemoryFile, got {other:?}"),
        }

        assert_eq!(
            vfs.read_file_string("/test/hello.txt").unwrap(),
            "hello world extra"
        );
        let written = vfs.written_files();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].0, "/test/hello.txt");
        assert_eq!(written[0].1, b"hello world extra");
    }

    #[test]
    fn in_memory_file_vfs_readonly_rejects_mutations() {
        let vfs = InMemoryFileVfs::new().readonly(true);
        assert_eq!(vfs.mkdir("/abc", 0o755).unwrap_err(), LINUX_EROFS);
        assert_eq!(vfs.unlink("/test").unwrap_err(), LINUX_EROFS);
        assert_eq!(vfs.rmdir("/test").unwrap_err(), LINUX_EROFS);
        assert_eq!(vfs.rename("/a", "/b").unwrap_err(), LINUX_EROFS);
        assert_eq!(vfs.chmod("/a", 0o644).unwrap_err(), LINUX_EROFS);
    }

    #[test]
    fn layered_vfs_lookup_and_readdir_merging() {
        let lower = InMemoryFileVfs::new();
        lower.add_dir("/data").unwrap();
        lower.add_file("/data/base.txt", b"base").unwrap();
        lower.add_file("/data/shared.txt", b"shared-lower").unwrap();

        let upper = InMemoryFileVfs::new();
        upper.add_dir("/data").unwrap();
        upper.add_file("/data/override.txt", b"override").unwrap();
        upper.add_file("/data/shared.txt", b"shared-upper").unwrap();

        let layered = LayeredVfs::new(vec![Box::new(upper), Box::new(lower)]);

        assert_eq!(layered.read_file("/data/base.txt").unwrap(), b"base");
        assert_eq!(
            layered.read_file("/data/override.txt").unwrap(),
            b"override"
        );
        assert_eq!(
            layered.read_file("/data/shared.txt").unwrap(),
            b"shared-upper"
        );

        let entries = layered.readdir("/data").unwrap();
        let names: Vec<String> = entries.into_iter().map(|e| e.name).collect();
        assert!(names.contains(&"base.txt".to_string()));
        assert!(names.contains(&"override.txt".to_string()));
        assert!(names.contains(&"shared.txt".to_string()));
        // Ensure no duplicate entry for shared.txt
        assert_eq!(names.iter().filter(|&n| n == "shared.txt").count(), 1);
    }

    #[test]
    fn filter_vfs_path_rewrite_and_access() {
        let base = InMemoryFileVfs::new();
        base.add_file("/secret/conf.json", b"{\"key\":\"123\"}")
            .unwrap();

        let filtered = FilterVfs::new(Box::new(base))
            .with_path_rewrite(|path| {
                if path == "/public/conf.json" {
                    Some("/secret/conf.json".to_string())
                } else if path.starts_with("/secret") {
                    None // hide secret
                } else {
                    Some(path.to_string())
                }
            })
            .with_access_filter(|path, flags| {
                if path == "/public/conf.json" && flags.write {
                    Err(LINUX_EACCES)
                } else {
                    Ok(())
                }
            });

        // /secret is hidden
        assert_eq!(
            filtered.lookup("/secret/conf.json").unwrap_err(),
            LINUX_ENOENT
        );
        // /public maps to /secret
        assert_eq!(
            filtered.read_file("/public/conf.json").unwrap(),
            b"{\"key\":\"123\"}"
        );

        // Writable open fails with EACCES from filter
        let flags = OpenFlags {
            read: true,
            write: true,
            create: false,
            excl: false,
            trunc: false,
            append: false,
            directory: false,
            nofollow: false,
            nonblock: false,
            cloexec: false,
            mode: 0,
        };
        let ctx = OpenContext::default();
        assert_eq!(
            filtered.open("/public/conf.json", flags, &ctx).unwrap_err(),
            LINUX_EACCES
        );
    }

    #[test]
    fn recording_vfs_traces_operations_and_preserves_errno() {
        let base = InMemoryFileVfs::new();
        base.add_file("/foo.txt", b"foo").unwrap();

        let recording = RecordingVfs::new(Box::new(base), 3);
        assert_eq!(recording.capacity(), 3);

        assert!(recording.lookup("/foo.txt").is_ok());
        assert_eq!(recording.lookup("/bar.txt").unwrap_err(), LINUX_ENOENT);
        assert!(recording.read_file("/foo.txt").is_ok());

        let events = recording.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].op, VfsOp::Lookup);
        assert_eq!(events[0].path, "/foo.txt");
        assert!(events[0].result.is_ok());

        assert_eq!(events[1].op, VfsOp::Lookup);
        assert_eq!(events[1].path, "/bar.txt");
        assert_eq!(events[1].result, Err(LINUX_ENOENT));

        assert_eq!(events[2].op, VfsOp::ReadFile);
        assert_eq!(events[2].path, "/foo.txt");

        // Exceed capacity and test dropped count
        assert_eq!(recording.lookup("/baz.txt").unwrap_err(), LINUX_ENOENT);
        assert_eq!(recording.dropped_count(), 1);
        assert_eq!(recording.events().len(), 3);

        recording.clear();
        assert_eq!(recording.dropped_count(), 0);
        assert!(recording.events().is_empty());
    }

    #[test]
    fn in_memory_file_vfs_truncation_and_capacity() {
        let mut vfs = InMemoryFileVfs::new().max_file_size(20);
        vfs.add_file("/test.bin", b"12345").unwrap();

        // Truncate expand with zero-fill
        vfs.truncate("/test.bin", 10).unwrap();
        let bytes = vfs.read_file_bytes("/test.bin").unwrap();
        assert_eq!(bytes.len(), 10);
        assert_eq!(&bytes[..5], b"12345");
        assert_eq!(&bytes[5..], &[0; 5]);

        // Truncate shrink
        vfs.truncate("/test.bin", 3).unwrap();
        assert_eq!(vfs.read_file_bytes("/test.bin").unwrap(), b"123");

        // Exceed max_file_size returns EFBIG
        assert_eq!(vfs.truncate("/test.bin", 21).unwrap_err(), LINUX_EFBIG);
    }

    #[test]
    fn in_memory_file_vfs_symlinks_and_directory_ops() {
        let vfs = InMemoryFileVfs::new();
        vfs.add_dir("/dir/nested").unwrap();
        vfs.add_file("/dir/nested/target.txt", b"secret payload")
            .unwrap();

        // Relative symlink
        vfs.add_symlink("/dir/link_rel", "nested/target.txt")
            .unwrap();
        assert_eq!(
            vfs.read_file_bytes("/dir/link_rel").unwrap(),
            b"secret payload"
        );

        // Absolute symlink
        vfs.add_symlink("/link_abs", "/dir/nested/target.txt")
            .unwrap();
        assert_eq!(vfs.read_file_bytes("/link_abs").unwrap(), b"secret payload");

        // Symlink loop returns ELOOP
        vfs.add_symlink("/loop1", "/loop2").unwrap();
        vfs.add_symlink("/loop2", "/loop1").unwrap();
        assert_eq!(vfs.lookup("/loop1").unwrap_err(), LINUX_ELOOP);

        // Rename directory with descendants
        vfs.rename("/dir", "/moved_dir").unwrap();
        assert_eq!(
            vfs.read_file_bytes("/moved_dir/nested/target.txt").unwrap(),
            b"secret payload"
        );
        assert_eq!(
            vfs.lookup("/dir/nested/target.txt").unwrap_err(),
            LINUX_ENOENT
        );

        // Rmdir non-empty returns ENOTEMPTY
        assert_eq!(vfs.rmdir("/moved_dir").unwrap_err(), LINUX_ENOTEMPTY);
        // Rmdir root returns EBUSY
        assert_eq!(vfs.rmdir("/").unwrap_err(), LINUX_EBUSY);
    }

    #[test]
    fn layered_vfs_write_dispatch_and_fallthrough_policy() {
        let bottom = InMemoryFileVfs::new();
        bottom.add_file("/shared.txt", b"bottom-shared").unwrap();
        bottom.add_file("/bottom-only.txt", b"bottom").unwrap();

        let top_ro = InMemoryFileVfs::new().readonly(true);
        let layered_ro = LayeredVfs::new(vec![Box::new(top_ro), Box::new(bottom)]);

        // Read-only open falls through to bottom
        let ro_flags = OpenFlags {
            read: true,
            write: false,
            create: false,
            excl: false,
            trunc: false,
            append: false,
            directory: false,
            nofollow: false,
            nonblock: false,
            cloexec: false,
            mode: 0,
        };
        let ctx = OpenContext::default();
        assert!(layered_ro.open("/bottom-only.txt", ro_flags, &ctx).is_ok());

        // Write open strictly targets top layer, which is readonly -> EROFS
        let rw_flags = OpenFlags {
            read: true,
            write: true,
            create: false,
            excl: false,
            trunc: false,
            append: false,
            directory: false,
            nofollow: false,
            nonblock: false,
            cloexec: false,
            mode: 0,
        };
        assert_eq!(
            layered_ro
                .open("/bottom-only.txt", rw_flags, &ctx)
                .unwrap_err(),
            LINUX_EROFS
        );

        // Create open strictly targets top layer -> EROFS
        let create_flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            excl: false,
            trunc: false,
            append: false,
            directory: false,
            nofollow: false,
            nonblock: false,
            cloexec: false,
            mode: 0o644,
        };
        assert_eq!(
            layered_ro
                .open("/new_file.txt", create_flags, &ctx)
                .unwrap_err(),
            LINUX_EROFS
        );
    }

    #[test]
    fn filter_vfs_content_and_metadata_transformation() {
        let base = InMemoryFileVfs::new();
        base.add_file("/data.txt", b"hello world").unwrap();

        let filtered = FilterVfs::new(Box::new(base))
            .with_content_filter(|_path, bytes| {
                bytes.into_iter().map(|b| b.to_ascii_uppercase()).collect()
            })
            .with_metadata_filter(|_path, mut meta| {
                meta.mode = 0o777;
                meta
            });

        assert_eq!(filtered.read_file("/data.txt").unwrap(), b"HELLO WORLD");
        let meta = filtered.lookup("/data.txt").unwrap();
        assert_eq!(meta.mode, 0o777);
    }
}
