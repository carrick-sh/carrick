//! In-memory tmpfs-style filesystem backend.
//!
//! [`MemoryBackend`] stores directories and file contents in memory maps with
//! tombstone sets for deletions. Cheap and ephemeral, ideal for tests and one-shot runs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::fs_backend::path::{child_name, normalize};
use crate::fs_backend::{
    ArchiveMutationGate, BackendError, FsBackend, HostFdOpen, OverlayEntry, OverlayEntryKind,
    SharedFileContents, SharedFileEntry, SharedFileObject,
};
use crate::rootfs::{RootFsEntryKind, RootFsMetadata};

/// In-memory FsBackend: directories and file contents live in maps,
/// deletions are a tombstone set. Cheap, ephemeral, exactly what CI
/// or `cargo test` wants.
type MemoryFile = Arc<SharedFileObject>;

trait MemoryFileExt {
    fn len(&self) -> usize;
    fn mode(&self) -> u32;
    fn to_vec(&self) -> Vec<u8>;
    fn shared_contents(&self) -> SharedFileContents;
    fn write_range(
        &self,
        offset: usize,
        bytes: &[u8],
        final_size: usize,
    ) -> Result<(), BackendError>;
    fn truncate_to_zero(&self);
}

impl MemoryFileExt for MemoryFile {
    fn len(&self) -> usize {
        self.read().len
    }

    fn mode(&self) -> u32 {
        SharedFileObject::mode(self)
    }

    fn to_vec(&self) -> Vec<u8> {
        let state = self.read();
        let mut out = vec![0; state.len];
        let copy_len = state.base.len().min(state.len);
        out[..copy_len].copy_from_slice(&state.base[..copy_len]);
        for (&start, bytes) in &state.dirty {
            if start >= state.len {
                continue;
            }
            let write_len = bytes.len().min(state.len - start);
            out[start..start + write_len].copy_from_slice(&bytes[..write_len]);
        }
        out
    }

    fn shared_contents(&self) -> SharedFileContents {
        self.snapshot()
    }

    fn write_range(
        &self,
        offset: usize,
        bytes: &[u8],
        final_size: usize,
    ) -> Result<(), BackendError> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or(BackendError::Invalid)?;
        if final_size < end {
            return Err(BackendError::Invalid);
        }
        let mut state = self.write();
        state.len = final_size;
        prune_dirty_ranges(&mut state.dirty, final_size);
        insert_dirty_range(&mut state.dirty, offset, bytes)?;
        Ok(())
    }

    fn truncate_to_zero(&self) {
        let mut state = self.write();
        state.base = Arc::<[u8]>::from([]);
        state.dirty.clear();
        state.len = 0;
    }
}

fn prune_dirty_ranges(dirty: &mut BTreeMap<usize, Vec<u8>>, len: usize) {
    let keys: Vec<usize> = dirty.range(len..).map(|(&start, _)| start).collect();
    for key in keys {
        dirty.remove(&key);
    }
    if let Some((&start, bytes)) = dirty.range(..len).next_back() {
        let keep = len.saturating_sub(start);
        if keep < bytes.len()
            && let Some(bytes) = dirty.get_mut(&start)
        {
            bytes.truncate(keep);
        }
    }
}

fn insert_dirty_range(
    dirty: &mut BTreeMap<usize, Vec<u8>>,
    offset: usize,
    bytes: &[u8],
) -> Result<(), BackendError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let end = offset
        .checked_add(bytes.len())
        .ok_or(BackendError::Invalid)?;
    let overlapping: Vec<usize> = dirty
        .range(..end)
        .filter_map(|(&start, existing)| {
            let existing_end = start.checked_add(existing.len())?;
            (existing_end > offset).then_some(start)
        })
        .collect();
    for start in overlapping {
        let Some(existing) = dirty.remove(&start) else {
            continue;
        };
        let existing_end = start
            .checked_add(existing.len())
            .ok_or(BackendError::Invalid)?;
        if start < offset {
            dirty.insert(start, existing[..offset - start].to_vec());
        }
        if existing_end > end {
            dirty.insert(end, existing[end - start..].to_vec());
        }
    }
    dirty.insert(offset, bytes.to_vec());
    Ok(())
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct MemoryBackendState {
    dirs: HashSet<PathBuf>,
    files: HashMap<PathBuf, MemoryFile>,
    deletions: HashSet<PathBuf>,
    /// AF_UNIX socket nodes materialised by `bind(2)` (path → permission bits).
    /// Reported as `RootFsEntryKind::Socket` (S_IFSOCK) by `metadata`; present
    /// (existing, empty) to `lookup`/`lookup_kind`. Bind + chmod + unlink all
    /// happen in the same process, so no cross-fork coherence is required here.
    sockets: HashMap<PathBuf, u32>,
}

/// In-memory FsBackend: directories and file contents live in maps,
/// deletions are a tombstone set. Cheap, ephemeral, exactly what CI
/// or `cargo test` wants.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    inner: RwLock<MemoryBackendState>,
    archive_mutation_gate: ArchiveMutationGate,
    generation: std::sync::atomic::AtomicU64,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Clone for MemoryBackend {
    fn clone(&self) -> Self {
        Self {
            inner: RwLock::new(self.inner.read().clone()),
            archive_mutation_gate: ArchiveMutationGate::default(),
            generation: std::sync::atomic::AtomicU64::new(
                self.generation.load(std::sync::atomic::Ordering::SeqCst),
            ),
        }
    }
}

impl PartialEq for MemoryBackend {
    fn eq(&self, other: &Self) -> bool {
        *self.inner.read() == *other.inner.read()
    }
}

impl Eq for MemoryBackend {}

impl FsBackend for MemoryBackend {
    fn archive_mutation_gate(&self) -> Option<&ArchiveMutationGate> {
        Some(&self.archive_mutation_gate)
    }

    fn lookup(&self, path: &str) -> Option<OverlayEntry> {
        let normalized = normalize(path)?;
        let inner = self.inner.read();
        if inner.deletions.contains(&normalized) {
            return Some(OverlayEntry::Deleted);
        }
        if inner.dirs.contains(&normalized) {
            return Some(OverlayEntry::Dir);
        }
        if let Some(file) = inner.files.get(&normalized) {
            return Some(OverlayEntry::File(file.to_vec()));
        }
        // An AF_UNIX socket node: present, but has no readable bytes. Report it
        // as an empty File-shaped entry so the layered lookup treats the path as
        // existing (the true Socket kind is carried by `metadata`).
        if inner.sockets.contains_key(&normalized) {
            return Some(OverlayEntry::File(Vec::new()));
        }
        None
    }

    fn lookup_kind(&self, path: &str) -> Option<OverlayEntryKind> {
        let normalized = normalize(path)?;
        let inner = self.inner.read();
        if inner.deletions.contains(&normalized) {
            return Some(OverlayEntryKind::Deleted);
        }
        if inner.dirs.contains(&normalized) {
            return Some(OverlayEntryKind::Dir);
        }
        if inner.files.contains_key(&normalized) || inner.sockets.contains_key(&normalized) {
            return Some(OverlayEntryKind::File);
        }
        None
    }

    fn metadata(&self, path: &str) -> Option<RootFsMetadata> {
        let normalized = normalize(path)?;
        let inner = self.inner.read();
        if let Some(&mode) = inner.sockets.get(&normalized) {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::Socket,
                mode: mode & 0o7777,
                size: 0,
            });
        }
        if let Some(file) = inner.files.get(&normalized) {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::File,
                mode: file.mode(),
                size: file.len(),
            });
        }
        if inner.dirs.contains(&normalized) {
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
        self.inner
            .read()
            .files
            .get(&normalized)
            .map(MemoryFile::to_vec)
    }

    fn shared_file_contents(&self, path: &str) -> Option<SharedFileContents> {
        let normalized = normalize(path)?;
        self.inner
            .read()
            .files
            .get(&normalized)
            .map(MemoryFile::shared_contents)
    }

    fn shared_file_entry(&self, path: &str, trunc: bool) -> Option<SharedFileEntry> {
        let normalized = normalize(path)?;
        if trunc {
            let mut inner = self.inner.write();
            if inner.deletions.contains(&normalized)
                || inner.dirs.contains(&normalized)
                || inner.sockets.contains_key(&normalized)
            {
                return None;
            }
            let file = inner.files.get_mut(&normalized)?;
            file.truncate_to_zero();
            let mode = file.mode();
            let contents = file.shared_contents();
            return Some(SharedFileEntry {
                metadata: RootFsMetadata {
                    path: normalized,
                    kind: RootFsEntryKind::File,
                    mode,
                    size: contents.len,
                },
                contents,
                object: Some(Arc::clone(file)),
            });
        }

        let inner = self.inner.read();
        if inner.deletions.contains(&normalized)
            || inner.dirs.contains(&normalized)
            || inner.sockets.contains_key(&normalized)
        {
            return None;
        }
        let file = inner.files.get(&normalized)?;
        let mode = file.mode();
        let contents = file.shared_contents();
        Some(SharedFileEntry {
            metadata: RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::File,
                mode,
                size: contents.len,
            },
            contents,
            object: Some(Arc::clone(file)),
        })
    }

    fn fast_nofollow_metadata(&self, path: &str) -> Option<RootFsMetadata> {
        self.metadata(path)
    }

    fn make_dir(&self, path: &str) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        inner.deletions.remove(&normalized);
        inner.dirs.insert(normalized);
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn create_file(&self, path: &str) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        inner.deletions.remove(&normalized);
        inner
            .files
            .entry(normalized)
            .or_insert_with(|| SharedFileObject::new(Arc::<[u8]>::from([]), 0o644));
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn may_have_fifo_nodes(&self) -> bool {
        false
    }

    fn create_file_from_rootfs(
        &self,
        path: &str,
        contents: Arc<[u8]>,
        mode: u32,
    ) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        inner.deletions.remove(&normalized);
        inner
            .files
            .insert(normalized, SharedFileObject::new(contents, mode));
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn create_socket(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        inner.deletions.remove(&normalized);
        // A bind to an existing path normally fails (EADDRINUSE) — the caller
        // (net.rs bind) only reaches create_socket after a successful host
        // bind, so just record/overwrite the node.
        inner.files.remove(&normalized);
        inner.sockets.insert(normalized, mode & 0o7777);
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn set_mode(&self, path: &str, mode: u32) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        let mode = mode & 0o7777;
        // Socket nodes track a mode directly.
        if let Some(slot) = inner.sockets.get_mut(&normalized) {
            *slot = mode;
            self.generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }
        // A regular file: upgrade its in-memory representation so the mode
        // STICKS (a bare `Dense` has no mode field and reports 0o644). This is
        // what lets a materialized O_TMPFILE (linkat from /proc/self/fd) report
        // its creation mode under `--fs memory`, matching `--fs host` (which
        // chmods the real inode). The contents are preserved verbatim.
        if let Some(existing) = inner.files.get(&normalized) {
            existing.write().mode = mode;
            self.generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }
        // Dirs report a fixed mode; chmod on those stays a tmpfs-no-op success.
        Err(BackendError::Unsupported)
    }

    fn set_file_contents(&self, path: &str, contents: Vec<u8>) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        inner.deletions.remove(&normalized);
        if let Some(existing) = inner.files.get(&normalized) {
            let mut state = existing.write();
            state.len = contents.len();
            state.base = Arc::from(contents);
            state.dirty.clear();
        } else {
            inner.files.insert(
                normalized,
                SharedFileObject::new(Arc::from(contents), 0o644),
            );
        }
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
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
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        if !inner.files.contains_key(&normalized) {
            return Err(BackendError::Unsupported);
        }
        inner.deletions.remove(&normalized);
        let Some(contents) = inner.files.get_mut(&normalized) else {
            return Err(BackendError::Unsupported);
        };
        contents.write_range(offset, bytes, final_size)?;
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn remove_entry(&self, path: &str) -> bool {
        let _mutation = self.archive_mutation_gate.mutation();
        let Some(normalized) = normalize(path) else {
            return false;
        };
        let mut inner = self.inner.write();
        let had_file = inner.files.remove(&normalized).is_some();
        let had_dir = inner.dirs.remove(&normalized);
        let had_socket = inner.sockets.remove(&normalized).is_some();
        let removed = had_file || had_dir || had_socket;
        if removed {
            self.generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        removed
    }

    fn mark_deleted(&self, path: &str) -> Result<(), BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let normalized = normalize(path).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        inner.files.remove(&normalized);
        inner.dirs.remove(&normalized);
        inner.sockets.remove(&normalized);
        inner.deletions.insert(normalized);
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn child_names(&self, dir: &str) -> Vec<(String, RootFsEntryKind, Option<u64>)> {
        self.child_names_bounded(dir, usize::MAX)
            .unwrap_or_default()
    }

    fn child_names_bounded(
        &self,
        dir: &str,
        limit: usize,
    ) -> Result<Vec<(String, RootFsEntryKind, Option<u64>)>, BackendError> {
        let Some(prefix) = normalize(dir) else {
            return Ok(Vec::new());
        };
        let inner = self.inner.read();
        let mut out = Vec::with_capacity(limit.checked_add(1).unwrap_or(0));
        for (path, contents) in inner.files.iter() {
            if let Some(name) = child_name(&prefix, path) {
                out.push((name, RootFsEntryKind::File, Some(contents.len() as u64)));
                if out.len() > limit {
                    return Ok(out);
                }
            }
        }
        for path in inner.sockets.keys() {
            if let Some(name) = child_name(&prefix, path) {
                out.push((name, RootFsEntryKind::Socket, Some(0)));
                if out.len() > limit {
                    return Ok(out);
                }
            }
        }
        for path in inner.dirs.iter() {
            if let Some(name) = child_name(&prefix, path) {
                out.push((name, RootFsEntryKind::Directory, None));
                if out.len() > limit {
                    return Ok(out);
                }
            }
        }
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
        let Some(prefix) = normalize(dir) else {
            return Ok(Vec::new());
        };
        let inner = self.inner.read();
        let mut deleted = Vec::with_capacity(limit.checked_add(1).unwrap_or(0));
        for name in inner
            .deletions
            .iter()
            .filter_map(|path| child_name(&prefix, path))
        {
            deleted.push(name);
            if deleted.len() > limit {
                break;
            }
        }
        Ok(deleted)
    }

    fn rename_overlay_entry(&self, from: &str, to: &str) -> Result<bool, BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let src = normalize(from).ok_or(BackendError::Invalid)?;
        let dst = normalize(to).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        if let Some(contents) = inner.files.remove(&src) {
            inner.deletions.remove(&dst);
            inner.files.insert(dst.clone(), contents);
            inner.deletions.insert(src);
            self.generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Ok(true);
        }
        if inner.dirs.remove(&src) {
            inner.deletions.remove(&dst);
            inner.dirs.insert(dst);
            inner.deletions.insert(src);
            self.generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Ok(true);
        }
        Ok(false)
    }

    fn exchange_overlay_entries(&self, a: &str, b: &str) -> Result<bool, BackendError> {
        let _mutation = self.archive_mutation_gate.mutation();
        let a_norm = normalize(a).ok_or(BackendError::Invalid)?;
        let b_norm = normalize(b).ok_or(BackendError::Invalid)?;
        let mut inner = self.inner.write();
        // Classify each side as a backend-owned file or directory. Anything not
        // present here (rootfs-only, or a tombstone) → Ok(false): the dispatcher
        // must materialise it into the overlay first, then retry.
        #[derive(Clone)]
        enum Slot {
            File(MemoryFile),
            Dir,
        }
        let classify = |state: &MemoryBackendState, p: &PathBuf| -> Option<Slot> {
            if state.deletions.contains(p) {
                return None;
            }
            if let Some(f) = state.files.get(p) {
                return Some(Slot::File(f.clone()));
            }
            if state.dirs.contains(p) {
                return Some(Slot::Dir);
            }
            None
        };
        let (Some(a_slot), Some(b_slot)) = (classify(&inner, &a_norm), classify(&inner, &b_norm))
        else {
            return Ok(false);
        };
        // Remove both, then re-insert each side's payload under the OTHER name.
        // The MemoryFile value carries its own mode + contents, so swapping the
        // values preserves all per-entry metadata.
        inner.files.remove(&a_norm);
        inner.files.remove(&b_norm);
        inner.dirs.remove(&a_norm);
        inner.dirs.remove(&b_norm);
        match a_slot {
            Slot::File(f) => {
                inner.files.insert(b_norm.clone(), f);
            }
            Slot::Dir => {
                inner.dirs.insert(b_norm.clone());
            }
        }
        match b_slot {
            Slot::File(f) => {
                inner.files.insert(a_norm.clone(), f);
            }
            Slot::Dir => {
                inner.dirs.insert(a_norm.clone());
            }
        }
        // Neither name is gone after a swap; clear any stale tombstones.
        inner.deletions.remove(&a_norm);
        inner.deletions.remove(&b_norm);
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(true)
    }

    fn open_raw_fd(
        &self,
        _path: &str,
        _write: bool,
        _create: bool,
        _trunc: bool,
    ) -> HostFdOpen<i32> {
        // No kernel fd backs an in-memory HashMap, and a real
        // libc::fork can't share it. The dispatcher uses its in-memory
        // File model for this backend.
        HostFdOpen::Unavailable
    }

    fn structural_generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn name(&self) -> &'static str {
        "memory"
    }
}

#[cfg(test)]
mod retained_object_tests {
    use super::*;

    fn bytes(object: &SharedFileObject) -> Vec<u8> {
        object.read_all()
    }

    #[test]
    fn retained_object_survives_rename_unlink_and_observes_mutation() {
        let backend = MemoryBackend::new();
        backend
            .set_file_contents("/image", b"old".to_vec())
            .unwrap();
        let entry = backend.shared_file_entry("/image", false).unwrap();
        let object = entry.object.expect("memory entry exposes live object");
        let id = object.object_id();

        assert!(backend.rename_overlay_entry("/image", "/renamed").unwrap());
        backend.write_file_range("/renamed", 0, b"new", 3).unwrap();
        assert_eq!(object.object_id(), id);
        assert_eq!(bytes(&object), b"new");

        assert!(backend.remove_entry("/renamed"));
        assert!(backend.shared_file_entry("/renamed", false).is_none());
        assert_eq!(bytes(&object), b"new", "retained inode outlives its name");
    }

    #[test]
    fn overwrite_preserves_identity_but_recreate_allocates_a_new_object() {
        let backend = MemoryBackend::new();
        backend
            .set_file_contents("/image", b"one".to_vec())
            .unwrap();
        let first = backend
            .shared_file_entry("/image", false)
            .unwrap()
            .object
            .unwrap();

        backend
            .set_file_contents("/image", b"two".to_vec())
            .unwrap();
        let overwritten = backend
            .shared_file_entry("/image", false)
            .unwrap()
            .object
            .unwrap();
        assert!(Arc::ptr_eq(&first, &overwritten));
        assert_eq!(bytes(&first), b"two");

        assert!(backend.remove_entry("/image"));
        backend
            .set_file_contents("/image", b"three".to_vec())
            .unwrap();
        let recreated = backend
            .shared_file_entry("/image", false)
            .unwrap()
            .object
            .unwrap();
        assert_ne!(first.object_id(), recreated.object_id());
        assert_eq!(bytes(&first), b"two");
        assert_eq!(bytes(&recreated), b"three");
    }

    #[test]
    fn retained_object_reads_sparse_dirty_prefix_without_materializing_tail() {
        let backend = MemoryBackend::new();
        backend
            .create_file_from_rootfs("/image", Arc::from(&b"abcdefgh"[..]), 0o755)
            .unwrap();
        backend.write_file_range("/image", 2, b"XY", 12).unwrap();
        backend.write_file_range("/image", 10, b"Z", 12).unwrap();
        let object = backend
            .shared_file_entry("/image", false)
            .unwrap()
            .object
            .unwrap();

        assert_eq!(object.read_prefix(0), b"");
        assert_eq!(object.read_prefix(3), b"abX");
        assert_eq!(object.read_prefix(9), b"abXYefgh\0");
        assert_eq!(object.read_prefix(usize::MAX), object.read_all());
        assert_eq!(object.read_all(), b"abXYefgh\0\0Z\0");

        backend.write_file_range("/image", 0, b"", 4).unwrap();
        assert_eq!(object.read_prefix(256), b"abXY");
        assert_eq!(object.read_all(), b"abXY");
    }
}
