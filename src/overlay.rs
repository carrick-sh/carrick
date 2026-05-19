// In-memory tmpfs-style writable overlay layered on top of the
// read-only OCI rootfs. Modelled after the bookkeeping a real
// overlayfs keeps in its upper directory:
//
//   * `dirs`      — directories the guest created (mkdirat).
//   * `files`     — files the guest opened with O_CREAT or wrote
//                   to. The Vec<u8> is the live contents; updates
//                   from write/writev/ftruncate/pwrite land here.
//   * `deletions` — paths the guest "removed" via unlinkat /
//                   rmdirat / renameat. A path in `deletions`
//                   appears absent even when the underlying rootfs
//                   layer still has it.
//
// Paths are stored without the leading slash so they line up with
// the `RootFs` internal representation (which strips `/` in
// `normalize_rootfs_path`). Look-up helpers accept either form via
// [`normalize`].
//
// The overlay is intentionally a free-standing data structure —
// the dispatcher owns one alongside its `Option<RootFs>` and does
// the layering by hand. That keeps `RootFs` pure (the OCI tarballs
// are an unchanging input) and matches the wording in the task:
// "Add a `WritableOverlay` to `SyscallDispatcher`".

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use crate::rootfs::{RootFs, RootFsDirEntry, RootFsEntryKind, RootFsError, RootFsMetadata};

/// What the overlay knows about a path. `Dir` and `File` are the
/// "exists in overlay" cases; `Deleted` is the negative entry that
/// shadows the rootfs layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayEntry<'a> {
    Dir,
    File(&'a [u8]),
    Deleted,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WritableOverlay {
    dirs: HashSet<PathBuf>,
    files: HashMap<PathBuf, Vec<u8>>,
    deletions: HashSet<PathBuf>,
}

impl WritableOverlay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Strip a leading `/` and collapse `.` / `..` so the overlay's
    /// internal keys match what `RootFs::normalize_rootfs_path` would
    /// produce. Returns `None` for paths that would escape the
    /// rootfs (`/../something`), matching `RootFsError::UnsafePath`.
    pub fn normalize(path: &str) -> Option<PathBuf> {
        let raw = Path::new(path);
        let mut out = PathBuf::new();
        for component in raw.components() {
            match component {
                Component::Prefix(_) => return None,
                Component::RootDir => {}
                Component::CurDir => {}
                Component::ParentDir => {
                    if !out.pop() {
                        return None;
                    }
                }
                Component::Normal(name) => out.push(name),
            }
        }
        Some(out)
    }

    /// Returns the overlay's view of `path`. Callers should consult
    /// this before falling through to the read-only rootfs.
    pub fn lookup<'a>(&'a self, path: &str) -> Option<OverlayEntry<'a>> {
        let Some(normalized) = Self::normalize(path) else {
            return None;
        };
        if self.deletions.contains(&normalized) {
            return Some(OverlayEntry::Deleted);
        }
        if self.dirs.contains(&normalized) {
            return Some(OverlayEntry::Dir);
        }
        if let Some(bytes) = self.files.get(&normalized) {
            return Some(OverlayEntry::File(bytes.as_slice()));
        }
        None
    }

    pub fn is_deleted(&self, path: &str) -> bool {
        matches!(self.lookup(path), Some(OverlayEntry::Deleted))
    }

    /// True iff the overlay can answer "what's at this path?" without
    /// falling through to the rootfs. Equivalent to
    /// `lookup(...).is_some()` but reads better at call sites.
    pub fn shadows(&self, path: &str) -> bool {
        self.lookup(path).is_some()
    }

    pub fn make_dir(&mut self, path: &str) -> Result<(), OverlayError> {
        let normalized = Self::normalize(path).ok_or(OverlayError::Invalid)?;
        self.deletions.remove(&normalized);
        self.dirs.insert(normalized);
        Ok(())
    }

    /// Create a new empty file in the overlay. Used by openat with
    /// O_CREAT.
    pub fn create_file(&mut self, path: &str) -> Result<(), OverlayError> {
        let normalized = Self::normalize(path).ok_or(OverlayError::Invalid)?;
        self.deletions.remove(&normalized);
        self.files.entry(normalized).or_insert_with(Vec::new);
        Ok(())
    }

    /// Replace the contents of `path` in the overlay (used by
    /// `OpenDescription::File::contents` write-back and by `rename`).
    pub fn set_file_contents(&mut self, path: &str, contents: Vec<u8>) -> Result<(), OverlayError> {
        let normalized = Self::normalize(path).ok_or(OverlayError::Invalid)?;
        self.deletions.remove(&normalized);
        self.files.insert(normalized, contents);
        Ok(())
    }

    /// Look up a file's live contents. Returns `None` for directories
    /// and for paths that the overlay doesn't own.
    pub fn file_contents(&self, path: &str) -> Option<&[u8]> {
        let normalized = Self::normalize(path)?;
        self.files.get(&normalized).map(Vec::as_slice)
    }

    /// Remove a path entirely (the overlay-backed case of unlinkat).
    /// Returns true iff the overlay was holding something there.
    pub fn remove_entry(&mut self, path: &str) -> bool {
        let Some(normalized) = Self::normalize(path) else {
            return false;
        };
        let had_file = self.files.remove(&normalized).is_some();
        let had_dir = self.dirs.remove(&normalized);
        had_file || had_dir
    }

    /// Record that `path` has been deleted from the layered view.
    /// Used when unlinkat targets a rootfs-backed entry.
    pub fn mark_deleted(&mut self, path: &str) -> Result<(), OverlayError> {
        let normalized = Self::normalize(path).ok_or(OverlayError::Invalid)?;
        self.files.remove(&normalized);
        self.dirs.remove(&normalized);
        self.deletions.insert(normalized);
        Ok(())
    }

    /// Iterate the names that the overlay contributes to `dir`. The
    /// caller is responsible for merging with the rootfs view and
    /// filtering out any names that are in `deletions`.
    pub fn child_names(&self, dir: &str) -> Vec<(String, RootFsEntryKind)> {
        let Some(prefix) = Self::normalize(dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for path in self.files.keys() {
            if let Some(name) = child_name(&prefix, path) {
                out.push((name, RootFsEntryKind::File));
            }
        }
        for path in self.dirs.iter() {
            if let Some(name) = child_name(&prefix, path) {
                out.push((name, RootFsEntryKind::Directory));
            }
        }
        out
    }

    /// Names in this directory that are tombstoned. The dispatcher
    /// uses this to filter rootfs-supplied entries.
    pub fn deleted_child_names(&self, dir: &str) -> Vec<String> {
        let Some(prefix) = Self::normalize(dir) else {
            return Vec::new();
        };
        self.deletions
            .iter()
            .filter_map(|path| child_name(&prefix, path))
            .collect()
    }

    /// Rename an overlay-backed entry. Returns Ok iff the source
    /// path was present in the overlay; otherwise the caller must
    /// fall back to the rootfs (rootfs-backed renames materialise
    /// the source's contents into the overlay).
    pub fn rename_overlay_entry(
        &mut self,
        from: &str,
        to: &str,
    ) -> Result<bool, OverlayError> {
        let src = Self::normalize(from).ok_or(OverlayError::Invalid)?;
        let dst = Self::normalize(to).ok_or(OverlayError::Invalid)?;
        if let Some(contents) = self.files.remove(&src) {
            self.deletions.remove(&dst);
            self.files.insert(dst.clone(), contents);
            // The source path is now gone from the layered view too.
            self.deletions.insert(src);
            return Ok(true);
        }
        if self.dirs.remove(&src) {
            self.deletions.remove(&dst);
            self.dirs.insert(dst);
            self.deletions.insert(src);
            return Ok(true);
        }
        Ok(false)
    }

    /// Merge `metadata`-style attributes for a path the overlay
    /// owns. Returns `None` when the overlay doesn't have it (caller
    /// falls back to rootfs).
    pub fn metadata(&self, path: &str) -> Option<RootFsMetadata> {
        let normalized = Self::normalize(path)?;
        if let Some(contents) = self.files.get(&normalized) {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::File,
                mode: 0o644,
                size: contents.len(),
            });
        }
        if self.dirs.contains(&normalized) {
            return Some(RootFsMetadata {
                path: normalized,
                kind: RootFsEntryKind::Directory,
                mode: 0o755,
                size: 0,
            });
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayError {
    Invalid,
}

fn child_name(prefix: &Path, candidate: &Path) -> Option<String> {
    let stripped = candidate.strip_prefix(prefix).ok()?;
    let mut components = stripped.components();
    let first = components.next()?;
    if components.next().is_some() {
        return None;
    }
    let Component::Normal(name) = first else {
        return None;
    };
    Some(name.to_string_lossy().into_owned())
}

/// Helper used by `getdents64` and `list_dir`-style call sites:
/// merge overlay child entries with rootfs entries while honouring
/// the overlay's tombstones. Returns entries in stable insertion
/// order (rootfs first, overlay's additions next).
pub fn layered_directory_entries(
    overlay: &WritableOverlay,
    rootfs: Option<&RootFs>,
    dir: &str,
) -> Result<Vec<RootFsDirEntry>, RootFsError> {
    let mut out: Vec<RootFsDirEntry> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let deleted: HashSet<String> = overlay
        .deleted_child_names(dir)
        .into_iter()
        .collect();

    if let Some(rootfs) = rootfs {
        // The rootfs only exposes directory_entries for directories
        // that exist in the underlying layer. The overlay might be
        // the only thing that says "this directory exists" — in that
        // case skip the rootfs lookup entirely.
        match rootfs.directory_entries(dir) {
            Ok(entries) => {
                for entry in entries {
                    if deleted.contains(&entry.name) {
                        continue;
                    }
                    if overlay.shadows(&joined(dir, &entry.name)) {
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

    for (name, kind) in overlay.child_names(dir) {
        if seen.contains(&name) || deleted.contains(&name) {
            continue;
        }
        let path = joined(dir, &name);
        let normalized = WritableOverlay::normalize(&path).unwrap_or_default();
        let metadata = match kind {
            RootFsEntryKind::File => {
                let size = overlay
                    .file_contents(&path)
                    .map(<[u8]>::len)
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
        };
        seen.insert(name.clone());
        out.push(RootFsDirEntry { name, metadata });
    }
    Ok(out)
}

fn joined(base: &str, name: &str) -> String {
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", base.trim_end_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_root_and_collapses_dots() {
        assert_eq!(
            WritableOverlay::normalize("/var/lib/apt/lists/partial"),
            Some(PathBuf::from("var/lib/apt/lists/partial"))
        );
        assert_eq!(
            WritableOverlay::normalize("/var/./lib/../lib/apt"),
            Some(PathBuf::from("var/lib/apt"))
        );
        assert_eq!(WritableOverlay::normalize("/../escape"), None);
    }

    #[test]
    fn make_dir_then_lookup_reports_directory() {
        let mut overlay = WritableOverlay::new();
        overlay.make_dir("/var/lib/apt/lists/partial").unwrap();
        assert!(matches!(
            overlay.lookup("/var/lib/apt/lists/partial"),
            Some(OverlayEntry::Dir)
        ));
        let meta = overlay.metadata("/var/lib/apt/lists/partial").unwrap();
        assert_eq!(meta.kind, RootFsEntryKind::Directory);
    }

    #[test]
    fn create_file_returns_zero_length_file() {
        let mut overlay = WritableOverlay::new();
        overlay.create_file("/tmp/example").unwrap();
        let entry = overlay.lookup("/tmp/example").unwrap();
        match entry {
            OverlayEntry::File(bytes) => assert!(bytes.is_empty()),
            _ => panic!("expected file entry, got {entry:?}"),
        }
    }

    #[test]
    fn mark_deleted_shadows_rootfs_view() {
        let mut overlay = WritableOverlay::new();
        overlay.mark_deleted("/etc/motd").unwrap();
        assert!(overlay.is_deleted("/etc/motd"));
    }

    #[test]
    fn child_names_only_returns_immediate_children() {
        let mut overlay = WritableOverlay::new();
        overlay.make_dir("/var/lib/apt").unwrap();
        overlay.make_dir("/var/lib/apt/lists").unwrap();
        overlay
            .set_file_contents("/var/lib/apt/lists/lock", Vec::new())
            .unwrap();
        let mut names: Vec<String> = overlay
            .child_names("/var/lib/apt")
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        names.sort();
        assert_eq!(names, vec!["lists".to_owned()]);
    }
}
