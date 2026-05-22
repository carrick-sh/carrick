use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Cursor, Read};
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use serde::Serialize;
use thiserror::Error;

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerSource {
    Tar(Vec<u8>),
    TarGz(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootFs {
    files: HashMap<PathBuf, FileEntry>,
    directories: HashSet<PathBuf>,
    symlinks: HashMap<PathBuf, SymlinkEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub mode: u32,
    pub size: usize,
    #[serde(skip)]
    contents: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SymlinkEntry {
    path: PathBuf,
    target: PathBuf,
    target_text: String,
}

impl FileEntry {
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootFsSummary {
    pub file_count: usize,
    pub directory_count: usize,
    pub symlink_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootFsEntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootFsMetadata {
    pub path: PathBuf,
    pub kind: RootFsEntryKind,
    pub mode: u32,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootFsDirEntry {
    pub name: String,
    pub metadata: RootFsMetadata,
}

#[derive(Debug, Error)]
pub enum RootFsError {
    #[error("failed to decode OCI layer: {0}")]
    Io(#[from] std::io::Error),
    #[error("layer contains a path outside the rootfs: {0}")]
    UnsafePath(String),
    #[error("rootfs path does not exist: {0}")]
    NotFound(String),
    #[error("rootfs path is not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("too many symlinks while resolving rootfs path: {0}")]
    TooManySymlinks(String),
}

/// Statistics returned by [`extract_layer_paths_to_dir`].
#[derive(Debug, Clone, Default)]
pub struct ExtractStats {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub skipped_special: u64,
}

/// Stream OCI layer blobs (gzip or raw tar) directly into `dir`, applying
/// overlay + whiteout semantics. Never materializes the file tree in memory.
///
/// Layers are applied in order (first to last). Each layer can add, replace,
/// or delete entries from prior layers using standard OCI whiteout conventions.
pub fn extract_layer_paths_to_dir(
    paths: &[PathBuf],
    dir: &cap_std::fs::Dir,
) -> Result<ExtractStats, RootFsError> {
    let mut stats = ExtractStats::default();
    for path in paths {
        let file = fs::File::open(path)?;
        let mut buf = BufReader::new(file);
        // Sniff first 2 bytes for gzip magic without consuming the stream.
        let magic = buf.fill_buf()?;
        let is_gz = magic.len() >= 2 && magic[0] == 0x1f && magic[1] == 0x8b;
        if is_gz {
            let decoder = GzDecoder::new(buf);
            let mut archive = tar::Archive::new(decoder);
            apply_tar_to_dir(&mut archive, dir, &mut stats)?;
        } else {
            let mut archive = tar::Archive::new(buf);
            apply_tar_to_dir(&mut archive, dir, &mut stats)?;
        }
    }
    Ok(stats)
}

fn apply_tar_to_dir<R: Read>(
    archive: &mut tar::Archive<R>,
    dir: &cap_std::fs::Dir,
    stats: &mut ExtractStats,
) -> Result<(), RootFsError> {
    use cap_std::fs::PermissionsExt as _;
    use std::io::ErrorKind;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.into_owned();
        let path = normalize_layer_path(&raw_path)?;

        // Whiteout detection — replicates apply_layer exactly.
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            if file_name == OPAQUE_WHITEOUT {
                // Opaque whiteout: clear the parent directory then recreate it.
                if let Some(parent) = path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    match dir.remove_dir_all(parent) {
                        Ok(()) | Err(_) => {}
                    }
                    dir.create_dir_all(parent)?;
                }
                continue;
            }

            if let Some(hidden_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
                if let Some(parent) = path.parent() {
                    let target = if parent.as_os_str().is_empty() {
                        PathBuf::from(hidden_name)
                    } else {
                        parent.join(hidden_name)
                    };
                    // Try removing as a file first, then as a directory tree.
                    match dir.remove_file(&target) {
                        Ok(()) => {}
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(_) => match dir.remove_dir_all(&target) {
                            Ok(()) | Err(_) => {}
                        },
                    }
                }
                continue;
            }
        }

        let entry_type = entry.header().entry_type();
        let mode = entry.header().mode().unwrap_or(0o644);

        // Ensure parent directory exists for all non-root entries.
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            dir.create_dir_all(parent)?;
        }

        if entry_type.is_dir() {
            dir.create_dir_all(&path)?;
            // A directory the owner can't read+search (r-x) would lock carrick
            // (a non-root macOS process) out of its own scratch. Preserve the
            // true mode in the carrick xattr and force owner r-x on the real
            // dir; otherwise apply the image mode directly. (See HostFsBackend
            // / CARRICK_MODE_XATTR.)
            if mode & 0o500 != 0o500 {
                let _ =
                    dir.set_permissions(&path, cap_std::fs::Permissions::from_mode(mode | 0o700));
                crate::fs_backend::write_mode_xattr(dir, &path, true, mode);
            } else {
                let _ = dir.set_permissions(&path, cap_std::fs::Permissions::from_mode(mode));
            }
            stats.dirs += 1;
        } else if entry_type.is_symlink() {
            let link_name = entry
                .link_name()?
                .ok_or_else(|| RootFsError::UnsafePath(path.display().to_string()))?
                .into_owned();
            // Remove any existing entry at path before creating the symlink.
            let _ = dir.remove_file(&path);
            let _ = dir.remove_dir_all(&path);
            // Store the raw link target verbatim (Linux symlinkat(2) semantics).
            dir.symlink_contents(link_name.to_string_lossy().as_ref(), &path)?;
            stats.symlinks += 1;
        } else if entry_type.is_file() {
            // Streaming copy — never buffers the whole file.
            let mut f = dir.create(&path)?;
            std::io::copy(&mut entry, &mut f)?;
            drop(f);
            // A file the owner can't read would lock carrick (non-root) out of
            // serving its content. Preserve the true mode in the carrick xattr
            // and force owner rw on the real file; otherwise apply the image
            // mode directly (real_stat reports it faithfully).
            if mode & 0o400 == 0 {
                let _ =
                    dir.set_permissions(&path, cap_std::fs::Permissions::from_mode(mode | 0o600));
                crate::fs_backend::write_mode_xattr(dir, &path, false, mode);
            } else {
                let _ = dir.set_permissions(&path, cap_std::fs::Permissions::from_mode(mode));
            }
            stats.files += 1;
        } else if entry_type.is_hard_link() {
            let link_name = entry
                .link_name()?
                .ok_or_else(|| RootFsError::UnsafePath(path.display().to_string()))?
                .into_owned();
            let target = normalize_layer_path(&link_name)?;
            match dir.hard_link(&target, dir, &path) {
                Ok(()) => {}
                Err(_) => {
                    // Fall back to copying target's bytes if hard_link fails.
                    let mut src = dir.open(&target)?;
                    let mut dst = dir.create(&path)?;
                    std::io::copy(&mut src, &mut dst)?;
                }
            }
            stats.files += 1;
        } else {
            // char/block/fifo/other special — skip.
            stats.skipped_special += 1;
        }
    }
    Ok(())
}

impl RootFs {
    pub fn from_layers<I>(layers: I) -> Result<Self, RootFsError>
    where
        I: IntoIterator<Item = LayerSource>,
    {
        let mut rootfs = Self {
            files: HashMap::new(),
            directories: HashSet::from([PathBuf::new()]),
            symlinks: HashMap::new(),
        };

        for layer in layers {
            rootfs.apply_layer(layer)?;
        }

        Ok(rootfs)
    }

    pub fn from_layer_paths<I, P>(paths: I) -> Result<Self, RootFsError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let layers = paths
            .into_iter()
            .map(|path| LayerSource::from_path(path.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_layers(layers)
    }

    pub fn summary(&self) -> RootFsSummary {
        RootFsSummary {
            file_count: self.files.len(),
            directory_count: self.directories.len(),
            symlink_count: self.symlinks.len(),
        }
    }

    /// Materialise the in-memory rootfs onto a real on-disk directory.
    /// This is what gets carrick out of "overlay on top of read-only
    /// in-memory tar" and onto "real filesystem owns everything" — the
    /// architectural shift the project moved to when apt's downstream
    /// fs ops (symlinkat, atomic rename, gpgv subprocess, ...) needed
    /// real kernel semantics instead of bespoke overlay logic.
    ///
    /// Directories are created first (sorted by depth so parents land
    /// before children), then regular files, then symlinks. The
    /// destination dir must exist and be empty (caller's job).
    ///
    /// Files are written with their stored permission bits. Symlinks
    /// use the as-stored target text (preserving relative vs absolute
    /// shape) — `clonefile(2)`-style identity would be ideal but works
    /// transparently here since we're laying down fresh inodes.
    pub fn extract_to_disk(&self, dest: &Path) -> Result<(), RootFsError> {
        use std::os::unix::fs::PermissionsExt;
        // Directories: process shallowest first.
        let mut dirs: Vec<&PathBuf> = self.directories.iter().collect();
        dirs.sort_by_key(|p| p.components().count());
        for d in dirs {
            let host = dest.join(d);
            std::fs::create_dir_all(&host)?;
        }
        // Files.
        for (path, entry) in &self.files {
            let host = dest.join(path);
            if let Some(parent) = host.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&host, &entry.contents)?;
            let _ = std::fs::set_permissions(&host, std::fs::Permissions::from_mode(entry.mode));
        }
        // Symlinks last (target paths might point at files we just wrote).
        for (link_path, entry) in &self.symlinks {
            let host = dest.join(link_path);
            if let Some(parent) = host.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // If the link path already exists (e.g. parent created it as a dir),
            // remove first.
            let _ = std::fs::remove_file(&host);
            std::os::unix::fs::symlink(&entry.target_text, &host)?;
        }
        Ok(())
    }

    /// Every path the rootfs holds, regardless of kind. Used by
    /// HostFsBackend's seed step to register the materialised view so
    /// dispatcher lookups stop falling through to the in-memory RootFs.
    pub fn all_paths(&self) -> Vec<PathBuf> {
        let mut out =
            Vec::with_capacity(self.files.len() + self.directories.len() + self.symlinks.len());
        out.extend(self.files.keys().cloned());
        out.extend(self.directories.iter().cloned());
        out.extend(self.symlinks.keys().cloned());
        out
    }

    pub fn read(&self, path: impl AsRef<Path>) -> Result<Vec<u8>, RootFsError> {
        let path = normalize_rootfs_path(path.as_ref())?;
        let path = self.resolve_symlink(&path, 0)?;
        self.files
            .get(&path)
            .map(|entry| entry.contents.clone())
            .ok_or_else(|| RootFsError::NotFound(display_rootfs_path(&path)))
    }

    pub fn read_to_string(&self, path: impl AsRef<Path>) -> Result<String, RootFsError> {
        Ok(String::from_utf8(self.read(path)?)?)
    }

    pub fn read_link(&self, path: impl AsRef<Path>) -> Result<String, RootFsError> {
        let path = normalize_rootfs_path(path.as_ref())?;
        self.symlinks
            .get(&path)
            .map(|entry| entry.target_text.clone())
            .ok_or_else(|| RootFsError::NotFound(display_rootfs_path(&path)))
    }

    pub fn list_dir(&self, path: impl AsRef<Path>) -> Result<Vec<String>, RootFsError> {
        let dir = normalize_rootfs_path(path.as_ref())?;
        if !self.directories.contains(&dir) {
            return Err(RootFsError::NotFound(display_rootfs_path(&dir)));
        }

        let mut names = BTreeSet::new();
        for child in self.files.keys().chain(self.directories.iter()) {
            insert_child_name(&mut names, &dir, child);
        }
        for child in self.symlinks.keys() {
            insert_child_name(&mut names, &dir, child);
        }

        Ok(names.into_iter().collect())
    }

    pub fn metadata(&self, path: impl AsRef<Path>) -> Result<RootFsMetadata, RootFsError> {
        let path = normalize_rootfs_path(path.as_ref())?;
        let path = self.resolve_symlink(&path, 0)?;
        self.metadata_for_normalized(&path)
    }

    pub fn symlink_metadata(&self, path: impl AsRef<Path>) -> Result<RootFsMetadata, RootFsError> {
        let path = normalize_rootfs_path(path.as_ref())?;
        self.metadata_for_normalized(&path)
    }

    pub fn directory_entries(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<Vec<RootFsDirEntry>, RootFsError> {
        let dir = normalize_rootfs_path(path.as_ref())?;
        if !self.directories.contains(&dir) {
            return Err(RootFsError::NotFound(display_rootfs_path(&dir)));
        }

        self.list_dir(&dir)?
            .into_iter()
            .map(|name| {
                let metadata = self.metadata_for_normalized(&dir.join(&name))?;
                Ok(RootFsDirEntry { name, metadata })
            })
            .collect()
    }

    pub fn contains(&self, path: impl AsRef<Path>) -> Result<bool, RootFsError> {
        let path = normalize_rootfs_path(path.as_ref())?;
        Ok(self.files.contains_key(&path)
            || self.directories.contains(&path)
            || self.symlinks.contains_key(&path))
    }

    fn apply_layer(&mut self, layer: LayerSource) -> Result<(), RootFsError> {
        let bytes = match layer {
            LayerSource::Tar(bytes) => bytes,
            LayerSource::TarGz(bytes) => {
                let mut decoder = GzDecoder::new(Cursor::new(bytes));
                let mut decoded = Vec::new();
                decoder.read_to_end(&mut decoded)?;
                decoded
            }
        };

        let mut archive = tar::Archive::new(Cursor::new(bytes));
        for entry in archive.entries()? {
            let mut entry = entry?;
            let raw_path = entry.path()?.into_owned();
            let path = normalize_layer_path(&raw_path)?;

            if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
                if file_name == OPAQUE_WHITEOUT {
                    if let Some(parent) = path.parent() {
                        self.apply_opaque_whiteout(parent);
                    }
                    continue;
                }

                if let Some(hidden_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
                    if let Some(parent) = path.parent() {
                        self.remove_path(&parent.join(hidden_name));
                    }
                    continue;
                }
            }

            if let Some(parent) = path.parent() {
                self.ensure_directories(parent);
            }

            let entry_type = entry.header().entry_type();
            let mode = entry.header().mode().unwrap_or(0o644);
            if entry_type.is_dir() {
                self.ensure_directories(&path);
                continue;
            }

            if entry_type.is_symlink() {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| RootFsError::UnsafePath(path.display().to_string()))?
                    .into_owned();
                let target_text = target
                    .to_str()
                    .ok_or_else(|| RootFsError::UnsafePath(path.display().to_string()))?
                    .to_owned();
                let target = normalize_symlink_target(&path, &target)?;
                self.symlinks.insert(
                    path.clone(),
                    SymlinkEntry {
                        path,
                        target,
                        target_text,
                    },
                );
                continue;
            }

            if entry_type.is_file() {
                let mut contents = Vec::new();
                entry.read_to_end(&mut contents)?;
                self.files.insert(
                    path.clone(),
                    FileEntry {
                        path,
                        mode,
                        size: contents.len(),
                        contents,
                    },
                );
            }
        }

        Ok(())
    }

    fn ensure_directories(&mut self, path: &Path) {
        let mut current = PathBuf::new();
        for component in path.components() {
            if let Component::Normal(name) = component {
                current.push(name);
                self.directories.insert(current.clone());
            }
        }
    }

    fn remove_path(&mut self, path: &Path) {
        self.files.remove(path);
        self.symlinks.remove(path);
        self.files
            .retain(|candidate, _| !candidate.starts_with(path));
        self.symlinks
            .retain(|candidate, _| !candidate.starts_with(path));
        self.directories
            .retain(|candidate| candidate == Path::new("") || !candidate.starts_with(path));
    }

    fn apply_opaque_whiteout(&mut self, path: &Path) {
        self.files
            .retain(|candidate, _| !candidate.starts_with(path));
        self.symlinks
            .retain(|candidate, _| !candidate.starts_with(path));
        self.directories.retain(|candidate| {
            candidate == Path::new("") || candidate == path || !candidate.starts_with(path)
        });
        self.ensure_directories(path);
    }

    /// Resolve symlinks along EVERY component of `path`, not just the
    /// leaf — Debian's `/lib -> usr/lib` makes the parent component a
    /// symlink, and the dynamic linker request for
    /// `/lib/ld-linux-aarch64.so.1` has to walk it before the final
    /// `ld-linux-aarch64.so.1` lookup succeeds. Cap recursion at 40
    /// (Linux's SYMLOOP_MAX) to bound pathological chains.
    fn resolve_symlink(&self, path: &Path, depth: usize) -> Result<PathBuf, RootFsError> {
        if depth > 40 {
            return Err(RootFsError::TooManySymlinks(display_rootfs_path(path)));
        }
        let mut acc = PathBuf::new();
        let components: Vec<_> = path.components().collect();
        for (i, component) in components.iter().enumerate() {
            acc.push(component.as_os_str());
            if let Some(entry) = self.symlinks.get(&acc) {
                let target_resolved = self.resolve_symlink(&entry.target, depth + 1)?;
                // The remaining components after the symlink we just
                // resolved get re-appended; they may themselves contain
                // further symlinks, hence the recursive call below.
                let mut rebuilt = target_resolved;
                for tail in &components[i + 1..] {
                    rebuilt.push(tail.as_os_str());
                }
                return self.resolve_symlink(&rebuilt, depth + 1);
            }
        }
        Ok(path.to_path_buf())
    }

    fn metadata_for_normalized(&self, path: &Path) -> Result<RootFsMetadata, RootFsError> {
        if let Some(entry) = self.files.get(path) {
            return Ok(RootFsMetadata {
                path: path.to_path_buf(),
                kind: RootFsEntryKind::File,
                mode: entry.mode,
                size: entry.size,
            });
        }

        if self.directories.contains(path) {
            return Ok(RootFsMetadata {
                path: path.to_path_buf(),
                kind: RootFsEntryKind::Directory,
                mode: 0o755,
                size: 0,
            });
        }

        if let Some(target) = self.symlinks.get(path) {
            return Ok(RootFsMetadata {
                path: path.to_path_buf(),
                kind: RootFsEntryKind::Symlink,
                mode: 0o777,
                size: target.target_text.len(),
            });
        }

        Err(RootFsError::NotFound(display_rootfs_path(path)))
    }
}

impl LayerSource {
    pub fn from_path(path: &Path) -> Result<Self, RootFsError> {
        let bytes = fs::read(path)?;
        if bytes.starts_with(&[0x1f, 0x8b]) {
            Ok(Self::TarGz(bytes))
        } else {
            Ok(Self::Tar(bytes))
        }
    }
}

fn normalize_layer_path(path: &Path) -> Result<PathBuf, RootFsError> {
    normalize_path(path, false)
}

fn normalize_rootfs_path(path: &Path) -> Result<PathBuf, RootFsError> {
    normalize_path(path, true)
}

fn normalize_symlink_target(link_path: &Path, target: &Path) -> Result<PathBuf, RootFsError> {
    if target.is_absolute() {
        return normalize_rootfs_path(target);
    }

    let parent = link_path.parent().unwrap_or_else(|| Path::new(""));
    normalize_path(&parent.join(target), false)
}

fn normalize_path(path: &Path, allow_absolute: bool) -> Result<PathBuf, RootFsError> {
    let mut out = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(_) => {
                return Err(RootFsError::UnsafePath(path.display().to_string()));
            }
            Component::RootDir => {
                if !allow_absolute {
                    return Err(RootFsError::UnsafePath(path.display().to_string()));
                }
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return Err(RootFsError::UnsafePath(path.display().to_string()));
                }
            }
            Component::Normal(component) => out.push(component),
        }
    }

    Ok(out)
}

fn display_rootfs_path(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", path.display())
    }
}

fn insert_child_name(names: &mut BTreeSet<String>, dir: &Path, child: &Path) {
    if child == dir {
        return;
    }
    if let Ok(stripped) = child.strip_prefix(dir)
        && let Some(component) = stripped.components().next()
    {
        names.insert(component.as_os_str().to_string_lossy().into_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symlink_target_with_parent_dir_resolves_within_root() {
        // etc/mtab -> ../proc/mounts should resolve to /proc/mounts
        let resolved =
            normalize_symlink_target(Path::new("etc/mtab"), Path::new("../proc/mounts")).unwrap();
        assert_eq!(resolved, PathBuf::from("proc/mounts"));
    }

    #[test]
    fn symlink_target_with_multiple_parent_dirs_resolves_within_root() {
        // a/b/c -> ../../x: resolution starts in the symlink's parent dir (a/b),
        // .. -> a, .. -> "" (root), then x -> /x.
        let resolved = normalize_symlink_target(Path::new("a/b/c"), Path::new("../../x")).unwrap();
        assert_eq!(resolved, PathBuf::from("x"));
    }

    #[test]
    fn symlink_target_one_parent_dir_pops_one_segment() {
        // a/b/c -> ../x: from a/b, .. -> a, x -> a/x.
        let resolved = normalize_symlink_target(Path::new("a/b/c"), Path::new("../x")).unwrap();
        assert_eq!(resolved, PathBuf::from("a/x"));
    }

    #[test]
    fn symlink_target_escaping_root_from_shallow_path_is_rejected() {
        // a -> ../../../etc/passwd (one level deep) MUST still be unsafe.
        let err =
            normalize_symlink_target(Path::new("a"), Path::new("../../../etc/passwd")).unwrap_err();
        assert!(matches!(err, RootFsError::UnsafePath(_)));
    }

    #[test]
    fn symlink_target_escaping_root_via_second_parent_dir_is_rejected() {
        // etc/foo -> ../../etc/passwd
        // First .. from /etc lands at /; second .. from / is the escape.
        let err = normalize_symlink_target(Path::new("etc/foo"), Path::new("../../etc/passwd"))
            .unwrap_err();
        assert!(matches!(err, RootFsError::UnsafePath(_)));
    }

    #[test]
    fn symlink_target_with_curdir_resolves() {
        // bin/sh -> ./busybox should resolve to /bin/busybox
        let resolved =
            normalize_symlink_target(Path::new("bin/sh"), Path::new("./busybox")).unwrap();
        assert_eq!(resolved, PathBuf::from("bin/busybox"));
    }

    #[test]
    fn layer_path_with_parent_dir_collapses() {
        // foo/../bar inside a layer path should collapse to bar
        let normalized = normalize_layer_path(Path::new("foo/../bar")).unwrap();
        assert_eq!(normalized, PathBuf::from("bar"));
    }

    #[test]
    fn layer_path_escaping_root_is_rejected() {
        let err = normalize_layer_path(Path::new("../escape")).unwrap_err();
        assert!(matches!(err, RootFsError::UnsafePath(_)));
    }

    #[test]
    fn rootfs_path_escaping_via_root_then_parent_is_rejected() {
        // "/../safe.txt" — / then .. on empty stack escapes.
        let err = normalize_rootfs_path(Path::new("/../safe.txt")).unwrap_err();
        assert!(matches!(err, RootFsError::UnsafePath(_)));
    }

    /// Build a tar in memory and load it as a RootFs. Mirrors what the
    /// OCI loader does, so the assertions exercise the same resolution
    /// path as `carrick run`.
    fn make_rootfs(files: &[(&str, &[u8])], dirs: &[&str], symlinks: &[(&str, &str)]) -> RootFs {
        use tar::{Builder, EntryType, Header};
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut builder = Builder::new(&mut buf);
            for path in dirs {
                let mut h = Header::new_gnu();
                h.set_path(format!("{}/", path)).unwrap();
                h.set_entry_type(EntryType::Directory);
                h.set_size(0);
                h.set_mode(0o755);
                h.set_cksum();
                builder.append(&h, std::io::empty()).unwrap();
            }
            for (path, bytes) in files {
                let mut h = Header::new_gnu();
                h.set_path(path).unwrap();
                h.set_size(bytes.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                builder.append(&h, *bytes).unwrap();
            }
            for (link, target) in symlinks {
                let mut h = Header::new_gnu();
                h.set_path(link).unwrap();
                h.set_entry_type(EntryType::Symlink);
                h.set_size(0);
                h.set_mode(0o777);
                h.set_link_name(target).unwrap();
                h.set_cksum();
                builder.append(&h, std::io::empty()).unwrap();
            }
            builder.finish().unwrap();
        }
        RootFs::from_layers(std::iter::once(LayerSource::Tar(buf))).unwrap()
    }

    #[test]
    fn resolve_walks_through_directory_symlinks() {
        // Debian usrmerge: /lib -> usr/lib, then
        // /usr/lib/ld-linux-aarch64.so.1 -> aarch64-linux-gnu/ld-linux-aarch64.so.1
        let fs = make_rootfs(
            &[(
                "usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
                b"FAKE-LD",
            )],
            &["usr", "usr/lib", "usr/lib/aarch64-linux-gnu"],
            &[
                ("lib", "usr/lib"),
                (
                    "usr/lib/ld-linux-aarch64.so.1",
                    "aarch64-linux-gnu/ld-linux-aarch64.so.1",
                ),
            ],
        );
        let bytes = fs
            .read("/lib/ld-linux-aarch64.so.1")
            .expect("walk parent symlink");
        assert_eq!(bytes, b"FAKE-LD");
    }
}
