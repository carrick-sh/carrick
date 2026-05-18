use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{Cursor, Read};
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
    symlinks: HashMap<PathBuf, PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub mode: u32,
    pub size: usize,
    #[serde(skip)]
    contents: Vec<u8>,
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
                let target = normalize_symlink_target(&path, &target)?;
                self.symlinks.insert(path, target);
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

    fn resolve_symlink(&self, path: &Path, depth: usize) -> Result<PathBuf, RootFsError> {
        if depth > 16 {
            return Err(RootFsError::TooManySymlinks(display_rootfs_path(path)));
        }

        match self.symlinks.get(path) {
            Some(target) => self.resolve_symlink(target, depth + 1),
            None => Ok(path.to_path_buf()),
        }
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
                return Err(RootFsError::UnsafePath(path.display().to_string()));
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
