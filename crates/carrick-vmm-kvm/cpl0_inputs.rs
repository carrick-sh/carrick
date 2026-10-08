//! Derive the rebuild inputs of the embedded production CPL0 image.
//!
//! Shared by `build.rs` (which emits `cargo:rerun-if-changed` for each input)
//! and `tests/cpl0_image_inputs.rs` (which proves the derivation covers every
//! source the image compiles). A hand list goes stale the first time a crate
//! joins the image or a `#[path]` reaches into a crate the image does not depend
//! on (carrick-x86's `cpl0_*.rs`), so the inputs are derived:
//!
//! * the workspace files that configure the image build (lockfile, toolchain,
//!   root manifest, `.cargo/config.toml` with its `code-model=kernel` flags);
//! * the directory of every path (workspace) package in the normal/build
//!   dependency closure of `carrick-x86-cpl0`, conservatively read from
//!   manifest path declarations (including workspace inheritance);
//! * every file a source in those directories pulls in by `#[path = ...]`,
//!   `include!`, `include_str!` or `include_bytes!` with a literal path that
//!   resolves outside them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const IMAGE_PACKAGE: &str = "carrick-x86-cpl0";

/// Workspace-relative files that configure every image build.
pub const WORKSPACE_INPUTS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    ".cargo/config.toml",
];

#[derive(Debug, Default)]
pub struct Cpl0Inputs {
    /// Directories of the path packages the image links.
    pub package_dirs: BTreeSet<PathBuf>,
    /// Files outside `package_dirs` that the image's sources include.
    pub external_files: BTreeSet<PathBuf>,
    /// Every literal include found: (including file, resolved target).
    pub includes: Vec<(PathBuf, PathBuf)>,
    /// Literal include paths that did not resolve from the including file.
    pub unresolved: Vec<(PathBuf, String)>,
}

impl Cpl0Inputs {
    /// Every path `build.rs` must watch.
    pub fn watch_list(&self, workspace: &Path) -> Vec<PathBuf> {
        WORKSPACE_INPUTS
            .iter()
            .map(|file| workspace.join(file))
            .chain(self.package_dirs.iter().cloned())
            .chain(self.external_files.iter().cloned())
            .collect()
    }

    /// True when `path` is watched through a package directory or directly.
    pub fn covers(&self, path: &Path) -> bool {
        self.external_files.contains(path) || self.package_dirs.iter().any(|d| path.starts_with(d))
    }
}

pub fn derive(workspace: &Path) -> Result<Cpl0Inputs, String> {
    let package_dirs = closure_dirs(workspace)?;
    let mut inputs = Cpl0Inputs {
        package_dirs,
        ..Cpl0Inputs::default()
    };
    let mut files = Vec::new();
    for dir in &inputs.package_dirs {
        rust_files(dir, &mut files);
    }
    let mut seen: BTreeSet<PathBuf> = files.iter().cloned().collect();
    while let Some(file) = files.pop() {
        let Ok(source) = std::fs::read_to_string(&file) else {
            continue;
        };
        for target in literal_includes(&file, &source) {
            let target = match target {
                Ok(target) => target,
                Err(literal) => {
                    inputs.unresolved.push((file.clone(), literal));
                    continue;
                }
            };
            inputs.includes.push((file.clone(), target.clone()));
            if !inputs.covers(&target) {
                inputs.external_files.insert(target.clone());
            }
            if target.extension().is_some_and(|ext| ext == "rs") && seen.insert(target.clone()) {
                files.push(target);
            }
        }
    }
    Ok(inputs)
}

// Conservatively include every normal/build path dependency, including optional
// and target-specific ones. Extra watches are safe; omitting a compiled input
// is not. Registry dependencies are immutable under the watched Cargo.lock.
fn closure_dirs(workspace: &Path) -> Result<BTreeSet<PathBuf>, String> {
    let root = read_manifest(&workspace.join("Cargo.toml"))?;
    let mut stack = vec![workspace.join("crates").join(IMAGE_PACKAGE)];
    let mut visited = BTreeSet::new();
    while let Some(dir) = stack.pop() {
        let dir = dir.canonicalize().map_err(|error| error.to_string())?;
        if !visited.insert(dir.clone()) {
            continue;
        }
        let manifest = read_manifest(&dir.join("Cargo.toml"))?;
        let mut tables = vec![&manifest];
        if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
            tables.extend(targets.values());
        }
        for table in tables {
            for kind in ["dependencies", "build-dependencies"] {
                let Some(deps) = table.get(kind).and_then(toml::Value::as_table) else {
                    continue;
                };
                for (name, declaration) in deps {
                    let inherited =
                        declaration.get("workspace").and_then(toml::Value::as_bool) == Some(true);
                    let (dependency, base) = if inherited {
                        let dependency = root
                            .get("workspace")
                            .and_then(|value| value.get("dependencies"))
                            .and_then(|value| value.get(name))
                            .ok_or_else(|| format!("missing workspace dependency {name}"))?;
                        (dependency, workspace)
                    } else {
                        (declaration, dir.as_path())
                    };
                    if let Some(path) = dependency.get("path").and_then(toml::Value::as_str) {
                        stack.push(base.join(path));
                    }
                }
            }
        }
    }
    Ok(visited)
}

fn read_manifest(path: &Path) -> Result<toml::Value, String> {
    let source =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    toml::from_str(&source).map_err(|error| format!("{}: {error}", path.display()))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name != "target") {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Literal include targets of `source` (read from `file`), resolved against the
/// including file's directory. A literal that does not resolve there is kept
/// in [`Cpl0Inputs::unresolved`]: the test fails on it rather than letting an
/// input escape the watch list.
pub fn literal_includes(file: &Path, source: &str) -> Vec<Result<PathBuf, String>> {
    let base = file.parent().unwrap_or(Path::new("."));
    let mut found = Vec::new();
    for marker in ["#[path", "include!(", "include_str!(", "include_bytes!("] {
        let mut rest = source;
        while let Some(at) = rest.find(marker) {
            rest = &rest[at + marker.len()..];
            let Some(open) = rest.find('"') else { break };
            // The literal must follow the marker directly (`= "..."` or `("...`).
            if !rest[..open].chars().all(|c| c == ' ' || c == '=') {
                continue;
            }
            let Some(len) = rest[open + 1..].find('"') else {
                break;
            };
            let literal = &rest[open + 1..open + 1 + len];
            let candidate = base.join(literal);
            found.push(candidate.canonicalize().map_err(|_| literal.to_owned()));
        }
    }
    found
}
