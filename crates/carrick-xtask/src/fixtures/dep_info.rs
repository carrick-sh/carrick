//! Compiler-reported fixture inputs. rustc and Cargo write Makefile-style
//! dep-info naming every file a build read: modules, `#[path]` modules,
//! `include_str!`/`include_bytes!` targets and build-script
//! `rerun-if-changed` paths. The publisher records the checkout-relative
//! subset so admission hashes exactly what the compiler consumed.
use super::{Result, fail};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Where a builder writes an executable's dep-info, relative to the checkout.
/// Cargo writes `<bin>.d` beside the binary; the raw builder writes
/// `<name>.d` beside its output; embed executables are copied out of their
/// crate's Cargo target directory.
pub fn dep_info_path(executable: &str, embed: &[(&str, &str)]) -> Result<String> {
    if let Some(file) = executable.strip_prefix("target/embed-fixtures/") {
        let name = file
            .strip_suffix("-aarch64")
            .ok_or_else(|| fail(format!("unexpected embed executable: {executable}")))?;
        let (directory, _) = embed
            .iter()
            .find(|(_, binary)| *binary == name)
            .ok_or_else(|| fail(format!("undeclared embed executable: {executable}")))?;
        return Ok(format!(
            "fixtures/{directory}/target/aarch64-unknown-linux-musl/release/{name}.d"
        ));
    }
    Ok(format!("{executable}.d"))
}

/// Every prerequisite named by a dep-info file (targets are outputs).
pub fn parse(text: &str) -> Vec<PathBuf> {
    let mut prerequisites = Vec::new();
    // A backslash-newline continues a rule onto the next line.
    for rule in text.replace("\\\n", " ").lines() {
        if rule.trim_start().starts_with('#') {
            continue;
        }
        let mut in_prerequisites = false;
        for token in tokens(rule) {
            if in_prerequisites {
                prerequisites.push(PathBuf::from(token));
            } else if token.ends_with(':') {
                in_prerequisites = true;
            }
        }
    }
    prerequisites
}

fn tokens(rule: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = rule.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&' ') => {
                current.push(' ');
                chars.next();
            }
            '\\' if chars.peek() == Some(&'\\') => {
                current.push('\\');
                chars.next();
            }
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Classify dep-info prerequisites against the build snapshot. Checkout files
/// are recorded relative to it. Files under an `external` root (the locked
/// registry/git cache, the pinned sysroot) are identified by `Cargo.lock`
/// checksums and the compiler pin instead. Generated files under any
/// `target` directory, relative paths and other external files fail closed.
pub fn classify(
    snapshot: &Path,
    dep_info_files: &[PathBuf],
    external: &[PathBuf],
) -> Result<Vec<String>> {
    let given = snapshot.to_path_buf();
    let snapshot = snapshot.canonicalize()?;
    let external: Vec<PathBuf> = external
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect();
    let mut recorded = BTreeSet::new();
    for file in dep_info_files {
        let text = fs::read_to_string(file).map_err(|error| {
            fail(format!(
                "missing or unreadable fixture dep-info {}: {error}",
                file.display()
            ))
        })?;
        let prerequisites = parse(&text);
        if prerequisites.is_empty() {
            return Err(fail(format!(
                "fixture dep-info names no inputs: {}",
                file.display()
            )));
        }
        for prerequisite in prerequisites {
            if !prerequisite.is_absolute() {
                return Err(fail(format!(
                    "relative compiler input in {}: {}",
                    file.display(),
                    prerequisite.display()
                )));
            }
            let lexical = prerequisite
                .strip_prefix(&snapshot)
                .or_else(|_| prerequisite.strip_prefix(&given));
            if let Ok(relative) = lexical {
                let relative = walk_without_symlinks(&snapshot, relative)?;
                recorded.insert(relative);
                continue;
            }
            let path = prerequisite.canonicalize().map_err(|error| {
                fail(format!(
                    "compiler input {} from {}: {error}",
                    prerequisite.display(),
                    file.display()
                ))
            })?;
            if path.starts_with(&snapshot) {
                return Err(fail(format!(
                    "compiler input reaches the checkout through a symlink: {}",
                    prerequisite.display()
                )));
            }
            if !external.iter().any(|root| path.starts_with(root)) {
                return Err(fail(format!(
                    "compiler input outside the checkout and locked caches: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(recorded.into_iter().collect())
}

/// Resolve a compiler-reported checkout path exactly as written, refusing a
/// symlink at any component: canonicalizing first would record a link's
/// current referent, so retargeting the link would keep the identity.
fn walk_without_symlinks(snapshot: &Path, relative: &Path) -> Result<String> {
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => {
                parts.push(name);
                let path = parts.iter().fold(snapshot.to_path_buf(), |p, n| p.join(n));
                let metadata = fs::symlink_metadata(&path).map_err(|error| {
                    fail(format!("compiler input {}: {error}", relative.display()))
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(fail(format!(
                        "compiler input passes through a symlink: {}",
                        relative.display()
                    )));
                }
            }
            Component::CurDir => {}
            // Each popped component was verified to be a real directory.
            Component::ParentDir if parts.pop().is_some() => {}
            _ => {
                return Err(fail(format!(
                    "compiler input escapes the checkout: {}",
                    relative.display()
                )));
            }
        }
    }
    let path: PathBuf = parts.iter().collect();
    if path
        .components()
        .any(|c| c == Component::Normal("target".as_ref()))
    {
        return Err(fail(format!(
            "generated compiler input under target/ is not a source input: {}",
            path.display()
        )));
    }
    if !fs::symlink_metadata(snapshot.join(&path))?.is_file() {
        return Err(fail(format!(
            "compiler input is not a regular file: {}",
            path.display()
        )));
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| fail(format!("non-UTF8 compiler input: {}", path.display())))
}
