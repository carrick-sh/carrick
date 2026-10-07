//! Linker inputs are invisible to dep-info, and a linker resolves script and
//! response-file paths against its own search rules, which may pull in further
//! files (`INCLUDE`, nested `@file`). Restricted dialect: fixture builds use no
//! linker scripts or response files at all. Any reference in a builder script,
//! an inventoried Cargo configuration or a build-script `rustc-link-arg`
//! output is refused; nothing is resolved or authorized.
use super::{Result, fail};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Linker-input references in a builder script, Cargo configuration or a
/// build-script `rustc-link-arg` value: `-T <f>`, `-T<f>`, `--script[=]<f>`,
/// `@<response-file>`, a linker-script `INCLUDE` and any `*.ld`/`*.lds` token.
pub fn references(text: &str) -> Vec<String> {
    let tokens: Vec<&str> = text
        .split(|c: char| c.is_whitespace() || "\"'`,=[]()".contains(c))
        .filter(|t| !t.is_empty())
        .collect();
    let mut found = Vec::new();
    let mut take_next = false;
    for token in tokens {
        if take_next {
            found.push(token.to_owned());
            take_next = false;
            continue;
        }
        if token == "INCLUDE" {
            found.push(token.to_owned());
        } else if token == "-T" || token == "--script" || token == "-script" {
            take_next = true;
        } else if let Some(rest) = token.strip_prefix("-T") {
            found.push(rest.to_owned());
        } else if let Some(rest) = token.strip_prefix('@').filter(|r| !r.is_empty()) {
            found.push(rest.to_owned());
        } else if token.ends_with(".ld") || token.ends_with(".lds") {
            found.push(token.to_owned());
        }
    }
    if take_next {
        found.push(String::new());
    }
    found
}

/// Refuse any linker-input reference in `text`, read from `origin`.
pub fn check(origin: &str, text: &str) -> Result<()> {
    if let Some(reference) = references(text).into_iter().next() {
        return Err(fail(format!(
            "linker input reference `{reference}` in {origin}: fixture builds may not use linker scripts or response files"
        )));
    }
    Ok(())
}

/// Scan the inventory's builder scripts and Cargo configuration.
pub(super) fn check_inventory(
    root: &Path,
    sources: &BTreeMap<String, super::ContentHash>,
    builder_scripts: &[&str],
) -> Result<()> {
    for path in sources.keys() {
        let config = path == ".cargo/config"
            || path == ".cargo/config.toml"
            || path.ends_with("/.cargo/config")
            || path.ends_with("/.cargo/config.toml");
        if config || builder_scripts.contains(&path.as_str()) {
            let text = std::fs::read_to_string(super::safe_path(root, path)?)?;
            check(path, &text)?;
        }
    }
    Ok(())
}

/// Publish-time scan of every build-script `output` file in the snapshot's
/// fixture target directories: `cargo:rustc-link-arg*` values follow the same
/// rule as checked-in configuration.
pub fn check_build_script_outputs(snapshot: &Path, fixtures: &[&str]) -> Result<()> {
    let mut pending: Vec<PathBuf> = fixtures
        .iter()
        .map(|fixture| snapshot.join(fixture).join("target"))
        .filter(|path| path.is_dir())
        .collect();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let path = entry.path();
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            let is_output = entry.file_name() == "output"
                && path
                    .parent()
                    .and_then(Path::parent)
                    .and_then(Path::file_name)
                    .is_some_and(|name| name == "build");
            if !is_output {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            for line in text.lines() {
                let Some(directive) = line
                    .strip_prefix("cargo::")
                    .or_else(|| line.strip_prefix("cargo:"))
                else {
                    continue;
                };
                let Some((key, value)) = directive.split_once('=') else {
                    continue;
                };
                if key.contains("link-arg") {
                    check(&format!("build-script output {}", path.display()), value)?;
                }
            }
        }
    }
    Ok(())
}
