//! Build scripts and proc-macros run arbitrary code at build time and may read
//! any file without reporting it in dep-info. Restricted dialect: every one in
//! a fixture's resolved (unfiltered, non-dev) graph must appear, with the hash
//! of its entry source, in the committed reviewed list. Publish and admission
//! refuse an unlisted, changed or stale entry; the list is itself an input.
use super::{ContentHash, Result, fail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// Committed, reviewed build code. Part of every fixture input identity.
pub const REVIEWED_BUILD_CODE: &str = "fixtures/reviewed-build-code.json";
const SCHEMA: &str = "carrick.fixtures.reviewed-build-code.v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedEntry {
    pub package: String,
    /// `path:<checkout-relative manifest>` for checkout packages, or
    /// `<cargo source>#<name>@<version>` for locked registry/git packages.
    pub location: String,
    /// `custom-build` or `proc-macro`.
    pub kind: String,
    /// Entry source relative to the package directory (e.g. `build.rs`).
    pub source: String,
    /// Typed, length-framed digest of the entry source.
    pub sha256: ContentHash,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedList {
    pub schema: String,
    pub entries: Vec<ReviewedEntry>,
}

pub(super) fn location(
    root: &Path,
    name: &str,
    version: &str,
    source: Option<&str>,
    manifest: &Path,
) -> Result<String> {
    Ok(match source {
        Some(source) => format!("{source}#{name}@{version}"),
        None => format!(
            "path:{}",
            manifest
                .strip_prefix(root)
                .ok()
                .and_then(Path::to_str)
                .ok_or_else(|| fail(format!(
                    "build code package outside checkout: {}",
                    manifest.display()
                )))?
        ),
    })
}

/// Compare the graph's build code with the reviewed list, exactly.
pub(super) fn check(root: &Path, found: &BTreeSet<ReviewedEntry>) -> Result<()> {
    let path = super::safe_path(root, REVIEWED_BUILD_CODE)?;
    let list: ReviewedList = serde_json::from_slice(&std::fs::read(&path).map_err(|error| {
        fail(format!(
            "missing reviewed build code list {REVIEWED_BUILD_CODE}: {error}"
        ))
    })?)?;
    if list.schema != SCHEMA {
        return Err(fail("unknown reviewed build code schema"));
    }
    let reviewed: BTreeSet<_> = list.entries.iter().cloned().collect();
    if reviewed.len() != list.entries.len() {
        return Err(fail("duplicate reviewed build code entry"));
    }
    let unreviewed: Vec<_> = found.difference(&reviewed).collect();
    let stale: Vec<_> = reviewed.difference(found).collect();
    if !unreviewed.is_empty() || !stale.is_empty() {
        let describe = |entries: &[&ReviewedEntry]| {
            entries
                .iter()
                .map(|e| format!("{} {} {} ({})", e.kind, e.location, e.source, e.sha256))
                .collect::<Vec<_>>()
                .join("; ")
        };
        return Err(fail(format!(
            "unreviewed build code in the fixture graph: [{}]; stale reviewed entries: [{}]. \
             Review each build script/proc-macro for undeclared file reads, then update \
             {REVIEWED_BUILD_CODE} (`carrick-xtask fixtures build-code` prints the current set)",
            describe(&unreviewed),
            describe(&stale)
        )));
    }
    Ok(())
}

pub fn render(found: &BTreeSet<ReviewedEntry>) -> Result<String> {
    Ok(serde_json::to_string_pretty(&ReviewedList {
        schema: SCHEMA.into(),
        entries: found.iter().cloned().collect(),
    })? + "\n")
}
