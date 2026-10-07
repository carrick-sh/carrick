//! Build scripts and proc-macros run arbitrary code at build time: they may
//! read any file without reporting it in dep-info, and an approved entry file
//! can delegate to modules or build-dependencies. Restricted dialect:
//! checkout packages in a fixture graph may not have build scripts or be
//! proc-macros at all, and git/path build code is refused. Only locked
//! registry build code is admitted, keyed by name, version, source and the
//! `Cargo.lock` checksum that pins the entire crate, and only when listed in
//! the committed reviewed list. Publish and admission refuse an unlisted,
//! changed or stale entry; the list is itself an inventory input.
use super::{Result, fail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Committed, reviewed registry build code. Part of every input identity.
pub const REVIEWED_BUILD_CODE: &str = "fixtures/reviewed-build-code.json";
const SCHEMA: &str = "carrick.fixtures.reviewed-build-code.v2";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedEntry {
    pub package: String,
    pub version: String,
    /// The Cargo registry source (`registry+...`).
    pub source: String,
    /// `custom-build` or `proc-macro`.
    pub kind: String,
    /// `Cargo.lock` checksum of the whole crate archive.
    pub checksum: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedList {
    pub schema: String,
    pub entries: Vec<ReviewedEntry>,
}

/// `(name, version, source) -> checksum` from a `Cargo.lock`.
pub fn lock_checksums(text: &str) -> BTreeMap<(String, String, String), String> {
    let mut checksums = BTreeMap::new();
    for block in text.split("[[package]]").skip(1) {
        let field = |key: &str| {
            block.lines().find_map(|line| {
                line.trim()
                    .strip_prefix(key)
                    .and_then(|rest| rest.trim_start().strip_prefix('='))
                    .map(|value| value.trim().trim_matches('"').to_owned())
            })
        };
        if let (Some(name), Some(version), Some(source), Some(checksum)) = (
            field("name"),
            field("version"),
            field("source"),
            field("checksum"),
        ) {
            checksums.insert((name, version, source), checksum);
        }
    }
    checksums
}

/// The reviewed-list entry for one build-code target, or a refusal.
pub(super) fn entry(
    name: &str,
    version: &str,
    source: Option<&str>,
    kind: &str,
    manifest: &Path,
    lock: &BTreeMap<(String, String, String), String>,
) -> Result<ReviewedEntry> {
    let Some(source) = source else {
        return Err(fail(format!(
            "checkout build code is forbidden in fixture graphs: {kind} in {}",
            manifest.display()
        )));
    };
    if !source.starts_with("registry+") {
        return Err(fail(format!(
            "non-registry build code is forbidden in fixture graphs: {kind} {name}@{version} from {source}"
        )));
    }
    let checksum = lock
        .get(&(name.to_owned(), version.to_owned(), source.to_owned()))
        .ok_or_else(|| {
            fail(format!(
                "no Cargo.lock checksum for build code {name}@{version}"
            ))
        })?;
    Ok(ReviewedEntry {
        package: name.to_owned(),
        version: version.to_owned(),
        source: source.to_owned(),
        kind: kind.to_owned(),
        checksum: checksum.clone(),
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
                .map(|e| format!("{} {}@{} ({})", e.kind, e.package, e.version, e.checksum))
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
