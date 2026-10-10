//! Check that declared USDT probes have live emitters in the workspace.
//!
//! A probe declared in the `carrick` DTrace provider that has no emitter in the
//! runtime will never fire. Tracing scripts arming such probes will observe zero
//! events. This module validates that every declared probe is emitted, ratcheting
//! down legacy unemitted probes identified in the 2026-10-10 audit.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(clap::Args, Debug, Clone)]
pub struct ProbeEmittersArgs {
    #[command(subcommand)]
    pub action: ProbeEmittersAction,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum ProbeEmittersAction {
    #[command(about = "List all declared USDT probes and their emission status")]
    List,
    #[command(about = "Fail if newly declared probes have no emitters in the workspace")]
    Check,
}

#[derive(Debug, Error)]
pub enum ProbeEmittersError {
    #[error("I/O error at '{}': {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("probe provider block not found in {}", path.display())]
    ProviderNotFound { path: PathBuf },
    #[error("probe emitter check failed:\n{0}")]
    Check(String),
}

/// Baseline of legacy probes declared in `carrick-observability/src/probes.rs` that
/// currently have no live emitter in the workspace (documented in audit 2026-10-10 §2.4).
/// New declared probes MUST have live emitters and must not be added here.
pub const KNOWN_UNEMITTED_PROBES: &[&str] = &[
    "dsr__cache__bounds",
    "dsr__cache__capacity",
    "dsr__cache__event",
    "dsr__exec__map__detail",
    "dsr__prepare__begin",
    "dsr__prepare__end",
    "dsr__resolve__begin",
    "dsr__resolve__end",
    "dsr__run__begin",
    "dsr__run__end",
    "dsr__synchronization__begin",
    "dsr__synchronization__end",
    "dsr__translate__begin",
    "dsr__translate__end",
    "dsr__translate__subphase__begin",
    "dsr__translate__subphase__end",
    "fork__footprint",
    "fork__footprint__class",
    "fork__lifecycle",
    "fork__post",
    "fork__pre",
    "fork__rebuild",
    "futex__unexpected__errno",
    "guest__image__base",
    "guest__mem__payload",
    "guest__mem__region",
    "guest__mem__subcount",
    "guest__mem__subedge",
    "guest__mem__subrange",
    "guest__mem__tail",
    "host__image__catalog",
    "host__image__text__range",
    "host__jit__range",
    "host__native__owned__range__add",
    "host__native__owned__range__ready",
    "host__native__owned__range__reset",
    "host__process__birth",
    "host__translated__private__range",
    "host__translated__range__ready",
    "host__translated__range__reset",
    "host__translated__shared__range",
    "hvpatch__el1__fault__root__mapping",
    "hvpatch__exec__predecessor__classification__asid",
    "hvpatch__exec__predecessor__classification__identity",
    "hvpatch__fork__frame",
    "hvpatch__fork__frame__identity",
    "hvpatch__fork__private__snapshot",
    "hvpatch__fork__private__snapshot__outcome",
    "hvpatch__frame__cow__identity",
    "hvpatch__frame__cow__intent",
    "hvpatch__frame__cow__trigger__identity",
    "hvpatch__guest__exit",
    "hvpatch__guest__fault",
    "hvpatch__guest__fault__asid",
    "hvpatch__guest__lifecycle__identity",
    "hvpatch__mapping__index__cost",
    "hvpatch__mm__maintenance__population",
    "hvpatch__mm__maintenance__work",
    "hvpatch__sparse__boundary__walk",
    "hvpatch__syscall__args",
    "hvpatch__syscall__service__begin",
    "native__syscall__service__branch",
    "native__syscall__service__end",
    "native__syscall__service__entry",
    "native__tierd__exception",
    "native__tierd__unsupported",
    "native__x86__fault",
    "native__x86__fault__history",
    "native__x86__fault__regs",
    "native__x86__fault__stack",
    "native__x86__pc",
    "native__x86__resolve",
    "native__x86__xstate__controls",
    "native__x86__xstate__edge",
    "native__x86__xstate__hashes",
    "pt__fault__next__walk",
    "pt__pause__timeout",
    "pt__pool",
    "signal__unsupported",
    "supervisor__child__exit",
    "supervisor__child__ready",
    "supervisor__foreground__pgrp",
    "supervisor__fork",
    "syscall__entry",
    "syscall__mailbox__lifecycle",
    "vcpu__fault__gprs",
    "vcpu__fault__regs",
];

/// Collect all `.rs` source files in `crates/` excluding probes and probe_emitters definitions.
fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let path_str = path.to_string_lossy();
        if path_str.ends_with("carrick-observability/src/probes.rs")
            || path_str.ends_with("carrick-xtask/src/probe_emitters.rs")
        {
            continue;
        }
        if path.is_dir() {
            collect_rust_files(&path, files)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

/// Parse declared probes from `carrick-observability/src/probes.rs`.
pub fn parse_declared_probes(probes_rs_content: &str) -> Vec<String> {
    let mut declared = Vec::new();
    let mut in_provider = false;
    for line in probes_rs_content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("#[::usdt::provider(provider = \"carrick\")]") {
            in_provider = true;
            continue;
        }
        if in_provider {
            if let Some(rest) = trimmed.strip_prefix("fn ") {
                let name = rest.split('(').next().unwrap_or(rest);
                declared.push(name.trim().to_string());
            } else if line.starts_with("    }") {
                in_provider = false;
            }
        }
    }
    declared
}

/// Analysis results for all declared probes.
#[derive(Debug, Clone)]
pub struct ProbeReport {
    pub declared: Vec<String>,
    pub emitted: BTreeSet<String>,
    pub unemitted: BTreeSet<String>,
}

pub fn analyze_probes(root: &Path) -> Result<ProbeReport, ProbeEmittersError> {
    let probes_path = root.join("crates/carrick-observability/src/probes.rs");
    let probes_text =
        std::fs::read_to_string(&probes_path).map_err(|source| ProbeEmittersError::Io {
            path: probes_path.clone(),
            source,
        })?;

    let declared = parse_declared_probes(&probes_text);
    if declared.is_empty() {
        return Err(ProbeEmittersError::ProviderNotFound { path: probes_path });
    }

    let mut other_rs_files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut other_rs_files).map_err(|source| {
        ProbeEmittersError::Io {
            path: root.join("crates"),
            source,
        }
    })?;

    let mut workspace_sources = String::new();
    for file in &other_rs_files {
        if let Ok(src) = std::fs::read_to_string(file) {
            workspace_sources.push_str(&src);
            workspace_sources.push('\n');
        }
    }

    let mut emitted = BTreeSet::new();
    let mut unemitted = BTreeSet::new();

    for probe in &declared {
        let macro_name = format!("carrick_usdt::{probe}!");
        let single_under = probe.replace("__", "_");

        let mut direct_callers = BTreeSet::new();
        direct_callers.insert(probe.as_str());
        direct_callers.insert(single_under.as_str());

        let is_emitted = workspace_sources.contains(&macro_name)
            || direct_callers
                .iter()
                .any(|name| contains_word(&workspace_sources, name));

        if is_emitted {
            emitted.insert(probe.clone());
        } else {
            unemitted.insert(probe.clone());
        }
    }

    Ok(ProbeReport {
        declared,
        emitted,
        unemitted,
    })
}

fn contains_word(haystack: &str, word: &str) -> bool {
    let mut offset = 0;
    while let Some(pos) = haystack[offset..].find(word) {
        let abs_pos = offset + pos;
        let before_ok = if abs_pos == 0 {
            true
        } else {
            haystack[..abs_pos]
                .chars()
                .next_back()
                .is_some_and(|c| !c.is_alphanumeric() && c != '_')
        };
        let end_pos = abs_pos + word.len();
        let after_ok = if end_pos == haystack.len() {
            true
        } else {
            haystack[end_pos..]
                .chars()
                .next()
                .is_some_and(|c| !c.is_alphanumeric() && c != '_')
        };
        if before_ok && after_ok {
            return true;
        }
        offset = abs_pos + word.len();
    }
    false
}

pub fn run(
    root: &Path,
    args: ProbeEmittersArgs,
    writer: &mut dyn std::io::Write,
) -> Result<(), ProbeEmittersError> {
    let report = analyze_probes(root)?;
    let io = |source| ProbeEmittersError::Io {
        path: PathBuf::from("stdout"),
        source,
    };

    match args.action {
        ProbeEmittersAction::List => {
            for probe in &report.declared {
                let status = if report.emitted.contains(probe) {
                    "EMITTED"
                } else {
                    "UNEMITTED"
                };
                writeln!(writer, "{:<12} {probe}", status).map_err(io)?;
            }
        }
        ProbeEmittersAction::Check => {
            let known: BTreeSet<&str> = KNOWN_UNEMITTED_PROBES.iter().copied().collect();
            let mut unexpected_unemitted = Vec::new();

            for probe in &report.unemitted {
                if !known.contains(probe.as_str()) {
                    unexpected_unemitted.push(probe.clone());
                }
            }

            if !unexpected_unemitted.is_empty() {
                let list = unexpected_unemitted.join("\n  ");
                return Err(ProbeEmittersError::Check(format!(
                    "{} newly declared USDT probe(s) have no live emitter in workspace:\n  {list}\n\
                     Add a caller in production code or remove the probe from provider definition.",
                    unexpected_unemitted.len()
                )));
            }

            let ceiling = KNOWN_UNEMITTED_PROBES.len();
            writeln!(
                writer,
                "probe-emitters: {} declared probes ({} live emitters, {} known unemitted, ceiling {})",
                report.declared.len(),
                report.emitted.len(),
                report.unemitted.len(),
                ceiling
            )
            .map_err(io)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_declared_probes_extracts_all_declarations() {
        let fake = r#"
#[::usdt::provider(provider = "carrick")]
mod carrick_usdt {
    fn foo__bar(_: u32) {}
    fn baz(_: u64, _: &str) {}
}
"#;
        let probes = parse_declared_probes(fake);
        assert_eq!(probes, vec!["foo__bar", "baz"]);
    }
}
