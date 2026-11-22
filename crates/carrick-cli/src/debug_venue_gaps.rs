//! `carrick debug venue-gaps`: diff native-oracle syscall profiles against
//! Carrick's routing for the root and a native child (#1906). The diff
//! itself lives in `crate::venue_gaps`.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

fn censuses(inputs: &[PathBuf]) -> Result<Vec<carrick_runtime::el1_census::Census>> {
    let mut out = Vec::new();
    for input in inputs {
        let mut files = Vec::new();
        if input.is_dir() {
            for entry in crate::debug_el1_census::collect(input)? {
                let path = entry?.path();
                if path.extension().is_some_and(|e| e == "json") {
                    files.push(path);
                }
            }
            files.sort();
        } else {
            files.push(input.clone());
        }
        for file in files {
            let bytes =
                std::fs::read(&file).with_context(|| format!("read census {}", file.display()))?;
            out.push(
                serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse census {}", file.display()))?,
            );
        }
    }
    Ok(out)
}

/// The row name of a profile: its parent directory (`<out>/<row>/profile.txt`).
fn row_name(profile: &Path) -> String {
    profile.parent().and_then(|p| p.file_name()).map_or_else(
        || profile.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

pub(crate) fn run_venue_gaps(profiles: &[PathBuf], census: &[PathBuf], all: bool) -> Result<()> {
    let census = if census.is_empty() {
        None
    } else {
        Some(crate::venue_gaps::census_refusals(&censuses(census)?))
    };
    for path in profiles {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read profile {}", path.display()))?;
        let profile = crate::venue_gaps::parse_profile(&text)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("profile {}", path.display()))?;
        print!(
            "{}",
            crate::venue_gaps::render(&row_name(path), &profile, census.as_ref(), all)
                .map_err(anyhow::Error::msg)?
        );
        println!();
    }
    Ok(())
}
