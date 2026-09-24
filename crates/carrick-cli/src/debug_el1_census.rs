//! `carrick debug el1-census`: rank one or more EL1 census files (written by
//! runs with `CARRICK_EL1_CENSUS=<directory>`) by host syscall CPU.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

fn collect(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for input in inputs {
        if input.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(input)
                .with_context(|| format!("read census directory {}", input.display()))?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .collect();
            entries.sort();
            files.extend(entries);
        } else {
            files.push(input.clone());
        }
    }
    Ok(files)
}

fn load(path: &Path) -> Result<carrick_runtime::el1_census::Census> {
    let bytes = std::fs::read(path).with_context(|| format!("read census {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse census {}", path.display()))
}

pub(crate) fn run_el1_census(inputs: &[PathBuf], limit: usize, json: bool) -> Result<()> {
    let files = collect(inputs)?;
    let censuses = files.iter().map(|f| load(f)).collect::<Result<Vec<_>>>()?;
    let aggregate =
        carrick_runtime::el1_census::aggregate(&censuses).map_err(anyhow::Error::msg)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&aggregate)?);
    } else {
        print!(
            "{}",
            carrick_runtime::el1_census::render_table(&aggregate, limit)
        );
    }
    Ok(())
}
