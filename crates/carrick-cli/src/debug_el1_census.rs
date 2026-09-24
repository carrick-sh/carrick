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

/// Join each census to its conformance result row (by `carrick_run_id`) and
/// print one line per suite, slowest ratio first.
fn per_suite(files: &[PathBuf], results: &Path, limit: usize) -> Result<()> {
    let mut by_run = std::collections::HashMap::new();
    for file in files {
        let census = load(file)?;
        if let Some(run_id) = census.run_id.clone() {
            by_run.insert(run_id, census);
        }
    }
    let text = std::fs::read_to_string(results)
        .with_context(|| format!("read results {}", results.display()))?;
    let mut rows = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let value: serde_json::Value =
            serde_json::from_str(line).with_context(|| format!("parse result line {line}"))?;
        let Some(run_id) = value["carrick_run_id"].as_str() else {
            continue;
        };
        let Some(census) = by_run.get(run_id) else {
            continue;
        };
        rows.push((
            value["name"].as_str().unwrap_or("?").to_owned(),
            value["ecosystem"].as_str().unwrap_or("?").to_owned(),
            value["verdict"].as_str().unwrap_or("?").to_owned(),
            value["perf"]["carrick_to_oracle_ratio"].as_f64(),
            value["perf"]["carrick_ms"].as_u64(),
            carrick_runtime::el1_census::summarize(census),
        ));
    }
    anyhow::ensure!(!rows.is_empty(), "no census matched a result row");
    rows.sort_by(|a, b| {
        b.3.unwrap_or(0.0)
            .partial_cmp(&a.3.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    println!("suites joined: {}", rows.len());
    println!(
        "| suite | ecosystem | verdict | ratio | carrick ms | host syscall ms | share of carrier CPU | EL1 served | host services | top forwarded class |"
    );
    println!("|---|---|---|---:|---:|---:|---:|---:|---:|---|");
    for (name, eco, verdict, ratio, ms, summary) in rows.iter().take(limit) {
        println!(
            "| {name} | {eco} | {verdict} | {} | {} | {:.1} | {} | {} | {} | {} |",
            ratio.map_or_else(|| "-".to_owned(), |r| format!("{r:.2}")),
            ms.map_or_else(|| "-".to_owned(), |m| m.to_string()),
            summary.host_syscall_ns as f64 / 1e6,
            summary
                .syscall_share()
                .map_or_else(|| "-".to_owned(), |s| format!("{s:.1}%")),
            summary.el1_served,
            summary.host_services,
            summary.top_class.as_ref().map_or_else(
                || "-".to_owned(),
                |(n, ns)| format!("{n} {:.1} ms", *ns as f64 / 1e6)
            ),
        );
    }
    Ok(())
}

pub(crate) fn run_el1_census(
    inputs: &[PathBuf],
    limit: usize,
    json: bool,
    results: Option<&Path>,
) -> Result<()> {
    let files = collect(inputs)?;
    if let Some(results) = results {
        return per_suite(&files, results, limit);
    }
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
