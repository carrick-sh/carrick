//! Deterministic longest-first placement and complete, identity-bound merging.
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const UNKNOWN_TIMING_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shard {
    /// User-facing indices are 1-based.
    pub index: usize,
    pub count: usize,
}

impl Shard {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        let (index, count) = value
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("--shard expects i/N (1-based)"))?;
        let shard = Self {
            index: index.parse()?,
            count: count.parse()?,
        };
        anyhow::ensure!(
            shard.count > 0 && shard.index > 0 && shard.index <= shard.count,
            "invalid shard {value:?}"
        );
        Ok(shard)
    }
}

pub fn partition(
    names: &[String],
    timings: &BTreeMap<String, u64>,
    count: usize,
) -> anyhow::Result<Vec<Vec<String>>> {
    anyhow::ensure!(count > 0, "shard count must be positive");
    anyhow::ensure!(
        names.iter().collect::<BTreeSet<_>>().len() == names.len(),
        "duplicate selection names"
    );
    let cost = |name: &String| {
        timings
            .get(name)
            .copied()
            .unwrap_or(UNKNOWN_TIMING_MS)
            .max(1)
    };
    let mut order = names.to_vec();
    order.sort_by(|a, b| cost(b).cmp(&cost(a)).then_with(|| a.cmp(b)));
    let mut shards = vec![Vec::new(); count];
    let mut loads = vec![0_u128; count];
    for name in order {
        let index = loads
            .iter()
            .enumerate()
            .min_by_key(|(index, load)| (**load, *index))
            .map(|(index, _)| index)
            .ok_or_else(|| anyhow::anyhow!("no shards"))?;
        loads[index] += u128::from(cost(&name));
        shards[index].push(name);
    }
    Ok(shards)
}

/// Committed timing records, max observed duration per name. No live timing
/// influences placement; unknown suites use the fixed one-second default.
pub fn timings(path: &Path) -> anyhow::Result<BTreeMap<String, u64>> {
    let mut timings: BTreeMap<String, u64> = BTreeMap::new();
    let text = std::fs::read_to_string(path)?;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line)?;
        let name = row["name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("timing missing name"))?;
        let elapsed = row["elapsed_ms"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("timing missing elapsed_ms"))?;
        timings
            .entry(name.into())
            .and_modify(|v| *v = (*v).max(elapsed))
            .or_insert(elapsed);
    }
    Ok(timings)
}

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunIdentity {
    pub head: String,
    pub carrick_sha256: String,
    pub kernel: String,
    pub manifest_hash: String,
    pub selection_hash: String,
    pub oracle_backend: String,
    pub lane: String,
    pub timings_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_images_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardHeader {
    pub identity: RunIdentity,
    pub shard_index: usize,
    pub assignments: Vec<Vec<String>>,
}

pub fn header_path(results: &Path) -> PathBuf {
    results.with_extension("header.json")
}

pub fn write_header(results: &Path, header: &ShardHeader) -> anyhow::Result<()> {
    if let Some(parent) = results.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(header_path(results), serde_json::to_vec_pretty(header)?)?;
    Ok(())
}

pub fn merge(paths: &[PathBuf]) -> anyhow::Result<Vec<serde_json::Value>> {
    anyhow::ensure!(!paths.is_empty(), "--merge-shards requires input files");
    let mut common: Option<ShardHeader> = None;
    let mut seen_indices = BTreeSet::new();
    let mut rows = BTreeMap::new();
    for path in paths {
        let header: ShardHeader = serde_json::from_slice(&std::fs::read(header_path(path))?)?;
        anyhow::ensure!(
            header.shard_index > 0 && header.shard_index <= header.assignments.len(),
            "invalid shard header"
        );
        if let Some(first) = &common {
            anyhow::ensure!(
                first.identity == header.identity && first.assignments == header.assignments,
                "mismatched shard headers: {}",
                path.display()
            );
        } else {
            let names: Vec<_> = header.assignments.iter().flatten().collect();
            anyhow::ensure!(
                names.len() == names.iter().collect::<BTreeSet<_>>().len(),
                "duplicate cases in shard assignment"
            );
            common = Some(header.clone());
        }
        anyhow::ensure!(
            seen_indices.insert(header.shard_index),
            "duplicate shard index"
        );
        let expected: BTreeSet<_> = header.assignments[header.shard_index - 1]
            .iter()
            .cloned()
            .collect();
        let mut have = BTreeSet::new();
        for line in std::fs::read_to_string(path)?
            .lines()
            .filter(|line| !line.trim().is_empty())
        {
            let row: serde_json::Value = serde_json::from_str(line)?;
            let name = row["name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("report missing name"))?
                .to_string();
            anyhow::ensure!(
                expected.contains(&name),
                "unexpected case {name} in {}",
                path.display()
            );
            anyhow::ensure!(
                have.insert(name.clone()) && rows.insert(name.clone(), row).is_none(),
                "duplicate case {name}"
            );
        }
        anyhow::ensure!(have == expected, "missing cases in {}", path.display());
    }
    let first = common.ok_or_else(|| anyhow::anyhow!("missing header"))?;
    anyhow::ensure!(
        seen_indices.len() == first.assignments.len(),
        "missing shard files"
    );
    Ok(rows.into_values().collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn merge_rejects_mismatch_duplicates_and_missing_cases() {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<_> = (0..2)
            .map(|i| dir.path().join(format!("shard-{i}.jsonl")))
            .collect();
        let identity = RunIdentity {
            head: "head".into(),
            carrick_sha256: "binary".into(),
            kernel: "kernel".into(),
            manifest_hash: "manifest".into(),
            selection_hash: "selection".into(),
            oracle_backend: "native".into(),
            lane: "kvm-local".into(),
            timings_hash: "timings".into(),
            native_images_hash: Some("images".into()),
        };
        let headers: Vec<_> = (0..2)
            .map(|i| ShardHeader {
                identity: identity.clone(),
                shard_index: i + 1,
                assignments: vec![vec!["a".into()], vec!["b".into()]],
            })
            .collect();
        for i in 0..2 {
            write_header(&paths[i], &headers[i]).unwrap();
            std::fs::write(
                &paths[i],
                format!("{{\"name\":\"{}\"}}\n", if i == 0 { "a" } else { "b" }),
            )
            .unwrap();
        }
        assert_eq!(merge(&paths).unwrap().len(), 2);
        for field in [
            "head",
            "carrick_sha256",
            "kernel",
            "manifest_hash",
            "selection_hash",
            "oracle_backend",
            "lane",
            "timings_hash",
            "native_images_hash",
        ] {
            let mut changed = serde_json::to_value(&headers[1]).unwrap();
            changed["identity"][field] = "different".into();
            std::fs::write(
                header_path(&paths[1]),
                serde_json::to_vec(&changed).unwrap(),
            )
            .unwrap();
            assert!(merge(&paths).is_err(), "must reject {field}");
        }
        write_header(&paths[1], &headers[1]).unwrap();
        assert!(merge(&paths[..1]).is_err());
        std::fs::write(&paths[1], "").unwrap();
        assert!(merge(&paths).is_err());
        std::fs::write(&paths[1], "{\"name\":\"b\"}\n{\"name\":\"b\"}\n").unwrap();
        assert!(merge(&paths).is_err());
        assert!(merge(&[paths[0].clone(), paths[0].clone()]).is_err());
    }
}
