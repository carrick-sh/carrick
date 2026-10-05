use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeInventoryRow {
    pub class: String,
    pub runner: String,
    pub excluded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePartition {
    pub generic_names: Vec<String>,
    pub shards: [Vec<String>; 3],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeCounts {
    pub total_sources: usize,
    pub class_counts: BTreeMap<String, usize>,
    pub runner_counts: BTreeMap<String, usize>,
    pub generic_conformance_count: usize,
    pub dedicated_conformance_count: usize,
    pub total_conformance_count: usize,
    pub two_libc_conformance_rows: usize,
}

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("I/O error at '{}': {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("duplicate probe key in inventory: {0}")]
    DuplicateKey(String),
    #[error(
        "probe source inventory drift: missing={missing_from_inventory:?}, absent_from_disk={absent_from_disk:?}"
    )]
    SourceInventoryDrift {
        missing_from_inventory: Vec<String>,
        absent_from_disk: Vec<String>,
    },
    #[error("invalid probe row for '{probe}': {details}")]
    InvalidRow { probe: String, details: String },
}

/// The authoritative topology-specific bindings used by coverage validation and
/// the closure harness. Every probe not listed here must use `generic`.
pub const DEDICATED_PROBE_RUNNERS: &[(&str, &str)] = &[
    // This probe needs signed execution of warm ptrace-patched text; the
    // `carrick-conformance-next` ptrace suite owns it instead of generic shards.
    (
        "ptracepoketext",
        "production_rx_poketext_executes_warm_patched_instruction",
    ),
    ("bridge_compose_client", "conformance_bridge_compose_pair"),
    ("bridge_compose_server", "conformance_bridge_compose_pair"),
    ("bridge_dns_epoll_wake", "conformance_bridge_dns_epoll_wake"),
    (
        "bridge_loopback_isolation",
        "conformance_bridge_loopback_isolation",
    ),
    ("bridge_net_identity", "conformance_bridge_net_identity"),
    ("bridge_publish_tcp", "conformance_bridge_publish_tcp"),
    ("bridge_reuse_sockopts", "conformance_bridge_reuse_sockopts"),
    (
        "bridge_tcp_nonblocking_refused",
        "conformance_bridge_tcp_nonblocking_refused",
    ),
    ("bridge_tcp_peer", "conformance_bridge_tcp_peer"),
    (
        "bridge_udp_connected_unreachable",
        "conformance_bridge_udp_connected_unreachable",
    ),
    ("bridge_udp_peer", "conformance_bridge_udp_peer"),
    (
        "bridge_udp_sendto_unreachable",
        "conformance_bridge_udp_sendto_unreachable",
    ),
    ("container_gate", "conformance_container_gate"),
    ("host_gateway_client", "conformance_native_host_gateway"),
    (
        "multi_network_client",
        "conformance_native_multi_network_roles",
    ),
    (
        "multi_network_dns_client",
        "conformance_native_multi_network_roles",
    ),
    (
        "multi_network_server",
        "conformance_native_multi_network_roles",
    ),
    (
        "sidecar_loopback_client",
        "docker_compose_shared_network_namespace_smoke",
    ),
    (
        "sidecar_loopback_isolated_client",
        "docker_compose_shared_network_namespace_smoke",
    ),
    (
        "sidecar_loopback_server",
        "docker_compose_shared_network_namespace_smoke",
    ),
    (
        "udp_published_client",
        "conformance_native_udp_service_pair",
    ),
    (
        "udp_published_server",
        "conformance_native_udp_service_pair",
    ),
];

pub fn is_authorized_runner(probe: &str, runner: &str) -> bool {
    let expected = DEDICATED_PROBE_RUNNERS
        .iter()
        .find_map(|(name, binding)| (*name == probe).then_some(*binding))
        .unwrap_or("generic");
    runner == expected
}

struct UniqueMapVisitor;

impl<'de> serde::de::Visitor<'de> for UniqueMapVisitor {
    type Value = BTreeMap<String, ProbeInventoryRow>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON object with unique probe names")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: serde::de::MapAccess<'de>,
    {
        let mut map = BTreeMap::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate probe key in inventory: {key}"
                )));
            }
            let value = access.next_value::<ProbeInventoryRow>()?;
            if value.class.trim().is_empty() {
                return Err(serde::de::Error::custom(format!(
                    "probe '{key}' has empty class"
                )));
            }
            if value.runner.trim().is_empty() {
                return Err(serde::de::Error::custom(format!(
                    "probe '{key}' has empty runner"
                )));
            }
            map.insert(key, value);
        }
        Ok(map)
    }
}

pub fn load_inventory(path: &Path) -> Result<BTreeMap<String, ProbeInventoryRow>, InventoryError> {
    let raw = std::fs::read_to_string(path).map_err(|e| InventoryError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    load_inventory_from_str(&raw)
}

pub fn load_inventory_from_str(
    raw: &str,
) -> Result<BTreeMap<String, ProbeInventoryRow>, InventoryError> {
    let mut deserializer = serde_json::Deserializer::from_str(raw);
    let inventory = deserializer
        .deserialize_map(UniqueMapVisitor)
        .map_err(|e| {
            let msg = e.to_string();
            if let Some(pos) = msg.find("duplicate probe key in inventory: ") {
                let rest = &msg[pos + "duplicate probe key in inventory: ".len()..];
                let key = rest.split_whitespace().next().unwrap_or(rest).to_string();
                InventoryError::DuplicateKey(key)
            } else {
                InventoryError::Json(e)
            }
        })?;
    deserializer.end().map_err(InventoryError::Json)?;
    Ok(inventory)
}

pub fn read_probe_source_names(src_bin_dir: &Path) -> Result<BTreeSet<String>, InventoryError> {
    let entries = std::fs::read_dir(src_bin_dir).map_err(|e| InventoryError::Io {
        path: src_bin_dir.to_path_buf(),
        source: e,
    })?;
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|e| InventoryError::Io {
            path: src_bin_dir.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "rs") {
            let stem = path.file_stem().and_then(|s| s.to_str());
            names.extend(stem.map(str::to_string));
        }
    }
    Ok(names)
}

pub fn validate_source_membership(
    inventory_names: &BTreeSet<String>,
    source_names: &BTreeSet<String>,
) -> Result<(), InventoryError> {
    if inventory_names != source_names {
        let missing_from_inventory: Vec<_> =
            source_names.difference(inventory_names).cloned().collect();
        let absent_from_disk: Vec<_> = inventory_names.difference(source_names).cloned().collect();
        return Err(InventoryError::SourceInventoryDrift {
            missing_from_inventory,
            absent_from_disk,
        });
    }
    Ok(())
}

pub fn derive_partition(inventory: &BTreeMap<String, ProbeInventoryRow>) -> ProbePartition {
    let mut generic_names: Vec<String> = inventory
        .iter()
        .filter_map(|(name, row)| {
            if row.class == "conformance" && !row.excluded && row.runner == "generic" {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect();
    generic_names.sort();

    let mut shards: [Vec<String>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for (i, name) in generic_names.iter().enumerate() {
        shards[i % 3].push(name.clone());
    }

    ProbePartition {
        generic_names,
        shards,
    }
}

pub fn derive_counts(inventory: &BTreeMap<String, ProbeInventoryRow>) -> ProbeCounts {
    let mut class_counts = BTreeMap::new();
    let mut runner_counts = BTreeMap::new();
    let mut generic_conformance_count = 0;
    let mut dedicated_conformance_count = 0;

    for row in inventory.values() {
        *class_counts.entry(row.class.clone()).or_insert(0) += 1;
        *runner_counts.entry(row.runner.clone()).or_insert(0) += 1;
        if row.class == "conformance" && !row.excluded {
            if row.runner == "generic" {
                generic_conformance_count += 1;
            } else {
                dedicated_conformance_count += 1;
            }
        }
    }

    let total_conformance_count = generic_conformance_count + dedicated_conformance_count;
    let two_libc_conformance_rows = total_conformance_count * 2;

    ProbeCounts {
        total_sources: inventory.len(),
        class_counts,
        runner_counts,
        generic_conformance_count,
        dedicated_conformance_count,
        total_conformance_count,
        two_libc_conformance_rows,
    }
}
