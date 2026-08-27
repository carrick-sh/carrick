//! Blocker and inventory audit for legacy multi-container dedicated service runners.
//!
//! # Unmigrated Legacy Runners (0 Migrated / 3 Blocked)
//!
//! The following multi-container service tests from `crates/carrick-cli/tests/conformance.rs`
//! cannot be migrated to `carrick-conformance-next` with the current `carrick-embed` API:
//!
//! 1. `conformance_bridge_compose_pair` (participating probes: `bridge_compose_server`, `bridge_compose_client`)
//! 2. `conformance_native_udp_service_pair` (participating probes: `udp_published_server`, `udp_published_client`)
//! 3. `conformance_native_multi_network_roles` (participating probes: `multi_network_server`, `multi_network_client`, `multi_network_dns_client`)
//!
//! # Authoritative Status
//!
//! These tests remain **authoritative only on the legacy out-of-process runner** in
//! `crates/carrick-cli/tests/conformance.rs`.
//!
//! # Missing `carrick-embed` Capabilities
//!
//! Executing these tests in-process requires APIs that do not currently exist in `carrick-embed`:
//! - `NetworkMode::Bridge` / `--net bridge` configuration on `ContainerBuilder` / `TestContainer`.
//! - Container naming (`--name <name>`) and embedded bridge DNS service discovery (resolving container names to peer bridge IPs).
//! - Concurrent in-process multi-container virtual network bridging and inter-container packet routing.
//! - Network-role isolation semantics and negative DNS resolution.
//!
//! Rather than faking, mocking, or simplifying the multi-container network topology, these runners
//! remain unmigrated until true in-process bridge networking is designed and implemented.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

/// The 3 unmigrated multi-container dedicated service runners.
pub const BLOCKED_SERVICE_RUNNERS: &[&str] = &[
    "conformance_bridge_compose_pair",
    "conformance_native_udp_service_pair",
    "conformance_native_multi_network_roles",
];

/// The 7 probe binaries required by the dedicated service runners.
pub const DEDICATED_SERVICE_PROBES: &[&str] = &[
    "bridge_compose_server",
    "bridge_compose_client",
    "udp_published_server",
    "udp_published_client",
    "multi_network_server",
    "multi_network_client",
    "multi_network_dns_client",
];

/// The categories of missing `carrick-embed` APIs blocking in-process migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingCapabilityCategory {
    BridgeNetworkMode,
    ContainerNamingAndDnsDiscovery,
    InterContainerRouting,
    NetworkRoleIsolation,
}

/// Blocker record for an unmigrated dedicated service test.
pub struct BlockedRunnerAudit {
    pub runner_name: &'static str,
    pub probes: &'static [&'static str],
    pub missing_capabilities: &'static [MissingCapabilityCategory],
    pub reason: &'static str,
}

pub const BLOCKED_RUNNER_AUDITS: &[BlockedRunnerAudit] = &[
    BlockedRunnerAudit {
        runner_name: "conformance_bridge_compose_pair",
        probes: &["bridge_compose_server", "bridge_compose_client"],
        missing_capabilities: &[
            MissingCapabilityCategory::BridgeNetworkMode,
            MissingCapabilityCategory::ContainerNamingAndDnsDiscovery,
            MissingCapabilityCategory::InterContainerRouting,
        ],
        reason: "Requires in-process bridge networking and DNS resolution of container name 'db'",
    },
    BlockedRunnerAudit {
        runner_name: "conformance_native_udp_service_pair",
        probes: &["udp_published_server", "udp_published_client"],
        missing_capabilities: &[
            MissingCapabilityCategory::BridgeNetworkMode,
            MissingCapabilityCategory::ContainerNamingAndDnsDiscovery,
            MissingCapabilityCategory::InterContainerRouting,
        ],
        reason: "Requires in-process bridge networking and UDP datagram routing to container name 'udp-server'",
    },
    BlockedRunnerAudit {
        runner_name: "conformance_native_multi_network_roles",
        probes: &[
            "multi_network_server",
            "multi_network_client",
            "multi_network_dns_client",
        ],
        missing_capabilities: &[
            MissingCapabilityCategory::BridgeNetworkMode,
            MissingCapabilityCategory::ContainerNamingAndDnsDiscovery,
            MissingCapabilityCategory::InterContainerRouting,
            MissingCapabilityCategory::NetworkRoleIsolation,
        ],
        reason: "Requires multi-container bridge topology, bridge DNS queries, and negative network isolation",
    },
];

// ---------------------------------------------------------------------------
// Host audit tests
// ---------------------------------------------------------------------------

#[test]
fn audit_blocked_runner_inventory_and_counts() {
    assert_eq!(
        BLOCKED_SERVICE_RUNNERS.len(),
        3,
        "exactly 3 legacy service runners must be tracked as blocked"
    );
    assert_eq!(
        BLOCKED_RUNNER_AUDITS.len(),
        3,
        "all 3 blocked service runners must have audit records"
    );

    let runner_names: BTreeSet<_> = BLOCKED_SERVICE_RUNNERS.iter().copied().collect();
    let audit_names: BTreeSet<_> = BLOCKED_RUNNER_AUDITS
        .iter()
        .map(|a| a.runner_name)
        .collect();
    assert_eq!(runner_names, audit_names);
}

#[test]
fn audit_dedicated_service_probes_inventory() {
    assert_eq!(
        DEDICATED_SERVICE_PROBES.len(),
        7,
        "exactly 7 dedicated probe binaries must participate in the blocked runners"
    );

    let unique_probes: BTreeSet<_> = DEDICATED_SERVICE_PROBES.iter().copied().collect();
    assert_eq!(
        unique_probes.len(),
        7,
        "all 7 dedicated probe names must be unique"
    );

    let repo_root = common::repo_root();
    for probe in DEDICATED_SERVICE_PROBES {
        let src_path = repo_root.join(format!("conformance-probes/src/bin/{probe}.rs"));
        assert!(
            src_path.is_file(),
            "source for dedicated probe binary {probe:?} must exist at {}",
            src_path.display()
        );
    }
}

#[test]
fn audit_missing_capability_categories_are_assigned() {
    for audit in BLOCKED_RUNNER_AUDITS {
        assert!(
            !audit.missing_capabilities.is_empty(),
            "runner {} must declare missing capability categories",
            audit.runner_name
        );
        assert!(
            !audit.reason.is_empty(),
            "runner {} must declare a descriptive blocker reason",
            audit.runner_name
        );
        for probe in audit.probes {
            assert!(
                DEDICATED_SERVICE_PROBES.contains(probe),
                "audit for {} references unknown probe {}",
                audit.runner_name,
                probe
            );
        }
    }
}
