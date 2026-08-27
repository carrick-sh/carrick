//! Dedicated container and topology conformance test audit.
//!
//! Evaluates the migration of legacy dedicated container and topology runners from
//! `crates/carrick-cli/tests/conformance.rs` into `carrick-conformance-next`.
//!
//! # Test Classification & Blocker Inventory
//!
//! All 3 legacy tests (covering 5 dedicated probe names) are currently **BLOCKED** from in-process
//! embed migration because the required topology and carrier verification primitives are not exposed
//! in `carrick-embed`'s public API without modifying library/runtime crates. Their legacy runners
//! in `crates/carrick-cli/tests/conformance.rs` remain authoritative.
//!
//! ### 1. `conformance_container_gate` (`container_gate` probe) — BLOCKED
//! - **Reason**: The legacy test asserts both `vm_create_success_events == 1` (proving both containers
//!   share exactly one HVF VM in one carrier per sequential/concurrent mode) and `live_containers_after == 0`
//!   (proving complete container teardown and zero carrier leaks).
//! - **Missing API**: `carrick-embed` does not expose carrier-level VM lifecycle telemetry
//!   (`vm_lifecycle::process_snapshot`) or live container census (`carrier::live_container_count`).
//! - **Authoritative Suite**: `crates/carrick-cli/tests/conformance.rs::conformance_container_gate`.
//!
//! ### 2. `conformance_native_host_gateway` (`host_gateway_client` probe) — BLOCKED
//! - **Reason**: Requires bridge networking mode (`--net bridge`), bridge gateway address allocation
//!   (`172.31.0.1`), and host gateway DNS resolution (`host.docker.internal` -> gateway IP) to connect
//!   from guest to a host TCP listener.
//! - **Missing API**: `carrick-embed` hardcodes `NetworkMode::Host` with `bridge_namespace_id: None`
//!   and does not provide builder APIs to configure bridge networking, allocate bridge gateways, or
//!   synthesize host gateway DNS resolution in-process.
//! - **Authoritative Suite**: `crates/carrick-cli/tests/conformance.rs::conformance_native_host_gateway`.
//!
//! ### 3. `docker_compose_shared_network_namespace_smoke` (`sidecar_loopback_server`, `sidecar_loopback_client`, `sidecar_loopback_isolated_client` probes) — BLOCKED
//! - **Reason**: Requires a multi-container shared network namespace topology (`network_mode: "service:db"`)
//!   where a sidecar container shares the loopback interface and network namespace of a server container
//!   while a third container is isolated on a bridge network.
//! - **Missing API**: `carrick-embed` does not provide an API to configure bridge networks, create
//!   shared container network namespaces, or join another container's network namespace in-process.
//! - **Authoritative Suite**: `crates/carrick-cli/tests/conformance.rs::docker_compose_shared_network_namespace_smoke`.
//!
//! Run verification via:
//!   cargo test -p carrick-conformance-next --test dedicated_container_topologies
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[derive(Debug, PartialEq, Eq)]
pub enum MigrationStatus {
    Migrated,
    Blocked { reason: &'static str },
}

pub struct DedicatedTestAudit {
    pub legacy_test: &'static str,
    pub probe_names: &'static [&'static str],
    pub status: MigrationStatus,
}

pub const DEDICATED_TOPOLOGY_AUDITS: &[DedicatedTestAudit] = &[
    DedicatedTestAudit {
        legacy_test: "conformance_container_gate",
        probe_names: &["container_gate"],
        status: MigrationStatus::Blocked {
            reason: "Missing public carrick-embed APIs to verify vm_create_success_events == 1 (single-VM sharing) and live_containers_after == 0 (carrier teardown)",
        },
    },
    DedicatedTestAudit {
        legacy_test: "conformance_native_host_gateway",
        probe_names: &["host_gateway_client"],
        status: MigrationStatus::Blocked {
            reason: "Missing public carrick-embed APIs for bridge networking mode (--net bridge), gateway IP allocation (172.31.0.1), and host.docker.internal resolution",
        },
    },
    DedicatedTestAudit {
        legacy_test: "docker_compose_shared_network_namespace_smoke",
        probe_names: &[
            "sidecar_loopback_server",
            "sidecar_loopback_client",
            "sidecar_loopback_isolated_client",
        ],
        status: MigrationStatus::Blocked {
            reason: "Missing public carrick-embed APIs for shared container network namespaces (network_mode: service:db) and inter-container loopback sharing",
        },
    },
];

#[test]
fn test_dedicated_container_topologies_blocker_audit() {
    let mut migrated_tests = Vec::new();
    let mut blocked_tests = Vec::new();
    let mut total_probes = 0;

    for audit in DEDICATED_TOPOLOGY_AUDITS {
        total_probes += audit.probe_names.len();
        match &audit.status {
            MigrationStatus::Migrated => migrated_tests.push(audit.legacy_test),
            MigrationStatus::Blocked { reason } => {
                assert!(
                    !reason.is_empty(),
                    "blocked test {} must provide a non-empty reason",
                    audit.legacy_test
                );
                blocked_tests.push(audit.legacy_test);
            }
        }
    }

    assert_eq!(
        migrated_tests.len(),
        0,
        "no dedicated topology test can be migrated with full fidelity without library/runtime API extensions: {migrated_tests:?}"
    );
    assert_eq!(
        blocked_tests.len(),
        3,
        "all 3 dedicated topology runners must be explicitly classified as blocked"
    );
    assert_eq!(
        total_probes, 5,
        "all 5 dedicated probe names across the 3 legacy runners must be audited"
    );
}
