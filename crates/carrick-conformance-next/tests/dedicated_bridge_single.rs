//! Dedicated single-container bridge probe blocker audit for `carrick-conformance-next`.
//!
//! Blocker audit; legacy tests in `crates/carrick-cli/tests/conformance.rs` remain authoritative.
//!
//! # Unmigrated Bridge Topology Blocker
//!
//! All 10 legacy dedicated single-container bridge probes require bridge networking:
//! - `NetworkMode::Bridge` (container-isolated network namespace with synthetic `eth0` interface
//!   assigned IPv4 address `172.31.0.2/16` and default gateway `172.31.0.1`).
//! - Synthetic rtnetlink routing, `/proc/net/dev`, `/etc/hosts` and `/etc/resolv.conf` bridge entries.
//! - Port publishing (`-p 127.0.0.1:<host_port>:8080` / `published_ports`) for `conformance_bridge_publish_tcp`.
//! - Gateway DNS responder for `conformance_bridge_dns_epoll_wake`.
//!
//! Current status in `carrick-embed`:
//! `carrick_embed::ContainerBuilder` and `TestContainer` currently hardcode `NetworkMode::Host`
//! (via `..RunRequest::default()`) and `bridge_namespace_id: None`. They do not expose builder
//! methods for `.network(NetworkMode::Bridge)`, `.publish_port(...)`, or bridge namespace configuration.
//!
//! Rather than faking, ignoring, or creating false-green test stubs, all 10 legacy cases remain
//! unmigrated (migrated=0, blocked=10). This file audits the manifest of blocked cases and their
//! required missing APIs until `carrick-embed` introduces first-class in-process bridge networking.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

/// Descriptor of a blocked dedicated single-container bridge probe and its missing embed API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedBridgeProbe {
    pub legacy_test_fn: &'static str,
    pub probe_name: &'static str,
    pub required_network_mode: &'static str,
    pub missing_embed_api: &'static str,
    pub reason: &'static str,
}

/// The exact 10 blocked legacy dedicated single-container bridge probe cases.
pub const BLOCKED_BRIDGE_PROBES: &[BlockedBridgeProbe] = &[
    BlockedBridgeProbe {
        legacy_test_fn: "conformance_bridge_dns_epoll_wake",
        probe_name: "bridge_dns_epoll_wake",
        required_network_mode: "bridge",
        missing_embed_api: "ContainerBuilder::network(NetworkMode::Bridge)",
        reason: "Requires bridge gateway DNS resolver (172.31.0.1) and epoll wake delivery",
    },
    BlockedBridgeProbe {
        legacy_test_fn: "conformance_bridge_loopback_isolation",
        probe_name: "bridge_loopback_isolation",
        required_network_mode: "bridge",
        missing_embed_api: "ContainerBuilder::network(NetworkMode::Bridge)",
        reason: "Requires eth0 IPv4 interface isolation from 127.0.0.1 loopback listener",
    },
    BlockedBridgeProbe {
        legacy_test_fn: "conformance_bridge_net_identity",
        probe_name: "bridge_net_identity",
        required_network_mode: "bridge",
        missing_embed_api: "ContainerBuilder::network(NetworkMode::Bridge)",
        reason: "Requires synthetic eth0 interface, bridge rtnetlink dump, and bridge hosts/resolv.conf",
    },
    BlockedBridgeProbe {
        legacy_test_fn: "conformance_bridge_publish_tcp",
        probe_name: "bridge_publish_tcp",
        required_network_mode: "bridge",
        missing_embed_api: "ContainerBuilder::published_ports / port forwarding",
        reason: "Requires published port mapping (-p 127.0.0.1:<host_port>:8080) and host connection orchestration",
    },
    BlockedBridgeProbe {
        legacy_test_fn: "conformance_bridge_reuse_sockopts",
        probe_name: "bridge_reuse_sockopts",
        required_network_mode: "bridge",
        missing_embed_api: "ContainerBuilder::network(NetworkMode::Bridge)",
        reason: "Requires SO_REUSEADDR/SO_REUSEPORT binding on eth0 IPv4 address",
    },
    BlockedBridgeProbe {
        legacy_test_fn: "conformance_bridge_tcp_nonblocking_refused",
        probe_name: "bridge_tcp_nonblocking_refused",
        required_network_mode: "bridge",
        missing_embed_api: "ContainerBuilder::network(NetworkMode::Bridge)",
        reason: "Requires nonblocking TCP connect to unused port on eth0 IPv4 returning ECONNREFUSED",
    },
    BlockedBridgeProbe {
        legacy_test_fn: "conformance_bridge_tcp_peer",
        probe_name: "bridge_tcp_peer",
        required_network_mode: "bridge",
        missing_embed_api: "ContainerBuilder::network(NetworkMode::Bridge)",
        reason: "Requires TCP listener on 0.0.0.0:8080 connecting back through own eth0 IPv4 address",
    },
    BlockedBridgeProbe {
        legacy_test_fn: "conformance_bridge_udp_connected_unreachable",
        probe_name: "bridge_udp_connected_unreachable",
        required_network_mode: "bridge",
        missing_embed_api: "ContainerBuilder::network(NetworkMode::Bridge)",
        reason: "Requires connected UDP socket to unreachable subnet IP verifying ICMP unreachable",
    },
    BlockedBridgeProbe {
        legacy_test_fn: "conformance_bridge_udp_peer",
        probe_name: "bridge_udp_peer",
        required_network_mode: "bridge",
        missing_embed_api: "ContainerBuilder::network(NetworkMode::Bridge)",
        reason: "Requires UDP datagram sendto/recvfrom on own eth0 IPv4 address",
    },
    BlockedBridgeProbe {
        legacy_test_fn: "conformance_bridge_udp_sendto_unreachable",
        probe_name: "bridge_udp_sendto_unreachable",
        required_network_mode: "bridge",
        missing_embed_api: "ContainerBuilder::network(NetworkMode::Bridge)",
        reason: "Requires unconnected UDP sendto to unreachable subnet IP verifying async ICMP delivery",
    },
];

#[test]
fn blocked_bridge_api_manifest_is_complete() {
    assert_eq!(
        BLOCKED_BRIDGE_PROBES.len(),
        10,
        "manifest must describe exactly 10 blocked dedicated bridge single-container probes"
    );

    let mut sorted_probes: Vec<&str> = BLOCKED_BRIDGE_PROBES.iter().map(|p| p.probe_name).collect();
    sorted_probes.sort_unstable();

    let probe_names: Vec<&str> = BLOCKED_BRIDGE_PROBES.iter().map(|p| p.probe_name).collect();
    assert_eq!(
        probe_names, sorted_probes,
        "blocked bridge probe manifest must be sorted lexicographically by probe name"
    );

    let unique_probes: BTreeSet<&str> = probe_names.into_iter().collect();
    assert_eq!(
        unique_probes.len(),
        10,
        "all 10 blocked probe names must be unique"
    );

    let legacy_fn_names: BTreeSet<&str> = BLOCKED_BRIDGE_PROBES
        .iter()
        .map(|p| p.legacy_test_fn)
        .collect();
    assert_eq!(
        legacy_fn_names.len(),
        10,
        "all 10 legacy test function names must be unique"
    );

    for entry in BLOCKED_BRIDGE_PROBES {
        assert!(
            !entry.missing_embed_api.is_empty(),
            "blocked entry {} must name missing embed API",
            entry.probe_name
        );
        assert!(
            !entry.reason.is_empty(),
            "blocked entry {} must provide blocker rationale",
            entry.probe_name
        );
    }
}
