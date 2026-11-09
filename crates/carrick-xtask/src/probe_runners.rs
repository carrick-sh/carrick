//! Dedicated probe runner registrations. Deliberately its own module: the
//! signed-fixture publisher reads `probe_inventory.rs`, so that file is a
//! fixture input, while these bindings select only the harness test that runs
//! a probe. Registering a new dedicated probe here therefore leaves fixture
//! input identity unchanged, and the Signed queue gate can build the added
//! probe from candidate code (#1980).

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
        "schedaffinitythreads",
        "case_sched_affinity_threads_mask_reflection",
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
