# Carrick Socket Network Namespace Design

## Status

Approved design direction. This document scopes the first private network mode
for Carrick: a Docker-bridge-compatible socket namespace provider for macOS,
with a provider boundary that can later support richer macOS backends and real
network namespaces on other hosts.

## Context

Carrick currently presents host networking. AF_INET, AF_INET6, and AF_UNIX
sockets are backed by real host sockets with Linux-to-host translation at the
syscall boundary. Synthetic rtnetlink and `/proc` networking files expose a
minimal host-network view to guest code.

The desired direction is to match Docker bridge semantics at the application
socket level first, without using PF as the initial datapath and without adding
a user-space TCP/IP stack. The architecture must still be ready for richer
providers: PF-backed bridge behavior on macOS, NetworkExtension-backed product
integrations, Linux host netns, FreeBSD VNET-style backends, or packet-device
backends where the host can do better.

The first provider is therefore a socket-namespace provider. It gives normal
TCP/UDP applications a Docker-like bridge view while keeping actual data
movement on Darwin sockets. It is not a packet-level bridge.

## Goals

- Add `--net bridge` as Carrick's first private network mode.
- Match Docker bridge semantics for normal application sockets:
  - same-bridge container-to-container connectivity by container IP;
  - outbound connectivity through a NAT-like guest-visible model;
  - published host ports via `-p host:container`;
  - per-bridge isolation for Carrick-managed sockets;
  - Linux-visible `eth0`, address, route, gateway, DNS, and rtnetlink state.
- Keep the Linux-visible network model platform-neutral.
- Keep the host networking provider replaceable and capability-driven.
- Avoid PF, NetworkExtension, vmnet, or a user-space TCP/IP stack in the first
  implementation.

## Non-Goals

- Packet-level bridge fidelity in v1.
- Host-routable container IPs in v1.
- Raw sockets, AF_PACKET, arbitrary ICMP, packet capture, multicast, or
  broadcast fidelity in v1.
- Guest-created `unshare(CLONE_NEWNET)`, `setns`, or nested network namespaces.
- Docker named networks as a full product surface in v1, though the data model
  should not block them.
- Netfilter, iptables, nftables, or Linux firewall emulation.

## Architecture

The design has two layers:

1. A platform-neutral Linux network model owned by Carrick's engine/runtime
   contract.
2. A host network provider that materializes that model using the current host's
   best available mechanism.

The Linux model is stable. Provider fidelity varies. The runtime can report
that a requested mode is satisfied at app-socket fidelity while packet-level
features remain unsupported.

### Linux Network Model

Add a network spec to the engine-to-runtime handoff, separate from the existing
PID namespace mode:

```rust
pub enum NetworkMode {
    Host,
    Bridge,
}

pub struct NetworkNamespaceSpec {
    pub namespace_id: NetworkNamespaceId,
    pub bridge_id: BridgeId,
    pub container_name: Option<String>,
    pub aliases: Vec<String>,
    pub ipv4: Ipv4Addr,
    pub gateway_v4: Ipv4Addr,
    pub dns_servers: Vec<IpAddr>,
    pub published_ports: Vec<PortMapping>,
}
```

The model owns Linux-visible state:

- rtnetlink replies for link, address, and route dumps;
- `/proc/net` views that are currently synthesized from host state;
- `/etc/hosts` and `/etc/resolv.conf` materialization;
- `getsockname`, `getpeername`, `accept`, `recvfrom`, and related address
  translation;
- policy semantics for same-bridge allow and different-bridge deny.

The initial bridge can be the default Carrick bridge. The types should include a
`BridgeId` from the start so Docker-style named networks can be added without
rewriting the runtime model.

### Provider Contract

Introduce a provider interface selected by platform and configuration:

```rust
pub trait NetworkProvider {
    fn capabilities(&self) -> NetworkCapabilities;
    fn create_namespace(&self, spec: &NetworkNamespaceSpec) -> Result<NetworkLease>;
    fn destroy_namespace(&self, lease_id: NetworkLeaseId) -> Result<()>;
    fn publish_port(&self, lease_id: NetworkLeaseId, mapping: PortMapping) -> Result<()>;
    fn materialize_bind(
        &self,
        namespace_id: NetworkNamespaceId,
        requested: SocketAddr,
    ) -> Result<BindTarget>;
    fn resolve_connect(
        &self,
        namespace_id: NetworkNamespaceId,
        requested: SocketAddr,
    ) -> Result<ConnectTarget>;
}
```

Capabilities must be explicit:

- same-bridge IP connectivity;
- multi-network attachments;
- embedded DNS service discovery;
- outbound connectivity;
- published ports;
- kernel datapath;
- host-routable container IPs;
- packet-level isolation;
- raw socket support;
- multicast or broadcast support;
- requires privilege.

This avoids provider names becoming semantic promises. For example, the v1
socket provider can satisfy app-socket same-bridge connectivity, multi-network
attachment routing, embedded service-name DNS, outbound connectivity, and
published TCP ports while explicitly not satisfying host-routable IPs or
packet-level isolation.

## Socket Namespace Provider

The v1 macOS provider does not assign the virtual container IP to a host
interface. Instead, it keeps a registry that maps virtual Docker-style endpoints
to loopback host endpoints.

Example:

```text
bridge: carrick0
container a: 172.31.0.2
container b: 172.31.0.3

guest a bind(0.0.0.0:80)
  -> host bind(127.0.0.1:ephemeral_a)
  -> registry (carrick0, 172.31.0.2, tcp, 80) = 127.0.0.1:ephemeral_a

guest b connect(172.31.0.2:80)
  -> provider resolves to 127.0.0.1:ephemeral_a
  -> Darwin TCP connection
  -> guest-visible peer remains 172.31.0.2:80
```

### Bind Behavior

For a bridge namespace:

- `bind(container_ip:port)` binds a host loopback endpoint and registers the
  virtual endpoint.
- `bind(0.0.0.0:port)` registers the port on all virtual addresses owned by the
  namespace, initially the primary container IP.
- `bind(127.0.0.1:port)` remains namespace-local loopback and is reachable only
  from the same namespace unless explicitly published.
- Binding an address not assigned to the namespace returns the Linux errno that
  Docker/Linux would expose.

The provider must preserve guest-visible addresses through `getsockname`.

### Connect Behavior

For a bridge namespace:

- Connecting to a same-bridge container IP resolves through the registry.
- Connecting to a different bridge's container IP is denied unless a future
  provider explicitly routes between those bridges.
- Connecting to host or internet addresses uses normal host sockets.
- Connecting to the namespace gateway resolves to Carrick-managed services such
  as DNS when present.

The provider must preserve guest-visible peers through `getpeername`, `accept`,
and datagram source address reporting.

### Published Ports

Because v1 avoids PF, published ports use Carrick-owned listeners:

```text
host 127.0.0.1:8080 or 0.0.0.0:8080
  -> Carrick port-forward listener
  -> virtual endpoint 172.31.0.2:80
  -> registered loopback target
```

This is user-space forwarding, but only for published host ingress. It does not
place the normal container-to-container datapath on a user-space TCP/IP stack.

The listener supports TCP streams and UDP datagrams. UDP published ingress uses
a Carrick-owned host UDP socket, resolves the current registered virtual
container endpoint, forwards the datagram to the loopback host socket backing
that endpoint, and temporarily exposes the proxy backend socket as a
guest-visible bridge-gateway source so guest replies route back to the host
client. This preserves app-socket Docker behavior without claiming multicast,
broadcast, raw socket, or packet-level NAT fidelity.

### Outbound Connectivity

Outbound connections to non-Carrick destinations use normal host sockets. The
guest-visible model reports the namespace source address and default route, but
the host sees ordinary Carrick process traffic.

This is NAT-like from the guest's perspective, not host-packet NAT. That
distinction must be visible in capability reporting and documentation.

## DNS and Name Resolution

The first implementation materialized `/etc/hosts` entries for known same-bridge
containers. The current bridge implementation also intercepts UDP DNS queries to
the namespace gateway address and builds Carrick-managed A-record responses with
Hickory DNS protocol types. Name, container-name, and alias answers are scoped to
the bridges shared by the querying namespace and the target endpoint.

The model preserves the distinction between Docker's default bridge and
user-defined bridge networks by carrying aliases and bridge membership per
attachment. Multi-homed targets expose only the addresses on bridges shared with
the querying namespace.

Bridge-mode `/etc/hosts` also materializes Docker Desktop-style host gateway
names. `host.docker.internal` and `gateway.docker.internal` resolve to the
namespace gateway address unless an explicit `ExtraHosts` entry overrides that
name. Compose/API `host-gateway` extra-host tokens expand to the namespace
gateway. The socket namespace provider maps TCP connects to an attached bridge
gateway onto host loopback on the requested port, so ordinary host-local
services are reachable without claiming host-routable container IPs or a packet
NAT datapath.

## Provider Roadmap

The provider boundary is intended to support these future implementations:

- `socket-namespace`: v1 macOS app-socket bridge compatibility, unprivileged.
- `pf-bridge`: macOS backend with host-routable container IPs, PF NAT, PF rdr,
  and stronger host-visible network behavior.
- `network-extension`: macOS product backend for policy, observability, safer
  install, and possible transparent proxy or tunnel integration.
- `linux-netns`: Linux host backend using real network namespaces where
  available.
- `freebsd-vnet`: future FreeBSD backend if the target host can provide a better
  primitive.
- `packet-device`: future backend for tap, vmnet, or VMM-style packet interfaces
  if Carrick grows a packet-facing network path.

These providers should share the same `NetworkNamespaceSpec` and Linux-visible
runtime model.

## Error Handling and Cleanup

The socket provider must maintain a lease registry keyed by run id and namespace
id. Cleanup is mostly ordinary process cleanup, but the registry still needs:

- stale lease detection when a Carrick process exits unexpectedly;
- deterministic release of published host ports;
- diagnostics for conflicting host published ports;
- clear errors when a requested Docker feature needs a capability the selected
  provider lacks.

Unlike PF-backed providers, v1 does not mutate global host packet policy. It
therefore does not need privileged rollback, but it still needs robust registry
and listener cleanup.

## Testing

Unit tests should cover:

- virtual endpoint allocation and registry lookup;
- bind address validation;
- same-bridge allow and cross-bridge deny;
- guest-visible `getsockname` and `getpeername` translation;
- published port conflict detection;
- multi-network service and alias DNS visibility;
- provider capability reporting.

Integration and conformance probes should cover:

- container A serves on `0.0.0.0:port`, container B connects to A's virtual IP;
- container A binds `127.0.0.1`, container B cannot connect to A's container IP;
- outbound TCP connect works and guest-visible route state is bridge-shaped;
- `-p host:container` reaches the container through the Carrick listener;
- rtnetlink reports `lo`, `eth0`, container IP, gateway, and default route;
- `/etc/hosts` and gateway DNS resolve same-network container/service names;
- connect/disconnect mutations on created or stopped containers are reflected
  when the container is next started.

Docker oracle comparisons should focus on app-level bridge behavior, not raw
packet features that the selected provider explicitly does not claim.

## Open Follow-Up Decisions

- Exact bridge subnet defaults and conflict detection policy.
- Whether v1 published ports bind loopback-only by default or match Docker's
  broader host bind behavior.
- Whether `/etc/hosts` name injection is sufficient for the first bridge milestone
  or if the gateway DNS responder should be part of v1.
