# Network Provider Roadmap

Carrick's default Docker bridge implementation is `socket-namespace`: an
unprivileged app-socket provider. It makes Linux guests see Docker-shaped bridge
addresses, routes, DNS, `/etc/hosts`, `/proc/net`, rtnetlink, same-bridge
connectivity, and Carrick-owned published TCP/UDP ports. It does not install a
host interface, mutate PF, load a NetworkExtension, expose host-routable
container IPs, or provide packet-level isolation.

The runtime provider contract must keep those facts explicit. The
`NetworkCapabilities` fields used for future-provider gating are:

- `kernel_datapath`: traffic is carried by a host kernel datapath for the
  virtual network rather than Carrick app-socket translation.
- `host_routable_container_ips`: the host can route directly to container IPs.
- `packet_level_isolation`: packets are isolated at a network-device/firewall
  boundary, not just at Carrick's socket policy layer.
- `netfilter`: Linux netfilter/iptables/nftables semantics are available.
- `pf_nat`: the provider owns PF NAT rules.
- `pf_rdr`: the provider owns PF rdr rules for published ports.
- `network_extension_policy`: the provider uses a macOS NetworkExtension policy
  or flow/packet integration.
- `requires_privilege`: creating or destroying the provider needs privilege,
  entitlement, or an installed helper.

Current providers report those future capabilities as false. The bridge socket
provider also reports `kernel_datapath: false`; its data path is Darwin sockets
plus Carrick endpoint translation, not a host bridge.

## Provider Shapes

`socket-namespace`

- Current default for bridge mode.
- Unprivileged.
- App-socket same-bridge TCP/UDP, embedded DNS, multi-network attachments,
  outbound host sockets, and Carrick-owned published TCP/UDP ports.
- No PF, NetworkExtension, packet capture, AF_PACKET, raw socket, multicast, or
  broadcast fidelity.

`pf-bridge`

- Future macOS privileged backend candidate.
- Would require a small helper owning only Carrick PF anchors and tables.
- Required ownership boundary:
  - per-run or per-project PF anchor, for example `com.carrick/<run-id>`;
  - tables for container IPs, gateway IPs, and published-port endpoints;
  - NAT rules for guest-visible bridge egress;
  - rdr rules for published ports;
  - rollback command that flushes only Carrick-owned anchors/tables;
  - startup reconciliation that removes stale Carrick anchors by run id;
  - tests gated behind an explicit privileged/manual flag, never `just ci`.
- It may satisfy `kernel_datapath`, `host_routable_container_ips`, `pf_nat`,
  `pf_rdr`, `packet_level_isolation`, and `requires_privilege` if proven by a
  live runtime demo.

`network-extension`

- Future macOS product integration candidate.
- Likely candidates are flow or packet tunnel style integration, depending on
  whether Carrick needs per-flow policy or packet visibility.
- Could provide policy and observability; it does not automatically provide
  Docker-compatible bridge routing, PF-style rdr, or host-routable container IPs.
- Blockers before default use: entitlement approval, install UX, upgrade/removal
  reliability, OS-version behavior, and a clear story for Compose-driven
  short-lived projects.
- It may satisfy `network_extension_policy`, `requires_privilege`, and possibly
  `kernel_datapath` only after a real implementation demonstrates those
  semantics.

`linux-netns`

- Future Linux host backend using real Linux network namespaces.
- Should reuse `NetworkNamespaceSpec` and the same guest-visible runtime model.
- May satisfy `kernel_datapath`, `host_routable_container_ips`,
  `packet_level_isolation`, `netfilter`, and guest-created namespace operations
  where the host can safely provide them.

## Request Handling

Names reserved for future providers must not silently fall back to the socket
provider. Docker API network creation currently rejects `pf-bridge`,
`network-extension`, and `linux-netns` with a clear "not implemented" error.
That keeps Compose/API state honest until a provider has a real implementation
and verification gate.

## Verification Rules

- Default CI exercises only unprivileged providers.
- Privileged PF or NetworkExtension experiments must be opt-in and must snapshot
  owned state before mutation.
- Any privileged provider completion claim requires:
  - capability tests for the provider flags it reports;
  - cleanup tests proving owned state is removed on normal shutdown;
  - crash-reconciliation tests proving stale Carrick-owned state is removable;
  - a live workload showing host-routable or packet-level behavior before those
    capabilities are set true.
