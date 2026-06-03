# WS-C3 — Netlink breadth & raw sockets (design spec)

Status: **spec only / demand-driven** (per the review-remediation roadmap, low
priority). This is the brainstorm→spec deliverable; implement a slice when a
target workload needs it.

## Context

`agy-report.md` §8. carrick already emulates a useful AF_NETLINK subset
(`dispatch/net.rs` + `dispatch/net/support.rs`): a synthetic `NETLINK_ROUTE`
socket (`SOCK_RAW`/`SOCK_DGRAM`), with `build_netlink_reply` answering
`RTM_GETLINK` (one `RTM_NEWLINK` for the interfaces) and `RTM_GETADDR` (one
`RTM_NEWADDR`), terminated by `NLMSG_DONE`; unmodelled requests already return a
clean empty `NLMSG_DONE` rather than hanging. Replies are queued and drained via
`drain_netlink_queue`, so poll/recv semantics already work. Raw sockets
(`SOCK_RAW` on AF_INET) are accepted at creation but are otherwise a stub.

So the mechanism exists; C3 is about *breadth* (more RTM message types, more
netlink families) and a real raw-socket data path — both demand-driven.

## Netlink breadth

Add message types to `build_netlink_reply`, each synthesized from a Darwin
source, mirroring the existing `RTM_GETLINK`/`GETADDR` pattern:

- **`RTM_GETROUTE` → `RTM_NEWROUTE`*** from the host routing table
  (`sysctl NET_RT_DUMP` / `PF_ROUTE`), so `ip route` and Go's `net` route probes
  resolve. Highest value (commonly hit after GETLINK/GETADDR).
- **`RTM_GETNEIGH` → `RTM_NEWNEIGH`** from the ARP/NDP cache
  (`sysctl NET_RT_FLAGS`), for `ip neigh`.
- **`NETLINK_KOBJECT_UEVENT`** (a second family): a recv-only socket that stays
  silent (no synthetic hotplug events). Many daemons (systemd-udevd, libudev)
  open it and `recv`; an empty-but-open socket is the correct degradation.
- **`RTM_NEWLINK`/`RTM_NEWADDR` write requests** (configuring interfaces): reject
  with `EPERM` (matches unprivileged Linux — carrick is non-root), not ENOSYS.

Each addition is a `match` arm + a Darwin source query + the existing
`push_nlmsg` framing; no structural change. Verification: a netlink probe doing
`RTM_GETROUTE` diffed against Docker for the *shape* (message types, NLMSG_DONE
terminator) — not addresses, which differ per host (deterministic-shape
assertion only).

## Raw sockets

A real `SOCK_RAW` data path (e.g. `ping`'s ICMP, `traceroute`) needs the host to
permit raw sockets, which on macOS requires root for `SOCK_RAW`/`IPPROTO_ICMP`
but allows unprivileged `SOCK_DGRAM`/`IPPROTO_ICMP` ("ping sockets", same as
Linux's `net.ipv4.ping_group_range`). Plan:

- Map guest `SOCK_RAW, IPPROTO_ICMP` → host `SOCK_DGRAM, IPPROTO_ICMP` when the
  guest only sends/receives ICMP echo (the `ping` case): the host kernel writes
  the IP header, the guest's is stripped/synthesized. This covers the common
  workload without requiring carrick to run as root.
- True `SOCK_RAW` with `IP_HDRINCL` (custom IP headers) → `EPERM` unless carrick
  runs privileged; document as a privileged-only capability.

Verification: an ICMP-echo probe to `127.0.0.1` under carrick vs Docker
(loopback ping), asserting a reply was received (boolean), not timing.

## Non-goals

`NETLINK_NETFILTER`/`NETLINK_GENERIC` families, `RTM_*` *set* operations beyond
the EPERM stance, netlink multicast group subscription with live event
generation. Add per concrete workload demand.
