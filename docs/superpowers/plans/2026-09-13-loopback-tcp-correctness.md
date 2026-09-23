# Loopback TCP correctness recovery plan

First priority in the approved correctness-recovery goal following the user's explicit direction to focus on inner workloads. Image startup, extraction, cache, and decoder overhead are deferred; their isolated branch is not a dependency of this work.

## Evidence

Full discovery at 7a3818034: Go SMTP TestTLSClient reports EPIPE sending TLS closeNotify; CPython httplib source-address test requests port 49466 but observes 32823. Fresh Docker-only runs pass both suites. Two comparisons each: preserved pre-inzone binary SHA256 457da5fb6521ff7bceacaff2e706242b9e5243610c0e935138f224a70a908239 passes, current fa1ec82e fails. Receipts: target/conformance/sep13-review/tcp-attribution/results.json and fresh-oracle/results.json.

Node libuv current fails not_readable_nor_writable_on_read_error, poll_oob, tcp_read_stop_start, tcp_reuseport, tcp_rst. Fresh Docker passes all 507 TAP entries. Partial DONTFORK node-app-smoke is a separate VM workstream, not a networking fix.

## Architecture fence

Guest loopback remains in Carrick's compat kernel. Preserve the complete file-description/socket state when converting host-backed unconnected sockets to in-memory connected halves: local binding/port reservation, options, pending error, readiness authority, shutdown/reset and close semantics. Do not bypass in-zone routing to regain test passes. A source-port number alone is insufficient: its binding reservation must remain owned until the appropriate lifetime ends, including failed connects and descriptor duplication.

## Tasks

- [ ] Extend the existing inzonetcp generic embedded probe for explicitly bound IPv4/IPv6 clients, wildcard local address resolution, local/peer address agreement, duplicate-descriptor lifetime, and connect failure rollback. Bound all waits; print observed errno values and relationships, not assumed Linux errno answers.
- [ ] Red-first current signed embedded execution and native-arm64 Docker oracle. Reuse existing probe; no new CLI subprocess probe.
- [ ] Repair in-zone connection publication as a transaction: preserve existing local endpoint and options, allocate only for unbound sockets, roll back failed publication, and transfer exactly one endpoint-reservation owner with the open-file description.
- [ ] Reduce the TLS close/reset and libuv failures independently before claiming a common cause. Cover peer close with unread data versus drained data, shutdown-write followed by close, pending reset consumed once, urgent byte semantics, SO_REUSEPORT listeners, and both blocking/nonblocking readiness.
- [ ] Correct socket state transitions and publication ordering, not timing. Keep shared-half lock ordering and probe-after-enrollment guarantees.
- [ ] Host tests, then signed reducers and original Go/CPython/libuv workloads with same-image Docker references. Preserve all raw outputs and declared assertions.
- [ ] Director integrates only reviewed changes, then frozen signed probes -> smoke -> full; red rung blocks promotion.

No retries, increased deadlines, ignored failures, numeric-user bypass, host-socket fallback, reactor migration or push. Exact 2127-row correctness accounting remains the campaign acceptance boundary.

## Director source review (current main)

`ConnectTarget::InZone` in dispatch/net/lifecycle.rs:2202 forgets old host address records before any fallible ephemeral allocation or enqueue. It then unconditionally allocates a new local port, even for an explicitly bound client. Backlog refusal releases the newly allocated port but does not restore the forgotten old address record. The server half is enqueued before the client file-description variant is replaced; audit publication ownership and failure rollback as one transaction. `OpenDescriptionBase::new(status_flags)` transfers only status flags explicitly, then connected state and ephemeral guard; identify which socket options/common state belong to the existing description before moving them. Do not blindly copy listener-only or non-inheritable options (accept02 also exposed an independent multicast-group assertion).

These are source-supported candidate causes, not independently reduced closure. Original full SMTP and HTTP attribution receipts remain the decisive guest evidence; expand probes red-first before changing this path.

`PureSocketInner::drop` (dispatch/net/unix_pure.rs:1000) marks both shutdown directions and notifies the peer, but does not inspect unread receive data or publish a TCP reset. `send_stream` consumes a pending error once and otherwise lowers a missing/closed peer to EPIPE. This is a source lead for libuv tcp_rst and SMTP closeNotify, not a demonstrated shared cause. Reduce graceful FIN, peer close with unread data, and explicit reset separately; preserve AF_UNIX behavior when adding TCP-specific semantics.

## Inner-workload execution checkpoint

User explicitly deferred image overhead; isolated image branch remains unmerged. TCP probe worker runs from main 7a381803487b5111c08d5f5442c40d31191295bb in `.worktrees/sep13-inner-tcp`, branch `agy/sep13-inner-tcp`, Antigravity run `sep13-inner-workloads`, worker `tcp-probe`. First task is probe-only, no runtime edits or guest runs. Director owns native Docker oracle and signed embedded red-first phases.

Further source review: `OpenDescriptionBase` in dispatch/fd_table.rs owns receive/send timeouts, reuse flags, buffer requests, pending error, and connect state; constructing a fresh base during connect loses those values. Existing bind records translated guest endpoints only when rewritten, so the transaction must read provider guest identity with authenticated host endpoint fallback before retiring the old socket. In-zone ephemeral allocation checks listeners and its own ephemeral inventory, while bound host socket lifetime currently owns other reservations. Merely copying the source port would not prove reservation lifetime preservation.

Signed red-first now proven on unchanged runtime main7a, revised inzonetcp musl: 230 observed and oracle keys, 48 differences. All4 bound-client cases lose source port and permit competing binds (Linux errno98), including live duplicate phase. Separate refused-connect cases hit bounded poll timeout rather than Linux readiness+SO_ERROR111. Both musl and glibc fresh Docker oracles recorded; signed shard stops after musl mismatch, so glibc red not executed. Negative entitlement control passed and scoped cleanup reported0 remaining. Evidence: target/conformance/sep13-review/inner-tcp-red-summary.json, inner-tcp-red-artifact.json, inner-tcp-red-differences.json and inner-tcp-embed-red.log. Worker turn3 implements runtime endpoint/reservation transaction with host tests, director retains guest validation. No runtime change accepted.

Native Darwin-only controlled check (inner-tcp-darwin-nonlistener.json): IPv4 and IPv6 bound non-listening target kept alive; nonblocking connect returns host EINPROGRESS36, 1000ms poll gives no events, SO_ERROR0. Native Linux revised probe instead poll1/SO_ERROR111. This supports a host-semantic cause for the separate refusal timeout, not proof of a lost readiness wake. Do not lengthen probe deadlines; guest-owned non-listening endpoint refusal needs compat semantics. Current provider can resolve registered bound host endpoints via resolve_registered_namespace_connect before host connect, whereas in-zone matching only sees listeners. Reconcile the bound-endpoint lifecycle with listener promotion so a guest target that has not listened refuses like Linux. Evidence is separate from proven source-port reservation failure.

Receipt correction: scripts/test-signed.sh publishes its aggregate artifact receipt only on success. Failed red runs have no aggregate receipt. Director preserved post-run exact signed binary SHA/CDHash/UUID/entitlements/load commands in inner-tcp-red-artifact.json; full signed log proves run/control/cleanup. Do not cite a nonexistent failed-run aggregate receipt.
