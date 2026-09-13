# In-Zone Loopback TCP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A TCP connection between two guest sockets inside one carrier never touches a host socket: connect pairs with the guest listener's accept queue in memory, and all data, readiness and close semantics are carrick's own.

**Architecture:** The socket-namespace provider (`crates/carrick-runtime/src/network/`) already resolves every `connect` to a `ConnectTarget` and the dispatcher already swaps a connecting host socket for an `OpenDescription::InMemorySocket` (the mock-intercept path). This plan adds a fourth target, `ConnectTarget::InZone`, backed by a per-carrier registry of listening guest sockets keyed by (network namespace, address, port). `listen` registers, `connect` pairs two `PureSocketInner` halves and enqueues the server half, `accept` drains the in-zone queue before the host queue, and the listener's readiness merges both sources. A connect that finds no in-zone listener falls through to the existing host path unchanged, which keeps cross-carrier sidecars, published ports and real network peers exactly as they are.

**Tech Stack:** Rust (`carrick-runtime`), existing `PureSocketInner` streams (`dispatch/net/unix_pure.rs`), the `NetworkProvider` trait, the epoll in-memory wake registry, conformance probes (Rust, musl+gnu) judged against the Docker oracle.

**Spec:** this document, section "Design" (the owner's rule, 2026-09-13: host syscalls only for host-crossing resources; anything inside the Linux boundary is carrick's own abstraction — `docs/host-facility-boundary.md`).

## Global Constraints

- Rule 0: run guests only from `just build` binaries; `just test` is the lib-test recipe, never bare `cargo test --workspace --lib`.
- Never `git stash`, never `--no-verify`; Conventional Commits with Why/What/Verified; worker trailer `Co-Authored-By: Antigravity <agy@google.com>`.
- Line-pinned inventories reconciled on a CLEAN tree after rebase, before lint (`just reconcile-inventories --rehome`), committed as `chore: reconcile line-pinned inventories ...`; a new `carrick_fatal!` site goes in `scripts/migrate/runtime-aborts/`; a new host-authority site (a `libc::`/`std::fs`/`std::process` call) gets a reviewed row in `scripts/migrate/host-authority-transition-inventory.json` (model rows HA-000650..652).
- Typed domains: no bare `i32`/`u16` port or fd crossing a module boundary; ports and keys are newtypes; a state rule lives in a type, not a comment.
- Probes are oracle instruments: print the errno NUMBER, bound every wait (5 s), red-first where a behaviour changes.
- Never run the Docker oracle concurrently with carrick guests.
- Scope v1: `AF_INET`/`AF_INET6` `SOCK_STREAM`. UDP loopback is a follow-up (documented, not stubbed).

## Design

### Where the seam is

- `connect` (`dispatch/net/lifecycle.rs` ~L1943) calls `this.network.provider.resolve_connect(namespace_id, GuestSocketAddr, PortProtocol)` and handles `ConnectTarget::{Host, Unchanged, Denied, Intercept}`; the `Intercept` arm builds a `PureSocketInner::new_mock(...)`, forgets the host socket's recorded addresses and replaces the description with `OpenDescription::InMemorySocket { base, socket }`. `InZone` follows the same shape with a real peer instead of a mock.
- `listen` (~L1829) calls `provider.prepare_listen(namespace_id, guest_local, host_local, protocol, reuse_port)` before `libc::listen`, then marks the description listening. In-zone registration happens here, after the host listen succeeds, keyed by the guest-visible local address (`provider.guest_visible_local_addr(SocketKey::for_host_fd(..))`, falling back to the host-bound address when the provider has none).
- `accept_common` (~L1020) currently only knows `HostSocket`. It gains a first step: dequeue from the in-zone listener; the fallback is unchanged host `accept`.
- Readiness: `OpenDescription::readiness` (`dispatch/fd_table.rs` ~L1797) answers `InMemorySocket` from `PureSocketInner::poll_mask()`; the `HostSocket` arm falls to the host `poll`. A listening `HostSocket` with an in-zone queue must report `IN` when the queue is non-empty. The epoll instance is woken through the existing `notify_inmem_epoll()` path (the `synthetic_recv` precedent in `queue_synthetic_datagram`, lifecycle.rs ~L975), and a blocked `accept` waits through `WaitFds::...with_redispatch_and_watched_slots` on the listener slot so an in-memory enqueue re-dispatches the syscall (the same mechanism a synthetic datagram uses to wake a blocked `recvfrom`).
- Data path: `InMemorySocket` already serves `send/recv/sendmsg/recvmsg`, `sendfile`, `splice`, `ioctl(FIONREAD)`, `shutdown`, `getsockname/getpeername`, `SO_ERROR/SO_*TIMEO` for the mock path (`send_recv.rs`, `fs/sendfile.rs`, `fs/transfer.rs`, `fs/ioctl.rs`, `sockopt.rs`). Task 3 audits it against TCP semantics.

### Types (all new code)

```rust
// crates/carrick-runtime/src/network/inzone.rs
/// Identity of a guest TCP listener as a connect target inside ONE carrier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InZoneListenerKey {
    pub scope: InZoneScope,          // Namespace(NetworkNamespaceId) | CarrierHost (network mode Host / no namespace)
    pub addr: GuestSocketAddr,       // the guest-visible bound address; port is the materialized port
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum InZoneScope { CarrierHost, Namespace(NetworkNamespaceId) }

/// One listening guest socket's in-zone accept queue. Owned by the registry
/// (Arc), referenced weakly from the listener's OpenDescription.
pub struct InZoneListener {
    key: InZoneListenerKey,
    backlog: AtomicUsize,
    queue: Mutex<VecDeque<Arc<PureSocketInner>>>,   // server halves awaiting accept
    wait_queue: Arc<crate::kernel::WaitQueue>,      // wakes blocked accept + epoll
    generation: InZoneGeneration,                    // bumped on unregister; a stale Arc never accepts
}

pub enum InZoneEnqueue { Queued, BacklogFull }

impl InZoneListener {
    pub fn enqueue(&self, server_half: Arc<PureSocketInner>) -> InZoneEnqueue;
    pub fn dequeue(&self) -> Option<Arc<PureSocketInner>>;
    pub fn pending(&self) -> usize;
    pub fn wait_queue(&self) -> Arc<WaitQueue>;
}

/// Per-carrier registry. Lives in `SocketNamespaceProvider` (and the no-op
/// provider gets the same field: in-zone is provider-independent).
pub struct InZoneRegistry {
    listeners: Mutex<HashMap<InZoneListenerKey, Vec<Arc<InZoneListener>>>>, // >1 only for SO_REUSEPORT groups
    ephemeral: Mutex<InZoneEphemeralPorts>,   // ports handed to in-zone client halves, per scope
}

impl InZoneRegistry {
    pub fn register(&self, key: InZoneListenerKey, backlog: usize) -> Arc<InZoneListener>;
    pub fn unregister(&self, listener: &Arc<InZoneListener>);
    /// The listener a guest connect to `target` in `scope` would reach, if any:
    /// exact address match, or a wildcard (0.0.0.0 / ::) listener on that port,
    /// for a loopback or scope-local destination address. Never matches a
    /// destination outside 127/8, ::1 or the scope's own addresses.
    pub fn resolve(&self, scope: &InZoneScope, target: GuestSocketAddr) -> Option<Arc<InZoneListener>>;
    pub fn allocate_ephemeral(&self, scope: &InZoneScope, family: AddrFamily) -> Option<InZonePort>;
    pub fn release_ephemeral(&self, scope: &InZoneScope, port: InZonePort);
    /// `bind` consults this so a host-backed bind cannot take a port an in-zone
    /// client half currently uses (one port space, like Linux).
    pub fn port_in_use(&self, scope: &InZoneScope, port: u16) -> bool;
}

// crates/carrick-runtime/src/network/mod.rs
pub enum ConnectTarget {
    Host(HostSocketAddr),
    Unchanged,
    Denied(LinuxErrno),
    Intercept(Arc<dyn interposer::MockService>),
    InZone { listener: Arc<InZoneListener>, target: GuestSocketAddr },  // NEW
}
```

### Semantics (Linux, from man pages and the Docker oracle)

- `connect` to an in-zone listener: create `PureSocketInner::pair_with_family(family, SOCK_STREAM, IPPROTO_TCP, creds, creds)`; client half: local = (scope loopback address of the family, allocated ephemeral port), peer = target; server half: local = target address as the client named it (for a wildcard listener Linux reports the destination address, e.g. 127.0.0.1:port), peer = client local. Enqueue the server half; the client's description becomes `InMemorySocket` with `connection_state = connected`. Return 0 for blocking AND non-blocking sockets (the loopback handshake completes synchronously; a guest that treats 0 as connected is right, one that polls for writability sees `OUT` at once). `BacklogFull`: a blocking connect waits on the listener's wait queue until space; a non-blocking connect returns `EINPROGRESS` and completes on the next dequeue (the client half is enqueued as *pending* and `SO_ERROR` reads 0 afterwards). Document this as the one deliberate approximation (Linux drops the SYN and retransmits).
- No in-zone listener: `resolve_connect` continues to the existing Host/Unchanged logic. `ECONNREFUSED` for a truly unbound loopback port therefore still comes from the host, exactly as today (`connrefused`, `bridge_tcp_nonblocking_refused` probes).
- `accept`: an in-zone dequeue installs the server half as a new fd (`accept4` flags honoured), writes the peer sockaddr, records addresses through `provider.record_socket_addresses` with a `SocketKey` for in-memory sockets (extend `SocketKey` with a second constructor `for_in_memory(id)` — it is currently host-fd-only). Ordering: in-zone queue first, then host `accept`; a blocked accept waits on the host fd AND the listener slot (redispatch), never on one alone.
- `getsockname` on the listener is unchanged (host truth). On in-zone halves, `PureSocketInner::local_addr/peer_addr`.
- `close` of the listener unregisters; queued-but-unaccepted server halves are reset (their client halves read EOF and `SO_ERROR = ECONNRESET`, as Linux does when a listener closes with a full accept queue).
- `shutdown(SHUT_WR)` on one half makes the peer's read return 0 after buffered bytes and raises `EPOLLRDHUP|EPOLLIN` on the peer (Task 3 verifies `poll_mask` does this for INET halves).
- `SO_REUSEPORT` group of in-zone listeners on one key: connections go to the member with the shortest queue.
- Fork/exec: `PureSocketInner` is `Arc`-shared in the one carrier process; fds survive exec (`execsocket` probe).
- Network modes: Host mode → `InZoneScope::CarrierHost` (all guest sockets in the carrier see each other's loopback, like one Linux netns); Bridge mode → `InZoneScope::Namespace(id)`; `None` mode → registry still applies (loopback exists in a `--net=none` netns).

### Judges and receipts

- Line-exact probes (existing): `acceptsock`, `connrefused`, `getsocknameval`, `loopbacksubnet`, `sidecar_loopback_{client,server,isolated_client}`, `bridge_*`, `socketpartialsend`, `sockbufreuseport`, `execsocket`, `epoll*`, `ppoll*`, `pollhup*`, `selectbits`, `splicenetpoll`.
- New line-exact probe `inzonetcp` (Task 4): the semantics above as booleans/errno numbers against the oracle.
- Receipts: `perf_net_tcp_rr` p50/p95 (direct measure of the loopback path), `perf_net_tcp_stream`, go-net_http harness wall (main 457da5fb6521ff7b: 14,095 / 18,652 ms; ratio 3.18x at w4), the carrier profile's host `poll`/`kevent`/`write`/`close` shares (`prof-mpnh/profk.sh` + `ksamp-agg.py`, baseline poll 9.1%, write 4.1%, close 1.7%, kevent 2.2%), and the event ring free of `EPWAIT ready=0` runs.

## File Structure

- Create `crates/carrick-runtime/src/network/inzone.rs`: `InZoneRegistry`, `InZoneListener`, `InZoneListenerKey`, `InZoneScope`, `InZonePort`, `InZoneEphemeralPorts`, `InZoneEnqueue` + unit tests. (Task 1)
- Modify `crates/carrick-runtime/src/network/mod.rs`: `ConnectTarget::InZone`, `SocketKey::for_in_memory`, `NetworkProvider::inzone(&self) -> &InZoneRegistry` (default implemented by every provider via a shared field), `resolve_connect` consults the registry before the host resolution. (Task 1)
- Modify `crates/carrick-runtime/src/network/socket_namespace.rs`, `interposer.rs`, the no-op provider: hold the registry; `resolve_connect` calls `inzone().resolve(scope, target)` first. (Task 1)
- Modify `crates/carrick-runtime/src/dispatch/fd_table.rs`: `OpenDescription::HostSocket` gains `inzone_listener: Option<Weak<InZoneListener>>`; `readiness` for a listening `HostSocket` ORs the in-zone queue; `SocketKey` use for in-memory sockets. (Task 2 — it is the only task touching this file)
- Modify `crates/carrick-runtime/src/dispatch/net/lifecycle.rs`: `listen` registers, `accept_common` drains, `connect` handles `InZone`, close/unregister on last fd ref, `bind` consults `port_in_use`. (Task 2)
- Modify `crates/carrick-runtime/src/dispatch/net/unix_pure.rs`, `send_recv.rs`, `sockopt.rs`, `fs/ioctl.rs`: INET-stream semantics audit for in-memory halves. (Task 3; file-disjoint from Task 2)
- Create `conformance-probes/src/bin/inzonetcp.rs` (+ registration in the probe manifest, both musl and gnu builds via the Docker toolchains). (Task 4; file-disjoint)
- Director: landing order, gate, paired measure, docs (`docs/conformance-campaigns/2026-09-04-ecosystem.md`). (Task 5)

---

### Task 1: In-zone registry and connect target (network/)

**Files:**
- Create: `crates/carrick-runtime/src/network/inzone.rs`
- Modify: `crates/carrick-runtime/src/network/mod.rs` (`ConnectTarget`, `SocketKey`, `NetworkProvider`), `crates/carrick-runtime/src/network/socket_namespace.rs` (`resolve_connect` ~L2443), `crates/carrick-runtime/src/network/interposer.rs` (its `resolve_connect` ~L503), the no-op provider in `mod.rs`.
- Test: unit tests inside `inzone.rs` and `mod.rs`.

**Interfaces:**
- Produces: everything under "Types" above, plus `NetworkProvider::inzone(&self) -> &InZoneRegistry`; `ConnectTarget::InZone { listener, target }`; `SocketKey::for_in_memory(u64)`.
- Consumes: `GuestSocketAddr`, `NetworkNamespaceId`, `PortProtocol` (existing), `PureSocketInner` (only as `Arc<...>` payload; no calls into it).

- [ ] **Step 1: Write the failing tests** (in `inzone.rs` `mod tests`):

```rust
#[test]
fn wildcard_listener_matches_loopback_destination_in_its_scope() {
    let reg = InZoneRegistry::default();
    let scope = InZoneScope::CarrierHost;
    let l = reg.register(InZoneListenerKey { scope: scope.clone(), addr: GuestSocketAddr("0.0.0.0:8080".parse().unwrap()) }, 16);
    assert!(Arc::ptr_eq(&reg.resolve(&scope, GuestSocketAddr("127.0.0.1:8080".parse().unwrap())).unwrap(), &l));
    assert!(Arc::ptr_eq(&reg.resolve(&scope, GuestSocketAddr("127.0.1.1:8080".parse().unwrap())).unwrap(), &l));
    assert!(reg.resolve(&scope, GuestSocketAddr("10.0.0.5:8080".parse().unwrap())).is_none(), "not a loopback destination");
    assert!(reg.resolve(&InZoneScope::Namespace(NetworkNamespaceId::from("other")), GuestSocketAddr("127.0.0.1:8080".parse().unwrap())).is_none(), "another namespace never sees it");
    reg.unregister(&l);
    assert!(reg.resolve(&scope, GuestSocketAddr("127.0.0.1:8080".parse().unwrap())).is_none());
}

#[test]
fn backlog_bounds_the_queue_and_dequeue_is_fifo() {
    let reg = InZoneRegistry::default(); let scope = InZoneScope::CarrierHost;
    let l = reg.register(InZoneListenerKey { scope, addr: GuestSocketAddr("127.0.0.1:1".parse().unwrap()) }, 2);
    let halves: Vec<_> = (0..3).map(|_| PureSocketInner::pair_with_family(LINUX_AF_INET, LINUX_SOCK_STREAM, LINUX_IPPROTO_TCP, LinuxUcred::default(), LinuxUcred::default()).1).collect();
    assert!(matches!(l.enqueue(Arc::clone(&halves[0])), InZoneEnqueue::Queued));
    assert!(matches!(l.enqueue(Arc::clone(&halves[1])), InZoneEnqueue::Queued));
    assert!(matches!(l.enqueue(Arc::clone(&halves[2])), InZoneEnqueue::BacklogFull));
    assert!(Arc::ptr_eq(&l.dequeue().unwrap(), &halves[0]));
    assert!(Arc::ptr_eq(&l.dequeue().unwrap(), &halves[1]));
    assert!(l.dequeue().is_none());
}

#[test]
fn ephemeral_ports_are_unique_per_scope_and_visible_to_bind() {
    let reg = InZoneRegistry::default(); let scope = InZoneScope::CarrierHost;
    let a = reg.allocate_ephemeral(&scope, AddrFamily::V4).unwrap();
    let b = reg.allocate_ephemeral(&scope, AddrFamily::V4).unwrap();
    assert_ne!(a, b); assert!(reg.port_in_use(&scope, a.raw()));
    reg.release_ephemeral(&scope, a); assert!(!reg.port_in_use(&scope, a.raw()));
}

#[test]
fn reuseport_group_gets_the_shortest_queue() {
    let reg = InZoneRegistry::default(); let scope = InZoneScope::CarrierHost;
    let key = InZoneListenerKey { scope: scope.clone(), addr: GuestSocketAddr("0.0.0.0:7".parse().unwrap()) };
    let a = reg.register(key.clone(), 16); let b = reg.register(key, 16);
    for _ in 0..3 {
        let target = reg.resolve(&scope, GuestSocketAddr("127.0.0.1:7".parse().unwrap())).unwrap();
        let half = PureSocketInner::pair_with_family(LINUX_AF_INET, LINUX_SOCK_STREAM, LINUX_IPPROTO_TCP, LinuxUcred::default(), LinuxUcred::default()).1;
        assert!(matches!(target.enqueue(half), InZoneEnqueue::Queued));
    }
    let (pa, pb) = (a.pending(), b.pending());
    assert_eq!(pa + pb, 3); assert!(pa.abs_diff(pb) <= 1, "shortest-queue placement: {pa}/{pb}");
}

#[test]
fn provider_resolve_connect_prefers_in_zone_then_falls_through() {
    // SocketNamespaceProvider + registry: register 127.0.0.1:9000 in CarrierHost;
    // resolve_connect(None, 127.0.0.1:9000, Tcp) == InZone; resolve_connect(None, 127.0.0.1:9001, Tcp) == the previous answer (Host/Unchanged)
}
```

- [ ] **Step 2: Run them, confirm they fail to compile** (`cargo test -p carrick-runtime --lib network::inzone`).
- [ ] **Step 3: Implement `inzone.rs` and the `mod.rs`/provider changes** exactly as typed above. `resolve` matches: exact `(scope, addr)`; else wildcard listener `(scope, 0.0.0.0/::, port)` when the destination is loopback (127/8, ::1) or equals a scope-local address the provider knows (`NetworkNamespaceSpec` attachment IPs for Bridge). Nothing else matches.
- [ ] **Step 4: Tests green**; `just clippy`; `just lint-domains` (a new `carrick_fatal!`? none expected; no host syscalls in this file).
- [ ] **Step 5: Commit** `feat(network): in-zone loopback listener registry and connect target`.

### Task 2: Dispatcher wiring — listen registers, connect pairs, accept drains

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/net/lifecycle.rs` (`listen` ~L1829, `accept_common` ~L1020, `connect` ~L1943 intercept seam, `bind` ~L1518, last-ref close path), `crates/carrick-runtime/src/dispatch/fd_table.rs` (`HostSocket.inzone_listener`, `readiness` ~L1797, in-memory `SocketKey`).
- Test: `crates/carrick-runtime/src/dispatch/tests.rs` (dispatcher-level tests exist there; add a `mod inzone_tcp`), `crates/carrick-runtime/tests/integration/syscall_net_*.rs` for a guest-level round trip.

**Interfaces:**
- Consumes: Task 1's registry (`this.network.provider.inzone()`), `ConnectTarget::InZone`, `PureSocketInner::pair_with_family`, `InMemorySocket` install (copy the Intercept arm's shape), `notify_inmem_epoll`, `WaitFds::raw_one(..).with_redispatch_and_watched_slots(&files, [host_listen_fd], [listen_fd])`.
- Produces: nothing new for other tasks; behaviour only.

- [ ] **Step 1: Failing dispatcher test** (`dispatch/tests.rs`): create listener fd via `socket/bind(127.0.0.1:0)/listen`, read its port with `getsockname`, create client `socket/connect(127.0.0.1:port)`; assert the client description is `InMemorySocket`, `accept` returns an fd whose description is `InMemorySocket`, `write` on client then `read` on accepted returns the bytes, `getpeername(accepted) == getsockname(client)`, and NO host `accept` was performed (count via a test hook or by asserting the host listen socket has no pending connection: `poll(host_fd, POLLIN, 0) == 0`).
- [ ] **Step 2: Failing readiness test**: with one queued in-zone connection, `poll_ready_events(listen_fd, POLLIN) & POLLIN != 0` and `epoll_ready_events(listen_fd, EPOLLIN)` agrees (the netlink precedent test at `net.rs` ~L905 is the model).
- [ ] **Step 3: Failing close test**: close the listener with one queued half → the client's `recv` returns `ECONNRESET`/EOF as specified and `SO_ERROR` reads `ECONNRESET` once.
- [ ] **Step 4: Implement** in the order listen → connect → accept → readiness → close/unregister → bind port check. Every host-authority call you add (none expected: this task removes host calls for in-zone flows) needs a reviewed inventory row.
- [ ] **Step 5: Tests green; `just test`; `just test-integration`; `just clippy`; `just lint-domains`.**
- [ ] **Step 6: Commit** `feat(net): pair guest loopback TCP connections in-zone`.

### Task 3: INET stream semantics of in-memory halves (audit, file-disjoint from Task 2)

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/net/unix_pure.rs` (`poll_mask`, shutdown, `so_error`, `connection_state` for INET halves), `crates/carrick-runtime/src/dispatch/net/send_recv.rs` (MSG_PEEK, MSG_DONTWAIT, MSG_NOSIGNAL/EPIPE+SIGPIPE on a closed peer, partial writes with SO_SNDBUF-sized in-memory buffer), `crates/carrick-runtime/src/dispatch/net/sockopt.rs` (`TCP_NODELAY`, `TCP_KEEP*`, `SO_KEEPALIVE`, `SO_RCVBUF/SO_SNDBUF` get/set as bookkeeping with Linux doubling semantics, `SO_LINGER`, `SO_ACCEPTCONN`, `SO_DOMAIN/SO_TYPE/SO_PROTOCOL`, `TCP_INFO` minimal), `crates/carrick-runtime/src/dispatch/fs/ioctl.rs` (`FIONREAD`/`SIOCINQ`, `SIOCOUTQ`).
- Test: unit tests beside each; use `PureSocketInner::pair_with_family(LINUX_AF_INET, SOCK_STREAM, IPPROTO_TCP, ..)`.

**Interfaces:** consumes only existing `PureSocketInner`; produces no new API (Task 2 relies on the behaviours listed).

- [ ] **Step 1: Failing tests, one per rule**: (a) peer `shutdown(SHUT_WR)` → `poll_mask` has `EPOLLIN|EPOLLRDHUP`, `recv` returns buffered bytes then 0; (b) peer fully closed → `send` returns `EPIPE` (and the SIGPIPE decision follows the existing INET host-socket rule); (c) `MSG_PEEK` does not consume; (d) `TCP_NODELAY` set/get round-trips on an INET in-memory half and is `ENOPROTOOPT` on an AF_UNIX half; (e) `SO_SNDBUF` caps buffered bytes and a full buffer makes `send` block/`EAGAIN` and clears `EPOLLOUT` until the peer reads (Linux semantic; pick Linux's default 212992 doubled value); (f) `FIONREAD` reports buffered bytes.
- [ ] **Step 2: Implement; tests green; clippy; lint.**
- [ ] **Step 3: Commit** `fix(net): in-memory INET stream halves carry TCP socket semantics`.

### Task 4: Line-exact probe `inzonetcp` (file-disjoint)

**Files:**
- Create: `conformance-probes/src/bin/inzonetcp.rs`; register it where the other generic probes are listed (follow `acceptsock`'s registration: probe manifest + `scripts/conformance/oracle-cache.jsonl` bless happens on the Docker host in a Docker-only phase).
- Build BOTH targets through the Docker toolchains (`rust:alpine` for musl, `rust:bookworm` for gnu) exactly as the existing probes are built; the gate uses the musl binary.

- [ ] **Step 1: Write the probe**: listener on `0.0.0.0:0`, read port; client connect from a second thread to `127.0.0.1:port` (blocking) and, separately, a non-blocking connect to the same port; accept both; print as `key=value` lines: `getpeername(accepted)==getsockname(client)`, `getsockname(accepted).ip==127.0.0.1`, the non-blocking connect's return (0 or errno number) and its later `SO_ERROR`, a 64 KiB echo checksum round trip, `shutdown(SHUT_WR)` → peer `recv` returns 0 after bytes and `poll` reports `POLLRDHUP|POLLIN` (numbers), `FIONREAD` after a write, closing the listener with a queued connection → client `recv` errno number, `SO_ACCEPTCONN` on the listener, `TCP_NODELAY` round trip. Every wait bounded by a 5 s `poll`.
- [ ] **Step 2: Run against Docker** (Docker-only phase) to bless the oracle line; run against main's binary to record which lines differ TODAY (host-backed) — those lines are the red-first evidence; then against the Task 2 binary: MATCH.
- [ ] **Step 3: Commit** `test(conformance): inzonetcp probe pins guest loopback TCP semantics`.

### Task 5: Director integration

- [ ] Land Task 1, then Task 3 (parallel with 2's development), then Task 2, then Task 4's probe; rebuild; `just conformance-probes` 46/46 (+1 new); `just conformance-quick`; cpython `test_socket` and `test_asyncio` subsets via the ecosystem harness; paired scorecard (`measure-sep13c.sh` from `measure-sep13b.sh` with the new pin); `perf_net_tcp_rr`/`perf_net_tcp_stream` before/after; profile shares; ecosystem doc + memory.
