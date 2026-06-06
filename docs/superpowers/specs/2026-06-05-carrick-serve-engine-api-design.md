# `carrick serve`: the Docker-ecosystem compatibility goal

**Status:** design approved; not yet executed. The new ecosystem north-star,
analogous in role to [`goal.md`](../../../goal.md) (which scopes the
process-control conformance push). This goal is about *Docker/OCI ecosystem
reusability*, not syscall conformance.

**Date:** 2026-06-05.

**Scope:** make carrick usable by the programmatic Docker ecosystem — the tools
that speak the Docker Engine API over a socket and never shell out to a CLI
(testcontainers, `docker compose`, the `docker` CLI via `DOCKER_HOST`, and the
SDKs bollard/docker-py/dockerode). **Not** in scope: image *build*, full network
isolation, or cgroup/capability enforcement (see [Non-goals](#non-goals)).

---

## 1. Goal

Make carrick a runtime the **Docker ecosystem can drive**, not just a CLI a
human types at.

Carrick today is an excellent single-container, host-networked, hand-typed
runner: `carrick run ubuntu:24.04 /bin/echo hi` pulls an OCI image and runs it
with faithful entrypoint/cmd/env/workdir/exit-code semantics, on a runtime that
already passes ~425/438 CPython conformance suites against Docker. But the
moment a user reaches for the ecosystem, the wall is uniform: **every
programmatic tool speaks the Engine API over a socket, and carrick exposes no
socket.** No amount of CLI parity substitutes — the tools fail at client
construction before any carrick code runs.

This goal ships `carrick serve`: an optional, user-started server that answers
the Docker Engine HTTP API over a unix socket by reusing carrick's existing
daemonless lifecycle and on-disk container registry, plus the network and
plumbing work that makes that API *meaningful* for real tools.

## 2. Ambitious autonomous target (the north-star)

`DOCKER_HOST=unix:///…/carrick.sock` drives the real Docker ecosystem against
carrick, proven green in CI versus a real Docker oracle across four consumer
tiers and a published compatibility matrix:

1. **testcontainers** — the upstream testcontainers smoke suites (Java + Go)
   pass: `GenericContainer` create → start → `waitingFor` → `getMappedPort` →
   `execInContainer` → stop → remove, with the **Ryuk** reaper *served* (not
   merely disabled), and ≥N real arm64 modules (redis, postgres, …) green
   end-to-end.
2. **compose** — `docker compose up` boots ≥M single-file multi-service apps:
   service-name DNS (`web` → `db`), `depends_on`/healthcheck gating, and
   per-service mapped ports.
3. **docker CLI** — a corpus of `docker -H unix:///…/carrick.sock
   run/ps/logs/inspect/exec` commands runs unmodified, proving general
   Engine-API schema fidelity, not just the subset two tools happen to hit.
4. **matrix** — all of the above published as a CI artifact comparing carrick to
   a real Docker oracle, the way `support-matrix.md` already does for language
   runtimes.

This is ambitious because it spans a net-new HTTP server, a syscall-level
network-address translation subsystem, split-stream log capture, hijacked exec
streams, a polling event stream, and container-label plumbing — each
individually scoped, collectively defining "carrick is ecosystem-compatible."

## 3. Why this goal (where carrick sits)

A 9-dimension investigation (2026-06-05) scored carrick's ecosystem
compatibility versus Docker parity (1 = absent, 5 = parity):

| Dimension | Score | Note |
|---|---|---|
| OCI image **consume** (pull/store) | 4 | Any-registry v2 pull, correct multi-arch select, content-addressed dedup |
| Runtime config fidelity (merge) | 4 | ENTRYPOINT/CMD/ENV/WORKDIR/exit-code parity faithful & tested |
| Container lifecycle (daemonless) | 3 | Solid single-container run/-d/ps/stop/kill/rm/logs/exec/inspect/wait |
| `docker run` flag parity | 2 | ~12 flags work; unknown flags hard-error (exit 2) |
| Portability / on-ramp | 2 | Apple-Silicon + macOS 15 intrinsic; self-codesign + raw `HV_DENIED` avoidable |
| Embeddable library | 2 | Clean crate DAG, but unpublished, no LICENSE files, `execute()` hijacks the host process |
| OCI image **produce** (build/push/save) | 1 | Pure consumer; `oci-client` *can* push, it's unwired |
| Networking / port publishing | 1 | Permanently `--net host`; `-p` remap is a hard error |
| **Docker Engine API / socket** | **1** | **Zero** API surface — the single dispositive ecosystem blocker |
| Ecosystem tooling | 1 | All blocked at the first `/_ping` |

The crux: the ecosystem blocker is the missing API socket, then host-only
networking, then no build — **in that order.** This goal attacks the first two;
build is deferred ([Non-goals](#non-goals)).

## 4. Reconciliation with the daemonless heritage

Carrick's design says "there is no `carrickd`" ([`lifecycle.rs:5-13`](../../../crates/carrick-cli/src/lifecycle.rs)):
a detached container is its own process tree, and the source of truth is the
on-disk registry, not a running service. `carrick serve` must not break that.

The resolution: **`carrick serve` is a translator, not an owner.** It is an
*optional, user-started* server that owns no containers; it is a stateless
HTTP-to-`lifecycle.rs` lens over the on-disk registry. While it runs,
testcontainers/compose/`docker -H` get a stable `DOCKER_HOST`. When it stops,
detached containers keep running because they remain their own process trees —
exactly today's `run -d` model. "There is no `carrickd`" stays true in spirit:
the server is a lens, not a resident owner of container lifetime.

## 5. Architecture: server-as-translator

Three approaches were considered for how the server drives guests:

| Approach | Verdict |
|---|---|
| **1 — Server forks per container via the existing lifecycle path; reads the on-disk registry for queries** | **Chosen.** Reuses battle-tested code (`run_detached`/`run_supervised_child`); preserves "no resident ownership"; honors the no-tokio-main invariant. |
| 2 — In-process multi-guest server (libcarrick handle API) | **Constraint-blocked.** Carrick is *one HVF VM per process* ([`fork_quiesce.rs:55`](../../../crates/carrick-hvf/src/fork_quiesce.rs), [`trap.rs:87`](../../../crates/carrick-hvf/src/trap.rs)); a live VM at `fork()` makes the child's `hv_vm_create` return `HV_BUSY`. Concurrent in-process guests are precluded. |
| 3 — A `carrickd` owning all container state in-process | **Rejected.** Contradicts the daemonless heritage; duplicates the registry as crash-fragile in-memory state. |

**Chosen flow.** `POST /containers/create` lowers the API body into a
`CliRunRequest` and writes a `Created` registry entry; `POST /{id}/start`
reuses the **exact detached-run fork dance** (the `run_detached` /
`run_supervised_child` path in
[`lifecycle.rs:105`](../../../crates/carrick-cli/src/lifecycle.rs)) to spawn the
container as its own process tree. Queries (`/containers/json`, `/{id}/json`,
`/{id}/logs`, `/{id}/wait`, `/events`) are reads against the registry +
reconciled host process table. Signals (`/stop`, `/kill`) reuse the existing
host-`kill(2)` path.

**Runtime isolation (the no-tokio-main invariant).** `main.rs` forks guests
while single-threaded, before any multi-thread tokio runtime is live
([`main.rs:54`](../../../crates/carrick-cli/src/main.rs); `block_on_oci` builds
and drops a per-call current-thread runtime). `carrick serve` must keep the HTTP
server's async runtime strictly isolated from the fork path: the container fork
goes through the existing lifecycle functions (which fork a fresh supervisor),
**not** an inline `engine.run` on a tokio worker.

**Dependencies.** `hyper`, `hyper-util`, `hyperlocal`/`http-body-util`, and
`bollard` are already in `Cargo.lock` (pulled by the `bollard` test dep), so the
unix-socket HTTP server stack and a bollard smoke client need no new external
deps. `tokio` must gain the `net` feature (currently `rt`-only).

## 6. Network subsystem: syscall-NAT + opt-in honest-IP

### 6.1 The premise

Carrick does not *emulate* the network — it *translates*. A guest `socket()` is
a host `socket()`, a guest `bind()` is a host `bind()`, and
"a Linux server under carrick is reachable from the macOS host"
([`net.rs:10-16`](../../../crates/carrick-runtime/src/dispatch/net.rs)). The only
synthetic piece is AF_NETLINK, faked to present "a single-`lo`, loopback-only
host — matching `docker run --net host`." So carrick **is** `--net host`,
permanently, and `NamespaceMode` has exactly one variant, `Host`
([`spec/lib.rs:191-213`](../../../crates/carrick-spec/src/lib.rs)). `-p` remap is
a hard error ([`runtime_util.rs:89,104,112`](../../../crates/carrick-cli/src/runtime_util.rs))
and `ps` hardcodes empty PORTS ([`lifecycle.rs:489`](../../../crates/carrick-cli/src/lifecycle.rs)).

testcontainers' `getMappedPort()` and compose's service DNS need *some* network
virtualization. The design principle: **lean on the macOS kernel for 100% of
TCP/IP; carrick only rewrites addresses/ports at the syscall boundary it already
owns.**

### 6.2 macOS primitive analysis (why "give each container a real IP" is root-gated)

The elegant route — rewrite guest `bind(0.0.0.0:6379)` → host
`bind(<container-ip>:6379)` on a real socket — hits a hard macOS wall:

| Primitive | macOS reality |
|---|---|
| `127.0.0.x` loopback aliases | On Linux all of `127.0.0.0/8` is bindable for free; on macOS only `127.0.0.1` is assigned. `bind(127.0.0.2)` → `EADDRNOTAVAIL` until `ifconfig lo0 alias` — `SIOCAIFADDR`, **root-only**. |
| Per-container IPv6 (ULA/link-local) | Same wall: assigning an address to an interface needs root. **IPv6's huge space doesn't help — the gate is address *assignment* privilege, not address scarcity.** |
| IPv4-mapped IPv6 (`::ffff:v4`) | A dual-stack *accept* feature (one `AF_INET6` socket serves both families); does **not** expand bindable space or give isolation. |
| `vmnet.framework` | Real per-container IPs, but needs the `com.apple.vm.networking` entitlement **and** is a *packet* interface — forces carrick back into moving packets + a userspace stack. Relocates the problem. |
| `utun` / `feth` / `pf` rdr | All packet-level and/or root-gated. |

Cute but useless: the v4 and v6 loopback are separate port spaces, so
`127.0.0.1:6379` and `[::1]:6379` can both be bound — a factor of **2**, not N.

**Conclusion:** every honest-per-IP route on macOS is root- or
entitlement-gated, which would break the "no sudo" on-ramp. So the *default* is
the privilege-free syscall-NAT path below; honest-IP is an opt-in.

### 6.3 Default: syscall-level NAT (zero-root)

A per-container NAT table in the dispatcher; `net.rs` rewrites at the seams it
already owns ([`bind:2360`, `connect:2563`, `getsockname:2659`,
`getpeername:2707`](../../../crates/carrick-runtime/src/dispatch/net.rs)):

1. **`bind(0.0.0.0:6379)`** → host `bind(127.0.0.1, 0)`; the kernel assigns an
   ephemeral port (e.g. `53412`). Record `container-A: guest 6379 ↔ host 53412`.
2. **`getsockname()`** → report the guest's original port (`6379`) back, so the
   guest still believes it is on 6379.
3. **Engine API** → `NetworkSettings.Ports["6379/tcp"] = [{HostPort:"53412"}]`,
   so `getMappedPort(6379)` returns `53412` and the client connects to
   `127.0.0.1:53412`. No aliases, no root.
4. **`connect("db", 5432)`** → an **embedded resolver** maps `db` →
   container-B, and a connect-rewrite table turns `(B, 5432)` into
   `127.0.0.1:<B's ephemeral>`.

The macOS kernel does 100% of the TCP/IP (handshakes, congestion control,
buffering, `epoll`/`kqueue` readiness that carrick already translates). Carrick
adds a NAT table in the syscall layer — a *syscall-level NAT* rather than a
packet-level one. This is more in carrick's spirit than a stack.

**Honest limits:** `getsockname` "lying" can confuse the rare app comparing its
advertised port against a peer's report; protocols embedding addresses/ports in
payload (FTP active mode, some RPC/SIP) break (true of all NAT); inter-container
traffic rides `127.0.0.1`, so there is no true isolation/firewalling and no
raw-socket/ICMP fidelity (those keep passing through).

### 6.4 Opt-in: honest-IP mode

For users who grant a one-time privileged setup (a launchd helper, `lo0`
aliases, or `vmnet`), an opt-in mode gives each container a real `127.0.0.x`
host IP, so guest `bind(6379)` maps to a real `<container-ip>:6379` and
`getsockname` is honest (two servers truly bind 6379). Layered on the same
bind-rewrite seam; **never the default**, so the zero-root path stays the happy
path.

## 7. Engine-API surface

Pin/negotiate an API version strongly-typed clients accept (target ~v1.43–1.44;
note Docker Engine 29 raised the minimum to v1.44 and the `/version`
`ApiVersion`/`MinAPIVersion` handshake gates older testcontainers). JSON schema
fidelity must satisfy bollard/docker-java deserialization for
`NetworkSettings.Ports`, `Config.Labels`, `State`, `HostConfig`, and `Mounts`.

Endpoints:

- **Handshake:** `GET /_ping`, `GET /version`, `GET /info`.
- **Lifecycle:** `POST /containers/create`, `POST /{id}/start`,
  `POST /{id}/wait`, `POST /{id}/stop`, `POST /{id}/kill`,
  `DELETE /containers/{id}`.
- **Query:** `GET /containers/json` (with label `?filters`),
  `GET /containers/{id}/json`, `GET /containers/{id}/logs`.
- **Images:** `POST /images/create` (pull), `GET /images/json`.
- **Exec:** `POST /containers/{id}/exec`, `POST /exec/{id}/start` (hijacked
  stream).
- **Events:** `GET /events` (polling-backed).

## 8. Connective plumbing

- **Container labels (net-new).** Thread a labels map through `CliRunRequest`
  ([`engine/lib.rs:83`](../../../crates/carrick-engine/src/lib.rs)) → `RunConfig`
  ([`container.rs:72`](../../../crates/carrick-runtime/src/container.rs)) →
  `ContainerState` ([`container.rs:36`](../../../crates/carrick-runtime/src/container.rs))
  and implement label-filtered listing. (Today only `ImageConfig.labels` exists;
  `CliRunRequest`/`ContainerState` carry none — `labels: None` at
  [`engine/lib.rs:328`](../../../crates/carrick-engine/src/lib.rs).) This is the
  discovery key for compose (`com.docker.compose.*`), testcontainers, and Ryuk
  (`org.testcontainers.*`).
- **Split-stream logs.** Re-plumb capture into *separate* stdout/stderr (today
  both `dup2` to one `output.log` —
  [`lifecycle.rs:438-439`](../../../crates/carrick-cli/src/lifecycle.rs)) so
  `/logs` emits the 8-byte stdcopy frame headers bollard/docker-java demux.
  Required for the docker-CLI tier and clean testcontainers logs.
- **exec hijack.** A bidirectional HTTP stream over the existing exec primitive
  ([`lifecycle.rs:846`](../../../crates/carrick-cli/src/lifecycle.rs), which
  requires `--fs host` + `--pid private`). Needed by `docker exec` and some
  wait strategies (e.g. `pg_isready`).
- **`/events` (polling-backed).** No inotify/daemon push exists; poll the
  registry + reconciled host proc table to synthesize container
  create/start/die/stop events for compose `depends_on`/healthcheck gating and
  `docker events`.
- **Ryuk (served).** With labels + syscall-NAT, the Ryuk reaper container works:
  it starts as a labeled container, the client connects back over a
  `getMappedPort`-discovered port, and it reaps labeled containers on session
  end. Serve it by default; `TESTCONTAINERS_RYUK_DISABLED=true` is the
  documented fallback.

## 9. Milestones

Each milestone lands with conformance/differential evidence versus a real Docker
oracle (the `bollard`-driven harness pattern already in `conformance.rs`).

### M0 — Socket handshake
`carrick serve --docker-api` listens on a unix socket and answers
`GET /_ping` + `/version` + `/info`, plus `POST /containers/create` +
`/{id}/start` + `/{id}/wait` + `DELETE /containers/{id}`.
**Exit:** a 20-line bollard script creates, starts, waits on, and removes an
`ubuntu:24.04 echo hi` container over the socket; the no-tokio-main fork
isolation is proven (the server forks via the lifecycle path, not a tokio
worker).

**Landed:** `carrick serve --docker-api` answers `/_ping`/`/version`/`/info` and the container create/start/wait/delete loop over a unix socket, reusing the daemonless on-disk registry + detached-fork lifecycle (the server shells out to the `carrick` binary, never forking a guest in its tokio process). Proven by `crates/carrick-cli/tests/serve.rs` (8 tests, incl. `m0_full_lifecycle_echo_hi` driving the full loop via bollard with a real HVF guest). Network model (syscall-NAT / honest-IP), labels, split-stream logs, exec, events, and Ryuk remain for M1+.

### M1 — testcontainers core
Container labels plumbed end-to-end; split-stream `/logs` with stdcopy framing;
`/containers/json` + `/{id}/json` extended to the real schema (incl.
`Config.Labels`); `POST /images/create` (pull). Ryuk *disabled* for this
milestone.
**Exit:** the testcontainers (Java or Go) `GenericContainer`
create/start/wait/logs/stop/remove loop passes its smoke suite against carrick
for one single-instance arm64 module, with `getMappedPort` returning the
container port (host-identity, pre-NAT).

### M2 — syscall-NAT + resolver
Per-container NAT table; `bind`/`getsockname`/`connect`/`getpeername` rewriting;
ephemeral host-port allocation; embedded name resolver; `NetworkSettings.Ports`
populated.
**Exit:** two instances of the same image both "bind 6379" and run concurrently;
`getMappedPort` returns distinct mapped ports; a connect-by-service-name probe
resolves and connects. Opt-in honest-IP mode lands behind a flag with the
privileged setup helper.

### M3 — compose
`/events` polling stream; exec hijack; healthcheck wiring.
**Exit:** `docker compose up` boots a ≥3-service app (e.g. web + db + redis) with
service DNS, `depends_on`/healthcheck gating, and per-service mapped ports;
shutdown reaps cleanly.

### M4 — docker CLI parity + Ryuk
JSON schema fidelity hardened for strongly-typed clients; Ryuk *served*.
**Exit:** a `docker -H unix:///…/carrick.sock run/ps/logs/inspect/exec` command
corpus runs unmodified; the testcontainers Ryuk reaper is served (not disabled)
and reaps labeled containers on session end.

### M5 — published matrix
**Exit:** a CI artifact (like `support-matrix.md`) reports N testcontainers
modules, M compose apps, and the docker-CLI corpus, each green versus a real
Docker oracle, with every divergence tracked or excused.

## 10. Acceptance rules

1. No endpoint counts as "done" without a differential test versus a real Docker
   oracle (bollard or the real client), asserting body shape, not just status.
2. No silent network divergence: a rewritten `getsockname`/`connect` must be
   covered by a probe that proves the guest-visible mapping matches the
   API-reported mapping.
3. The zero-root syscall-NAT path is the default and must never require
   privilege; honest-IP mode is opt-in and must fail with an actionable message
   if its setup is absent.
4. The server owns no container lifetime: killing `carrick serve` must leave
   detached containers running (proven by a restart-survival test).
5. Keep commits logical: API endpoint, network rewrite, plumbing
   (labels/logs/exec/events), and matrix/harness changes split when
   independently meaningful.

## 11. Non-goals

- **Full userspace network stack / true isolation / netfilter / raw sockets /
  honest `/proc/net`** (smoltcp/lwIP/gVisor-netstack). This inverts
  translate-don't-emulate and is a separate, larger bet.
- **Image build / Dockerfile / BuildKit / commit.** Carrick is an OCI consumer;
  build needs a net-new layer-diff/commit subsystem the runtime lacks (only the
  extract/read side exists). A separate goal. (`push`/`save`/`load` are cheap and
  may be done opportunistically, but are not this goal's success criteria.)
- **cgroup / capability / seccomp / apparmor enforcement** — no LSM/cgroup model
  under HVF; `--memory`/`--cpus`/`--cap-*` stay warn-and-accept.
- **Kubernetes/CRI**, `docker stats`/`pause`/GPU/log-drivers — daemon/cgroup
  dependent, low value here.
- **Non-Apple-Silicon hosts** — intrinsic HVF gate. (amd64 *guests* run via
  Rosetta and are in scope for what they are.)

## 12. Risks & open questions

- **API-version fidelity is a moving floor.** The `/version` handshake and the
  typed-client JSON schemas must match a version the target clients accept;
  getting `NetworkSettings`/`State`/`HostConfig` shape wrong fails
  deserialization before any logic runs. Mitigation: pin a version, snapshot-test
  the JSON against the real Docker response.
- **Connect-rewrite keying.** The embedded resolver + connect table must be keyed
  per *container* (not per host process) and survive fork; needs a fork-coherent
  store like the existing `MAP_SHARED`/`cred_ipc` patterns. Open: exact storage.
- **exec hijack ↔ `--fs host`/`--pid private` constraint.** The exec primitive
  requires those flags; memory-overlay containers are not joinable. Open: do we
  force `--fs host` for served containers, or report a clear error?
- **Ryuk's privileged-container surface.** Ryuk normally mounts the docker socket
  and runs privileged; we serve a carrick-shaped equivalent. Open: how faithfully
  must we emulate Ryuk's own protocol versus shipping a carrick-native reaper that
  satisfies the same client expectations.
- **Long-tail dominance.** The "everything" north-star risks events/exec/schema
  edge cases dominating. Mitigation: the milestone gates are independently
  shippable; M0–M1 deliver real value before the tail.

## Appendix — code anchors (verified 2026-06-05)

- Daemonless model, detached fork dance, exec primitive:
  `crates/carrick-cli/src/lifecycle.rs:5-13,105,438-439,489,846`.
- `-p` remap hard error: `crates/carrick-cli/src/runtime_util.rs:89,104,112`.
- `CliRunRequest` (no labels), `labels: None`:
  `crates/carrick-engine/src/lib.rs:83,328`; USER-by-name warning (already
  shipped) at `:205-207,260`.
- `ContainerState`/`RunConfig` (no labels): `crates/carrick-runtime/src/container.rs:36,72`.
- `uid`/`gid` already on `RunSpec` (so `--user` is shipped):
  `crates/carrick-spec/src/lib.rs:327,331`; `NamespaceMode` single `Host` variant
  at `:191-213`.
- Networking translation + rewrite seams:
  `crates/carrick-runtime/src/dispatch/net.rs:10-16,2360,2563,2659,2707`.
- One-HVF-VM-per-process constraint: `crates/carrick-hvf/src/fork_quiesce.rs:55`,
  `crates/carrick-hvf/src/trap.rs:87`.
- No-tokio-main invariant: `crates/carrick-cli/src/main.rs:54`.
- Prior conservative audit (superseded posture): `docs/archive/docker-compat-audit.md`.
