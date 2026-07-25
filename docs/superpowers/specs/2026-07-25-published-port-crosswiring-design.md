# Design spec — published-port cross-wiring (DEFECT 1)

Status: **PROPOSED — for maintainer ruling. Not implemented.**
Author: design lane (subagent), 2026-07-25.
Subject: `crates/carrick-runtime/src/network/socket_namespace.rs`, `crates/carrick-spec/src/lib.rs`.
Sibling work: DEFECT 2 (endpoint-dir O(n) scans + unbounded litter) is tracked separately; this
spec is deliberately orthogonal to it and notes where the two compose.

---

## 1. The defect, precisely

The fork-coherent endpoint namespace is a **machine-global flat directory** —
`$TMPDIR/carrick-netns-socket-bridge` (`socket_namespace.rs:1032-1054`; no env override; shared by
every carrick process on the box, including sibling git worktrees). Records are keyed **only** by
`(scope, guest addr, protocol)`:

```rust
// socket_namespace.rs:1087-1098
endpoint_dir.join(format!("{scope}-{ip}-{}-{protocol}", endpoint.addr.0.port()))
// socket_namespace.rs:1151-1156
EndpointScope::Bridge(b)    => format!("bridge-{}", hex_name(b.as_str()))
EndpointScope::Namespace(n) => format!("ns-{}",     hex_name(n.as_str()))
```

For a container with **no `--name`** on the **default bridge**, every component of that key is a
compile-time constant:

| component | value | source |
| --- | --- | --- |
| bridge id | `carrick0` → hex `6361727269636b30` | `BridgeId::default_bridge()`, `carrick-spec/src/lib.rs:390-392` |
| guest ip | `172.31.0.2` | `bridge_ipv4_for_name(None)` early-return, `carrick-spec/src/lib.rs:533-536` |
| namespace id | `"default"` on the un-overridden path | `NetworkNamespaceSpec::bridge_default`, `carrick-spec/src/lib.rs:491` |

So two concurrent `carrick run` instances that publish a port for an unnamed container write and read
**the same file**. The relay that serves an inbound host connection reads that file
(`published_tcp_accept_loop:1391-1398`; UDP `:1494-1501`) — the in-process `registry` cannot help,
because the guest listener is bound by a **forked descendant** whose `register_virtual_endpoint`
landed in its own COW copy of the registry, invisible to the parent's relay thread. The file is the
only channel, and the file is aliased.

### 1.1 Evidence

**On disk right now** (production endpoint dir, this machine, verified while writing this spec):

```
$ ls $TMPDIR/carrick-netns-socket-bridge | wc -l
24219
$ ls | grep '^bridge-6361727269636b30-172.31.0.2-'
bridge-6361727269636b30-172.31.0.2-49152-tcp   →  127.0.0.1:51175  pid=24838
bridge-6361727269636b30-172.31.0.2-80-tcp      →  127.0.0.1:49152  pid=24838
bridge-6361727269636b30-172.31.0.2-8081-udp    →  127.0.0.1:56430  pid=26769
bridge-6361727269636b30-172.31.0.2-8082-tcp    →  127.0.0.1:51614  pid=26769
bridge-6361727269636b30-172.31.0.2-8092-tcp    →  127.0.0.1:63808  pid=6563
```

Five distinct guest ports on the **one** constant key, last-written by **three different owner
pids**. Every unnamed run this machine has ever done has been overwriting its predecessors' records
on that key.

**Empirically reproduced, 12/12.** The determinism investigation that produced this spec ran two
concurrent test processes that each published a port for an unnamed container: **12 out of 12 runs
cross-wired, 8 of them hanging.** `lldb` on a wedged process showed its relay thread proxying an
inbound connection **to the other process's target listener**, while its own listener sat in
`__accept` having never received an inbound connection. The peer process observed the discarded
connection as `ECONNRESET`. Commit `c0c8ded8` removed the *test* exposure (a pid-scoped
`#[cfg(test)]` subdirectory, `socket_namespace.rs:1041-1052`) — the shipped binary is unchanged and
still uses the flat global dir.

**Second aliasing channel, same root cause, worse consequence.** `endpoint_scope` routes *loopback*
endpoints to `EndpointScope::Namespace(namespace_id)` (`:1139-1149`). The CLI already makes that id
instance-unique (`anon-<pid>`, `carrick-engine/src/lib.rs:404-410`), **but two paths do not**:
`NetworkNamespaceSpec::bridge_default` hardcodes `Some("default")` (`carrick-spec:491`), and the
bare native runner builds its spec straight from `bridge_default` without overriding it
(`crates/carrick-runtime/src/lib.rs:989-994`, using `guest_hostname()` — a per-machine constant).
On those paths `ns-64656661756c74-127.0.0.1-<port>-tcp` is also a shared key, i.e. **one guest's
`127.0.0.1:8080` is resolvable and connectable from a concurrent instance.** Guest loopback leaving
the instance is a stronger isolation violation than the relay flake, and it is fixed by the same
work.

### 1.2 Why the key is *only* ambiguous for unnamed containers (load-bearing)

`bridge_ipv4_for_name` (`carrick-spec:533-546`) computes, for a non-empty name,
`third = 1 + bucket/253` (bucket ∈ `0..253*253-1`, so `third ∈ 1..=253`) and
`fourth = 2 + bucket%253` (`fourth ∈ 2..=254`). **Every name-derived address is in
`172.31.[1..253].[2..254]`; the unnamed placeholder `172.31.0.2` is in a disjoint /24.** The
gateway is `172.31.0.1`. So `172.31.0.0/24` is de facto reserved for "no address was allocated,
here is a placeholder", and every routable bridge address in use today belongs to a *named*
container that publishes DNS records (`service_names_for:1167-1180` only emits records for a
non-empty name/alias). That disjointness is the fact the recommended fix is built on.

---

## 2. User-visible impact — severity

**Yes: this can send one container's traffic to a different container, including a different
user's / different project's container on the same machine.** Concretely, with two concurrent
`carrick run -p …` of unnamed containers (two terminals, two worktrees, two `just ci` lanes, a
conformance lane beside a manual run — C14):

1. **Mis-delivery (the severity case).** An inbound connection to instance A's published host port
   is proxied to **instance B's** container listener. The client gets a well-formed response from
   the wrong workload. Nothing logs anything. If the containers are, say, two revisions of the same
   service, the response is plausible and the user cannot tell. If they are unrelated, the user sees
   protocol garbage. Data written by an external client can land in the wrong container.
2. **Hang.** A's own listener never receives the connection; a client doing request/response blocks
   until its own timeout (8/12 in the repro).
3. **`ECONNRESET`.** The instance whose record lost the race sees connections opened and discarded.
4. **Cross-instance loopback resolution** (on the `bridge_default`/native-runner paths): a guest's
   `connect(127.0.0.1:8080)` can be routed to *another instance's* guest process.
5. **Feedback into DEFECT 2.** The overwritten owner's `destroy_namespace` content-compare
   (`:1681-1701`) no longer matches, so it silently skips its own cleanup and leaks the record
   forever — this is visible in the 5 files above.

Not a privilege escalation (both instances are the same host uid, and the relay only ever connects
to a `127.0.0.1` host port), but it **is** a silent cross-tenant data-path error on a single
developer machine, with no diagnostic. Severity: **high for correctness, low for security**.

Trigger conditions: two carrick instances alive at once, at least one publishing a port
(`-p`) for a container with **no `--name`**, on the default bridge. That is the default shape of
`carrick run -p 8080:80 <image>` and the shape of the conformance published-port probe.

---

## 3. Recommended design

**Realm-qualify the ambiguous key; keep every unambiguous key exactly where it is; add cheap
self-verification as defense in depth.** Three parts, in dependency order.

### F1 — No constant namespace id can ever reach a path builder

*Fixes channel 2 (loopback) outright and makes F2's private realm meaningful.*

- `carrick-spec/src/lib.rs:491`: `NetworkNamespaceSpec::bridge_default` stops naming the namespace
  (`namespace_id: None`). `carrick-spec` stays pure — it must not call `std::process::id()`.
- `crates/carrick-runtime/src/network/mod.rs:296` (`RuntimeNetwork::create`): **single defaulting
  choke point** — if `spec.namespace_id` is `None` (or the legacy literal `"default"`), fill it with
  `anon-<pid>` before `select_provider`/`create_namespace`. This runs in the root host process,
  strictly before any guest fork, so the id is frozen in the spec that `fork()` copies.
  One site instead of N construction sites; no future spec-builder can regress it.
- `crates/carrick-runtime/src/lib.rs:989-994` (bare native runner) needs no change once the choke
  point exists, but a `debug_assert` there documents the invariant.
- Invariant to assert in a unit test: **no spec reaching `SocketNamespaceProvider` has
  `namespace_id ∈ {None, "default"}`.**

Existing overrides are untouched: `carrick-engine/src/lib.rs:404-410` keeps
`network_namespace_id → network_container → name → anon-<pid>`, which is exactly the identity
`carrick exec` and `--network container:X` inherit — so **anything that resolves loopback today keeps
resolving it**, because the matching condition is unchanged (equal `namespace_id`).

### F2 — A private realm directory for the unnamed-placeholder bridge key

Add the realm to the **key type**, so the compiler enumerates every site and the registry and the
file can never disagree:

```rust
// socket_namespace.rs, replacing EndpointScope::Bridge(BridgeId)
enum EndpointScope {
    Bridge { bridge: BridgeId, realm: BridgeRealm },
    Namespace(NetworkNamespaceId),
}
enum BridgeRealm {
    /// Name-derived address: intentionally visible machine-wide (C2/C3/C4).
    Shared,
    /// The unnamed 172.31.0.0/24 placeholder: only its own instance can mean it.
    Private(NetworkNamespaceId),
}

/// The ONE decision function. Pure; identical at publisher and resolver.
fn bridge_realm(namespace_id: &NetworkNamespaceId, guest_ip: IpAddr) -> BridgeRealm {
    match guest_ip {
        IpAddr::V4(ip) if ip.octets()[..3] == [172, 31, 0] => BridgeRealm::Private(namespace_id.clone()),
        _ => BridgeRealm::Shared,
    }
}
```

Path mapping (`endpoint_scope_path_component:1151-1156` + `endpoint_path:1087`,
`listener_path:1113`):

| realm | path |
| --- | --- |
| `Shared` | `<dir>/bridge-<hex bridge>-<ip>-<port>-<proto>` — **byte-identical to today** |
| `Private(ns)` | `<dir>/inst-<hex ns>/bridge-<hex bridge>-<ip>-<port>-<proto>` |

Only **two** families move, and only in the `Private` case: the forward endpoint file and the
write-only `listen-*` file (which is keyed by the same `VirtualEndpoint`, so it follows for free and
`destroy_namespace`'s `listener_path`-keyed retain at `:1714-1718` stays consistent — C11 untouched).

**Deliberately unchanged:**
- `reverse-<host ip>-<host port>-<proto>` (`:1100-1111`) stays at the root. Its key is a **real host
  socket address**, globally unique while live — it cannot alias, and C4 (cross-instance reverse
  translation on every accept/recvfrom) depends on it being findable machine-wide.
- `service-<hex bridge>-<hex name>-addr-<ip>` (`:1122-1137`) stays at the root, unchanged. These
  exist only for named containers, i.e. only for `Shared` addresses. C2 and C5 are untouched, and
  the DNS/hosts `read_dir` scans (`:323`, `:369`) see the same directory shape as today.

Construction sites the compiler will flag (only **four** outside tests; each already has what it
needs — verified):

| site | how it gets the realm |
| --- | --- |
| `endpoint_scope` `:1139-1149` (bind/register path) | already takes `namespace_id` — zero new params |
| `resolve_registered_connect` `:395-406` (`:402`) | caller `resolve_bridge_connect` `:498` has `spec` → pass `spec.namespace_id` |
| `publish_tcp` `:768-775` | has `spec` |
| `publish_udp` `:834` | has `spec` |

`translate_host_source`'s forward-verification loop (`:720`) iterates `(namespace × attachment)`
with each namespace's own id, so it derives the same realm — consistent by construction.

Why a **subdirectory** rather than a filename prefix: it is the only variant that also helps
DEFECT 2. Every private realm id is `anon-<pid>` in practice (F1's choke point + engine's fallback;
a *named* container is never `Private`, by §1.2's disjointness), so `inst-anon-<pid>/` is
**pid-decidable as a whole directory** — exactly the `test-<pid>` precedent already in tree
(`reclaim_dead_test_endpoint_dirs:1062-1085`). That converts the `bridge-`/`listen-` families, which
the lazy per-file rule can *never* reach (nothing ever `read_dir`s for them), into a decidable
`remove_dir_all` sweep. See §7.

### F3 — Self-verification (defense in depth, reduced form of angle C)

Cheap, spec-free, and each item is an independent bug fix:

1. **Atomic publication.** `write_endpoint_file:1208-1226`, `register_service_names:296-308` and
   `prepare_tcp_listen:1020-1027` currently `fs::write` = `O_TRUNC` + `write`. A concurrent reader
   can observe an **empty** file → `read_namespace_file` returns `None` → spurious "no endpoint" →
   dropped connection / `ECONNREFUSED`. Replace with write-temp-in-same-dir + `fs::rename`. This is a
   real latent load-sensitive defect, independent of DEFECT 1, and it is a prerequisite for any
   content verification to be sound.
2. **`key=` self-identification.** Append `key=<the record's own path stem>` to every forward and
   reverse record; readers reject a record whose `key=` does not equal the tuple they asked for. This
   catches a path-scheme bug, a build-skew record, and a mid-migration mixed directory *loudly*
   instead of by mis-serving. Cost: one `str` compare on a string the reader already read; no extra
   syscalls; O(1) reads stay O(1).
3. **Strict own-instance check at the relay only.** Add `instance=<hex u128>` (process-global
   `OnceLock`, forced in `SocketNamespaceProvider::new:241` — i.e. pre-fork, so parent and every
   fork child compare equal) and have `published_tcp_accept_loop:1398` / `published_udp_loop:1501`
   **refuse any record whose `instance` is not their own**. The relay's target is built from *its
   own lease's spec*; a foreign record there is *always* wrong, with no exception — including the
   duplicate-`--name` case F2 cannot fix. One-shot `AtomicBool`-gated warning to stderr, then drop
   the connection. Guest-facing paths stay silent and map to `ECONNREFUSED` (`:511`, `:533`) as
   Linux would; observability goes to the always-on event ring (one new
   `event_ring.rs` kind `NSREJECT`, one dict entry in `scripts/carrick_lldb.py:331`).
4. **Guard the stale unlink.** `read_namespace_file:1289` unlinks any dead-owner record; a reader
   that read old bytes, lost the CPU while a writer renamed fresh bytes in, then unlinked, would
   **destroy a live publication**. Re-read-and-compare before unlink (same pattern as `:1681-1691`).
   Pre-existing; 6 lines; F3.1 makes it reachable more often, so it ships together.

### 3.1 Why this over the alternatives

**Not angle A (docker-like IPAM) as the primary fix.** It is the right long-term direction and it is
recommended as *follow-up* work, but it is the wrong instrument here:
- It closes one of the three channels. It cannot touch channel 2 (`ns-default-127.0.0.1-<port>`, an
  address-independent key), and it makes channel 3 (duplicate `--name` across instances) *worse
  shaped*: with distinct IPs, `resolve_service_name` starts returning **two live addresses for one
  name**, so the cross-wire moves out of the endpoint file and into DNS, where it is harder to see.
- It converts a **pure function** into allocated state that six independent sites recompute
  (`carrick-spec:433`, `:479`; `carrick-engine:366`, `:389`; `carrick-cli/src/lifecycle.rs:486`;
  `carrick-cli/src/serve/resources.rs:968`). Any missed site becomes a user-visible
  `inspect`-vs-guest divergence.
- Its allocation record has **no correct owner under this liveness rule**: `carrick create` claims an
  address and exits, pid-liveness reclaims it, another container takes it, `carrick start` then uses
  a stolen address. Fixing that needs a *second* liveness predicate ("owner container still exists in
  the registry") alongside the pid one — a direct conflict with C10.
- ~600-750 LoC across 5 crates for one channel, vs ~265 for all three.

**Not angle B in its assigned form (per-instance endpoint namespace).** It would delete shipped,
tested features. **Decisive evidence:** `conformance_bridge_compose_pair`
(`crates/carrick-cli/tests/conformance.rs:1562`) runs two separate `carrick run` processes with
`--net bridge --name db` / `--name web` — i.e. **carrick's cross-instance service networking happens
on the *default* bridge today**, not on a user-declared network (`bridge_named_probe_args:412-441`
passes no `--network <name>`). A per-instance directory, or a realm keyed on "user-declared network
only", breaks that test and the `carrick exec` loopback path (`lifecycle.rs:1187-1193`, which sets
`network_namespace_id` and relies on the file being visible from a brand-new process) and the
`--network container:X` sidecar path. F2 keeps every one of those on the *identical* path bytes it
uses today, because they are all **named**.

**Not full angle C.** Its private/public taxonomy is exactly right — and F2 encodes it
*structurally in the path*, which is strictly better than encoding it in record **content**:
content-based policy is a second source of truth that can disagree with the key, and it must be
consulted at six read sites instead of being unforgeable. So C's taxonomy is adopted as F2's
partition rule, and only C's three genuinely additive mechanisms (atomic rename, `key=`,
relay-only instance check) are kept as F3.

**Why F2's partition is the correct semantic line, not a hack:** an unnamed container's
`172.31.0.2` is not an address, it is a placeholder — no DNS record exists for it
(`service_names_for:1167-1180`), no user can name it, and §1.2 proves it can never collide with a
real name-derived address. The set of processes that can *meaningfully* mean it is exactly one
instance and its fork children. A named container's address is name-derived, advertised in DNS, and
intended to be reachable machine-wide. F2 makes the storage location equal the meaning.

---

## 4. Fork-coherence argument

The property that must survive: **a forked guest child must resolve endpoints its parent published,
and the parent's relay thread must resolve endpoints a forked child published after the fork** (C1,
locked in by `publish_tcp_forwards_from_fork_coherent_endpoint_file:2744`, which explicitly asserts
the registry does *not* contain the key).

1. The realm is a pure function of `(namespace_id, guest_ip)`. `guest_ip` is the address both sides
   already key on. `namespace_id` lives in `NetworkNamespaceSpec`, which is **plain memory copied by
   `fork()`**, and `after_fork_child:1575-1616` deliberately does *not* clear `namespaces` /
   `registry` (it clears only fd tracking, relay handles and `owned_endpoint_files:1612`). So a
   child computes the identical realm string as its parent, for every key, with no communication.
2. `namespace_id` is frozen **before any fork**: F1's choke point is in `RuntimeNetwork::create`
   (`network/mod.rs:296`), which runs in the root host process during run setup, before guest boot
   (`execute.rs:288`, `lib.rs:1030`, `lib.rs:1732`). There is no window in which a child could
   derive a *different* id. Crucially it must never be `getpid()`-at-use: a child's pid differs from
   its parent's, which would break C1 immediately. It is `getpid()`-at-**spec-build**, stored.
3. `endpoint_dir` is an `Arc<PathBuf>` captured by the relay threads at `publish_tcp:783`, i.e. the
   realm subdirectory is baked into the same value the parent's relay already uses. Adding a path
   component changes nothing about who can see it: both parent and child `create_dir_all` before
   writing (`:1215`, `:1021`) and both compute the same subpath.
4. `carrick exec` and `--network container:X` are **not** forks — they are new processes — and they
   work today only because they are handed the same `namespace_id` (`lifecycle.rs:1187-1193`). F2's
   private realm is keyed on that same id, so exec's matching condition is *identical to today's*
   for loopback and becomes the *same* condition for the unnamed bridge key. Nothing new can break
   that isn't already broken today.
5. F3's `instance=` id is a process-global `OnceLock` forced in `new()` (pre-fork), so it is inherited
   memory: parent and children compare equal, and the relay's strict check does not reject a child's
   post-fork publication. It must be process-global, not per-provider, or
   `translate_host_source_reads_fork_coherent_endpoint_files:2534` (two providers in one process,
   standing in for a fork child) would fail. Identity (`instance=`, may read) stays separate from
   delete-ownership (`owned_endpoint_files`, may delete) — C8 requires exactly that split.

---

## 5. Race analysis

| race | outcome |
| --- | --- |
| Two instances create the same `inst-<hex ns>/` | Impossible for distinct `namespace_id`s; and `create_dir_all` is idempotent anyway (C13). |
| Reader `read_dir`s the root while another instance creates a realm dir | The two scans (`:323`, `:369`) only match `service-*` prefixes and already `flatten()` over entries; a new subdirectory is skipped, not an error. A realm dir must therefore never be named with a `service-` prefix. |
| Writer renames a record while a reader reads it | `rename` is atomic: the reader sees either the old complete record or the new complete one, never an empty file (F3.1 removes today's `O_TRUNC` window). |
| Reader unlinks a dead-owner record while the owner's successor renames a live one in | Fixed by F3.4 (re-read-and-compare before unlink). |
| Two processes sweep the same realm dir | Idempotent; `remove_dir_all`/`remove_dir` errors ignored, as `:1233`, `:1289` already do (C13). |
| Sweep removes a live instance's realm dir | Cannot: `remove_dir_all` only for `inst-anon-<pid>` with `process_is_alive(pid) == false`; and non-recursive `remove_dir` only succeeds when the dir is empty, after which any writer `create_dir_all`s it back (`:1215`, `:1021`). Predicate unchanged from C10. |
| pid reuse gives false-live | Pre-existing (42 files measured). F2 *reduces* the damage: a false-live record in a foreign private realm is now unreachable, and F3.3 rejects it at the relay. Never worsened. |
| `fork()` racing a file write | Unchanged: every point write/read still holds `fork_gate` (`:1214`, `:1229`, `:1245`, `:1269`). F2 adds no bulk work under the gate; the sweep runs *outside* it (C9). |
| TOCTOU: record accepted, owner exits, host port rebound by another process before `connect_tracked_tcp:1304` | **Not fixed.** Bounded, pre-existing, only closable by passing the listening fd. Recorded as residual. |
| Mixed-version directory during migration | Old flat `bridge-…-172.31.0.2-…` records are simply not found by a new reader (different path) → treated as "no endpoint" → the correct conservative answer, since those records are ambiguous by definition. F3.2's `key=` makes any surviving ambiguity loud. |

---

## 6. Reclamation story

F2 *improves* DEFECT 2 and costs it nothing:

- **Shared realm** (`service-*`, `reverse-*`, named `bridge-*`): unchanged location, unchanged lazy
  per-file pid reclamation (`read_namespace_file:1282-1291`).
- **Private realm**: `inst-anon-<pid>/` is decidable as a unit. A once-per-process `OnceLock` sweep
  — structurally identical to `reclaim_dead_test_endpoint_dirs:1062-1085` — `remove_dir_all`s realm
  dirs whose `anon-<pid>` owner is dead, and non-recursively `remove_dir`s empty ones. This reaches
  the `bridge-`/`listen-` families that the lazy rule **can never** reach today (nothing ever
  `read_dir`s for them: 2,323 + 1,160 = 3,483 of the 24,219 current files are in that unreachable
  class). Cost: one `read_dir` of the root + one `kill(2)` per realm dir, off the fork path, outside
  `fork_gate` (C9), once per process.
- Realm ids that are *not* `anon-<pid>` (only possible if a future caller sets an explicit
  `network_namespace_id` **and** uses an unnamed placeholder address) fall back to per-file
  reclamation plus empty-dir removal. No new liveness predicate is introduced (C10).
- `destroy_namespace:1736`'s non-recursive `fs::remove_dir` of the **shared root** is a latent
  hazard that becomes reachable once reclamation works (it can succeed under a concurrent instance,
  after which the two `read_dir` scans silently return empty → transient DNS/hosts misses). Remove
  that line as part of this work, or as part of DEFECT 2 — but it must not be left standing once
  the directory can become empty.

---

## 7. Deterministic testing

Every test below decides on a **pid** or a **pipe/`waitpid` happens-before edge**. No sleeps, no
retries, no `#[ignore]`, no gating, no widened assertions (C12).

Enabler (test-only, no env override — C14): `SocketNamespaceProvider::with_endpoint_root(&Path)`
under `#[cfg(test)]`, plus a `#[cfg(test)] with_instance_id` seam for F3.3. Today's pid-private test
dir (`:1048-1052`) *masks* cross-instance layouts, so without this seam no unit test can model two
instances at all.

1. **`unnamed_bridge_endpoints_are_private_per_instance`** — one process, one shared root, two
   providers with `namespace_id = anon-A` / `anon-B`, both publishing `172.31.0.2:8080`. Assert the
   two endpoint paths differ, each provider resolves **its own** host addr, and A's
   `destroy_namespace` leaves B's file intact. Pure path/registry assertions.
2. **`published_relay_serves_only_its_own_instance`** — the investigation's harness, made
   deterministic: parent spawns **two real child processes** (a tiny helper bin, or the test binary
   re-executed with a marker env var). Each child binds a target listener that replies with its own
   identity token, publishes a port, then writes one byte to a pipe and blocks on a read. The parent
   `read_exact`es both ready bytes (a happens-after edge — both listeners are bound and both records
   are published), connects to each published host port, and asserts the reply token equals **that
   child's** token; then releases the children and `waitpid`s. **This is the regression test for
   DEFECT 1: it must fail pre-fix** (12/12 in the investigation) **and pass post-fix.** No timing
   assumption anywhere: every ordering edge is a blocking pipe read.
3. **`named_bridge_endpoints_remain_visible_across_instances`** (guards C2/C3/C4 from regression) —
   two providers, distinct `namespace_id`s, both **named** (`db` / `web`). Assert each resolves the
   other's `service-*` records, bridge endpoint and reverse translation. Mirrors `:3402` / `:2534`.
4. **`loopback_endpoints_are_private_after_default_namespace_removal`** — assert no spec reaching the
   provider carries `namespace_id ∈ {None, "default"}` (F1), and that two providers' loopback keys
   differ.
5. **`fork_child_post_fork_publication_reaches_parent_relay`** — real `fork()`; the child publishes
   in the private realm and exits; the parent `waitpid`s (happens-before) and asserts its relay
   target resolves. Plus: `publish_tcp_forwards_from_fork_coherent_endpoint_file:2744` and
   `fork_guard_unlocks_registry_and_child_abandons_parent_publications:3710` must stay green
   **unmodified** — that is the C1/C8 gate.
6. **`private_realm_of_dead_instance_is_reclaimed`** — seed `inst-anon-<pid of a reaped child>/…`
   and `inst-anon-<self>/…`; run the sweep; assert the first is gone and the second survives. Dead is
   decidable after `waitpid`; `pid=0` is the existing fixture precedent (`:2570`).
7. **`endpoint_publication_is_atomic`** (F3.1) — assert no reader can observe a record without a
   `pid=` line: publish over an existing record and assert the observed content is always one of the
   two complete versions (deterministic by construction with `rename`, and the pre-fix `O_TRUNC`
   variant is demonstrable with a seeded partial file).
8. **`relay_refuses_a_foreign_instance_record`** (F3.3) — seed a record with a foreign
   `instance=`; the relay resolves `None`, drops the inbound socket, and the client's `read_to_end`
   returns `0` — a happens-after edge, not a timeout. Then assert the foreign listener was never
   connected via `set_nonblocking(true)` + `accept() == WouldBlock`, which is sound because any
   connection would necessarily have preceded the drop the client already observed.
9. **Existing conformance gate**: `conformance_bridge_compose_pair` (`conformance.rs:1562`) and the
   `-p` published-port probe (`conformance.rs:2763`) must both stay green, unmodified. They are the
   end-to-end proof that C1 and C2-C4 survived.

---

## 8. Rough sizing

| item | production LoC | files |
| --- | --- | --- |
| F1 (spec `None`, choke point, assert) | ~25 | `carrick-spec/src/lib.rs`, `network/mod.rs`, `runtime/src/lib.rs` |
| F2 (`BridgeRealm`, `bridge_realm()`, 2 path builders, 4 construction sites) | ~130 | `network/socket_namespace.rs` |
| F2 reclamation sweep (realm dirs) | ~35 | `network/socket_namespace.rs` |
| F3.1 atomic rename (3 writers) | ~30 | `network/socket_namespace.rs` |
| F3.2 `key=` + reject | ~25 | `network/socket_namespace.rs` |
| F3.3 `instance=` + relay reject + event ring | ~45 | `network/socket_namespace.rs`, `event_ring.rs`, `scripts/carrick_lldb.py` |
| F3.4 guarded stale unlink | ~8 | `network/socket_namespace.rs` |
| **total production** | **~300** | 5 files, 3 crates + 1 script |
| tests (9 above, incl. the two-process harness) | ~320 | `socket_namespace.rs` tests + 1 helper bin |

`carrick-spec` change is 2 lines (the `namespace_id` literal, and an `--ip` validation rejecting
`172.31.0.0/24` to preserve §1.2's disjointness). **No guest-visible IP, bridge id, DNS record or
`inspect` field changes** — a real advantage over angle A, which moves all of them.

---

## 9. What this does NOT fix

1. **Two *unnamed* concurrent containers cannot reach each other by IP.** Docker gives each container
   a distinct address and mutual reachability; carrick gives both `172.31.0.2`, so "reaching each
   other" is undefined today and only appears to work via the cross-wire this spec removes. Closing
   this genuinely requires angle A (IPAM). See ruling R2.
2. **Duplicate `--name` across concurrent instances still aliases** — both are `Shared` with the same
   name-derived IP. F3.3 makes the relay case loud and fast instead of silent; the durable fix is a
   name-uniqueness claim (an `O_EXCL` `name-<hex bridge>-<hex name>` record with stale-owner
   takeover, checked in `create_namespace:1640`, failing with Docker's "name is already in use") or
   IPAM. Recommended as a small follow-up.
3. **Name-hash birthday collisions** — `bridge_ipv4_for_name` has 253×253 = 64,009 buckets
   (`carrick-spec:542`), so two *different* names collide with ~50% probability around 300
   concurrent named containers. Needs IPAM.
4. **DEFECT 2's scan cost.** The per-call full `read_dir` in `service_hosts_entries:314-352` and
   `resolve_service_name:354-393` (10-12 ms warm at 24,219 entries; the latter once **per attached
   bridge**, on the guest `getaddrinfo` datapath via `dispatch/net.rs:2182`) is untouched. F2 only
   makes the never-reclaimable `bridge-`/`listen-` families reclaimable.
5. **TOCTOU between accepting a record and `connect_tracked_tcp:1304`** (§5).
6. **pid-reuse false-live**, and the pid being the *writer's* rather than the socket owner's (a
   grandchild holding an inherited listening fd is already a false-dead hazard). C10 forbids
   "improving" this; unchanged.
7. **Adjacent pre-existing defects found while mapping**, both out of scope but worth filing:
   (a) the VMM/HVF guest-fork child arm (`crates/carrick-runtime/src/runtime.rs:1099-1130`) never
   calls `network_after_fork_child`, unlike the native lanes
   (`crates/carrick-runtime/src/native/fork_child.rs:88`), so it keeps inherited relay fds **and** a
   populated `owned_endpoint_files` — a child that runs `destroy_namespace` deletes the *parent's*
   live records (content matches, since the recorded string carries the parent's pid); it also forks
   (`crates/carrick-aarch64/src/engine.rs:1138`) without taking `fork_gate`, so a child can inherit
   that mutex locked by a vanished relay thread. (b) `register_service_names:306` writes files
   without `fork_gate` while every other mutation holds it.
8. **The 10 ms poll sleeps** in both relays (`:1414`, `:1552`) — the dominant latency term on the
   published-port path, in the same two loops this work touches, but a separate change.

---

## MAINTAINER RULING

**R1 — Primary mechanism.**
*Either* (a) **realm-qualify the ambiguous key**: `Private(namespace_id)` subdirectory for the
`172.31.0.0/24` unnamed placeholder, `Shared` (today's exact path) for every name-derived address,
plus killing the constant `namespace_id` — ~300 LoC, 3 crates, no guest-visible surface change,
closes both proven channels;
*or* (b) **allocate per-container IPs (angle A / IPAM)** — ~600-750 LoC, 5 crates, closes one
channel, leaves loopback aliasing, needs a second liveness predicate for `create`-then-`start`.
**Recommendation: (a).** Sub-question inside (a): realm as a **subdirectory** (recommended — makes
the currently-unreclaimable `bridge-`/`listen-` litter decidable as a unit, per §6) or as a mere
filename prefix (smaller diff, no reclamation win).

**R2 — The one behaviour change.**
*Either* accept that **two concurrent *unnamed* containers become mutually unreachable** at
`172.31.0.2` (they alias today — the "reachability" being removed is the cross-wire itself, and
Docker's equivalent gives distinct addresses, so nothing well-defined is lost);
*or* require mutual reachability to keep working, which **mandates IPAM now** and makes R1(b) the
primary fix with R1(a) layered on top.
**Recommendation: accept the change**, and schedule IPAM separately for its own reasons (`--ip`
conflict enforcement, `inspect` realism, name-collision headroom) rather than as the cross-wiring
fix.

**R3 — How much of angle C to adopt.**
*Either* **F3 as scoped here** (atomic `rename`, `key=` self-check, own-instance check **at the relay
only**, guarded stale unlink — ~110 LoC, each an independent bug fix);
*or* full angle C (per-record `instance=`/`owner=` policy evaluated at all six read sites), which
duplicates F2's partition in record content and creates a second source of truth that can disagree
with the path;
*or* none (F2 alone), which leaves the duplicate-`--name` case silent and leaves the `O_TRUNC`
empty-read window open.
**Recommendation: F3 as scoped.**
