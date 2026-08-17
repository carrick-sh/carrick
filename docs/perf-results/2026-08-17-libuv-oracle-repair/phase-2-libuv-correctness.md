# Phase report — closing `node-libuv` against the repaired oracle

**Date:** 2026-08-17
**Lane:** canonical macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest
**Predecessor:** `README.md` in this directory (step 1, the oracle repair)

Step 1 made the `node-libuv` docker row real (507 positions: 499 pass, 0 fail,
8 skip). This phase measured Carrick against it and closed six divergences.

## Method

Carrick was invoked exactly as the harness invokes it, taken from
`--dry-run` on the suite, and diffed position-by-position against the committed
oracle TAP:

```
target/release/carrick run --name <run-id> --max-traps <u64::MAX> --raw --fs host \
  --entrypoint /usr/local/bin/nodejs-conformance \
  -e NODEJS_CONFORMANCE_IN_IMAGE=1 -e NODEJS_CONFORMANCE_EFFECTIVE_RUNNER=carrick \
  localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 \
  --runner docker --suite libuv --line 24 --timeout 180
```

Every run was stamped with `CARRICK_RUN_ID`, serialized against Docker (no
container ran while Carrick did), and left no processes behind. All 507
positions were emitted on every run — no timeouts, no truncation.

## Divergences closed

| # | row | was | now | commit |
|---|---|---|---|---|
| 1 | `platform_output` | fail | pass | `/proc/uptime` served `0.00` on first read |
| 269 | `pipe_set_chmod` | skip | pass | `bind(2)` did not stamp the socket's owner |
| 418 | `thread_priority` | fail | pass | `nice` was a runtime-global static |
| 470 | `udp_multicast_interface6` | fail | pass | Darwin rejects `IPV6_MULTICAST_IF` index 0 |
| 471 | `udp_multicast_join` | skip | pass | blanket `ENODEV` on group membership |

Each was proven RED first against the unfixed binary and GREEN after, either by
a unit/integration test with the fix removed, or — for `thread_priority` — by a
full signed-binary A/B:

- pre-fix binary `17e5f05f…f44b5cd5` → `not ok 418 - thread_priority`
- post-fix binary `091d0c46…40f9d035` → `ok 418`

`thread_priority` is worth calling out because a single-test reducer **cannot**
reproduce it: libuv forks a fresh process per test, and the leak comes from
`process_priority` (position 281) setting nice 19 and exiting, 137 positions
earlier. The reducer has to be the whole suite.

## What the fixes had in common

Four of the five were not missing features. They were **wrong models**:

- a per-process attribute kept in a process-global `static`, correct only while
  one Linux process exists (`nice`, and its untouched twin `ioprio`);
- a second clock for `/proc/uptime` that disagreed with `CLOCK_BOOTTIME`;
- a fabricated `fe80::1` on bridge uplinks, justified by a claim about Docker
  that the oracle container disproves;
- a blanket `ENODEV` on multicast membership, justified as "the honest outcome
  for an unsupported feature" — while Darwin supports it, measured here:
  join 239.255.0.1 / send / receive / drop all return 0.

Each carried a doc comment arguing it was correct. The comments were written
under assumptions that had since stopped holding, which is exactly the
`docs/identity-and-scope-domains.md` failure mode.

## Remaining divergences (7) and their state

Measured on binary `6271fcb7…1628060905`.

### Real Carrick gaps

| # | row | root cause | evidence |
|---|---|---|---|
| 395 | `tcp_reuseport` | two listeners bind `127.0.0.1:9123` with `SO_REUSEPORT`; the test needs BOTH to accept ≥1 of 10 connections (`ASSERT_GT(thread_loopN_accepted, 0)`). Not yet distinguished: Darwin not load-balancing vs a Carrick epoll/accept dispatch defect. | not started |
| 488 | `udp_reuseport` | same shape, 10 datagrams across 2 receivers | not started |
| 483 | `udp_recvmsg_unreachable_error` | needs `IP_RECVERR` (absent from the SOL_IP option gate), so `uv_udp_bind` fails before any recvmsg. Then needs the ICMP error delivered as (a) `ECONNREFUSED` on the next recvmsg, (b) a `MSG_ERRQUEUE` entry with a `SOL_IP`/`IP_RECVERR` cmsg carrying `sock_extended_err` + `SO_EE_OFFENDER`, (c) `EPOLLERR` on the fd, (d) `EAGAIN` on the second errqueue read. Exactly 3 `recv_cb` calls. | `MSG_ERRQUEUE` is currently hard-coded to a no-error-queue stub |
| 484 | `udp_recvmsg_unreachable_error6` | same, `IPV6_RECVERR` | " |
| 456 | `tty_pty_partial` | 8×8192 bytes written to a pty slave must read back as exactly 65536 on the master, ten times. NOT upstream flakiness: the "not 100% deterministic" comment says a BUGGY implementation fails ~1 in 3, which is why it loops 10× — the assertion itself is exact with no tolerance. | not started |

### Harness-level netns asymmetry

| # | row | state |
|---|---|---|
| 370 | `tcp_connect6_link_local` | INVERSION: Docker skips, Carrick runs |
| 472 | `udp_multicast_join6` | Docker skips, Carrick now fails |

Both come from one cause: **`carrick run` defaults to `--network host` while
`docker run` defaults to bridge**, so the two engines are compared with
different network namespaces. The oracle container has only `::1/128` on `lo`;
Carrick in host mode surfaces the Mac's `en0`, which has a link-local. libuv's
skip conditions scan enumerated interfaces for `fe80::`, so Carrick runs what
Linux declines.

The bridge model itself has been corrected to match the oracle netns. Aligning
the suite is blocked on a separate bug found while testing it:

> **`--network bridge` aborts the libuv workload.** Exit 134, zero stdout:
> `objc[…]: +[NSNumber initialize] may have been in progress in another thread
> when fork() was called. … Crashing instead.` A trivial
> `--network bridge … sh -c 'echo hello'` succeeds, so it is workload-specific.
> This is the known fork-unsafe CoreFoundation/ObjC class; the likely entry
> point is `getaddrinfo` via `to_socket_addrs` in `network/dns.rs`
> (`scutil` is a `posix_spawn` subprocess and is not the culprit). Not yet
> root-caused.

### Stability — two rows are NOT deterministic

Four consecutive runs of the same signed binary:

| # | row | run 1 | run 2 | run 3 | run 4 |
|---|---|---|---|---|---|
| 29 | `eintr_handling` | ok | ok | **fail** | ok |
| 399 | `tcp_try_write_error` | ok | ok | **fail** | **fail** |

These were invisible while the oracle was absent. They are correctness
blockers in their own right: the goal admits no flakiness and no
retry-recovered acceptance, so a clean final pass is impossible until they are
deterministic. Neither has been root-caused, and neither may be dismissed as
load — that has to be measured, not assumed.

## Ledger impact beyond libuv

The repaired oracle turns 507 previously-`docker = absent` rows into real
comparisons, so the closure ledger's "unexercised" count should drop by ~507
for this suite alone once a full closure run is taken. No such run has been
made since the repair; the counts in `docs/conformance-closure-ledger.md` and
the handoff's "current counts" still describe the pre-repair state.

## Measured Darwin facts (keep these — each cost an experiment)

Every one of these was established with a small host-only C program, no guest
involved. They are the difference between "Carrick is slow/wrong somewhere" and
a known host capability gap with a known bridge.

| question | answer |
|---|---|
| `IPV6_MULTICAST_IF` with ifindex 0 (Linux's "clear") | `EINVAL`. And there is NO way to clear it once set: 0 as `u32`, 0 as `int`, and a zero-length optval all `EINVAL`, readback keeps the old index. |
| IPv4 multicast join on `239.255.0.1`, `imr_interface = INADDR_ANY` | Fully supported: join / send / receive-own-datagram / drop all return 0. The blanket `ENODEV` was an excuse, not a limitation. |
| `struct ip_mreq_source` field order | Darwin `{ multiaddr, sourceaddr, interface }` vs Linux `{ multiaddr, interface, sourceaddr }`; option numbers 70..73 vs 37..40. |
| `SO_REUSEPORT` distribution, 2 sockets / 10 connections | TCP `listener0=0 listener1=10`; UDP `receiver0=0 receiver1=10`. Darwin never distributes — the last binder takes everything. |
| write to a TCP socket whose peer closed | `ECONNRESET` after ~27 four-byte writes. Darwin does the right thing here, so `tcp_try_write_error`'s EAGAIN is Carrick's, not the host's. |
| ICMP port-unreachable on an UNCONNECTED UDP socket | Not reported at all: `SO_ERROR` stays 0, `poll` shows nothing, `recv` gives `EAGAIN`. |
| ICMP port-unreachable on a CONNECTED UDP socket | `recv` returns `ECONNREFUSED`. |
| **shadow-socket bridge for the above** | **Works.** A second socket bound to the SAME local `addr:port` with `SO_REUSEADDR|SO_REUSEPORT` and `connect`ed to the destination receives the `ECONNREFUSED`, while the original unconnected socket still receives from third parties normally and the shadow does not steal them. |

That last row is the whole feasibility question for `IP_RECVERR`: Linux reports
ICMP errors on an unconnected UDP socket *because* `IP_RECVERR` asks it to, and
Darwin will not — but a same-address connected shadow can be made to, without
changing the packets on the wire or what the real socket receives.

## Provenance

Signed artifacts used, in order:

| binary sha256 | contents |
|---|---|
| `17e5f05f53c184c4a9cb2ba73c5c04d7911ff8ba64df4b2766bfb2a5f44b5cd5` | pre-fix (statics restored) — red reference |
| `091d0c4667b3c4cf18b4d060167b5be425a984cf63e76d6f5d44db9440f9d035` | nice/ioprio fix |
| `f2e3daf2853d198997cbc263fe80da6337af401baf5ff57c24116c1628060905` | + uptime, + `IPV6_MULTICAST_IF` |
| `6271fcb787224245d310b76cf1e46f50870d3a18be2a1acd6388c19b6d4846b6` | + owner stamp, + multicast membership, + netmodel |

Every guest-running binary came from `just build` (codesigned, hypervisor
entitlement present, `__TEXT,__dof_carrick` present). The frozen scope's
`binary_sha256` is stale by construction and must be re-frozen before the next
authoritative closure run.
