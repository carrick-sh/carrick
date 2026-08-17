# Phase report — closing `node-libuv` against the repaired oracle

**Date:** 2026-08-17
**Lane:** canonical macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest
**Predecessor:** `README.md` in this directory (step 1, the oracle repair)

Step 1 made the `node-libuv` docker row real (507 positions: 499 pass, 0 fail,
8 skip). This phase measured Carrick against it and closed EIGHT divergences, taking libuv from 12 divergent positions to 5.

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

## Divergences closed (continued)

| # | row | was | now | root cause |
|---|---|---|---|---|
| 29 | `eintr_handling` | FLAKY (8/15 fail) | 20/20 pass | EINTR surfaced for a signal delivered to another thread |
| 395 | `tcp_reuseport` | fail | pass | Darwin never distributes `SO_REUSEPORT` |
| 488 | `udp_reuseport` | fail | pass | same |

`eintr_handling` is the one worth reading twice. It looked exactly like a
missing entry in the `SA_RESTART` restartable syscall set — that set really was
wrong (only `waitid`/`wait4`) and really was fixed — but expanding it moved the
failure rate not at all. The new `signal__restart__decision` probe showed why:
in a failing run the ONLY SIGUSR1 decision was on the thread that called
`kill(2)`, at its own syscall boundary. The blocked reader that returned
`-EINTR` had received no signal at all. SA_RESTART could never have repaired
that, because the restart path works by rewinding the PC behind a handler frame
and there was no frame. An ABSENT trace line was the evidence.

## Remaining divergences (5) and their state

Measured on binary `a1ee8ef2…01a7032f7`.

### Real Carrick gaps

| # | row | state |
|---|---|---|
| 456 | `tty_pty_partial` | **Deterministic**, and reduced: 64512 of 65536 bytes arrive, i.e. **exactly 1024 lost**, on every run. A host-only C reducer doing the same 8×8192 slave writes and master reads loses NOTHING, so the loss is Carrick's, not the pty's. A round 1024 points at a fixed-size buffer or a drop of the final partial chunk on the slave-close/EOF edge. Not yet localised in `pty_relay.rs` / the pty read path. |
| 483 | `udp_recvmsg_unreachable_error` | Needs `IP_RECVERR` accepted (absent from the SOL_IP gate, so `uv_udp_bind` fails before any recvmsg), then a real `MSG_ERRQUEUE`. **Feasibility is now settled — see the shadow-socket row in the Darwin facts table.** Design below. |
| 484 | `udp_recvmsg_unreachable_error6` | same, `IPV6_RECVERR` |

#### Settled design for the UDP error queue

Darwin reports an ICMP port-unreachable only on a CONNECTED UDP socket; Linux
reports it on an unconnected one precisely because `IP_RECVERR` asked. Measured
bridge: a shadow socket bound to the SAME local `addr:port` with
`SO_REUSEADDR|SO_REUSEPORT` and `connect`ed to the destination receives the
`ECONNREFUSED`, while the real unconnected socket still receives from third
parties and the shadow does not steal them.

So: accept `IP_RECVERR`/`IPV6_RECVERR` and record the flag; when such a socket
sends, route the send through a shadow connected to that destination (same
packet on the wire, same source `addr:port`); drain the shadow's error and push
an error-queue entry; serve `MSG_ERRQUEUE` `recvmsg` from that queue with a
`SOL_IP`/`IP_RECVERR` cmsg carrying `sock_extended_err` + `SO_EE_OFFENDER`, set
`MSG_ERRQUEUE` in the returned `msg_flags`, report `EPOLLERR` while the queue is
non-empty, and answer `EAGAIN` once drained. The test wants exactly three
`recv_cb` calls: `ECONNREFUSED` on the plain read, the errqueue entry, then
`EAGAIN`.

### Harness-level netns asymmetry (unchanged)

| # | row | state |
|---|---|---|
| 370 | `tcp_connect6_link_local` | INVERSION: Docker skips, Carrick runs |
| 472 | `udp_multicast_join6` | Docker skips, Carrick fails |

One cause: **`carrick run` defaults to `--network host` while `docker run`
defaults to bridge**, so the two engines are compared with different network
namespaces. The oracle container has only `::1/128` on `lo` (verified inside the
image); Carrick in host mode surfaces the Mac's `en0`, which has a link-local,
and libuv's skip conditions scan enumerated interfaces for `fe80::`.

The bridge model has been corrected to match the oracle netns, but the suite
cannot be switched to bridge yet:

> **`--network bridge` aborts the libuv workload.** Exit 134, zero stdout:
> `objc[…]: +[NSNumber initialize] may have been in progress in another thread
> when fork() was called. … Crashing instead.` A trivial
> `--network bridge … sh -c 'echo hello'` succeeds, so it is workload-specific,
> not setup. Known fork-unsafe CoreFoundation/ObjC class; likely entry point is
> `getaddrinfo` via `to_socket_addrs` in `network/dns.rs` (`scutil` in
> `vfs/resolvconf.rs` is a `posix_spawn` subprocess and is NOT the culprit).
> Not root-caused. It is a crash, so it outranks a wrong answer.

### Stability

`eintr_handling` is fixed (20/20). `tcp_try_write_error` remains
non-deterministic: **8 of 20 isolated runs fail**, and it is a genuine
Heisenbug — under `carrick trace` it passed 6 of 6, which at a 60% base pass
rate is ~4.7% likely by chance, so tracing really does perturb it away. The
recommended instrument is therefore the always-on event ring via `carrick-lldb`,
not a tracer.

What IS known: it fails with `uv_try_write` returning `-11` (EAGAIN) where the
test requires `UV_EPIPE`/`UV_ECONNABORTED`/`UV_ECONNRESET` after the peer
closes. A host-only reducer shows Darwin returns `ECONNRESET` after ~27
four-byte writes, and `blocking_io` genuinely calls the host write, so the
EAGAIN is real — meaning the peer's host socket was still open when the writes
ran. That points at the guest's `close` of the accepted fd not having reached a
host `close` yet (a lingering `HostFdRef`, or ordering between `uv_close`'s
callback and the actual descriptor teardown). Unproven.

## Ledger impact beyond libuv
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
