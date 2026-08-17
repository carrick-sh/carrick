# Phase report — closing `node-libuv` against the repaired oracle

**Date:** 2026-08-17
**Lane:** canonical macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest
**Predecessor:** `README.md` in this directory (step 1, the oracle repair)

Step 1 made the `node-libuv` docker row real (507 positions: 499 pass, 0 fail,
8 skip). This phase measured Carrick against it and closed TEN divergences, taking libuv from 12 divergent positions to 2.

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
| 456 | `tty_pty_partial` | fail (exactly 1024 lost) | 4/4 pass | Darwin destroys queued pty data at slave close |
| 483 | `udp_recvmsg_unreachable_error` | fail | 3/3 pass | no `IP_RECVERR`, no error queue |
| 484 | `udp_recvmsg_unreachable_error6` | fail | 3/3 pass | same |

`eintr_handling` is the one worth reading twice. It looked exactly like a
missing entry in the `SA_RESTART` restartable syscall set — that set really was
wrong (only `waitid`/`wait4`) and really was fixed — but expanding it moved the
failure rate not at all. The new `signal__restart__decision` probe showed why:
in a failing run the ONLY SIGUSR1 decision was on the thread that called
`kill(2)`, at its own syscall boundary. The blocked reader that returned
`-EINTR` had received no signal at all. SA_RESTART could never have repaired
that, because the restart path works by rewinding the PC behind a handler frame
and there was no frame. An ABSENT trace line was the evidence.

## Remaining divergences (2)

Measured on binary `ba4c0603…c564714d3`: **500 ok / 6 skip / 1 fail** against
the oracle's 499 ok / 8 skip. libuv is down from 12 divergent positions to 2,
and BOTH are the same cause.

| # | row | |
|---|---|---|
| 370 | `tcp_connect6_link_local` | INVERSION: Docker skips, Carrick runs |
| 472 | `udp_multicast_join6` | Docker skips, Carrick fails |

**`carrick run` defaults to `--network host` while `docker run` defaults to
bridge**, so the two engines are compared with different network namespaces.
The oracle container has only `::1/128` on `lo` (verified inside the image);
Carrick in host mode truthfully surfaces the Mac's `en0`, which has a
link-local. libuv's skip conditions scan enumerated interfaces for `fe80::`, so
Carrick runs what Linux declines. Neither row is a bug in the feature it names.

The bridge model has been corrected to match the oracle netns (uplinks
IPv4-only, `lo` keeps `::1`), so the fix is to compare like with like — give
the suite `--network bridge`, which changes only `carrick_flags` and therefore
does NOT invalidate the oracle key. That is blocked on the next section.

## Blocker: carrick's bridge networking breaks glibc's `getaddrinfo`

```
carrick run --network bridge ... python3 -c \
  'import socket; socket.getaddrinfo("localhost", 80)'

Fatal glibc error: getaddrinfo.c:1673 (rfc3484_sort): assertion failed:
  a1->source_addr.sin6_family == PF_INET6
```

Host mode resolves the same name fine. This is what actually kills the libuv
workload under `--network bridge` (earlier it surfaced as a fork-time ObjC
abort, `+[NSNumber initialize] … Crashing instead`, which is the same
resolution path reached from a different phase).

Ruled OUT by measurement, so the next session does not repeat it:

- `getsockname` after `connect` on an `AF_INET6` UDP socket returns the right
  family in BOTH modes, for `::1` and for a v4-mapped `::ffff:127.0.0.1`, and
  matches the Docker oracle byte-for-byte. The source-address path is not it.
- `/proc/net/if_inet6` in bridge mode now correctly holds only `::1` on `lo`,
  matching the oracle exactly.

Also RULED OUT: the synthetic netlink `RTM_GETADDR` reply. It really did
differ from Linux (no `IFA_F_PERMANENT`, no `IFA_CACHEINFO`/`IFA_FLAGS`,
spurious `IFA_LOCAL`/`IFA_LABEL` on IPv6, `fe80::` scoped UNIVERSE instead of
LINK) and has been corrected to match the oracle's shape exactly — the crash
still reproduces, so that was not the cause either.

And it is PRE-EXISTING: it reproduces on the network model from before this
campaign touched it, so dropping the fabricated uplink link-local did not
introduce it.

What still correlates is the one remaining difference: bridge mode has NO
non-loopback IPv6 address while host mode does. Docker's netns is in the same
position (only `::1` on `lo`) and does NOT crash, so something else about how
Carrick answers glibc's per-candidate source-address probe must differ. The
next step is to observe the exact syscall sequence glibc makes in each mode —
`carrick trace` on the Carrick side, bpftrace inside Docker for the Linux
ground truth — rather than more black-box differential probing, which has now
eliminated every cheap hypothesis.

This is a crash in a shipped network mode, so it outranks the two rows it
blocks.

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
| pty: slave closes with data still queued | **Darwin DISCARDS it.** Write 1024 bytes to a slave, do not read the master, `close` the slave — the master then reads `0` (EOF) and the bytes are gone. Linux delivers them and only then reports EOF. |
| pty: `FIONREAD` on a master with queued data | reports **0**, so it cannot be used to size a rescue read. |
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
