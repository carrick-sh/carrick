# SCTP: 42 skipped tests now run, 21 of them pass

`cpython-socket` was the largest single genuine gap — 42 diverging rows, every
one of them `('skipped','ok')`, every one SCTP.

## The refusal was CARRICK'S, not Darwin's

The first reading of this gap (recorded in `GENUINE-GAPS.md`) said carrick passes
`IPPROTO_SCTP` through and macOS returns `EPROTONOSUPPORT`. That is WRONG.
`canonical_socket_errno` rejects any `SOCK_STREAM` protocol other than 0 or TCP
before the host ever sees the call:

    LINUX_SOCK_STREAM => if protocol != 0 && protocol != LINUX_SOL_TCP { EPROTONOSUPPORT }

Linux accepts `AF_INET/SOCK_STREAM/IPPROTO_SCTP`, so carrick's own validation was
the divergence. Worth stating because it makes the fix an order of magnitude
smaller than "implement SCTP".

## What shipped

`IPPROTO_SCTP` on `SOCK_STREAM` is accepted and backed by a plain TCP socket —
the same substitution `IPPROTO_UDPLITE` already gets over UDP, and the same shape
as backing a guest AF_UNIX `SOCK_SEQPACKET` with a host `SOCK_STREAM`. The guest
protocol is recorded unchanged, so `SO_PROTOCOL` still reports SCTP.

`SOCK_SEQPACKET` is deliberately NOT included: it is message-oriented and
multi-streamed, and TCP cannot reconstruct its boundaries. It stays
`EPROTONOSUPPORT` rather than pretending. (Docker creates one; that remains an
open gap, and no failing test needs it.)

Result on `test_socket`:

| | carrick before | carrick after | docker |
|---|---:|---:|---:|
| comparable tests | 615 | **657** | 657 |
| skipped | 117 | **75** | 75 |
| failures | 0 | 21 | 0 |

The population now matches the oracle exactly, and diverging rows drop 42 -> 21.

## The 21 that remain — one cause, and the rule measured

Every one of the 21 fails the same assertion:

    AssertionError: <MsgFlag: 0> != <MsgFlag.MSG_EOR: 128>

`SendrecvmsgSCTPFlagsBase` sets `msg_flags_eor_indicator = MSG_EOR`. Rather than
infer when Linux sets it, `reducers/sctp-eor.py` measured it on the oracle:

| case | returned | msg_flags | EOR |
|---|---:|---|---|
| buf 1024, msg 64 | 64 | 0x80 | yes |
| buf 16, msg 64 | 16 | 0x00 | no |
| buf 64, msg 64 | 64 | 0x80 | yes |
| MSG_PEEK buf 1024 | 64 | 0x80 | yes |
| MSG_PEEK buf 16 | 16 | 0x00 | no |

**`MSG_EOR` marks consuming the END of a message** — real boundaries, which a TCP
backing does not carry.

## Two ways to finish it, and why the cheap one is not acceptable

1. **Bytes-available proxy** — set EOR when `returned == available before the
   read`. Matches all five probes above and would likely pass all 21 tests. It is
   still WRONG: with two messages queued, a read that ends exactly at the first
   boundary sees more data available and would report no EOR, where Linux reports
   one. That is an approximation standing in for a real implementation, which the
   engineering standards rule out — it would pass the gate while being wrong.

2. **Real boundaries, out-of-band.** Every SCTP peer is necessarily another
   carrick socket (macOS has no SCTP stack, so no external peer can exist), and
   under HVPatch both endpoints usually live in ONE carrier. Carrick can record
   message boundaries in a per-connection structure the receiver consults — true
   semantics with no wire-format change, following the AF_UNIX path-hash registry
   precedent. Framing the payload instead would also work but changes the bytes on
   the wire and makes partial nonblocking sends much harder to keep atomic.

Option 2 is the one to build. It is a data-path change scoped strictly to sockets
whose guest protocol is SCTP, so the blast radius is contained.
