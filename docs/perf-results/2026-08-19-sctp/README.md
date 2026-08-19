# SCTP: `cpython-socket` closed — 42 diverging rows to ZERO

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

Option 2 is the one built.

## Real boundaries, tracked out of band

`dispatch/net/sctp.rs` keeps, per connection, the lengths of the messages the
sender has written and how far the receiver has consumed into the first one. The
connection is keyed by its address PAIR, which the two ends see reversed, so a
sender's `(local, peer)` is the receiver's `(peer, local)`.

Two properties fall out, and both are things the drained-buffer shortcut gets
wrong:

- a `recvmsg` is capped at the current message's remainder, so it can never
  merge two messages the way its TCP backing would;
- `MSG_EOR` is reported when a read consumes that remainder — including under
  `MSG_PEEK`, which reports the same answer without consuming.

The data path stays byte-identical to TCP: nothing is framed onto the wire, so a
partial non-blocking send needs no special atomicity. A short write EXTENDS the
message in flight rather than ending it, which is SCTP's rule — the boundary is
where the sender finished. Boundaries are dropped at close while the fd is still
open, so a recycled address pair cannot inherit a dead connection's state.

Hooking `sendmsg` alone recorded NOTHING: CPython's `socket.send()` lowers to
`sendto`, so both paths carry the hook.

## Result

carrick reproduces the oracle's EOR table exactly, all five rows, and

    test_socket: run=732 skipped=75  Result: SUCCESS   (two consecutive runs)

against the oracle's 657 comparable + 75 skipped. **42 diverging rows -> 0**, with
zero failures and the skip count identical to Linux. `just ci` green (3,913
tests).

`SOCK_SEQPACKET` SCTP remains EPROTONOSUPPORT and is still an open gap: it is
multi-streamed as well as message-oriented, and this design carries boundaries
but not stream ids. No currently-failing row needs it.


---

# CORRECTION — the first closure claim was premature

`d41139cb6` reported `cpython-socket` closed, "verified on two consecutive runs".
Those two runs were LUCK. Re-measured, that same binary fails **8-13 SCTP rows,
varying run to run** — all `MsgFlag: 0 != MSG_EOR: 128`. Two samples was not
enough evidence for a suite whose implementation had a race in it, and the
single-threaded reducer passed every time while the threaded CPython tests did
not, which should have been the warning.

Attribution was done properly the second time: checking out that commit's own
`net.rs`/`sctp.rs` and rebuilding reproduced 8/9/11, proving the later work had
not caused it.

## The actual defect

`forget()` dropped BOTH directions of a connection when either socket closed.
Closing the SENDER does not discard bytes already queued — Linux still delivers
them, and the receiver still needs their boundaries. CPython's SCTP tests send
from a separate thread and close, so the receiver kept finding `NO STREAM` and
reporting no `MSG_EOR`. A gated `CARRICK_SCTP_DEBUG` trace showed it directly:
the publish key and the lookup key were byte-identical, and the entry was simply
gone.

    SCTPDBG begin_send   fd=164 len=28 key=(1002d20c7f...,1002d20b7f...)
    SCTPDBG complete_read fd=166 lookup=(1002d20c7f...,1002d20b7f...)
    SCTPDBG complete_read fd=166 got=28 NO STREAM

Two wrong theories were tested and discarded first — that publication happened
after the send (moved it before; no change), and that the keys disagreed (they
were identical). The trace ended the guessing.

`forget()` now drops the RECEIVE direction unconditionally (nobody will read it)
and the SEND direction only once drained. The leftover is not a leak: the peer's
own close removes it, since one socket's send direction is the other's receive
direction.

## Result

    test_socket: run=732 skipped=75 Result: SUCCESS   x6 consecutive runs

Six samples this time, not two. The EOR table still matches the oracle exactly,
and `just ci` is green (3,913 tests).
