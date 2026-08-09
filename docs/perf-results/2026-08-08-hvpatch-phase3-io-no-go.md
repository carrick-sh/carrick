# HvPatch Phase 3 — mapped-I/O mechanisms rejected by semantics and gate arithmetic

Date: 2026-08-08

Controller: `/Volumes/CaseSensitive/carrick/hybrid.md`, Phase 3

Trace artifact: `1547f0d7`

Normalized records: [`hvpatch-phase3-io-no-go.jsonl`](hvpatch-phase3-io-no-go.jsonl)

## Decision

Phase 3 is complete as a decisive **no-go** for the three proposed mechanisms.
No product code was added.

- Removing every measured `read`, `write`, and `mmap` host dispatch would
  remove at most 12,808 exits from Phase 2's 68,276-exit build, leaving 55,468.
  The `<8K` gate is therefore unreachable even under an impossible 100% hit
  rate.
- The proposed mapped-file `read` does not preserve Linux's fd-offset,
  short-read, EOF, `EAGAIN`, pipe/socket, truncation, dup/fork, or fault
  contracts without a coherent guest-visible fd implementation.
- A deferred write ring cannot report the exact synchronous result of the
  current `write(2)` before the guest continues. Optimistic success loses
  short-write, `EAGAIN`, `EPIPE`, signal, and blocking semantics; waiting for a
  host consumer restores the synchronization/exit the ring claims to remove.
- The anonymous-mmap proposal imports a native-DSR zero-fill diagnosis into the
  HVF lane. HvPatch's measured population is 1,785 anonymous mmap syscalls, not
  553K VM exits; fresh anonymous maps already use lazily zeroed backing.

The narrow reusable result is the committed I/O-shape census. It gives future
work a measured eligibility denominator, but it does not justify an EL0 I/O
shortcut.

## Provenance and method

The signed binary and digest-pinned image are the Phase 2 artifacts:

- Carrick source: `7063ffecca692567dbe0d0901f4f43b36f53155f` plus diagnostic-only
  commits.
- Binary SHA-256:
  `a4eb901aade91c4501270dba996a99f643bd54899437c6b6ec4d2b494add65ff`.
- Image:
  `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`.
- Workload: the canonical one-file cold Go build with a fresh dedicated
  `GOCACHE`, followed by executing the result and requiring `BUILD_OK`.

The committed
[`hvpatch-phase3-io-shapes.d`](../../scripts/dtrace/hvpatch-phase3-io-shapes.d)
uses qualified `syscall-entry`/`syscall-return` USDT arguments, follows the
fork/exec tree, and ended naturally (`bounded=0`). Its raw capture SHA-256 is
`95e4e9524cd02932db6754d1ba5fd4daf50f236577c017ff07f011b4c4930a17`.
The copyin/aggregation perturbs, so timings are excluded.

## Measured I/O shapes

| Syscall | Calls |
|---|---:|
| `read` | 6,097 |
| `write` | 4,782 |
| `mmap` | 1,926 |
| **Total proposed population** | **12,805** |

Read results were not a single immutable-file shape:

| Result | Calls |
|---|---:|
| Positive byte count | 4,898 |
| EOF / zero | 1,138 |
| `EAGAIN` | 61 |

The reads span many guest fds; fd 6 accounts for 3,331, fds 7 and 8 for 719
and 741, and at least eleven other descriptors are live. Request sizes span
105 calls at <=64 bytes, 3,730 at 65..4096, and 2,262 above 4096 through 64 KiB.
A map-copy fast path would first need an authoritative per-description kind,
offset, alias, and mutation protocol; a per-fd pointer/length table is
insufficient because dup shares an open-file description and offset.

Writes likewise span multiple fds and sizes: fd 6 has 4,175 calls, fd 7 has
459, and the remainder touch stdout/stderr and nine other fds. There are 4,750
positive results and 32 zero-length successes. Although this run did not hit a
write error, Linux-visible errors and short writes remain required behavior,
and the existing dispatcher has explicit EAGAIN/EPIPE/partial-write handling.

Mmap shape:

| Kind | Calls |
|---|---:|
| Anonymous (`MAP_ANONYMOUS`, fd -1) | 1,785 |
| File-backed | 141 |

Lengths span 364 <=4 KiB, 264 through 64 KiB, 625 through 1 MiB, and 673 above
1 MiB. Results include 1,644 positive addresses and 282 zero-address results.
The existing memory path already relies on lazy-zero backing for fresh private
anonymous maps and separately preserves fixed placement, reuse-zeroing,
protection, unmap, and file-beyond-EOF behavior.

## Gate arithmetic

Using the naturally completed Phase 2 census:

```text
68,276 total
-6,096 read
-4,784 write
-1,928 mmap
=55,468 remaining
```

That remainder exceeds Phase 3's `<8K` target by **47,468**. It also makes the
controller's description “only openat, close, exec, fork, wait, epoll” false:
`fcntl` (12,062), `rt_sigaction` (11,115), `nanosleep` (6,818), `futex`
(3,967), and `newfstatat` (3,960) remain before counting the stated families.

The CPU target is not claimed. Phase 2's first exact-code untraced result was
4.55 CPU-s, 0.05 above Phase 3's `<4.5` threshold, and there is no accepted
Phase 3 mechanism whose controlled comparison would make another run a useful
decision.

## Verification and next boundary

- The focused cold build completed and printed `ok` and `BUILD_OK`.
- The capture ended naturally with nonzero events and internally reconciled
  entry/return populations for the selected calls.
- The product tree remains the clean `just ci`-passed Phase 2 tree; this phase
  adds only a durable DTrace question/receipt surface.

Phase 4 begins by testing its own load-bearing premise: the controller converts
68 cumulative forks into an assumed 68 simultaneous VMs and therefore mandates
a single-host-process rewrite. The next probe must measure **peak concurrent**
Carrick guest processes/VMs on the cold build before accepting that premise.

