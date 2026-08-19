# The real remaining gaps, once load noise is removed

Taken from the `current` arm of the controlled A/B (24 heavy suites, 8 workers),
which is quiet enough that timeout-induced rows do not swamp real ones. The
closure runs' 1,100-1,400 diverging rows are dominated by suites truncating on
their budget; this is what is actually WRONG.

## Wrong answers — 5 suites, 50 rows

| suite | rows | shape |
|---|---:|---|
| `cpython-socket` | 42 | every row is SCTP (see below) |
| `go-syscall` | 3 | `TestFchmodat`, `TestPrlimitFileLimit`, `TestSCMCredentials` |
| `cpython-multiprocessing_fork` | 3 | `WithManagerTestLock` (`test_lock_context`, `test_rlock`) |
| `cpython-tarfile` | 1 | `TestExtractionFilters.test_parent_symlink` |
| `node-libuv` | 1 | suite-level |

## `cpython-socket` — 42 rows, ONE cause: no SCTP

Pair states are unambiguous: `('skipped','ok') x42`, plus
`('ok','ok') x615` and `('skipped','skipped') x75`. Carrick reports 615 passed /
117 skipped against Docker's 657 / 75 — exactly 42 tests that Linux RUNS and
carrick SKIPS.

Attributed to a syscall answer, not inferred (`sctp-probe.py`, run on both sides):

    carrick:  AF_INET/SOCK_STREAM/IPPROTO_SCTP    errno=93 (EPROTONOSUPPORT)
              AF_INET/SOCK_SEQPACKET/IPPROTO_SCTP errno=93 (EPROTONOSUPPORT)
    docker:   AF_INET/SOCK_STREAM/IPPROTO_SCTP    OK fd=3
              AF_INET/SOCK_SEQPACKET/IPPROTO_SCTP OK fd=3

CPython's `test_socket` gates the SCTP mixins on being able to create the socket,
so `EPROTONOSUPPORT` turns 42 tests into skips. Docker Desktop's LinuxKit kernel
ships SCTP; **Darwin has no kernel SCTP at all**, so there is no host primitive to
lower onto — unlike almost every other gap in this campaign.

The scope is smaller than "implement SCTP" sounds, and that should be established
before anyone starts: the failing tests are the generic `sendmsg`/`recvmsg`
mixins parameterised over an SCTP socket (`RecvmsgSCTPStreamTest`,
`RecvmsgIntoSCTPStreamTest`, `SendmsgSCTPStreamTest`), and both endpoints are
inside the same guest talking over loopback. What they exercise is message
boundaries (`MSG_EOR`), ancillary data and `msg_flags` — not congestion control,
multihoming, or the wire format. A loopback-only association between two
carrick-managed endpoints would close all 42, and never has to interoperate with
a real SCTP peer.

That is still a transport implementation and the largest single item left. It is
also the only gap here whose answer is "build a protocol", so it should be
scheduled deliberately rather than picked up mid-cluster.

## Timeouts — perf, not wrong answers

| suite | ms |
|---|---:|
| `cpython-multiprocessing_forkserver` | 600,408 |
| `cpython-importlib` | 300,402 |
| `ltp-inotify09` | 40,323 |
| `ltp-shmctl05` | 40,531 |

No diverging assertions — they simply do not finish. Under the goal these are
correctness blockers (zero timeouts), and they are the same work as the >=10x
rule and the fork/exec pathology.

## Why this list and not the closure ranking

`closure-v10` ranks `cpython-multiprocessing_fork` at 225 rows and
`ltp-futex_cmp_requeue01` at 227. At this load they are 3 rows and ZERO — both
were reporting their whole unexercised inventory after truncating. Ranking work
off a load-contaminated run points at the wrong suites; rank off a quiet one and
verify the big ones separately.
