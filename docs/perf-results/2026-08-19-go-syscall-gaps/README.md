# `go-syscall` — three rows, two closed

Ranked off the quiet A/B arm, `go-syscall` had 3 diverging rows. Two are fixed
and verified; the third is attributed but not yet fixed.

## FIXED — `TestFchmodat`

    fchmodat2(symlink, AT_SYMLINK_NOFOLLOW)   docker rc=-1 errno=95   carrick rc=0

Linux cannot change a symlink's mode, so `AT_SYMLINK_NOFOLLOW` is not advisory
there — it is `EOPNOTSUPP`. carrick treated the flag as advisory and chmod'd the
link's TARGET, the one thing the caller asked not to happen. Narrow by
construction: on a non-symlink the flag is a no-op on both sides, and plain
`fchmodat` (nr 53) ignores flags entirely on both. Reducer
`reducers/fchmodat-nofollow.py` runs the raw syscalls on both sides.

## FIXED — the `msg_flags` half of `TestSCMCredentials`

    recvmsg(..., MSG_CMSG_CLOEXEC)  docker msg_flags=0x40000000  carrick 0x0

`MSG_CMSG_CLOEXEC` has no macOS equivalent, so the host never reports it back and
the translated flags arrived without it; Linux echoes the caller's request. The
close-on-exec was already applied to the installed fd — only the echo was
missing. Reducer `reducers/recvmsg-cmsg-cloexec.py`.

## OPEN — the payload half of `TestSCMCredentials`

With the echo fixed the test advances from `creds_test.go:110` to `:122`,
"ReadMsgUnix oob bytes don't match". **Attributed by source reading, NOT yet
confirmed differentially** — the confirming Docker run has not been taken because
a carrick gate was occupying the host, and Carrick-vs-Docker concurrency is not
allowed.

The hypothesis, and why it is likely: on a `recvmsg` with `SO_PASSCRED` carrick
APPENDS an `SCM_CREDENTIALS` record built from `peer_ucred(host_fd)`
(`net.rs:2417` -> `carrick_portable::peer_credentials`), which on macOS reads
`xucred` plus a HOST pid. Under HVPatch every guest process is a thread of ONE
carrier, so a host pid is the carrier's for every peer and never a guest pid,
while Linux reports the actual sending process. That is the identity/scope-domain
class `docs/identity-and-scope-domains.md` names: Darwin PID-owned state standing
in for a Linux-process concept.

Next step, in order:

1. Confirm differentially — print the received `ucred` on both sides and compare
   against the sender's guest pid. Do NOT skip this; the payload could also
   differ in the pass-through direction (Linux delivers what the SENDER supplied,
   subject to permission checks, rather than regenerating it).
2. If confirmed, source the ucred from carrick's kernel graph — the guest task
   owning the peer endpoint — instead of the host. `socket_namespace` tracks an
   owner pid for endpoint records but has no per-socket guest-task mapping today.

## OPEN — `TestPrlimitFileLimit`

    helper2 cached rlimit is 43, want 42

A `prlimit` applied to ANOTHER process is not observed by that process's Go
runtime cache. Not investigated further.

---

# Post-change verification (24-suite matched comparison)

Same 24 suites, 8 workers, cached oracles, before and after the DNS + interface
changes:

| | match | diverging rows |
|---|---:|---:|
| before | 15 | 50 |
| after | **17** | **46** |

| suite | before | after |
|---|---|---|
| `cpython-importlib` | timeout 300 s | **match**, 68.5 s |
| `ltp-shmctl05` | timeout | **match** |
| `go-syscall` | 3 rows | **2 rows** |
| `cpython-multiprocessing_fork` | 3 rows, 280 s | timeout, 600 s |

`multiprocessing_fork` is the campaign's most load-flaky suite and has now read
420 s / 600 s / 600 s / 280 s / 600 s across five runs of comparable scope. Not
attributed to this change, and not dismissed either — it needs its own controlled
measurement.

## `node-libuv` — what the closure ledger actually says

The 24-suite runs report `n=0` assertions for libuv on BOTH sides. That is an
artifact of the measurement mode, not a harness defect: `TapParser` parses TAP
positions only in CLOSURE mode, and `--closure` rejects suite filters, so a
filtered run falls back to the coarse exit-code verdict.

`closure-v10` has the real ledger — 507 pairs, 4 diverging:

| position | carrick | docker | status |
|---|---|---|---|
| 370 `tcp_connect6_link_local` | ok | skipped | **closed** — both skip now |
| 472 `udp_multicast_join6` | fail | skipped | **closed** — both skip now |
| 395 `tcp_reuseport` | ok | **fail** | ORACLE-side flake; carrick passed |
| 399 `tcp_try_write_error` | fail | ok | known non-deterministic (8/20) |

Two of the four are closed by the IPv6 change, verified as a 0-line TAP diff
against a freshly-taken oracle. `tcp_reuseport` is worth noting carefully: the
goal names "SO_REUSEPORT distribution" as a libuv gap, but in this run the ORACLE
failed it and carrick passed — the inversion trap `AGENTS.md` warns about, where a
divergence is read as a carrick gap when the oracle is the side that broke.

Under gate load libuv shows a different single failure (`ipc_tcp_connection`),
which standalone runs pass. libuv has residual load-coupled positions; the two
STRUCTURAL divergences are gone.
