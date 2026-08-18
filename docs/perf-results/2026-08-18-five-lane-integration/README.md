# Phase report — five bring-up lanes + capability/namespace semantics

**Date:** 2026-08-18
**Artifact under measurement:** HEAD `069f26e27` (binary built at `35a4337ed`;
the later commit touches only `handoff.md`, so the binary is code-identical).

| field | value |
|---|---|
| binary sha256 | `81e72675bcc342ab33c8d901295e0c68b6d1a11c9a3fc1538d163f8a62c04f1c` |
| CDHash | `ee9f546876ae0162938d3dabd2b1bc596834eb81` |
| LC_UUID | `526DF34B-829B-33EA-9EC7-DA567CDD893E` |
| hypervisor entitlement | present |
| `__dof_carrick` | present |
| worktree | clean (excluding the oracle cache the run rewrites) |

Measurement: `carrick-conformance --closure --force --refresh-oracle`, run id
`closure-v3-first`, phases strictly serial (full carrick pass, then a full
Docker re-bless under the new `closure-v3` cache determinant). One orphaned
guest from earlier profiling (`carrick:mh3`, parked at 0% CPU for 1h53m) was
reaped before the run; no other carrick processes were alive.

## What changed since the last authoritative tally (1,862 MATCH / 265 INCOMPLETE)

### Integrated bring-up lanes (subagents, each rebased onto main and re-verified before merge)

| lane | result |
|---|---|
| `bpf(2)` | maps + structurally-validated prog load; all 8 `ltp-bpf_*` row-exact |
| `userfaultfd` + `memfd_secret` | policy denial (oracle TCONFs all six) + real secretmem fds; six suites line-match |
| `perf_event_open(2)` | software counters off the per-thread CPU ledger; three suites line-exact |
| new mount API | CAP_SYS_ADMIN-gated as the oracle is; 14/16 suites line-exact |
| fork+exit round trip | 5.62 -> 1.34 ms at threads=0 (Docker 0.17); 8.81 -> 3.39 at threads=16 |

### Coordinator work

- **HWCAP/HWCAP2 parity** — carrick advertised 8 feature bits against the
  oracle's 30+, so feature-gated guest code (go crypto/sha512's Armv8.2 rows,
  glibc IFUNC selection) silently skipped hardware paths.
- **Capability model** — Linux uid-transition rules (a guest that `setuid`'d
  away from root kept every capability), `CAP_NET_RAW` on `SOCK_RAW`,
  `CAP_SYS_NICE` on priority raising, `CAP_SYS_ADMIN` on `fanotify_init`.
- **Namespace semantics** — `unshare`/`setns`/`clone3` denied as Docker denies
  them, `clone`'s namespace flags gated, `/proc/config.gz` gaining
  `CONFIG_NAMESPACES` and `CONFIG_TIME_NS`. `unshare` previously returned
  SUCCESS with the namespace unchanged.
- **Extra fd types removed** — io_uring denied like Docker, fanotify gated.
  This was the dominant term in the `tst_fd` matrix suites: carrick built fd
  types the oracle cannot, so it ran pairings the oracle skips.
- **splice/FICLONE error precedence** modelled from the oracle's 17x17
  matrices. `splice07` LINE-EXACT; `ioctl_ficlone04` 252 -> 33 diverging rows.

## Method corrections (each invalidated earlier evidence)

1. **The oracle must be invoked the way the harness invokes it** —
   `docker run … /bin/sh -c '<binary>'`. A direct exec makes the test PID 1 and
   misfires LTP's heartbeat, yielding "Main test process might have exit!"
   transcripts on BOTH sides. This produced a reported "carrick stdio bug"
   that does not exist (retracted by its author after the same discovery).
2. **Closure parity is outcome EQUALITY, not all-pass.** ~600 suites in exact
   agreement with the oracle (matched skips, matched oracle-side failures)
   were structurally INCOMPLETE forever under the old rule.
3. **LTP asserts from `.h` headers too.** The `.c`-only regex dropped those
   rows, so ~50 suites parsed to `None` on both sides.

## Open leads recorded for the next cycle

- `ioctl_ficlone04`'s remaining 33 rows all involve the guest's `/dev/zero`,
  which never reaches the FICLONE arm. Both plausible early exits are in the
  ioctl handler: the top-level `fd_is_valid` guard and the arm's own
  `fd_is_valid(src_fd)` check. Needs a live probe to decide.
- `cpython-posix` reduces to two real failures (`fexecve`, `posix_spawnp`
  PATH search); the third (`unshare`/`setns`) is fixed. Both survivors are
  exec-in-a-child shaped.
- `cpython-threading` is a gating regression against the blessed baseline
  (`free(): invalid pointer` in a forked child) that reproduces on unmodified
  main — same family as `cpython-importlib`'s SIGSEGV.
- `multiprocessing_main_handling` is exec/startup bound, not fork bound; the
  exec path needs its own measurement.

## Tally

Pending — this section is filled from the `closure-v3-first` run against the
1,862 MATCH / 265 INCOMPLETE baseline. Nothing here should be quoted until it
is.
