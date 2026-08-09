# HvPatch Phase 2 — exec repatching landed; proposed exit gate is a measured no-go

Date: 2026-08-08

Controller: `/Volumes/CaseSensitive/carrick/hybrid.md`, Phase 2

Implementation: `7063ffecca692567dbe0d0901f4f43b36f53155f`

Trace artifacts: `67cd4fd9`

Normalized records: [`hvpatch-phase2-exec-repatch-and-no-go.jsonl`](hvpatch-phase2-exec-repatch-and-no-go.jsonl)

## Boundary decision

Phase 2 is closed with one required implementation and one decisive plan
correction:

1. **Exec replacement repatching is implemented.** The selected backend is now
   retained in `SyscallDispatcher`; an HvPatch `execve` patches the newly loaded
   guest text before Carrick adds its executable trampoline/vector pages. The
   VMM path returns the same image byte-for-byte. This pulls forward the
   controller's Phase 4 repatching prerequisite because without it the proposed
   Phase 2 islands would not run in the compiler processes that dominate the
   workload.
2. **The `<20K` host-dispatched-exit target is impossible from the listed Phase
   2 paths.** A naturally completed cold-build census measured 68,276 exits.
   Even crediting every listed path—including the semantically invalid futex
   shortcut—removes only 15,346 and leaves 52,930, missing the target by
   32,930. The CPU target already passes at 4.55 CPU-s in the first untraced
   exact-code run.

No incorrect signal, memory, or wait behavior was introduced to manufacture an
exit count. Subsequent phases may reduce the measured dominant exits, but this
phase's arithmetic cannot be called green.

## Provenance

- Host: Mac16,12, arm64, macOS 27.0 build 26A5388g, 16 KiB host pages.
- Toolchain: rustc 1.96.0 (ac68faa20 2026-05-25).
- Signed candidate binary SHA-256:
  `a4eb901aade91c4501270dba996a99f643bd54899437c6b6ec4d2b494add65ff`.
- Mach-O UUID: `450CF18B-AE9A-3CF2-AA81-C9D54A8EDBFB`.
- Hypervisor entitlement and `__DATA,__dof_carrick` were present.
- Image:
  `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`.
- Workload: create a one-file Go program under `/tmp`, delete its dedicated
  `GOCACHE`, run `go build`, then execute the result and require `BUILD_OK`.
- Carrick and Docker were never run concurrently; no Docker oracle ran in this
  measurement wave.

The committed
[`hvpatch-phase2-exit-census.d`](../../scripts/dtrace/hvpatch-phase2-exit-census.d)
counts the one `vcpu-trap` USDT site after EL1 has HVC-forwarded a syscall and
before host dispatch. It therefore measures **host-dispatched syscall exits**,
not kicks or fault exits. Its one-copyin aggregation perturbs timing, so only
counts and rank are cited.

## Exec repatching correctness

The red-first test initially failed because
`prepare_exec_image_for_dispatcher` did not exist. The implementation then made
the backend policy explicit and proved:

- VMM exec text containing exact `svc #0` remains unchanged.
- HvPatch exec text is rewritten and gains its fixed information page/island.
- Patching happens before Carrick's executable EL0/EL1 maintenance pages exist,
  so those pages are never scanned as guest text.
- `ubuntu:24.04 /bin/sh -c 'exec /bin/echo repatched'` printed `repatched` and
  exited 0 through the signed binary.
- A full cold Go build completed and its result printed `ok` and `BUILD_OK`.

The post-change census's dominant trap PCs are generated-stub shaped. For
example, `fcntl` exits were concentrated at `0xc20004` (8,703), `0x8e8004`
(1,954), and `0x478004` (1,264); `rt_sigaction` at `0x4780c4` (3,876),
`0xc200c4` (3,812), and `0x8e80cc` (3,078). The low offsets are the
site-specific `svc` resume PCs in 16 KiB-aligned island regions, proving the
reloaded compiler images no longer silently use original SVC sites.

## Cold-build exit census

The authoritative post-repatch capture completed naturally (`bounded=0`):

- Total host-dispatched syscall exits: **68,276**.
- Raw capture SHA-256:
  `e6d7314965300b4280e16b510294e93e848095b025294d4e4cdeb85b6e010890`.

| Rank | Syscall | Number | Exits |
|---:|---|---:|---:|
| 1 | `fcntl` | 25 | 12,062 |
| 2 | `rt_sigaction` | 134 | 11,115 |
| 3 | `nanosleep` | 101 | 6,818 |
| 4 | `read` | 63 | 6,096 |
| 5 | `write` | 64 | 4,784 |
| 6 | `futex` | 98 | 3,967 |
| 7 | `newfstatat` | 79 | 3,960 |
| 8 | `openat` | 56 | 3,265 |
| 9 | `epoll_ctl` | 21 | 3,140 |
| 10 | `close` | 57 | 3,051 |
| 11 | `mmap` | 222 | 1,928 |
| 12 | `rt_sigprocmask` | 135 | 1,252 |

The pre-repatch baseline capture had 69,437 exits; its raw SHA-256 is
`d323065a7c19e23c59fdb35ffeeb59d7f59c17d6f9c71db1d0f41e9f499106e9`.
The 1,161-count difference is ordinary run population variation, not an
optimization claim: repatching changes trap origin but the Phase 1 stub still
executes a real `svc #0`.

## Why the controller's arithmetic cannot reach `<20K`

| Proposed Phase 2 path | Measured host exits | Qualification |
|---|---:|---|
| `getpid/gettid/getuid/getgid` family | 0 | Already serviced in Carrick's default EL1 identity shim. |
| `rt_sigaction` | 11,115 | Needs dispatcher signal state and host disposition/pump updates. |
| `clock_gettime` | 0 | The shipped vDSO already avoids host dispatch here. |
| `tgkill` | 258 | Mostly cross-thread; needs registry validation, queueing, and a kick. |
| `brk` | 6 | Mutates authoritative memory state and must zero shrink/regrowth pages. |
| `futex` | 3,967 | Wait/wake result, timeout, interruption, and scheduling are host-owned. |
| **Maximum projected removal** | **15,346** | Grants even the rejected futex design. |
| **Projected remainder** | **52,930** | **32,930 above the `<20K` gate.** |

The focused argument census (raw SHA-256
`2b7f45d06ab52b528df6dfac42d0297dea97f2ab7748393606b92d577a8895d7`)
also showed that the rejected paths are not harmless constants:

- Futex: 2,628 waits and 2,159 wakes in that run. Linux `FUTEX_WAKE` must return
  the actual number woken; `wfe`/`sev` cannot supply that contract, and timeout
  or signal interruption needs scheduler participation.
- `tgkill`: 292 of 337 calls targeted another thread; a self-only pending flag
  would not cover the measured population.
- `rt_sigaction`: repeated whole-table query and set waves. Setter calls must
  keep Carrick's delivery state and host dispositions coherent across fork and
  exec, not merely update an EL0-visible shadow.
- `fcntl`: 6,091 `F_GETFL`, 5,833 `F_SETFL`, and 206 other calls. This is the
  largest measured exit family but was absent from the Phase 2 proposal.

These conclusions match Carrick's existing
[`syscall-shim-design.md`](../syscall-shim-design.md): an earlier asynchronous
futex ring was removed specifically because it could not return an exact wake
count or block without spinning/another exit.

## CPU gate

One untraced exact-code run after exec repatching reported:

| Metric | Result |
|---|---:|
| In-guest workload wall | 2.470 s |
| Host real | 2.92 s |
| Host user | 2.48 s |
| Host sys | 2.07 s |
| Host user + sys | **4.55 CPU-s** |

This is below Phase 2's `<6.5 CPU-s` target. It is a single-run gate proof, not
an optimization comparison; the pre-change untraced run was 4.28 CPU-s under a
different host-load point, so no performance delta is claimed.

## Repository gate and next boundary

- Focused HvPatch tests: 15 passed, 0 failed.
- Targeted clippy with `-D warnings`: pass.
- Signed exec replacement and cold-build product smokes: pass.
- `just ci` on clean `67cd4fd9`: pass on 2026-08-08. The affected large suites
  reported 1,245 runtime unit tests with 5 ignored and 296 integration tests,
  with zero failures; formatting, workspace clippy, typed-domain lint,
  dependency policy, matrix drift, build/check/doc, and remaining suites also
  passed.

Phase 3 may proceed as a semantics-first investigation of the measured I/O and
fd-state exits. Its own proposed mapped-read, queued-write, and anonymous-mmap
mechanisms must be qualified before implementation: reads require coherent
offset/EOF/short-I/O behavior, writes require an exact synchronous return, and
the controller's 553K zero-fill number came from the native DSR host-allocation
campaign rather than this HVF exit census.

