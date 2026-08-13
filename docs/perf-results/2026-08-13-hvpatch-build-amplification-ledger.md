# HVPatch cold `go build`: where the host syscalls come from

**Recorded 2026-08-13.** The goal's gating number is a cold `go build` below
2.3 CPU-s; HVPatch is at ~4.2-4.7 CPU-s, and
[`2026-08-13-hvpatch-guest-vs-host-cost.md`](2026-08-13-hvpatch-guest-vs-host-cost.md)
established that the bar is ~1.01x the workload's own intrinsic cost, so
~1.9 CPU-s of overhead must go. This ledger says where it is, so the work is
ranked by measurement rather than by guess.

## Method

`scripts/dtrace/syscall-amplification.d` against a cold `go build` on the
signed binary, HVPatch backend, `dtrace -Z` (the USDT probes live in a process
that has not started when the script compiles — without `-Z` the script fails
to compile rather than silently measuring nothing). Docker not running. The
build completed (`BUILD_OK`).

DTrace perturbs this path heavily; **proportions are what this measures**, not
wall-clock. The script's own header states the same caveat.

## Headline

| | count |
| --- | ---: |
| guest Linux syscalls | 76,503 |
| host macOS syscalls | 360,002 |
| **overall amplification** | **4.71x** |

## The actionable split

| bucket | host syscalls | share |
| --- | ---: | ---: |
| `linux:openat` | 107,144 | 29.8% |
| `carrick-only` | 108,210 | 30.1% |
| `linux:newfstatat` | 54,910 | 15.3% |
| `linux:mkdirat` | 25,742 | 7.2% |
| `linux:unlinkat` | 11,530 | 3.2% |
| `linux:fcntl` | 10,260 | 2.9% |
| everything else | ~42,206 | 11.5% |

**Filesystem path operations are 55.4% of all host syscalls** (openat +
newfstatat + mkdirat + unlinkat = 199,326), and they serve only ~7,500 guest
calls.

## Per-operation amplification, with denominators

| guest syscall | guest calls | host calls | host per guest |
| --- | ---: | ---: | ---: |
| `openat` | 3,268 | 107,144 | **32.78** |
| `newfstatat` | 3,967 | 54,910 | **13.84** |
| `mkdirat` | 283 | 25,742 | **90.96** |
| `fcntl` | 9,587 | 10,260 | 1.07 |
| `read` | 6,188 | 6,645 | 1.07 |

`fcntl` and `read` are essentially 1:1 and are not the problem. The path
operations are, and `mkdirat` at ~91 host syscalls per guest call is the worst
single ratio in the run.

### What one guest `openat` actually costs

| host syscall | count | per guest openat |
| --- | ---: | ---: |
| `openat` | 34,483 | 10.55 |
| `close` | 27,571 | 8.44 |
| `fcntl` | 21,008 | 6.43 |
| `fstat64` | 11,147 | 3.41 |
| `flistxattr` | 5,364 | 1.64 |

Those five are 93% of the bucket. The shape — open, fcntl, fstat, close,
repeated — is a **component-by-component path walk**: each guest path is
resolved by opening every directory component, interrogating it, and closing
it, with no reuse across calls. `newfstatat` shows the same signature
(18,253 host `openat` + 14,520 `close` to service 3,967 guest stats).

The per-instance distribution confirms it is structural, not a tail: the mode
for `openat` is 16-31 host syscalls per guest call (2,365 of 3,268 instances),
with 413 instances above 64. `mkdirat`'s entire population sits in the 64-127
bucket.

## Which code issues those opens

`scripts/dtrace/hvpatch-phase4-openat-callers.d` (also `-Z`) joins every host
`openat` to its Carrick user stack inside the guest `openat`/`newfstatat`
service windows. It reproduces the counts above exactly — 3,268 guest `openat`
→ 34,458 host, 3,967 guest `newfstatat` → 18,266 host — and attributes them:

| caller | host opens | share |
| --- | ---: | ---: |
| `cap_primitives::rustix::fs::open_unchecked` | 25,034 | **47.5%** |
| `HostFsBackend::fast_open_contained` | 16,744 | 31.8% |
| `HostFsBackend::stat_cache_get_or_fill` | 3,528 | 6.7% |
| `HostFsBackend::validate_parents_fast` | 3,297 | 6.3% |
| `HostFsBackend::fast_open_for_guest` | 2,224 | 4.2% |
| `HostFsBackend::root_marker_xattr` | 264 | 0.5% |
| `cap_primitives::…::ReadDirInner::new` | 257 | 0.5% |

**Nearly half of all host opens are cap-std's**, and this is the default OCI
rootfs path, not `--fs host`. `open_unchecked` is reached through cap-std's
containment walk, which resolves a path by opening EVERY component with
`O_NOFOLLOW` so a symlink cannot escape the root — which is exactly the
open/fcntl/fstat/close-per-component signature the bucket shows, and the same
mechanism already documented for the `--fs host` backend in
[`../fs-host-capstd-amplification.md`](../fs-host-capstd-amplification.md).

Carrick's own contained fast path (`fast_open_contained`) already handles
31.8%, so the fast path exists and simply does not cover enough: the remaining
half still falls back to a full cap-std re-walk on every call, with no reuse
between calls that share a prefix — and in a `go build` nearly every path
shares a long prefix.

That makes the lever specific rather than architectural: widen the contained
fast path to cover the fallback cases and give it a resolved-prefix cache, so
repeated resolution of the same directory chain stops re-opening it. The
correctness constraint is the shipped fast-path errno rule — only `ENOENT` is
authoritative on a contained fast path, and errnos carrick synthesises from
its own flags (`O_NOFOLLOW` → `ENOTDIR` on symlinked dirs) must fall back.

### Negative result: `open_raw_fd` is NOT the hot cap-std caller

Routing `HostFsBackend::open_raw_fd`'s non-create, non-truncate case through
`fast_open_for_guest` (carrick's own one-`openat` + `F_GETPATH` contained open)
before falling back to cap-std produced **no measurable reduction**: host
syscalls per guest syscall went 4.644 → 4.560 and `linux:openat` stayed flat at
~104.4k, inside run-to-run variation. The change was reverted rather than kept
as an unproven second path.

So the 47.5% arrives through some OTHER route into cap-std — the metadata and
lookup variants (`open_raw_fd_with_metadata`, `lookup`/`lookup_kind`,
`real_stat`) and `validate_parents_fast` are the remaining candidates, and
`rootfs.rs`'s `open_for_dispatch` calls those directly. **Identify the exact
caller before widening anything else**: the caller-stack aggregation above
collapses on the first Carrick frame, so re-run it aggregating on the first
frame BELOW `open_unchecked` to name cap-std's callers rather than its
callees.

## The `carrick-only` bucket

30.1% of host syscalls are issued with **no guest work in flight** — carrick's
own schedulers, pumps and cross-thread signalling:

| host syscall | count |
| --- | ---: |
| `kevent` | 17,277 |
| `write` | 13,303 |
| `ulock_wake` | 10,438 |
| `ulock_wait2` | 10,198 |
| `fcntl` | 8,162 |
| `read` | 7,448 |
| `close` | 7,392 |
| `psynch_cvwait` | 7,303 |

No amount of per-syscall emulation tuning touches this bucket; it is the
runtime's own overhead. The `ulock`/`psynch` traffic is the vCPU scheduler and
futex plumbing — the same machinery the M:N executor design
([`2026-08-13-mn-scheduler-design.md`](../superpowers/specs/2026-08-13-mn-scheduler-design.md))
proposes to replace, which is a second, independent reason to do it beyond the
correctness and determinism arguments recorded there.

## Ranking

1. **Path resolution (55% of host syscalls), and specifically cap-std's
   containment walk (47.5% of host opens).** The single largest lever by a wide
   margin, and it is one mechanism, not five: the same walk serves `openat`,
   `newfstatat`, `mkdirat` and `unlinkat`. Carrick's own `fast_open_contained`
   already covers a third of it, so this is widening an existing path and
   giving it prefix reuse — not new architecture.
2. **`carrick-only` (30%).** Scheduler/futex/pump traffic, addressed by the
   executor model rather than by syscall tuning.
3. Everything else is under 3% each and cannot move a double-digit ratio.

The honest read: the 2.3 CPU-s bar is not reachable by tuning individual
syscalls. It needs the path-resolution mechanism replaced and the scheduler's
own syscall traffic removed — items 1 and 2 are most of the run.
