# EL1 census, interim: where the ecosystem rows spend host syscall CPU

Stage 0 of [`2026-09-24-zone-the-workloads.md`](../superpowers/specs/2026-09-24-zone-the-workloads.md).
Interim: the per-suite join and the share of carrier CPU need a rerun (see
Caveats).

## Run

- Binary: signed build of `412a9638f` (EL1 census, before the carrier-CPU
  fields), EL1 on.
- `CARRICK_EL1_CENSUS=<dir> cargo run -p carrick-conformance -- --tier full
  --ecosystem cpython --ecosystem go --ecosystem node --workers 6`.
- 635 rows: 595 MATCH, 11 BUDGET_KILL, 29 gating failures. 617 runs wrote a
  census; the other 18 crashed or were killed before carrier teardown.

## Host syscall CPU by class (617 runs, 168.2 CPU-s total)

| Class | Services | Host CPU s | Share | µs per call |
|---|---:|---:|---:|---:|
| openat | 596,294 | 34.5 | 20.5% | 57.8 |
| renameat | 52,294 | 14.3 | 8.5% | 273.2 |
| unlinkat | 86,770 | 11.2 | 6.7% | 129.0 |
| newfstatat | 973,134 | 10.6 | 6.3% | 10.9 |
| mmap | 203,477 | 10.1 | 6.0% | 49.4 |
| futex | 1,323,017 | 9.0 | 5.4% | 6.8 |
| write | 626,182 | 8.9 | 5.3% | 14.3 |
| close | 535,905 | 8.6 | 5.1% | 16.1 |
| brk | 75,629 | 8.3 | 4.9% | 109.6 |
| getdents64 | 124,410 | 5.4 | 3.2% | 43.8 |
| munmap | 90,167 | 5.4 | 3.2% | 60.2 |
| execve | 7,868 | 4.7 | 2.8% | 595.2 |
| fstat | 468,534 | 4.5 | 2.7% | 9.6 |
| read | 356,003 | 3.3 | 2.0% | 9.3 |

EL1 served 94,155 writes and 336,947 reads in-guest; every other class was
forwarded.

## What it says

1. Path lookup (openat, newfstatat, fstat, readlinkat, getdents64) is about a
   third of host syscall CPU; namespace mutation (renameat, unlinkat,
   mkdirat) about 16%; memory (mmap, munmap, brk, mprotect, madvise, mremap)
   about 18%.
2. Per-call costs, not call counts, are the pathology. Linux does rename,
   unlink and brk in single-digit microseconds; carrick's host path takes
   109-273 µs. By the project's standard these are structurally wrong work,
   and fixing them is worth more than moving them into the zone.
3. The classes the zone serves today (read, write, lseek, inotify) are small
   on these workloads.
4. A cold hello-world `go build` spent 481 ms of host syscall CPU in about
   70,000 syscalls, while the whole Docker build takes about 1.4 s wall: its
   gap is mostly outside syscall service.

## Consequence for the plan

Stage 2 (name resolution) stays next, but split in two: first make the host
namespace operations cheap per call (rename, unlink, mkdir, openat's
resolution, brk), with structural budgets per operation; then move the lookup
half into the zone. The paged file cache (stage 1.5) waits for the
per-suite join, which will show whether file-byte classes matter anywhere.

## Caveats

- The host was loaded during the run (a concurrent `cargo` build), so
  per-call CPU is inflated somewhat; the ranking, not the absolute values, is
  the result.
- The run's per-suite results file was overwritten by a later filtered run
  (filtered runs share one default results path), so this interim has no
  per-suite join; the rerun passes `--jsonl <path>` explicitly.
- Of the 29 gating failures, the seven rechecked serially split two ways:
  go-go_importer and node-libuv match (load flakes), and cpython-fork1,
  cpython-wait4, cpython-pkgutil, cpython-zipfile and cpython-zipimport fail
  identically with `CARRICK_EL1=0` and on pre-branch main `b700bef18`. In the
  guest, Python's `time.time()` returns about 1980 (seconds since the epoch),
  which breaks zipfile and zipimport and plausibly the other time-dependent
  suites. Bisect in progress; the rerun follows the fix.
