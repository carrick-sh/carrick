# HVPatch fork+wait round trip — attribution and the first two levers

**Recorded 2026-08-18.** Base revision `44744a166`; work on
`worktree-agent-aa8759e313da0d785`.

## The question

A guest `fork()` + `_exit(0)` + `waitpid()` round trip was the largest
un-attributed cost under HVPatch, and the cpython `multiprocessing_fork` (305
diverging rows), `multiprocessing_forkserver` (225), `concurrent_futures` (175)
and `multiprocessing_main_handling` (29) tranches were all filed against it.
Neither existing fork ledger could see the exit half: both
`hvpatch-phase4-fork-runtime-stages.d` and
`hvpatch-phase4-fork-process-spec-stages.d` stop at the parent's fork critical
section.

## Instruments added

Three durable D artifacts, all consuming existing USDT providers:

- [`scripts/dtrace/hvpatch-fork-wait-roundtrip.d`](../../scripts/dtrace/hvpatch-fork-wait-roundtrip.d)
  — joins the fork and exit halves on the CHILD's Linux pid and partitions one
  iteration into fork / child / reap.
- [`scripts/dtrace/hvpatch-fork-wait-amplification.d`](../../scripts/dtrace/hvpatch-fork-wait-amplification.d)
  — counts the host work one guest fork+wait induces. Counts are load-invariant,
  which is the only thing that was trustworthy on this box.
- [`scripts/dtrace/hvpatch-fork-host-syscall-callers.d`](../../scripts/dtrace/hvpatch-fork-host-syscall-callers.d)
  — attributes those host syscalls to exact Carrick user stacks.

The reducer is N idle `pause()` pthreads, then a timed loop of
`fork` / `_exit(0)` / `waitpid`, self-timing each iteration and reporting
percentiles, run under `gcc:13` both dynamically and statically linked.

**Host caveat, and it is not a small one.** Sibling agents were building and
running tests throughout. The one-minute load average moved between 4 and 45,
and the SAME binary on the SAME reducer reported 1.8 ms/iteration at load 18 and
9.0 ms at load 45. Every wall figure below is therefore a paired same-session
measurement at a stated load, never a controlled experiment, and the first
"7x improvement" this investigation produced was pure load artefact — it
compared a load-34 run against a load-14 run. The controlled pairs are the ones
in the table.

## Where the time went

Round-trip partition on the base binary (101 forks, traced, so relative shares
only):

| interval | per iteration |
| --- | ---: |
| parent fork critical section | 1.303 ms |
| child: fork-return .. process-exit publication | 6.591 ms |
| whole iteration (`fork_start(i+1) - fork_start(i)`) | 3.803 ms |

The child interval EXCEEDS the iteration, which is the first structural finding:
the parent's `wait4` is satisfied by the Kernel zombie publication, and the
child's remaining teardown (stage-2 retirement, ASID/bank retirement, vCPU
destroy) runs CONCURRENTLY with the parent's next fork. Fixing "the exit half"
as if it were serial latency would have been aimed at nothing.

Host-syscall amplification per round trip on the base binary (101 forks):

| | per fork+wait |
| --- | ---: |
| host syscalls | 148 |
| frame-COW copies | 8.0 |
| stage-2 map / unmap | 11.4 / 11.4 |
| guest syscalls | 4.9 |

The caller attribution then named the top ones. `madvise` (19.9/cycle), `mmap`
(12.5) and `munmap` (12.4) were dominated by two stacks, both under
`resolve_frame_cow_fault`:

- `diagnostic_fault_page_tables` → `read_gpa(root, LINUX_PAGE_TABLES_SIZE)`.
  A 1.75 MiB copy to read four descriptors for a diagnostic probe, per COW
  fault.
- `perform_frame_cow` → `manager.clone()`. Another 1.75 MiB, as the
  transaction's rollback pre-image, per COW fault.

macOS serves a 1.75 MiB allocation from a fresh `mmap`, so each of those cost an
`mmap`, a zero-fill fault per page as the copy touched it, and a
`munmap`/`madvise` on drop. At ~6 COW faults per round trip that is ~21 MiB of
copying and ~36 host VM syscalls per guest fork+wait — for a workload whose
guest side is three syscalls.

Two more whole-image copies sat on the fork path itself: the parent's rollback
pre-image (`ParentPageTablesClone`, 32.4% of the fork process-spec stage) and a
clone in the HVF `ProcessSpec` that `materialize_process` overwrote unread
(`BackendSpecFinalize`, 18.4%).

## What changed

`cce92b62f`. The diagnostic walk now reads the live backing in place through a
new `walk_descriptors_host`; the unread `ProcessSpec` copy is deleted; and the
three publication pre-images plus the fork-time parent pre-image are taken into
recycled buffers via a hand-written `Clone::clone_from`. No snapshot was
weakened — each is still the complete pre-transaction image.

## Result

Reducer, `gcc:13`, dynamically linked, untraced, two reps per side, load ~8-9.
Median ms per round trip:

| threads | before | after | docker | before/docker | after/docker |
| ---: | --- | --- | ---: | ---: | ---: |
| 0 | 1.124 / 1.202 | 0.735 / 0.724 | 0.092 | 12.6x | 7.9x |
| 0 (no reap in window) | 0.973 / 0.970 | 0.667 / 0.653 | 0.045 | 21.6x | 14.7x |
| 1 | 1.682 / 1.721 | 1.006 / 0.971 | 0.107 | 15.9x | 9.2x |
| 2 | 1.977 / 1.915 | 1.240 / 1.055 | 0.130 | 15.0x | 8.8x |
| 4 | 2.263 / 2.335 | 1.462 / 1.384 | 0.138 | 16.7x | 10.3x |
| 8 | 3.130 / 3.053 | 2.020 / 1.874 | 0.159 | 19.4x | 12.2x |
| 16 | 4.803 / 5.845 | 2.769 / 2.963 | 0.178 | 29.9x | 16.1x |

Same-instrument confirmations: the traced round-trip partition moved the fork
critical section 1.303 -> 0.349 ms and the whole iteration 3.803 -> 0.790 ms
(the latter matching the guest's own self-timed mean to 0.3%), and the
amplification counter moved `madvise` 2,006 -> 331 per 101 forks with
`mmap`/`munmap` unchanged — i.e. the removed traffic is the whole-image buffers,
not the COW's own 16 KiB frame backing.

## The next lever, sized

An ablation build that simply SKIPS the frame-COW rollback pre-image (correctness
deliberately broken; never committed) reports threads=0 medians of 0.504 / 0.466
ms at load ~13, against 0.735 / 0.724 for the shipped build at load ~8. The
remaining pre-image memcpy is therefore worth roughly another 1.5x on this
reducer, and the measurement is a lower bound because the ablation ran at higher
load.

Capturing it properly means replacing the whole-image pre-image with a bounded
undo journal. The pre-transaction descriptor values are still readable from the
LIVE HOST BACKING until `sync_to_host` runs, and `PageTableManager` already
records the edited byte offsets in `dirty`, so the journal can be built with no
change to the write path. The complication that must be handled — and the reason
it was not done here — is `alloc_table`: it zeroes a spare page in the shadow
without going through `write_desc`, so an undo must also restore `next_free`,
`free_tables`, `reclaim_pending`, and the shadow bytes of every page the
transaction allocated (readable from the host backing, which those offsets never
reached). Getting that wrong corrupts a live page-table graph, which is why it
wants its own change with its own red-first test rather than being folded into a
perf pass.

## What this does NOT fix

`cpython-multiprocessing_main_handling` is unmoved: 18.8 / 21.1 s guest-reported
before, 19.8 / 17.5 s after, against a 3.4 s native arm64 Docker oracle (~5x).
The suite runs 39 `runpy` cases that each start a fresh interpreter, so it is
exec/startup bound rather than fork bound. The fork lever is aimed at
`multiprocessing_fork` / `forkserver` / `concurrent_futures`, and
`main_handling` needs the exec path measured separately.

## Reproducing

```
target/release/carrick run --rm -v <dir>:/w -w /w gcc:13 /bin/sh -c '/w/forkbench_dyn 0 400 0'
sudo /usr/sbin/dtrace -Z -q -o out -s scripts/dtrace/hvpatch-fork-wait-roundtrip.d \
  -c "target/release/carrick run --rm --name fb -v <dir>:/w -w /w gcc:13 /bin/sh /w/g100.sh"
```

`carrick trace --script` is the intended launcher; it re-execs under `sudo`, and
this worktree's path falls outside the tree's NOPASSWD prefixes, so the captures
above drove the same durable `.d` artifacts through `sudo /usr/sbin/dtrace`
instead.
