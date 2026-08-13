# KF's ceiling, from the oracle — and three refuted designs

**Recorded 2026-08-13.** The kernel lane's largest CPU term is 145,453
zero-fill faults taken inside guest `mmap` service windows, all of them
carrick's own `__bzero` scrubbing anonymous memory it is about to hand back
([ledger](2026-08-13-hvpatch-kernel-lane-amp-ledger.md)). This settles the two
questions that decide whether KF is worth building: **is the win real, and does
any known mechanism deliver it.**

## The objection that had to be answered first

Three independent designs were produced and each was adversarially refuted (see
below). Every one of them drew the same cost objection, and it is the same trap
this campaign already fell into once:

> Removing the scrub does not remove the fault. Today the guest's first touch of
> a scrubbed page is free *because carrick's `__bzero` already made it
> resident*. Stop scrubbing and the fault simply moves from carrick to the
> guest's first store.

That is a real mechanism and it cannot be argued away — it has to be measured.
The saving is exactly **the pages carrick scrubs that the guest never touches**.

## The measurement: ask the oracle

Docker's Linux already implements the design under discussion — anonymous
memory is demand-zeroed on first touch and nothing is pre-scrubbed. So its
minor-fault count for the same build **is** the number of pages the guest
genuinely needs.

Same image, same fixture, same cold `GOCACHE`, read from `/proc/<shell>/stat`
after the build:

| | value |
| --- | ---: |
| Docker guest `children_minflt` | **55,126** |
| Docker guest page size | 4,096 B |
| **memory the guest actually touches** | **~225.8 MB** |
| carrick pages scrubbed (`zfod`, 16 KiB) | 145,453 |
| **memory carrick scrubs** | **~2.38 GB** |

**carrick touches about 10.5x more memory than the workload needs.**

Two things make that a conservative reading:

- `children_minflt` counts **every** minor fault — file-backed page-ins, COW,
  stack growth — not just anonymous zero-fill. So 225.8 MB is an **upper
  bound** on the anonymous memory the guest genuinely touches.
- carrick's host page is 16 KiB against Linux's 4 KiB, so covering the same
  bytes costs carrick *fewer* faults, not more: between ~13,800 (if the guest's
  touches are dense) and ~55,126 (if every 4 KiB fault lands in a distinct
  16 KiB page).

**So the ceiling is a reduction of roughly 90,000–131,000 faults, i.e. 62–90%
of the term.** The "it just moves the fault" objection is quantitatively wrong
on this workload: most of those faults genuinely disappear because the guest
never touches the memory at all.

At the tree's 6.42 µs/fault that is **0.6–0.8 CPU-s** of a ~4.09 CPU-s build —
15–20%. Large, and short of the ~1.8 CPU-s the term was first estimated at,
because part of that estimate was always going to move rather than vanish.

## The three designs, and why each was refuted

Every candidate was attacked by three independent skeptics (zero-guarantee,
HVF-semantics, cost-reality) instructed to refute rather than appreciate.
**All three designs were refuted, two of them fatally.** Recorded in full
because a refuted design is a saved week.

### 1. Port the native remap — `mmap(MAP_FIXED|MAP_ANON)` over the arena

**FATAL, on the tree's own rule.** `crates/carrick-mem/src/memory.rs:549-566`:
an IPA once `hv_vm_map`'d can never be safely re-pointed to different host
memory, because revoking it needs `TLBI IPAS2E1`, which is EL2-only. A
`MAP_FIXED` replacement destroys and recreates the host VM entry that
`hv_vm_map` registered — exactly the entry-level re-pointing that rule forbids.
No code in the tree does it, and the one confirmed replacement path
(`hv_vm_unmap` then `hv_vm_map` at exec, 67 times per build) works only because
the whole address space is being torn down with its siblings retired.

### 2. `madvise(MADV_ZERO)` on the host backing

**FATAL on HVF semantics, MAJOR on the zero guarantee.** It needs two
unverified XNU properties — that `madvise` neither splits nor re-points the
registered entry, and that the guest observes the zeroing through a stage-2
entry carrick cannot invalidate. The skeptic produced a concrete
single-threaded stale-read sequence: a 16 MiB anonymous mapping written to
0xAB, then freed and re-handed-out, whose stage-2 entries carrick can never
invalidate.

### 3. An arena provenance ledger — track what could have been written

**FATAL on the zero guarantee, and independently FATAL on HVF semantics.**
The ledger clears itself on `MADV_DONTNEED` over a range that **remains
guest-writable**, and there is no store hook, so the next guest store into that
range goes unrecorded and survives into a later fresh anonymous `mmap`.
Separately, the marks are per-process, but `CLONE_VFORK` makes HVF mark every
`guest_writable && !guest_shared` region `VM_INHERIT_SHARE` before
`libc::fork` (`trap.rs:5567-5573`), so marks that must flow child→parent
cannot.

## What survives — and one important correction

The refutations killed every design that mutates state **under a live
`hv_vm_map`**. They did **not** kill the phase, and an early reading of this
document that said "no known mechanism delivers it" was too pessimistic. The
investigation found two mechanisms the tree already ships.

### A. `hv_vm_unmap` then `hv_vm_map` at the SAME IPA — confirmed, not hypothetical

This is exactly what the hvpatch **execve** path does, **67 times per cold
`go build`**, inside a live VM that is never destroyed and on a vCPU that keeps
running: it unmaps the old extents (`trap.rs:6612`), drops the old host
mappings, and re-maps *fresh* host mmaps at IPAs packed from the same
`bank_base` (`trap.rs:7044-7053`), with `trap.rs:6769` making it a hard error if
the page-table region does not land back at `bank_base`. The guest then walks
its stage-1 tables *through that reused IPA* — which could not work if stage-2
had retained the old physical pages.

**The cost trade is enormous and measured**: ~7.24 µs per `hv_vm_map` and
~6.83 µs per `hv_vm_unmap` on the real exec path (p50 2.46 µs / 0.50 µs on
16 KiB frames in the K0 probe), against ~6.42 µs per avoided fault. One
unmap+map pair replacing a ~1,500-fault scrub is **roughly a 1000x trade**.

Two structural blockers, both concrete and both checkable:

- every unmap in the tree targets an **exact `(ipa, size)` extent** from the
  frame inventory, and the 32 GiB arena is ONE extent — there is no precedent
  for unmapping the 16 MiB sub-range a single guest `mmap` needs;
- every confirmed instance ran with the affected address space's **siblings
  already retired**, so nothing yet shows the swap is coherent for other live
  vCPUs in the same VM.

### B. Stage-1 re-pointing to a fresh IPA — no stage-2 mutation at all

The tree already ships `repoint_private`-style stage-1 re-pointing: leave
stage-2 alone, and instead point the guest's stage-1 leaves at a **different
IPA** whose host backing is a fresh anonymous `mmap`, invalidating with the
EL1 TLBI carrick already owns. This sidesteps the forbidden operation entirely
rather than arguing about it.

Its constraint is a **finite, never-reclaimed alias-IPA budget** (32,768 global
2 MiB blocks; a 40 GiB per-process bank cursor for hvpatch children) — which is
why it suits **the 66 large calls that carry ~90% of the term** and not the
long tail. That is a good fit for this population, not a coincidence: the
measured distribution is exactly "a few very large scrubs plus many tiny ones".

### C. The smallest safe step, independent of both

`mmap_dirty_high` is **a bug on its own terms**, regardless of performance: a
watermark named "dirty" that is raised on **allocation** (`dispatch/mem.rs:1649`,
`:1680`, `:3803`) rather than on writability, so a `PROT_NONE` reserve the guest
can never store to poisons it and forces later allocations below it to be
scrubbed. Fixing what it measures needs no new Darwin primitive, no stage-2
interaction, and no HVF qualification.

**Sequence: C first (it is a correctness bug and free), then measure what is
left, then B for the large tail if the term survives.**

---

## RESULT — step C landed, and it took most of the term

Implemented at `3d45b1a98`: the watermark is renamed `mmap_writable_high` and
raised by **writability** rather than allocation, at all three points where an
arena range can become guest-writable — the `mmap` that creates it, a
`MAP_FIXED` mapping placed over it, and an `mprotect` that adds `PROT_WRITE`.
The `MAP_FIXED` site was a hole that predated the change and is closed with it,
because lowering the watermark would have widened it.

### Measured

Faults, cold `go build`, signed binary, `BUILD_OK`:

| | before | after | change |
| --- | ---: | ---: | ---: |
| in-window `zfod`, `anon/private/RW-` | 145,453 | **1,592** | **−98.9%** |
| in-window `zfod`, all shapes | 148,758 | **2,858** | **−98.1%** |
| **whole-build `zfod`** | 230,298 | **86,721** | **−62.3%** |
| whole-build `cow_fault` | 8,350 | 8,570 | flat |

CPU, five samples per arm, untraced on the signed binary — the retention
authority:

| arm | user | sys | CPU | window |
| --- | ---: | ---: | ---: | ---: |
| before (`f850336c5`) | 2.474 | 1.652 | 4.087 | 1,938 ms |
| **after (`3d45b1a98`)** | 2.370 | **1.450** | **3.803** | **1,828 ms** |
| change | −4.2% | **−12.2%** | **−6.9%** | **−5.7%** |

Windows do not overlap: before `[1920, 1929, 1938, 2004, 2026]`, after
`[1791, 1818, 1828, 1846, 1853]`. **Retained.**

### The refutation was right, and so was the oracle

Both predictions held, which is the useful part:

- **Faults did partly move.** In-window `zfod` fell 98.1% but whole-build
  `zfod` fell only 62.3%, so ~84,000 faults reappeared outside the service
  windows — the guest taking its own first touches, exactly the mechanism every
  skeptic named.
- **Most of them genuinely disappeared.** The oracle put the workload's real
  touched set at ~226 MB, i.e. ~14k–55k faults at 16 KiB pages; the residue
  outside execve and `carrick-only` lands in that band. The scrub really was
  doing ~10x more work than the workload needs.

Neither number alone would have shown this. The in-window census alone would
have claimed a 98% win that the whole-build count does not support; the
whole-build count alone would have hidden where the win came from.

### Gates

- `just ci`: **green, exit 0, 3,886 tests passed, 0 failed.**
- Probe gate: **the arm64:musl failure SET is byte-identical to the pre-KN
  baseline** (123 = 123, `comm` diff empty in both directions) — no new
  failures. Every memory-invariant probe passes on both libcs:
  `mmapzerofill`, `mmapreuse`, `mmaprecl`, `mmapmunmap`, `mmapcage`, `memmap`,
  `brkheapgrow`, `mremapgrow`, `protnonesyscall`.
- Two new unit tests pin both halves of the invariant, because either alone is
  satisfiable by a wrong implementation: a `PROT_NONE` reserve must not raise
  the watermark and must not force a scrub when re-handed out, and a writable
  mapping must raise it and must force one. A watermark that is simply never
  raised passes the first test and fails the second.

### Still open for KF

The gate asked for whole-build `as_fault` below 60,000. `zfod` reached 86,721
and `as_fault` was not captured post-change — the AMP1 reader refused the
follow-up capture with a named internal-consistency error (`host CPU maximum
for guest op getegid's "thread_selfusage" exceeds its own sum`), which is an
instrument defect to fix before the next ledger. Mechanisms **A** and **B**
above remain available for the residue, and the 66 large mappings are no longer
the population they were — that census should be re-run before either is built.

## What is NOT established

- Whether the 66 large commits actually land below `mmap_dirty_high` because of
  the `PROT_NONE` over-raise, or for some other reason. That is one census away
  and decides whether step 2 above is worth anything.
- The 6.42 µs/fault cost is a native-lane figure carried over, so the CPU-second
  conversions here are order-of-magnitude, not measured, on this lane.
- Nothing here is an ABBA. No code changed; this is a scoping result.
