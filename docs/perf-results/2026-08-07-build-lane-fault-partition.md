# Build-lane fault partition — who owns the in-mmap-window zfod mass

**Date:** 2026-08-07
**Scope:** Move-3 Task 6 / E2, the fault-mass partition
([`2026-08-06-move3-amplification-ledger.md`](../superpowers/plans/2026-08-06-move3-amplification-ledger.md)
§2/E2, §3 Task 6). Measurement only — **no production memory change ships in
this entry** (the winning lowering is designed in §7 and deliberately not
implemented; it is not small, and the plan's own instruction for that case is
design-and-stop).
**Lane:** shipped default — Darwin/AArch64 native DSR (`--exec-backend native`),
cold `go build` canonical fixture.

## 0. The re-opened STOP, restated per the plan

The 2026-08-03 fault-ownership document closes with **"STOP — the named
translation-publication memory mechanism does not clear the 10% total-CPU gate…
No production memory change is authorized."** That STOP was issued *under the
≥10% single-mechanism policy*, and only the opportunity gate failed — the
measurement itself was accepted. The category-collapse spec §3 Move 0 and
category-budgets §5 supersede that policy (the ≥10% gate "remains an
attribution filter but stops being a veto"), which is the authority under which
this entry ranks the same territory. What is *not* relaxed is the ABBA
retention discipline: this entry authorizes a successor's design, not its
retention.

## 1. The question

E0 measured **553,526 zfod inside guest `mmap` service windows** — 36.0% of all
build zfod
([`2026-08-06-build-lane-amplification-ledger.md`](2026-08-06-build-lane-amplification-ledger.md)
§7). Task 5 then refuted the hypothesis that ranked E1 first: the build's
file-private mmap population is 18 calls / 3.8 MiB, which cannot own
553k × 16 KiB ≈ 8.6 GB of first touch. Its review bounded the identified
anonymous *commit* population (570 `MAP_FIXED` commits ≈ 701.5 MiB + 716 plain
≈ 2,313.7 MiB ≈ 188k pages) at **≤ ~34%** of the mass, leaving ~365k faults
unattributed, and required this closure before any successor is coded
([`task-5-report.md`](../superpowers/sdd/2026-08-06-move3-amplification-ledger/task-5-report.md)
§4).

This entry partitions the mass into the four candidate owners the brief names:
(a) the guest's own first touch, (b) carrick's whole-range zero-fill scrub,
(c) carrick's own heap allocated while servicing the op, (d) anything else.

## 2. Authority

- Source at capture: HEAD `e7501317` (= `ca96024a` + one doc-only commit)
  plus this entry's uncommitted parser extension and docs — the recorded
  `git_dirty: true` is exactly those files (`native_fault_profile.rs`,
  `carrick-runtime/src/lib.rs` re-export, AGENTS.md, the plan note, this
  document); no runtime dispatch/memory path differs from HEAD, and the
  partition numbers reproduce the *pre-change* binary's raws (below) to
  0.05%, which is the stronger check.
- Fresh HEAD confirmation: two `carrick trace --profile native-fault
  --summary-jsonl` captures, binary `e0c8997e…` (`just build`, codesigned,
  `__dof_carrick` present), same digest-pinned image
  `carrick-go-conformance@sha256:357a…` and canonical fixture as E0; run ids
  `task6e2a4391` / `task6e2b4582`, both rc 0, `BUILD_OK` once each, zero
  run-id survivors after `scripts/sudo/kill.sh`, zero
  identity/lifecycle/catalog/probe violations, natural completion. The host
  was verified quiet by hand (1-min loadavg 2.90/2.93, no stray
  carrick/cargo/`yes` processes) — `--preflight-quiet-host` is not used
  because only the AMP1 header carries the receipt field (the launch refuses
  it for other profiles; first-arming note for Task 3's flag). Receipts:
  `target/perf/task6-e2/` (`nfault-head-{a,b}.raw` + `.summary.jsonl`,
  `capture.log`, `head-partition-summary.txt`). Counts are the claim; the
  fault instrument's perturbation is VERY HIGH and no wall from any traced
  run is citable.
- Corroborating offline join: the **existing Task-4 receipts unchanged**
  (`target/perf/task4-e0/nfault-{a,b}.raw`, captured at the `623ea52b` tip,
  binary `2913209a…`, same image/fixture, both rc 0, zero drop/violation
  counters — the same pair E0's §7 ownership verdict rests on), joined by
  `target/perf/task6-e2/offline-join-e0arms.txt`. Two binaries two days
  apart, one partition.
- Gate: `just ci` exit 0 at the parser change
  (`target/perf/task6-e2/just-ci-2.log`).

## 3. The partition

Per-fault classification of every `during-operation` zfod (the fault fired
while a guest memory op's service window was open on the faulting thread),
joined to its completed memory-intent record and classified by (op sub-shape ×
fault locus). Locus vocabulary: **own-biased-backing** = the op's own range
reached through the per-process host bias (`guest_va + bias`,
`carrick-dsr/src/address.rs` `BIAS_CANDIDATES`; the live captures selected
`0x80_0000_0000`); **carrick-host** = below every bias candidate (carrick's own
heap/images/JIT); **other-high** = at-or-above the lowest candidate but outside
the op's own range.

**Instrument note.** No new capture instrument was built and the D program is
unchanged (`program_sha256` identical to E0's): the NFAULT2 raw already carried
every needed record — exact `fault-event` lines with page addresses and the
active op, plus `memory-intent` lines with args and retval. What was missing
was the *join*, which this entry adds to the typed parser as summary schema
**`carrick.native-fault-attribution.v4`** (`memory_fault_partition` section,
closure-asserted against `memory_census.active_memory_faults`, host-bias
candidates imported from the runtime's `carrick_dsr::address::BIAS_CANDIDATES`
re-export, not hand-copied). Every future native-fault capture now publishes
this partition, which is the successor's red-first gate.

E0-tip arms (offline join over the committed Task-4 raws; both arms, agreeing
to 0.01%):

| slice | owner | arm A | arm B | share of in-window |
|---|---|---:|---:|---:|
| **(b) whole-range scrub, op's own biased backing** | carrick `zero_anonymous_reuse` | **550,100** | **550,086** | **99.41%** |
| — of which: 66 hint-less **128 MiB `PROT_NONE` reserves** | | 540,475 | 540,472 | 97.7% |
| — `MAP_FIXED` commits (Go `sysMap`) | | 5,787 | 5,782 | 1.0% |
| — plain anon + smaller reserves | | ~3,840 | ~3,830 | 0.7% |
| (c) carrick host heap (< every bias candidate) | libmalloc during service | 2,999 | 2,987 | 0.54% |
| (d) file-path residue (pre-E1 eager materialization + loader) | | 244 | 242 | 0.04% |
| (a) guest natural first touch in-window | — | 0 by construction | 0 | 0% |
| **total in-mmap-window zfod** | | **553,343** | **553,315** | 100% |

(Full bucket listing, including the 74/80 non-mmap in-op faults that close the
export total exactly: `target/perf/task6-e2/offline-join-e0arms.txt`.)

Fresh HEAD typed arms (schema v4 summaries, post-E1 binary `e0c8997e…`; every
row closure-asserted against `active_memory_faults`, 553,595 / 553,351):

| slice | HEAD arm a | HEAD arm b | share |
|---|---:|---:|---:|
| (b) scrub, own biased backing (reserve + fixed-commit + plain + madvise) | 550,331 | 550,101 | **99.41%** |
| — `mmap-anon-reserve / own-biased-backing` alone | 544,014 | 543,802 | 98.27% |
| — `mmap-anon-fixed-commit / own-biased-backing` | 6,015 | 6,014 | 1.09% |
| (c) carrick-host in-window (all shapes) | 3,041 | 3,029 | 0.55% |
| (d) `mmap-file-private / other-high` | 221 | 220 | 0.04% |

The four arms — two binaries, two days apart, offline join vs typed v4 — agree
on every headline row to 0.05%. The HEAD ownership census in the same
summaries reads host-other zfod 62.997% / 63.185% (scaled 963,520 / 967,040),
consistent with E0's confirmation pair.

**Slice (a) sits outside the window by construction** (guest code does not run
inside its own syscall's service window). Its measured size *today*: the
ownership census's guest-owned scaled estimate (~563k) minus the in-window
guest-biased mass (~550k) leaves **~10–13k guest natural first-touch zfod per
build** — the scrub pre-faults nearly every guest page before the guest can
touch it.

## 4. The mechanism, code-cited

The chain, verified record-by-record in the raws (worked example pid 81348,
arm A):

1. Go's runtime probes its arena hints: ~63 hinted 64 MiB `PROT_NONE` reserves
   at `0x14_0000_0000_0`-style addresses all fail on this lane (carrick answers
   an unplaceable hint with address 0 — sequences 10–72), so Go falls back to
   **hint-less** reserves.
2. Earlier, seq 8/9 allocated and immediately munmapped a 64 MiB reserve at the
   bump frontier. The munmap lowered `mmap_next`, but
   `mmap_dirty_high` had already been raised to that allocation's END —
   `next_mmap_address` raises it on **allocation**, not on any write or even
   writability (`dispatch/mem.rs:1447,1478`). Nothing in the range was ever
   touched, or even touchable (`PROT_NONE` for its whole life).
3. Seq 73: the hint-less **128 MiB `PROT_NONE` reserve** bumps back onto that
   address, `requested < mmap_dirty_high` → `reused=true`
   (`dispatch/mem.rs:1477`; the free-region arm at `:1466` returns
   `reused=true` unconditionally).
4. The scrub gate — `(reused || fixed_anonymous)` at `dispatch/mem.rs:2347` —
   runs `zero_anonymous_reuse(address, FULL length)` **before** the
   `PROT_NONE` branch at `:2378`, so a reserve the guest cannot even read is
   eagerly memset end to end.
5. On this lane `zero_anonymous_reuse` is the trait default → `zero_backing`
   (`carrick-guest-mem/src/lib.rs:456`), i.e. the single-lift **memset**
   (`carrick-dsr-aarch64/src/mapped_memory.rs:4004`). The write walks the
   range's host backing at `guest_va + 0x80_0000_0000`: arm A shows one
   contiguous 8,192-page run at exactly `[retval+bias, retval+bias+128MiB)`
   per op — 8,189 of the op's 8,230 faults; the other ~41 are libmalloc
   (slice c).
6. 66 such ops per build (one per guest process, Go startup) × ~8,192 fresh
   pages = **540k zfod ≈ 8.3 GB of zero-fill first touch, for memory that is
   provably zero already** (never touched, half of it never even allocated
   before — the stale test is a single boolean on the start address, and the
   scrub length is the full request).

Why the record misread this twice:

- **The E1-review's ≤34% bound silently excluded `PROT_NONE` reserves** from
  the scrubbable population (it summed only the *commit* shapes). The reserves
  are 4,691 calls / ~343 GiB of requested bytes, and the 66 that land on
  "stale" addresses are exactly the missing ~365k faults. The bound was
  arithmetic on the wrong population, not a wrong measurement.
- **The fault-attribution D script's "guest-arena" windows are guest VAs**
  (`[0xa0_0000_0000, 0xa8_0000_0000)` etc.), but under the biased address mode
  every fault lands at `guest_va + bias`, so that export scope is dead code —
  476 hits per build against 553k in-window events. The in-op export (which is
  thread-temporal, not address-based) is what caught the mass. The ownership
  census is unaffected — its owned-range catalogs are host ranges and already
  include the biased backing (its guest-owned ~563k ≈ this entry's ~550k
  in-window own-backing plus the natural residue).

## 5. Cross-instrument closure

One story, three instruments, no silent gaps:

| quantity | value | instrument |
|---|---:|---|
| in-window zfod (AMP1, E0 arm A) | 553,526 | `carrick trace --profile native-amplification` |
| in-window zfod (AMP1, e1on, post-E1) | 552,996 | task-5 receipts |
| in-op zfod (NFAULT2, arms A/B) | 553,417 / 553,395 | this entry's join |
| — scrub own-backing (b) | 550,100 / 550,086 | v4 partition |
| — carrick heap in-window (c) | 2,999 / 2,987 | v4 partition |
| guest-owned sampled zfod, scaled | ~563k (36.74%) | birth-keyed ownership census |
| host-other sampled zfod | 63.26%/63.30% (≈970k) | ownership census (E0 §7, CONFIRMED) |
| unexported (outside ops, non-arena-window) | 982,254 | NFAULT2 census |

- The **host-other 63.3%** mass is untouched by this entry: it remains
  carrick's own allocation churn (owner portfolio at HEAD:
  `publication-recovery` 52.1%, `publication-map` 14.1%,
  `block-assembler-transient` 10.6% of 30.2 GB requested — E0 §9). That is
  E2-proper and its fix (owner-by-owner reuse) is a different program from
  this entry's successor.
- **Residual row:** in-window (c)+(d) ≈ 3,240 events (0.6%) are attributed but
  not worth a lever; out-of-window guest-owned ~10–13k is slice (a) today.
  Nothing else remains unattributed: partition rows close exactly against
  `active_memory_faults` (analyzer-asserted), and exported+unexported equals
  the exact zfod total (pre-existing census assertion).

## 6. Verdict

**The in-window fault mass belongs to slice (b): carrick's own whole-range
zero-fill scrub — 99.4% — and within it, 98% serves hint-less `PROT_NONE`
reserves that are already zero.** It is not the guest's memory being touched
(a), not allocation churn (c: 0.54% in-window), and not the file-mmap path E1
attacked (d: 0.04%). E0 §7's working hypothesis ("the guest-owned fault mass
is mostly E1's destination-copy touches") is now doubly refuted: the guest-owned
mass is the **scrub's** touches.

A second misattribution was caught before coding, as the brief priced: the
Task-5 successor chip's framing ("the scrub is the real E1 mass") is
*confirmed in mechanism but was unsized*; this entry sizes it and shows the
population is dominated by reserves, which changes the fix's shape (the
`MAP_FIXED`-commit scrub is only 1% of the mass — a commit-side-only fix would
be near-worthless).

## 7. The successor: kernel-side anonymous-reuse replacement (design; NOT implemented)

**Template:** the x86 identity backend already does this —
`carrick-dsr/src/identity_memory.rs:1275` (`zero_anonymous_reuse`) replaces the
range with `mmap(host_va, len, RW, MAP_FIXED|MAP_ANON|{PRIVATE|SHARED})`:
fresh zero pages from the kernel, **zero touches, zero zfod at scrub time**,
sharing preserved through the typed seam, failure leaves the old mapping
intact. The aarch64 lowering is the same call at `host_address(guest_va)`
(the biased VA), with these lane-specific obligations:

1. **Eligibility mirrors `zero_backing`'s existing carve-outs:** single
   region (`region_contains`), NOT `range_may_execute` (W^X metadata and
   translation invalidation need the write path), not the linux4k subpage
   lane. Ineligible ranges keep the memset.
2. **Protection re-establishment is the correctness edge.** The memset path
   writes *through* a temporary lift and restores the prior host protection;
   a `MAP_FIXED` replacement comes back RW. The override must re-apply the
   recorded native protection state for the range (from `native_prot_ranges`)
   after replacement — callers do not all re-protect (brk/madvise sites), and
   a stage-1-invalidated (host `PROT_NONE`) reclaimed range must not become
   readable. This, plus the `host_access_lifts` interplay, is why this is not
   a small change.
3. **Sharing:** `MappingSharing::Shared` maps `MAP_SHARED` (the typed seam's
   whole point); the shared-aperture arm keeps its own path.
4. **Gates, in order (all standing):** red-first probe (reused range reads
   back zero; prior protection preserved; fork-visibility of a replaced
   shared range) → `just ci` → one-worker conformance-probe delta → the
   **v4 partition row** `mmap-anon-reserve / own-biased-backing → ~0` on a
   fresh capture (this entry's instrument is the red-first evidence) → AMP1
   `amplification-compare` on the mmap row → cold-build ABBA. Retained only
   on an ABBA win; a mechanism win with an ABBA loss is the spec's §6 second
   invalidation condition — stop and report.
5. **Do not** implement the alternative (a writability-epoch dirty tracker
   that skips provably-clean scrubs) first: it is more state, misses
   dirty-reuse, and only helps the case the replacement already makes free.
   Reconsider it only if the replacement's ABBA is a wash.

**Honest ceiling.** Removes up to ~553k zfod/build (36% of all zfod), minus
resurfaced guest natural touches for pages the guest actually uses:
today those are pre-faulted by the scrub, and their upper bound is the
committed-anon population ≈ 188k pages (the E1-review bound, returning as the
resurfacing bound), so the **net fault removal is ~365k–543k/build**. At the
2026-08-01 audit's untraced 1.81–3.84 µs per fault this is **~0.7–2.1 CPU-s
against the 21.391 s build (≈3–10% of total CPU)**, plus ~8.3 GB of memset
writes and their dirty-page/reclaim pressure removed from the host — and the
storm is concentrated at process startup under the exclusive mem guard, so
some serialization relief is plausible but unpriced. Both audit per-fault
figures are load-sensitive; the ABBA decides, and the ≥10% gate is an
attribution filter, not a veto, per §0. Even the top of this band does not
close Move 3's 7.555 CPU-s gap — the out-of-window 63.3% host-other mass
(E2-proper) remains the larger, separate territory.

## 8. Record corrections landed with this entry

- AGENTS.md's fault bullet: the parenthetical attributing the 36% in-window
  mass to "the eager `MAP_PRIVATE` materialization path" is replaced with the
  scrub attribution (Task 5 measured the file-private population at 3.8 MiB;
  this entry names the real owner).
- The plan's §2/E2 gains a measured-partition note (this document).
- Chip filed: the fault-attribution D script's identity-VA "guest-arena"
  export windows are dead under the biased address mode (476 hits) and should
  be re-pointed at the biased ranges or dropped — a D-program change, so it
  re-qualifies `program_sha256` and is deliberately not folded in here.
