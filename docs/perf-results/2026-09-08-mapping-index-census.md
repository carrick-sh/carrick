# The residual super-linearity is the ALIAS registry, not the mapping index

**Recorded 2026-09-08.** Binary `2576a8793c2333fe` at `b3d5cba62`
(branch `opus/compile4-sep08`), built through `just build`; hypervisor
entitlement and `__dof_carrick` both present. Host load 10.4-16.0 across every
capture, recorded per run in `target/perf/compile4/*.meta`.

[`2026-09-08-mapping-index-measurement.md`](2026-09-08-mapping-index-measurement.md)
closed with three open items and named the reason the other two were open:
"the per-fault scan COUNT was never instrumented. No probe reports it." This is
that count.

## The instrument

`hvpatch-mapping-index-begin` / `-fault` / `-cost`
(`crates/carrick-observability/src/probes.rs`), read by
[`scripts/dtrace/hvpatch-mapping-index-census.d`](../../scripts/dtrace/hvpatch-mapping-index-census.d).
One record per `HvfInner::ensure_sparse_mmap_backing` call — the
anonymous/private first-touch service — carrying the live row population of
BOTH structures a fault consults, the rows each one's walks visited **for that
fault**, and the service nanoseconds.

The visited counts are differences of the per-thread `HotPathScan` counters
across the call, so they are that fault's walk length, not a running total.
They are structural: they do not vary with host load, which is why they are
readable at load 10-16 where the wall-clock columns are not.

Perturbation is declared in the script header and is one-sided: the row
counting is one thread-local `Cell` add per visited row and is always on, while
the timestamps, the registry lock and the probe fires happen only while the
`begin` probe is enabled. The `ns` columns are therefore inflated and only
same-instrument ratios are citable; the ROW columns are exact.

## The census

Reducer `compile('a' + '()' * DEPTH, '<test>', 'single')`, `--fs host`,
`localhost:5050/cpython-test:3.12.13`:

| depth | faults | index rows | index visits | **per fault** | alias rows | alias visits | **per fault** | service ns |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100,000 | 5,752 | 1,270 | 9,802 | **1.70** | 1,257 | 1,963,695 | **341** | 37.0 ms |
| 200,000 | 11,049 | 1,802 | 18,101 | **1.64** | 1,789 | 4,006,622 | **363** | 71.3 ms |
| 400,000 | 45,431 | 10,015 | 73,639 | **1.62** | 10,002 | 24,748,685 | **545** | 419 ms |
| 800,000 | 131,425 | 18,746 | 209,012 | **1.59** | 18,733 | 111,294,130 | **847** | 1467 ms |

("index rows" is the largest live `TaskMappingIndex` population the run
reached; "alias rows" the matching `AliasRegistry` total. Displaced rows were
1 in every bucket of every run.)

## What is super-linear, named

**Not the `TaskMappingIndex`.** Its walks visit **1.59-1.70 rows per fault**,
and that number FALLS slightly while the row population it is walking grows
**15x**. The ordered VA map and the IPA view are doing exactly what they were
built to do; there is no full-table walk left in that structure. Over 8x depth
its total visited rows grow 21.3x — that is the fault count growing, not the
per-fault cost.

**It is the `AliasRegistry` VA-window walk.** Per fault it visits 341 rows at
depth 100,000 and 847 at depth 800,000 — 2.5x more work per fault for the same
kind of fault — and in absolute terms it visits **111 million rows** against
the mapping index's 209 thousand at depth 800,000, a factor of **532**.

The mechanism is exact, and the census measures it directly. Six call sites ask
"which alias rows' VA windows overlap this probe range" as

```rust
registry.by_va_start.range(va.saturating_sub(registry.widest_va)..end)
```

`widest_va` is a **monotone global maximum** — its own comment says "Only ever
grows: a stale-wide bound makes a query walk further than needed, never miss a
row." So the walk length is *(rows registered inside a `widest_va`-wide VA
window)*, which is a property of the POPULATION, not of the answer. The census
reports `widest_va` growing 6,615,040 → 8,392,704 → 16,781,312 bytes across the
sweep, and the arena is densely packed with per-extent rows:

| depth | `widest_va` | window / 4 KiB | alias visits per fault | ratio |
|---:|---:|---:|---:|---:|
| 100,000 | 6.31 MiB | 1,615 | 341 | 0.21 |
| 400,000 | 8.00 MiB | 2,048 | 528 | 0.26 |
| 800,000 | 16.00 MiB | 4,096 | 1,026 | 0.25 |

The per-fault walk is a fixed fraction of the window width in pages, in every
run. One live large mapping widens the window for every later query, and every
materialized extent adds a row inside it.

## The consequence for the briefed representation change

Round 4's brief asked for "one owner per VMA run" so `can_coalesce_mappings`
can fire and `TaskMappingIndex` rows stay O(#VMAs). **The census says that
would not move this workload.** The index already visits 1.6 rows per fault
with 18,746 rows in it; collapsing those rows to a few hundred cannot reduce
1.6. The row count is a memory cost, not a time cost, on this path.

Two further findings bear on it, recorded so the next attempt does not pay for
them again:

1. **The per-extent owner is not the only coalescing blocker, and probably not
   the binding one.** `can_coalesce_mappings` additionally requires
   `left.ipa + left.size == right.ipa`, host-pointer adjacency, physical
   adjacency, and `stage2_lease`/`host_mapping`/`structural_owner` all absent
   on both rows. Sparse materialization gives every extent its **own host
   `mmap` and its own IPA** (`sparse_materialization::prepare` allocates a
   fresh `OwnedHostMapping` or a pooled compound per extent), so consecutive
   extents are not physically adjacent and would still refuse to merge even if
   they shared one `owner_generation`. Making them mergeable means changing
   what a first-touch materialization ALLOCATES, not just how it is labelled.
2. **The fault count is itself super-linear** and no change here addresses it:
   8x depth costs 22.8x faults, and the row population grows 14.9x, lumpily
   (1,789 rows at depth 200,000 becomes 10,002 at 400,000). That is a
   workload-shape observation, not an attributed defect; it is unexplained.

## Still open

1. The fault-count and row-population growth above.
2. The IPA axis of the registry keeps the same monotone bound (`widest_ipa`).
   It was not hot on this workload and is not measured here.
