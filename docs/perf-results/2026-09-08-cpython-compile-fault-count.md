# cpython-compile: the fault count is linear, not super-linear

**Recorded 2026-09-08.** Base revision `251ab7b4f` (branch
`opus/opus-compile-faults-sep08`). Binary
`26b9db0c046aeb6d3407f4593f0dbe10d023c6226af22b7bcc78e690e184a3ab`
(pre-change control:
`487b72a36a0a7e20508820d8c7b0f68eaecf7517d4e2aa9dfd2ad1f2b6d09ccb`).

## 1. The open item

`docs/conformance-campaigns/2026-09-04-ecosystem.md` (2026-09-08 07:00) closed
the per-fault lookup cost on `cpython-compile` and left one item open:

> the fault count itself is still super-linear (8x depth = 22.8x faults, rows
> 14.9x, lumpy)

The working hypothesis was a lost-mapping / torn-down-window / evicted-leaf
mechanism, i.e. re-faults on pages already materialized.

**That hypothesis is refuted.** The fault count is LINEAR in the guest's
memory footprint; the apparent 22.8x is a constant 128 MiB zero-fault offset,
and carrick already takes FEWER faults than Linux does for the same program at
every depth measured. The instrument is the new
`scripts/dtrace/hvpatch-fault-class-census.d`; the sweep driver is
`target/conformance/eco-load/compile-fault-sweep.sh`.

## 2. Fault classification (new census)

`compile('a' + '()' * D)`, one fresh guest per depth, under
`hvpatch-fault-class-census.d` (counts are exact under this script; wall time
is not citable against an untraced run).

| depth | EL0 aborts | distinct 4 KiB | distinct 16 KiB | distinct 64 KiB | faults / 64 KiB window |
|---:|---:|---:|---:|---:|---:|
| 100,000 | 4,812 | 4,811 | 1,233 | 322 | 14.9 |
| 200,000 | 9,022 | 9,021 | 2,287 | 589 | 15.3 |
| 400,000 | 39,179 | 38,705 | 9,712 | 2,455 | 16.0 |
| 800,000 | 110,258 | 109,105 | 27,316 | 6,862 | 16.1 |

Growth 100k → 800k is **22.9x for 8x depth** — the recorded open item,
reproduced exactly.

By class and kind at depth 800,000 (a second run, 121,898 mmap faults):
`mmap` 121,898, `img` 938, `heap`/`stack`/`low` zero; `xlate` write 117,295,
`xlate` read 4,281, `perm` write 322. So the row is **99.6 % anonymous
mmap-arena WRITE translation faults** — ordinary first touches.

Repeat structure: 1.0 % of faults at depth 800k are a page this run already
faulted (2.6 % at 100k). There is no re-fault term to speak of: not a lost
mapping, not a torn-down window, not an evicted stage-1 entry.

Service arm (depth 400,000): `stale_retries=0`, `delivered=0`,
`serviced_by_plan=39,179`. **Every single fault is serviced by
`resident_fault_plan` → `protect_range(page, LINUX_PAGE_SIZE, prot)` in
`crates/carrick-runtime/src/vcpu_loop/signal.rs`.**

## 3. Why the count looks super-linear: a 128 MiB offset

Docker oracle (native arm64, `localhost:5050/cpython-test:3.12.13`), **one
fresh process per depth** — measuring all four depths in one process is the
trap that makes Linux look sub-linear, because later depths reuse pages the
earlier ones already faulted:

| depth | Linux minflt (compile only) | Linux VmHWM | Linux secs |
|---:|---:|---:|---:|
| 100,000 | 19,108 | 82.8 MB | 0.081 |
| 200,000 | 37,657 | 156.7 MB | 0.143 |
| 400,000 | 74,227 | 304.7 MB | 0.272 |
| 800,000 | 146,848 | 600.6 MB | 0.557 |

Linux is **linear**: 8x depth costs 7.68x faults and 7.3x memory.

Carrick's arena faults are that same linear footprint minus a constant: the
128 MiB brk heap (`LINUX_HEAP_BASE` + `LINUX_HEAP_SIZE`,
`crates/carrick-mem/src/memory.rs`) is mapped eagerly and costs **zero**
faults, so only the part of the guest's footprint that spills past it reaches
the sparse arena and faults.

| depth | Linux VmHWM − 128 MiB | carrick arena faulted (4 KiB × distinct) |
|---:|---:|---:|
| 200,000 | 28 MB | 35 MB |
| 400,000 | 176 MB | 151 MB |
| 800,000 | 472 MB | 426 MB |

A linear function with a large negative offset grows super-linearly in RATIO
terms over any range that starts near the offset. That is the whole of the
"22.8x". **There is no super-linear mechanism to fix, and the open item is
retired.**

The corollary matters more than the retirement: carrick's fault count is
**0.25x** Linux's at depth 100k and **0.84x** at 800k. The row's cost is
per-fault COST, not fault count.

## 4. The 16x publication/materialization mismatch (real, and deliberate)

Every depth shows ~16 EL0 aborts per distinct 64 KiB fault window. The
mechanism is exact and is not a defect of the window:

- `HvfInner::ensure_sparse_mmap_backing` widens a `len == PAGE_SIZE` first
  touch to a 64 KiB window (`DEFAULT_FAULT_WINDOW_BYTES`) and materializes the
  whole window: one host mapping, one stage-2 lease, one inventory frame per
  16 KiB compound.
- `resolve_mutating_fault` then publishes the stage-1 leaf for **one 4 KiB
  page** — `ResidentFaultPlan` carries `page` + `prot` and discards the range
  it was found in, and `commit_resident_fault` marks exactly one page
  resident.

So the backing is batched 16:1 and the trap is not. This is **deliberate**:
`crates/carrick-runtime/src/dispatch/mem.rs` (the `CARRICK_MINCORE_EXACT`
arm) states it outright — "one trap per anonymous page on first touch — paid
deliberately" — because `resident_ranges` is the `mincore` answer for
post-exec anonymous VMAs, host residency is only exact per 16 KiB Darwin page,
and Linux populates anonymous private memory one page per fault (LTP
mincore03). Widening the publication to the window would make `mincore` report
a window-granular answer where Linux reports a page-granular one.

Two things were checked before concluding that:

- **`CARRICK_MINCORE_EXACT=0` does not remove these faults.** The hatch is
  short-circuited by `defer_anonymous ||` in the `mmap` arm, and the deferred
  arena path — which is the one CPython's compile arena takes — arms the
  per-page fault regardless. Measured: 800k reducer 2.707 s with the hatch on,
  2.711 s with it off.
- **There is no hardware access-flag alternative on this host.** FEAT_HAFDBS
  would let a leaf be published valid with `AF=0` so the hardware records the
  touch without a trap, and `mincore` could read `AF` per 4 KiB leaf. Qualified
  live from inside a guest (carrick already emulates the EL0 `MRS` of the
  feature-ID space, `crates/carrick-vmm-hvf/src/trap.rs`):
  `ID_AA64MMFR1_EL1 = 0x0000_1000_1131_2000`, **HAFDBS = 0** on Apple M4 under
  HVF. The approach is closed on this hardware.

## 5. Does the window earn its keep? Yes, decisively

`CARRICK_FAULT_WINDOW_BYTES` sweep, depth 800,000, two runs each, same load
window (1-min load 5.5 → 11.6 across the sweep, so only the within-sweep
ordering is citable):

| window | run 1 | run 2 |
|---:|---:|---:|
| 4 KiB | 185.7 s | 293.6 s |
| 16 KiB | 11.3 s | 6.4 s |
| 64 KiB (default) | 6.3 s | 6.1 s |
| 256 KiB | 7.9 s | 5.7 s |

At 4 KiB every fault materializes, the mapping and alias populations grow 16x,
and the row degrades ~30-48x. 64 KiB sits at the knee; 256 KiB buys nothing.
The default is right.

## 6. Where the per-fault cost actually is

At depth 800,000 near-quiet (1-min load 5.3): carrick 2.71 s vs Docker
0.557 s. The excess over 110,258 faults is **19.5 µs per fault** (Linux's own
is under 1 µs).

`hvpatch-mapping-index-census.d` on the same reducer puts
`ensure_sparse_mmap_backing` at a **2.4 µs mean** (census-inflated; 321.8 ms
of service across the run), i.e. **at most ~12 %** of the per-fault excess.
The remaining ~17 µs is the EL0 abort round trip plus the dispatcher and
`protect_range` publication path — the mm-mutation authority, two `mem` lock
acquisitions (plan and commit), the stage-1 edit, and
`observe_frame_cow_protection`. **That is the next attribution on this row**,
and it is a per-fault-cost problem, not a fault-count one.

## 7. Instrument caution: a profile taken under `carrick trace` is not steady state

`docs/perf-results/2026-09-07-cpython-compile-attribution.md` ranked
`ProcessContext::trace_fault` at **30.1 % of CPU**. That profile was taken
with `carrick trace` attached, which ENABLES the guest-fault probes — so what
it measured was the cost of firing probes a consumer had asked for, not a
steady-state cost.

Acting on it here produced no measurable win. The three per-fault costs that
only a delivered or traced fault needs were made lazy
(`diagnostic_fault_page_tables` behind `pt_fault_with`, the MM-binding read
behind `hvpatch_guest_fault_with`, and `capture_kernel_context` hoisted below
the resolve attempt). Four interleaved A/B pairs at depth 800,000, load 8-13:

| pair | before | after |
|---:|---:|---:|
| 1 | 2.678 | 2.668 |
| 2 | 3.324 | 3.736 |
| 3 | 3.591 | 3.947 |
| 4 | 4.562 | 4.149 |

Two favour before, one is a tie, one favours after: **no measurable
difference.** The change is kept because it removes work a disabled probe
cannot use — the contract the two probes immediately upstream in the same
fault arm (`vcpu_fault_regs_with`, `vcpu_fault_gprs_with`) already document —
but it is recorded as a neutral result, not a win.
