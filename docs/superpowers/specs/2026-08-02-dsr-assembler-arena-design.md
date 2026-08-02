# DSR block-assembler heap: attribution, ceiling, and the staged plan

**Date:** 2026-08-02 · **Status:** plan only — nothing implemented, no crate
source touched. · **Lane:** Darwin/aarch64 native DSR (`--exec-backend native`,
the shipped default). No VMM/HVF/KVM/bhyve behaviour is in scope. · **Campaign
task:** #14 (heap/allocator).

---

## 0. The verdict, up front

**This workstream does not clear the campaign's bar, and the plan says so
before it says anything else.**

The complete pot addressable by *any* change to carrick's own heap is **17.1% of
total CPU** on the reference cold `go build`. The share of that pot owned by the
DSR block assembler — the thing this task is named after — is **12.5% of total
CPU**, and that is the ceiling reached only if the assembler's entire heap
footprint went to literally zero. The realistic band is **1.2% to 12.2% of
CPU**, i.e. a build-lane wall of **14.48x → between 14.3x and 12.7x**.

AGENTS.md is explicit that "a 3-15% improvement does not move a 14.5x ratio".
Every outcome of this workstream lands inside that band. It is worth doing only
as a cheap, contained follow-on, and it must not be sold as progress toward the
2x bar.

Three further findings that change how the work should be shaped:

1. **The largest single lever here is not the assembler at all.** If Phase 0
   shows that carrick's heap faults track *cumulative* allocation rather than
   *peak* footprint, the highest-leverage move is **allocator policy** — stopping
   Darwin's libmalloc from returning and re-faulting heap pages — which reaches
   ~15.8% of CPU across carrick's whole heap, not just the assembler's 73% of
   it, and needs no assembler surgery. carrick has never chosen an allocator:
   there is exactly one `#[global_allocator]` in the tree and it is the
   `alloc-census` instrument (`crates/carrick-cli/src/main.rs:165`).
2. **The compact retained representation already exists in this tree, measured,
   and is simply not used on the default path.** The shared/mapped unit path
   stores recovery metadata as run-length spans against a deduplicated action
   pool (`crates/carrick-dsr-aarch64/src/mapped_metadata/wire.rs:259`,
   `:267`) — 16 bytes per *run* — while the private JIT path retains a
   `Vec<RecoveryEntry>` at **72 bytes per 4-byte instruction**. The V3 design
   measured the coalescing at 3,456,821 entries → 454,986 runs (**7.60x**)
   on go-build-shaped data
   (`docs/superpowers/specs/2026-07-31-native-mapped-translation-metadata-design.md:28`).
3. **The two attempts already rejected on measurement both changed the
   allocation *strategy* and left the *representation* alone.** That is why they
   failed, and it is the one rule this plan is built around.

Ranking against task #13 (whole-image AOT / translation coverage, ceiling
14.5x → 10-11.5x) is in §8: **#13 is the better investment**, and neither
reaches the bar.

---

## 1. Evidence this builds on — do not re-derive

Everything in this section is measured and committed. Cite it; do not re-run it
to start this work.

| fact | value | source |
|---|---|---|
| build-cold workload wall | 11,728 ms vs Docker 810 ms = **14.48x** | `docs/perf-results/2026-08-01-native-wall-audit-and-fault-cost.md` §1 |
| carrick's own host userspace | **36.9%** of CPU, "has never been attacked" | AGENTS.md; measured 35.8% / 12.29 CPU-s at `docs/perf-results/2026-07-29-native-cpu-budget-evidence.md:563` |
| page faults | **25.7%** of CPU (kernel-non-syscall bucket 30.7% incl. sched/interrupts) | AGENTS.md; `2026-07-29-native-cpu-budget-evidence.md:17` |
| syscall bodies | 9.9% of CPU | AGENTS.md |
| zfod (first touch of anon) | 1,780,734 of 2,129,690 `as_fault` = **83.6%** | `2026-08-01-native-wall-audit…md` §3 |
| **carrick's own Rust heap** | **1,254,000 zfod = 66.7% of zfod ≈ 20.5 GB** | `2026-08-01-native-wall-audit…md` §4 |
| guest mmap arena (`zero_backing`) | 561,394 zfod = 29.9% ≈ 9.2 GB | ibid. |
| **DSR block assembler share of carrick's heap traffic** | **73%**, allocated fresh per translated block | `handoff.md:126`; census table at `2026-08-01-native-wall-audit…md:272` |
| translations per cold build | **433,249** over **107,320** distinct guest VAs (1.00x intra-process, 4.04x cross-process) | `2026-08-01-native-wall-audit…md` §5 |
| the heap is invisible to syscall instruments | 2,172 `mmap` calls against 1.88M zfod; libmalloc sub-allocates | ibid. §4 |
| recovery run-encoding ratio | 3,456,821 entries → **454,986 runs (7.60x)** | `docs/superpowers/specs/2026-07-31-native-mapped-translation-metadata-design.md:28` |

The census table itself (dhat, `--features alloc-census`), reproduced for
reference — note the line numbers are from that run and have since drifted:

| bytes | allocations | site |
|---|---|---|
| 3.63 GiB | 1,212,262 | `emit.rs` `recovery.push(RecoveryEntry)` |
| 1.06 GiB | 851,303 | `emit.rs` `VecAssembler::new` + `entries` |
| 0.18 GiB | 203,247 | `emit.rs` |
| 0.57 GiB | — | `dynasmrt` VecAssembler / reloc / label registries |

Sum: **5.44 GiB** attributed to the assembler over that run's process coverage,
which the source doc scales to ~20.4 GB of total heap traffic across all ~70
processes.

**Two honesty notes carried forward from the source doc, both load-bearing:**

- The census's "large zone" label was **corrected in place**: the dominant sites
  average 1-3 KiB, i.e. libmalloc's *small* zone. The `0x7x_xxxx_xxxx` window
  decomposition stands; the label does not.
- The census's own translation count ("~800k per cold build") **disagrees** with
  the `CARRICK_XLAT_CENSUS_DIR` measurement in the same document (433,249 over
  34 processes). Under a `Vec` doubling ladder the published byte and allocation
  counts are not mutually consistent with either figure, so **per-block entry
  counts are NOT derivable from the committed table**. Phase 0 measures them
  directly rather than inferring them. This plan uses 433,249 (the direct
  instrument) wherever a translation count is needed.

---

## 2. Attribution: what the assembler allocates, and what survives publication

The assembler is `assemble_block_inner`
(`crates/carrick-dsr-aarch64/src/emit.rs:5912`). Its allocation prologue is at
`emit.rs:5919-5934`; it finalizes at `emit.rs:7035-7050`.

### 2.1 Measured type sizes

Obtained this session by linking `carrick-dsr-aarch64` at HEAD into a scratch
binary outside the workspace and printing `size_of`/`align_of` (no crate source
modified). Reproduce with a path-dependency crate; the numbers are load-bearing
for everything below.

| type | size | align | note |
|---|---|---|---|
| `PcMapEntry` | **16 B** | 8 | `guest: GuestVa` (u64) + `cache: CacheOffset` (u32) + 4 B pad |
| `RecoveryEntry` | **72 B** | 8 | `cache` (u32) + 4 B pad + `RecoveryAction` |
| `RecoveryAction` | **64 B** | 8 | sized by its largest variant, `RecoverBiasedMemory(BiasedMemoryRecovery)` |
| `DirectLink` | **32 B** | 8 | |
| `Vec<T>` header | 24 B | 8 | |
| `Box<[T]>` header | 16 B | 8 | |

**`RecoveryEntry` is 72 bytes and most entries are unit variants.** A
`RecoveryAction::RestoreGuestX17` carries no payload whatsoever, and it is the
single most-emitted action (14 distinct emission sites in `emit.rs`; the
`step_by(4)` loops at `emit.rs:1068`, `:1655`, `:2178`, `:5192`, `:6099`,
`:6237`, `:7004`, `:7027`, `:8208`, `:8267`, `:9229`, `:9286` push **one entry
per 4-byte emitted word** across exit regions, guard regions and direct-link
stubs). The retained cost of recording "restore x17 here" is 72 bytes, of which
64 are slack reserved for a variant that region never uses. That is where the
bytes are, and it is a *representation* problem, not an allocation-strategy
problem.

### 2.2 Transient vs retained — the split that decides the strategy

`AssembledBlock` (`emit.rs:121-132`) → `publish` (`emit.rs:161-177`) →
`EmittedBlock` (`emit.rs:108-119`) → `ProcessState::publish_emitted`
(`translator.rs:3917`, `let (map, links, recovery) = emitted.into_runtime_metadata();`)
→ `PublishedBlockMetadata::Owned` (`translator.rs:1447-1452`).

| allocation | site | fate | classification |
|---|---|---|---|
| `VecAssembler` internal code buffer | `emit.rs:5919` | `finalize()` → `instruction_bytes`, copied into the JIT cache by `writer.write_instruction_bytes`, then dropped | **TRANSIENT** |
| dynasmrt reloc + label registries | inside `VecAssembler` | dropped at `finalize()` | **TRANSIENT** |
| `direct_links: Vec<DirectLink>` | `emit.rs:5933` | consumed by the `for link in links` loop in `publish_emitted` (`translator.rs:3955`); never stored | **TRANSIENT** |
| `instruction_words()` staging `Vec<u32>` | `emit.rs:154` | only when `CARRICK_DSR_DIRECT_BYTES=0` (a deliberate same-binary control arm) | **TRANSIENT, control-arm only** |
| `#[cfg(test)] words: Vec<u32>` | `emit.rs:7045` | test builds only | not in production |
| `entries: Vec<PcMapEntry>` | `emit.rs:5924` | `InstructionMap::new(entries)` → `map` | **RETAINED for the process's life** |
| `recovery: Vec<RecoveryEntry>` | `emit.rs:5934` | moved into `PublishedBlockMetadata::Owned.recovery` | **RETAINED for the process's life** |

`entries` is already `Vec::with_capacity(...)` with an estimate; `recovery` is
`Vec::new()` and grows by doubling, so its retained capacity carries the
ladder's slack forever (mean ~1.4x over `len` for a doubling allocator).

### 2.3 Retained bytes are read only on the exception path

The production consumer of `recovery` is `ProcessState::guest_pc_for_cache`
(`translator.rs:4803`), reached from the trapped-signal and async-kick arms
(`translator.rs:6019`, `:6093`). The `Owned` arm does a **linear scan**:
`recovery.iter().find(|entry| entry.cache == offset)` (`translator.rs:4834`).

This matters: the retained representation is on a cold path already, so it can be
made arbitrarily compact — run-encoded, pooled, bit-packed — with no hot-path
cost. The `Mapped` arm already does exactly that with a **binary search over run
spans plus one indexed pool read** (`mapped_metadata/view.rs:944-991`), so the
compact form is *faster* than what the private path does today, not slower.

### 2.4 The compact representation already exists — and one path actively undoes it

Three recovery representations coexist today:

1. **`Owned.recovery: Vec<RecoveryEntry>`** — private JIT (the default path).
   72 B per emitted word. Linear scan.
2. **`Owned.shared_recovery: Option<SharedRecoveryMetadata>`**
   (`translator.rs:1479`) — V2 shared units, holding
   `artifact_spike::PortableRecoveryMetadata::Runs(Vec<PortableRecoveryRun>)`.
   Run-encoded (`artifact_spike.rs:1575-1604`), but the run record is
   `{ start: CacheOffset, entry_count: NonZeroU32, action: PortableRecoveryAction }`
   — still carries a full inline action.
3. **`Mapped { loaded_unit_index, block_index }`** (`translator.rs:1453`) —
   V3 mapped units. **16 bytes total per published block.** Metadata is
   `WireRecoverySpanV3` (16 B: `cache_offset` u32, `entry_count` u32,
   `action_index` u64) indexing a **deduplicated** `WireRecoveryActionV3` pool
   (48 B, dedup keyed on the raw 48 bytes at
   `mapped_metadata/builder.rs:41`). Zero allocation per block, zero allocation
   at fault time.

Representation (3) is strictly the best and it is the newest. The private path
— the one carrying 433,249 translations per build — is on representation (1).

**A separate, immediately-actionable defect found while attributing this:**
`ArtifactTemplate::take_runtime_metadata` (`artifact_spike.rs:1858-1880`)
takes run-encoded recovery and calls `.into_entries()` to **expand every run
back into one entry per 4-byte instruction**, allocating *two* fresh Vecs per
block (`Vec<PortableRecoveryEntry>` then `Vec<RecoveryEntry>`). It throws the
7.6x compression away at load time. It is reached on the V2 shared arm when
`CARRICK_DSR_SHARED_RECOVERY_LAZY=0` (`translator.rs:3352`). Worth deleting on
its own merits.

---

## 3. The fork that decides the prize — and it is NOT yet measured

A page fault is a **first touch**. So carrick's heap zfod count is governed by
how far the heap's *high-water mark* grows, **unless** libmalloc returns pages to
the kernel (`madvise`/`mach_vm_deallocate`) and the next allocation re-faults
them. Which of those is true decides this workstream's entire shape, and it has
never been measured.

**Branch (A) — faults track cumulative allocation.** libmalloc returns pages;
churn re-faults. The prize is the ~89% of assembler traffic that is transient,
and — more importantly — the whole-heap allocator-policy lever in Phase 3.

**Branch (B) — faults track peak footprint.** libmalloc recycles within the
process; transient churn is free in fault terms. The only prize is the retained
metadata, and it is small.

**Circumstantial evidence for (A), and why it is not sufficient.** The source
document observes that cumulative heap allocation scaled to all processes
(~20.4 GB) and measured heap zfod (20.5 GB) agree to within 1%
(`2026-08-01-native-wall-audit…md:284`). That is a coincidence-of-magnitudes
argument, not a mechanism — precisely the class of inference that produced this
campaign's four reverts (`handoff.md:196`). **Do not build on it. Measure it.**

The discriminator is cheap and already available: dhat reports both cumulative
bytes and bytes live **at t-gmax**. If per-process at-gmax heap is on the order
of the ~293 MB/process implied by 20.5 GB over ~70 processes, branch (B) holds
and the lever is retained compaction. If at-gmax is an order of magnitude
smaller than cumulative, branch (A) holds and the lever is churn.

---

## 4. Sizing the prize — arithmetic shown

### 4.1 The pot

```
faults                          = 25.7% of total CPU        (AGENTS.md)
carrick's heap share of zfod    = 66.7%                     (wall-audit §4)
=> carrick's whole heap         = 0.667 x 25.7%  =  17.1% of total CPU
assembler share of heap traffic = 73%                       (handoff.md:126)
=> assembler ceiling            = 0.73 x 17.1%   =  12.5% of total CPU
```

12.5% of CPU is what this task is worth **if the DSR assembler's heap footprint
went to exactly zero.** Wall: `14.48x x (1 - 0.125) = 12.67x`.

### 4.2 Splitting the assembler's 14.9 GB into retained and transient

Assembler traffic = `0.73 x 20.4 GB = 14.9 GB` cumulative across the build.

Retained, per block, using the measured sizes from §2.1 and a PC-map entry count
of ~34.6/block (the V3 corpus's 3,708,221 PC-map entries over the union of
107,320 distinct blocks; `InstructionMap`'s own doc comment at `emit.rs:57` says
"~25 entries each", so treat 25-35 as the band and confirm in Phase 0), with
recovery at 0.932 entries per PC-map entry (V3 corpus ratio, `…metadata-design.md:28`):

```
map      : 34.6 entries x 16 B                      =   554 B
recovery : 32.2 entries x 72 B                      = 2,320 B
recovery Vec doubling slack (~1.4x on capacity)     =   928 B
two Vec headers                                     =    48 B
                                                     ---------
retained per block                                  ~ 3,850 B

x 433,249 translations                              =  1.67 GB retained
=> transient = 14.9 - 1.67                          = 13.2 GB  (89% of assembler traffic)
```

### 4.3 What each lever removes

**Retained compaction (Phase 1).** Converge the private path on the V3 shape:
16 B per *run* against a per-process deduplicated action pool. On the measured
7.60x coalescing ratio, `32.2 entries → 4.24 runs x 16 B = 68 B/block`, plus an
exact-size `Box<[T]>` (no capacity slack, 16 B header). The PC map is unchanged
at 16 B/entry unless it is delta-encoded (out of scope here).

```
retained per block: 3,850 B -> 554 + 68 + 32 = ~654 B     (5.9x)
removed:            (3,850 - 654) x 433,249  = 1.38 GB
share of the 20.5 GB heap-fault term:          6.8%
=> CPU removed:     0.068 x 17.1%            = 1.17% of total CPU
```

**Transient elimination (Phase 2), valid ONLY under branch (A).**

```
removed: up to 13.2 GB of 20.5 GB heap zfod  = 64.4%
=> CPU:  0.644 x 17.1%                       = 11.0% of total CPU
```

**Userspace CPU, either branch.** Bounded hard by the measured host-leaf table
(`2026-07-29-native-cpu-budget-evidence.md:569`): `_xzm_xzone_malloc_tiny` is
**0.45%** of total CPU, and `_platform_memmove` (1.16%) + `_platform_memset`
(0.82%) are shared with the JIT-cache writes and guest population that stay.
**Call the allocator-call-and-copy prize ≤1.5% of total CPU** and do not claim
more without a directional PC census that separates the callers.

**Allocator policy (Phase 3), valid ONLY under branch (A).** This one is not
limited to the assembler's 73%:

```
churn fraction of heap zfod (branch A, ~(cumulative-peak)/cumulative) ~ 92%
=> 0.92 x 17.1%                              = 15.8% of total CPU
```

### 4.4 The honest band

| outcome | CPU removed | build wall |
|---|---|---|
| branch (B), Phase 1 only | ~1.2% | 14.48x → **14.3x** |
| branch (A), Phases 1+2 | ~12.2% | 14.48x → **12.7x** |
| branch (A), Phase 3 (whole heap) | ~15.8% | 14.48x → **12.2x** |
| theoretical ceiling, assembler heap = 0 | 12.5% | 12.67x |

**Every row is inside AGENTS.md's "3-15% does not move a 14.5x ratio" band.**
This workstream does **not** clear the bar. It is also **build-lane only**: on the
steady-state compute workload translation is noise (2,066 translations across a
1.2 s run, `2026-08-01-native-wall-audit…md` §6), so none of this touches the
~12x emitted-code penalty that `handoff.md` identifies as the campaign's goal.

---

## 5. Why the two previous attempts failed, and the rule that follows

Both rejected arms are recorded at `2026-08-01-native-wall-audit…md:296` and
`handoff.md:110`:

| arm | GiB/process | verdict |
|---|---|---|
| baseline (`Vec::new`) | 0.292 | — |
| pre-size `recovery` by emitted-word count | 0.449 | **+54%, regressed** |
| thread-local scratch + one exact-size copy | 0.286 | -2%, inside noise |

Pre-sizing regressed because `recovery` is **moved into `AssembledBlock` and
retained**, so over-allocation is retained too. Scratch reuse could not help
because the buffer escapes, so only the doubling ladder was avoidable — and the
"one exact-size copy" reproduced the *same 72-byte-per-word representation*.

> **The rule this plan is built on: change the REPRESENTATION, not the
> allocation strategy.** Any arm that keeps `Vec<RecoveryEntry>` as the retained
> form is already known to be worth ≤2%, and any arm that pre-sizes a retained
> buffer is already known to regress. Do not re-propose either.

The corollary is that Phase 2 (a reusable scratch buffer) is **only** viable
once Phase 1 has made the retained form a separate, exact-size structure that
the scratch does not become.

---

## 6. Design

### Phase 0 — settle branch (A) vs (B), and fix the instrument (blocking)

Nothing else may be planned in detail until this lands. Deliverables:

> **CORRECTION (2026-08-02, measured).** Deliverable 1 below names the wrong
> mechanism, and a fix built against it was implemented, measured, and reverted
> unlanded. carrick's guest `execve` does **not** host-`execve`: it loads the
> new image in-process (`runtime.rs` `load_execve_image`), and the only host
> `execve` in the tree (`native_exec_capsule.rs`) is not taken by a cold
> `go build`. Hooking that path produced **no** coverage change (23 census
> files, inside the documented 23/25/34 band, and no pid wrote twice). The
> ~70 processes of a build are host **forks**, so the blind spot is a forked
> child that leaves via `_exit` without running `atexit` — that is what Phase 0
> must actually close. One real defect was found along the way and is worth
> fixing regardless: census file names are keyed on pid alone, so any path that
> does keep a pid across images would silently overwrite its own census.
>
1. **Close the census's `execve` blind spot.** `crates/carrick-cli/src/main.rs:174-206`
   parks the `dhat::Profiler` in a static and drops it from a libc `atexit`
   hook, so a process that `execve`s (carrick's guest-exec is a host
   self-re-exec) **never writes its JSON**. Process coverage varied 23/25/34
   across three runs of the identical workload, and that variance swamps
   anything under ~10% (`2026-08-01-native-wall-audit…md:311`). Flush the
   profiler on the pre-exec path so coverage is complete rather than
   representative.
2. **Build the aggregator.** There is **no** in-tree tool that sums the per-pid
   `dhat-<pid>.json` files — the committed census table was assembled by hand
   and scaled. Per AGENTS.md ("Rust first; extend ourselves"), this belongs as a
   `carrick debug alloc-census` subcommand with a typed parser and a `just ci`-
   gated test, not as a script. It must report, per site and in total:
   cumulative bytes, allocation count, **bytes live at t-gmax**, and process
   coverage (processes that wrote a JSON / processes observed).
3. **Answer the branch question.** Compare summed cumulative heap against summed
   at-t-gmax heap on one cold build. Record the ratio. Also record, per block:
   the `len` and `capacity` histograms of `entries` and `recovery`, and the run
   count under the `artifact_spike.rs:1553 recovery_entry_run_count` coalescer —
   this replaces the §4.2 estimates with measurements and settles the 25-vs-35
   PC-map band.
4. **Confirm the fault term is heap, directionally**, with the instrument that
   already exists (`scripts/dtrace/native-fault-attribution.d` +
   `scripts/perf/native_fault_directional.py`), so Phase 1/2/3 have a
   before-picture in the same units as their after-picture.

**Exit criterion:** a committed `docs/perf-results/2026-08-0X-…md` stating the
cumulative/peak ratio and the per-block histograms. If branch (B) holds, Phases
2 and 3 are cancelled and only Phase 1 proceeds.

### Phase 1 — retained: run spans against a pooled action table

Applies regardless of branch. This is the change the two rejected arms should
have been.

Replace `PublishedBlockMetadata::Owned { map: Vec<PcMapEntry>, recovery: Vec<RecoveryEntry>, .. }`
with an owned analogue of the V3 shape:

```
recovery: Box<[RecoverySpan]>            // 16 B/run: cache_offset u32, entry_count NonZeroU32, action_index u32 (+pad)
map:      Box<[PcMapEntry]>              // exact-size; drops Vec capacity slack and 8 B of header
```

plus **one per-`ProcessState` deduplicated `RecoveryAction` pool** (a
`Vec<RecoveryAction>` + a `HashMap<RecoveryAction, u32>` built at publication).
The pool is process-scoped, not block-scoped: the distinct action set is small
and highly repeated (register-parameterized variants over 16 GPRs plus a
handful of unit variants), so it amortizes to near-zero across 12,000+ blocks
per process while each span costs 16 B instead of 72 B per word.

Reuse, do not reimplement:

- the coalescer: `artifact_spike.rs:1553 recovery_entry_run_count` and
  `PortableRecoveryMetadata::into_runs` (`artifact_spike.rs:1575`) already
  implement exactly this run detection (`previous.action == entry.action &&
  previous.cache + 4 == entry.cache`);
- the record shape and the dedup key discipline:
  `mapped_metadata/wire.rs:259` (`WireRecoverySpanV3`), `:267`
  (`WireRecoveryActionV3`), `mapped_metadata/builder.rs:41` (dedup on raw bytes);
- the lookup: `mapped_metadata/view.rs:944-991`
  (`MappedRecoveryView::action_for_cache`) is a binary search over spans plus one
  pool read. Port that to the `Owned` arm of `ProcessState::guest_pc_for_cache`
  (`translator.rs:4834`), replacing today's linear `.iter().find(...)`. This is a
  strict improvement on the fault path, not a trade.

Convergence work that comes free and is required by "no second implementation":

- After this lands there are **two** recovery representations (owned spans,
  mapped spans) instead of three. Delete `SharedRecoveryMetadata`
  (`translator.rs:1479`) and its `CARRICK_DSR_SHARED_RECOVERY_LAZY` flag in the
  same change if the V2 arm is still live; if it is not, delete it anyway.
- Delete `ArtifactTemplate::take_runtime_metadata`'s run-expansion
  (`artifact_spike.rs:1858-1880`) — it allocates two per-block Vecs to undo the
  compression this phase is adding.
- Fix the two test helpers that silently `continue` past `Mapped` blocks:
  `recovery_points_for_test` (`translator.rs:5301`) and
  `patch_recovery_word_for_test` (`translator.rs:5434`). A test that skips the
  representation under test is not a test.

**Default:** ON. Escape hatch `CARRICK_DSR_RECOVERY_SPANS=0` for the A/B window
only; **the flag and the old `Vec<RecoveryEntry>` retained form are both deleted
in the commit that banks the gate result**, per AGENTS.md's opt-out rule and the
"no second path" rule. Do not leave a control arm parked.

### Phase 2 — transient: one reusable emit scratch (branch A only)

`assemble_block_inner` runs under the **`ProcessState` write lock** — the call
chain is `ThreadTranslator::translate` (`translator.rs:5014`) →
`translate_read_mostly` (`:4934`) → `self.process.state.write()` (`:5002`) →
`ProcessState::translate(&mut self, ...)` (`:4015`) → `emit::emit_block_with_generation(&mut self.cache, ...)`
(`:4413`) → `assemble_block_inner` (`emit.rs:4979`). **No two threads can be
inside the assembler concurrently in one process.**

Therefore: **do not use a `thread_local!`.** The mutual exclusion is already
total; TLS would add a fork/exec reset surface for nothing, and this crate's
only production `thread_local!` (`mapped_memory.rs:4250`) is profiling-only and
is *not* reset by any fork hook. Instead:

- Add a `struct EmitScratch { code: Vec<u8>, entries: Vec<PcMapEntry>, recovery: Vec<RecoveryEntry>, direct_links: Vec<DirectLink> }`
  owned by `ProcessState`, threaded as `&mut EmitScratch` through the three
  emit entry points (`emit_block_with_generation`,
  `emit_block_recording_artifact_optional`, `record_portable_block_artifact`) —
  all of which already take `&mut self.cache`, so the `&mut` is available at
  every call site.
- Each block `clear()`s the scratch (retaining capacity) rather than allocating.
  This is exactly the `ThreadBlockCache` pattern already established in this
  crate (`translator.rs:455-514`: allocate once in `new()`, `clear()` on
  fork/exec, never release capacity).
- `dynasmrt::VecAssembler::new(0)` allocates its own buffer. Use
  `VecAssembler::new_with_capacity`-equivalent seeding from the scratch, or —
  if dynasmrt does not expose buffer donation — accept that the code buffer
  keeps its own allocation and bank only the three metadata Vecs. **Check the
  dynasmrt 5.1 API before committing to the larger claim; do not assume.**
- Publication converts scratch contents into the Phase 1 exact-size
  `Box<[...]>` forms. The scratch itself never escapes, which is what makes
  it safe — and is the precise difference from the rejected "thread-local
  scratch + one exact-size copy" arm, which copied into the *same fat
  representation*.

**Fork/exec safety.** Because the scratch lives in `ProcessState` behind the
`RwLock`, it is covered by machinery that already exists and is already tested:

- fork: `ProcessTranslator::after_fork_child_inner` (`translator.rs:2930`) runs
  under `self.state.write()` (`:2934`). Add `state.emit_scratch.clear()` there.
  The fork barrier guarantees no thread holds `process.state` at the fork
  instant (`translator.rs:2020-2033`), so the child cannot inherit a
  half-written scratch.
- exec: `PreparedDirectBindingExecReset::commit*` (`translator.rs:331-380`)
  already clears essentially all of `ProcessState`; add the scratch alongside
  `state.cache.reset_after_fork_for_exec()` (`:377`).
- `crates/carrick-runtime/src/native/fork_child.rs` needs **no change** —
  `AFTER_FORK_CHILD_STEPS` (`:80`) is dispatcher-scoped and takes only
  `&SyscallDispatcher`; the DSR-side hook is `ThreadTranslator::after_fork_child`
  (`translator.rs:1969`), reached from
  `native_darwin.rs:2600 repair_native_fork_child_before_resume`.

**No new dependency.** `bumpalo` and `id-arena` appear in `Cargo.lock` only
through `wasm-bindgen`/`wit-parser` proc-macro transitives; neither is a
declared dependency of any carrick crate. A reused-buffer struct needs no crate.

**Default:** ON, `CARRICK_DSR_EMIT_SCRATCH=0` for the A/B window only, deleted
with the flag when the gate is banked.

### Phase 3 — allocator policy (branch A only; sized, not yet designed)

If Phase 0 shows faults track cumulative allocation, then libmalloc is returning
heap pages and carrick re-faults them. That reaches **the whole 17.1% heap
term**, not the assembler's 73% share, and it does not require touching the
assembler at all — which makes it the highest-leverage item in this task and
the reason Phases 1 and 2 must not be started before Phase 0 answers the
question.

The design direction, from AGENTS.md's dual-port-oracle rule: **Go's Darwin port
never destroys a VM entry to decommit.** Its whole vocabulary is
`mmap(MAP_ANON|MAP_PRIVATE)` to allocate and the
**`MADV_FREE_REUSABLE` / `MADV_FREE_REUSE`** pair to decommit and recommit,
leaving the mapping intact — and a `REUSE` of a page the kernel has not yet
reclaimed comes back **without** a zero-fill. `mem_linux.go` uses `mprotect`;
`mem_darwin.go` does not. Diff `$GOROOT/src/runtime/mem_linux.go` against
`mem_darwin.go` before designing this; it is BSD-licensed and explicitly fine to
read.

Candidate shapes, in ascending cost — **all unvalidated, all requiring their own
single-variable experiment**:

1. A `#[global_allocator]` shim that keeps `System` for correctness but holds a
   per-process free-page cache so freed spans are re-handed-out rather than
   returned. Smallest change with a real mechanism.
2. A Darwin malloc-zone policy change (there is no documented "never madvise"
   knob; verify before planning around one).
3. A purpose-built bump allocator for the translation subsystem only.

**Do not begin Phase 3 without Phase 0's numbers.** Its ceiling is stated here
so the next session can rank it; its mechanism is explicitly not designed.

### Interactions to preserve

- **`CARRICK_DSR_DIRECT_BYTES`.** Default ON publishes dynasm's byte stream
  directly (`emit.rs:141-148`, `:161-177`); `=0` selects the old
  `instruction_words()` `Vec<u32>` staging copy. That `=0` arm exists **as a
  faithful same-binary control** for the change that removed the staging
  allocation. **Leave it allocating exactly as it does today.** Optimizing a
  control arm destroys the control. Note it in the commit body so nobody
  "fixes" it later.
- **`mapped_metadata` / the shared-unit path.** `PublishedBlockMetadata::Mapped`
  blocks allocate nothing per block and are already optimal; Phase 1 must not
  touch them beyond converging the `Owned` lookup onto the same span+pool
  algorithm. The V3 wire format (`SectionKind::RecoverySpan` / `RecoveryAction`,
  `mapped_metadata/wire.rs:26`) is **unchanged** by this work — Phase 1 changes
  only the in-memory owned form, so no schema version bump and no cache
  invalidation.
- **`#[cfg(test)] AssembledBlock::words`** (`emit.rs:126`) stays; structural
  emitter tests depend on it and it is not in production builds.

---

## 7. Gates, and the kill criterion

Per the campaign's discipline: one knob at a time, everything else held,
including core class (this host is 4 Performance + 6 Efficiency cores;
`hw.logicalcpu` is not homogeneous). Never run carrick and the Docker oracle
concurrently.

### 7.1 The gate set

**Primary — build-cold wall.** `scripts/perf/workload-spread.sh N` (N≥5), after
`just build`. Strictly serial phases, in-guest timing windows on both engines,
median reported. It writes **no files** — redirect stdout yourself and
transcribe accepted numbers into `docs/perf-results/`. The `compute` and
`fs-walk` rows must not regress; `build-cold` is the row this work moves.
Requires the local registry at `localhost:5005`.

**Allocation census — directional only.**

```sh
./scripts/build-signed.sh -p carrick-cli --features alloc-census
mkdir -p target/perf/alloc-census
CARRICK_ALLOC_CENSUS_DIR="$PWD/target/perf/alloc-census" \
  ./target/release/carrick run --exec-backend native -w /tmp \
    localhost:5005/carrick-go-conformance:1.24 \
    /bin/sh -c 'cd /tmp; printf "package main\nfunc main(){println(\"ok\")}\n" > b.go; GOCACHE=/tmp/gcx /usr/local/go/bin/go build -o bx ./b.go'
```

Note the workspace root is virtual, so `just build --features alloc-census` does
**not** work — `-p carrick-cli` must be passed through `build-signed.sh`.
**Resolution limit, stated as a gate condition:** process coverage varied
23/25/34 across three runs of the identical workload; the instrument caught a
+54% regression immediately and could not adjudicate a 2% change. **It may be
used to fail a change and may not be used to pass one under ~10%**, until Phase
0's `execve` flush and aggregator land. After Phase 0, re-state this limit from
the measured coverage.

**Fault census — directional only, and it perturbs.**

```sh
sudo dtrace -s scripts/dtrace/native-fault-attribution.d \
  -o target/perf/native-faults.raw \
  -c "target/release/carrick run --exec-backend native -w /tmp \
      localhost:5005/carrick-go-conformance:1.24 /bin/sh -c '<workload>'"

python3 scripts/perf/native_fault_directional.py \
  --input target/perf/native-faults.raw --page-size 16384 \
  --output target/perf/native-fault-directional-v1.json
```

Needs passwordless `sudo /usr/sbin/dtrace` (`sudo -n -l`). The `as_fault` probe
fires ~2.1M times and pushes sys from 3.92 s to 7.78 s, so **absolute traced sys
is unusable — only ratios between two arms carrying the same instrument are
valid.** The consumer hardcodes `gating_eligible: false`; treat it as
before/after evidence for the mechanism, never as the promotion number. If
DTrace rejects the `execve` target transition, use
`scripts/perf/native_go_dtrace_target.py --trace-launcher standalone`.

**Correctness.** `just ci` (fmt-check → clippy → lint-domains → deny →
check-matrix → check → doc → test → test-integration), plus
`just conformance-native` (tier defaults to `smoke`; depends on `build`, so the
binary is signed). Two caveats to state in the result: the native lane's overlay
`scripts/conformance/baseline.native-dsr.jsonl` is essentially empty and
unblessed, so its output is a measurement rather than a regression check; and
its verdicts are load-coupled — run it on a quiet machine.

**Red-first.** Phase 1's span lookup must be proven against a deliberately
corrupt span table (out-of-order spans, an invalid action index, an offset
inside a span but not on a 4-byte boundary) producing a typed error, before the
correct table is wired in. A recovery test that passes immediately proves
nothing.

### 7.2 KILL CRITERION

Revert — **delete the code, do not park it behind a flag** — if **any** of:

- **Neutral or negative primary metric.** Build-cold median wall improvement
  `< 3%` over ≥5 paired same-binary samples with non-overlapping populations.
  3% is this lane's day-to-day drift floor; below it there is no result. AGENTS.md:
  "When a mechanism is MEASURED WORSE, delete it."
- **Retained memory grows.** Summed bytes live at t-gmax increases at all
  against the control arm. This is the exact failure mode of the rejected
  pre-sizing arm and it is non-negotiable.
- **Total allocated bytes increase** in the alloc census (the instrument
  resolves this direction reliably — it caught +54% immediately).
- **Any new DIFF, CRASH or TIMEOUT** in `just conformance-native smoke` that
  reproduces on a quiet machine and is not present in the control arm. Attribute
  before fixing: does Docker fail it too, does the pre-change binary fail it,
  what did the baseline say — and sample each point ≥2x, since verdicts here are
  load-probabilistic.
- **`just ci` red**, including clippy `-D warnings` and `just lint-domains`.
- **`compute` or `fs-walk` regress** in `workload-spread.sh` beyond noise. A
  build-lane win paid for elsewhere is not a win.

A phase that is killed is deleted in the same session, with a commit message
pointing at the measurement. Per AGENTS.md, a commit message citing a
measurement is worth more than dead code implying the idea might still be good.

---

## 8. Ranking: this (#14) against translation coverage (#13)

| | #14 heap/allocator | #13 whole-image AOT |
|---|---|---|
| ceiling | 12.5% of CPU (15.8% incl. Phase 3) | ~15-25% of CPU |
| build wall | 14.48x → 12.7x (12.2x with Phase 3) | 14.5x → **10-11.5x** |
| clears the 2x bar? | no | no |
| helps steady-state compute? | no (2,066 translations/1.2 s) | no (translation is noise there) |
| cost | contained; reuses an in-tree coalescer and lookup | rewrite of the publication path around whole-image AOT |
| risk | low; the compact form is already validated by the mapped path | high; the existing shared lane is measured +58% cold / +285% warm with **0 units published** |

**#13 is the better investment on prize: 21-31% of build wall against 1-12%.**
The sizing is committed at `2026-08-01-native-wall-audit…md:373` and its blocker
is understood — not persistence, but coverage: `claim_recording`
(`aot_cache.rs:1426`) requires a second sighting, and across three runs the
cache held exactly one key against 107,320 distinct blocks.

Three qualifiers that matter for sequencing:

1. **#13 partially subsumes #14, not the reverse.** An AOT-loaded block is
   `PublishedBlockMetadata::Mapped` — it allocates neither the assembler's
   transient state nor any per-block retained metadata. Every block #13 serves
   from a unit is a block #14 no longer has to make cheap. Doing #14 first does
   not shrink #13 at all.
2. **#14's Phase 0 is a prerequisite for honest #13 sizing too.** Whether an
   AOT-loaded build actually sheds the fault term depends on the same
   cumulative-vs-peak question. Phase 0 is ~a day and feeds both.
3. **Phase 3 is the one item here that #13 does not subsume**, because it
   addresses carrick's whole heap rather than the assembler's share of it.

**Recommendation for the next session:** run **#14 Phase 0** first (it is cheap,
it fixes an instrument the whole campaign depends on, and it settles a question
both tasks need). Then invest in **#13**. Land **#14 Phase 1** opportunistically
— it is a small change against an existing, validated representation and it
improves the fault-path lookup as a side effect. Start **#14 Phase 2** only if
Phase 0 proves branch (A), and treat **Phase 3** as the branch-(A) headline
rather than an afterthought.

And state plainly in whatever ships: per `handoff.md`, neither task reaches the
2x bar. Steady-state emitted code is ~12x independently of how the code got
there, and codegen is the only term that touches it.

---

## 9. Task list for the next session

Phase 0 (blocking, do this first):

1. Flush the `dhat::Profiler` on carrick's pre-`execve` self-re-exec path so a
   process that execs still writes its JSON (`crates/carrick-cli/src/main.rs:174-206`).
2. Add `carrick debug alloc-census` (Rust, typed, `just ci`-gated) to aggregate
   `dhat-<pid>.json` across processes: per-site cumulative bytes, allocation
   count, **bytes live at t-gmax**, and process coverage.
3. Run one cold build under the census; record cumulative vs at-t-gmax. **This
   answers branch (A) vs (B).**
4. In the same run, record per-block `len`/`capacity` histograms for `entries`
   and `recovery`, and the run count under `recovery_entry_run_count`
   (`artifact_spike.rs:1553`). Replaces §4.2's estimates.
5. Capture the before-picture with `native-fault-attribution.d` +
   `native_fault_directional.py`.
6. Commit the numbers to `docs/perf-results/`. Update §4 of this doc in place
   with measurements; do not leave the estimates standing once they are
   superseded.

Then, gated on the branch answer, Phases 1 / 2 / 3 as specified in §6, each
with the gate set and kill criterion of §7.

---

## Appendix — how the type sizes in §2.1 were obtained

A scratch binary outside the workspace with a path dependency on
`crates/carrick-dsr-aarch64`, printing `size_of`/`align_of` for
`emit::{PcMapEntry, RecoveryEntry, RecoveryAction, DirectLink}`. No crate source
was modified. Repeat this rather than trusting the table if `RecoveryAction`
gains a variant — the 72-byte `RecoveryEntry` is sized entirely by
`RecoverBiasedMemory(BiasedMemoryRecovery)` (`emit.rs:320`, `:439`), so one new
fat variant moves every number in §4.
