# Attributing the live-arena policy-ON overhead

**Date:** 2026-08-06 (**revised same day** — see the correction notes in §4,
§5 and §7; the counter figures and the fix route in the first version were
wrong, the mechanism and its shares were not).
**Verdict: the excess is ONE mechanism, and it is not any of the five suspects
the reviews named.** Under
`CARRICK_DSR_LIVE_ARENA=compiler` the guest executes **790x more gateway
round trips** for the same work, because a block installed from the live
arena never patches its outgoing direct links. Everything in the cost table
below is that one fact, charged in a different phase.

Mechanism evidence only. No ABBA, no retention claim, no fix.

---

## 1. Provenance

| | |
|---|---|
| source | `08531c73afcb44760bae771160ccbc1a54fbaa7c` (tree clean), campaign tip `9acf7684` + the instrument commit |
| binary | `95491fb7e4ab741f3c327d63a45b3601a5e7c5eeef69d0af6c7e1dec3541dc6d`, signed, `__dof_carrick` present, one build for **all eight runs** |
| host | macOS 27.0, Apple M4, `hw.logicalcpu=10` (4 Performance + 6 Efficiency) |
| workload | cold `go build` of a one-line `main` under `localhost:5005/carrick-go-conformance:1.24`, `--exec-backend native`, in-guest `WORKLOAD_NS` window — byte-identical to Task 9's `series-b` |
| discipline | quiet-host preflight receipt per run (settled 1-min load, `pgrep -x yes == 0`, no stray `carrick:`), `CARRICK_RUN_ID` stamped, `scripts/sudo/kill.sh <run-id>` after each, no Docker anywhere |
| driver | `target/perf/attr36/capture.sh` (uncommitted receipts) |

Receipts and digests (`target/perf/attr36/`):

| file | sha256 |
|---|---|
| `capture.log` | `ceeef2deda0af13f67eb3b7ef60203236d6cab2bdb2e43bf1558db1cabb58d11` |
| `C1ON.err` / `C1OFF.err` (counters) | `18be1b658087a8477257dd8a8081098f9d2dbfcc398539be3cc82ebf96188aa5` / `dd9f571656c48d7c2c2f84dd7cabbdf34c55b6b783128ab2c9514ac6ad0f3b4d` |
| `W1ON.raw` / `W1OFF.raw` (native-wall) | `1ac04c5f9745575376ab01f12cfb075e79ba33e1d60c3dae59816387b9328ff2` / `fca1711298ecfc97c7997a0b51f3bc45dfa5ad36537d508342b3c3b885f0f2f0` |

Run ids: `attr36{A1ON,A1OFF,A2ON,A2OFF,C1ON,C1OFF,W1ON,W1OFF}<pid>`.

The `W1ON` stream carries
`program_sha256=d6c1e2dcfa94f061d3fd5033034b716b30b3544159d5b59297c6d2c9dda88776`,
which is `shasum -a 256 scripts/dtrace/native-wall.d` exactly — the launch
authority still names the immutable bundled template even though the capture
ran with a substituted bound (§3).

---

## 2. The anchor (untraced, the only wall numbers quoted)

| arm | wall | in-guest workload window |
|---|---|---|
| `A1ON` | 405 s | **402.69 s** |
| `A2ON` | 429 s | **428.22 s** |
| `A1OFF` | 9 s | **8.388 s** |
| `A2OFF` | 9 s | **8.458 s** |

Mean ON **415.5 s**, mean OFF **8.42 s** → **49.3x**, excess **407.0 s**.
Two runs per arm on one binary and one quiet host: this is a measured
anchor, but the ON arm's own spread across the campaign is wide (332–441 s
over eleven quiet runs), so treat the multiple as "≈40–50x", not 49.3.

**The load-insensitivity signature was read wrong.** Task 9's inference —
loaded ON only 6–10% slower than quiet ON, therefore lock-serialized — does
not survive measurement. The ON run is CPU-bound at **~3.1–3.5 way
parallelism** (`native-wall` reports 3.06 average CPUs; the phase ledger
implies 3.50). On a 4P+6E box, ~3.5 busy threads leave six cores idle, so
eight `yes` loops land on the idle Efficiency cores and barely touch it.
Load insensitivity here means *spare cores*, not *a serialized critical
section*.

---

## 3. The instrument gap this round had to close first

The broad `native-wall` profile could not describe the policy-ON arm at all:
its ceiling was the literal probe name `tick-180s` and the workload runs
~400 s, so every attempt ended at `gating DSRPROF2 capture timed out`
(Task 9 §7). Editing the literal was not an escape — the launch authority
names the SHA-256 of the bundled template, so an edited program cannot
authenticate its own stream.

`feat(trace): bound long-run wall captures` makes the bound a declared
parameter: `bound_limit_s` in the D program (defaulted to the historical
180 s so the unrendered template stays legal), one
`/* CARRICK_DSRPROF2_BOUND */` substitution slot, a `tick-10s` accumulator
guarding the exit, `--profile-bound-seconds`, and the value reported in the
completion record so a timeout names the ceiling it hit. Raw schema v5 → v6.

`W1ON` is the **first complete policy-ON `native-wall` capture**:
`bounded=0 | timed_out=0 | elapsed_ns=590322278292 | bound_limit_s=3600`,
natural target exit, zero identity/lifecycle/range/kernel/off-CPU violations,
zero DTrace drops.

---

## 4. The mechanism

`ProcessState::publish_emitted_with_metadata`
(`crates/carrick-dsr-aarch64/src/translator.rs:4572-4607`) ends with a loop
over the block's emitted direct-link sites, patching each one at its target's
trusted entry so the next execution branches straight there.

`ProcessState::install_live_block`
(`crates/carrick-dsr-aarch64/src/translator.rs:4866-4922`) — the path every
arena-served block takes, from both `live_ready_consultation` (`:4735`) and
`live_winner_publication` (`:4829`) — **has no such loop.** It records
counters, notes the source page, pushes the published block, and returns.
The block's outgoing branch sites are left pointing at the gateway, and
nothing ever patches them, because the block was never emitted locally: its
DirectLink site list lives undecoded in the arena's COLD metadata.

Incoming links are fine — `direct_link_target` resolves a LIVE target, which
is what the comment at `:4582-4585` describes — but that is 12,809 link
attempts in the whole build (3,367 patched, 9,442 out of reach) against
644,244 installed live blocks.

So every branch out of every live block is a full gateway round trip,
forever. The counters say exactly that:

| counter | policy OFF | policy ON | ratio |
|---|---|---|---|
| `gateway_entries` = `reconciled_exits` (see note) | 1,846,656 | **1,459,213,262** | **790.2x** |
| `exit_resolve_direct` | 794,886 | **1,457,106,872** | 1833x |
| distinct private→private edges | 446,924 | 661,215 | 1.5x |
| **resolutions per distinct edge** | **1.78x** | **2,204x** | **1,240x** |
| gateway entries per installed live block | — | **2,265** | — |
| `live_links_patched` / `_out_of_reach` | — | 3,367 / 9,442 | — |

> **Counter note (corrected 2026-08-06).** `gateway_entries` is emitted in
> BOTH the `core` and `resolver-thread` NATIVEPERF frames with the same value,
> so summing every record double-counts it. The first version of this document
> reported 2,918,426,524 ON / 3,693,312 OFF and presented `gateway_entries` and
> `reconciled_exits` as two corroborating counters. They are **one number**:
> 1,459,213,262 ON / 1,846,656 OFF. The 790.2x ratio is unaffected (both arms
> were doubled equally), but per-installed-block is **2,265**, not 4,530. The
> figure in `769124e6`'s commit body is superseded by this table. `fusion_*`
> counters share the same two-frame shape; every other counter quoted here was
> verified to come from exactly one frame.

An edge that should be resolved about once and then executed as a patched
branch is instead re-resolved **2,204 times**. That single row is the whole
finding: the arena's blocks are correct, shared, and reused (564,187 READY
hits, 80,048 publication wins, 6.0x fewer private translations, 4.2 s of
translation work saved) — and then executed through the slowest possible
control-flow path.

The `native-wall` capture corroborates it from the opposite side. Share of
on-CPU **user** samples spent in translated guest code:

Shares below are of on-CPU **user** samples **after removing the instrument's
own clock from the denominator** — see the instrument note that follows, which
is why these differ from the raw numbers a reader would compute off the JSONL.

| | policy OFF | policy ON |
|---|---|---|
| JIT / translated guest | **49.6%** | **0.67%** |
| carrick's own Rust | 31.8% | 78.1% |
| absolute JIT samples | 4,558 | 3,195 |

Guest execution is roughly **flat — 3,195 against 4,558 samples, −29.9%** —
while everything around it grew ~70x. It is not literally unchanged (an
earlier version of this document said "unchanged", which overstated it): a
30% drop over one sample pair is within what a single capture can show, and
the point that survives is the contrast in orders of magnitude, not equality.

> **Instrument note (corrected 2026-08-06).** The `native-wall` capture runs
> with `CARRICK_DSR_PROFILE=1`, whose phase clock is **28.3% of ON user
> samples but only 3.0% of OFF** — it scales with the very round trips being
> counted. It therefore sits INSIDE the raw user totals and deflates the ON
> arm's shares asymmetrically. Every share in this document is **rescaled by
> `1/(1 − clock)` per arm**. The first version said the clock was "excluded
> from every quoted share", which was false for the denominators; the correct
> statement is that the clock **is not attributed to any carrick bucket**, and
> is now also removed from the denominator. The clock span used is
> `libsystem_kernel` offsets `0x1010..0x1110` (`mach_continuous_time` through
> the end of `mach_absolute_time`, §8). Excluding the whole `libsystem_kernel`
> image instead — which sweeps in ~1.2% of genuine syscall-stub time — gives
> 15.2% / 14.5% / 50.0% where this document says 14.9% / 14.2% / 49.6%.

Two independent instruments agree on how much real guest execution there
is, which is what makes the "unchanged" claim safe: policy OFF's
`translated-run` phase timer says **7.44 CPU-s** and its JIT on-CPU samples
at 499 Hz say **9.13 CPU-s**; policy ON's JIT samples say **6.40 CPU-s** (3,195/499)
against a `translated-run` phase timer of 133.59 CPU-s. Guest work is a
constant ~7–9 CPU-s in both arms.

---

## 5. The cost ledger

**Denominator: the excess summed thread CPU, ON − OFF = 1,645.3 − 20.2 =
1,625.1 s**, from the `NATIVEPERF1` per-thread records of `C1ON`/`C1OFF`
(454 and 452 complete records, 71 guest processes each). Rows 1–6 are the
run-loop phase timers; the residual row is everything those timers do not
bracket. Same-instrument shares only.

| # | mechanism | excess (s) | share | ns per gateway exit (ON) | instrument | confidence |
|---|---|---|---|---|---|---|
| 1 | **`prepare-index`** — resolver entry bookkeeping per round trip. Hottest named symbol on the whole run: `carrick_dsr::cache::PageGenerationTable::observe` at **10.2%** of on-CPU user samples (three call sites, `cache.rs:181/186/196`) | 638.1 | **39.3%** | 437 | NATIVEPERF phases + `W1ON` symbols | high |
| 2 | **`translate`** — the per-exit resolver lookup (a cache hit 99.99% of the time: 1.459e9 lookups, 128,895 actual translations) | 327.1 | **20.1%** | 235 | NATIVEPERF phases | high |
| 3 | **`finish-exit`** — exit reconciliation per round trip | 319.4 | **19.7%** | 219 | NATIVEPERF phases | high |
| 4 | **`translated-run`** — the phase bracket around guest execution. Of its 133.6 s ON, only ≈**6.40 s is real guest execution** (`W1ON`'s 3,195 JIT samples at 499 Hz); **95.2% of the phase is bracket** | 126.2 | **7.8%** | 92 | NATIVEPERF + `W1ON` JIT share | medium |
| 5 | `loop-quiesce` | 11.7 | 0.7% | 8 | NATIVEPERF phases | high |
| 6 | `syscall-dispatch` (guest syscalls only rose 2.8x: 88,174 → 248,620) | 2.8 | 0.2% | 3 | NATIVEPERF phases | high |
| 7 | **residual / unattributed** — ON thread CPU outside every loop phase: process startup, fs and dispatch work off the loop, fork/exec, counter emission | 199.9 | **12.3%** | — | subtraction | low (bound, not decomposed) |
| | **total** | **1,625.1** | **100%** | 995 | | |

**Rows 1–6 (87.7%) are one mechanism.** They are what a gateway round trip
costs, multiplied by 1.457 billion excess round trips. The counterfactual is
stark: at ON's own measured 995 ns per exit, the OFF exit count would cost
**1.84 s**. The per-exit cost is not the problem; the count is.

Two caveats on the `ns per gateway exit` column. First, **its rows do not
share a denominator**: every row divides by `reconciled_exits`
(1,459,213,262), but `translate` fires 1,458,987,978 times and
`syscall-dispatch`/`sensitive-emulation` only 248,620 and 3,033 times. Read
the column as "cost per round trip contributed by this phase", which is what
makes it summable to 995 — not as the cost of one invocation of that phase.
Second: `C1ON`/`C1OFF` run with
`CARRICK_DSR_PROFILE=1`, whose phase timestamps are themselves measurable —
`C1ON` took 476 s against the untraced anchor's 415 s, so roughly **15% of
that column is the timer**. It inflates every row about equally (one clock
read per phase boundary), so the shares stand; the absolute per-exit figure
is nearer 700–850 ns untraced.

### Cross-cutting, not additive

| | ON | OFF | note |
|---|---|---|---|
| `parking_lot` lock slow paths (on-CPU user samples) | **14.9%** | 0.25% | 60x. Raw shares before rescaling: `lock_exclusive_slow` 6.28%, `raw_mutex::lock_slow` 1.71%, `lock_shared_slow` 1.13%, `lock_upgradable_slow` 0.72% |
| `psynch_cvwait`/`mutexwait`/`cvsignal`/… (all CPU samples) | **8.1%** | 2.6% | kernel-side of the same parking |
| off-CPU blocked in `lock_exclusive_slow` | 86.5 s of 10,081 s | — | **0.86%** of off-CPU; the other 99% is idle waiters (`wait_proc_exit`, `wait_kqueue`, `FutexTable::wait_prepared_with_token`) |
| `libsystem_platform` **image** | 16.9% | 9.4% | the image, not the `_platform_memmove` symbol — an earlier version labelled this row with the symbol name. `_platform_memmove` is its dominant but not sole occupant |

**Which lock, and is it downstream? — corrected, and it is NOT `ProcessState`.**
The first version of this document asserted that the ~15% is `ProcessState`
contention downstream of the round trips. The assertion was not shown, and it
names the wrong lock. The receipts:

- `translate_read_mostly`'s per-thread `block_cache` hit is taken **before any
  lock** (`translator.rs:6240-6246`, and the comment there says so explicitly),
  as is the lock-free `published_blocks` index. Only a miss through BOTH takes
  `ProcessState` write. `one_entry_hits` is 2,829,406,956 — **1.94 per gateway
  exit** — so the per-thread cache serves essentially everything.
- `ProcessState` write is therefore taken **1,246,783 times**, not per exit —
  and that number is measured, not inferred: `ProcessState::translate`
  increments `cache_lookups` unconditionally on entry
  (`translator.rs:5262-5263`), so it counts one per acquisition through that
  path. It reconciles exactly against the five branches that each hold the
  lock for the full call:

  | branch | C1ON | C1OFF |
  |---|---|---|
  | `cache_lookup_hits` (`blocks.get` hit) | 896 | 23,691 |
  | `live_index_hits` | 22,688 | 0 |
  | `shared_unit_hits` | 450,060 | 450,191 |
  | `live_blocks_installed` | 644,244 | 0 |
  | `translations` | 128,895 | 767,960 |
  | **sum = `cache_lookups`** | **1,246,783** | **1,241,842** |

  (Corrected 2026-08-06: an earlier revision of this section used
  128,895 + 644,244 = 773,139, omitting the three HIT branches, which put the
  denominator **38.0% too low**.)
- But `ThreadTranslator::translate_read_mostly` opens with
  `memory.dsr_generation_observation(guest)` (`translator.rs:6239`), which is
  `PageGenerationTable::observe` (`carrick-dsr/src/cache.rs:179-195`) — and
  that takes **`self.pages.write()`, an EXCLUSIVE lock, per gateway exit**,
  under `DsrSynchronizationKind::GenerationTableWrite`.

So the per-exit exclusive lock is **`GenerationTableWrite`, acquired
1,459,213,262 times against `ProcessState`'s 1,246,783 — a ratio of
~1,170:1** — and it is taken *before* the lockless fast path can help. That
ratio is an **upper bound**: the mutation seam (`translator.rs:3541`,
`:3551`) also takes the `ProcessState` write lock on every guest code
mutation, and `cache_lookups` does not count it, so the true separation is
somewhat narrower still.

The contrast between arms is itself informative: under policy OFF the same
counters give 1,846,656 exits against 1,241,842 `ProcessState` entries —
**1.5:1**, i.e. nearly every exit reaches the write path. Under ON it is
1,170:1. The per-thread cache is not newly effective; there are simply three
orders of magnitude more exits for it to absorb. That is consistent
with `PageGenerationTable::observe` being the hottest named symbol on the run
(14.2%), with its hottest line being `cache.rs:181`, the acquisition itself.

**Confidence: medium-high, and the residue is named.** The DTrace CPU sampler
records leaf user PCs without stacks, so `lock_exclusive_slow`'s 6.28% cannot
be split between its two possible callers by this capture alone. Attributing
the bulk of it to `ProcessState` instead would require each `ProcessState`
acquisition to be ~1,170x more expensive than each `GenerationTableWrite` one.
**What would settle it:** a capture keyed on the existing
`DsrSynchronizationKind` USDT (the probe is already emitted at both sites via
`probes::acquire_with_synchronization_reason`), which no profile currently
consumes. That is a one-profile gap, not a research question.

**This matters for fix ranking**, which is why it is not left as a footnote:
if the ~15% is `GenerationTableWrite` per exit, fix (1) removes it along with
the round trips. If it is `ProcessState` on the install path, fix (1) does
not, and it needs its own work. The evidence favours the former; it is not
yet proven.

---

## 6. The five named suspects, measured

Each was given a share. Four of the five are **quantitatively refuted**; the
fifth is real but downstream.

| # | suspect | measured | verdict | confidence |
|---|---|---|---|---|
| 1 | `active_chunks_for_source_page` — 1,024-descriptor linear scan per covered 16 KiB page under the ProcessState write lock, on every code-mutation event | Every `live_arena` symbol together is **0.02%** of on-CPU user samples (0.016% raw). `live_revoked_chunks = 0` and `live_stale_instruction_aborts = 0` across all 454 thread records — the revocation path found nothing to revoke in the entire build, and `note_live_source_page`'s scan is guarded (`translator.rs:4932-4937`) to first-install per (page, chunk) | **REFUTED as a leading term.** The O(pages×chunks) shape is real and worth fixing on principle, but it is not in this workload's excess | high |
| 2 | Per-install / winner publication (SHA-256 + I-cache + memcpy) | 80,048 publication wins, 9 adoptions. `sha2::compress256` is **0.10%** of on-CPU user samples under ON — against **2.23%** under OFF, where it is the single hottest carrick symbol | **REFUTED.** SHA-256 is 30x *less* prominent with the arena on | high |
| 3 | READY-hit validation: per-acquire SHA-256 over mapped RX + HOT validation + I-cache invalidate | 564,187 READY hits + 644,244 installs, same 0.10% `sha2` share | **REFUTED** | high |
| 4 | ProcessState `RwLock` serialization | 14.9% of on-CPU user in `parking_lot` slow paths; 8.1% of all CPU in `psynch_*`; 0.86% of off-CPU | **The ~15% is REAL — but it is NOT `ProcessState`.** The per-exit exclusive lock is `GenerationTableWrite` inside `PageGenerationTable::observe`, 1,459,213,262 acquisitions against `ProcessState`'s 1,246,783 (§5, ~1,170:1). Downstream of the round trips on that reading | medium-high; the leaf-PC sampler cannot split `lock_exclusive_slow` between callers |
| 5 | B3 arena CAS/cursor protocol under concurrent publishers | `lfb_arena_cas_lost = 6` for the whole build; `lfb_arena_exhausted_probes`, `_capacity`, `_invalid_record`, `_failed` all **0** | **REFUTED.** The lock-free protocol is not contending | high |

The reviews looked at the arena's *maintenance* paths. The cost is in what
the arena does to *execution*.

---

## 7. Fix ranking

1. **Bind live blocks' direct links BEFORE publication, via the dormant
   `prebind` seam.**

   The first version of this document proposed replaying the DirectLink site
   list from COLD metadata at install "the way `publish_emitted` does". That
   is **unimplementable by design, not merely unimplemented**, and the
   correction matters because it changes the risk profile of the whole fix:

   - `ArtifactBuilder::finish_shared_initial` passes `Vec::new()` for links
     (`artifact_spike.rs:1356`), and its doc comment (`:1327-1332`) states the
     rule: "Direct-link sites are deliberately omitted from the portable
     record… a shared source must never re-enter a mutable link index
     afterward."
   - `validate_shared_initial_metadata` (`:1116`) and
     `validate_shared_initial_hot` (`:1165`) both **reject** a non-empty
     `hot.direct_links`, so a record carrying links cannot become READY.
   - The design doc is explicit and permanent
     (`docs/superpowers/specs/2026-08-05-native-live-translation-arena-design.md`,
     "Immutable direct links"): "READY shared code is immutable. A process may
     never run `patch_code_word` on a shared source block."

   **The route that exists** is pre-publication binding, which the design
   already sanctions in the next sentence: "Before publishing a new block, the
   winner may bind a direct link only when its target is already READY in the
   same arena and the final displacement is reachable. The branch word is
   written into the still-BUILDING source block."

   `DarwinLiveReservedPublication::prebind`
   (`crates/carrick-native-darwin/src/live_arena.rs:1239`) implements exactly
   that, over `emit.rs:250 prebind_live_direct_link`. It is **built, tested
   (`emit.rs:7677`, `:7733`, `:7785`) and has no production caller** — its
   only callers are `cfg(test)`. The seam is between `claim.reserve`
   (`live_arena.rs:1465`) and `reserved.publish` (`:1469`) on the winner path.

   **Two things must be resolved with it, and neither is bookkeeping:**

   - **Task 6E's publication-ordering question** (6E report §1): `prebind`
     needs the target as an *acquired capability at reservation time*, so a
     block can only bind to targets **already READY**. A build's blocks are
     published in execution order, so back-edges bind and forward-edges do
     not. Nobody has measured what fraction that leaves.
   - **`live_links_out_of_reach` is 9,442 against 3,367 patched (74%
     unreachable)** on the *incoming* private→live links that do run today.
     A prebind design that cannot reach its target re-creates the problem at
     the new scale. This is arena RX placement / branch range, not translator
     work.

   **Risk profile, stated plainly:** the superseded proposal was a
   translator-local change to a path that runs after publication. This one
   writes executable bytes into a BUILDING block inside the unique-claim
   window, on the publication path, in the one place the design permits it —
   higher-stakes code, with a correctness argument (claim uniqueness, exact
   post-prebind expected bytes, `certify_mapped`) that already exists in the
   tests but has never run in production.

   Plausible effect if it lands and the ordering constraint is not fatal: the
   round-trip count, hence rows 1–6 — **~88% of the excess**. It remains the
   only item within an order of magnitude of the problem. The design doc
   predicted the trade ("sacrifices some of the measured 62% same-unit link
   opportunity in the first slice"); what this measurement adds is that "some"
   is worth roughly 40x on this workload.
2. **Settle the lock question with a `DsrSynchronizationKind`-keyed capture
   before budgeting anything from the ~15%.** The probe already exists at
   both acquisition sites and no profile consumes it. It is cheap, and it
   decides whether item (1) also removes the lock cost or whether that is
   separate work (§5).
3. **`PageGenerationTable::observe` at 14.2% of on-CPU user** (corrected up
   from 10.2%: the instrument was in the denominator) is worth its own look
   even after (1). It is the single hottest named symbol in the run, it takes
   an EXCLUSIVE lock once per gateway exit before the lockless fast path can
   help, and it is **not live-arena-specific** — a win there helps the shipped
   default lane too. If (1) lands, this shrinks with the round-trip count; if
   (1) stalls on the ordering constraint, this becomes the top item.
4. Everything else measured here (SHA-256 on the READY path, the descriptor
   scan, the publication transaction, the CAS protocol) is **not worth fix
   effort against this workload**. Fix the descriptor scan's O(pages×chunks)
   shape when it is convenient, on correctness/scaling grounds, not as
   overhead work.

Do not read row 7 (the 12.3% residual) as a target until it is decomposed;
it is a subtraction, not a measurement.

---

## 8. Honest limits

- **One traced run per arm; two untraced runs per arm.** Every share is
  single-capture. The counts (`gateway_entries`, edge re-resolution) are
  exact and instrument-independent; the CPU shares are one sample.
- **`W1ON`'s own instrument is 28.3% of its on-CPU user samples** — that is
  `mach_absolute_time` (offsets `0x10f8`/`0x10fc` in `libsystem_kernel`,
  which disassemble to the `mrs` timebase read and its seqlock re-read; the
  identification is by `dladdr` + live `lldb` disassembly, not `atos`, which
  named an adjacent export). It is `CARRICK_DSR_PROFILE`'s phase clock,
  scaling with the very round trips being counted. It is **not attributed to
  any carrick bucket, and is removed from the denominator of every share
  quoted above** (see the instrument note in §4 — the first version of this
  document said "excluded from every quoted share", which was true of the
  numerators only and left the ON arm's shares understated by ~39%). It is
  *not* present in the untraced anchor.
- **The phase timers measure per-phase WALL, not CPU**, so they do not
  strictly nest inside `thread_cpu_ns` (policy OFF's phases exceed its
  thread CPU by 29%). Row 7's residual is therefore a soft bound.
- **Nothing here says the arena is bad.** It demonstrably does its job:
  6.0x fewer private translations, 4.2 s of translation work saved, 98%+
  READY service, zero revocations, zero CAS losses, zero stale aborts. It
  is one missing link-patch away from being measurable on its merits.
- No retention claim, no ABBA, and no fix was attempted or implied.

---

## 9. Appendix — reproducing §4–§6

**Capture** (three phases, in this order, on a quiet host; each phase writes a
preflight receipt and refuses to run on a dirty one):

```
scripts/perf/live-arena-attribution-capture.sh anchor     # untraced ON/OFF pairs
scripts/perf/live-arena-attribution-capture.sh counters   # CARRICK_DSR_PROFILE=1
scripts/perf/live-arena-attribution-capture.sh wall       # native-wall, bounded
```

**Counters (§4, §5).** Aggregate `NATIVEPERF1|thread|` records from
`C1{ON,OFF}.err`, grouping each counter **by frame first**: a counter carried
by more than one frame (`gateway_entries`, the `fusion_*` family) must be taken
once, not summed. The phase ledger is `phase_<name>_ns` / `phase_<name>_count`
over `Phase::ALL`.

**CPU attribution (§4, §6).** Use the existing tool — there is no second
parser:

```
python3 scripts/perf/native_wall_attribution.py \
  --profile target/perf/attr36/W1ON.jsonl \
  --binary  target/release/carrick \
  --output  target/perf/attr36/W1ON-attr.json
```

For per-symbol shares, reuse that module's own machinery rather than
re-implementing address classification: `native_wall_attribution.load_profile`
for the rows, `image-base`/`jit-range` rows for the host and JIT ranges,
`_dyld_image_ranges` for dylibs, and `symbolicate.atos_batch` (base = the
`image-base` row's `source_pc`) for carrick symbols. Classify each
`cpu-user-pc` row's `(pid, source_pc)` as JIT → carrick → dylib → unattributed,
in that order, then divide by the instrument-free denominator.

**Identifying a dylib PC (the trap this round hit).** `atos -o <path> -l <base>`
resolved `libsystem_kernel+0x10f8` to `task_get_special_port`, which is
**wrong** — its preferred vmaddr skews the mapping. Resolve offsets with
`dladdr` on live symbol addresses instead, then confirm by disassembly:

```
lldb -b -o "b main" -o run -o "disassemble -n mach_absolute_time" /tmp/probe
```

On this host that gives `libsystem_kernel` base `0x199efc000`,
`mach_absolute_time` at `+0x108c`, and `0x10f8` = `mach_absolute_time+108`
= `mrs x0, S3_4_C15_C10_6` — the timebase read, with `0x10fc` its seqlock
re-read. `task_get_special_port` is at `+0x11b4`, i.e. past it. Re-qualify
these offsets on any OS update before reusing them.

