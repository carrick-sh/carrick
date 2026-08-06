# Attributing the live-arena policy-ON overhead

**Date:** 2026-08-06. **Verdict: the excess is ONE mechanism, and it is not
any of the five suspects the reviews named.** Under
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
| `gateway_entries` | 3,693,312 | **2,918,426,524** | **790x** |
| `reconciled_exits` | 1,846,656 | **1,459,213,262** | **790x** |
| `exit_resolve_direct` | 794,886 | **1,457,106,872** | 1833x |
| distinct private→private edges | 446,924 | 661,215 | 1.5x |
| **resolutions per distinct edge** | **1.78x** | **2,204x** | **1,240x** |
| gateway entries per installed live block | — | **4,530** | — |
| `live_links_patched` / `_out_of_reach` | — | 3,367 / 9,442 | — |

An edge that should be resolved about once and then executed as a patched
branch is instead re-resolved **2,204 times**. That single row is the whole
finding: the arena's blocks are correct, shared, and reused (564,187 READY
hits, 80,048 publication wins, 6.0x fewer private translations, 4.2 s of
translation work saved) — and then executed through the slowest possible
control-flow path.

The `native-wall` capture corroborates it from the opposite side. Share of
on-CPU **user** samples spent in translated guest code:

| | policy OFF | policy ON |
|---|---|---|
| JIT / translated guest | **48.1%** | **0.48%** |
| carrick's own Rust | 30.8% | 56.0% |
| absolute JIT samples | 4,558 | 3,195 |

The absolute amount of guest execution is **unchanged** (it is the same
build). Only the non-guest work grew — by a factor of seventy.

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
| 4 | **`translated-run`** — the phase bracket around guest execution. Of its 133.6 s ON, the `W1ON` JIT sample share says only ≈**0.5 s is real guest execution**; the rest is bracket | 126.2 | **7.8%** | 92 | NATIVEPERF + `W1ON` JIT share | medium |
| 5 | `loop-quiesce` | 11.7 | 0.7% | 8 | NATIVEPERF phases | high |
| 6 | `syscall-dispatch` (guest syscalls only rose 2.8x: 88,174 → 248,620) | 2.8 | 0.2% | 3 | NATIVEPERF phases | high |
| 7 | **residual / unattributed** — ON thread CPU outside every loop phase: process startup, fs and dispatch work off the loop, fork/exec, counter emission | 199.9 | **12.3%** | — | subtraction | low (bound, not decomposed) |
| | **total** | **1,625.1** | **100%** | 995 | | |

**Rows 1–6 (87.7%) are one mechanism.** They are what a gateway round trip
costs, multiplied by 1.457 billion excess round trips. The counterfactual is
stark: at ON's own measured 995 ns per exit, the OFF exit count would cost
**1.84 s**. The per-exit cost is not the problem; the count is.

Caveat on the absolute `ns/exit` column: `C1ON`/`C1OFF` run with
`CARRICK_DSR_PROFILE=1`, whose phase timestamps are themselves measurable —
`C1ON` took 476 s against the untraced anchor's 415 s, so roughly **15% of
that column is the timer**. It inflates every row about equally (one clock
read per phase boundary), so the shares stand; the absolute per-exit figure
is nearer 700–850 ns untraced.

### Cross-cutting, not additive

| | ON | OFF | note |
|---|---|---|---|
| `parking_lot` lock slow paths (on-CPU user samples) | **10.70%** | 0.24% | 44x. `lock_exclusive_slow` 6.28%, `raw_mutex::lock_slow` 1.71%, `lock_shared_slow` 1.13%, `lock_upgradable_slow` 0.72% |
| `psynch_cvwait`/`mutexwait`/`cvsignal`/… (all CPU samples) | **8.1%** | 2.6% | kernel-side of the same parking |
| off-CPU blocked in `lock_exclusive_slow` | 86.5 s of 10,081 s | — | **0.86%** of off-CPU; the other 99% is idle waiters (`wait_proc_exit`, `wait_kqueue`, `FutexTable::wait_prepared_with_token`) |
| `_platform_memmove` | 12.08% | 9.09% | share up, but roughly flat in character |

ProcessState lock pressure is **real and large — and it is a consequence of
row 1–3, not a peer of them.** 790x more round trips means 790x more
`translate_read_mostly` calls contending for the same `ProcessState` write
lock. It is counted inside rows 1–3, not added to them.

---

## 6. The five named suspects, measured

Each was given a share. Four of the five are **quantitatively refuted**; the
fifth is real but downstream.

| # | suspect | measured | verdict | confidence |
|---|---|---|---|---|
| 1 | `active_chunks_for_source_page` — 1,024-descriptor linear scan per covered 16 KiB page under the ProcessState write lock, on every code-mutation event | Every `live_arena` symbol together is **0.016%** of on-CPU user samples. `live_revoked_chunks = 0` and `live_stale_instruction_aborts = 0` across all 454 thread records — the revocation path found nothing to revoke in the entire build, and `note_live_source_page`'s scan is guarded (`translator.rs:4932-4937`) to first-install per (page, chunk) | **REFUTED as a leading term.** The O(pages×chunks) shape is real and worth fixing on principle, but it is not in this workload's excess | high |
| 2 | Per-install / winner publication (SHA-256 + I-cache + memcpy) | 80,048 publication wins, 9 adoptions. `sha2::compress256` is **0.071%** of on-CPU user samples under ON — against **2.165%** under OFF, where it is the single hottest carrick symbol | **REFUTED.** SHA-256 is 30x *less* prominent with the arena on | high |
| 3 | READY-hit validation: per-acquire SHA-256 over mapped RX + HOT validation + I-cache invalidate | 564,187 READY hits + 644,244 installs, same 0.071% `sha2` share | **REFUTED** | high |
| 4 | ProcessState `RwLock` serialization | 10.70% of on-CPU user in `parking_lot` slow paths; 8.1% of all CPU in `psynch_*`; 0.86% of off-CPU | **REAL, ~10%, but DOWNSTREAM** — the acquisition count is what changed, and that is row 1–3's doing | high |
| 5 | B3 arena CAS/cursor protocol under concurrent publishers | `lfb_arena_cas_lost = 6` for the whole build; `lfb_arena_exhausted_probes`, `_capacity`, `_invalid_record`, `_failed` all **0** | **REFUTED.** The lock-free protocol is not contending | high |

The reviews looked at the arena's *maintenance* paths. The cost is in what
the arena does to *execution*.

---

## 7. Fix ranking

1. **Patch a live block's outgoing direct links at install
   (`install_live_block`).** This is the whole finding. The block's
   DirectLink site list has to survive publication into the arena's COLD
   metadata and be replayed by the installer the way `publish_emitted` does
   at `translator.rs:4572-4607`. Plausible effect: the round-trip count,
   hence rows 1–6 — **~88% of the excess**. Nothing else on this list is
   within an order of magnitude of it.
2. **Decide what to do about `live_links_out_of_reach` (9,442 vs 3,367
   patched, 74% unreachable)** before or with (1) — a patched-link design
   that cannot reach the arena's RX payload from the private cache will
   re-create the problem at the new scale. This is an arena-placement
   question (branch range), not a translator one.
3. **`PageGenerationTable::observe` at 10.2% of on-CPU user** is worth its
   own look even after (1). It is the single hottest named symbol in the
   run, it is on the per-entry path, and it is not live-arena-specific — a
   win there helps the default lane too.
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
  scaling with the very round trips being counted. It is excluded from every
  quoted share above, and it is *not* present in the untraced anchor.
- **The phase timers measure per-phase WALL, not CPU**, so they do not
  strictly nest inside `thread_cpu_ns` (policy OFF's phases exceed its
  thread CPU by 29%). Row 7's residual is therefore a soft bound.
- **Nothing here says the arena is bad.** It demonstrably does its job:
  6.0x fewer private translations, 4.2 s of translation work saved, 98%+
  READY service, zero revocations, zero CAS losses, zero stale aborts. It
  is one missing link-patch away from being measurable on its merits.
- No retention claim, no ABBA, and no fix was attempted or implied.
