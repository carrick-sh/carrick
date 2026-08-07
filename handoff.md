# Native-lane performance: state of play

**Date:** 2026-08-06 · **Integration target:** local `main` · **Latest
decision:** the live-translation-arena campaign is **closed negative**. The
complete runtime (Tasks 2-9) was deleted in `1cb06de6` per the plan's Task-10
failure arm; the shipped default is unchanged and reprofiled below ·
**Scope:** Darwin/aarch64 native backend (`--exec-backend native`, the shipped
default). VMM is explicitly NOT the target: one process per VM against a
~127-VM macOS ceiling makes it a dead end for build-shaped workloads.

## 2026-08-06 wrap-up — read this first

This section supersedes the 2026-08-05 wrap-up below and the older **What's
next** / **Branch state at handoff** sections. All of those remain as campaign
history, not live instructions.

### The campaign conclusion, measured results first

The live translation arena was built to completion (Tasks 2-9 all landed,
independently review-clean: protocol, Darwin substrate, fd transport, READY
lookup and winner publication, target authority, typed metrics, revocation,
counters and diagnostics), qualified correct end to end — and then lost the
measurements it existed for:

- **Cold go build, quiet box:** policy-ON ~**36x** policy-OFF wall (8 ON runs
  364-368 s vs 3 OFF runs 9-11 s; ~43x at the prebind tip within a 38-48x
  spread). Attribution: live blocks are never direct-linked, so the build
  takes **790.2x more gateway round trips = 87.7%** of the 1,625 s excess
  CPU. The sharing itself worked — 98%+ READY hit rate, 6x fewer private
  translations — the cost is structural: READY-immutable shared code cannot
  be link-patched.
  ([`2026-08-06-live-arena-36x-attribution.md`](docs/perf-results/2026-08-06-live-arena-36x-attribution.md))
- **Publication-window prebind, implemented and refuted** (`e9b12836` →
  reverted `9922cb26`): 23.7% of candidate links bind, round trips fall
  19.8%, wall unchanged. The residue split (`c1600799`) shows the remainder
  is 68.4% forward edges — unreachable by ANY publication-window binding
  under the READY-immutability contract. This is the design's load-bearing
  refutation, not an implementation miss.
- **20-exec micro, the arena's friendliest shape:** policy-ON ~**16% slower**
  (OFF 1,373.5 ms vs ON 1,593.9 ms, 3+3 ABBA). The persistent unit store
  already absorbs the startup translation set (translations only -20%
  despite ~1.4k READY hits), so the arena's original prize was already
  banked and the round-trip tax lands immediately.

Verdict: the arena loses on both measured shapes, the cause is structural,
and the prize was pre-claimed. Deleted per the house rule in `1cb06de6`
(`revert(native): remove the live translation arena runtime`);
`CARRICK_DSR_LIVE_ARENA` now hard-errors by name (`7318f583`).

### What survives the delete

- **The hold-and-wait deadlock fix** (`8d5b3a19` + `bcd2062e`): alias installs
  consumed under the dispatch-held exclusive memory guard. The bug predates
  the arena (`d2c54e5c`) and is guest-reachable on the shipped default; the
  residual same-class read-arm escalation audit is chip `task_ca1e49ea`.
- **The 6E executable-range-catalog publication** through
  `enter_translated_with_executable_authority` (sole node = the private cache
  range; equivalence-preserving and slightly cheaper than the null-pointer
  arm), defended by the oracle test pair.
- **Trace instrument improvements** (`08531c73` + `d774a3ff`): DSRPROF2
  capture bounds with fail-closed verification, sudo `--store` forwarding,
  and the carrick-cli `trace_profile` suite now genuinely gated in
  `just test-integration`.
- **Host test fixes** (`0fcaade7` fd-leak scoping, `b5d0ff2b` ulock race).
- **All design docs and evidence ledgers** — the two arena design docs and
  the plan carry dated CLOSED banners; the category-collapse spec's Move-1
  §6 invalidation condition is annotated FIRED, Move 2 re-costed against the
  persistent store, Move 3 promoted.

### The new official scoreboard

The post-delete serialized five-sample Carrick-then-Docker refresh
([`2026-08-06-post-arena-default-refresh.md`](docs/perf-results/2026-08-06-post-arena-default-refresh.md)):

| metric | Carrick | Docker | ratio |
|---|---:|---:|---:|
| cold `go build` workload wall | 8,676 ms | 799 ms | **10.8586x** |
| cold `go build` process elapsed | 9,448 ms | 964 ms | **9.8008x** |

Prior official: 8,254 ms / 811 ms = 10.1776x (2026-08-04). Carrick is
+5.11% wall and the ratio +6.69% against that run; the 3-arm byte-identical
smoke pins the delete itself as computation-neutral on the default arm, so
the drift is tip drift (~40 commits including the deadlock fix and the 6E
catalog publication) plus host state, and this single run cannot decompose
them — re-attribute on a quiet box before pricing any redesign against it.
At the new Docker denominator: 8x needs 26.33% wall removal, 5x needs
53.95%, 3x needs 72.37%, the 2x product bar needs 81.58%.

### Confidence after the campaign (projections, clearly labeled)

The remaining levers are Move 3 (kernel amplification ledger, now front of
the queue), the re-costed Move-2 codegen passes (the compute lane already
went 10.9x → 3.8x under the steady-state codegen campaign), the fs-walk
lanes (~20x → 3.8x on that shape), and the ~8.5 ms/exec Darwin exec floor.
The translation category's 15-25% arena claim is dead; whatever the
persistent store has not already taken from that category is not coming from
sharing.

- **8x cold build (~26% wall removal): ~75%.** Multiple named, partially
  proven levers each plausibly worth several percent; no structural blocker.
- **5x (~54% removal): ~45%.** Needs the kernel bucket to move, not just
  user-side codegen; the amplification ledger has named entries but few
  landed wins at this scale.
- **3x (~72% removal): ~25%,** down from the 45% carried while the arena
  was still projected to deliver its category. The category-collapse
  arithmetic reached 3.2-3.9x only with all three moves hitting their upper
  halves, and Move 1 is now dead.
- **2x product bar (~82% removal): ~10%.** Requires essentially every
  remaining bucket to approach its floor simultaneously.

### Exact next steps

1. **Move 3 first:** the Darwin kernel amplification ledger — instrument,
   then entries in ledger order (guest `open`, `mmap(MAP_PRIVATE, fd)`
   pread-materialization, exec's remaining full executable read).
2. **Move 2 re-costed:** liveness-gated borrow save/restore priced against
   the persistent store's replay economics, gated on the compute micro then
   a build ABBA.
3. Keep the two-gate discipline: any candidate that wins its mechanism must
   still win its ABBA before it ships (the augmentation, optimistic-decode,
   and now arena precedents).

## 2026-08-05 wrap-up (campaign history — superseded above)

Campaign strategy authority is now
[`docs/superpowers/specs/2026-08-05-category-collapse-strategy-design.md`](docs/superpowers/specs/2026-08-05-category-collapse-strategy-design.md)
(category budgets over the sequential ≥10% mechanism gate; live arena
accounted as the whole translation category; AOT-priced codegen after
runtime-on; kernel amplification ledger). The task sequencing below is
unchanged by it.

### Current truth

- The official shipped-default cold-build result is still **10.1776x**:
  Carrick 8,254 ms / Docker 811 ms. No runtime-on live-arena measurement has
  run, so this session claims **no performance improvement**.
- Task 6B3 is committed as `dc8ad47a` (`feat(dsr): pack live code by source
  page`). It replaces the rejected page-per-block V1 layout; there is no
  compatibility path.
- The V2 protocol uses 262,144 128-byte block records, 4,096 source-group
  records, and 1,024 permanently owned 64 KiB chunks over 64 MiB code, 1 MiB
  HOT, and 32 MiB COLD. A group is exact `(unit live digest, 16 KiB source
  page)` and owns its chunks exclusively.
- READY lookup is read-only. Eligible claim authority binds the same-domain
  INITIAL observation and exact decoded `[start,end)` span; a different
  same-page or cross-page prepared span fails before allocation and terminalizes
  the one-attempt claim. Publication retains the existing exact mapped-byte,
  digest, metadata, generation, W^X, and publisher/consumer I-cache authority.
- Darwin and the outer exec capsule are V2-only. The real
  `POSIX_SPAWN_SETEXEC` successor maps the same objects at fresh VAs, observes
  the creator's packed READY record and exact code/HOT/COLD bytes, and locally
  invalidates the exact RX extent.
- Runtime ownership and translation routing remain deliberately disabled.
  `resume_guest_from_capsule` still discards the transported arena pending C2;
  this is the next implementation seam, not dead code to remove casually.

### Capacity and provenance authority

The conservative checked fixture contains 85,525 exact blocks across 407
source groups. It records 36,341,884 code bytes, 684,200 aligned HOT bytes,
24,681,640 aligned COLD bytes, a 5,536-byte maximum block, ideal 781 chunks,
and an order-independent Next-Fit upper bound of 794 chunks. Encounter order,
guest-sorted order, and 100 deterministic production-hash shuffles produce
zero block refusals, zero group refusals, and 781–784 chunks.

- Capacity fixture:
  `crates/carrick-dsr-aarch64/tests/fixtures/live-arena-v2-capacity.bin`
  (1,197,990 bytes; SHA-256
  `576ee809efd4091abbd9b85c7aa2a729ad0d81cfc31940abbe3852454cb01368`).
- Durable capture-source patch:
  `crates/carrick-dsr-aarch64/tests/fixtures/live-arena-v2-capture-source.patch`
  (974 bytes; SHA-256
  `6df147f2a49a2af862e190ff49f5a606f387e94964656918bbd09a0d94587564`).
- The fixture authenticates the base source, capture-source patch, signed
  binary, OCI image, raw manifests, and every exact compiler
  `TranslationUnitKey` determinant. The test reconstructs captured stem
  `a5948df7…`, recomputes production V2 live digest `17aecdd6…`, and uses only
  that recomputed digest for the capacity simulation.
- Full commands, hashes, RED/GREEN receipts, limitations, and the three review
  fix rounds are in
  `.superpowers/sdd/2026-08-05-native-live-translation-arena/task-6b3-report.md`;
  controller recovery state is in the sibling `progress.md`.

### Accepted gates and review

Before `dc8ad47a`, the exact reviewed tree passed:

- portable 311/311 plus 3/3 doctests;
- Darwin 90/90 plus 2/2 doctests;
- serialized capsule family 33/33, including the real SETEXEC successor;
- serialized runtime library 1,180 passed / 0 failed / 5 ignored;
- scoped all-target Clippy with warnings denied, format, matrix, diff check,
  and affected-V1 search.

The cumulative independent review initially found two Important issues: an
unsealed prepared span and incomplete source-to-binary provenance. Three
bounded RED/GREEN fix rounds sealed the span, reconstructed the exact production
key/digest, and checked in the durable capture-source patch. Final verdict:
**0 Critical / 0 Important / 0 Minor, APPROVED**.

### Exact next steps

1. **Task 6C2 — owner and exec transport.** Include `direct_runner.rs` and an
   explicit `DirectExecServices` owner; do not use a process-global. Create the
   arena once in `run_image_in_child` for `pid == 0` before the direct/DSR
   split, adopt it once into `Arc`, retain it through resumed direct, DSR, and
   clone-thread paths, and transport it on both self-exec paths. SETEXEC
   failure tests must prove the registered vector is unchanged, duplicate send
   rights are released, and FD flags are restored.
2. **Tasks 6D/6E/6F — real translation path.** Add READY lookup, unique winner
   publication, lazy metadata/indexes, target authority/gateway routing, and
   typed metrics. Every miss, BUILDING state, collision, corruption, or
   capacity refusal immediately uses the unchanged private translator.
3. **Task 7 — revocation and stale-instruction recovery.** Runtime-on compiler
   evidence is forbidden until exact source-page/group/chunk enumeration,
   revocation, and stale-instruction abort recovery are complete.
4. **Only then:** signed correctness smoke, DTrace/USDT mechanism proof, and a
   controlled host-environment ABBA. Retain the arena only if correctness and
   the real cold-build result both hold; then refresh compute, 20-exec,
   cold-build, and workload-spread scoreboards.

### Confidence at handoff

- **98%:** B3's protocol/capacity/exec-adoption substrate is sound within its
  runtime-disabled scope.
- **82%:** C2 ownership and transport can be completed without another
  architecture replacement; the real successor proof already exercises the
  hardest mapping boundary.
- **70%:** the completed live-arena path will produce at least a 10% cold-build
  improvement once fully routed and revocation-safe. This remains a projection,
  not evidence.
- **45%:** the overall campaign reaches the <=3x goal. That confidence moves
  only after runtime-on mechanism and ABBA evidence; B3 alone cannot establish
  it.

## The goal

**Cold `go build` within 2-3x of native-arm64 Docker.** Carrick's premise is
running unmodified Linux binaries at host-native cost, so this number is the
product, not a metric about it.

The plan is [`docs/superpowers/specs/2026-08-02-performance-roadmap.md`](docs/superpowers/specs/2026-08-02-performance-roadmap.md).
Read it first; it carries the phase structure, the invalidation conditions, and
an appendix of rejected alternatives so nobody re-litigates them.

## Where we are

The authoritative shipped-default cold-build scoreboard is the refreshed,
serialized five-sample Carrick-then-Docker run in
[`docs/perf-results/2026-08-04-current-default-wall-refresh.md`](docs/perf-results/2026-08-04-current-default-wall-refresh.md):

| metric | Carrick | Docker | ratio |
|---|---:|---:|---:|
| cold `go build` workload wall | 8,254 ms | 811 ms | **10.1776x** |
| cold `go build` process elapsed | 8,991 ms | 995 ms | **9.0362x** |

This supersedes the prior 10.4446x result. Reaching 3x requires removing another
70.52% of Carrick's current workload wall (a 3.3925x reduction); reaching the
2x product bar requires removing 80.35% (5.0888x).

The required current-default three-sample workload spread is also complete:
compute **3.3868x**, fs-walk **18.9286x**, 20-exec `compile -V` **72.1579x**,
and cold build **10.8761x**. It confirms the band but does not replace the
five-sample official result. Startup rounded Docker to zero milliseconds and
has no citable ratio. Full provenance and raw samples:
[`docs/perf-results/2026-08-03-current-default-workload-spread.md`](docs/perf-results/2026-08-03-current-default-workload-spread.md).

The latest campaign tested monotonic augmentation of already-published
translation units. Its mechanism was real: private translations fell 56.0%
and `segment-repeat` fell 56.3%. Its product result was decisively negative:
eight-quad same-binary ABBA measured child CPU ratio **1.0728**, paired 95%
interval **[1.0653, 1.0806]**, and workload-wall ratio **1.2786**. The candidate
lost every quad, so it and its temporary controls were removed. Full evidence:
[`docs/perf-results/2026-08-03-native-store-monotonic-augmentation.md`](docs/perf-results/2026-08-03-native-store-monotonic-augmentation.md).

The approved trusted-entry route attribution is now complete. Two independent,
naturally completed 997 Hz captures agreed within 0.1703 percentage points on
the dominant route. Direct arrival projects to only 4.17% of total CPU;
indirect arrival to 3.77%; even removing all three route copies projects to
only 7.96%. All samples joined to exact JIT ranges, both native-emitted and
persistent-unit replay origins were observed, and all DTrace drop/error counts
were zero. The route line is therefore stopped without a production candidate.
Full evidence:
[`docs/perf-results/2026-08-03-trusted-entry-route-attribution.md`](docs/perf-results/2026-08-03-trusted-entry-route-attribution.md).

The approved exec/exit attribution is also complete. The opt-in `EXECSTAMP2`
export and fail-closed Rust census reconciled every exec, fork, terminal exit,
and reap in two independent 20-exec runs and two independent cold builds. The
micro named exec-total at a stable 16.80% of invocation CPU, but that same
segment was only 4.98% on the cold build. The cold build's complete strict
lifecycle opportunity was **8.858% / 8.791%** (mean **8.824%**), below the
campaign gate. The separately reported child-to-exec window averaged 9.644%,
mixed guest execution with Carrick repair, and did not name the same segment.
The first capture was correctly rejected for a missing spawned-thread terminal
stamp; the fixed exporter then closed all accepted trees exactly. No production
exec/exit hypothesis was selected. Full evidence:
[`docs/perf-results/2026-08-03-current-exec-exit-attribution.md`](docs/perf-results/2026-08-03-current-exec-exit-attribution.md).

The approved exact context-traffic census is now complete. The new Rust
diagnostic fail-closed joins sampled JIT PCs to authenticated retirement
snapshots and classifies each 64-bit context access by exact slot, physical
register, and direction. Two independent accepted cold-build captures joined
every JIT sample. Aggregate context traffic projects to **16.0730% / 16.1738%**
of total CPU, but source audit splits it into distinct mechanisms. The largest,
x17 authority through slot 1128, is only **7.0008% / 7.1812%**. No
non-overlapping mechanism clears 10%, so no emitter candidate was selected.
Full evidence:
[`docs/perf-results/2026-08-03-current-context-traffic.md`](docs/perf-results/2026-08-03-current-context-traffic.md).

The refreshed current-default fault ownership line is now complete. Two
source-identical NFAULT2 captures put host-other at **63.2115% / 62.7395%** of
sampled zfod, with exact `as_fault` and `zfod` totals agreeing within 0.67% and
0.52%. Two independent export-only translation censuses then reconciled
140/140 process-image epochs apiece and named 6.873/6.877 GB of initialized PC
map/recovery metadata plus 618.7/618.9 MB of JIT output. Even charging the old,
favorable 3.84 us all-system-CPU cost to every corresponding page projects
only **7.4111% / 7.4247%** of total CPU. No production allocation or metadata
change was selected. Full evidence:
[`docs/perf-results/2026-08-03-current-native-fault-ownership.md`](docs/perf-results/2026-08-03-current-native-fault-ownership.md).

The approved lifecycle-complete allocation-owner census is now complete. The
opt-in tagged `System` allocator exported every fork/self-reexec/process-exit
fragment and the strict Rust reader joined **140/140 process-image epochs and
71 pids** in both accepted runs. Its coverage fallback worked as intended:
v1 failed at 13.3776% `other`, v2 failed at 10.0369%, and the one-boundary-at-a-
time v3 refinement accepted at **8.7628% / 8.7611%**. Two ordinary NFAULT2
captures and two untraced NATIVEPERF CPU denominators bound the complete owner
portfolio to normal execution. The largest owner, publication recovery, is
only **8.3375% / 8.0484%** of total CPU even under the favorable 3.84 us per
host-zfod model; every other named owner is below 2.3%. No allocation
optimization was selected. Full evidence:
[`docs/perf-results/2026-08-03-native-allocation-owner-census.md`](docs/perf-results/2026-08-03-native-allocation-owner-census.md).

The refreshed current-default broad CPU attribution is now complete. Two
independent, naturally completed captures used the same clean runtime source,
binary, and locked store; every DTrace drop/error/lifecycle counter was zero,
wall timer coverage was 100%, and resolved CPU coverage was 99.94% in both.
Darwin kernel is the stable dominant category at **50.6261% / 50.8335%** of all
sampled CPU. It divides into named-syscall work at **28.7315% / 28.7129%** and
non-syscall work at **21.8945% / 22.1207%**, both above the campaign gate. The
prior exact N1/N2/C1/C2 binding puts all zero-fill service at a favorable
**25.3299% / 24.4248%** opportunity ceiling; even its host-other subset is
**15.9822% / 15.4279%**. This carries a memory-intent census, not a patch: the
3.84 us input is a favorable cost model, and the already-complete allocation
owner census found no individual owner above 10%. Full evidence:
[`docs/perf-results/2026-08-04-current-default-broad-cpu-attribution.md`](docs/perf-results/2026-08-04-current-default-broad-cpu-attribution.md).

The approved lifecycle-complete memory-intent census is now complete. Two
captures closed 11,671 / 11,789 intents with zero aborted records or lifecycle
errors. The largest exact semantic sequence was anonymous-private mmap work
while the guest operation was active: 927,321 / 935,942 zfod faults. Even
charging the favorable 3.84 us cost to all of them projects to only **6.5569% /
6.3527%** of ordinary CPU. No memory sequence clears 10%, so no production
lowering was selected; the export-only diagnostic remains.

The named-syscall/stack split then found `psynch_cvwait` at **17.7664% /
17.5852%** of all sampled CPU. Exact user stacks assigned **15.2293% /
15.1220%** to one process-wide translation-state lock: warm published-block
lookups were 10.20-10.27%, and indirect trusted-entry lookups another
4.85-5.03%. Commit `64bebc26` moved those two read-only paths to a 64-shard
published-block mirror while leaving authoritative translation/publication
semantics under the original lock. An eight-quad signed-binary ABBA measured
total-CPU ratio **0.91498** (95% interval **[0.91023, 0.92113]**, 8/8 wins,
exact sign p=1/256): a retained **8.50% CPU reduction**. System CPU fell 23.46%.
Workload-wall ratio was 0.98593 but its interval crossed parity, so no causal
wall win is claimed. A subsequent serialized shipped-default refresh measured
8,254 ms Carrick / 811 ms Docker = **10.1776x**; that is current scoreboard
authority, while the ABBA remains mechanism authority. Candidate stacks prove
the old reader paths disappeared and the remaining wait is exclusive
translation.
Full evidence:
[`docs/perf-results/2026-08-04-memory-intent-and-published-block-lock.md`](docs/perf-results/2026-08-04-memory-intent-and-published-block-lock.md).

The exclusive-writer follow-up is now measured and stopped. Moving pure decode
and planning outside the writer materially reduced the exact targeted
mechanism: same-instrument `psynch_cvwait` share fell 19.4-20.9% relative, and
the strict adjacent writer stack fell 26.6-29.7%. The authoritative
same-workload eight-quad ABBA nevertheless measured candidate/control total
child CPU **1.137399 [1.124574, 1.146825]**, user CPU **1.112970
[1.102824, 1.122284]**, system CPU **1.218661 [1.193188, 1.225041]**, and
workload wall **1.014402 [1.005370, 1.022172]**. The candidate won 0/8 quads
on every metric. The precise extra-cost root cause remains inferred rather than
proven; the no-retain decision does not depend on resolving it. Commits
`9e0b0817` and `3733eeef` were reverted in that order as `99ce4d0c` and
`89e82b84`. The reviewed diagnostics in `d4c84088` and parser correction in
`9a2788d6` remain, and the restored tree passed the full serialized CI and
23/23 native smoke gate. Full evidence:
[`docs/perf-results/2026-08-04-native-optimistic-decode.md`](docs/perf-results/2026-08-04-native-optimistic-decode.md).

The first restored-tree refresh then failed closed twice without contributing
performance evidence. At unchanged runtime/evidence `90e35cc6` and binary
SHA-256 `82572dd3f7da5f2a4252782038f2c52bec8b30f6cdd7f1fc3a121f13ccceae51`,
Task 8 A1 found 5,082 named-syscall kernel samples but only 5,081 samples in an
independently aggregated per-function view. A2 serialized a positive-duration
off-CPU stack with `count=0`, `total_ns=5125`: independent `ustack(24)`
evaluations had produced count and duration keys differing by a strict-prefix
extension. Both workloads reached natural, clean `BUILD_OK`, but both receipts
remain rejected and no B or attribution was admitted.

Commit `6fa105d2` (`fix(trace): unify native wall sample authority`) repairs both
producer flaws as raw v5: one aggregation owns kernel class, normalized
function, and PC, and one stack evaluation owns duration-only off-CPU evidence.
Kernel and targeted `psynch_cvwait` stacks remain exact positive-count
authority. Focused gates passed 63/63 trace-profile Rust tests, 21/21 integration
tests, and 58/58 affected Python consumer tests; Clippy/fmt/diff and
forbidden-shape scans passed. Independent review approved with no findings and
97% confidence. This was tracing/control-plane repair, not a runtime performance
change.

Task 10's first live v5 A proved the producer shape naturally and losslessly,
but its outer Python wrapper rejected only because its stale exact drop schema
did not know `dynamic_rinse_drops` and `dynamic_dirty_drops`. It remains
excluded; there was no retry, B, or attribution. Commit `8214c136`
(`fix(perf): synchronize trace drop schema`) updates all five strict Python
consumers to require the exact seven-field object: literal
`interrupted=false` plus six typed-zero counters. Missing, extra, mistyped, or
nonzero values fail closed. Named tests passed 16/16, affected modules 260/260,
and full Python discovery 516/516; independent review approved with no findings
and 97% confidence.

Task 12 finally accepted two fresh natural v5 captures at clean `8214c136`,
runtime/CLI source `6fa105d2`, and frozen signed binary SHA-256
`74a1c9be5325402bcf8d3c96e85d6551a5c7378dc067671dee2b5f64927418fd`.
A/B receipts are
`f33f58965cad00bf60c2bbec8bfbb1a56c09057219852382b09385242fe17349` /
`1e3a349e72f2087c9db3a4166cca134dcf5bf06b18860035ff59e92b7a91d13c`;
Every drop, lifecycle, cleanup, contamination, kernel PC/stack, off-CPU
duration, symbolization, and >=99% coverage gate passed. Regenerated analysis
matches the wrapper artifact at SHA-256
`8dadf9dd2c93a19ecf10e71fc29f443c9553ae1a465b8378cdcb45fcc001f02e`;
broad attribution is
`6aac67d71e571bf6f5b1eec9fbf8b9c4bfed3a3fa8e1a9275b4d93b618bccc18`.

The fresh stable all-CPU split is Darwin kernel **48.0232% / 48.7901%**,
translated guest **25.8818% / 25.3278%**, Darwin userspace **10.0290% /
9.9863%**, other Carrick **8.3174% / 8.5377%**, and translation **6.0589% /
5.9643%**. Kernel divides into named-syscall **27.7520% / 28.8889%** and
non-syscall **20.2712% / 19.9012%**. Carry no new family: exact host
`psynch_cvwait` is **11.1172% / 11.5775%**, but it is the already-attributed
closed lock line; the apparent larger `ml_set_interrupts_enabled_with_debug`
family is a rejected symbolizer alias, profiler/fasttrap and closed lines remain
excluded, and every remaining specific host syscall is below 6%. These shares
do not map whole host-syscall populations to guest operations. DTrace remains
mechanism evidence only, and the official scoreboard remains **10.1776x**.

The authenticated translated-guest follow-up is also complete at clean
`96b2b59e2c691427d2ad6e22a428e10c44fa15f2`, signed binary SHA-256
`515f299b40786f98da00779affe11be653ef8f3e9d1cac517b565bebff8058b3`.
The final A3/B3 cold-build captures used byte-identical target argv SHA-256
`7d3129d9ab334f45dd5ac246fb26d9f61d1a2d671b7fc5150be101e611c25bcb`,
the digest-pinned Go image, a 997 Hz DTrace template SHA-256
`b052c21296ae5c6d2df73efe3020f3f7ce77a2c080d3b6249c573c21c944a63b`,
and classifier `carrick.jit-shape-classifier.aarch64.v3`. Receipts are
`3eb91105a4f7b8863c89ba16e0c96d25a2091920ec09862f7489b33dc2a35e74` /
`7b837113de0a882fef4bcdcac053c3973dd90d0dd8b12a9720c9518233602500`,
raw traces `be4b032b18d9b5ef924502e4ca97bb397122e10c2b614564783aa01c1ffa5a20` /
`c04c26916ae87738482e078f4fa43a7fff039f1619ca5b58bd90a36da4dd1079`,
snapshot manifests
`9f2673d363c90dbba3e1f3db830aee83084849f4c2a05a78890d4d6658bc467f` /
`aebb2e5fcac72ec5cfaf63df105460866f6c049f234b2c88c80906ec6b4feab5`,
and byte-identical census SHA-256 values
`d913ea8ca62ff998a50e5452feeceec6ffd1a10d78ee2e522e98bbe6e3f9b0be` /
`1222a59eeeaeac7927350d9c95b00012fc630847c601d6a9ea19942a6670017a`.
The independently reconstructed comparison SHA-256 is
`afa49a045f29873b022ebb36880e885949206b19a3b988cc9fec8f9edf357ef7`.

All 12,226 / 12,302 JIT samples resolved, the complete populations were 36,966 /
37,317 all-CPU samples, and `mechanical_crossings` is empty. The largest family,
`ctx-load64`, is only **8.764810% / 8.481389%** of all CPU. The broader exact
inserted floor is **11.559271% / 11.394271%**, but it is exactly the sum of
`ctx-load64` and `ctx-store64`: source audit binds `ldr/str x17,[x28,#1128]`
to virtual-register recovery state in `emit_virtualized_register`, while
`ldr x19,[x28,#1192]` is separately the host-bias load in biased-memory
lowering. Superblocks already amortize their entry context work. Grouping those
source-distinct, already-closed mechanisms would manufacture a crossing, and
the common `mov x17,#0` row is guest-producible/exact-ambiguous. Decision:
**no-carry at 99% confidence**. A1 remains console-rejected; A2/B2 remain valid
pre-repair evidence but excluded from the final pair by analyzer identity.
Traced elapsed times are attribution metadata and change no baseline.

An independent final review approved exact range `96b2b59e..be1c36cf` with no
Critical or Important findings at **99% confidence**. It independently rebuilt
all 17 family, 2,387 word, and 24 context full-outer rows plus every share,
drift, and gate; reproduced the empty crossing set; verified both 622 MiB
snapshot manifests, accepted receipts, lifecycle/loss closure, frozen signed
binary, and exact evidence hashes; and independently disassembled and rebound
the four cited words to the emitter/classifier sources. Focused comparator
11/11, full JIT-shape 44/44, formatting, diff, strict-JSON, and commit checks
were green. The intentionally excluded live replay/rebuild is the only stated
residual risk and does not change the no-carry or official-score decisions.

## What landed (2026-08-02/03, six waves, all merged with `just ci` green)

**Exec pipeline.** Payload SHA-256 removed from the default artifact digest
(`CARRICK_EXEC_FAST=0` hatch); eligible PT_LOADs map `MAP_PRIVATE` from the
executable's own host file (`CARRICK_EXEC_FILE_BACKED=0`); execve probes read 1
and 256 bytes instead of walking the whole image twice. The per-exec chain is
~20 ms, of which ~5.3 ms is Darwin's own execve+dyld floor. The roadmap's "fixed
~18 ms" item was mis-measured and is corrected in place
([`2026-08-03-native-exec-fixed-cost-decomposition.md`](docs/perf-results/2026-08-03-native-exec-fixed-cost-decomposition.md)):
the zygote shape cannot exist under the libdispatch and PID-preservation
constraints, and the real win there was a per-MB term misfiled as fixed.

**Tier D (direct execution).** From "a guest could only leave by calling exit"
to: exit path plus a written guest-leave contract, dynamic linking (real glibc
`ld.so`), guest-created executable pages (`mmap(PROT_EXEC, fd)` scan+patch, two
lowerings), per-thread TLS via a **runtime-proven** Darwin TSD chain, wiring
into the shipped driver with fork/vfork/execve and real fd passthrough, and
async signal delivery + `rt_sigreturn`. Live-verified: `/bin/dash -c 'echo hi'`,
real CPython `print(1)`, real CPython `threading.Thread`, `timeout 1 sleep 5` →
rc=124 all-tier-D. Everything unproven fails closed with a named reason.
Reachable behind `CARRICK_NATIVE_DIRECT=1`; **default OFF** (blockers below).

**Persistent translation store.** Per-host, keyed by image identity, single
publisher elected via non-blocking host locks, LRU-pruned, crash-safe, corrupt
store fails closed to local translation. Template emission reached **parity with
native emission** (proven by disassembly plus a word-identity test) once the
regression was root-caused to block-ENTRY shape — an 11-12 instruction
`BindingIndex` guard versus a 3-instruction trusted entry, NOT the recorded
fusion-loss suspect. The v5 wire splits each block into a hot blob (decoded at
first lookup) and a cold blob (pc-map/recovery, ~98% of records, left undecoded
in the mmap until a fault needs it). The persistent store is now **default
ON**; exact
`CARRICK_DSR_PERSISTENT_STORE=0` is the rollback/control hatch. Its retained
same-binary result was -8.33% child CPU and -8.84% workload wall. Roughly 22k
lines of superseded machinery (the Mach-O emitter, the
codesign+dlopen transport, `BindingIndex`, cell sidecars, edge trampolines, V3
metadata) were DELETED, not parked behind flags.

**Memory.** Protection bookkeeping went from one BTreeMap entry per 16 KiB page
(~295k entries per Go process, re-consulted on every dispatch write) to
coalesced intervals — anon reservations are O(1), and the fixture that pinned it
went 1.66 s → <10 ms. Identical host syscall sequence, identical guest ABI.

## What's next

The exec/exit, context-traffic, fault-publication, residual-allocation, broad-
attribution, and memory-intent lines are closed at measurement. Their exact
exporters and censuses remain opt-in diagnostics. A crashed run can also be
read from a saved core through the always-on event ring. The lock split is a
retained CPU win; its ABBA wall interval did not resolve below parity. The
user-requested serialized current-default refresh is nevertheless complete and
sets the official absolute scoreboard to 10.1776x without converting that
scoreboard movement into a causal lock-split claim.

1. **Return to the next broad Task 12 host/kernel opportunity.** Authenticated
   NativeShape attribution is closed with no selectable >=10% emitted-code
   mechanism. The next non-regrettable measurement is a source- and
   KDK-address-bound split of the stable non-syscall Darwin-kernel population
   (**20.2712% / 19.9012%** of all CPU), excluding profiler/fasttrap families,
   symbolizer aliases, and already-closed lines before selecting one mechanism.
   No implementation candidate is authorized yet.
2. **Keep eager full translation as a deferred future design, not the next
   patch.** Translating a complete eligible image once up front could amortize
   publication and avoid the losing per-process merge path measured here. It
   would not replace incremental augmentation for JIT-on-JIT/dynamically
   generated code, so both semantics would eventually be required. The user
   explicitly deferred this until the current performance campaign has a
   higher-confidence next bucket.
3. **Tier D remains default-off.** Its ubuntu image-specific x18 crash,
   multi-threaded fork/signal tail, bad64 decode gap, and record-lock blocker
   still require correctness closure before any performance flip.

## Confidence

- **Very high (99%):** the memory line is correctly stopped. Both accepted
  captures are lifecycle-complete, and the largest exact sequence reaches only
  6.56% / 6.35% under a deliberately favorable cost model.
- **Very high (98%):** the original ProcessState reader mechanism is correctly
  attributed. Two clean captures agree within 0.11 percentage points on the
  combined lock path, and candidate captures show both source paths gone.
- **Very high (98%):** the lock split reduces total CPU. All 8/8 ABBA quads win,
  the 95% interval excludes parity by 7.89 percentage points, and the system-
  CPU movement agrees with the `psynch_cvwait` mechanism.
- **High (94%):** the mirror preserves publication/invalidation semantics.
  Publication ordering is explicit, all 226 crate tests pass, and the full
  serialized repository gate is green.
- **Very high (99%):** the optimistic decode-outside-writer candidate is a
  regression and must not be retained. The accepted 34-sample campaign lost all
  eight quads, and every CPU and wall interval excludes parity in the wrong
  direction.
- **High (97%):** the preserved optimistic-discard diagnostics and validator
  remain semantically useful. They are typed, fail closed, passed 165 tests,
  and naturally report zero on the restored serialized path.
- **Very high (99%):** the authenticated NativeShape A3/B3 pair is valid and
  carries no selectable emitted-code mechanism. Receipts, manifests, double
  censuses, comparison regeneration, full outer joins, exact arithmetic, and
  source binding all reconcile; no row crosses 10% in both arms, and the only
  aggregate above 10% combines distinct closed mechanisms.
- **Very high (99%):** the fresh v5 A/B pair is valid. Both exact receipts,
  every reconciliation and coverage gate, deterministic regeneration, and the
  stable broad analyzer agree.
- **Very high (98%):** the fresh pair carries no new selectable family. The
  apparent interrupt alias is excluded, the only qualifying exact syscall is
  the already-closed lock line, and all remaining specific syscalls are below
  6%.
- **High (90%):** returning to the broad Task 12 host/kernel split is the
  smallest non-regrettable next step. The non-syscall kernel bucket is stable
  and large enough to matter, but no implementation confidence is claimed
  until a source-distinct mechanism survives the repeated >=10% gate.
- **High (95%):** the official shipped-default result is now 10.1776x. No
  projection or unresolved wall result was substituted for a fresh
  Carrick/Docker run.
- **High (90%):** the sequential ≥10% policy is the right route toward 3x.
  The 8.50% lock split is a justified exception because it removes a measured,
  source-distinct wait and enables the next lock reduction; it is not described
  as sufficient movement toward 3x by itself.

## Discipline that earned its keep (do not relearn these)

- **The perf knobs are HOST env vars.** Passing them through `carrick run -e`
  makes both ABBA arms identical — an entire measurement round was invalidated
  this way and read as "no effect".
- **Rebuild and prove the binary.** `just build` after runtime changes, then
  `strings -a target/release/carrick | grep <knob>`. A second round was
  invalidated by measuring a pre-merge binary, and it was caught only because
  the numbers contradicted mechanism-level counters.
- **Verify every merge with the FULL serial suite, twice.** Two defects reached
  the merge gate that the lanes' own green runs missed: a cross-lane SIGTRAP
  (which turned out to be a fork-poisoned libdispatch semaphore masking a real
  panic) and a suite-order failure from tier D hint cursors colliding with
  `BIAS_CANDIDATES` to the digit.
- **Attribute before fixing.** Three investigations each redirected the campaign
  off a wrong target: the build is amplified, not serialized; the template
  regression is entry shape, not fusion; lazy install alone could not win
  because `compile` touches ~99% of its unit's blocks.
- Counter and mechanism evidence beat wall clock under load. Wall numbers taken
  with siblings running are "suggests", never "confirmed".

## Branch state at handoff

Current branch authority before this controller-hygiene commit is
`8214c136`. Current runtime/CLI trace authority is `6fa105d2`; the only later
commit is the reviewed Python consumer repair `8214c136`. Commits `87ab04f9` and
`44de0656` retain the export-only, lifecycle-complete memory-intent census;
`98ae5e26` and `c4be3c23` retain exact syscall and `psynch_cvwait` stack
attribution; `64bebc26` is the measured published-block index split. The losing
optimistic implementation commits `3733eeef` and `9e0b0817` are neutralized by
reverts `89e82b84` and `99ce4d0c`; diagnostics commit `d4c84088` and parser
commit `9a2788d6` remain. The frozen signed v5 binary has SHA-256
`74a1c9be5325402bcf8d3c96e85d6551a5c7378dc067671dee2b5f64927418fd`.
The clean detached optimistic-decode ABBA control remains at `a5bd4971` in
`.worktrees/native-optimistic-control`; do not delete it until controller
closeout. The last full `RUST_TEST_THREADS=1 just ci` and
`just conformance-native smoke` (23/23 MATCH) apply to the restored runtime tree
at `89e82b84` and evidence/handoff commit `90e35cc6`. Later `6fa105d2` trace
producer/parser and `8214c136` Python consumer changes have focused gates,
independent reviews, and the fresh accepted v5 A/B qualification described
above; no full `just ci` or native smoke is claimed at current HEAD. Nothing has
been pushed and local `main` has not moved. Target-only raw ABBA, mechanism,
signed-binary, store, attribution, and scoreboard receipts remain under
`target/perf/` and are intentionally not committed. Eager full translation is
deferred, incremental augmentation remains required for JIT-on-JIT, and Tier D
remains default-off.
