# Native-lane performance: state of play

**Date:** 2026-08-04 · **Branch:** `codex/native-store-default` · **Latest
decision:** fresh current-retained-tree v5 attribution is accepted, but carry no
new source-distinct family; the proposed next step is an authenticated typed
`NativeShape` profile/Rust census and awaits explicit design approval ·
**Scope:** Darwin/aarch64 native backend (`--exec-backend native`, the shipped
default). VMM is explicitly NOT the target: one process per VM against a
~127-VM macOS ceiling makes it a dead end for build-shaped workloads.

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

1. **Await explicit design approval for `NativeShape`; do not implement or
   capture it yet.** The fresh broad pair makes translated guest the next stable
   unsplit bucket at 25.88% / 25.33% of all CPU. The existing generic
   `native-cpu-attribution.d` plus `shape_classify.py` mechanism is not evidence
   authority: generic `carrick trace --script` lacks a typed receipt/program
   hash and the classifier does not bind raw trace, snapshots, source, binary,
   image, command, or run IDs. The proposed next task is to adapt it into an
   authenticated typed `NativeShape` profile and Rust census (or an equivalently
   complete immutable manifest), then require one non-overlapping, non-closed
   emitted shape to clear 10% of all CPU twice. This is a proposal, not an
   approved design, guest-operation mapping, or source-change recommendation.
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
- **Unscored pending attribution:** no specific next implementation candidate
  is promoted from the losing arm or fresh broad pair. Confidence will be
  assigned only after an explicitly approved, authenticated `NativeShape`
  design names a non-closed source-distinct >=10% opportunity.
- **Very high (99%):** the fresh v5 A/B pair is valid. Both exact receipts,
  every reconciliation and coverage gate, deterministic regeneration, and the
  stable broad analyzer agree.
- **Very high (98%):** the fresh pair carries no new selectable family. The
  apparent interrupt alias is excluded, the only qualifying exact syscall is
  the already-closed lock line, and all remaining specific syscalls are below
  6%.
- **High (90%):** authenticated emitted-shape attribution is the smallest
  non-regrettable next split, but no implementation confidence is claimed
  before explicit design approval.
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
