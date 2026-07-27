# Native-lane performance handoff

**Date:** 2026-07-27
**Branch:** `codex/native-aarch64-container-cache`
**Scope:** Darwin/aarch64 native DSR (`--exec-backend native`, the shipped
default). No VMM/HVF/KVM/bhyve behaviour was touched.

> Supersedes the FreeBSD native x86 bring-up handoff (`1b55b4b0`, branch
> `perf/native-xstate-transfer`). That work is unrelated to this and still open;
> read it from git if you are picking up x86. Its live caveat still stands:
> **`neutral-domains` remains opt-in — do not make it the production default
> until Tasks 43, 55 and 58 close.**

---

## Current state

Goal in flight: **get carrick's overhead on real workloads toward 2x.** The
first session took the reference workload from **15.7x to 10.7x** under its
CPU-overhead convention. The continuation on
`codex/native-aarch64-container-cache` reduced the authoritative wall median
from **21,786 ms to 19,485 ms** (−10.56%). This is meaningful progress, but it
is not close to the 2x destination and must not be presented as completion.

The earlier fusion/gateway work is on `main`; the continuation is committed on
the branch named above. `just ci` is green and
`just conformance-native smoke --workers 4` is clean (no regressions, including
`go-sync` 52/52 and `cpython-threading` 193/193 — the suites that would break
first if fused atomics or shared generation authority were wrong).

Reference workload: the conformance `go-build` case — `go build` of a
hello-world with a cold `GOCACHE`.

| state | wall | vs baseline |
|---|---|---|
| session start | 31,965 ms | — |
| + exclusive fusion (`8ffcbb4b`) | 23,650 ms | −26.0% |
| + gateway indirection (`26de3c07`) | **21,786 ms** | **−31.8%** |
| + two-way chaining + cold-publication cleanup (`deb9a80e`) | **19,485 ms** | **−39.0%** |
| Docker oracle | 942 ms (2.26 CPU-s) | — |

Every carrick figure is five untraced back-to-back runs on an idle machine,
median reported. **Measure this way or not at all** — see Traps.

The workload now has a checked-in runner:
`scripts/perf/native_go_build.py`. The authoritative continuation evidence is
`scripts/perf/evidence/native-go-build-post-cache-v1.json` (19,485, 19,392,
19,342, 19,707, 19,917 ms; clean commit and accepted idle-host preflight).

## 2026-07-27 continuation

### Default-path wins retained

- The per-thread indirect target cache is now two-way set associative (2 MiB
  per thread). Against the old direct-mapped profile, indirect resolver exits
  fell **1,509,230 → 862,580** (−42.9%) and total gateway entries fell
  **3,037,449 → 2,395,609** (−21.1%).
- Translation no longer captures source words unless artifact recording or
  shared-unit publication is enabled. Emitted PC maps, direct links and
  recovery metadata move into process ownership instead of cloning.
- AArch64 cold publication no longer enters a second mutex/B-tree arbitration
  index. `ProcessState::translate` already holds the process write guard and
  rechecks the authoritative block map under it; profiles recorded zero
  duplicates across ~1.87M translations. Clean-profile publication time fell
  **2.824 s → 1.148 s** (−59.3%).
- `InstructionMap` validates monotonic emitted offsets in one scan rather than
  allocating and sorting a second vector. Keep this as dead-allocation removal;
  its isolated five-run wall result was inside host noise.

Profile evidence:
`scripts/perf/evidence/native-go-build-post-cache-profile-v1.json`.

### Active wall-time attribution campaign

The next campaign is governed by
`docs/superpowers/specs/2026-07-27-native-wall-time-attribution-campaign-design.md`
and tracked in `docs/perf-results/native-wall-time-campaign.md`.

Its primary metric is the cold-GOCACHE `go-build` Carrick/Docker wall-time
ratio. The checked-in 19,485/942 ms pair is a historical 20.68x reference, not
the official campaign denominator: the first milestone refreshes five
untraced samples on both sides, in separate phases. Whole-process-tree DTrace
then partitions elapsed wall state and on-/off-CPU resource time before the
next optimization is selected. Node and CPython remain guardrails.

The measured official baseline is `C0=19,375 ms` (five fresh untraced Carrick
samples), `D0=1,007 ms` (five fresh native-arm64 Docker samples), and
`R0=19.2403x` (`C0 / D0`). It replaces neither the historical 19,485/942 ms
reference nor any one-sample screen.

The M1 attribution gate is now closed at commit `34ce4c3c`. The user explicitly
lowered the CPU classification threshold from 90% to 85% so the campaign could
return to wall-clock work. The clean `688357ef` pair classified 88.3%/89.8% of
CPU samples, reconciled 100% of wall samples with zero drops, and kept all
categories above 10% within five percentage points. Translated guest execution
and Darwin kernel work are about 71% of sampled CPU together.

The first post-M1 cache isolation found a concrete step-function seam:

| untraced one-sample screen | wall |
|---|---:|
| default control | 19.809 s |
| full shared translation | 40.211 s |
| full shared translation without publication `fsync` | 39.98 s |
| publish only; never load | 20.74 s |
| load/parse unit; skip eager block indexing | 22.78 s |
| cap unit to 10,000 / 1,000 / 250 / 100 blocks | 41.49 / 37.62 / 21.30 / 20.44 s |

The kept full-cache census contained four dylibs (about 28 MiB) and four
manifests (about 49 MiB). Publication is not the regression: removing all
durability syncs changed almost nothing, and publishing while translating
normally adds only about 0.93 s. A 100-block cap collapses the regression but
does not beat default, confirming a size cliff.

The first isolation made eager metadata indexing look responsible, but the
implementation spikes falsified that interpretation. Fully lazy metadata took
57.45 s; retaining only the compact guest-entry index took 39.12 s, barely
better than the original. Omitting the portable generation guard still took
38.73 s. All were reverted.

The reconciled shared-mode count profile identifies the real amplification:
**262,216,112 gateway entries**, including **68,932,094 direct resolver exits**
and **62,056,062 indirect resolver exits**, with 127.1 child CPU-s. The default
profile had 2,395,609 gateway entries, 1,433,321 direct exits, 862,580 indirect
exits and 43.8 child CPU-s. Translation fell only 1,867,805 → 1,256,885, nowhere
near enough to repay roughly 260 million additional exits. Filtering to a
transitively closed direct-target subset made things worse (55.24 s) and was
also reverted.

**H004 is selected as `SPIKING`:** the first immutable-code-compatible
late-binding precursor now carries exact
target authority through the two-way per-thread cache. It is correct across
private/shared and cross-unit targets, and translator ABI 2 rejects the old
16-byte cache population. Three untraced samples were stable at 25.169,
25.268 and 25.082 s. That recovers much of the 40.2 s shared-mode regression,
but it is still slower than the 19.375 s official baseline and is not a
retained primary-goal win.

A natural resolver-only DTrace run measured 941,784 remaining indirect misses.
Although 82,266/124,947 source sites were monomorphic, the top one/two targets
cover only 44.6%/54.9% of miss events; the hot tail is high-entropy. A second,
bounded trace saw 17,155,262 direct misses in 45 traced seconds. Its hottest
edge alone fired 1,473,595 times: `0x1a748 → 0x1a74c`, verified in the native
arm64 Docker oracle as Go `compile`'s `CBZ R1` fall-through.

Two conditional-edge spikes are rejected and reverted. Emitting the full
authority-aware lookup at every private/shared edge exhausted the 64 MiB
private JIT cache. Restricting it to portable artifacts produced one 24.664 s
sample, then crashed in Go runtime stack code on replication. Do not resurrect
that inline family.

**Next implementation target:** an immutable-code-compatible, compact per-edge
binding sidecar. Each loaded unit should own mutable cells keyed by stable edge
identity; the cell must publish target PC plus executable authority/version,
and the short immutable edge stub must have explicit asynchronous recovery
coverage. Screen two untraced runs first, then require five samples to beat the
official 19.375 s baseline and pass correctness guardrails.

### Portable translation reuse is correct but not a default performance win

The container-scoped design is implemented through image-digest keys, portable
artifact normalization, immutable signed Mach-O units, exec-carried authority,
unit-scoped generation bindings and cross-unit fail-closed chaining.
`CARRICK_DSR_ARTIFACT_SPIKE=1` and
`CARRICK_DSR_SHARED_TRANSLATION=1` remain explicit opt-ins:

- artifact replay median: 19,967 ms versus its 19,759 ms nearby control;
- signed shared-unit variants: 31–77 s, depending on unit policy.

The correctness seam is worth keeping, but enabling it by default would be a
regression. The next design must amortize signing/dlopen at a much coarser
granularity and publish early enough for sibling compiler processes to reuse
the code.

### Experiments stopped

- startup Clap/bincode fast path: 19,748 ms versus 19,759 ms control;
- eager return-continuation priming: 19,676 ms versus 19,614 ms control;
- four-way 4 MiB target cache: 19,705 ms;
- two-way 1 MiB target cache: 19,735 ms;
- custom block-index hasher: 19,464 ms versus 19,466 ms control.

All were reverted. Do not resurrect them without new evidence.

### Verification receipts

- Signed native demo: Linux `aarch64`, Go 1.24.13, compile and execute
  `native-go-ok`.
- `just conformance-native smoke --workers 4`: 23/23 MATCH, including
  `go-sync` 52/52, `cpython-threading` 193/193 and
  `cpython-subprocess` 278/278.
- `just ci`: green after the final implementation commits.
- Red-first tests cover cache collisions, trusted private-cache entry,
  shared-unit authority, cross-unit rejection, portable image isolation,
  metadata ownership, monotonic PC maps and redundant publication removal.

## Commits

| commit | what |
|---|---|
| `477d2df5` | Probes + tooling + the CPU attribution that found everything else. |
| `52011a46` | Root-cause writeup of the 40x CPU gap. |
| `8ffcbb4b` | **Biased-mode exclusive fusion enabled** — the big win. |
| `26de3c07` | **Gateway exit addresses moved into `DsrContext`** — smaller win, and the prerequisite for sharing translations. |
| `423895d5` | Container-scoped portable translation reuse plus the default two-way cache and allocation reductions. |
| `deb9a80e` | Remove redundant AArch64 cold-publication arbitration. |

Findings doc:
`docs/superpowers/specs/2026-07-26-native-cpu-attribution-findings.md`.

---

## Completed progress

### Exclusive load/store no longer traps on every atomic

76% of **38.9M gateway exits** on one hello-world build were
`sensitive_exclusive` — `LDXR`/`STXR`. Go takes an atomic on every mutex,
channel op, scheduler transition and GC write barrier, so this was most of what
the guest did.

The lowering that avoids it (`block::analyze_exclusive_region`) already existed,
and fused **nine** regions in that entire build while reporting **14,916,457**
sites as `fusion_eligible_backend_disabled`. Fusion shipped enabled only in
`Direct` address mode; production runs `Biased`.

The gate was one documented obligation that decomposed into two claims which are
not the same kind of thing:

- **Registers** — the lowering clobbers exactly two guest GPRs. Both are already
  spilled to context slots 1120/1128 before either changes, every emitted word in
  the clobber window already carries a `RecoverBiasedExclusive` entry, and
  `recover_rewrite_state` already restores both on the fault and kick paths. Live
  code, not new work.
- **NZCV** — nothing to roll back. No DSR-inserted word in the region writes
  flags. The correct gate is a **static assertion**, not a recovery mechanism.

Resume legality is per word via the PC map, not a rewind. A blanket
restart-from-load would be *unsound*: an accepted body may contain a
non-re-derivable `add w9, w9, #1` that restarting double-applies.

Result: `sensitive_exclusive` 29,589,283 → **0**; exits 38.9M → 8.9M; CPU
88.7s → 53.1s.

### Gateway addresses no longer baked into every block

Each block exit materialized its gateway entry point as a four-word
`movz`/`movk` chain — three words more than a load, on every exit, and it bakes
a **host code address** into translated bytes. Guest processes self-reexec with
different ASLR slides, so such a block is valid only in its emitting process.
Now `ldr x17, [x28, #off]; br x17`, with the six new `DsrContext` slots pinned by
`offset_of!` asserts on both the Rust and C sides.

### A latent trampoline bug, found by accident

The taken edge of a conditional direct exit was emitted as `0x1400_0012` —
hardcoded "branch forward 18 instructions", silently encoding the *length of the
gateway stub emitted after it*. Shortening that stub sent the taken edge three
instructions **into** it, past its `mov x17, <target>`, publishing whatever `x17`
held as the guest's branch target. Latent before this session: **any** change to
stub length would have mis-branched every conditional direct exit. Now a dynasm
label.

### Observability

The Darwin native lane fired **neither** `execve-argv` nor `guest-exit`, though
the shared and FreeBSD native lanes fire both — the shipped default backend was
invisible to tracing at process granularity. Both now fire, plus new
`host-image-base` / `guest-image-base` probes so each guest process announces its
own image base/slide/path and a profile can be symbolicated after the
(short-lived) process exits.

| path | what |
|---|---|
| `scripts/dtrace/guest-process-census.d` | Per-guest-process shape and lifetimes. Deliberately cheap. |
| `scripts/dtrace/guest-translation-census.d` | Translation volume per image. Expensive; counts only. |
| `scripts/dtrace/native-cpu-attribution.d` | Sampled CPU attribution, windowed + raw PC histogram. |
| `scripts/symbolicate.py` | Offline per-pid symbolication against host **and** guest images. |

---

## Where the remaining time goes

Post-fusion, on 53.1 thread-seconds of CPU (phases overlap where translation
nests, so they do not sum to 100%):

| phase | CPU | share |
|---|---|---|
| `phase_translate_ns` | 28.3 s | **53%** |
| `phase_translated_run_ns` | 19.9 s | 37% |
| `phase_prepare_index_ns` | 6.9 s | 13% |
| `phase_syscall_dispatch_ns` | 4.1 s | 8% |
| `phase_finish_exit_ns` | 0.7 s | 1% |

The residual **8.9M gateway exits** are now almost entirely one thing:

| exit kind | count | share |
|---|---|---|
| `exit_resolve_indirect` | 7,388,024 | **82.9%** |
| `exit_resolve_direct` | 1,415,702 | 15.9% |
| `exit_syscall` | 101,606 | 1.1% |
| `exit_sensitive` | 540 | 0.006% |

**Translation is now the largest single cost**, and it barely moved when fusion
landed (31.6 → 28.3 s): fusion merged exclusives into blocks but did not reduce
how many distinct blocks get translated. The same few binaries are translated
from scratch 65 times per build (27 `compile`, 34 `asm`, 2 `link`, the driver,
the output binary).

Separately measured and unaddressed: **~18% of all CPU is carrick re-running
container/capsule setup per guest process** — serde JSON 8.2%, SHA-256 of the
executable 3.9%, volume mountpoints 2.4%, clap arg parsing 1.2%. Docker does none
of this per process.

---

## Prior work ranking and disposition

### A. Translation cache — largest lever, 28.3 s

Scoped by the project owner to **the container's lifecycle**: share across the 65
guest processes of one `carrick run`. Durable cross-run caching is out of scope.

**Use the on-disk signed Mach-O path, not Mach named memory entries.**
`crates/carrick-native-darwin/src/aot.rs` (`2ae15078`) already emits a loadable
`MH_DYLIB` by hand with `HEADER_SLACK` reserved for `LC_CODE_SIGNATURE`, proven
end-to-end (emit → `codesign -s -` → `dlopen` → `dlsym` → call). A design pass
concluded file-backed executable memory was dead because raw
`mmap(FILE|*, r-x)` returns EPERM — that is a **false negative**: we do not
raw-mmap, we `dlopen` a *signed* dylib, which is the AMFI-sanctioned route, gets
cross-process sharing free via the unified buffer cache, and survives `execve`
trivially.

Publish costs from `crates/carrick-native-darwin/examples/aot_bench.rs`:
1 MiB = 80 µs emit / 15 ms sign / 105 ms cold dlopen; 64 MiB = 10 ms / 122 ms /
449 ms. Signing dominates and is a subprocess; an ad-hoc signature is just a
CodeDirectory of page hashes and could be emitted in-process.

**Remaining prerequisite before a block is portable:** gateway addresses are done,
but `GenerationAddress` / `GenerationExpected` are still process-varying and need
the same treatment.

**Do not re-derive per-block relocation.** `artifact_spike` already built
normalize-then-rebind and measured it **2.95% slower** at 71,244 cross-process
hits and **21.7% slower** at 931,094. Verdict `STOP_PER_BLOCK_ARTIFACT_CACHE`.
Any design that *writes* to a block per process collapses back into that.

**Highest-risk hazard, and it is silent:** *guest VA is not a code identity.* Two
guest images can hold different text at the same VA, so a VA-keyed shared cache
hands one process another's code — wrong compiler output, no crash, and LTP will
never see it. The key needs image identity (dev/ino/size/mtime, segment offset,
address-mode tag). Red-first test: two ELFs with identical load placement and
different text, run concurrently as siblings in one `carrick run`.

### B. Indirect branch chaining — 7.4M exits, 82.9% of the residual

`ret` is `br x30` on aarch64 and Go is call/return-heavy, so every function
return leaves translated code. The x86 lane already has edge patching
(`CARRICK_NATIVE_X86_EDGE_BARRIER`); aarch64 does not.

### C. Per-gateway-entry cost — 6.9 s over 38.9M entries (~290 ns each)

`phase_prepare_index_ns`. Only partially addressed by (B).

### D. Stop re-running capsule setup per guest process — ~18% of CPU

Hash the executable digest once; skip clap/serde re-parse on self-reexec.

### E. Calibration

Published same-ISA DBT (AArch32→AArch64, MAMBO, PLDI'16) runs under **7.5%**
overhead. We are far above that, so treat "translation is inherently expensive"
as refuted — the gap is defects, not physics.

## Next work, ranked by current evidence

1. **Make coarse portable units cheap enough to win.** The correctness path is
   present, but signing/dlopen and late publication overwhelm saved
   translations. Measure unit production/consumption by executable and publish
   one immutable unit before sibling fan-out; do not reintroduce per-block
   rebinding.
2. **Reduce the remaining 862k indirect exits.** The two-way cache proved
   collision pressure was real. The residual is now the next chaining target:
   classify return/call-site locality and test a bounded return-target strategy,
   retaining only a five-run win.
3. **Reduce emission cost.** The clean profile spends 5.806 s in emission for
   1.868M translations. Attribute assembler allocation, relocation recording,
   cache publication and icache work separately before changing code.
4. **Revisit per-process capsule setup only with a process-lifetime trace.** The
   attempted Clap/bincode shortcut was noise. Digest and mountpoint reuse may
   still matter, but the old ~18% sample needs fresh attribution after the
   translation changes.

---

## Traps — read before measuring or debugging here

**Never time a hot path by bracketing its own probes.** Bracketing
`dsr-translate-begin`/`-end` fires ~3M USDT probes and each pair's cost lands
*inside* the window being timed; it reported 17.7 s of translation inside a 19 s
window. Sample instead; use per-block probes only for exact counts.

**Guest processes self-reexec, so each has a different ASLR slide.**
Symbolicating against one assumed base yields plausible, wrong symbols — that is
what made bad64's decoder look like the hot path when it is 0.2%.

**Measurements are load-coupled, and this bit twice.** One run was 6x slow
because 44 orphaned spin loops — leaked by a subagent load-injection experiment
whose parent died before its `kill` — burned CPU for 93 minutes. Another was
invalid because it ran while three agents were compiling. Before any perf run:
`ps -eo pid,args | grep "while :"`, check `uptime`, let the machine go quiet.

**Agents sharing a worktree destroy each other's edits.** A subagent restoring its
red-first mutation with `git checkout <file>` silently reverted an unrelated
concurrent change in the same file.

**Disassemble before theorising.** Four hypotheses about the trampoline bug were
wrong; dumping the emitted block found it in one step. `bad64::decode` over
`emitted.entry()` is the fastest path to truth.

**Adversarially verify agent-written tests.** Of three, one was tautological: it
hardcoded the policy and called `plan_with_reader` directly, bypassing the very
function the change touched, so reverting the production mapping left it green.
Replaced by `biased_address_mode_selects_the_enabled_fusion_policy`, which was
*shown* to go red on that revert. Extracting `fusion_policy_for` from `plan_block`
is what made the shipped decision assertable at all.

**Docker/registry.** `just conformance-quick` blocks on `localhost:5005`
(`vt-ferry-registry`) to check image freshness. With Docker down it hangs on I/O
indefinitely — 44 minutes at 0.42 s CPU before it was noticed. Start Docker and
`docker start vt-ferry-registry` first.

---

## Open / unverified

- **Conformance perf outliers moved and it is unexplained.** Between two runs
  `node-app-smoke` went 27x → 48x and `cpython-glob` 38x → 48x. Very likely load
  (the second followed a full CI, unisolated) but **unmeasured**. Re-measure
  cleanly before reading anything into it. `go-build` is measured properly and
  improved.
- **The `InstructionMap` dead-`BTreeMap` removal shows no measurable wall-clock
  win**, against a 3–10 s estimate. Kept for dead-work and retained-memory
  reduction only (two maps per block × ~1.5M blocks). Not a speed win; do not
  claim one.
- **Exposing all 10 CPUs made things worse** (`CARRICK_EXPOSED_CPUS=10` →
  34.8/38.9 s vs ~31.4 s on the 4 P-cores). More guest parallelism currently
  costs more than it buys. `host_facts.rs` still exposes
  `hw.perflevel0.logicalcpu` behind an HVF-era rationale that does not apply to
  the native lane — the comment is stale even though the value is currently right.
- **The async-interrupt oracle test asserts on a microarchitecturally-determined
  PC distribution** (which words a kick lands on). It passed with wide margins
  here — 7,812 kicks, 15 distinct landing words, all five classes — but could
  false-red on other silicon. A reviewer also found
  `BiasedExclusiveResume::{Load,Exact,Retry}` semantically inert:
  `recover_rewrite_state` never reads it and resume semantics live entirely in the
  PC map, yet four tests pin it. Either wire it or delete it.
- **`cargo clippy -p carrick-runtime --all-features`** fails with ~67 pre-existing
  compile errors (broken feature combination), so that invocation is not a usable
  gate. Unrelated to this work.
