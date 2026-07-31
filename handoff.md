# Native-lane performance handoff

**Date:** 2026-07-30
**Branch:** `codex/native-performance-m1` (M1 correctness checkpoint
`5020e509`)
**Scope:** Darwin/aarch64 native DSR (`--exec-backend native`, the shipped
default). No VMM/HVF/KVM/bhyve behaviour was touched.

> The FreeBSD native x86 bring-up work (`1b55b4b0`, branch
> `perf/native-xstate-transfer`) is unrelated and still open; its live caveat
> stands: **`neutral-domains` remains opt-in — do not make it the production
> default until Tasks 43, 55 and 58 close.**

Historical M1 and pre-M2 evidence is in
[`docs/perf-results/2026-07-29-native-cpu-budget-evidence.md`](docs/perf-results/2026-07-29-native-cpu-budget-evidence.md),
runs 1–31. Current M2 execution state is recorded here and in
`.superpowers/sdd/2026-07-30-native-performance-m2-translation-ownership/`;
its ignored raw trace receipts remain under `target/perf/`.

---

## Current checkpoint — M2 fork replay accepted, speed result still open

M2 now has an accepted process-owned translated-range catalog through the
first real shared-code consumer and checked post-fork replay. This is an
observability/correctness milestone, not a performance result.

The retained signed binary is
`403b12878e36412943c0c5b79ba2271d11b0afbf77f2036afafa2211e610d69f`.
Strict codesign and `__DATA,__dof_carrick` verification passed. The shared
install path now:

- derives a stable typed unit identity and exact PC-map guest ownership;
- prepares catalog, block/index, direct-binding, dependency, retention, and
  executable-range state without logical mutation on recoverable failure;
- emits the shared catalog record first and release-publishes executable
  authority last;
- distinguishes block-start ownership from converging sensitive-terminal
  ownership; and
- has an actual-path regression test proving catalog event, complete logical
  install under the old executable head, then head publication.

The maintained
[`scripts/dtrace/native-translated-range-catalog.d`](scripts/dtrace/native-translated-range-catalog.d)
now fails closed over:

```text
shared-range announcement
  -> post-commit kind-12 unit-loaded
  -> PROFILE-only gateway entry inside that exact half-open range
```

It keys state by PID incarnation, keeps retained identities/addresses/epochs
at explicit 64-bit width, separates commit failures from optional run-witness
failures, and records root status, DTrace drops/errors, and every violation in
its schema-2 summary.

Accepted live receipts:

| mode | run ID | result | trace SHA-256 |
|---|---|---|---|
| semantic, profile absent | `m2-shared-commit-proof-019fb496-20260731i` | 2 announcements, 2 matched unit loads, `commit_ok=1`, `run_ok=0`, zero commit violations/drops/errors, clean exit and cleanup | `734124bf58941cd3d544d3d313fd8c823f4825a7bea76a0e2216f438a5f97cde` |
| trace-only, profile enabled | `m2-shared-run-proof-019fb496-20260731j` | 2 announcements, 2 unit loads, 2 in-range gateway entries, `commit_ok=1`, `run_ok=1`, every violation/pending/drop/error counter zero, clean exit and cleanup | `9d2868d56e29566071c17932bf43c9ead97f7b5575fc28cd77a2d544000a235d` |

The profile-enabled final child independently reported
`shared_unit_loads=2`, `shared_blocks_mapped=1168`, and
`shared_translations_avoided=2`.

Preserve the rejected precursor
`m2-shared-commit-proof-019fb496-20260731g`: it said `commit_ok=1` but exposed
DTrace dynamic-array truncation (`0x10edbc380 -> 0xedbc380` and a unit ID to
its low 32 bits). Commit `0c13a7bf` corrected the complete retained scalar
path; only the later `...31i` and `...31j` receipts are accepted.

Fork replay landed as `488e569d`, with failure hardening in `c771e23a` and the
bounded real-COW supervisor cleanup in `b32bb6f6`. It now:

- validates the complete active catalog and ready frontier before emission;
- advances the epoch with checked failure propagation;
- replays reset/private/shared/ready under the process writer and re-keys
  retained shared events for grandchild forks;
- clears the thread cache only after process replay succeeds; and
- aborts the open runtime resume service exactly once before any rebuild,
  fork-post, syscall-completion, stack-mutation, or guest-resume event on
  failure.

Focused catalog, fork, runtime failure, full DSR library, and serialized native
Darwin tests passed. Two independent review passes closed the bounded-wait,
child-allocation, inherited-frontier, runtime-event, and fork-failure FD
findings. Signed live fork/exec tracing is deliberately still pending until the
exec half is complete.

**Next:** implement the prepared exec-reset transaction and post-success
activation/metadata handoff, including production self-reexec proof. Then take
two default and two shared Go-build attribution captures with the same signed
binary, use the complete catalog to stop misclassifying shared JIT code as
host, select the first opt-out optimization from measured CPU/kernel ownership,
and retain it only through the primary ABBA CPU gate.

The ≥30% CPU goal remains open; no new paired CPU ratio has been measured.

---

## Prior checkpoint — M1 authority closed, M2 performance work opened

**M1 instrument authority is complete, but it is not a speed result.** The
accepted same-binary control/control artifact is
[`scripts/perf/evidence/native-go-build-abba-control-control-v1.json`](scripts/perf/evidence/native-go-build-abba-control-control-v1.json)
(SHA-256
`13f53bfec091cbbdee53dd1cbd91e8bad061948989a004113fe8fb1c24171ee8`).
Its eight-quad total-child-CPU B/A median is `1.0052799282253981`, with
`statistical_pass=false` and `retained=false`. It validates receipt-bound ABBA
execution and the instrument's 2.5021% n=8 resolution; it does not update H0,
establish a regression, or claim an optimization.

**The load-coupled correctness defect discovered during closeout is fixed.**
The first retry-enabled broad smoke reported 21/23 and its two targeted retries
reported 2/2; preserve that sequence as discovery evidence, not as a rewritten
23/23 run. A real LLDB core then proved that translated execution still carried
control and address state through physical x18 even though Darwin may clear its
platform register asynchronously. Commit `5020e509` removes all such emitted
live ranges and adds fail-closed decoded-instruction, cold-arm, stack-pointer,
DC-ZVA, and every-recovery-boundary coverage.

The retained signed binary
`d31e60966075c3709ac3cd83a0fe4b4b6d672371ba2b6ff9e99ae6400d13c9e0`
passed the exact concurrent CPython `test_close_fds` reducer 4/4. A fresh
`just conformance-native smoke --workers 4 --flake-retries 1` then reported
23/23 MATCH, including `cpython-subprocess` 278/278; the oracle phase used all
23 cached results and ran Docker zero times. Final `just ci` passed.

**Next:** begin M2 with a fresh signed binary from this retained code state, an
untraced Go-build run, and DTrace/carrick-trace attribution. Keep the Go-build
workload as the primary retention gate, use controls that opt out of one
hypothesis at a time, and do not turn a trace sample into a performance claim.
The ≥30% CPU goal is still open.

---

## The goal

**Make carrick's translation pipeline pay for itself:** land container-lifetime
translation sharing as a net win, and cut non-guest work on the native/aarch64
go-build reference workload by ≥30% CPU.

| | |
|---|---|
| **Primary metric** | `cpu_median_s` on the go-build reference workload, as a paired ratio vs baseline `0686248a` |
| **Target** | ≤ 0.70 |
| **Protocol** | ABBA-ordered, ≥8 quads, `abbascreen.sh` + `abbastats.py` |

Ratio, not absolute: total CPU ranges 32–44 CPU-s run-to-run on the same binary.

### Workstream targets, and where the numbers stand

| gate | metric | start | target | now |
|---|---|---|---|---|
| A0 | `direct_resolver_exits`, sharing ON vs OFF | 779,874 → 135,259,579 (173x) | mechanism named + control arm | **0** |
| A1 | wall, sharing ON ÷ OFF | 3.2–4.2x | ≤ 1.0x | 1.268x |
| A2 | translations per build | 1,031,914 | ≤ 400,000 | 819,901 |
| A2 | shared-unit block coverage | 14.2% | ≥ 60% | 33.1% |
| B | emitted bytes per build | 599 MB | ≤ 400 MB | 553 MB |
| B | host-code share of on-CPU | 35.8% | ≤ 25% | not re-measured |
| C | kernel, non-syscall | 30.7% | ≤ 25% | unchanged |
| C | address-space faults | 2,204,683 | ≤ 1,500,000 | 2,098,739 |

**Primary metric today: ~1.0.** Sharing ships OFF, so the shipped path is
unchanged. Every number above is reproducible; none is final.

---

## What was attempted, and what each attempt measured

### A0 — root-cause the exit amplification → **met**

Classified every `ResolveDirect` by whether the source PC falls *inside* a
shared block's `[start, end)` range — not equality against block-start keys, the
mistake that forced a retraction in run 6. Result: 99.4% of amplified exits are
private→shared, across 74,726 distinct edges at ~1,822 traversals each,
confirmed by a control arm shipped in the same commit.

### A1 — stop being a regression

Five constructions, in order.

**1–4: install the unit's binding table at gateway ENTRY.** Each removed the
amplification (135,715,237 → 0 / 48 / 44) and each faulted. Attributing the
fault (run 22) explained all four at once: a context holds ONE
`generation_bindings` pointer while a private context reaches blocks from N
units, so the guard indexes the wrong unit's table as soon as a second unit is
touched. The wandering fault address (`0x20`, `0x60`, `0`) was that, not one bug
relocating. All four reverted.

**5: install at the EDGE** — `b23503ea`, landed. Each private→shared edge is
patched to a six-word trampoline (`movz`/`movk` chain, `str x17, [x28,
#CTX_GENERATION_BINDINGS]`, `b`) built from the per-block
`SharedBlockAuthority::generation_bindings` pointer already available at patch
time. An edge statically knows its target's unit; entry-time install never can.
Amplification 135,715,237 → **0**, and the workload completes with sharing ON
for the first time. A1: 3.2–4.2x → **1.114x**.

The coverage work below then moved A1 to **1.268x**.

### A2 — raise coverage

Measured that fused blocks were excluded from shared units
(`block.extensions.is_empty()`), worth 2.2x of coverage: 14.4% with fusion on
vs 32.1% with it off (run 26). Fusion is a shipped win (76% fewer gateway
exits), so disabling it is not the trade — it also raises translations 22%.

**Made fusion and sharing work together** — `7781d97e`, landed. The exclusion's
premise held: superblock formation extends only along the fall-through and stops
at `page_end`, so a fused plan is contiguous and single-page and the template key
already spans it. Removing it exposed two consume-side defects, one **latent
since before fusion** — sensitive-exit metadata was keyed by block START while
the lookup is by the SENSITIVE instruction's PC, which differ for any block
longer than one instruction.

Coverage 14.4% → **33.1%**; translations 1,045,248 → **819,901** (−21.6%).

**The paired ratio moved the wrong way**: 1.106 → 1.235 CPU, 0/8 quads, sd 1.4%.
This is the campaign's most important open result — on this workload, cutting
fresh translations by a fifth did not buy CPU, and the reason is not yet
established. See *Open questions* #1; the leaf profile currently cannot see the
likeliest mechanism.

### B — per-translation host cost

Narrow guest-PC materialization (`3d480e88`) cut emitted bytes 610.0 → 553.3 MB
(−9.3%), mechanism gate confirmed. Paired CPU effect: zero. Extrapolated to B's
full 400 MB target that is ~0.9%, which raises the question of whether emitted
bytes are the right proxy for the CPU they were chosen to represent.

### C — kernel fault term

Baselined (2,098,739 `as_fault`, 82% zero-fill, 50 processes, flat at
31–39k each) and three candidates probed:

| candidate | result |
|---|---|
| scavenger decommit (`madvise`) | 328 calls vs 1,716,964 zfod — 1:5000, not the mechanism |
| per-process address-space setup | ~2,000 faults/process trivial vs ~34,000/process build — not startup |
| sub-page `PROT_NONE` amplifier | **real**: any 16 KB host page whose four 4 KB guest sub-pages disagree on protection maps `PROT_NONE`, so every access faults, not just the first. Bounds to ~382,000 faults = 18% of the term |
| the zero-fill majority (82%) | **open** |

---

## What landed (all gated, all on `main`)

| commit | change |
|---|---|
| `b23503ea` | private→shared edges patch through a binding-install trampoline (A0) |
| `7781d97e` | fused superblocks shareable + sensitive-metadata keying fix |
| `3d480e88` | narrow guest-PC materialization (−9.3% emitted) |
| `5f9cedfb` | `--variant shared` — sharing without the artifact spike |
| `602df3af` | per-thread block cache (`lock_shared_slow` 8.2% → 4.0%) |
| `0e969f07` | hardware SHA-256 (0.55 → 2.20 GB/s; 1.99% → 0.40% in-profile) |
| `22394916` | frame pointers enforced workspace-wide + `just ci` check |
| `7c701293` | CPU-seconds in the perf runner |
| `0686248a` | JIT-aware profiler |

**Guardrails:** `baseline.jsonl` and `baseline.native-dsr.jsonl` unchanged
across all 33 commits; `just ci` green at tip (36 suites, zero failures).
Sharing remains off by default, so shipped behaviour is unchanged.

---

## Open questions, ranked

1. **Why did −21.6% translations cost CPU?** Leading hypothesis is execution
   locality: 400,000+ blocks across 54 separately `dlopen`ed unit mappings
   replacing a compact bump-allocated private cache. **Blocked on tooling** —
   the JIT-aware profiler classifies a PC by the PRIVATE cache bounds, so
   unit-mapped code is misfiled as `host` and the arms' bucket totals are not
   comparable across a sharing boundary (run 24). `shared_guest_ranges` already
   tracks what the classifier needs. Fix that first; it gates the question.

2. **The zero-fill majority of the fault term** (82%, 1.72 M). `vminfo` carries
   no fault address, which is why all three probes so far were indirect. Needs
   distinct-address accounting — `fbt::vm_fault:entry`, or a guest-side census
   of pages touched. Peak-RSS sampling gave median 91 MB/process against the
   531 MB the fault count implies, but 0.3 s sampling of 1–2 s processes is not
   evidence.

3. **The sub-page `PROT_NONE` amplifier** is real and independent of everything
   above — worth fixing on its own terms. Sized at 18% of the fault term and
   under the goal's 5%-of-CPU chase threshold, so it will not move the headline
   alone.

4. **Re-screen the earlier rejections.** The instrument is now ~4x sharper (ABBA
   + CPU resolves ≥0.8–1.1% at n=8, vs ~3.2% for the wall screens that produced
   them). The whole-generation-guard arm measured 0.9867 (p=0.38) — unmeasurable
   then, resolvable now. The goal placed codegen cycle quality out of scope;
   revisit that scoping before spending on it.

5. **A2's remaining coverage gap** (33.1% vs ≥60%). Each unit load serves ~2,930
   blocks where a process translates ~26,707. Why an artifact covers ~11% of one
   process's needs is unmeasured — narrow capture, a cap, or a keying mismatch.

---

## Instrument and traps

- **Use `abbascreen.sh` / `abbavariant.sh` + `abbastats.py`.** A null screen
  measured a ~1% penalty on whichever arm runs SECOND; ABBA cancels it inside
  each quad. Report CPU-seconds, not wall: sd 1.4–1.8% vs 4.3–5.5%.
- **One unpaired run is not an instrument.** A single JIT-aware profile put the
  ON arm faster while 8 ABBA quads said 1.235x slower. The screen governs — and
  the temptation is always to quote whichever number flatters the change.
- **Check the arm actually contains your change.** The first A1 screen used
  `--variant candidate`, which also enables `CARRICK_DSR_ARTIFACT_SPIKE=1`;
  neither the fix nor the gate's baseline involves it, so the result was void.
  `--variant shared` is the gate's configuration.
- **`native_go_build.py` refuses a dirty worktree.** Commit harness edits before
  measuring — that guard turned a void run into an obvious crash rather than a
  plausible-looking ratio.
- **`sudo dtrace` needs a foreground call.** Detached/`nohup` runs lose the
  credential silently while the workload still succeeds, yielding an empty
  profile. Give D scripts a `tick-Ns { exit(0); }` so they self-terminate;
  killing the `sudo` pid leaves dtrace running and hangs the harness.
- **Attribute before building.** Four hypotheses in A1 and three in C died on
  first contact with a counter. Two could have been refuted by arithmetic alone
  — 817 M extra instructions is ~0.2 CPU-s, not the 3.2 being explained.
- Stamp `CARRICK_RUN_ID` and reap with `scripts/sudo/kill.sh <run-id>`; never
  `pkill -f carrick`.
