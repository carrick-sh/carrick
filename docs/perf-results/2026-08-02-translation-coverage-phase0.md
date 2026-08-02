# Translation coverage, Phase 0: sharing is achievable, and the blocker is a producer that throws its own units away

**Date:** 2026-08-02 · **Lane:** Darwin/aarch64 native DSR (`--exec-backend
native`, the shipped default). No VMM/HVF/KVM/bhyve behaviour is in scope. ·
**Design:** [`docs/superpowers/specs/2026-08-02-translation-coverage-design.md`](../superpowers/specs/2026-08-02-translation-coverage-design.md)
§7 Phase 0 · **Campaign task:** #13.

**Recommendation: GO, re-sequenced — with the ceiling restated and one hard
gate inserted ahead of everything else.** The reasoning is in §7; read §6 first
if you only read one section.

---

## 0. The ceiling, restated before any good news

**Even a perfect outcome takes build-cold from ~14.5x native-arm64-Docker to
roughly 10-11.5x. It does not reach the 2x bar.** Nothing measured here changes
that, and this section is deliberately first so no later number gets quoted
without it.

The redundancy this phase measured is **2.2x higher** than the audit's — 8.98x
against 4.04x — which raises the share of translation work that perfect sharing
could remove from ~75% to **88.4%**. That improvement is real and it moves the
ceiling by less than one turn of the ratio:

| removable share of translation work | build CPU after (from 28.3 CPU-s) | build-cold ratio |
|---|---|---|
| 75% (the audit's 4.04x) | 21.1 CPU-s | ~10.8x |
| **88.4% (measured here)** | **19.8 CPU-s** | **~10.1x** |
| 100% (translation free) | 18.7 CPU-s | ~9.6x |

Sizing inputs are the committed ones
([`2026-08-01-native-wall-audit-and-fault-cost.md`](2026-08-01-native-wall-audit-and-fault-cost.md)
§5: 28.3 CPU-s on build-cold, translation ≈34% of thread CPU). Three honesty
notes on that table:

- **It is CPU, not wall.** Converting saved CPU to saved wall needs a
  parallelism factor this phase did not measure. The true wall win is at most
  this and plausibly less.
- **It is build-lane only.** On the steady-state compute workload translation is
  noise (2,066 translations across a 1.2 s run). Nothing here touches the ~12x
  emitted-code penalty that `handoff.md` names as the campaign goal.
- **The baseline was not re-measured against Docker.** The exit criterion asked
  for it; the Docker oracle cannot run alongside carrick, so the 0.78 s
  reference stands un-refreshed. In-guest build windows on this (loud, load
  4.4-7.8) box read 10.7-25.2 s across the runs below; the quiet-box total-wall
  control was 11,223-12,218 ms (n=5). **Do not bank either as the baseline** —
  re-take it on a quiet machine before quoting a Phase 1/2 delta.

---

## 1. What was built, and what "measured" means here

Phase 0 is a measurement phase. It changes no default-path runtime behaviour;
what it adds is an instrument, and the instrument is the deliverable.

- `xlat_census` (`crates/carrick-dsr-aarch64/src/translator.rs`) now flushes at
  three seams instead of only `libc::atexit` — process exit, the host
  self-re-exec that implements guest `execve`, and in-process exec — and records
  the **unit key** and segment-containment class alongside each guest VA, plus
  typed shared-store lookup outcomes.
- `carrick debug xlat-census` (`crates/carrick-cli/src/debug_census.rs`)
  aggregates the per-process files in Rust, under `just ci`, against the same
  type the runtime renders with. There is exactly one definition of the file
  format.
- Arming is `CARRICK_XLAT_CENSUS_DIR=<dir>`; the shared lane is
  `CARRICK_DSR_SHARED_TRANSLATION=1` (still opt-in, per §2.7 of the design —
  fixing that is Phase 2's job, not this one).

Every number below was produced by the **committed** binary, `just build`-signed,
on `localhost:5005/carrick-go-conformance:1.24`, running the canonical
`workload-spread.sh` build-cold shape. All runs returned `BUILD_OK`, rc=0.

---

## 2. The headline: the workload is 2.8x bigger than the audit recorded

`atexit` does not run on `execve`, and carrick's guest `execve` is a host
self-re-exec — so **every process that exec'd never wrote a census file.** On a
cold `go build` that is 67 of 69 processes. The audit's figures were lower
bounds and are superseded:

| | audit (truncated census) | **measured** |
|---|---|---|
| translations, one cold build | 433,249 | **1,202,667** |
| distinct guest VAs | 107,320 | **133,931** |
| distinct scoped blocks | — | **139,816** |
| process incarnations | 34 | **136** (over 69 pids) |
| cross-process redundancy | 4.04x | **8.98x upper / 8.60x lower** |

Redundancy is bracketed rather than exact and the report emits both ends: the
native lane loads PIE guests at a **fixed base**, so a union over bare VAs
under-counts distinct code (over-stating redundancy), while scoping each VA by
its content-addressed unit stem over-counts distinct code for a library two
executables share (under-stating it). The truth is between 8.60x and 8.98x.

**Independent cross-check.** `CARRICK_DSR_PROFILE` is a pre-existing instrument
with a different flush discipline. On this run it reports **1,202,667**
translations — equal to the census to the unit — across **69** pids and **136**
main-thread eras, matching the census's 69 and 136 exactly.

---

## 3. The four questions

### (a) How many distinct unit keys? Ten, over seven images. A handful.

| stem | image | blocks | translations | incarnations | redundancy | share |
|---|---|---:|---:|---:|---:|---:|
| `7ead8102…` | `5d3ce715…` | 85,515 | 867,488 | 27 | **10.14x** | 72.13% |
| `2e379372…` | `b1e92ca4…` | 11,305 | 280,485 | 34 | **24.81x** | 23.32% |
| `c1887ed4…` | `3d8da962…` | 16,357 | 22,965 | 2 | 1.40x | 1.91% |
| `15a70265…` | `aedb1694…` | 20,465 | 22,577 | 65 | 1.10x | 1.88% |
| 6 more | 5 images | ≤920 | ≤1,704 | ≤5 | ≤2.00x | 0.76% total |

**Two keys carry 95.45% of all translation in the build.** Per-key publication
cost therefore amortises trivially over a run, which is what question (a) was
asked to settle. It does **not** follow that in-process signing is optional —
see §5, refutation 1.

Key identity is **stable**, which the design did not assume and which matters
because an unstable key would fake a low count in one direction or a high one in
the other: every stem maps to exactly one `(guest_start, guest_len)` and exactly
one image digest, no stem is shared by two images, one image yielded the same
stem across 65 separate incarnations, and stems are byte-identical across runs
hours apart. The count varies slightly run to run (8 on one run, 10 on another)
with which images the build happens to exercise, not with key instability.

### (b) What fraction falls inside a configured segment? 99.65%. The KILL criterion is not met.

| bucket | blocks | translations |
|---|---:|---:|
| `contained` (whole block inside one segment) | 137,448 | 1,198,481 |
| `entry_only` (entry inside, block runs past the end) | **0** | **0** |
| `outside` (no unit of any design can serve these) | 2,368 | 4,186 |

**`inside_segment_share_of_translations` = 99.65%; by distinct blocks, 98.31%.**
The KILL threshold was "under 40%". It is not met, and not remotely.

`entry_only` being exactly 0 is worth naming: the *lookup* predicate (entry VA
in a segment) and the *producer* predicate (whole block in a segment) select the
identical population on this workload, so the publishable share equals the
lookup ceiling with no gap between them.

**§2.4(b) is refuted for this workload.** The design predicted that libraries
the guest's own `ld.so` maps fall outside every configured segment and can never
be served. Only 2,368 blocks / 4,186 translations — 0.35% — are outside. The
lane's own instrument partitions the same population identically, which is a
second, independent confirmation: on the lane-on arm the store's
`outside-segment` skip is 776 and `regenerated` 3,408, and 776 + 3,408 = 4,184
against the census's 4,186 outside translations.

**Consequence: Phase 3 (segment coverage) has nothing to do. Delete it.** Its
own KILL says to delete it if extending enumeration cannot raise the in-segment
fraction by ≥10 points; the fraction has 0.35 points of headroom.

### (c) Where does the "one key" go? None of the three hypotheses. It is publication.

Direct cache-directory evidence (`CARRICK_DSR_KEEP_CONTAINER_CACHE=1`):
**10 `.seen`, 10 `.lock`, 5 `.builder`, ZERO `.dylib`, ZERO `.metadata-v3`.**

Store counters over the whole lane-on run:

| counter | value |
|---|---:|
| `lookups` | 1,203,368 |
| `consulted` (reached `TranslationUnitStore::load`) | 72 |
| `loaded` | **0** |
| `file_miss` | 72 |
| `misses` (typed refusals, `no-authority` among them) | **{}** — empty |
| `recording_claimed` / `recording_declined` | 33 / 39 |
| `processes_without_authority` | **0** (of 68 consulting incarnations) |
| `processes_that_loaded` | 0 |

- **Hypothesis (a) — "the authority does not survive the host self-re-exec" — is
  refuted.** `processes_without_authority` is 0, `misses` is empty (no
  `NoAuthority`, no `MissingPair`), and the incarnations that consult are
  precisely the post-`execve` ones. The authority chain works.
- **Hypothesis (b) — "segment enumeration covers too little" — is refuted** by
  (b) above: 99.65%.
- **§2.4's deduction is itself refuted.** It reasoned that a directory holding
  one key proves `claim_recording` was reached for exactly one key. All ten
  configured keys got a `.seen`, so it was reached for **every** key.

What actually happens: **33 recording claims → 33 publication attempts → 0 units
published.** On the earlier, independently-run instance of the same experiment
the failure reasons were 30 × `ManifestRange` and 1 × the 64 MiB branch-range
cap. Publication is where the lane dies, and it has apparently never published a
unit in its life.

The 1,199,112 `segment-repeat` skips (99.65% of lookups) are not themselves a
loss — one consultation per segment is the design — but see refutation 3.

### (d) Does recording double emission? Yes. +55% to +78% of emission CPU, translation count flat.

Same binary, same fixture, `CARRICK_DSR_SHARED_TRANSLATION` the only variable.
`decode` and `plan` are the controls: recording adds a second
`assemble_block_inner` over an already-computed plan, so if §2.5's mechanism is
right, emission must rise while decode and plan do not.

| measurement | translations off→on | decode ms | plan ms | **emit ms** |
|---|---|---|---|---|
| this run (n=1) | 1,202,667 → 1,203,368 (+0.06%) | 3,109 → 3,166 (+1.8%) | 28 → 29 | 4,346 → **7,738 (+78.0%)** |
| earlier, census arm | +0.5% | 6,441 → 6,298 | — | 9,752 → 15,142 (+55%) |
| earlier, rep 3 | +0.2% | 7,628 → 7,627 | — | 11,787 → 19,725 (+67%) |
| earlier, rep 4 | +0.1% | 7,582 → 7,606 | — | 11,427 → 18,286 (+60%) |
| adversarial re-run (n=4 vs 4, matched load) | +0.03% | −1.8% | — | **+68.2%** |

Five independent measurements, same sign, all large. **§2.5's warm-+285%
mechanism is confirmed as real.** The inference from it — that the recorded
segments therefore held ~55-78% of emission work — assumes recording costs
exactly one extra assembly per block and is named as an assumption, not a
result. One further caveat found by the adversarial pass: the `emit` timer also
encloses the lane's per-translation linear segment scan and a
`block_source_words.clone()`, so the delta is double-assembly *plus* those; with
one or two segments per image the scan is negligible and the attribution
survives.

Total wall follows, but only *suggests*: quiet-box lane-off 11,223-12,218 ms
(mean 11,718, n=5) against lane-on 19,430-20,300 ms (mean 19,779, n=4) = **1.69x
on total wall**, ~1.79x after removing ~1.7 s of fixed container create/teardown
from both arms. Per AGENTS.md this is a wall number on a non-homogeneous
4P+6E host and is not a controlled single-variable experiment at the core-class
level; the phase decomposition above is the citable instrument.

### (e) Static enumerability — NOT RUN.

0e was not executed. It is the only input that decides whether Phase 4 (eager
whole-image production) exists at all, and it remains outstanding. Phase 4 must
not be planned before it runs.

---

## 4. Process coverage, stated plainly

`census_files` 136 · `distinct_pids` 69 · `incarnations` 136 · `flush_balance`
**0** · `reexec_successors_missing` **0** · `sequence_anomalies` **0** ·
`files.failed` **0** · `dangling_segment_references` 0 · `inconsistent_totals` 0.

The denominator is independent: `CARRICK_DSR_PROFILE` flushes on a different
discipline and reports 69 pids and 136 main-thread eras, matching exactly, with
translation totals equal to the unit. An `ps`-based enumeration during an
equivalent run by the adversarial pass found 69 carrick host pids against 69
census pids, the one un-censused pid being the `carrick run` orchestrator, which
executes no guest code.

**Treat every count as a LOWER BOUND anyway.** Three classes are invisible to
*both* instruments, so their agreement cannot rule them out:

1. a process killed by a fatal signal, which never flushes;
2. a thread-loop error / `_exit(125)` abort;
3. a guest process that never enters the DSR translator at all.

A clean `go build` should produce none of these. **Nothing here proves that.**

Two of the three self-checks are additionally **vacuous on this fixture** and
should not be read as evidence: every file carries `seq=0`, so
`sequence_anomalies` short-circuits, and `flush_balance` is
`incarnations − (terminal + handoffs)`, to which a process that translated and
died before flushing contributes 0 on *both* sides. Only
`reexec_successors_missing` carries information here.

---

## 5. Adversarial verification: what survived, and what did not

An independent pass re-parsed the raw census with its own parser, re-aggregated
the pre-existing DSR profiler, ran nine fresh guest builds, and enumerated
carrick's host processes with a `ps` poller that knows nothing about the
instrument.

**Survived, several digit-for-digit:** workload size, redundancy bracket, unit-key
count *and key identity stability*, segment coverage, store counters,
cache-directory state, authority adoption, the recording emission tax, the wall
ratio, and the perfect-sharing ceiling arithmetic. The claims in §2, §3(a),
§3(b), §3(d) and §4 above are all re-derived work, not single-source.

Three claims did **not** survive. All three were mechanism claims in §3(c), and
all three are corrected above and re-verified on the committed binary:

**Refutation 1 — "publication never reaches `emit_dylib` or `codesign`, so the
0.06-0.16 s/unit subprocess cost is not on the critical path."** False.
A full-system `ps` poll across paired runs on the committed binary:

| arm | distinct `codesign` processes observed |
|---|---|
| lane OFF | **0** (the single match is launchd's `CodeSigningHelper` XPC, ppid 1) |
| lane ON | **37**, from **31 distinct carrick parent pids** |

The only runtime `codesign` spawn in the tree is `sign_and_verify`
(`crates/carrick-native-darwin/src/aot_cache.rs`), reachable only *after*
`emit_dylib`. So ~33 publications per run emit a Mach-O and shell out to
`codesign` twice, then throw the result away. A polling loop misses short-lived
processes, so 37 is a lower bound against an expected ~66. **In-process signing
is not optional; it is paid today, per attempt, for nothing.**

**Refutation 2 — "the failure is a self-rejection at the preflight manifest
validate."** Not supported. `UnitMissReason::ManifestRange` is returned from
**four** distinct sites in `publish_unit_with_metadata_mode` — the preflight size
check, the preflight manifest validate, `emit_dylib` failure, and the
**post-signature** `validate_manifest` — and the log prints only the reason, so
the four are indistinguishable in the artifact the claim rested on. Refutation 1
positively places ~32 of ~33 attempts *past* the preflight. **Whatever rejects
these units is downstream of signing, and Phase 1 must not be planned against
the preflight.**

**Refutation 3 — "one consultation per segment per process is the design."**
False, and the invariant matters for Phase 2's load-side ceiling.
`shared_unit_segments_consulted` is cleared only on the exec-reset path and
**not** by `after_fork_child`, so a fork child inherits its parent's
"already consulted" set. On this run 68 of 136 incarnations consulted the store
and 68 did not, the split falling exactly on `process-exit` (post-`execve`, 69
incarnations, 68 consulting) versus `host-self-reexec` (pre-exec fork children,
67 incarnations, 0 consulting). So it is one consultation per segment **per fork
lineage since the last exec**, and **half of all incarnations never reach the
store at all**, whatever it holds. The quantitative impact on *this* workload is
small — the affected population is ~1.9% of translations and a fork child
inherits its parent's warm in-process index anyway — but the stated invariant is
false and must not be used to derive a ceiling.

One method claim was **overstated**: "132/132 = 100%, the denominator is
independent." The denominator was hand-supplied via `--processes-observed` from
`CARRICK_DSR_PROFILE`, which flushes at the *same two seams* as the census, so
it could not have caught a process that dies before either. The substance holds
— the `ps` enumeration above establishes it independently — but not by the route
originally claimed. The flag's documentation now says so, and
`processes.coverage` now carries the caveat in its own doc comment.

### Instrument defects the adversarial pass found, and their disposition

The instrument is the deliverable, so its defects are fixed in this commit
rather than noted:

| # | defect | disposition |
|---|---|---|
| D1 | `FLUSH_SEQUENCE` survived `fork`, so a child of a process that had `execve`d **in place** wrote its first file at `seq=1` and contributed no `seq=0` start. The aggregator keys its whole lineage model on `seq==0`, so `incarnations`, `flush_balance` (which went *negative*) and `reexec_successors_missing` all lied, with none of the three self-checks firing. | **FIXED** — `reset_after_fork` zeroes the ordinal. Live-verified on the `exec`-in-place fixture that exposed it: reported 3 incarnations / balance −2 / 2 missing successors before, **5 / 0 / 0** after, matching ground truth. Locked by a regression test. It did not contaminate any number in this document: every census file on the build-cold fixture carries `seq=0`. |
| D2 | `coverage.publishable_share_*` was documented as "what today's producer can actually publish". It encodes whole-block containment only; recording is additionally gated on a **won recorder election**, so on the default path the truly-published share is 0 while the field read 99.65%. | **FIXED** — renamed `contained_share_*`, doc corrected at both the field and the `SegmentCoverage::Contained` variant. The kill number, `inside_segment_share_*`, was always sound. |
| D3 | The parser's `STORE` line assigned wholesale over `file.store`, discarding any `SKIP`/`MISS` counts that preceded it — and neither construction identity covers those maps, so the loss parsed clean and reported zero. A duplicate `STORE` line silently won. | **FIXED**, red-first (both new cases fail against the pre-fix parser). Maps are carried across; a second `STORE` line is now a parse error. |
| D4 | Arming the census makes several `Unsupported` arms of segment enumeration reachable on the default path, and both call sites turn them into a fatal error — so the census could abort a guest that runs fine without it. Never observed to fire. | **KEPT, deliberately, and documented in the code.** The alternative — swallowing the failure — emits a census reading `image=-` and 0% segment coverage, a plausible-looking *wrong* answer to the exact question that gates the KILL criterion. A named abort is the lesser failure. |
| D5 | `flush` never cleared `state.image`, and `configure_image` was skipped for a segment-less image, so an in-process `execve` into such an image left the predecessor's segments installed — and under the fixed PIE base the successor's blocks would alias into them and be attributed to another binary's unit stem. | **FIXED** — `clear_image()`, called on that path. Unreachable in practice, but it was the one place a wrong answer would have been silent rather than absent. |
| D6 | `store.lookups == translations.total` was presented as a mechanical invariant. It holds only while `loaded` is 0 — a lookup that returns a unit short-circuits before the block is recorded — i.e. it breaks exactly when the lane starts working. | **FIXED (documentation)** — the field now says so. Do not use it as a Phase 2 cross-check. |

---

## 6. What the numbers say

Every architectural precondition for translation sharing is met on this
workload, and by a wide margin:

- **Coverage is not the blocker.** 99.65% of translations are inside a
  configured segment; the `entry_only` gap is zero.
- **Authority adoption is not the blocker.** 100%, including across the host
  self-re-exec.
- **The election is not the blocker.** Every configured key reached it.
- **Key count is not the blocker.** Ten keys, two of which carry 95.45%.
- **Redundancy is 2.2x larger than believed.** 8.98x, not 4.04x — a
  perfect-sharing ceiling of **88.4%** of translation work, 1,202,667
  translations collapsing to 139,816 distinct scoped blocks.

**The blocker is a producer that emits and signs Mach-O units its own
downstream validator then rejects, 33 times out of 33, while charging 55-78% of
emission CPU and two `codesign` spawns per attempt for the privilege.** That is
a bug, not an architectural limit — which is the single most important thing
Phase 0 was asked to determine.

---

## 7. Recommendation: GO, re-sequenced

**GO** — with three changes to the plan and one hard gate ahead of everything
else.

**Why GO.** Phase 0 existed to settle whether sharing is achievable at all
before anyone builds a persistent store. It is: the ceiling is higher than the
design assumed, every precondition holds, and the one thing that does not work
is a defect with a bounded failure site. A NO-GO here would be a decision to
abandon the campaign's largest identified lever on the strength of a bug.

**Why the enthusiasm stops at the ceiling.** This buys build-cold ~14.5x →
~10-11.5x. It does not approach 2x, it does not touch the steady-state
emitted-code penalty, and the wall conversion is unmeasured. It is worth doing
because it is the largest single build-lane lever, because it **subsumes** the
assembler-arena candidate rather than competing with it (translations that never
happen allocate nothing), and because its blocker is now mechanical rather than
mysterious — not because it gets anyone to the bar.

### The gate that comes first

**Phase 1a — publish one unit, load it once, on this exact workload.**
Zero units have ever been published by this lane. Everything downstream —
persistence, GC, eager production — assumes a producer that works. Before any of
it:

1. Make `UnitMissReason::ManifestRange` distinguish its four return sites
   (refutation 2 — today the log cannot tell you which validator rejected the
   unit, and that is the first thing to measure).
2. Fix whichever downstream validator rejects a signed unit.
3. Prove, live: one `.dylib` and one `.metadata-v3` on disk, and
   `store.loaded > 0` in a second process.

**KILL:** if a unit cannot be made to publish and load within a bounded effort,
**stop the workstream and re-rank against #14.** A producer that has never
worked is not a foundation to build persistence on. Zero published is an error,
never an empty result.

### Changes to the phased plan

- **Phase 3 (segment coverage): DELETE.** Its own KILL criterion demands ≥10
  points of improvement in the in-segment fraction; there are 0.35 points
  available. §2.4(b)'s prediction is refuted.
- **Phase 1: re-scope, and keep in-process signing.** The stated justification
  ("publication is cheap because there are few keys") is refuted by refutation 1
  — ~66 `codesign` spawns happen per run *today*. Keep the in-process
  CodeDirectory work, red-first as specified. Drop the assumption that the
  preflight is the failure. Add Phase 1a above as its first item.
- **Phase 2: fold in the fork-lineage fix.** Refutation 3 means half of all
  incarnations never consult the store because `after_fork_child` does not clear
  `shared_unit_segments_consulted`. That must be fixed before the Phase 2 gate
  is read, or the load-side result will be measured against a population half
  the size of the real one.
- **Recording cost is now a first-class Phase 2 concern, not a footnote.**
  Demand recording taxes emission 55-78%. On a workload where translation is
  ~34% of thread CPU, a lane that records must pay that back from the sharing
  win in the *same* run, or it must record on a background path. §2.5's
  observation that `record_portable_block_artifact` does not require the block
  to have executed is the escape hatch; 0e decides whether it is reachable.
- **Phase 4: still gated on 0e, which was not run.**

### Before quoting any delta

Re-take the build-cold baseline on a quiet machine, both against Docker and
lane-off/lane-on. The numbers in this document that are *counts* (translations,
blocks, keys, coverage, store outcomes) are load-insensitive and stand. The
numbers that are *times* were taken on a box at load 4.4-7.8 and are labelled
"suggests" throughout for that reason.

---

## Appendix — reproducing this

```sh
just build                       # signed; the census needs no entitlement (native lane)
SCRIPT='cd /tmp; rm -rf gcx bx;
  printf "package main\nfunc main(){println(\"ok\")}\n" > b.go;
  GOCACHE=/tmp/gcx /usr/local/go/bin/go build -o bx ./b.go; echo BUILD_OK'

# lane OFF (the shipped default) — questions (a), (b), and the headline
CARRICK_XLAT_CENSUS_DIR=/tmp/xlat-off CARRICK_DSR_PROFILE=1 CARRICK_RUN_ID=p0-off \
  target/release/carrick run --exec-backend native -w /tmp \
  localhost:5005/carrick-go-conformance:1.24 /bin/sh -c "$SCRIPT"

# lane ON, cache kept — questions (c) and (d)
CARRICK_XLAT_CENSUS_DIR=/tmp/xlat-on CARRICK_DSR_PROFILE=1 \
  CARRICK_DSR_SHARED_TRANSLATION=1 CARRICK_DSR_KEEP_CONTAINER_CACHE=1 \
  CARRICK_RUN_ID=p0-on \
  target/release/carrick run --exec-backend native -w /tmp \
  localhost:5005/carrick-go-conformance:1.24 /bin/sh -c "$SCRIPT"

target/release/carrick debug xlat-census /tmp/xlat-off --top 20
```

`--processes-observed N` turns `processes.coverage` on. **N must be counted in
incarnations** (process-image lifetimes), not pids and not guest programs, and
must come from an instrument with a different flush discipline or the ratio is
1.0 by construction. Never run the Docker oracle alongside any of this.
