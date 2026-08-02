# Performance redesign: the options on the table, and what a human has to decide

**Date:** 2026-08-02 · **Status:** decision document — nothing implemented, no
crate source touched. · **Lane:** Darwin/aarch64 native DSR
(`--exec-backend native`, the shipped default). No VMM/HVF/KVM/bhyve behaviour
is in scope. · **Read at** `ddb23127`.

Five prospective redesigns were generated and independently judged on
arithmetic, prior evidence and feasibility. This document exists so a human can
**weigh** them: it preserves the judges' disagreements instead of averaging them,
records what is permanently refuted so it is never re-proposed, recommends a
*sequence* rather than a winner, and states plainly which workloads can reach the
2x bar and which cannot.

Every number is traceable to a committed record. Where two records conflict, both
are named and the conflict is arbitrated in §3, not hidden.

---

## 0. Read this first: the denominator moved, and it re-ranks everything

Two whole-CPU budget records exist for the cold `go build`, and **the second
corrects the first by name**:

| record | git | inserted codegen | carrick host userspace | kernel | guest-shaped JIT words |
|---|---|---|---|---|---|
| `whole-cpu-budget-single-run-denominator` | `d4292368` | **18.6%** | **36.9%** (user outside JIT) | 35.6% | 8.5% |
| `CORRECTION-user-module-split-codegen-IS-the-biggest-bucket` | `e63975d3` | **36.4%** | **11.5%** (+ 6.1% dylibs) | 29.5% | **16.5%** |

Both in `docs/perf-results/native-dsr-shape-census.jsonl`. The correction's own
words: *"58% of user PCs did not match any per-process JIT snapshot, and I read
the unmatched population as host code. It was mostly JIT."* Its method —
`umod(uregs[R_PC])` on every user sample, so any PC in no Mach-O image **is** the
`MAP_JIT` cache — needs no snapshot join and no unwind, and is the sounder of the
two.

**Three consequences, and they run in opposite directions for the options below:**

1. **Inserted codegen is the single largest bucket on the build (36.4%), not
   18.6%.** That doubles the prize of anything that stops emitting code.
2. **"carrick's own host userspace is 36.9% and has never been attacked" is
   stale.** It is 11.5% host text plus 6.1% dylibs. That roughly thirds the prize
   of anything that makes carrick's host-side work cheaper — including translation
   sharing. **AGENTS.md still quotes the superseded 36.9% figure in its
   Engineering-standards ranking bullet, and should be corrected.**
3. Judge 1 built its entire arithmetic on the superseded record. Its rankings are
   therefore biased *against* the patching family and *for* the sharing family by
   roughly 2x and 3x respectively. See §3.1.

**Caveat that must travel with the corrected numbers:** record 16 was taken at
`e63975d3`, i.e. **before** the seven codegen phases (`bb17be5e`..`e743cd8f`)
landed. Those phases were compute-targeted, but the wall audit's same-binary A/B
shows codegen switches are worth **25% of build wall and 31% of build user CPU**
(`2026-08-01-native-wall-audit-and-fault-cost.md` §1). Today's build inserted-word
share is therefore probably lower than 36.4% and **has not been re-measured**.
Re-measuring it is the first line item of any build-lane Phase 0.

### Baselines used throughout

| workload | carrick | docker | ratio | source |
|---|---|---|---|---|
| container lifecycle (no-op) | 425 ms | 160 ms | **2.7x** | `container-lifecycle-split.jsonl` `total-wall-drained-baseline` |
| fs-walk, in-guest window | 221–225 ms | 12 ms | **~18.4x** | ibid.; `2026-08-02-fs-walk-endgame-design.md` §1 |
| fs-walk, total wall | 620 ms | 163 ms | **3.8x** | `total-wall-drained-baseline` |
| compute (8M-iteration awk, in-guest) | 356 ms | 110 ms | **3.2x** | `native-dsr-shape-census.jsonl` `phase4d-entry-ldp-packing` |
| build, cold GOCACHE (workload wall) | 11,728 ms | 810 ms | **14.48x** | `2026-08-01-native-wall-audit-and-fault-cost.md` §1 |
| build, cold GOCACHE (latest arm) | 10,058 / 10,200 / 10,075 ms | *not paired* | ~12.4–12.9x | `native-dsr-shape-census.jsonl` `build-translation-spike-1-and-2` |

Two housekeeping notes. The most recent build measurement has **no paired Docker
sample in the same record**; 12.9x is that arm against the audit's 810 ms. Nothing
below turns on 12.9 vs 14.48. And `handoff.md` still reads compute at 3.8x — that
is the P4c arm; the census's P4d record supersedes it at **3.2x**.

---

## 1. The options, on one screen

**A — Warm Exec.** Stop making guest `execve` a host process boundary: delete the
self-re-exec, route fork-child exec through the in-process `replace_image` path,
key the prepared image by content digest.

**B — Shared code arena.** One `MAP_JIT` arena created before the first guest
process and marked `minherit(VM_INHERIT_SHARE)`, so every guest process maps the
same translated code.

**C — In-place patching.** Execute the guest's own instruction words at their own
addresses; divert only the encodings Darwin cannot run (`svc #0`, divergent system
registers, cache maintenance, x18) into a branch island reaching the existing
0.29 µs gateway. Three write-ups of one mechanism.

The three committed designs are included for comparison because the options
subsume, cancel or stack with them.

| option | retires | compute 3.2x → | fs-walk 3.8x wall → | build ~12.9x → | blast radius | cheapest kill test |
|---|---|---|---|---|---|---|
| **A — Warm Exec** | `native_exec_capsule.rs` (2,048 L), the `native_reexec_*` snapshot/restore surface in `dispatch/` | **no change** | **no change** | **10.7–12.6x** (headline term unmeasured) | ~3,500 L net deleted, *wide* — touches `dispatch/`, `vfs/`, `fs_backend.rs` | **one line.** Gate `native_darwin.rs:3542`/`:3562` on `CARRICK_NATIVE_SELF_REEXEC=0`; run 100 fork→thread→execve cycles + cpython-subprocess + node + apt. Answers correctness *and* the missing measurement in one run |
| **B — Shared arena** | `aot_cache.rs` (3,272 L), `aot.rs`, `claim_recording`, `artifact_spike.rs` | **no change** | **no change** | **≈ no change** — mechanism does not reach the pot (§4.2) | ~4–6k touched / ~4k deleted; most contained of the five | fork, `execve` a *second* binary, then reach the arena via Mach memory entry + `mach_vm_remap` at a fixed VA. ~60 lines. **Not** the proposal's own fork-only test, which cannot detect the flaw |
| **C — In-place patching** | most of `emit.rs` (10,407 L) + `translator.rs` (12,333 L) — *only for Direct-mode images* | **1.0–1.6x — crosses the bar** | **no change** | **≈ no change on the Go toolchain** (§4.3) | 25–40k L claimed; realistically the translator **stays** for Biased images | (a) offline: what share of executed guest code is in `Direct`-mode images, per workload? (b) hand-patch `mawk`, run the 8M loop with no DBT, kill if not ≤ ~1.6x Docker's 110 ms |
| **#13 translation coverage** (committed, `in_progress`) | the broken publication path; adds a persistent store | none (2,066 translations/run) | none | **10.3–11.2x** (committed ceiling: 14.48x → 10–11.5x) | `carrick-dsr-aarch64` + `carrick-native-darwin` | Phase 0: fix the `xlat_census` `execve` flush, then count distinct unit keys |
| **#14 assembler arena** (committed) | the per-block `Vec<RecoveryEntry>` representation | none | none | **14.48x → 14.3–12.7x** (its own §0) | contained | Phase 0: do heap faults track cumulative or peak allocation? |
| **fs-walk endgame** (committed) | the per-run `clonefileat` seed; `find`'s per-child `fstatat` | none | **~1.8x — crosses the bar** | none | `dispatch/fs.rs`, `vfs/` | Lever B is a redesign, not a knob; Lever A needs a field-for-field `getattrlistbulk` parity test |

**How the two derived build bands were reached.** *Option A:* its three terms are
translation redundancy (mechanically undeliverable by A alone — a `go build` is
sibling fan-out, so a child exec'ing `compile` inherits `go`'s cache, never its
sibling's), per-exec host process construction (**unmeasured at HEAD**; bounded
above by the 37 ms `startup` row of `workload-spread.sh`, which is boot *plus* one
exec, at ~40–70 execs per build), and exec image amplification (no measurement
supports it; both committed SHA-256 figures are translation-unit hashing). That
gives 250–1,700 ms of ~10,100 ms = 2.5–17%. *Option #13:* translation user CPU is
now bounded by carrick's whole host text (11.5%, §0) at ~0.72 translation share
≈ 8%, plus assembler-driven zfod ≈ 8.7% (21.3% fault CPU × 83.6% zfod × 66.7%
carrick heap × 73% assembler), × the 75% redundancy = **13–20% of build CPU**.
That straddles the committed 15–25% band from the wall audit §5, which was sized
on the superseded denominator.

**The one-line summary of that table: no option moves more than one workload, and
no workload is moved by more than one option.** That is the shape of the decision.

---

## 2. The 2x verdict, stated without optimism

**No combination on this table reaches 2x on all three workloads. Two of three
are reachable; the build is not, and the reason is now arithmetic.**

### Compute — reachable, by exactly one mechanism

3.2x today. Translation is noise (2,066 translations across a 1.2 s run,
`2026-08-01-native-wall-audit…` §6), so options A, B and #13 are worth **exactly
zero** here. Two consecutive dispatch experiments measured NULL
(`ldar-relaxation-null-result`, `dispatch-chain-restructuring-null-result`), the
second concluding *"Compute at 3.2x is at or near the emitted-code floor for an
interpreter-dispatch-bound workload."* That floor is a property of **emitting
code**. Option C does not emit code, and the compute workload runs in Direct
(identity) mode (`compute-steady-state-shape-census`), so C applies. Estimated
1.0–1.6x — under the bar, and **not yet measured**. That measurement is Move 3.

### fs-walk — reachable on total wall, not on the in-guest window

Total wall 3.8x. The fs endgame's Lever B removes the 333 ms per-run
`clonefileat` seed (`total-wall-drained-baseline`), taking 620 → ~290 ms ≈
**1.8x**. That is the only design in the tree that reaches the bar on a
wall-clock workload. The **in-guest window (18.4x) is not reachable**: it is 57%
host kernel / 43% carrick dispatch (`fs-walk-in-guest-cpu-attribution`), so even
a free dispatch leaves ~10x. Lever A (`getattrlistbulk`) attacks the kernel half
by issuing fewer host calls; how far it gets is not yet sized. **None of options
A, B or C moves fs-walk at all** — all three proposal families say so themselves,
and all three judges agree.

### Build — not reachable, and here is the arithmetic

Reaching 2x from 12.9x means removing **84.5%** of total CPU (86.2% from 14.48x).
Against record 16's corrected budget:

| bucket | share | can any option on this table remove it? |
|---|---|---|
| JIT: DSR-inserted words | 36.4% | only C — and C cannot run on the build's Biased images (§4.3) |
| kernel (faults + syscall bodies) | 29.5% | partly: ~8.7% is assembler-driven zfod, reachable by #13/#14/C; the rest is the guest's own anonymous memory and syscall bodies, **unowned by every option here** |
| JIT: guest-shaped words | 16.5% | no |
| carrick host text | 11.5% | ~0.72 of it is translation → reachable by #13 |
| dylibs (mostly libmalloc/libplatform) | 6.1% | partly, as a second-order effect of allocating less |

**Remove all inserted codegen, all kernel time, and all of carrick's host text —
every one of them, to zero — and 22.6% remains, which is 12.9 × 0.226 = ~2.9x
(or 3.3x from the 14.48x baseline).** The residual is guest-shaped JIT words plus
dylibs. So the build cannot reach 2x by any combination on this table, and it is
not close.

The uncomfortable sub-finding: guest-shaped emitted words alone are 16.5% of
40.94 traced CPU-s ≈ **6.8 CPU-s against Docker's entire 2.10 CPU-s budget** — a
3.2x on the instruction stream before a single carrick, kernel or fault cycle is
counted. Part of that is classification (in Biased mode one guest access lowers
to several words, only some of which classify as guest shapes); part is genuine
extra work (~70 process constructions per build). Either way, **the build's floor
sits above 3x until the Biased lowering itself gets cheaper**, and nothing on
this table does that.

**The decision this hands to a human is the one `handoff.md` already flagged:**
does the 2x bar apply to cold builds specifically, or to representative
workloads? If the latter, compute and fs-walk are both reachable and the campaign
has a credible target. If the former, the honest answer is that the bar is not
reachable and the goal needs restating.

---

## 3. Where the judges disagreed — preserved, not averaged

### 3.1 The build-lane denominator (Judge 1 vs Judges 2 and 3)

**Judge 1** wrote: *"The only whole-CPU-denominator budget in the tree is
`whole-cpu-budget-single-run-denominator`"* and built its entire table on it —
inserted words 18.6%, carrick userspace 36.9%.

**Judges 2 and 3** both cite the later `CORRECTION-user-module-split…` record,
which supersedes it: inserted words 36.4%, carrick host text 11.5%.

**Arbitration: use the correction.** It is later, it corrects the earlier record
by name, and its method is the sounder one (attribute by module before symbol;
`umod()` needs no unwind info and no snapshot join). Consequence: Judge 1's
build-lane ranking of option C at **7–9x understates C's own headline term by
~2x**, and its ranking of options A/B/#13 **overstates their pot by ~3x**. Judge
1's *rankings* are still directionally usable; its *numbers* are not.

### 3.2 Is the build patchable at all? (Judge 2 vs Judge 3)

**Judge 2:** killed options C outright on the build lane — the cold build runs in
**Biased** address mode, so guest code is not at guest VAs and cannot be.

**Judge 3:** raised the whole C family, noting that guest text is *already* mapped
at the guest VA with `PROT_EXEC` deliberately stripped
(`mapped_memory.rs:4686-4690`), and that `execmem` / `fixed-map` /
`branch-gateway` probes all already passed
(`docs/2026-07-09-no-vmm-native-feasibility-evidence.md`).

**Judge 1** did not consider address mode at all.

**Arbitration: both are right about different images, and Judge 2's objection is
decisive for the build.** Verified independently for this document:

- `NativeLayout::select` (`crates/carrick-dsr/src/address.rs:507-536`) chooses
  `Direct` **only** when every image region starts at or above
  `NATIVE_DARWIN_HARD_PAGEZERO_END = 0x1_0000_0000`. Everything else gets a
  `Biased { host_bias }` layout from `BIAS_CANDIDATES`.
- The reason is a hard platform floor, not a carrick choice: XNU requires every
  64-bit arm64 Mach-O process to carry a **4 GiB `__PAGEZERO`**, and deallocating
  part of it does not make a low fixed mapping available
  (`2026-07-09-no-vmm-direct-execution-design.md` §"Darwin low-address boundary").
- Go links `ET_EXEC` at low addresses. Scanning the tree's own aarch64 fixtures:
  `…-static` min vaddr `0x10000`, `…hello.test` `0x400000`, the whole
  `go-base-_T_*` family `0x1f0000`–`0xff0000`. None can be Direct.
- And it is **measured on the actual build**, not inferred:
  `compact-ORR-bias-REMEASURED` records `ldr_x19_host_bias_share_of_jit = 0.167`
  on a cold build, and the emitted-word census shows `dsr:window-cbz-x18` 5.7%,
  `dsr:window-ubfm-x18` 2.9%, `dsr:bias-orr` 2.9% across 68 build processes.
  The compute census by contrast records *"Direct (identity): zero window-check /
  bias-orr samples."*

In Biased mode the obstacle is not "can we map executable memory there" (Judge 3
is right that we can) — it is that **every guest memory access must be
re-expressed through the bias**, which is precisely the ~25% of instructions the
DBT rewrites. An in-place patcher cannot do that without rewriting them, at which
point it is a translator again.

**What this does to option C:** it is a **compute-and-Direct-image vehicle**, not
a translator replacement. The "delete 25–40k lines" story evaporates — the
translator must stay for Biased images. That converts C from "wholesale
replacement" into "a second execution vehicle beside the DBT", which is exactly
the parallel path AGENTS.md forbids. Proposal 4 was the only one of the three that
faced this honestly, and it proposed the right mitigation (a fallback whose
executed-instruction share is a **gated number**, not a silent degrade).

### 3.3 Option A: is the libdispatch post-fork hazard dead? (unresolved)

The self-re-exec exists for a measured reason
(`2026-07-13-native-pid-preserving-self-reexec-design.md`): *"Node, Go, and
CPython repeatedly trap in libdispatch after their fork-to-exec children create
threads … `_dispatch_sema4_wait`."*

The proposal cites `native_darwin.rs:5766` as evidence the reason expired. **Judge
2** read the same comment as saying the retirement *rests on* the self-re-exec
(*"The fork-child host self-reexec does exactly the host-state reinitialization
this message says is impossible"*), and the 100 clean fork→thread→execve cycles
were run **with** it. **Judge 3** called it honestly uncertain, noting the later
bullets (carrick never calls libdispatch; the real bug was a CoreFoundation
`proctitle` round-trip since removed) genuinely do weaken the premise.

**Arbitration: unresolved, and it does not need arbitrating — it needs the
one-line flip.** This is the cheapest open question in the packet by an order of
magnitude.

### 3.4 Option B's standing (Judge 1 vs Judges 2 and 3)

**Judge 1** ranked B second and independently reproduced its band (9.5–11.5x),
calling its arithmetic internally consistent.

**Judges 2 and 3** both called it refuted on **mechanism reach**: the 4.04x
redundancy is *cross-process*, and on this lane a cross-process boundary is a
guest `execve`, which is a **host self-re-exec** that destroys the address space.
`minherit(VM_INHERIT_SHARE)` propagates across `fork`, not across `execve`. The
fork-without-exec case is already free — `jit.rs:82-89` returns
`ForkChildJit::Inherited` because `MAP_JIT` is `MAP_PRIVATE` and the child
already holds COW pages of the parent's cache.

**Arbitration: Judge 1 priced the pot correctly and never checked whether the
mechanism reaches it; Judges 2 and 3 checked.** The pot is real; B's route to it
is not. Worse, **B's own kill test cannot detect this** — it forks and checks
sharing, never crossing an exec, so a pass would be misleading. If B is run at
all, run the corrected test in the table.

### 3.5 The compute arithmetic `356 × (1 − 0.524)` (Judge 1 vs Judge 3)

**Judge 1** called it an error: `dsr_overhead_floor_pct_of_matched` is a share of
*matched JIT samples* with no recorded total, taken on the **P4c** arm (418 ms)
and multiplied against the **P4d** wall (356 ms); and residency→wall conversion is
this campaign's most-refuted inference (four recorded nulls, plus P2's
x17-materialize swinging 24.7%→4.9% at zero wall change).

**Judge 3** called it sound, because matched-sample count tracks wall almost 1:1
across the whole ladder: 5787 → 4776 → 3247 → 2866 matched against 652 → 529 →
418 → 356 ms.

**Arbitration: both are right about different things.** Judge 3's correlation is
real and I re-checked it from the census. But every step of that ladder removed
words *and* moved wall together, so the correlation licenses "removing inserted
words moves wall on this loop" — it does not license extrapolating linearly to
zero inserted words. The **conclusion** (native execution should be materially
faster on compute) is structurally sound and independent of the census; the
**specific 1.54x** is not established. That gap is exactly what Move 3 measures,
and it must be measured before anything is built, because the campaign's four
dispatch nulls are all instances of "words removed, wall unchanged".

### 3.6 Where the judges agreed

- **fs-walk is moved by none of the five options.** Unanimous, and correct: its
  in-guest half is 57% host kernel / 43% carrick *syscall dispatch*, and its
  lifecycle half is `clonefileat`. Neither is emitted code or translation.
- **`baseline.native-dsr.jsonl` is essentially empty** (one line, verified). Every
  option here deletes between 3,500 and 40,000 lines of the shipped default
  backend and **no gate exists that would tell any of them they broke Go, CPython,
  Node, apt/dpkg or LTP.** Only Proposal 5 raised it; Judge 3 promoted it to a
  cross-cutting prerequisite. It is Move 0 below.
- **No proposal re-proposed any of the campaign's six recorded NULLs.** Proposal 4
  cited the `rewritten_word_onto` null correctly and repurposed it (move the work
  offline rather than re-optimise it), which is the right use of a null.

---

## 4. ALREADY-REFUTED — with the record that kills it

Do not re-propose any of these. Each is a measurement, not an opinion.

**4.1 Low `ET_EXEC` guest images at their own guest VA — permanently impossible.**
XNU requires a 4 GiB `__PAGEZERO` on every 64-bit arm64 Mach-O and a smaller
segment is rejected with `LOAD_BADMACHO`
(`2026-07-09-no-vmm-direct-execution-design.md` §"Darwin low-address boundary");
`address.rs:507-536` therefore selects Biased for any image with a region below
`0x1_0000_0000`. This is a platform floor, not a carrick limitation. Any design
whose value depends on running the Go toolchain at its own addresses is dead on
arrival.

**4.2 `minherit(VM_INHERIT_SHARE)` as the vehicle for the 4.04x redundancy.**
Redundancy is 1.00x intra-process / 4.04x cross-process (wall audit §5), and the
cross-process boundary is a guest `execve` implemented as a host self-re-exec
(`native_exec_capsule.rs`; `2026-07-13-native-pid-preserving-self-reexec-design.md`);
~70 carrick processes per build (wall audit §4). Fork-only sharing is already
free (`jit.rs:82-89`).

**4.3 In-place patching as a *replacement* for the translator.** See §3.2. It is
a Direct-mode-only vehicle; the translator stays for Biased images.

**4.4 `mmap(PROT_EXEC)` on an unsigned file — `EPERM`.** AMFI refuses; an ad-hoc
signed dylib is the only supported file route
(`2026-07-26-file-backed-aot-cache-design.md` §1.4).

**4.5 A persistent AOT cache on the current publication path.** Cold +58%, warm
**+285%**, **0 units published**; the cache directory held exactly one key across
three runs against 107,320 distinct blocks (wall audit §5). The blocker is
coverage, not persistence. Also: **do not delete the shared-translation lane** —
it is ~90% of a persistent AOT cache and an earlier recommendation to delete it
was wrong (`handoff.md`).

**4.6 Full shared-unit mode / the H004 direct-binding sidecar.** 40.211 s vs
19.809 s control; publish-but-never-load 20.74 s, so the producer adds 0.93 s and
the **consumer is dominant** (~17.2 s in eager block indexing after load) —
`docs/perf-results/native-wall-time-campaign.md`. Any sharing design must answer
the consumer-side indexing cost, not just the producer.

**4.7 Re-implementing COW/file-backed guest *image* mapping.** Already shipped:
`map_prepared_region_extent` does this in production, 709 `MAP_PRIVATE|MAP_FIXED`
file mmaps against a guest-image zfod count of **11** (wall audit §4).
`map_prepared_for_plan`'s `dead_code` marker is a test-only helper and has already
misled two analyses.

**4.8 Parallelising the APFS directory clone.** NULL — 430 ms both arms; APFS
serialises namespace work inside a volume
(`container-lifecycle-split.jsonl` `parallel-cow-seed-null-result`).

**4.9 `MADV_WILLNEED` / `mlock` / `MAP_POPULATE` as populate primitives.** All
measured slower or identical (wall audit §4).

**4.10 Sub-1% micro-optimisation of the translator as a strategy.** Two spikes
NULL (rewrite-search hoist; `PageGenerationTable::observe` read-lock fast path)
plus the CORRECTION that `publish_emitted` 6.6% / `observe` 4.0% /
`sha2::compress256` 2.7% were shares of a 2,527-sample **subpopulation** and
rescale to 0.68% / 0.41% / 0.28% of total CPU
(`build-microopt-spikes-null-and-a-correction`).

**4.11 The dispatch load-chain-depth model on compute.** `ldar`→`ldr` NULL;
removing a whole L1 level from the dispatch probe NULL. Both reverted unlanded.

**4.12 `brk`/SIGTRAP as an in-place-patch syscall transport (Vehicle A).** Deleted
at `27af742f` ("make DSR the sole execution path"). The same-revision floor was
3.917 µs vs the gateway's 0.25 µs (`native-dsr-syscall-floor.jsonl`). Note the
file's 2026-08-02 annotation: the DSR floor remeasured at **0.292 µs** and *"the
syscall service floor is NOT a constraint"* — the brk number has never been
remeasured. Either way, the live form of patching is **Vehicle B** (branch to an
island reaching the gateway), whose feasibility probe passed
(`docs/2026-07-09-no-vmm-native-feasibility-evidence.md`:
`probe=branch-gateway status=pass return=77 branch_word=0x14000010`).

**4.13 Pre-sizing the `recovery` Vec** (+54%, it is retained so over-allocation is
retained), **thread-local scratch reuse** (−2%, inside noise), **the exit-target
literal pool** (reverted at `d4292368`). Wall audit §4 and `handoff.md`.

---

## 5. Recommended sequence

Ordered by *what each move decides*, not by expected prize. Nothing after Move 2
should be built before Move 2 returns.

### Move 0 — bless a native-DSR conformance baseline. **Prerequisite for everything.**
`scripts/conformance/baseline.native-dsr.jsonl` is one line. Every option here
deletes 3.5k–40k lines of the shipped default backend against no regression gate.
Needs no design, unblocks all four following moves, and is the single highest-
leverage risk reduction available. **Do this first regardless of which option
wins.**

### Move 1 — flip the self-re-exec off. One line, one afternoon. Decides option A *and* unblocks B and #13.
Gate `native_darwin.rs:3542`/`:3562` on `CARRICK_NATIVE_SELF_REEXEC=0` in a
throwaway worktree; run 100 fork→live-thread→`execve` cycles, `cpython-subprocess`,
node, go-osexec, apt-install, and `workload-spread.sh 5` build-cold on both arms.

- **Correctness result** settles §3.3 — is the libdispatch post-fork trap still
  real on Node/Go/CPython?
- **Value result** is the Phase 0 measurement option A's headline term (per-exec
  host process construction) is entirely missing. A <5% build-cold delta reduces
  A to a code-deletion-and-correctness PR.
- **It also decides the shape of every sharing design.** If exec stops destroying
  the address space, the within-run 75% of the 4.04x becomes reachable in memory,
  and #13's signed on-disk store is only needed for *cross-run* warmth — which is
  the smaller residual. If exec keeps destroying it, #13's store is the only route
  and option B is dead (§4.2).

### Move 2 — the address-mode and patch-density census. Offline, one afternoon. Decides the whole C family.
One instrument over the **actual conformance-image binaries** (`go`, `compile`,
`link`, `python3.12`, `node`, `bash`, `dpkg`, `ld-linux-aarch64.so.1`,
`libc.so.6`), answering two questions:

1. **What share of *executed* guest code lives in images that select `Direct`?**
   Per workload. No proposal asked this, and it is the question that sizes C.
   Instrument it from `NativeLayout::select`'s own decision, not from a static
   guess.
2. Within Direct images: must-patch density (`svc`, divergent system registers,
   cache maintenance, x18) and the literal-pool collision hazard — words at
   non-instruction positions that a linear sweep would corrupt.

**Kill:** if (1) is near zero on everything but compute, C is a compute-only
vehicle. It may still be worth building — compute is the campaign's named goal
and C is the only thing that reaches it — but it must then be scoped and sold as
a second vehicle beside the translator, with the fallback share reported as a
gated number.

### Move 3 — the hand-patched compute prototype. About a week, throwaway. Decides whether C's prize is real.
Hand-patch `mawk`'s sensitive sites, map at the guest VA, install the existing
gateway, run the 8M-iteration loop with **no DBT at all**, in-guest window, quiet
box, ≥5 samples, against Docker's 110 ms. **Kill if not ≤ ~176 ms (1.6x).** This is
the experiment that catches the exact failure mode of the campaign's last four
codegen experiments — words removed, wall unchanged — *before* any deletion.

### Move 4 — fs-walk Lever B. Independent of Moves 1–3; can run concurrently in a separate worktree.
The only lever in the tree that reaches 2x on a wall-clock workload (620 → ~290 ms
total wall). Serve reads from the shared cache tree as a read-only lower layer
instead of cloning it per run. It conflicts with today's scratch-is-truth trusted
lanes and needs its own design — but its prize is measured, not estimated.

**Sequencing conflict to respect:** Lever B changes what a "trusted dirfd" means
and Move 1 changes when one is destroyed. Land them in either order, **not
concurrently in the same worktree.**

### Move 5 — conditional on Move 1: re-scope #13.
If in-process exec is safe, #13's Phase 2 persistent store shrinks to a cold-start
seed and the within-run share is reachable without signing, `dlopen` or a GC'd
on-disk store. If it is not, #13 proceeds as written — and its Phase 0 (fix the
`xlat_census` `execve` flush) is mandatory first, because **433,249 and 107,320
are lower bounds until it lands** and every sizing in this document leans on them.

### What composes, and what is mutually exclusive

| pair | relationship |
|---|---|
| A + C | **compose.** Different terms (process construction vs emitted code), different workloads |
| A + #13 | **compose**, and A is an *enabler*: in-process exec makes retained translations reachable |
| A + fs-walk endgame | compose on total wall; **do not land concurrently in one worktree** (trusted-dirfd lifecycle) |
| B vs #13 | **mutually exclusive** — two implementations of one prize. B's mechanism is refuted (§4.2), so #13 survives |
| C vs #13 | **compose in practice.** C would subsume #13 only for Direct images; the build is Biased, so C leaves the build's translation cost untouched and #13 still owns it |
| P3 vs P4 vs P5 | **mutually exclusive write-ups of one mechanism.** Merge target: P4's mechanism detail (per-site scratch by liveness, `TPIDR_EL0`+TSD context reach, x18 killed on measured evidence) + P3's demand-paged containment (a page is executable only after it was scanned — the only proposal whose worst failure is closed by construction) + P5's historical framing and its baseline prerequisite |
| #14 assembler arena | **subsumed on the build** by whichever of #13 / C lands; its Phase 3 (allocator policy, reaching carrick's whole heap rather than the assembler's 73%) **survives independently** and should be re-ranked on its own after Move 1 |
| fs-walk endgame vs everything | **orthogonal.** Different subsystem, different term, no shared code |

---

## 6. Risks that no proposal named

Carried forward so the next design does not pay for them again.

1. **Branching out of an `ldxr`/`stxr` exclusive region to an island clears the
   monitor.** The translator carries a whole `ExclusiveFusionRejection` taxonomy
   for this. A `b <island>` between the pair silently converts a bounded retry
   loop into a livelock. Affects the entire C family.
2. **The C family's fallback is structurally permanent, not a phase-in artifact**
   (§3.2). Two of the three write-ups framed it as temporary; both are wrong.
3. **Promoting `BindingIndex`-guarded blocks to the hot path can regress compute.**
   The trusted-entry, single-store-exit-tail and `ldp`-packing work exists only
   for the `Absolute` guard flavor. Any sharing design that makes loaded units the
   default (B, and #13's Phase 1) **puts the banked 10.9x → 3.2x compute result at
   risk** unless that codegen work is extended first. Proposal 2 named this; it is
   a prerequisite, not a footnote.
4. **The census denominators are lower bounds.** `xlat_census`'s `atexit` flush is
   skipped by the self-re-exec, and the alloc census's process coverage varied
   23/25/34 across identical runs for the same reason. Any Phase 0 measuring exec
   cost must fix the flush first, or it measures the wrong 34 of ~70 processes.
5. **`ustack()` on this workload lies rather than fails** — ~70 self-re-exec'd
   processes with independent ASLR slides resolve surviving frames against the
   wrong image. Attribute by **module** (`umod()`) before symbol. That rule is what
   caught the §0 correction.

---

## 7. What this document does not decide

- **Whether the 2x bar applies to cold builds or to representative workloads.**
  §2 shows the build cannot reach it; compute and fs-walk total wall can. This is
  a product decision and needs no further code to answer.
- **Whether a compute-only execution vehicle is worth a permanent second path**,
  given AGENTS.md's opt-out rule. Move 2 prices it; a human decides it.
- **Whether a persistent on-disk translation cache is architecturally acceptable**
  (staleness, disk growth, GC). Unchanged from `handoff.md`; the key already
  carries `translator_abi`, so stale entries miss rather than corrupt.
