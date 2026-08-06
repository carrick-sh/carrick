# Category collapse: the strategy from 10x to 3x

**Status:** adopted 2026-08-05 (user-approved). Supersedes the ranking and
phase-ordering sections of
[`2026-08-02-performance-roadmap.md`](2026-08-02-performance-roadmap.md);
that document's §5 appendix (rejected alternatives, DSR fallback playbook)
remains authoritative and is incorporated here by reference.
**Scope:** Darwin/aarch64 native backend (`--exec-backend native`, the shipped
default), cold `go build` as the canonical workload. VMM is explicitly not the
target (one process per VM against a ~127-VM ceiling).
**Goal:** cold `go build` within 3x of native-arm64 Docker; the 2x product bar
per [`AGENTS.md`](../../../AGENTS.md) stays the horizon.

Numbers in this document are measured unless marked *derived* or *estimated*.

---

## 1. Where we are

Official shipped-default scoreboard
([`2026-08-04-current-default-wall-refresh.md`](../../perf-results/2026-08-04-current-default-wall-refresh.md)):
cold-build workload wall **10.1776x** (8,254 ms vs 811 ms). Workload spread
([`2026-08-03-current-default-workload-spread.md`](../../perf-results/2026-08-03-current-default-workload-spread.md)):
compute **3.3868x**, fs-walk **18.9286x**, 20-exec `compile -V` **72.1579x**,
cold build 10.8761x.

Fresh authenticated v5 all-CPU split, two independent captures
([`2026-08-04-current-default-broad-cpu-attribution.md`](../../perf-results/2026-08-04-current-default-broad-cpu-attribution.md)):

| category | share of sampled CPU |
|---|---|
| Darwin kernel | **48.0232% / 48.7901%** |
| — named-syscall | 27.7520% / 28.8889% |
| — non-syscall (faults, VM) | 20.2712% / 19.9012% |
| translated guest | 25.8818% / 25.3278% |
| Darwin userspace (libs) | 10.0290% / 9.9863% |
| other Carrick host code | 8.3174% / 8.5377% |
| translation | 6.0589% / 5.9643% |

*Derived* CPU-seconds at the current default: 8.254 s wall × ~2.5-core
utilization (utilization measured at
[`2026-08-03-build-serialization-attribution.md`](../../perf-results/2026-08-03-build-serialization-attribution.md))
≈ **20.6 CPU-s**, vs Docker ≈ 2.0. The translated-guest bucket alone is
≈ 5.3 CPU-s — **≈ 2.6x Docker's entire build**. Reaching 3x means finishing at
≈ 6.1 CPU-s: every category above must shrink several-fold simultaneously.

## 2. Diagnosis: the ≥10% single-mechanism policy has exhausted its search space

The policy — attribute until one source-distinct mechanism clears ≥10% of CPU
in both captures, then implement — produced correct attributions and has now
returned "no candidate" across the board. Receipts (all in
[`handoff.md`](../../../handoff.md) with full evidence links):

| line | best mechanism found | verdict |
|---|---|---|
| context traffic | x17/slot-1128 7.00–7.18%; ctx-load64+store64 floor 11.56/11.39% but source-distinct | no-carry @99% |
| fault ownership | metadata-page projection ~7.41–7.42% | closed, none selected |
| allocation owners | publication recovery 8.05–8.34% | closed, none selected |
| memory intent | anon-private mmap zfod 6.35–6.56% | closed, none selected |
| exec/exit lifecycle | strict cold-build opportunity 8.82% mean | closed, below gate |
| trusted-entry routes | all three routes combined 7.96% | stopped |

Two candidates implemented despite the gate both **improved their targeted
mechanism and lost their ABBA**: monotonic store augmentation (private
translations −56%, child CPU ratio 1.0728, wall 1.2786 — removed) and
decode-outside-writer (`psynch_cvwait` share −19–21%, total CPU 1.1374, 0/8
quads — reverted). That is the signature of coupled costs: local mechanism
removal moves the cost instead of deleting it. The one retained win of the week
is the 8.50% published-block lock split (`64bebc26`).

Conclusion: the remaining ~70% of the wall is not hiding in any single
mechanism. It is structural, spread across categories, and each category needs
an architectural change. The handoff's own 45% confidence in the ≤3x goal is
the honest readout.

## 3. The strategy: collapse categories, not mechanisms

Four moves. Move 0 is policy; Moves 1–3 each target one category wholesale.

### Move 0 — category budgets, with Docker-side denominators

Every attribution to date is carrick-side only; **Docker's user/sys CPU split
for the same build has never been measured**, so "how much kernel CPU should
this workload cost?" has no denominator. First action: capture Docker-side
`getrusage`/cgroup CPU splits for the cold build and the spread fixtures, then
derive a CPU-second budget per category from the 3x goal, of roughly this
shape (final numbers come from the measurement):

- translation + translation-lock + translation-metadata: ≈ 0 (amortized);
- translated guest: ≤ ~1.3x Docker user CPU;
- Darwin kernel: ≤ ~2x Docker sys CPU;
- carrick host userspace + Darwin userspace: ≤ ~1 CPU-s combined.

Work is ranked by **category-budget movement**. The ABBA discipline is
unchanged for retention decisions. The ≥10% gate remains an attribution
filter but stops being a veto: it systematically no-carries architectural
families that are individually <10% while summing to the gap — the ctx-traffic
family (16.07–16.17% of all CPU, disqualified as 7.0% + 8.7% source-distinct
halves) is the worked example. A family addressed by ONE mechanism (one
compiler pass, one shared mapping) is judged as one candidate.

### Move 1 — finish the live arena; account it as a memory-system fix

The in-flight work and its sequencing are unchanged: Tasks 6C2 → 6D/6E/6F → 7
per [`handoff.md`](../../../handoff.md); runtime-on correctness, DTrace, and
ABBA evidence remain forbidden until Tasks 6D/6E/7 close.

What this spec changes is the expectation accounting. The arena's addressable
pool is not the 6% translation CPU; it is the whole translation *category*:

| component | measured share | why the arena addresses it |
|---|---|---|
| translation CPU | ~6.0% | translate-once/attach-many |
| `psynch_cvwait` translation lock | 11.12–11.58% | remaining wait is exclusive translation; attach path takes no exclusive lock |
| publication-recovery allocation | 8.05–8.34% | publication happens once per image, not per process |
| PC-map/recovery metadata zfod (6.87 GB/build initialized per-process) | ~7.4% projection | becomes shared read-only mappings — this is the largest *identified* chunk of the kernel non-syscall bucket |

These overlap and the zfod cost model is favorable, so the net expectation is
**15–25% of total CPU**, plus the ~49 ms/exec retranslation term that dominates
the 72x exec micro. *Estimated* landing point: cold build ~7.5–8.5x.

**Acceptance gates** (in addition to the correctness/revocation gates already
in the handoff):

- attach cost **< 1 ms per process**, measured — the earlier store lost
  because its 14.8 ms/process load ate an 87% translation reduction
  (roadmap §0);
- the 20-exec micro moves decisively (72.16x today; target well under 20x);
- cold-build ABBA and the serialized shipped-default refresh both hold.

### Move 2 — AOT-quality translation, priced by the arena (the new bet)

Every codegen decision to date has been priced under JIT economics: 8.4 µs per
block × 1.7 M blocks, paid by every process, so expensive passes were never
affordable. Translate-once/attach-many changes the amortized price of
translation quality to ~zero. This converts the deferred "eager full
translation" idea into the vehicle for a codegen-quality campaign, in
expected-value order:

1. **Liveness-gated borrow save/restore.** The x17/x19 context traffic is
   carrick saving and restoring the four registers it *borrows*, gated on the
   emitter's own needs rather than on whether the guest value is live
   ([`AGENTS.md`](../../../AGENTS.md): "a stolen-register problem"). One pass
   addresses the whole ~16%-of-CPU family the mechanism gate split and
   rejected.
2. **The DSR fallback playbook** (roadmap §5, all previously unaffordable
   per-process): guard-page aperture checks replacing the per-access
   `lsr`/`cbz` pair; bias preloaded in a reserved register; scratch-spill
   folding across consecutive memory ops; monomorphic inline cache + shadow
   return stack for indirect exits.
3. **Function/superblock-scope translation with real register allocation** on
   hot units, since compile time no longer multiplies by process count.

*Estimated* target: emitted code from ≈2.6x to ≈1.3–1.5x Docker CPU, worth
~13–15% of total build CPU, and substantially more on compute-shaped
workloads — the 3.39x compute micro is where this shows first and is the
cheapest gate for each pass.

Tier D is explicitly **not** this lever for go build: the Go toolchain is
ET_EXEC and Darwin's low-VA physics keep it on DSR permanently (roadmap §5).
Tier D remains the cpython/node lane with its four named correctness blockers,
on its own cadence; it must not absorb this campaign.

### Move 3 — the Darwin kernel tax as an amplification ledger

Half the CPU is kernel and no single owner clears 10%, because the tax is a
sum of small per-guest-op amplifications. The program: a standing **ledger of
host operations and host CPU-ns per guest operation** for the top ~20 guest
operations on the build, each driven toward 1, ranked by ledger movement
against the Move-0 kernel budget. Per the Rust-first rule, the ledger is a
`carrick debug` / `carrick trace` capability, not a script pile.

Known entries with evidence already in hand:

- guest `mmap(MAP_PRIVATE, fd)` → full-length `pread` into fresh anon instead
  of a host file-backed mmap
  ([`dispatch/mem.rs`](../../../crates/carrick-runtime/src/dispatch/mem.rs));
- guest heap decommit/recommit → lower intent to
  `MADV_FREE_REUSABLE`/`REUSE` per the Go dual-port oracle, not re-issued
  Linux idioms;
- the `HostAliasTransactions` process-global gate held across `zero_backing`:
  9.74 µs vs 6.42 µs per fault and 15x involuntary context switches under
  in-process parallelism
  ([`2026-08-01 audit §4`](../../perf-results/2026-08-01-native-wall-audit-and-fault-cost.md));
- **the fs-walk in-guest amplification**: the current spread measures the
  in-guest fs-walk window at **18.9286x** (265 ms / 14 ms). The 2026-08-02
  trusted-dirfd result of ~3.8x was **total wall** (container lifecycle
  included; lifecycle reached 2.7x), while the in-guest window was 18.5x
  then and is 18.9x now
  ([`container-lifecycle-split.jsonl`](../../perf-results/container-lifecycle-split.jsonl),
  records `fs-walk-lifecycle-vs-in-guest`, `total-wall-drained-baseline`) —
  a denominator difference, not a regression. The in-guest fs term was never
  fixed; the named redesign is fs endgame Lever B (serve reads from the
  shared cache tree as a read-only lower layer, copy-up on write — roadmap
  Phase 4). First ledger entry: re-measure host-ops-per-guest-op on the
  `find /usr/local/go -type f` fixture at HEAD (AGENTS.md's 19.68
  hosts-opens-per-guest-open figure is flagged stale by AGENTS.md itself).

## 4. Arithmetic to 3x (all *derived/estimated*)

From ≈20.6 CPU-s: Move 1 −3 to −5; Move 2 −2.5 to −3; Move 3 must deliver −5
to −6 (kernel ≈10 CPU-s → ≈4, the hardest ask); carrick-host and Darwin-user
partially fall out of Moves 1–2 (the named allocation owners are
translation-linked). Landing zone ≈ 6.5–8 CPU-s ≈ **3.2–3.9x** if all three
moves hit their upper halves. 3x is reachable, tight, and requires all three
categories — which is exactly why a mechanism-at-a-time strategy could not get
there.

## 5. Sequencing

1. **Wave 0 (now, non-regrettable, no interference with arena tasks):**
   Docker-side CPU-split measurement + the category-budget table; the fs-walk
   in-guest amplification-ledger entry (Task 4 of the Wave-0 plan). Both are pure measurement.
2. **Wave 1 (in flight):** live arena Tasks 6C2 → 6D/6E/6F → 7, runtime-on
   evidence, ABBA, scoreboard refresh — exactly as the handoff sequences it.
3. **Wave 2 (gated on Wave 1 runtime-on ABBA):** the AOT codegen campaign,
   pass by pass, each gated on the compute micro then the build ABBA.
4. **Wave 3 (start after Wave 0 budgets exist; runs parallel to Wave 2):**
   the amplification ledger instrument, then entries in ledger order.

## 6. What would invalidate this plan

- **The arena's runtime-on ABBA lands under ~10%.** Then the translation
  category was smaller than its components suggested (overlap larger than
  modeled); Move 3 promotes to the front and Move 2 is re-costed against
  whatever translation economics actually shipped.
- **A Move-2 pass wins its mechanism and loses its ABBA** (the augmentation /
  optimistic-decode pattern). Stop the pass line; the coupling is in the
  memory system, and Move 3 leads.
- **Docker-side measurement shows the kernel budget is already near 2x
  Docker sys.** Then the kernel share is mostly *induced by* translation and
  guest amplification rather than an independent tax, and Move 3 shrinks to
  the named entries only.

## 7. The honest ceiling

The self-re-exec chain has a measured ~8.5 ms Darwin exec floor
([`2026-08-03-native-exec-fixed-cost-decomposition.md`](../../perf-results/2026-08-03-native-exec-fixed-cost-decomposition.md));
61 execs ≈ 0.5 CPU-s ≈ +0.25x wall on this shape, and the zygote is
structurally impossible under the libdispatch and PID-preservation constraints
(2026-07-13 self-reexec finding). The only path under that floor is full
guest-pid virtualization decoupling guest pids from host pids — a deliberate
research spike against that finding, explicitly parked, not a campaign item.
On the exec-churn shape, ~1x is not on the table without it. State the shape
with the number, always.

## 8. Alternatives considered and rejected

- **Keep the sequential ≥10% grind.** The week of 2026-08-03/04 is the
  evidence against it: six lines closed with no candidate, two implemented
  candidates reverted on ABBA, one retained 8.5% win, 45% self-assessed goal
  confidence.
- **Pivot the campaign to tier D.** Patch-not-translate is right for PIE, but
  the Go toolchain is ET_EXEC and low VAs are hard-unreachable on Darwin
  (probed; roadmap §5). It structurally cannot carry the go-build goal.
- Everything in roadmap §5's rejected list stays rejected: ORR-bias,
  general identity mapping, `TPIDR_EL0` context, `mprotect`-based W^X
  invalidation.
