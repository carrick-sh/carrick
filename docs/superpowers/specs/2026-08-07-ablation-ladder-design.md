# The ablation ladder: sizing architectural levers before building them

**Status:** proposed 2026-08-07 (user-directed). Measurement-only program; no
shipped behavior changes.
**Scope:** Darwin/aarch64 native backend, cold `go build` as the canonical
workload, with a PIE-heavy secondary workload where the canonical one is
structurally ineligible.

## 1. Why this exists

Move 3 closed with the shipped-default cold build at **10.1806x** Docker
(8,175 ms / 803 ms), essentially where it stood on 2026-08-04. The campaign
produced one controlled win (the anon-reuse remap, −0.660 CPU-s / −3.24%),
several correct negative results, and a working amplification ledger. But the
plan's own arithmetic says the named entries sum to ~5.6 of the 7.555 CPU-s
gap — **the identified levers cannot close it**, and every instrument built so
far answers "where does carrick's time go," which is a hot-spot question that
finds hot-spot-sized answers.

Three costs dominate and all three are **designed in**, not accidental:

| designed-in cost | the decision that created it |
|---|---|
| the anon scrub, aperture gate, `HostAliasTransactions` serialization, alias windows | guest VA ≠ host VA: the **biased aperture** |
| ~768k block translations/build, emitted-code overhead, the translation lock | **translating** same-ISA code instead of patching it |
| ~8.5 ms × ~61 execs, capsule build/teardown | **self-re-exec** with PID preservation |

No profile will ever print "the aperture should not exist." The ladder's job
is to put a **hard upper bound** on each of those decisions' total cost, so
the next campaign is aimed at a lever whose size is known *before* the
engineering starts — which is exactly what the arena campaign lacked.

## 2. The method, and its one rule

For each subsystem, produce a binary that **does not do the work at all** and
measure the same fixture. The result is a **ceiling**: no correct optimization
of that subsystem can ever beat it.

**The rule: ablations are incorrect by construction and must never be
shippable.** Every rung is gated behind an env var whose name begins
`CARRICK_ABLATE_`, every ablated run prints a loud unmissable banner to
stderr, and the gate additionally requires a build-time
`--features ablation` so an ablation cannot be enabled on a normal binary at
all. No `CARRICK_ABLATE_*` path may be reachable in a release build without
that feature. A rung that cannot be built that way is not run.

Corollaries:

- A guest that **crashes** under ablation is a valid result: measure to the
  crash, report where it died, and say the ceiling is a lower bound on the
  ceiling. Do not repair the guest.
- A guest that **completes with wrong output** is the expected case for
  several rungs. Verify only that it did the same *work* (same syscall
  count / same phase progression), not that it produced the right answer.
- Ceilings compose only loosely: two ablations together are not the sum.
  Measure the pairwise combination where it matters rather than adding.

## 3. The ladder

Rungs 1 and 2 are **not ablations** — they are existing, correct, opt-in paths
that have never been compared head-to-head on a controlled measurement. They
come first because their numbers are trustworthy and cost nothing to obtain.

### Rung 1 — Translation ceiling (correct path, never measured)

**Question:** what does translating same-ISA code cost, when the alternative
is patching it?

**Method:** tier D (`CARRICK_NATIVE_DIRECT=1`) versus tier T on the same PIE
workload. Tier D runs real CPython 3.12 including `threading.Thread`
end to end (2026-08-02 direct-execution work); the census says intervention
is needed for **0.048%** of instructions.

**Fixture:** a CPython workload with real compute and real syscall traffic —
not `print(1)`. Propose `python3 -c` doing measurable work plus a small
`subprocess`/file component; pin it and reuse it for every rung that uses the
PIE workload.

**Reports:** wall + CPU-s both arms, plus the translation counters. This is
the ceiling on *everything* the translate/emit/cache/publish machinery costs
for an eligible guest.

**Caveat to state:** the Go toolchain is ET_EXEC and cannot take this path
(Darwin `__PAGEZERO` owns 0–4 GiB), so this bounds the PIE lane, and the
canonical build lane only insofar as tier-D-for-ET_EXEC is later shown
possible. That question is rung 5.

### Rung 2 — Bias ceiling (correct path where legal, never measured)

**Question:** what does the biased aperture cost — the whole family of scrub,
gate, alias-window and host-alias-transaction machinery that exists *because*
guest VA ≠ host VA?

**Method:** `NativeAddressMode::Direct` versus `Biased` on a PIE guest whose
regions sit above 4 GiB (`address.rs:507` already supports this). Same PIE
fixture as rung 1, tier T both arms so translation is held constant.

**Reports:** wall, CPU-s, host syscall count, zfod count, and the AMP1
per-op ledger for both arms — the ledger will show directly which guest
operations get cheaper when the bias goes away.

**Why this is the highest-value rung:** the bias is the root of the cost
family Move 3 spent its entire budget nibbling at. If direct addressing is
worth >15% on the PIE lane, then "make the canonical lane direct-addressable"
becomes the campaign, and the specific sub-question is rung 5.

### Rung 3 — Zeroing ceiling (true ablation)

**Question:** after the remap landed, how much is left in the guarantee?

**Method:** `CARRICK_ABLATE_ZEROING=1` makes `zero_anonymous_reuse` /
`zero_backing` no-ops that claim success. Guest correctness is forfeit — Go's
runtime may or may not survive; CPython's `multiprocessing.Pool` is documented
to corrupt (`dispatch/mem.rs:2350`).

**Fixture:** the canonical cold `go build`.

**Reports:** wall/CPU-s vs the shipped default; the residual after the remap.
If this rung is <1%, the zeroing line is closed for good — a genuinely useful
negative.

### Rung 4 — Exec-chain ceiling (true ablation)

**Question:** what is the total cost of the self-re-exec architecture, as
opposed to its measured ~8.5 ms Darwin floor?

**Method:** `CARRICK_ABLATE_EXEC_CHAIN=1` short-circuits the capsule
build/serialize/re-exec path — run the successor image in-process without PID
preservation, accepting wrong process semantics. Expect breakage; measure to
it.

**Fixtures:** the 20-exec micro (isolates the term) and the cold build
(weights it).

**Reports:** per-exec cost with the chain versus without. Bounds the
zygote/pid-virtualization question that §7 of the performance roadmap parked.

### Rung 5 — The ET_EXEC question (analysis, not measurement)

**Question:** can the canonical lane ever take rungs 1 and 2's path?

Not a measurement — a costed design answer. Darwin's `__PAGEZERO` owns
0–4 GiB and static Linux binaries load at `0x400000`; the 2026-08-02 probes
found low VAs hard-unreachable (`mach_vm_deallocate` of pagezero "succeeds"
but the range stays unmappable). The question is whether the *guest binary*
can be relocated (PIE-ified, pre-linked, or loaded at a high VA with its
absolute references fixed up) rather than whether the address space can be
reshaped. Deliverable: a yes/no with the mechanism and its risks, sized
against rungs 1+2's measured ceilings.

## 4. Protocol

- Quiet host per arm (`carrick trace --preflight-quiet-host` where the profile
  allows; otherwise the documented preflight receipt), `CARRICK_RUN_ID`
  stamped, `scripts/sudo/kill.sh` reaping only, never carrick‖Docker.
- **n ≥ 4 per arm, interleaved**, one binary per arm with its SHA-256 recorded
  per sample. Wall and CPU-s both reported with intervals.
- Ablation arms are compared **only against a same-binary control** where the
  feature exists but the env var is unset — never against a different build.
- Every rung's entry states: the ceiling, what it does NOT bound, and the
  guest's correctness status (completed / completed-wrong / crashed-at-X).
- Receipts under `target/perf/ablation/`, evidence under
  `docs/perf-results/2026-08-XX-ablation-ladder.md`.

## 5. What this produces

One table: **subsystem → measured ceiling → what it would take to claim it.**
That table is the input to the next campaign's ranking, replacing the
estimate-based rankings that produced the arena bet and E1's misattribution.

An honest expectation: the most likely outcome is that **no single rung is a
2x lever** and the answer is a combination — in which case the table says
which combination, which is still strictly more than we know today. The
second most likely outcome is that the bias rung is large, which would make
"canonical-lane direct addressing" the campaign and rung 5 its gate.

## 6. What would invalidate this program

- **A rung's ablated binary cannot run the fixture far enough to measure.**
  Then that subsystem's ceiling needs a different instrument (a synthetic
  microbenchmark of the subsystem alone), and the rung is deferred, not faked.
- **Rungs 1–2 show the PIE lane is already near Docker.** Then the entire
  overhead is ET_EXEC-specific and rung 5 becomes the whole program.
- **Every rung comes back small.** Then the overhead is not in any single
  subsystem but in the per-operation lowering cost spread across all of them,
  and the amplification ledger's per-op program is the right one after all —
  it just needs to run the full top-20 rather than the four entries Move 3
  reached.
