# Ablation ladder: measured ceilings for the designed-in costs

**Date:** 2026-08-07 (run window 15:06Z–15:21Z)
**Spec:** [`../superpowers/specs/2026-08-07-ablation-ladder-design.md`](../superpowers/specs/2026-08-07-ablation-ladder-design.md)
**Scope:** Darwin/AArch64 native backend. Every number below is a **ceiling**:
the subsystem's work deleted (or replaced by its correct cheaper sibling) and
the same fixture re-measured. No correct optimization of that subsystem can
ever beat its ceiling.

## The table

| rung | subsystem | fixture | measured ceiling | what it would take to claim it | guest correctness |
|---|---|---|---|---|---|
| 1 | same-ISA **translation** (tier T machinery vs tier D patching) | PIE/CPython | **63.8% of workload wall** (4,097.9 → 1,484.4 ms, 2.76x; CPU −54.2%) | Grow tier D: flip default-on behind the conformance smoke, close the window-scan gaps (OpenSSL/MTE text). **PIE lane only** — ET_EXEC is kernel-blocked (rung 5) | completed, output-correct, census-verified 9/9 images direct |
| 2 | **biased aperture**, per-access family | PIE/CPython, superblocks off both arms | **13.6% of workload wall** (5,317.5 → 4,593.3 ms; CPU −12.8%) | Canonical-lane direct addressing — blocked by rung 5. Cheaper biased lowering: the compact ORR path was already measured 3.76% WORSE (H008) | completed, output-correct |
| 3 | **zeroing guarantee** (residual after the anon-reuse remap) | PIE; cold go build | **<1% — noise** (PIE: −0.43% wall, −0.55% CPU); build: unmeasurable, crashed | Nothing. The line is CLOSED: the remap (`52342762`) already claimed the win (−0.660 CPU-s controlled) and the residual is bounded under noise | PIE completed (output still correct); build **crashed** at Go GC init (`gcBgMarkStartWorkers`) |
| 4 | **capsule self-re-exec chain** (fork-child execve) | 20-exec micro; cold go build | **7.2 ms/exec** in-window (341.8 → 198.5 ms micro window, −41.9%); by arithmetic ≈ **5.4% of the build** (61 execs × 7.2 ms ≈ 437 ms of 8,144 ms) | Sound in-process exec for forked children (validate inherited fd/thread/store state) — the parked zygote/PID question. Must also beat the ablated arm's unattributed **extra out-of-window cost** (below) | micro completed; build **crashed** at first `go tool compile` (fatal signal 5 in host code, ~1.4 s) |
| 5 | **ET_EXEC → direct/tier-D** (analysis, not measurement) | — | n/a — this is the gate on rungs 1–2's levers | **NO on Darwin/arm64.** Address floor is settled kernel policy; binary relocation is unsound without relocation records (below) | n/a |

**Headline verdict: no single subsystem is a 2x lever on the canonical build
lane.** The one big measured lever — translation, 2.76x — exists only on the
PIE lane and is kernel-blocked for ET_EXEC (rung 5). For the canonical lane
every measured ceiling is ≤~5–14%, which is the spec's third outcome: the
overhead is per-operation lowering cost spread across subsystems, so the
amplification ledger's per-op program (run the full top-20, not four entries)
is the right canonical campaign. On the PIE lane, tier D default-on plus the
residual dispatch/VFS work is a real ~2.8x product lever.

**Invalidation checks** (spec §6): condition 1 fired for rungs 3–4 on the
canonical fixture (ablated build cannot run) — both fell back to the
prescribed alternate instruments rather than being faked. Condition 2 did
NOT fire: the PIE lane is not near Docker (tier T 22.1x, tier D 8.0x).

## Protocol and provenance

- Host: Apple M4 (Mac16,12, 4P+6E, 10 logical), macOS 27.0. 1-minute load
  2.9–3.6 throughout (below the 10-CPU preflight bar); preflight
  (`busy_host_reasons`) passed without `--allow-busy` on every phase.
- Harness: [`scripts/perf/ablation_ladder.py`](../../scripts/perf/ablation_ladder.py)
  (drives `native_go_build.py`'s primitives). Interleaved arms, 1 warmup per
  arm then n=5 per arm (n=2 for the crash-record phases), `CARRICK_RUN_ID`
  stamped, `kill.sh` reaping only, carrick and Docker in separate phases,
  never concurrent. CPU is the harness's `RUSAGE_CHILDREN` delta (a floor).
  The workload window is in-guest `date +%s%N` bracketing, excluding
  container boot/teardown.
- Binaries (SHA-256 recorded per sample in the receipts):
  - rungs 1–2: default features at `81d915b0`, `2a5a6906…849714`
    (preserved as `target/perf/ablation/carrick-default-81d915b0`);
  - rungs 3–4: `--features ablation` at `7336ecc1`, `1084b4f7…4f79ca`
    (`target/perf/ablation/carrick-ablation`). Its **control arms reproduce
    the shipped scoreboard** — go-build workload medians 8,208/8,144 ms and
    CPU 19.88/20.07 s against the official 8,175 ms / 19.795 s
    ([`2026-08-07-post-move3-default-refresh.md`](2026-08-07-post-move3-default-refresh.md)) —
    so the dormant feature does not distort the control.
- The ablation rule held: knobs exist only under `--features ablation`
  (grep-proof: every `CARRICK_ABLATE_*` site is inside cfg-gated code;
  `strings` on the default binary finds zero `CARRICK_ABLATE` matches), the
  env opt-in is exactly `=1`, and the harness fails closed on banner
  mismatch (ablated arm without the `CARRICK ABLATION ACTIVE` banner, or a
  control arm with it, aborts the phase).
- PIE fixture (`ablation-pie-fixture-v2`, pinned in the harness): CPython
  3.12.13 from `localhost:5005/cpython-test:3.12.13` (image
  `4af881c7d613`) — the conformance campaign's exact interpreter build.
  Pure-interpreter FNV-1a byte kernel, dict churn, 300 file
  write/read/unlink cycles, 4 threads, 5 subprocess execs; ~9 exec'd images
  per run. All arms of all rungs produced byte-identical guest output
  (`PY_OK 387249772879650636 3118138912 4916400 4`) except where crashed.
- Docker reference: the SAME image bytes (OCI archive assembled from
  carrick's own store, `docker load`ed; identical image ID `4af881c7d613`),
  measured in its own phase after all carrick phases: workload median
  **185.3 ms** (182.9–187.8). Docker CPU is not host-observable (LinuxKit
  VM) — only the workload wall is cross-engine comparable.
- Receipts: `target/perf/ablation/rung{1,2,3,4}-*.jsonl` + `.summary.json`
  (per-sample env overlays, run ids, SHA-256, loadavg, tier census, stderr
  tails).

## Rung 1 — translation ceiling (correct path vs correct path)

| arm | workload ms (median, n=5) | spread | CPU s | vs Docker 185.3 ms |
|---|---|---|---|---|
| tier T (shipped default) | 4,097.9 | 4,024–4,155 | 4.505 | 22.1x |
| tier D (`CARRICK_NATIVE_DIRECT=1`) | 1,484.4 | 1,454–1,486 | 2.061 | 8.0x |

Everything the translate/emit/cache/publish machinery costs an eligible PIE
guest is at most **63.8% of its wall**. The tier census confirms every
sample's every exec (sh, python3, date ×2, `/bin/true` ×5) entered tier D
with zero refusals.

**What it does NOT bound:** the canonical (ET_EXEC) lane — rung 5; and the
8.0x residual, which is untouched by translation and is dispatch/VFS/exec
lowering. **Scope caveat:** the fixture deliberately avoids `hashlib` —
tier D's window scan refuses libcrypto's text (undecodable word
`0x38764d52`), and a tier-D leave at `mmap(PROT_EXEC, fd)` has no mid-run
fallback. OpenSSL-shaped text is a real tier-D coverage gap this ceiling
does not cover.

## Rung 2 — bias ceiling (correct path vs correct path)

Both arms tier T, both `CARRICK_DSR_SUPERBLOCK=off`, each arm a fresh
`CARRICK_DSR_STORE_DIR` (warmed by its warmup sample).

| arm | workload ms (median, n=5) | spread | CPU s |
|---|---|---|---|
| direct (`selects_direct_layout` default) | 4,593.3 | 4,563–4,693 | 4.983 |
| biased (`CARRICK_NATIVE_FORCE_BIASED=1`) | 5,317.5 | 5,295–5,351 | 5.717 |

The biased aperture's whole per-access family (rebias ORRs, aperture gate,
alias windows, host-alias transactions as exercised here) costs at most
**13.6% of the biased wall** on this workload.

**What it does NOT bound:** (a) the canonical build lane's bias family —
this fixture is compute-heavy with ~9 execs and 5 forks, so the
fork/exec-driven scrub, alias-window and `HostAliasTransactions` costs that
the build lane exercises are barely weighted here; treat 13.6% as the
**per-access** term, not the whole family on the build; (b) the shipped
default's superblock interaction — superblocks had to be OFF because
superblock windows pull glibc's never-executed MTE strlen variants into
biased emission and the biased emitter refuses `LDG`
("memory family unsupported in biased mode", observed live). Rung 1's
tier-t arm (direct + default superblocks, same fixture/binary) prices the
superblock term separately: 4,097.9 ms on vs 4,593.3 ms off (−10.8%).

Two defects found in passing, flagged, not fixed here: the biased-emitter
LDG refusal above, and a persistent-store poisoning — consuming a store
populated under superblock-ON from a superblock-OFF run dies with "DSR
cache policy error: shared block … lost sensitive metadata identity"
(spawned as its own task).

## Rung 3 — zeroing ceiling (true ablation)

`CARRICK_ABLATE_ZEROING=1` makes `zero_backing` / `zero_anonymous_reuse`
claim success without doing anything (same binary as its control).

- **PIE fixture (n=5/arm, interleaved):** control 4,107.1 ms / 4.532 CPU-s;
  ablated 4,089.4 ms / 4.507 CPU-s → **−0.43% wall, −0.55% CPU — inside
  noise** (distributions overlap). The guest, remarkably, still produced
  correct output — CPython did not observe the stolen guarantee on this
  workload.
- **Cold go build (n=2):** ablated **crashes 2/2** during Go runtime
  startup (`gcBgMarkStartWorkers` fatal; buildID probe exits 133) after
  ~5.3 s wall / 13.6 CPU-s; control 8,208 ms / 19.88 CPU-s. The canonical
  residual is therefore **not measurable by this instrument** (spec §6
  condition 1) — the standing bound is the remap's own controlled result:
  the win already landed as −0.660 CPU-s [−0.750, −0.570]
  ([`2026-08-07-anon-reuse-remap.md`](2026-08-07-anon-reuse-remap.md)),
  and what zeroing work remains after it is bounded small.

**Verdict: the zeroing line is closed.** A genuinely useful negative — no
further zeroing engineering can recover more than noise on measurable
workloads.

## Rung 4 — exec-chain ceiling (true ablation)

`CARRICK_ABLATE_EXEC_CHAIN=1` routes a forked child's execve down the root
process's in-process replacement path instead of the capsule
build/serialize/host-self-reexec chain.

- **20-exec micro (n=5/arm, interleaved):** control window 341.8 ms;
  ablated window 198.5 ms → **−143.2 ms / 20 = 7.2 ms per exec** (−41.9%
  of the window). Consistent with the ~8.5 ms fixed-chain decomposition
  ([`2026-08-03-native-exec-fixed-cost-decomposition.md`](2026-08-03-native-exec-fixed-cost-decomposition.md)),
  minus what in-process replacement itself costs.
- **Honesty note:** the ablated arm's **total** process wall (1,652 vs
  1,177 ms) and CPU (1.385 vs 0.918 s) are WORSE than control — the
  in-process path spends more outside the workload window (unattributed;
  plausibly teardown/publication across 21 in-process incarnations). The
  7.2 ms/exec is an in-window ceiling only; a sound implementation must
  also not pay this offsetting cost.
- **Cold go build (n=2):** ablated **crashes 2/2** at the first
  `go tool compile` (fatal signal 5 at a host-library PC, ~1.4 s wall) —
  exactly the unvalidated-inherited-state breakage the knob's comment
  predicts. Weighting the micro's per-exec figure arithmetically:
  ~61 execs × 7.2 ms ≈ **437 ms ≈ 5.4% of the 8,144 ms build** —
  arithmetic, not measurement (ceilings compose loosely).

**What it does NOT bound:** post-exec retranslation/cache effects shared by
both paths, and the observed extra out-of-window cost of the in-process
route.

## Rung 5 — the ET_EXEC question (costed design answer: NO)

Can the canonical lane (Go's ET_EXEC toolchain, text at low VAs) ever take
rungs 1–2's direct/tier-D path on Darwin/arm64?

1. **The address floor is settled kernel policy, not a probe gap.** The
   2026-08-02 probes ([direct-execution tier design §probes](../superpowers/specs/2026-08-02-direct-execution-tier-design.md)):
   a main binary linked `-pagezero_size 0x4000` is **SIGKILLed at exec**;
   `mach_vm_deallocate` of a pagezero slice returns `KERN_SUCCESS` but the
   range stays unmappable (mmap → `MAP_FAILED`, remap →
   `KERN_INVALID_ADDRESS`). There is no supported arm64 process shape with
   mappable low VAs.
2. **Relocating the binary instead is unsound.** ET_EXEC images carry no
   relocation records. AArch64 *text* is PC-relative (ADRP/ADD) and could
   run rebased, but *data* holds absolute link-time pointers — for Go,
   `moduledata` (text/etext, functab anchors) — and identifying every
   absolute pointer without records is undecidable in general.
   Version-specific `moduledata` patching would be a fragile, Go-only,
   clean-room-hostile heuristic; rebuilding or PIE-ifying guest binaries
   violates the unmodified-binaries premise.
3. **Translation-assisted rebasing already exists — it is the biased
   tier T**, the exact thing rung 2 priced at ~14% per-access. The
   remaining lowering trick, the ORR-compact bias, was measured 3.76%
   worse (H008).
4. **Sizing against rungs 1–2:** even a full unlock would land the
   canonical lane near the PIE lane's tier-D residual — **8.0x Docker** on
   this fixture — because the post-translation residual is dispatch/VFS/
   exec lowering. It is not a route to the 2x bar by itself.

**Verdict: NO.** The translation lever stays PIE-lane-only; canonical-lane
work should go to the per-op amplification program, and PIE-lane work to
tier D coverage and the shared residual.
