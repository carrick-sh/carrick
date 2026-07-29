# Native-lane performance handoff

**Date:** 2026-07-28 (evening session)
**Branch:** `codex/native-aarch64-container-cache` (local, unpushed; merge-base
with `main` is `72b5a419`)
**Scope:** Darwin/aarch64 native DSR (`--exec-backend native`, the shipped
default). No VMM/HVF/KVM/bhyve behaviour was touched.

> Supersedes the FreeBSD native x86 bring-up handoff (`1b55b4b0`, branch
> `perf/native-xstate-transfer`). That work is unrelated and still open; its
> live caveat stands: **`neutral-domains` remains opt-in — do not make it the
> production default until Tasks 43, 55 and 58 close.**

---

## Current state

Goal in flight: **get carrick's overhead on real guest workloads toward 2x.**

**The metric changed on 2026-07-28 by user direction** (campaign Decision 13):
engine container setup and teardown are no longer measured. The primary metric
is the guest **workload window** — `scripts/perf/native_go_build.py` v3
brackets exactly the compile-and-execute steps with in-guest clock reads,
symmetrically for Carrick and Docker, and reports `workload_median_ms` plus
`carrick_over_docker_workload`. Full process wall stays as a secondary
diagnostic. Decision 14 records that this host will not reach a fully quiet
state: testing proceeds in ambient desktop noise, and paired alternating
candidate/control screens are the decision instrument, not absolute medians.

**Frozen official baseline at the branch tip**
(`scripts/perf/evidence/native-go-build-workload-w0-v1.json`):

| series | value | samples |
|---|---|---|
| `W0` (Carrick workload median) | **18,321 ms** | 18,321/18,457/18,140/18,286/18,622 |
| `DW0` (Docker workload median) | **842 ms** | 946/832/842/839/901 |
| `RW0` | **21.7589x** | — |
| full-wall medians (secondary) | 20,260 / 1,021 ms (19.84x) | — |

Excluded engine lifecycle per run: ~1.9 s Carrick (rootfs seeding, orphan
sweep, scratch teardown), ~0.18 s Docker.

**Both validation gates are closed at the tip:** `just ci` is green (36
suites, 2,663 tests) after clearing five workspace clippy findings, and
`just conformance-native smoke --workers 4` is 23/23 MATCH, "no regressions"
(go-sync 52/52, cpython-threading 193/193, cpython-subprocess 278/278).

## The headline: H008 — inserted code owns most of the CPU

The session built a safe instruction-shape census and it re-ranked everything.
Chain of evidence (all on one cold go-build at the tip, evidence rows in
`docs/perf-results/native-dsr-shape-census.jsonl`):

1. **Region split** (34,439 sampled user-mode PCs across the guest process
   tree): 68.9% in JIT/guest-range code, 16.8% host carrick text, 14.7%
   shared-cache dylibs.
2. **Shape split** (18,396 JIT samples matched against per-process code
   snapshots): **DSR-inserted words are 81.3% of residency** — context-slot
   stores `str xN,[x28,#slot]` 43.2%, context-slot loads 20.4%,
   x17 materialization 13.9%, aperture window checks ~3%, and the
   generation guard just **0.1%** (a trusted-entry chaining optimization
   would have been pointless — the census killed it before it was built).
3. **Disassembly of the hottest block** (Go's memclr-style loop): the 3-word
   guest body `stp xzr,xzr,[x17],#16; cmp; b.le` executes as **~22 emitted
   words per iteration** — guest x16/x17 slot reloads (slots 1120/1128), an
   NZCV round-trip via slot 936, `lsr #41`+`cbz` window check, host-bias
   load from slot 1192 plus `add`, the tagged slow path, and an un-bias
   `sub`+`mov` to recover the post-index writeback base.

Net: **inserted overhead ≈ 56% of all user-mode CPU** (0.813 × 0.689). This
is the largest single lever found all campaign and is consistent with
published same-ISA DBT overhead (<7.5%, MAMBO) being achievable — the gap is
addressing/register-pressure lowering, not physics.

**H008 (SPIKING — compact lowering implemented in `406b7bfe`, with an open
correctness leak; see "Next work"): register-resident biased addressing.**
Stop round-tripping guest `x16`/`x17` values and the host bias through
context slots on every guest memory access. Candidate shapes, in increasing
ambition: per-block dead-register scratch selection (liveness over the
decoded block), block-resident bias, loop-aware self-link entries that keep
loop-carried state in registers across back edges. Mechanism gate: the
ctx-slot share of shape-census samples must drop materially; wall gate:
paired alternating screens vs the `W0` anchor. Danger zones: every new
emitted shape needs its recovery entries (fault + async-kick restore exact
guest state at every interruptible word) — the jitter/recovery oracles and
`bad64::decode` disassembly tests are the proof pattern.

**Before designing H008, read the emitter protocol end-to-end** — do not
infer it from disassembly alone: `emit_biased_memory`,
`rewritten_biased_virtual_word`, `biased_scratch_registers`,
`BIASED_SCRATCH_CONTEXT_OFFSETS`, and the recovery contract
(`BiasedMemoryRecovery`, `recover_rewrite_state`) in
`crates/carrick-dsr-aarch64/src/emit.rs`, plus how `x17` doubles as the
internal indirect-edge register (comment near `emit.rs:4071`).

## What landed this session (all committed on the branch)

| commit | what |
|---|---|
| `8a76d273` + follow-up | Cleared five workspace clippy findings (expect_used, too_many_arguments, load-bearing vec_box with documented pin invariant, useless_conversion ×2, manual_c_str_literals ×2); `just ci` green. |
| `830d99f8` | Runner v3: in-guest workload window, fail-closed `WORKLOAD_NS` parsing, workload medians and ratio (red-first, 20+12 tests). |
| `5aecc7fb` | Workload census no longer flags its own launcher shell (ancestor-chain exclusion, red-first). |
| `5ffb5cd0` | `W0`/`DW0`/`RW0` freeze + Decisions 13/14. |
| `919a7f77` | H007 rejected on ceiling after the post-wave open-caller census. |
| `de945e19` | Shape census: dtrace PC histogram + `ProcessTranslator::code_snapshot` + `CARRICK_DSR_CODE_SNAPSHOT_DIR` dump + offline classifier + the H008 evidence. |
| `a104aff1` | H008 selection prerequisites: aperture-disjoint ORR-encodable first bias candidate `0x200_0000_0000`, underflow-window reservation, `aperture_disjoint_orr_immediate()`; 17/17 layout tests. |
| `406b7bfe` | **The compact biased lowering** for immediate/base forms plus writeback — ~6 words replacing ~13-15. Red-first exact-sequence tests. **Carries the open host-address leak below.** |
| `d131ac92` | The three instruments that bound the leak, plus `CARRICK_DSR_COMPACT_BIASED=0\|nowriteback`. |

Campaign authority lives in
`docs/perf-results/native-wall-time-campaign.md` (hypothesis backlog H001-H008
with statuses, spike decision log, Decisions 1-14). The fs-amplification
story is closed: the contained-metadata wave held (`lookup_kind` 35,235 →
2,363; `read_link` 11,435 → 772) and the remaining walk families' ~242 ms
traced ceiling rejected H007 (`native-fs-amplification.jsonl`).

## Next work, ranked

1. **Fix the Phase A reserved-scratch fault — the mechanism is proven and
   worth ~12%.** Goal restated 2026-07-28: translated execution within 2x of
   the guest's own work (16.1 CPU-s today against 3.0 CPU-s real guest
   computation). Design:
   `docs/superpowers/specs/2026-07-28-native-codegen-2x-design.md`; plan:
   `docs/superpowers/plans/2026-07-28-native-codegen-phase-a.md`.

   Phase A reserves x19 (chosen by a sample-weighted guest-register census:
   zero hot-path weight, tied with x21-x25) so the biased-address lowering
   needs no per-access spill — the 33.5% category. It is implemented
   (`3a6ab083`, `fce32ea0`) behind `CARRICK_DSR_RESERVED_SCRATCH=1`,
   DEFAULT OFF, with 170 dsr + 162 runtime oracle tests green.

   **Measured, switch ON:** one clean cold go-build at **16,137 ms** against
   the frozen `W0` of 18,321 ms — **~12% faster**. That is the first real
   evidence the codegen direction pays.

   **Blocker:** it faults on roughly three of four runs with
   `unexpected fault address 0xffff00a0...`. The arithmetic is exact and is
   the lead: **fault address == guest address − 2^48**, and 2^48 is the
   invalid-host tag bit (2^47) applied TWICE and then subtracted. Observed
   values `0xffff00a04882f900`, `0xffff00a05207d2d0`, `0xffff00a0513d97f0`
   are all valid Go stack addresses minus 2^48. Look first at any path that
   can apply `orr #1<<47` twice to one address, or that un-biases a
   double-tagged value — the tagged slow path and the writeback commit are
   the two places the tag and a subtract meet.

   **Also fix before measuring again:** the reservation is currently
   UNCONDITIONAL — the `gateway_aarch64.S` register save/restore change and
   the x19 decode classification are not behind the switch. So the "off" arm
   is not the untouched baseline, and a paired screen through the switch
   measures only the lowering, not the phase. Interestingly the off arm is
   itself ~3-4% faster than `W0` (17,593 / 17,807 ms), most likely because
   the gateway now saves one fewer register per transition — worth
   confirming and keeping on its own merits.

2. **Re-run the shape census after any H008 spike** — the census is now one
   command pair (see Methods) and is the mechanism gate.
3. **Root-cause the dtrace copyin kill** (spawned as a separate task chip):
   probe-context `copyin` of the interrupted word killed the guest 2/2 times
   within ~1 s ("DSR could not read guest instruction at <wild address>"),
   zero copyin errors recorded, while copyin-free tracing and untraced runs
   are clean. A passive profiler read should never corrupt a guest; until
   root-caused the census script's header carries the hazard note and the
   copyin clause is removed.
4. **Kernel-leaf symbolization repair** (inherited): restore ≥95% symbolized
   kernel-leaf coverage before any future broad kernel capture; never rerun
   or recycle the preserved v1/v2 capture roots. The darwin-kernel 34.5%
   category is otherwise attributed only at syscall-family granularity.
5. **Standing prohibitions** (unchanged): do not resume H004 Variant 1, do
   not enlarge the 64 MiB DSR cache to rescue it, do not re-enable
   `CARRICK_DSR_SHARED_TRANSLATION` by default (correct but a measured 2x
   regression), and do not re-litigate the experiments in the tracker's
   "Experiments stopped" list without new evidence.

## Methods — the census pipeline (new this session)

```sh
# one traced go-build with snapshots (attribution run, never wall evidence)
RUN_ID=shape-$(date +%s)
CARRICK_RUN_ID=$RUN_ID CARRICK_DSR_CODE_SNAPSHOT_DIR=$PWD/target/perf/snaps \
  target/release/carrick run --exec-backend native -e CARRICK_RUN_ID=$RUN_ID \
  -w /tmp localhost:5005/carrick-go-conformance:1.24 /bin/sh -c '<go-build script>' &
sudo -n /usr/sbin/dtrace -Z -s scripts/dtrace/native-shape-census.d -p $! -o raw
python3 scripts/perf/shape_classify.py raw --snapshots target/perf/snaps
```

- `sudoers` allows `dtrace` NOPASSWD; use `-Z` (USDT probes register after
  attach); never attach with a script that may fail to compile — a
  grab-then-abort on a just-started native process correlated with a guest
  kill.
- Snapshots are ~800 MB per run under `target/perf/`; delete after analysis.
- Official wall numbers come only from `scripts/perf/native_go_build.py`
  (`--engine both --samples 5`), which preflights foreign workloads itself.

## Traps — read before measuring or debugging here

- **Never `copyin` from dtrace probe context against a native guest** (see
  above). PC histograms + retirement snapshots replace it.
- **Never time a hot path by bracketing its own probes** — sample instead.
- **Guest processes self-reexec with different ASLR slides**; symbolicate
  per-pid via the recorded image bases (`scripts/symbolicate.py`).
- **Load-coupling**: paired alternating screens decide; check
  `ps -eo pid,args | grep "while :"` and `uptime` before campaigns; the
  runner's preflight rejects foreign workloads/compilers itself.
- **Docker/registry**: `vt-ferry-registry` + `carrick-registry-5050` must be
  up; Docker Desktop died mid-session once — `open -a Docker`, wait for the
  socket, restart both registries.
- **Piping a gate through `tail` masks its exit code** — capture status
  explicitly; two clippy findings hid behind exactly that this session.
- **carrick‖docker never run concurrently** (two-phase gates).
- **Agents sharing a worktree destroy each other's edits**; this branch's
  worktree is `.worktrees/codex-native-aarch64-cache`. A stash
  (`wip joined native parser fixtures`, `trace_profile.rs` +445) belongs to
  the previous agent and was left untouched.
- **The agent shell's cwd can silently reset to the MAIN checkout**
  (`/Volumes/CaseSensitive/carrick`) between commands. Relative-path reads
  then hit main's files — same content only where the branch never diverged
  — and relative git/cargo commands hit the wrong tree entirely. Check
  `pwd` before any relative-path work; absolute paths into the worktree are
  immune (every Edit/Write this session used them and landed correctly).
- **Adversarially verify agent-written tests** — a tautological test burned
  this campaign before; red-first with a shown-red control is the standard.

## Open / unverified

- The final `just ci` including the shape-census commits is green (exit 0,
  36 suites, zero failures), matching the earlier green run at the clippy
  tip; native smoke was run at the clippy tip and the only Rust change since
  is `de945e19`'s exit-seam diagnostics dump, which is env-gated off.
- `W0` was frozen at ambient load ~2.2 (Decisions 13/14 record why that is
  acceptable); the excluded-lifecycle deltas (~1.9 s / ~0.18 s) replicated
  across the validation sample and the official campaign.
- The shape census leaves 5,307 JIT-range samples unmatched (22% — pre-exec
  phases and cache generations replaced before the exit snapshot). The
  matched split is decisive regardless; a pre-exec snapshot hook would close
  the gap if it ever matters.
- The async-interrupt oracle's PC-distribution assertion and the inert
  `BiasedExclusiveResume` variants remain open review items from the
  previous session; one probabilistic DSR landing-coverage failure was seen
  once at `564dd281` in a serialized suite and has not recurred in the
  gates run since.
