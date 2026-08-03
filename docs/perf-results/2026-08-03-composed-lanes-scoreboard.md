# Composed-lanes scoreboard: the exec lanes landed, the ratio did not move

**Date:** 2026-08-03. **Tree:** `88345b9f` (tier D exit path + dynamic
linking, file-backed exec image mapping, metadata-only artifact digest,
MAP_JIT shared-unit transport — all default-ON except shared translation),
full `just ci` green. **Box:** quiet (verified zero build/guest processes),
signed release binary, all phases serial per the two-phase rule.

## Scoreboard (`scripts/perf/workload-spread.sh 3`, in-guest wall, medians)

| workload | carrick | docker | ratio |
|---|---|---|---|
| startup (2 `date` execs) | 42 ms | ~0 | — (~21 ms/exec) |
| compute (awk 8M) | 365 ms | 118 ms | **3.1x** |
| fs-walk | 257 ms | 14 ms | **18.4x** |
| build-cold (hello go build) | 10 382 ms | 800 ms | **13.0x** |
| build-warm | 10 240 ms | 803 ms | 12.8x |

build-warm ≈ build-cold on BOTH engines: each sample is a fresh container,
so the script's GOCACHE priming cannot survive into the measured run — this
row is a second cold sample, not a warm build. The roadmap section-0 warm
numbers came from a different (in-container consecutive) window.

Cold build vs the same script's pre-campaign figure: **~10.4 s → ~10.4 s.
Unchanged.** Compute improved (3.8x → 3.1x band).

## Controlled experiments (single-variable, counterbalanced ABBA, N=8)

1. **Exec-lane hatches on the cold build** (`CARRICK_EXEC_FILE_BACKED=0
   CARRICK_EXEC_FAST=0` vs defaults): ON ≈ OFF (10.1–10.5 s both arms,
   monotone thermal drift dominates the spread). **No effect.**
2. **Exec-lane hatches on the 20-exec `compile -V` micro**: ON ~2195 ms vs
   OFF ~2210 ms. **< 1 ms/exec.**
3. **`CARRICK_DSR_SHARED_TRANSLATION=1` on the same micro** (store primed;
   sharing also operates within-run): SHARED ~2194 ms vs OFF ~2185 ms.
   **No effect.** With the MAP_JIT copy transport the load cost argument is
   gone, and the answer is unchanged: translation is not the per-exec term.
   The default stays OFF on measured grounds, per the opt-out rule's
   measured-worse/no-benefit clause.

The mechanisms ARE engaged: `RUST_LOG` shows `executable_file_backed=true`
on all ~65 execs of the cold build (grep the log with `-a` AND remember the
ANSI codes sit between the key and the value).

## Where one `compile -V` exec (~105 ms, flat across 20 iterations) goes

`CARRICK_EXEC_STAMPS` (untraced) + `CARRICK_DSR_PROFILE`, single exec:

| segment | cost |
|---|---|
| execve-dispatch → capsule-prepare (old side, 25 MB image) | 10.0 ms |
| pre-exec → main-entry (kernel execve + dyld, 24 MB binary) | 6.8 ms |
| main-entry → runtime-ready (dispatcher + file-backed map) | 3.2 ms |
| **exec chain total** | **~20 ms** |
| guest threads' own CPU (incl. translation 2.8 ms, 36+113 blocks) | ~10 ms |
| one guest thread `phase_blocked_ns` across 15 syscalls | 30.5 ms |
| unattributed remainder of the ~105 ms window | ~45 ms |

Supervisor `self_cpu_ns` = **342 ms per run** (plus 135 ms children) — not
per-exec, but enormous against a Docker total of 21 ms for the whole
20-exec workload.

## Verdict

The exec lanes did exactly what they claimed at the mechanism level (image
bytes are no longer hashed or materialized; the chain is ~20 ms) and it did
not move either gate shape, because the per-exec money was never where the
Phase 3 sizing put it: **~80 ms of every exec is post-runtime-ready guest
window** — blocked syscall time, the unattributed ~45 ms, and supervisor-side
CPU. Phase 3's remaining worth should be re-ranked behind attributing and
attacking that term (and fs-walk's 18.4x). This is the roadmap's
"invalidate the plan" clause firing for the build shape: Phase 4-class
kernel/runtime work is promoted, not optional.

Raw logs: `target/perf-spread-composed-20260802.log`,
`target/perf-hatch-abba-20260802.log`, `target/perf-micro-abba-20260802.log`,
`target/perf-shared-abba-20260802.log`, stamps/profile in the session
transcript.
