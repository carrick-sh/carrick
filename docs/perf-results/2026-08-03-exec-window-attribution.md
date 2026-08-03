# The ~105 ms exec window attributed: it was retranslation and mmap compute, not teardown or blocking

**Date:** 2026-08-03. **Tree:** `ed1bb372` (lifecycle stamps landed this
session), signed release binary, native backend. **Fixture:** the composed-lanes
scoreboard's 20-exec `compile -V` micro on
`localhost:5005/carrick-go-conformance:1.24`, in-guest wall bracketed. **Box:**
quiet — verified by `ps` before each batch; a stale root dtrace consumer and a
runaway `spotlightknowledged.updater` (a full core busy since Fri) were found
and stopped first. A control re-run showed the updater did NOT gate this
fixture (2.07-2.18 s with it running vs 2.09-2.18 s without), so the prior
session's numbers are not invalidated by it.

**Instruments** (untraced first, tracers declared): the `CARRICK_EXEC_STAMPS`
gauge, extended this session to the full fork/exit/reap lifecycle
(`diagnostics(runtime)` `ed1bb372`); `CARRICK_DSR_PROFILE` NATIVEPERF thread
frames + supervisor rusage record; two new durable D scripts
(`scripts/dtrace/exec-window-syscall-latency.d`,
`scripts/dtrace/guest-mmap-shape.d`) run via `carrick trace` — both PERTURB
(DOF re-registration per self-reexec while a consumer is attached), so traced
numbers are used for **ranking and shape only**, never totals; one
`profile-997` + `ustack` pass on the supervisor pid.

Raw evidence: `target/perf-attr-20260803/` (stamps, NATIVEPERF stderr, trace
aggregations, supervisor profile, chronological walls in `abba-walls.txt`).

## 1. The per-exec wall now sums — the "~45 ms unattributed" is gone

Lifecycle stamps, steady-state medians of 3×19 iterations (runs life10-12;
ranges across runs). Serial segments; the sum matches the measured full
iteration within <1.5%:

| # | segment (stamp pair) | ms |
|---|---|---|
| 1 | fork: parent `clone-enter` → child `fork-child-start` | 1.50-1.56 |
| 2 | child post-fork repair + pre-exec guest → `execve-dispatch` | 0.88-0.93 |
| 3 | resolve + load target ELF (25 MB `compile` from VFS) | 5.62-5.87 |
| 4 | capsule snapshot write | 0.43-0.44 |
| 5 | kernel execve + dyld + static init | 5.20-5.60 |
| 6 | carrick resume → `runtime-ready` | 2.78-2.99 |
| 7 | **guest window** `runtime-ready` → `exit-begin` | **86.2-86.8** |
| 8 | carrick teardown (runtime unwind) → `pre-host-exit` | 0.31-0.32 |
| 9 | host `_exit` + kernel teardown + parent wake → `wait-reaped` | 2.65-2.80 |
| 10 | sh loop to next `clone-enter` | 0.34-0.38 |
| | **full iteration** (`clone-enter` → next `clone-enter`) | **106.2-107.5** |

Run-level closure: 20 × ~106.5 ms + the two `date` bracket iterations ≈ the
measured `WORKLOAD_NS` 2.15-2.22 s. Iterations are flat (p10-p90 within ~2 ms).

**The three teardown/fork suspects are all SMALL.** Dying-image teardown at
this 25 MB image size is 0.32 ms (carrick unwind) + 2.7 ms (host `_exit` +
kernel address-space teardown + parent wake); the parent's fork is 1.5 ms; the
wait/reap path and shell loop add ~0.7 ms. Everything the scoreboard could not
see lives inside the guest window.

## 2. Inside the 86.5 ms guest window: retranslation and syscall-dispatch CPU

Untraced NATIVEPERF, per steady compile process. The scoreboard's starting
numbers were misread from these frames and are **corrected** here:

| claim (scoreboard) | measured (this session) |
|---|---|
| guest threads' own CPU ~10 ms | **~97 ms** per process (sum of threads, exec epoch 1) |
| translation only 2.8 ms (36+113 blocks) | **61-63 ms** (main thread 48.6-49.2 over ~7,960 blocks; siblings the rest) |
| 30.5 ms blocked across 15 syscalls | a **sibling** Go runtime thread parked in overlap; main-thread blocked is 2.7-3.8 ms. Sibling parks (20-40 ms × 4-5 threads) are concurrent with main-thread work — not additive wall |
| ~45 ms unattributed | eliminated (§1) |

Main-thread (tid == pid, epoch 1) phase medians: translate **48.6-49.2 ms**
(~7,960 blocks, ~6.2 µs/block — the whole Go runtime startup path is
re-translated **every exec**), syscall dispatch **20.8 ms** over ~280 calls,
translated guest code **2.58 ms**, prepare+finish ~3-4 ms, blocked 2.7-3.8 ms.
Phase sum ≈ 78-80 ms; the residue to the 86.5 ms window is ~6-8 ms of
unbracketed loop segments plus preemption by the 5 sibling threads (11-15 ms
CPU between them). Named honestly as residue.

Cross-check: supervisor `children_cpu_ns` 2.14-2.31 s/run ≈ 20 × (97 ms guest
CPU + ~14 ms exec chain) + sh 62-70 ms — the additive CPU model closes.

## 3. The syscall term is mmap COMPUTE, not futex/timer blocking

Traced ranking (`exec-window-syscall-latency.d`, whole 20-exec tree; ranking
only): **mmap 392 ms wall / 390 ms CPU over 1,789 calls (~85% of all
guest-syscall time; wall ≈ CPU ⇒ compute, not blocking)**; openat 23 ms and
munmap 23 ms next; **futex totals 1.6 ms wall for the entire run** — the
suspected futex/nanosleep/kqueue-park lowering class is a non-issue on this
fixture.

Shape (`guest-mmap-shape.d`, per exec ≈ traced total/20, consistent with the
untraced 21 ms dispatch phase):

| mmap class | calls/exec | bytes/exec | ~ms/exec |
|---|---|---|---|
| `PROT_NONE` `MAP_PRIVATE\|MAP_ANONYMOUS`, 16-256 MiB (Go 64 MiB arena reserves) | 66 | ~4.5 GiB | 9.4 |
| `PROT_NONE` anon ≥ 256 MiB (~512 MiB summary/bitmap reserves) | 2 | ~1 GiB | 7.8 |
| RW anon ≥ 16 MiB (heap commit) | 1 | ~33 MiB | 1.6 |
| everything else | ~20 | small | ~1 |

Cost is size-proportional (~2-7 µs/MiB) on **address-space reservations that
touch no memory**. Go's own Darwin port (`sysReserve` in `mem_darwin.go`)
lowers this intent to a bare `mmap(PROT_NONE)` — effectively free. This is the
"translate the intent, not the mechanism" case in AGENTS.md, verbatim.

## 4. Shared translation: the scoreboard's "no effect" is CONTRADICTED

Single-variable `CARRICK_DSR_SHARED_TRANSLATION=1` on the same micro, same
instruments both arms:

- **Mechanism:** per-exec translate drops **63 → 24 ms** (5,200 vs 7,960
  blocks still privately translated — partial coverage); steady iteration
  **106 → 81 ms**.
- **Costs it adds:** `execve-dispatch → capsule-prepare` 5.6 → 12.1 ms
  (old-image publication) and `image-mapped → runtime-ready` 0.12 → 5.93 ms
  (unit copy-in): **+12 ms/exec of chain**, plus a one-time first-exec priming
  iteration of ~285 ms (vs ~113 cold).
- **Wall:** interleaved on/off/on/off pairs: 1.86/2.01 and 1.94/2.04 s — ON
  wins both pairs. Net run-level gain ~90-160 ms (~5-8 ms/exec averaged over
  the run; steady-state iterations gain ~25 ms/exec, priming eats the rest).

The prior experiment (scoreboard exp. 3, "SHARED ~2194 vs OFF ~2185, no
effect") is not reproducible against this evidence; the default-OFF decision
rests on it and should be revisited. Suggested cause not established here —
this session only establishes that the mechanism DOES engage and DOES pay.

## 5. The supervisor's 342 ms/run: it is the rootfs clonefile seed

- Floor (`/bin/sh -c true`): `self_cpu_ns` **314-404 ms** vs micro runs
  **304-498 ms** — statistically the same ⇒ per-exec supervision is noise;
  it is all container lifecycle.
- `profile-997` + `ustack` on the supervisor pid (declared: consumer
  attached): **278 of 290 samples inside `clonefileat` under
  `HostFsBackend::extract_layers`** — the per-run COW rootfs seed of the
  go-conformance image tree. Everything else (dispatcher init, image plan,
  regex init) is single samples.
- Floor `children_cpu_ns` is 14.6 ms — container pid-1 setup is cheap; the
  micro's 2.2 s children CPU is the guest tree itself (§2 cross-check).

## 6. Ranked levers

Per-exec numbers are steady-state on this micro; build-level extrapolations
are hypotheses ("suggests") until the paired cold-build A/B is run.

| rank | lever | size | evidence |
|---|---|---|---|
| 1 | **Kill per-exec retranslation** (share/persist translations across execs of the same image; make the publish/attach transport cheap) | 49 ms/exec main-thread (61-63 all-thread); shared-translation ON already banks ~25 ms/exec steady at +12 ms chain + priming — ceiling ≈ 45 ms/exec | NATIVEPERF translate phase; lifecycle stamps; §4 A/B |
| 2 | **Lower guest `PROT_NONE` anon reservations to O(1)** (Darwin `mmap(PROT_NONE)` intent, not per-page bookkeeping) | ~17 ms/exec CPU | `guest-mmap-shape.d` + untraced 21 ms dispatch phase |
| 3 | **Stop re-loading the 25 MB target ELF per exec** (prepared-artifact reuse keyed by image within the container) | 5.6-5.9 ms/exec | stamps segment 3 |
| 4 | Kernel execve+dyld floor | 5.2-5.6 ms/exec, only ~1.7 recoverable (heroics; see 2026-08-03 exec decomposition) | stamps segment 5 |
| 5 | Resume-to-runtime-ready | 2.8-3.0 ms/exec | stamps segment 6 |
| 6 | Exit + reap + fork + shell loop edges | ~5.9 ms/exec combined — leave alone | stamps segments 1,2,8,9,10 |
| 7 | **Rootfs seed clonefile churn** | ~350 ms/run (≈3.4% of the 10.4 s cold build; fixed per run) | supervisor rusage + profile-997 |
| — | futex/timer lowering | **not a lever here** (1.6 ms/run total) | `exec-window-syscall-latency.d` |

Reference point: Docker runs the whole 20-exec workload in 21 ms (~1 ms/exec,
scoreboard). Even a perfect exec chain leaves the guest window as the entire
gap; levers 1+2 together attack ~66 ms of the 106 ms iteration.

## 7. Reproduction

- Micro: `CARRICK_EXEC_STAMPS=/tmp/st.txt CARRICK_DSR_PROFILE=1 target/release/carrick run --exec-backend native -e CARRICK_RUN_ID=<id> -w /tmp localhost:5005/carrick-go-conformance:1.24 /bin/sh -c 'w0=$(date +%s%N); i=0; while [ $i -lt 20 ]; do /usr/local/go/pkg/tool/linux_arm64/compile -V >/dev/null; i=$((i+1)); done; w1=$(date +%s%N); echo WORKLOAD_NS=$((w1-w0))'`
- Traced ranking: `carrick trace --script scripts/dtrace/exec-window-syscall-latency.d --trace-out <f> -- run …` (and `guest-mmap-shape.d`).
- Supervisor: same run under `dtrace -n 'profile-997 /pid == $target/ { @[ustack(40)] = count(); }' -c …` with `/bin/sh -c true`.
