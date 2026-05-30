---
name: ltp-conformance
description: >-
  Use when bringing up or verifying carrick's Linux syscall emulation against
  the Linux Test Project (LTP), comparing carrick with Docker Linux, triaging
  LTP failures, TIMEOUTs, TBROKs, TCONFs, false MATCHes, timing-jitter
  inversions, or reducing noisy LTP cases into deterministic conformance
  probes. Also use when choosing the next conformance gap, checking whether
  Linux behavior is emulated correctly, or proving a fix landed end-to-end.
---

# LTP conformance bring-up for carrick

carrick runs unmodified Linux aarch64 binaries on macOS via HVF, emulating the
Linux syscall ABI on Darwin primitives. To bring that up *correctly* — not just
"it compiles, the demo ran once" — you need an oracle that says what real Linux
does, and a way to collapse a noisy disagreement into a focused, reproducible
goal. This skill is that loop.

## The loop in one breath

1. **Discover** gaps broadly: run an LTP test under carrick AND under real Linux
   (Docker) and **diff the verdicts**. LTP is the oracle for "what should happen."
2. **Reduce** a confirmed gap to a tiny **deterministic conformance probe** —
   a static musl ELF run via `carrick run-elf`, its stdout compared line-for-line
   to the same probe on real Linux. This is the focusing move: it strips the LTP
   framework, the fork tree, and the timing noise down to the exact behavior, and
   it leaves a permanent regression guard behind.
3. **Root-cause** with `carrick trace` (see the `carrick-trace` skill), then
   **fix using the Darwin kernel as the source of truth** (libproc, `__ulock`,
   `thread_info`, `kqueue`/`EVFILT_USER`, host `MAP_SHARED`) rather than
   in-memory emulation. Re-run the probe AND the LTP test to confirm.

Never chase the verdict number. A green verdict you don't understand is a
liability; a red one you've root-caused is progress.

## Why two tiers (LTP sweep + own probes)

- **LTP** is broad and authoritative but noisy: ~1457 syscall binaries, a heavy
  test framework (`tst_test`/`tst_sig`), forks, `/proc` polling, timing
  thresholds, and a count-based pass/fail report. Great for *finding* gaps,
  treacherous as a precise gate (see "Reading results honestly").
- **Conformance probes** (`conformance-probes/src/bin/*.rs`) are small, you
  wrote them, they print **deterministic** lines (booleans/relationships, never
  raw times/pids), and the harness (`tests/conformance.rs`) compares carrick vs
  Docker **line-exact** in `cargo test`. They are the precise gate and the
  durable artifact. The LTP sweep tells you where to dig; the probe nails it
  down so it can never silently regress.

## Setup

```sh
# 1. Build SIGNED, always — `cargo build` strips the HVF entitlement → HV_DENIED
./scripts/build-signed.sh

# 2. Local registry on :5050 (NOT :5000 — macOS ControlCenter/AirPlay owns it)
docker start registry 2>/dev/null \
  || docker run -d --restart=always -p 5050:5000 --name registry registry:2
docker push localhost:5050/ltp:arm64        # built by docker/ltp/Dockerfile
export CARRICK_INSECURE_REGISTRIES=localhost:5050
```

## Discover: run the differential sweep

Use the bundled scripts (durable; the verdict logic is the subtle part):

```sh
.agents/skills/ltp-conformance/scripts/ltp-check.sh pause01 futex_wake03 ...
.agents/skills/ltp-conformance/scripts/ltp-sweep.sh   # the full curated 4-area sweep
```

Each test runs under Docker (the oracle) and under
`carrick run … --raw --fs host /bin/sh -c /opt/ltp/testcases/bin/<t>`, with a
`timeout` and a `scripts/sudo/kill.sh "$CARRICK_RUN_ID"` between runs — ALWAYS
SCOPED to this run's id (the bundled scripts export a unique `CARRICK_RUN_ID`;
`kill.sh` now REQUIRES a run-id and refuses the global reap, so concurrent
lanes/worktrees/agents never reap each other — an unscoped kill mid-run looks
like an unrelated flake). carrick guests rename argv0 to `carrick:<run-id>` so a
plain `pkill` misses wedged vCPUs; a hung guest holding the stdout pipe will
otherwise hang the whole sweep — capture carrick stdout to a FILE, never a pipe,
and scoped-force-kill guests before+after each run.

## Reading results honestly (this is where false wins hide)

The verdict is a tool, not the truth. Each of these has burned us:

- **Count-based "MATCH" ≠ same assertions.** `passed 5 failed 1` on both sides
  is recorded as MATCH even if a *different* assertion failed. For a Go-critical
  or canonical test, don't trust the count — diff the actual `TPASS`/`TFAIL`
  *lines*, or reduce to a probe (which is line-exact by construction).
- **Old-API tests print no `Summary:` block** — only per-line `TPASS`. A
  summary-only verdict false-MATCHes them as both-empty. The bundled verdict
  falls back to counting `TPASS/TFAIL/TBROK/TCONF`; never regress to summary-only.
- **Inversions ("carrick passes, Docker fails") are NOT automatically wins.**
  Docker's LinuxKit arm64 VM has real timing jitter, so threshold tests
  (`tst_timer_test.c`, "slept too long") fail there while carrick passes —
  carrick is genuinely more correct, exclude them. BUT the identical signature
  is produced by carrick **failing to enforce a check** Docker enforces — a
  *false pass* masquerading as superiority. **Verify each inversion individually**
  (read the failing Docker assertion; confirm it's timing, not under-enforcement)
  before excluding it. This is the single most dangerous trap.
- **`TBROK` is a hidden test, not a fail.** It means setup broke (missing
  `/proc/config.gz`, `tst_checkpoint`, `RLIMIT_CORE`, `/proc/<pid>/stat`…),
  hiding every real assertion behind it. The high-leverage move is to clear the
  **framework blocker** so the assertions actually run — that unblocks a whole
  class at once, not one test.
- **`TCONF` on both sides verifies nothing.** Both skipped → "agreement" but
  zero behavior exercised. Track it as "not exercised," not "passing."
- **`TIMEOUT` = a hang** (the worst class). Often a blocking syscall that never
  wakes (EINTR/signal/futex/poll), or a `/proc` poll waiting for a state that
  never appears. Treat as a real DIFF and root-cause.
- **Single-run verdicts on flaky tests mislead.** If a test is timing-sensitive
  (e.g. a clone-thread racing a 40s deadline), run it 3× before believing either
  a MATCH or a DIFF.

## Reduce: the focusing move

A raw LTP failure is a poor goal — it drags in the framework, a fork tree, root
vs non-root divergence (the `carrick trace` auto-sudo confounder), and timing.
**Reduce it to the smallest deterministic probe that reproduces the exact
behavior.** This is what converts "futex_wake03 fails somewhere in 11 cycles"
into "a forked child FUTEX_WAITs on a shared-anon word; the parent's FUTEX_WAKE
must wake exactly N" — a goal you can iterate on in <10s and assert precisely.

Recipe:
1. From the LTP source (often only the *binary* is in the image — fetch the `.c`
   from LTP upstream if needed) or a `carrick trace`, identify the **one**
   syscall interaction that diverges and its inputs.
2. Write a probe (next section) that performs just that, printing deterministic
   booleans/relationships.
3. Run it under carrick (`run-elf`) and Docker; diff. Iterate the fix against the
   probe (fast, no framework noise), then re-confirm against the real LTP test.

The probe is also the **durable goal record**: it stays in the suite and fails
loudly if the behavior ever regresses. Existing examples to imitate: `itimer.rs`
(interval-timer delivery incl. forked child), `futexshare.rs` (cross-process
futex on shared mmap), `procstat.rs` (a paused child's `/proc/<pid>/stat` state).

## Write a conformance probe

`conformance-probes/src/bin/<name>.rs`, then `./scripts/build-probes.sh`
(static aarch64-musl in a Docker rust:alpine). Rules that make it a good gate:

- **Deterministic output only.** Print booleans, counts that are invariant, and
  relationships (`a <= b`) — NEVER raw times, pids, durations, or addresses.
  The harness compares byte-for-byte across two machines; any nondeterminism is
  a false DIFF.
- **Bound every wait.** A broken delivery path should make the probe print
  `false`, not hang the harness — spin/wait against a deadline, then give up.
- **Use libc raw where the libc wrapper hides the syscall** (e.g. `libc::syscall`
  for `futex`); the point is to exercise carrick's syscall, not glibc/musl.
- **Run it:** `carrick run-elf --fs host <probe>` (the JSON envelope's `stdout`
  field is the guest output) vs `docker run --platform linux/arm64 -v …:ro
  alpine /<probe>`. Gotchas: `run-elf`'s rootfs is EMPTY — `mkdir("/tmp")` before
  opening a file there; and a shared-FILE/`__ulock` futex only engages under
  `--fs host` (real host file → host `MAP_SHARED`), not `--fs memory`.
- The harness `tests/conformance.rs` auto-discovers probe binaries and
  line-diffs them in `cargo test --release` — that's the permanent gate.

## Fix it right

- Root-cause with the **`carrick-trace`** skill, not `eprintln`. Note its
  confounder: `carrick trace` auto-sudos → runs the guest as **root**, which can
  diverge from the bare non-root run for signal/fs tests. A `run-elf` probe runs
  as you and sidesteps this — prefer it for those.
- Fix by deferring to the **Darwin kernel as source of truth** where one exists,
  instead of in-memory emulation: e.g. per-thread state via
  `thread_info(THREAD_BASIC_INFO)`, cross-process futex via `__ulock`
  (`UL_COMPARE_AND_WAIT_SHARED`), process identity via libproc `proc_pidinfo`,
  cross-thread wakeups via `kqueue` `EVFILT_USER`, fork-coherent shared memory
  via host `MAP_SHARED`. It's less state to manage, and it's more faithful.
- After fixing: re-run the probe (must MATCH) AND the originating LTP test, plus
  `cargo test --release --lib` for regressions. Only then is it done.

## Honest scoping

"Complete coverage of area X" means the curated test list for X, not all 1457
LTP binaries. State the scope. Periodically run a broader/full syscall sweep to
surface blind spots in the areas you haven't curated. Distinguish, in any
report, "verified (assertions ran and matched)" from "skipped both sides
(TCONF)" and "excluded (Docker-VM jitter, individually confirmed)".

## Pointers

- Memory: `project_ltp_go_coverage.md` (this campaign + the Darwin-as-truth
  research backlog), `project_ltp_conformance.md` (harness origins).
- `docs/ltp_baseline_4areas.log` — last full baseline.
- `docs/superpowers/specs/2026-05-23-procfs-pid-introspection-design.md` — a
  worked example of the spec→probe→fix flow.
- `handoff.md` (repo root) — current state, open gaps, next steps.
