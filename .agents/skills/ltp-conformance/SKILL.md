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
  raw times/pids), and the harness (`crates/carrick-cli/tests/conformance.rs`,
  run via `just conformance-probes`) compares carrick vs Docker **line-exact**.
  They are the precise gate and the durable artifact. The LTP sweep tells you
  where to dig; the probe nails it down so it can never silently regress.

The broad differential sweep itself now lives in the unified
`carrick-conformance` harness (the `just conformance` recipes below), which spans
four ecosystems — `cpython·go·node·ltp` — not just LTP.

## Setup

carrick needs the HVF entitlement, so it must run as a **SIGNED** binary — a bare
`cargo build` strips the signature → HV_DENIED (0xfae94007). Always build through
`just`, which routes every build through `scripts/build-signed.sh`:

```sh
just build        # build + codesign the whole workspace (carrick AND the harness)
```

The differential harness pulls its Linux images from two local registries —
`:5050` (cpython + ltp) and `:5005` (go + node); NOT `:5000`, macOS
ControlCenter/AirPlay owns it. **You don't set them up by hand.** The durable,
self-healing driver does the whole dance — starts/creates both registries,
pushes any image the registry doesn't already serve, rebuilds the signed binary
+ harness, then runs:

```sh
scripts/conformance/run-full.sh              # full tier: registries + build + run
TIER=smoke scripts/conformance/run-full.sh   # fast gate
```

The harness sets `CARRICK_INSECURE_REGISTRIES` itself per-suite, so no manual
export is needed. Once the registries are up, the `just` recipes are the quick
day-to-day entry points:

| recipe | what it does |
| --- | --- |
| `just conformance` | full differential gate (cpython·go·node·ltp) vs the cached Docker oracle |
| `just conformance smoke` / `just conformance-quick` | fast pre-merge tier; non-zero exit on any regression |
| `just conformance-probes` | the line-exact ABI probe gate (`crates/carrick-cli/tests/conformance.rs`) |
| `just conformance full --ecosystem ltp` | restrict to one ecosystem (repeatable; also `--suite <name>`) |
| `just conformance full --bless` | record: rewrite `scripts/conformance/baseline.jsonl` + `docs/support-matrix.md` |
| `just matrix` | re-render `docs/support-matrix.md` from the latest results (runs nothing) |
| `just test` | host `--lib` unit tests (the regression check after a fix) |

A routine run executes ONLY carrick and diffs against the committed oracle cache
(`scripts/conformance/oracle-cache.jsonl`); Docker is re-run for a suite only
when its cache key is absent — or you pass `--refresh-oracle` after rebuilding an
image's contents. An image-freshness guard re-pulls carrick's copy of any image
whose registry digest moved, so carrick and Docker run identical bytes.

## Discover: run the differential sweep

The unified harness (`just conformance`, above) IS the differential sweep for the
suites in the manifest (`scripts/conformance/suites.toml`) — it runs each under
carrick and diffs against the Docker oracle. For ad-hoc LTP work OUTSIDE that
curated manifest — checking specific tests by name, or sweeping the full LTP
suite to find the gap denominator — use the bundled scripts (durable; the verdict
logic is the subtle part):

```sh
.agents/skills/ltp-conformance/scripts/ltp-check.sh pause01 futex_wake03 ...
.agents/skills/ltp-conformance/scripts/ltp-sweep.sh        # curated 4-area subset (~192)
.agents/skills/ltp-conformance/scripts/ltp-full-sweep.sh   # every LTP syscall binary (~1457)
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
- The harness `crates/carrick-cli/tests/conformance.rs` auto-discovers probe
  binaries and line-diffs them; run it with `just conformance-probes` — that's
  the permanent gate.

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
  `just test` (host `--lib` suite) for regressions. Only then is it done.

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
