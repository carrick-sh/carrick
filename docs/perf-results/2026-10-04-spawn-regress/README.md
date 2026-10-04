# Phase B spawn capacity work and inconclusive timing

The timing evidence is **inconclusive on this busy Mac**. Neither the original
approximately 8% spawn-loop regression nor a speedup from the fix is confirmed.
Across 12 complete ABBA rounds, the median paired wall-time delta was +13.53%,
with candidate slower in 8 rounds and faster in 4. The four rounds with zero
`rustc` processes at all measured starts disagree: median +1.25%, 2 slower and
2 faster. Other builds and host tests may overlap despite the guest gate.

The deterministic work removal stands independently: process-only startup
previously reserved four unused executable sibling cells. The VM-free budget
witness fails with `4 != 0` before the fix and passes afterwards. The first
actual host thread clone still reserves the four-cell sibling pool. Signed
correctness and candidate-plus-fix timing have not been verified.

## Artifacts and host

Host: macOS 27.2, build 26B5091g, Apple Silicon. No Docker containers or load
generators were started. The original signed artifacts were reused without
rebuilding or resigning; hashes were checked again after the measurements.

| Identity | Base | Phase B candidate |
| --- | --- | --- |
| Build source HEAD | `5e23be1a2a09eaa098149ae3997280a80b74b9a0` | `1e61be8e8cf8a0320e764e363031261c46059f40` |
| Build source tree | `56407acdfdb4aa479a27636c2583203a9125af6d` | `116a8b630eb3a4bb79d76dd60f56551b802d9685` |
| SHA-256 | `00eacdb4e063903ba99e7b1ca9198650693dacbba39f2fdc3a32aea337ea079b` | `61c6126f25baed039db04a8afd20f2e59498e59224beafe7013b1d05a4d6c9a4` |
| CDHash | `c9c247453fecdfefd6d65135b79a707845a63bc5` | `9fe8df0059bf729f61f3944904d2c75908d85d9f` |
| LC_UUID | `9D81A7FB-114F-3F68-84FF-4A78689ABDEC` | `134BBF6E-843C-3B9D-A5BD-9C161000C0E2` |
| Hypervisor entitlement / DOF | present / present | present / present |

Paths were `../impact-base/target/release/carrick` and
`../impact-pb/target/release/carrick`. Each artifact's
`__build-source-marker` reported the corresponding clean source tree. The
receipt's top-level `head` describes the driver's working tree, **not** the
artifact's build source. Its artifact identity is recorded separately.

The patched impact driver adds a one-minute load average and exact `rustc`
process census immediately before each launch, outside both the wall-time
and child-CPU windows. Its frozen executable SHA-256 was
`2fcf8777849bfaed29ff359090215d1e9783b71741eafa57b9d32380291487f9`.
The script was changed to use the frozen copy while the shell loop was already
running; `target/debug/carrick-xtask` and the frozen copy had identical bytes.

Workload: 1,000 `/bin/true` invocations from `/bin/sh -c`, `--fs host`, no trap
limit, default HVPatch backend. The harness's guest timing window surrounds the
shell loop, while `wall_s` also includes CLI startup and teardown. Every
completed receipt uses Ubuntu arm64 digest
`sha256:08571ca13e00ca07a2a84eab83a959b4242e22cceb16486a11bef1428c9e93a7`
and declaration hash
`274ba3647fcd504cda075ee32ffa88cc406304c4397ab459bca168b20f4c67dc`.

## Measurement design and interruption

The director replaced the initially requested separate 20-sample phases with
20 ABBA rounds because no build-free window could be promised. Each round has
four invocations: base, candidate, candidate, base. Each invocation calls
`impact carrick --workload spawn-loop --samples 1`, which runs one excluded
warmup and one measured guest. The whole sequence inherited one exclusive
`just lease gate` descriptor. [abba-command.txt](abba-command.txt) preserves
the command and runner script.

The gate serializes cooperating guests and acceptance runs. It cannot exclude
unleased builds, Clippy, rustdoc, or host tests. Observed load at all completed
warmup/measured starts ranged from 5.99 to 22.95, with up to 10 `rustc`
processes. A zero compiler census is a point-in-time observation, not proof of
a quiet guest interval. These measurements must not be described as a
controlled quiet-host confirmation.

The director asked to stop after the current complete round to release the
critical lease for N1 and queued signed work. The stop controller failed to
recognize the round-12 boundary. Round 12 completed, then round 13's base
invocation completed. The next invocation failed during registry manifest
resolution with HTTP 429, before any candidate guest launched. The shell and
lease holder exited; no measurement lease remains queued or held.

Only complete rounds enter paired analysis. Round 13 is excluded because it
has no pair, not because of a measured value. Its successful base receipt and
failed candidate receipt are retained in [incomplete.json](incomplete.json),
along with an earlier incomplete pilot interrupted by another gate. The
anonymous registry pull token in the failed diagnostic was redacted; the 429
and all other error information remain. Registry throttling is a harness
follow-up, not a guest conformance verdict.

[abba.json](abba.json) preserves all 48 complete invocation receipt objects,
including all 96 warmup/measured guest records. All 96 have unique run IDs,
zero exit status, no timeout, and successful scoped cleanup through
`scripts/sudo/kill.sh <run-id>`. Both arms have 24 measured samples. No
complete-round sample was discarded or retried.

An earlier unpaired base-only `--samples 20` invocation is retained as
[base-first.json](base-first.json). Its wall median was 1.55447 s, range
1.27163–3.95815 s. It used the previous driver without per-sample host load
and is exploratory evidence only.

## All paired rounds

For each metric, `A = (slot 1 + slot 4) / 2`,
`B = (slot 2 + slot 3) / 2`, and paired delta is `100 * (B / A - 1)`.
Wall columns are seconds; load and compiler lists follow ABBA slot order.
[analysis.json](analysis.json) contains the full-precision calculations.

| Round | Base wall | Candidate wall | Wall delta | Guest-window delta | Child-CPU delta | rustc | Load average 1m |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| 1 | 3.9514 | 1.9391 | -50.93% | -52.14% | -35.08% | 2,4,0,0 | 21.8,18.0,15.5,14.5 |
| 2 | 1.3547 | 3.1410 | +131.85% | +136.26% | +95.94% | 0,0,0,0 | 12.5,11.3,11.6,10.5 |
| 3 | 1.4951 | 1.6280 | +8.89% | +9.00% | +8.21% | 0,0,0,0 | 9.5,8.4,7.9,7.2 |
| 4 | 1.5636 | 6.1700 | +294.61% | +304.50% | +120.54% | 0,0,9,0 | 6.7,6.3,8.5,12.0 |
| 5 | 2.5127 | 5.4242 | +115.87% | +119.24% | +66.39% | 1,10,1,1 | 10.6,12.4,13.5,11.7 |
| 6 | 3.7149 | 4.3897 | +18.17% | +18.70% | +39.85% | 1,1,2,1 | 12.5,13.3,13.8,15.6 |
| 7 | 3.6008 | 2.0215 | -43.86% | -44.43% | -25.73% | 0,0,0,0 | 14.3,13.7,12.8,10.9 |
| 8 | 1.8855 | 1.7653 | -6.38% | -6.28% | -6.23% | 0,0,0,0 | 10.4,9.1,8.3,7.8 |
| 9 | 1.8764 | 2.2960 | +22.36% | +22.03% | +21.63% | 0,2,0,0 | 7.3,12.8,11.4,10.1 |
| 10 | 2.7855 | 2.7136 | -2.58% | -3.89% | -5.94% | 1,0,4,1 | 14.6,13.0,12.0,13.6 |
| 11 | 3.4107 | 3.4430 | +0.95% | +1.06% | -18.35% | 2,1,7,3 | 12.8,11.0,12.6,11.5 |
| 12 | 1.4373 | 1.7183 | +19.55% | +19.35% | +17.19% | 1,2,0,0 | 10.4,9.5,8.4,8.0 |

| Population / metric | Median paired delta | Minimum | Maximum | Slower / faster |
| --- | ---: | ---: | ---: | ---: |
| All 12, wall | +13.53% | -50.93% | +294.61% | 8 / 4 |
| All 12, guest window | +13.85% | -52.14% | +304.50% | 8 / 4 |
| All 12, child CPU | +12.70% | -35.08% | +120.54% | 7 / 5 |
| Measured-start zero-rustc rounds 2,3,7,8, wall | +1.25% | -43.86% | +131.85% | 2 / 2 |
| Same four, guest window | +1.36% | -44.43% | +136.26% | 2 / 2 |
| Same four, child CPU | +0.99% | -25.73% | +95.94% | 2 / 2 |

Requiring zero `rustc` at warmup starts as well leaves rounds 2, 3, and 7:
wall median +8.89%, range -43.86% to +131.85%, 2 slower / 1 faster. That
subset also disagrees. No subset proves the original timing claim.

Across the 24 measured values per arm, wall medians were 1.76406 s base and
2.08518 s candidate, ranges 1.27229–6.63047 s and 1.38362–10.77880 s. These
unpaired distributions suggest increased cost but are not attribution or a
controlled performance result. Candidate-plus-fix was never measured.

## Structural attribution and change

Phase B introduced `Kernel::prepare_executable_thread_births` and installed an
executable adoption factory during logical job preparation. It calls
`ThreadLedger::replenish` even when the process has only its initial thread.
The pool's depth is four. Each entry calls the runtime factory to reserve an
executable sibling cell although a fork/exec-only process never uses it.
Activation also calls preparation; those repeated calls are covered by the
witness and do not double the pool depth.

The new `process-spawn-birth-capacity` contract counts the factory's actual
reservation calls through the public kernel API in `carrick-kernel-example`.
It checks 1, 8, and 32 singleton process startups with preparation called twice
per process. [budget-red.txt](budget-red.txt) records the unchanged regressed
code failing at scale 1: four calls against a zero budget. The fixed witness
passes all scales ([budget-green.txt](budget-green.txt)). A separate positive
test performs an actual host thread-clone publication and checks that four
executable sibling reservations and four standing identities still appear;
rebinding does not reserve more.

The fix returns before replenishment when the exact process lifecycle reports
one live thread. It retains post-exec reopening before this check, so exec
custody is still released through the existing authority. The first real host
clone already publishes the second thread and replenishes the sibling pool
before returning. Admission routing, credential updates, and setid handling
are untouched. Existing host/kernel tests pass; this does not establish signed
EL1 or setid correctness.

This attributes **four unused runtime reservations per fresh singleton
binding**, not the original wall-time difference. There is no live base versus
candidate gate, redispatch, host-entry, or wake census yet. The original base
artifact rejected `trace` before guest launch, and scoped cleanup found zero
survivors. A durable script, `scripts/dtrace/hvpatch-spawn-work.d`, is prepared
but not live-qualified. Its header explicitly distinguishes topology-lock
events from CloneAdmissionGate operations, for which the original artifacts
have no direct USDT binding. A current CLI supports `trace -- --external`
and can trace the frozen artifacts later without replacing them. Zero events
from the failed attempt are not evidence of zero work.

## Verification and continuation

Passed: the budget witness red then green; all 15 impact-driver tests;
`just test-kernel`; `just test`; Clippy and `lint-domains` through the ordered
`just ci` run. The macOS authority census passed its local profiles, with
other host profiles explicitly pending. Source capture was refreshed on the
clean runtime-fix commit without moving any inventory rows.

`just ci` stopped at pre-existing rustdoc failures in `carrick-mmu-core`:
literal `[5:0]`, `AP[1]`, and links to a test-only function. A temporary
documentation repair exposed additional pre-existing `carrick-signal-core`
bare URLs. The director requested no duplicate repair because CI PR #3 covers
both. The temporary repair is reverted, leaving no net documentation change
in either crate. CI's later test/integration recipes did not run; `just test`
was run separately and passed.

Pending: rebase after PR #3; full `just ci`; signed
`just test-embed el1_ --nocapture`; `just accept` host and signed with its
receipt; live USDT qualification/counts; candidate-plus-fix versus base in a
scheduled quiet window. No acceptance receipt or signed-fix result exists.
The director explicitly requested draft review-ready with signed EL1 and
acceptance pending for batch 5's cloudmac signed gate. Those gates will not be
queued on this Mac. Per director instruction, there will be no further timing
runs in this session.

For a future single-variable comparison, the detached worktree
`../spawn-regress-fixed-pb` is at `0661cbe3b`: exactly Phase B candidate
`1e61be8e8` plus runtime fix `74f9f63aa`. Its copied build cache still contains
the **old, unfixed candidate executable**. The attempted signed rebuild was
canceled while waiting for a shared lease, before the build. It must be rebuilt
and signed under `just lease carrick` before use. Preserve the original base
and candidate artifacts and record the new artifact identity separately.
