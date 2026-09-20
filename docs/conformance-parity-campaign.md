# Autonomous conformance parity campaign

User authorization (2026-09-20): full-auto pursuit of conformance parity,
including production fixes. This supersedes the investigation-only production
review boundary for this campaign. Do not push. Preserve unrelated changes.

## Current checkpoint

Logical commits on local main (not pushed):

- `333d5ba6d`: coherent inotify watch indexes and queued readiness.
- `cc02e4af6`: positive scalar-write notifications, contracts, and signed probes.
- `09bec08d6`: strict closure preserves first observations and rejects serial recovery.
- `bcf9c1f50`: preserve generic and dedicated signed receipts separately.
- `e1de4b9e4`: fresh native ARM64 Go build oracle evidence.

The exact signed candidate remains the previously recorded dirty-source artifact
at SHA `bcbb4668628a0c15139fcb25dd44026a684923b5ca16f1b8012f5fe2615ad511`.
These commits do not retroactively turn its original source receipt into a
clean-source release claim. Pre-existing sparse-state, fd-path, and VFS fast-path
edits remain uncommitted, as do the unrelated older plans.

Two clean baseline comparisons at `5b666b580` establish that the loaded failures
predate this campaign's fixes. Baseline A: Go build completed in 3,124 ms, but
cpython-subprocess hit 44,167 ms on a 44,000 ms budget. Baseline B: Go build hit
7,255 ms on the same 7,000 ms budget as the candidate. Both ledgers contain
22 MATCH and one BUDGET_KILL, with serial confirmation disabled. Both have scoped
cleanup receipts. They are attribution evidence, not parity acceptance.
Baseline artifact identity is in `baseline-cli-artifact.json`; measurements are
`baseline-smoke-{a,b}.{jsonl,log}` in the campaign receipt directory.

Next work is a loaded Go-build reduction/profile or live scheduler capture that
explains the repeatable budget failure, retaining the current concurrency and
budgets. Standalone low-rate profiling did not reproduce or diagnose it.
Full-suite promotion remains blocked by non-clean smoke; the frozen 2,127 rows,
zero-query write/seek contract, and <=2x performance requirement remain open.

## Acceptance

Use the canonical macOS/Apple Silicon/HVF ARM64 lane and the frozen 2,127-suite
core-emulation denominator from `handoff.md`. Prove executed assertion parity;
skips, known gaps, empty results, oracle failures and retry-recovered passes do
not close it. Preserve the existing structural budgets and <=2x Docker runtime
requirement. Promote the final exact signed artifact through probes, smoke and
full gates, with source/artifact/image provenance and scoped cleanup. Hardware
coverage outside this lane must remain explicit, not inferred from host tests.

## Starting checkpoint

Source HEAD: `5b666b580`. Existing uncommitted runtime changes were preserved.
The write/seek bindings are real and the unchanged zero-query budget is red:
scales 1/8/32/128 execute that many preparatory SEEK_CUR queries. Signed and
native ARM64 Docker semantic checks pass; full workload parity remains open.
See `investigation-evidence-enforcement.md` for exact previous receipts.

The current VM-free baseline, `RUSTC_WRAPPER= just test-kernel`, passed (log
`/tmp/carrick-parity-kernel-before.log`). The fresh broad signed probe gate is
running via `RUSTC_WRAPPER= CARRICK_RUN_ID=parity-probes-20260920 just
conformance-probes`, log `/tmp/carrick-parity-probes.log`. No new production
change has been applied during this baseline build.

Previous full discovery is preserved in
`target/investigations/parity-20260920/prior-full-discovery.jsonl`. Its 2,127 rows
contain 2,095 matches, 14 budget kills, seven diffs, seven new differences,
three timeouts and one regression. This is prior discovery, not current closure.
The raw finit_module01 regression is host ENFILE before guest launch. Pidfd
rows compare active Carrick assertions against cached Docker TCONF, so their
Linux authority needs refreshing before changing runtime semantics.

## Write/seek architecture finding

A per-fd 'never sought beyond EOF' hint is insufficient: truncation through a
separate open description can move EOF behind the existing shared offset.
An unauthenticated offset cache is not a correction. Scalar write currently
uses its position for RLIMIT_FSIZE, sparse metadata, and implicit post-write
hole punching. The latter can race another writer; removing it also changes
APFS physical allocation behavior. Preserve the zero-query contract while
qualifying a coherent correction; do not silently remove sparse guarantees or
hold an ordinary mutex across host-wait suspension.

## Execution policy

Reduce confirmed failures at the cheapest capable layer, capture red evidence,
fix the underlying ownership/algorithm/lifecycle seam, and validate adjacent
semantics before signed promotion. Carrick and Docker phases never overlap.
Keep a failure open rather than widening timeouts, reducing concurrency,
relabeling it as a known gap, or treating registration as execution proof.

## First new semantic reduction

`rejected_write_does_not_modify_or_consume_watch` was witnessed red on the
unchanged scalar write implementation. A nonempty write through an O_RDONLY
handle returns EBADF, but the inotify read incorrectly returns 32 bytes (MODIFY
and IGNORED) instead of EAGAIN, consuming an IN_ONESHOT watch. Log:
`/tmp/carrick-inotify-rejected-red.log`. The existing pre-write notification hook
in `dispatch/fs/rw.rs` precedes write-access and other success checks. Corrective
work must emit only after positive completion and preserve the original file
identity across the operation. Linux differential confirmation and production
correction are pending; this red host-only reduction is not signed acceptance.

## Write completion correction in validation

The baseline broad probe gate stopped on `dentrycache`: a second write reported
cached size 5 instead of Linux's 11. Its complete log and signed receipts are
preserved in `target/investigations/parity-20260920/baseline-probes.log` and
`baseline-probe-artifacts.jsonl`; scoped cleanup found zero remaining guests.

Native ARM64 Docker confirmed `inotifywrite` for both libc builds. A one-off
execution against the preserved pre-fix signed CLI reproduced the false MODIFY
and IGNORED events after EBADF, followed by no event after the real write.
Permanent coverage is registered in conformance-next, with source-hashed oracle
files. This diagnostic CLI invocation is not a new subprocess probe gate.

The correction captures the target pathname from the acquired open description
and publishes only after positive scalar-write completion. It covers host,
in-memory and writable synthetic files; no descriptor lock survives host wait.
The captured path avoids re-resolving a reused fd slot, but does not solve the
registry's existing inode/rename identity limitation. Positive host writes
invalidate metadata and update sparse bookkeeping before waking a watcher;
actual modifications still notify if subsequent hole maintenance errors.

The once-per-open metadata invalidation experiment was reverted: every positive
write invalidates caches, including those repopulated by an intervening stat.
Its flag and the unused, unqualified sought-past-EOF hint were removed. Other
pre-existing inotify/VFS changes remain intact. The zero-position-query contract
is still red and has not been weakened.

Five focused VM-free tests pass, covering failed/empty/partial/successful writes
on host and memory backends plus repeated-write metadata freshness. The full
`just test-kernel` passed before the final notification-ordering adjustment;
its log is `/tmp/carrick-parity-write-kernel.log`. Independent review verified
the final ordering correction. The fresh complete signed probe gate is running
under run ID `parity-write-fix-20260920`; log
`/tmp/carrick-parity-write-probes.log`. No full parity claim is made.

The final five focused tests also passed after the ordering correction, and
kernel/kernel-example clippy passed with warnings denied. Formatting and the
542-source inventory/strategy checks pass. The final CLI's SHA-256 is
`a22ccb30ba8f8cfdcf57b594c563d885efe9be8ffc32892aea0b77f603d8f734`; full signing,
load-command and source identity records are retained in
`target/investigations/parity-20260920/write-fix-cli-artifact.json`. The
pre-existing dirty inputs are captured in `write-fix-worktree.patch`; this is
not a claim of a clean-source release checkpoint.

## Signed probe inventory correction

The first corrected-runtime probe run completed all 910 expected generic rows
with no missing rows, duplicates, or semantic differences. Dedicated embedded
cases, entitlement negative controls, and the CLI boundary contract passed.
The final legacy-retained harness failed its host inventory assertion (540
expected sources versus 542 actual); `writeseek` and `inotifywrite` account for
the increase. Its frozen inventory is now 542 sources, 491 generic plus 23
dedicated conformance sources, 27 performance sources, and one helper. The
2,127-suite workload denominator is unchanged. The repaired assertion passes.

The full public probe gate is rerunning without the build dependency under
`parity-write-inventory-20260920`, preserving the CLI SHA above. Original failed
gate evidence is `target/investigations/parity-20260920/write-fix-probes-inventory-red.log`;
scoped cleanup reported zero remaining guests. No smoke/full promotion has
occurred yet.

Dependency review found that the pending inotify reverse index leaks displaced
watch keys during rename-over-destination and cannot represent multiple paths
for one watch descriptor. Those changes are not ready for integration. The
single-lock notification helper and wake suppression had no new review blocker.

Two focused registry regression tests are staged in the working source (not
executed yet): repeated rename-over-watched-destination must retain one reverse
entry, and unregister must remove every alias path for one descriptor. The
implementation remains unchanged pending their red execution. These test-only
additions were made after the signed test executables were built; they are not
part of the running signed artifact. Active probe rerun log:
`/tmp/carrick-parity-write-inventory-probes.log` (exec session 57060).

## Reverse-index correction

The inventory-corrected public probe gate completed successfully (46 retained
harness tests passed, one oracle-bless helper ignored); all 910 generic rows
were accounted for. Cleanup found zero remaining guests and the CLI SHA stayed
unchanged. The command log is `write-inventory-probes.log` in the campaign
receipt directory. The signed helper overwrote its generic receipt with its
second invocation's dedicated receipt; this run is useful semantic evidence,
not final complete artifact provenance. The public recipe now preserves both
receipts separately, for validation on the next runtime revision.

The two review findings reproduced in the exact inotify registry unit module:
rename replacement retained displaced reverse keys, and descriptor unregister
left an alias path registered. Red evidence: `/tmp/carrick-inotify-index-red.log`.
The reverse index now maps each descriptor to its full set of registered paths.
Path removal updates only its membership, rename removes displaced memberships,
and descriptor removal visits its indexed paths without a global fallback scan.
Cost is proportional to those paths and the watches examined there, not O(1).
A third test covers path removal and rename with shared-descriptor aliases.
Independent final review found no blocker. All-inotify unit validation is running
(`/tmp/carrick-inotify-index-green.log`, session 85230). This runtime revision
still requires full kernel and signed validation before integration.

All 14 inotify unit tests passed after the reverse-index correction. The full
`just test-kernel` also passed (`/tmp/carrick-parity-index-kernel.log`), including
2,080 parallel kernel tests and the scripted semantics suites. Clippy with
warnings denied is running before the fresh signed rebuild. No production
integration or full parity claim is made from this host-only evidence.

## Current signed artifact and first smoke observation

The index-corrected signed probe gate passed with all 910 generic rows, 31
embedded case executions, both entitlement negative controls, and scoped cleanup.
Generic and dedicated signed receipts are now retained separately as
`index-generic-artifacts.jsonl` and `index-dedicated-artifacts.jsonl` in the
campaign receipt directory. CLI SHA-256:
`bcbb4668628a0c15139fcb25dd44026a684923b5ca16f1b8012f5fe2615ad511`.
Full identity: `index-fix-cli-artifact.json`; command log: `index-probes.log`.

Smoke reported 23 MATCH rows but is NOT clean acceptance: `go-build` hit its
7,000 ms diagnostic budget at 7,257 ms, then normal regression mode replaced
that observation with a 1,700 ms serial confirmation. The original log, ledger,
and cleanup receipts are `index-smoke.log`, `index-smoke.jsonl`, and
`index-smoke-cleanup.log`. The CLI hash remained unchanged. Full promotion has
not occurred; the original budget failure stays open.

This exposed a mechanical closure gap. A red unit test demonstrated that
`validate_closure_reports` accepted MATCH carrying serial-confirmation metadata.
Closure now skips automatic Phase 1b and rejects such reports as a backstop.
All 215 conformance-harness tests pass and independent review found no other
retry bypass. Logs: `/tmp/carrick-closure-confirm-{red,green}.log`.
The guest runtime was not changed by this harness correction.

A fresh Docker-only native ARM64 oracle run of `go-build` succeeded in 1,426 ms
(`/tmp/carrick-go-build-oracle-refresh.log`, raw `fill-48493-d00.{out,err}`).
Both oracle parser profiles were updated by that real execution. An unchanged
23-row smoke diagnostic is running with automatic serial confirmation disabled,
not reduced concurrency or larger budgets, to collect first-observation
behavior. Session 16193; `/tmp/carrick-parity-smoke-first-observation.log`.
Passing this diagnostic alone cannot erase the earlier load-sensitive failure.

The first-observation smoke diagnostic reproduced the Go failure: 22 MATCH,
one BUDGET_KILL (`go-build`, 7,257 ms on 7,000 ms), serial confirmation disabled.
The normal regression command still exits zero for this non-gating diagnostic
verdict; its ledger, not its exit code, is the evidence. Archived as
`smoke-first-observation.{jsonl,log}`, with per-run cleanup verified. Additional
cached-oracle ratios exceeded 2x for node-app-smoke and cpython-glob; these need
fresh paired qualification, not a baseline exemption.

A bounded standalone `hvpatch-carrier-cpu-low-rate` trace of the exact Go command
completed successfully on image digest
`357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`.
The trace validates 575 samples across 223 stacks, no drops, successful root
exit and scoped cleanup. 279 samples are in the opaque guest/HVF execution
bucket; this does not identify a Rust hotspot or prove a loaded hang diagnosis.
Raw trace, command, log and symbolicated top stacks are `go-build-profile.*` in
the campaign receipt directory. The rejected capture-bound override failed
before guest launch and is preserved as `go-build-profile-preflight.log`.

Next attribution step: build an isolated, unmodified main at `5b666b580` and
measure the same smoke workload at unchanged concurrency before attributing the
repeatable loaded Go failure to pending changes. The primary runtime artifact
and edits remain preserved; no full-suite promotion has occurred.

The isolated baseline worktree is clean at
`/Users/tjfontaine/.codex/worktrees/parity-baseline/carrick`, HEAD `5b666b580`.
Its signed build uses separate cargo output
`/private/tmp/carrick-parity-baseline-target`; session 26399, log
`/tmp/carrick-parity-baseline-build.log`. This leaves the candidate CLI at SHA
`bcbb4668628a0c15139fcb25dd44026a684923b5ca16f1b8012f5fe2615ad511` intact.
After the build, compare at least two baseline observations using the same
23-row smoke harness and unchanged concurrency, with serial confirmation
explicitly disabled; preserve every initial budget failure and exact artifact
identity. No guest workload should overlap this build.

## Loaded Go diagnostic capture (2026-09-20)

`target/investigations/parity-20260920/loaded-go-kernel/` captured a
successful loaded Go run (2711 ms); the subsequent `loaded-go-kernel-b/`
run hit its unchanged 7000 ms budget (7252 ms observed). No reachable
kernel debug socket was found at its sampled times. That absence alone
does not establish a startup failure.

`loaded-go-lldb/` contains a coherent kernel snapshot, all-thread
backtraces, event ring and modified-memory core for `conf-66325-c10`,
carrier PID 66529. This carrier had run guest work: the ring recorded
80125 events, including repeated dispatch/preemption. Executor 8 was
in `PersistentCarrierMappings::audit` collecting carrier mappings;
executor 4 was yielding in `run_executor_loop`. These are sampled
locations, not a proven causal diagnosis. The attach perturbed the run,
which ended as a regression with missing run metadata; it is not timing
or acceptance evidence. The original cleanup script rejected that empty
ID. Follow-up cleanup covered the explicit captured ID and all 22 other
ledger IDs, with exit zero; see `cleanup-completed.log`.

Parity remains open. Diagnose the dispatch/preemption and mapping-audit
behavior before changing runtime code; do not infer closure from a
successful neighboring run or from the debugger capture.
