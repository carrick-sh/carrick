# Fix-forward ecosystem closure controller

Goal: fulfill the 2026-09-09 user closure contract on macOS/Apple Silicon HVF/HVPatch arm64. This controller supplements the historical handoff and campaign ledger; no historical scoped acceptance closes this goal.

## Authority and acceptance

Codex owns diagnosis, invariants, decomposition, oracle policy, review, integration and promotion. Antigravity implements production changes in manually created isolated worktrees based on an explicitly verified commit. Return concrete review findings to the same worker. Codex production takeover requires three substantive implementation/revision rounds with no measurable progress on that bounded task, recorded here with the repeated blocker and justification.

Never close a failure with reduced concurrency, retries, raised deadlines, new expected gaps, symptom serialization or weakened assertions. Treat load-dependent fatal, liveness and resource failures as architectural until disproven. Oracle or declaration changes require native-arm64 Linux evidence first. No push.

At every cluster/architectural milestone freeze a rebuilt signed artifact, identify source HEAD, source dirt, SHA-256, CDHash, LC_UUID, hypervisor entitlement and DTrace section. Promote in order: full `just conformance-probes`, `just conformance smoke`, then `just conformance`. Check binary identity across the recipes' build prerequisites; archive all embedded signed executables as well. A red rung blocks promotion and is reduced first. Routine runs use committed cached oracles; deliberate Docker refreshes are serial and never overlap Carrick. Every run has scoped cleanup and host-activity evidence.

Final acceptance requires 2,127 unique executed suites, zero crash/regression/timeout/empty/unexpected skip/oracle failure/NEW/Carrick-specific expected-gap rows, no assertion loss or gap expansion against the previous ledger, stable one-worker and four-worker slices and targeted stress, every row and CPython/Go/Node/LTP aggregate below 2.0x native-arm64 Docker, and cold go-build as a named gate. Performance evidence requires controlled quiet-host measurements. Reconcile committed inventories and clean completed worktrees.

## Work sequence

- [ ] Establish current public-probe baseline and freeze provenance; reduce any red before promotion.
- [ ] Node/libuv: recheck child lifecycle, embedded completion and nested epoll against current signed source and Linux; bound a regression in conformance-next/embed, trace ownership/wake/retirement, then brief a cohesive production worker.
- [ ] LTP semantic blockers: group tty0, sparse seek, capacity accounting, packet ring and large VMA cases by evidenced authority boundary; separately reproduce and delegate cohesive fixes rather than one combined speculative rewrite.
- [ ] Oracle/feature exposure: verify semctl06/syslog12 privileges and SCTP recvmsg behavior against actual native-arm64 Docker declarations; distinguish wrong oracle from false feature advertisement before edits.
- [ ] Structural cost/liveness: reduce futex/epoll/pipe and subprocess/multiprocessing/Go importer/type-checking paths, with one/four-worker outcomes and ownership/resource instrumentation. Preserve cold go-build.
- [ ] Independently review every actual worker diff and receipts, rerun decisive regression and adjacent gates, integrate narrow commits, then promote each milestone through the ladder.
- [ ] Final exact-artifact ladder, denominator/assertion/performance audit and scoped cleanup.

## Entry checkpoint

Clean main `01f812101` at entry. `docs/perf-results/2026-09-09-per-exec-goal.md` records scoped normal Python spawn acceptance, with full subprocess and multiprocessing still above 2x. The historical generated closure ledger uses source `3ef2bf7a8`; the newer campaign records a full 2,127-row run with unresolved failures. Neither is a current green closure ledger.

Antigravity preflight passed. Initial public probe launch failed before compilation because sccache returned EPERM. Reissued with `RUSTC_WRAPPER=` and unchanged gate requirements. Run ID `fixforward-20260909-probes`; log `target/conformance/fix-forward-20260909/public-probes.log`. No production changes or worker implementation rounds yet.

## Baseline ladder and active reduction

Public probes exited 0: 876 unique generic executions, 31 dedicated cases, CLI boundary and retained 46 passed/1 ignored. The 30 amd64 report-only differences are outside the canonical arm64 lane. Frozen CLI `target/conformance/fix-forward-20260909/carrick-baseline` SHA-256 `ceff5866d87e51699c7d31e4f02871f4b28b0345a8c9e9bf5a96f25af6740856`, CDHash `a17ac3f0a02949d93d617fd8c478045231c8cb6c`, UUID `065B73A7-4E6E-3E32-B462-A432CC299376`; source `01f812101974abe9cf1a13c9ca6371d3a58f45c8`. Provenance and post-gate executable captures are in that directory. The script overwrites the generic manifest during the dedicated invocation; the retained dedicated manifest and post-gate hashes are archived, with capture timing explicit. Future milestone runs must archive both stage manifests before overwrite.

Four-worker smoke on that frozen CLI exited 1: cpython-subprocess TIMEOUT, 62/297 passed assertions, 44,232 ms against cached 20,698 ms; harness reports blocked. Run `conf-67689-c21`. Raw stderr ends at `test_send_signal_dead`; this names the active test, not yet the cause. Node app/V8 smoke MATCH. Full promotion is prohibited until reduced. Native-arm64 Docker single `test.test_subprocess.POSIXProcessTestCase.test_send_signal_dead` passes in 1.016 s; its strict existing embed reducer is running under `fixforward-20260909-senddead`.

Antigravity read-only node-audit conversation `73e8ce92-48b8-4047-a7ef-7de7b58036c4`, run `fixforward-20260909`, required one report revision because claimed findings were absent from its output. No implementation round has occurred. Historical nested-epoll passes and existing cycle/generation handling mean the original failure must be revalidated, not assumed current. No production changes have been made.

### Subprocess reduction and XSIG-1 dispatch

One-worker subprocess repeats the same 62/297 timeout at 44,162 ms (`conf-69405-c00`). Single send-signal-dead passes embed in 1.181 s with scoped cleanup. Real carrier core at 35 s (`subprocess-debug/`) shows root blocked on an fd wait and live child executing during `test_pass_fds`; it does not prove a lost wake. Source read from the actual image shows pass-fds executes 20 children, with ten scanning fstat over SC_OPEN_MAX using fd_status.py.

Native-arm64 Docker pass-fds passes in 4.872 s. Durable CPU sampling passes naturally with zero errors, 6,760 user samples and 7,287 kernel samples; 620 user leaf samples are xsig_has_unblocked_for_self. Return-site validation identifies all 374/374 sampled return addresses on the exact trace artifact. Trace launch through the frozen path required a password and did not start; the configured shipped-path tracer succeeded on identical source (separately archived signed artifact). The traced 27.687 s is diagnostic only. The unoptimized embed case passes in 112.233 s and is semantic evidence, not a release timing ratio. Untraced frozen release measurement is running in passfds-release.log.

XSIG-1 worker `xsig-index`, conversation `bef41ee0-7bf1-4220-8e09-cc7555fd016e`, is in implementation round 1 in manually created `.worktrees/fixforward-xsig-20260909`, branch `codex/fixforward-xsig-20260909`, verified base `01f812101`. Scope: signal-core xsig.rs and its adjacent tests. Design: authoritative shared publication metadata avoids scanning all 256 payload slots when empty; publication/retirement/reuse and mask-change visibility must remain exact. Never restore XSIG_DIRTY as authority. Require deterministic red work-count and adversarial shared-signal tests, full signal-core tests and Clippy, then independent signed/performance review. Brief at /private/tmp/fixforward-xsig-brief.md. Worker currently has edit-only lease; send build/test authorization through the same conversation when its initial turn returns. No main production edits, no integration, no push.

Untraced release pass-fds completed in 23.537 s versus the serial Docker sample's 4.872 s (4.83x single-sample ratio, not paired acceptance). The embedded run and release run both cleaned up. Round 1 produced `92ecda6ef` with claimed 49 passing signal-core tests, Clippy and fmt. Worker violated its initial edit-only lease by starting host tests; this happened after the timed release run ended, so no cited measurement overlapped the build.

Round 1 is NOT accepted. Actual diff review found (a) a stale target PID check followed by generationless CAS allows another drainer and producer to recycle a slot for a different destination before the old claim succeeds, and (b) a stale occupancy mask can claim a new ready incarnation before its producer publishes the bitmap bit, then leave a late stale bit after retirement. Require deterministic production-path interleavings and incarnation-safe publication/claim/retirement; sequential reuse tests do not establish this. Review sent to same worker in /private/tmp/fixforward-xsig-review1.md. Round 2 is active; signal-core-only host build/test lease now granted, no guest/Docker validation by worker. Codex has written no production code. No task has met the takeover condition.
