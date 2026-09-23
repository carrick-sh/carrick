# inotify09 / syscall-floor handoff — 2026-09-22

Resume from this document and the local `main` checkpoint, not the older
`handoff.md` or `handoff-inotify09-2026-09-21.md`. The user requested a handoff and
local fast-forward so another session can continue. Development stopped at the
active instruction-content drain step. This is an unfinished research and
implementation checkpoint, not signed acceptance, release promotion, or goal
completion. Nothing was pushed.

## Goal and decision

The user's objective is near **1x** for Carrick-controlled overhead on common
Linux workloads, including Node, Go and Python. Native macOS I/O may remain
slower than Linux for now: measure that platform cost separately and preserve
Carrick's direct host-file advantage over a VM filesystem bridge. Keep raw Linux
ratios visible. Do not subtract unrelated microbenchmark medians from the
concurrent original workload. The repository's older generic 2x target is an
intermediate milestone for this campaign, not the user's final objective.

The selected next milestone is one signed current-kernel HVPatch carrier running
the **unchanged, dynamically linked original inotify09, including both race
participants**, with resident native regions across synchronous syscalls and
precise HVF fallback. Reuse the project's recovered DSR instruction machinery;
do not expand the small research fixture translator into a second DSR.

Read [the selected architectural design](docs/perf-results/2026-09-21-syscall-floor/native-islands/design.md)
first. The predeclared expansion screen is at least **20% lower original
completion time in both balanced timing blocks**, with unchanged semantics,
loop limit and deadline. That would be about 17.5 seconds against the historical
21.885-second reference; refresh the reference when measuring. This is a screen
for further investment, not parity or a forecast. More helper contracts alone
do not make that outcome more likely.

## Impact so far

- Last accepted full original reference: **21.885 s Carrick / 5.980 s native
  ARM64 Linux = 3.66x**. The preceding mailbox improvement of roughly 10.4% is
  already included. No native-region improvement has been measured.
- [Context borrowing](docs/perf-results/2026-09-21-syscall-floor/context-borrow/README.md)
  reduced exact context retains but measured 22.015 s, 0.594% slower with
  overlapping samples. The candidate was removed. Do not revisit context-copy
  counts without a new causal reason.
- [Seek-header tuning](docs/perf-results/2026-09-21-syscall-floor/seek-header/README.md)
  was also rejected. The completed original census reconciled 3M add-watch and
  3M remove-watch host services, but only one host-service seek. EL1/engine fast
  paths are outside that population. Counts establish reachability, not the
  critical path; shell-wrapper CLI totals are not the workload census.
- The native valid-watch research fixture approached 1.15x Linux. It does not
  establish original inotify09, dynamic-libc, memory, compute or atomic parity.
- Separate Node work produced measured improvements: the aligned-interior
  discard step reduced app-smoke from 243.5 to 184.0 ms in warmed balanced
  comparisons. See [discard edges](docs/perf-results/2026-09-21-syscall-floor/discard-edges/README.md).
  Do not compound historical percentages or call this an inotify09 gain.

The chronological [assessment](docs/perf-results/2026-09-21-syscall-floor/assessment.md)
contains earlier experiments and superseded artifact statements. Prefer each
experiment's exact receipt and this handoff for current state.

## What is in this checkpoint

The campaign had remained uncommitted on base
`9bb2392396b8531e93f5262657bf3aa9c5767488`. The checkpoint preserves its product
changes, contracts, tests, non-product experiment, trace tools and archived
receipts together. It includes syscall/metadata and inotify work, signal
lease-gap correctness, anonymous-discard/retirement work, retained-query bounds,
and the current-MM/native execution authority foundation. Historical rejected
patches remain evidence only.

The native foundation comprises exact kernel execution scopes and interrupt
handshakes, carrier data grants and retained activation, current-MM instruction
reads, physical-backing content dependencies, ordinary syscall destination write
admission, and now active content revocation/drain. The runtime still uses the
existing HVPatch execution engine. **There is no carrier executable publication
permit and no production native/DSR executor.**

The latest step is [code-execution-drain](docs/perf-results/2026-09-21-syscall-floor/code-execution-drain/README.md),
contract `kernel.mm.native-code-drain`:

- A participating writer first revokes affected physical-page dependencies,
  blocks future entries, and waits for active users to leave before changing
  bytes. It releases the registry lock while waiting and does not drain
  unrelated pages. Pending references and last-observer cleanup are covered.
- `InstructionRead::prepare_tracked_content` retains copied bytes and their
  dependencies while releasing the cold execution-lease borrow. Activation
  requires the exact real `NativeExecution` scope, task/MM/kernel/executor
  identity and live mapping revisions. Warm activation does not copy a VMA map.
- The active borrow must end before the running execution scope, dispatch or
  scheduler handoff. It checks content revocation and pending native control.
  Missing backend support refuses admission. Neither type grants an executable
  address, pins all publication authority, or proves hardware-write exclusion.
- The source files are `crates/carrick-vmm-hvf/src/trap/code_content.rs`,
  `trap/foreign_mm/instruction_read.rs`, `crates/carrick-hal/src/foreign_mm.rs`,
  `crates/carrick-kernel/src/kernel/mm_access/instruction_content.rs`, and the
  real-carrier composition test in `crates/carrick-runtime/src/vcpu_loop/memory.rs`.

Two behaviorally red controls preceded the fixes: a writer passed a live
content scope; a final observer/writer-reference race retained a dead registry
entry. The final focused content suite passed 22 tests. The real-carrier scope
contract passed at 1/8/32/128 with **zero measured warm heap allocations**, a
positive allocator control, wrong-MM refusal, actual interrupt propagation,
write invalidation and mapping-revision refusal. Two compile-fail lifetime tests
passed. The existing syscall-write budget passed with zero warm allocations and
exactly N affected-page visits. These are structural/lifetime results, not
wall-time gains. All raw logs, including failed test setup attempts, are archived.

## Open failures and acceptance boundaries

Do not quietly replace these failures with a later passing focused test:

1. **Read-only readv consumes input on EFAULT.** The signed destination fixture
   returns EFAULT but advances a source offset from 8192 to 8196. The identical
   new fixture reproduced it on the exact before-step source. Native ARM64
   Linux passes all seven final subchecks; Carrick passes six and fails globally.
   Evidence: [syscall-code-writes](docs/perf-results/2026-09-21-syscall-floor/syscall-code-writes/README.md).
2. **Fresh-publication maintenance budget:** one page-table invalidation where
   zero is allowed. Qualified before-step controls reproduced it twice. The
   budget remains unchanged.
3. **Intermittent signed anonymous foreign-copyout EFAULT 14**, child status
   1024, remains unattributed. A later fixed ABBA population passing all four
   runs did not repair or waive the original failure.
4. The private-file Linux fixture's unqualified 16-KiB mmap alignment assumption
   is still a fixture problem. It is not passing differential evidence.
5. Earlier broad Clippy found six `manual_is_multiple_of` diagnostics in
   `carrick-aarch64`; subsequent scoped checks used `--no-deps`. Whole-workspace
   CI is not green by implication.
6. **Post-merge governance is not green.** The position reconciler updated only
   seven existing dispatch-lock line numbers. It refused the new `madvise`
   abort site and K1 category-count changes (mapping 1109→1117,
   description_guard 210→203, epoll 419→421); these need review, not a blind
   re-bless. A direct host-authority diagnostic names a tooling defect:
   `scripts/migrate/check-host-authority-transitions.py::PRODUCT_SOURCE_PATHS`
   omits `experiments/native-syscall-slice` from its temporary source snapshot,
   so resolving the runtime dev-dependency fails before a census candidate
   exists. Preserve snapshot completeness and authority when fixing this.
7. Full signed probes, smoke/full promotion, cross-engine state/atomics/signals,
   private RX authority and original mixed-engine timing remain open. The latest
   drain step has **no signed binding yet**. A normal HVF ptrace text-patching
   pass from an earlier step does not qualify mixed native/HVF publication.

[Code-content evidence](docs/perf-results/2026-09-21-syscall-floor/code-content/README.md)
records items 2–4 and their exact candidate/control provenance. The final handoff
checks and any additional integration failures are recorded in
[session-handoff/verification.json](docs/perf-results/2026-09-21-syscall-floor/session-handoff/verification.json).
No gate is to be relaxed to make this checkpoint appear complete.

## Next session: bounded path to the original workload

1. Finish a conservative **private RX admission proof**. Cover or exclude
   hardware stores, writable aliases in other MMs, external shared-file changes
   and remaining raw/internal host writes. RX VMA permissions and retained pins
   alone do not prove immutable code. The current content receipt has independent
   page state; a publication permit must retain exact backing and ownership too.
2. Compose that permit, active drain, block publication and direct-link
   revocation with current-MM DSR emission. Donor links may bypass entry guards.
   Existing emitter `Direct`/`Biased` modes are not current-MM authority; do not
   disguise a host pointer with a dummy fixed bias. Keep native data access
   from holding mutation exclusion across an execution quantum.
3. Integrate precise `GuestCpuState` / `Aarch64TaskCpuStateV1` native↔HVF
   handoff. Preserve registers, SIMD/flags, Linux TLS/SP, syscall completion and
   restart state. Unsupported instructions exit before side effects; completed
   syscalls are never replayed. Retain bounded control checkpoints and the
   current blocked-continuation/scheduler ownership. Avoid self-deadlock by
   ending an active content scope before a syscall or participating write.
4. Prove signed mixed-engine semantics with both race participants and actual
   guest atomics, then run the original LTP ELF through the normal shell wrapper.
   This is the next delivery, not another stand-alone infrastructure milestone.
5. Freeze exact signed control/candidate artifacts, run the predeclared balanced
   untraced comparisons, then native ARM64 Docker serially. Separately measure
   native residence, real HVF exits, engine switches, fallback reasons and slow
   memory accesses. A frequent profile frame is not automatically the largest
   removable wall-time term. Stop architectural expansion if the completed
   workload screen fails; preserve receipts and remove ineffective product code.

Do not start a general code-cache, decoder-coverage or scheduler project before
this path works. The selected design and existing contract boundaries are the
controller. The user already approved the low-level carrier data capability;
do not re-request that old approval. No new unsafe executable authority is
established merely by that prior approval.

## Where the recoverable state lives

- Resume source work from `/Volumes/CaseSensitive/carrick` on local `main`.
  The prior campaign checkout is
  `/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick`; preserve it.
  Its ignored `target/lease-cost/` contains frozen binaries, before-step source
  snapshots, raw intermediate data and recovered DSR. They are **not** moved
  into `main/target` by a Git fast-forward and must not be garbage-collected.
- Measured baseline: that worktree's `target/release/carrick` and
  `target/lease-cost/context-borrow/carrick-baseline`, both freshly rechecked at
  handoff as SHA-256
  `1142bb6dc6202ab3675dc6485b4f479e1d9425b2b75a293c948aef5e65db8918`.
  Historical signed identity: CDHash
  `64c1c705666abcfa74d1e889dc191a96bfe7140f`, LC_UUID
  `20213344-A8B9-38E2-BA97-4038961F4E22`. This is the measured older artifact,
  **not a build of this new checkpoint**. Do not run an arbitrary stale
  `main/target/release/carrick` as the candidate.
- DSR donor is `20add4f9f1138cbca98cc672182cb093d473ac72`. The recovered
  workspace is `<campaign-worktree>/target/lease-cost/dsr-reuse` and is not in
  the product dependency graph. Its manifests currently point at the campaign
  checkout by absolute paths; update them deliberately if rebuilding against
  `main`. [Reuse evidence](docs/perf-results/2026-09-21-syscall-floor/dsr-reuse/README.md)
  preserves donor hashes and dependency resolution.
  [The current-MM planner snapshot](docs/perf-results/2026-09-21-syscall-floor/dsr-current-mm-planner/README.md)
  preserves `current_mm.rs`, manifest and lockfile. Its `UnpublishedPlan`
  cannot emit or execute. The original-instruction audit classified 1,344
  selected sites; that is not full-callgraph execution coverage.
- `experiments/native-syscall-slice` is committed but remains a non-product test
  instrument. Runtime uses it only as a macOS dev-dependency. Existing fixtures
  use a stage-2 stub/private research text and do not prove executable carrier
  authority. The current source checkpoint and evidence are identified by Git;
  the latest step additionally has an input SHA manifest and a bounded patch.
- Permissive guidance and license/source receipts are archived in
  [permissive-guidance](docs/perf-results/2026-09-21-syscall-floor/permissive-guidance/sources.json).
  Do not inspect GPL implementation sources. LTP/libc binary instruction audit
  was for workload requirements, not implementation copying.

## Useful checks when resuming

Run from the checkout being tested, with `RUSTC_WRAPPER=`. The feature flag on
the runtime allocation contract is required. Tests below are VM-free; they do
not require or prove HVF entitlement.

```sh
RUSTC_WRAPPER= just test-kernel
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf --lib code_content -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf --lib syscall_code_write_cost_contract -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib --features conformance-metrics native_instruction_content_scope_contract -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-kernel --doc instruction_content
RUSTC_WRAPPER= cargo run -p carrick-conformance-contract --bin check-contracts -- --root .
```

Use the existing signed runner for guest tests and `just build` for any new CLI
candidate. Record HEAD/source scope, SHA-256, CDHash, LC_UUID, entitlement and
DOF; freeze a tested artifact before another runner re-signs it. Stamp
`CARRICK_RUN_ID` and use scoped cleanup. Never build over a live guest and never
run Carrick and Docker phases concurrently. The current handoff intentionally
does not launch another performance experiment or pretend a failed gate passed.
