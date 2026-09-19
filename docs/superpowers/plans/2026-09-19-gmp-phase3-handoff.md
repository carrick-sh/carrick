# GMP Phase 3 — session handoff

Updated 2026-09-19. **Phase 3 is incomplete. Resume implementation, not promotion.**

## Workspace and authority

- Resume in any Carrick checkout containing the checkpoint commits below.
  Resolve the repository root and inspect its current status before editing;
  no particular branch name or worktree path is required.
- Original base: `93f648aa956feeeb256d4bbd3aaa0c9a60101a8a`.
- Rebased onto local `main`: `a58a89c219574b9aaad382db67fcf7206dd300f5`.
- Implementation is preserved as logical checkpoint commits:
  runtime/kernel foundation, public regression suites,
  debugging documentation, then this plan/evidence handoff. These are incomplete
  feature checkpoints, not acceptance or promotion commits.
- Rebase used a recovery stash, still retained:
  `bb93803fdb9ec55a386858a04e2b2ac09ef97224`.
  It is a backup, **not something to apply again**. Tracked patch IDs matched
  before/after rebase; all 12 pre-rebase untracked files matched their saved
  hashes. The only tracked overlap, embed `lib.rs`, auto-merged cleanly.
- The user explicitly authorized local-main integration as an incomplete
  checkpoint, deferring the known lint issues. This does not establish signed
  guest acceptance or Phase 3 completion. No push or default executor-sizing
  change is authorized by that checkpoint integration.
- User initially approved Antigravity, then explicitly chose to finish ourselves.
  Three Antigravity drafts were rejected earlier. Use native implementation.
- User approved bounded native fanout: main owns production, a file-disjoint
  test lane supplies regressions, and a read-only audit lane checks seams.
  All lanes were stopped for this handoff; no new contention test file exists.

Read `AGENTS.md` and these controllers before changing code:

1. `docs/superpowers/plans/2026-09-19-gmp-phase3.md`
2. `docs/superpowers/specs/2026-09-07-guest-cpu-scheduler-design.md`
3. `docs/superpowers/plans/2026-09-19-gmp-phase3-host-waits.md`
4. `.superpowers/sdd/2026-09-19-gmp-phase3/progress.md`

The ledger preserves red/green evidence and superseded designs. The audit at
`.superpowers/sdd/2026-09-19-gmp-phase3/host-wait-seam-audit.md` is useful but
its early frozen-registration proposal was superseded as explained below.
`stdio-handoff-experiment.patch` there is an **obsolete, failing experiment**;
do not reapply it. Current source contains the corrected implementation.

## Implemented foundation

- Public kernel scheduler host-wait token conserves each CPU ownership slot;
  exact executor/epoch/thread/generation authentication; non-cloneable and
  thread-affine guard; synchronous CPU reacquisition on drop/unwind.
- Nested handoff, no spare, concurrent return, affinity, close/control/residency
  behavior and public sibling/process progress have VM-free coverage.
- Production executor lends its registration and execution lease explicitly.
  No HVF vCPU is moved to another host thread; defaults remain unchanged.
- Selected dispatch waits leave MM participation before lending P and reclaim
  P before exact MM readmission. Retired threads return `HostWaitRetired` and
  runtime settles only that member, without guest-register writes.
- Real retirement deadlock fixed: a waiting dispatch must consume its file-table
  functional use before handoff. Retaining/reacquiring that lease while waiting
  for P creates a cycle with peer exec/exit. Later file lookup in a consumed
  scope fails closed. Only owned operations may cross this boundary.
- Actual durability operations use injected `HostIo` with pinned flush endpoints.
  Builder/runtime extension wiring supports embedder injection, not observer-only
  hooks. Public peer-exec cancellation test exercises graph replacement.
- Debug snapshots expose typed host-wait slots, owner/waiter identity and
  enter/resume census. Contention is unavailable (`None`), never fake zero.
  Structural validation rejects malformed ownership/counts.

## Latest implemented slice: scalar stdio

`dispatch/fs.rs::write_owned_stdio_sink` supports scalar `write(2)`:

- Stages all guest bytes before release.
- Captured output stays in memory and does not hand off.
- Inherited output pins a host descriptor before release; existing tail/EINTR/
  EAGAIN handling is reused without changing shared nonblocking flags.
- Piped output takes the caller's writer mutex **inside** the host operation,
  after releasing P/MM, and drops it before CPU reacquisition.
- Redirected piped stdio drops description guards/unused leases first.
- Off-executor and zero-length paths retain their prior non-handoff behavior.
- Canonical syscall 64 is explicitly execution-lease routed; native x86 number
  1 is not mistaken for canonical write.

The initial implementation exposed a post-I/O epoll epilogue that accessed the
consumed table and aborted. Corrected design:

- The **handler's actual selected description** becomes `net::WriteRearm`.
  Never capture via a second fd lookup before entering the handler: close/reuse
  can make the receipt name A while the operation writes B.
- Receipt is staged in exact captured dispatch-scope state. Epilogue consumes
  it once without acquiring a new file-table lease. Empty bare-stdio receipt is
  distinct from no staged receipt.
- Completion pins a still-live endpoint briefly, enumerates its **current**
  epoll owners, and updates only pointer-equal target descriptions.
- Do not freeze registration generations before I/O: a new watch can deliver
  an edge during the blocked operation and needs consumption rearm afterward.
  MOD uses current masks/data; a reused fd naming a different description is
  untouched. BSD rebind computes the current union without table callbacks.
- Current `epoll_ctl` requires a table-backed target; old comments implying
  bare-stdio registrations are stale. New bare-stdio epoll support is not claimed.

Key new code:

- `crates/carrick-kernel/src/kernel/scheduler/host_wait.rs`
- `crates/carrick-kernel/src/dispatch/host_io.rs`
- `crates/carrick-kernel/src/dispatch/net/epoll_ops/write_rearm.rs`
- `crates/carrick-kernel-example/tests/scheduler_handoff.rs`
- `crates/carrick-kernel-example/tests/host_wait_cancellation.rs`
- `crates/carrick-embed/tests/host_wait_policy.rs`

Other touched files are the existing dispatcher/resource/runtime/debug seams.
The repository's debugging skill was also expanded: `.agents/skills/carrick-lldb/`
documents `carrick debug`, live kernel tables, LLDB, cores, artifact validation,
carrier selection and caveats. There is no shell-level `carrick lldb` command.

## Evidence and limitations

Latest **pre-rebase** source passed:

- `RUSTC_WRAPPER= just test-kernel`: 2072 parallel kernel tests, one existing
  ignored; serial and all semantics suites passed.
- Handoff suite: 19/19, including bare/redirected writer progress, retirement,
  short-write suffix/error behavior, normal unwind and retired unwind.
- Peer-exec cancellation: 1/1. No bound production ThreadRunner in that fixture;
  production runner-drain and signed proof remain open.
- Six epoll completion regressions: consumed authority, outcomes, target reuse,
  new registration, current owners, MOD mask/data.
- Actual embed AdversarialPolicy and RecordReplay at 1/8/32 tasks: 2/2 tests,
  pinned placement, exact completion/census, zero replay fallback. VM-free only.
- Serialized runtime lib: 578 passed, one existing ignored.
- All-target clippy for kernel/kernel-example/runtime/embed and fmt-check passed.

Logs are `/private/tmp/gmp-phase3-stdio-{kernel-final,runtime,policy,clippy,fmt}.log`.
Post-rebase verification is recorded at the end of this document once complete.

No whole-workspace `just ci`, supported-platform closure sweep, signed embed,
Docker differential/ABBA or probe → smoke → full acceptance has been performed
for this feature. Contract `kernel.scheduler.host-wait-handoff` is named but
not registered/bound. Do not invent binding names or weaken registry validation
to imply coverage. Main now includes more conformance contracts than the earlier
two-contract audit; inspect the rebased registry before adding ours.

## Next concrete work

1. Add actual writer-mutex contention proof: one P, two spares. Hold task A
   inside caller `Write`; task B writes to the same writer and waits for its
   mutex; task C must acquire P and perform MM mutation before releasing A.
   Channels establish ordering; assert two simultaneous host waits. Preserve
   bounded failure cleanup and settle claims before assertions/unwind. Proposed
   file `crates/carrick-kernel-example/tests/stdio_host_wait_contention.rs`
   **does not yet exist**.
2. Add inherited-host backpressure/pinning and capture-bypass proof. Do not
   mutate process-global stdout in parallel tests; follow serial-host partition
   rules or use an owned endpoint fixture through the actual production seam.
3. Vector/transfer stdio remains unimplemented. Preserve partial-fault and
   committed-prefix semantics and bounded allocation; do not insert consuming
   handoff per chunk or flatten arbitrarily large iovecs blindly.
4. Stage regular positional I/O, then shared-offset/append transactions, VFS
   path/content work and runtime fault/fork/exec/retirement boundaries per the
   inventory. No guest pointers, lock guards or publication authority may be
   retained across a handoff that the replacement needs to progress.
5. Finish policy/runtime/backend/signed bindings and typed contract observations;
   cover pre-park races, signals and lifecycle composition. Only then change
   default bound-executor count and pursue exact-artifact acceptance.

Use `RUSTC_WRAPPER=`. Run build/test commands from the selected repository root;
do not assume the session's default directory is correct. Do not build under live guests.
Coordinate one build slot across agents and never overlap Carrick with Docker.
Do not push without request. Resume the committed source in the chosen checkout;
do not repeat the already verified foundation or depend on the original worktree.

## Post-rebase checks

Post-rebase host validation:

- `just test-kernel`: passed (2072 parallel kernel tests, 1 existing ignored;
  serial kernel and semantics suites also passed).
- Runtime serial library tests: 578 passed, 1 existing ignored.
- `host_wait_policy`: 2 passed.
- Targeted all-targets clippy: blocked by four `needless_borrow` errors in
  `crates/carrick-kernel/src/inotify.rs` at lines 1226, 1248, 1265 and 1266.
  That file is unchanged from incoming local main, verified by an empty diff.
  These are not Phase 3 edits; no unrelated lint fixes were made during wrap-up.
- `just fmt-check`: passed (exit 0), run separately because clippy stopped the
  chained command. `git diff --check` also passed.

Logs: `/private/tmp/gmp-phase3-rebase-{kernel,runtime,policy,clippy}.log`.
The chained validation exited 101 at clippy, so this is NOT an all-green gate.
No signed guest, Docker, performance or full CI acceptance was performed.
All implementation agents and the validation chain have stopped.

## Logical checkpoint commits and integration decision

On the user's subsequent request, work was split into implementation (including
internal tests), public regression suites, debugging documentation, and this
handoff/evidence commit. The commits are `4f36777b9` (implementation),
`58313ffeb` (public tests), `66a252e24` (debugging documentation), and
`9e2bdb611` (handoff/evidence). These identifiers are independent of branch names.

Fresh pre-commit validation exited 0: `just test-kernel` (2072 parallel passed,
1 ignored, plus serial/semantics suites), serial runtime lib (578 passed,
1 ignored), embed policy (2 passed), and `just fmt-check`. Logs are
`/private/tmp/gmp-phase3-checkpoint-{kernel,runtime,policy,fmt}.log`.
Commit formatting hooks remained enabled.

The initial conditional integration request was deferred. The user subsequently
explicitly requested this checkpoint on local main and authorized deferring the
four incoming lint findings. Signed exact-artifact proof, contract binding,
broader gates and the remaining implementation are still required for acceptance.
Preserve unrelated checkout changes. No push, branch deletion, worktree removal,
or recovery-stash modification is part of this handoff.
