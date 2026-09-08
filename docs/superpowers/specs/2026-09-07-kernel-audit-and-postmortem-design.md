# Kernel auditors and the fail-closed post-mortem sink

Status: approved design (owner ruling 2026-09-07: "our embed runner should be
able to handle this and abort in this scenario"; "introduce more surfaces to
embed to catch the forks that misbehave and give us better test runners that
can abort the kernel to do faster post-mortem analysis"). Companion to
[the guest-CPU scheduler design](2026-09-07-guest-cpu-scheduler-design.md),
which owns *ordering*; this document owns *judgement* and *capture*.

## The problem it solves

Today a misbehaving run has three endings, all slow: it hangs until a human
attaches `lldb` and runs `carrick debug hvpatch-kernel`; it dies with a
carrier `abort()` that leaves a core and no kernel-graph view; or it delivers
a guest signal (SEGV_MAPERR from a refused first-touch publication) that the
guest reports as its own bug. The wedge of 2026-09-07 (`tasks: []`, one
zombie pid 1 with no parent, every executor parked, `join` waiting forever)
was diagnosed only because a host-wide shell watchdog took a backtrace. That
is the wrong instrument: the kernel knew the process graph was empty and a
job was unpublished the instant it happened.

## Three surfaces, one sink

```
 SchedulingPolicy (ordering)      KernelAuditor (judgement)     deadline / runner invariant
   adversarial, record/replay       fork/exec/exit/reap events     process-graph liveness
            \                              |                              /
             \____________  KernelAbort(reason)  → PostMortem  __________/
                                      |
                       EmbedError::KernelAborted { reason, post_mortem }
                       (+ optional JSON directory for the CLI / watchdog)
```

### 1. `KernelAuditor` — lifecycle judgement

A new trait in `carrick-runtime::observe`, registered through
`ContainerBuilder::auditor(Arc<dyn KernelAuditor>)`. Unlike `SyscallObserver`
(syscall-shaped, per call) it sees the **kernel-graph transitions** the
scheduler and process machinery already perform, keyed by exact
`TaskKey`/generation, never a host pid:

| event | where it fires | what an auditor can catch |
|---|---|---|
| `fork_admitted { parent, child, kind: Fork\|Vfork\|Thread }` | `reserve_fork` / `reserve_thread_clone` commit | fork storms, a child with no parent |
| `child_first_run { child, executor, cpu }` | first executor load | a child that never runs |
| `exec_committed { task, generation_before, generation_after }` | exec retire-at-commit | wake of a stale generation |
| `exit_settled { task, status, owner: ExitOwner }` | terminal settlement | exit claimed by nobody |
| `zombie_created { task, parent: Option<TaskKey> }` | `commit → Zombie` | **zombie with no parent that is not pid 1** |
| `reaped { parent, child }` | `wait_child` | reap of the wrong child |
| `wake_rejected { target, reason }` | scheduler `wake` | wake of a reaped thread (the exec-generation abort class) |
| `executor_parked / executor_claimed { executor, cpu, task }` | run queue | all executors parked while a row is runnable |
| `first_touch_delivered { task, addr, reason }` | `apply_first_touch` fallthrough | **a refused publication lowered to SIGSEGV** (the 2026-09-07 SEGV class) |
| `process_graph_empty { unpublished_jobs }` | last task retires | the exit wedge |

Each callback returns `AuditVerdict::Continue | Abort(AuditReason)`. Auditors
are pure judgement; they hold no kernel locks beyond the event's own scope and
must not block. The events are emitted from the same points as the existing
`carrick*:::` USDT probes and event-ring records, so the three views (probe,
ring, auditor) can never disagree about *when* something happened.

**Built-in invariants** (ship ON in `TestContainer`, opt-out per test; opt-in
through the builder for production embeds):

- `NoOrphanZombie` — a zombie whose parent is `None` and whose pid is not 1.
- `ProcessGraphLiveness` — `process_graph_empty` with `unpublished_jobs > 0`.
- `NoWakeOfReapedTask` — any `wake_rejected { reason: Reaped }`.
- `FirstTouchNeverDelivered` — any `first_touch_delivered` whose reason is
  `BackendRefused` (a correct publication that carrick refused).
- `EveryChildRuns { within: Duration }` — `fork_admitted` without a matching
  `child_first_run` (timed, so it is a test-only invariant).
- `ExitBudget { select, within: Duration }` — a per-process exit timer
  (owner: "set timers on procs failing to exit"). `select` is a typed matcher
  over the kernel graph — `Pid(NsPid)`, `ChildrenOf(TaskKey)`, `Exec(glob)`,
  `Any` — and the clock starts at the matched event (`fork_admitted`,
  `exec_committed`, or an explicit `ContainerHandle::arm_exit_budget(task,
  within)` from the test body). A task still alive at expiry trips the sink;
  the post-mortem names the task's snapshot row (state, what it is parked in,
  which executor holds it, its pending signals) so the reader sees *why* it
  did not exit, not just that it did not. The timer lives in the test runner
  (a `TestContainer` budget thread keyed by `TaskKey`), never in the kernel,
  and it is disarmed by the matching `exit_settled`, so a task that exits on
  time costs nothing.

### 2. `KernelAbort` — the fail-closed sink

One path, used by every judge:

1. **Freeze.** Bump the scheduler control epoch so every executor returns to
   the run queue at its next boundary (`RunQueueError::ControlPoked` is the
   existing mechanism) and refuse new claims. Executors mid-guest are
   interrupted through the existing vCPU kick. No new lock.
2. **Capture, in process.** `Kernel::snapshot(deadline)` (`KernelSnapshotV1`,
   all tables), the run-queue and per-CPU queue view, every executor's
   `{executor, cpu, held task, last boundary, parked_in}`, the event ring
   drained oldest→newest, and the `AuditReason` with the event that triggered
   it. Bounded by a deadline (default 2 s); a table that misses the deadline
   is recorded as `Truncated`, never omitted silently.
3. **Publish.** Every unpublished process job is completed with
   `TerminalReason::KernelAborted`; `ContainerJobGroup::join` returns
   `EmbedError::KernelAborted { reason, post_mortem: Box<PostMortem> }`.
   Parking is unrepresentable: a job with no result and no live task cannot
   exist after this step.
4. **Persist (optional).** `ContainerBuilder::post_mortem_dir(path)` or
   `CARRICK_POSTMORTEM_DIR` writes `post-mortem.json` + `event-ring.jsonl`;
   the CLI sets it from `--post-mortem-dir`.

Triggers: an auditor `Abort`; the runner liveness invariant (always on, not
optional — it is the fix for the exit wedge class, the auditor form exists so
tests can observe it); `TestContainer::deadline(Duration)` (a wall-clock
budget that ends in a post-mortem, replacing host-side `SIGKILL`) and the
per-process `ExitBudget` timers above; and
`carrick debug abort --run-id <id>`, a new request on the existing
`KernelDebugServer` socket, so the host-wide watchdog becomes a one-line Rust
subcommand instead of a shell script that runs `lldb`.

### 3. Where the scheduler design meets this

- The **adversarial policy** (`SchedulingPolicy`, scheduler design step 6)
  *provokes*; it reports through `KernelAbort` when its own detection fires
  (e.g. record/replay divergence), never through a panic.
- `ProcessGraphLiveness` is the runner invariant the scheduler's phase 3
  (M = P) depends on; it lands with the exit-wedge fix.
- Auditor events and policy callbacks share `TaskKey` and `GuestCpuId` from
  `carrick-hal::scheduler`; no second identity domain.

## Non-goals

No new tracing format (the event ring and USDT probes stay the wire); no
host-pid keyed state; no timer-driven detection inside the kernel (the
deadline is a test-runner budget, the invariants are event-driven); no
backward-compatible second sink beside `EmbedError::KernelAborted`.

## Delivery

- **Lane B (exit-wedge worktree, `opus/exitwedge-sep07`):** `KernelAbort`,
  `PostMortem`, `ProcessGraphLiveness` as the runner invariant, the debug
  server `abort` request and `carrick debug abort`, `TestContainer::deadline`.
  Red first on the pre-fix exit wedge: hang → named abort with a post-mortem
  naming the pid-1 zombie.
- **Lane A (new worktree):** `KernelAuditor`, the ten events, the built-in
  invariants, `ContainerBuilder::auditor`, `TestContainer` defaults, a signed
  embed test per invariant. Until lane B lands, `Abort` verdicts surface as
  `EmbedError::CarrierFailed { reason }`; the swap to `KernelAborted` is a
  one-line follow-up.
- **Scheduler round 2** keeps its brief; its adversarial policy adopts the
  sink when lane B lands.
