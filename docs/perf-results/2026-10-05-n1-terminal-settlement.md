# N1 terminal settlement: live exit-participant membership

## Evidence and scope

The director reported `el1_thread_lifecycle_spawn_slope` aborting in
`terminal_settlement` with `task2 changed after exit preparation` on n1-cm's
`50d648e76`. Its signed evidence remains on cloudmac at
`/Volumes/carrick-build/evidence/n1-cm/fork-50d648e76/`. That evidence was not
rerun here, and `work/n1-cm` was not merged.

On the unchanged production sources of N1 `229194ae6`, a VM-free kernel unit
witness reproduced the same `ExitTopologyChanged` error for a live child of
the exiting task. The child had two live threads. Its sibling claimed an ABI
pool entry before the parent's exit preparation, then published Born after
preparation. Committing the parent's exit settled the real ABI ledger and
failed the child's captured revision check. This establishes a current-tip
mechanism for the reported abort class; the identity and role of task2 in the
signed run still require the director's coordinated runtime confirmation.

The red command was:

```sh
cargo run --locked -p carrick-xtask -- worktree-run -- cargo test --locked -p carrick-kernel --lib prepared_parent_exit_preserves_late_abi_birth_in_live_child
```

It exited 101 with `ExitTopologyChanged(TaskId(9851))`, one failed test, in
`target/n1g6/terminal-settlement/red.log`. Initial witness compilation and ABI
fixture mistakes are retained separately; neither is counted as the red.

## Ownership defect and correction

`PreparedTaskExit` reserved all affected task identities and captured each
task's broad revision. That excludes topology mutations, but a live child,
adopter or autoreaping parent can still finish admitted thread activity.
`ThreadLedger::settle` publishes ABI births through `PublicationLane::AbiBorn`
without checking the topology reservation. That publication advances the task
revision. The subsequent exit settlement incorrectly treats it as a changed
parent/child graph. Nonfinal ABI exit had the complementary problem: it met
the exclusive task reservation and could fail with `TaskBusy` in the ledger.

The reservation now has typed `Exclusive` and `ExitParticipant` scopes. The
exiting task, fork and exec retain exclusive custody. Each live participant
owns exact-key revision custody and one reserved topology publication credit.
A membership transition validates the current revision before irreversible
thread work and consumes a prepared publication token under the same registry
write guard. That advances both membership and participant custody together.
The exit validates this custody and consumes its own credit against the latest
revision. It cannot overwrite an intervening birth or retirement revision.

The reservation remains live through terminal clear and completion publication.
Nonfinal thread retirement can proceed in an exit participant; whole-task exit
and other topology mutations remain refused. Unowned revision changes still
produce `ExitTopologyChanged`. Drop releases the participant credit. No retry,
assertion relaxation, lifecycle gate close, budget change or new wait is added.

The Linux authority is [_exit(2)](https://man7.org/linux/man-pages/man2/_exit.2.html):
process termination reparents surviving children to init or a subreaper, while
raw thread exit reparents only when the thread group loses its final thread.
The applicable contract remains `kernel.el1.thread-lifecycle`.

## Focused witnesses and pending validation

`kernel::thread_ledger::tests::prepared_parent_exit_*` covers:

- An admitted ABI birth in a two-thread live child after exit preparation.
- An admitted ExitedInZone publication and host retirement of an ABI thread.
- Membership after graph retirement but before completion publication.
- Revision exhaustion after preparation, preserving birth, topology and
  retirement credits, plus credit release when preparation is dropped.
- Rejection of a deliberately unowned participant revision change.

`prepared_task_exit_preserves_its_late_{abi_birth,zone_exit}` covers the
second terminal-settlement window directly: task2's own admitted thread
membership completes after its task exit is prepared and before retirement.

The interleavings use the real Kernel graph, lifecycle page and ledger rather
than a duplicated model. Each successful case proves exact reparenting,
membership, lifecycle state and graph invariants with a live fixture root.
Whole-task exit and process-group changes are still refused during reservation;
the live child's lifecycle gate stays Open. Additional accounting is bounded
per participating task and membership publication; no new population sweep is
introduced. Runtime ratios and signed spawn acceptance are not claimed.

Verification commands and receipts are kept under
`target/n1g6/terminal-settlement/`. Before push, run the focused kernel tests,
recapture inventories on the committed clean source, then `just ci` and
`just test-loom`. Signed execution remains held by the director.
