# N2 L1 red witness handoff

Preparatory tests only, based on main `b1167c6e19811c5b3a601d979cedca844656454f`
and the readiness plan fetched from draft PR #25. N1 is not accepted and
there is no N2 driver. No production path, registration, shared integration
file or contract descriptor changes. No readiness row is closed.

The auto-discovered target is
`crates/carrick-kernel-example/tests/n2_readiness_task.rs`. All three tests
carry `#[ignore = "N2 red witness: ..."]` as explicitly requested for this
preparation phase. Ordinary target success does not mean these assertions pass.

## Witnesses and observed reds

Each test completes all three scales before the final assertion. Two parent
tasks remain live in one kernel graph. The robust scripts also retain the root,
hold both parents through all rounds, and verify identical buffer VAs in their
independent MMs. No pool override, retry or increased timeout is used.

| Witness | Readiness row / contract | Observed red on the base | Production change needed |
| --- | --- | --- | --- |
| `delayed_birth_after_exec_cannot_publish_predecessor_edges_at_1_8_32` | 1/13; `kernel.el1.thread-lifecycle`, creation-native-path obligation | With 1/8/32 prepared births per parent, exec publishes a distinct MM and file table, then delayed `record_birth` / `settle_thread_ledger` publishes **[2, 16, 64]** stale threads, required **[0, 0, 0]**. Their exact keys are discoverable and retain the predecessor file table. | Bind birth custody to the exact predecessor execution/resources and cancel stale claims across exec. The one extracted production publication core must enforce this on ledger settlement as well as direct host clone commit. |
| `robust_list_death_marks_owned_words_in_two_live_mms_at_1_8_32` | 2/4/7; `kernel.el1.thread-lifecycle`, robust death / futex composition | After successful robust registration/readback and clear-TID join, **[2, 16, 64]** owned words lack `FUTEX_OWNER_DIED`, required **[0, 0, 0]**. | Bind the real Linux robust-death operation to retirement before completion becomes observable, through the same extracted production core at the public backend and owner venues. Do not add a fixture-only walker. |
| `robust_pending_death_marks_owned_words_in_two_live_mms_at_1_8_32` | 2/4/7; same family | The head is empty but `list_op_pending` names the acquired word. After clear-TID join, **[2, 16, 64]** words lack `FUTEX_OWNER_DIED`, required **[0, 0, 0]**. | Include the pending-operation word in that same retirement operation, with exact MM/thread custody. |

Linux authority: [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
for removal of sibling threads and file-table unsharing;
[set_robust_list(2)](https://man7.org/linux/man-pages/man2/set_robust_list.2.html)
for death notification of owned futexes. The robust fixture builds real guest
list data using public `Layout` operands and pipe copies, checks registration
and the signed futex offset, then reads the resulting word through the
dispatcher. Clear-TID supplies a bounded, independent completion handshake;
these tests do **not** yet prove robust waiter wake cardinality.

The first witness exposes a public graph admission/custody hole, not proof
that a currently admitted EL1 task reaches that schedule. The two robust reds
expose the scripted backend's measured retirement deficit: it currently clears
TID but does not invoke robust cleanup. They do not establish signed runtime
behavior. Preserve the observations when wiring the
production core; merely making the example simulate expected bytes is invalid.

## Existing controls and explicit reuse

Unchanged `n2_task_transactions`: **8 passed**. It already pins failed
acquisitions and prepared-drop rollback (including MM/resource references and
uid claims), clone during exec close, shared/private edges, durable delayed
status, and exact vfork release. Those passing cases are controls, not new reds.

Unchanged `n2_task_lifecycle --ignored --nocapture`: **4 failed as expected**,
all against zero host task-service entries at 1/8/32:

| Reused red | Observed entries |
| --- | --- |
| `exit_group_budget_red` | [4, 18, 66] |
| `reparent_reap_budget_red` | [14, 58, 199] |
| `wnohang_echild_budget_red` | [14, 90, 328] |
| `sa_nocldwait_budget_red` | [12, 65, 203] |

Wait counts include actual dispatcher retries/resumes and can vary with the
schedule. These are the recorded run's observations, not replacement budgets.

## Dependencies that cannot be manufactured here

The existing scripted driver explicitly refuses process/thread TID stores;
public graph failpoints cover acquisition stages, not fallible MM/fd/TID
publication or Linux copyout ordering. N1 UserTransfer and a driver-owned
production binding must provide those fault seams. Dropping a prepared birth
is already a green control and is not a new TID-fault red.

Recycled-task notification already has its own exact-key contract and runtime
binding (`kernel.wait.child-exit-notification-lifecycle`); the delayed birth
test adds the distinct same-task, successor-resource case. No duplicate queue,
fake zero counter, invented MM owner API or new contract registration was added.
Driver must reconcile `kernel.el1.creation-native-path` from N1 (absent on this
base), bind the extracted core, and remove ignores only when these same
observations pass. Signed routing, robust wakes, group-wide cleanup, default
executor exhaustion, atomic TID publication and native Linux oracle evidence
remain open. No HVF or Docker execution is claimed.

## Reproduction and receipts

Source `/Volumes/carrick/dev/env.sh` in the worktree first. Foreground runs:

```sh
CARRICK_RUN_ID=n2-l1-red-birth cargo test -p carrick-kernel-example --test n2_readiness_task delayed_birth_after_exec_cannot_publish_predecessor_edges_at_1_8_32 -- --ignored --exact --nocapture
CARRICK_RUN_ID=n2-l1-red-list cargo test -p carrick-kernel-example --test n2_readiness_task robust_list_death_marks_owned_words_in_two_live_mms_at_1_8_32 -- --ignored --exact --nocapture
CARRICK_RUN_ID=n2-l1-red-pending cargo test -p carrick-kernel-example --test n2_readiness_task robust_pending_death_marks_owned_words_in_two_live_mms_at_1_8_32 -- --ignored --exact --nocapture
CARRICK_RUN_ID=n2-l1-red cargo test -p carrick-kernel-example --test n2_task_lifecycle -- --ignored --nocapture
CARRICK_RUN_ID=n2-l1 cargo test -p carrick-kernel-example --test n2_readiness_task --test n2_task_transactions -- --nocapture
```

The four red commands each exit **101**, selecting respectively 1/1/1/4 tests
that fail their intended assertions. Logs on cloudmac:
`/tmp/n2-l1-red-{birth,list,pending,lifecycle}.log`.
The ordinary command exits **0**: 8 passed, 3 preparatory reds ignored;
`/tmp/n2-l1-controls.log`. The ordinary lifecycle target also passes (4 passed,
4 ignored), `/tmp/n2-l1-lifecycle-control.log`.

`CARRICK_RUN_ID=n2-l1-clippy just clippy`,
`CARRICK_RUN_ID=n2-l1-fmt-check just fmt-check`, and
`CARRICK_RUN_ID=n2-l1-lint just lint-domains` all exit **0**;
logs `/tmp/n2-l1-{clippy,fmt-check,lint}.log`. Authority capture checks all three
macOS profiles (618 reviewed rows); other host profiles remain outside this
host's receipt. Scoped `scripts/sudo/kill.sh` cleanup reports zero remaining
guests, `/tmp/n2-l1-cleanup.log`. Pre-push CI is reported separately in the PR.
