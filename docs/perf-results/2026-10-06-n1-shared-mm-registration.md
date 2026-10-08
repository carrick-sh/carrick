# N1 shared-MM directory lifetime

Base: `347be17151617a9772172438e837468b3f446ca6`.
This repair has no signed verdict and does not establish parity with main
`65098ea0e`. The last exact signed stack, `fa98b9f9c`, remains red.

## Qualified defect and scope

Task activation registered each native MM projection independently. A
CLONE_VM sibling's registration destructor removed the shared directory row
even when another registered task still used that exact MM and access state.
The initial task and a committed exec successor also published identities
without holding their own registration claims. The initial root's closed
first-load publication is distinct: it runs with user-memory admission held
and cannot call normal identity installation, which may promote an owner.

These are production source defects reproduced through the native directory
and the extracted, unchanged task-publication helpers. The older incomplete
`fork-fa98b9f9c/owner-fault-retained.trace` contains owner grant-supply phase 3
(missing physical binding) observations, but its exact live cause has not
been attributed to this defect. That trace remains incomplete; no repaired
guest workload or probe closure is claimed here.

The correction is in fork/CLONE_VM MM custody. It changes no file-table lease,
clone-TID, clear-child-tid, anonymous-brk or copyout policy. Existing grant
selection and descriptor receipt protocols remain unchanged.

## Repair and contract

Each exact MM/state directory entry holds a weak reference to one shared
registration owner. Task claims retain that owner. The final claim removes
only the entry whose MM, state allocation and owner allocation all match.
Weak allocation identities prevent a stale destructor from removing a
successor; state expiry does not leave a historical row.

The task claim moves with the whole execution state, including worker swaps.
Successful child activation transfers its temporary backend claim into that
state; activation failure drops only the temporary claim. Initial and exec
publication install a task claim after retaining the exact successor, then
release the predecessor outside the claim mutex. An independent live peer
keeps its predecessor MM. Closed first-load publication retains the same
shared owner without promoting through user-memory admission.

Contract: `kernel.el1.thread-lifecycle`. Linux CLONE_VM sharers keep access
to their common address space after another sharer exits; exec replaces the
caller without retiring a distinct peer's MM. The VM-free teardown witness
requires zero historical directory rows after the final claim, even if the
access state expired first. No work budget, timeout, scale point or guest
concurrency changed. These tests do not register a new runtime cost claim.

## Red-first evidence

Receipts are under
`/Volumes/carrick-build/evidence/n1-cm/main-match-20261005/`.

| Receipt | Behavioral negative |
| --- | --- |
| `sibling-registration-red.log` | One retired sibling removes another live registered task's MM: MissingBinding. |
| `root-registration-red.log` | Initial-task and exec-successor publication both lose their MM after sibling retirement: two independent MissingBinding failures. |
| `closed-registration-red.log` | Closed first-load publication loses the initial task's MM after sibling retirement: MissingBinding. |
| `expired-registration-red.log` | Restoring the pre-fix expired-state early return leaves a historical directory row after the final claim. |

The first three receipts precede their corresponding implementation changes.
The expired-state control reverses only the former teardown early return
against the new shared-owner representation; it is not a live guest
observation. The compiler-error attempt `sibling-registration-green.log`
is retained and excluded from both red and green claims.

Restored focused receipts pass all three task-publication witnesses, all
three owned-registration witnesses (including exact refresh and stale
successor preservation), and the existing first-load backing/admission
witness. `shared-mm-final-verify/` records broader restored verification.
All 753 runnable HVF tests and 709 runtime tests pass (12 existing ignored).
Contract validation reports 98 contracts, 16 claims and 175 surfaces;
fmt-check and workspace all-target clippy pass.
Read-only review found no confirmed safety or lifetime blocker; its test-only
helper dead-code concern was addressed with the existing support cfg.

Concurrent last-drop races, real EL0/MMU execution, the older trace's phase 3
attribution, signed fork workloads and main-result parity remain unqualified.
A director-published exact bundle is required for the next signed cycle.
