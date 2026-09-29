# IPC development integration (unaccepted)

Join adapter b0313df83 with host 77b6f40a1. The merge is development work,
not checkpoint acceptance or a merge to main. The adapter alone and joined
runtime compile checks passed. The existing host blocking-eventfd witness
initially failed with EAGAIN when an owned continuation was required; that red is retained below.
Initial joined IPC tests completed: 53 passed, one ignored and the same blocking-eventfd continuation test failed. No other failure was reported. Generated compiler capture remains the
prior adapter snapshot and must be refreshed at stable source qualification.

Current controller: ../wt-batch3/docs/superpowers/plans/2026-09-26-el1-completion.md
in the sibling worktree (user-requested priority reset). Finish owned blocking
operations and descriptor lifecycle, then qualify the five signed IPC tests.
Lifecycle historical failures and full final acceptance remain open.

## Runtime backing integration

Source inspection found `host_window_backing` still returned `None`, preventing
the existing runtime registration path from exposing the shared IPC authority
to EL1. It now returns the same kernel-owned `Arc<HostIpc>` through the backing
trait. The focused `serial_host_el1_ipc_runtime_backing_retains_the_kernel_authority`
test failed at backing admission before the fix and passed afterward (1/1).
It checks pointer/extent identity, access to the existing eventfd after dropping
the dispatcher/kernel references, and final release of the retained owner.
Logs: `backing-red.log`, `backing-green.log`. This is a VM-free ownership proof,
not signed mapping or checkpoint acceptance. The blocking-eventfd correction is described below; descriptor publication and
owed-host-wake integration remain open.

## Host-originated blocking eventfd write

The retained baseline `joined-tests.log` has EAGAIN instead of an owned wait.
The correction uses the existing BlockingWrite continuation with a captured
scalar and functional FileDescriptionFdLease; its transfer still calls the
shared eventfd core. Object waits subscribe to the existing WaitQueue, do not
contribute host pollfds, and probe once after enrollment to close the gap.
Ready events resume the owned write instead of resolving the numeric fd or
rereading guest memory. A still-blocked resumption returns the same owned
operation. The single-task runner bridges that queue to its existing waiter;
the production carrier releases executor capacity via CarrierWaitService.

The original retained-value witness now passes. Added fd-reuse and pre-enrollment
capacity-drain coverage also passed in the 57-pass IPC suite (one pre-existing
ignored test). The continuation regression suite passed 90/90; runtime check
and workspace formatting check passed. Exact logs accompany this file. The final 57-pass IPC run additionally asserts that the wait does not enter the reactor's host-fd
population. These are development checks, not signed checkpoint acceptance.

Next: publish descriptor tables through create/fork/unshare/destroy and descriptor
mutation, wire owed host wakes, integrate the fixture branch, then run the five
signed guest IPC witnesses. These checks were captured before the development integration commit.

## Guest-to-host wake delivery

The unregistered process-global wake callback was a no-op. A red kernel test
observed zero callbacks after an EL1-style shared-object publication and host
boundary. The runtime now passes its exact Kernel; that kernel drains its own
IPC pending index and authenticates/consumes owed flags under object locks.
The obsolete global hook and its inventory row are removed.

ABI v3 adds a two-level atomic pending bitmap. Publication sets the object bit
before its summary bit; a bounded host batch visits only indexed candidates.
Repeated writes coalesce. A publication during delivery remains indexed for a
later batch. Layout hash includes the new fields; stale layouts fail closed.
The ABI suite passes 21/21, including one candidate for eight writes among 128
live objects. The final kernel IPC suite passes 58 with one pre-existing ignored
test, including kernel isolation, exactly-once delivery, retirement/reuse and
preservation of a successor notification. Formatting and ABI/kernel/runtime Clippy pass. Logs: wake-red.log,
wake-abi.log, wake-kernel-final.log. Signed guest execution remains unqualified.

Descriptor tables are still unpublished: FileTable has no shared descriptor
binding. Next integration must connect its admission, mutation, fork/unshare,
CLOEXEC and destruction to the shared core before publishing IpcTableMap entries;
a one-time snapshot would leave a competing stale namespace and is insufficient.

## Descriptor lifetime admission

Eventfd admission now creates one pinned shared description. The host owns that
pin; installed shared slots and guest operations retain the same OFD. Last host
close drops its pin instead of freeing the object directly. Only the shared
core's final release retires the backing. Failed OFD admission releases the
new object before returning an error.

The admission witness first failed at the explicitly missing shared-install
bridge (StalePin); after implementation it proves that a guest operation keeps
the eventfd alive across closing its shared slot and the last host reference.
It verifies exact holds (two pins then one), preserved counter contents, and
retirement after the final guest pin. An exhaustion test fills all 2048 OFDs,
refuses eventfd admission, then proves all 1024 object slots remain available.
Final kernel IPC: 60 pass, one existing ignored. This does not publish a table
or complete flag/fork/unshare ownership. Receipt: description-final.log.

## Fixture branch review: not accepted

Source-reviewed `work/cp3-ipc-fixture` at fd27e748d; not merged. In
fixtures/embed-el1-sched/src/ipc.rs, run_threads_topology and
run_two_process_topology derive guest_parks/resumes and host counts from
is_el1_ipc_active and the loop count, rather than observing them. Output fixes
carrier/task/object generations to 1 and labels the window steady-state.
The signal-restart mode runs the same exchange without installing/sending a
signal or exercising partial writes. fd-lifetime duplicates descriptors but
falls back silently on failed dup and does not force blocked-close/reuse.
The embed runner samples whole-container counters, including startup/teardown,
while describing those measurements as the steady-state window.

These fixture reports cannot establish the named acceptance obligations.
Retain their useful workload scaffolding/contracts, but replace these claims
with actual semantic cases and scoped observations before signed acceptance.
Do not add a control response that simply turns the derived counters green.
This review changes qualification planning, not the implementation priority:
continue shared table/description ownership; repair fixtures at that boundary.

## Shared pipe endpoint lifetime

Anonymous pipe creation now admits two shared OFDs before publishing endpoints.
Host functional references retain the corresponding host pin. Guest descriptor
slots and operation pins retain the same OFD; the last host close therefore
cannot manufacture EOF while a guest writer is still alive. Final shared release
retires the endpoint and delivers both guest and host readiness outside locks.
Creation rolls back both raw endpoints and any admitted OFD on refusal.

The writer witness failed at the missing shared-install bridge, then passed:
close shared slot, close host writer, retain one guest pin, transfer the expected
bytes, release the guest pin, observe EOF, and retire the reader. A second-OFD
exhaustion test proves all object slots remain available and pipe storage is
reusable after repeated refused admissions. Initial pipe regressions: 87/87.
Final IPC filter: 62 passed, one pre-existing ignored. Kernel/runtime Clippy and
workspace formatting passed. Receipts: pipe-description-red.log,
pipe-regression.log, pipe-description-final.log, pipe-description-clippy.log.

Tables remain unpublished. Shared flags and FileTable admission/mutation,
fork/unshare, CLOEXEC and destruction are the next implementation boundary.
No signed guest execution or checkpoint acceptance is claimed here.
