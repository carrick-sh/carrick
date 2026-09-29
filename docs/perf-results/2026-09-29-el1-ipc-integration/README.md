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

## Shared descriptor flags

Pipe and eventfd FileDescriptions now bind their DescriptionCommon to the
existing shared OFD. Supported mutable flags (APPEND/NONBLOCK/ASYNC) and access
mode are read from that record. F_SETFL and ioctl updates write its flags;
there is no second mutable host word for these bound descriptions. Rebinding
the same common view does not reset admission-time flags. Other description
kinds retain their existing authority, and existing DIRECT/NOATIME limitations
are unchanged. The host-side observation retains no functional pin: final
host close snapshots terminal flags and unpins even if diagnostic Arcs remain.

The first witness failed because a nonblocking host eventfd admitted blocking
shared flags. Final witnesses prove host-to-guest and guest-to-host changes,
alias binding without reset, independent pipe-end flags and preserved access
modes, and guest-pin retirement despite retained host observations.

A native ARM64 Linux control on the retained python:3.12-slim image reports
F_GETFL=2050 for eventfd(EFD_NONBLOCK): RDWR=2 plus NONBLOCK=2048. Host eventfd
reporting had omitted RDWR; reading the shared access mode corrects it. Command:
`docker run --rm --pull=never --platform linux/arm64 python:3.12-slim python3 -c
'import os,fcntl,platform; print("machine="+platform.machine()); fd=os.eventfd(0,os.EFD_NONBLOCK); print("eventfd_getfl="+str(fcntl.fcntl(fd,fcntl.F_GETFL))); print("rdwr="+str(os.O_RDWR)); print("nonblock="+str(os.O_NONBLOCK)); os.close(fd)'`.
Image identity: flags-oracle-image.log. This control is not a full differential
or signed acceptance receipt. No Carrick guest was launched in this change.

Final checks: 64 IPC tests passed, one existing ignored; 89 pipe, 9 eventfd and
6 fcntl regressions passed (these populations overlap). Kernel/runtime Clippy
and workspace formatting passed. Flags logs are retained alongside this file.
The initial Clippy check found ambiguous arithmetic/bitwise precedence; explicit
parentheses corrected it before the final checks. Shared descriptor table
publication/create/mutation/fork/unshare/CLOEXEC/destroy remains unfinished.

## Atomic slot replacement and owned table lifecycle

The shared core previously exposed only empty-slot pin installation. The new
replace_pin uses the same locked replacement transaction as dup2/dup3; retaining
the incoming description first prevents alias retirement. An occupied target
now changes atomically, without a close/install gap. Final displaced backing
is returned to the venue for release outside the descriptor lock. The initial
witnesses failed with TooManyFiles; final core tests pass 27/27, including
foreign-pin and capacity refusals with unchanged contents/flags/holds.

HostTable owns one admitted shared table and its storage. It supports growth,
fork, atomic replacement, close, exec and destruction through the existing core.
The retirement witness initially observed BadFd after dropping an empty child,
instead of StaleTable: the table identity had not been reclaimed. Teardown now
invalidates the table and returns its extent. Collected final releases run only
after leaving core locks; storage for the collection is reserved before locking,
bounded by min(table capacity, OFD capacity). A bounded-lock reentry witness
checks final host-resource destructors after exec and table destruction.

Additional checks prove a replaced operation pin still accesses its original
eventfd, fork preserves its slots, CLOEXEC does not touch the parent's successor,
and repeated fork/grow/drop cycles beyond the 256-table identity capacity recycle
all storage. Review caught a consumed-extent trap in the initial fork adapter:
on success the source extent is cleared, and its token zero must NOT be reclaimed
because pool offset zero may belong to the live parent. Reclamation is now only
on failed fork; the storage witness checks three distinct live allocations.
Final kernel IPC filter: 67 passed, one pre-existing ignored.

HostTable is not yet attached to kernel FileTable. Table publication and the live
namespace mutation/lifecycle wiring remain open. These are development checks,
not signed guest execution or checkpoint acceptance.


## Live FileTable publication and host-token retirement

Production FileTable now owns a shared HostTable binding. Initial publication
includes all real slots and implicit stdio; insert/remove/mutable-slot guards
update only touched slots, and descriptor storage grows geometrically. Bare
stdio close/CLOEXEC changes update the same projection while explicit slots
retain priority. Fork and exec tables admit their own complete namespace on
first use. Functional retirement withdraws and destroys shared table identity,
even if diagnostic FileTable Arcs survive. Admission failure withdraws the
entire namespace and retains host service, without a full-table retry on every
syscall. An independent fork/exec namespace can attempt admission again.

Runtime boot and syscall entry publish the current table only into a mapped
IPC window owned by the same Kernel. The first red FileTable witness refused
publication (NoMemory). The implementation now passes mutation, guest-pin,
stdio, growth, fork/exec, teardown and storage-refusal checks. A real dispatcher
creates an eventfd whose shared guest view reads both its initial value and a
later host write; close removes the slot and retires the object. Final focused
serial IPC filter: 29 passed. These are VM-free observations, not guest execution.

Host-backed descriptions have one forwarding OFD pin tied to functional
lifetime. A real completion witness found that final Host tokens were ignored
by IPC handback completion: its release count was zero rather than one.
Completion now validates the exact Kernel mapping before effects and releases
the owning Kernel's token once. A second Kernel with the same numeric token is
rejected before consuming the operation. Cancellation uses the retained
Kernel owner without requiring the cancelled task's context to resolve.
Prior focused completion checks: 88 passed; IPC 69 passed, one existing ignore;
affected Clippy and formatting passed.

The first broader kernel regression had 2,197 pass, one existing ignore and one
failure in status_flags_are_one_value_owned_by_description_common. It expected
F_SETFL to erase eventfd O_RDWR. The retained flags-oracle.log proves O_RDWR=2
is present with NONBLOCK=2048; expectations now preserve that access mode when
mutable status flags are set or cleared. The failed output remains retained.

A new signed el1_ipc_live_routing test performs 1,024 pipe and eventfd round
trips, checks bytes/values and reads actual EL1 served/forwarded counters. It
makes only a whole-run routing claim; it does not fabricate parked operations,
claim a scoped zero-exit window, or replace the five full vertical witnesses.
Signed execution, full CI, inventory reconciliation and promotion are pending.

Final development regression: just test-kernel passed (2,198 kernel tests,
one existing ignore, then all kernel-semantics suites); serial host tests
passed 138/138. No guest execution was concurrent. Affected ABI/kernel/runtime/
embed Clippy passed before the final test-only O_RDWR expectation correction.


The first signed routing run on 5cc3b64a6 completed correct data transfers but
failed: served read=6/write=0, forwarded read=2052/write=2049. Entitlement
negative control passed; both scoped cleanup populations were zero. The
runner did not publish its failed manifest, so the still-unchanged failing
executable was copied and independently fingerprinted before any rebuild;
see live-routing-red-artifact.json and the preserved target path. The
prerequisite scheduler fixture lockfile gained the fd/pipe core dependencies;
its exact delta is retained separately. No promotion claim uses this run.

Source tracing found the direct routing blocker: IPC backing was registered
from the loader's temporary bootstrap Kernel before initialize_root_process
rebound the dispatcher to the authoritative HVPatch graph. Exact-owner
publication therefore correctly refused the mapped foreign authority.
Registration now occurs at the authoritative executor launch before window
installation, and that root's FileTable is published after mapping, before
its start gate opens. The earlier bootstrap registration/publication is
removed. The same signed witness must now prove this correction.


### First live routing milestone (not vertical acceptance)

On clean source e6e2ab3bf, the unchanged signed witness passes: 1,024 pipe
round trips plus 1,024 eventfd round trips return exact bytes/values. Actual
whole-run EL1 counters report served read=2054/write=2048, forwarded
read=4/write=1. The prior artifact reported forwarded read=2052/write=2049
and served read=6/write=0. These counts demonstrate production routing;
they are not steady-state exit attribution or a native-Linux timing ratio.

Run el1-ipc-routing-20260929-b has one positive signed execution, a passing
unentitled negative control and zero scoped leftovers. The source is clean,
and the tested executable SHA-256 independently matches the official manifest:
e1c036c86ac45cdc93b2ceec8a5c05fb7298d6afa1110d77368608b2390a010e.
Its tested bytes are preserved at the absolute path in
live-routing-preserved.json. Full output and the official receipt are retained.

Next: real blocking/park/wake, close/reuse, mixed-venue and signal/partial-write
witnesses at the required scales and two-process shapes. The rejected fixture
reports remain rejected. Full CI/inventory reconciliation, native-Linux cost
and complete promotion remain open; main is unchanged. No checkpoint closed.


## Blocking IPC execution

The first signed two-thread pipe-pingpong check passed, including an assertion
of at least 256 real EL1 parks and EL1-served reads/writes across 256 measured
rounds plus the existing warmup. Entitlement negative control and scoped
cleanup passed. This initial development run used an uncommitted test on
ab5ec3e1d; the manifest does not capture that test delta, so retain it as a
diagnostic result, not promotion evidence. Tested bytes were preserved in
target/el1-ipc-blocking-initial before any signed rebuild.

The next committed witness reuses the static scheduler fixture and adds real
request/response IPC pairs at 1/8/64 for both pipes and eventfds. Every payload
carries pair/round identity and each response is checked. Guest output counts
completed checked operations only. The embed runner reads real whole-run
EL1 park and served/forwarded counters; no feature flag or loop count creates
an execution observation. Scoped zero-exit, two-process, descriptor reuse,
signal/partial-progress and full vertical acceptance remain open.


The first committed scale run (9055c465b) passed pipe N=1, with 258 actual
EL1 parks. Pipe N=8 completed all 1,024 checked round trips with 2,056 EL1
parks, but only 2,047 of 2,048 writes were served in guest (one data write
forwarded, plus the output write). Its strict whole-run served-write assertion
failed and prevented N=64/eventfd from running. Preserve that red; no bound is
weakened. The runner now collects the same counter failures across the fixed
six-case population before failing, so this mismatch does not hide later
results. This is bounded coverage discovery, not retry-to-green. Admission,
lock contention, pending host work and phase boundaries remain hypotheses
for the forwarding; no root-cause or scoped zero-exit claim is made.

Unrelated rustfmt churn in the standalone fixture main file was removed,
leaving only the intended module/mode additions relative to ab5ec3e1d.

## Blocking population: capability demonstrated, acceptance still open

Signed source `c1c17d963`, run `el1-ipc-pairs-20260929-b`, completed all
six pipe/eventfd populations at 1/8/64 pairs and 128 rounds. Each population
checked payload identity and completed 128/1024/8192 round trips. Real EL1
parks were pipe 258/2065/16514 and eventfd 258/2061/16512. The entitlement
negative control passed and scoped cleanup was zero. Official manifest and
raw log are retained beside this file; tested bytes were independently
hash-checked and preserved at the path in `pairs-population-preserved.json`.

This does not clear `pairs-first-red.log`: the earlier pipe-eight population
completed its data checks but missed the served-write bound by one. No
product fix separates these executions. The runner now collects unchanged
counter assertions across the fixed population rather than stopping early.
Whole-run generic counters can count park/resume entries and do not prove
unique completed operations, scoped zero IPC host exits or timing ratios.
Forwarding variability remains an acceptance blocker. No retry-until-green
claim or full checkpoint acceptance is made.

Next: real blocked close/reuse and two-process functional witnesses, then
mixed host/guest operation and signals with partial progress. Keep exit
attribution bounded and separate from independent capability development.

## Two-process inherited IPC: first signed execution is red

Source `15021dfb8`, run `el1-ipc-processes-20260929-a`: pipe one-pair
completed 128 checked round trips with 257 guest parks. Pipe eight-pair
hit the unchanged 60-second watchdog. The census shows four idle-WFI slots
and parked tasks spanning both address spaces. It also reports one lost
adoption and one address-space refusal; these are observations, not a
root-cause attribution. Later scales/eventfd did not run. Entitlement
negative control passed; scoped cleanup found zero processes.

Raw census/output and post-run executable fingerprint are retained in
`processes-first-red*`. The exact failing bytes are preserved before any
rebuild. No product fix, retry or acceptance is claimed. This concrete
cross-process blocker takes priority over generic counter attribution.
Next: inspect existing wake/handback ownership and reduce the parked state
using existing scheduler/IPC contracts; no new diagnostic framework.

## Unplaceable guest wake correction, remaining eventfd failure

`8c9617950` removes a proved ownership gap: object readiness could leave
an unplaceable waiter parked with only a pending-host flag and no specific
delivery owner. The existing scheduler fallback instead queues its owned
operation and requests misplaced handback. The deterministic regression
fails before (queued=0), passes after; all 62 scheduler-core and 14 focused
EL1 IPC tests pass. An initial exact-name invocation selected zero tests
and was not counted; the subsequent selected test supplied the red.

Unchanged signed run `el1-ipc-processes-20260929-b` completes pipe at
1/8/64 pairs and eventfd at 1/8 pairs, with every payload checked. Eventfd64
hits the existing watchdog: two home records with wait entries and two
remaining worker records are parked. Full test remains RED. Some completed
populations also miss the unchanged served-write bound; no zero-exit claim
is made. Negative entitlement passes; scoped cleanup zero. Exact failed
bytes and complete census are preserved in `processes-wake-fix*`.

Next decisive experiment: use existing kernel post-mortem/event-ring capture
on the remaining eventfd case to identify the two workers' wait ownership.
Do not rerun until green or assume the first correction explains this state.

## Existing post-mortem capture narrows remaining eventfd stall

One diagnostic execution of the preserved `8c9617950` binary, without
rebuild/re-signing, enables `CARRICK_POSTMORTEM_DIR`. Run
`el1-ipc-processes-capture-20260929` stalls at eventfd8 after pipe1/8/64
and eventfd1 complete. This is timing-dependent, not limited to eventfd64.
The capture has no truncation markers or findings. Worker serials1742/1766
are enrolled on zone-record continuations960/962, records3#89 and5#63.
Only eventfd descriptions301/302 remain, each with two functional fd refs;
both process tables retain fd9/10. Raw captures and extracted facts are
in `processes-capture/`. Scoped cleanup confirms zero remaining processes.

The graph has no eventfd counter or saved IPC operation payloads. These
observations do not distinguish missed wake, consumed operation or replay.
Next is a bounded LLDB capture of those existing values on the authoritative
carrier, not new counters, repeated acceptance attempts or another framework.
