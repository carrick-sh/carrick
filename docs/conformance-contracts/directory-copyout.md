# Directory copyout into untouched private memory (#759 stage 2)

`kernel.fs.directory-copyout` covers record publication and the selected
open description across an owner-memory wait. The director's signed Python
log at `c94769c21` reaches importlib `_fill_cache` and reports EFAULT for
`/usr/local/lib/python3.12`; that log alone does not identify the syscall.
The production getdents64 path submits the entire assembled result to
`write_bytes`; the ARM owner adapter passes it to `prepare_owner_write`,
whose production `PreparedStreamRanges` admits at most 4096 bytes. Larger
results become `HostMap`, then the blanket MemoryError conversion lowers
that internal condition to EFAULT. Untouched pages can also return a typed
supply/wait through this same unsuitable direct-copy path.

The VM-free RED witnesses use the production directory encoder and bounded
PREPARE admission, plus an actual immutable HostFs lower directory and sparse
AddressSpace. The first fault consumed all 402 entries before copyout:
retry into a never-touched private buffer returned zero (`exit 101`,
`/tmp/759-directory-red.log`). The bound witness checks the actual encoded
batch through production admission; it does not simulate an ARM backend.
The signed `case_libpython_directory_copyout` reports openat/fstat/getdents64
separately for mmap and malloc buffers. Its pre-fix owner failure, exact
ARM64 oracle bless, runtime work/timing and Python startup verification remain
explicit director gates on the Mac; this Linux worker cannot claim them.

The reviewed stage-2 repair splits complete records at guest-page/transfer
boundaries, calls the existing owner `prepare_write`, commits bytes, then
advances the shared description cursor. A refusal before progress retains the
exact description lease and thread, drops the description guard, and uses the
existing supply/owner-zone resume machinery. A refusal after progress returns
only the complete records already delivered. Internal preparation failures are
runtime errors; only `OutOfBounds` becomes EFAULT. EOF does not access the
buffer. No owner permit or editor guard is stored in `OwnedDirectoryRead`.

Directory I/O retains its selected description in the existing owner-resume
route. Owner receipts, supply and physical dependencies all settle through
#802's shared `OwnerWait`; there is no directory-specific wait adapter or
cancellation query. Resumption consumes the saved operation and releases its
physical dependency before preparing a new destination. Fatal settlement
releases the operation without output or cursor progress.

Secured directory output acquires the same `ProcessEffect` admission as other
owner copyouts. It retains custody through bytes and cursor publication, then
releases it before the next batch. Fatal publication during re-preparation
therefore cannot authorize output from a prior readiness sample.

The VM-free bindings cover cursor retention after a real address fault,
mixed-width records at 10/100/400/4096 entries, unaligned output, existing
PREPARE limits, page-proportional work, and retained descriptions across sibling
fd reuse. Runtime bindings use production dispatch, scheduler enrollment,
shared settlement and terminal publication with real `PendingContentWrite`.
They cover unready SIGKILL, a non-leader waiter with a live leader, readiness
during enrollment, writer release before both retry paths, and cancellation
during destination re-preparation. None uses a second memory-wait path.

The committed native ARM64 oracle and its source fingerprint are preserved.
Fresh signed HVF execution, live sibling-editor contention, handled-signal
delivery, final runtime ratios and exact-artifact promotion remain
director-owned. VM-free evidence does not close those integration gates.
## Retained executable file services

`process.exec.files` covers executable source selection with retained caller
filesystem, credential, executable and descriptor-source capabilities. Two
independent callers retain those resources after their dispatchers are dropped;
ENOENT (2) and EACCES (13) remain ordinary pre-commit failures. Filesystem
syscalls and exec share the layered path resolver, and host exec consumes the
same capability API intended for ring service requests. The fixture verifies
resource lifetime and isolation, not two executing native processes. Native
transaction publication and signed replacement witnesses remain #785 work.

## Uninstalled executable backing

Native exec payload intake authenticates metadata against the exact retained
MM root using the shared AArch64 translation path. The VM-free
`native_exec_payload_authenticates_a_live_metadata_block` was red when the
host-only walker rejected a valid L2 block. It now resolves the occupied
page in three descriptor loads without reading an absent L3 table; signed
fork/exit/exec composition remains required.


`process.exec.backing` covers the physical preparation leaf shared by the
existing host exec mapper and its extracted owned preparation. Two real private
file views survive descriptor closure without sharing writes; dropping one
releases only its mapping. Invalid anonymous extents return EINVAL (22) and leave
an independent preparation intact. Sparse payloads retain their offsets and
zero tails without a full-extent copy. The initial witness is API compile-red.
These tests do not prove service admission, successor-MM publication, aggregate
IPA/root-slot rollback, or two executing native processes; those remain #785.

The aggregate `PreparedExecBacking` retains the exact carrier and owns every
prepared region, unmapped IPA lease and checked-out pooled root slot. Host exec
consumes it before stage-2 installation. Its VM-free macOS unit fixture forces
a second-region failure and compares the real IPA ledger while another prepared
image stays live. Linux cross-checks this fixture but cannot execute it; pooled
root recovery and unpublished successor-MM rollback are not covered by it.

## Prepared native service delivery

The scheduler service contract also covers custody-bearing responses. A ticket
transfers its prepared resource to an established recipient under the same exact
identity reservation as completion publication. Cancellation before transfer
returns both resource and ticket; failed cleanup retains them without an ACK.
Cancellation after transfer leaves the recipient responsible for the resource.
The two-request VM-free witness covers independent completion and stale MM or
sequence refusal. This transport primitive does not authorize exec adoption or
claim native loader/new-MM integration.

## Retained unpublished MM publication

`kernel.mm.address-space-occupancy` now also covers closed successor publication
through a retained carrier venue. Two independent ABI regions reuse the same
numeric MM key: dropping one successor releases only that carrier's reservation
root and COW settlement, while the other remains closed and retained. The
successor exposes neither initial binding nor an opening operation. A refusal
witness checks the final retained reference is released; the host-provider
witness runs both with normal policy and `CARRICK_EL1_MM_SWITCH=0`.

These are publication-component witnesses. They do not prove image import,
physical installation, ring exec adoption, or two running native processes.
The HVF two-carrier COW-pool witness additionally checks exact mapping selection,
retired-generation refusal and weak registration lifetime; Linux can compile
that macOS-only fixture but cannot run it.

The successor reservation-import witness rejects overlapping prepared mappings,
returns the still-owned closed successor for retry, and leaves a peer's admitted
root intact. Successful import issues the exact carrier/MM/incarnation handle
but keeps the execution gate closed. The host admission adapter calls the same
`Reservations::import_image` operation; its node-exhaustion witness verifies
rollback returns nodes rather than confusing allocator high-water with live use.
This still does not prove installed physical backing or exec commit.

## Abandoned metadata waits during sibling exit (#978)

`kernel.el1.deferred-handback-identity` also covers metadata wait receipts
abandoned before resume. Their token owns no external endpoint pin, so the
exclusive cancellation owner retires the receipt before recycling its record.
A producer still transferring the record retains custody until its existing
completion boundary; cancellation never frees underneath that producer.
The VM-free witnesses require one incarnation advance and zero orphan ready
publications, including a deferred completion and stale cancellation after reuse.
These are constant-work retirement assertions, not timing measurements.

The scheduler binding admits two live threads, parks one on the metadata
object queue, publishes the leader's task-exit intent, then uses the real
control wake and executor exit settlement without resuming the operation.
A second schedule publishes an object completion before the control wake:
the transfer already retains the request and delivers exactly one runnable
sibling on the unmodified implementation. It does not reproduce a lost control
wake or prove the idle-vCPU doorbell/kick route. No wake protocol is changed.

IPC operation tokens still retain their external descriptor pins for their
existing adapter. Calling `ipc::finish` from `ZoneWait::drop` would introduce
peer-wake callbacks under `Thread.execution` and
`Scheduler.generation_transition`; that lock-order gap is outside this
metadata-only repair. Signed `el1_files_exit_group_stress`, idle-vCPU behavior,
IPC abandonment and release runtime/oracle acceptance remain director-owned.

## Completed wait output during exit (#1009)

`kernel.memory.owner-wait` includes zero output from a completed sleep or
select wait. Completion folding retains the original result and the next
unwritten byte across Editor, supply and physical waits. It must not restart
the original syscall or convert an owner wait to a configuration failure.
Each preparation covers at most one portal-sized interval; a permit and its
process-effect custody are released before parking. Group-exit cancellation
settles through the existing owner cancellation route without another output.

The VM-free bindings `completion_owner_wait_during_group_exit_is_not_a_configuration_failure`
and `completion_owner_wait_retains_output_progress_and_original_result` drive
production completion folding with owner-refusing memory. Main returned
`MemoryError::OwnerWait(Editor)` after group-exit publication; the runtime
converted that error directly into `RuntimeError::Configuration`. The progress
binding refuses the second of three page chunks and requires exactly four
preparations, three non-overlapping commits and the original return value.
Cancellation after that refusal requires zero further preparations or commits.
A drop-sensitive physical dependency must release writer exclusion before the
next preparation, even though the pending operation also retained its receipt.
These fixtures prove the boundary, not attribution of the signed stress event.
Thirty signed `el1_files_exit_group_stress` runs remain director-owned on HVF.

The #1010 review witnesses preserve legacy timeout completion after fatal
publication, authenticate the independent ASID generation on retained output,
and drive the completion resume arm through both zone and physical parks.
The group-exit witness retains two live sibling threads: output must first
suspend on the owner refusal, then sibling cancellation prevents re-preparation.
These VM-free witnesses do not replace the director's signed stress acceptance.

## Carrier shutdown at physical entry (#978)

`kernel.vcpu.shutdown-entry` separates sticky carrier shutdown from consumable
reschedule requests. The owner publishes each physical entry before observing
shutdown, including backend-internal re-entry; shutdown latches before kicking
published entrants. Two live executor threads prove independent observations,
zero pre-entry hardware kicks and one active-peer kick. The loom binding uses
the shipping gate and retains an edge-only cancellation counterexample.

The model requires pending-entry cancellation from the backend. The director
qualified HVF: a kick completed before entry made the next run return CANCELED
immediately. Run both raw signed qualification cases on macOS with:

`just test-hvf-shutdown-kick`

Both cases run in fresh signed subprocesses. The before-entry case waits for
the sole kick to complete before running; the in-run case observes the guest's
entry marker before its sole kick. Only that diagnostic observer polls guest
memory, with a bound; production shutdown never polls. The parent kills and
reaps a run that does not return within two seconds of its entry notification,
without sending a recovery kick. A failed pre-entry qualification leaves this
candidate pending a backend latch; a passing qualification still requires the
director's signed `el1_files_exit_group_stress` on the PR artifact. The mirror
spins after its marker so raw-VM WFI trapping cannot end its run.

Closing host executors park on their CPU condvars while drain work remains.
They sample the wake ticket before checking close readiness: a final release
either makes that check return Closed or changes the ticket before sleep.
Closing admission precedes a registry write barrier and safe revocation of
unused thread-birth capacity. The pool's existing CAS preserves claimed/born
entries, whose normal settlement remains responsible for their obligations.
The VM-free binding primes actual thread pools with runtime adoption
reservations containing real process-birth submissions. Two live tasks then
exit during close; unused capacity must retire before executor joins.

An irrevocable process-exit owner also retains custody when a host control
request wins just before its futex park. The queue owner undoes the unpublished
enrollment and hands the exact continuation to that request through the existing
unswitch transition. Ordinary interruptible parks keep their refusal behavior;
foreign guards, stale bindings and absent owner continuations cannot authorize
this terminal handback. The VM-free two-live-member witness was red with
`NativeQuarantined`: the refused park reached `run_failed`, which retired the
record before reporting failure. It requires retained custody, sibling retirement
and the original exit status 0 after host re-entry. The core binding additionally
checks zero remaining wait entries and one exact handback. The pool binding runs
that same native fixture inside an executor's idle quantum, joins every worker
and requires status 0 plus clean shutdown. Its refused native entry retains the
actual execution binding through the production failure codec and one-shot
carrier consumer. These are constant-work assertions. Signed stress attribution
remains director-owned; the observed missing-record error alone cannot prove
expected group retirement rather than secondary retirement by `run_failed`.
A refused zone reload carries its exact missing `RecordRef` as a typed error.
The neutral terminal owner authenticates it against the retained member's
birth and saved zone binding. Only irreversible zone-retirement intent, committed in-zone exit or an exact
host retirement receipt authorizes terminal settlement; cancellation requests,
closed process admission and missing records alone do not. The pool witness
`group_close_retires_claimed_sibling_without_killing_executor` starts two real
Kernel threads, holds the sibling's load claim while process close starts,
retires it through Kernel thread exit and publishes its exact host retirement
receipt, then resumes the refused reload. The leader remains alive, so MM
retirement cannot supply this verdict. It requires zero guest entries for the
retired sibling and every executor joined and destroyed. Native group exit
additionally exercises the in-zone provenance in the terminal-park binding.
These are constant-work assertions; signed branch attribution and stress
acceptance remain with the director.
The neutral `TerminalCustody<Thread, Terminal>` publishes zone-retirement intent
before releasing the member's current record. This intent is distinct from the
later lifecycle receipt and is not available to `run_failed`. The core binding
`terminal_member_proof_precedes_lifecycle_receipt_after_record_release` observes
the freed continuation while the lifecycle receipt still says Active. It must
already receive a terminal verdict. Ordinary failure cleanup of an identical
record must still receive an invariant-violation verdict.
Host graph cleanup reuses the exact native member's membership ownership when
terminal intent or its committed receipt already exists. It must neither reserve
a second live unit nor retire the ABI entry again. The two-live-thread binding
`group_exit_member_graph_retirement_does_not_retire_reaped_abi_twice` publishes a
real ABI birth, retires that member natively, and then retires its host graph.
The core binding also checks this ownership while native page commit is pending.
The cleanup token pins the member control and snapshots its entry incarnation.
Host graph retirement commits that same terminal intent before removing a thread
can drop its kernel-owned Zone wait. A queued claim can acquire the still-Runnable
execution state after this cancellation frees the record. The binding
`serial_host_retirement_cancels_zone_wait_before_queued_claim` drives this actual
cancellation through Kernel, then exercises DirectLoad and clean pool shutdown
without a manual record free or synthetic host retirement receipt. Host intent
has permanent provenance distinct from native-reserved membership, including on
a refused ABI transition. Once committed, its token cannot refund live membership.
Ordinary host continuation consumption requires the exact executor lease; it
cannot overlap another valid claim of that generation and grants no terminal
intent. Generic cancellation and failure cleanup also grant no such authority.
The signed captures identify DirectLoad but do not yet join each missing record
to its physical release; the director's signed A/B remains the acceptance gate.
The terminal continuation bindings also cover a losing `exit_group` or fatal
caller with and without a pool entry, a host retirement reservation already in
flight, raw thread exit racing host graph cleanup, and whole-task removal before
raw ABI publication. Exact ABI reap custody remains on the registry ledger until
the native exit publishes; it owns one activity completion and cannot be inferred
from graph absence. The native release seam commits the member's exclusive live
reservation and terminal intent after the scheduler excludes requeue and before
freeing the record. A raw ABI admission becomes irreversible at the same point;
a later ABI refusal fails the run. The process effects owner authorizes intent
before process-exit cancellation. A shutdown request preserves native zone waits
for signal/control delivery until a terminal owner admits retirement.
The scheduler Loom binding uses production claim, release, free and absent-record
operations; it abstracts the unrelated process-owner record. The core Loom
binding uses the shipping cancellation and exact member-admission protocols to
check that competing terminal callers cannot decrement one member twice. The
VM-free schedules cover constant work per retired member and one retained raw
reap ticket per pending member. Signed 30-run acceptance remains director-owned;
these bindings do not establish a signed pass rate.

Native record retirement also owes any already-enrolled host ZoneWait a
producer notification. `serial_host_arm_exit_group_unregistered_sibling_wakes_parked_host`
drives the production ARM exit_group adapter with three actual live Kernel
threads, two parked host continuations, and a sibling switched in on another
slot. The one control wake defers to that slot; native cancellation releases
its record after host enrollment. The existing host-work doorbell carries the
terminal publisher's slot, whose retained identity indexes that member's wait
interests. The callback reuses the wait service's exact-token readiness probe;
record absence only wakes a recheck and grants no terminal authority. Enrollment
installs the interest before its existing one-shot probe. An earlier release
therefore needs no later producer edge. Slot work is consumed before another
host task load can reset its terminal identity.

The witness requires both host jobs runnable without a timer or another guest
event, exact host graph retirement, one exit-channel wake for the retained
Closing owner, and the original exit status. Every wait remains nonperiodic.
Enrollment costs one member-index insertion and one probe; retirement visits
only the released member's interests, rather than all parked siblings. The
existing unregistered-cancellation binding additionally holds a real host
membership reservation for one refusal, drops it, and re-enters the production
checkpoint: Busy emits no terminal notification, then successful release emits
one exact source. Its terminal frame stays within the existing image budget.
These VM-free bindings do not supply signed guest-instruction evidence; the
director's repeated `el1_sched_exit_group_with_parked_threads` run remains the
hardware acceptance binding.

The host executor binding
`serial_host_missing_terminal_continuation_finishes_exit_owner` holds a sibling's
DirectLoad claim across the `cancelled_on_slot` neutral retirement seam. The
closing process retains a second live Kernel member. Native retirement consumes
one membership and releases the exact record without a host receipt; the real
runtime job must then withdraw its host registry membership, publish its exact
host retirement and complete its losing-member result. The neutral process
owner must observe those receipts and settle. The fixture calls the production ARM cancellation checkpoint through a host-test
wrapper; it does not execute guest instructions.
This is constant work per member; the signed parked-thread exit-group stress
remains director-owned on HVF.

`executor_failure_after_exit_group_keeps_thread_done_and_finishes_owner`
removes a sibling through real Kernel process exit before syscall context
recapture. The failed capture must retain the member's previously admitted
exact context for executor-failure settlement. That settlement withdraws the
registry member, returns its host retirement receipt and publishes `ThreadDone`
so the neutral exit owner can complete. Guest syscall dispatch still
requires a fresh successful capture. Retirement remains constant work per
member through the existing terminal-owner path.

## Interrupted-sleep remainder publication (#986 Slice 1)

`kernel.memory.owner-wait` includes the frozen remainder from an interrupted
relative sleep and terminal errno 4 (`EINTR`). Linux nanosleep does not restart
with `SA_RESTART`. Completion output owns the original range identity and
encoded bytes; owner, supply and physical waits resume publication without
admitting another sleep or redispatching its syscall. Zero-filled timeout
output keeps its existing bounded cursor and does not allocate a byte buffer.

The kernel binding `interrupted_sleep_completion_retains_bytes_across_refusals`
requires cumulative preparation/commit counts of 1/0, 2/0 and 3/1 for a
page-contained 16-byte destination. Page crossing adds one committed window.
Physical custody must be released before the final preparation. Group exit or
fatal cancellation after either refusal permits no further preparation or
commit. Range authentication, genuine errno 14 (`EFAULT`) and null remainder
are covered separately. Existing zero-output identity and legacy fatal-timeout
bindings remain applicable.

The runtime binding
`serial_host_interrupted_sleep_completion_retains_remainder_and_eintr`
drives persistent sleep interruption and the existing owner resume routes,
including signal delivery after publishing errno 4 with no restart despite
`SA_RESTART`. These VM-free schedules do not prove real guest instruction or
signal-frame execution. Signed HVF acceptance and the applicable Linux oracle
remain director-owned; neither is available on ctb-w4.

## Shared retained output (#986 Slice 2)

`kernel.memory.owner-wait` now includes recvfrom's post-payload address-length
completion alongside completed-wait output. One suspension envelope transfers
its memory dependency by value to existing owner-wait settlement. The retained
operation owns no second dependency, memory permit or process-effect custody.
Directory reads now share this transport (Slice 3 below); IPC retains its existing route.

Every resumed operation authenticates its exact kernel/task binding, thread
incarnation, MM and independent ASID before any memory access. Identity failures
are completion invariants rather than guest errno 14. Cancellation permits no
further reads, preparations or commits. Completed sleeps preserve frozen bytes,
the bounded zero-fill cursor, terminal result and restart disposition.

Recvfrom captures execution authority before consuming payload. It reads the
address length after payload publication, including aliases. Read suspension
retains the original input continuation. Negative length returns errno 22;
once validated, only the four-byte zero-length write is retried, as one prepared
unit even across a page boundary. Its saved payload count cannot replay a receive.
The deterministic write witness requires one refused and one successful metadata
preparation and exactly one four-byte commit. Stale read/write and cancellation
witnesses require zero resumed memory operations.

The stale-task witness fails on main and Slice 1 by overwriting another live
task's addrlen with zero. This is an injected stale runtime handoff, not an
observed spontaneous guest workload failure. VM-free runtime routing and physical
settlement add custody evidence; signed HVF, Docker differential, runtime ratios
and exact-artifact acceptance remain director-owned and unavailable on ctb-w4.

## Directory reads on shared retained output (#986 Slice 3)

`kernel.fs.directory-copyout` and `kernel.memory.owner-wait` bind getdents64
publication to the same retained-output transport as completed waits and
recvfrom address metadata. The directory payload owns the selected open
description, its functional lease, destination and capacity. It holds no memory
dependency, description guard, prepared permit or process-effect custody.
Publication obtains a fresh filesystem view inside captured-resource scope;
no borrowed dispatch services survive suspension.

Owner-memory entry captures the actual execution lease's exact kernel/task,
thread incarnation, MM and independent ASID. Resumption authenticates that
binding before touching memory or the shared cursor. Legacy task memory and
carrier buffers remain lease-free and cannot admit owner-memory publication.
Genuine internal preparation failures remain dispatch errors; only a genuine
invalid destination becomes errno 14. Completed-wait initial publication and
folding retain their narrower completion-invariant error type.

The directory encoder, complete-record batching, page and 4096-byte bounds,
shared open-description cursor and effect admission are preserved. Each resume
locks the live shared cursor; it retains no offset snapshot and never resolves
a reused numeric fd. A fault or refusal after committed records returns exactly
that prefix without retaining replay state. Before progress, owner, supply and
physical refusal retain the selected description through the shared envelope.
Fatal cancellation releases that selection without output or cursor progress;
handled signals remain deferred by existing killable-only owner-wait settlement.

The structural witness
`serial_host_directory_shared_route_transfers_only_dependency_custody` fails
on Slice 2 with three dependency references instead of two. Shared routing
transfers the envelope's dependency by value, leaving only the external witness
and routed wait. Repeated-refusal tests require zero commits/cursor progress at
preparations 1/2/3, dependency release before preparation 4 and exactly one final
commit. Prefix tests require one complete 24-byte record, cursor 1 and no
suspended replay on either refusal or fault. Stale handoff tests require zero
resumed memory operations and no cursor progress. Existing close/reuse/drop,
batching at 10/100/400/4096 and all seven runtime physical scenarios remain
behavior-preservation evidence.

This is a transport refactor, not a fix for a demonstrated failing guest
workload. The stale handoff cases are injected internal authentication tests.
Signed HVF execution, Docker differential, paired runtime ratios and exact
artifact promotion remain director-owned and unavailable on ctb-w4. Existing
fixture/oracle inputs are unchanged; these VM-free checks do not discharge
those higher-layer obligations.

## Requeued terminal admission and host publication (#1057 A1)

`core.lifecycle.publication` and `core.entry.completion` require the terminal
release owner to retain both admission and member custody until the scheduler
chooses commit or requeue. Only a successful OnCpu-to-Queued CAS authorizes
rollback. Rollback restores admission and the reserved live unit and releases
the member claim before linking the runnable record, using only retained atomic
cells under the slot lock. Lock refusal or a losing CAS must keep ownership for
commit. Host-home release uses that same finish owner and commits only after
its refusal checks. An old rolled-back admission cannot publish a later window.

The VM-free two-record bindings keep a peer live while asserting one chosen
finish, zero visible queue entries before rollback, and unchanged admission and
membership on the commit alternative. The CAS-loss binding advances the claim
adversarially at the actual contended slot lock; it is a scheduler seam witness,
not a claim that this transition is naturally produced by a host claimant.
Lifecycle bindings inject the reserved waiter bit only in tests and require one
RMW observation across terminal publication and claim destruction, with no flag
aliasing at reference exhaustion and no reset while a claim retains a reference.
No production waiter is armed and InFlight remains fail-closed in layer 1.

Host terminal publication requires a registry-write capability borrowed from the
actual write guard. Process cancellation attaches that venue after topology
release, acquires it for publication, and drops it before cancellation callbacks
can reenter the registry. A two-live-Kernel-thread binding observes the published
terminal state while an independent reader is excluded, then verifies registry
read admission during each cancellation callback. It uses real prepared exit
effects and reservation release; it does not boot a guest or prove full runtime
retirement. There are no new scans, waits, wake transports or fatal cohorts.
The existing structural budgets remain unchanged. Complete notification, Busy,
ARM/x86 forced crossings and signed acceptance remain layer 2/director work;
HVF and Docker are unavailable on ctb-w4.

The existing personality `x5_exit_requeued_after_wake_wakes_once` binding now
uses the production scheduler release instead of a simulated false return.
With two live member records, a second lane locks the real runnable queue and
requires the completed clear/wake marker before the native adapter returns.
It was red with `requeued record became visible before its clear/wake marker`.
The clear and wake each run exactly once; publishing the existing marker right
after both succeed is correct on commit and requeue because the work is already
done. A newer `set_tid_address` injected between wake and marker must remain
pending at the newer address. No new marker, callback or progress flag is added.

This requeue interleaving invokes the public Linux lifecycle policy boundary:
the injected object park advances the scheduler generation, so the fixture
cannot reuse an entry token from before that injected park. Its later exit
retry takes a fresh authenticated dispatch turn. It does not assert that the
old entry token can return Forward after an intervening scheduler generation.

The core CAS-loss binding additionally retains genuine member and ABI admission
tokens while a second lane advances the record through a production object
park/wake and a fresh OnCpu generation. The stale requeue CAS must lose, then
terminal commit must keep live=1 and ExitingPublished until actual ABI commit.
This supplements the scheduler callback-count guard without manufacturing a
natural Kernel/Kernel claim overlap.

## Shared file arena reuse (#1104)

`kernel.mm.shared-file-reuse` requires read-only shared file initialization to
replace retired anonymous bytes without anonymous backing maintenance. The
VM-free binding `shared_file_reuse_after_affinity_change_needs_no_anonymous_scrub`
uses real mmap/munmap and guest affinity dispatch at 1, 7 and 32 pages. It
models the admitted ARM owner's unsupported shared scrub and requires the
file's bytes, the partial-page zero tail, one full-range initialization and zero
anonymous scrubs. Affinity changes policy here; this is no claim of real
vCPU migration or scheduler execution. Private-file fallback and anonymous
reuse retain their existing paths. Eager owner-copy contention and eager-shape
repairs remain #1124/#1141. Signed 10/10 affinity-handoff acceptance, the
Linux oracle and runtime ratios remain director-owned; this worker has
neither HVF nor Docker.
## Private proc-executable mmap under owner exclusion (#1103)

`kernel.mm.private-file-fixed-replacement` includes the `ProcExecutable`
description used by `/proc/self/exe`. The admitted private mapping retains
that exact executable source through the existing private-source custody;
map-time initialization must perform zero eager owner writes. The VM-free
binding uses an admitted dispatcher and a backend that refuses the otherwise
eager copy. It checks a fixed two-page mapping, source retention after fd close,
source bytes and the zero-filled partial EOF page. Existing HostFile bindings
remain behavior-preservation controls.

The `kernel.memory.owner-wait` VM-free binding registers the real HAL
editor-exclusion witness for the calling thread and exact MM. A self-held
Gate is a typed invariant only after owner source custody has been secured;
that venue must never eagerly copy. A registration alone is insufficient:
POPULATE/LOCKED HostFile maps and SyntheticFile/InMemoryFile/VFS File maps
still take the eager path. Their existing errno 12 outcome is preserved,
rather than promoted to a run-fatal error. The admitted POPULATE/LOCKED and
SyntheticFile witnesses characterize that boundary; they do not claim Linux
conformance for the outstanding eager self-reacquisition repair (#1141).
The existing owner-wait venue remains the only producer enrollment mechanism.

A genuinely foreign refusal during eager initialization remains #1124:
address and source snapshot have already been selected, so resumption needs
retained custody rather than numeric syscall redispatch. This stabilization
slice does not change that residual main behavior or the indeterminate and
post-repoint fail-stop boundaries.

The signed `el1_tlb_mm_edit_window_excludes_sibling_allocations` and
`el1_tlb_running_thread_mm_edits_cost_no_maintenance` bindings, native oracle
comparison and exact-artifact acceptance remain director-owned. This Linux
worker has neither HVF nor Docker.


## Already-retired native backing (#1099)

`process.native.terminal-child` includes unused backing whose exact stage-2
owner has already retired through replay, teardown or generation replacement.
The neutral retirement owner classifies that state; the release adapter must
not turn clean absence into carrier failure or MM-lifetime retention. Live
pins and exact-generation retirement contention keep the existing interim
retention, and an owner-identity mismatch remains an invariant failure.

The VM-free binding
`native_backing_release_already_retired_owner_is_clean_absence_without_quarantine`
settles the original physical/table journal with zero retained rollback entries,
no quarantine and no failed rollback. It covers VM destruction, a later VM
generation, a later owner generation and an absent record. Its pre-fix failure
was `indeterminate release: TerminalizedByVmDestroy`. The assertions cover
exact-record settlement and resource recovery; they do not measure a runtime
ratio. HVF adapter and signed runtime verification remain director-owned.
The macOS-only
`native_backing_absence_does_not_claim_a_retiring_successor` binding drives a
real successor retirement callback with a second live backing owner, checking
absent predecessor release before and during that claim and after carrier
teardown.
Its red/green run is pending on macOS. Descriptor-capacity waiting,
the staging/offer lock gap and callback lock scopes are tracked in #1149;
an immediate empty-success retry is not an accepted capacity wait.
