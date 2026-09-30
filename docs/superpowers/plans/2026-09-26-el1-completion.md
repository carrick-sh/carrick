# EL1 migration: current completion controller

> **For agentic workers:** Execute the current authorized task with
> `superpowers:executing-plans`; use delegated execution only when authorized.
> This controller is director-owned. Workers report evidence and proposed
> status changes; the director maintains this file.

**Updated:** 2026-09-29, from local Git state, source inspection and retained
receipts. After requesting the refresh, the user explicitly said "Set the
goal and go." The end-to-end goal is active; execution now advances B+D memory ownership after the bounded C coherence slice below; A and full C remain unaccepted.

**Goal:** Complete the accepted AArch64/macOS EL1 migration,
with one authoritative owner and one semantic implementation per object,
verified Linux behavior, bounded work and the per-workload ≤2x native-Linux
objective. A branch merge or a focused green test does not close a checkpoint.

**Architecture:** Shared neutral cores with venue adapters; guest-kernel
ownership of Linux semantics. Preserve elastic bulk host frame grants/returns,
host-scheduled vCPUs, host-native I/O and the substrate/personality boundary.
Host requests are validated, batched and asynchronous; a guest wait releases
execution capacity. Retain adapters needed by other backends until their
replacement is accepted; delete superseded semantic paths.

**Scope decision (2026-09-29):** The user said "go all the way but don't do
x86 for now." Continue every ARM64 ownership stage and its full acceptance
gates. Defer checkpoint 6, x86 hardware discovery and x86 execution; preserve
existing backend interfaces. Deferred x86 is not accepted or complete. This
explicit decision supersedes the older goal text that includes x86.

**Tech stack:** Rust; HVPatch/AArch64 EL1 on macOS/HVF. The shared x86 engine
and real KVM/bhyve/NVMM venue remain a deferred follow-up.

**Authorities:** [accepted design](../specs/2026-09-24-el1-kernel.md),
[AGENTS.md](../../../AGENTS.md),
[contracts](../../conformance-contracts.md), and this controller.
[Previous controller](2026-09-29-el1-controller-history.md) preserves the full
historical campaign verbatim. The local handoff is
`.worktrees/EL1-HANDOFF-2026-09-29.md`; this controller supersedes its stale
status/order statements where explicitly corrected below.

## Current execution decision — impact reset, 2026-09-29

This section is the current work order. The chronological observations below
preserve evidence; their older “next” statements are not competing work orders.

**Diagnosis:** development has accumulated useful foundations and regression
receipts faster than it has activated production ownership. On adapter source
`a5ca5ed03` after the copyout conversion, guest descriptor admission still has
`host_copyout=false` and `backend_writers=false`; anonymous reservation dispatch
has only test callers. A passing helper or ordinary boot test cannot demonstrate
that either disabled path executes. The controller itself compounded drift by
retaining mutually inconsistent immediate priorities.

**Next capability milestone:** make the production ARM64 anonymous-memory path
use one reservation authority and EL1 descriptor publication, then demonstrate
allocation, host copyout, fork/COW, protection and retirement on that path.
Deliver this as one connected ownership change with focused development checks;
do not turn each adapter into a separate broad qualification campaign.

| Order | Required work | Evidence that advances the milestone |
|---|---|---|
| 1 | Finish the existing prepared-copyout transaction, including refusal and exact-MM commit; retain exclusion | Real runtime caller consumes the verified EL1 publication receipt before committing residency. The current one-test green is model evidence only |
| 2 | Convert remaining COW, sparse/foreign materialization and exec descriptor writers using existing transaction/copy machinery | Explicit caller-to-writer checklist; every live writer has an owned submission/completion path, including failure and cancellation |
| 3 | Join anonymous facts and lifecycle to SharedReservations; connect production anonymous syscall dispatch | MemState no longer independently decides the migrated anonymous facts; brk/mmap/protection/retirement and fork/exec/exit share the same authority |
| 4 | Enable the complete production path and run a signed ownership witness | Actual guest-owned lane observed; allocation, copyout, two-live-MM fork/COW and retirement verified. Ordinary boot or test-only owner selection is insufficient |
| 5 | Remove the host page-table pause only after the writer census closes; qualify checkpoint 2 | Pause-free two-MM progress, scoped frame return, real host-COW observations, full applicable correctness and cost gates |

Steps 2 and 3 may interleave where an exact dependency requires it. Do not flip
admission booleans to bypass an unconverted writer. File/shared mapping and
host-boundary semantics remain part of the conversion review.

**Completed prerequisite:** copyout is committed in adapter `a5ca5ed03`.
The engine's prepared-copyout caller now uses the shared fork/EL1 descriptor
drain; the runtime retains exact-MM exclusion and kernel residency commits
only after an exact Publish/Write receipt. Retained model red/green, 11 runtime
descriptor tests, 15 kernel first-touch tests, affected Clippy and formatting
pass. Refused root/backing/editor/permission leaves remain unchanged; wrong
MM/page/read receipts preserve arming. See adapter memory-integration
`copyout.md` and raw logs. Production admission remains disabled; no signed
activation or checkpoint acceptance is claimed. Do not restart this slice.

**Guest copy transport prerequisite:** adapter `9b0047959` now reserves two
invalid kernel-only aliases at EL1 offsets `[0x1A0000,0x1A2000)` and the hardware
descriptor handler uses them to copy a page before CowRepoint. Both aliases are
revoked before completion; failed revocation is fatal. This reuses the descriptor
submission/receipt channel. Boot-layout red/green, revocation mutation control,
four window tests (including two roots), EL1/ABI/memory/MMU suites, affected
Clippy and hardware EL1 image build pass. See adapter `cow-window.md`. No signed
COW execution or production host submission is claimed.

**Production COW caller joined (development):** adapter `bda5f4cb0` routes
`HvfTaskState::perform_frame_cow` through the driving vCPU and the existing EL1
descriptor service. The host retains the source owner and publishes a provisional
replacement grant; one compound receipt precedes the existing inventory split.
Overlapping copy extents are rejected red-first; each of four descriptor-store
failures restores the full preimage. Real provisional-grant refusal releases
backend references and physical ownership in the HVF model. The unused synthetic
runtime continuation/backing gate is removed. MMU 159, backend 11, runtime 10,
affected Clippy, formatting and EL1 image build pass. See `cow-join.md` and logs.
Admission remains disabled; no signed COW execution or checkpoint acceptance.

**Private-anonymous mixed permissions:** adapter `1b121731c` fixes the next
production transaction restriction. The red four-page witness was refused with
PermissionDenied; it now preserves RW/read-only/PROT_NONE/prepared states while
repointing the compound. The guest backend no longer refuses merely read-only
source metadata. MMU 160, EL1 114 and affected all-target Clippy pass. See
`cow-permissions-*` receipts. This is executor/model evidence; admission remains
disabled and successful real-authority COW execution is still unproven.

**Local COW shape conversion (development):** adapter `09afdd4c5` routes
kernel-only, legacy user, maintenance and private-file reuse through the existing
compound EL1 transaction. Protocol v4 carries typed access authority; tagged
private permissions remain EL1-owned. Maintenance retains the exact completion
leaf for deferred protection publication. Reused private-file destinations retain
their pin and authenticate the existing kernel row/MM/owner/revision without a
duplicate grant. The remaining local COW shape refusal is removed. Red controls,
MMU 163, EL1 114, inventory 22, backend 11, the real kernel-inventory authority
witness and affected Clippy pass; see `cow-access.md`. The authority witness uses
the existing fixed-owner fixture; it is not full carrier/hardware COW execution.
Admission remains disabled and signed COW acceptance remains open.

**Next implementation:** convert private/shared repoint publishers, replacement
grants, retired reuse, sparse replacement and foreign-MM publication, then the
remaining engine protection/alias/discard and exec writers. Join reservation
policy/lifecycle as the production writer dependencies close. Successful complete
COW execution with real ownership and signed guest proof remains part of the
connected memory milestone. No second copy transport or broad boot campaign.
The caller checklist in adapter `cow-join.md` is historical at its recorded
source; `cow-access.md` records the local COW progression. Neither claims an
exhaustive writer-closure audit.

**Dependency review after two prerequisite intervals:** copyout and the guest
copy transport remove concrete missing operations but have not activated the
lane. Continue only the real backing transaction next; extra helper tests,
accounting or documentation cannot substitute for that integration. This is a
bounded reason to finish the existing dependency, not a reset of the impact
counter. Full acceptance and all later ARM64 stages remain required.

**Priority rules:** before each implementation task, name the production caller,
the authority or host operation being replaced, and the decisive observable
result. Classify disabled-lane plumbing as prerequisite work, even when connected
to a runtime caller. It is progress toward activation, not capability delivered.
At each update report remaining activation dependencies, not just passing tests.
Two support/prerequisite-only intervals require a concrete course correction or
a bounded explanation of why the named dependency must finish; rewriting the
plan or accumulating helper greens does not reset the count. Consolidate signed
builds/full CI/inventories at the connected milestone, retaining focused red/green
checks during implementation and all final acceptance gates.

**Then:** finish the open IPC/lifecycle acceptance blockers, host namespace cost,
remaining descriptors/IPC/signals, names/page cache, and process lifecycle,
followed by final ARM64 qualification. Earlier IPC/lifecycle failures stay open;
resume their investigation only for a new discriminating test or a concrete
dependency. No new broad capture campaign. x86 remains deferred.

Current accepted base remains local main `f304f8415`; development integration is
adapter `09afdd4c5` (clean development commit).
No checkpoint has been accepted by this work.

**Execution correction after the renewed rabbit-hole warning:** keep one active
implementation workstream: production memory ownership. The immediate COW slice
is bounded by the real `HvfTaskState::perform_frame_cow` caller, the existing
allocation/inventory transaction, one compound EL1 publication, and verified
completion before source retirement. Compound rollback and refused-grant cleanup are now model-verified; the next
decisive check is successful real-authority composition with preserved permissions.
Another standalone transport abstraction is not a milestone. This development
implementation is not accepted runtime evidence.

Before extending that slice, reconcile the concrete remaining writer list against
production call sites. For each refusal, record the writer to convert and its
activation dependency; do not turn an unsupported shape into an accepted
exclusion. Reuse the existing submission and journal mechanisms. Remove redundant
orchestration as its real caller is joined. Do not start IPC captures, unrelated
performance work or later subsystem implementation during this slice.

Progress updates must state: production capability activated (or explicitly none),
activation blockers removed and remaining, current decisive check, and next action.
If an investigation consumes 30 minutes without new evidence or removing a named
blocker, stop that investigation and choose a smaller discriminating check or a
simpler integration. This is a reassessment trigger, never permission to weaken
correctness or abandon the necessary dependency. Broad qualification remains at
the connected production milestone; existing final acceptance gates remain intact.

## Historical state and evidence rules

At refresh, the implementation baseline on local `main` and local
remote-tracking `origin/main` is `a70b40466`. The documentation commit for
this refresh advances local main only; no remote fetch was performed.
Batch 3 is on `integ/batch3`, unlanded. Its scheduler correction is
`a2c0fcee3`, following the atomic re-park correction `0e1d7c12c` and exact
zone handback targeting `da84671b7`. The latter has a deterministic red-first
reaped-child witness, continuation authentication and pre-enrollment kick
controls. Direct adoption reserves ownership before publishing readiness.
Final kernel/semantics 2,462 (one existing ignore), three focused controls
and affected Clippy passed. Serial kernel 109 and runtime 630 passed before
the ordering-only follow-up. Registry, clean-source lint and exact contract
coverage passed; the 595-row authority census remains macOS-only.

Fresh signed source `257de53e0` passed 49 unique positive EL1 executions
across nine artifacts, the unentitled negative control and scoped cleanup.
The nine executable SHA-256 hashes were independently matched to the
retained `exact-zone-wake/signed-artifacts.jsonl`; full output and final
source-gate logs are in that receipt directory. This replaces `8916e1fe2`
as current scheduler regression evidence, but does not supply deterministic
signed race bindings, historical crash attribution or full task-A acceptance.
New focused signed source `2e6e3794a` adds the notification capture audit
event (`b55e57803`) and a deterministic three-process fixture. Delivery is
held across the exact parent's reap: the retained pre-fix method produces one
reaped-wake rejection; restored exact targeting produces zero. Entitlement
negative controls and cleanup passed. See `notification-order/` for both
artifacts, the controlled source patch and the initially non-discriminating
fixture result. This closes this producer's signed interleaving gap only; the
49-execution receipt above predates the new audit event and is not full-tree
acceptance for this source. Broad regressions after the audit event passed:
kernel/semantics 2,462 (one existing ignore), serial kernel 110, runtime 630
(eight existing ignores) and affected Clippy. Clean compiler reconciliation
on `3fb63f608` retained all 595 rows and positions; `852fedd48` records the
source stamp. Final lint and contract coverage passed on `852fedd48`. The
compiler census remains the macOS subset; other host profiles are unqualified.
Full `just ci` passed on `f256ce2`; fresh musl/GNU ARM64 probe inputs
(544 binaries each) are hashed in `arm64-acceptance/`. The signed EL1 gate
on `e8db2fd51` completed: 50 EL1 tests, 912 generic probe/libc pairs, 32
dedicated tests, retained CLI cases and both inotify routes passed. The exact
216-row LTP population reports 215 baseline MATCHes and one allowed fanotify25
DIFF; this is regression evidence, not strict closure. Three generic shard
files were re-signed by the later dedicated stage; their passing receipts
remain, but final promotion must retain the tested bytes. Controlled ratios
and the remaining lifecycle obligations stay open.
Fixed Python8x2 now passes all16 rows against fresh native Linux, with
normal concurrency and serial confirmation disabled. The initial fixed Go20 was RED:
round2 conf-20571-c00 aborted while publishing terminal inventory retirement
(frame2697 still mapped; kernel_mm14). The other19 passes do not clear it.
This stopped batch3 promotion and triggered the reduction below.
See `arm64-acceptance/workloads/`.
A bounded 20-run diagnostic population on a separately debug-signed copy
completed without reproduction or core capture. This does not clear the red
acceptance result. Sampling was stopped in favor of the deterministic
interleaving below. See `arm64-acceptance/retirement-debug/`.
The deterministic backend reduction now fails red on mixed-time population
counts and passes after moving the existing backend-registry acquisition
before the authority query. Eleven retirement tests, serial HVF 598 (three
existing ignores), and affected Clippy pass. This is a branch-local correction,
not retrospective attribution of the Go failure. See `retirement-population/`
for limits and failed invocations. On source `b5a751775`, full `just ci` and
the signed rebuild pass. The corrected CLI (SHA `ec12ac299cd4c7200fb8befe663da2803dc154ba148be9f45150a29f9acd342f`)
passes all 20 fixed Go rows against the verified native ARM64 oracle, with
no retries, diffs or leftover guests. This closes that candidate population;
the original failure stays preserved. Prior EL1/probe receipts do not transfer
to this executable. See `retirement-acceptance/`. The corrected source now
passes 50 unique signed EL1 executions across nine hash-verified, preserved
executables, with negative entitlement and zero scoped leftovers. This includes
the parked-thread crash-register witness. See `retirement-signed-el1/`.
Remaining lifecycle/structural proofs and full batch qualification still block
acceptance. The notification structural binding now passes on source
`9ba825eac` with two visits, two authentications and one delivered wake,
complete counters, negative controls and verified cleanup. Its exact tested
bytes are preserved; this is not full-tree acceptance.

VM-free additions now prove exact retirement after control/failed-load
settlement (110 serial kernel passes) and enforce zero retired-delivery wake
publications at 1/8/32 with excess-work negative controls. Those scoped
observations do not establish total scheduler work or signed cost.

All twelve active
batch/memory/IPC/sigsuspend worktrees inventoried below were clean at the
initial refresh inspection; only batch 3 has been advanced in this goal.

Evidence labels:
- **Source-confirmed:** code or Git ancestry inspected on the named revision;
  not a claim that it compiles or runs.
- **Receipt-confirmed:** retained results inspected; valid only for their
  recorded source/artifact/fixture population, not the new merged tree.
- **Handoff claim:** prior worker/director report not independently requalified
  here. “Ready” means a review candidate, never automatic acceptance.
- **Accepted slice:** historical acceptance for a named limited surface, not
  completion of its containing checkpoint or current full-tree acceptance.

| Checkpoint | Current state | Completion boundary |
|---|---|---|
| 0: scheduler/address-space execution | Implemented on main; batch 3 still has lifecycle blockers | Preserve scheduling, wake, GIC/timer, occupancy and address-space-switch contracts on the integrated artifact |
| 2: memory | First-touch, resident permission and resident munmap slices historically accepted; ownership migration incomplete | Anonymous semantics, faults, COW, descriptor publication and elastic return owned in EL1; all host writers converted before pause removal |
| 2a: host namespace cost | Earlier namespace budget work merged; full objective open | Containment/coherence plus controlled Linux ratios and native macOS I/O controls; finish before checkpoint 4 |
| 3: descriptors/IPC/signals | Production pipe/eventfd routing has one signed red/green witness; blocking/lifecycle qualification and checkpoint acceptance remain open | Full descriptor lifecycle, in-zone IPC/readiness/signals and all assigned ownership obligations |
| 4: names/page cache | Pending | EL1 name/dentry/stat/page-cache ownership with host namespace/writer coherence; retire old file zone |
| 5: process lifecycle | Pending | EL1 fork/exec, image loading and process lifecycle; host only supplies boundary services |
| 6: x86 venue | Deferred by user on 2026-09-29; outside the active goal | Same neutral cores in ring 0, each declared backend qualified with real execution and native x86 oracle |
| Final acceptance | Pending | Entire declared conformance/workload denominator, provenance, cost gates, dead-path removal and unresolved-item closure |

Main includes batches 1/2 (handoff batches `043ffbcc9` and `a70b40466`):
namespace/syscall budgets, futex-exit bounds, close locking, directory identity,
idle service rescue, fixture port/liveness fixes, dispatch/empty-steal cost
reductions and carrier-CPU attribution. Merged presence does not transfer their
old gate results to future integrations.

Two obsolete open items are corrected: parked-EL1-thread crash registers have
an implementation and signed fixture on main (`4d43ade6a`); the personality
boundary has a mechanical gate for scheduler/MMU cores (`26f104341`,
`1bc6c8900`). Preserve those gates and extend coverage as new cores move;
neither is still “not implemented.” Derived entrant bounds, GIC/SPI recovery
obligations, complete boundary coverage and paired attribution remain open
until their own receipts close them. Do not re-open historically accepted
memory traces absent a new failure.

## Branch inventory and integration dependencies

All paths are under `.worktrees/`. Heads below are verified local snapshots.
Do not discard a branch because a subset was merged elsewhere.
Bring this controller forward from main when integrating an older branch;
do not overwrite it with that branch's pre-refresh controller.

| Worktree / branch | Head | Disposition |
|---|---|---|
| `wt-batch3` / `integ/batch3` | `a2c0fcee3` implementation; signed `257de53e0` | Current blocker owner; review original slot-liveness/pgrp/ICMP changes, notification fix and deferred-handback identity correction together |
| `wt-cp2-descr` / `work/cp2-el1-descriptor-owner` | `c555f5dd1` | Review candidate; 9 signed filters and first-touch slopes 0.004–0.009 are handoff claims |
| `wt-cp2-cow` / `work/cp2-hvf-cow-adapters` | `d581dd099` | Ancestry-confirmed in descriptor branch; do not merge it a second time |
| `wt-cp2-return` / `work/cp2-elastic-return` | `8f268dee4` | Review candidate; scoped grant/return accounting and signed green are handoff claims |
| `wt-cp2-tests` / `work/cp2-ownership-tests` | `45fa94124` | Contains deliberately red ownership witnesses; dedicated host-COW accessor still panics |
| `wt-cp2-reserve` / `work/cp2-el1-reservations` | `f2efa3716` | Explicit unverified WIP; reservation provider/projection and host authority work incomplete |
| `wt-cp3-adapter` / `work/cp3-ipc-adapter` | `c1c17d963` (latest signed population source) | Live routing and blocking 1/8/64-pair data populations demonstrated; forwarding variability and full vertical acceptance open |
| `wt-cp3-host` / `work/cp3-ipc-host` | `77b6f40a1` | Shared backing/lifetime foundation; descriptor-table integration and host blocking continuation open |
| `wt-cp3-fixture` / `work/cp3-ipc-fixture` | `fd27e748d` | Five signed acceptance tests plus report validators/contracts; baseline red is a handoff claim |
| `wt-cp3-objects` / `work/cp3-ipc-shared-objects` | `bb93917a4` | Ancestry-confirmed in adapter branch |
| `wt-cp3-waits` / `work/cp3-ipc-object-waits` | `7debfcc13` | Ancestry-confirmed in adapter branch |
| `wt-sigsuspend` / `work/rt-sigsuspend-parallel-flake` | `5011caffa` | Unverified WIP; establish root cause/pre-change evidence before considering integration |

Preserve `wt-slotlive` (`1cd5071d6`), `wt-pgrpsnap` (`849e2119c`) and
`wt-icmpflake` (`2a097c0bd`) until batch-3 integration is accepted. Older
`wt-sysret` (`56f848a2b`) and `el1-inotify` (`7eb9a6853`) are not part of the
next slice; inventory their work before reuse/cleanup. Reuse suitable existing
checkouts; retire worktrees only after verifying no task/process relies on them
and saving recoverable state. Never sweep shared probe/build storage.

## Execution order and review focus

### Historical IPC deliverable and drift check

The first production-routing deliverable is demonstrated, including real
blocking pipe/eventfd populations at 1/8/64 pairs. The next deliverable is
correct descriptor close/reuse while an operation is blocked, plus two-live-
process IPC. No checkpoint has been accepted by these focused results.

Earlier development sequence (superseded by the current execution decision):
1. Connect HostTable to the real FileTable: complete initial namespace,
   implicit stdio, incremental mutation, fork/exec and functional retirement.
   A partially published namespace is invalid because missing slots become
   guest EBADF rather than host forwarding. Reuse the existing shared core.
2. Run one honest signed end-to-end pipe/eventfd witness using actual
   execution observations. Repair the existing fixture's fabricated reports;
   do not build a new diagnostic framework. This first witness demonstrates
   routing only, not acceptance of the vertical.
3. Expand to the five required lifetime, wake, mixed-venue, round-trip and
   signal/partial-progress witnesses, then qualify the stable integration.
4. Continue B+D memory ownership, followed by E and final ARM64 acceptance.

At each progress interval report whether production routing advanced, a
directly blocking defect was eliminated, or only supporting work occurred.
Two consecutive supporting-only intervals require an explicit dependency
review and course correction; passing helper tests alone do not reset this
counter. Historical lifecycle investigations stay off this development path
unless a concrete failure or acceptance dependency requires them. Preserve
their unresolved acceptance status. No repeated full-suite runs on unchanged
code and no infrastructure expansion without a named blocked execution step.

Latest development observation: adapter commit `5cc3b64a6` connects HostTable
to production FileTable publication and mutation/retirement. Boot and syscall
entry attempt admission only into the exact Kernel's mapped IPC window.
Initial namespace admission is complete; incremental updates touch changed
slots and grow geometrically. Refused admission withdraws the whole projection
and forwards that table, without rescanning it on every syscall. Fork/exec
namespaces independently admit their complete snapshot.

The red-first table witness, fork/exec/refusal checks and real dispatcher
eventfd/shared-view check pass. `just test-kernel` passes (2,198 kernel tests,
one existing ignore, then semantics suites); serial host 138/138; affected
Clippy passes. A stale eventfd test expected F_SETFL to erase O_RDWR; corrected
against retained native-Linux evidence, with its failed run preserved. Exact-
owner host-token retirement also fixes the reproduced handback leak.

The first honest signed routing witness now passes on clean source
`e6e2ab3bf` (receipt commit `ab5ec3e1d`, clean adapter head). Initial signed
source `5cc3b64a6` transferred correct data but forwarded all 2,048 loop
writes. The mapped IPC authority belonged to the loader's temporary bootstrap
Kernel; root initialization later rebound the dispatcher to the authoritative
HVPatch graph. Moving registration into authoritative executor launch before
window installation, and publishing the root table after mapping, fixes that
source-confirmed dependency. No extra audit hook was needed.

The unchanged witness checks 1,024 pipe and 1,024 eventfd round trips. Actual
whole-run counters: served read=2054/write=2048; forwarded read=4/write=1,
versus prior forwarded read=2052/write=2049. Run ID
`el1-ipc-routing-20260929-b` passed one positive signed execution plus the
unentitled negative control, with zero scoped leftovers. Tested SHA-256
`e1c036c86ac45cdc93b2ceec8a5c05fb7298d6afa1110d77368608b2390a010e` was
independently matched to the official manifest and its bytes preserved.
The first failed run, fixture-lock delta and failing executable remain saved.

**Latest blocking evidence:** signed source `c1c17d963`, run
`el1-ipc-pairs-20260929-b`, completed pipe and eventfd at 1/8/64 pairs,
128 rounds each, with checked payloads and real guest parks. All six cases,
entitlement negative control and scoped cleanup passed. Exact manifest,
raw output and preserved-artifact location are in the adapter's
`docs/perf-results/2026-09-29-el1-ipc-integration/pairs-population*` receipts.

The earlier pipe-eight served-write shortfall remains unresolved; no product
fix separates that red from this green. Whole-run counters do not establish
unique completed syscalls or zero IPC-caused host exits. Do not retry this
population to manufacture acceptance or build a new observation framework.

**New direct blocker:** signed source `15021dfb8` runs real inherited IPC
across forked parent/child descriptor tables. Pipe one-pair completed 128
checked round trips with 257 parks. Pipe eight-pair hit the 60-second watchdog:
four idle-WFI slots and parked tasks in both address spaces. The census also
records one lost adoption and one space refusal; cause is unproven. Later
cases did not run. Negative entitlement passed and cleanup was zero. Exact
failed executable and raw census are preserved in the adapter's
`processes-first-red*` receipts. No retries or product fix yet.

**Follow-up `8c9617950`:** deterministic test proves an unplaceable object
wake had no runnable owner. Reusing the existing misplaced handback queue
fixes that gap: 62 scheduler-core and 14 focused EL1 IPC tests plus affected
Clippy pass. Unchanged signed execution now completes pipe 1/8/64 and
eventfd 1/8, but eventfd64 still hits the watchdog with two worker records
parked alongside the two waiting leaders. Full test remains red; completed
cases also retain served-write bound failures. Negative entitlement and
cleanup pass. Exact executable/census preserved in adapter
`processes-wake-fix*`; do not claim full liveness or zero-exit closure.

Existing post-mortem capture on the preserved artifact reproduces the stall
at eventfd8, showing two enrolled zone continuations and one remaining
shared eventfd pair (two tables, fd9/10, exact descriptions301/302).
Capture is untruncated, cleanup zero; see adapter `processes-capture/`.
Counter values and saved IPC operation payloads are absent from this graph.
LLDB capture now reproduces pipe8, with both pipes empty, request sequences
113/113 and response112/112, and two live zero-progress read operations.
The captured ABI hash matches the decoder. See adapter `resumption-core/`;
core retained outside Git, scoped cleanup zero. This suggests lost/replayed
progress rather than unread bytes stranded by a missing wake; exact cause
remains unproven. Two supporting intervals trigger reassessment: stop live
captures. Next is one deterministic completed-operation resumption/handback
reduction; if nondiscriminating, advance independent descriptor lifetime
while preserving this acceptance blocker. This qualifies
as a direct dependency, unlike the stopped historical capture investigation.
Do not label the counters a diagnosis or reopen unrelated lifecycle work.

**Independent lifetime result:** source4a7d705bc signed inherited-table
replacement/EOF witness passes128 payload roundtrips with257 guest parks;
negative entitlement and cleanup pass, exact artifact retained. Bounded
resumption reduction passes without reproducing the liveness issue.

**New concrete coherence defect:** source50b2a6dc1 mixed-venue pipe case
passes128 roundtrips with128 host readv/writev each and127 guest parks.
Eventfd fails at writev. Native ARM64 Docker accepts eventfd vector I/O;
Carrick readv explicitly rejects this description. Exact red artifact and
oracle retained in adapter IPC integration receipts. Next is red-first
VM-free vector-eventfd coverage, multi-iovec/fault oracle semantics, and
routing through the existing shared eventfd authority. Do not resume the
broad parked-worker investigation before this direct defect is handled.

**Following implementation/qualification step:** blocked close/reuse and two-live-
process witnesses, then mixed venue and signals/partial progress. Keep the
forwarding/counter issue as an explicit acceptance blocker while independent
functional migration proceeds. Any investigation must name its blocked
capability, a decisive experiment and a stopping condition. After two failed
fixture designs or two supporting-only intervals, reassess before more work.
Full suites belong at stable integration boundaries; focused contracts guide
implementation. Main is unchanged; x86 remains deferred.

**Priority reset, explicitly requested by the user on 2026-09-29:** stop the
expanding deferred-capture investigation and resume work on guest capabilities.
Task A remains an acceptance blocker, but unresolved historical attribution
and additional race fixtures are not dependencies of every development edit.
Do not mark A accepted or merge its unqualified candidate to main.

The initial development frontier after the reset was **C: the pipe/eventfd vertical**. Review
and compile the existing adapter/host/fixture integration, complete the actual
blocking continuation and descriptor-lifetime gaps, then turn the five named
signed witnesses green with nonzero guest parks and the required exit/work
bounds. Reuse existing implementations. Establish any concrete prerequisite
from source before pulling it in; do not require all of B or A by assumption.
A development integration is explicitly unaccepted until its applicable gates
pass. A newly reproduced lifecycle failure on this path is a direct blocker
and receives a bounded reduction; the old failure is not silently dismissed.

Then join **B and D** into the memory ownership milestone: reviewed descriptor,
COW and elastic-return foundations, reservation authority and production
routing, copyout/backend writers, and finally host pause removal. Keep all E
ownership stages and final conformance/cost acceptance in scope; x86 stays
deferred. This changes development order, not completion requirements.

Progress is measured by guest capability and removed host ownership, not
commits, receipt count or added hooks. Work on one vertical at a time. Before
adding infrastructure, identify the acceptance test it directly enables and
why the existing mechanisms cannot do so. After two failed fixture designs or
a work session without new discriminating evidence, reassess the dependency
and choose another independent high-impact action; preserve the open blocker.
Batch inventory/full-CI/artifact promotion at stable integration boundaries.
Use focused checks during development; never reuse old receipts as proof of
a new artifact. Do not add a second audit or hook merely to validate the first.

Review focus across every slice: exact task/MM/record generation after reuse;
two live processes with overlapping VAs and independent identity; partial I/O
and SA_RESTART during exec/exit; rollback under allocation/publication refusal;
coherence with host file mutations and shared aliases. Each owning task below
must provide those witnesses where applicable.

### Current frontier after bounded IPC coherence delivery

Source `6970e3e` fixes vector eventfd operations through the existing shared
counter and owned write continuation. Native ARM64 shape/fault oracles,
red-first split read, 32 focused IPC tests and affected Clippy pass. Signed
`el1-ipc-vector-20260929-a` completes 128 checked mixed-venue roundtrips each
for pipe/eventfd, with 127/128 EL1 parks. Negative entitlement and zero-leftover
cleanup pass. Exact tested bytes and manifest are retained in adapter
`docs/perf-results/2026-09-29-el1-ipc-integration/vector-*`.

**Next implementation: B+D memory ownership.** Review and join descriptor/COW
`c555f5dd1` and elastic return `8f268dee4` on the development integration;
check their shared layout and run the focused memory regression net. Then
review reservation candidate `f2efa3716` and wire authoritative reservation
routing and remaining writers. All three worktrees were clean at this reset.
Host pause removal remains last. Avoid a new diagnostic framework or another
broad IPC capture before a specific new hypothesis provides a decisive test.

C remains unaccepted: multi-process liveness and served-operation bounds,
blocked shared-table close/reuse, signals/restart/partial progress, scoped
zero-IPC-exit proof and full qualification remain required. A remains an
acceptance blocker. Advancing independent memory work defers these blockers;
it does not resolve or waive them. Keep one implementation vertical active.

**Memory development integration:** adapter `8fc9513fd` joins elastic-return
`8f268dee4` (merge `3f8e349fc`) and descriptor/COW `c555f5dd1`. Additive IPC/MMU
exports and dependencies are preserved. Six return-lifecycle tests and one
three-scale discard/fork-retention test pass; combined 97 EL1 + 55 ABI + 152
MMU + 37 runtime guest + three architecture authority tests pass. Embed test
compile and affected Clippy pass. Receipts are in adapter
`docs/perf-results/2026-09-29-el1-memory-integration/`.

This advances the development integration only. Compiler capture and line
inventories remain stale pending clean stable reconciliation; full source
writer census, signed memory tests and checkpoint acceptance are open.
`GuestCowContinuation` and guest `copy_granted_cow_page` currently have only
test callers. Production admission still refuses host copyout and backend
writers. Do not count their helper coverage as migrated guest memory.

**Immediate next action:** review/join reservation provider candidate
`f2efa3716`, implement its carrier-bound resolver/installation, and connect
real reservation operations and host-copyout/backend transitions. Preserve
its explicit fixture race as a bounded validation obligation. Do not spend
the next interval expanding accounting or rerunning unchanged helper suites;
connect a production owner. Keep host pause removal last.

**Carrier provider connection:** adapter `96e912e6a` joins reservation
candidate `f2efa3716` and installs the carrier-bound host provider before
worker admission. Owned metadata access retains the exact carrier mapping
and VM generation; prepared views pin dynamic extents and cache unchanged
storage generations. The lifetime/retirement witness is red-first; 27 kernel
reservation tests, 114 EL1 + 56 ABI tests and affected Clippy pass.

Signed `el1-reservation-provider-20260929-a` passes the existing first-touch
parent/child regression at 256/1024/4096 pages (99/106/136 exits), entitlement
negative control and zero-leftover cleanup. Exact bytes/manifest are retained
in adapter memory-integration `provider-*` receipts. This is joined boot
regression evidence, not anonymous-policy activation or complete provider
operation coverage. `MemState` remains the anonymous owner and admission
still refuses a second owner.

**Next implementation:** convert `Aarch64EngineCore::commit_prepared_host_write`
and `KernelFrameCowAuthority::commit_host_first_touch` to use guest descriptor
publication while retaining exact-MM exclusion and committing arming only
with an authenticated receipt. Reuse `plan_host_first_touch` and
`commit_host_first_touch_after_guest_publish`; these currently have no runtime
callers. Preserve Linux write permission and cross-MM/reuse rejection. Then
continue reservation policy ownership and the remaining backend writers.
The host page-table pause stays until the complete writer census is converted.

### A. Close batch-3 lifecycle blockers

Deferred investigation: [signed deferred handback ordering](2026-09-29-el1-signed-handback-proof.md).
Resume only for an explicit acceptance dependency or a concrete failure in the
active vertical; do not keep adding trigger experiments as the main work.
The capture hook is implemented with VM-free red/green and lock-release
controls. Its first signed two-process trigger failed with zero captures
on `497096b2f`; retain that fixture failure and establish actual queued-record
evacuation before adding retirement/reuse ordering or expanding populations. The parked-restore
admission fixture now confirms generic and exact wakes cannot queue a parked
record; this is negative coverage, not historical crash attribution.

Sources: `crates/carrick-runtime/src/vcpu_loop/{wait_wake.rs,zone.rs,executor/}`,
`crates/carrick-kernel/src/{el1_zone.rs,kernel/scheduler.rs}`, and
`crates/carrick-sched-core/src/`. Contract for the new notification reduction:
`kernel.wait.child-exit-notification-lifecycle` (currently branch-local).

- [x] Preserve the original two failures and distinguish their boundaries.
- [x] Reduce delayed parent notification to a deterministic VM-free red;
  `932a33568` uses the existing exact task/thread/generation wake API.
- [x] Retain 630 runtime passes/8 existing ignores, Clippy and registry checks;
  signed shard at `df9741d88`: 314 musl/glibc executions, negative control and
  zero scoped leftovers. These are receipt-confirmed, not rerun for this edit.
- [ ] Attribute the historical `otmpfileforkexec` reaped-task wake to an exact
  producer/interleaving. The reduction is a real defect but not that attribution.
- [x] Reduce deferred evacuation identity reuse, fix it with retained
  RecordRefs (`3981c0366`), and preserve the red/green witness at 1/8/32
  records. Kernel/semantics 2,459 passes, serial-host 109 passes, kernel
  Clippy and `just lint-domains` passed. The authority census is the macOS
  subset (595 unchanged rows); non-macOS profiles remain pending. All 14
  signed `el1_sched` tests at `0542e2d2f` passed, with negative entitlement
  control and zero scoped leftovers. This is regression evidence; signed
  deterministic interleaving and WorkObservation bindings remain open.
- [x] Preserve identity at the earlier core publication boundary (`99c8cd5ac`):
  three red-first callback/returned-batch/executor-take witnesses. Core 53,
  EL1 host-test 74, kernel/semantics 2,459, serial-host 109 and runtime 630
  passed (existing ignores unchanged). At `40a707ba0`, all 49 selected signed
  EL1 executions across nine executables passed, with negative control and
  zero scoped leftovers. Clippy and lint passed. These are regression receipts,
  not historical attribution or deterministic signed-interleaving closure.
- [ ] Repair the newly reproduced producer lifetime defect: Host becomes
  visible before `claim_for_host` finishes unlinking. Cancellation can free
  and reuse that slot; the old producer then removes the replacement waiter's
  queue entry while it remains Parked (deterministic count 0 instead of 1).
  Two VM-free reds are retained in the branch receipt's `host-publication/`.
  Implementation census/order: `2026-09-29-el1-handback-publication.md`.
  The guest placement preparation now moves futex unlinking before target
  queue-lock release; its 1/8/32-waiter witness was red and is green. This
  does not repair the host-transfer red or close this checklist item.
  The producer-transfer implementation now passes the two restored red-first
  witnesses, waitv/cancellation and host-request controls (core 58, EL1 host
  74, ABI 32, kernel/semantics 2,459, serial-host 109, runtime 630; existing
  ignores unchanged). The combined fixes now have signed EL1 regression
  coverage at `257de53e0`; deterministic signed interleavings and the remaining
  retirement/restore lifetime audit are still required. See `owned-transfer/`
  and `exact-zone-wake/` for their distinct proof scopes.
  Cancellation-before-El1Held and delayed flag writes now have red-first
  repairs using incarnation-bound requests; incarnation exhaustion is also
  fail-closed. Core62/EL1host74/ABI32 and the broader VM-free regressions
  passed; see `tagged-requests/`. RecordRef still does not grant exclusive
  field access; post-publication retirement/restore audit remains open.
  Scheduler handback wakes now use exact targets: the captured-key/reaped-child
  witness is red-first, and matching continuation plus pre-enrollment delivery
  controls pass. Remaining producer/service/restore lifetime boundaries and
  deterministic signed bindings stay open; historical attribution is separate.
- [ ] Reduce Python's `SnapshotRestoreFailed`: record 1/incarnation 35925 was
  `Parked { seq: 17965 }` during host materialization; subsequent MM cleanup
  aborted. Compare against main before calling it a batch regression.
- [ ] Capture carrier stacks, event ring and core on reproduction; prove the
  failing ownership transition in a deterministic contract, then fix it.
  Deferred evacuation now has a deterministic red-first identity reduction:
  after cancellation/reuse, a saved bare RecordId publishes the replacement
  incarnation. Retaining RecordRef fixes that reduction at 1/8/32 records.
  Attribution to the historical Python crash is still open; see the branch
  receipt's deferred-handback section. A rebuilt, pinned Python run at
  `5ce5bd059` passed (395 tests, 51 skips), with no fatal capture triggered.
- [x] Bind delayed parent notification to deterministic signed capture/reap/
  delivery ordering. Source `2e6e3794a` passes with zero reaped wake attempts;
  the same fixture with the retained pre-fix method fails at one attempt.
  This is producer proof, not attribution of the original otmp failure.
- [x] Close the notification contract's scoped structural observation gap.
  Full candidate gates remain separate and open below.
  The new graph-scoped counters have red/green VM-free observations at 1/8/32
  deliveries: one retained thread visit per delivery, zero scheduler attempts
  after reap, plus a live-parent positive control and excess-work rejections.
  The first signed observation exposed an incorrect budget assumption:
  exact scheduler authentication can reject a retained generation after reap.
  It reported two visits/two attempts, with semantic ordering preserved.
  Counters now distinguish attempts from actual Queued/Kicked deliveries;
  the corrected signed bound is one authentication per thread and at most one
  delivered wake for the whole fixture. A live-parent delivery counter control
  was separately red-first. Corrected signed qualification passes on `9ba825eac`: two visits, two
  authentications, one delivered wake, complete observations, negative controls
  and zero scoped leftovers. Exact tested bytes and manifest are preserved.
  See `notification-work/`; no total scheduler work or timing claim is made.
- [ ] Accept and integrate locally only when all blockers/gates close.

Receipt on branch `integ/batch3`:
`docs/perf-results/2026-09-29-el1-batch3-resume/README.md` and its raw artifacts
(initial receipt commit `11e8c6a29`, extended by the deferred-handback
receipts). Read it in `wt-batch3`; it is not on main yet. Quiet Python passes
and 100 passing probe diagnostics do not erase the original reds.

### B. Integrate reviewed memory foundations

Development may proceed on the current unaccepted integration base; A's
acceptance is required for final landing, not independent memory development.
Produces one reviewed descriptor/return foundation without claiming the
still-disabled guest descriptor lane is active.

- [ ] Review descriptor + elastic-return diffs and branch-local receipts;
  preserve exact MM/frame/IPA/owner domains and rollback receipts.
- [ ] Integrate `work/cp2-el1-descriptor-owner` and `work/cp2-elastic-return`,
  reconciling interfaces/layout before running the memory regression net.
- [ ] Review T6 witnesses and wire a real scoped HostCowStats embed accessor.
  `wt-cp2-tests/.../tests/el1_sched.rs::host_cow_resolutions` currently panics;
  do not replace it with host-fault counts, zero, ignore or expected-green.
- [ ] Keep future-feature red witnesses explicit on their development branch
  until they are satisfiable. Never mark an intentionally red gate accepted.
- [ ] Record which foundation contracts are proven and which ownership gates
  remain open; pass the full batch gate before accepting this integration.

Source-confirmed in descriptor `vcpu_loop/signal.rs`:
`GuestDescriptorLanePrecondition::current()` has `fork_parent_arming=true`,
`host_copyout=false`, `backend_writers=false`. Descriptor Prepare/Publish/
Protect/Retire/CowRepoint/ForkArm machinery is not full production ownership.

### C. Complete the pipe/eventfd vertical

**Open vertical; current implementation priority is memory, as specified above.**
Consumes reviewed adapter, host and fixture branches; produces live in-guest
pipe/eventfd service with exact descriptor/operation lifetime. Checkpoint 3
still includes the broader work in E.

Development update (2026-09-29): `wt-cp3-adapter` is clean at local development
merge `923c55550` (adapter `b0313df83` + host `77b6f40a1`). Runtime backing now
retains the same kernel IPC authority. Blocking-eventfd writes own their value
and functional description lease, use object-queue enrollment, survive fd reuse
and enrollment gaps, and avoid the host-fd reactor population. Guest-produced
host wakes now drain an indexed pending set through the exact kernel; the
unregistered global callback is removed. ABI v3 authenticates that layout.
Final wake-stage checks: 21 ABI IPC pass; 58 kernel IPC pass, one pre-existing
ignored; ABI/kernel/runtime Clippy and formatting pass. The prior continuation
stage passed 90 regression tests. Receipts live in that worktree's
`docs/perf-results/2026-09-29-el1-ipc-integration/`. No signed qualification or
main integration is claimed. Table publication/lifecycle, fixture integration
and the five signed witnesses remain open. Refresh compiler captures only at
the stable qualification boundary.

Descriptor-lifetime follow-up at development commit `7a44fa384`:
Eventfd host ownership is a shared OFD pin; last host close no longer directly
retires backing held by a guest pin. Admission refusal rolls back its object.
Kernel IPC: 60 pass, one existing ignored; kernel/runtime Clippy and fmt pass.
Pipe OFD lifetime is committed at `964c48bb4`: both endpoint
pins are admitted transactionally; guest writer pins prevent premature EOF after
last host close. Second-OFD refusal rolls back endpoints, OFD and storage.
Pipe regressions passed 87/87; final IPC 62 pass, one existing ignored;
kernel/runtime Clippy and formatting pass. Shared supported mutable flags and
access mode are bound at `3721ff3a3`; host/guest changes use one OFD and terminal observations do
not retain functional pins. Native ARM64 Linux confirmed eventfd O_RDWR reporting.
Final IPC 64 pass/one existing ignore, pipe 89, eventfd 9 and fcntl 6 pass;
populations overlap. Affected Clippy and formatting pass. Full table lifecycle
and publication remain open. These remain development receipts, not signed
migration acceptance.

Earlier IPC development head was `375dddee3` in `wt-cp3-adapter`; the live routing update above supersedes this snapshot.
Atomic pinned replacement reuses dup2's transaction; HostTable now owns shared
create/grow/fork/replace/close/exec/destroy and releases backing after core locks.
Red-first replacement/retirement witnesses are retained. Descriptor core 27/27,
kernel IPC 67 pass/one existing ignore, affected Clippy and formatting pass.
HostTable is not yet attached to the kernel FileTable, and nothing new is
published to EL1. Connect live namespace mutations, implicit stdio, fork/exec
and functional retirement next; do not equate diagnostic Arc lifetime with
functional table lifetime. Signed qualification remains pending.

Fixture review rejected `fd27e748d` as acceptance evidence: guest parks/resumes
and host counts are calculated from a feature flag and loop count, generations
are fixed to 1, the signal mode lacks signal/partial-write operations, and the
embed runner labels whole-container counters as a steady-state window. Do not
merge or enable these reports unchanged. Retain useful scaffolding/contracts,
replace the invalid observations and missing semantic cases at qualification;
continue descriptor ownership rather than starting another diagnostics detour.

- [ ] Review and reconcile adapter + host + fixture on one integration base.
  T1 objects and T2 waits are already ancestors of the adapter. Host prerequisite
  subsets were merged; do not assume the complete host branch is integrated.
- [ ] Compile/test the existing runtime glue before adding missing code.
  Contrary to the handoff, the adapter already contains the handback intercept
  before ordinary preparation (`vcpu_loop/mod.rs`), owed host-wake delivery at
  `served_with_work`, backing registration (`runtime.rs`), and interrupt/restart/
  partial-progress helpers (`vcpu_loop/zone.rs`). `7baabfd95` and the top WIP
  contain code, not verified completion. Audit ordering and every return path.
- [ ] Complete the host-originated blocking continuation sharing the existing
  completion engine; `block_on_object` was not found in either active branch.
  Turn `serial_host_el1_ipc_blocking_eventfd_write_retains_value_until_capacity`
  green without dropping the pending value or parking an executor on guest work.
- [ ] Complete table publication/create/fork/unshare/destroy, dup/dup2/fcntl,
  CLONE_FILES, exec CLOEXEC, SCM_RIGHTS/install_pin and endpoint retirement.
  Unpublished tables must continue to fail closed to the host path.
- [ ] Turn all five `el1_ipc_*` signed witnesses green: `fd_lifetime`,
  `park_wake_races`, `pipe_eventfd_roundtrips`, `mixed_venue_lifecycle`,
  `signal_restart_and_partial_write`. Use scales 1/8/64 and two-process pairs;
  require nonzero guest parks, zero IPC-caused exits per round trip, correct
  bytes/errno/SIGPIPE/restart behavior and complete scoped counters.
- [ ] Run the full batch gate and accept only this named vertical.

The fixture handoff reports ~261k host exits and ~64k service placements per
baseline test, all five red on absent guest parks. Requalify that baseline
against the actual integrated fixture; do not infer execution from validators.

### D. Finish checkpoint-2 memory ownership

Consumes B, the reservation branch and ownership fixtures; produces full
anonymous-memory ownership with no remaining host descriptor writer/pause.

- [ ] Reproduce/reduce the reservation fixture race in
  `vcpu_loop/memory.rs::production_carrier_active_target_services_publication_at_its_next_entry`.
  The source still polls `is_quiescing` for one second while LeaveGuestOnKick
  clears guest entry; a latched handshake is a proposal, not a verified fix.
- [ ] Review the unverified reservation-provider/projection WIP; complete the
  carrier-owned metadata resolver across runtime/HVF. Reuse the present
  `plan_host_first_touch` / `commit_host_first_touch_after_guest_publish` split.
- [ ] Move anonymous-private facts from MemState to the authoritative shared
  reservation model: brk/mmap/munmap/mprotect, VMA split/merge, FirstTouchArming,
  madvise/mincore, proc maps, fork/exec/exit and exact lifecycle handoff in
  `dispatch/mm_authority.rs`. Preserve file/shared-mapping semantics.
- [ ] Activate `dispatch_anonymous_with_reservations` in personality dispatch
  only after those authorities are joined; no independent EL1 policy cache.
- [ ] Complete copyout conversion, guest replacement-frame COW copy window,
  fork arming/publication and all remaining backend writers. Prove foreign
  accesses, two-live-MM isolation, denied access and rollback/refusal behavior.
- [ ] Publish the complete writer census; only then remove the host page-table
  pause. Prove first-touch/COW in guest, prompt scoped frame return/reuse and
  pause-free two-MM progress using the strengthened T6 witnesses.
- [ ] Pass semantic and scaling contracts, full batch gate and workload ratios;
  accept checkpoint 2 only after the integrated ownership path is active.

Frozen layout: counters `[0x100000,0x120000)`, SharedReservations
`[0x120000,0x180000)`, descriptor transactions `[0x180000,0x1A0000)`;
IPC table map region offset `0x103_0000`. Adapter IPC window is
`0x2D_0C00_0000` with 2 MiB directory + 128 MiB pool. Coordinate any change
centrally and prove layout bounds; these are interface assignments, not
permission to overlap or silently resize regions.

### E. Close all remaining ownership stages

| Stage | Required deliverable and decisive proof |
|---|---|
| 2a host namespace | Finish measured namespace budget/cost work before names/cache ownership; transactions preserve containment and physical/cache coherence, including rename no-op/hardlinks; controlled Linux ratios plus native macOS I/O controls |
| 3 remainder | EL1 fd tables/descriptions/offsets/flags, AF_UNIX, timerfd, epoll/poll/select, signals and in-zone loopback; preserve credentials, peer/SCM identity, readiness, partial operations and cancellation under exhausted default executor capacity |
| 4 names/cache | Authoritative EL1 dentry/stat/name resolution and host-file page cache; validated host namespace operations, host-writer/shared-alias coherence, mutation rollback; remove replaced file-zone implementation |
| 5 lifecycle | EL1 fork/exec/address-space lifecycle and image loading; parent/child identity, vfork sharing, exec sibling drain, wait/reparent/reap, credentials/rlimits/pgrps/sessions; ptrace and core semantics with host core-file output |
| 6 x86 (deferred) | Outside the active goal; future work requires the same neutral semantic cores through shared x86 engine; native x86 oracle and real KVM/bhyve/NVMM lane evidence for the declared support matrix; no translated amd64 Docker substitute |

Clocks remain guest reads of calibrated vvar/CNTVCT where appropriate; external
sockets/DNS, contained host-file operations, shared host-file aliases, CLI
terminal/stdin/stdout and process-boundary reporting retain the host roles in
the design. These boundaries must be audited, not counted as missing EL1 work
or accidentally migrated into duplicate semantics.

Before each stage starts, attach its bounded source/contract/fixture brief and
explicit acceptance population here. Keep every ownership row in the design
assigned to a stage. Checkpoint 6 and its hardware/oracle discovery are
explicitly deferred by the user, not dependencies of ARM64 acceptance.

## Common acceptance and landing protocol

1. Review the exact diff and relevant contracts; reduce new failures red-first
   in the cheapest capable layer. Assert semantics and deterministic work.
2. Integrate onto the current accepted base; commit, reconcile inventories on
   a clean tree, inspect generated changes, then run `just lint-domains` and
   full `just ci`. No stale branch-local result qualifies the merged tree.
3. With no guest alive, `just build`; record HEAD, SHA-256, CDHash, LC_UUID,
   hypervisor entitlement and DOF. Record each signed embed executable
   separately. Preserve fixture source/executable hashes and image digests.
4. Run the batch regression population: `roreadwrite`, `protnonesyscall`,
   `memflagmatrix`, `coredumpbit`; empty `mmapprivfile` diff; `windowcoherence`
   four executions per libc; signed `carrick-embed el1_` plus changed contracts
   and crash-register witness; full `just --no-deps conformance-probes`.
5. Run the eight cpython suites twice: fork1, wait3, wait4, threading,
   concurrent_futures, multiprocessing_fork, mmap, subprocess; Go build twenty
   times. These are fixed acceptance populations, not retry-until-green.
   Preserve every failure/automatic-confirmation result. Existing serial
   oracle orchestration is not permission to reduce fixture concurrency.
6. Run `just --no-deps el1-gate` on the built artifact and the applicable smoke
   and full conformance promotion (`just --no-deps conformance smoke`, then
   `just --no-deps conformance full`). Check CLI identity between rungs;
   rebuild/re-sign invalidates prior artifact acceptance. The current el1-gate
   recipe is only one required population, not the entire migration gate.
7. Measure uninstrumented release workloads on a quiet host against pinned
   same-image native Linux, serialized Carrick/Docker phases, with the contract's
   declared statistic/sample count. Start with Go build, cpython-threading and
   cpython-subprocess; final acceptance covers the full declared ecosystem.
   Keep raw Linux ratios and native macOS I/O controls separate. CPU attribution
   profiles diagnose cost; they are not timing acceptance.
8. Record run IDs and prove scoped cleanup. Advance status only for the
   proven population; then integrate accepted work locally and reverify the
   final merged artifact. No push/PR is authorized by this documentation edit.
   Do not follow the old scratch script's unconditional push instructions.

Memory regression filters: `el1_memory_first_touch_stays_in_guest`,
`el1_memory_fault_entry_preserves_context`,
`el1_anonymous_permission_transitions_stay_in_guest`,
`el1_anonymous_mapping_retirement_returns_and_reuses_frames`,
`el1_fork_cow_resolves_in_guest`, `discard_fork_threads_contract`,
`el1_sched_mm_occupancy_two_processes`,
`el1_sched_signal_reaches_a_parked_thread`,
`el1_sched_exec_from_a_sibling_with_parked_threads`,
`crash_core_attributes_the_el1_parked_sibling_registers`; add the reservation,
discard/exit-return and pause-free tests when their implementation is joined.
Use function-name filters with `scripts/test-signed.sh`, not filenames.

## Stop conditions and definition of completion

A semantic mismatch, load-dependent failure, lost wake, ownership ambiguity,
structural-budget failure or invalid measurement stops promotion. Missing
identity, dropped/unknown counters, absent required execution bindings and
unavailable native hardware/oracles remain explicit blockers. A ≥10x ratio
for a valid completing workload returns immediately to correctness triage;
ratios above the ≤2x objective remain performance failures. Timeout rows are
not ratios. Do not weaken budgets, inflate timeouts, poll away races, reduce
concurrency, hide red fixtures, or use passing reruns to dismiss failures.

Every acceptance update records: exact revision/artifacts, merged versus
branch-local state, contracts and before/after ownership census, red/green
witnesses, completed row counts, timing controls, cleanup, removed paths and
remaining blockers. Update this controller after each accepted batch so the
next agent does not reconstruct state from chronological reports.

The active ARM64 migration goal is complete only when checkpoints
0/2/2a/3/4/5 and final acceptance are closed on the declared ARM64
support/workload population; all in-scope design
ownership rows have accepted owners, production routing uses them by default,
replaced paths are removed, and no required proof is deferred. This remains
experimental software, not a claim of a hardened boundary or production
readiness. Checkpoint 6 remains explicitly deferred and must not be reported
as accepted by ARM64 completion.
