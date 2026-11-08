# #1879: contention cannot become a fatal or errno

Read-only design draft, 2026-11-08. Base: `84cb22e9f56ee3b1d106f33cf06e56c62f2f6b7c`; GitHub main still named that SHA when checked. Read #1879, PR #1875 comments/diff at head `63308d2179`, and fetched PR #1863 head `b3f51a91480fc0b58df144debd181988fe26b7f6`. No builds, code changes or GitHub writes. This convenience document is the only workspace addition.

Recommendation: reuse the existing scheduler refusal protocol. Admission attribution is valuable, but a diagnostic payload is not release-notification custody. PR #1875 still explicitly converts contention into a fatal reason, despite its direct-conversion compile-fail tests.

## 1. Existing-mechanism inventory

Searches performed, followed by targeted source reads:

```
rg -n 'enum .*|Busy|WouldBlock|Retry|Contended\(' crates/{carrick-kernel,carrick-el1-linux,carrick-personality-linux,carrick-x86-cpl0,carrick-core,carrick-runtime}/src
rg -n '^\s*(Busy|WouldBlock|Retry\w*|Contended)\b|enum (ObjectWaitError|SpaceWaitCause|NativeProcessError|Refusal)' crates --glob '*.rs'
rg -n 'Contended\(' crates --glob '*.rs'
rg -n 'invalid_completion\(|native_service_invariant|\.errno\(|linux_errno\(' crates/carrick-el1-linux/src/{dispatch.rs,native_process_runtime*} crates/carrick-x86-cpl0/src
rg -n 'NativeServiceBusy|invalid_completion\(|fn errno|fn error_result|::errno|run_failure_reason\(' crates/carrick-el1-linux/src crates/carrick-personality-linux/src crates/carrick-x86-cpl0/src --glob '*.rs'
rg -n 'coordinate_.*wait' crates/carrick-el1-linux/src crates/carrick-personality-linux/src crates/carrick-core/src
rg -n 'MmErrorLinux|\.errno\(' crates/carrick-personality-linux/src/mm* crates/carrick-kernel/src/dispatch/mem*
rg -n '\.errno\(' crates/carrick-el1-linux/src/mm_portal
rg -n --hidden 'contention_variant:Busy|NativeProcessError' .agents .github scripts
```

A supplementary local enum-body scan associated variants with enum names. Locations below are base-SHA locations unless labelled PR. All paths start with `crates/`. “Reuse” preserves an existing mechanism; “migrate” replaces mixed producer/consumer outcomes; “retire” removes an unsafe or redundant conversion.

| Representation | Location | Disposition |
|---|---|---|
| NativeProcessError::{Busy,OwnerWait,ForkRefused} | carrick-el1-linux/src/native_process_runtime.rs:299 | Migrate; retire universal errno at 329 and run_failure_reason at 313. |
| NativeForkCause::Busy and error() | carrick-el1-linux/src/native_fork_refusal.rs:37,72 | Migrate; retain diagnostic stage separately. |
| NativeServiceBusy construction | carrick-el1-linux/src/dispatch.rs:2375 | Retire contention-to-fatal production conversion. |
| reservation Refusal::{Busy,PreparedConflict,MetadataRequired} | carrick-core-abi/src/mm/reservation.rs:539 | Migrate at authenticated owner boundary; distinguish release sources. |
| SpaceWaitCause | carrick-sched-core/src/spaces/notification.rs:14 | Reuse PreparedOverlap, Editor, Reservations, PendingEdit, Gate, Metadata. A cause is not a ticket. |
| Refusal::Contended(ReleaseTicket), Attempt::Contended(ReleaseCause) | carrick-sched-core/src/refusal.rs:29,47 | Reuse; these are the tuple Contended declarations found on base. Reuse Settled and Rerun too. |
| ObjectWaitError::{Busy,Changed,Occupied,Stale,Exhausted} | carrick-sched-core/src/object_wait.rs:402 | Migrate adapters. Changed retains/reprobes; Occupied requires ownership/handoff discrimination. |
| NativeAdmissionError::Contended(Box<NativeAdmissionContention>) | PR #1875, native_process_runtime.rs added declaration | Migrate to scheduler refusal; reuse seven origin diagnostics; retire fatal_reason(). |
| DelegatedAnonymous::Contended(SpaceWaitCause) | PR #1863, carrick-el1/src/memory.rs:867 | Reuse narrow cause transport into authenticated source. |
| DelegatedStep::Contended(SpaceWaitCause) | PR #1863, carrick-personality-linux/src/pending_anonymous.rs:6 | Reuse same transport; no independent contention vocabulary. |
| Parked::Retry(IpcOpToken) | carrick-el1-linux/src/ipc.rs:1395 | Reuse retained token; migrate undifferentiated Refused. |
| NativeResume::{RetrySavedSyscall,RetrySyscall}; ServiceCompletion::RetrySyscall | carrick-el1-linux/src/native_process_runtime.rs:105; native_process_runtime/service.rs:342 | Reuse resume actions with owned phase. |
| RootMappingIncarnation::Busy; RootFaultAdmission::Busy | carrick-core/src/mm/fault.rs:45,150 | Migrate; never collapse contention into Unmapped. |
| ForkError::Busy; MmError::Busy | carrick-core/src/mm/fork.rs:28; mm/transaction/error.rs:36 | Migrate with fork/MM terminal consumers. |
| CopyoutPreparation::Busy(OperationToken); UserWriteError::Busy | carrick-core/src/mm/transaction/user_write.rs:31,71 | Reuse operation storage; migrate bare refusal; preserve cursor. |
| ThreadPublicationReservationAttempt::Busy(PreparedThreadClone) | carrick-kernel/src/kernel/operations/thread.rs:182 | Reuse retained preparation; witness actual release. |
| ProcessThreadExit::Busy | carrick-kernel/src/kernel/process_lifecycle.rs:151 | Reuse owned lifecycle handoff. |
| SnapshotError::Busy; KernelSnapshotError::Busy; RingReadError::Busy | carrick-kernel/src/kernel/address.rs:192; kernel/snapshot.rs:276; event_ring.rs:1134 | Reuse diagnostic refusal; not syscall completion. |
| AuthorityError::WouldBlock; PipeDrain::WouldBlock | carrick-kernel/src/file_authority/types.rs:1347; dispatch/fs/pipe.rs:937 | Reuse actual readiness semantics; separate nonblocking EAGAIN from internal contention. |
| HostFirstTouchError::Busy(ReservationBusy); RootAccessRefusal::Busy(ReservationBusy) | carrick-kernel/src/dispatch/mem/host_first_touch.rs:11; dispatch/mem/el1_reservations/provider.rs:33 | Migrate boundary handling using existing reservation owner. |
| ProcessForkStart::Busy; PreparedInProcessFork::Retry | carrick-runtime/src/vcpu_loop/quiesce.rs:254,320 | Reuse owned continuation; migrate bare refusal adapters. |
| HvpatchProductionPhase::RetryProcessFork/RetryCloneThread/RetryThreadExit | carrick-runtime/src/vcpu_loop/binding.rs:299 | Reuse lifecycle phase custody. |
| PersistentThreadExitDisposition::Busy | carrick-runtime/src/vcpu_loop/threads.rs:1540 | Reuse owned exit. |
| CrashLeaseDrainTimeout::Busy(ThreadId) | carrick-runtime/src/vcpu_loop/crash.rs:37 | Reuse timeout diagnostic; not permission to fatal on initial contention. |

No Busy/WouldBlock/Retry enum declarations were found in base carrick-personality-linux or carrick-x86-cpl0; both consume shared types. Test-only MockReadMode::RetryOnce (`carrick-kernel/src/kernel/mm_access/test_support.rs:123`) and ServiceWitness::Retry (`carrick-el1-linux/src/aarch64_process_tests/native_child_handoff_tests.rs:992`) remain test-only.

Wider shared representations:

- Migrate mixed producer adapters: ServiceError::Busy (`carrick-core-abi/src/service.rs:575`), MetadataResolutionError::Busy (`metadata_extent.rs:43`), EntryDecodeError::Busy (`carrick-guest-arch/src/lib.rs:587`), ProcessRecordTransitionError::Busy (`carrick-kernel-arena/src/process.rs:475`), ArchError::Busy (`carrick-el1/src/isa.rs:4`).
- Reuse scheduler owners, migrate error boundaries: BirthError::Busy(TaskId) (`carrick-sched-core/src/process/birth.rs:29`), ExitError/TaskSetError::Busy(TaskId) (`process/exit.rs:135,557`), WaitError::Busy(TaskId) (`process/wait.rs:114`), ExclusionRefusal::Busy (`spaces/notification.rs:575`).
- Migrate internal contention separately from readiness: pipe Error::{WouldBlock(WaitFor),Busy} (`carrick-pipe-core/src/lib.rs:32`); fd Error::{Busy,Contended,PinRaced} (`carrick-fd-core/src/lib.rs:68`), StorageError::Contended (`storage.rs:14`), HandleError::Contended (`handle.rs:470`); IpcError::Contended (`carrick-el1-abi/src/ipc.rs:883`). IpcTableMapError::Occupied (`ipc_tables.rs:66`) cannot justify treating a transient lookup as authoritative absence.
- Reuse dependencies: MemoryPrepareError::OwnerWait (`carrick-guest-mem/src/prepared.rs:138`), MemoryError::OwnerWait (`lib.rs:1333`), SupplyProgress/TransferProgress::OwnerWait (`carrick-aarch64/src/user_transfer.rs:15,386`). Their adapters must preserve custody.
- Reuse retained retry/retirement: CarrierStage2RetireOutcome::RetryPending (`carrick-core-abi/src/mm/custody.rs:47`), ResumeAction (`carrick-el1/src/sched.rs:223`), VcpuLeaseDrainEnrollment::Busy (`carrick-hal/src/threaded.rs:471`), ForeignMmTransportError::Retry (`foreign_mm.rs:704`), SharedWaitStep::Retry (`futex.rs:19`).
- Reuse distinct owner/diagnostic representations pending producer audit: SlotSearch::Busy (`carrick-signal-core/src/fasync.rs:142`), DescriptorRefusal::{Occupied,Contended} (`carrick-mmu-core/src/descriptor_refusal.rs:6`), TerminalRefusal::Occupied (`aarch64.rs:1553`), VirtualPtraceStopRequest::Busy (`carrick-host/src/guest_cpu.rs:840`). Host address Occupied (`host_proc.rs:62,1286`) and fd slot Occupied (`carrick-fd-core/src/handle.rs:746`) are states, not automatically contention.
- Outside this migration: xtask maintenance/CI Busy states; HVF diagnostic Observation::Contended (`carrick-vmm-hvf/src/metadata_grant.rs:1328`), retirement RetryPending (`trap/memory_protection.rs:2642,3107`), RetryCommittedWinner (`trap/cow_engine.rs:8054`), and observability OwnerWait (`carrick-observability/src/probes.rs:322`). Reuse unless their actual guest boundary is implicated.

## 2. Type split and control flow

Use existing `Refusal<'z, LinuxVisibleError, C>` for resumable operations, and `Settled<LinuxVisibleError>` after commitment. Keep the scheduler crate personality-neutral. Never embed a mixed error in its Guest branch.

`invalid_completion` accepts only invariant-only `NativeInvariant`. Replace its broad NativeService fatal-reason payload with a closed invariant payload. Fatal encoding accepts only that payload. x86 fatal adapters and NativeRunFailureReason encoding receive the same restriction. Remove Busy, OwnerWait and metadata-wait encodings from these production terminal APIs.

Introduce closed `LinuxVisibleError` in the Linux personality, with private representation and named constructors at validated semantic producers. The sole final lowering is `lower_linux_error(LinuxVisibleError) -> LinuxErrno`, followed by wire retval encoding. It accepts neither Refusal, invariant, native mixed error nor ReleaseTicket. Real nonblocking/resource-limit/timeout EAGAIN, EFAULT and unsupported-operation errors remain legitimate; replenishable internal capacity is not automatically a guest resource limit.

No From/Into between contention, invariant and guest halves. No blanket adapter from the old mixed error. The only reviewed terminal encoders map validated invariant→fatal transport and validated Linux-visible error→LinuxErrno. There is no contention→terminal conversion. Split legacy owner results exhaustively while holding authenticated authority; do not guess the cause later.

External contention retains the exact operation, task/record generation, inputs, completion phase and partial-I/O cursor. Observe the existing source before probing; enroll with the ticket, probe once after enrollment, release execution capacity, and resume the owned checkpoint. Reuse `coordinate_prepared_edit_wait` (`carrick-core/src/wait.rs:239`) and existing object/service coordinators. No polling, unbounded immediate retry, dropped signal checkpoint or replay of completed work.

Self-contention must resume or finish the existing operation. Fresh-root admission first recognizes an existing pending writer instead of acquiring a second root authority. Host-requested handoff transfers custody to its existing venue. Before external park, release local guards and finish/transfer self-held publication responsibilities. Never suspend the only operation able to release the authority being awaited.

Registration acquires/reserves pending custody before releasing an adopted birth slot or publishing credentials, or retains an explicit rollback-capable transaction. PR #1875 does not fix this order. For registry collisions, identical admitted identity resumes, unrelated live ownership supplies a release source, and incompatible immutable identity becomes an invariant only after validation. A collision label is insufficient.

Pre-reserve checkpoint storage before irreversible effects. Preserve EL1/CPL0 stack budgets; do not introduce large by-value payloads or require infallible allocation on refusal.

Use the repository's compile-fail doctests. Exact proposed failing function bodies, with real public imports:

```
fn fatal(t: ReleaseTicket<'_>) -> ! { invalid_completion(t) }
fn errno(t: ReleaseTicket<'_>) -> LinuxErrno { lower_linux_error(t) }
fn fatal_union(r: Refusal<'_, LinuxVisibleError>) -> ! { invalid_completion(r) }
fn errno_union(r: Refusal<'_, LinuxVisibleError>) -> LinuxErrno { lower_linux_error(r) }
fn convert(t: ReleaseTicket<'_>) -> NativeInvariant { t.into() }
fn convert_guest(t: ReleaseTicket<'_>) -> LinuxVisibleError { t.into() }
fn wrong_half(e: LinuxVisibleError) -> ! { invalid_completion(e) }
```

Pair with positive compilation controls using the same imports; unresolved/private imports must not falsely satisfy the negative tests. Reject a mixed refusal in Settled too. #1875's two negative tests do not prohibit its explicit `contention.fatal_reason()` route. Types also cannot prevent deliberately discarding an error and manufacturing an unrelated invariant: private constructors, exhaustive matching and review of wildcard terminal branches remain necessary.

## 3. Fatal and errno boundary inventory

Classification: **a** already handles/retains contention locally; **b** needs an external wait or narrower no-contention signature; **c** includes self-contention/handoff and must resume/transfer existing custody. Mixed b/c boundaries are not proof every concrete producer returns Busy. Paths below default to `crates/carrick-el1-linux/src/`.

| Sites | Classification and action |
|---|---|
| dispatch.rs:1523,1811,1913 | b/c: service exit, declined fault, user-return admission; retain result/fault/checkpoint. |
| dispatch.rs:1525 via native_service_completion:2324 and converters:2314,2336,2363 | b/c: split settled completion from resumable refusal. |
| dispatch.rs:1437,1798,1902 | Current constructors produce Stale, not demonstrated Busy; narrow signatures. |
| native_process_runtime.rs:4922,4925 | c for operation restoration; duplicate preparation remains authenticated invariant. |
| native_process_runtime.rs:7843,7851,7858 | a for explicit preparation retention, c for yield/cancel failure. Retention alone does not prove wake liveness. |
| dispatch.rs:3425,3432,3440 | b/c candidates in PipeOutput Drop cancel/unpin/backing release. Move fallible cleanup into owned settlement before Drop. |
| dispatch.rs:3469,3488 | b: map_fd_error maps Busy→EBUSY and Contended→EIO; map_ipc_error has broad EIO fallback. |
| dispatch.rs:3512,3515,3517,3608,3619,3621,3656,3661,3665,3667,3670,3729,3734 | b/c fan-in to those maps; retain growth, claims, pins, dup and release state. Later fd family arms need the same migration. |
| dispatch.rs:3759 neighborhood, bind_object_wait is_err→EIO | b: distinguish stale binding from contention. |
| native_process_runtime/service.rs:769 | a: locally narrowed to Fault/Unsupported/NoChild after Busy/OwnerWait handling at 752; express this in the type. |
| native_process_runtime/service.rs:619,655,752,874,1128 | a/c: retain checkpoint behavior, prove real release and preserved identity. |
| native_process_runtime/service.rs:1835,2062,2066 | a/c: Changed rerun and host-requested Occupied handoff are precedents. |
| native_process_runtime.rs:4408,4415,9772 | b/c: signal already enqueued; retain owed wake publication, do not invite replay via errno. |
| native_process_runtime.rs:4470 | b/c: remove universal native error-return helper. |
| native_process_runtime.rs:5352,5355,5375 | Explicit Stale identity producers, not Busy sources; classify invariant versus guest error explicitly. |
| native_process_runtime.rs:5388,5392,5427 | c for pending IPC/self-handoff; b for independent timer admission. Remove direct Busy→errno. |
| native_process_runtime.rs:5396 | Distinguish actual resource exhaustion from internal replenishable capacity. |
| native_process_runtime.rs:5443,9454,9522,9842,9848 | b at service interface: clock/deadline APIs must become infallible/invariant-only or provide a real dependency, never an invented clock wait. |
| native_process_runtime.rs:7966,8018,8032,8100 | b/c: thread stock, MM/member binding and lifecycle settlement; committed birth cannot become a fresh clone error. |
| native_process_runtime.rs:9861,9917 | b/c: preserve timed-wait/suspend masks, deadline and continuation. |
| carrick-personality-linux/src/mm.rs:305–320 | b: retire MmErrorLinux on mixed MmError; Busy→16 and MetadataRequired/Wait→11 are unsafe generic lowerings. |
| aarch64_process.rs:1363; carrick-x86-cpl0/src/native_process.rs:154 | b: both OwnerVenue::encode_error signatures change in the same slice. |
| mm_portal/production.rs:40,372,417,523; maintenance.rs:432; fork.rs:698,795 | b/c: retain MM/fork/owed-return state and exact owner dependency. |

Additional terminal fan-in: runtime `run_failure_reason()` at 4159,4428,5649,5674,5964,7695,7935,7989,8040,8378 and service.rs:2415 are b/c until producers are narrowed. Literal Quarantined/Stale encodings at runtime 4162,5898,5913,5942,5971,6010 are not themselves contention conversions.

On x86, `linux_personality.rs:412,414,424` ordinary/forced signal return, `505,507,517` IRQ signal return, `539` service continuation, and `981,986,989,999` root/runtime/admission/entry are mixed-error fatal boundaries, b/c. Use shared checkpoint ownership with ARM; only frame mechanics differ. A forced fault cannot report handled without a signal frame or retained delivery. Other fatal_boot calls checking missing bindings/frames or invalid terminal statuses are not evidence of Busy by themselves.

Wider fatal search found lifecycle.rs, ipc.rs, cow_resolver.rs, native_run_failure.rs, process_owner.rs and native_process_custody.rs. Some are legitimate graph/revision/stale-token invariants; erased Option/Refused/wildcard branches need producer tracing. Specifically `ipc.rs:1147` sends Parked::Refused to fatal; snapshot at 1373 collapses object-wait errors to None. These are b/c candidates. IPC ticket paths at 609,2298,2366 are a precedents.

**Coverage limitation:** this inventories principal typed native/MM sinks and wider candidate families, but does not establish exhaustive transitive reachability for every erased Option/wildcard or kernel/runtime errno adapter. It therefore does not satisfy the requested “EVERY call site” proof yet. Finish source tracing for later fd family arms, poll readiness helpers, lifecycle/IPC wildcard fatals and host first-touch lowering before implementation briefs are frozen. #1856/#1878 also require accounting for wrong boolean/readiness answers, not merely errno calls.

## 4. Census and authority debt

`authority_source.rs:2638–2644` already exempts closed scheduler `refusal::{Refusal,Attempt}` vocabulary. At 2647–2662 it counts Busy, Contended, OwnerWait, PinRaced and Occupied as `contention_variant:<name>`. `authority_debt.rs:486` assigns exact owner/lane cohorts. #1875 correctly fails because its new owner has no allowance.

Existing cohort, `scripts/migrate/authority-debt-ceilings.json:35032`:

- family: contention_variant
- operation: contention_variant:Busy
- owner: carrick_el1_linux::native_process_runtime::NativeProcessError
- lane: shared
- ceiling: 1.

The same owner's contention_variant:OwnerWait at 35298 has ceiling 1. NativeForkCause has its own Busy cohort immediately before the native-process cohort.

Do not add a ceiling for NativeAdmissionError's contention_variant:Contended. Replace that duplicate declaration with existing scheduler Refusal. Delete NativeProcessError::Busy as its remaining producers migrate and lower the existing cohort 1→0. Similarly retire OwnerWait and NativeForkCause::Busy. Do not transfer an allowance to a new owner while leaving the old declaration alive. Admission-only conversion can leave a counter unchanged temporarily; it cannot honestly claim a decrease until the old declaration is removed. A strict first-slice decrease requires eliminating an entire existing cohort, not hiding its residual uses.

#1863 adds a narrow exception at scanner line 2648: exactly owners `carrick_el1::memory::DelegatedAnonymous` and `carrick_personality_linux::pending_anonymous::DelegatedStep`, variant Contended, one unnamed SpaceWaitCause field. Fold this into the same closed transport classification, not a global Contended exemption. Its last-path-segment check is weaker than canonical type identity: reject shadow/unrelated SpaceWaitCause, extra fields and extra owners. Resolve the canonical imported scheduler cause; if identity cannot be proven, count/reject rather than guess.

Admission origin/record diagnostics do not qualify for that exemption: they have no authenticated release source. Reuse scheduler Refusal instead of adding NativeAdmissionError as a third exempt owner.

Known-answer scanner witnesses: base Busy counted once; deleting it lowers the existing cohort; scheduler refusal accepted; diagnostic-only Contended rejected; both approved cause transports accepted; fake/shadow cause and third owner rejected; old Busy plus arbitrary new contention vocabulary rejected. Compare against the actual merge-base, never HEAD itself. No raised ceilings, rename-to-escape-census or blanket test exemption.

## 5. Ordered migration slices and witnesses

All slices target fewer than about 4k changed lines and include both ISAs. These are estimates, not measured diffs. Split oversized work by producer family without permanent V2 shims. Review shared interfaces and cross-crate lock order before coding.

1. **Admission/checkpoint custody; absorbs #1875.** Reuse its seven origin diagnostics, replace diagnostic contention with existing Refusal, make registration transactional, resume self-held work, retain ordinary/IRQ/forced-fault delivery on both ISAs. Proposed production-entry red witnesses: `user_return_external_owner_busy_once_then_signal_delivered`, `fresh_root_own_pending_writer_handoff_completes`, `thread_birth_busy_once_preserves_adopted_slot`. Hold the real owner, call actual entry, release it, and let scheduler resume. Cover all seven origins; synthetic collision seams are not naturally reachable signed schedules. Lone spinning EL0 must receive SIGKILL after the one IRQ without a second test-invoked entry. Preserve completed syscall result and single signal delivery.
2. **Service/lifecycle settlement.** Split service outcomes and run-failure conversions; retain committed birth/wake/publication. Witness `service_completion_busy_once_keeps_result_and_releases_executor`, plus clone/exit/signal-wake variants through production lifecycle entry. Assert no duplicate birth or replay, one completion, and progress with default pool exhausted. Lower each fully eliminated cohort immediately.
3. **IPC/fd/readiness.** Carry authenticated map/table/object refusal through read/write, poll, pipe creation, dup and cleanup. Witness `poll_unrelated_map_publication_busy_once_preserves_ready_answer`, `pipe_pair_publication_busy_once_preserves_claims`, `ipc_handoff_busy_once_retains_token`. Use two live tasks and real publication/release. Assert unchanged output before completion, exact descriptor generation/cursor and no repeated readiness query after poll has completed. Existing IPC slot Busy-once tests are controls, not substitutes.
4. **MM/fork/owed physical return.** Remove mixed MmErrorLinux lowering from shared OwnerVenue and both ISA adapters; retain exact reservation/editor/pending-edit/metadata source. Integrate #1863 semantics and narrow census treatment. Witness `owed_physical_return_reservations_busy_once_then_success`: wrong-cause publication must not wake; Reservations release must complete exactly once. Add self-owned edit handoff and two-live-MM copyout witnesses retaining delivered bytes without guards across park.
5. **Final union removal and terminal enforcement.** Delete NativeProcessError, universal errno/run-failure helpers, contention fatal methods and remaining legacy cohorts once all producers have typed outcomes. Run compile-fail/positive controls and source-gate known answers. Re-run the converted-site Busy-once matrix through production entry points. This is not mechanical until section 3's audit gap is closed.

Every runtime witness demonstrates real refusal, retained custody, release notification, scheduler-driven success and cancellation/exit cleanup. Cover release-before-enrollment and release-after-park. One post-enrollment probe is allowed; polling/retry-until-green is not. Assert exact completion/publication counts and bounded enrollment work; scale unrelated objects/tasks to detect global scans.

Use existing `kernel.el1.signal-delivery-owner`, `kernel.memory.owner-wait` and el1-ipc-two-process bindings where applicable. Register missing admission/settlement surfaces and deterministic budgets red-first. Linux authority comes from specifications and native Docker, never GPL sources; Docker and Carrick phases remain serial.

Implementation verification: focused native/shared suites, doctest controls, source/authority gates against merge-base, contract-change, CPL0 build and applicable Linux/macOS checks. Director supplies signed/KVM evidence through required gates. The #887 flaky/crash claim requires paired ten-run base/head populations with one artifact per arm, restored fixtures, actual verdict counts, identity and cleanup. Compilation or one green run does not close it. None of these tests ran in this design round.

### Owner questions, risks and scope

- Should atomic registration be absorbed or become a prerequisite layer from its separately filed fix? It must precede any assumption that admission refusal has no effects.
- Admission plus both-ISA checkpoint ownership may exceed 4k lines; confirm a reviewed transactional-registration layer if necessary. Do not fit the cap by adding a mixed-error compatibility converter.
- #887's actual producer is unproven here. Retain attribution for signed populations; fresh-root self-contention is a case to handle, not an established diagnosis.
- Ticket lifetimes, generation reuse, cancellation, release under queue contention and partial commitment are major risks. No forged static lifetimes or fake backends.
- Drop/wildcard terminal paths can bypass nominal type separation. Tighten ownership and signatures; do not move neutral logic into ISA carriers.
- Diagnostic snapshot Busy, real Linux nonblocking errors, maintenance states and unrelated performance work remain outside scope unless their guest boundary is implicated.
- This is a substantial design draft, not exhaustive reachability certification or implementation-ready closure. Section 3 names the remaining source-audit gap. No runtime correctness, green census or signed crash-fix claim is made.
