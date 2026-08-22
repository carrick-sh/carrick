# Authority-mismatch audit — 2026-08-22

Hunting one defect shape, the one `docs/identity-and-scope-domains.md` predicts:

> **A value recorded at publication time describes a relationship — ownership,
> sharing, identity, a generation. A later transition changes that relationship
> but does not update the record. A predicate then reads the record and answers
> about a world that no longer exists.**

Six instances of it were fixed or diagnosed on 2026-08-22 (`00131530`,
`b2097fc5`, `a1eaad6a`, `d4ad1aaa`, `f250844d`, and the dangling-mm defect).
This audit went looking for the rest, via two directed read-only workers.

**Every finding below was checked by hand before being written here, and two
were rejected.** The workers' confidence field is not evidence — in this
campaign it has been uniformly "certain", including for three symbols that
turned out to be live production code.

## Verdicts

| # | recorded value | site | verdict |
|---|---|---|---|
| 1 | `HvpatchTaskInventoryAuthority::SharedProcess` | `trap.rs:6700` | **CONFIRMED** — survives execve; the dangling-mm defect |
| 2 | `HvpatchTaskMmAuthority.kernel_mm` | `trap.rs:7093` | **CONFIRMED** — set-once, so an adopted authority can never bind the post-exec mm |
| 3 | sibling adopts an `Active` authority | `trap.rs:6714` | **REJECTED** — that is the design; threads share the mm and its authority |
| 4 | `Active { ledger }` holds the pre-exec ledger | `trap.rs:6715` | **REFUTED** — `frame_inventory` is reassigned only inside the `shared_process_mm` branch (`trap.rs:5170`) |
| 5 | `HvpatchMmAuthorityKey` in the carrier directory | `trap.rs:7660` | **CONFIRMED** — still maps the pre-exec `mm_root_slot` |
| 6 | `Stage1MmBackend.binding` | `stage1_mm.rs:127` | **REFUTED** — `publish_binding` overwrites and bumps a revision, and exec does republish |

**1, 2 and 5 share one root cause: execve mutates the task's HVF state in place
and never re-publishes it.** One change closes all three; the plan is
`docs/hvpatch-exec-authority-routing-plan.md`.

Finding 2 is the most useful of the three, because it converts a judgement call
into a proof: `bind_kernel_mm` returns `Ok` only for `None` or an identical mm
and otherwise errors with "HVPatch MM binding changed across sibling
registrations". Since `apply_retirement` passes `*self.kernel_mm.lock()` as
`expected_mm`, an adopted authority would authenticate a post-exec retirement
receipt against the PRE-exec mm. In-place transition is not merely unsafe, it is
impossible.

## Finding 6 — refuted

`Stage1MmBackend.binding` was reported stale after `publish_stage1_root`. It is
not: `publish_binding` (`stage1_mm.rs:401`) overwrites the binding under a write
lock and bumps a revision, and execve does republish — `commit_exec`
(`hvpatch/mod.rs:748`) calls `backend.publish_binding(binding)` with the new
stage-1 root read back from `TTBR0`. Nothing goes stale.

## Calibration — half of this audit was wrong

Six candidates, **three rejected or refuted** on inspection: the pre-exec ledger,
the sibling adopting an `Active` authority, and this one. All six were reported
with `confidence: certain`.

That is the reason every finding here carries a set-site, an invalidating
transition, and the predicate that reads it: those three fields are what make a
claim checkable in minutes. A finding stated as a conclusion rather than as a
chain would have cost an afternoon each to disprove — and two of these would
have been "fixed", changing correct code.

## Cleared — relationships that ARE maintained

This half is worth as much as the findings: it is the search nobody has to
repeat. Each was checked and found to have code keeping it in sync.

**carrier / task state machines** (13 cleared)

- HvfTaskState.shared_process_mm (trap.rs:4860): Initialized at registration (trap.rs:7766); reset to false on execve in HvfVmState::execve_rebuild (trap.rs:17328), correctly updating the task's exec retirement eligibility in exec_r
- HvfTaskState.is_forked_child (trap.rs:4881): Initialized false for HVPatch tasks (trap.rs:7769); preserved across execve in HvfVmState::execve_rebuild (trap.rs:17138, 17326) so descendants retain their _exit shutdown discipline.
- HvfTaskState.forked_no_exec (trap.rs:4886): Initialized false (trap.rs:5058); reset to false on execve in HvfVmState::execve_rebuild (trap.rs:17327) so stale-stage2 reasoning resets for live replacement VMs.
- HvfTaskState.pending_exec_mm_root_slot & pending_exec_asid (trap.rs:4855-4856): Staged in HvfVmState::prepare_exec_address_space (trap.rs:5295-5296); consumed and cleared during HvfVmState::execve_rebuild (trap.rs:17047-17048).
- HvfTaskState.pending_exec_stage2_cleanup (trap.rs:4857): Armed with predecessor mappings and extents in HvfVmState::execve_rebuild (trap.rs:17300); consumed and retired via retire_task_state_exec_predecessor (trap.rs:10180) with a
- HvfTaskState.protections & HvfTaskState.page_tables (trap.rs:4890, 4899): Replaced with fresh instances in HvfVmState::execve_rebuild (trap.rs:17330, 17363) and seeded with readonly spans from the replacement mapping plan (trap.rs
- HvfTaskState.cow_armed & cow_deferred_publications (trap.rs:4928-4929): Replaced with fresh empty Arc allocations on execve in HvfVmState::execve_rebuild (trap.rs:17336-17337) to prevent pre-exec COW ranges from corrupting replace
- HvfVmState.reclaim_authority (trap.rs:4830): Maintained through ReclaimParkAuthority state machine (trap.rs:4763); transitioned in mark_vcpu_parked (trap.rs:14652), mark_vm_parked (trap.rs:14788), mark_live_after_recreate (trap.rs
- global_frame_host_owners generation matching (trap.rs:2050): Evaluated in global_frame_host_owner_matches (trap.rs:2064); unowned extents published with generation 0 authenticate without requiring a host mapping owner (fixed in co
- PendingForkFrameReceipt retirement accounting (trap.rs:6961): Evaluated in authenticate_pending_retirement; obligations for mappings superseded by COW transactions are discharged from retirement requirements (fixed in commit b2097
- Retirement emptiness revision check (crates/carrick-runtime/src/kernel/state.rs): mm_empty_at_revision is evaluated inside apply_inner under the state lock assigning next_revision (fixed in commit a1eaad6a), preventing TOCTOU race
- HvpatchTaskRegistration.key & child token authentication (trap.rs:7830-7865): bind_child_kernel validates exact equality of task_serial, thread_serial, execution_generation, linux_pid, linux_tid, asid against key and expected_iden
- AliasPublicationReceipt exact retirement (trap.rs:7183-7185, 8122-8131): Captured at directory publish and retired during HvpatchTaskMmAuthority::drop or publication rollback.

**runtime hvpatch + kernel** (11 cleared)

- AsidAllocator, AsidResidency, AsidGeneration, and AsidRetirement (hvpatch/asid.rs): Numeric ASID reuse always mints a monotonically increasing NonZeroU64 generation. Reused ASIDs are held in retired state until all resident and lo
- MmResources task-sharing accounting (hvpatch/mm_resources.rs): MmResourceState tracks task leases across TaskKeys. On commit_exec (line 235) and retire (line 262), it checks whether any other active task shares the Arc<Stage1MmLea
- ObjectIdRegistry & MmId uniqueness (kernel/ids.rs): MmId is allocated monotonically from an AtomicU64 and is never recycled or reused across the lifetime of a Carrick kernel instance, preventing ABA / stale ID collisions.
- TaskRevision & parent_at_capture (kernel/core.rs, kernel/operations.rs): KernelContext records parent_at_capture alongside TaskRevision. In operations.rs:2301-2305, reserve_fork validates exact parent_at_capture for CLONE_PARENT w
- ThreadExecutionRecord, ThreadExecutionLease, and ExecutionGeneration (kernel/objects.rs, kernel/scheduler.rs): ExecutionGeneration advances monotonically on every state transition. During execve, old_caller.transfer_runner_to invo
- TaskRecord::has_execed (kernel/exec.rs, kernel/operations.rs): Initialized to false at task creation, set to true during commit_exec_transition (line 445), and checked under the registry lock by set_process_group to reject setpgid
- TaskRecord::dead_leader (kernel/operations.rs, kernel/exec.rs): When a thread group leader exits before siblings, its RetiredThreadRecord is held in dead_leader. If a sibling execs, commit_exec_transition reclaims the leader TID c
- FrameInventoryAuthority transactional reservations (kernel/frame_inventory.rs): Reservations validate that all mappings transition from Prepared(tx) to Published before applying changes to live frame state. Frame retirement (Retir
- RunnerGate and ThreadRunner (kernel/objects.rs): transfer_runner_to transitions ownership to replacement thread key; adopt_thread verifies pointer equality and owner key before adopting the replacement thread.
- CrashCaptureAuthority and CrashQuorum (kernel/crash_capture.rs): Generational quorum separates live Linux thread count from live safe-point participants via Thread::is_crash_safe_point_participant and explicit CrashRegisterVote (P
- Sighand::for_exec, FileTable::for_exec, and ThreadSignalState::for_exec (kernel/objects.rs, kernel/exec.rs): Reset caught signal handlers to SIG_DFL, purge O_CLOEXEC file descriptors, and reset alternate signal stacks across execv

## Method note

Both workers were given the confirmed defect as a calibration example, told that
a doc comment is not evidence (three defects here carry comments justifying the
wrong behaviour), and asked to name a guest-visible consequence per finding or
lower their own confidence. That framing is why the findings are checkable: each
names a set-site, an invalidating transition, and the predicate that reads it.
