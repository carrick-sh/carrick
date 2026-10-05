# N1 fork refusal audit after closed child-root publication

The retained signed trace at `1dfba1500` reaches root phase 9 for child MM 3,
then exits before runtime phase 3 (`ProcessSpec`). Runtime phase 2 precedes
`publish_owner_child_address_space`; phase 3 follows `ops.prepare` and parent
COW arming in `prepare_in_process_fork`. The trace has no raw guest errno.
The new `OWNERFORKREFUSAL1` probe is needed to identify an EL1 service stage
and errno on a signed artifact. This is a static audit, not a signed verdict.

## Returns in the phase 2 to phase 3 interval

| Site | Refusal condition under the N1 owner path | Result |
|---|---|---|
| `validate_hvpatch_process_prepare_boundary` | Copied inventory does not carry a distinct parent/child `OwnerCopied` projection, or child MM differs from the prepared MM generation. Owner projection has no host VMA ranges to validate. | Runtime configuration error. |
| `Aarch64EngineCore::build_owner_process_spec` entry | Another process/owner fork is pending; request shares an MM; or the fork projection lost exact parent/child MM identities. | Host trap. |
| `HvfVmState::prepare_owner_fork_builder` | Child root is outside its aligned 2 MiB slot, source is absent or cannot supply the control arena, parent COW runtime has no owner binding, physical root/control publication fails, or either slot already has a structural owner. | Host trap; no owner service ran. |
| `Stage1Authority::reserve_owner_fork_arena` | Parent has no physical table publisher, no spare table arena, or publishing the selected arena fails. | Host trap; no owner service ran. |
| Owner `BIND` and request construction | Service transport fails or refuses; its incarnation, generation or sequence is zero; parent or child MM is zero. | Host trap. |
| `PortalForkSlot::submit` | Slot occupied or `PortalForkRequest::valid` rejects carrier/MM, control alignment, table extent, or overlap. Missing executor slot or carrier region also rejects before submission. | Host trap. |
| EL1 service stage 0 | Fork slot index is invalid, or the slot cannot be claimed. | `EINVAL` (22) or `EBUSY` (16). |
| EL1 stage 1 | Carrier differs, a transfer is outstanding on the parent MM, pending slot index is invalid, or another fork occupies it. | `ESTALE` (3), `EBUSY` (16), or `EINVAL` (22). |
| EL1 stage 2 | Parent address-space slot is absent or its grant cannot be taken. | `ESTALE` (3) or `EBUSY` (16). |
| EL1 stage 3 | Child/parent table arena or parent root escapes the fixed table pool; live word window cannot be constructed. | `EINVAL` (22) or `EIO` (5). |
| EL1 stage 4, `census_fork` | Parent editor/grant or owner identity is stale/busy; parent has pending fork/copy work; live descriptor read, policy, split, metadata observation, or bounded allocation fails. | `ESTALE` (3), `EBUSY` (16), `ENOMEM` (12), `EINVAL` (22), or `EIO` (5), according to `MmError::errno`. |
| EL1 stage 5, `prepare_fork` | Parent/closed-child editor or grant is stale/busy; child root differs from supplied physical tables or is already admitted; parent generation, incarnation or sequence changed; parent is not fork-ready; mapping/descriptor walk or bounded child/parent/undo capacity fails. | `ESTALE` (3), `EBUSY` (16), `ENOMEM` (12), `EINVAL` (22), or `EIO` (5). |
| EL1 stage 6, custody loop | Host declines an exact `HostBacking`, `Frame`, or `StructuralCopy` selection. A stale host custody acknowledgment or a host retention error instead fails the host transaction. A frame can be declined when no live exact global-frame or structural record covers its IPA; structural copy also requires distinct source/destination records in the supplied control window. | Owner `EBUSY` (16), lowered by runtime to guest `EAGAIN` (11), or host trap. |
| EL1 stage 7, `publish_fork` | Parent/child edit or identity revalidation fails; a live word changed since census; capacity, descriptor CAS/store, fork certificate, child origin, or reservation clone fails. Rollback must restore parent descriptors. | `ESTALE` (3), `EBUSY` (16), `ENOMEM` (12), or `EIO` (5). |
| EL1 stage 8 | Detached completion no longer matches the exact slot/request. | `ESTALE` (3). |
| Host completion consumption | Published request, physical capacity, parent/child MM, retained frame, structural lifetime, inventory extent, frame offset, host backing, or child table resolver is inexact/missing. Child live manager, arena source, register snapshot, or ASID construction can also fail. | Host trap; pending EL1 child is aborted. |
| Task-only materialization and initial CPU | Child inventory reservation fails; alias escapes physical extent; stage-2 map/owner registration fails; borrowed structural mapping lacks its exact owner; child root is missing/duplicated; runtime identity or initial CPU snapshot fails. | Host trap and backend rollback. |
| External control exec publication | The external exec work was cancelled after backend preparation. This branch does not apply to the four guest `fork()` fixtures. | Guest `EAGAIN` (11). |

For the four guest fixtures, phase 3 is emitted immediately after
`ops.prepare`, its work counters, and infallible `arm_parent`. The direct
recoverable mapping at this boundary is `TrapError::OwnerForkRefused`: EL1
`EBUSY` or `ESTALE` becomes guest `EAGAIN`; other owner errno values pass
through. Other preparation failures propagate as runtime errors, so the signed
probe must decide whether the guest failures are owner refusals or a different
runtime exit path.

## Adjacent fork work outside this interval

| Work | Placement and refusal |
|---|---|
| Fd table, signal state, credentials and leader thread copy | `ForkReservation::prepare_with_mm_backend` runs **before** runtime phase 2 and child-root phase 9. It can refuse a draining file table, MM/object-ID allocation, shared/resources copy, thread attachment, or failpoint. The parent tid/pidfd/child tid preflight also precedes root publication and can return `EFAULT`; pidfd install can return its own errno. These cannot explain this trace's post-root gap. |
| Frame inventory | Only the reservation occurs inside `ops.prepare` through `ProcessSpecPlan::stage_with_reservation_factory`; capacity/reservation refusal is a host error. Applying/publishing the transaction follows runtime phase 3. |
| COW arming | EL1 `publish_fork` arms live private leaves at stage 7. Runtime `ops.arm_parent` after backend preparation is infallible. The old host range planner is not used for `OwnerCopied`. |
| Child root admission | `ForkCommit::admit_owner_child_root` runs **after** runtime phase 3, following dispatcher child install and exact owner completion. A wrong transaction, shared/previously published child, non-twin MM, stale owner root or mismatched source can refuse/fail-stop there, but cannot explain this interval. |
| Child continuation and backend commit | Parent copyout, kernel/backend commit, child binding, and continuation construction all follow runtime phase 3. Their failures cannot suppress phase 3 in this trace. |

## Portable witness and remaining unknown

`owner_fork_publishes_child_with_two_live_same_va_mms` drives the production
EL1 census, preparation, child descriptor/COW publication and final settlement
through the actual AArch64 fork slot/custody handshake. It keeps a peer MM
live at the same VA with a different IPA and models the bootstrap control and
table-alias block. It passes at this tip; its physical custodian is an exact
in-memory test implementation. The macOS `HvfVmState` physical custodian and
runtime task-only materialization are target-gated and cannot execute on this
Linux VM. No refusal stage or errno is proven for the signed four yet.

On the next signed artifact, run
`el1_delegated_root_concurrent_vma_ops`,
`el1_delegated_root_map_fixed_over_cow_pages`,
`el1_thread_lifecycle_ptrace_traceclone`, and
`el1_thread_lifecycle_spawn_slope` with
`scripts/dtrace/hvpatch-owner-fork-refusal.d`. The probe's raw errno and stage
distinguish the EL1 branches above. Run `el1_fork_cow_resolves_in_guest`
separately to verify the sparse-root fix.
