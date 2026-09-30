# Production COW backing transaction: development integration

Parent adapter source: `9b0047959`. Contract: `kernel.el1.stage1-publication`.
This joins the real `HvfTaskState::perform_frame_cow` caller to EL1 descriptor
submission through its driving vCPU. No production activation or signed COW
acceptance is claimed. The source still refuses unconverted writer shapes.

The existing host allocation and inventory transaction now has a guest-owned
branch: retain the old source owner, allocate replacement backing without host
copying, publish an authenticated provisional frame grant, submit one compound
CowRepoint, then commit the old inventory split after the verified receipt.
Grant refusal rolls back backend references and retires the new physical owner.
Once publication has an unknown outcome, fail stopped instead of freeing possibly
live backing. Exact-MM exclusion remains held through the transaction.

The wire operation carries the semantic span (up to a 16 KiB compound). EL1
copies its pages using the existing private aliases, then publishes all leaves
under one journal. Distinct but overlapping physical spans are refused before
copying. Old and new intra-compound offsets are preserved. The existing host
lane remains for unconverted admission; only host completions increment its
counter. The unused runtime GuestCowContinuation and its synthetic backing gate
are removed: the real backing transaction uses the existing descriptor receipt.

Evidence on this development tree:
- Overlap control was Applied before the fix; now refused with BadRange.
- Injection at each of four descriptor stores restores the complete preimage.
  The initial fixture incorrectly expected eight stores; retained separately,
  corrected to the executor's four stores before the meaningful red run.
- MMU core: 159 passed; final HVF COW tests: 11 passed. Backend grant-refusal
  witness runs the real provisional-grant code with a refusing authority and
  modeled HVF mappings; verifies empty inventory/reference maps and owner release.
- Runtime descriptor tests: 10 passed after deleting the unused continuation.
- Affected all-target Clippy, formatting and EL1 image build pass. These are
  host/model/build checks, not execution of the guest-owned production lane.

## Remaining activation dependencies

| Production caller | Work still required |
| --- | --- |
| perform_frame_cow | Kernel-only, non-writable, maintenance and private-file shapes; mixed prepared/resident permissions; successful real kernel-authority composition and signed ownership proof |
| publish_private_repoint / publish_shared_repoint | Owned EL1 submission and completion before backend repoint |
| prepare_el1_frame_grant replacement branch | Authenticate descriptor completion before retiring replaced backing |
| materialize_retired_reuse | Preserve invalid leaves, reuse identity and protection through receipt |
| sparse_materialization::publish_replacing | Replace host editor with the same owned publication path |
| foreign_mm::perform_foreign_cow_transaction | Target-MM driving service and exact completion/lifetime |
| Aarch64EngineCore memory edit funnel and exec | Convert remaining protection, alias, discard and image publication writers; census before pause removal |
| Anonymous syscall/lifecycle dispatch | Join SharedReservations as sole policy authority, then enable admission |

This table records identified blockers, not a claim of exhaustive writer closure.
Next action: extend the joined COW transaction's remaining writer shapes using
existing permission-preserving MMU operations, and compose its successful backing
commit with the real kernel authority. Do not add a second copy transport or
another broad boot qualification campaign. Final signed memory, two-MM progress,
frame return, full gates and all later ARM64 checkpoints remain required.


## Mixed private-anonymous permissions follow-up

The compound executor previously refused at a read-only neighbor. The retained
red witness receives PermissionDenied for a four-page compound containing RW,
read-only, PROT_NONE and untouched prepared leaves. The executor now restores
write only from the current intent recorded by fork arming; other resident
permissions and execute attributes remain unchanged. Prepared neighbors are
repointed without becoming resident. Retired, unowned and unarmed resident
leaves remain refused. The backend no longer rejects the whole guest transaction
solely because its source metadata is read-only.

The witness passes; MMU 160 and EL1 114 tests plus affected all-target Clippy
pass. This removes the private-anonymous mixed-permission executor restriction,
not the remaining legacy/kernel/private-file/maintenance writers. No signed or
real kernel-authority successful COW composition is claimed. The existing
runtime production-carrier fixture in vcpu_loop/memory.rs composes real kernel
and backend ownership and should be reused for that check; a synthetic grant
commit without descriptor execution would be insufficient.
