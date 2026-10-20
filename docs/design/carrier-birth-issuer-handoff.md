# Carrier birth issuer: bounded implementation handoff (#489)

Status: **neutral storage prerequisite implemented; receiver repair incomplete**.
`ZoneTables<C>` now contains one zero-valid `SerialIssuerWord`, exposed only
through a lifetime-bound `SerialIssuer` borrow. Production host/native
allocation and receiver authentication are unchanged. The canonical receiver
witness remains RED. This foundation must not be promoted as receiver closure.

Applicable contracts are `kernel.el1.signal-delivery-owner`,
`kernel.el1.thread-lifecycle`, `core.lifecycle.publication`, and
`process.native.arm-admission`. Their Linux authorities include signal(7),
kill(2), tgkill(2), clone(2), and exit(2). The additional structural obligation
is non-reuse across reserved and unpublished births without expanding the
receiver's indexed lookup or serializing guest execution.

## Reproduced failure

The canonical observer uses internal TID 42, snapshot 1, thread serial 103.
After its retirement the native fork allocates task 102, thread 103, MM 104,
and transaction 105. The queued process event still targets P1, but the
unrelated P2 occupies its observing prefix. The test fails at
`valid P1 event must survive observer TaskId reuse by P2`.

The four-line diagnostic retains the final pending-signal consumption. It
does not reset counters, weaken a receiver comparison, or keep the obsolete
record alive. The focused run has 0 passed / 1 failed / 442 filtered; the
native runtime module has 46 passed / 1 failed / 396 filtered, with the same
sole failure. These are RED evidence, not acceptance.

## Existing zone storage and missing host ownership connection

The issuer is appended to the existing `ZoneTables<C>`, already mapped in
the carrier. It needs no new metadata page, mapping, `GuestMetadataPin`, or
guest pointer transport. `SerialIssuerWord` is exactly one `AtomicU64`:
zero means no serial issued, allocation atomically advances the last-issued
value, and MAX is terminal. The last successful allocation may issue MAX;
all subsequent allocations refuse. Dropping a borrow never resets storage.
There is deliberately no shared-word transfer/reset operation.

`ZoneTables::serial_issuer()` borrows the actual zone. The private fields
prevent safe construction from an unchecked raw address or a copied counter;
the compile-fail binding proves the borrow cannot escape its storage owner.
This is a storage-lifetime prerequisite, **not** carrier authentication or a
retained host owner. The ARM image layout hash includes the issuer protocol,
size, alignment and zone offset even if append-only storage fits old padding.

Verified production ownership starting points:

- ARM `CarrierMetadataAccess` retains `Arc<PersistentCarrierMappings>` and
  checks its exact custody's live generation in `region()`. The mapping
  owner's drop path retires stage-2 before releasing host backing. Its safe
  acquisition currently follows root preparation: `binding.rs` extracts the
  persistent executor authority only after preparing the root and registering
  its authoritative IPC window. The API comment on `fd_ceiling_publisher`
  explicitly identifies extraction as the fixed mappings' Arc-ownership point.
- x86 `ProductionCpuFactory::capture_physical_state` reads the initialized
  `X86Cpl0Zone` through `custody.ram.host_ptr` while holding physical custody.
  `GuestRam`'s owning drop unmaps the windows. `SharedWindows` alone is an Arc
  to descriptors, not a retained mmap owner; cloning it cannot prove lifetime.

Neither starting point is connected to host birth issuance yet:

- `Kernel::bootstrap_root` constructs `ObjectIdRegistry` and issues the root
  identities before `CarrierRuntime::boot_kernel_root_prepared` calls its
  initialization callback. The new source must be owned on the host before
  that issuance, rather than installed by a later binding callback.
- Prefer supplying the actual retained carrier source through `RootBootstrap`
  before those births. If the first root needs a local-to-zone handoff, it
  must precede every native allocation/publication and hold the actual
  registry's issuance write authority through complete high-water capture and
  permanent source replacement. That includes reserved, retired and
  unpublished values. Every later root must use the existing carrier source
  before bootstrap; an independently seeded source cannot join a live carrier.
- `CarrierMetadataAccess` and the runtime lifecycle mapper are compiled only
  for macOS/AArch64. A neutral issuer cannot depend on those concrete types.
  Other active launch adapters need a binding or a demonstrated reason they
  cannot import host-issued births. An optional local allocator preserves the
  defect.

The unresolved work is a typed connection between the pre-bootstrap source
owner, the exact receiving VM, and the guest borrower. VM generation alone
is insufficient: independent custody objects both begin at generation one.
HVF already distinguishes this case with `CarrierVmCustody::transfer_carrier`
and `MmPortalSlots::bind_carrier`; those domains must be authenticated, not
replaced with a zone address, MM identity, or arbitrary integer. The
implementation establishes only the neutral borrowed source, and does not
introduce an unchecked pointer, independent host source, or guest-only switch.

The architecture review's blanket eight-Reserved-entry assertion does not hold
on this base. `ThreadControlArena::with_lifecycle` creates empty free/deferred
and birth bookkeeping. `thread_ledger::replenish` issues identities according
to actual pool depth, admission and publication state; storage for eight
control slots does not prove eight issued identities for a singleton root.

## Required integration after resolving that boundary

`ObjectIdRegistry::{task_serial,thread_serial}` must use the same source as
every admitted native graph, from before any root or pool reservation.
Other object IDs retain their existing domain. A lifecycle lease must retain
the source through host replenishment, fork, exec/rehome, and mapped guest
access; retaining a raw zone pointer or descriptor array is insufficient.

`ThreadIdentity::reserve` already reserves the serial before publishing a
Reserved entry. That custody must continue through `page.claim_any()` and
registration. `admit_fresh_root` must stop reconstructing birth issuance from
visible members. `register_thread` imports an already-issued identity, never
advances a private cursor. `ForkReservation` must own task/thread identities
before unlocked preparation. MM and transaction allocation need separate
domain accounting when the existing graph cursor is split; this is not a
license to redesign them.

`BootLaunchExport` currently transfers an exclusive local cursor and revokes
the host registry. Its source refusal behavior must remain explicit when
births move to shared storage. Moving its cursor into a new allocator cannot
duplicate an issuer still used by live pools. Any deliberately shared handle
must reach the same retained source; an exclusively transferred handle must
refuse further issuance while preserving already-owned births.

The intended issuance cost is one checked atomic RMW per birth, with
contention-dependent retries and no latency claim. Relaxed counter ordering
can establish uniqueness only after safe initialization and capability
publication; it does not publish the surrounding birth record. No graph lock
may span backend preparation. Registration must add only constant work;
receiver lookup remains `O(log N + matching incarnation + target members)`.
No timing measurement was made.

`SerialIssuer::advance_past` monotonically observes an already-issued value,
including MAX. It is useful for idempotent admission accounting, not live
source convergence. The negative control
`late_observation_cannot_repair_independently_issued_tickets` retains two
colliding prepared tickets even after advancing the private cursor. The word
tests cover zero initialization, unpublished/abandoned allocations, concurrent
borrowers, terminal imports and exhaustion; the zone test covers shared borrows
and independent storage. These do not substitute for production-bound root,
pool, registration/fork, rehome, cross-carrier or boot-transfer witnesses.

Before promotion, prove production-bound reserved-before-admission and
birth-after-admission cases, both registration/fork orders with prepared
children, two independent graphs sharing one carrier source, independent
carriers, rollback, partial exhaustion, transfer, and real rehome/foreign
ownership controls. Preserve all event, process-birth, live-record and exact
thread-prefix authentication. Then run changed-crate checks, contract/ABI and
stack gates, independent review, and director-owned portable and signed
acceptance. No GREEN identity-custody or runtime claim is made here.
