# Carrier birth issuer: bounded implementation handoff (#489)

Status: **unimplemented**. The retained diagnostic changes only the receiver
test. Production allocation and receiver authentication are unchanged. This
handoff records the unresolved integration boundary; it is not an accepted
storage design or a proof that a shared issuer is impossible.

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

## Concrete storage candidate and missing connection

The useful existing storage owner is
`kernel/objects/thread_control.rs::SharedAbiPage`, not an Arc stored in guest
memory. Its closed layouts occupy aligned 16 KiB granules in MAP_SHARED
512 KiB slabs. Arc, pool bitmap, mutex and allocation metadata stay outside
the exposed bytes. A birth-source lease could retain a new neutral atomic
layout in this pool. The counter must be initialized before the first host
birth, without obtaining a large per-process reservation.

The useful existing mapping owner is
`metadata_grant.rs::CarrierMetadataAccess::map_retained`. It authenticates a
live `CarrierVmCustody` generation and publishes stage-2 plus its inventory
record before returning an extent. `RetainedMetadataMapping` and
`HostMetadataExtentPin` provide retention and retirement exclusion.
`CarrierLifecycleMappings` retains mapped backing through executor lifetime;
its drop path attempts retirement only after executors stop, and failed
retirement leaves backing in VM custody.

Those pieces do **not** currently form a birth-issuer capability:

- `Kernel::bootstrap_root` constructs `ObjectIdRegistry` and issues the root
  identities before `CarrierRuntime::boot_kernel_root_prepared` calls its
  initialization callback. The new source must be owned on the host before
  that issuance, rather than installed by a later binding callback.
- `CarrierLifecycleMappings::publish` transports lifecycle/control addresses
  and the ledger notification address. Neither the lifecycle page nor the
  native admission API carries a birth-source capability. Reusing
  `bind_guest_activity` would give an address with the wrong authority and
  lifetime contract.
- `MetadataExtent` is a base/length/token receipt. Its carrier and VM
  authentication belongs to the resolver; copying the receipt does not
  transfer that authentication. The production guest `GuestMetadataPin` is
  uninhabited and explicitly does not construct a host pin. A proposed guest
  reference therefore needs its own admitted borrow and retention argument;
  the host pin trait cannot simply stand in for it.
- `CarrierMetadataAccess` and the runtime lifecycle mapper are compiled only
  for macOS/AArch64. A neutral issuer cannot depend on those concrete types.
  Other launch adapters need an explicit binding or a demonstrated reason
  that they cannot import host-issued births. An optional local allocator
  would preserve the defect.

The unresolved work is a typed connection between the pre-bootstrap source
owner, the exact receiving VM, and the guest borrower. VM generation alone
is insufficient: independent custody objects both begin at generation one.
HVF already distinguishes this case with `CarrierVmCustody::transfer_carrier`
and `MmPortalSlots::bind_carrier`; those domains must be authenticated, not
replaced with a zone address, MM identity, or arbitrary integer. The
implementation pass did not establish that complete connection and stopped
before introducing an unchecked pointer or a second issuer.

## Required integration after resolving that boundary

`ObjectIdRegistry::{task_serial,thread_serial}` must use the same source as
every admitted native graph, from before any root or pool reservation.
Other object IDs retain their existing domain. A lifecycle lease must retain
the source through host replenishment, fork, exec/rehome, and mapped guest
access; merely retaining the surrounding slab must not permit its issuer
granule to be recycled.

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

Before promotion, prove production-bound reserved-before-admission and
birth-after-admission cases, both registration/fork orders with prepared
children, two independent graphs sharing one carrier source, independent
carriers, rollback, partial exhaustion, transfer, and real rehome/foreign
ownership controls. Preserve all event, process-birth, live-record and exact
thread-prefix authentication. Then run changed-crate checks, contract/ABI and
stack gates, independent review, and director-owned portable and signed
acceptance. No GREEN identity-custody or runtime claim is made here.
