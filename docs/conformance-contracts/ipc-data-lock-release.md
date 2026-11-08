# IPC data-lock release sources (#1845)

`kernel.el1.ipc-two-process` owns this slice. Linux pipe and eventfd
operations retain their descriptions and byte cursors while waiting; internal
lock contention must not become errno, fatal completion, or a retained pool
worker. Constructors additionally cannot return EINTR on caught signals or
job-control stops. This slice supplies the shared guard publishers needed by
the operation migration; it does not claim that migration is complete.

## Existing mechanisms and capacity

The notification owner is `ObjectNotificationSource` in
`carrick-sched-core/src/object_wait.rs`. Its counted tickets publish through
`ObjectNotificationTicket::publish`, using the existing queue, sticky pending
bit, admission handbacks, completion chain, and venue callback. The precedent
is `ControlRelease` in `carrick-el1-linux/src/native_process_runtime/thread_stock.rs`.
There is no callback registry or separate release queue implementation.

`IPC_OBJECT_CAPACITY` owns the object-slot range. The IPC descriptor authority's
`IPC_DESCRIPTOR_TABLE_CAPACITY` owns the following table-slot range; the ABI's
`IPC_FD_TABLES` consumes that same constant. `IpcLockIndex` admits only those
ranges, and the compile-time domain gate proves they do not overlap readiness,
MM, delegated-file, service, or member-control queues. The x86 initial-image GPA follows the actual metadata and scheduler end,
rounded to its existing 2 MiB granule; the compile-time non-overlap gate
remains in place as the domain grows. Object wait protocol 17
includes the new range and storage offset in its layout hash.

The source identity is the carrier IPC authority plus its directory slot,
not an object incarnation or numeric fd. The physical lock survives object
and table reuse. The carrier owns a base publisher from admission until zone
destruction. Admission must precede exposure of the corresponding slot; it is
idempotent only for the exact carrier. Views authenticate the carrier identity before borrowing the venue, and guard
release reserves a counted ticket from that already admitted base. No binding,
allocation, or waiting occurs on unlock. Object and descriptor table guards
release exclusion before advancing the notification revision.

A release wakes only waiters of that lock slot. The existing notification
protocol bounds work by the enrolled record population; there is no scan of
all objects or tables and no new polling loop. Borrowed-source `contend`
produces the existing linear `Refusal::Contended(ReleaseTicket)` with the
observation preceding the final failed probe.

## Evidence and remaining integration

The red-first ABI bindings call production `IpcRegion::lock` and descriptor
`Authority::transaction`. Without the two guard publishers, three assertions
fail: object unlock must publish, table unlock must publish, and release before
enrollment must force an immediate rerun. The green bindings additionally
park a real scheduler record with an exact operation token while another live
host thread holds the object lock, release it, and consume that exact token
once through the existing completion chain. Both ARM and x86 parked-context
layouts run that schedule. All coordination receives have five-second bounds;
no retry or timing-based correctness assertion is used.

These are shared-guard and scheduler witnesses, not executor-pool or guest
instruction witnesses. Production views are not yet attached to the release
venue. The next operation layer must admit sources during directory
publication, attach every host and guest view, retain create/read/write/metadata
operations, route suspension through `OwnedSyscallResume` and the killable owner
continuation, and supply the x86 completion consumer and physical wake. It must
then remove `HostLockWait` spinning and prove default-pool exhaustion plus
non-EINTR constructor behavior. Signed/HVF and Docker acceptance remain open.
