# x86 private file source binding (#1722)

The production KVM read-only and private-write witnesses now pass. The same
shared mapping handler and file-fault supply serve the x86 calls. Acceptance
is still incomplete: prepared-edit contention has no owned suspension binding,
the stronger fork-lifetime case stops at parent close errno 9,
and a CLI `/bin/echo ok` attempt exits 127 without a host-file crossing.
Neither libc loading nor Python startup is proven.

## Shared mapping and source transport

The mapping adapter calls shared `native_host_file::stage` and
`serve_delegated_mapping`. Its synchronous crossing carries the existing
host-file record, authenticates retained supervisor POD storage, and calls
`SyscallDispatcher::serve_native_host_file` outside physical custody. Sources
are retained before reply publication under the complete address context.
Fork stock carries `ForkHostBackingCustody` and authenticates host-source rows
separately from physical frame rows. File grant reads clone the capability,
release custody and CPU-I/O borrows, read its bounded prefix, then authenticate
the execution and selection again before physical publication. Fault entries
supply their file slots to the shared fault owner.

## Descriptor-window installation

The carrier retains the original `HostIpc` directory and pool through
`BackingExtent::ipc_window`, using the existing batch memslot rollback owner.
It maps supervisor writable NX aliases at `X86_CPL0_IPC_BASE` and
`X86_CPL0_IPC_POOL_BASE`, binds the operation-slot generation, and publishes
its root namespace. Dynamic grants start beyond the reserved physical IPC
window. Shared guest attachment selects the ISA's alias addresses.

`IpcTableMapBinding::Retained` keeps the descriptor-map allocation alive until
the host file table withdraws its publication; it does not manufacture a static
reference to carrier-owned storage. Storage admission validates the host base
before constructing the retained view. VM-free tests check original allocation
pointer identity, authority retention through memslot lifetime, and map
withdrawal before storage release.

ARM's reference installation is `install_registered_ipc_window` in
`carrick-vmm-hvf/src/trap/stage2_backend.rs`. Both installations map the
original authority's bytes. Copying its directory or pool would create a
second allocator/descriptor authority and is incorrect. X86 publication is
explicitly carrier-scoped instead of using ARM's process-global registration.

## Shared physical source projection

`FileTable::publish_ipc` exports host slots as `IpcPhysicalHold`, while native
opens use `NativeOpenFile`. Both now reach `native_map_reference`, which checks
read access and registers the same retained private source. The projection
shares the original physical lifetime, backing, identity and seals, but owns
no fd reference, cursor authority or publication pin. Its original-description
backlink is weak. Mapping admission recalls a live original delegation before
incrementing the shared mapping count under the physical transition lock.
The pinned IPC resource authorizes admission after the host numeric fd closes;
final resource release still waits for both IPC holds and mappings to end.
Only MapPrivate is projected: unrelated host operations retain their existing
service admission.

Do not replace this with a numeric host-fd lookup, copied namespace, or a
strong original-description backlink (which cycles through publication).
The VM-free production-service witness closes the host fd, proves the original
description is gone and then reads the retained bytes. Disabling the physical
resource branch reproduces `NativeHostFileRefusal` in that witness.

File grants use the existing authenticated descriptor/inventory publisher.
They are excluded from the anonymous-only evidence population; that recorder
continues to reject a file-backed input rather than miscounting file pages as
anonymous pages.

## Witnesses and remaining acceptance

`cpl0_initial_mm` exercises read-only first-touch, private writes with an
unchanged source, write-only fd rejection (errno 13), beyond-EOF SIGBUS, and
a red child first-touch case after the parent unmaps. The child case blocks SIGUSR1 before
fork; the parent unmaps and closes its fd before signalling. The child closes
its inherited fd before its bounded five-second sigtimedwait, then faults and
writes the mapping. The host compares the file bytes after both tasks finish.
Every fixture also runs under a bounded native Linux control.
The strengthened child case currently fails at the parent close with errno 9
(exit 38), before the signal and child first-touch. The earlier case passed
when close results were unchecked and the child kept its fd; that result is
not evidence for mapping-only lifetime. Keep the red case as an acceptance
blocker rather than weakening its fd-lifetime requirements.

The shared host-source witness samples a partial final page, truncates the
already retained file, and requires inaccessible supply past its new EOF. This
proves source revalidation, not a real-KVM truncation verdict. A guest
ftruncate-based KVM attempt stopped at ENOSYS before touching the mapping.
The real-KVM EOF witness separately proves SIGBUS when a file page has no accessible
supply. A plain CLI echo attempt against a locally imported image containing
the host echo, interpreter and libc exited 127, with no host-file crossing;
it does not prove the loader mapped libc. Later loader services remain #1714.

The cross-crate lock order remains capture under physical custody, release
custody for host service/file I/O, then reacquire and revalidate exact
execution/MM/root before publishing. Independent review must cover it.

Prepared-edit contention remains a P1 acceptance blocker: x86 currently
forwards `PreparedConflict` and implements no `park_prepared`. A sound follow-up
must share `coordinate_prepared_edit_wait` and ARM's semantic overlap predicate,
retain the exact `NativeMapKey` and source in the existing per-member map-source
custody across parking, consume the matching scheduler operation on resume,
and release execution capacity through the existing native process owner.
Restarting and staging a new source is not an equivalent fix: it changes
custody and can leak sources. Root Busy needs the same owned release protocol.
Add production Busy-once/then-success and prepared-conflict witnesses before
claiming concurrency acceptance. Full signed ARM gates and loader acceptance
remain outstanding.
