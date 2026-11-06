# x86 private file source binding (#1722)

The production KVM read-only and private-write witnesses now pass. The same
shared mapping handler and file-fault supply serve the x86 calls. Acceptance
is still incomplete: prepared-edit contention has no owned suspension binding,
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
opens use `NativeOpenFile`. Both now reach `native_map_reference`, which rejects O_PATH with errno 9, checks
read access and registers the same retained private source. The projection
shares the original physical lifetime, backing, identity and seals, but owns
no fd reference, cursor authority or publication pin. Its delegation handle and inode registration live in that same physical
lifetime. Mapping admission recalls through this shared identity before
incrementing the shared mapping count under the physical transition lock.
The pinned IPC resource authorizes admission after the host numeric fd closes;
final resource release still waits for both IPC holds and mappings to end.
Only MapPrivate is projected: unrelated host operations retain their existing
service admission.

Do not replace this with a numeric host-fd lookup, copied namespace, or a
strong original-description backlink (which cycles through publication).
The VM-free production-service witness closes the host fd, proves the original
description is gone and then reads the retained bytes. Disabling the physical
resource branch reproduces `NativeHostFileRefusal` in that witness. The
O_PATH witness was separately red (exit 33) before the shared access check.

File grants use the existing authenticated descriptor/inventory publisher.
They are excluded from the anonymous-only evidence population; that recorder
continues to reject a file-backed input rather than miscounting file pages as
anonymous pages.

## Witnesses and remaining acceptance

`cpl0_initial_mm` exercises read-only first-touch, private writes with an
unchanged source, write-only fd rejection (errno 13), path-only fd rejection
(errno 9), beyond-EOF SIGBUS, and
child first-touch after the parent unmaps. The child case blocks SIGUSR1 before
fork; the parent unmaps and closes its fd before signalling. The child closes
its inherited fd before its bounded five-second sigtimedwait, then faults and
writes the mapping. The host compares the file bytes after both tasks finish.
Every fixture also runs under a bounded native Linux control.
The strengthened case was red at parent close (errno 9, exit 38), then at
child close (errno 9, child exit 37). The x86 dispatcher did not attach its
mapped IPC venue and the fork service copied only the legacy descriptor
projection. Native records now select their complete published namespace;
borrowed host records retain their host mutation owner. ARM's existing
shared-IPC fork and retirement operations moved into
`file_table::{fork_native_namespace,retire_native_namespace}` and both ISAs
call them. Delegated-child rollback and deferred physical release are
preserved. The strengthened KVM case now passes with both close results
checked. The existing VM-free vfork schedule also checks that a borrowed host
record cannot claim this descriptor ownership while its native child can.

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
custody and can leak sources. Root Busy and an unavailable native descriptor publication need the same
owned release protocol. The descriptor selector retains native ownership
when its publication is unavailable; it still forwards rather than parking,
which remains a P1 acceptance blocker.
Add production Busy-once/then-success and prepared-conflict witnesses before
claiming concurrency acceptance. Full signed ARM gates and loader acceptance
remain outstanding.

### Suspension consumer dependency

The owner noted on PR #1735 that #1728 needs this same CPL0 suspension
consumer for host copyouts into lazy ELF pages. The remaining supply path
must have one consumer with guest-fault and host-copy callers. The current
focused private-file witnesses do not establish either continuation contract.

Mapping admission now uses one physical-reference owner with typed evidence
for an owned descriptor or the exact pinned IPC projection. Both paths use
the existing checked mapping-reference increment; the authority-debt ceiling
is unchanged.

### Rebased review witnesses

The added `private_file_source_limit_returns_enomem` binding attempts 1,024
untouched mappings, checks errno 12 on the next admission, unmaps one source
and requires a new first-touch mapping to read the original bytes. Native
Linux runs the bounded control with successful mappings (it has no Carrick
source limit). On the rebased pre-fix tree, this binding returned errno 38 with 506
host-file crossings recorded. Each private mapping consumes both a VMA node
and a source-index node, exhausting the 1,024-node bootstrap pool before the
source bound. The shared mapping handler now consumes the root guard to
provision an elastic bank through the existing metadata allocator, reacquires
the exact MM and redecides with the original frame and retained source. It
does not repeat the host-file request. One bank supplies 4,096 nodes; the
proposal needs at most five spare nodes. There is one capacity provision
attempt, with no polling or syscall replay. Both ISAs use this same path.

The real KVM binding now passes all 1,024 admissions, exact errno 12, release
and readmission, and first-touch bytes. Its execution witness requires exactly
1,026 host-file crossings and no guest refusals or trap-limit truncation. The
seven private-file KVM cases pass together. General owned admission waits,
metadata grant suspension after allocator exhaustion, and loader acceptance
remain outside this population correction.

`published_private_mapping_waits_for_recall_before_source_read` exercises the
production host-file service with a published IPC projection while its
original description has dirty delegated bytes. The writeback hook holds
recall in flight; the source reply must wait for release. Reading the retained
source then requires the new bytes and a zero-filled page tail. This witness
passes on the rebased base layer without changing delegation policy.

### Shared source identity and bounded admission review fixes

The delegation handle belongs to the physical description lifetime, alongside
its inode registration. IPC mapping projections and their original description
therefore observe the same live handle even when delegation begins after IPC
publication. Admission and fault-time `read_for_io` use that same identity;
the weak original-description recall workaround is removed. This adds no
publication backlink or lock order: recall still precedes the physical
transition lock, and source reads still run outside physical carrier custody.

`ForkHostBackingCustody::prepare_private_mapping` is now the common ARM/x86
record-admission owner. It validates the complete release list, retires those
sources, and writes errno 12 at 1,024 retained sources before host service.
Its VM-free binding fills the actual custody to that bound, checks the error
reply, and releases one source through the next request before readmission.
The existing thousand-cycle release witness moves from HVF to this shared
owner. This component witness does not resolve the real-KVM reservation
population failure or the suspension consumer dependency described above.

The fault-specific binding
`published_private_source_fault_joins_late_delegation_recall` admits the pinned
IPC mapping during a real delegation's fill-to-publication interval. The
already eligible delegation then publishes and receives a dirty guest write.
The production retained-source read must enter recall, publish no bytes while
writeback is held, and return the updated bytes and zero tail after release.
This is distinct from the older mapping-admission witness. The source-retention
operation now has a narrow MM-authority method shared by production host-file
admission and this test; it retains the original metadata-lock scope.


### Elastic bank review boundary

The cross-crate ordering for node growth is reservation root release, metadata
allocator lock and bank publication, then exact-MM root reacquisition and
descriptor editing. No MM guard or descriptor edit survives allocation.
Unused retained sources still retire through the shared mapping wrapper.

Independent review identified an adjacent P2 diagnostic gap: the stopped-host
`ProductionCpuFactory::initial_reservation_census` uses an unresolved host
root view and returns `MetadataRequired` once an elastic bank exists. Its
consumers are diagnostic tests; production guest fork uses identity-bank
access. A retained host bank resolver is a separate follow-up, not evidence
of a guest fork failure or a reason to change this source-limit witness.
