# IPC window binding and attachment (#1756)

The `kernel.el1.ipc-two-process` contract has VM-free admission and
attachment witnesses for `IpcWindowBinding`. The binding reuses
`FileRegionBinding`'s carrier identity, keeps supervisor VA and frame GPA
distinct, requires 2 MiB alignment and exact ABI lengths, and refuses
zero identity, overflow and overlap in either address domain. Table-map
derivation uses `KernelLayout.region` and refuses a foreign layout.
Admission does constant work independent of descriptor or pipe population.

The host view is `HostIpcWindow`, with `HostVa` addresses and `GuestLen`
sizes, borrowed from its backing owner. The guest view is `GuestIpcWindow`, with `KernelVa`, `FrameGpa`
and `GuestLen`. Both attach through the existing `IpcRegion::attach`.
The host view refuses pointer overflow. Guest attachment returns the
caller's retained mapping lifetime rather than manufacturing a static
lifetime. A typed binding validates geometry; it does not supply mapping
custody or permission to dereference a guest VA from the host.

`FileRegionRegistration` initializes the existing IPC table-map reservation
in place before publishing its identity. `FileTables::ipc_table_map` borrows
that map through the same authenticated registration as the file records.
Consuming the temporary view with `into_ipc_table_map` preserves the
original registration lifetime. Registered-map witnesses check the actual
reservation, isolation between two live registrations, and clearing a
poisoned reservation before publication.

The shared unsafe `guest_venue(layout, binding)` constructor authenticates
`FileRegionBinding` through `FileTables::in_guest`. It checks window
publication before touching the directory or pool, then attaches through
`GuestIpcWindow` and `IpcRegion`. The caller must retain all three mappings
and their exact virtual-to-physical bindings through the venue's lifetime.
The map comes from the supplied layout, without an ARM fixed address.

The Linux VM-free attachment witness maps initialized storage at a userspace
relocation of the x86 region, preserving the x86 layout's other fields and
all shared ABI offsets. The real x86 region VA is upper canonical and
cannot be mapped by host userspace; exercising that VA requires KVM.
The witness attaches an initialized directory and pool with distinct frame
addresses and resolves an owned table publication through the venue. It
requires refusal before window publication and after registration
retirement. A second witness requires foreign-layout refusal before memory
access. These are construction and authentication witnesses, not pipe
transfer or vCPU execution witnesses.

The original geometry witnesses were compile-red because `IpcWindowBinding`
did not exist; typed host-view admission was compile-red with E0433, and
registered-map access was compile-red with E0599. The constructor witnesses
were compile-red with E0425 before `guest_venue(layout, binding)` existed.

ARM now retains `FileRegionRegistration` in the same backing owner as its
birth-source mapping. Boot initializes it before stage-2 publication and
before the host aperture is observable. Mapping retirement clears its live
identity while any retained issuance handle still owns the backing. ARM
recovers the binding from its image's typed layout and uses the same
`guest_namespace` attachment as `guest_venue`; fork/exec namespace access
uses that entry too. The two old fixed-aperture guest accessors are removed.
The live/retired layout-lookup assertions were compile-red with E0599.
The HVF mapping-owner witness also checks that retiring the mapping withdraws
the registration while a retained backing handle remains alive; execution
of that macOS-only witness is unavailable on the Linux worker.

Slice 1 remains incomplete: `EL1_REGION_HOST_PTR` remains. Existing host
delegation and memory-mailbox consumers still use the global region;
replacing only IPC lookup cannot migrate their lifetimes.
No Slice 1 completion or x86 runtime pipe-service acceptance is claimed.
Slices 2–6 remain outside this continuation's scope.

Host handback, continuation and resume now borrow their operation storage
from `ZoneHostServices`, whose existing `Arc<HostIpc>` retains the exact
kernel's authority. The borrowed `IpcRegion` cannot outlive that service.
The two-kernel production-service witness drops both dispatchers, contexts
and external storage owners before looking up and completing an operation;
the peer service rejects that region and cannot find its operation. The
witness was compile-red with E0599 before the borrowed region accessor.
Descriptor admission now receives a scoped region borrow from the existing
carrier installation. The installation retains its backing while the callback
runs, including across replacement by a successor. Watchdog IPC census uses
the same scoped access. Reset withdraws admission while retaining the memory
needed by the installation's stage-2 records. `IPC_WINDOW_HOST`, its live word
and both publication accessors are removed rather than renamed. No pointer
array is reconstructed in another crate.

The host attachment lifetime is bounded by its window borrow. Its compile-fail
witness was red because the old attachment could escape as `IpcRegion<'static>`.
Descriptor admission still compares its kernel owner with the supplied mapped
window: a reused carrier can retain the first kernel's window while a later
kernel presents a different authority. The production admission witness keeps
two kernels live with colliding kernel-local file-table IDs, refuses the peer
and an unpublished map, and publishes the installed owner's table. A peer
cannot replace that published entry. Admission performs the same constant-work mapping
comparison before the existing bounded descriptor publication.

Descriptor publication now retains its table map through `IpcTableMapBacking`.
The ARM implementation visits the map through its existing
`FileRegionRegistration`, holding registration custody for the visit and
refusing a retired registration. The installed venue retains this same owner
alongside the IPC storage. Runtime admission receives both owners from that
installation; `ipc_table_map_host` is removed. File-table bindings retain the
map owner until withdrawal, rather than storing a static reference into a
mapping that teardown can release. Publication and withdrawal use the same
owner and neither reconstructs a region pointer.

`publication_retains_map_until_namespace_withdrawal` drives production
`FileTable::publish_ipc`: after the caller drops its handle, the namespace
keeps the map alive; namespace drop withdraws its entry before releasing its
last owner. The two-kernel admission witness no longer installs a global
aperture. The macOS mapping-owner witness checks that the retained registration
visits its map while live and refuses to invoke the visitor after retirement.
The latter witness requires HVF and is only cross-compiled on Linux.
The first attempt to pass a borrowed registered map to publication failed with
E0521: `FileTable::Binding` still required a static map. The retained owner
removes that requirement without extending the reference lifetime.

Other region consumers still use `EL1_REGION_HOST_PTR`; migrating those onto
retained registration remains unfinished. Neither these scoped IPC accesses
nor the earlier ARM migration proves real KVM pipe service or completes Slice 1.
