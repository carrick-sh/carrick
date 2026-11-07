# IPC window binding and attachment (#1756)

The `kernel.el1.ipc-two-process` contract has VM-free admission and
attachment witnesses for `IpcWindowBinding`. The binding reuses
`FileRegionBinding`'s carrier identity, keeps supervisor VA and frame GPA
distinct, requires 2 MiB alignment and exact ABI lengths, and refuses
zero identity, overflow and overlap in either address domain. Table-map
derivation uses `KernelLayout.region` and refuses a foreign layout.
Admission does constant work independent of descriptor or pipe population.

The host view is `HostIpcWindow`, with `HostVa` addresses and `GuestLen`
sizes. The guest view is `GuestIpcWindow`, with `KernelVa`, `FrameGpa`
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

Slice 1 remains incomplete. ARM's existing entry is now named
`current_guest_venue`; it shares the attachment body and table-map
implementation with the new constructor, but still obtains its window
from the fixed aperture. ARM registration ownership migration and removal
of `IPC_WINDOW_HOST` and `EL1_REGION_HOST_PTR` remain outstanding. Existing
host delegation and memory-mailbox consumers still use the global region;
replacing only the IPC accessor does not migrate their lifetimes. No
Slice 1 completion or x86 runtime pipe-service acceptance is claimed.
Slices 2–6 remain outside this continuation's scope.
