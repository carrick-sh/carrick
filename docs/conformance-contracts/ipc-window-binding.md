# IPC window geometry admission (#1756)

The `kernel.el1.ipc-two-process` contract now has VM-free geometry
witnesses for `IpcWindowBinding`. The binding reuses `FileRegionBinding`'s
carrier identity, keeps guest supervisor VA and frame GPA distinct, requires
2 MiB alignment and exact ABI lengths, and refuses overflow and overlap in
either address domain. Table-map derivation uses the supplied
`KernelLayout.region` and refuses a layout from another file region.
Admission does constant work, independent of descriptor or pipe population.

The first three tests were compile-red because `IpcWindowBinding` did not
exist. They are now unit tests in the existing ABI lib target so the normal
ABI test gate executes them. Additional edge cases cover overflow, zero
VAs, overlap with the carrier region and nonidentity VA/GPA mappings.

The host view is now `HostIpcWindow`, with `HostVa` addresses and
`GuestLen` sizes. The guest view is `GuestIpcWindow`, with distinct
`KernelVa` and `FrameGpa` addresses and ABI lengths returned as `GuestLen`.
Both attach through the existing `IpcRegion::attach`. The host view refuses
pointer overflow before attachment; its typed-address witness was compile-red
with E0433 before the split. The guest view can be derived from the admitted
binding without converting frame GPAs into supervisor pointers.

This remains partial slice-1 work. The ARM fixed-address guest constructor
and both process-global publications are still present. Retained
`FileRegionRegistration` integration, a shared `guest_venue(layout, binding)`,
the live x86-layout venue witness and ARM migration remain unimplemented.
The typed guest view witness proves address preservation, not a live venue.
No slice-1 completion or x86 runtime acceptance is claimed.

The typed-view continuation passed the ABI suite (191 tests; serial filter
matched zero), EL1-native (742 tests, one ignored), freestanding CPL0 build,
Linux and macOS cross-checks, native KVM crate check, clippy, formatting,
contract-change validation and source-only authority validation including the
admitted-main delta ratchet. The initial ARM image compile refusal and derive
audit refusal were corrected before these final passes. These checks do not
supply the missing live venue or real-KVM pipe-service acceptance. Docker and
HVF execution are unavailable on this Linux runner; runtime KVM was not run.

The retained file registration now initializes the existing IPC table-map
reservation in place before publishing its identity. `FileTables::ipc_table_map`
borrows that map through the same authenticated registration as the file
records. The x86-layout witness was compile-red with E0599 before this
accessor existed. It checks the actual mapped reservation and publication
isolation between two live carrier registrations; a second witness poisons
the reservation before registration and requires an empty unpublished map.
These checks prove a live registered table-map view, not a complete IPC venue:
no IPC directory/pool is attached and no pipe bytes are transferred by them.

The shared guest constructor, ARM registration ownership migration and removal
of both global publications remain outstanding. Existing ARM consumers also
use the global region for delegation and memory mailboxes; replacing the IPC
map accessor alone does not migrate those lifetimes. The work still does not
meet Slice 1 acceptance. Slices 2–6 remain out of this continuation's scope.

The shared unsafe `guest_venue(layout, binding)` constructor now authenticates
`FileRegionBinding` through `FileTables::in_guest` before borrowing its map.
The map is derived from the supplied layout's region; no ARM address is used.
The constructor checks window publication before touching the directory or
pool, then uses `GuestIpcWindow::attach` and the existing `IpcRegion::attach`.
Guest attachment now returns the caller's retained mapping lifetime rather
than inventing a static lifetime. The map view can retain the original
registration lifetime after consuming the temporary `FileTables` view.

The Linux VM-free witness maps initialized storage at a userspace relocation of
the x86 region (the actual upper-canonical VA requires KVM), attaches an IPC directory and pool with distinct frame addresses,
and resolves an owned table publication through the constructed venue. It
requires refusal before window publication and after registration retirement.
A second witness requires foreign-layout refusal before memory access. Both
were compile-red with E0425 before the constructor existed. These witnesses
prove construction and identity checks, not pipe transfer or vCPU execution.

ARM's existing entry is now named `current_guest_venue`; it shares the
attachment body and table-map implementation with the new constructor, but
still obtains its mapping from the fixed aperture. ARM registration ownership
migration and removal of `IPC_WINDOW_HOST` and `EL1_REGION_HOST_PTR` remain
unfinished. This is an incomplete draft checkpoint, not Slice 1 acceptance.
