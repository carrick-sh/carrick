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
