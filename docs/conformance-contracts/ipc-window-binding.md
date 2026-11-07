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

This is geometry admission only. It does not authenticate a live mapping,
construct an IPC venue, or serve a syscall. The existing `IpcWindow`,
`IPC_WINDOW_HOST`, `EL1_REGION_HOST_PTR` and ARM guest publication remain
unchanged. The approved slice still requires the typed host/guest view
split, shared `guest_venue(layout, binding)`, reuse of retained
`FileRegionRegistration` and `IpcRegion::attach`, and migration of ARM to
that publication path. No slice-1 completion or x86 runtime acceptance is
claimed by these witnesses.
