# x86 private file source binding (#1722)

The two production KVM witnesses in `cpl0_initial_mm` remain red: both native
controls exit 0, but Carrick returns mmap errno 38 and exits 32. This work is
not ready to land. Neither libc loading nor echo nor Python startup is proven.

The mapping adapter now calls shared `native_host_file::stage` and
`serve_delegated_mapping`. Its synchronous crossing carries the existing
host-file record, authenticates retained supervisor POD storage, and calls
`SyscallDispatcher::serve_native_host_file` outside physical custody. Sources
are retained before reply publication under the complete address context.
Fork stock carries `ForkHostBackingCustody` and authenticates host-source rows
separately from physical frame rows. File grant reads clone the capability,
release custody and CPU-I/O borrows, read its bounded prefix, then authenticate
the execution and selection again before physical publication. Fault entries
supply their file slots to the shared fault owner.

## Remaining namespace prerequisite

Production x86 does not install or publish the shared `HostIpc` directory and
pool. `ipc_table_map_guest` also used the ARM region address. The new staging
entry initially hit that wrong address (`CR2=0x2d054b0004`) and reached the
supervisor page-fault fixup's invalid instruction. Selecting the x86 retained
region fixes that address error. Its unpublished map now refuses attachment;
there is still no source service available to the production mapping entry.

The missing integration must retain the original authority's memory:

- Obtain the backing via `kernel::continuation::ipc::host_window_backing`.
- Admit the directory and pool through typed retained external carrier
  backing, including rollback and slot custody. `BackingExtent` currently
  supports owned `GuestRam`, not borrowed `HostIpc` pointers.
- Publish supervisor writable NX mappings at x86 kernel addresses.
  `ipc_window_guest` still assumes the ARM directory/pool addresses.
- Attach the window, bind the zone's operation-slot generation, then publish
  the exact carrier's table map and admit the root's file table with
  `FileTable::publish_ipc`.

ARM's reference implementation is `install_registered_ipc_window` in
`carrick-vmm-hvf/src/trap/stage2_backend.rs`. Copying its directory or pool
would create a second allocator/descriptor authority and is incorrect.
Generic `publish_file_table` depends on ARM process-global region/window
registration; x86 needs explicit carrier-scoped publication.

## Review and evidence still owed

The cross-crate lock order is capture under physical custody, release custody
for host service/file I/O, then reacquire and revalidate exact execution/MM/root
before publishing. This requires independent review together with namespace
installation, before acceptance.

The new no-backing completion leaves an authenticated file selection pending;
the fault entry cancels it and delivers SIGBUS. EOF/truncation and inaccessible
source behavior need production witnesses after source staging is reachable.
Prepared-edit contention still needs an owned suspension binding: the existing
x86 anonymous adapter forwards `PreparedConflict` and has no `park_prepared`
implementation. A real child must also fault an untouched file page after its
parent unmaps/exits, then write privately without changing the source. The
single-MM read-only and private-write cases cannot prove that fork lifetime.
