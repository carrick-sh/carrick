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

## Descriptor-window integration checkpoint

The carrier now retains the original `HostIpc` directory and pool through
`BackingExtent::ipc_window`, using the existing batch memslot rollback owner.
It maps supervisor writable NX aliases at `X86_CPL0_IPC_BASE` and
`X86_CPL0_IPC_POOL_BASE`, binds the operation-slot generation, and publishes
its root namespace. Dynamic grants start beyond the reserved physical IPC
window. The shared guest attachment selects the ISA's alias addresses.

`IpcTableMapBinding::Retained` keeps the descriptor-map allocation alive until
the host file table withdraws its publication; it does not manufacture a static
reference to carrier-owned storage. VM-free tests check original allocation
pointer identity, authority retention through memslot lifetime, and map
withdrawal before storage release.

The two real KVM witnesses still return mmap errno 38 (exit 32). Their
execution witnesses now count one `host-file` crossing each, proving staging
and the synchronous transport are reached. They do not reach a physical
file-page grant. The remaining refusal is in the shared host-file resource
service: `FileTable::publish_ipc` exports preopened host slots as
`IpcPhysicalHold`, whereas `serve_native_resource` accepts `NativeOpenFile`
(and implicit stdio). The x86 forwarded open path also installs host slots;
ARM native opens install `NativeOpenFile` through `NativeOpenSink`.

Do not fix this with a numeric host-fd lookup, a copied namespace, a strong
FileDescription backlink in IpcPhysicalHold (which cycles through publication),
or by changing the witnesses to bypass the x86 open authority. The integration
needs a shared physical resource/source projection or the shared native-open
service admission, with the same functional lifetime and delegation recall
rules. This checkpoint does not claim loader, echo, Python, fork-source, EOF,
or prepared-edit contention acceptance.
