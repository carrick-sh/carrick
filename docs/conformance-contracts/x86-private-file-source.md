# x86 private file source binding (#1722)

The two production KVM witnesses in `cpl0_initial_mm` remain red: their native
controls exit 0, but Carrick returns mmap errno 38 and exits 32. This work is
not ready to land. Neither libc loading nor echo nor Python startup is proven.

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

## Remaining resource prerequisite

Each real KVM witness now counts one `host-file` crossing, proving staging
and synchronous transport are reached. Neither reaches a physical file-page
grant. The remaining refusal is in shared host-file resource service:
`FileTable::publish_ipc` exports preopened host slots as `IpcPhysicalHold`,
whereas `serve_native_resource` accepts `NativeOpenFile` (and implicit stdio).
The x86 forwarded open path also installs host slots; ARM native opens install
`NativeOpenFile` through `NativeOpenSink`.

Do not fix this with a numeric host-fd lookup, a copied namespace, a strong
FileDescription backlink in IpcPhysicalHold (which cycles through publication),
or by changing the witnesses to bypass x86 open authority. Integration needs
a shared physical resource/source projection or shared native-open service
admission, with the same functional lifetime and delegation recall rules.

## Review and evidence still owed

The cross-crate lock order is capture under physical custody, release custody
for host service/file I/O, then reacquire and revalidate exact execution/MM/root
before publishing. Independent source review covered the installation and
retained storage, confirmed the IPC/dynamic-grant aperture overlap fix, and
requests changes for the unresolved resource refusal and these missing proofs.

The no-backing completion leaves an authenticated file selection pending;
the fault entry cancels it and delivers SIGBUS. EOF/truncation and inaccessible
source behavior need production witnesses after source staging is accepted.
Prepared-edit contention still needs an owned suspension binding: the existing
x86 adapter forwards `PreparedConflict` and has no `park_prepared`
implementation. A real child must also fault an untouched file page after its
parent unmaps/exits, then write privately without changing the source. The
single-MM read-only and private-write cases cannot prove that fork lifetime.
