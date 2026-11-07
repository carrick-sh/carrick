# Native file staging must retain descriptor admission

Issue #1694, Bet 6 slice 3, extends `kernel.native.host-file-venue` and
`kernel.memory.owner-wait`. This is an implementation design, not passing
retention evidence. The existing input outcome changes do not close this
contract.

Linux `write(2)` and `writev(2)` act on the admitted open description. A
Carrick-internal memory wait must not admit the numeric descriptor again.
The same rule applies when preparing `read(2)` and `readv(2)` destinations.
Only `CopyOutcome::Fault` becomes errno 14; `NotYet` retains the operation
and uses the existing owner-memory notification and rerun protocol.

## Two admission boundaries currently remain

`native_host_file_stage` resolves the descriptor through
`ipc::native_descriptor`, which reads the table without owning a pin. Its
`HostFileStage::Fault` result reaches the native service fault adapter,
which retains the syscall frame and reruns staging after supply. Closing
and reusing the number during that wait changes the next lookup.

The carrier then calls `HostIpc::with_pinned_host_resource` in
`serve_native_host_file_in`. That helper creates a new pin from the record's
table and numeric fd. Retaining a pin only in the ring is insufficient:
the carrier must serve the admitted description too.

## Ownership change required before claiming closure

1. Pin through `carrick_fd_core::Authority::pin` before any potentially
   suspending input gather or output preparation. Check access against that
   pinned description. Keep the owned `OfdPin` in exact-task pending state,
   outside the temporary dispatch entry. Re-entry takes that state before
   consulting a numeric fd. A reference-count observation is not ownership.
2. Extend the typed host-file record to identify the retained pin using its
   authority, index and generation. Define the record layout in
   `carrick-core-abi`, with layout tests and independent review before code
   changes. Do not hide the identity in untyped operation argument words or
   add a service-time numeric-fd fallback. Path-only operations need no pin.
3. Authenticate the retained pin with `Authority::pinned` at carrier service,
   resolve its `IpcBacking::Host` resource, and run the existing resource
   operation. Reuse the resource lookup and release code in `el1_ipc` rather
   than duplicating it. The published service record borrows this identity;
   it must not manufacture a second owner with `OfdPin::from_raw`.
4. Keep ownership until carrier completion or cancellation acknowledgement.
   Release exactly once on every terminal path. A final host-backed release
   belongs to the existing host cleanup authority; the ring-only IPC
   `release_pin` helper cannot finalize it. No editor or copy permit survives
   a memory wait.
5. Retain the gathered input and byte cursor across subsequent refusals.
   A refused piece has no host effect; a completed piece is never replayed.
   Use the existing neutral `UserCopy` and `CopyOutcome` throughout the file
   and delegation adapters, with ISA code limited to access mechanics.

This changes a crossing record, so the wire-layout design requires its own
review under AGENTS.md. It does not require a second copy outcome or a new
wait protocol. The ordinary file delegation adapters are shared with x86;
an ARM-only staging test does not qualify that shared surface.

## Required production witnesses

Use the VM-free EL1 native-process harness and production dispatch, owner
wait and carrier service entries. For `write` and `writev`, refuse one valid,
read-only lazy source piece, observe the owner park, close/reuse the original
numeric fd, release the owner, and resume. Require the original pin identity,
exactly one copy of the expected bytes in the original description, and no
bytes in the replacement. Exercise a later vector/piece too, so a successful
prefix cannot be replayed. For `read` and `readv`, refuse destination
preparation and require the same description and cursor on resumption.

Count one enrollment and one successful completion, and verify pin retirement
after completion and fatal cancellation. Bound actor coordination waits. Run
each witness red on the pre-fix production implementation, then green; a
direct call to the staging helper cannot prove these ownership transitions.
The existing adapter classification tests remain useful but are not these
witnesses. Signed and Docker evidence remain separate higher-layer gates.

## Borrowed-pin API checkpoint

`OfdPin::identity` now lends an `OfdPinIdentity`, which can authenticate a
lookup through `Authority::pinned_identity` without manufacturing ownership.
`HostIpc::with_retained_host_resource` uses that lookup and the existing host
resource table. `release_host_pin` shares the existing final backing release
authority with numeric admission. The borrowed key cannot be passed to
`unpin`; the owned pin must remain live through every borrower.

The fd-core binding closes/reuses the numeric descriptor and checks the
original description, unchanged hold count, foreign authority, oversized
index, retirement and generation reuse. The carrier binding writes the
original host resource after numeric reuse, checks the replacement remains
empty, and counts exactly one final release per resource. These are API and
carrier-resource witnesses only. No crossing wire change, exact-task staging
retention or production lazy-memory syscall witness is claimed by this
checkpoint. The production staging path still has the two admission
boundaries described above.
