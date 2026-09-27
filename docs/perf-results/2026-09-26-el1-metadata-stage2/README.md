# Metadata extent stage-2 ledger integration

Pre-change source 1c22dcdb3. Contract kernel.el1.metadata-allocation.
The production map operation was extracted without adding record publication;
the exact-record witness then failed because a successful map returned no
ownership identity (red.log, semantic failure exit 101). An earlier compile
error in the witness was corrected before capturing this semantic red.

Metadata now uses CarrierVmCustody's shared stage-2 records. Record admission
and backend map occur under one lifecycle lock: all fallible record admission
precedes backend publication, backend refusal removes the unpublished record,
and no observer can see a partially published pair. The callback must not
re-enter custody. Aperture ownership remains locked until its backing/record
pair is installed. Destruction follows the same aperture-before-lifecycle
lock order.

Grant records carry exact stage-2 identity, VM generation, receipt token and
owned shared backing. Return uses existing custody retirement; failed unmap
retains both ledger and backing, successful return removes the terminal record
and frees the aperture. Successful VM destruction terminalizes/removes its
metadata records before releasing backing. Metadata uses a reserved aperture,
so it never releases these IPAs into the global-frame allocator.

Five metadata tests and 48 existing custody tests pass; all-target HVF Clippy
with -D warnings and formatting pass. Tests cover failed map rollback, stale
VM rejection before map, exact identity, failed unmap with retry, exact-once
release and removal of terminal records. Signed verification of the combined
backing/custody/ledger changes is next; the previous signed green still belongs
to c33e1d152. Concurrent guest use, IRQ discipline, structural/retention budgets
and private test-control gating remain before full allocator acceptance.
First-touch and all remaining migration stages stay open.
