# Owed-return exclusion bound (#1482)

`kernel.el1.anonymous-reservations` requires retirement settlement to lower
and re-raise the MM's editor exclusion between chunks of at most 512 pages.
A merged extent must not turn a single exclusion into a whole-range walk.
The doorbell may process multiple chunks in one crossing, but acknowledgement
must advance the exact observed cursor only after that chunk's apply.

## Mechanism

The bound lives in the neutral owner, shared by the x86 CPL0 and HVF
carriers:

- `carrick-core-abi` `SETTLEMENT_CHUNK_PAGES` (512) and
  `SettlementBound::Chunk`. `ReturnSettlementRequest::retire_and_apply`, the
  only mint of acknowledgement authority, clips the observed request to one
  chunk before the venue's `prepare`. It mints one `SettledChunk` per covered
  extent whose `new_start` is the chunk's end, so the acknowledgement covers
  only the pages settled. The chunk takes at most 512 pages across all of
  the MM's extents, in slot order. An extent cut short ends on the 2 MiB
  grid, so no block terminal straddles the cut, and the first extent always
  advances.
- The progress record is the owed slot's `start`, the settlement cursor that
  slice 2 already introduced (`acknowledge_chunk`, a compare-and-swap of
  `start`). The next exclusion observes the journal again and continues from
  the advanced cursor. It never restarts from the extent's original front,
  and no second cursor exists.
- `carrick-hal` `settle_ring_owned_returns` settles one chunk per exclusion,
  and its receipt reports `owed_remains`. `settle_in_bounded_pauses` is the
  doorbell's drive: it raises one exclusion per chunk, settles under it,
  lowers it, and repeats until nothing is owed or a pause answers otherwise
  (a refused re-raise, a fork-loan skip or a busy root). Both carriers'
  doorbells (`ring_settlement` on x86, `settle_at_doorbell` on HVF) and the
  full-table drain call it. Every other exclusion settles one chunk and
  leaves the rest owed for the next exclusion.
- The host venue (`reconcile_el1_deferred_returns`, deleted by #1393) keeps
  `SettlementBound::WholeRequest`, because fork planning needs its whole
  journal settled at the boundary.

## Witnesses

The production KVM binding is
`production_gib_owed_extent_settles_one_chunk_per_pause_in_one_doorbell`.
It runs `native_owed_return_gib.S` through the real CPL0 carrier, checks the
Linux-visible result against a native Linux execution, and checks two
counts: exactly one doorbell, and the maximum owed pages covered under one
exclusion.
The fixture loads its ELF above the initial low stack so the production mmap
arena is not clipped below a GiB by that stack. Two abutting half-GiB
retirements, each containing one resident page, must merge into a GiB owed
extent; reusing its far end then requires settlement. Sparse residency keeps
the witness cheap without constructing reservation roots in the harness.

The neutral drive's VM-free witnesses are in
`carrick-hal::return_settlement::tests` (one chunk acknowledged per
exclusion, a GiB in 512 exclusions within one drive, resumption from the
cursor after a refused re-raise). The clip's witnesses are in
`carrick-core-abi::mm::return_settlement::bound_tests`.

The counter is scoped to the carrier and recorded by the production
`OwedReturnRetirement::prepare` path. It measures covered virtual pages,
including holes, rather than counting only resident terminals. It is a
structural work assertion, not elapsed-time performance evidence. This
binding does not prove the HVF adapter at runtime (it needs the signed Mac
lane), foreign-holder waits, COW ordering, or concurrent retirement and
claim lifecycle behavior.
