# Owed-return exclusion bound (#1482)

`kernel.el1.anonymous-reservations` requires retirement settlement to lower
and re-raise the MM's editor exclusion between chunks of at most 512 pages.
A merged extent must not turn a single exclusion into a whole-range walk.
The doorbell may process multiple chunks in one crossing, but acknowledgement
must advance the exact observed cursor only after that chunk's apply.

The production KVM binding is
`production_gib_owed_extent_settles_one_chunk_per_pause_in_one_doorbell`.
It runs `native_owed_return_gib.S` through the real CPL0 carrier, checks the
Linux-visible result against a native Linux execution, and checks both the
one-doorbell count and the maximum owed pages covered under an exclusion.
The fixture loads its ELF above the initial low stack so the production mmap
arena is not clipped below a GiB by that stack. Two abutting half-GiB
retirements, each containing one resident page, must merge into a GiB owed
extent; reusing its far end then requires settlement. Sparse residency keeps
the witness cheap without constructing reservation roots in the harness.

The counter is scoped to the carrier and recorded by the production
`OwedReturnRetirement::prepare` path. It measures covered virtual pages,
including holes, rather than counting only resident terminals. It is a
structural work assertion, not elapsed-time performance evidence. This
binding does not prove the ARM or HVF adapter, foreign-holder waits, COW
ordering, or concurrent retirement/claim lifecycle behavior.
