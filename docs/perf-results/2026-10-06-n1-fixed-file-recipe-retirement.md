# N1 fixed private-file recipe retirement

The exact `03796941f` E+A cycle still matches zero of three main-pass
bindings. Host-buffers fails with SIGSEGV, inotify fails loading libpython
with exit 127, and transparent fork advances beyond its previous owner
parent-transfer refusal but fails with SIGSEGV. Its results and fresh image
identities are retained at
`/Volumes/carrick-build/evidence/n1-cm/fork-03796941f/`.

## Qualified loader failure

The retained `3804e37e7` inotify executable and matching dSYM stop at the
production file-lowering error with `PrivateFileSource::ImmutableLower`:

- VA `0x600048a000`, length `0x1d4000`, file offset `0x47a000`;
- `defer private file backing: deferred anonymous range is empty,
  unaligned, or overflows`;
- eager fallback then fails with `MemoryError::OutOfBounds` at the same
  range, becoming mmap errno 12 and the loader's exit 127.

The extent is aligned and does not overflow. The same deferred-state error
also rejects overlapping file recipes. Root placement retired the opaque
owner row, but reclaimed first-touch recipes only in prior root holes.
An overlapping fixed loader segment therefore retained the old recipe.
This is separate from the remaining host-buffers SIGSEGV.

## Red-first witness and correction

`delegated_fixed_lazy_file_replacement_retires_only_replaced_recipe` uses
the admitted production reservation root and production deferred file
state. Its first red showed that owner-held file rows also escaped the
placement overlap check: MAP_FIXED_NOREPLACE returned a mapping address
instead of errno 17. After correcting that check, the recipe red read byte
2 from the old offset instead of byte 4 from the replacement offset.

Collision checks now observe all committed root mappings. After successful
fixed host placement replaces the exact old root range, first-touch
retirement removes that range's previous recipes and residency facts before
the backend retains the new recipe. Existing deferred-state splitting
preserves the left and right file fragments and their offsets. Refused
placement does not reach retirement. No fallback, deadline, retry budget,
concurrency reduction or descriptor-copy bypass is added.

Evidence lives under
`/Volumes/carrick-build/evidence/n1-cm/fixed-deferred-recipe/`:
`noreplace-red.log` and `red.log` contain the two qualified reds. Initial
compile and test-outcome adapter mistakes are preserved separately and do
not count as behavioral reds. The final extended backing-suite green passed
30 tests, the delegated-root suite passed 81, and the fault suite passed 17.
Formatting, workspace clippy and the 98-contract registry check passed.
The verification driver's initial registry command named a nonexistent
Python script; its failure is retained and the actual Rust registry checker
passed separately in `contracts.log`.

The registered contract is `kernel.mm.owner-reserved-file-content`. This
VM-free witness closes file bytes, offsets, refused-placement preservation
and zero eager writes at the kernel seam. Its memory adapter does not run
HVF descriptor publication. A newly published exact fixture bundle and
signed inotify result are still required; no signed green or whole-stack
acceptance is claimed by this change.
