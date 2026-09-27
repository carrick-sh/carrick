# MMU metadata allocation admission audit

Source inspected: `31e3e3a14` (the integrated MMU implementation is unchanged
by the concurrent fault-entry worker). This is static evidence for the next
prerequisite, not a reproduced current guest failure or an accepted design.

The existing reservation witness already rejects enabling `BumpAllocator`: its
first allocation overlaps the object table. The ABI also places the fd/open-file
tables, file cache, inotify/name caches and scheduler zone inside the nominal
heap window. Merely moving past the object table does not establish exclusion
from the rest of those ranges. The allocator has no deallocation operation.

A second prerequisite exists independently of heap placement. In
`crates/carrick-mmu-core/src/aarch64.rs`:

- `PageTableManager::begin_undo` returns `()`, uses `collect` for arena watermarks
  and clones the free-table vector. There is no allocation-refusal result.
- `note_undo` grows `journal.words` and `first_written`; `write_desc` and
  `write_table_desc` grow the staged hash map and dirty vector. Their existing
  `Result` covers other errors, but these collection operations allocate
  infallibly. Owned-table writes can also resize their byte vector.
- `rollback_undo` validates/resolves memory and restores descriptor words,
  then takes the undo journal. It subsequently creates and grows `popped`
  while removing extension arenas and returning them to the source. This
  path still allocates after consuming the journal. A recoverable metadata
  refusal model cannot rely on a fresh allocation at that point.
- `TableArenaSource::take_arena` returning `None` covers table-frame refusal;
  it does not cover these distinct metadata allocation sites. Existing
  frame-refusal/rollback tests therefore cannot alone prove metadata refusal.

Consequently, installing a reclaiming global allocator alone would not close
EL1 allocation acceptance. Before the MMU core is used in live EL1 fault
service, its selected mutation/rollback paths need explicit admission and
refusal evidence. Required witnesses include refusal before journal creation,
during journal/staged/dirty growth, and during extension-arena bookkeeping;
they must preserve authoritative descriptors, owner generations and retained
rollback state, return unused frame grants exactly once, and permit subsequent
success. Exercise scales 1/8/32/128 and repeated allocate/free cycles without
widening existing work budgets. Register the precise contract red-first.

The accepted end state remains elastic host grants and guest reclamation; a
fixed metadata or frame pool is not final acceptance. The implementation
choice (pre-admitted capacity, fallible containers or another explicit storage
interface) still requires a bounded plan and concrete refusal witness. This
audit does not authorize duplicating memory policy or enabling guest writers
before publication/ownership invariants are proved.
