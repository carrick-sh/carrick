# Extension reuse and retirement ordering

Base: `df1b13634`. Contract: `kernel.fork.stage1-image`.

The live resolver discarded `record_populated_prefix` updates. A real one-slot
pool witness writes byte 0xab into a live extension, records its prefix,
retires its exact structural backing, then reissues the same host slot. Before
the fix the byte remains 171 rather than zero. Afterward the reissued range is
zero. The fixture uses actual pool storage and an explicit backend test stub;
it does not run a guest or invoke HVF.

The resolver now records the prefix on the current non-retired structural owner,
checking generation presence, owner length and the complete offset/range. It
uses a bounded ordered lookup without a new allocation or owner pin.
`PageTableManager::sync_to_host` and snapshot restore already issue the updates
at publication; this repairs their live adapter.

Source review found the sole `release_structural_owner_at` caller in
`HvfTaskState::retire_stage1_extension_arenas`. The exec replacement takes the
old manager out of `Stage1Authority` under its inner lock before calling that
retirer; subsequent authority readers see no old manager. Undo retirement is
separately covered by the existing authority/arena retirement tests.

Root retirement had an inverse lock order relative to
`HvfTaskState::record_stage1_populated_prefix`: it took the root-slot lock before
the descriptor authority. It now follows publication's authority-then-root
order while retaining exclusion through the transaction. This order correction
is source-derived; no empirical concurrent deadlock reproduction is claimed.

Verification (`RUSTC_WRAPPER=`, serial HVF tests): 3 focused live-resolver tests
pass, the full HVF suite passes 564 with 3 existing ignores, all-target HVF
Clippy passes, and all abort-ledger shards pass. The pool witness was red first.

This completes the identified director corrections for source integration.
Clean-tree inventory/CI and signed promotion must still qualify the integrated
artifact. Actual EL1 fault service, elastic grants, COW migration, and later
checkpoints remain open.
