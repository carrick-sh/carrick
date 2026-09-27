# MMU metadata refusal implementation plan

> For agentic workers: use executing-plans task by task. The director owns integration and signed acceptance. This task follows the already authorized EL1 goal and execution method.

**Goal:** Make the existing neutral MMU edit/publication/rollback transaction recover from metadata allocation refusal, so it can later execute in EL1 without aborting or losing its authoritative state.

**Architecture:** Retain one PageTableManager and its existing undo journal. Admit collection capacity through fallible reservations before the corresponding state mutation. Propagate an explicit metadata-refusal error through existing host adapters. Rollback consumes pre-admitted storage and performs zero allocations, including extension-arena return bookkeeping. Do not enable the dormant EL1 allocator or guest page-table writers in this task.

**Tech stack:** Rust no_std + alloc, hashbrown, current host VM-free tests.

**Spec:** docs/superpowers/specs/2026-09-24-el1-kernel.md (Memory); docs/superpowers/plans/2026-09-26-el1-completion.md; docs/perf-results/2026-09-26-el1-first-touch/allocator-prerequisite/mmu-allocation-audit.md.

## Constraints and review focus

- Elastic host grants and guest reclamation remain the end state. No fixed-capacity pool, independent page-table implementation, widened work budget, or allocator that overlaps ABI regions.
- Preserve live descriptor authority, owner generations, publication ordering, resolver revocation recovery, existing fork snapshot allocation bounds and source identity. Metadata refusal is distinct from table-frame refusal.
- An error before journal installation leaves the original state unchanged. An error after earlier edits retains a complete usable journal and cannot expose partial uncommitted descriptors. Subsequent rollback and retry must succeed.
- No allocation after rollback starts restoring descriptors. Reserve its returned-arena list while the transaction is recoverable, before attaching another arena; preserve exactly-once source return even when metadata refuses a newly obtained grant.
- Include publication scratch when arena count exceeds the current eight inline slots, owned byte growth, free-table zeroing/reuse, and extension bookkeeping. Journal/dirty/staged vectors alone are not the complete mutation closure.
- Test repeated writes, revoked resolver during recovery, existing dirty state, primary/extension exhaustion, and repeated failed then successful transactions. Do not globally serialize tests or introduce allocation failpoints that bypass the actual allocator.

## Files and interfaces

Modify crates/carrick-mmu-core/src/aarch64.rs (and focused modules beneath that crate if useful), crates/carrick-aarch64/src/stage1_authority.rs and engine.rs, crates/carrick-vmm-hvf/src/trap/{sparse_materialization,cow_engine}.rs for propagation only. Register conformance-contracts/contracts/mmu-metadata-refusal.toml and any necessary registry/test binding. Evidence goes in docs/perf-results/2026-09-26-mmu-metadata-refusal/.

Add PageTableError::MetadataAllocation. Change the existing begin_undo(&mut self) to return Result<(), PageTableError>, with no parallel infallible entry point. Preserve rollback_undo's result type and caller semantics, using pre-admitted storage for returned bases. Propagate the error through the existing transaction owners; do not silently ignore it or turn it into a fatal allocation failure. Narrow necessary call-site updates are part of this task. Snapshot construction, root-manager construction and rebasing must be inventoried as later prerequisites if not reachable from the selected edit transaction; do not claim all MMU allocations are fallible.

## Task 1: red evidence and contract

- [ ] Register kernel.mm.metadata-refusal with Linux mapping preservation after failure as semantic authority and zero-allocation rollback as a structural invariant. Bind the cheapest capable VM-free tests and state signed guest binding remains pending until guest MMU service exists.
- [ ] Extend the existing test-only System allocator wrapper (do not install a competing global allocator). Count all allocations in a thread-local, bounded operation scope. A real current rollback that returns extension arenas must fail an assertion requiring zero allocations; retain that red output on the original implementation. Set up backing and source bookkeeping before counting so unrelated test allocations do not create the red.
- [ ] Capture original descriptors, translations, journal state, source grants/returns and owner identity at scales 1/8/32/128. Do not call compile errors semantic red.

## Task 2: fallible edit transactions

- [ ] Implement fallible begin_undo, descriptor pre-image admission, staged/dirty capacity admission, owned byte growth, arena/free-table bookkeeping and publication scratch. Reserve before changing the corresponding recoverable state. Include alloc_table, free_table, write_desc, write_table_desc, sync_to_host and rollback_undo; inspect their callees for other mutation allocations.
- [ ] Propagate refusal through all production begin_undo callers and matching tests. Preserve their existing rollback and cleanup paths. A capacity failure while obtaining an extension returns any unused grant exactly once.
- [ ] Exercise genuine allocator refusal with the test allocator returning null for selected allocation attempts in guarded transaction scopes. Enable refusal only after fixture setup; restore it before assertions/logging. Sweep actual allocation attempts and prove no panic/abort, no leaked grants, preserved recovery and subsequent successful mutation. Keep a red allocation-count witness separate from refusal tests that an old infallible implementation would abort.
- [ ] Require zero allocations during rollback at 1/8/32/128 extension scales and repeated cycles; no scans proportional to unrelated historical mappings, and retain current snapshot warm-allocation zero budget. Test the >8-arena publication scratch branch and refusal after partial staged edits.
- [ ] Inventory any remaining infallible allocations outside this transaction closure explicitly. They remain migration prerequisites, not exemptions from the final goal.

## Verification and acceptance

Run exactly, with RUSTC_WRAPPER=:

- cargo test -p carrick-mmu-core -p carrick-mem -p carrick-aarch64 --lib
- cargo clippy -p carrick-mmu-core -p carrick-mem -p carrick-aarch64 -p carrick-vmm-hvf --all-targets -- -D warnings
- cargo check -p carrick-mmu-core --lib --target aarch64-unknown-none-softfloat
- cargo test -p carrick-conformance-contract
- cargo fmt --all -- --check

Commit narrow changes with the required body and agent trailer. The director reruns these and reviews every changed caller before integration, then full CI and signed promotion. No Docker, signed guests, builds replacing the integration binary, or acceptance of first-touch performance in the worker. Heap region exclusion, reclaiming allocator, bulk frame grants and actual first-touch service remain subsequent work; this prerequisite must not be presented as the memory checkpoint's completion.
