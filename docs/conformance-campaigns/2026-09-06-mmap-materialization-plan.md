# Exact-MM materialization implementation plan

> For agentic workers: execute sequentially with review checkpoints; preserve the existing authorized worker boundaries.

Goal: share physical materialization across local and foreign access and meet the mmap campaign contracts.
Architecture: MM-owned semantic state feeds one backing/publication transaction. Caller adapters supply already-acquired mutation exclusion and exact-ASID invalidation.
Tech stack: Rust, Darwin arm64 HVF, existing Carrick frame inventory and Stage1Authority.
Spec: `2026-09-06-mmap-materialization-design.md`.

## Constraints

macOS only. No Docker concurrent with Carrick. Every execution uses CARRICK_RUN_ID.
Do not claim a main milestone before full serial runtime, whole probe family,
Ubuntu shell/Python launches, exact signed artifact and 10/6 us measurements.

## Backing preparation

- [x] Extract the allocation block from HvfVmState::materialize_sparse_mmap_extent
  into `crates/carrick-vmm-hvf/src/trap/sparse_materialization.rs`.
- [x] Return a PreparedSparseBacking owning GlobalFrameOwnerRollback plus the
  exact physical and semantic host/IPA extents, permissions, backing identity
  and owner generation. The caller cannot accidentally release staged ownership.
- [x] Preserve existing behavior during extraction; full signed HVF lib suite.
- [x] Red allocation-shape assertion: a 4 KiB anonymous extent starting 4 KiB
  before a 2 MiB boundary requires one 16 KiB host allocation, not 2 MiB.
  Keep file and bulk-anonymous congruence unchanged. Prove green and commit.

## MM-scoped publication

- [ ] Move page-table/inventory publication from the executor into this module.
  Input is prepared backing plus exact-MM mutation permit; output is the
  authenticated committed mapping/frame/owner receipt.
- [ ] Page-table resolver uses MM-owned structural owners. Make extension arena
  custody MM-owned so foreign publication does not require an executor cache.
- [ ] Journal and test failures after stage-2 registration, page-table edits,
  live sync, invalidation and inventory application. Each recoverable failure
  must preserve preimages and pristine state with no published dangling owner.
- [ ] Local adapter updates mappings/deferred-protection receipt only from the
  successful common receipt. Run full signed HVF tests before committing.

## Anonymous consumers

- [ ] Add a nonmutating pristine-range query; verify no logical residency change.
- [ ] Validate writable syscall buffers per page with explicit pristine
  provenance and logical permissions. Copyout uses the common materializer.
- [ ] Foreign unarmed pristine writes call the common transaction under their
  existing target-MM mutation guard, then refresh the retained snapshot and
  commit through the ordinary prepared-write path.
- [ ] Red/green tests: partial pages, mixed backing, target isolation, stale MM,
  denied permission, missing provenance, fork policies, unmapped/reused address.
- [ ] Signed guest first-touch tests plus host allocation census: untouched
  mappings allocate no private host backing; faults preserve neighboring bytes.

## Final campaign gates

- [ ] Attribute residual file-map overhead with the existing exact-binary
  counter and low-perturbation trace, fixing structural work rather than
  weakening owner authentication or copying the entire file.
- [ ] Whole-file zero-copy plus isolated file <=10 us and anon <=6 us.
- [ ] Full serial runtime and whole probe family on final source/binary.
- [ ] Ubuntu sh true and Python print receipts, clean-tree inventory reconcile,
  commit and lint; FF only from main checkout.
- [ ] Quiet-host fork measurement and full 2127-row cached-only ecosystem ledger
  replace Sep 4 floor; rank correctness failures and meaningful >2x ratios.
