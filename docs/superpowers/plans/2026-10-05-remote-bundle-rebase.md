# Remote bundle rebase plan

Goal: rebase PR #54 onto batch 6 without weakening fixture identity,
clean acceptance, archive integrity or run-bound provenance.

Architecture: keep #43's v2 manifests, controlled source closure and fresh
validation receipts; admit a shared archive once into private run storage,
then verify that capture against the checkout before recording provenance.
Receipt annotation must preserve input-validation evidence atomically.

Stack: Rust xtask, Git, foreground portable tests; cloudmac scratch worktree
under the shared host lease. No Docker or full acceptance gates.

Review focus: both receipt fields survive, archive verification validates
policy and scoped inputs before provenance, gzip reaches EOF, attach reads
only run-specific evidence, ancestor symlinks remain rejected.

- [x] Inspect main and replay the three branch commits, union Verify CLI
  receipt/bundle options and retain both atomic_file and ci_scaler modules.
- [x] Run new cross-contract rejection tests red on the rebased code.
- [x] Apply checkout-aware archive verification and atomic verification
  receipts; preserve both evidence fields in annotation tests.
- [x] Run the complete xtask suite (including #43 and all prior regressions),
  xtask clippy, just clippy and fmt-check on Linux.
- [x] Transfer the exact source snapshot to cloudmac; run the full VM-free
  xtask suite with the real system TMPDIR under just lease carrick; remove
  only this task's scratch worktree and transfer bundle.
- [ ] Commit conflict-resolution evidence, run clean-tree lint-domains,
  force-with-lease push and update PR #54 plus director review-ready.

The plan is checked against the user's explicit implementation and push
instructions. Existing red-first evidence remains in the test-results file;
new boundary regressions need fresh failing controls before their fixes.
