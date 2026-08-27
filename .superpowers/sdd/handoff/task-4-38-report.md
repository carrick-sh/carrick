# Task 4.38 report — HVPatch madvise fork policy

Date: 2026-08-26

## Outcome

The original monolithic Antigravity candidate remains rejected. Its replacement
Swing A semantic-MM transaction is accepted and integrated as `16ebcefc`
(`feat(runtime): prepare exact fork MM projection`) after two review/correction
cycles and independent semantic plus rollback GO reviews. Physical leaf
application and signed evidence remain deliberately unimplemented until Swings
B and C, so `ltp-madvise10` remains open and this checkpoint earns no frozen
ledger credit.

The frozen ledger remains 23/156 focused-closed, 133 remaining, or 1,994 of
2,127 accepted suites overall (93.75%).

## Delegation and current state

- Antigravity worker: `madvise-fork-policy`
- Conversation: `b77edcf4-3822-4afa-a445-b8b107645de5`
- Run: `core-roadmap-t438`
- Isolated branch: `agy/madvise-fork-t438`
- Isolated worktree: `.worktrees/madvise-fork-t438`
- Base: `ae76f6d19785d10e1705bca1d549d51b28026f99`
- Candidate state: dirty and uncommitted; rejected as a monolithic slice.

The worker reported completion after the prior correction round. Codex read the
actual diff rather than accepting that report. The same architectural failures
survived both rounds. Codex then authored
`docs/superpowers/plans/2026-08-26-hvpatch-madvise-fork-policy-final-correction.md`
in the worker worktree and sent it to the same conversation as the controlling
third-round contract. That round completed with about 2,000 added lines and
claimed green targeted tests, a Carrick/Docker probe, and DTrace.

Codex reran `CARGO_BUILD_RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p
carrick-runtime --lib prepared_fork_mm`: 3 passed, 0 failed. The passing test
does not close the slice. Independent semantic, physical, and probe/trace
reviews all returned no-go, including a retained trace that says
`status=ok ... exit_code=1`.

## Useful facts retained

- Current Linux `MADV_DONTFORK` sets `VM_DONTCOPY` without the `VM_SPECIAL`
  rejection used by `MADV_DOFORK`.
- `MADV_WIPEONFORK` rejects file-backed and shared mappings.
- `MADV_KEEPONFORK` rejects `VM_DROPPABLE`.
- The candidate corrected `brk` semantic-VMA growth/trimming and changed
  cross-VMA `mremap` to fail with `EFAULT`.
- The candidate also preserved PTE attributes for WIPE leaves and improved
  several probe cases. Those improvements are not safely separable from the
  incomplete MM/physical-authority transaction and are not accepted.

## Final-round blocking findings

1. **Semantic projection still fails open.** Missing projection entries default
   to Preserve, validation errors are discarded, copied prepare can roll the
   parent back twice, and MM exclusion ends before complete child dispatcher
   construction. Exact authority identity, move-only preparation, real parent
   `MmId`, exact `CLONE_VM` authority, droppable state, and heap projection are
   useful but insufficient improvements.
2. **Partial `DONTFORK` physical coverage is not authoritative.** Lookup checks
   only a starting leaf or bypasses coverage; translated IPA is not used to
   derive compound membership; inventory, alias, overlay, COW, retirement, and
   grandchild paths widen holes back to full compounds.
3. **Fresh WIPE ownership is not transactional.** Production registers a
   nonzero owner generation, but no generation-exact RAII receipt survives to
   rollback. Reusable generation-zero publication still passes and fresh moved
   Preserve leaves keep stale COW authority.
6. **The probe is not fail-closed.** It contains unchecked `fork` failures,
   blocking `read`/`waitpid` paths, a process-wide alarm that truncates output,
   an allocator-dependent `mremap` assertion, and an exec check whose
   `MAP_FIXED` remap can erase the stale policy it claims to test.
7. **The DTrace receipt false-passes.** It treats Darwin `proc:::exit` `arg0`
   as an exit status, does not authenticate a real zero target status or typed
   Omit/Wipe transformation, and retained `status=ok` with `exit_code=1`.
8. **No current acceptance receipt exists.** The retained baseline predates the
   current probe contract; the all-true oracle file is Docker data, not a green
   Carrick result. There is no current red-first/current-green byte diff or
   corrected fail-closed trace.

## Required next decomposition

- Swing A: **accepted at `16ebcefc`** — semantic MM identity, total validated
  projection, type-bound mode and exact parent/child MM identities, one-owner
  rollback, canonical heap/droppable/mremap policy, and exclusion through
  complete installation.
- Swing B: translation-derived physical leaf masks propagated through mapping,
  inventory, alias, lookup, COW, retirement, and grandchild projection, plus a
  generation-exact WIPE rollback receipt and fail-closed generation-zero rules.
- Swing C: bounded probe mechanics and missing semantic cases, typed
  Preserve/Zero/Omit transaction receipts, corrected real exit-status DTrace,
  probe denominator repair, and retained native-arm64 Docker provenance.

Each swing must be independently red-first and reviewable. Codex owns their
interfaces and final signed integration; do not resume by polishing the whole
dirty candidate in place.

## Accepted Swing A evidence

- Exact parent/child `MmId`, authority `Arc`, VMA revision, Share/Copy mode,
  child authority, and total `Preserve`/`Zero`/`Omit` projection are retained in
  a move-only preparation and revalidated under exclusion through complete
  child dispatcher construction.
- Heap growth/shrink, `MAP_DROPPABLE`, and split `mremap` move/grow/shrink now
  publish canonical semantic VMA state. Newly grown heap pages use default
  RW/private-anonymous/default-fork/non-droppable semantics rather than
  inheriting a modified tail.
- Backend preparation rejects malformed projection and inventory/MM-mode or
  generation mismatch before mutation. Every post-prepare unwind attempts both
  child abort and copied-parent rollback before fail-stop; prepare errors remain
  backend-owned and stale semantic install rolls back exactly once.
- Fresh Codex verification on the final tree: `cargo fmt --all -- --check`,
  `git diff --check`, `cargo clippy -p carrick-runtime --all-targets -- -D
  warnings`, and `CARGO_BUILD_RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p
  carrick-runtime --lib` all exited zero; the serial runtime suite passed
  **1,850/1,850**.
- No guest, Docker oracle, signed build, DTrace, or conformance gate was claimed
  for Swing A. Those belong to physical Swing B and evidence Swing C.

## Explicit non-completion at this checkpoint

- `ltp-madvise10` remains open.
- The full 2,127-suite closure gate remains open.
- Go, CPython, Node, LTP aggregate, and cold go-build performance gates remain
  open.
- No push occurred.
