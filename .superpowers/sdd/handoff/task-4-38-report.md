# Task 4.38 report — HVPatch madvise fork policy

Date: 2026-08-26

## Outcome

Not accepted after two Antigravity implementation rounds and three independent
Codex-side reviews. Per the owner's explicit direction, a third and final
context-rich correction round is now in progress before Codex decides whether
to finish remaining bounded corrections locally or quarantine the slice. No
source from the dirty candidate is integrated yet.

The frozen ledger remains 23/156 focused-closed, 133 remaining, or 1,994 of
2,127 accepted suites overall (93.75%).

## Delegation and current state

- Antigravity worker: `madvise-fork-policy`
- Conversation: `b77edcf4-3822-4afa-a445-b8b107645de5`
- Run: `core-roadmap-t438`
- Isolated branch: `agy/madvise-fork-t438`
- Isolated worktree: `.worktrees/madvise-fork-t438`
- Base: `ae76f6d19785d10e1705bca1d549d51b28026f99`
- Candidate state: dirty and uncommitted; final correction in progress.

The worker reported completion after the prior correction round. Codex read the
actual diff rather than accepting that report. The same architectural failures
survived both rounds. Codex then authored
`docs/superpowers/plans/2026-08-26-hvpatch-madvise-fork-policy-final-correction.md`
in the worker worktree and sent it to the same conversation as the controlling
third-round contract.

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

## Findings the final correction must eliminate

1. **Prepared MM identity is fail-open.** `PreparedDispatchMmFork` records a
   numeric revision but not the exact parent `DispatchMmAuthority` identity.
   Preparation releases its guard and installation accepts a replacement
   authority with the same revision. `CLONE_VM` also creates a new authority
   wrapper instead of cloning the exact authority `Arc`.
2. **Partial `DONTFORK` has no physical live mask.** The child stage-1 PTE is
   invalidated, but compound-wide mapping and inventory descriptors remain
   authoritative for all 16 KiB. A later child-to-grandchild fork can
   rediscover or reconstruct an omitted 4 KiB leaf.
3. **Fresh WIPE backing has no production owner generation.** The task-only
   projection carries generation zero without registering a live global-frame
   owner, while the inherited-inventory path treats zero as an authentication
   bypass. Reused IPA authority can therefore become stale.
4. **Child heap projections disagree.** Semantic metadata removes a partial
   `DONTFORK` heap range, but VMA/core-map projection reconstructs the full heap
   from `brk_current`, publishing omitted bytes as mapped.
5. **`MAP_DROPPABLE` state disappears.** ABI decode accepts the flag, but the
   semantic VMA stores no droppable capability, so `MADV_KEEPONFORK` cannot
   return Linux's required `EINVAL`.
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

## Required architecture for the active correction

- Bind prepared state to the exact parent MM authority object and reject any
  authority replacement, not just revision drift.
- Represent 4 KiB live/omit/wipe state in the physical mapping and inventory
  authority consumed by alias, COW, fork, and grandchild projection.
- Register and authenticate a fresh owner generation before publishing every
  WIPE replacement frame.
- Make semantic VMA, heap/core-map, stage-1, stage-2, and inventory publication
  one rollback-capable transaction.
- Preserve `VM_DROPPABLE` as typed VMA state.
- Replace the probe and trace with bounded deterministic contracts that print
  false on every failure and reject nonzero target status, missing events,
  drops, or untyped fork transformation.

## Explicit non-completion at this checkpoint

- `ltp-madvise10` remains open.
- The full 2,127-suite closure gate remains open.
- Go, CPython, Node, LTP aggregate, and cold go-build performance gates remain
  open.
- No push occurred.
