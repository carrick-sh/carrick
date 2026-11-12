# Follow-up: generalise the exclusion-time hook to settle owed returns (from #1480)

#1480 landed the neutral `ReturnSettlement` transaction
(`carrick_hal::return_settlement::settle_owed_returns`) and moved the host root onto it.
It did **not** generalise `CowGrantSettlement` (`carrick-core-abi/src/mm/cow_pool.rs:493`,
run by `settle_excluded`, `carrick-kernel/src/kernel/mm_occupancy.rs:848`) into
"COW completions, then owed returns".

Why it was left out: no carrier has a ring-owned physical retirement
(`OwedReturnRetirement` impl) yet. Without one, the hook's returns step would be an
empty extension point. #1482's must-include #1 already moves settlement into the
exclusion primitive (`try_exclude_editor` sites settle nothing today), so the hook
change belongs with the first real implementer.

Acceptance (fold into #1482):
- One hook entry runs COW, then returns, for every exclusion. The returns step
  takes the MM's `SettlementLock` (blocking) and calls `settle_owed_returns`.
- HVF and CPL0 `OwedReturnRetirement` impls: walk retired leaves from the
  authenticated `El1MmHandle` root, then the inventory reserve, leaf clear with an
  undo log, the stage-2 release, and one infallible inventory apply.
- Witness: an exclusion that settles COW before returns.
