# #1482 remainder after #2250

#2250 lands slice 3's mechanism on both ISAs. Still open for #1482 to close:
1. Run on a Mac: signed `el1_memory_first_touch_stays_in_guest` at three
   scales (`child_ok=true`, `root_unavailable == 0`) plus the el1_sched
   rows. The HVF code is only cross-checked.
2. Witnesses: `ForkLoanPending` (the final wake comes after the loan
   settles and the rerun is served), `exit_group` of a holder mid-drain, a
   fork racing a drain, the nine-MM full-table case, and the round-4
   two-live-process cases.
3. The drain should skip holders whose fork fence (`PtQuiesce`) is raised.
   When it frees no slot (busy holders, or retired MMs' slots awaiting their
   release receipts), the refuser should enrol on that holder's
   `Gate`/`Editor` release; today its rerun rings again.
4. x86: revoke a settled extent's backing slot once its `alias_count`
   reaches 0, instead of keeping it admitted until the MM retires.
5. The carrick-kernel exclusions of the host-served root still settle only
   COW in the hook. The root's returns settle at its host venue's
   boundaries, as before.
