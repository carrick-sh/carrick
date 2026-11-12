# Follow-up: join whole-MM return teardown with the inventory release receipt (from #1480)

#1480 typed teardown acknowledgement: `retire_final` frees its owed slots only
through `ReturnSettlement::whole_mm()`, which advances each slot's epoch. The
`ReturnSettlement` type is private to `carrick-core/src/mm/reservation/root.rs`.

Not yet done (#1369 round 2, item 5): mint the whole-MM settlement from
`release_child_mm`'s result (`carrick-hal/src/fork_stock.rs:646`), so the slots are
acknowledged only after the MM's frame inventory has retired. Today the carrier
retires the root, which frees the slots, before `release_child_mm` runs. That order
is safe, because the frames stay in the inventory until `retire_mm`, but the type
does not record the release.

Acceptance: `retire_final` returns a linear retired-journal token, and the carrier
acknowledges it together with the `MmReleaseReceipt`. Covered by a two-root witness
where the slot's next owner is unaffected by a late acknowledgement.
