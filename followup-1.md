# Follow-up: a full owed-return table whose holders are all retiring has no wait authority

Found while fixing #2250 P0-1 (Part of #1482).

## What happens

The full-table drain (`carrick_hal::return_settlement::drain_owed_return_table`)
now answers the oldest refusing holder's wait authority (MM, release cause,
revision) when no slot could be freed, and the ring parks on that release.

When every remaining holder has **no live notification source** (its space
entry was retired: an MM between `exit_group`'s root retirement and its
carrier release receipt), there is no source to enrol on. The drain returns
`DrainOutcome::Retiring` and both carriers answer `Settled`, so the caller
reruns once. The x86 carrier counts it
(`ReturnSettlementCounters::drain_retiring`).

On x86 CPL0 the retired child's release (`release_retired_child` ->
`release_child_mm`) frees the slots in the same carrier-serialized operation
that unpublishes the entry, so the window is one ring exit path long and
bounded. On HVF the same holds for `service_terminal_operation`'s child retire,
but no witness proves the window is closed on either carrier.

## Why it matters

If a retiring MM's release ever lags (a failed `release_child_mm` is fatal on
x86 today, but HVF retries), the caller would ring repeatedly while the slots
stay owed: repeated crossings, the shape P0-1 forbids.

## Proposed fix

Give a whole-MM release receipt a wait authority: publish a table-level (or
caller-MM `Reservations`) release when `RetiredReturns::settle_whole_mm`
frees slots, and have the drain answer `Retiring` with that source so the
caller enrols and probes once. Witness: a holder whose release is delayed by
a fixture parks the waiter with exactly one doorbell, and the release wakes it.
