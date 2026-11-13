# Follow-up: no KVM witness of two processes waiting on one full owed-return table

Found while fixing #2250 P0-1 (Part of #1482).

The x86 CPL0 KVM witness `production_full_owed_return_table_parks_on_its_busy_holder_until_release`
covers one waiting process (the root). A second waiting process cannot be
added on KVM today:

- an MM owns at most `OWED_RETURNS_PER_MM` = 8 slots of the 64-slot table,
  so filling it takes 8 holder MMs that are not waiting (a waiter's own
  doorbell settles its own slots first);
- the root plus 8 holders leaves no room for a second waiting child: the
  x86 carrier admits `FORK_LIFECYCLE_SLOTS` = 8 fork children
  (`crates/carrick-x86-cpl0-host/src/cpl0_boot.rs:136`). A 9th `fork`
  fails (measured: the fixture's step 2, exit 2).

Two live MMs parked on one holder's real release queue are covered at the
park level (`carrick-core/tests/entry_completion.rs`, the holder-release
two-waiter test), not on the production doorbell.

Proposed: once the fork lifecycle stock grows (or the table and per-MM cap
become configurable for fixtures), add `-DWAITERS=2` to
`native_owed_return_table_full.S` (a second child forked after the ready
handshake retires one page) and assert both waiters ring once and park.
