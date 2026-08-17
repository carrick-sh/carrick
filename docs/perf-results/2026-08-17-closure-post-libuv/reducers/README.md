# Reducers

Deterministic reproducers for crashes found by the 2026-08-17 closure run.
Each replaces a multi-minute ecosystem suite with a few seconds.

## `alias-churn-fatal.py`

Reproduces the FATAL that kills `cpython-multiprocessing_spawn`:

```
carrick: FATAL: apply HVPatch alias retirement inventory:
  mapping MappingId(1847) is not live
```

Run it under the canonical lane:

```sh
carrick run --raw --fs host -v <dir>:/probe \
  --entrypoint /usr/bin/python3 \
  localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 \
  /probe/alias-churn-fatal.py 800
```

It performs 800 cycles of `mmap(MAP_SHARED, fd, 4096)` + `munmap` on a
`/dev/shm` temp file — the shape `page_table.rs:959-963` already names
("CPython multiprocessing maps+unmaps 400+ SemLock/Pool shm files").

**It aborts at the same `MappingId(1847)` on every run**, around cycle 400-500,
so this is a deterministic state bug and NOT a race — which also means a fix
can be proven red-first against it in seconds.

Where it lands:

- abort site: `crates/carrick-vmm-hvf/src/trap.rs:9669`, on
  `authority.apply(reservation.commit(()))`;
- invariant: `crates/carrick-runtime/src/kernel/frame_inventory.rs:518,527`
  (`live_mapping_mut` -> `FrameInventoryError::NonliveMapping`), which fails
  when the mapping is absent from the overlay or is not `MappingState::Published`;
- the retirement shape is computed under `self.frame_inventory.lock()`
  (`trap.rs:9639-9641`) and the lock is released before `apply`.

### Narrowed: the mapping is ABSENT, not unpublished

`NonliveMapping` used to cover two different situations — the mapping is not in
the overlay at all, versus it exists but is still `Prepared`. They are now
separate errors (`NonliveMapping` and `MappingNotPublished`), and the reducer
still reports **"is not live"**. So `MappingId(1847)` is **gone from the
inventory's mapping table** while the retirement shape still names it. This is
a stale/double-retire, NOT a mid-transaction race.

The likely mechanism, and where to look next: the retirement shape is built by
scanning `inventory.extents` for entries whose stage-2 lease matches
(`trap.rs:5099-5104`), and **`extents` is keyed by `(gpa, length)` — a stage-2
address pair, not by `MappingId`**. An extent therefore has no lifetime tie to
the mapping it names: it can outlive a retired mapping, and a later alias that
lands on the same `(gpa, length)` can collide with it. Relevant sites:
`trap.rs:5189` and `:5304` (remove), `:5386` (a contains_key guard) and `:5484`
(insert).

Ordering matters here and rules out the obvious candidate: the sequence is
shape -> reserve -> stage -> `unregister_alias` -> **apply (aborts)** ->
`commit_inventory_lease_retirement`. The commit is the only place that removes
`extents` entries (`trap.rs:5189`), and it runs AFTER the apply — so the stale
extent was left behind by an EARLIER cycle, not by this one.

Two structural facts worth having before the next attempt:

- A COW split (`commit_cow_inventory_split`, `trap.rs:5300`) gives each
  fragment its own `MappingId` but leaves every fragment sharing the ORIGINAL
  `stage2_base`/`stage2_length`. So one stage-2 lease legitimately fans out to
  many extents, and a lease retirement selects all of them at once
  (`trap.rs:5099-5104`). Duplicate mapping ids are therefore NOT the cause.
- `inventory.extents` and the kernel frame-inventory authority are two records
  of the same fact, and only the alias-retirement path keeps them in step.

So the leading hypothesis is that some OTHER path retires a mapping in the
authority — a low-arena `munmap`, a fork COW retirement, an exec teardown —
without removing the matching `extents` entry, and the alias retirement later
trips over the orphan. Confirm by logging every authority mapping-retirement
with its origin, then diffing that set against `extents` at the abort.

So the question to answer first is: which path removes a mapping from the
authority WITHOUT removing its `extents` entry?

Note the sibling crash is DIFFERENT and this reducer does not produce it:
`cpython-multiprocessing_fork` and `cpython-concurrent_futures` die with
`map hvpatch child VA ...: OutOfTables`. A plain 800-fork storm
(`fork` + `_exit` + `waitpid`) completes cleanly, so that one is not a simple
fork-path table leak.
