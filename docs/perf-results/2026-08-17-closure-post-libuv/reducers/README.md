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

Two candidate causes, both consistent with the determinism: the same mapping is
retired twice, or a `MappingId` is reused while an earlier retirement still
references it. Distinguish them by logging the entry's `MappingState` and
generation at `frame_inventory.rs:527` before the error is returned.

Note the sibling crash is DIFFERENT and this reducer does not produce it:
`cpython-multiprocessing_fork` and `cpython-concurrent_futures` die with
`map hvpatch child VA ...: OutOfTables`. A plain 800-fork storm
(`fork` + `_exit` + `waitpid`) completes cleanly, so that one is not a simple
fork-path table leak.
