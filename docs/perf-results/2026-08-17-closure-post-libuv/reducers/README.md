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


## `mremap-grow-shapes.c` + `mremap01-oracle-shape.bt` — mremap grow

`mremap-grow-shapes.c` runs six one-page grows and prints one line each, so a
carrick run and a Docker run diff directly. Build it static (`gcc -static -O0`)
so the same binary runs under both. Two things it will teach you the hard way if
you change it:

- **Unbuffer stdout.** The first version block-buffered, the shared-anon case
  took a SIGBUS, and the whole transcript was discarded — it looked like the
  program had not run at all. `setvbuf(stdout, NULL, _IONBF, 0)` is load-bearing.
- **Do not touch the grown tail of a `MAP_SHARED|MAP_ANONYMOUS` mapping.** Real
  Linux keeps the original tmpfs object at its original size across the grow, so
  the new pages have no backing and the access is a genuine SIGBUS. That is
  correct Linux behaviour, not a bug in either side, and it is why the harness
  takes a `touch_tail` argument.

Measured (real Linux 6.12, docker gcc:latest, arm64, 2026-08-17) vs carrick:

| shape | Linux | carrick before | carrick after |
|---|---|---|---|
| priv-anon grow MAYMOVE | ok (moved) | ok | ok |
| priv-anon grow noflag | ENOMEM | ok | ok |
| shared-anon grow MAYMOVE | ok (moved) | **ENOMEM** | **ok** |
| shared-anon grow noflag | ENOMEM | ENOMEM | ENOMEM |
| shared-file grow MAYMOVE | ok (moved) | **ENOMEM** | **ENOMEM** |
| priv-file grow MAYMOVE | ok (moved) | ok | ok |

`moved` is not an ABI guarantee — Linux happens to relocate and carrick grows in
place — so the reducer prints it for information rather than as a verdict.

### `ltp-mremap01` is the shared-FILE row, not the shared-anon one

Do not assume the anon fix closes it. `mremap01-oracle-shape.bt` captures the
suite's actual syscall shape from inside the Docker oracle (the sanctioned
method — never guest `strace`), and it is unambiguous:

```
mmap  addr=0 len=3e8000 prot=2 flags=1 fd=3 off=0     # MAP_SHARED, a FILE
mremap old=... oldsz=3e8000 newsz=7d0000 flags=1      # MREMAP_MAYMOVE
mremap -> ffff9fa00000                                # moved
munmap addr=ffff9fa00000 len=7d0000
```

So mremap01 needs the shared-FILE grow, which is a different mechanism: carrick
backs `MAP_SHARED` file mappings with a LIVE host alias of the file's page cache
at a fresh high VA, not with aperture bytes. Growing one means re-establishing
the alias at the larger size (re-mmapping the same fd preserves sharing exactly,
unlike a byte copy), and the request grows PAST the file's EOF — 0x3e8000 to
0x7d0000 — so the tail beyond EOF has to become a `bus_fault_ranges` entry, the
same treatment `mmap` already gives an over-EOF `MAP_SHARED` file mapping.

Note also that `carrick trace` was NOT able to answer this: its syscall stream
carries the loader's mmaps and then stops at `execve-loaded`, showing nothing
the test itself issued. Reach for the oracle-side bpftrace rather than trying to
make the tracer follow the guest's self-re-exec.
