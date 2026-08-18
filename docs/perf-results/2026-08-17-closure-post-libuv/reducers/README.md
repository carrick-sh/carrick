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

**RESOLVED.** The answer was neither of the leading hypotheses. Two distinct
bugs sat on top of each other, and the abort was only the outer one.

Inode recycling was refuted cheaply first: a variant that keeps every temp file
OPEN (so the host never reuses an inode, and every mapping gets a distinct
`SharedFile { device, inode, .. }` backing identity) aborts at the SAME
`MappingId`. Varying the mapping size 4 KiB -> 16 KiB also aborts at the same
id, while a `MAP_PRIVATE` variant completes cleanly — so the trigger was
count-driven and MAP_SHARED-specific, not data-driven.

What settled it was reading the inventory's own `tracing` output
(`RUST_LOG=carrick_runtime::kernel::frame_inventory=trace`) alongside two new
trace points at the ends of the alias transaction. Every healthy cycle reads
`stage(N) -> take -> prepare(N) -> unmap(N)`. The failing one reads
`stage(N) -> unmap(N)` — no `take`, no `prepare`. So the extent had been staged
into the backend ledger while the authority never learned the mapping existed.

1. **The abort.** `map_host_alias_with_sharing` stages the extent, then installs
   the stage-1 mapping. When that install FAILS its cleanup called
   `unmap_alias_range` — the RETIREMENT path — which walks the extents covering
   the VA's stage-2 lease and stages an `UnmapMapping` for each. It therefore
   picked up the extent staged moments earlier and asked the authority to retire
   a mapping it had never seen, aborting the whole carrier for one process's
   failed mmap. Fixed by discarding the staging BEFORE the teardown.

2. **Why the install failed at all:** `stage-1 page-table pool exhausted
   (in_use=438 free=0 capacity=440 reclaim_disabled=true engines=3 pmr=false)`.
   That is a page-table leak, one table per `mmap(MAP_SHARED, fd)`, and the
   reclaim that should prevent it was disabled by a POPULATION mismatch — see
   below.

### The populations bug behind the leak

Reclaiming an emptied stage-1 sub-table is only safe when the edit is exclusive,
so the engine gated it on `Arc::strong_count(&page_tables) > 1`. That counts
live engine HANDLES. The runtime, meanwhile, decides whether to take the
Pause-Modify-Resume barrier from `has_peer_guest_executor()` — threads that can
execute guest code, parked siblings included.

Those two populations disagree, and the diagnostic above shows exactly how:
`engines=3` with `pmr=false`. Three live engine handles, no peer able to execute
guest code. The runtime correctly skipped the pause because the edit was already
exclusive; the engine read its own proxy, concluded "shared", and never
reclaimed. This is the `docs/identity-and-scope-domains.md` populations hazard
in the wild — two `usize`s that mean different things.

The fix publishes the runtime's answer instead of approximating it:
`carrick_hal::stage1_exclusive` is a thread-local marker the runtime raises for
any stage-1-editing syscall (both because it holds the pause AND because there
is no peer to be exclusive against), and the engine reads it.

Result: the 1,200-cycle reducer completes, 5,000 cycles complete, and
`cpython-multiprocessing_spawn` goes from an 88-assertion crash to running all
397 tests with 3 of its 4 test files passing.

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

### Correction: mremap01's file is SPARSE, and the fix is a re-alias

The syscall capture above is real but INCOMPLETE, and reading it literally sent
this investigation down a blind alley for several rounds. It shows two
`write(fd, ..., 1)` calls and no `ftruncate`, which reads as "a 1-byte file
mapped 0x3e8000 long" — i.e. a mapping that is almost entirely past EOF. Two
reproducers were built on that reading and both behaved correctly under carrick
while the suite kept failing.

What the capture omits is `lseek`. LTP builds the file SPARSELY — seek to
`size-1`, write one byte — so the truth is:

- at `mmap` time the file is already 0x3e8000 long, the mapping fits inside it,
  and carrick maps it as a LIVE alias (`addr=0x10000000000`), not as an arena or
  aperture snapshot;
- the test then EXTENDS the file to 0x7d0001 the same way;
- the `mremap` to 0x7d0000 is therefore entirely INSIDE the file.

So nothing about this suite involves SIGBUS. The fix is to re-establish the live
alias over the same descriptor at the new length — re-mmapping the same fd
aliases the same page cache, so sharing stays exact where a byte copy would
silently break it.

**Trace file setup, not just the operation under test.** Had the first capture
included `lseek`/`fstat`, the shape would have been unambiguous immediately.

### What actually settled it: a gated diagnostic, not a reproducer

Four reproducers all passed while the suite failed. What ended it was extending
the existing `CARRICK_FAULT_DEBUG` hatch with an `mremap GROW` line reporting
every discriminant the grow plans key on:

```
[FAULTDBG] mremap GROW addr=0x10000000000 old=0x3e8000 new=0x7d0000 flags=0x1
  sharing=Shared in_arena=false aperture=None anon_plan=false
  arena_past_eof=None alias_plan=None aperture_plan=None
  alias_file_extent=Some((8192001, 0)) path=".../mremapfile"
```

`alias_file_extent=Some((8192001, 0))` is the whole answer: the file is 8 MiB,
not 1 byte. The line is kept — it is behind an env hatch that already existed,
and it is the instrument that answers "why did this grow refuse?" in one run.

**`CARRICK_FAULT_DEBUG` is read from the HOST environment**, by the dispatcher
in the carrick process — passing it with `-e` into the guest sets it for the
guest and produces nothing. That cost a round too.

### Two traps in this handler that present as a hang

- **Do not call `mmap_fault_is_sigbus` from `mremap`.** It opens its own
  host-alias dispatch guard and `mremap` already holds one, so the guest wedges
  in the syscall and the run dies on its timeout with no output past the `mmap`.
  Read `mem.bus_fault_ranges` directly instead.
- **Do not `protect_range` arena VA above the bump pointer.** Publishing a
  PROT_NONE mapping over never-established backing hangs the same way. A tail
  that is meant to fault needs no page-table work at all — reserving the VA is
  the whole job.

### The aperture's SharedFile backing is dead in production

Worth knowing before writing code against it: `BackingObject::SharedFile` is
constructed ONLY in tests. The live-alias model replaced the old
aperture-snapshot-plus-msync-writeback model, so no production path creates one
today, and a grow plan keyed on `alloc.backing.shared_file_parts()` can never
fire. One was written here and then deleted rather than left in as defensive
dead code.

### Separate unfixed bug found on the way: MAP_SHARED past EOF loses writes

A `MAP_SHARED` file mapping that runs PAST its file's EOF becomes an arena
snapshot under carrick, and that snapshot is never written back. Store to
offset 0, `munmap`, re-read the file:

| | byte 0 |
|---|---|
| Docker (real Linux) | `Z` (the store) |
| carrick | `a` (the original) |

`reducers/mremap-eof-shape.c` with `NOREMAP=1` reproduces it in about a second.
This is a silent data-loss divergence, it is INDEPENDENT of `mremap`, and it is
NOT fixed here.


## The multiprocessing fork/forkserver SIGSEGV — reduced, NOT yet fixed

The former 300 s hang is gone (post-`10c62b8cb` the suite completes test files),
leaving two separate defects:

1. **`test_manager` takes 3m32s** — unmeasured, probably a pathological-ratio
   correctness signal of its own.
2. **A deterministic child SIGSEGV**, reduced to a 2.5 s two-test pair:

```
python3 -m unittest test.test_multiprocessing_fork.test_misc.TestStartMethod.test_context \
                    test.test_multiprocessing_fork.test_misc.TestStartMethod.test_set_get
```

carrick: `test_set_get` ERRORs with EOFError and
`Dangling processes: {<Process ... exitcode=-SIGSEGV>}`. Docker: OK. Either
test alone passes on carrick — the pair is required, and it is 2/2
deterministic.

### The fault signature (from `CARRICK_FAULT_DEBUG=1`, host env)

Two crashes, IDENTICAL machine state, different Python paths:

```
esr=0x92000007 elr=0x6000179108 far=0x18 x0=0x0 insn=ldr x1,[x0,#0x18]
```

With `PYTHONFAULTHANDLER=1` passed into the guest (it propagates into
forkserver children via the environment where `-X faulthandler` does not):

- crash 1: a forkserver-forked child inside `_compile_bytecode` (marshal)
  while importing `logging` from `spawn.prepare` (`forkserver.py:315
  _serve_one`);
- crash 2: `Garbage-collecting / <no Python frame>`.

Same PC, same NULL+0x18 load, one crash in marshal and one in GC: some earlier
load returned 0 from memory that should have held a pointer. That is the shape
of a stale or zeroed page in a FORKED child (HVPatch frame-COW territory), but
that attribution is a HYPOTHESIS — the label "COW bug" has been wrong in this
project before, and nothing here yet ties the zero to a specific page
transition.

### Dead ends already paid for (do not repeat)

- Five standalone replicas of the pair's shape — plain contexts, simplex pipes,
  `set_start_method(force=True)`, preload changes, repeated children from one
  server — ALL pass under carrick. The unittest environment itself is a
  necessary ingredient; stop trying to remove it.
- `carrick trace --profile hvpatch-frame-cow` on the reducer returns an EMPTY
  capture (`receipt needs exactly one header and summary, got {}`). Zero events
  means the probes did not fire on this shape, not that no COW happened; the
  validator correctly refuses it. Do not cite it either way.
- A guest `ulimit -c unlimited` produced no core file in the mounted cwd.
  Whether carrick's guest core-dump path covers a forked CHILD's SIGSEGV is
  unverified; `carrick debug lldb-run` / attaching the carrier is the
  documented next instrument.

### Core-based debugging DOES work — the earlier "no core" was retrieval error

`ulimit -c unlimited` in the guest works today; the earlier attempt looked in
the wrong place. `publish_core_atomic` (`dispatch/mod.rs`) writes `<cwd>/core`
through the OVERLAY backend, so a bind-mounted cwd is bypassed and `--rm`
discards the overlay. The working recipe:

```sh
carrick run --rm --raw --fs host -v host-dir:/out IMAGE /bin/sh -c \
  'cd /tmp && ulimit -c unlimited && <crashing thing>; cp /tmp/core /out/'
```

crash in an OVERLAY cwd, then copy the core out inside the same guest run.
Note the guard: no core if `!dumpable || rlimit_core == 0`, and children
inherit cwd from the forkserver server, so `cd` before starting anything.

### What the core says (child SIGSEGV, 20 MB core in hand)

- `carrick debug core` validates it: pid 6, signal 11, fault_address 0x18,
  pc `0x6000179108`.
- NT_FILE places the PC in `usr/local/lib/libpython3.12.so.1.0` at file offset
  `0x169108`. **Symbolizing that took three attempts, and the first two were
  wrong in instructive ways.** (1) A libc attribution joined the PC against
  another process's mapping base — NT_FILE from the core is the only
  trustworthy join. (2) `PyType_GenericAlloc+0x18` came from symbolizing
  against the WRONG image's libpython: the layer cache holds THREE
  `libpython3.12.so.1.0` copies, and a glob-and-head-1 picked python:3.12-slim's.
  Pick the file by matching sampled text pages against the core
  (`e1aefb8a…`, the 28 MB unstripped cpython-test build, matches 5/5).
  Symbolized wrongly, the same bytes even "disassembled" into a plausible
  story — a page-content match is the only proof of file identity.
- Against the RIGHT file: guest text is PRISTINE (0 of 0x47a pages differ),
  and the crash is **`unicodekeys_lookup_unicode+0x68`** — CPython's
  unicode-key dict probe reading `me_key->hash` (`ldr x1,[x0,#0x18]`; 0x18 is
  the hash field of PyASCIIObject) with **`me_key == NULL`**. A NULL me_key
  reached through a VALID index-table slot breaks a dict invariant: the keys
  object's INDEX page says the entry is live, its ENTRIES page reads NULL.
  `x22=0x3fff` (a 16K-slot table) on an interning path makes the corrupted
  object almost certainly the INTERNED-STRINGS dict — which both crash paths
  share (marshal interns every unmarshalled name; GC walks dicts).
- Sharpened hypothesis, still unproven: ONE heap page of the interned dict's
  keys object reads stale/zeroed in the forkserver child while its neighbors
  read fine — a per-page fork-inheritance inconsistency, not text, not
  file-backed data, not library bss.
- **Refuted along the way: the zeroed-library-page hypothesis.** PyUnicode_Type, PyDict_Type,
  PyLong_Type, PyType_Type, PyBaseObject_Type read INTACT from the core
  (immortal refcounts, ob_type all pointing at PyType_Type), and the crash
  registers even hold valid pointers to two of them beside x0=0. libpython's
  data pages are fine in the child; whatever read as NULL lives in ANONYMOUS
  (heap) memory.
- The fp-walk backtrace symbolized against dynamic symbols is approximate
  (static functions dominate at these offsets) and the crashing frame's x30
  does not line up with a call instruction — likely a tail-call chain; do not
  build on those frame names.

### PROVEN from the core: one 16 KiB granule of the interned dict is ZEROED

Register decoding against the disassembly (x20 = dict entries base, x19 = probe
index, x22 = mask) identified the dict — its entry[0] has `me_key == me_value`,
the interning signature — and a full audit of its 10,167 entries found the
smoking gun:

```
dk@0x60010c1010  log2_size=14 kind=unicode  nentries=10167
NULL me_key run: entries 765..1788  =  VA [0x60010cc000, 0x60010d0000)
```

**Exactly one 16 KiB host granule, page-aligned at both ends, 1,024 consecutive
zeroed entries in the MIDDLE of the array**, with the crash's probe index
inside it. Entries before and after read fine; the handful of scattered
single-entry NULLs elsewhere are ordinary dict deletions. This is no longer a
hypothesis: carrick loses the content of one anonymous 16 KiB page across the
fork that creates the worker, deterministically.

Two negative probes (both committed beside this file, both pass under carrick
AND Docker — the corruption needs more of the real topology):

- `double-fork-page-probe.py` — fork, child dirties 8 MiB anon, child forks,
  grandchild verifies. Clean.
- `mremap-grow-fork-probe.py` — glibc realloc chain (mremap-grow shape, which
  the real workload's own FAULTDBG shows firing), dirty, fork, verify. Clean.

### ROOT CAUSE (found via CARRICK_FORK_DEBUG_VA / CARRICK_FORK_DEBUG_IPA)

Two env-gated hooks (kept in-tree) settled it: `CARRICK_FORK_DEBUG_VA=<hex>`
prints, at each fork, the covering mapping, its inventory extents, the parent
frame's BYTES at that offset, and the parent's live stage-1 leaf;
`CARRICK_FORK_DEBUG_IPA=<hex>` prints every global-frame host-owner
register/retire overlapping that IPA, with backtraces.

What they showed, in order:

1. At fork #1 the parent frame holds live data at the granule; at fork #2 the
   SAME frame offset reads zero — with the parent's stage-1 leaf still
   read-only, still pointing at the SAME physical address, and AGREEING with
   the inventory. The parent never wrote the granule between forks; the
   physical backing changed under it.
2. The owner lifecycle names the killer:
   - guest mmap -> `materialize_sparse_mmap_extent` registers host owner
     `(0x9e2bc00000, 0x1a4000)` — the region the dict lives in;
   - guest **munmap of PART of the region** -> `unregister_process_alias` ->
     `retire_stage2_extent` retires the WHOLE owner, dropping the
     `OwnedHostMapping` while live sibling mappings (the dict) still point
     into it;
   - a later guest mmap re-materializes `(0x9e2bc00000, 0x154000)` — fresh
     ZEROED host memory under the parent's still-mapped VAs.
3. The parent's own dict extent carries a THIRD length for the same base
   (`(0x9e2bc00000, 0xf4000)`).

So the defect: **sparse-materialized stage-2 regions re-register one base IPA
at different lengths as they grow, and every refcount — `stage2_references`,
the host-owner registry, `final_exec_physical_extents`'s
`references == local` gate — keys on the exact `(base, length)` tuple.
Overlapping leases with independent refcounts are blind to each other, so a
partial munmap (or a process exit) retires host backing that other live
mappings still reference through a different key.** Granules rewritten after
the re-registration re-materialize; a granule written before and never after
silently becomes zeros. Fork is not the bug — it merely copies the loss into a
child that then reads it.

This is the `docs/identity-and-scope-domains.md` class again — two keys for
one physical range — and the third instance this campaign (engine-handle
count vs guest-executor population; `(gpa,len)` extents vs `MappingId`; now
`(base,len)` leases vs physical range).

### FINAL: the writer is the mmap-reuse scrub over a DOUBLE-ALLOCATED range

A third hook (`zero_guest_backing` logging any scrub covering the debug VA)
ended it. Three scrubs cover the granule, all from guest `mmap` reuse:

```
before fork#1:  zero va=0x6000fd1000 len=0x100000   (1 MiB grant)
before fork#1:  zero va=0x60010c1000 len=0x31000    (the dict chunk's grant)
BETWEEN forks:  zero va=0x6000fd1000 len=0x100000   (the SAME 1 MiB again)
```

`[0x6000fd1000, +0x100000)` ends at `0x60010d1000` — overlapping the LIVE dict
mapping `[0x60010c1000, 0x60010f4000)` by four granules. The dispatcher's
arena allocator granted a reused range that overlaps a live mapping, and
`zero_anonymous_reuse` faithfully scrubbed the grant — including the dict's
granule. Every HVPatch-side hypothesis along the way (fork COW, lease
refcounts, owner generations) was WRONG; the stage-2 lease-keying observations
earlier in this file are real hygiene issues but not this bug. The defect is a
guest-VA double allocation in `dispatch/mem.rs` (`next_mmap_address` /
`free_regions` bookkeeping): the same freed region was handed out twice with
overlap.

Note the overlap also explains the survivor pattern in the core: entries below
the hole live in pages the guest rewrote after the scrub; the hole granule was
never rewritten.

### Provenance instrumentation is COMPLETE; final reduction is one run away

Five env-gated hooks now cover every layer, all keyed on
`CARRICK_FORK_DEBUG_VA` (plus `CARRICK_FORK_DEBUG_IPA` and
`CARRICK_MMAP_GRANT_DEBUG=1`):

| hook | layer |
|---|---|
| fork spec build | mapping + extents + parent frame BYTES + live stage-1 leaf |
| owner register/retire | global-frame host-owner lifecycle, with backtraces |
| `zero_guest_backing` | every scrub covering the VA, with backtraces |
| `next_mmap_address` | overlapping grants; ledger neighbourhood on covering grants |
| `remove_mapping_metadata` / `free_regions_insert` | ledger removals and free-list inserts, with backtraces |

What single-run captures established so far:

- The grant audit found NO non-FIXED grant overlapping a live `dynamic_maps`
  entry — yet the killer scrub covers memory the trap-side registry still
  shows as a live 0x33000 mapping at both forks. The DISPATCHER ledger and the
  TRAP-side alias rows disagree about what is alive: the guest munmap'd a
  0x33000 mapping (LEDGERDBG line), the dispatcher trimmed its ledger and
  free-listed the range, but the trap-side row `[0x60010c1000,0x60010f4000)`
  persists across both forks. The corruption sits in that divergence: scrubs
  resolve host bytes through trap-side rows, grants through the dispatcher
  ledger.
- One run's full chain (`fr.err`): guest munmap 0xf000 -> free insert; 1 MiB
  scrub-grant; guest munmap 0x33000 -> free insert; 0x31000 scrub-grant (the
  live array); guest munmap 0xf000 AGAIN over the head of that grant; the
  killer 1 MiB re-grant whose scrub covers the granule.

**WARNING for the next session — a mistake to not repeat: do not
cross-reference addresses BETWEEN runs.** The debug VA `0x60010cc000` came
from the original core; each run's leases and chunk layout shift (observed
0x174000 / 0xf4000 / 0x1a4000 / 0x154000 for "the same" lease), so the same VA
plays different roles run to run. Two log analyses in this file's history
conflated layers this way. The closing move is ONE run with ALL hooks enabled,
analysed entirely within itself: establish which mapping the crash VA belongs
to IN THAT RUN (FORKDBG prints the covering mapping), then read the
LEDGER/FREE/GRANT/scrub events for those exact ranges in that same log.

### RESOLVED (mechanism): a cross-process scrub through an unscoped VA fallback

Adding PROCESS IDENTITY to every hook dissolved the "double allocation"
entirely: the interleaved grants belong to FIVE different guest processes
(pids 2, 5, 6, 7, 9) legitimately reusing the same NUMERIC arena VAs in their
own address spaces. Every grant, munmap, free-list insert and scrub is
per-process correct. The corruption is that **pid 9's scrub of its own fresh
1 MiB grant zeroes pid 6's (the forkserver server's) physical frame**.

The guilty resolution chain, in `zero_guest_backing`'s fallback:

- `mapping_for_range` (trap.rs) resolves a VA in three branches. The stage-1
  IPA-keyed branches authenticate through the caller's own translation; the
  VA-keyed alias fallback filters by `alias_matches_process_scope`; but the
  bare `self.mappings` VA fallback — `mapping.contains_range(address, length)
  && region_is_live(mapping)` — has NO scope or stage-1 authentication.
- A fork child's engine state inherits the parent's mapping rows, several as
  `ForkMappingHost::Borrowed(parent_host_addr)`. For the scrub's chunks the
  caller's stage-1 is INVALID by construction (a reused range is scrubbed
  before its stage-1 is re-validated), so `stage1_ipa` is None and resolution
  falls through to exactly that unscoped fallback — matching a stale inherited
  row for the numerically-identical VA and handing back the ANCESTOR'S host
  pointer. `write_bytes(…, 0, …)` then zeroes another process's memory.

This is the identity/scope-domains class, fourth instance this campaign, and
the precise shape AGENTS.md's HVPatch memory rule warns about: "never feed one
domain back into a lookup for another: authenticate through the live stage-1
translation and the exact current owner generation."

**CORRECTION — the unscoped-fallback attribution above was WRONG, and the fix
built on it did not move the bug.** Chunk-level SCRUBDBG logging with the
server's frame pointer printed beside it settled the true mechanism:

```
server frame granule host = 0x17a798000 + 0xcc000 = 0x17a864000
[SCRUBDBG pid=7] chunk va=0x60010cc000 live_ipa=None
                 retained_ipa=0x9e2bacc000 target=0x17a864000   ← THE SAME POINTER
```

pid 7 (a fork child) resolves its OWN retained stage-1 output — a leaf cloned
at fork that legitimately names the COW-SHARED frame — and the resolution is
fully authenticated (VA-consistent, owner live). The write is wrong not
because the lookup crossed processes but because **the write went through a
still-shared frame without a copy-on-write break**: `ensure_frame_cow_write`
routed `Direct` because the child's `cow_armed` span set did not cover the
range. The armed-set is derived at fork from alias rows and can omit ranges
(the in-tree `mtforkcorrupt` comment describes the same class); the FRAME
INVENTORY, which knows the frame is referenced by more than one mm, is the
authority that should have decided "shared". Populations, fifth instance.

The scrub also cannot simply SKIP such a chunk: leaving the shared frame
un-scrubbed lets the reusing child READ the other process's bytes through the
reused VA — a cross-process disclosure instead of a corruption. The correct
operation is a REPOINT: materialize a fresh zeroed granule for this mm
(update the retained leaf's output and split the inventory extent), leaving
the shared frame untouched — the same transactional shape as
`materialize_retired_reuse`/`perform_frame_cow`.

The stage-1-authentication tightening of `zero_guest_backing` (dropping the
unscoped VA fallback) is KEPT — it closes a real adjacent hole — it just is
not this bug's fix.

Raw logs preserved in the scratchpad (`fd*.err`, `gd*.err`, `ld.err`,
`fr.err`, `id.err` — the pid-tagged run); the proving core at `/tmp/core`.

### Why this cluster is worth the next cycle

`cpython-multiprocessing_forkserver` (366 unexercised rows),
`cpython-multiprocessing_fork` (227), `cpython-importlib` (349, guest SIGSEGV
deep in a threading test), and `cpython-concurrent_futures` (178, left a
`core` behind) are all plausibly this one family — a context-dependent child
SIGSEGV. Confirming or splitting that attribution is worth ~1,100 rows.


## THE FIX (landed): exclusive-claim authentication for maintenance writes

`frame_cow_write_route` gains a fourth discriminant: a `BackingMaintenance`
write whose retained stage-1 output LACKS AN EXCLUSIVE CLAIM routes to
`MaterializeRetired` — a fresh private zeroed granule, transactionally
repointed — instead of writing Direct through the frame. A claim is lacking
when:

- this mm's inventory holds NO extent covering the IPA (a stale retained leaf
  that survived its mapping's retirement — the forkserver worker's exact
  shape: 606 own extents, none covering the IPA, writing straight into the
  server's frame), or
- an extent exists with a `Private` backing whose frame the shared backend
  registry counts more than one reference on (fork-COW sharing).

`SharedAnon`/`SharedFile` backings are exempt — MAP_SHARED means every mapper
must keep seeing the same bytes, and the first version of this fix privatized
a shared semaphore page and hung multiprocessing's Barrier. Deliberate sharing
is not a lost claim.

Two earlier fix attempts did NOT move the bug and are kept only as adjacent
hardening: dropping `zero_guest_backing`'s unscoped VA fallback, and the
`retained_frame_is_shared` refcount-only test (defeated by the missing-extent
case).

Verified on the signed binary:

| check | before | after |
|---|---|---|
| the 2.5 s pair | FAILED 3/3, child SIGSEGV | OK 5/5 |
| `test_multiprocessing_fork.test_misc` | 1 ERROR | SUCCESS |
| `test_multiprocessing_spawn` | 3/4 files | **SUCCESS 4/4** |
| `test_multiprocessing_forkserver` | 0 assertions (hang) | **SUCCESS 4/4** |
| `test_multiprocessing_fork.test_processes` | never completed | completes; 1 isolated ERROR |
| churn reducers, `ltp-mremap01`, `go-net_http` 53 s | — | all unchanged-green |

Remaining, now ISOLATED and deterministic: `WithProcessesTestPicklingConnections
.test_pickling` fails standalone under carrick (recv EOF), passes under Docker —
an fd-passing (SCM_RIGHTS pickled-connection) gap, nothing to do with memory.
