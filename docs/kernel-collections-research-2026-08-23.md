# Kernel collection data structures — research report (2026-08-23)

Produced by a read-only research pass (Opus) commissioned after live profiling
kept finding O(n)/O(n^2) scans in global structures under one mutex — the
measured trigger was `retire_task_state_process_mappings` at ~540 ms per
process exit in a 1000-process fork storm (fixed tactically the same day by
keying `mutate_external_alias_state`'s diff; this report is the strategic
follow-through). Every current-structure claim carries a file:line from HEAD
at the time of research (`c49c4334` lineage). The ranked migration list
(M1–M12) is the actionable core; each entry names the invariant the migration
must preserve.

**Method note:** complexity claims are read off the code shape; the only
*measured* numbers are ≈540 ms/process exit at 1000 processes, ~35 ms/fork at
1000 live, the 45 s-in-a-10 s-window retirement total, and
`docs/perf-results/2026-08-19-futex-requeue-durability/README.md`'s 179
broadcasts × ~1000 waiters ≈ 179 k unparks in one probe. Everything else is a
hypothesis about ordering, not a measurement.

---

## 1. Taxonomy of the kernel's collection needs

### T1 — Generation-keyed identity maps ("a stale generation must MISS")

`TaskKey { id: TaskId /*NonZeroI32 pid*/, serial: TaskSerial /*NonZeroU64, never reused*/ }` (`crates/carrick-runtime/src/kernel/objects.rs:72`), `ThreadKey { tid, serial }` (`objects.rs:78`). The serial **is** a generation, and `ObjectIdRegistry` (`kernel/ids.rs:170`) is a pure `AtomicU64` — so the key is already `(slot, generation)`.

**Current:** the key is thrown away and only the *numeric* half is used as the map key:
- `RegistryState.tasks: BTreeMap<TaskId, TaskRecord>` (`kernel/core.rs:1502`) — keyed by pid, **not** by TaskKey.
- `Kernel::context()` (`core.rs:1054-1071`) does a numeric-only lookup; the generation check is a *separate, opt-in* step bolted on by the caller — `KernelTaskBinding::capture` (`core.rs:208-214`) and `capture_signal_snapshot` (`core.rs:229-231`) compare `context.task.key() != self.task` after the fact.
- `Task::threads: Mutex<BTreeMap<LinuxTid, (ThreadKey, ThreadRef)>>` (`objects.rs:2582`) — same shape; `Task::retire_thread` (`objects.rs:3862-3872`) hand-checks `*published_key != key`.
- `MmResourceState { leases: BTreeMap<TaskKey, …>, retired: BTreeSet<TaskKey> }` (`crates/carrick-runtime/src/hvpatch/mm_resources.rs:82,86`) — the `retired` set is documented "**Permanent within one runtime**" and grows without bound for the life of the carrier.

**Failure mode:** generation discipline is *convention*, enforced at ~8 call sites and absent at the rest; and the tombstone set is an unbounded leak whose only job is to re-derive what the generation already encodes. `AsidAllocator` (`hvpatch/asid.rs:244-250`) proves the team already knows the right shape — `AsidGeneration { asid, generation }` with a bounded `retired` set drained on TLB ack.

### T2 — Reverse indexes that are missing, forcing O(live-processes) scans

**Current:** there is no `LinuxTid → (TaskKey, ThreadKey)` index anywhere. Every resolution walks the whole process table:
- `live_keys_for_thread` `operations.rs:1855` — `state.tasks.values().find_map(|r| r.task.thread(tid))`, on **any syscall entry that resolves a bare tid**.
- `exact_thread_for_scheduler` `operations.rs:1870` — same shape, on **every scheduler wake/kick that names a `ThreadKey`**.
- `with_live_active_scheduler_thread` `operations.rs:1886`; `with_live_scheduler_descendant` family `operations.rs:1907, 1959, 1986, 2011`.
- `wait_child_matching` `operations.rs:3730-3740` scans **all zombies VM-wide** and `operations.rs:3768` scans **all tasks**, per `wait4`.
- `set_oom_score_adj` `core.rs:1341`, `task_nice` `core.rs:1361`, `set_task_nice` `core.rs:1372` do `tasks.iter().find(|(id,_)| id.raw()==pid)` — **linear over a BTreeMap already keyed by that value**. That is a straight bug in shape, not a data-structure question.
- `process_group_prio_targets` `core.rs:1395`, `user_prio_targets` `core.rs:1419` — full scans for `setpriority(PRIO_PGRP/PRIO_USER)`.
- `update_fs_umask` `operations.rs:2735-2748` — nested `for record in tasks × for thread in threads` = **O(processes × threads)**.

**Failure mode:** exactly the defect class AGENTS.md names — O(live-processes) work on a per-event hot path, all under one lock (`Registry.state: RwLock<RegistryState>`, `core.rs:1199`).

### T3 — Interval / range maps (point-stab + overlap scan)

Five distinct populations, four of them hand-rolled differently:

| site | structure | query | complexity |
|---|---|---|---|
| `carrick-guest-mem/src/protections.rs:45` `RangeSet { ranges: Vec<(u64,u64)> }` | sorted, merged, non-overlapping | `contains`/`covers`/`intersections` via `partition_point` | **query O(log n)**, insert O(n) memmove — *this is the good one* |
| `carrick-vmm-hvf/src/trap.rs:2181` `copy_from_global_frame_owner` | `BTreeMap<(ipa,len), Owner>` | "which owner extent contains this IPA" via `owners.iter().find(...)` | **O(owners)**, and the `volatile_copy_from_guest` runs **while holding the global lock** |
| `trap.rs:4580` `CowArmedRanges { ranges: Vec<ForkCowRange> }` | overlapping allowed | `span_for` = `filter(contains).max_by(most-specific)` (`trap.rs:4586-4602`) | **O(armed ranges)** per COW fault |
| `trap.rs:5765` `GlobalFrameIpaAllocator { free: Vec<(u64,u64)>, live: BTreeMap }` | free list | `allocate` linear best-fit `trap.rs:5789`; `release` does **`push` + full `sort_unstable_by_key` + full merge-rebuild** `trap.rs:5863-5875` | alloc O(F), **release O(F log F) with a realloc** |
| `trap.rs:1912` `alias_registry(): Mutex<Vec<AliasBacking>>` | overlapping, duplicate-keyed | VA/IPA containment, see T4 | O(rows) — the big one |

**Failure mode:** the same query ("which extent contains X") is answered four different ways, three of them linear, and the one correct implementation (`protections.rs`) is not reusable because it carries no value payload and is private to its module.

### T4 — Duplicate-key ordered registries with *two conflicting* disciplines

This is the subtlest need in the tree and the one a naive migration will silently break. The single `Vec<AliasBacking>` at `trap.rs:1912` is read under **two incompatible tie-break rules**:

- **First-match-wins, keyed `(ipa, ownership_scope)`** — the *publication/identity* index. `register_shared_alias` `trap.rs:2295-2301` uses `iter_mut().find(...)` to replace the **first** matching row; `process_alias_index` `trap.rs:2513-2521` reproduces it with `.or_insert` ("First occurrence wins, mirroring the linear scans' `.find` semantics this replaces"); `mutate_external_alias_state` `trap.rs:7663-7674` builds first-occurrence `before_by_key`/`after_by_key` for the same reason.
- **Last-match-wins, keyed `(scope, VA interval)`** — the *translation* index. `lookup_shared_alias_by_va` `trap.rs:2558` and `lookup_live_alias_by_va_any_scope` `trap.rs:2578` use `.iter().rev().find(...)`, documented at `trap.rs:2438-2444`: a Go arena page is covered by both a `PROT_NONE` reservation row **and** a later `MAP_FIXED` commit row, and the commit — registered last — is the one stage-1 actually uses. `physical_cow_source` `trap.rs:11452` and `shared_futex_location` `trap.rs:14104` are also `.rev()`.

So it is **one row set with two indexes**, and insertion order carries load-bearing semantics for one of them. Any replacement must keep both.

**Additional failure mode inside the same structure:** `alias_backing_is_live` (`trap.rs:2359`) issues a **`mach_vm_region` Mach trap** — and it is used as the *predicate of the linear scan* at `trap.rs:2565`, `trap.rs:2585`, `trap.rs:14108`, `trap.rs:11558`. With thousands of rows that is thousands of Mach traps per lookup, taken while holding the global mutex.

### T5 — Version chains / epoch registries

`AliasVersionRegistry { aliases: Vec<AliasVersionChain>, replays: Vec<ReplayVersionChain>, alias_epochs: Vec<((u64, Scope), u64)>, replay_epochs: Vec<(u64, u64)> }` (`trap.rs:7567-7573`). Every access is a linear `find`: `bump_version_epoch` `trap.rs:7583`, chain lookup `trap.rs:7615-7618` and `trap.rs:7635-7638`, and again at `trap.rs:7695-7698`, `trap.rs:7735-7738`.

**Failure mode:** four parallel association-lists where the key is a plain `Copy + Eq` tuple. This is a `BTreeMap`/`HashMap` written as a `Vec`, and it sits directly under the COW-fault path.

### T6 — Snapshot / rollback

- **HVF side:** `mutate_external_alias_state` `trap.rs:7649-7652` clones the **entire** `BTreeSet<ReplayMappingKey>` and the **entire** `Vec<AliasBacking>` on **every mutation**, then diffs. Seven further sites do a bare `alias_registry().lock().clone()`: `trap.rs:11145, 14779, 15429, 15651, 16033, 16458`. `CowArmedRanges::snapshot()` `trap.rs:4580` is a full `Vec::clone`, taken per fork transaction (`trap.rs:11194`), and `arm()` `trap.rs:4570-4574` does `extend + sort + dedup` = O(n log n) per arm.
- **Kernel side:** `snapshot.rs` is a **full owned projection with no rollback path at all** — `KernelSnapshotV1` is 20 `Vec<…Row>` (`snapshot.rs:29-51`), rebuilt from scratch, retried up to `MAX_ATTEMPTS = 3` (`snapshot.rs:26`) with races detected by **re-reading revisions** (`snapshot.rs:873-920`), not by undo. Rollback everywhere in the graph is RAII-discard: `MmTransaction::drop` clears staged ops (`mm_transaction.rs:119-125`), `ReservationToken::drop` releases the pid claim (`registry.rs:288-294`), `InventoryOverlay` is simply dropped (`frame_inventory.rs:94-104`).
- **`ObservationInventory::sweep`** `core.rs:455-468` — six `retain`s over the whole weak index plus **two** full `observation_count` traversals, on every snapshot.
- **`FileTableRwWriteGuard`** `objects.rs:1449-1458` — clones the **entire fd map** (`HashMap<i32,(u64,FileDescriptionId)>`) on every write guard, purely to diff for change publication.

**Failure mode:** clone-the-world is the *only* snapshot primitive in the tree. It is correct and it is O(global) per event — the exact coupling the architecture forbids.

### T7 — MPMC queues, wait queues, broadcast wakeups

- **Run queue:** `RunQueueState { rows: VecDeque<QueueRow>, queued: BTreeSet<QueueKey> }` (`scheduler.rs:369-379`) under one `Mutex` + one broadcast `Condvar` (`scheduler.rs:399-400`). Targeted dequeue is `rows.iter().position(...)` — `scheduler.rs:865`, O(runnable).
- **Executor directory:** `binding_for_thread` `scheduler.rs:304-315` **clones every kick token** then `.find()`; `has_running` `:317`, `current_tokens` `:330` do the same.
- **Futex table:** 64-way Fibonacci-sharded `HashMap<u64, Arc<FutexBucket>>` (`carrick-thread/src/thread.rs:899, 1006-1009`) — that part is well designed. The defect is `all_buckets()` `thread.rs:1022-1030`: locks all 64 shards, clones every bucket into a fresh `Vec`, and is called by `notify_signal_pending` `thread.rs:1351` **and** `notify_signal_pending_for(tid)` `thread.rs:1369`. **Buckets are never removed from the shard maps** — no `remove`/`retain` on them — so the cost of *any* signal wake grows monotonically with the number of distinct futex addresses the carrier has ever seen. Waking **one** thread by tid costs O(all buckets ever).
- **Wait/wake enrollment:** `Task::wake_listeners: Mutex<BTreeMap<u64, TaskWakeListener>>` (`objects.rs:2593`), `job_control: Mutex<TaskJobControl> + Condvar` (`objects.rs:2579`), `ReservationGate` `Mutex<u64> + Condvar + BTreeMap<u64,_>` (`core.rs:475-484`), `fork_quiesce.rs:99/542/561` listener maps. These are fine in shape.

### T8 — Free-list / ID allocators

- `IdRegistry::reserve_next` `registry.rs:91-119` — **linear probe** over `next..wrap` skipping `claims.contains_key`, O(claims) when the pid namespace is dense.
- `GlobalFrameIpaAllocator` — see T3.
- `AsidAllocator` `hvpatch/asid.rs:244` — correct: `VecDeque` reuse pool + generation-stamped live/retired sets bounded by the 16-bit ASID space.

---

## 2. Recommended structure per need, mapped to crates

Workspace license policy is `deny.toml` `[licenses].allow` — MIT, Apache-2.0, BSD-2/3, ISC, Zlib, MPL-2.0, BSL-1.0, 0BSD, Unlicense, Unicode-3.0, CDLA-Permissive-2.0. Everything recommended below clears it; exceptions are flagged.

### T1 — Generation-keyed identity → **`slotmap` 1.1.1 (Zlib)**, plus a small in-house `PidTable`

`slotmap` — Zlib, 24.6 M recent downloads, last release 2025-12-06, `no_std`-capable, stable 1.x. Its `KeyData` is exactly `(index: u32, version: u32)` and `SlotMap::get` is an array index + a version compare: **a stale key structurally cannot alias**, which is precisely the discipline `core.rs:208-214` currently hand-writes.

- `SecondaryMap<K, V>` gives the per-task side tables (`mm_resources.leases`, `reservations`, `watchers`) keyed by the *same* key with the same miss discipline, deleting `MmResourceState.retired` (`mm_resources.rs:86`) outright — a generational key needs no tombstone.
- `SlotMap::insert_with_key` lets `TaskKey` be produced *by* the store, so identity allocation and storage stop being two facts that can disagree.

**Why not the alternatives:**
- `generational-arena` 0.2.9 — MPL-2.0 (allowed), 1.06 M downloads, but last release **May 2023** and no `SecondaryMap` equivalent. Strictly dominated by `slotmap`.
- `thunderdome` 0.6.1 — MIT/Apache, last release **June 2023**, 185 k downloads. Nicer 64-bit `Index`, but low adoption and stale.
- `slab` 0.4.12 — MIT, 201 M downloads, actively released (2026-01-31). **Has no generation** — a reused slot silently aliases. That is the exact bug the serials exist to prevent. Use `slab` only where the key never escapes a single transaction.

**The gap `slotmap` does not close:** `TaskId` is a *Linux-visible, recyclable* `NonZeroI32` pid, not a slotmap index, and `pid_max` is 4 Mi so it cannot be dense-indexed. One small in-house structure is needed:

```text
// crates/carrick-collections/src/pid_table.rs
/// pid -> live slot, generation-checked. Two-level radix (4096 entries/page,
/// pages allocated on demand) so a sparse 22-bit pid space costs O(live pids)
/// memory and O(1) lookup — no hashing, no tombstones.
pub struct PidTable<K: slotmap::Key> { pages: Vec<Option<Box<[Option<(TaskSerial, K)>; 4096]>>> }
impl PidTable<K> { fn get(&self, key: TaskKey) -> Option<K>   // serial mismatch => None
                   fn get_numeric(&self, id: TaskId) -> Option<(TaskSerial, K)> }
```

That single type replaces `RegistryState.tasks`' numeric keying, kills `registry.rs:91`'s linear probe (a free-page bitmap over the same pages gives O(1) `reserve_next`), and makes `core.rs:1054`'s lookup generation-checked *by construction* instead of by convention. Nothing on crates.io does the pid-recycling + never-reused-serial combination; this is ~150 lines and belongs to us.

### T2 — Reverse indexes → **plain `std` maps with a fast hasher: `rustc-hash` 2.1.3 (Apache-2.0 OR MIT)**

No exotic crate is warranted. What's missing is the index itself:
- `tid_index: HashMap<LinuxTid, (TaskKey, ThreadKey)>` in `RegistryState`, maintained by the same code that mutates `Task::threads` (`objects.rs:2582`). Kills `operations.rs:1855, 1870, 1886, 1907, 1959, 1986, 2011`.
- `children_by_parent` / `zombies_by_parent: HashMap<TaskKey, SmallVec<[TaskId; 4]>>`. Kills `operations.rs:3730` and `:3768` (`wait4`).
- `by_pgid` / `by_uid` membership sets. `ProcessGroupRecord.members: BTreeSet<TaskKey>` already exists (`core.rs:1549`) — `core.rs:1395` just doesn't use it. Same for `user_prio_targets` `core.rs:1419`.
- `fs_context_index: HashMap<FsContextId, SmallVec<[TaskKey;…]>>` kills the `O(procs × threads)` loop at `operations.rs:2735-2748`.
- `core.rs:1341/1361/1372` need no index at all — change `.iter().find(|(id,_)| id.raw()==pid)` to `.get(&TaskId…)`. Three one-line fixes.

`rustc-hash`: Apache-2.0 OR MIT, 199 M recent downloads, released 2026-07-02, `no_std`, and `FxHashMap` is the same hasher rustc uses. The kernel graph currently uses **default SipHash-1-3 everywhere** — a repo-wide grep found `BuildHasherDefault`/`FxHash` in exactly one file (`carrick-dsr-x86/src/translator.rs`). For `u64`/`i32` keys hashed on every syscall entry this is pure loss. Adopt `FxHashMap` as **the** map type for kernel-internal, non-adversarial keys via a `carrick-collections` re-export; keep SipHash only where a key is guest-controlled and collision-attackable (it isn't, inside one carrier).

**Anti-note:** do not reach for `dashmap`/`papaya`/`scc` here (see §4).

### T3 — Interval maps

Two shapes, two answers.

**(a) Non-overlapping, newest-wins, value-carrying → `rangemap` 1.8.0 (MIT/Apache-2.0).**
1.8.0, 11.3 M recent downloads, released **2026-08-14** — the healthiest interval crate in the ecosystem by a wide margin. `RangeMap::insert` semantics: an overlapping insert "partially or completely replaces" the existing range(s), and equal-valued neighbours coalesce. **That is exactly the newest-wins-with-automatic-splitting rule** that `lookup_shared_alias_by_va`'s `.rev()` (`trap.rs:2558`) and `unregister_alias_entries`' manual split loop (`trap.rs:2602-2645`) implement by hand today. Bounds are `K: Ord + Clone`, `V: PartialEq + Clone` — `AliasBacking` is `Copy + Eq` (`trap.rs:1861`), so it fits directly. Queries: `get`, `get_key_value`, `overlapping(range)`, `overlaps`, `gaps`, `remove` — `gaps` alone replaces the `GlobalFrameIpaAllocator` free list.

Fits: the alias VA index (T4b), `copy_from_global_frame_owner` (`trap.rs:2181`), `GlobalFrameIpaAllocator.free` (`trap.rs:5767`), and — if the payload is wanted — a generalized `MemoryProtections` (`protections.rs:45`).

Caveats: no declared `no_std`/`alloc` feature (irrelevant here); `insert` is a `BTreeMap` splice, so O(log n + touched) not O(1); and its coalescing means two distinct-valued rows cannot cover the same bytes, which is *correct* for the translation index and *wrong* for the publication index.

**(b) Overlapping, keep-all, most-specific-wins → `iset` 0.3.3 (MIT).**
Released 2026-05-09, 66 k recent downloads. Self-balancing AVL in a flat `Vec`, insert/remove O(log N), overlap query O(log N + K), and — critically — `force_insert` **permits duplicate/overlapping intervals**, with `iter(query)`/`overlap(point)` returning all of them. The only crate found that matches `CowArmedRanges::span_for` (`trap.rs:4586`), which must see *every* containing range and then pick the most specific.

Caveats: 0.3.x, small user base, and `get`/`remove` on a duplicated interval pick an entry "arbitrarily" — so a duplicate-keyed use must drive removal off a stored handle, not off the interval.

**Alternatives considered and rejected:**
- `nodit` 0.10.0 — MIT, 68 k downloads, last release 2025-10-18. Good `BTreeMap`-based discrete interval tree; fails-closed on overlapping insert instead of overwriting — arguably *safer* but requires an explicit cut at every call site and does not match today's semantics. **Licensing trap: 0.7.0 and 0.7.1 were AGPL-3.0-or-later**; only ≥0.8.0 is MIT. If ever used, pin `>=0.8` and let `cargo deny` enforce it.
- `interavl` 0.6.0 — Apache-2.0, released 2026-04-16, but 25 k downloads and ~1.9 kLOC. Viable but not better than `iset` and much less exercised.
- `store-interval-tree` 0.4.0 — MIT/Apache but **2 366 recent downloads, last release 2022-11-22**. Dead. Do not adopt.

### T4 — The alias registry: one row store, two indexes (build ours, on `slotmap` + `rangemap` + `FxHashMap`)

Nothing off the shelf gives "duplicate-keyed rows, first-wins on one key and last-wins on another, with generation authentication and rollback." Build it:

```text
// crates/carrick-vmm-hvf/src/alias_space.rs
struct AliasSpace {                       // ONE per AliasOwnershipScope
    rows: SlotMap<AliasRowKey, AliasBacking>,          // the only owner of a row
    by_publication: FxHashMap<Gpa, AliasRowKey>,       // (ipa) -> FIRST publication  [first-wins]
    by_va: RangeMap<GuestVa, AliasRowKey>,             // VA extent -> covering row   [newest-wins, auto-split]
    by_physical: FxHashMap<Gpa, SmallVec<[AliasRowKey; 2]>>, // physical_ipa -> rows (replay + retirement)
    epochs: FxHashMap<Gpa, u64>,                       // replaces AliasVersionRegistry's Vecs
}

static ALIAS_SPACES: Mutex<FxHashMap<AliasOwnershipScope, AliasSpace>>;
```

Three properties fall out:

1. **`AliasOwnershipScope` (`trap.rs:1821`) *is* the process key** — `MmRootSlot { base, size }` is the mm identity, and `alias_is_owned_by_process` (`trap.rs:2452`) already tests exactly that. Sharding by scope turns `retire_task_state_process_mappings`' global `registry.retain(...)` (`trap.rs:10591-10601`) into **`spaces.remove(&scope)`** — O(own footprint), not O(global). The single change that most directly attacks the 540 ms/process-exit measurement.
2. `by_publication` preserves first-wins exactly (insert only if vacant, mirroring `process_alias_index`'s `.or_insert`, `trap.rs:2518`); `by_va` preserves newest-wins exactly (`RangeMap::insert` overwrites and splits, mirroring `.rev().find` + `unregister_alias_entries`).
3. `mutate_external_alias_state`'s clone-and-diff (`trap.rs:7649-7652`) disappears: a keyed mutator *knows* its touched keys, which is already what `scoped_alias_epoch_update` (`trap.rs:7601`) proved when it was added as a fast path. Once every mutator is keyed, the general diff has no callers left — delete it, per "no second path."

**Separately and independently: hoist `alias_backing_is_live` out of the scan predicate.** `trap.rs:2565/2585/14108/11558` call a `mach_vm_region` Mach trap once per candidate row under the global lock. Even after the index change it must become a single check on the *selected* row, not a filter over candidates.

### T5 — Version chains → delete the `Vec`s, use `FxHashMap` + `smallvec`

`AliasVersionRegistry`'s four `Vec` association-lists (`trap.rs:7567-7573`) become `FxHashMap<(Gpa, Scope), Chain>` / `FxHashMap<Gpa, Chain>` folded into `AliasSpace.epochs` above. `bump_version_epoch` (`trap.rs:7583`) becomes `*epochs.entry(key).or_insert(0) += 1`. No new dependency; `smallvec` (MIT/Apache, already ubiquitous transitively) for the per-key version vectors.

### T6 — Snapshot / rollback → **`rpds` 1.2.1 (MIT)** for the clone-heavy paths, RAII journals elsewhere

`rpds` — MIT, 3.7 M recent downloads, released **2026-05-15**, actively maintained. Persistent `HashTrieMap`/`RedBlackTreeMap`/`Vector` with structural sharing: `.clone()` is O(1) and an update is O(log n) with the old handle still valid. That converts "snapshot = clone the world" into "snapshot = copy a pointer," which is precisely what `CowArmedRanges::snapshot` (`trap.rs:4580` → `trap.rs:11194`) and the seven `alias_registry().lock().clone()` sites (`trap.rs:11145, 14779, 15429, 15651, 16033, 16458`) need.

- `imbl` 7.0.1 is the maintained fork of `im` (released 2026-07-18, 2.1 M downloads) and is generally faster than `rpds` for large maps. **Licensing caution:** crates.io reports its license string as **`MPL-2.0+`**, and `deny.toml` allows the exact token `MPL-2.0`. That `+` may not match cargo-deny's SPDX expression list — verify with `just deny` before committing to it. `rpds`' plain MIT avoids the question, hence the lead.
- **`im` 15.1.0 is unmaintained** (last release 2022-04-29). Do not adopt.

**Do not** persistent-ify the kernel graph wholesale. `snapshot.rs` is a *debug/observability* projection with a 3-attempt revision-race retry (`snapshot.rs:26, 873-920`), not a transaction; the right fix there is cheaper indexes (T2) and a *bounded* `ObservationInventory` sweep, not persistence. Concretely for `core.rs:455-468`: drop the two full `observation_count` traversals and make `sweep` amortized — evict a weak entry when its key is next touched, plus a generation-bounded pass, so it stops being O(all observed generations) per snapshot.

For the real transactions (`MmTransaction` `mm_transaction.rs:34`, `InventoryOverlay` `frame_inventory.rs:94`, `AliasPublicationReceipt` `trap.rs:7524`), the current **RAII undo-journal** pattern is already right and should be the *only* pattern. Generalize it into one `carrick-collections::Journal<Undo>` type so stage-1 / stage-2 / frame-inventory really do compose into one rollback-capable transaction rather than three parallel ad-hoc ones.

`FileTableRwWriteGuard`'s full fd-map clone (`objects.rs:1449`) is the same shape and takes the same fix: journal the touched slots, don't clone the map.

### T7 — Queues and wakeups → mostly **std, plus one missing index**; `crossbeam`/`concurrent-queue` only if lock-free is actually needed

- **Run queue** (`scheduler.rs:369`): keep the `Mutex<VecDeque> + Condvar`. Ten persistent executors on one queue is *not* a scalability problem, and a lock-free queue would lose the `queued: BTreeSet` membership invariant. The one real defect is `remove_exact`'s `rows.iter().position(...)` (`scheduler.rs:865`) — replace `VecDeque<QueueRow>` with an **intrusive doubly-linked list** so a targeted removal is O(1). `intrusive-collections` 0.10.3 (MIT/Apache, 5.8 M downloads, released **2026-08-04**, `no_std`) is the right crate; the simpler pure-safe alternative is `slotmap` for the rows plus prev/next slot keys, keeping everything inside the existing `Mutex`.
- **Executor directory** (`scheduler.rs:304-342`): the clone-then-`find` is gratuitous. Add `by_thread: FxHashMap<ThreadKey, ExecutorId>` alongside `entries` (`scheduler.rs:194`).
- **Futex table** — two fixes, no new crate:
  1. **GC the buckets.** Nothing removes entries from the 64 shard maps, so `all_buckets()` (`thread.rs:1022`) grows forever. Drop a bucket when `enrolled == 0 && waiters == 0 && pending_redirects == 0` (all already tracked, `thread.rs:713-732`) under its shard lock.
  2. **Index parked waiters by tid.** `notify_signal_pending_for(tid)` (`thread.rs:1369`) walks *every* bucket to wake *one* thread. Add `parked_by_tid: FxHashMap<ThreadId, SmallVec<[BucketKey; 2]>>` maintained at park/unpark, and the thread-directed wake becomes O(that thread's buckets). This is also the structural half of the process-global-broadcast problem `docs/perf-results/2026-08-19-futex-requeue-durability/README.md` names: "a signal is delivered to a TASK; waking every waiter in the carrier to ask 'was it you?' is the process-global surrogate `docs/identity-and-scope-domains.md` warns about."
  3. `notify_signal_pending()` (process-directed) additionally wants a `task → buckets` index so it broadcasts inside one Linux process, not the whole carrier.
- `crossbeam-skiplist` 0.1.3 (MIT/Apache) — last release **2024-01-08**, still 0.1.x. Not needed and not stable enough to be THE structure.
- `concurrent-queue` 2.5.0 (MIT/Apache, 72 M downloads, last release 2024-04-26) — solid, but there is no site here where a lock-free MPMC queue beats the existing `Mutex + Condvar` at 10 executors.
- `boxcar` 0.2.14 (MIT) — a concurrent append-only vector. Genuinely useful for the **event ring / diagnostics accumulators** (`event_ring.rs`, `FrameInventoryEvent` batches, `frame_inventory.rs:178`) where readers must not block writers. Not for anything that needs removal.

### T8 — Allocators → `rangemap::RangeSet` + a size index

`GlobalFrameIpaAllocator` (`trap.rs:5765`) should be:
- `free: RangeSet<u64>` — `insert` coalesces automatically, **deleting the sort-and-rebuild at `trap.rs:5863-5875` entirely**;
- `by_size: BTreeSet<(u64 /*len*/, u64 /*base*/)>` — makes the smallest-fitting-extent best-fit policy (`trap.rs:5803-5807`, deliberately chosen to preserve large holes for exec frames) an O(log F) `range((length,0)..).next()` instead of the O(F) scan at `trap.rs:5789`;
- `live: BTreeMap<u64,u64>` — keep as-is; the fail-closed exact-extent authority (`trap.rs:5857`), already O(log n).

`IdRegistry::reserve_next` (`registry.rs:91`) gets a free-slot bitmap over the same pages as `PidTable` (T1), turning the linear probe into a word scan.

---

## 3. Ranked migration list

Ranked by *expected* impact against the measurements above. Each entry names the invariant the migration must preserve — the things that will silently break.

**M1 — Shard the alias registry by `AliasOwnershipScope`.** `trap.rs:1912` → `Mutex<FxHashMap<Scope, AliasSpace>>`.
*Impact:* directly attacks the 540 ms/process-exit storm (`retire_task_state_process_mappings` `trap.rs:10591` global `retain` → `remove`) **and** the ~35 ms/fork (`process_alias_index` `trap.rs:2513` and the six `alias_registry().lock().clone()` sites now touch one scope, not all). Prerequisite for M2–M4.
*Invariants:* (a) `AliasOwnershipScope::Global` rows are visible to *every* scope — keep a separate `global` space consulted after the process space, matching `alias_matches_process_scope` (`trap.rs:2432`); (b) `Root` means "no mm root slot" (`trap.rs:2454`), a distinct scope, not a wildcard; (c) `rebind_inherited_alias_to_process` (`trap.rs:1848`) *moves* a row between scopes on fork — it becomes a remove+insert and must be atomic under the scopes lock; (d) lock order stays `replay → alias → version` (`trap.rs:7646`).

**M2 — Split the alias row store into `rows` + `by_publication` + `by_va`.**
*Impact:* removes the linear scan from `physical_cow_source` (`trap.rs:11452`) — **per COW fault**, the hottest path in a fork storm — and from `lookup_shared_alias_by_va` (`trap.rs:2558`), `lookup_live_alias_by_va_any_scope` (`trap.rs:2578`), `shared_futex_location` (`trap.rs:14104`), `fork_translation_has_overlay_owner` (`trap.rs:6428`, called once per mapping inside the fork loop at `trap.rs:16957` → O(mappings × aliases)), and `trap.rs:11553/11614/11647`.
*Invariants:* **first-wins on `(ipa, scope)`; last-wins on VA containment.** Prove both with a red-first probe: a Go-arena fixture where a `PROT_NONE` reserve and a later `MAP_FIXED` commit cover the same VA (the case documented at `trap.rs:2438-2444`) must still resolve to the commit; and a re-register of the same `(ipa, scope)` must still replace the *first* row (`trap.rs:2295`). Also: whole-range-in-one-entry or `None` (`trap.rs:2434`) — a buffer straddling two rows must still EFAULT, which `RangeMap::get_key_value` gives only if the returned range is checked to cover the whole query.

**M3 — Delete `mutate_external_alias_state`'s clone-and-diff.** `trap.rs:7642-7745`.
*Impact:* the wholesale `replay.clone()` + `registry.clone()` per mutation is O(global) on every `unregister_alias`, `clear_alias_registry`, and process retirement. After M2 every mutator knows its keys, so `scoped_alias_epoch_update` (`trap.rs:7601`) becomes the *only* path. Per "no backward compatibility," delete the general one rather than keeping both.
*Invariants:* epoch monotonicity and abort-on-exhaustion (`trap.rs:7607-7610`); chain reset semantics (`chain.base = after; chain.versions.clear()`, `trap.rs:7619-7620`) must be byte-identical for the same input.

**M4 — Replace `AliasVersionRegistry`'s four `Vec`s with maps.** `trap.rs:7567-7573`, `bump_version_epoch` `trap.rs:7583`.
*Impact:* removes four linear `find`s from the same COW-fault path. Small code, no new dependency, folds naturally into `AliasSpace` from M1.
*Invariant:* `bump_version_epoch` currently returns `Some(1)` for a *new* key (`trap.rs:7588`); the map version must too, or every first mutation on a key silently changes epoch semantics.

**M5 — Range-index `global_frame_host_owners` and get the copy out of the lock.** `trap.rs:1974`, `copy_from_global_frame_owner` `trap.rs:2181`.
*Impact:* a linear `iter().find` range-containment lookup **plus a `volatile_copy_from_guest` performed while holding the process-global mutex**. `RangeMap<u64, OwnerKey>` makes the lookup O(log n); then take the owner's host pointer + generation under the lock, release, and copy.
*Invariants:* the generation identity is load-bearing and non-negotiable — `global_frame_host_owner_matches` (`trap.rs:2125`) documents that a `map_shared_anon`/`munmap` cycle returned the *same* host VA 499/499 times, and that the pointer-only predicate was the `cpython-importlib` SIGSEGV. The `(None, 0) => true` case (a row published while nothing owned the extent) must survive exactly as written; tightening it "killed the guest outright." Releasing the lock before the copy requires pinning the owner (refcount or `Arc`) so retirement cannot `munmap` under the copy — a real new hazard this migration introduces that must be designed for, not assumed away.

**M6 — Futex bucket GC + `tid → buckets` index.** `thread.rs:1022, 1351, 1369`.
*Impact:* `notify_signal_pending_for` currently walks every bucket ever created to wake one thread; `notify_signal_pending` broadcasts carrier-wide. The recorded number is 179 broadcasts × ~1000 waiters ≈ 179 k unparks in a single probe.
*Invariants:* the enrolled-vs-parked distinction (`thread.rs:713-723`) is what makes the requeue durable — a bucket may only be GC'd when `enrolled == 0 && waiters == 0 && pending_redirects == 0`, and the wake-credit mechanism must be drained too. Process-directed broadcast must still reach *every* waiter in the target Linux process, including one caught mid-requeue (`thread.rs:724-732`).

**M7 — `RegistryState` reverse indexes + generation-keyed task store.** `core.rs:1500-1509`, `operations.rs:1855/1870/1886/…`, `operations.rs:3730/3768`, `core.rs:1341/1361/1372`, `operations.rs:2735-2748`.
*Impact:* the kernel-graph half of the load coupling — every scheduler kick and every `wait4` is O(live processes) today. Start with the three trivial `.iter().find` → `.get` fixes (`core.rs:1341/1361/1372`), then `tid_index`, then `zombies_by_parent`.
*Invariants:* the generation check must move from *after* the lookup to *inside* it — `KernelTaskBinding::capture` (`core.rs:208-214`) and `exact_thread_for_scheduler` (`operations.rs:1870`) currently compare keys post-hoc, and a `PidTable::get(TaskKey)` that returns `None` on serial mismatch must produce the *same* `StaleTaskBinding` error, not `UnknownTask`. Every index must be updated inside the same registry write-lock section that mutates the authoritative map, or the index becomes a second source of truth.

**M8 — `GlobalFrameIpaAllocator` free list → `RangeSet` + size index.** `trap.rs:5765-5883`.
*Impact:* removes an O(F log F) sort-and-rebuild from every extent release in the exit storm, and an O(F) best-fit from every allocation.
*Invariant:* the "smallest fitting extent, lowest base as tie-break" policy (`trap.rs:5803-5807`) exists specifically to preserve large contiguous holes for HVPatch exec frames — preserve it exactly, and keep `live` as the fail-closed exact-extent authority (`trap.rs:5857`).

**M9 — `MmResourceState.retired` deletion + `slotmap` for the mm leases.** `mm_resources.rs:82-86`.
*Impact:* removes an explicitly-permanent unbounded set. Small, but a pure leak.
*Invariant:* the duplicate-task rejection at `mm_resources.rs:112/155/172` must still fire — a generational store gives it for free (the key is either live or it misses), but `publish_root`/`publish_child` must return `DuplicateTask` on a *live* key, not silently overwrite.

**M10 — `carrick-collections` crate + `FxHashMap` as the default kernel map.**
*Impact:* the enabling refactor. Houses `PidTable`, `Journal<Undo>`, the generalized `RangeSet<V>` promoted out of `protections.rs:45`, and re-exports `slotmap`/`rangemap`/`iset`/`rustc-hash` so there is one answer per shape. Switching kernel-internal maps off SipHash is a broad, mechanical, measurable win — run it through `scripts/migrate/rewrite.py` as a count-asserted spec, per AGENTS.md.
*Invariant:* keep SipHash anywhere a key could be adversarially chosen. Inside one carrier with carrick-allocated keys, none are.

**M11 — Run-queue intrusive list + executor `by_thread` index.** `scheduler.rs:865, 304-342`.
*Impact:* real but smaller — bounded by runnable threads and by ~10 executors. Do after M1–M7.

**M12 — `rpds` for `CowArmedRanges` and the fork-spec snapshots.** `trap.rs:4580/11194`, the six `.lock().clone()` sites.
*Impact:* turns O(n) snapshot into O(1). Deliberately last: after M1–M3 the cloned sets are per-scope and small, so the benefit may largely evaporate — **measure after M3 before spending the dependency.**

**Cross-cutting invariant for all of the above:** the existing lock order `replay → alias → version` (`trap.rs:7646`, restated at `trap.rs:2291`) and `registry → observations` (`snapshot.rs:967-969`) must be preserved verbatim; adding an index is a new lock only if you let it be, and the right move is to put each index *inside* the existing critical section, not beside it.

---

## 4. Anti-recommendations

**`dashmap` (6.2.1, MIT), `papaya` (0.2.5, MIT), `scc` (3.8.6, Apache-2.0), `flurry`.** All healthy, all popular. All wrong here. Every one of them replaces "one lock over a consistent map" with "many locks over a map with no consistent snapshot." The kernel graph's correctness rests on multi-key atomicity — `retire_task_state_process_mappings` (`trap.rs:10555`) mutates the registry, the mappings, and the frame inventory as **one** transaction; `snapshot.rs:934` takes registry-then-observations in a fixed order. A sharded concurrent map cannot give a cross-key consistent read, so adopting one converts a lock-contention problem into a correctness problem. Additionally `DashMap` deadlocks on re-entrant access to the same shard, which is exactly the shape `mutate_external_alias_state` has today. **The measured problem is O(n) work under the lock, not lock contention.** Fix the algorithm; keep the lock.

**`left-right` (0.11.8, MIT/Apache) and `evmap` (11.0.0, MIT/Apache).** The obvious-looking answer for a "read-mostly global registry," and both are well maintained. But writes go through an oplog and are **applied twice**, `publish()` waits for reader epochs, and "writes through left-right are slower than direct access." The alias registry is *not* read-mostly — `register_shared_alias` (`trap.rs:2290`) fires on **every COW fault**, which in a fork storm is the dominant event. A frequently-written left-right either publishes constantly (paying the epoch wait per write) or grows an unbounded oplog. Wrong axis.

**`im` 15.1.0.** Unmaintained since 2022-04-29 despite 4.75 M recent downloads. For persistent structures: `rpds` (MIT, 2026-05) or `imbl` (the maintained fork, 2026-07) — never `im`.

**`nodit` <0.8.0.** AGPL-3.0-or-later. `cargo deny` will reject it, correctly.

**`store-interval-tree`.** 2 366 recent downloads, last touched 2022-11-22. Adopting a dead 4-year-old crate for a load-bearing kernel structure is worse than the hand-rolled `Vec` it replaces.

**`crossbeam-skiplist`.** Still 0.1.3, last release 2024-01-08. An ordered lock-free map is tempting for `global_frame_host_owners`, but it does not answer the range-containment question (still needs `range(..=ipa).next_back()` plus a manual extent check), and a 0.1.x crate cannot be THE structure under an opt-out-not-opt-in policy.

**`slab` as a task/thread store.** MIT, 201 M downloads, actively maintained — and it has **no generation**. `TaskSerial`/`ThreadSerial` exist precisely because a recycled pid must not alias its predecessor (`objects.rs:3862-3872`, `mm_resources.rs:84-86`). A `slab` key silently aliases on reuse. Use only for arena storage whose keys never outlive one transaction.

**`indexmap`.** 2.14.0, Apache/MIT, 326 M downloads — excellent crate, wrong problem. It buys *insertion-order iteration*, which looks like it might serve the newest-wins alias discipline. It does not: newest-wins needs interval overwrite-and-split, not ordered iteration, and `IndexMap` would preserve the O(n) scan while adding a dependency.

**A single global `RwLock<RegistryState>` "just made finer-grained."** Tempting after reading `core.rs:1199`, and wrong as a *first* move. Every O(live-processes) scan listed in T2 stays O(live-processes) after the lock is split — the wrong work would be parallelized and a lock-ordering hazard taken on for it. Add the indexes first (M7), then re-measure before touching lock granularity at all.

**Persistent (`rpds`/`imbl`) data structures for the kernel graph as a whole.** O(1) clone is seductive given `snapshot.rs`'s 20 full `Vec`s. But `snapshot.rs` is a debug projection with a revision-race retry (`snapshot.rs:26, 873-920`), not a transaction, and persistent maps cost a pointer-chase per *lookup* — taxing every syscall to speed up a diagnostic path. Use `rpds` narrowly (M12) where a genuine snapshot-and-restore exists, and only after M3 proves the clone is still large.

**Adding any crate without making it THE structure.** Per AGENTS.md, a parallel `rangemap`-backed index alongside the `Vec` would be the fifth interval implementation in the tree (after `protections.rs:45`, `trap.rs:5767`, `trap.rs:4580`, and the alias `Vec` itself). Each migration must *delete* what it replaces in the same change.

---

## Two flags outside the brief

1. **`protections.rs:45` `RangeSet` is the best interval structure in the repo and it is private and value-less.** Sorted-merged `Vec` with `partition_point` queries, a two-cursor `intersects_set`, and — notably — a **range-local** `snapshot_mapping_range`/`restore_mapping_range` (`protections.rs:266-300`) that "cannot erase a sibling's disjoint VMA." That range-local rollback is exactly the primitive the HVF side is missing. Promoting it (generic over a value `V`, typed on `GuestVa`/`Gpa`) into `carrick-collections` is higher leverage than any single crate adoption, and it satisfies "look for what already exists before writing anything new."

2. **The bare `u64` keys are the T4 bug shape all over again.** `FutexTable.shards: HashMap<u64, …>` (`thread.rs:899`) holds a *guest futex address* on the private path and a *`SharedFutexLocation::waiter_key()`* on the shared path — two domains in one integer type, which `docs/typed-interfaces-audit.md` lists as the origin of three shipped bugs. `ReplayMappingKey = (u64, usize, usize, u64)` (`trap.rs:2236`) and `global_frame_host_owners`' `(u64, u64)` (`trap.rs:1974`) are the same shape. Whatever structure replaces them should take the opportunity to key on `Gpa`/`GuestVa`/a `FutexKey` newtype, so the migration also closes a `just lint-domains`-class gap instead of carrying it forward.
