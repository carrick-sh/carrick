# Per-mm Topology Authority Implementation Plan

> **For agentic workers:** this plan is executed by the campaign director
> through file-disjoint Antigravity worktrees (one task per worktree, briefs
> derived from the task sections below) with director-owned live
> verification; the superpowers executing-plans / subagent-driven flows are
> not used here. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a multi-process guest workload runs its processes concurrently:
`cpython-multiprocessing_main_handling` uses the CPUs the guest is given
(today 1.3 cores of 4 while Docker uses ~5 of 10) and finishes within 2x of
native Docker at the four-worker ledger condition.

**Architecture:** the carrier-wide `fork_quiesce::topology_lock()` mutex is
held across whole fork, exec and process-exit transactions and is also taken
by every mmap, COW fault and munmap in every process, so one process's fork
stalls every other process's fault. Its original reason (a fork destroying
and rebuilding the HVF VM while a sibling creates a vCPU) no longer exists in
HVPatch: there is no production `hv_vm_destroy` call. What the lock still
protects is (a) publication of frames into the carrier-wide shared-frame
registry, (b) the carrier-global alias/replay/version containers, and (c)
sibling-execution exclusion that the per-mm stage-1 pause already provides.
The plan measures first, then replaces the one mutex with authorities scoped
to what they protect: the mm's own mutation guard for per-process
transactions, a short leaf frame-registry critical section for cross-mm
frame publication, and per-mm alias containers so exit and unmap are O(own
rows). The fork barrier's carrier-global `quiescing` flag and the single
per-carrier process-fork coordinator become per-parent-mm, riding the per-mm
quiesce binding that already landed (mm-scope, 2026-09-07). Acceptance is a two-process contention test in the signed embed
lane plus the paired ecosystem scorecard.

**Tech Stack:** Rust workspace (`carrick-thread`, `carrick-runtime`,
`carrick-vmm-hvf`, `carrick-embed`), DTrace USDT
(`carrick*:::hvpatch-topology-lock`), the conformance harness.

**Spec:** `docs/superpowers/specs/2026-09-07-guest-cpu-scheduler-design.md`
(section "Safe point as a primitive" and phasing item 4) and
`docs/superpowers/specs/2026-08-28-mm-authority-lock-order-design.md`
(structural lock ordering: `MmMutationGuard -> HostAliasPermit ->
HostAliasGuard`; "This design does not serialize unrelated MMs globally").
Evidence: `docs/superpowers/plans/2026-09-10-feedback-holistic.md` (the
2026-09-11 multiprocessing finding) and
`docs/perf-results/2026-08-09-hvpatch-phase4-topology-lock.md`.

## Global Constraints

- Lock order is structural and unchanged in direction: stage-1 pause
  (`PtQuiesce`, per mm) before any topology-scoped authority; topology-scoped
  authorities before the frame-inventory authority, which stays a leaf
  (`frame_inventory.rs` never calls out while holding it). A token only the
  outer acquisition can mint, never discipline (AGENTS.md "A rule that lives
  in a comment is a bug that has not happened yet").
- No carrier-wide `'static` mutex may be introduced or kept for per-process
  work. The runtime-global-state ledger gate (`just lint-domains`) is the
  monotonic baseline; new statics need a row with a carrier-scope rationale.
- Correctness before speed: every change lands behind the full probe gate
  (`just conformance-probes`), `just ci`, and the two-process tests below.
  No hatch that keeps the old path alive beside the new one; a mechanism
  measured worse is deleted.
- Perf claims come only from interleaved paired runs on a quiet host
  (`target/conformance/eco-load/paired-sep11.sh` pattern); no other agent
  runs guests on the host during a measurement.
- Clean-room: BSD-licensed references only (FreeBSD `vm_map` per-map locks,
  gVisor `mm.MemoryManager` per-mm `mappingMu`/`activeMu`, Go `runtime`).
- Every worker brief carries the scope fence from its task; the director
  re-homes line-pinned inventories at landing.

---

### Task 0: Measure the serializer on the multiprocessing row (director, quiet host)

**Files:**
- Read: `scripts/dtrace/hvpatch-phase4-topology-lock.d`,
  `scripts/dtrace/hvpatch-guest-syscall-flow.d`
- Create: `target/perf/perf2x-sep11/topology-multiprocessing.out`,
  `target/perf/perf2x-sep11/cpus10-multiprocessing.time`
- Modify: `docs/superpowers/plans/2026-09-10-feedback-holistic.md` (append
  the numbers)

**Interfaces:**
- Produces: the per-operation wait/hold table (fork, exec, retire, alias
  map, frame COW, alias unmap) and the parallelism (user CPU-s / wall) of the
  row at 4 and at 10 exposed CPUs. Task 2's brief cites these numbers.

- [ ] **Step 1: Wait for a quiet host** (no worker builds, no guests):
  `until [[ $(sysctl -n vm.loadavg | awk '{print $2}' | cut -d. -f1) -lt 5 ]] && ! pgrep -q 'cargo|rustc'; do sleep 30; done`
- [ ] **Step 2: Trace the topology lock on the row**

```
CARRICK_RUN_ID=topo-mp target/release/carrick trace \
  -s scripts/dtrace/hvpatch-phase4-topology-lock.d \
  --trace-out target/perf/perf2x-sep11/topology-multiprocessing.out -- \
  run --fs host localhost:5050/cpython-test:3.12.13 \
  /usr/local/bin/python3 -m test -v --randseed 0 test_multiprocessing_main_handling
```
  Expected: non-zero request/acquire/release counts; a table of wait and
  hold per operation class. Zero events is a failed capture, not idle.
- [ ] **Step 3: Parallelism at 4 vs 10 exposed CPUs** (single variable):

```
for n in 4 10; do CARRICK_RUN_ID=cpus$n CARRICK_EXPOSED_CPUS=$n /usr/bin/time -l \
  target/release/carrick run --fs host localhost:5050/cpython-test:3.12.13 \
  /usr/local/bin/python3 -m test --randseed 0 test_multiprocessing_main_handling \
  </dev/null > target/perf/perf2x-sep11/cpus$n-multiprocessing.out \
  2> target/perf/perf2x-sep11/cpus$n-multiprocessing.time; done
```
  Record wall, user, sys for each; parallelism = (user+sys)/wall.
- [ ] **Step 4: Fork-side waits**: `carrick trace -s scripts/dtrace/hvpatch-fork-wait-roundtrip.d`
  on the same command to attribute fork retries (`Barrier`, `Admission`,
  `Lease`, `Topology` sub-states) and how long each child's first
  instruction waits after the parent's `fork` returns.
- [ ] **Step 5: Per-task flow** if steps 2 and 4 show short holds (the serializer
  is then not the lock): `carrick trace -s scripts/dtrace/hvpatch-guest-syscall-flow.d`
  on the same command; report which syscalls the children are parked in.
- [ ] **Step 6: Append the numbers** to the feedback-holistic progress log
  and commit (`docs: measure the multiprocessing serializer`).

---

### Task 1: Two-process contention and parallelism tests (red first)

**Files:**
- Create: `crates/carrick-embed/tests/two_process_parallelism.rs`
- Create: `conformance-probes/src/bin/forkstorm.rs` (guest-side workload;
  libc-only, cross-compiles locally)
- Modify: `conformance-probes/probe-inventory.json` (declare `forkstorm` as
  a workload binary, not an oracle probe)

**Interfaces:**
- Consumes: the signed embed test lane (`just test-embed`, runs each test
  executable under `RUST_TEST_THREADS=1` with the hypervisor entitlement).
- Produces: `two_process_parallelism::children_run_concurrently` and
  `two_process_parallelism::fault_latency_is_independent_of_sibling_fork`,
  both red on main today, green at the end of Task 4. Later tasks name these
  exact test ids in their Verified sections.

- [ ] **Step 1: Write the guest workload** `forkstorm.rs` with two modes:
  `forkstorm busy <n> <ms>` forks `n` children that spin on a monotonic
  clock for `ms` milliseconds and `_exit`; the parent prints
  `wall_ms=<..>` and `children=<n>`. `forkstorm faulter <iters>` maps a 64 MiB
  anonymous region, touches one page per 4 KiB in a loop `iters` times,
  unmapping and remapping each round, and prints the p50 and p99 of the
  per-round latency in microseconds. Bound every wait (5 s); no asserts.
- [ ] **Step 2: Build it for the guest**:
  `cd conformance-probes && cargo build --release --target aarch64-unknown-linux-musl --bin forkstorm`
- [ ] **Step 3: Write the failing tests** in the embed lane. Use the
  in-process `carrick-embed` API exactly as `crates/carrick-embed/tests/`
  siblings do (copy their setup of the container image and the signed
  fail-closed entitlement check; `HV_DENIED` is a failure, never a skip).

```rust
#[test]
fn children_run_concurrently() {
    // 4 children x 400 ms of spinning; with 4 exposed CPUs the wall time is
    // ~400 ms when they run in parallel and ~1600 ms when serialized.
    let out = run_guest(&["/p/forkstorm", "busy", "4", "400"]);
    let wall_ms: u64 = field(&out, "wall_ms");
    assert!(wall_ms < 800, "children serialized: wall_ms={wall_ms} ({out})");
}

#[test]
fn fault_latency_is_independent_of_sibling_fork() {
    // Process A: fork storm (200 forks). Process B: fault loop. B's p99
    // round latency with A running must stay within 3x of B alone.
    let alone = fault_p99(run_guest(&["/p/forkstorm", "faulter", "50"]));
    let (a, b) = run_two_guests(
        &["/p/forkstorm", "busy", "200", "5"],
        &["/p/forkstorm", "faulter", "50"],
    );
    assert!(a.exit_ok());
    let contended = fault_p99(b);
    assert!(contended < alone * 3, "fault p99 {contended}us vs alone {alone}us");
}
```
  `run_two_guests` starts both processes in ONE carrier (the second via the
  embed API's spawn of a sibling process, the same entry the conformance
  harness's two-process scenarios use) and waits for both.
- [ ] **Step 4: Run and record the red**:
  `just test-embed two_process_parallelism` — expected: both FAIL with the
  serialized numbers; paste them into the commit body.
- [ ] **Step 5: Commit** `test(embed): two-process parallelism and fork-vs-fault contention (red)`.

---

### Task 2: Delete the dead reason — VM custody no longer needs a carrier mutex

**Files:**
- Modify: `crates/carrick-thread/src/fork_quiesce.rs:113-123` (doc), `:301`
  (`acquire_topology_lock`), `:345` (`try_acquire_topology_lock`)
- Modify: `crates/carrick-vmm-hvf/src/trap/persistent_executor.rs:823-828`,
  `:1421-1429` (the "rebuilt VM cell" reads)
- Modify: `crates/carrick-observability/src/probes.rs:1681-1693`
  (operation classes stay append-only; no edit unless a new class is added)
- Test: `crates/carrick-thread/src/fork_quiesce.rs` (`#[cfg(test)]`),
  `crates/carrick-vmm-hvf/src/trap/persistent_executor.rs` tests

**Interfaces:**
- Produces: `TopologyOp` (the existing operation enum) split into three
  typed authorities that Task 3 and Task 4 consume:
  `MmTransactionGuard<'mm>` (minted only from the mm's `MmMutationGuard`),
  `FrameRegistryGuard` (a short leaf critical section over the shared-frame
  registry), and `VmCustodyGuard` if and only if Step 2 proves a live
  vCPU-create versus VM-teardown race remains.

- [ ] **Step 1: Prove the rebuilt-VM path is dead**: grep for
  `rebuilt_vm_cell` writers; there must be none outside tests and the legacy
  removal commits. Write a source-shape test in `persistent_executor.rs`
  asserting no non-test `hv_vm_destroy` call exists in `carrick-vmm-hvf`
  (`include_str!` over the crate's `src/` is the pattern the tree uses).
- [ ] **Step 2: Remove the "vCPU create vs `hv_vm_destroy`" justification**
  from the `topology_lock` doc and from `persistent_executor.rs:823-828`;
  delete `rebuilt_vm_cell` and its reads at `:1254` and `:1422-1429`
  (there is no rebuild). Keep `acquire_topology_lock` compiling: this task
  changes the doc contract and the dead reads only.
- [ ] **Step 3: Add the three guard types** in `fork_quiesce.rs` next to
  `TopologyLockGuard`, each with a private constructor:

```rust
/// Exclusion for one mm's fork/exec/retire transaction. Minted only by the
/// mm's `MmMutationGuard` (see carrick-runtime `dispatch/mm_authority.rs`),
/// so holding it proves the stage-1 pause is already held: the P -> topology
/// order becomes a type, not a comment.
pub struct MmTransactionGuard<'mm> { _mm: core::marker::PhantomData<&'mm ()>, depth: TopologyDepth }

/// Leaf critical section for the carrier-wide shared-frame registry: staging
/// and publishing frames another process may install next. Never held across
/// a guest write, a wait, or another lock.
pub struct FrameRegistryGuard<'r> { _guard: parking_lot::MutexGuard<'r, ()> }
```
  and a `frame_registry_lock() -> &'static parking_lot::Mutex<()>` whose only
  callers are Task 3's publication sites. Add a `runtime-global-state.json`
  row for it with rationale "carrier-scoped: frames shared across mms".
- [ ] **Step 4: Tests**: `mm_transaction_guard_requires_mm_mutation_guard`
  (does not compile without the guard — express as a `trybuild`-free doc
  test that shows the only constructor path) and
  `frame_registry_guard_is_a_leaf` (source-shape: no `acquire_topology_lock`
  or `.lock()` call between `frame_registry_lock().lock()` and its drop).
- [ ] **Step 5: Verify** `just fmt-check && just clippy && just lint-domains && RUST_TEST_THREADS=1 cargo test -p carrick-thread --lib && RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib trap::persistent_executor`
- [ ] **Step 6: Commit** `refactor(runtime): retire the VM-rebuild rationale and type the topology authorities`.

---

### Task 3: Frame publication under the leaf registry section, not the carrier mutex

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:1763-1858`
  (`install_alias` closure: `AliasMap`)
- Modify: `crates/carrick-vmm-hvf/src/trap/cow_engine.rs:772`
  (`materialize_sparse_mmap_extent_inner`), `:1097`
  (`materialize_retired_reuse`), `:1889` (`perform_frame_cow`)
- Modify: `crates/carrick-vmm-hvf/src/trap/foreign_mm.rs:1492`
  (`perform_foreign_cow_transaction`)
- Modify: `crates/carrick-vmm-hvf/src/trap/frame_inventory.rs:1720-1728`
  (doc: which lock the publication order now rides on)
- Test: `crates/carrick-vmm-hvf/src/trap/cow_engine/tests.rs`,
  `crates/carrick-runtime/src/vcpu_loop/tests.rs` (or the sibling `tests.rs`
  the split created)

**Interfaces:**
- Consumes: `FrameRegistryGuard` / `frame_registry_lock()` from Task 2;
  `MmMutationGuard` from `dispatch/mm_authority.rs`.
- Produces: `begin_alias_inventory` / `apply_alias_frame_inventory` take a
  `&FrameRegistryGuard` parameter; `perform_frame_cow` and the two
  materialize paths take `&MmTransactionGuard` (per-mm) and mint the
  registry guard only around the publish step.

- [ ] **Step 1: Write the failing shape test**: a source-shape test in
  `cow_engine/tests.rs` that `perform_frame_cow`, `materialize_*` and
  `install_alias` contain no `acquire_topology_lock(` call (red today).
- [ ] **Step 2: Convert `install_alias`** (mmap): the mm's own
  `MmMutationGuard` is already held by the dispatcher on this path
  (pre-dispatch page-table pause); replace `acquire_topology_lock(AliasMap)`
  with `let registry = FrameRegistryGuard::new(frame_registry_lock().lock());`
  taken immediately before `begin_alias_inventory` and dropped right after
  `apply_alias_frame_inventory` (publication order == staging order, as the
  2026-09-08 `UnreservedFrame` fix requires: both happen under the same
  guard). The error unwind at `:1830` releases the same guard.
- [ ] **Step 3: Convert the COW paths** (`perform_frame_cow`,
  `materialize_sparse_mmap_extent_inner`, `materialize_retired_reuse`,
  `perform_foreign_cow_transaction`): the exact-mm `authority.quiesce()`
  already precedes them (the comment at `cow_engine.rs:1881` states the
  order); take `FrameRegistryGuard` only around the frame-inventory
  reservation/publish step of each, and hold nothing carrier-wide across the
  frame copy.
- [ ] **Step 4: Run the shape test green and the crate tests**:
  `RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib trap::cow_engine` and
  `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib vcpu_loop`.
- [ ] **Step 5: Commit** `refactor(hvf): publish frames under the registry leaf, not the carrier mutex`.

---

### Task 4: Fork, exec and exit transactions hold their mm, not the carrier

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs:1740-2098`
  (in-process fork prepare)
- Modify: `crates/carrick-runtime/src/vcpu_loop/exec.rs:1719-1834`
  (`drive_execve`)
- Modify: `crates/carrick-runtime/src/vcpu_loop/binding.rs:967-1232`
  (`finalize_persistent_process_terminal`)
- Modify: `crates/carrick-runtime/src/vcpu_loop/executor.rs:4543`,
  `:4926-4940` (`acquire_process_retire_topology_lock_servicing`)
- Modify: `crates/carrick-vmm-hvf/src/trap/cow_engine.rs:4180`
  (`unregister_process_alias`)
- Modify: `crates/carrick-runtime/src/vcpu_loop/executor.rs:2309`
  (boundary refusal keys on the mm transaction depth)
- Test: the `tests.rs` siblings of each file; Task 1's embed tests

**Interfaces:**
- Consumes: `MmTransactionGuard` (Task 2), `FrameRegistryGuard` (Task 2).
- Produces: `acquire_topology_lock` / `try_acquire_topology_lock` have no
  production callers; Task 5 deletes them.

- [ ] **Step 1: Write the failing shape test**: no production
  `acquire_topology_lock(`/`try_acquire_topology_lock(` in `quiesce.rs`,
  `exec.rs`, `binding.rs`, `executor.rs`, `cow_engine.rs` (red today).
- [ ] **Step 2: Fork** (`quiesce.rs:1740`): the parent already holds its
  exact-mm pause (the P -> topology order the 2026-09-02 fix established);
  mint `MmTransactionGuard` from it for the whole child-publication
  transaction. The only carrier-wide step inside is the frame-inventory
  reservation for the child's shared frames: wrap exactly that in
  `FrameRegistryGuard`. A second process's fork now proceeds concurrently.
- [ ] **Step 3: Exec** (`exec.rs:1725`): `ExecReplace` serialized "concurrent
  execs" because all processes mutate stage-2 in one VM; stage-2 edits for
  distinct mms touch distinct IPA ranges owned by distinct mms, so the
  exclusion is the mm's guard plus `FrameRegistryGuard` around
  `execve_into`'s frame publication. Keep the `drop` before the
  frame-inventory authority (`:1831-1834`) as a `drop(registry)`.
- [ ] **Step 4: Exit** (`binding.rs:967`, `executor.rs:4543`): terminal
  retirement edits the exiting mm's rows and retires its frames. Hold the
  mm's guard for the classification and `FrameRegistryGuard` around the
  retirement reservation + apply. Delete
  `acquire_process_retire_topology_lock_servicing` and its backoff loop (it
  existed to stay responsive while contending on the carrier mutex).
- [ ] **Step 5: Unmap** (`cow_engine.rs:4180`): `unregister_process_alias`
  runs under the caller's mm exclusion; take `FrameRegistryGuard` only for
  `commit_process_alias_retirement`'s inventory publish. The
  "alias registry changed under topology lock" fatal at `:4285` becomes
  "changed under the mm guard" and keeps its ledger row.
- [ ] **Step 6: Executor boundary** (`executor.rs:2309`): refuse to hand the
  host thread to another logical thread while an `MmTransactionGuard` is
  live (same depth counter, renamed).
- [ ] **Step 7: Run** Task 1's tests: `just test-embed two_process_parallelism`
  — expected green (`wall_ms` < 800; fault p99 within 3x). Then the crate
  tests and `just lint-domains`.
- [ ] **Step 8: Commit** per site (fork, exec, exit, unmap, boundary) so a
  bisect can land between them; each commit names the shape test.

---

### Task 5: Per-mm alias containers and deletion of the carrier mutex

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/trap.rs:4005-4016` (the alias
  registry, replay set and version chains: carrier-global containers)
- Modify: `crates/carrick-vmm-hvf/src/trap/memory_protection.rs`
  (`AliasRegistry` — keep the per-scope buckets; make the scope map the
  owner of its rows' lifetime so a process exit drops one bucket)
- Modify: `crates/carrick-thread/src/fork_quiesce.rs` (delete
  `topology_lock`, `acquire_topology_lock`, `try_acquire_topology_lock`,
  `TopologyLockGuard`, the release-generation subscription)
- Modify: `crates/carrick-observability/src/probes.rs` (the
  `hvpatch-topology-lock` USDT keeps firing for `MmTransactionGuard` and
  `FrameRegistryGuard` with the same append-only operation ids, so
  `hvpatch-phase4-topology-lock.d` still measures the new authorities)
- Modify: `scripts/migrate/runtime-global-state.json` (drop the
  `topology_lock` row, add the registry row from Task 2 if not yet)
- Test: `memory_protection.rs` tests; `trap/tests.rs`

**Interfaces:**
- Consumes: everything above.
- Produces: `AliasRegistry::retire_scope(scope) -> RetiredRows` (O(rows in
  scope)); no `topology_lock` symbol in the workspace.

- [ ] **Step 1: Failing test**: `exit_cost_is_bounded_by_own_rows` in
  `memory_protection.rs` — with 1,000 scopes of 64 rows each, retiring one
  scope visits ≤ 64 + log(1000) rows (test-only visit counter); red today
  because retirement walks the carrier-global replay/version containers.
- [ ] **Step 2: Make replay set and version chains per scope** (owned by
  the scope bucket); `retire_scope` drops the bucket. Keep the by-VA/IPA
  start indexes as they are (Task `alias-newest-index` owns their shape).
- [ ] **Step 3: Delete the carrier mutex** and its API; `just clippy` finds
  every remaining use — there must be none outside tests, which convert to
  the new guards.
- [ ] **Step 4: Verify** `just ci`; `just conformance-probes`; `just test-embed`.
- [ ] **Step 5: Commit** `refactor(hvf): own alias rows per mm and delete the carrier topology mutex`.

---

### Task 6: Fork's carrier-wide serializers become per-parent-mm

**Files:**
- Modify: `crates/carrick-thread/src/fork_quiesce.rs` (`QuiesceBarrier`;
  `is_quiescing() = fork barrier || is_current_mm_quiescing()` at
  `:106-109`; the fork flag is one carrier-global `AtomicBool`)
- Modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs:531`
  (`try_begin_hvpatch_process_fork_with_admission`: ONE process-fork
  coordinator per carrier, `Busy` -> `Retry{Barrier}` for every other
  forker), `:1345-1366` (barrier raise from `fork_barrier_participants`),
  `:1330-1342` (why `quiescing` stays raised across the lease wait)
- Modify: `crates/carrick-runtime/src/vcpu_loop/binding.rs:4521`, `:4132`
  (`bind_current_mm_quiesce`: the per-poll binding that already makes the
  page-table pause per mm; the fork flag must ride the same binding)
- Modify: `crates/carrick-runtime/src/kernel/objects.rs:5408`
  (`fork_barrier_participants` — durable thread membership of the forking
  task, already per thread group)
- Test: `fork_quiesce.rs` tests; `quiesce.rs` tests; Task 1's
  `children_run_concurrently`

**What is wrong today (from the 2026-09-11 map):** the page-table pause is
already per mm (`DispatchMmAuthority` mints a `PtQuiesce` per mm; a vCPU
running another process is never kicked by it). Two fork-side mechanisms
are still carrier-wide: (1) the fork `QuiesceBarrier`'s `quiescing` flag is
one carrier-global bool that EVERY executor's `enter_guest_or_park` reads,
so while any threaded process is mid-fork, every vCPU in the carrier parks
at its next boundary, and the flag stays raised across the forker's lease
wait by design; (2) `try_begin_hvpatch_process_fork_with_admission` admits
one process fork per carrier at a time, so forks in unrelated processes
queue behind each other. A CPython `multiprocessing` parent is threaded
(resource tracker, result handler), so both fire on every child it starts.

**Interfaces:**
- Consumes: `DispatchMmAuthority` (`dispatch/mm_authority.rs:22-46`), the
  per-poll `bind_current_mm_quiesce` binding.
- Produces: `ForkQuiesce` owned by the forking task's mm authority (next to
  its `PtQuiesce`), `is_quiescing()` reads only the bound mm's fork flag;
  `ProcessForkCoordinator` keyed by parent mm (one in flight per parent,
  unlimited across parents); `QuiesceBarrier::kick_participants(&[VcpuId])`
  from `fork_barrier_participants` only; the carrier-global fork flag and
  the carrier-global fork coordinator are deleted.

- [ ] **Step 1: Failing tests** in `fork_quiesce.rs` /
  `quiesce.rs` tests: `fork_in_one_mm_does_not_park_executors_of_another`
  (two mm authorities bound on two executors; raise mm A's fork quiesce;
  executor bound to B reports `is_quiescing() == false`) and
  `two_parents_fork_concurrently` (two `try_begin_..._with_admission` on
  distinct parent mms both return `Ok`, not `Busy`). Both red today.
- [ ] **Step 2: Move the fork flag** into the mm authority: add
  `fork_quiesce: Arc<ForkQuiesce>` beside `pt_quiesce` in
  `DispatchMmAuthority`; `bind_current_mm_quiesce` binds both;
  `is_quiescing()` = `is_current_mm_fork_quiescing() ||
  is_current_mm_quiescing()`. Delete the static flag.
- [ ] **Step 3: Key the process-fork coordinator by parent mm**: the
  coordinator cell lives in the parent's `DispatchMmAuthority`; `Busy` now
  means "this parent already has a fork in flight" (Linux serializes those
  too, never with `EAGAIN`, so the `Retry{Barrier}` path stays).
- [ ] **Step 4: Kick only participants**: `kick_participants` iterates the
  durable membership from `fork_barrier_participants`; delete
  `kick_all_except`.
- [ ] **Step 5: Verify** `RUST_TEST_THREADS=1 cargo test -p carrick-thread --lib`,
  `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib vcpu_loop::quiesce`,
  `just test-embed two_process_parallelism`, then the `execthreads`,
  `forkcow`, `vfork*` and `setidthreadchurn` probes via `just conformance-probes`.
- [ ] **Step 6: Commit** per mechanism (flag, coordinator, kick).

---

### Task 7: Exposed CPU policy (owner decision) and acceptance

**Files:**
- Modify: `crates/carrick-host/src/host_facts.rs:128-213` if the owner
  chooses to expose every logical CPU like Docker (10 here) instead of the
  performance cluster (4)
- Modify: `docs/conformance-campaigns/2026-09-04-ecosystem.md` (scorecard
  entry), `docs/superpowers/plans/2026-09-10-feedback-holistic.md`

- [ ] **Step 1: Decision input**: Task 0's 4-vs-10 measurement. If 10 CPUs
  is faster for the row AND no other row regresses in a paired run, the
  default changes to `host_logical` with `CARRICK_EXPOSED_CPUS` as the exact
  hatch; otherwise the policy stays and the doc records why.
- [ ] **Step 2: Paired scorecard** (`paired-sep11.sh` with base = the
  pinned 3c8dbee5b686c49d binary, cand = the tree after Tasks 2–6): all 11
  rows MATCH; `multiprocessing_main_handling` ≤ 2x at w4; no row worse than
  base beyond noise (paired cand/base ≤ 1.05).
- [ ] **Step 3: Record** the result in both docs and commit.

---

## Self-review notes

- Spec coverage: phase 4 of the scheduler spec ("per-mm quiesce; retire the
  global election [done by mm-scope]; the fork barrier's carrier-wide kick
  [Task 6]; scope the topology lock per mm [Tasks 2–5]") is covered; the
  lock-order design's "does not serialize unrelated MMs globally" is the
  invariant Task 2's guard types encode.
- What stays carrier-wide, on purpose: the shared-frame registry leaf
  section (frames genuinely shared across mms) and HVF VM custody itself.
- Risk: Task 4 Step 3 (exec) assumes distinct mms never edit the same
  stage-2 IPA range; the frame-inventory authority's reservation is the
  arbiter for shared frames, which is why the registry guard wraps exactly
  the publication step. Task 0's trace decides ordering of Tasks 3–6 by
  where the wait time actually sits.

## Measurement note (2026-09-12, after Task 4)

`hvpatch-phase4-topology-lock.d` on the multiprocessing row recorded zero
events (`empty=1`) and `hvpatch-fork-wait-roundtrip.d` recorded `pairs=0`:
both key on the `carrick*:::hvpatch-topology-lock` USDT firings, which now
have no production site. That is Task 4 working, and it also blinds the two
instruments. Task 5 must fire the same append-only operation ids from
`MmTransactionGuard` (per-mm hold) and `FrameRegistryGuard` (leaf hold)
acquisitions so the scripts measure the new authorities, and the fork-wait
script's anchors must be re-qualified live before its numbers are cited.

## Measurement (2026-09-12, binary 56fe7daa3cd2d54d = main 9c04adc56, quiet host)

- Task 1 acceptance: `children_run_concurrently` PASSED (0.60 s for four
  400 ms spinners; serialized would be ~1.6 s) — child processes run in
  parallel after Task 4. `fault_latency_is_independent_of_sibling_fork`
  failed on a TEST defect (second `Carrier::new()` while the first was
  alive → `CarrierAlreadyActive`, after a 472 s alone phase); restructured
  around one carrier with an 8-round fault loop, rerun pending.
- Task 0 traces: the topology-lock instrument records `empty=1` (no
  carrier-mutex site left — Task 5 re-attaches the USDT to the guards);
  the fork-wait trace on the multiprocessing row now pairs 293 forks:
  fork mean 1.35 ms, child lifetime mean 79.7 ms, reap mean 59.5 ms.
- Exposed CPUs 4 vs 10 on the multiprocessing row: 6.53 s vs 6.55 s wall
  (10.2 s user + 2.6 s sys both) — the CPU count is not the limiter;
  parallelism is ~1.95 cores (was 1.3 before Task 4; Docker ~5 of 10 in
  2.9 s). The row is now ~2.2x Docker at one worker; the remaining
  serialization is Task 6's (fork flag/coordinator) and Task 5's.
